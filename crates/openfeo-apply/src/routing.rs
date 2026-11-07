// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The routing applier: addresses on managed interfaces (point-to-point ones with their peer),
//! routes and policy rules with `RTPROT_OPENFEO`. Adds what is missing; deletes IPv4
//! global-scope addresses on managed interfaces, IPv6 global-scope addresses on the interfaces whose IPv6 the router owns
//! (`DesiredRouting::ipv6_owned`), and protocol-200 routes and rules that are no longer
//! desired; touches nothing else (IPv6 on any other interface, which stays the kernel's;
//! link-local addresses; connected routes; anything on other interfaces; routes and rules
//! with other protocols). A pass is best-effort: a refused operation or a missing interface is
//! reported at the end, after everything else was attempted.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;

use ipnet::IpNet;
use openfeo_netlink::{
    Cache, Error as NetlinkError, Netlink, RTPROT_OPENFEO, Route, RouteKind, Rule, RuleAction,
    SCOPE_UNIVERSE, describe_rule,
};
use openfeo_reconcile::routing::{
    DesiredRoute, DesiredRouting, DesiredRuleAction, RouteKind as DesiredKind,
};

use crate::{ApplyError, Pass, Report, is_managed, resolve};

/// Makes the kernel's addresses and routes match [`DesiredRouting`].
#[derive(Debug, Default)]
pub struct RoutingApplier;

impl RoutingApplier {
    /// A fresh applier (it keeps no state: the cache is the state).
    #[must_use]
    pub fn new() -> Self {
        RoutingApplier
    }

    /// One pass: addresses first (routes need them), then routes.
    ///
    /// # Errors
    ///
    /// The first failure of the pass, after every other operation was attempted:
    /// [`ApplyError::Netlink`] when the kernel refused one, [`ApplyError::Unresolvable`] when a
    /// desired interface does not exist yet.
    pub async fn apply(
        &mut self,
        desired: &DesiredRouting,
        observed: &Cache,
        nl: &Netlink,
    ) -> Result<Report, ApplyError> {
        let mut pass = Pass::default();

        addresses(&mut pass, desired, observed, nl).await;

        let mut wanted_routes: BTreeSet<Route> = BTreeSet::new();
        // Routes without a gateway (hosts on the port) first: a route through such a host is
        // refused until it exists.
        let mut ordered: Vec<&DesiredRoute> = desired.routes.iter().collect();
        ordered.sort_by_key(|route| route.gateway.is_some());
        for desired_route in ordered {
            let oif = match &desired_route.ifname {
                Some(ifname) => match resolve(observed, nl, ifname).await {
                    Ok(index) => Some(index),
                    Err(err) => {
                        pass.fail(err);
                        continue;
                    }
                },
                None => None,
            };
            let route = Route {
                v6: desired_route.gateway.map_or_else(
                    || matches!(desired_route.dst, Some(IpNet::V6(_))),
                    |gateway| gateway.is_ipv6(),
                ),
                table: desired_route.table,
                dst: desired_route.dst,
                gateway: desired_route.gateway,
                oif,
                protocol: desired_route.protocol,
                priority: desired_route.priority,
                kind: match desired_route.kind {
                    DesiredKind::Unicast => RouteKind::Unicast,
                    DesiredKind::Blackhole => RouteKind::Blackhole,
                    DesiredKind::Unreachable => RouteKind::Unreachable,
                },
                pref_src: desired_route.pref_src,
            };
            wanted_routes.insert(route.clone());
            if !observed.routes.contains(&route) {
                let ifname = desired_route.ifname.as_deref().unwrap_or("-");
                let op = format!("add route {}", describe(&route, ifname));
                pass.op(&op, nl.route_add(&route).await, NetlinkError::is_exist);
            }
        }
        for route in &observed.routes {
            if route.protocol != RTPROT_OPENFEO || wanted_routes.contains(route) {
                continue;
            }
            let ifname = route
                .oif
                .and_then(|oif| observed.links.get(&oif))
                .map_or("?", |link| link.name.as_str());
            let op = format!("del route {}", describe(route, ifname));
            pass.op(&op, nl.route_del(route).await, NetlinkError::is_absent);
        }

        rules(&mut pass, desired, observed, nl).await;
        pass.finish()
    }
}

/// Addresses: add the desired ones that are missing, delete the global-scope ones on managed
/// interfaces (IPv4) and on interfaces whose IPv6 the router owns that are not desired. An
/// address is its interface, its prefix and, on a point-to-point link, its peer: a new session's
/// address with a new peer is a new address, and the old one goes.
async fn addresses(pass: &mut Pass, desired: &DesiredRouting, observed: &Cache, nl: &Netlink) {
    let mut wanted: BTreeSet<(u32, IpNet, Option<IpAddr>)> = BTreeSet::new();
    for addr in &desired.addrs {
        let index = match resolve(observed, nl, &addr.ifname).await {
            Ok(index) => index,
            Err(err) => {
                pass.fail(err);
                continue;
            }
        };
        wanted.insert((index, addr.net, addr.peer));
        let present = observed
            .addrs
            .iter()
            .any(|a| a.ifindex == index && a.net == addr.net && a.peer == addr.peer);
        if present {
            continue;
        }
        let (op, result) = if let Some(peer) = addr.peer {
            (
                format!("add addr {} peer {peer} dev {}", addr.net, addr.ifname),
                nl.addr_add_peer(index, addr.net, peer).await,
            )
        } else {
            (
                format!("add addr {} dev {}", addr.net, addr.ifname),
                nl.addr_add(index, addr.net).await,
            )
        };
        pass.op(&op, result, NetlinkError::is_exist);
    }
    for addr in &observed.addrs {
        let Some(link) = observed.links.get(&addr.ifindex) else {
            continue;
        };
        let ours = match addr.net {
            IpNet::V4(_) => is_managed(&link.name),
            IpNet::V6(_) => desired.ipv6_owned.contains(&link.name),
        };
        if !ours
            || addr.scope != SCOPE_UNIVERSE
            || wanted.contains(&(addr.ifindex, addr.net, addr.peer))
        {
            continue;
        }
        let (op, result) = if let Some(peer) = addr.peer {
            (
                format!("del addr {} peer {peer} dev {}", addr.net, link.name),
                nl.addr_del_peer(addr.ifindex, addr.net, peer).await,
            )
        } else {
            (
                format!("del addr {} dev {}", addr.net, link.name),
                nl.addr_del(addr.ifindex, addr.net).await,
            )
        };
        pass.op(&op, result, NetlinkError::is_absent);
    }
}

/// Policy rules (SPEC §7.4): add the desired ones that are missing, delete the protocol-200
/// ones that are not desired; the kernel's own rules are never touched.
async fn rules(pass: &mut Pass, desired: &DesiredRouting, observed: &Cache, nl: &Netlink) {
    let mut wanted: BTreeSet<Rule> = BTreeSet::new();
    for desired_rule in &desired.rules {
        let rule = Rule {
            v6: desired_rule.v6,
            priority: desired_rule.priority,
            src: desired_rule.src,
            action: match desired_rule.action {
                DesiredRuleAction::ToTable(table) => RuleAction::ToTable(table),
                DesiredRuleAction::Unreachable => RuleAction::Unreachable,
            },
            suppress_prefixlen: desired_rule.suppress_prefixlen,
            protocol: RTPROT_OPENFEO,
        };
        wanted.insert(rule.clone());
        if !observed.rules.contains(&rule) {
            let op = format!("add {}", describe_rule(&rule));
            pass.op(&op, nl.rule_add(&rule).await, NetlinkError::is_exist);
        }
    }
    for rule in &observed.rules {
        if rule.protocol != RTPROT_OPENFEO || wanted.contains(rule) {
            continue;
        }
        let op = format!("del {}", describe_rule(rule));
        pass.op(&op, nl.rule_del(rule).await, NetlinkError::is_absent);
    }
}

/// `default via 203.0.113.1 dev p0 proto 200 metric 10`, or `blackhole 192.0.2.248/29 proto 200
/// metric 1000`: the form the console shows.
fn describe(route: &Route, ifname: &str) -> String {
    let mut text = match route.kind {
        RouteKind::Unicast => String::new(),
        RouteKind::Blackhole => "blackhole ".to_owned(),
        RouteKind::Unreachable => "unreachable ".to_owned(),
    };
    text.push_str(
        &route
            .dst
            .map_or_else(|| "default".to_owned(), |dst| dst.to_string()),
    );
    if let Some(gateway) = route.gateway {
        let _ = write!(text, " via {gateway}");
    }
    if route.kind == RouteKind::Unicast {
        let _ = write!(text, " dev {ifname}");
    }
    if let Some(src) = route.pref_src {
        let _ = write!(text, " src {src}");
    }
    let _ = write!(text, " proto {} metric {}", route.protocol, route.priority);
    if route.table != openfeo_netlink::TABLE_MAIN {
        let _ = write!(text, " table {}", route.table);
    }
    text
}
