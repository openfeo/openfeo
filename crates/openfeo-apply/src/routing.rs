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
    DesiredRoute, DesiredRouting, DesiredRuleAction, Lifetimes, RouteKind as DesiredKind,
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

/// How far apart two deadlines may be before the kernel is told again (#27): the ISP's
/// advertisement and the monitor's event are seconds apart at most, never this much.
pub const LIFETIME_TOLERANCE_MS: u64 = 5_000;

/// Whether the kernel's lifetimes (`preferred`, `valid` deadlines; `None` forever) differ from
/// the desired ones enough to be set again: a different kind (forever against finite), or a
/// deadline moved by more than [`LIFETIME_TOLERANCE_MS`]; two deadlines already past are the
/// same deadline, since what the kernel did with them is done.
fn lifetimes_differ(desired: &Lifetimes, cached: (Option<u64>, Option<u64>), now_ms: u64) -> bool {
    let differs = |want: Option<u64>, have: Option<u64>| match (want, have) {
        (None, None) => false,
        (Some(want), Some(have)) => {
            !(want <= now_ms && have <= now_ms) && want.abs_diff(have) > LIFETIME_TOLERANCE_MS
        }
        _ => true,
    };
    differs(desired.preferred_until_ms, cached.0) || differs(desired.valid_until_ms, cached.1)
}

/// How close to its valid end a lifetimed address is left alone: the kernel drops it on its
/// own timer, up to a second before the deadline we hold, and it may not be added back with a
/// zero lifetime the kernel refuses; the client removes it from the fact a moment later.
pub const LAPSE_GRACE_MS: u64 = 1_000;

/// What to do about a desired address with lifetimes, given what the cache holds for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifetimeAction {
    /// Present with lifetimes near enough, or about to lapse: nothing.
    Leave,
    /// Absent: add it with its lifetimes.
    Add,
    /// Present with lifetimes that moved: set them again, quietly.
    Refresh,
}

fn lifetimed_action(
    desired: &Lifetimes,
    cached: Option<(Option<u64>, Option<u64>)>,
    now_ms: u64,
) -> LifetimeAction {
    if desired
        .valid_until_ms
        .is_some_and(|end| end <= now_ms.saturating_add(LAPSE_GRACE_MS))
    {
        return LifetimeAction::Leave;
    }
    match cached {
        None => LifetimeAction::Add,
        Some(cached) if lifetimes_differ(desired, cached, now_ms) => LifetimeAction::Refresh,
        Some(_) => LifetimeAction::Leave,
    }
}

/// What the kernel is told of a deadline: seconds from now, 0 once it has passed, `None`
/// forever.
fn seconds_from_now(deadline: Option<u64>, now_ms: u64) -> Option<u32> {
    deadline.map(|at| u32::try_from(at.saturating_sub(now_ms) / 1000).unwrap_or(u32::MAX))
}

/// Addresses: add the desired ones that are missing, delete the global-scope ones on managed
/// interfaces (IPv4) and on interfaces whose IPv6 the router owns that are not desired. An
/// address is its interface, its prefix and, on a point-to-point link, its peer: a new session's
/// address with a new peer is a new address, and the old one goes. An address with lifetimes is
/// added with them and set again when they move (#27).
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
            .find(|a| a.ifindex == index && a.net == addr.net && a.peer == addr.peer);
        if let Some(lifetimes) = &addr.lifetimes {
            let now_ms = openfeo_runtime::clock::uptime_ms();
            let action = lifetimed_action(
                lifetimes,
                present.map(|a| (a.preferred_until_ms, a.valid_until_ms)),
                now_ms,
            );
            if action == LifetimeAction::Leave {
                continue;
            }
            let preferred = seconds_from_now(lifetimes.preferred_until_ms, now_ms);
            let valid = seconds_from_now(lifetimes.valid_until_ms, now_ms);
            let lft =
                |secs: Option<u32>| secs.map_or_else(|| "forever".to_owned(), |s| s.to_string());
            let result = nl
                .addr_add_with_lifetimes(index, addr.net, preferred, valid)
                .await;
            let op = format!(
                "addr {} dev {} lifetimes {}/{}",
                addr.net,
                addr.ifname,
                lft(preferred),
                lft(valid)
            );
            if action == LifetimeAction::Add {
                pass.op(&format!("add {op}"), result, NetlinkError::is_exist);
            } else {
                // The ISP's refresh: not a change of the router's state, so no console line
                // and no converging op (which would re-announce `ready` at every advertisement).
                pass.quiet_op(&format!("set {op}"), result, NetlinkError::is_exist);
            }
            continue;
        }
        if present.is_some() {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Review of #27: an address whose valid lifetime is about to run out (or has) is left to
    /// the kernel and the client, never added with a zero lifetime the kernel refuses.
    #[test]
    fn a_lifetimed_address_about_to_lapse_is_left_alone() {
        let now = 50_000;
        let soon = Lifetimes {
            preferred_until_ms: Some(10_000),
            valid_until_ms: Some(now + 500),
        };
        assert_eq!(lifetimed_action(&soon, None, now), LifetimeAction::Leave);
        assert_eq!(
            lifetimed_action(&soon, Some((Some(10_000), Some(now + 500))), now),
            LifetimeAction::Leave
        );
        let past = Lifetimes {
            preferred_until_ms: Some(10_000),
            valid_until_ms: Some(now - 1),
        };
        assert_eq!(lifetimed_action(&past, None, now), LifetimeAction::Leave);
        let live = Lifetimes {
            preferred_until_ms: Some(100_000),
            valid_until_ms: Some(200_000),
        };
        assert_eq!(lifetimed_action(&live, None, now), LifetimeAction::Add);
        assert_eq!(
            lifetimed_action(&live, Some((Some(101_000), Some(200_000))), now),
            LifetimeAction::Leave
        );
        assert_eq!(
            lifetimed_action(&live, Some((Some(130_000), Some(200_000))), now),
            LifetimeAction::Refresh
        );
    }

    /// #27: a refresh that moves a deadline by more than the tolerance is sent; jitter is not;
    /// two deadlines already in the past are the same deadline; forever is its own value.
    #[test]
    fn lifetimes_differ_beyond_the_tolerance_or_in_kind() {
        let desired = Lifetimes {
            preferred_until_ms: Some(100_000),
            valid_until_ms: Some(200_000),
        };
        let now = 50_000;
        assert!(
            !lifetimes_differ(&desired, (Some(102_000), Some(199_000)), now),
            "jitter"
        );
        assert!(
            lifetimes_differ(&desired, (Some(110_000), Some(200_000)), now),
            "moved"
        );
        assert!(
            lifetimes_differ(&desired, (None, Some(200_000)), now),
            "forever vs finite"
        );
        assert!(
            lifetimes_differ(&desired, (Some(100_000), None), now),
            "finite vs forever"
        );
        let forever = Lifetimes {
            preferred_until_ms: None,
            valid_until_ms: None,
        };
        assert!(!lifetimes_differ(&forever, (None, None), now));
        let past = Lifetimes {
            preferred_until_ms: Some(10_000),
            valid_until_ms: Some(200_000),
        };
        assert!(
            !lifetimes_differ(&past, (Some(40_000), Some(200_000)), now),
            "both preferred deadlines have passed: deprecated is deprecated"
        );
        assert!(
            lifetimes_differ(&past, (Some(60_000), Some(200_000)), now),
            "one still ahead"
        );
    }
}
