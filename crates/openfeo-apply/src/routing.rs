// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The routing applier: addresses on managed interfaces and routes with `RTPROT_OPENFEO`. Adds
//! what is missing; deletes IPv4 global-scope addresses on managed interfaces and protocol-200
//! routes that are no longer desired; touches nothing else (IPv6 addresses, whose ownership M2
//! defines and which the kernel autoconfigures from router advertisements; link-local addresses;
//! connected routes; anything on other interfaces; routes with other protocols). A pass is
//! best-effort: a refused operation or a missing interface is reported at the end, after
//! everything else was attempted.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use ipnet::IpNet;
use openfeo_netlink::{
    Cache, Error as NetlinkError, Netlink, RTPROT_OPENFEO, Route, RouteKind, SCOPE_UNIVERSE,
};
use openfeo_reconcile::routing::{DesiredRoute, DesiredRouting, RouteKind as DesiredKind};

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

        let mut wanted_addrs: BTreeSet<(u32, IpNet)> = BTreeSet::new();
        for addr in &desired.addrs {
            let index = match resolve(observed, nl, &addr.ifname).await {
                Ok(index) => index,
                Err(err) => {
                    pass.fail(err);
                    continue;
                }
            };
            wanted_addrs.insert((index, addr.net));
            let present = observed
                .addrs
                .iter()
                .any(|a| a.ifindex == index && a.net == addr.net);
            if !present {
                let op = format!("add addr {} dev {}", addr.net, addr.ifname);
                pass.op(
                    &op,
                    nl.addr_add(index, addr.net).await,
                    NetlinkError::is_exist,
                );
            }
        }
        for addr in &observed.addrs {
            let Some(link) = observed.links.get(&addr.ifindex) else {
                continue;
            };
            if !matches!(addr.net, IpNet::V4(_))
                || !is_managed(&link.name)
                || addr.scope != SCOPE_UNIVERSE
                || wanted_addrs.contains(&(addr.ifindex, addr.net))
            {
                continue;
            }
            let op = format!("del addr {} dev {}", addr.net, link.name);
            pass.op(
                &op,
                nl.addr_del(addr.ifindex, addr.net).await,
                NetlinkError::is_absent,
            );
        }

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
                },
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

        pass.finish()
    }
}

/// `default via 203.0.113.1 dev p0 proto 200 metric 10`, or `blackhole 192.0.2.248/29 proto 200
/// metric 1000`: the form the console shows.
fn describe(route: &Route, ifname: &str) -> String {
    let mut text = match route.kind {
        RouteKind::Unicast => String::new(),
        RouteKind::Blackhole => "blackhole ".to_owned(),
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
    let _ = write!(text, " proto {} metric {}", route.protocol, route.priority);
    if route.table != openfeo_netlink::TABLE_MAIN {
        let _ = write!(text, " table {}", route.table);
    }
    text
}
