// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The routing applier: addresses on managed interfaces and routes with `RTPROT_OPENFEO`. Adds
//! what is missing; deletes global-scope addresses on managed interfaces and protocol-200 routes
//! that are no longer desired; touches nothing else (link-local addresses, connected routes,
//! anything on other interfaces, routes with other protocols).

use std::collections::BTreeSet;
use std::fmt::Write as _;

use ipnet::IpNet;
use openfeo_netlink::{Cache, Netlink, RTPROT_OPENFEO, Route, SCOPE_UNIVERSE};
use openfeo_reconcile::routing::DesiredRouting;
use tracing::info;

use crate::{ApplyError, Report, is_managed, resolve};

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
    /// [`ApplyError::Netlink`] when the kernel refuses an operation, [`ApplyError::Unresolvable`]
    /// when a desired interface does not exist yet.
    pub async fn apply(
        &mut self,
        desired: &DesiredRouting,
        observed: &Cache,
        nl: &Netlink,
    ) -> Result<Report, ApplyError> {
        let mut ops = 0;

        let mut wanted_addrs: BTreeSet<(u32, IpNet)> = BTreeSet::new();
        for addr in &desired.addrs {
            let index = resolve(observed, nl, &addr.ifname).await?;
            wanted_addrs.insert((index, addr.net));
            let present = observed
                .addrs
                .iter()
                .any(|a| a.ifindex == index && a.net == addr.net);
            if !present {
                match nl.addr_add(index, addr.net).await {
                    Ok(()) => {}
                    Err(err) if err.is_exist() => {}
                    Err(err) => {
                        return Err(ApplyError::netlink(
                            format!("add addr {} dev {}", addr.net, addr.ifname),
                            err,
                        ));
                    }
                }
                info!("add addr {} dev {}", addr.net, addr.ifname);
                ops += 1;
            }
        }
        for addr in &observed.addrs {
            let Some(link) = observed.links.get(&addr.ifindex) else {
                continue;
            };
            if !is_managed(&link.name)
                || addr.scope != SCOPE_UNIVERSE
                || wanted_addrs.contains(&(addr.ifindex, addr.net))
            {
                continue;
            }
            match nl.addr_del(addr.ifindex, addr.net).await {
                Ok(()) => {}
                Err(err) if err.is_absent() => {}
                Err(err) => {
                    return Err(ApplyError::netlink(
                        format!("del addr {} dev {}", addr.net, link.name),
                        err,
                    ));
                }
            }
            info!("del addr {} dev {}", addr.net, link.name);
            ops += 1;
        }

        let mut wanted_routes: BTreeSet<Route> = BTreeSet::new();
        for desired_route in &desired.routes {
            let oif = resolve(observed, nl, &desired_route.ifname).await?;
            let route = Route {
                v6: desired_route.gateway.map_or_else(
                    || matches!(desired_route.dst, Some(IpNet::V6(_))),
                    |gateway| gateway.is_ipv6(),
                ),
                table: desired_route.table,
                dst: desired_route.dst,
                gateway: desired_route.gateway,
                oif: Some(oif),
                protocol: desired_route.protocol,
                priority: desired_route.priority,
            };
            let text = describe(&route, &desired_route.ifname);
            wanted_routes.insert(route.clone());
            if !observed.routes.contains(&route) {
                match nl.route_add(&route).await {
                    Ok(()) => {}
                    Err(err) if err.is_exist() => {}
                    Err(err) => return Err(ApplyError::netlink(format!("add route {text}"), err)),
                }
                info!("add route {text}");
                ops += 1;
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
            let text = describe(route, ifname);
            match nl.route_del(route).await {
                Ok(()) => {}
                Err(err) if err.is_absent() => {}
                Err(err) => return Err(ApplyError::netlink(format!("del route {text}"), err)),
            }
            info!("del route {text}");
            ops += 1;
        }

        Ok(Report { ops })
    }
}

/// `default via 203.0.113.1 dev p0 proto 200 metric 10`, the form the console shows.
fn describe(route: &Route, ifname: &str) -> String {
    let mut text = route
        .dst
        .map_or_else(|| "default".to_owned(), |dst| dst.to_string());
    if let Some(gateway) = route.gateway {
        let _ = write!(text, " via {gateway}");
    }
    let _ = write!(
        text,
        " dev {ifname} proto {} metric {}",
        route.protocol, route.priority
    );
    if route.table != openfeo_netlink::TABLE_MAIN {
        let _ = write!(text, " table {}", route.table);
    }
    text
}
