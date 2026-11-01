// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired addresses and routes (SPEC §7.2 Static, §7.4): a LAN's address on its bridge, a static
//! WAN's address on its port and a default route via its gateway in the main table, tagged with
//! `RTPROT_OPENFEO` and carrying the WAN's priority as metric.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};
use openfeo_config::wan;
use openfeo_world::World;
use serde::Serialize;

use crate::{RTPROT_OPENFEO, TABLE_MAIN, bridge_name};

/// One address on one interface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DesiredAddr {
    /// Kernel interface name.
    pub ifname: String,
    /// Address and prefix.
    pub net: IpNet,
}

/// One route OpenFeO owns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DesiredRoute {
    /// Output interface.
    pub ifname: String,
    /// Destination; `None` is the default route.
    pub dst: Option<IpNet>,
    /// Next hop.
    pub gateway: Option<IpAddr>,
    /// Routing table ([`TABLE_MAIN`] until M6's per-WAN tables).
    pub table: u32,
    /// Always [`RTPROT_OPENFEO`].
    pub protocol: u8,
    /// Metric: the WAN's priority.
    pub priority: u32,
}

/// Everything the routing applier makes true.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DesiredRouting {
    /// Addresses.
    pub addrs: BTreeSet<DesiredAddr>,
    /// Routes.
    pub routes: BTreeSet<DesiredRoute>,
}

/// The addresses and routes the World calls for. A WAN whose port the map does not know, or
/// whose text does not parse, contributes nothing (validation already rejected it).
#[must_use]
pub fn routing(world: &World) -> DesiredRouting {
    let mut desired = DesiredRouting::default();
    for lan in &world.config.lans {
        if let Ok(net) = lan.ipv4.parse::<IpNet>() {
            desired.addrs.insert(DesiredAddr {
                ifname: bridge_name(&lan.name),
                net,
            });
        }
    }
    for wan_config in &world.config.wans {
        if world.ports.id_of(&wan_config.port).is_none() {
            continue;
        }
        let ifname = crate::wan_ifname(wan_config);
        let route = |dst: Option<IpNet>, gateway: IpAddr| DesiredRoute {
            ifname: ifname.clone(),
            dst,
            gateway: Some(gateway),
            table: TABLE_MAIN,
            protocol: RTPROT_OPENFEO,
            priority: wan_config.priority,
        };
        match &wan_config.kind {
            Some(wan::Kind::Static(static_wan)) => {
                if let Ok(net) = static_wan.address.parse::<IpNet>() {
                    desired.addrs.insert(DesiredAddr {
                        ifname: ifname.clone(),
                        net,
                    });
                }
                if let Ok(gateway) = static_wan.gateway.parse::<IpAddr>() {
                    desired.routes.insert(route(None, gateway));
                }
            }
            Some(wan::Kind::Dhcp(_)) => {
                let Some(lease) = world.dhcp4.get(&wan_config.name) else {
                    continue;
                };
                desired.addrs.insert(DesiredAddr {
                    ifname: ifname.clone(),
                    net: IpNet::V4(lease.address),
                });
                // RFC 3442: classless routes replace the router option, and `0.0.0.0/0` among
                // them is the default route. A gateway outside the leased subnet (a /32 lease,
                // say) first gets a host route on the port, or the kernel refuses the route
                // through it.
                let wanted: Vec<(Option<IpNet>, Ipv4Addr)> = if lease.routes.is_empty() {
                    lease
                        .gateway
                        .map(|gateway| (None, gateway))
                        .into_iter()
                        .collect()
                } else {
                    lease
                        .routes
                        .iter()
                        .map(|(dst, via)| ((dst.prefix_len() > 0).then_some(IpNet::V4(*dst)), *via))
                        .collect()
                };
                for (dst, via) in wanted {
                    if !lease.address.contains(&via) {
                        desired.routes.insert(DesiredRoute {
                            ifname: ifname.clone(),
                            dst: Some(IpNet::V4(Ipv4Net::from(via))),
                            gateway: None,
                            table: TABLE_MAIN,
                            protocol: RTPROT_OPENFEO,
                            priority: wan_config.priority,
                        });
                    }
                    desired.routes.insert(route(dst, IpAddr::V4(via)));
                }
            }
            None => {}
        }
    }
    desired
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn static_wan_and_one_lan_routing() {
        let desired = routing(&fixtures::static_world());
        let addrs: Vec<String> = desired
            .addrs
            .iter()
            .map(|a| format!("{} {}", a.ifname, a.net))
            .collect();
        assert_eq!(addrs, ["br-lan0 192.168.1.1/24", "p0 203.0.113.10/24"]);
        assert_eq!(desired.routes.len(), 1);
        let route = desired.routes.iter().next().unwrap();
        assert_eq!(route.ifname, "p0");
        assert_eq!(route.dst, None);
        assert_eq!(
            route.gateway.map(|g| g.to_string()),
            Some("203.0.113.1".to_owned())
        );
        assert_eq!(route.table, TABLE_MAIN);
        assert_eq!(route.protocol, RTPROT_OPENFEO);
        assert_eq!(route.priority, 10);
        insta::assert_yaml_snapshot!(desired);
    }

    fn routes_of(desired: &DesiredRouting) -> Vec<String> {
        desired
            .routes
            .iter()
            .map(|r| {
                format!(
                    "{} via {} dev {} proto {} metric {}",
                    r.dst
                        .map_or_else(|| "default".to_owned(), |d| d.to_string()),
                    r.gateway.map_or_else(|| "-".to_owned(), |g| g.to_string()),
                    r.ifname,
                    r.protocol,
                    r.priority
                )
            })
            .collect()
    }

    #[test]
    fn dhcp_wan_with_a_lease_gets_address_and_classless_routes() {
        let desired = routing(&fixtures::dhcp_world());
        let addrs: Vec<String> = desired
            .addrs
            .iter()
            .map(|a| format!("{} {}", a.ifname, a.net))
            .collect();
        assert_eq!(addrs, ["br-lan0 192.168.1.1/24", "p0 203.0.113.100/24"]);
        assert_eq!(
            routes_of(&desired),
            [
                "default via 203.0.113.1 dev p0 proto 200 metric 10",
                "198.51.100.0/24 via 203.0.113.1 dev p0 proto 200 metric 10",
            ]
        );
        insta::assert_yaml_snapshot!(desired);
    }

    #[test]
    fn classless_routes_replace_the_router_option() {
        let mut world = fixtures::dhcp_world();
        let mut fact = fixtures::dhcp_fact();
        fact.gateway = Some("203.0.113.9".parse().unwrap());
        world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let desired = routing(&world);
        assert_eq!(
            routes_of(&desired),
            [
                "default via 203.0.113.1 dev p0 proto 200 metric 10",
                "198.51.100.0/24 via 203.0.113.1 dev p0 proto 200 metric 10",
            ],
            "nothing via the ignored router option"
        );
    }

    #[test]
    fn dhcp_wan_with_gateway_only_gets_a_default_route() {
        let mut world = fixtures::dhcp_world();
        let mut fact = fixtures::dhcp_fact();
        fact.routes.clear();
        fact.gateway = Some("203.0.113.1".parse().unwrap());
        world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let desired = routing(&world);
        assert_eq!(
            routes_of(&desired),
            ["default via 203.0.113.1 dev p0 proto 200 metric 10"]
        );
        assert!(
            desired
                .addrs
                .iter()
                .any(|a| a.ifname == "p0" && a.net.to_string() == "203.0.113.100/24")
        );
    }

    #[test]
    fn dhcp_wan_without_a_lease_contributes_nothing() {
        let desired = routing(&fixtures::dhcp_world_without_lease());
        let addrs: Vec<String> = desired.addrs.iter().map(|a| a.ifname.clone()).collect();
        assert_eq!(addrs, ["br-lan0"]);
        assert_eq!(desired.routes, BTreeSet::new());
    }

    #[test]
    fn prefix_only_classless_routes_invent_no_default() {
        let mut world = fixtures::dhcp_world();
        let mut fact = fixtures::dhcp_fact();
        fact.routes.retain(|(dst, _)| dst.prefix_len() > 0);
        fact.gateway = Some("203.0.113.9".parse().unwrap());
        world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        assert_eq!(
            routes_of(&routing(&world)),
            ["198.51.100.0/24 via 203.0.113.1 dev p0 proto 200 metric 10"]
        );
    }

    #[test]
    fn off_link_gateway_gets_a_host_route_first() {
        let mut world = fixtures::dhcp_world();
        let mut fact = fixtures::dhcp_fact();
        fact.address = "203.0.113.100/32".parse().unwrap();
        fact.routes.clear();
        fact.gateway = Some("203.0.113.1".parse().unwrap());
        world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        assert_eq!(
            routes_of(&routing(&world)),
            [
                "default via 203.0.113.1 dev p0 proto 200 metric 10",
                "203.0.113.1/32 via - dev p0 proto 200 metric 10",
            ]
        );
        let mut fact = fixtures::dhcp_fact();
        fact.address = "203.0.113.100/32".parse().unwrap();
        world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let routes = routes_of(&routing(&world));
        assert!(
            routes.contains(&"203.0.113.1/32 via - dev p0 proto 200 metric 10".to_owned()),
            "{routes:?}"
        );
        assert_eq!(routes.len(), 3, "one host route for both classless routes");
    }

    #[test]
    fn first_boot_routing_has_only_the_lan_address() {
        let desired = routing(&fixtures::first_boot_world());
        assert_eq!(desired.addrs.len(), 1);
        assert_eq!(desired.addrs.iter().next().unwrap().ifname, "br-lan0");
        assert_eq!(desired.routes, BTreeSet::new());
        insta::assert_yaml_snapshot!(desired);
    }
}
