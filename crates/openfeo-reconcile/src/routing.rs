// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired addresses and routes (SPEC §7.2 Static, §7.4): a LAN's address on its bridge, a static
//! WAN's address on its port and a default route via its gateway in the main table, tagged with
//! `RTPROT_OPENFEO` and carrying the WAN's priority as metric; a blackhole per declared public
//! block, so an address nobody answers for is dropped here and never sent back to the ISP.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use openfeo_config::{Ipv6Wan, Wan, wan};
use openfeo_world::World;
use serde::Serialize;

use crate::public::{self, BLOCK_METRIC};
use crate::{RTPROT_OPENFEO, TABLE_MAIN, bridge_name};

/// One address on one interface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DesiredAddr {
    /// Kernel interface name.
    pub ifname: String,
    /// Address and prefix.
    pub net: IpNet,
}

/// A route's type: unicast, or a blackhole for a declared public block (SPEC §7.4). Mirrors
/// `openfeo_netlink::RouteKind`, which this pure crate may not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum RouteKind {
    /// Through an interface, with or without a gateway.
    Unicast,
    /// Dropped silently; no interface.
    Blackhole,
}

/// One route OpenFeO owns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DesiredRoute {
    /// Output interface; `None` for a blackhole.
    pub ifname: Option<String>,
    /// Destination; `None` is the default route.
    pub dst: Option<IpNet>,
    /// Next hop.
    pub gateway: Option<IpAddr>,
    /// Routing table ([`TABLE_MAIN`] until M6's per-WAN tables).
    pub table: u32,
    /// Always [`RTPROT_OPENFEO`].
    pub protocol: u8,
    /// Metric: the WAN's priority, or [`BLOCK_METRIC`] for a blackhole.
    pub priority: u32,
    /// Unicast or blackhole.
    pub kind: RouteKind,
    /// The source address for the router's own traffic over the route: its loopback address
    /// on the IPv6 default (SPEC §7.4).
    pub pref_src: Option<IpAddr>,
}

/// Everything the routing applier makes true.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DesiredRouting {
    /// Addresses.
    pub addrs: BTreeSet<DesiredAddr>,
    /// Routes.
    pub routes: BTreeSet<DesiredRoute>,
    /// Interfaces whose global IPv6 addresses the router owns: `lo` always (nothing else puts a
    /// global address there), and once a WAN carries IPv6 that WAN's port and every LAN bridge.
    /// A global address there that nothing wants is removed, so a LAN that loses its `ipv6`
    /// loses the address and a box that drops `[wans.ipv6]` loses its loopback address. Any
    /// other interface's IPv6 is left to the kernel (SPEC §7.3).
    pub ipv6_owned: BTreeSet<String>,
}

/// `::1` of the routed prefix's first /64: the router's own IPv6 address (SPEC §7.3).
#[must_use]
pub fn router_address(prefix: Ipv6Net) -> Ipv6Addr {
    let mut segments = prefix.network().segments();
    segments[7] = 1;
    Ipv6Addr::from(segments)
}

fn is_link_local(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// The addresses and routes the World calls for. A WAN whose port the map does not know, or
/// whose text does not parse, contributes nothing (validation already rejected it).
#[must_use]
pub fn routing(world: &World) -> DesiredRouting {
    let mut desired = DesiredRouting::default();
    lan_addresses(world, &mut desired);
    for wan_config in &world.config.wans {
        if world.ports.id_of(&wan_config.port).is_none() {
            continue;
        }
        let ifname = crate::wan_ifname(wan_config);
        let route = |dst: Option<IpNet>, gateway: IpAddr| DesiredRoute {
            ifname: Some(ifname.clone()),
            dst,
            gateway: Some(gateway),
            table: TABLE_MAIN,
            protocol: RTPROT_OPENFEO,
            priority: wan_config.priority,
            kind: RouteKind::Unicast,
            pref_src: None,
        };
        if let Some(ipv6) = &wan_config.ipv6
            && ipv6.mode != "disabled"
        {
            ipv6_routing(world, wan_config, ipv6, &ifname, &mut desired);
        }
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
                            ifname: Some(ifname.clone()),
                            dst: Some(IpNet::V4(Ipv4Net::from(via))),
                            gateway: None,
                            table: TABLE_MAIN,
                            protocol: RTPROT_OPENFEO,
                            priority: wan_config.priority,
                            kind: RouteKind::Unicast,
                            pref_src: None,
                        });
                    }
                    desired.routes.insert(route(dst, IpAddr::V4(via)));
                }
            }
            None => {}
        }
    }
    for block in public::blocks(&world.config) {
        desired.routes.insert(DesiredRoute {
            ifname: None,
            dst: Some(IpNet::V4(block)),
            gateway: None,
            table: TABLE_MAIN,
            protocol: RTPROT_OPENFEO,
            priority: BLOCK_METRIC,
            kind: RouteKind::Blackhole,
            pref_src: None,
        });
    }
    desired
}

/// Every LAN's address on its bridge, both families; and the interfaces whose global IPv6
/// addresses the router owns (`lo` always, every bridge once a WAN carries IPv6; the WAN's
/// port joins in [`ipv6_routing`]).
fn lan_addresses(world: &World, desired: &mut DesiredRouting) {
    for lan in &world.config.lans {
        if let Ok(net) = lan.ipv4.parse::<IpNet>() {
            desired.addrs.insert(DesiredAddr {
                ifname: bridge_name(&lan.name),
                net,
            });
        }
        if let Ok(net) = lan.ipv6.parse::<Ipv6Net>() {
            desired.addrs.insert(DesiredAddr {
                ifname: bridge_name(&lan.name),
                net: IpNet::V6(net),
            });
        }
    }
    let ipv6_wan = world.config.wans.iter().any(|wan| {
        world.ports.id_of(&wan.port).is_some()
            && wan
                .ipv6
                .as_ref()
                .is_some_and(|ipv6| ipv6.mode != "disabled")
    });
    desired.ipv6_owned.insert("lo".to_owned());
    if ipv6_wan {
        desired
            .ipv6_owned
            .extend(world.config.lans.iter().map(|lan| bridge_name(&lan.name)));
    }
}
/// The IPv6 side of one WAN (SPEC §7.3, §7.4): what the advertisement client learned lands on
/// the WAN port (addresses, on-link prefixes, route information); the default goes via the typed
/// gateway or the advertised router with the router's loopback address as preferred source (a
/// typed global gateway on no on-link prefix first gets a host route, as IPv4 does); and a
/// routed prefix gives the loopback address and the blackhole.
fn ipv6_routing(
    world: &World,
    wan_config: &Wan,
    ipv6: &Ipv6Wan,
    ifname: &str,
    desired: &mut DesiredRouting,
) {
    desired.ipv6_owned.insert(ifname.to_owned());
    let fact = world.ipv6.get(&wan_config.name);
    let prefix = ipv6.prefix.parse::<Ipv6Net>().ok().map(|p| p.trunc());
    let loopback = prefix.map(router_address);
    let route =
        |dst: Option<Ipv6Net>, gateway: Option<Ipv6Addr>, src: Option<Ipv6Addr>| DesiredRoute {
            ifname: Some(ifname.to_owned()),
            dst: dst.map(IpNet::V6),
            gateway: gateway.map(IpAddr::V6),
            table: TABLE_MAIN,
            protocol: RTPROT_OPENFEO,
            priority: wan_config.priority,
            kind: RouteKind::Unicast,
            pref_src: src.map(IpAddr::V6),
        };
    if let Some(fact) = fact {
        for addr in &fact.addresses {
            desired.addrs.insert(DesiredAddr {
                ifname: ifname.to_owned(),
                net: IpNet::V6(*addr),
            });
        }
        for on_link in &fact.on_link {
            desired.routes.insert(route(Some(*on_link), None, None));
        }
        for (dst, via, _) in &fact.routes {
            desired.routes.insert(route(Some(*dst), Some(*via), None));
        }
    }
    let typed = ipv6.gateway.parse::<Ipv6Addr>().ok();
    if let Some(via) = typed.or(fact.and_then(|f| f.router)) {
        let on_link = is_link_local(via)
            || fact.is_some_and(|f| {
                f.on_link
                    .iter()
                    .chain(&f.addresses)
                    .any(|net| net.contains(&via))
            });
        if !on_link {
            desired
                .routes
                .insert(route(Some(Ipv6Net::new_assert(via, 128)), None, None));
        }
        desired.routes.insert(route(None, Some(via), loopback));
    }
    if let (Some(prefix), Some(loopback)) = (prefix, loopback) {
        desired.addrs.insert(DesiredAddr {
            ifname: "lo".to_owned(),
            net: IpNet::V6(Ipv6Net::new_assert(loopback, 128)),
        });
        desired.routes.insert(DesiredRoute {
            ifname: None,
            dst: Some(IpNet::V6(prefix)),
            gateway: None,
            table: TABLE_MAIN,
            protocol: RTPROT_OPENFEO,
            priority: BLOCK_METRIC,
            kind: RouteKind::Blackhole,
            pref_src: None,
        });
    }
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
        assert_eq!(route.ifname.as_deref(), Some("p0"));
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

    #[test]
    fn every_declared_block_gets_a_blackhole_and_the_dmz_gets_its_address() {
        let desired = routing(&fixtures::public_world());
        let blackholes: Vec<&DesiredRoute> = desired
            .routes
            .iter()
            .filter(|r| r.kind == RouteKind::Blackhole)
            .collect();
        assert_eq!(
            blackholes
                .iter()
                .map(|r| r.dst.unwrap().to_string())
                .collect::<Vec<_>>(),
            ["192.0.2.232/29", "192.0.2.248/29"]
        );
        assert!(blackholes.iter().all(|r| r.ifname.is_none()
            && r.gateway.is_none()
            && r.priority == crate::public::BLOCK_METRIC
            && r.table == TABLE_MAIN
            && r.protocol == RTPROT_OPENFEO));
        assert!(
            desired
                .addrs
                .iter()
                .any(|a| a.ifname == "br-dmz" && a.net.to_string() == "192.0.2.233/29")
        );
        assert_eq!(
            desired
                .routes
                .iter()
                .filter(|r| r.kind == RouteKind::Unicast)
                .count(),
            1,
            "the WAN default is the only unicast route"
        );
        insta::assert_yaml_snapshot!(desired);
    }

    fn routes_of(desired: &DesiredRouting) -> Vec<String> {
        desired
            .routes
            .iter()
            .map(|r| {
                let mut line = format!(
                    "{} via {} dev {} proto {} metric {}",
                    r.dst
                        .map_or_else(|| "default".to_owned(), |d| d.to_string()),
                    r.gateway.map_or_else(|| "-".to_owned(), |g| g.to_string()),
                    r.ifname.as_deref().unwrap_or("-"),
                    r.protocol,
                    r.priority
                );
                if let Some(src) = r.pref_src {
                    use std::fmt::Write as _;
                    let _ = write!(line, " src {src}");
                }
                line
            })
            .collect()
    }

    fn addrs_of(desired: &DesiredRouting) -> Vec<String> {
        desired
            .addrs
            .iter()
            .map(|a| format!("{} {}", a.ifname, a.net))
            .collect()
    }

    #[test]
    fn ipv6_world_routes_default_via_the_learned_router_with_the_loopback_as_source() {
        let desired = routing(&fixtures::ipv6_world());
        let routes = routes_of(&desired);
        assert!(
            routes.contains(
                &"default via fe80::1 dev p0 proto 200 metric 10 src 2001:db8:1::1".to_owned()
            ),
            "{routes:?}"
        );
        assert!(
            routes.contains(&"2001:db8:1::/48 via - dev - proto 200 metric 1000".to_owned()),
            "the routed prefix is blackholed: {routes:?}"
        );
        let addrs = addrs_of(&desired);
        for addr in [
            "lo 2001:db8:1::1/128",
            "br-lan0 2001:db8:1:222::1/64",
            "br-dmz 2001:db8:1:232::1/64",
            "p0 203.0.113.10/24",
        ] {
            assert!(addrs.contains(&addr.to_owned()), "{addr} in {addrs:?}");
        }
        insta::assert_yaml_snapshot!(desired);
    }

    #[test]
    fn a_typed_gateway_replaces_the_learned_router_and_an_off_link_one_gets_a_host_route() {
        let mut world = fixtures::ipv6_world();
        let mut config = (*world.config).clone();
        config.wans[0].ipv6.as_mut().unwrap().gateway = "fe80::9".to_owned();
        world.config = Arc::new(config.clone());
        let routes = routes_of(&routing(&world));
        assert!(
            routes
                .iter()
                .any(|r| r.starts_with("default via fe80::9 dev p0")),
            "{routes:?}"
        );
        assert!(
            !routes.iter().any(|r| r.contains("via fe80::1 ")),
            "the learned router is not used: {routes:?}"
        );

        config.wans[0].ipv6.as_mut().unwrap().gateway = "2001:db8:ffff::1".to_owned();
        world.config = Arc::new(config.clone());
        let routes = routes_of(&routing(&world));
        assert!(
            routes.contains(&"2001:db8:ffff::1/128 via - dev p0 proto 200 metric 10".to_owned()),
            "{routes:?}"
        );
        assert!(
            routes
                .iter()
                .any(|r| r.starts_with("default via 2001:db8:ffff::1 dev p0")),
            "{routes:?}"
        );

        let mut fact = fixtures::ipv6_fact();
        fact.on_link = vec!["2001:db8:ffff::/64".parse().unwrap()];
        world.ipv6 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let routes = routes_of(&routing(&world));
        assert!(
            !routes.iter().any(|r| r.starts_with("2001:db8:ffff::1/128")),
            "on-link: no host route in {routes:?}"
        );
        assert!(
            routes.contains(&"2001:db8:ffff::/64 via - dev p0 proto 200 metric 10".to_owned()),
            "{routes:?}"
        );
    }

    #[test]
    fn without_a_router_fact_there_is_no_ipv6_default_but_the_prefix_is_still_blackholed() {
        let mut world = fixtures::ipv6_world();
        let mut fact = fixtures::ipv6_fact();
        fact.router = None;
        world.ipv6 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let desired = routing(&world);
        let routes = routes_of(&desired);
        assert!(
            !routes
                .iter()
                .any(|r| r.starts_with("default via fe80::") || r.starts_with("default via 2001:")),
            "{routes:?}"
        );
        assert!(routes.contains(&"2001:db8:1::/48 via - dev - proto 200 metric 1000".to_owned()));
        assert!(addrs_of(&desired).contains(&"lo 2001:db8:1::1/128".to_owned()));
        world.ipv6 = Arc::new(BTreeMap::new());
        let routes = routes_of(&routing(&world));
        assert!(
            !routes.iter().any(|r| r.starts_with("default via fe80::")),
            "no fact at all: {routes:?}"
        );
    }

    #[test]
    fn without_a_prefix_the_default_has_no_preferred_source_and_lo_gets_nothing() {
        let mut world = fixtures::ipv6_world();
        let mut config = (*world.config).clone();
        config.wans[0].ipv6.as_mut().unwrap().prefix = String::new();
        for lan in &mut config.lans {
            lan.ipv6 = String::new();
            lan.ra = None;
        }
        world.config = Arc::new(config);
        let desired = routing(&world);
        let routes = routes_of(&desired);
        assert!(
            routes.contains(&"default via fe80::1 dev p0 proto 200 metric 10".to_owned()),
            "{routes:?}"
        );
        assert!(
            !routes.iter().any(|r| r.contains("2001:db8:1::/48")),
            "no blackhole: {routes:?}"
        );
        assert!(
            addrs_of(&desired).iter().all(|a| !a.starts_with("lo ")),
            "{:?}",
            addrs_of(&desired)
        );
    }

    #[test]
    fn the_wan_facts_addresses_on_link_prefixes_and_routes_land_on_the_wan() {
        let mut world = fixtures::ipv6_world();
        let mut fact = fixtures::ipv6_fact();
        fact.addresses = vec!["2001:db8:ffff:0:1234:5678:9abc:def0/64".parse().unwrap()];
        fact.on_link = vec!["2001:db8:ffff::/64".parse().unwrap()];
        fact.routes = vec![(
            "2001:db8:2::/48".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            openfeo_world::Preference::High,
        )];
        world.ipv6 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let desired = routing(&world);
        assert!(
            addrs_of(&desired).contains(&"p0 2001:db8:ffff:0:1234:5678:9abc:def0/64".to_owned())
        );
        let routes = routes_of(&desired);
        assert!(
            routes.contains(&"2001:db8:ffff::/64 via - dev p0 proto 200 metric 10".to_owned()),
            "{routes:?}"
        );
        assert!(
            routes.contains(&"2001:db8:2::/48 via fe80::1 dev p0 proto 200 metric 10".to_owned()),
            "{routes:?}"
        );
    }

    #[test]
    fn an_ipv4_only_world_changes_nothing() {
        for world in [
            fixtures::static_world(),
            fixtures::dhcp_world(),
            fixtures::public_world(),
        ] {
            let desired = routing(&world);
            assert!(
                desired.addrs.iter().all(|a| a.net.addr().is_ipv4()),
                "{:?}",
                addrs_of(&desired)
            );
            assert!(
                desired.routes.iter().all(|r| r.pref_src.is_none()
                    && r.gateway.is_none_or(|g| g.is_ipv4())
                    && r.dst.is_none_or(|d| d.addr().is_ipv4())),
                "{:?}",
                routes_of(&desired)
            );
        }
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
