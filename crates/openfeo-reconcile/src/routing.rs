// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired addresses, routes and policy rules (SPEC §7.2 Static, §7.3, §7.4): a LAN's addresses
//! on its bridge (IPv4, and every IPv6 /64 `lan6` says it carries), a static WAN's address on
//! its port and a default route via its gateway in the main table, tagged with `RTPROT_OPENFEO`
//! and carrying the WAN's priority as metric; a blackhole per declared public block and per
//! routed or delegated IPv6 prefix, so an address nobody answers for is dropped here and never
//! sent back to the ISP; the IPv6 WAN's own table with its default (or an unreachable one while
//! it has none), the `suppress_prefixlength` main lookup, a source rule per delegated prefix
//! into that table and an `unreachable` rule per deprecated prefix.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use openfeo_config::rules::{self, is_global_unicast_v6};
use openfeo_config::{Ipv6Wan, Wan, wan};
use openfeo_world::World;
use serde::Serialize;

use crate::lan6::{self, Lan6};
use crate::public::{self, BLOCK_METRIC};
use crate::{RTPROT_OPENFEO, TABLE_MAIN, bridge_name};

/// The policy rule that looks `main` up but suppresses a default found there (SPEC §7.4).
/// Mirrors `openfeo_netlink::RULE_PRIORITY_MAIN_SUPPRESS`.
pub const RULE_PRIORITY_MAIN_SUPPRESS: u32 = 1500;
/// The IPv6 source-prefix rules. Mirrors `openfeo_netlink::RULE_PRIORITY_SOURCE`.
pub const RULE_PRIORITY_SOURCE: u32 = 2000;

/// The routing table of the WAN at `index` in the configuration (SPEC §7.4): `100 + index`.
#[must_use]
pub fn wan_table(index: usize) -> u32 {
    100 + u32::try_from(index).unwrap_or(0)
}

/// One address on one interface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DesiredAddr {
    /// Kernel interface name.
    pub ifname: String,
    /// Address and prefix.
    pub net: IpNet,
    /// The far end of a point-to-point link (a PPP netdev's peer), `IFA_ADDRESS` to the kernel.
    pub peer: Option<IpAddr>,
}

/// A route's type: unicast, or a blackhole for a declared public block (SPEC §7.4). Mirrors
/// `openfeo_netlink::RouteKind`, which this pure crate may not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum RouteKind {
    /// Through an interface, with or without a gateway.
    Unicast,
    /// Dropped silently; no interface.
    Blackhole,
    /// Dropped with an ICMP destination unreachable; no interface (a down WAN's default,
    /// SPEC §7.3).
    Unreachable,
}

/// What a policy rule does. Mirrors `openfeo_netlink::RuleAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum DesiredRuleAction {
    ToTable(u32),
    Unreachable,
}

/// One policy rule OpenFeO owns (SPEC §7.4); the applier gives it [`RTPROT_OPENFEO`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DesiredRule {
    pub v6: bool,
    pub priority: u32,
    /// `from <prefix>`; `None` is `from all`.
    pub src: Option<IpNet>,
    pub action: DesiredRuleAction,
    /// `suppress_prefixlength`.
    pub suppress_prefixlen: Option<u8>,
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
    /// Routing table: [`TABLE_MAIN`], or the IPv6 WAN's own ([`wan_table`]).
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
    /// Policy rules (IPv6 only until M6).
    pub rules: BTreeSet<DesiredRule>,
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

/// A learned prefix the router may act on: global unicast, not `::/0`, and overlapping neither
/// the routed prefix nor a LAN's /64. An ISP advertising the customer's prefix back, or a
/// neighbour on the WAN link, must not pull the router's own prefixes onto the WAN port, and a
/// `::/0` route information option (the default's preference, RFC 4191 §2.3) is not a route.
fn learned_prefix_is_usable(net: Ipv6Net, routed: Option<Ipv6Net>, lans: &[Ipv6Net]) -> bool {
    let net = net.trunc();
    let overlaps = |other: Ipv6Net| other.contains(&net) || net.contains(&other);
    net.prefix_len() > 0
        && is_global_unicast_v6(net)
        && !routed.is_some_and(overlaps)
        && !lans.iter().any(|lan| overlaps(*lan))
}

fn is_link_local(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// The addresses and routes the World calls for. A WAN whose port the map does not know, or
/// whose text does not parse, contributes nothing (validation already rejected it).
#[must_use]
pub fn routing(world: &World) -> DesiredRouting {
    let mut desired = DesiredRouting::default();
    let lan6 = lan6::prefixes(world);
    lan_addresses(world, &lan6, &mut desired);
    for (index, wan_config) in world.config.wans.iter().enumerate() {
        if world.ports.id_of(&wan_config.port).is_none() {
            continue;
        }
        let ifname = crate::wan_netdev(wan_config);
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
        // A PPP netdev exists only while its session does: until the kernel shows it, nothing
        // is desired for it (ADR-0023), or every pass would wait on a missing interface.
        let netdev_present = !rules::is_pppoe(wan_config) || world.links.contains_key(&ifname);
        if let Some(ipv6) = &wan_config.ipv6
            && ipv6.mode != "disabled"
            && netdev_present
        {
            ipv6_routing(world, wan_config, ipv6, &ifname, index, &lan6, &mut desired);
        }
        match &wan_config.kind {
            Some(wan::Kind::Pppoe(_)) => {
                if netdev_present {
                    pppoe_routing(world, wan_config, &ifname, &mut desired);
                }
            }
            Some(wan::Kind::Static(static_wan)) => {
                if let Ok(net) = static_wan.address.parse::<IpNet>() {
                    desired.addrs.insert(DesiredAddr {
                        ifname: ifname.clone(),
                        net,
                        peer: None,
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
                    peer: None,
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

/// Every LAN's address on its bridge: IPv4 from the configuration, IPv6 `::1/64` of every
/// prefix `lan6` says the LAN carries (routed, delegated, ULA, and deprecated for its two hours,
/// so the reverse-path check keeps a route back to hosts still using it); and the interfaces
/// whose global IPv6 addresses the router owns (`lo` always, every bridge once a WAN carries
/// IPv6; the WAN's port joins in [`ipv6_routing`]).
fn lan_addresses(world: &World, lan6: &Lan6, desired: &mut DesiredRouting) {
    for lan in &world.config.lans {
        if let Ok(net) = lan.ipv4.parse::<IpNet>() {
            desired.addrs.insert(DesiredAddr {
                ifname: bridge_name(&lan.name),
                net,
                peer: None,
            });
        }
    }
    for prefix in &lan6.prefixes {
        desired.addrs.insert(DesiredAddr {
            ifname: prefix.ifname.clone(),
            net: IpNet::V6(Ipv6Net::new_assert(prefix.router, 64)),
            peer: None,
        });
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
/// routed prefix gives the loopback address and the blackhole. From part 3 (SPEC §7.3, §7.4):
/// the `IA_NA` addresses on the port; a loopback address and a blackhole per delegated prefix;
/// the WAN's own table holding the default, or `unreachable default` while there is none; the
/// 1500 suppress-main rule; a source rule per delegated prefix into the WAN's table and an
/// `unreachable` rule per deprecated prefix.
/// A PPPoE WAN's session on its netdev (ADR-0023): the IPCP address as a point-to-point
/// address with the peer, the default through the netdev (via the peer when it is numbered),
/// and the IPV6CP identifiers as our link-local address and the peer's on-link /128.
fn pppoe_routing(world: &World, wan_config: &Wan, ifname: &str, desired: &mut DesiredRouting) {
    let Some(fact) = world.pppoe.get(&wan_config.name) else {
        return;
    };
    let route = |dst: Option<IpNet>, gateway: Option<IpAddr>| DesiredRoute {
        ifname: Some(ifname.to_owned()),
        dst,
        gateway,
        table: TABLE_MAIN,
        protocol: RTPROT_OPENFEO,
        priority: wan_config.priority,
        kind: RouteKind::Unicast,
        pref_src: None,
    };
    if let Some(ipv4) = &fact.ipv4 {
        desired.addrs.insert(DesiredAddr {
            ifname: ifname.to_owned(),
            net: IpNet::V4(Ipv4Net::from(ipv4.local)),
            peer: ipv4.peer.map(IpAddr::V4),
        });
        desired
            .routes
            .insert(route(None, ipv4.peer.map(IpAddr::V4)));
    }
    if let Some(ipv6) = &fact.ipv6 {
        let link_local = |iid: u64| Ipv6Addr::from((0xfe80u128 << 112) | u128::from(iid));
        desired.addrs.insert(DesiredAddr {
            ifname: ifname.to_owned(),
            net: IpNet::V6(Ipv6Net::new_assert(link_local(ipv6.local_iid), 64)),
            peer: None,
        });
        desired.routes.insert(route(
            Some(IpNet::V6(Ipv6Net::from(link_local(ipv6.peer_iid)))),
            None,
        ));
    }
}

#[allow(clippy::too_many_lines)]
fn ipv6_routing(
    world: &World,
    wan_config: &Wan,
    ipv6: &Ipv6Wan,
    ifname: &str,
    index: usize,
    lan6: &Lan6,
    desired: &mut DesiredRouting,
) {
    desired.ipv6_owned.insert(ifname.to_owned());
    let fact = world.ipv6.get(&wan_config.name);
    let fact6 = world.dhcp6.get(&wan_config.name);
    let prefix = ipv6.prefix.parse::<Ipv6Net>().ok().map(|p| p.trunc());
    let loopback = lan6.pref_src;
    let table = wan_table(index);
    let route_in = |table: u32,
                    dst: Option<Ipv6Net>,
                    gateway: Option<Ipv6Addr>,
                    src: Option<Ipv6Addr>| DesiredRoute {
        ifname: Some(ifname.to_owned()),
        dst: dst.map(IpNet::V6),
        gateway: gateway.map(IpAddr::V6),
        table,
        protocol: RTPROT_OPENFEO,
        priority: wan_config.priority,
        kind: RouteKind::Unicast,
        pref_src: src.map(IpAddr::V6),
    };
    let route = |dst, gateway, src| route_in(TABLE_MAIN, dst, gateway, src);
    let blackhole = |net: Ipv6Net| DesiredRoute {
        ifname: None,
        dst: Some(IpNet::V6(net)),
        gateway: None,
        table: TABLE_MAIN,
        protocol: RTPROT_OPENFEO,
        priority: BLOCK_METRIC,
        kind: RouteKind::Blackhole,
        pref_src: None,
    };
    // Prefixes the router owns: nothing the ISP advertises may pull them onto the WAN port.
    let mut own: Vec<Ipv6Net> = lan6.prefixes.iter().map(|p| p.net).collect();
    own.extend(world.ula.map(|ula| ula.trunc()));
    if let Some(fact6) = fact6 {
        own.extend(fact6.prefixes.iter().map(|p| p.net.trunc()));
        own.extend(fact6.deprecated.iter().map(|p| p.net.trunc()));
    }
    let usable = |net: &Ipv6Net| learned_prefix_is_usable(*net, prefix, &own);
    if let Some(fact) = fact {
        for addr in fact.addresses.iter().filter(|addr| usable(addr)) {
            desired.addrs.insert(DesiredAddr {
                ifname: ifname.to_owned(),
                net: IpNet::V6(*addr),
                peer: None,
            });
        }
        for on_link in fact.on_link.iter().filter(|net| usable(net)) {
            desired.routes.insert(route(Some(*on_link), None, None));
        }
        for (dst, via, _) in fact.routes.iter().filter(|(dst, _, _)| usable(dst)) {
            desired.routes.insert(route(Some(*dst), Some(*via), None));
        }
    }
    if let Some(fact6) = fact6 {
        for addr in fact6.addresses.iter().filter(|addr| usable(&addr.net)) {
            desired.addrs.insert(DesiredAddr {
                ifname: ifname.to_owned(),
                net: IpNet::V6(addr.net),
                peer: None,
            });
        }
        for delegated in fact6.prefixes.iter().chain_deprecated(fact6) {
            desired.routes.insert(blackhole(delegated));
        }
    }
    let typed = ipv6.gateway.parse::<Ipv6Addr>().ok();
    let mut has_default = false;
    if let Some(via) = typed.or(fact.and_then(|f| f.router)) {
        let on_link = is_link_local(via)
            || fact.is_some_and(|f| {
                f.on_link
                    .iter()
                    .chain(&f.addresses)
                    .filter(|net| usable(net))
                    .any(|net| net.contains(&via))
            });
        if !on_link {
            let host = Some(Ipv6Net::new_assert(via, 128));
            desired.routes.insert(route(host, None, None));
            desired.routes.insert(route_in(table, host, None, None));
        }
        desired.routes.insert(route(None, Some(via), loopback));
        desired
            .routes
            .insert(route_in(table, None, Some(via), loopback));
        has_default = true;
    }
    if !has_default {
        desired.routes.insert(DesiredRoute {
            ifname: None,
            dst: None,
            gateway: None,
            table,
            protocol: RTPROT_OPENFEO,
            priority: BLOCK_METRIC,
            kind: RouteKind::Unreachable,
            pref_src: None,
        });
    }
    if let Some(prefix) = prefix {
        desired.addrs.insert(DesiredAddr {
            ifname: "lo".to_owned(),
            net: IpNet::V6(Ipv6Net::new_assert(router_address(prefix), 128)),
            peer: None,
        });
        desired.routes.insert(blackhole(prefix));
    }
    for addr in &lan6.loopback {
        desired.addrs.insert(DesiredAddr {
            ifname: "lo".to_owned(),
            net: IpNet::V6(Ipv6Net::new_assert(*addr, 128)),
            peer: None,
        });
    }
    desired.rules.insert(DesiredRule {
        v6: true,
        priority: RULE_PRIORITY_MAIN_SUPPRESS,
        src: None,
        action: DesiredRuleAction::ToTable(TABLE_MAIN),
        suppress_prefixlen: Some(0),
    });
    if let Some(fact6) = fact6 {
        for delegated in &fact6.prefixes {
            desired.rules.insert(DesiredRule {
                v6: true,
                priority: RULE_PRIORITY_SOURCE,
                src: Some(IpNet::V6(delegated.net.trunc())),
                action: DesiredRuleAction::ToTable(table),
                suppress_prefixlen: None,
            });
        }
        for gone in &fact6.deprecated {
            desired.rules.insert(DesiredRule {
                v6: true,
                priority: RULE_PRIORITY_SOURCE,
                src: Some(IpNet::V6(gone.net.trunc())),
                action: DesiredRuleAction::Unreachable,
                suppress_prefixlen: None,
            });
        }
    }
}

/// The delegated prefixes a fact holds, live ones then deprecated ones, truncated.
trait ChainDeprecated<'a>: Iterator<Item = &'a openfeo_world::Lifetimed> + Sized + 'a {
    fn chain_deprecated(
        self,
        fact: &'a openfeo_world::WanDhcp6Fact,
    ) -> Box<dyn Iterator<Item = Ipv6Net> + 'a> {
        Box::new(
            self.map(|p| p.net.trunc())
                .chain(fact.deprecated.iter().map(|p| p.net.trunc())),
        )
    }
}

impl<'a, I: Iterator<Item = &'a openfeo_world::Lifetimed> + 'a> ChainDeprecated<'a> for I {}

#[cfg(test)]
mod tests {
    #[test]
    fn a_pppoe_world_routes_a_point_to_point_address_and_a_dev_default() {
        let desired = routing(&fixtures::pppoe_world());
        assert!(
            desired.addrs.contains(&DesiredAddr {
                ifname: "ppp-wan0".to_owned(),
                net: "203.0.113.100/32".parse().unwrap(),
                peer: Some("203.0.113.1".parse().unwrap()),
            }),
            "{:?}",
            desired.addrs
        );
        let default = desired
            .routes
            .iter()
            .find(|route| {
                route.dst.is_none()
                    && route.ifname.as_deref() == Some("ppp-wan0")
                    && route.table == TABLE_MAIN
                    && !route.gateway.is_some_and(|g| g.is_ipv6())
            })
            .expect("an IPv4 default through the netdev");
        assert_eq!(default.gateway, Some("203.0.113.1".parse().unwrap()));
        assert_eq!(default.priority, 10);
        assert!(
            desired.addrs.iter().all(|addr| addr.ifname != "p0"),
            "nothing on the port: {:?}",
            desired.addrs
        );
        insta::assert_yaml_snapshot!(desired);
    }

    #[test]
    fn the_ipv6cp_identifiers_give_the_link_local_and_the_peer_route() {
        let desired = routing(&fixtures::pppoe_world());
        assert!(
            desired.addrs.contains(&DesiredAddr {
                ifname: "ppp-wan0".to_owned(),
                net: "fe80::1234:5678:9abc:def0/64".parse().unwrap(),
                peer: None,
            }),
            "{:?}",
            desired.addrs
        );
        assert!(
            desired
                .routes
                .iter()
                .any(|route| route.ifname.as_deref() == Some("ppp-wan0")
                    && route.dst == Some("fe80::2/128".parse().unwrap())
                    && route.gateway.is_none()),
            "the peer's link-local is on the link: {:?}",
            desired.routes
        );
    }

    #[test]
    fn a_pppoe_wan_desires_nothing_for_its_netdev_until_the_link_exists() {
        let desired = routing(&fixtures::pppoe_world_without_link());
        assert!(
            desired.addrs.iter().all(|addr| addr.ifname != "ppp-wan0"),
            "{:?}",
            desired.addrs
        );
        assert!(
            desired
                .routes
                .iter()
                .all(|route| route.ifname.as_deref() != Some("ppp-wan0")),
            "{:?}",
            desired.routes
        );
        assert!(!desired.ipv6_owned.contains("ppp-wan0"));
    }

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
                use std::fmt::Write as _;
                let mut line = match r.kind {
                    RouteKind::Unicast => String::new(),
                    RouteKind::Blackhole => "blackhole ".to_owned(),
                    RouteKind::Unreachable => "unreachable ".to_owned(),
                };
                let _ = write!(
                    line,
                    "{} via {} dev {} proto {} metric {}",
                    r.dst
                        .map_or_else(|| "default".to_owned(), |d| d.to_string()),
                    r.gateway.map_or_else(|| "-".to_owned(), |g| g.to_string()),
                    r.ifname.as_deref().unwrap_or("-"),
                    r.protocol,
                    r.priority
                );
                if let Some(src) = r.pref_src {
                    let _ = write!(line, " src {src}");
                }
                if r.table != TABLE_MAIN {
                    let _ = write!(line, " table {}", r.table);
                }
                line
            })
            .collect()
    }

    fn rules_of(desired: &DesiredRouting) -> Vec<String> {
        desired
            .rules
            .iter()
            .map(|r| {
                let action = match r.action {
                    DesiredRuleAction::ToTable(TABLE_MAIN) => "lookup main".to_owned(),
                    DesiredRuleAction::ToTable(table) => format!("lookup {table}"),
                    DesiredRuleAction::Unreachable => "unreachable".to_owned(),
                };
                format!(
                    "{} {} from {} {}{}",
                    if r.v6 { "v6" } else { "v4" },
                    r.priority,
                    r.src.map_or_else(|| "all".to_owned(), |s| s.to_string()),
                    action,
                    r.suppress_prefixlen
                        .map_or_else(String::new, |len| format!(" suppress_prefixlength {len}"))
                )
            })
            .collect()
    }

    #[test]
    fn pd_world_installs_the_wan_table_rules_and_lan_addresses() {
        let desired = routing(&fixtures::pd_world());
        let routes = routes_of(&desired);
        for route in [
            "default via fe80::1 dev p0 proto 200 metric 10 src 2001:db8:100::1",
            "default via fe80::1 dev p0 proto 200 metric 10 src 2001:db8:100::1 table 100",
            "blackhole 2001:db8:100::/56 via - dev - proto 200 metric 1000",
        ] {
            assert!(routes.contains(&route.to_owned()), "{route} in {routes:?}");
        }
        assert_eq!(
            rules_of(&desired),
            vec![
                "v6 1500 from all lookup main suppress_prefixlength 0",
                "v6 2000 from 2001:db8:100::/56 lookup 100",
            ]
        );
        let addrs = addrs_of(&desired);
        for addr in [
            "lo 2001:db8:100::1/128",
            "lo fd12:3456:789a::1/128",
            "br-lan0 2001:db8:100:1::1/64",
            "br-lan0 fd12:3456:789a:1::1/64",
            "br-lan1 2001:db8:100:2::1/64",
            "br-lan1 fd12:3456:789a:2::1/64",
            "p0 2001:db8:ffff::1a4/128",
        ] {
            assert!(addrs.contains(&addr.to_owned()), "{addr} in {addrs:?}");
        }
        assert!(
            !routes.iter().any(|r| r.contains("fd12:3456:789a::/48")),
            "the ULA is not blackholed: {routes:?}"
        );
        assert!(desired.ipv6_owned.contains("br-lan1"));
    }

    #[test]
    fn a_deprecated_prefix_gets_an_unreachable_rule_and_keeps_its_bridge_address() {
        let mut world = fixtures::pd_world();
        let mut fact = fixtures::dhcp6_fact();
        fact.deprecated.push(openfeo_world::Deprecated {
            net: "2001:db8:200::/56".parse().unwrap(),
            until_ms: 70_000,
        });
        world.dhcp6 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let desired = routing(&world);
        assert_eq!(
            rules_of(&desired),
            vec![
                "v6 1500 from all lookup main suppress_prefixlength 0",
                "v6 2000 from 2001:db8:100::/56 lookup 100",
                "v6 2000 from 2001:db8:200::/56 unreachable",
            ]
        );
        let addrs = addrs_of(&desired);
        assert!(
            addrs.contains(&"br-lan0 2001:db8:200:1::1/64".to_owned()),
            "the router keeps its address on the deprecated /64: {addrs:?}"
        );
        assert!(
            !addrs.contains(&"lo 2001:db8:200::1/128".to_owned()),
            "no loopback address for it: {addrs:?}"
        );
        assert!(
            routes_of(&desired).contains(
                &"blackhole 2001:db8:200::/56 via - dev - proto 200 metric 1000".to_owned()
            ),
            "the deprecated prefix stays blackholed"
        );
    }

    #[test]
    fn a_wan_without_an_ipv6_default_gets_an_unreachable_default_in_its_table() {
        let mut world = fixtures::pd_world();
        let mut ipv6 = (*world.ipv6).clone();
        ipv6.get_mut("wan0").unwrap().router = None;
        world.ipv6 = Arc::new(ipv6);
        world.routes = Arc::new(std::collections::BTreeSet::new());
        let desired = routing(&world);
        let routes = routes_of(&desired);
        assert!(
            routes.contains(
                &"unreachable default via - dev - proto 200 metric 1000 table 100".to_owned()
            ),
            "{routes:?}"
        );
        assert!(
            !routes.iter().any(|r| r.starts_with("default via")),
            "no default anywhere: {routes:?}"
        );
        assert_eq!(
            rules_of(&desired),
            vec![
                "v6 1500 from all lookup main suppress_prefixlength 0",
                "v6 2000 from 2001:db8:100::/56 lookup 100",
            ],
            "the source rule stays, so traffic from the prefix fails fast in the table"
        );
    }

    #[test]
    fn a_routed_prefix_world_has_no_rules_beyond_suppress() {
        let desired = routing(&fixtures::ipv6_world());
        assert_eq!(
            rules_of(&desired),
            vec!["v6 1500 from all lookup main suppress_prefixlength 0"]
        );
        let routes = routes_of(&desired);
        assert!(
            routes.contains(
                &"default via fe80::1 dev p0 proto 200 metric 10 src 2001:db8:1::1 table 100"
                    .to_owned()
            ),
            "the WAN's table holds the default too: {routes:?}"
        );
        let addrs = addrs_of(&desired);
        for addr in [
            "lo 2001:db8:1::1/128",
            "lo fd12:3456:789a::1/128",
            "br-lan0 2001:db8:1:222::1/64",
            "br-lan0 fd12:3456:789a:1::1/64",
            "br-dmz 2001:db8:1:232::1/64",
            "br-dmz fd12:3456:789a:2::1/64",
        ] {
            assert!(addrs.contains(&addr.to_owned()), "{addr} in {addrs:?}");
        }
    }

    #[test]
    fn pd_world_routing_snapshot() {
        insta::assert_yaml_snapshot!(routing(&fixtures::pd_world()));
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
            routes.contains(
                &"blackhole 2001:db8:1::/48 via - dev - proto 200 metric 1000".to_owned()
            ),
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
        assert!(
            routes.contains(
                &"blackhole 2001:db8:1::/48 via - dev - proto 200 metric 1000".to_owned()
            )
        );
        assert!(addrs_of(&desired).contains(&"lo 2001:db8:1::1/128".to_owned()));
        assert!(
            routes.contains(
                &"unreachable default via - dev - proto 200 metric 1000 table 100".to_owned()
            ),
            "the WAN's table says unreachable while there is no default: {routes:?}"
        );
        world.ipv6 = Arc::new(BTreeMap::new());
        let routes = routes_of(&routing(&world));
        assert!(
            !routes.iter().any(|r| r.starts_with("default via fe80::")),
            "no fact at all: {routes:?}"
        );
    }

    #[test]
    fn without_a_prefix_the_default_has_no_preferred_source_and_lo_gets_only_the_ula() {
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
        let lo: Vec<String> = addrs_of(&desired)
            .into_iter()
            .filter(|a| a.starts_with("lo "))
            .collect();
        assert_eq!(
            lo,
            vec!["lo fd12:3456:789a::1/128".to_owned()],
            "no routed prefix, no global loopback address; the ULA's stays"
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

    /// A learned prefix that is not global unicast, that is `::/0`, or that overlaps the routed
    /// prefix or a LAN's /64 is never installed: an ISP advertising the customer's prefix back,
    /// or a neighbour on the WAN link, must not pull the router's own prefixes onto the WAN port.
    #[test]
    fn learned_prefixes_that_are_not_global_or_are_the_routers_own_are_ignored() {
        let mut world = fixtures::ipv6_world();
        let mut fact = fixtures::ipv6_fact();
        fact.addresses = vec![
            "2001:db8:1:222::abcd/64".parse().unwrap(),
            "2001:db8:ffff:0:1234:5678:9abc:def0/64".parse().unwrap(),
        ];
        fact.on_link = vec![
            "2001:db8:1::/48".parse().unwrap(),
            "fe80::/64".parse().unwrap(),
            "2001:db8:ffff::/64".parse().unwrap(),
        ];
        let via: Ipv6Addr = "fe80::1".parse().unwrap();
        fact.routes = vec![
            (
                "::/0".parse().unwrap(),
                via,
                openfeo_world::Preference::High,
            ),
            (
                "2001:db8:1:5::/64".parse().unwrap(),
                via,
                openfeo_world::Preference::Medium,
            ),
            (
                "ff00::/8".parse().unwrap(),
                via,
                openfeo_world::Preference::Medium,
            ),
            (
                "2001:db8:2::/48".parse().unwrap(),
                via,
                openfeo_world::Preference::High,
            ),
        ];
        world.ipv6 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let desired = routing(&world);
        let addrs = addrs_of(&desired);
        assert!(
            addrs.contains(&"p0 2001:db8:ffff:0:1234:5678:9abc:def0/64".to_owned()),
            "{addrs:?}"
        );
        assert!(
            !addrs.iter().any(|a| a.starts_with("p0 2001:db8:1:222:")),
            "a LAN's /64 on the WAN port: {addrs:?}"
        );
        let routes = routes_of(&desired);
        for kept in [
            "2001:db8:ffff::/64 via - dev p0 proto 200 metric 10",
            "2001:db8:2::/48 via fe80::1 dev p0 proto 200 metric 10",
        ] {
            assert!(
                routes.contains(&kept.to_owned()),
                "{kept} missing: {routes:?}"
            );
        }
        // The routed prefix keeps its blackhole; nothing learned lands on the WAN port.
        for dropped in [
            "2001:db8:1::/48 via - dev p0",
            "fe80::/64 via - dev p0",
            "::/0 via fe80::1",
            "2001:db8:1:5::/64 via fe80::1",
            "ff00::/8 via fe80::1",
        ] {
            assert!(
                !routes.iter().any(|r| r.starts_with(dropped)),
                "{dropped} was installed: {routes:?}"
            );
        }
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
