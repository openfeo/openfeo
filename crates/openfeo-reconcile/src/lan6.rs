// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What each LAN carries over IPv6 (SPEC §7.3): the /64 its `ipv6` names inside the routed
//! prefix, one /64 at its index inside every delegated prefix, one inside the router's ULA,
//! and the /64s of prefixes being deprecated, each with the router's address in it and the
//! state its advertisement follows. The routing, advertisement, responder, DNS and ruleset
//! reconcilers all read this and none derives a prefix on its own.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use openfeo_config::{Lan, Wan, rules};
use openfeo_world::{Deprecated, Lifetimed, World};
use serde::Serialize;

use crate::routing::router_address;
use crate::{bridge_name, wan_netdev};

/// Where a LAN's /64 comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Source {
    /// The LAN's `ipv6` inside the routed prefix (part 2).
    Routed,
    /// Cut from a prefix the WAN was delegated.
    Delegated { wan: String, parent: Ipv6Net },
    /// Cut from the router's ULA /48.
    Ula,
}

/// What the advertisement says about a prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum State {
    /// A routed or ULA prefix: it never goes away; RFC 4861's default lifetimes.
    Static,
    /// A delegation in force on a WAN with carrier and an IPv6 default route: the remaining
    /// lifetimes, capped.
    Live {
        obtained_ms: u64,
        preferred_secs: u32,
        valid_secs: u32,
    },
    /// A delegation in force on a WAN without carrier or without an IPv6 default route:
    /// preferred 0, valid the lower of the remainder and two hours.
    Stale { obtained_ms: u64, valid_secs: u32 },
    /// A prefix the ISP took back: preferred 0, valid counting down to the deadline.
    Deprecated { until_ms: u64 },
}

/// One /64 a LAN carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LanPrefix {
    pub lan: String,
    /// `br-<lan>`.
    pub ifname: String,
    pub net: Ipv6Net,
    /// The router's address in it, `::1`.
    pub router: Ipv6Addr,
    pub source: Source,
    pub state: State,
}

/// Everything the LANs carry, in configuration order.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Lan6 {
    pub prefixes: Vec<LanPrefix>,
    /// The router's own addresses on loopback: `::1` of each delegated prefix that holds more
    /// than one /64, and of the ULA.
    pub loopback: Vec<Ipv6Addr>,
    /// The preferred source of the IPv6 default route: the routed prefix's loopback address
    /// (part 2), else the first delegation's.
    pub pref_src: Option<Ipv6Addr>,
    /// (delegated prefix, LAN) pairs where the delegation was too short for the LAN's index.
    pub left_out: Vec<(Ipv6Net, String)>,
}

/// The WAN that carries `[wans.ipv6]` in mode auto, when its port is known.
#[must_use]
pub fn ipv6_wan(world: &World) -> Option<&Wan> {
    world.config.wans.iter().find(|wan| {
        world.ports.id_of(&wan.port).is_some()
            && wan
                .ipv6
                .as_ref()
                .is_some_and(|ipv6| ipv6.mode != "disabled")
    })
}

/// The gate of ADR-0019 for the WAN's prefixes: carrier and an IPv6 default route in the
/// kernel through it.
#[must_use]
pub fn wan_usable(world: &World, wan: &Wan) -> bool {
    let ifname = wan_netdev(wan);
    world.links.get(&ifname).is_some_and(|link| link.carrier) && world.has_default(true, &ifname)
}

/// A LAN's effective index: the typed `ipv6_index`, or its 1-based `position` counting every
/// LAN (SPEC §7.3).
#[must_use]
pub fn lan_index(lan: &Lan, position: usize) -> u32 {
    if lan.ipv6_index == 0 {
        u32::try_from(position).unwrap_or(u32::MAX)
    } else {
        lan.ipv6_index
    }
}

/// The /64 at `index` below `parent`: `None` when the parent is a /64 or longer, or holds
/// fewer than `index + 1` subnets.
#[must_use]
pub fn subnet(parent: Ipv6Net, index: u32) -> Option<Ipv6Net> {
    let bits = 64u8.checked_sub(parent.prefix_len())?;
    if bits == 0 || (bits < 32 && u64::from(index) >= 1u64 << bits) {
        return None;
    }
    let base = u128::from_be_bytes(parent.network().octets());
    let addr = base | (u128::from(index) << 64);
    Ipv6Net::new(Ipv6Addr::from(addr.to_be_bytes()), 64).ok()
}

/// What every LAN carries (SPEC §7.3); empty without a WAN that carries `[wans.ipv6]`.
#[must_use]
pub fn prefixes(world: &World) -> Lan6 {
    let Some(wan) = ipv6_wan(world) else {
        return Lan6::default();
    };
    let mut out = Lan6::default();
    let usable = wan_usable(world, wan);
    let routed: Option<Ipv6Net> = wan
        .ipv6
        .as_ref()
        .and_then(|ipv6| ipv6.prefix.parse::<Ipv6Net>().ok())
        .map(|net| net.trunc());
    let fact = world.dhcp6.get(&wan.name);
    let delegations: &[Lifetimed] = fact.map_or(&[], |fact| &fact.prefixes);
    let deprecated: &[Deprecated] = fact.map_or(&[], |fact| &fact.deprecated);
    let lans: Vec<(&Lan, u32)> = world
        .config
        .lans
        .iter()
        .enumerate()
        .filter(|(_, lan)| !rules::lan_is_ipv4_only(lan))
        .map(|(i, lan)| (lan, lan_index(lan, i + 1)))
        .collect();
    let lowest = lans
        .iter()
        .min_by_key(|(_, index)| *index)
        .map(|(lan, _)| lan.name.as_str());

    for lifetimed in delegations {
        if lifetimed.net.prefix_len() < 64 {
            out.loopback.push(router_address(lifetimed.net.trunc()));
        }
    }
    if let Some(ula) = world.ula {
        out.loopback.push(router_address(ula.trunc()));
    }
    out.pref_src = routed.map(router_address).or_else(|| {
        delegations
            .iter()
            .find(|lifetimed| lifetimed.net.prefix_len() < 64)
            .map(|lifetimed| router_address(lifetimed.net.trunc()))
    });

    for (lan, index) in &lans {
        let entry = |net: Ipv6Net, source: Source, state: State| LanPrefix {
            lan: lan.name.clone(),
            ifname: bridge_name(&lan.name),
            net,
            router: router_address(net),
            source,
            state,
        };
        if let Ok(net) = lan.ipv6.parse::<Ipv6Net>() {
            out.prefixes
                .push(entry(net.trunc(), Source::Routed, State::Static));
        }
        for lifetimed in delegations {
            let parent = lifetimed.net.trunc();
            let state = if usable {
                State::Live {
                    obtained_ms: lifetimed.obtained_ms,
                    preferred_secs: lifetimed.preferred_secs,
                    valid_secs: lifetimed.valid_secs,
                }
            } else {
                State::Stale {
                    obtained_ms: lifetimed.obtained_ms,
                    valid_secs: lifetimed.valid_secs,
                }
            };
            let source = Source::Delegated {
                wan: wan.name.clone(),
                parent,
            };
            match cut(parent, *index, &lan.name, lowest) {
                Cut::Net(net) => out.prefixes.push(entry(net, source, state)),
                Cut::TooShort => out.left_out.push((parent, lan.name.clone())),
                Cut::NotThisLan => {}
            }
        }
        if let Some(ula) = world.ula
            && let Cut::Net(net) = cut(ula.trunc(), *index, &lan.name, lowest)
        {
            out.prefixes.push(entry(net, Source::Ula, State::Static));
        }
        for gone in deprecated {
            let parent = gone.net.trunc();
            if let Cut::Net(net) = cut(parent, *index, &lan.name, lowest) {
                out.prefixes.push(entry(
                    net,
                    Source::Delegated {
                        wan: wan.name.clone(),
                        parent,
                    },
                    State::Deprecated {
                        until_ms: gone.until_ms,
                    },
                ));
            }
        }
    }
    out
}

enum Cut {
    Net(Ipv6Net),
    TooShort,
    NotThisLan,
}

/// The /64 of `lan` inside `parent`: a single /64 goes whole to the lowest-index LAN (SPEC
/// §7.3); otherwise the subnet at `index`, or nothing when the parent is too short for it.
fn cut(parent: Ipv6Net, index: u32, lan: &str, lowest: Option<&str>) -> Cut {
    if parent.prefix_len() >= 64 {
        if parent.prefix_len() == 64 && lowest == Some(lan) {
            Cut::Net(parent)
        } else {
            Cut::NotThisLan
        }
    } else {
        subnet(parent, index).map_or(Cut::TooShort, Cut::Net)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_pppoe_wan_is_usable_through_its_netdev() {
        let world = fixtures::pppoe_world();
        let wan = ipv6_wan(&world).expect("wan0 carries IPv6");
        assert!(wan_usable(&world, wan));
        assert!(!wan_usable(&fixtures::pppoe_world_without_link(), wan));
    }

    use super::*;
    use crate::fixtures;
    use openfeo_world::WanDhcp6Fact;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn net(text: &str) -> Ipv6Net {
        text.parse().unwrap()
    }

    fn addr(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }

    fn with_fact(world: &mut World, fact: WanDhcp6Fact) {
        world.dhcp6 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
    }

    fn nets_of(lan6: &Lan6, lan: &str) -> Vec<Ipv6Net> {
        lan6.prefixes
            .iter()
            .filter(|p| p.lan == lan)
            .map(|p| p.net)
            .collect()
    }

    #[test]
    fn subnet_places_the_index_below_the_prefix() {
        assert_eq!(
            subnet(net("2001:db8:100::/56"), 1),
            Some(net("2001:db8:100:1::/64"))
        );
        assert_eq!(
            subnet(net("2001:db8:100::/56"), 255),
            Some(net("2001:db8:100:ff::/64"))
        );
        assert_eq!(subnet(net("2001:db8:100::/56"), 256), None);
        assert_eq!(
            subnet(net("fd12:3456:789a::/48"), 2),
            Some(net("fd12:3456:789a:2::/64"))
        );
        assert_eq!(
            subnet(net("fd12:3456:789a::/48"), 65535),
            Some(net("fd12:3456:789a:ffff::/64"))
        );
        assert_eq!(
            subnet(net("2001:db8:100::/64"), 1),
            None,
            "a /64 has no room"
        );
        assert_eq!(subnet(net("2001:db8:100::/60"), 16), None);
        assert_eq!(
            subnet(net("2001:db8:100::/60"), 15),
            Some(net("2001:db8:100:f::/64"))
        );
        assert_eq!(
            subnet(net("2001:db8::/32"), 1),
            Some(net("2001:db8:0:1::/64")),
            "a /32 holds every index"
        );
    }

    #[test]
    fn a_delegation_and_the_ula_give_every_lan_two_prefixes() {
        let lan6 = prefixes(&fixtures::pd_world());
        assert_eq!(
            nets_of(&lan6, "lan0"),
            vec![net("2001:db8:100:1::/64"), net("fd12:3456:789a:1::/64")]
        );
        assert_eq!(
            nets_of(&lan6, "lan1"),
            vec![net("2001:db8:100:2::/64"), net("fd12:3456:789a:2::/64")]
        );
        let first = &lan6.prefixes[0];
        assert_eq!(first.ifname, "br-lan0");
        assert_eq!(first.router, addr("2001:db8:100:1::1"));
        assert_eq!(
            first.source,
            Source::Delegated {
                wan: "wan0".to_owned(),
                parent: net("2001:db8:100::/56"),
            }
        );
        assert_eq!(
            first.state,
            State::Live {
                obtained_ms: 10_000,
                preferred_secs: 40,
                valid_secs: 60,
            }
        );
        assert_eq!(lan6.prefixes[1].source, Source::Ula);
        assert_eq!(lan6.prefixes[1].state, State::Static);
        assert_eq!(
            lan6.loopback,
            vec![addr("2001:db8:100::1"), addr("fd12:3456:789a::1")]
        );
        assert_eq!(lan6.pref_src, Some(addr("2001:db8:100::1")));
        assert_eq!(lan6.left_out, vec![]);
    }

    #[test]
    fn a_routed_prefix_world_gains_only_the_ula() {
        let lan6 = prefixes(&fixtures::ipv6_world());
        assert_eq!(
            nets_of(&lan6, "lan0"),
            vec![net("2001:db8:1:222::/64"), net("fd12:3456:789a:1::/64")]
        );
        assert_eq!(
            nets_of(&lan6, "dmz"),
            vec![net("2001:db8:1:232::/64"), net("fd12:3456:789a:2::/64")],
            "ra = false does not change what the DMZ carries"
        );
        assert_eq!(lan6.prefixes[0].source, Source::Routed);
        assert_eq!(lan6.prefixes[0].state, State::Static);
        assert_eq!(lan6.loopback, vec![addr("fd12:3456:789a::1")]);
        assert_eq!(
            lan6.pref_src,
            Some(addr("2001:db8:1::1")),
            "the routed prefix keeps the preferred source of part 2"
        );
    }

    #[test]
    fn a_short_delegation_leaves_a_high_index_lan_out() {
        let mut world = fixtures::pd_world();
        let mut config = (*world.config).clone();
        config.lans[1].ipv6_index = 20;
        world.config = Arc::new(config);
        with_fact(&mut world, fixtures::dhcp6_fact_with("2001:db8:100::/60"));
        let lan6 = prefixes(&world);
        assert_eq!(
            nets_of(&lan6, "lan0"),
            vec![net("2001:db8:100:1::/64"), net("fd12:3456:789a:1::/64")]
        );
        assert_eq!(
            nets_of(&lan6, "lan1"),
            vec![net("fd12:3456:789a:14::/64")],
            "index 20 fits the ULA but not a /60"
        );
        assert_eq!(
            lan6.left_out,
            vec![(net("2001:db8:100::/60"), "lan1".to_owned())]
        );
    }

    #[test]
    fn a_single_64_goes_whole_to_the_lowest_index_lan() {
        let mut world = fixtures::pd_world();
        with_fact(&mut world, fixtures::dhcp6_fact_with("2001:db8:100:7::/64"));
        let lan6 = prefixes(&world);
        assert_eq!(
            nets_of(&lan6, "lan0"),
            vec![net("2001:db8:100:7::/64"), net("fd12:3456:789a:1::/64")]
        );
        assert_eq!(nets_of(&lan6, "lan1"), vec![net("fd12:3456:789a:2::/64")]);
        assert_eq!(lan6.prefixes[0].router, addr("2001:db8:100:7::1"));
        assert_eq!(
            lan6.loopback,
            vec![addr("fd12:3456:789a::1")],
            "no loopback address from a /64 that a LAN uses whole"
        );
        assert_eq!(lan6.pref_src, None);
        assert_eq!(lan6.left_out, vec![]);
    }

    #[test]
    fn a_stale_wan_marks_delegated_prefixes_stale_and_leaves_the_ula_static() {
        let mut world = fixtures::pd_world();
        world.routes = Arc::new(std::collections::BTreeSet::new());
        let lan6 = prefixes(&world);
        assert_eq!(
            lan6.prefixes[0].state,
            State::Stale {
                obtained_ms: 10_000,
                valid_secs: 60,
            }
        );
        assert_eq!(lan6.prefixes[1].state, State::Static);
        let mut world = fixtures::pd_world();
        let mut links = (*world.links).clone();
        links.get_mut("p0").unwrap().carrier = false;
        world.links = Arc::new(links);
        assert!(matches!(
            prefixes(&world).prefixes[0].state,
            State::Stale { .. }
        ));
    }

    #[test]
    fn deprecated_prefixes_are_listed_last_with_their_deadline() {
        let mut world = fixtures::pd_world();
        let mut fact = fixtures::dhcp6_fact();
        fact.deprecated.push(Deprecated {
            net: net("2001:db8:200::/56"),
            until_ms: 70_000,
        });
        with_fact(&mut world, fact);
        let lan6 = prefixes(&world);
        assert_eq!(
            nets_of(&lan6, "lan0"),
            vec![
                net("2001:db8:100:1::/64"),
                net("fd12:3456:789a:1::/64"),
                net("2001:db8:200:1::/64"),
            ]
        );
        let gone = &lan6.prefixes[2];
        assert_eq!(gone.state, State::Deprecated { until_ms: 70_000 });
        assert_eq!(
            gone.source,
            Source::Delegated {
                wan: "wan0".to_owned(),
                parent: net("2001:db8:200::/56"),
            }
        );
        assert_eq!(
            gone.router,
            addr("2001:db8:200:1::1"),
            "the router keeps its address"
        );
        assert!(
            !lan6.loopback.contains(&addr("2001:db8:200::1")),
            "no loopback address for a prefix on its way out"
        );
    }

    #[test]
    fn ipv6_none_gets_nothing() {
        let mut world = fixtures::pd_world();
        let mut config = (*world.config).clone();
        config.lans[1].ipv6 = "none".to_owned();
        config.lans[1].ipv6_index = 0;
        world.config = Arc::new(config);
        let lan6 = prefixes(&world);
        assert_eq!(nets_of(&lan6, "lan1"), vec![]);
        assert_eq!(nets_of(&lan6, "lan0").len(), 2);
    }

    #[test]
    fn no_ipv6_wan_gives_nothing() {
        assert_eq!(prefixes(&fixtures::static_world()), Lan6::default());
        let mut world = fixtures::pd_world();
        let mut config = (*world.config).clone();
        config.wans[0].ipv6.as_mut().unwrap().mode = "disabled".to_owned();
        world.config = Arc::new(config);
        assert_eq!(prefixes(&world), Lan6::default());
    }

    #[test]
    fn an_unpinned_lan_takes_its_position() {
        let mut world = fixtures::pd_world();
        let mut config = (*world.config).clone();
        config.lans[0].ipv6_index = 0;
        config.lans[1].ipv6_index = 0;
        world.config = Arc::new(config);
        let lan6 = prefixes(&world);
        assert_eq!(nets_of(&lan6, "lan0")[0], net("2001:db8:100:1::/64"));
        assert_eq!(nets_of(&lan6, "lan1")[0], net("2001:db8:100:2::/64"));
    }

    #[test]
    fn wan_usable_needs_carrier_and_the_route() {
        let world = fixtures::pd_world();
        let wan = ipv6_wan(&world).expect("wan0 carries IPv6");
        assert_eq!(wan.name, "wan0");
        assert!(wan_usable(&world, wan));
        assert!(!wan_usable(&fixtures::ipv6_world_without_route(), wan));
    }

    #[test]
    fn pd_world_lan6_snapshot() {
        insta::assert_yaml_snapshot!(prefixes(&fixtures::pd_world()));
    }
}
