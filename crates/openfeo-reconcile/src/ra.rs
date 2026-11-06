// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What each LAN's router-advertisement server says (SPEC §7.3, §6.2's `reconcile::ra`): every
//! prefix the LAN carries (`lan6`) with the lifetimes its state calls for, the router's
//! addresses in the LAN as resolvers with the ULA one first, the bridge's MAC and MTU, the
//! search domain, O = 1 for the stateless responder, route information for the ULA and the
//! delegations in force (RFC 7084 L-3), and the router lifetime, which is 1800 only while the
//! WAN that carries IPv6 has carrier and an IPv6 default route in the kernel (ADR-0019) and 0
//! otherwise, so hosts fall back to IPv4 the moment the WAN's IPv6 is gone.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use openfeo_config::load::DEFAULT_DOMAIN;
use openfeo_world::{MacAddr, World};
use serde::Serialize;

use crate::bridge_name;
use crate::lan6::{self, LanPrefix, Source, State};

/// The router lifetime advertised while the WAN has IPv6 (SPEC §7.3).
pub const ROUTER_LIFETIME: u16 = 1800;
/// The most an unauthenticated advertisement may shorten a host's valid lifetime to (RFC 4862
/// §5.5.3): what a prefix whose WAN is down, or one being deprecated, is advertised with.
pub const DEPRECATION_SECS: u32 = 7200;

/// The lifetimes a prefix information option follows (SPEC §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PioLifetimes {
    /// A routed or ULA prefix: RFC 4861's defaults, it never goes away.
    Static,
    /// A delegation in force: the remaining lifetimes, capped at the defaults (RFC 7084 L-13).
    FromDelegation {
        obtained_ms: u64,
        preferred_secs: u32,
        valid_secs: u32,
    },
    /// A delegation whose WAN has no carrier or no IPv6 default: preferred 0, valid the lower
    /// of the remainder and [`DEPRECATION_SECS`].
    Stale { obtained_ms: u64, valid_secs: u32 },
    /// A prefix the ISP took back: preferred 0, valid counting down to the deadline.
    Deprecated { until_ms: u64 },
}

/// One prefix information option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredPio {
    pub prefix: Ipv6Net,
    pub source: Source,
    pub lifetimes: PioLifetimes,
}

/// What one LAN's server advertises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredRa {
    /// `br-<lan>`.
    pub ifname: String,
    /// The WAN that carries IPv6, for the console.
    pub wan: String,
    pub lan: String,
    /// The prefixes, in `lan6`'s order: routed, delegated, ULA, deprecated.
    pub prefixes: Vec<DesiredPio>,
    /// The router's addresses in the LAN as resolvers, the ULA one first because it survives
    /// renumbering; a deprecated prefix's address is left out.
    pub rdnss: Vec<Ipv6Addr>,
    /// The bridge's MAC, the source link-layer address option, once the bridge exists.
    pub mac: Option<MacAddr>,
    /// The bridge's MTU, once the bridge exists.
    pub mtu: Option<u32>,
    /// The search domain.
    pub domain: String,
    /// [`ROUTER_LIFETIME`] while the WAN has carrier and an IPv6 default route, else 0.
    pub router_lifetime: u16,
    /// The O flag: the stateless DHCPv6 responder answers.
    pub other: bool,
    /// Route information options via this router: the ULA /48 and every delegation in force.
    pub routes: Vec<Ipv6Net>,
}

/// One advertisement per LAN that carries a prefix and does not say `ra = false`, in
/// configuration order; nothing without a WAN that carries IPv6.
#[must_use]
pub fn desired(world: &World) -> Vec<DesiredRa> {
    let domain = world
        .config
        .system
        .as_ref()
        .map(|system| system.domain.as_str())
        .filter(|domain| !domain.is_empty())
        .unwrap_or(DEFAULT_DOMAIN)
        .to_ascii_lowercase();
    let Some(wan) = lan6::ipv6_wan(world) else {
        return Vec::new();
    };
    let usable = lan6::wan_usable(world, wan);
    let lan6 = lan6::prefixes(world);
    let mut routes: Vec<Ipv6Net> = world.ula.map(|ula| ula.trunc()).into_iter().collect();
    for prefix in &lan6.prefixes {
        if let (Source::Delegated { parent, .. }, State::Live { .. }) =
            (&prefix.source, &prefix.state)
            && !routes.contains(parent)
        {
            routes.push(*parent);
        }
    }
    world
        .config
        .lans
        .iter()
        .filter(|lan| lan.ra != Some(false))
        .filter_map(|lan| {
            let mine: Vec<&LanPrefix> = lan6
                .prefixes
                .iter()
                .filter(|prefix| prefix.lan == lan.name)
                .collect();
            if mine.is_empty() {
                return None;
            }
            let bridge = bridge_name(&lan.name);
            Some(DesiredRa {
                mac: world.links.get(&bridge).and_then(|link| link.mac),
                mtu: world.links.get(&bridge).map(|link| link.mtu),
                ifname: bridge,
                wan: wan.name.clone(),
                lan: lan.name.clone(),
                prefixes: mine.iter().map(|prefix| pio(prefix)).collect(),
                rdnss: resolvers(&mine),
                domain: domain.clone(),
                router_lifetime: if usable { ROUTER_LIFETIME } else { 0 },
                other: true,
                routes: routes.clone(),
            })
        })
        .collect()
}

fn pio(prefix: &LanPrefix) -> DesiredPio {
    DesiredPio {
        prefix: prefix.net,
        source: prefix.source.clone(),
        lifetimes: match prefix.state {
            State::Static => PioLifetimes::Static,
            State::Live {
                obtained_ms,
                preferred_secs,
                valid_secs,
            } => PioLifetimes::FromDelegation {
                obtained_ms,
                preferred_secs,
                valid_secs,
            },
            State::Stale {
                obtained_ms,
                valid_secs,
            } => PioLifetimes::Stale {
                obtained_ms,
                valid_secs,
            },
            State::Deprecated { until_ms } => PioLifetimes::Deprecated { until_ms },
        },
    }
}

/// The router's addresses hosts are pointed at: ULA first, then the rest, never a deprecated
/// prefix's.
fn resolvers(prefixes: &[&LanPrefix]) -> Vec<Ipv6Addr> {
    let live = |prefix: &&&LanPrefix| !matches!(prefix.state, State::Deprecated { .. });
    prefixes
        .iter()
        .filter(live)
        .filter(|prefix| prefix.source == Source::Ula)
        .chain(
            prefixes
                .iter()
                .filter(live)
                .filter(|prefix| prefix.source != Source::Ula),
        )
        .map(|prefix| prefix.router)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use openfeo_world::MacAddr;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    fn net(text: &str) -> Ipv6Net {
        text.parse().unwrap()
    }

    fn addr(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }

    fn prefixes_of(ra: &DesiredRa) -> Vec<Ipv6Net> {
        ra.prefixes.iter().map(|p| p.prefix).collect()
    }

    #[test]
    fn every_lan_with_ipv6_and_ra_on_gets_an_advertisement_and_the_dmz_does_not() {
        let ras = desired(&fixtures::ipv6_world());
        assert_eq!(ras.len(), 1, "{ras:?}");
        let ra = &ras[0];
        assert_eq!(ra.ifname, "br-lan0");
        assert_eq!(ra.lan, "lan0");
        assert_eq!(ra.wan, "wan0");
        assert_eq!(
            prefixes_of(ra),
            vec![net("2001:db8:1:222::/64"), net("fd12:3456:789a:1::/64")]
        );
        assert_eq!(ra.prefixes[0].source, Source::Routed);
        assert_eq!(ra.prefixes[0].lifetimes, PioLifetimes::Static);
        assert_eq!(ra.prefixes[1].source, Source::Ula);
        assert_eq!(ra.prefixes[1].lifetimes, PioLifetimes::Static);
        assert_eq!(ra.domain, "home.arpa");
        assert_eq!(ra.router_lifetime, 1800);
        assert!(ra.other, "O = 1: the stateless responder answers");
        assert_eq!(ra.routes, vec![net("fd12:3456:789a::/48")]);
        let mut world = fixtures::ipv6_world();
        let mut config = (*world.config).clone();
        config.lans[1].ra = None;
        world.config = Arc::new(config);
        let ras = desired(&world);
        assert_eq!(
            ras.len(),
            2,
            "the DMZ advertises once ra is not false: {ras:?}"
        );
        assert_eq!(ras[1].ifname, "br-dmz");
        assert!(
            desired(&fixtures::static_world()).is_empty(),
            "no IPv6, no advertisements"
        );
    }

    #[test]
    fn lifetime_follows_the_wan_carrier_and_route() {
        assert_eq!(desired(&fixtures::ipv6_world())[0].router_lifetime, 1800);
        let without = desired(&fixtures::ipv6_world_without_route());
        assert_eq!(
            without[0].router_lifetime, 0,
            "no IPv6 default in the kernel"
        );
        let mut world = fixtures::ipv6_world();
        let mut links = (*world.links).clone();
        links.get_mut("p0").unwrap().carrier = false;
        world.links = Arc::new(links);
        assert_eq!(desired(&world)[0].router_lifetime, 0, "carrier gone");
        let mut world = fixtures::ipv6_world();
        world.routes = Arc::new(BTreeSet::from([openfeo_world::DefaultRoute {
            v6: false,
            ifname: "p0".to_owned(),
        }]));
        assert_eq!(
            desired(&world)[0].router_lifetime,
            0,
            "an IPv4 default is not an IPv6 one"
        );
    }

    #[test]
    fn the_mtu_is_the_bridges() {
        assert_eq!(desired(&fixtures::ipv6_world())[0].mtu, Some(1500));
        let mut world = fixtures::ipv6_world();
        let mut links = (*world.links).clone();
        links.remove("br-lan0");
        world.links = Arc::new(links);
        assert_eq!(
            desired(&world)[0].mtu,
            None,
            "unknown until the bridge exists"
        );
    }

    #[test]
    fn the_advertisement_carries_the_bridges_mac_and_follows_it() {
        let world = fixtures::ipv6_world();
        assert_eq!(
            desired(&world)[0].mac,
            Some(MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, 0x02]))
        );
        let mut world = world;
        let mut links = (*world.links).clone();
        let changed = MacAddr([0x02, 0x00, 0x00, 0xfe, 0x00, 0x09]);
        links.get_mut("br-lan0").expect("br-lan0 is known").mac = Some(changed);
        world.links = Arc::new(links);
        assert_eq!(
            desired(&world)[0].mac,
            Some(changed),
            "the server follows the bridge's MAC"
        );
    }

    #[test]
    fn pd_world_advertises_delegated_and_ula_prefixes_with_o_set() {
        let ras = desired(&fixtures::pd_world());
        assert_eq!(ras.len(), 2);
        let lan0 = &ras[0];
        assert_eq!(lan0.ifname, "br-lan0");
        assert_eq!(
            prefixes_of(lan0),
            vec![net("2001:db8:100:1::/64"), net("fd12:3456:789a:1::/64")]
        );
        assert_eq!(
            lan0.prefixes[0].lifetimes,
            PioLifetimes::FromDelegation {
                obtained_ms: 10_000,
                preferred_secs: 40,
                valid_secs: 60,
            }
        );
        assert_eq!(lan0.prefixes[1].lifetimes, PioLifetimes::Static);
        assert!(lan0.other);
        assert_eq!(lan0.router_lifetime, 1800);
        assert_eq!(
            lan0.routes,
            vec![net("fd12:3456:789a::/48"), net("2001:db8:100::/56")]
        );
        assert_eq!(prefixes_of(&ras[1])[0], net("2001:db8:100:2::/64"));
    }

    #[test]
    fn a_stale_delegation_is_advertised_deprecated_while_the_ula_stays_static() {
        let mut world = fixtures::pd_world();
        world.routes = Arc::new(BTreeSet::new());
        let ra = &desired(&world)[0];
        assert_eq!(
            ra.prefixes[0].lifetimes,
            PioLifetimes::Stale {
                obtained_ms: 10_000,
                valid_secs: 60,
            }
        );
        assert_eq!(ra.prefixes[1].lifetimes, PioLifetimes::Static);
        assert_eq!(ra.router_lifetime, 0);
        assert_eq!(
            ra.routes,
            vec![net("fd12:3456:789a::/48")],
            "a stale delegation is no route to advertise"
        );
    }

    #[test]
    fn rdnss_puts_the_ula_address_first() {
        let ra = &desired(&fixtures::pd_world())[0];
        assert_eq!(
            ra.rdnss,
            vec![addr("fd12:3456:789a:1::1"), addr("2001:db8:100:1::1")]
        );
        let ra = &desired(&fixtures::ipv6_world())[0];
        assert_eq!(
            ra.rdnss,
            vec![addr("fd12:3456:789a:1::1"), addr("2001:db8:1:222::1")]
        );
    }

    #[test]
    fn routes_name_the_ula_and_every_live_delegation_and_a_deprecated_prefix_counts_down() {
        let mut world = fixtures::pd_world();
        let mut fact = fixtures::dhcp6_fact();
        fact.deprecated.push(openfeo_world::Deprecated {
            net: net("2001:db8:200::/56"),
            until_ms: 70_000,
        });
        world.dhcp6 = Arc::new(BTreeMap::from([("wan0".to_owned(), fact)]));
        let ra = &desired(&world)[0];
        assert_eq!(
            prefixes_of(ra),
            vec![
                net("2001:db8:100:1::/64"),
                net("fd12:3456:789a:1::/64"),
                net("2001:db8:200:1::/64"),
            ]
        );
        assert_eq!(
            ra.prefixes[2].lifetimes,
            PioLifetimes::Deprecated { until_ms: 70_000 }
        );
        assert_eq!(
            ra.routes,
            vec![net("fd12:3456:789a::/48"), net("2001:db8:100::/56")],
            "a deprecated prefix is no route"
        );
        assert_eq!(
            ra.rdnss,
            vec![addr("fd12:3456:789a:1::1"), addr("2001:db8:100:1::1")],
            "a deprecated address is no resolver"
        );
    }

    #[test]
    fn ipv6_world_ra_snapshot() {
        insta::assert_yaml_snapshot!(desired(&fixtures::ipv6_world()));
    }

    #[test]
    fn pd_world_ra_snapshot() {
        insta::assert_yaml_snapshot!(desired(&fixtures::pd_world()));
    }
}
