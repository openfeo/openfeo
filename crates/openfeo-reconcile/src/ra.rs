// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What each LAN's router-advertisement server says (SPEC §7.3, §6.2's `reconcile::ra`): the
//! LAN's /64 and the router's address in it, the bridge's MTU, the search domain, and the router
//! lifetime, which is 1800 only while the WAN that provides the prefix has carrier and an IPv6
//! default route in the kernel (ADR-0019) and 0 otherwise, so hosts fall back to IPv4 the moment
//! the WAN's IPv6 is gone.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use openfeo_config::load::DEFAULT_DOMAIN;
use openfeo_world::World;
use serde::Serialize;

use crate::{bridge_name, wan_ifname};

/// The router lifetime advertised while the WAN has IPv6 (SPEC §7.3).
pub const ROUTER_LIFETIME: u16 = 1800;

/// What one LAN's server advertises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredRa {
    /// `br-<lan>`.
    pub ifname: String,
    /// The WAN whose routed prefix the LAN's /64 comes from, for the console.
    pub wan: String,
    /// The LAN's /64.
    pub prefix: Ipv6Net,
    /// The router's address in the LAN: the resolver hosts are pointed at.
    pub router: Ipv6Addr,
    /// The bridge's MTU, once the bridge exists.
    pub mtu: Option<u32>,
    /// The search domain.
    pub domain: String,
    /// [`ROUTER_LIFETIME`] while the WAN has carrier and an IPv6 default route, else 0.
    pub router_lifetime: u16,
}

/// One advertisement per LAN with `ipv6` and `ra` not `false`, in configuration order. A LAN
/// whose `ipv6` does not parse, or that no WAN with a prefix covers, contributes nothing
/// (validation already refused it).
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
    let Some(wan) = world.config.wans.iter().find(|wan| {
        world.ports.id_of(&wan.port).is_some()
            && wan
                .ipv6
                .as_ref()
                .is_some_and(|ipv6| ipv6.mode != "disabled" && !ipv6.prefix.is_empty())
    }) else {
        return Vec::new();
    };
    let ifname = wan_ifname(wan);
    let usable = world.links.get(&ifname).is_some_and(|link| link.carrier)
        && world.has_default(true, &ifname);
    world
        .config
        .lans
        .iter()
        .filter(|lan| lan.ra != Some(false))
        .filter_map(|lan| {
            let net = lan.ipv6.parse::<Ipv6Net>().ok()?;
            let bridge = bridge_name(&lan.name);
            Some(DesiredRa {
                mtu: world.links.get(&bridge).map(|link| link.mtu),
                ifname: bridge,
                wan: wan.name.clone(),
                prefix: net.trunc(),
                router: net.addr(),
                domain: domain.clone(),
                router_lifetime: if usable { ROUTER_LIFETIME } else { 0 },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    #[test]
    fn every_lan_with_ipv6_and_ra_on_gets_an_advertisement_and_the_dmz_does_not() {
        let ras = desired(&fixtures::ipv6_world());
        assert_eq!(ras.len(), 1, "{ras:?}");
        let ra = &ras[0];
        assert_eq!(ra.ifname, "br-lan0");
        assert_eq!(ra.wan, "wan0");
        assert_eq!(ra.prefix.to_string(), "2001:db8:1:222::/64");
        assert_eq!(ra.router.to_string(), "2001:db8:1:222::1");
        assert_eq!(ra.domain, "home.arpa");
        assert_eq!(ra.router_lifetime, 1800);
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
    fn ipv6_world_ra_snapshot() {
        insta::assert_yaml_snapshot!(desired(&fixtures::ipv6_world()));
    }
}
