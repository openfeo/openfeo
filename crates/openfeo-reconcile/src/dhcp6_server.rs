// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What each LAN's stateless DHCPv6 responder says (SPEC §7.3): on every LAN that advertises,
//! the router's addresses in that LAN as resolvers (the ULA one first, as the advertisement's
//! RDNSS has them) and the search domain.

use std::net::Ipv6Addr;

use openfeo_world::World;
use serde::Serialize;

use crate::ra;

/// One LAN's responder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredResponder {
    /// `br-<lan>`.
    pub ifname: String,
    pub lan: String,
    /// The resolvers: the router's addresses in the LAN, ULA first.
    pub dns: Vec<Ipv6Addr>,
    /// The search domain.
    pub domain: String,
}

/// One responder per LAN the advertisement server serves, in the same order.
#[must_use]
pub fn desired(world: &World) -> Vec<DesiredResponder> {
    ra::desired(world)
        .into_iter()
        .map(|ra| DesiredResponder {
            ifname: ra.ifname,
            lan: ra.lan,
            dns: ra.rdnss,
            domain: ra.domain,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use std::sync::Arc;

    #[test]
    fn every_advertising_lan_gets_a_responder_with_the_ula_address_first() {
        let responders = desired(&fixtures::pd_world());
        assert_eq!(responders.len(), 2);
        assert_eq!(responders[0].ifname, "br-lan0");
        assert_eq!(responders[0].lan, "lan0");
        assert_eq!(
            responders[0].dns,
            vec![
                "fd12:3456:789a:1::1".parse::<Ipv6Addr>().unwrap(),
                "2001:db8:100:1::1".parse().unwrap(),
            ]
        );
        assert_eq!(responders[0].domain, "home.arpa");
        assert_eq!(responders[1].ifname, "br-lan1");
        // The DMZ of the routed world says ra = false: no advertisements, no responder.
        let routed = desired(&fixtures::ipv6_world());
        assert_eq!(routed.len(), 1);
        assert_eq!(routed[0].ifname, "br-lan0");
        let mut world = fixtures::ipv6_world();
        let mut config = (*world.config).clone();
        config.lans[1].ra = None;
        world.config = Arc::new(config);
        assert_eq!(desired(&world).len(), 2);
        assert_eq!(desired(&fixtures::static_world()), vec![]);
    }

    #[test]
    fn pd_world_dhcp6_server_snapshot() {
        insta::assert_yaml_snapshot!(desired(&fixtures::pd_world()));
    }
}
