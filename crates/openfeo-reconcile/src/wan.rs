// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Where a WAN stands (SPEC §6.2), as a pure view of the World. Until M6's probes a WAN is up
//! when it has carrier and its lease, its session or its address; IPv6 does not enter into it.

use openfeo_config::{Wan, wan::Kind};
use openfeo_world::{WanPhase, World};

use crate::{wan_ifname, wan_netdev};

/// Whether the WAN's port has carrier: the 802.1Q sub-interface's when the WAN is tagged and
/// the kernel shows it, the port's own otherwise.
fn carrier(world: &World, wan: &Wan) -> bool {
    world
        .links
        .get(&wan_ifname(wan))
        .or_else(|| world.links.get(&wan.port))
        .is_some_and(|link| link.carrier)
}

/// The WAN's phase.
#[must_use]
pub fn phase(world: &World, wan: &Wan) -> WanPhase {
    if !carrier(world, wan) {
        return WanPhase::Down;
    }
    let up = match &wan.kind {
        Some(Kind::Static(config)) => config.address.parse::<ipnet::IpNet>().is_ok_and(|net| {
            let netdev = wan_netdev(wan);
            world
                .addresses
                .iter()
                .any(|addr| addr.ifname == netdev && addr.net == net)
        }),
        Some(Kind::Dhcp(_)) => world.dhcp4.contains_key(&wan.name),
        Some(Kind::Pppoe(_)) => world
            .pppoe
            .get(&wan.name)
            .is_some_and(|session| session.ipv4.is_some()),
        None => false,
    };
    if up {
        WanPhase::Up
    } else {
        WanPhase::Connecting
    }
}

/// Why the WAN is not up, in the console's words: nothing when it is, `no carrier` without
/// carrier, otherwise the cause its task last published (or nothing, while it first connects).
#[must_use]
pub fn reason(world: &World, wan: &Wan) -> String {
    match phase(world, wan) {
        WanPhase::Up => String::new(),
        WanPhase::Down => "no carrier".to_owned(),
        WanPhase::Connecting => world
            .wan_status
            .get(&wan.name)
            .and_then(|status| status.cause.clone())
            .unwrap_or_default(),
    }
}

/// The WAN's own IPv4 address when a task learned it: the lease's, or the PPP session's.
/// A static WAN's is configuration, not news.
#[must_use]
pub fn learned_ipv4(world: &World, wan: &Wan) -> Option<String> {
    match &wan.kind {
        Some(Kind::Dhcp(_)) => world
            .dhcp4
            .get(&wan.name)
            .map(|lease| lease.address.to_string()),
        Some(Kind::Pppoe(_)) => world
            .pppoe
            .get(&wan.name)
            .and_then(|session| session.ipv4.as_ref())
            .map(|ipv4| ipv4.local.to_string()),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use openfeo_world::AddrFact;

    use super::*;
    use crate::fixtures;

    /// `world` with carrier on `port`: the fixtures' links start dark.
    pub(crate) fn lit(mut world: World, port: &str) -> World {
        let link = Arc::make_mut(&mut world.links)
            .get_mut(port)
            .expect("the port");
        link.up = true;
        link.carrier = true;
        world
    }

    #[test]
    fn a_dhcp_wan_is_up_with_a_lease_connecting_without_and_down_without_carrier() {
        let up = lit(fixtures::dhcp_world(), "p0");
        let wan = &up.config.wans[0];
        assert_eq!(phase(&up, wan), WanPhase::Up);
        assert_eq!(reason(&up, wan), "");
        let waiting = lit(fixtures::dhcp_world_without_lease(), "p0");
        assert_eq!(phase(&waiting, wan), WanPhase::Connecting);
        assert_eq!(reason(&waiting, wan), "", "first connecting: no cause yet");
        let mut refused = waiting.clone();
        refused.set_wan_cause("wan0", "nak");
        assert_eq!(reason(&refused, wan), "nak");
        let dark = fixtures::dhcp_world();
        assert_eq!(phase(&dark, wan), WanPhase::Down);
        assert_eq!(reason(&dark, wan), "no carrier");
    }

    #[test]
    fn a_static_wan_is_up_only_with_carrier_and_its_address() {
        let mut world = lit(fixtures::static_world(), "p0");
        let wan = world.config.wans[0].clone();
        assert_eq!(
            phase(&world, &wan),
            WanPhase::Connecting,
            "the address is not on yet"
        );
        let Some(Kind::Static(config)) = &wan.kind else {
            panic!("a static WAN");
        };
        Arc::make_mut(&mut world.addresses).insert(AddrFact {
            ifname: "p0".to_owned(),
            net: config.address.parse().expect("a CIDR"),
            peer: None,
            deprecated: false,
        });
        assert_eq!(phase(&world, &wan), WanPhase::Up);
        Arc::make_mut(&mut world.links)
            .get_mut("p0")
            .expect("p0")
            .carrier = false;
        assert_eq!(phase(&world, &wan), WanPhase::Down);
    }

    #[test]
    fn a_pppoe_wan_is_up_only_with_ipcp() {
        let up = fixtures::pppoe_world();
        let wan = &up.config.wans[0];
        assert_eq!(phase(&up, wan), WanPhase::Up);
        assert_eq!(learned_ipv4(&up, wan).as_deref(), Some("203.0.113.100"));
        let mut no_ipcp = up.clone();
        Arc::make_mut(&mut no_ipcp.pppoe)
            .get_mut("wan0")
            .expect("the session")
            .ipv4 = None;
        assert_eq!(phase(&no_ipcp, wan), WanPhase::Connecting);
        let mut no_session = up.clone();
        Arc::make_mut(&mut no_session.pppoe).clear();
        assert_eq!(phase(&no_session, wan), WanPhase::Connecting);
        Arc::make_mut(&mut no_session.links)
            .get_mut("p0")
            .expect("p0")
            .carrier = false;
        assert_eq!(phase(&no_session, wan), WanPhase::Down);
        assert_eq!(reason(&no_session, wan), "no carrier");
    }
}
