// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The API's snapshot of the router (SPEC §8.3): a pure view of the World plus the few facts
//! about the system the World does not hold. Like the reconcilers it is a function of a
//! `&World` and is tested against fixtures without a kernel.

use std::net::IpAddr;

use ipnet::IpNet;
use openfeo_config::load::{DEFAULT_DOMAIN, DEFAULT_HOSTNAME};
use openfeo_config::portname::parse_port_ref;
use openfeo_config::state::{
    AddressOrigin, AddressState, ConfigProblem, LanState, PortState, PortUse, PortUseKind, State,
    SystemState, WanKind, WanState,
};
use openfeo_config::{Lan, Wan, wan::Kind};
use openfeo_world::health::HealthView;
use openfeo_world::{AddrFact, WanPhase, World};

use crate::wan::{phase, reason};
use crate::{bridge_name, wan_netdev};

/// What the snapshot needs that the World does not hold, read when it is built.
#[derive(Debug, Clone)]
pub struct SystemFacts {
    /// The binary's version.
    pub version: String,
    /// Seconds since the kernel booted.
    pub uptime_secs: u64,
    /// Now, in milliseconds since the kernel booted (the clock the WAN statuses are stamped on).
    pub boot_ms: u64,
    /// Now, on the wall clock, in Unix milliseconds.
    pub now_unix_ms: u64,
    /// The heartbeat's latest view.
    pub health: HealthView,
    /// SHA-256 of the certificate the listener presents.
    pub tls_fingerprint: String,
    /// Why `config.toml` was refused, when it was.
    pub config_problem: Option<ConfigProblem>,
}

/// The snapshot of `world`.
#[must_use]
pub fn state(world: &World, system: &SystemFacts) -> State {
    State {
        generation: world.generation,
        system: Some(system_state(world, system)),
        ports: ports(world),
        wans: world
            .config
            .wans
            .iter()
            .map(|wan| wan_state(world, wan, system))
            .collect(),
        lans: world
            .config
            .lans
            .iter()
            .map(|lan| lan_state(world, lan, system))
            .collect(),
        addresses: world
            .addresses
            .iter()
            .map(|addr| address_state(world, addr))
            .collect(),
    }
}

fn system_state(world: &World, system: &SystemFacts) -> SystemState {
    let config = world.config.system.as_ref();
    let or_default = |value: Option<&str>, default: &str| {
        value
            .filter(|value| !value.is_empty())
            .unwrap_or(default)
            .to_owned()
    };
    SystemState {
        hostname: or_default(config.map(|s| s.hostname.as_str()), DEFAULT_HOSTNAME),
        domain: or_default(config.map(|s| s.domain.as_str()), DEFAULT_DOMAIN),
        version: system.version.clone(),
        uptime_secs: system.uptime_secs,
        time_synced: world.time.synced,
        healthy: system.health.healthy,
        unhealthy: system.health.unhealthy.clone(),
        tls_fingerprint: system.tls_fingerprint.clone(),
        config_problem: system.config_problem.clone(),
        // Filled from the World's pending change where the state is completed (Task 16).
        pending_config: None,
    }
}

fn ports(world: &World) -> Vec<PortState> {
    world
        .ports
        .ports
        .iter()
        .map(|port| {
            let link = world.links.get(&port.name);
            let mut uses = Vec::new();
            for wan in world.config.wans.iter().filter(|wan| wan.port == port.name) {
                uses.push(PortUse {
                    kind: PortUseKind::Wan.into(),
                    name: wan.name.clone(),
                    vlan: wan.vlan,
                });
            }
            for lan in &world.config.lans {
                for member in lan.ports.iter().filter_map(|member| parse_port_ref(member)) {
                    if member.port == port.name {
                        uses.push(PortUse {
                            kind: PortUseKind::Lan.into(),
                            name: lan.name.clone(),
                            vlan: member.vlan.map_or(0, u32::from),
                        });
                    }
                }
            }
            PortState {
                name: port.name.clone(),
                id: port.id.clone(),
                mac: link
                    .and_then(|link| link.mac)
                    .map(|mac| mac.to_string())
                    .unwrap_or_default(),
                carrier: link.is_some_and(|link| link.carrier),
                speed_mbps: link.and_then(|link| link.speed_mbps),
                uses,
            }
        })
        .collect()
}

fn wan_state(world: &World, wan: &Wan, system: &SystemFacts) -> WanState {
    let netdev = wan_netdev(wan);
    let lease = world.dhcp4.get(&wan.name);
    let session = world
        .pppoe
        .get(&wan.name)
        .and_then(|session| session.ipv4.as_ref());
    let (kind, ipv4, ipv4_peer, gateway4) = match &wan.kind {
        Some(Kind::Static(config)) => (
            WanKind::Static,
            config.address.clone(),
            String::new(),
            config.gateway.clone(),
        ),
        Some(Kind::Dhcp(_)) => (
            WanKind::Dhcp,
            lease
                .map(|lease| lease.address.to_string())
                .unwrap_or_default(),
            String::new(),
            lease
                .and_then(|lease| {
                    lease.gateway.or_else(|| {
                        lease
                            .routes
                            .iter()
                            .find(|(dst, _)| dst.prefix_len() == 0)
                            .map(|(_, via)| *via)
                    })
                })
                .map(|gateway| gateway.to_string())
                .unwrap_or_default(),
        ),
        Some(Kind::Pppoe(_)) => (
            WanKind::Pppoe,
            session
                .map(|ipv4| ipv4.local.to_string())
                .unwrap_or_default(),
            session
                .and_then(|ipv4| ipv4.peer)
                .map(|peer| peer.to_string())
                .unwrap_or_default(),
            String::new(),
        ),
        None => (
            WanKind::Unspecified,
            String::new(),
            String::new(),
            String::new(),
        ),
    };
    let ipv6 = world
        .ipv6
        .get(&wan.name)
        .and_then(|fact| fact.addresses.first())
        .or_else(|| {
            world
                .dhcp6
                .get(&wan.name)
                .and_then(|fact| fact.addresses.first())
        })
        .map(|address| address.net.to_string())
        .unwrap_or_default();
    let mut ipv6_prefixes: Vec<String> = wan
        .ipv6
        .iter()
        .filter(|ipv6| !ipv6.prefix.is_empty())
        .map(|ipv6| ipv6.prefix.clone())
        .collect();
    if let Some(fact) = world.dhcp6.get(&wan.name) {
        ipv6_prefixes.extend(fact.prefixes.iter().map(|prefix| prefix.net.to_string()));
    }
    let status = world.wan_status.get(&wan.name);
    WanState {
        name: wan.name.clone(),
        kind: kind.into(),
        port: wan.port.clone(),
        vlan: wan.vlan,
        mtu: world.links.get(&netdev).map_or(0, |link| link.mtu),
        default4: world.has_default(false, &netdev),
        default6: world.has_default(true, &netdev),
        interface: netdev,
        phase: pb_phase(phase(world, wan)).into(),
        reason: reason(world, wan),
        phase_since_unix_ms: status.map(|status| {
            system
                .now_unix_ms
                .saturating_sub(system.boot_ms.saturating_sub(status.since_boot_ms))
        }),
        ipv4,
        ipv4_peer,
        gateway4,
        ipv6,
        ipv6_prefixes,
    }
}

fn pb_phase(phase: WanPhase) -> openfeo_config::state::WanPhase {
    match phase {
        WanPhase::Down => openfeo_config::state::WanPhase::Down,
        WanPhase::Connecting => openfeo_config::state::WanPhase::Connecting,
        WanPhase::Up => openfeo_config::state::WanPhase::Up,
    }
}

fn lan_state(world: &World, lan: &Lan, system: &SystemFacts) -> LanState {
    let interface = bridge_name(&lan.name);
    let tags: Vec<Option<u16>> = lan
        .ports
        .iter()
        .map(|member| parse_port_ref(member).and_then(|member| member.vlan))
        .collect();
    let vlan = match tags.first() {
        Some(Some(first)) if tags.iter().all(|tag| *tag == Some(*first)) => Some(u32::from(*first)),
        _ => None,
    };
    let pool_size = lan
        .dhcp
        .as_ref()
        .and_then(|dhcp| {
            let start: std::net::Ipv4Addr = dhcp.range.first()?.parse().ok()?;
            let end: std::net::Ipv4Addr = dhcp.range.get(1)?.parse().ok()?;
            u32::from(end).checked_sub(u32::from(start))?.checked_add(1)
        })
        .unwrap_or(0);
    let leases = world.leases.get(&lan.name).map_or(0, |leases| {
        leases
            .iter()
            .filter(|lease| lease.expires_unix.saturating_mul(1000) > system.now_unix_ms)
            .count()
    });
    LanState {
        name: lan.name.clone(),
        members: lan.ports.clone(),
        ipv4: lan.ipv4.clone(),
        ipv6: world
            .addresses
            .iter()
            .filter(|addr| addr.ifname == interface && is_global_v6(addr.net))
            .map(|addr| addr.net.to_string())
            .collect(),
        interface,
        vlan,
        dhcp: lan.dhcp.is_some(),
        pool_size,
        leases: u32::try_from(leases).unwrap_or(u32::MAX),
        reaches: if lan.reaches.is_empty() {
            vec!["wan".to_owned()]
        } else {
            lan.reaches.clone()
        },
    }
}

fn is_link_local(net: IpNet) -> bool {
    matches!(net.addr(), IpAddr::V6(addr) if addr.segments()[0] & 0xffc0 == 0xfe80)
}

fn is_global_v6(net: IpNet) -> bool {
    matches!(net, IpNet::V6(_)) && !is_link_local(net)
}

fn address_state(world: &World, addr: &AddrFact) -> AddressState {
    AddressState {
        interface: addr.ifname.clone(),
        address: addr.net.to_string(),
        peer: addr.peer.map(|peer| peer.to_string()).unwrap_or_default(),
        origin: origin(world, addr).into(),
        deprecated: addr.deprecated,
    }
}

/// Where an address came from, by the fact that explains it; the first that does wins.
fn origin(world: &World, addr: &AddrFact) -> AddressOrigin {
    if is_link_local(addr.net) {
        return AddressOrigin::LinkLocal;
    }
    let ip = addr.net.addr();
    for wan in &world.config.wans {
        if wan_netdev(wan) != addr.ifname {
            continue;
        }
        if world
            .dhcp4
            .get(&wan.name)
            .is_some_and(|lease| IpAddr::V4(lease.address.addr()) == ip)
        {
            return AddressOrigin::Dhcp;
        }
        if world
            .pppoe
            .get(&wan.name)
            .and_then(|session| session.ipv4.as_ref())
            .is_some_and(|ipv4| IpAddr::V4(ipv4.local) == ip)
        {
            return AddressOrigin::Ppp;
        }
        if world.ipv6.get(&wan.name).is_some_and(|fact| {
            fact.addresses
                .iter()
                .any(|learned| IpAddr::V6(learned.net.addr()) == ip)
        }) {
            return AddressOrigin::RouterAdvertisement;
        }
    }
    if let IpAddr::V6(v6) = ip {
        if world.ula.is_some_and(|ula| ula.contains(&v6)) {
            return AddressOrigin::Ula;
        }
        if world
            .dhcp6
            .values()
            .any(|fact| fact.prefixes.iter().any(|prefix| prefix.net.contains(&v6)))
        {
            return AddressOrigin::DelegatedPrefix;
        }
    }
    AddressOrigin::Config
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use openfeo_config::{Config, PortMap};

    use super::*;
    use crate::derive::derive;
    use crate::fixtures;
    use crate::wan::tests::lit;

    fn system() -> SystemFacts {
        SystemFacts {
            version: "0.4.0".into(),
            uptime_secs: 3_600,
            boot_ms: 3_600_000,
            now_unix_ms: 1_794_300_000_000,
            health: HealthView {
                healthy: true,
                unhealthy: vec![],
            },
            tls_fingerprint: "AB:CD".into(),
            config_problem: None,
        }
    }

    /// `world` with these addresses in the kernel, and its statuses stamped at `boot_ms`.
    fn seen(mut world: World, addresses: &[(&str, &str)], boot_ms: u64) -> World {
        world.addresses = Arc::new(
            addresses
                .iter()
                .map(|(ifname, net)| AddrFact {
                    ifname: (*ifname).to_owned(),
                    net: net.parse().expect("a CIDR"),
                    peer: None,
                    deprecated: false,
                })
                .collect(),
        );
        derive(
            &World::new(Config::default(), PortMap::default()),
            &mut world,
            boot_ms,
        );
        world
    }

    #[test]
    fn the_dhcp_world_reports_wan0_up_with_its_lease_and_when() {
        let world = seen(
            lit(fixtures::dhcp_world(), "p0"),
            &[("p0", "203.0.113.100/24"), ("br-lan0", "192.168.1.1/24")],
            3_000_000,
        );
        let state = state(&world, &system());
        let wan = &state.wans[0];
        assert_eq!(
            (wan.name.as_str(), wan.phase()),
            ("wan0", openfeo_config::state::WanPhase::Up)
        );
        assert_eq!(wan.kind(), WanKind::Dhcp);
        assert_eq!(wan.ipv4, "203.0.113.100/24");
        assert_eq!(wan.gateway4, "203.0.113.1", "the classless default route's");
        assert_eq!(wan.reason, "");
        // Up for the last 600 s of the 3600 s the kernel has been up.
        assert_eq!(wan.phase_since_unix_ms, Some(1_794_300_000_000 - 600_000));
        assert!(wan.default4);
        assert!(!wan.default6);
        let system = state.system.as_ref().expect("system");
        assert_eq!(system.uptime_secs, 3_600);
        assert_eq!(
            (system.hostname.as_str(), system.domain.as_str()),
            ("openfeo", "home.arpa")
        );
        let lan = &state.lans[0];
        assert_eq!(
            (lan.name.as_str(), lan.interface.as_str(), lan.ipv4.as_str()),
            ("lan0", "br-lan0", "192.168.1.1/24")
        );
        assert_eq!(lan.pool_size, 101, "192.168.1.100 to .200");
        assert_eq!(lan.reaches, ["wan"]);
        let origin = |text: &str| {
            state
                .addresses
                .iter()
                .find(|a| a.address == text)
                .map(AddressState::origin)
        };
        assert_eq!(origin("203.0.113.100/24"), Some(AddressOrigin::Dhcp));
        assert_eq!(origin("192.168.1.1/24"), Some(AddressOrigin::Config));
    }

    #[test]
    fn a_wan_that_lost_its_lease_says_why() {
        let mut world = seen(lit(fixtures::dhcp_world_without_lease(), "p0"), &[], 100);
        world.set_wan_cause("wan0", "lease expired");
        let state = state(&world, &system());
        assert_eq!(
            state.wans[0].phase(),
            openfeo_config::state::WanPhase::Connecting
        );
        assert_eq!(state.wans[0].reason, "lease expired");
        assert_eq!(state.wans[0].ipv4, "");
    }

    #[test]
    fn a_port_carrying_a_lan_and_vlans_of_others_lists_them_all() {
        let state = state(&fixtures::vlans_world(), &system());
        let port = state.ports.iter().find(|p| p.name == "p2").expect("p2");
        let uses: Vec<(&str, u32)> = port
            .uses
            .iter()
            .map(|u| (u.name.as_str(), u.vlan))
            .collect();
        assert_eq!(uses, [("lan0", 0), ("guest", 223), ("trusted", 224)]);
        assert!(port.uses.iter().all(|u| u.kind() == PortUseKind::Lan));
        let wan_port = state.ports.iter().find(|p| p.name == "p0").expect("p0");
        assert_eq!(wan_port.uses[0].kind(), PortUseKind::Wan);
        let guest = state
            .lans
            .iter()
            .find(|l| l.name == "guest")
            .expect("guest");
        assert_eq!(guest.vlan, Some(223));
        let trusted = state
            .lans
            .iter()
            .find(|l| l.name == "trusted")
            .expect("trusted");
        assert_eq!(trusted.vlan, None, "a tagged member and an untagged one");
    }

    #[test]
    fn each_address_says_where_it_came_from() {
        let world = seen(
            fixtures::pd_world(),
            &[
                ("br-lan0", "192.168.1.1/24"),
                ("br-lan0", "2001:db8:100:1::1/64"),
                ("br-lan0", "fd12:3456:789a:1::1/64"),
                ("br-lan0", "fe80::1/64"),
            ],
            0,
        );
        let state = state(&world, &system());
        let origin = |text: &str| {
            state
                .addresses
                .iter()
                .find(|a| a.address.starts_with(text))
                .map(AddressState::origin)
        };
        assert_eq!(origin("192.168."), Some(AddressOrigin::Config));
        assert_eq!(
            origin("2001:db8:100:1:"),
            Some(AddressOrigin::DelegatedPrefix)
        );
        assert_eq!(origin("fd12:3456:789a:"), Some(AddressOrigin::Ula));
        assert_eq!(origin("fe80:"), Some(AddressOrigin::LinkLocal));
        let lan0 = state.lans.iter().find(|l| l.name == "lan0").expect("lan0");
        assert_eq!(
            lan0.ipv6,
            ["2001:db8:100:1::1/64", "fd12:3456:789a:1::1/64"],
            "global addresses on the bridge, no link-local"
        );
        assert!(
            state.wans[0]
                .ipv6_prefixes
                .contains(&"2001:db8:100::/56".to_owned())
        );
    }

    #[test]
    fn leases_in_use_are_those_not_yet_expired() {
        let world = fixtures::static_world_with_leases();
        assert_eq!(state(&world, &system()).lans[0].leases, 2);
        let mut later = system();
        later.now_unix_ms = 1_800_000_000_001;
        assert_eq!(state(&world, &later).lans[0].leases, 0);
    }

    #[test]
    fn snapshots_of_the_fixtures() {
        for (name, world) in [
            ("first_boot", fixtures::first_boot_world()),
            ("dhcp", lit(fixtures::dhcp_world(), "p0")),
            ("pppoe", fixtures::pppoe_world()),
            ("pd", fixtures::pd_world()),
            ("vlans", fixtures::vlans_world()),
        ] {
            let world = seen(world, &[("p0", "203.0.113.100/24")], 1_000);
            insta::assert_yaml_snapshot!(name, state(&world, &system()));
        }
    }
}
