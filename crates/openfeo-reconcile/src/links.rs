// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired links (SPEC §7.1): one bridge `br-<lan>` per LAN with VLAN filtering on, its members
//! enslaved and up, bridge MAC = lowest member MAC; every port with a role up, every port without
//! one down and free. Logical names never reach the kernel.

use std::collections::{BTreeMap, BTreeSet};

use openfeo_config::wan;
use openfeo_world::{MacAddr, World};
use serde::Serialize;

use crate::bridge_name;

/// One LAN bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredBridge {
    /// `br-<lan>`.
    pub name: String,
    /// Always on (SPEC §7.1); LAN VLANs arrive later.
    pub vlan_filtering: bool,
    /// The lowest member MAC, when the facts know one.
    pub mac: Option<MacAddr>,
    /// Port names enslaved to it.
    pub members: BTreeSet<String>,
    /// Always up.
    pub up: bool,
}

/// One physical port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredPort {
    /// `pN`.
    pub name: String,
    /// Up iff it has a role (WAN, or member of a LAN).
    pub up: bool,
    /// The bridge it belongs to, for LAN members.
    pub master: Option<String>,
    /// A DHCP WAN's lease MTU (SPEC §7.2), or [`DEFAULT_MTU`] once the lease is gone; `None`
    /// leaves the kernel's alone (static WANs, LAN members).
    pub mtu: Option<u32>,
}

/// The MTU a DHCP WAN port returns to when its lease (and the MTU it carried) is gone.
pub const DEFAULT_MTU: u32 = 1500;

/// Everything the links applier makes true.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DesiredLinks {
    /// Bridges by name.
    pub bridges: BTreeMap<String, DesiredBridge>,
    /// Every known port by name.
    pub ports: BTreeMap<String, DesiredPort>,
}

/// The links the World calls for. Ports the port map does not know are ignored (validation has
/// already rejected such a config; defaults never produce one).
#[must_use]
pub fn links(world: &World) -> DesiredLinks {
    let known: BTreeSet<&str> = world.ports.names().collect();
    let mut desired = DesiredLinks::default();
    let mut master_of: BTreeMap<String, String> = BTreeMap::new();
    for lan in &world.config.lans {
        let name = bridge_name(&lan.name);
        let members: BTreeSet<String> = lan
            .ports
            .iter()
            .filter(|port| known.contains(port.as_str()))
            .cloned()
            .collect();
        let mac = members.iter().filter_map(|m| world.mac_of(m)).min();
        for member in &members {
            master_of.insert(member.clone(), name.clone());
        }
        desired.bridges.insert(
            name.clone(),
            DesiredBridge {
                name,
                vlan_filtering: true,
                mac,
                members,
                up: true,
            },
        );
    }
    let wan_ports: BTreeSet<&str> = world
        .config
        .wans
        .iter()
        .map(|wan| wan.port.as_str())
        .filter(|port| known.contains(port))
        .collect();
    // A DHCP WAN port's MTU is ours to set: the lease's while there is one, the default again
    // when it is gone, so a lease that lowered it does not outlive itself.
    let dhcp_wan_ports: BTreeSet<&str> = world
        .config
        .wans
        .iter()
        .filter(|wan| matches!(wan.kind, Some(wan::Kind::Dhcp(_))))
        .map(|wan| wan.port.as_str())
        .collect();
    let lease_mtu: BTreeMap<&str, u32> = world
        .config
        .wans
        .iter()
        .filter_map(|wan| {
            let mtu = world.dhcp4.get(&wan.name)?.mtu?;
            Some((wan.port.as_str(), mtu))
        })
        .collect();
    for port in world.ports.names() {
        let master = master_of.get(port).cloned();
        let up = master.is_some() || wan_ports.contains(port);
        let mtu = lease_mtu
            .get(port)
            .copied()
            .or_else(|| dhcp_wan_ports.contains(port).then_some(DEFAULT_MTU));
        desired.ports.insert(
            port.to_owned(),
            DesiredPort {
                name: port.to_owned(),
                up,
                master,
                mtu,
            },
        );
    }
    desired
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use openfeo_world::MacAddr;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn first_boot_bridges_every_port() {
        let desired = links(&fixtures::first_boot_world());
        let bridge = &desired.bridges["br-lan0"];
        assert_eq!(
            bridge
                .members
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["p0", "p1", "p2"]
        );
        assert!(bridge.vlan_filtering);
        assert_eq!(
            bridge.mac,
            Some(MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, 0x00]))
        );
        assert!(
            desired
                .ports
                .values()
                .all(|p| p.up && p.master.as_deref() == Some("br-lan0"))
        );
        insta::assert_yaml_snapshot!(desired);
    }

    #[test]
    fn static_wan_and_one_lan() {
        let desired = links(&fixtures::static_world());
        assert_eq!(desired.bridges.len(), 1);
        let bridge = &desired.bridges["br-lan0"];
        assert_eq!(
            bridge
                .members
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["p2"]
        );
        assert_eq!(
            bridge.mac,
            Some(MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, 0x02]))
        );
        assert!(desired.ports["p0"].up, "WAN port is up");
        assert_eq!(desired.ports["p0"].master, None);
        assert!(!desired.ports["p1"].up, "a port without a role stays down");
        assert_eq!(desired.ports["p1"].master, None);
        assert_eq!(desired.ports["p2"].master.as_deref(), Some("br-lan0"));
        insta::assert_yaml_snapshot!(desired);
    }

    #[test]
    fn dhcp_wan_port_takes_the_lease_mtu() {
        let desired = links(&fixtures::dhcp_world());
        assert_eq!(desired.ports["p0"].mtu, Some(1400));
        assert_eq!(desired.ports["p1"].mtu, None);
        assert_eq!(desired.ports["p2"].mtu, None);
        assert!(desired.ports["p0"].up);
        let before = links(&fixtures::dhcp_world_without_lease());
        assert_eq!(
            before.ports["p0"].mtu,
            Some(DEFAULT_MTU),
            "no lease: the default, so a lease's MTU is undone"
        );
        let static_world = links(&fixtures::static_world());
        assert_eq!(
            static_world.ports["p0"].mtu, None,
            "static WANs keep theirs"
        );
    }

    #[test]
    fn missing_link_fact_gives_no_bridge_mac() {
        let mut world = fixtures::static_world();
        world.links = Arc::new(BTreeMap::new());
        assert_eq!(links(&world).bridges["br-lan0"].mac, None);
    }
}
