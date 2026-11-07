// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired links (SPEC §7.1): one bridge `br-<lan>` per LAN with VLAN filtering on, its members
//! enslaved and up, bridge MAC = lowest member MAC; a tagged member or a tagged WAN is an 802.1Q
//! sub-interface `pN.V` of its port (ADR-0017); every port with a role up, every port without one
//! down and free. Logical names never reach the kernel.

use std::collections::{BTreeMap, BTreeSet};

use openfeo_config::portname::{parse_port_ref, vlan_ifname};
use openfeo_config::rules;
use openfeo_config::wan;
use openfeo_world::{MacAddr, World};
use serde::Serialize;

use crate::{bridge_name, wan_ifname};

/// One LAN bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredBridge {
    /// `br-<lan>`.
    pub name: String,
    /// Always on (SPEC §7.1): a tagged frame for a VLAN no LAN carries is dropped here.
    pub vlan_filtering: bool,
    /// The lowest member MAC, when the facts know one (a sub-interface's is its parent's).
    pub mac: Option<MacAddr>,
    /// Interface names enslaved to it: ports and `pN.V` sub-interfaces.
    pub members: BTreeSet<String>,
    /// Always up.
    pub up: bool,
}

/// What a desired port is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PortKind {
    /// A physical port `pN` from the port map.
    Physical,
    /// An 802.1Q sub-interface `pN.V` of a physical port, created by the router (ADR-0017).
    Vlan {
        /// The physical port.
        parent: String,
        /// The VLAN id.
        id: u16,
    },
}

/// One port: physical, or a VLAN sub-interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredPort {
    /// `pN` or `pN.V`.
    pub name: String,
    /// Physical or VLAN.
    pub kind: PortKind,
    /// Up iff it has a role (WAN, member of a LAN, or parent of a sub-interface with one).
    pub up: bool,
    /// The bridge it belongs to, for LAN members.
    pub master: Option<String>,
    /// A DHCP WAN's lease MTU (SPEC §7.2), or [`DEFAULT_MTU`] once the lease is gone; `None`
    /// leaves the kernel's alone (static WANs, LAN members, parents of tagged WANs).
    pub mtu: Option<u32>,
    /// The port of a WAN with `[wans.ipv6]`: its link-local address is a stable-privacy one
    /// from the persisted secret, written before the port comes up (SPEC §7.3).
    pub ipv6_stable_privacy: bool,
}

/// The MTU a DHCP WAN port returns to when its lease (and the MTU it carried) is gone.
pub const DEFAULT_MTU: u32 = 1500;

/// The MTU a PPPoE WAN's port (and a tagged one's parent) is asked for, so a 1500-byte PPP
/// payload fits under the 8 bytes of PPPoE and PPP (RFC 4638); a NIC that refuses stays at 1500
/// and nothing above 1492 is offered (SPEC §7.2).
pub const PPPOE_PORT_MTU: u32 = 1508;

/// A PPPoE session's netdev: the kernel's `ppp<unit>`, to be renamed `ppp-<wan>`, sized and
/// brought up by the applier (ADR-0023).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredPpp {
    /// The kernel's unit number: the netdev is `ppp<unit>` until renamed.
    pub unit: u32,
    /// The negotiated PPP payload: the netdev's MTU.
    pub mtu: u32,
}

/// Everything the links applier makes true.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DesiredLinks {
    /// Bridges by name.
    pub bridges: BTreeMap<String, DesiredBridge>,
    /// Every known port by name.
    pub ports: BTreeMap<String, DesiredPort>,
    /// PPPoE sessions' netdevs by their final name (`ppp-<wan>`).
    pub ppp: BTreeMap<String, DesiredPpp>,
}

/// VLAN sub-interfaces by name: the physical port and the id.
type Vlans = BTreeMap<String, (String, u16)>;

/// The links the World calls for. Members and WANs whose physical port the port map does not
/// know are ignored (validation has already rejected such a config; defaults never produce one).
#[must_use]
pub fn links(world: &World) -> DesiredLinks {
    let known: BTreeSet<&str> = world.ports.names().collect();
    let mut desired = DesiredLinks::default();
    let mut master_of: BTreeMap<String, String> = BTreeMap::new();
    let mut vlans = Vlans::new();
    for lan in &world.config.lans {
        let name = bridge_name(&lan.name);
        let mut members = BTreeSet::new();
        let mut macs = Vec::new();
        for member in &lan.ports {
            let Some(port_ref) = parse_port_ref(member) else {
                continue;
            };
            if !known.contains(port_ref.port) {
                continue;
            }
            let ifname = match port_ref.vlan {
                None => port_ref.port.to_owned(),
                Some(id) => {
                    let ifname = vlan_ifname(port_ref.port, id);
                    vlans.insert(ifname.clone(), (port_ref.port.to_owned(), id));
                    ifname
                }
            };
            macs.extend(world.mac_of(port_ref.port));
            master_of.insert(ifname.clone(), name.clone());
            members.insert(ifname);
        }
        desired.bridges.insert(
            name.clone(),
            DesiredBridge {
                name,
                vlan_filtering: true,
                mac: macs.into_iter().min(),
                members,
                up: true,
            },
        );
    }
    let wans = wan_interfaces(world, &known, &mut vlans);
    // A PPPoE WAN's port carries no IPv6 of its own: the stable-privacy address belongs to the
    // PPP netdev's link-local, which IPV6CP settles.
    let ipv6_ports: BTreeSet<String> = world
        .config
        .wans
        .iter()
        .filter(|wan| known.contains(wan.port.as_str()) && !rules::is_pppoe(wan))
        .filter(|wan| {
            wan.ipv6
                .as_ref()
                .is_some_and(|ipv6| ipv6.mode != "disabled")
        })
        .map(crate::wan_ifname)
        .collect();
    for wan in &world.config.wans {
        if !known.contains(wan.port.as_str()) || !rules::is_pppoe(wan) {
            continue;
        }
        if let Some(fact) = world.pppoe.get(&wan.name) {
            desired.ppp.insert(
                rules::ppp_ifname(&wan.name),
                DesiredPpp {
                    unit: fact.unit,
                    mtu: fact.mtu,
                },
            );
        }
    }
    for port in world.ports.names() {
        let master = master_of.get(port).cloned();
        let has_upper = vlans.values().any(|(parent, _)| parent == port);
        desired.ports.insert(
            port.to_owned(),
            DesiredPort {
                name: port.to_owned(),
                kind: PortKind::Physical,
                up: master.is_some() || wans.contains_key(port) || has_upper,
                master,
                mtu: wans.get(port).copied().flatten(),
                ipv6_stable_privacy: ipv6_ports.contains(port),
            },
        );
    }
    for (ifname, (parent, id)) in vlans {
        let master = master_of.get(&ifname).cloned();
        let mtu = wans.get(ifname.as_str()).copied().flatten();
        let ipv6_stable_privacy = ipv6_ports.contains(&ifname);
        desired.ports.insert(
            ifname.clone(),
            DesiredPort {
                name: ifname,
                kind: PortKind::Vlan { parent, id },
                up: true,
                master,
                mtu,
                ipv6_stable_privacy,
            },
        );
    }
    desired
}

/// The WAN interfaces ([`wan_ifname`]) whose port is known, with the MTU rule: a DHCP WAN's MTU
/// is ours to set, the lease's while there is one and the default again when it is gone, so a
/// lease that lowered it does not outlive itself; a static WAN keeps the kernel's. A tagged WAN
/// registers its sub-interface in `vlans`.
fn wan_interfaces(
    world: &World,
    known: &BTreeSet<&str>,
    vlans: &mut Vlans,
) -> BTreeMap<String, Option<u32>> {
    let mut wans = BTreeMap::new();
    for wan in &world.config.wans {
        if !known.contains(wan.port.as_str()) {
            continue;
        }
        let ifname = wan_ifname(wan);
        if let Ok(id) = u16::try_from(wan.vlan)
            && id != 0
        {
            vlans.insert(ifname.clone(), (wan.port.clone(), id));
        }
        let mtu = match &wan.kind {
            Some(wan::Kind::Dhcp(_)) => Some(
                world
                    .dhcp4
                    .get(&wan.name)
                    .and_then(|fact| fact.mtu)
                    .unwrap_or(DEFAULT_MTU),
            ),
            // The port, and a tagged WAN's parent, carry 1508-byte frames for RFC 4638.
            Some(wan::Kind::Pppoe(_)) => {
                if ifname != wan.port {
                    wans.insert(wan.port.clone(), Some(PPPOE_PORT_MTU));
                }
                Some(PPPOE_PORT_MTU)
            }
            Some(wan::Kind::Static(_)) | None => None,
        };
        wans.insert(ifname, mtu);
    }
    wans
}

#[cfg(test)]
mod tests {
    #[test]
    fn wan_netdev_is_the_port_or_ppp_dash_wan() {
        let world = crate::fixtures::pppoe_world();
        assert_eq!(crate::wan_ifname(&world.config.wans[0]), "p0");
        assert_eq!(crate::wan_netdev(&world.config.wans[0]), "ppp-wan0");
        let world = crate::fixtures::static_world();
        assert_eq!(crate::wan_netdev(&world.config.wans[0]), "p0");
    }

    #[test]
    fn a_pppoe_wan_port_wants_1508_and_its_unit_netdev_is_desired() {
        let desired = links(&crate::fixtures::pppoe_world());
        assert_eq!(
            desired.ports["p0"].mtu,
            Some(1508),
            "room for a 1500-byte payload"
        );
        assert!(desired.ports["p0"].up);
        assert!(
            !desired.ports["p0"].ipv6_stable_privacy,
            "no IPv6 on the port itself"
        );
        assert_eq!(
            desired.ppp.get("ppp-wan0"),
            Some(&DesiredPpp { unit: 0, mtu: 1492 })
        );
        let without = links(&crate::fixtures::pppoe_world_without_link());
        assert_eq!(
            without.ppp.get("ppp-wan0"),
            Some(&DesiredPpp { unit: 0, mtu: 1492 }),
            "the rename is wanted as soon as the unit exists"
        );
        insta::assert_yaml_snapshot!(desired);
    }

    #[test]
    fn a_tagged_pppoe_wan_raises_the_parent_to_1508_too() {
        let mut world = crate::fixtures::pppoe_world();
        let mut config = (*world.config).clone();
        config.wans[0].vlan = 101;
        world.config = std::sync::Arc::new(config);
        let desired = links(&world);
        assert_eq!(desired.ports["p0"].mtu, Some(1508));
        assert_eq!(desired.ports["p0.101"].mtu, Some(1508));
    }

    use super::*;

    #[test]
    fn only_the_ipv6_wan_port_asks_for_stable_privacy() {
        let desired = links(&crate::fixtures::ipv6_world());
        assert!(desired.ports["p0"].ipv6_stable_privacy);
        assert!(!desired.ports["p2"].ipv6_stable_privacy);
        assert!(!desired.ports["p3"].ipv6_stable_privacy);
        let desired = links(&crate::fixtures::static_world());
        assert!(desired.ports.values().all(|p| !p.ipv6_stable_privacy));
        let desired = links(&crate::fixtures::vlans_world());
        assert!(
            desired.ports.values().all(|p| !p.ipv6_stable_privacy),
            "a tagged WAN without [wans.ipv6]"
        );
    }
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
    fn tagged_members_become_vlan_ports_enslaved_to_their_lan() {
        let desired = links(&fixtures::vlans_world());
        let guest = &desired.ports["p2.223"];
        assert_eq!(
            guest.kind,
            PortKind::Vlan {
                parent: "p2".into(),
                id: 223
            }
        );
        assert_eq!(guest.master.as_deref(), Some("br-guest"));
        assert!(guest.up);
        assert_eq!(
            desired.bridges["br-trusted"]
                .members
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["p2.224", "p3"]
        );
        assert_eq!(
            desired.bridges["br-guest"].mac,
            Some(MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, 0x02])),
            "a sub-interface's MAC is its parent's"
        );
        assert_eq!(desired.ports["p2"].master.as_deref(), Some("br-lan0"));
        assert_eq!(desired.ports["p3"].master.as_deref(), Some("br-trusted"));
        assert_eq!(
            desired.ports["p2.224"].master.as_deref(),
            Some("br-trusted")
        );
        assert!(desired.ports["p1"].kind == PortKind::Physical && !desired.ports["p1"].up);
        insta::assert_yaml_snapshot!(desired);
    }

    #[test]
    fn a_tagged_wan_runs_on_its_sub_interface() {
        let world = fixtures::vlans_world();
        let desired = links(&world);
        let wan = &desired.ports["p0.101"];
        assert_eq!(
            wan.kind,
            PortKind::Vlan {
                parent: "p0".into(),
                id: 101
            }
        );
        assert!(wan.up && wan.master.is_none());
        assert_eq!(
            wan.mtu,
            Some(DEFAULT_MTU),
            "the DHCP MTU rule follows the WAN"
        );
        assert!(desired.ports["p0"].up, "the parent is up for its upper");
        assert_eq!(desired.ports["p0"].mtu, None);
        assert_eq!(crate::wan_ifname(&world.config.wans[0]), "p0.101");
        assert_eq!(
            crate::wan_ifname(&fixtures::static_world().config.wans[0]),
            "p0"
        );
    }

    #[test]
    fn missing_link_fact_gives_no_bridge_mac() {
        let mut world = fixtures::static_world();
        world.links = Arc::new(BTreeMap::new());
        assert_eq!(links(&world).bridges["br-lan0"].mac, None);
    }
}
