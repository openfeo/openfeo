// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Desired addresses and routes (SPEC §7.2 Static, §7.4): a LAN's address on its bridge, a static
//! WAN's address on its port and a default route via its gateway in the main table, tagged with
//! `RTPROT_OPENFEO` and carrying the WAN's priority as metric.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;
use openfeo_config::wan;
use openfeo_world::World;
use serde::Serialize;

use crate::{RTPROT_OPENFEO, TABLE_MAIN, bridge_name};

/// One address on one interface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DesiredAddr {
    /// Kernel interface name.
    pub ifname: String,
    /// Address and prefix.
    pub net: IpNet,
}

/// One route OpenFeO owns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DesiredRoute {
    /// Output interface.
    pub ifname: String,
    /// Destination; `None` is the default route.
    pub dst: Option<IpNet>,
    /// Next hop.
    pub gateway: Option<IpAddr>,
    /// Routing table ([`TABLE_MAIN`] until M6's per-WAN tables).
    pub table: u32,
    /// Always [`RTPROT_OPENFEO`].
    pub protocol: u8,
    /// Metric: the WAN's priority.
    pub priority: u32,
}

/// Everything the routing applier makes true.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DesiredRouting {
    /// Addresses.
    pub addrs: BTreeSet<DesiredAddr>,
    /// Routes.
    pub routes: BTreeSet<DesiredRoute>,
}

/// The addresses and routes the World calls for. A WAN whose port the map does not know, or
/// whose text does not parse, contributes nothing (validation already rejected it).
#[must_use]
pub fn routing(world: &World) -> DesiredRouting {
    let mut desired = DesiredRouting::default();
    for lan in &world.config.lans {
        if let Ok(net) = lan.ipv4.parse::<IpNet>() {
            desired.addrs.insert(DesiredAddr {
                ifname: bridge_name(&lan.name),
                net,
            });
        }
    }
    for wan_config in &world.config.wans {
        if world.ports.id_of(&wan_config.port).is_none() {
            continue;
        }
        if let Some(wan::Kind::Static(static_wan)) = &wan_config.kind {
            if let Ok(net) = static_wan.address.parse::<IpNet>() {
                desired.addrs.insert(DesiredAddr {
                    ifname: wan_config.port.clone(),
                    net,
                });
            }
            if let Ok(gateway) = static_wan.gateway.parse::<IpAddr>() {
                desired.routes.insert(DesiredRoute {
                    ifname: wan_config.port.clone(),
                    dst: None,
                    gateway: Some(gateway),
                    table: TABLE_MAIN,
                    protocol: RTPROT_OPENFEO,
                    priority: wan_config.priority,
                });
            }
        }
    }
    desired
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

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
        assert_eq!(route.ifname, "p0");
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
    fn first_boot_routing_has_only_the_lan_address() {
        let desired = routing(&fixtures::first_boot_world());
        assert_eq!(desired.addrs.len(), 1);
        assert_eq!(desired.addrs.iter().next().unwrap().ifname, "br-lan0");
        assert_eq!(desired.routes, BTreeSet::new());
        insta::assert_yaml_snapshot!(desired);
    }
}
