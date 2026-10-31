// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! World fixtures for the snapshot tests: the lab's three ports, first-boot defaults, and the
//! static configuration from `harness/fixtures/vm-static.toml`.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use openfeo_config::{Config, PortMap, PortMapEntry};
use openfeo_world::{Dhcp4Fact, LinkFact, MacAddr, World};

pub const VM_STATIC: &str = include_str!("../../../harness/fixtures/vm-static.toml");
pub const VM_DHCP: &str = include_str!("../../../harness/fixtures/vm-dhcp.toml");

pub fn portmap() -> PortMap {
    PortMap {
        ports: ["pci-0000:00:03.0", "pci-0000:00:04.0", "pci-0000:00:05.0"]
            .iter()
            .enumerate()
            .map(|(i, id)| PortMapEntry {
                id: (*id).to_owned(),
                name: format!("p{i}"),
            })
            .collect(),
    }
}

/// Link facts for `p0..p2` with MACs `52:54:00:fe:00:0N`, all down.
pub fn link_facts() -> BTreeMap<String, LinkFact> {
    (0..3u8)
        .map(|i| {
            let name = format!("p{i}");
            (
                name.clone(),
                LinkFact {
                    index: 2 + u32::from(i),
                    name,
                    up: false,
                    carrier: false,
                    mac: Some(MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, i])),
                    mtu: 1500,
                },
            )
        })
        .collect()
}

fn world(config: Config) -> World {
    World {
        generation: 1,
        config: Arc::new(config),
        ports: Arc::new(portmap()),
        links: Arc::new(link_facts()),
        dhcp4: Arc::new(BTreeMap::new()),
        leases: Arc::new(BTreeMap::new()),
    }
}

/// No `config.toml`: every port in `lan0` at 192.168.1.1/24.
pub fn first_boot_world() -> World {
    world(Config::first_boot(&portmap()))
}

/// `vm-static.toml`: static WAN on p0, LAN on p2, p1 idle.
pub fn static_world() -> World {
    world(openfeo_config::file::parse(VM_STATIC).expect("fixture parses"))
}

/// The lease the lab's Kea hands out (`harness/fixtures/kea-dhcp4.json.tmpl`), as a fact:
/// classless routes carry the default route, so option 3 is ignored.
pub fn dhcp_fact() -> Dhcp4Fact {
    let server = Ipv4Addr::new(203, 0, 113, 1);
    Dhcp4Fact {
        address: "203.0.113.100/24".parse().expect("fixture"),
        server,
        gateway: None,
        routes: vec![
            ("0.0.0.0/0".parse().expect("fixture"), server),
            ("198.51.100.0/24".parse().expect("fixture"), server),
        ],
        dns: vec![server],
        domain: Some("isp.example".to_owned()),
        mtu: Some(1400),
    }
}

/// `vm-dhcp.toml` with `wan0` holding [`dhcp_fact`].
pub fn dhcp_world() -> World {
    let mut world = dhcp_world_without_lease();
    world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), dhcp_fact())]));
    world
}

/// `vm-dhcp.toml` before any lease: the WAN port is up and has nothing else.
pub fn dhcp_world_without_lease() -> World {
    world(openfeo_config::file::parse(VM_DHCP).expect("fixture parses"))
}
