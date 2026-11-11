// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! World fixtures for the snapshot tests: the lab's three ports, first-boot defaults, and the
//! static configuration from `harness/fixtures/vm-static.toml`.

// Test support: compiled for tests only (here, or elsewhere through the `fixtures` feature), so
// a fixture that does not parse may panic.
#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    missing_docs
)]

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use openfeo_config::{Config, PortMap, PortMapEntry};
use openfeo_world::{
    Dhcp4Fact, KernelRoute, LeaseFact, Lifetimed, LinkFact, MacAddr, PppIpv4, PppIpv6, PppoeFact,
    TimeFact, WanDhcp6Fact, WanIpv6Fact, World,
};

pub const VM_STATIC: &str = include_str!("../../../harness/fixtures/vm-static.toml");
pub const VM_DHCP: &str = include_str!("../../../harness/fixtures/vm-dhcp.toml");
pub const VM_VLANS: &str = include_str!("../../../harness/fixtures/vm-vlans.toml");
pub const VM_PUBLIC: &str = include_str!("../../../harness/fixtures/vm-public.toml");
pub const VM_IPV6: &str = include_str!("../../../harness/fixtures/vm-ipv6.toml");
pub const VM_PD: &str = include_str!("../../../harness/fixtures/vm-pd.toml");
pub const VM_PPPOE: &str = include_str!("../../../harness/fixtures/vm-pppoe.toml");

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
                    link_local6: None,
                    speed_mbps: None,
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
        time: TimeFact::default(),
        ipv6: Arc::new(BTreeMap::new()),
        routes: Arc::new(std::collections::BTreeSet::new()),
        dhcp6: Arc::new(BTreeMap::new()),
        pppoe: Arc::new(BTreeMap::new()),
        ula: None,
        addresses: Arc::new(std::collections::BTreeSet::new()),
        wan_status: Arc::new(std::collections::BTreeMap::new()),
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

/// The leases `lan0`'s server has granted: the `nas` reservation taken up, and `pc` from the
/// pool.
pub fn lease_facts() -> BTreeMap<String, Vec<LeaseFact>> {
    BTreeMap::from([(
        "lan0".to_owned(),
        vec![
            LeaseFact {
                address: Ipv4Addr::new(192, 168, 1, 10),
                mac: MacAddr([0x52, 0x54, 0x00, 0xfe, 0x10, 0x10]),
                hostname: Some("nas".to_owned()),
                expires_unix: 1_800_000_000,
            },
            LeaseFact {
                address: Ipv4Addr::new(192, 168, 1, 120),
                mac: MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
                hostname: Some("pc".to_owned()),
                expires_unix: 1_800_000_000,
            },
        ],
    )])
}

/// [`static_world`] with [`lease_facts`].
pub fn static_world_with_leases() -> World {
    let mut world = static_world();
    world.leases = Arc::new(lease_facts());
    world
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
        ntp: vec![server],
        domain: Some("isp.example".to_owned()),
        mtu: Some(1400),
    }
}

/// `vm-dhcp.toml` with `wan0` holding [`dhcp_fact`].
pub fn dhcp_world() -> World {
    let mut world = dhcp_world_without_lease();
    world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), dhcp_fact())]));
    // The lease's default route is in the kernel, so its resolvers count (ADR-0019).
    world.routes = Arc::new(std::collections::BTreeSet::from([KernelRoute {
        v6: false,
        ifname: "p0".to_owned(),
        dst: None,
    }]));
    world
}

/// `vm-dhcp.toml` before any lease: the WAN port is up and has nothing else.
pub fn dhcp_world_without_lease() -> World {
    world(openfeo_config::file::parse(VM_DHCP).expect("fixture parses"))
}

/// The lab with its optional fourth port: `p0..p3`.
pub fn portmap4() -> PortMap {
    let mut map = portmap();
    map.ports.push(PortMapEntry {
        id: "pci-0000:00:06.0".to_owned(),
        name: "p3".to_owned(),
    });
    map
}

/// Link facts for `p0..p3`.
pub fn link_facts4() -> BTreeMap<String, LinkFact> {
    let mut facts = link_facts();
    facts.insert(
        "p3".to_owned(),
        LinkFact {
            index: 5,
            name: "p3".to_owned(),
            up: false,
            carrier: false,
            mac: Some(MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, 0x03])),
            mtu: 1500,
            link_local6: None,
            speed_mbps: None,
        },
    );
    facts
}

/// `vm-vlans.toml` on the four-port lab, before any lease: a tagged DHCP WAN on p0.101, lan0
/// untagged on p2, guest tagged 223 on p2, trusted tagged 224 on p2 and untagged on p3.
pub fn vlans_world() -> World {
    world4(VM_VLANS)
}

/// `vm-public.toml` on the four-port lab: the static WAN and lan0 of `vm-static.toml`, a public
/// DMZ on p3 from 192.0.2.232/29, a second block 192.0.2.248/29 fronting a forward, one rule.
pub fn public_world() -> World {
    world4(VM_PUBLIC)
}

fn world4(toml: &str) -> World {
    let mut world = world(openfeo_config::file::parse(toml).expect("fixture parses"));
    world.ports = Arc::new(portmap4());
    world.links = Arc::new(link_facts4());
    world
}

/// What the ISP's advertisements taught `wan0` in the IPv6 lab: the router at `fe80::1`, the
/// resolver and search domain, an MTU of 1500, no link prefix.
pub fn ipv6_fact() -> WanIpv6Fact {
    WanIpv6Fact {
        router: Some("fe80::1".parse().expect("an address")),
        addresses: Vec::new(),
        on_link: Vec::new(),
        routes: Vec::new(),
        dns: vec!["2001:db8:ffff::1".parse().expect("an address")],
        search: vec!["isp.example".to_owned()],
        mtu: Some(1500),
    }
}

/// `vm-ipv6.toml` on the four-port lab: p0 up with carrier and the facts of [`ipv6_fact`], the
/// bridges `br-lan0` and `br-dmz` known with MTU 1500, and no default route in the kernel yet.
pub fn ipv6_world_without_route() -> World {
    let mut world = world4(VM_IPV6);
    let mut links = link_facts4();
    if let Some(p0) = links.get_mut("p0") {
        p0.up = true;
        p0.carrier = true;
    }
    for (name, index) in [("br-lan0", 10), ("br-dmz", 11)] {
        links.insert(
            name.to_owned(),
            LinkFact {
                index,
                name: name.to_owned(),
                up: true,
                carrier: true,
                mac: Some(MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, 0x02])),
                mtu: 1500,
                link_local6: None,
                speed_mbps: None,
            },
        );
    }
    world.links = Arc::new(links);
    world.ipv6 = Arc::new(BTreeMap::from([("wan0".to_owned(), ipv6_fact())]));
    world.ula = Some(ULA.parse().expect("a prefix"));
    world
}

/// [`ipv6_world_without_route`] once the kernel holds both of `wan0`'s default routes.
pub fn ipv6_world() -> World {
    let mut world = ipv6_world_without_route();
    world.routes = Arc::new(std::collections::BTreeSet::from([
        KernelRoute {
            v6: false,
            ifname: "p0".to_owned(),
            dst: None,
        },
        KernelRoute {
            v6: true,
            ifname: "p0".to_owned(),
            dst: None,
        },
    ]));
    world
}

/// The lab router's ULA /48 (`identity/ula`), the same on every IPv6 world.
pub const ULA: &str = "fd12:3456:789a::/48";

/// A DHCPv6 binding of `prefix` and the address `2001:db8:ffff::1a4`, obtained at 10 s with
/// preferred 40 s and valid 60 s (the lab's Kea lifetimes), the ISP's resolver and domain.
pub fn dhcp6_fact_with(prefix: &str) -> WanDhcp6Fact {
    let lease = |net: &str| Lifetimed {
        net: net.parse().expect("a prefix"),
        obtained_ms: 10_000,
        preferred_secs: 40,
        valid_secs: 60,
    };
    WanDhcp6Fact {
        prefixes: vec![lease(prefix)],
        addresses: vec![lease("2001:db8:ffff::1a4/128")],
        deprecated: Vec::new(),
        dns: vec!["2001:db8:ffff::1".parse().expect("an address")],
        search: vec!["isp.example".to_owned()],
        server: vec![0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        restored: false,
    }
}

/// [`dhcp6_fact_with`] for the lab's first delegation pool, `2001:db8:100::/56`.
pub fn dhcp6_fact() -> WanDhcp6Fact {
    dhcp6_fact_with("2001:db8:100::/56")
}

/// `vm-pd.toml` on the four-port lab: p0 up with carrier, the advertisement facts of
/// [`ipv6_fact`] and the delegation of [`dhcp6_fact`], the bridges `br-lan0` and `br-lan1`
/// known with MTU 1500, the ULA loaded, and both of `wan0`'s default routes in the kernel.
pub fn pd_world() -> World {
    let mut world = world4(VM_PD);
    let mut links = link_facts4();
    if let Some(p0) = links.get_mut("p0") {
        p0.up = true;
        p0.carrier = true;
    }
    for (name, index) in [("br-lan0", 10), ("br-lan1", 11)] {
        links.insert(
            name.to_owned(),
            LinkFact {
                index,
                name: name.to_owned(),
                up: true,
                carrier: true,
                mac: Some(MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, 0x02])),
                mtu: 1500,
                link_local6: None,
                speed_mbps: None,
            },
        );
    }
    world.links = Arc::new(links);
    world.ipv6 = Arc::new(BTreeMap::from([("wan0".to_owned(), ipv6_fact())]));
    world.dhcp6 = Arc::new(BTreeMap::from([("wan0".to_owned(), dhcp6_fact())]));
    world.ula = Some(ULA.parse().expect("a prefix"));
    world.routes = Arc::new(std::collections::BTreeSet::from([
        KernelRoute {
            v6: false,
            ifname: "p0".to_owned(),
            dst: None,
        },
        KernelRoute {
            v6: true,
            ifname: "p0".to_owned(),
            dst: None,
        },
    ]));
    world
}

/// The session the lab's access concentrator grants (`vm-pppoe.toml`): IPCP numbered us from
/// the ISP's pool with the ISP as peer and resolver, IPV6CP settled both identifiers.
pub fn pppoe_fact() -> PppoeFact {
    PppoeFact {
        session_id: 1,
        ac_mac: [0x52, 0x54, 0x00, 0xfe, 0x00, 0x01],
        ac_name: "isp".to_owned(),
        unit: 0,
        mtu: 1492,
        ipv4: Some(PppIpv4 {
            local: "203.0.113.100".parse().expect("an address"),
            peer: Some("203.0.113.1".parse().expect("an address")),
            dns: vec!["203.0.113.1".parse().expect("an address")],
        }),
        ipv6: Some(PppIpv6 {
            local_iid: 0x1234_5678_9abc_def0,
            peer_iid: 2,
        }),
        up_since_ms: 5_000,
    }
}

/// `vm-pppoe.toml` with the session up and the kernel showing `ppp-wan0`: p0 up with carrier,
/// the unit's netdev at index 9 with the negotiated MTU and the IPV6CP link-local, the router
/// learned over the link, both defaults through the netdev, the ULA loaded.
pub fn pppoe_world() -> World {
    let mut world = pppoe_world_without_link();
    let mut links = (*world.links).clone();
    links.insert(
        "ppp-wan0".to_owned(),
        LinkFact {
            index: 9,
            name: "ppp-wan0".to_owned(),
            up: true,
            carrier: true,
            mac: None,
            mtu: 1492,
            link_local6: Some("fe80::1234:5678:9abc:def0".parse().expect("an address")),
            speed_mbps: None,
        },
    );
    world.links = Arc::new(links);
    world.ipv6 = Arc::new(BTreeMap::from([("wan0".to_owned(), ipv6_fact())]));
    world.routes = Arc::new(std::collections::BTreeSet::from([
        KernelRoute {
            v6: false,
            ifname: "ppp-wan0".to_owned(),
            dst: None,
        },
        KernelRoute {
            v6: true,
            ifname: "ppp-wan0".to_owned(),
            dst: None,
        },
    ]));
    world
}

/// `vm-pppoe.toml` with the session fact published but the kernel not yet showing the unit's
/// netdev: nothing may be desired for `ppp-wan0`.
pub fn pppoe_world_without_link() -> World {
    let mut world = world(openfeo_config::file::parse(VM_PPPOE).expect("fixture parses"));
    let mut links = link_facts();
    if let Some(p0) = links.get_mut("p0") {
        p0.up = true;
        p0.carrier = true;
    }
    world.links = Arc::new(links);
    world.pppoe = Arc::new(BTreeMap::from([("wan0".to_owned(), pppoe_fact())]));
    world.ula = Some(ULA.parse().expect("a prefix"));
    world
}
