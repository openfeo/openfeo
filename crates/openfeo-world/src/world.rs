// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The snapshot every reconciler reads (SPEC §6.2): config, the live port map and link facts,
//! behind `Arc`s so a new generation is cheap to make and share.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use openfeo_config::{Config, PortMap};

use ipnet::Ipv6Net;

use crate::{
    Dhcp4Fact, KernelRoute, LeaseFact, MacAddr, PppoeFact, TimeFact, WanDhcp6Fact, WanIpv6Fact,
};

/// What the netlink monitor knows about one interface (SPEC §7.1: link state is a fact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkFact {
    /// Kernel interface index.
    pub index: u32,
    /// Kernel interface name.
    pub name: String,
    /// Administratively up (`IFF_UP`).
    pub up: bool,
    /// Carrier present (`IFF_LOWER_UP`).
    pub carrier: bool,
    /// Hardware address, when the link has one.
    pub mac: Option<MacAddr>,
    /// MTU in bytes.
    pub mtu: u32,
    /// The kernel's link-local IPv6 address on the link, once it has made one.
    pub link_local6: Option<std::net::Ipv6Addr>,
}

/// One immutable snapshot. Reconcilers are `fn(&World) -> Desired`.
#[derive(Debug, Clone, PartialEq)]
pub struct World {
    /// Monotonic; bumped on every change.
    pub generation: u64,
    /// The running configuration.
    pub config: Arc<Config>,
    /// The live port map (identity to `pN`).
    pub ports: Arc<PortMap>,
    /// Link facts keyed by interface name.
    pub links: Arc<BTreeMap<String, LinkFact>>,
    /// DHCPv4 leases keyed by WAN name (SPEC §7.2).
    pub dhcp4: Arc<BTreeMap<String, Dhcp4Fact>>,
    /// The leases each LAN's DHCPv4 server has granted, keyed by LAN name, ascending by
    /// address (SPEC §7.6).
    pub leases: Arc<BTreeMap<String, Vec<LeaseFact>>>,
    /// The clock's state (SPEC §7.10).
    pub time: TimeFact,
    /// What each WAN's router-advertisement client learned, keyed by WAN name (SPEC §7.3).
    pub ipv6: Arc<BTreeMap<String, WanIpv6Fact>>,
    /// The default routes the kernel holds in the main table (ADR-0019).
    pub routes: Arc<BTreeSet<KernelRoute>>,
    /// What each WAN's DHCPv6 client holds, keyed by WAN name (SPEC §7.3).
    pub dhcp6: Arc<BTreeMap<String, WanDhcp6Fact>>,
    /// Every PPPoE WAN's session, by WAN name, while it exists (SPEC §7.2).
    pub pppoe: Arc<BTreeMap<String, PppoeFact>>,
    /// The router's ULA /48 (`identity/ula`), once loaded; `None` when it could not be kept.
    pub ula: Option<Ipv6Net>,
}

impl World {
    /// Generation 0 with no facts yet.
    #[must_use]
    pub fn new(config: Config, ports: PortMap) -> Self {
        World {
            generation: 0,
            config: Arc::new(config),
            ports: Arc::new(ports),
            links: Arc::new(BTreeMap::new()),
            dhcp4: Arc::new(BTreeMap::new()),
            leases: Arc::new(BTreeMap::new()),
            time: TimeFact::default(),
            ipv6: Arc::new(BTreeMap::new()),
            routes: Arc::new(BTreeSet::new()),
            dhcp6: Arc::new(BTreeMap::new()),
            pppoe: Arc::new(BTreeMap::new()),
            ula: None,
        }
    }

    /// Whether the kernel holds a default route of the family through `ifname`: the gate a
    /// learned fact waits behind (ADR-0019).
    #[must_use]
    pub fn has_default(&self, v6: bool, ifname: &str) -> bool {
        self.routes
            .iter()
            .any(|route| route.v6 == v6 && route.ifname == ifname && route.dst.is_none())
    }

    /// Whether the kernel can send to `addr` through `ifname`: a default route of its family
    /// there, or any route that covers it (a classless-only DHCPv4 lease installs no default,
    /// #32). The gate a learned resolver waits behind (ADR-0019).
    #[must_use]
    pub fn reaches(&self, addr: std::net::IpAddr, ifname: &str) -> bool {
        self.routes.iter().any(|route| {
            route.v6 == addr.is_ipv6()
                && route.ifname == ifname
                && route.dst.is_none_or(|dst| dst.contains(&addr))
        })
    }

    /// The MAC of the named link, if the monitor has reported one.
    #[must_use]
    pub fn mac_of(&self, name: &str) -> Option<MacAddr> {
        self.links.get(name).and_then(|link| link.mac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_config::{Config, PortMap};

    #[test]
    fn has_default_matches_family_and_interface() {
        let mut w = World::new(Config::default(), PortMap::default());
        assert!(!w.has_default(true, "p0"));
        w.routes = Arc::new(BTreeSet::from([
            KernelRoute {
                v6: true,
                ifname: "p0".to_owned(),
                dst: None,
            },
            KernelRoute {
                v6: false,
                ifname: "p1".to_owned(),
                dst: None,
            },
        ]));
        assert!(w.has_default(true, "p0"));
        assert!(!w.has_default(false, "p0"), "the family matters");
        assert!(!w.has_default(true, "p1"), "the interface matters");
        assert!(w.has_default(false, "p1"));
        assert!(w.ipv6.is_empty(), "no WAN IPv6 facts yet");
    }

    /// #32: a resolver is reachable through a default route or through any route that covers
    /// it (a classless-only DHCPv4 lease installs no default).
    #[test]
    fn reaches_needs_a_covering_or_default_route() {
        let mut w = World::new(Config::default(), PortMap::default());
        w.routes = Arc::new(BTreeSet::from([
            KernelRoute {
                v6: false,
                ifname: "p0".to_owned(),
                dst: None,
            },
            KernelRoute {
                v6: false,
                ifname: "p1".to_owned(),
                dst: Some("198.51.100.0/24".parse().unwrap()),
            },
        ]));
        let v4 = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert!(
            w.reaches(v4("192.0.2.53"), "p0"),
            "a default covers everything"
        );
        assert!(w.reaches(v4("198.51.100.53"), "p1"), "a covering route");
        assert!(!w.reaches(v4("192.0.2.53"), "p1"), "outside the only route");
        assert!(!w.reaches(v4("2001:db8::53"), "p0"), "the family matters");
        assert!(
            !w.reaches(v4("198.51.100.53"), "p2"),
            "the interface matters"
        );
    }

    #[test]
    fn world_new_starts_at_generation_zero_with_no_links() {
        let w = World::new(Config::default(), PortMap::default());
        assert_eq!(w.generation, 0);
        assert!(w.links.is_empty());
        assert_eq!(w.config.config_version, 0);
    }
}
