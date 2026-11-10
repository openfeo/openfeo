// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The snapshot every reconciler reads (SPEC §6.2): config, the live port map and link facts,
//! behind `Arc`s so a new generation is cheap to make and share.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use openfeo_config::{Config, PortMap};

use std::net::IpAddr;

use ipnet::{IpNet, Ipv6Net};

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
    /// Negotiated speed in Mbit/s, for a physical port with carrier whose driver says (SPEC §10).
    pub speed_mbps: Option<u32>,
}

/// One address the kernel holds (SPEC §6.2), whoever put it there.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AddrFact {
    /// Kernel interface name.
    pub ifname: String,
    /// Address and prefix length.
    pub net: IpNet,
    /// The far end of a point-to-point address.
    pub peer: Option<IpAddr>,
    /// The kernel no longer prefers it for new connections.
    pub deprecated: bool,
}

/// Where a WAN stands (SPEC §6.2): derived from carrier and its lease, session or address
/// until M6's probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanPhase {
    /// No carrier.
    Down,
    /// Carrier, and no lease or session yet.
    Connecting,
    /// Carrier and its lease, session or address.
    Up,
}

/// A WAN's phase, when it entered it, and why it last left `Up`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanStatusFact {
    /// Stamped where the World is published.
    pub phase: WanPhase,
    /// When it entered the phase, in milliseconds since the kernel booted.
    pub since_boot_ms: u64,
    /// The cause its task last gave for losing the lease or the session, in the console's words;
    /// cleared when it comes up.
    pub cause: Option<String>,
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
    /// Every address the kernel holds, from the netlink monitor.
    pub addresses: Arc<BTreeSet<AddrFact>>,
    /// Each configured WAN's status, kept by the publisher's derive step; a WAN's task writes
    /// only the cause.
    pub wan_status: Arc<BTreeMap<String, WanStatusFact>>,
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
            addresses: Arc::new(BTreeSet::new()),
            wan_status: Arc::new(BTreeMap::new()),
        }
    }

    /// Record why `wan` lost its lease or session, for the API to report (SPEC §6.2). The phase
    /// is the publisher's to stamp: a WAN with no status yet starts as down at boot.
    pub fn set_wan_cause(&mut self, wan: &str, cause: &str) {
        Arc::make_mut(&mut self.wan_status)
            .entry(wan.to_owned())
            .or_insert(WanStatusFact {
                phase: WanPhase::Down,
                since_boot_ms: 0,
                cause: None,
            })
            .cause = Some(cause.to_owned());
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
    fn a_cause_can_be_recorded_before_any_status_exists() {
        let mut world = World::new(Config::default(), PortMap::default());
        world.set_wan_cause("wan0", "nak");
        let status = &world.wan_status["wan0"];
        assert_eq!(
            (status.phase, status.cause.as_deref()),
            (WanPhase::Down, Some("nak"))
        );
        world.set_wan_cause("wan0", "lease expired");
        assert_eq!(
            world.wan_status["wan0"].cause.as_deref(),
            Some("lease expired")
        );
        assert_eq!(world.wan_status.len(), 1);
    }

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
