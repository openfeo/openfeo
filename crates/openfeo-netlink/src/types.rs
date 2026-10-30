// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The cache's value types: what the monitor knows about links, addresses and routes, in the
//! shape the appliers compare against.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;

/// Routes OpenFeO owns carry this protocol (SPEC §6.2); nothing else is ever deleted.
pub const RTPROT_OPENFEO: u8 = 200;
/// The main routing table.
pub const TABLE_MAIN: u32 = 254;
/// `RT_SCOPE_UNIVERSE`: a global address.
pub const SCOPE_UNIVERSE: u8 = 0;
/// `RT_SCOPE_LINK`: a link-local address, kernel-originated, never ours.
pub const SCOPE_LINK: u8 = 253;

/// What a link is, from `IFLA_INFO_KIND`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinkKind {
    /// A software bridge.
    Bridge,
    /// One end of a veth pair.
    Veth,
    /// Anything else the kernel names (`vlan`, `dummy`, `tun`, …).
    Other(String),
}

/// One interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Kernel interface index.
    pub index: u32,
    /// Kernel interface name.
    pub name: String,
    /// `None` for physical and loopback devices, which carry no `IFLA_INFO_KIND`.
    pub kind: Option<LinkKind>,
    /// The index of the bridge (or other controller) this link is enslaved to.
    pub master: Option<u32>,
    /// `IFF_UP`.
    pub up: bool,
    /// `IFF_LOWER_UP`: carrier present.
    pub carrier: bool,
    /// Hardware address, when six bytes long.
    pub mac: Option<[u8; 6]>,
    /// MTU in bytes.
    pub mtu: u32,
}

/// One address on an interface.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr {
    /// Interface index.
    pub ifindex: u32,
    /// Address and prefix length.
    pub net: IpNet,
    /// `RT_SCOPE_*` ([`SCOPE_UNIVERSE`] is global).
    pub scope: u8,
}

/// One route.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Route {
    /// IPv6 route (needed when `dst` is `None`, the default route).
    pub v6: bool,
    /// Routing table.
    pub table: u32,
    /// Destination; `None` is the default route.
    pub dst: Option<IpNet>,
    /// Next hop.
    pub gateway: Option<IpAddr>,
    /// Output interface index.
    pub oif: Option<u32>,
    /// `RTPROT_*`; ours is [`RTPROT_OPENFEO`].
    pub protocol: u8,
    /// Metric.
    pub priority: u32,
}

/// Everything the monitor has seen, as of its last notification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cache {
    /// Links by interface index.
    pub links: BTreeMap<u32, Link>,
    /// Every address.
    pub addrs: BTreeSet<Addr>,
    /// Every route (all tables, both families).
    pub routes: BTreeSet<Route>,
}

impl Cache {
    /// The link called `name`, if any.
    #[must_use]
    pub fn link_by_name(&self, name: &str) -> Option<&Link> {
        self.links.values().find(|link| link.name == name)
    }
}
