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
    /// An 802.1Q VLAN sub-interface of another link (ADR-0017).
    Vlan,
    /// Anything else the kernel names (`dummy`, `tun`, …).
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
    /// `IFLA_LINK`: the lower device of a VLAN or other upper.
    pub parent: Option<u32>,
    /// `IFLA_VLAN_ID`: the 802.1Q id of a VLAN link.
    pub vlan_id: Option<u16>,
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

/// A route's type (`RTN_*`): everything OpenFeO adds is unicast except the blackholes for
/// declared public blocks (SPEC §7.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteKind {
    /// `RTN_UNICAST`, the kernel's default.
    #[default]
    Unicast,
    /// `RTN_BLACKHOLE`: silently dropped, no interface.
    Blackhole,
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
    /// Unicast, or a blackhole (which has no `oif`).
    pub kind: RouteKind,
    /// `RTA_PREFSRC`: the source address the kernel picks for locally generated traffic over
    /// the route (the router's loopback address on the IPv6 default, SPEC §7.4).
    pub pref_src: Option<IpAddr>,
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

    /// Drop the cached route a delete notification names. The kernel's notification carries
    /// the fields that identify the route (family, table, destination, gateway, interface,
    /// protocol, metric, kind) but not always the preferred source an IPv6 route was added
    /// with, so that field is not compared. `true` when something was removed.
    pub fn remove_route(&mut self, deleted: &Route) -> bool {
        let before = self.routes.len();
        self.routes.retain(|route| {
            route.v6 != deleted.v6
                || route.table != deleted.table
                || route.dst != deleted.dst
                || route.gateway != deleted.gateway
                || route.oif != deleted.oif
                || route.protocol != deleted.protocol
                || route.priority != deleted.priority
                || route.kind != deleted.kind
        });
        self.routes.len() != before
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    fn default6(pref_src: Option<IpAddr>) -> Route {
        Route {
            v6: true,
            table: TABLE_MAIN,
            dst: None,
            gateway: Some("fe80::1".parse().unwrap()),
            oif: Some(3),
            protocol: RTPROT_OPENFEO,
            priority: 10,
            kind: RouteKind::Unicast,
            pref_src,
        }
    }

    /// The kernel's delete notification for an IPv6 route does not carry the preferred source
    /// the route was added with; the cache drops the route by the fields that identify it.
    #[test]
    fn a_delete_without_the_preferred_source_removes_the_route_that_had_one() {
        let mut cache = Cache::default();
        cache
            .routes
            .insert(default6(Some("2001:db8:1::1".parse().unwrap())));
        assert!(cache.remove_route(&default6(None)));
        assert!(cache.routes.is_empty());
        cache.routes.insert(default6(None));
        let mut other = default6(None);
        other.priority = 20;
        assert!(
            !cache.remove_route(&other),
            "a different metric is another route"
        );
        assert_eq!(cache.routes.len(), 1);
    }
}
