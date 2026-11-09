// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! IPv6 facts (SPEC §6.2, §7.3): what a WAN's router-advertisement client has learned, and
//! which default routes the kernel holds (ADR-0019: a learned fact is acted on once the kernel
//! shows the route it needs). A fact is what to apply; an address carries the lifetimes the
//! kernel is told (#27), everything else leaves the fact when its lifetime lapses.

use std::net::Ipv6Addr;

use ipnet::{IpNet, Ipv6Net};

use crate::Lifetimed;

/// RFC 4191 router preference, as the client reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Preference {
    Low,
    Medium,
    High,
}

/// Everything a WAN currently knows from the ISP's advertisements. Changes only when its
/// content does; leaves the World with the WAN's carrier.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WanIpv6Fact {
    /// The default router's link-local address; `None` once its lifetime lapsed or it withdrew.
    pub router: Option<Ipv6Addr>,
    /// Addresses from prefixes advertised with the A flag, for the WAN port, with the lifetimes
    /// the kernel deprecates and drops them by.
    pub addresses: Vec<Lifetimed>,
    /// Prefixes advertised with the L flag: on-link routes through the WAN port.
    pub on_link: Vec<Ipv6Net>,
    /// Route information options: (prefix, via, preference).
    pub routes: Vec<(Ipv6Net, Ipv6Addr, Preference)>,
    /// RDNSS resolvers, in the order first seen.
    pub dns: Vec<Ipv6Addr>,
    /// DNSSL search names, in the order first seen.
    pub search: Vec<String>,
    /// The MTU option, for the WAN's IPv6 MTU.
    pub mtu: Option<u32>,
}

/// A unicast route the kernel holds in the main table through an interface, whatever installed
/// it (ADR-0019). `dst: None` is a default route.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelRoute {
    pub v6: bool,
    /// The output interface's name.
    pub ifname: String,
    /// The destination; `None` for a default route.
    pub dst: Option<IpNet>,
}
