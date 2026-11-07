// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! DHCPv6 facts (SPEC §6.2, §7.3): what a WAN's client holds from the ISP's server, the
//! prefixes it is deprecating, and the resolvers it was given. Timers stay with the client;
//! the fact is what to apply. Moments are milliseconds on the process's monotonic clock
//! (`openfeo_runtime::clock::uptime_ms`), never the wall clock, so a clock step after SNTP
//! moves no lifetime.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use serde::Serialize;

/// A delegated prefix or an address with the lifetimes the server gave, counted from the
/// moment the Reply arrived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lifetimed {
    /// The prefix (`2001:db8:100::/56`) or the address as a `/128`.
    pub net: Ipv6Net,
    /// When the Reply arrived, monotonic milliseconds.
    pub obtained_ms: u64,
    /// Seconds from `obtained_ms`; `u32::MAX` is infinite.
    pub preferred_secs: u32,
    pub valid_secs: u32,
}

/// A prefix the ISP took back, kept for its deprecation (SPEC §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Deprecated {
    pub net: Ipv6Net,
    /// When the deprecation ends, monotonic milliseconds: the lower of two hours and the
    /// prefix's remaining valid lifetime at the moment it left the binding.
    pub until_ms: u64,
}

/// Everything a WAN's DHCPv6 client currently holds. Changes only when its content does; it
/// outlives the WAN's carrier, since the binding does.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct WanDhcp6Fact {
    /// Delegated prefixes (`IA_PD`).
    pub prefixes: Vec<Lifetimed>,
    /// Addresses for the WAN port (`IA_NA`).
    pub addresses: Vec<Lifetimed>,
    /// Prefixes being deprecated.
    pub deprecated: Vec<Deprecated>,
    /// DNS servers (option 23), for the forwarder.
    pub dns: Vec<Ipv6Addr>,
    /// The domain search list (option 24).
    pub search: Vec<String>,
    /// The server's DUID, for the console.
    pub server: Vec<u8>,
}
