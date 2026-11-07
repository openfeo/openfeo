// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What a PPPoE WAN's session is (SPEC §7.2): published by the WAN task from discovery on,
//! filled in as LCP, IPCP and IPV6CP settle, withdrawn when the session ends. The kernel's
//! own view of the netdev (`LinkFact` for `ppp-<wan>`) is the other half every reconciler
//! reads; nothing is desired for the netdev until the World's links show it.

use std::net::Ipv4Addr;

use serde::Serialize;

/// IPCP's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PppIpv4 {
    pub local: Ipv4Addr,
    /// The peer's address from its own request; `None` for an unnumbered peer.
    pub peer: Option<Ipv4Addr>,
    /// Primary then secondary resolver.
    pub dns: Vec<Ipv4Addr>,
}

/// IPV6CP's outcome: the interface identifiers behind the two link-local addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PppIpv6 {
    pub local_iid: u64,
    pub peer_iid: u64,
}

/// One WAN's PPPoE session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PppoeFact {
    pub session_id: u16,
    pub ac_mac: [u8; 6],
    pub ac_name: String,
    /// The kernel's unit: its netdev is `ppp<unit>` until the applier renames it.
    pub unit: u32,
    /// The PPP payload both ends settled on: 1500 with RFC 4638, else 1492.
    pub mtu: u32,
    pub ipv4: Option<PppIpv4>,
    pub ipv6: Option<PppIpv6>,
    /// When the session came up, on the process monotonic clock.
    pub up_since_ms: u64,
}
