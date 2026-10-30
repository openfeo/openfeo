// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A DHCPv4 lease as a fact (SPEC §6.2, §7.2): what the client on a WAN's port holds, published
//! by the router for the reconcilers. Timers stay with the client; the fact is what to apply.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// The lease a WAN's DHCPv4 client holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp4Fact {
    /// The leased address and its prefix, for the WAN port.
    pub address: Ipv4Net,
    /// The server that granted it.
    pub server: Ipv4Addr,
    /// Option 3's first router; `None` when `routes` carry the routing (RFC 3442).
    pub gateway: Option<Ipv4Addr>,
    /// Classless static routes as `(destination, via)`; a `0.0.0.0/0` entry is the default.
    pub routes: Vec<(Ipv4Net, Ipv4Addr)>,
    /// DNS servers, for the forwarder.
    pub dns: Vec<Ipv4Addr>,
    /// The domain name the ISP gave.
    pub domain: Option<String>,
    /// Interface MTU, already checked to be sane; `None` leaves the port's alone.
    pub mtu: Option<u32>,
}
