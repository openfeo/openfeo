// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What the DHCPv4 server publishes about each LAN's leases (SPEC §7.6: "published as facts
//! for DNS and the panel").

use std::net::Ipv4Addr;

use crate::MacAddr;

/// One active lease on a LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseFact {
    pub address: Ipv4Addr,
    pub mac: MacAddr,
    /// The reservation's name, else the client's sanitised one; what `<hostname>.<domain>`
    /// resolves to.
    pub hostname: Option<String>,
    /// Wall-clock expiry, seconds since the Unix epoch.
    pub expires_unix: u64,
}
