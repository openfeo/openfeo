// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Reconcilers (SPEC §6.2): pure functions from a `&World` to the desired kernel state of one
//! subsystem, unit-tested with snapshots and never touching tokio, sockets or clocks (SPEC §13).
//! Appliers in `openfeo-apply` diff these against the netlink monitor's cache.

#![forbid(unsafe_code)]

pub mod derive;
pub mod dhcp;
pub mod dhcp6_server;
pub mod dns;
pub mod lan6;
pub mod links;
pub mod nft;
pub mod public;
pub mod ra;
pub mod routing;
pub mod slices;
pub mod state;
pub mod sysctl;
pub mod time;
pub mod wan;

/// World fixtures for tests, this crate's and (with the `fixtures` feature) other crates'.
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;

/// Routes OpenFeO owns carry this protocol (SPEC §6.2). Mirrors `openfeo_netlink::RTPROT_OPENFEO`.
pub const RTPROT_OPENFEO: u8 = 200;
/// The main routing table. Mirrors `openfeo_netlink::TABLE_MAIN`.
pub const TABLE_MAIN: u32 = 254;
/// The one nftables table OpenFeO owns, `table inet openfeo` (SPEC §7.5).
pub const TABLE: &str = "openfeo";

/// The kernel name of a LAN's bridge (SPEC §7).
#[must_use]
pub fn bridge_name(lan: &str) -> String {
    format!("br-{lan}")
}

/// The kernel interface a WAN runs on (SPEC §7.2): its port, or the 802.1Q sub-interface `pN.V`
/// when `vlan` is set (ADR-0017). For a PPPoE WAN this is the port the PPPoE frames cross;
/// its IP interface is [`wan_netdev`].
#[must_use]
pub fn wan_ifname(wan: &openfeo_config::Wan) -> String {
    match u16::try_from(wan.vlan) {
        Ok(id) if id != 0 => openfeo_config::portname::vlan_ifname(&wan.port, id),
        _ => wan.port.clone(),
    }
}

/// The interface a WAN's IP traffic flows through: `ppp-<wan>` for a PPPoE WAN (the kernel's
/// unit, renamed, ADR-0023), the port or sub-interface for every other kind. Every reconciler
/// that means "the WAN's IP interface" reads this one.
#[must_use]
pub fn wan_netdev(wan: &openfeo_config::Wan) -> String {
    if openfeo_config::rules::is_pppoe(wan) {
        openfeo_config::rules::ppp_ifname(&wan.name)
    } else {
        wan_ifname(wan)
    }
}
