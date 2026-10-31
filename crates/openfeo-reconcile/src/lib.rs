// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Reconcilers (SPEC §6.2): pure functions from a `&World` to the desired kernel state of one
//! subsystem, unit-tested with snapshots and never touching tokio, sockets or clocks (SPEC §13).
//! Appliers in `openfeo-apply` diff these against the netlink monitor's cache.

#![forbid(unsafe_code)]

pub mod dhcp;
pub mod dns;
pub mod links;
pub mod nft;
pub mod routing;
pub mod sysctl;
pub mod time;

#[cfg(test)]
pub(crate) mod fixtures;

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
