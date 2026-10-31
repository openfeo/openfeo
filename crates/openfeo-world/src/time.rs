// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What the time task publishes about the clock (SPEC §7.10: "TLS verification and updates wait
//! for `time.synced`").

use std::net::Ipv4Addr;

/// The clock's state as a fact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeFact {
    /// A valid sample has been applied and none of the recent polls went unanswered.
    pub synced: bool,
    /// The server the last valid sample came from.
    pub source: Option<Ipv4Addr>,
    /// That server's stratum (we serve the LAN one below it).
    pub stratum: u8,
    /// The last measured offset, positive when the clock was behind.
    pub offset_ms: i64,
    /// Wall-clock seconds of the last valid sample.
    pub last_sync_unix: Option<i64>,
}
