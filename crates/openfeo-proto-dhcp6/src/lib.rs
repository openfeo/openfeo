// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! DHCPv6 without sockets or clocks (SPEC §7.3, §13): the wire format of RFC 8415 with the
//! options a delegating ISP and a stateless responder use, the WAN client core that asks for a
//! prefix and an address and keeps them renewed, and the responder core that answers an
//! Information-Request. Nothing here opens a socket or reads a clock; `openfeo-net` drives the
//! cores and `crates/openfeo` owns the facts and the files.

#![forbid(unsafe_code)]

pub mod client;
pub mod iaid;
pub mod wire;

/// Milliseconds on the driver's monotonic clock, as the other cores count time.
pub type Timestamp = u64;
