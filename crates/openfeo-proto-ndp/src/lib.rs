// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Neighbour discovery without sockets or clocks (SPEC §7.3, §13; ADR-0018): the router
//! solicitation and advertisement codec with the options of RFC 4861, RFC 8106 and RFC 4191, the
//! WAN client core that learns the ISP's router and link facts, the LAN server core that
//! advertises a prefix, and the RFC 7217 stable identifier over an in-tree SHA-256. Nothing
//! here opens a socket or reads a clock; `openfeo-net` drives the cores.

#![forbid(unsafe_code)]

pub mod client;
pub mod iid;
pub mod server;
pub mod sha256;
pub mod wire;

/// Milliseconds on the driver's monotonic clock, as the other cores count time.
pub type Timestamp = u64;
