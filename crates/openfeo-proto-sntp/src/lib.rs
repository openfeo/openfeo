// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! SNTP without sockets or clocks (SPEC §7.10, §13): RFC 4330's 48-byte packet, the client state
//! machine that polls servers and decides how the clock should move, the steering rule
//! (ADR-0016), and the responder that answers LAN clients. Nothing here opens a socket or reads
//! a clock; `openfeo-net` drives it and applies its decisions.

#![forbid(unsafe_code)]

pub mod packet;
pub mod timestamp;

pub use packet::Packet;
pub use timestamp::{Now, NtpTimestamp, iso8601};
