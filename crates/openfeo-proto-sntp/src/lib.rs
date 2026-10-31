// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! SNTP without sockets or clocks (SPEC §7.10, §13): RFC 4330's 48-byte packet, the client state
//! machine that polls servers and decides how the clock should move, the steering rule
//! (ADR-0016), and the responder that answers LAN clients. Nothing here opens a socket or reads
//! a clock; `openfeo-net` drives it and applies its decisions.

#![forbid(unsafe_code)]

pub mod client;
pub mod discipline;
pub mod packet;
pub mod responder;
pub mod timestamp;

pub use packet::Packet;
pub use timestamp::{Now, NtpTimestamp, iso8601};

/// A time server as configured: an address, or a name the driver resolves through the box's own
/// forwarder before each poll interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerSpec {
    Address(std::net::Ipv4Addr),
    Name(openfeo_proto_dns::Name),
}
