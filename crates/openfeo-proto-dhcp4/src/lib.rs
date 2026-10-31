// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! DHCPv4 without sockets (SPEC §6.3, §7.2, §13): the wire format shared by the client and the
//! M1 part 3 server, the IPv4/UDP encapsulation the raw-socket path needs before the client has
//! an address, RFC 4361 identifiers, and the client state machine. Nothing here opens a socket or
//! reads a clock; `openfeo-net` drives it.

#![forbid(unsafe_code)]

pub mod arp;
pub mod client;
pub mod identity;
pub mod server;
pub mod udp;
pub mod wire;

pub use client::{
    Client, ClientConfig, Input, Lease, LeaseError, Output, PARAMETERS, State, Timestamp, Unbound,
};
pub use server::{
    Destination, LeaseRecord, NakReason, Reservation, Server, ServerConfig, ServerEvent,
};
