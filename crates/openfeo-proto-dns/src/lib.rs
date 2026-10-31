// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! DNS without sockets (SPEC §6.3, §7.7, §13): names and the wire format, a TTL cache with
//! negative caching, and the forwarder's state machine. Nothing here opens a socket or reads a
//! clock; `openfeo-net` drives it. The parser is our own (ADR-0015); hickory-proto is the test
//! oracle only.

#![forbid(unsafe_code)]

pub mod cache;
pub mod forwarder;
pub mod name;
pub mod wire;

/// Milliseconds on the driver's monotonic clock.
pub type Timestamp = u64;

pub use name::Name;
pub use wire::{Header, Message, Question, RData, Record};
