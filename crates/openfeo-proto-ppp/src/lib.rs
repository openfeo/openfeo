// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! PPPoE and PPP without sockets or clocks (SPEC §7.2, §13): the discovery codec and client
//! (RFC 2516, RFC 4638), the PPP frame, the RFC 1661 automaton and the control protocols a
//! residential line needs (LCP, PAP, CHAP-MD5, IPCP, IPV6CP), and the session core that runs
//! them in order. Nothing here opens a socket or reads a clock; `openfeo-net` drives the cores
//! over `AF_PACKET` and `/dev/ppp`, and `crates/openfeo` owns the facts.

#![forbid(unsafe_code)]

pub mod chap;
pub mod discovery;
pub mod frame;
pub mod fsm;
pub mod ipcp;
pub mod ipv6cp;
pub mod lcp;
mod md5;
pub mod pap;
pub mod pppoe;

/// Milliseconds on the driver's monotonic clock, as the other cores count time.
pub type Timestamp = u64;

/// One second of [`Timestamp`].
pub const MS: Timestamp = 1000;
