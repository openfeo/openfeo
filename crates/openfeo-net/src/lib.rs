// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Drivers for the sans-IO protocol cores (SPEC §6.3, §13): sockets and timers around a state
//! machine that has neither. `unsafe` lives in [`sys`] alone (ADR-0013), where `AF_PACKET`
//! addresses are built, the ICMPv6 socket gets its filter and multicast membership, and the
//! PPP unit and channel are made over `/dev/ppp` and an `AF_PPPOX` socket; everything else is
//! safe Rust.

#![deny(unsafe_code)]

pub mod bound;
pub mod clock;
pub mod dhcp4;
pub mod dhcp4_server;
pub mod dhcp6;
pub mod dns;
pub mod ndp;
pub mod pppoe;
pub mod resolve;
pub mod sntp;
#[allow(unsafe_code)]
mod sys;
pub mod throttle;
