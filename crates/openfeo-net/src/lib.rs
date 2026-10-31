// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Drivers for the sans-IO protocol cores (SPEC §6.3, §13): sockets and timers around a state
//! machine that has neither. `unsafe` lives in [`sys`] alone (ADR-0013), where `AF_PACKET`
//! addresses are built; everything else is safe Rust.

#![deny(unsafe_code)]

pub mod bound;
pub mod clock;
pub mod dhcp4;
pub mod dhcp4_server;
pub mod dns;
pub mod resolve;
pub mod sntp;
#[allow(unsafe_code)]
mod sys;
pub mod throttle;
