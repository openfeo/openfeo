// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The World (SPEC §6.2): one immutable snapshot of config plus facts with a generation number,
//! and the pure logic around it: sticky port naming (§7.1), interface rename planning, and the
//! health report PID 1's heartbeat is gated on (§5.3). No tokio, no libc, no clocks: everything
//! here is unit-testable without a kernel (SPEC §13). The runtime around it lives in
//! `openfeo-runtime` (ADR-0009).

#![forbid(unsafe_code)]

pub mod dhcp4;
pub mod health;
pub mod mac;
pub mod portmap;
pub mod rename;
pub mod world;

pub use dhcp4::Dhcp4Fact;
pub use mac::MacAddr;
pub use world::{LinkFact, World};
