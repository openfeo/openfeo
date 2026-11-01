// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Rootless QEMU + network-namespace harness for OpenFeO (SPEC §11, ADR-0006).
//!
//! The process enters a user, mount and network namespace of its own ([`sandbox`]), creates one
//! named network namespace per ISP and LAN with a tap device in each ([`netns`], [`tun`]), boots the
//! router kernel in QEMU with those taps as its ports ([`lab`]), and drives scenarios against the
//! serial console ([`scenario`]).

pub mod daemons;
pub mod lab;
pub mod lanclient;
pub mod lines;
pub mod netns;
pub mod nftlist;
pub mod nftprobe;
pub mod qemu;
pub mod qmp;
pub mod sandbox;
pub mod scenario;
pub mod statedisk;
pub mod tun;
pub mod vlanprobe;
