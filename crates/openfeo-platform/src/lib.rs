// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Platform services for OpenFeO (SPEC §13 `openfeo-platform`): durable file writes (§5.2), the
//! boot-time kernel-option check (§4.2) and sysfs port enumeration (§7.1). Plain std, no async
//! runtime, no `unsafe`.

#![forbid(unsafe_code)]

pub mod atomic;
pub mod kconfig;
pub mod ports;
