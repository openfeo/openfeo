// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! PID 1 for OpenFeO (SPEC §6.1): mounts, reaper, supervisor, watchdog.
//! Blocking std + libc only; no async runtime. `unsafe` is confined to `sys`.

pub mod cmdline;
