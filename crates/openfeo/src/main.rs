// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The OpenFeO binary: PID 1 when it is process 1, the router child otherwise (SPEC §6.1).

#![forbid(unsafe_code)]

mod boot;
mod chaos;
mod cli;
mod dhcp4;
mod dhcp4_server;
mod dns;
mod heartbeat;
mod router;
mod state;
mod time;
mod version;

use openfeo_init::cmdline;

/// mimalloc as the global allocator (SPEC §2 Build): musl's own allocator is slow under async load.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> anyhow::Result<()> {
    let cli = cli::parse(std::env::args().skip(1));
    if std::process::id() == 1 {
        // The kernel hands init whatever command-line words it did not recognise, so argv may
        // hold things that are not our flags; only `--mode` matters here.
        let mode_flag = cli.as_ref().ok().and_then(|cli| cli.mode);
        openfeo_init::main(&version::version(), mode_flag, version::build_epoch());
    }
    let cli = cli?;
    if cli.print_version {
        println!("openfeo {}", version::version());
        return Ok(());
    }
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .ok()
        .and_then(|s| cmdline::parse(&s).ok())
        .unwrap_or_default();
    let mode = cli::resolve_mode(cli.mode, cmdline.mode);
    router::run(mode, &cmdline, &version::version())
}
