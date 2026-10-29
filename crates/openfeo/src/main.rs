// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The OpenFeO binary: PID 1 when it is process 1, the router child otherwise (SPEC §6.1).

#![forbid(unsafe_code)]

mod chaos;
mod cli;
mod ports;
mod router;
mod version;

use openfeo_init::cmdline;

fn main() -> anyhow::Result<()> {
    if std::process::id() == 1 {
        openfeo_init::main(&version::version());
    }
    let cli = cli::parse(std::env::args().skip(1))?;
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
