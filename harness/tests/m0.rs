// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M0 acceptance scenarios (SPEC §12), run inside the rootless sandbox. `harness = false`: this
//! binary is its own runner. An optional first argument filters scenarios by substring.

use std::process::ExitCode;

use openfeo_harness::lab::Lab;
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};

const SCENARIOS: &[Scenario] = &[Scenario {
    name: "lab_topology",
    run: lab_topology,
}];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("{err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

fn lab_topology(lab: &mut Lab) -> anyhow::Result<()> {
    anyhow::ensure!(
        lab.isp0
            .ip(&["-4", "addr", "show", "wan0"])?
            .contains("203.0.113.1/24")
    );
    anyhow::ensure!(
        lab.isp1
            .ip(&["-4", "addr", "show", "wan1"])?
            .contains("198.51.100.1/24")
    );
    anyhow::ensure!(lab.lan0.ip(&["link", "show", "lan0"])?.contains("lan0"));
    Ok(())
}
