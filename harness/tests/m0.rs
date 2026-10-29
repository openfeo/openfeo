// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! M0 acceptance scenarios (SPEC §12), run inside the rootless sandbox. `harness = false`: this
//! binary is its own runner. An optional first argument filters scenarios by substring.

use std::process::ExitCode;
use std::time::Duration;

use openfeo_harness::lab::{BOOT_TIMEOUT, Lab};
use openfeo_harness::lines::{Cursor, Regex};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "lab_topology",
        run: lab_topology,
    },
    Scenario {
        name: "boots_and_logs",
        run: boots_and_logs,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("{err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("bad test regex {pattern:?}: {err}"))
}

const SOON: Duration = Duration::from_secs(10);

/// The namespaces and taps exist with the addresses the ISP sides should have.
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

/// M0 acceptance: the VM boots to PID 1, which logs the version and the port map.
fn boots_and_logs(lab: &mut Lab) -> anyhow::Result<()> {
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    let m = c.wait_for(
        &mut cur,
        &re(r"openfeo-init: start version=(\S+) mode=vm slot=none"),
        BOOT_TIMEOUT,
    )?;
    anyhow::ensure!(
        m.groups[0]
            .as_deref()
            .is_some_and(|v| v.starts_with("0.1.0+")),
        "unexpected version in {:?}",
        m.line
    );
    c.wait_for(
        &mut cur,
        &re(r"openfeo-init: watchdog /dev/watchdog0 timeout=60s"),
        SOON,
    )?;
    c.wait_for(&mut cur, &re(r"openfeo-init: child started pid=\d+"), SOON)?;
    c.wait_for(
        &mut cur,
        &re(r"openfeo: router mode=vm version=0\.1\.0\+"),
        SOON,
    )?;
    c.wait_for(&mut cur, &re(r"openfeo: ports total=3"), SOON)?;
    let ports = c.count(&re(
        r"openfeo: port p[0-2] eth\d id=pci-0000:00:[0-9a-f]{2}\.0 mac=52:54:00:fe:00:0[0-2]",
    ));
    anyhow::ensure!(ports == 3, "expected 3 port lines, saw {ports}");
    anyhow::ensure!(
        c.count(&re(r"openfeo-init: child exited")) == 0,
        "child exited during boot"
    );
    Ok(())
}
