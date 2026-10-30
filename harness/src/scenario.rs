// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A tiny scenario runner: each scenario gets a fresh [`Lab`], results print libtest-style.

use std::process::ExitCode;
use std::time::Instant;

use anyhow::Context;

use crate::lab::Lab;

/// One named scenario.
#[derive(Debug)]
pub struct Scenario {
    /// Shown in the output; filters match on it.
    pub name: &'static str,
    /// The scenario body.
    pub run: fn(&mut Lab) -> anyhow::Result<()>,
}

/// The scenarios whose name contains `filter` (all of them when `None`).
#[must_use]
pub fn select<'a>(all: &'a [Scenario], filter: Option<&str>) -> Vec<&'a Scenario> {
    all.iter()
        .filter(|s| filter.is_none_or(|f| s.name.contains(f)))
        .collect()
}

/// Run the selected scenarios one after another, each in a fresh lab, and summarise.
#[must_use]
pub fn run_all(all: &[Scenario], filter: Option<&str>) -> ExitCode {
    let selected = select(all, filter);
    println!("running {} scenarios", selected.len());
    let (mut passed, mut failed) = (0, 0);
    for scenario in selected {
        let started = Instant::now();
        match run_one(scenario) {
            Ok(()) => {
                passed += 1;
                println!(
                    "scenario {} ... ok ({:.1}s)",
                    scenario.name,
                    started.elapsed().as_secs_f64()
                );
            }
            Err(err) => {
                failed += 1;
                println!(
                    "scenario {} ... FAILED ({:.1}s)",
                    scenario.name,
                    started.elapsed().as_secs_f64()
                );
                eprintln!("{err:#}");
            }
        }
    }
    println!(
        "\nresult: {}. {passed} passed; {failed} failed",
        if failed == 0 { "ok" } else { "FAILED" }
    );
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_one(scenario: &Scenario) -> anyhow::Result<()> {
    let mut lab = Lab::new("lab").context("create lab")?;
    let result = (scenario.run)(&mut lab);
    if result.is_err() {
        dump_diagnostics(&lab);
    }
    result
}

/// On failure: the end of the VM console, of QEMU's stderr and of every daemon's log, so the
/// cause is in the output.
fn dump_diagnostics(lab: &Lab) {
    for daemon in &lab.daemons {
        eprintln!("--- {} (last 20 lines) ---", daemon.name);
        for line in daemon.log.tail(20) {
            eprintln!("{line}");
        }
    }
    if let Some(vm) = &lab.vm {
        if let Some(console) = &vm.console {
            eprintln!("--- console (last 80 lines) ---");
            for line in console.tail(80) {
                eprintln!("{line}");
            }
        }
        if let Some(errors) = &vm.qemu_errors {
            let tail = errors.tail(20);
            if !tail.is_empty() {
                eprintln!("--- qemu stderr ---");
                for line in tail {
                    eprintln!("{line}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unnecessary_wraps)] // the signature is the Scenario fn-pointer type
    fn noop(_: &mut Lab) -> anyhow::Result<()> {
        Ok(())
    }

    #[test]
    fn select_filters_by_substring() {
        let all = [
            Scenario {
                name: "boots_and_logs",
                run: noop,
            },
            Scenario {
                name: "lab_topology",
                run: noop,
            },
        ];
        assert_eq!(
            select(&all, Some("topo"))
                .iter()
                .map(|s| s.name)
                .collect::<Vec<_>>(),
            ["lab_topology"]
        );
        assert_eq!(select(&all, None).len(), 2);
    }
}
