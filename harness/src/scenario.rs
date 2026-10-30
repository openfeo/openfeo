// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A tiny scenario runner: each scenario gets a fresh [`Lab`], results print libtest-style.

use std::process::ExitCode;
use std::time::Instant;

use anyhow::Context;

use crate::lab::Lab;

/// Returned (inside `anyhow::Error`) by a scenario that cannot run on this machine, with the
/// reason: it counts as skipped, not failed, unless `OPENFEO_NO_SKIP` is set (CI sets it, so a
/// kernel that cannot run a scenario fails the build there instead of hiding it).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Skip(pub String);

/// The environment variable that turns a skip into a failure.
pub const NO_SKIP_VAR: &str = "OPENFEO_NO_SKIP";

/// How a scenario ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Returned `Ok`.
    Passed,
    /// Returned an error.
    Failed,
    /// Returned [`Skip`] and skipping is allowed.
    Skipped,
}

/// Classifies a scenario's result; `no_skip` is whether [`NO_SKIP_VAR`] is set.
#[must_use]
pub fn outcome(result: &anyhow::Result<()>, no_skip: bool) -> Outcome {
    match result {
        Ok(()) => Outcome::Passed,
        Err(err) if !no_skip && err.downcast_ref::<Skip>().is_some() => Outcome::Skipped,
        Err(_) => Outcome::Failed,
    }
}

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
    let no_skip = std::env::var_os(NO_SKIP_VAR).is_some();
    let (mut passed, mut failed, mut skipped) = (0, 0, 0);
    for scenario in selected {
        let started = Instant::now();
        let result = run_one(scenario);
        let elapsed = started.elapsed().as_secs_f64();
        match outcome(&result, no_skip) {
            Outcome::Passed => {
                passed += 1;
                println!("scenario {} ... ok ({elapsed:.1}s)", scenario.name);
            }
            Outcome::Skipped => {
                skipped += 1;
                let reason = result.err().map(|err| err.to_string()).unwrap_or_default();
                println!("scenario {} ... skipped ({reason})", scenario.name);
            }
            Outcome::Failed => {
                failed += 1;
                println!("scenario {} ... FAILED ({elapsed:.1}s)", scenario.name);
                if let Err(err) = result {
                    eprintln!("{err:#}");
                }
            }
        }
    }
    println!(
        "\nresult: {}. {passed} passed; {failed} failed; {skipped} skipped",
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
    fn skip_counts_as_skipped_unless_no_skip_is_set() {
        let skip: anyhow::Result<()> = Err(Skip("kernel lacks nft_ct".into()).into());
        let fail: anyhow::Result<()> = Err(anyhow::anyhow!("boom"));
        assert_eq!(outcome(&skip, false), Outcome::Skipped);
        assert_eq!(outcome(&skip, true), Outcome::Failed);
        assert_eq!(outcome(&fail, false), Outcome::Failed);
        assert_eq!(outcome(&Ok(()), true), Outcome::Passed);
        let wrapped: anyhow::Result<()> =
            Err(anyhow::Error::from(Skip("x".into())).context("probe"));
        assert_eq!(outcome(&wrapped, false), Outcome::Skipped);
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
