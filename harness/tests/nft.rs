// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Kernel-backed tests for `openfeo-nft` (libnftables linked in-process, ADR-0012) inside the
//! rootless sandbox: no QEMU. `harness = false`: this binary is its own runner; an optional first
//! argument filters scenarios by substring. Every scenario uses a table of its own and deletes it
//! on the way out, because the sandbox's network namespace outlives the scenarios.

use std::process::ExitCode;

use anyhow::{Context, ensure};
use openfeo_harness::lab::Lab;
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_nft::{Nft, NftError};
use serde_json::{Value, json};

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "applies_and_lists_a_table",
        run: applies_and_lists_a_table,
    },
    Scenario {
        name: "replace_is_idempotent",
        run: replace_is_idempotent,
    },
    Scenario {
        name: "rejected_ruleset_reports_the_error",
        run: rejected_ruleset_reports_the_error,
    },
    Scenario {
        name: "init_works_without_capabilities_until_used",
        run: init_works_without_capabilities_until_used,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("{err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

fn add_table(name: &str) -> Value {
    json!({"add": {"table": {"family": "inet", "name": name}}})
}

fn delete_table(name: &str) -> Value {
    json!({"delete": {"table": {"family": "inet", "name": name}}})
}

fn add_input_chain(table: &str) -> Value {
    json!({"add": {"chain": {
        "family": "inet", "table": table, "name": "input",
        "type": "filter", "hook": "input", "prio": 0, "policy": "accept"
    }}})
}

fn add_rule(table: &str, expr: &Value) -> Value {
    json!({"add": {"rule": {"family": "inet", "table": table, "chain": "input", "expr": expr}}})
}

/// Best-effort cleanup: the table may legitimately not exist.
fn drop_table(nft: &mut Nft, name: &str) {
    let _ = nft.apply(&[delete_table(name)]);
}

/// The listed objects of `kind` (`"table"`, `"chain"`, …) whose `"name"` is `name`, in `table`
/// when given.
fn listed<'a>(ruleset: &'a Value, kind: &str, name: &str, table: Option<&str>) -> Vec<&'a Value> {
    ruleset
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|object| object.get(kind))
        .filter(|object| object.get("name").and_then(Value::as_str) == Some(name))
        .filter(|object| {
            table.is_none_or(|t| object.get("table").and_then(Value::as_str) == Some(t))
        })
        .collect()
}

fn applies_and_lists_a_table(_lab: &mut Lab) -> anyhow::Result<()> {
    let mut nft = Nft::new()?;
    drop_table(&mut nft, "t0");
    let result = nft.apply(&[
        add_table("t0"),
        add_input_chain("t0"),
        add_rule("t0", &json!([{"accept": null}])),
    ]);
    let listed_ruleset = nft.list_ruleset();
    drop_table(&mut nft, "t0");
    result.context("apply")?;
    let ruleset = listed_ruleset.context("list")?;
    ensure!(
        listed(&ruleset, "table", "t0", None).len() == 1,
        "table t0 not listed once: {ruleset}"
    );
    ensure!(
        listed(&ruleset, "chain", "input", Some("t0")).len() == 1,
        "chain input not listed once: {ruleset}"
    );
    Ok(())
}

fn replace_is_idempotent(_lab: &mut Lab) -> anyhow::Result<()> {
    let mut nft = Nft::new()?;
    drop_table(&mut nft, "t1");
    let batch = [
        add_table("t1"),
        delete_table("t1"),
        add_table("t1"),
        add_input_chain("t1"),
        add_rule("t1", &json!([{"accept": null}])),
    ];
    let first = nft.apply(&batch);
    let second = nft.apply(&batch);
    let listed_ruleset = nft.list_ruleset();
    drop_table(&mut nft, "t1");
    first.context("first apply")?;
    second.context("second apply")?;
    let ruleset = listed_ruleset?;
    ensure!(
        listed(&ruleset, "table", "t1", None).len() == 1,
        "expected exactly one table t1: {ruleset}"
    );
    ensure!(
        listed(&ruleset, "chain", "input", Some("t1")).len() == 1,
        "expected exactly one chain input in t1: {ruleset}"
    );
    Ok(())
}

fn rejected_ruleset_reports_the_error(_lab: &mut Lab) -> anyhow::Result<()> {
    let mut nft = Nft::new()?;
    drop_table(&mut nft, "t2");
    let result = nft.apply(&[
        add_table("t2"),
        add_input_chain("t2"),
        add_rule(
            "t2",
            &json!([{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "nosuchfield"}}, "right": 1}}]),
        ),
    ]);
    let listed_ruleset = nft.list_ruleset();
    drop_table(&mut nft, "t2");
    match result {
        Err(NftError::Rejected { message }) => {
            ensure!(!message.trim().is_empty(), "empty error message");
        }
        other => anyhow::bail!("expected Rejected, got {other:?}"),
    }
    let ruleset = listed_ruleset?;
    ensure!(
        listed(&ruleset, "table", "t2", None).is_empty(),
        "a rejected batch must add nothing, but t2 exists: {ruleset}"
    );
    Ok(())
}

fn init_works_without_capabilities_until_used(_lab: &mut Lab) -> anyhow::Result<()> {
    // Creating the context opens no socket; listing does, and the sandbox has CAP_NET_ADMIN in
    // its own namespace, so a fresh context can list straight away.
    let mut nft = Nft::new().context("new")?;
    let ruleset = nft.list_ruleset().context("list on a fresh context")?;
    ensure!(
        ruleset.is_array(),
        "list_ruleset must yield the nftables array: {ruleset}"
    );
    let raw = nft.run(r#"{"nftables": [{"list": {"ruleset": null}}]}"#)?;
    ensure!(
        raw.contains("\"nftables\""),
        "raw output is the JSON document: {raw}"
    );
    Ok(())
}
