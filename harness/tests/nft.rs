// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Kernel-backed tests for `openfeo-nft` (libnftables linked in-process, ADR-0012) inside the
//! rootless sandbox: no QEMU. `harness = false`: this binary is its own runner; an optional first
//! argument filters scenarios by substring. Every scenario uses a table of its own and deletes it
//! on the way out, because the sandbox's network namespace outlives the scenarios.

use std::process::ExitCode;

use anyhow::{Context, ensure};
use openfeo_config::{PortMap, PortMapEntry};
use openfeo_harness::lab::Lab;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_harness::{nftprobe, sandbox};
use openfeo_nft::{Nft, NftError};
use openfeo_reconcile::nft::nft;
use openfeo_world::World;
use serde_json::{Value, json};

const VM_STATIC: &str = include_str!("../fixtures/vm-static.toml");

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
    Scenario {
        name: "generated_ruleset_is_accepted_by_libnftables",
        run: generated_ruleset_is_accepted_by_libnftables,
    },
    Scenario {
        name: "generated_public_ruleset_is_accepted_by_libnftables",
        run: generated_public_ruleset_is_accepted_by_libnftables,
    },
];

const VM_PUBLIC: &str = include_str!("../fixtures/vm-public.toml");

/// The lab's four ports.
fn lab_portmap4() -> PortMap {
    let mut map = lab_portmap();
    map.ports.push(PortMapEntry {
        id: "pci-0000:00:06.0".to_owned(),
        name: "p3".to_owned(),
    });
    map
}

/// The public-world ruleset, with its interval concatenations (rules sets with an `ifname`
/// field), the public-address forward maps, the translated-subnet set and the echo limit, is
/// accepted by the pinned libnftables and this kernel, and every set and map is listed. This is
/// the proof the design asks for before the rules sets stand (SPEC §7.5).
fn generated_public_ruleset_is_accepted_by_libnftables(_lab: &mut Lab) -> anyhow::Result<()> {
    nftprobe::require_expressions()?;
    let config = openfeo_config::file::parse(VM_PUBLIC)?;
    let world = World::new(config, lab_portmap4());
    let desired = nft(&world);
    let mut nft = Nft::new()?;
    let applied = nft.apply(&desired.ruleset);
    let listed_ruleset = nft.list_ruleset();
    drop_table(&mut nft, "openfeo");
    applied.context("apply the public ruleset")?;
    let ruleset = listed_ruleset?;
    for set in [
        "wan_if",
        "lan_if",
        "lan_priv_if",
        "lan_pub_dhcp_if",
        "lan_to_wan",
        "lan_pairs",
        "lan_same",
        "nat_nets",
        "rules_tcp",
        "rules_udp",
        "rules_other",
        "rules_any",
    ] {
        ensure!(
            listed(&ruleset, "set", set, Some("openfeo")).len() == 1,
            "set {set} missing or duplicated: {ruleset}"
        );
    }
    for map in ["fwd_tcp", "fwd_udp", "fwd_pub_tcp", "fwd_pub_udp"] {
        ensure!(
            listed(&ruleset, "map", map, Some("openfeo")).len() == 1,
            "map {map} missing or duplicated: {ruleset}"
        );
    }
    Ok(())
}

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

/// The lab's three ports, as the QEMU VM sees them.
fn lab_portmap() -> PortMap {
    PortMap {
        ports: (0..3)
            .map(|i| PortMapEntry {
                id: format!("pci-0000:00:0{}.0", 3 + i),
                name: format!("p{i}"),
            })
            .collect(),
    }
}

/// The real ruleset for the lab's static configuration goes through libnftables into this
/// kernel, twice (the add/delete/add prologue makes the second apply a replace), and every chain
/// is there afterwards. Skips on a kernel that cannot load the ct/fib/nat modules.
fn generated_ruleset_is_accepted_by_libnftables(_lab: &mut Lab) -> anyhow::Result<()> {
    nftprobe::require_expressions()?;
    let config = openfeo_config::file::parse(VM_STATIC)?;
    let world = World::new(config, lab_portmap());
    let desired = nft(&world);
    ensure!(desired.forwarding, "the static fixture has a WAN and a LAN");
    let mut nft = Nft::new()?;
    let first = nft.apply(&desired.ruleset);
    let second = nft.apply(&desired.ruleset);
    let listed_ruleset = nft.list_ruleset();
    drop_table(&mut nft, "openfeo");
    first.context("first apply")?;
    second.context("second apply (replace)")?;
    let ruleset = listed_ruleset?;
    ensure!(
        listed(&ruleset, "table", "openfeo", None).len() == 1,
        "exactly one table openfeo: {ruleset}"
    );
    for chain in ["rpfilter", "input", "forward", "dstnat", "srcnat"] {
        ensure!(
            listed(&ruleset, "chain", chain, Some("openfeo")).len() == 1,
            "chain {chain} missing or duplicated: {ruleset}"
        );
    }
    ensure!(
        listed(&ruleset, "map", "fwd_tcp", Some("openfeo")).len() == 1,
        "map fwd_tcp missing: {ruleset}"
    );
    Ok(())
}
