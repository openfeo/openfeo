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
use openfeo_harness::{nftlist, nftprobe, sandbox};
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
        name: "the_ipv6_ruleset_applies_on_the_pinned_nftables",
        run: the_ipv6_ruleset_applies_on_the_pinned_nftables,
    },
    Scenario {
        name: "generated_public_ruleset_is_accepted_by_libnftables",
        run: generated_public_ruleset_is_accepted_by_libnftables,
    },
    Scenario {
        name: "ula_toward_the_wan_is_rejected_with_no_route",
        run: ula_toward_the_wan_is_rejected_with_no_route,
    },
];
const VM_PD: &str = include_str!("../fixtures/vm-pd.toml");

const VM_PUBLIC: &str = include_str!("../fixtures/vm-public.toml");
const VM_IPV6: &str = include_str!("../fixtures/vm-ipv6.toml");

/// The ICMPv6 types the WAN input accepts per RFC 4890, as a numeric listing gives them:
/// destination-unreachable 1, packet-too-big 2, time-exceeded 3, parameter-problem 4,
/// mld-listener-query 130, mld-listener-report 131, mld-listener-done 132, nd-router-advert 134,
/// nd-neighbor-solicit 135, nd-neighbor-advert 136 and mld2-listener-report 143.
const RFC_4890_WAN_TYPES: [u64; 11] = [1, 2, 3, 4, 130, 131, 132, 134, 135, 136, 143];

/// `icmpv6 type echo-request`, accepted on its own behind the limit when `wan_ping = true`.
const ICMPV6_ECHO_REQUEST: u64 = 128;

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

/// The IPv6-world ruleset (SPEC §7.3, §7.5): the IPv6 rule sets with their `ipv6_addr`
/// concatenations, the advertising-LAN set, the ICMPv6 type rules on the WAN input and the
/// link-local reverse-path exemption are accepted by the pinned libnftables and this kernel,
/// every IPv6 set is listed, and the listing keeps the rules' shapes: `Nft` lists numerically,
/// so the types are compared as numbers (`nftlist`), never as the names the generator wrote.
fn the_ipv6_ruleset_applies_on_the_pinned_nftables(_lab: &mut Lab) -> anyhow::Result<()> {
    nftprobe::require_expressions()?;
    let config = openfeo_config::file::parse(VM_IPV6)?;
    let world = World::new(config, lab_portmap4());
    let desired = nft(&world);
    let mut nft = Nft::new()?;
    let applied = nft.apply(&desired.ruleset);
    let listed_ruleset = nft.list_ruleset();
    drop_table(&mut nft, "openfeo");
    applied.context("apply the IPv6 ruleset")?;
    let ruleset = listed_ruleset?;
    for set in [
        "lan_pub_ra_if",
        "rules6_tcp",
        "rules6_udp",
        "rules6_other",
        "rules6_any",
        "rules_tcp",
        "nat_nets",
    ] {
        ensure!(
            listed(&ruleset, "set", set, Some("openfeo")).len() == 1,
            "set {set} missing or duplicated: {ruleset}"
        );
    }
    let icmpv6_type = json!({"payload": {"protocol": "icmpv6", "field": "type"}});
    let rights = nftlist::match_rights(&ruleset, "input", &icmpv6_type);
    let mut wan_types: Vec<u64> = rights
        .iter()
        .filter_map(|right| right.get("set").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_u64)
        .collect();
    wan_types.sort_unstable();
    ensure!(
        wan_types == RFC_4890_WAN_TYPES,
        "the WAN input accepts ICMPv6 types {wan_types:?}, not {RFC_4890_WAN_TYPES:?}: {ruleset}"
    );
    ensure!(
        rights
            .iter()
            .any(|right| right.as_u64() == Some(ICMPV6_ECHO_REQUEST)),
        "icmpv6 echo-request is not matched on its own in input: {ruleset}"
    );
    let ip6_saddr = json!({"payload": {"protocol": "ip6", "field": "saddr"}});
    let link_local = json!({"prefix": {"addr": "fe80::", "len": 10}});
    ensure!(
        nftlist::match_rights(&ruleset, "rpfilter", &ip6_saddr).contains(&&link_local),
        "link-local sources are not exempt from the reverse-path check: {ruleset}"
    );
    Ok(())
}

/// The delegated-prefix ruleset (SPEC §7.3, §7.5): the pinned libnftables and this kernel
/// accept the ULA rules (a unique local source or destination leaving by a WAN is rejected
/// with ICMPv6 no-route, one arriving on a WAN is dropped), the DHCPv6 client's port 546 on the
/// WAN input and port 547 among the LAN services, and the listing keeps their shapes.
fn ula_toward_the_wan_is_rejected_with_no_route(_lab: &mut Lab) -> anyhow::Result<()> {
    nftprobe::require_expressions()?;
    let config = openfeo_config::file::parse(VM_PD)?;
    let mut world = World::new(config, lab_portmap4());
    world.ula = Some("fd12:3456:789a::/48".parse()?);
    let desired = nft(&world);
    let mut nft = Nft::new()?;
    let applied = nft.apply(&desired.ruleset);
    let listed_ruleset = nft.list_ruleset();
    drop_table(&mut nft, "openfeo");
    applied.context("apply the delegated-prefix ruleset")?;
    let ruleset = listed_ruleset?;
    let ula = json!({"prefix": {"addr": "fc00::", "len": 7}});
    for field in ["saddr", "daddr"] {
        let ip6 = json!({"payload": {"protocol": "ip6", "field": field}});
        ensure!(
            nftlist::match_rights(&ruleset, "forward", &ip6).contains(&&ula),
            "no ULA {field} rule in forward: {ruleset}"
        );
    }
    let ip6_saddr = json!({"payload": {"protocol": "ip6", "field": "saddr"}});
    ensure!(
        nftlist::match_rights(&ruleset, "input", &ip6_saddr).contains(&&ula),
        "no ULA source drop in input: {ruleset}"
    );
    let forward_text = listed(&ruleset, "rule", "forward", Some("openfeo"))
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    ensure!(
        forward_text.matches("\"reject\"").count() >= 2,
        "the ULA rules reject: {forward_text}"
    );
    let udp_dport = json!({"payload": {"protocol": "udp", "field": "dport"}});
    let input_ports = nftlist::match_rights(&ruleset, "input", &udp_dport);
    ensure!(
        input_ports.iter().any(|right| right.as_u64() == Some(546)),
        "udp 546 is not accepted on the WAN input: {input_ports:?}"
    );
    ensure!(
        input_ports.iter().any(|right| right
            .get("set")
            .and_then(Value::as_array)
            .is_some_and(|set| set.contains(&json!(547)))),
        "udp 547 is not among the LAN services: {input_ports:?}"
    );
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
