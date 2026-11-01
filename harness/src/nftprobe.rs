// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Can this kernel run OpenFeO's ruleset? The sandboxed nft scenarios need the `ct`, `fib`,
//! `nat` and `masquerade` expressions, which distribution kernels ship as modules. A host whose
//! running kernel cannot load them (typically: upgraded on disk, not yet rebooted, so
//! `/lib/modules/$(uname -r)` is gone) answers `ENOENT` to the first such rule. The probe applies
//! a throwaway table using each expression once and turns that answer into a [`Skip`].

use anyhow::{Context, Result};
use openfeo_nft::{Nft, NftError};
use serde_json::{Value, json};

use crate::scenario::Skip;

const TABLE: &str = "openfeo_probe";

/// A table with one rule per module-backed expression: `ct state`, `fib`, `dnat`, `masquerade`.
fn probe_ruleset() -> Vec<Value> {
    let table = json!({"family": "inet", "name": TABLE});
    let chain = |name: &str, kind: &str, hook: &str, prio: i32| {
        json!({"add": {"chain": {"family": "inet", "table": TABLE, "name": name,
            "type": kind, "hook": hook, "prio": prio, "policy": "accept"}}})
    };
    let rule = |chain: &str, expr: Value| json!({"add": {"rule": {"family": "inet", "table": TABLE, "chain": chain, "expr": expr}}});
    vec![
        json!({"add": {"table": table}}),
        json!({"delete": {"table": table}}),
        json!({"add": {"table": table}}),
        chain("pre", "filter", "prerouting", -300),
        chain("dnat", "nat", "prerouting", -100),
        chain("snat", "nat", "postrouting", 100),
        rule(
            "pre",
            json!([{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "invalid"}}, {"drop": null}]),
        ),
        rule(
            "pre",
            json!([{"match": {"op": "==", "left": {"fib": {"result": "oif", "flags": ["saddr"]}}, "right": false}}, {"drop": null}]),
        ),
        rule(
            "dnat",
            json!([{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1}}, {"dnat": {"family": "ip", "addr": "192.0.2.1"}}]),
        ),
        rule("snat", json!([{"masquerade": null}])),
        // M2 part 1: a rate limit, and an interval set concatenating an interface name with an
        // address range and a port (the rules sets, SPEC §7.5).
        rule(
            "pre",
            json!([{"limit": {"rate": 50, "per": "second", "burst": 100}}, {"accept": null}]),
        ),
        json!({"add": {"set": {"family": "inet", "table": TABLE, "name": "probe_rules",
            "type": ["ifname", "ipv4_addr", "inet_service"], "flags": ["interval"],
            "elem": [{"concat": ["p0", {"range": ["192.0.2.1", "192.0.2.2"]}, 80]}]}}}),
        rule(
            "pre",
            json!([{"match": {"op": "==", "left": {"concat": [
                {"meta": {"key": "iifname"}},
                {"payload": {"protocol": "ip", "field": "daddr"}},
                {"payload": {"protocol": "tcp", "field": "dport"}}]},
                "right": "@probe_rules"}}, {"accept": null}]),
        ),
    ]
}

/// `Ok` when the running kernel accepts every expression the ruleset uses; `Err(Skip)` when it
/// cannot load one of them, any other error when the probe itself failed.
///
/// # Errors
///
/// [`Skip`] (inside the `anyhow::Error`) for a kernel that cannot load the expressions; a plain
/// error when libnftables could not be used at all (not inside the sandbox, say).
pub fn require_expressions() -> Result<()> {
    let mut nft = Nft::new().context("libnftables context")?;
    let result = nft.apply(&probe_ruleset());
    let _ = nft.apply(&[json!({"delete": {"table": {"family": "inet", "name": TABLE}}})]);
    match result {
        Ok(()) => Ok(()),
        Err(NftError::Rejected { message }) if message.contains("No such file or directory") => {
            Err(Skip(format!(
                "kernel {} cannot load the nft ct/fib/nat modules ({}); reboot or modprobe \
                 nft_ct nft_fib_inet nft_nat nft_masq nft_chain_nat",
                running_kernel(),
                message.lines().next().unwrap_or_default().trim()
            ))
            .into())
        }
        Err(err) => Err(err).context("nft probe"),
    }
}

pub(crate) fn running_kernel() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_or_else(|_| "?".to_owned(), |s| s.trim().to_owned())
}
