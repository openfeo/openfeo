// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Questions about a ruleset as libnftables lists it. `Nft` lists with
//! `NFT_CTX_OUTPUT_NUMERIC_ALL`, so symbolic constants come back as numbers (`icmp type
//! echo-request` is `"right": 8`): ask about the shape of a rule's expressions, never about
//! their text.

use serde_json::Value;

/// Whether a rule of `chain` in the listed `ruleset` (the `nftables` array `Nft::list_ruleset`
/// returns) has a `match` whose left-hand side is `left`, such as
/// `{"payload": {"protocol": "icmp", "field": "type"}}`.
#[must_use]
pub fn chain_matches(ruleset: &Value, chain: &str, left: &Value) -> bool {
    ruleset
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|object| object.get("rule"))
        .filter(|rule| rule.get("chain").and_then(Value::as_str) == Some(chain))
        .filter_map(|rule| rule.get("expr").and_then(Value::as_array))
        .flatten()
        .any(|expr| expr.pointer("/match/left") == Some(left))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// `nft -n -j list ruleset` (numeric output, as `Nft` lists) after
    /// `add rule inet t input icmp type echo-request accept`; nftables 1.1.7 on Linux 7.2.
    const LISTING: &str = r#"[{"metainfo": {"version": "1.1.7", "release_name": "Commodore Bullmoose #8", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "t", "handle": 1}}, {"chain": {"family": "inet", "table": "t", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}, {"rule": {"family": "inet", "table": "t", "chain": "input", "handle": 2, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "icmp", "field": "type"}}, "right": 8}}, {"accept": null}]}}]"#;

    #[test]
    fn numeric_listing_keeps_the_match_shape_but_not_the_symbol() {
        assert!(
            !LISTING.contains("echo-request"),
            "the fixture is a numeric listing"
        );
        let listing: Value = serde_json::from_str(LISTING).unwrap();
        let icmp_type = json!({"payload": {"protocol": "icmp", "field": "type"}});
        assert!(chain_matches(&listing, "input", &icmp_type));
        assert!(!chain_matches(&listing, "forward", &icmp_type));
        assert!(!chain_matches(
            &listing,
            "input",
            &json!({"payload": {"protocol": "udp", "field": "dport"}})
        ));
        assert!(!chain_matches(&json!([]), "input", &icmp_type));
    }
}
