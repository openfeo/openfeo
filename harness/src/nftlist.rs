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
    expressions(ruleset, chain).any(|expr| expr.pointer("/match/left") == Some(left))
}

/// The right-hand side of every `match` in the rules of `chain` whose left-hand side is `left`,
/// in listing order: what a numeric listing keeps of a symbolic constant, such as `128` for
/// `icmpv6 type echo-request` or `{"set": [134, 143]}` for a list of types.
#[must_use]
pub fn match_rights<'a>(ruleset: &'a Value, chain: &str, left: &Value) -> Vec<&'a Value> {
    expressions(ruleset, chain)
        .filter(|expr| expr.pointer("/match/left") == Some(left))
        .filter_map(|expr| expr.pointer("/match/right"))
        .collect()
}

/// Every expression of every rule of `chain`, in listing order.
fn expressions<'a>(ruleset: &'a Value, chain: &str) -> impl Iterator<Item = &'a Value> {
    ruleset
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|object| object.get("rule"))
        .filter(move |rule| rule.get("chain").and_then(Value::as_str) == Some(chain))
        .filter_map(|rule| rule.get("expr").and_then(Value::as_array))
        .flatten()
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

    /// The IPv6 world's ruleset (`harness/fixtures/vm-ipv6.toml`) as nftables 1.1.7 listed it on
    /// CI's ubuntu-24.04 runner, cut down to the WAN's ICMPv6 rules and the link-local
    /// exemption: the RFC 4890 types are a set of numbers, `echo-request` is `128`, and only
    /// the prefix keeps its text.
    const IPV6_LISTING: &str = r#"[{"metainfo":{"json_schema_version":1,"release_name":"Commodore Bullmoose #8","version":"1.1.7"}},{"table":{"family":"inet","handle":13,"name":"openfeo"}},{"chain":{"family":"inet","handle":22,"hook":"prerouting","name":"rpfilter","policy":"accept","prio":-300,"table":"openfeo","type":"filter"}},{"chain":{"family":"inet","handle":28,"hook":"input","name":"input","policy":"drop","prio":0,"table":"openfeo","type":"filter"}},{"rule":{"chain":"rpfilter","expr":[{"match":{"left":{"payload":{"field":"saddr","protocol":"ip6"}},"op":"==","right":{"prefix":{"addr":"fe80::","len":10}}}},{"accept":null}],"family":"inet","handle":26,"table":"openfeo"}},{"rule":{"chain":"input","expr":[{"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":"@wan_if"}},{"match":{"left":{"payload":{"field":"type","protocol":"icmpv6"}},"op":"==","right":{"set":[1,2,3,4,130,131,132,134,135,136,143]}}},{"accept":null}],"family":"inet","handle":45,"table":"openfeo"}},{"rule":{"chain":"input","expr":[{"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":"@wan_if"}},{"match":{"left":{"payload":{"field":"type","protocol":"icmpv6"}},"op":"==","right":128}},{"limit":{"burst":100,"per":"second","rate":50}},{"accept":null}],"family":"inet","handle":47,"table":"openfeo"}}]"#;

    #[test]
    fn match_rights_gives_every_right_hand_side_of_a_shape_in_listing_order() {
        assert!(
            !IPV6_LISTING.contains("nd-router-advert"),
            "the fixture is a numeric listing"
        );
        let listing: Value = serde_json::from_str(IPV6_LISTING).unwrap();
        let icmpv6_type = json!({"payload": {"protocol": "icmpv6", "field": "type"}});
        assert_eq!(
            match_rights(&listing, "input", &icmpv6_type),
            [
                &json!({"set": [1, 2, 3, 4, 130, 131, 132, 134, 135, 136, 143]}),
                &json!(128)
            ]
        );
        assert_eq!(
            match_rights(&listing, "forward", &icmpv6_type),
            [] as [&Value; 0]
        );
        let ip6_saddr = json!({"payload": {"protocol": "ip6", "field": "saddr"}});
        assert_eq!(
            match_rights(&listing, "rpfilter", &ip6_saddr),
            [&json!({"prefix": {"addr": "fe80::", "len": 10}})]
        );
        assert_eq!(
            match_rights(&listing, "rpfilter", &icmpv6_type),
            [] as [&Value; 0]
        );
    }
}
