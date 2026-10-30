// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The firewall and NAT ruleset (SPEC §7.4 reverse-path filtering, §7.5, §9) as the libnftables
//! JSON `nftables` array for one `table inet openfeo`, regenerated from the World. The batch
//! begins `add table; delete table; add table` so applying it replaces the table atomically and
//! idempotently. Zones are named sets of interface names (`wan_if`, `lan_if`), port forwards are
//! maps (`fwd_tcp`, `fwd_udp`): rule counts never grow with the configuration.
//!
//! Chains: `rpfilter` (prerouting -300: strict reverse-path on LAN, loose on WAN, DHCP exempt),
//! `input` (drop; LAN→router services, WAN→router only the DHCPv4 client's replies and, when
//! `wan_ping`, echo requests), `forward` (drop; LAN→WAN, within one LAN, and translated flows),
//! `dstnat` (port forwards from WAN and, by hairpin, from LAN clients reaching a router address),
//! `srcnat` (masquerade on WAN; hairpinned flows masqueraded to the router's LAN address).

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use openfeo_config::Firewall;
use openfeo_world::World;
use serde::Serialize;
use serde_json::{Value, json};

use crate::{TABLE, bridge_name};

/// The table's family: one ruleset for IPv4 and IPv6 (SPEC §9).
pub const FAMILY: &str = "inet";
/// LAN→router UDP services: DNS, DHCP, NTP.
pub const LAN_UDP_SERVICES: [u16; 3] = [53, 67, 123];
/// LAN→router TCP services: DNS, HTTP, HTTPS.
pub const LAN_TCP_SERVICES: [u16; 3] = [53, 80, 443];

/// Everything the nft applier makes true.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DesiredNft {
    /// The complete `nftables` array, starting with add/delete/add of the table.
    pub ruleset: Vec<Value>,
    /// Whether forwarding may be switched on: at least one WAN and one LAN.
    pub forwarding: bool,
    /// Interfaces in the WAN zone (ports with a WAN role).
    pub wan_if: BTreeSet<String>,
    /// Interfaces in the LAN zone (the LAN bridges).
    pub lan_if: BTreeSet<String>,
}

/// Port forwards by protocol: router port → (LAN address, LAN port).
type Forwards = BTreeMap<u16, (Ipv4Addr, u16)>;

/// The ruleset the World calls for. A WAN whose port the map does not know contributes no
/// interface; a forward whose text does not parse is left out (validation already rejected it).
#[must_use]
pub fn nft(world: &World) -> DesiredNft {
    let wan_if: BTreeSet<String> = world
        .config
        .wans
        .iter()
        .filter(|wan| world.ports.id_of(&wan.port).is_some())
        .map(|wan| wan.port.clone())
        .collect();
    let lan_if: BTreeSet<String> = world
        .config
        .lans
        .iter()
        .map(|lan| bridge_name(&lan.name))
        .collect();
    let firewall = world.config.firewall.as_ref();
    let wan_ping = firewall.is_some_and(|f| f.wan_ping);
    let (fwd_tcp, fwd_udp) = forwards(firewall);

    let mut ruleset = vec![
        json!({"add": {"table": table()}}),
        json!({"delete": {"table": table()}}),
        json!({"add": {"table": table()}}),
        ifname_set("wan_if", &wan_if),
        ifname_set("lan_if", &lan_if),
        ifname_pair_set("lan_same", &lan_if),
        forward_map("fwd_tcp", &fwd_tcp),
        forward_map("fwd_udp", &fwd_udp),
    ];
    ruleset.extend(rpfilter_chain());
    ruleset.extend(input_chain(wan_ping));
    ruleset.extend(forward_chain());
    ruleset.extend(dstnat_chain());
    ruleset.extend(srcnat_chain());

    DesiredNft {
        ruleset,
        forwarding: !wan_if.is_empty() && !lan_if.is_empty(),
        wan_if,
        lan_if,
    }
}

fn forwards(firewall: Option<&Firewall>) -> (Forwards, Forwards) {
    let (mut tcp, mut udp) = (Forwards::new(), Forwards::new());
    for forward in firewall.into_iter().flat_map(|f| &f.port_forwards) {
        let (Ok(port), Ok(to)) = (u16::try_from(forward.port), forward.to.parse::<Ipv4Addr>())
        else {
            continue;
        };
        let to_port = match u16::try_from(forward.to_port) {
            Ok(0) => port,
            Ok(to_port) => to_port,
            Err(_) => continue,
        };
        match forward.proto.as_str() {
            "tcp" => tcp.insert(port, (to, to_port)),
            "udp" => udp.insert(port, (to, to_port)),
            _ => None,
        };
    }
    (tcp, udp)
}

// --- objects ---------------------------------------------------------------------------------

fn table() -> Value {
    json!({"family": FAMILY, "name": TABLE})
}

/// `set <name> { type ifname; elements = { … } }` (`elem` omitted when empty).
fn ifname_set(name: &str, members: &BTreeSet<String>) -> Value {
    let mut set = json!({"family": FAMILY, "table": TABLE, "name": name, "type": "ifname"});
    if !members.is_empty() {
        set["elem"] = json!(members);
    }
    json!({"add": {"set": set}})
}

/// `set <name> { type ifname . ifname; elements = { a . a, b . b } }`: each interface paired
/// with itself, so `iifname . oifname @<name>` matches traffic staying within one LAN.
fn ifname_pair_set(name: &str, members: &BTreeSet<String>) -> Value {
    let mut set = json!({
        "family": FAMILY, "table": TABLE, "name": name, "type": ["ifname", "ifname"]
    });
    if !members.is_empty() {
        let pairs: Vec<Value> = members
            .iter()
            .map(|ifname| json!({"concat": [ifname, ifname]}))
            .collect();
        set["elem"] = Value::Array(pairs);
    }
    json!({"add": {"set": set}})
}

/// `map <name> { type inet_service : ipv4_addr . inet_service; elements = { port : addr . port } }`.
fn forward_map(name: &str, forwards: &Forwards) -> Value {
    let mut map = json!({
        "family": FAMILY, "table": TABLE, "name": name,
        "type": "inet_service", "map": ["ipv4_addr", "inet_service"]
    });
    if !forwards.is_empty() {
        let elements: Vec<Value> = forwards
            .iter()
            .map(|(port, (to, to_port))| json!([port, {"concat": [to.to_string(), to_port]}]))
            .collect();
        map["elem"] = Value::Array(elements);
    }
    json!({"add": {"map": map}})
}

fn chain(name: &str, kind: &str, hook: &str, prio: i32, policy: &str) -> Value {
    json!({"add": {"chain": {
        "family": FAMILY, "table": TABLE, "name": name,
        "type": kind, "hook": hook, "prio": prio, "policy": policy
    }}})
}

fn rule(chain: &str, expr: Vec<Value>) -> Value {
    let mut rule = json!({"family": FAMILY, "table": TABLE, "chain": chain});
    rule["expr"] = Value::Array(expr);
    object(vec![("add", object(vec![("rule", rule)]))])
}

// --- expressions -----------------------------------------------------------------------------

/// A JSON object from owned values (`json!` would clone them).
fn object(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn matching(op: &str, left: Value, right: Value) -> Value {
    object(vec![(
        "match",
        object(vec![("op", json!(op)), ("left", left), ("right", right)]),
    )])
}

fn meta(key: &str) -> Value {
    json!({"meta": {"key": key}})
}

fn payload(protocol: &str, field: &str) -> Value {
    json!({"payload": {"protocol": protocol, "field": field}})
}

fn eq(left: Value, right: Value) -> Value {
    matching("==", left, right)
}

/// `left in right`: flag sets such as `ct state established,related`.
fn is_in(left: Value, right: Value) -> Value {
    matching("in", left, right)
}

fn iifname_in(set: &str) -> Value {
    eq(meta("iifname"), json!(format!("@{set}")))
}

fn oifname_in(set: &str) -> Value {
    eq(meta("oifname"), json!(format!("@{set}")))
}

/// `iifname . oifname @<set>`.
fn iif_oif_pair_in(set: &str) -> Value {
    eq(
        object(vec![(
            "concat",
            Value::Array(vec![meta("iifname"), meta("oifname")]),
        )]),
        json!(format!("@{set}")),
    )
}

fn ct_state(states: Value) -> Value {
    is_in(json!({"ct": {"key": "state"}}), states)
}

fn ct_status_dnat() -> Value {
    is_in(json!({"ct": {"key": "status"}}), json!("dnat"))
}

/// `fib saddr [. iif] oif missing`.
fn fib_saddr_oif_missing(with_iif: bool) -> Value {
    let flags = if with_iif {
        json!(["saddr", "iif"])
    } else {
        json!(["saddr"])
    };
    eq(
        object(vec![(
            "fib",
            object(vec![("result", json!("oif")), ("flags", flags)]),
        )]),
        json!(false),
    )
}

/// `fib daddr type local`: the packet is addressed to this router.
fn fib_daddr_local() -> Value {
    eq(
        json!({"fib": {"result": "type", "flags": ["daddr"]}}),
        json!("local"),
    )
}

/// `dnat ip addr . port to <proto> dport map @<map>`.
fn dnat_map(protocol: &str, map: &str) -> Value {
    let lookup = object(vec![
        ("key", payload(protocol, "dport")),
        ("data", json!(format!("@{map}"))),
    ]);
    object(vec![(
        "dnat",
        object(vec![
            ("family", json!("ip")),
            ("addr", object(vec![("map", lookup)])),
            ("type_flags", json!(["concat"])),
        ]),
    )])
}

fn accept() -> Value {
    json!({"accept": null})
}

fn drop() -> Value {
    json!({"drop": null})
}

fn masquerade() -> Value {
    json!({"masquerade": null})
}

// --- chains ----------------------------------------------------------------------------------

/// Reverse-path filtering in nft, not sysctl (SPEC §7.4): strict (`saddr . iif`) on LAN zones,
/// loose on WAN zones. DHCP is exempt in both directions: server replies reach a client that
/// has no address yet, and LAN DISCOVERs come from 0.0.0.0; neither passes a route lookup.
fn rpfilter_chain() -> Vec<Value> {
    vec![
        chain("rpfilter", "filter", "prerouting", -300, "accept"),
        rule(
            "rpfilter",
            vec![
                eq(
                    object(vec![(
                        "concat",
                        Value::Array(vec![payload("udp", "sport"), payload("udp", "dport")]),
                    )]),
                    json!({"set": [{"concat": [67, 68]}, {"concat": [68, 67]}]}),
                ),
                accept(),
            ],
        ),
        rule(
            "rpfilter",
            vec![iifname_in("lan_if"), fib_saddr_oif_missing(true), drop()],
        ),
        rule(
            "rpfilter",
            vec![iifname_in("wan_if"), fib_saddr_oif_missing(false), drop()],
        ),
    ]
}

/// Traffic to the router itself: default drop (SPEC §9).
fn input_chain(wan_ping: bool) -> Vec<Value> {
    let mut rules = vec![
        chain("input", "filter", "input", 0, "drop"),
        rule(
            "input",
            vec![ct_state(json!(["established", "related"])), accept()],
        ),
        rule("input", vec![ct_state(json!("invalid")), drop()]),
        rule("input", vec![eq(meta("iif"), json!("lo")), accept()]),
        rule(
            "input",
            vec![
                iifname_in("lan_if"),
                eq(payload("udp", "dport"), json!({"set": LAN_UDP_SERVICES})),
                accept(),
            ],
        ),
        rule(
            "input",
            vec![
                iifname_in("lan_if"),
                eq(payload("tcp", "dport"), json!({"set": LAN_TCP_SERVICES})),
                accept(),
            ],
        ),
        rule(
            "input",
            vec![
                iifname_in("lan_if"),
                eq(meta("l4proto"), json!({"set": ["icmp", "icmpv6"]})),
                accept(),
            ],
        ),
        rule(
            "input",
            vec![
                iifname_in("wan_if"),
                eq(payload("udp", "sport"), json!(67)),
                eq(payload("udp", "dport"), json!(68)),
                accept(),
            ],
        ),
    ];
    if wan_ping {
        rules.push(rule(
            "input",
            vec![
                iifname_in("wan_if"),
                eq(payload("icmp", "type"), json!("echo-request")),
                accept(),
            ],
        ));
    }
    rules
}

/// Forwarded traffic: default drop; LAN→WAN, within one LAN, and whatever `dstnat` translated.
fn forward_chain() -> Vec<Value> {
    vec![
        chain("forward", "filter", "forward", 0, "drop"),
        rule(
            "forward",
            vec![ct_state(json!(["established", "related"])), accept()],
        ),
        rule("forward", vec![ct_state(json!("invalid")), drop()]),
        rule("forward", vec![ct_status_dnat(), accept()]),
        rule(
            "forward",
            vec![iifname_in("lan_if"), oifname_in("wan_if"), accept()],
        ),
        rule("forward", vec![iif_oif_pair_in("lan_same"), accept()]),
    ]
}

/// Port forwards from the WAN and, by hairpin, from LAN clients reaching any router address.
fn dstnat_chain() -> Vec<Value> {
    vec![
        chain("dstnat", "nat", "prerouting", -100, "accept"),
        rule(
            "dstnat",
            vec![iifname_in("wan_if"), dnat_map("tcp", "fwd_tcp")],
        ),
        rule(
            "dstnat",
            vec![iifname_in("wan_if"), dnat_map("udp", "fwd_udp")],
        ),
        rule(
            "dstnat",
            vec![
                iifname_in("lan_if"),
                fib_daddr_local(),
                dnat_map("tcp", "fwd_tcp"),
            ],
        ),
        rule(
            "dstnat",
            vec![
                iifname_in("lan_if"),
                fib_daddr_local(),
                dnat_map("udp", "fwd_udp"),
            ],
        ),
    ]
}

/// IPv4 masquerade on WAN zones; hairpinned flows within one LAN are masqueraded to the
/// router's LAN address so the reply comes back through the router (SPEC §7.5).
fn srcnat_chain() -> Vec<Value> {
    vec![
        chain("srcnat", "nat", "postrouting", 100, "accept"),
        rule("srcnat", vec![oifname_in("wan_if"), masquerade()]),
        rule(
            "srcnat",
            vec![iif_oif_pair_in("lan_same"), ct_status_dnat(), masquerade()],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    /// The `add` objects of `kind` in the ruleset.
    fn added<'a>(ruleset: &'a [Value], kind: &str) -> Vec<&'a Value> {
        ruleset
            .iter()
            .filter_map(|object| object.get("add").and_then(|add| add.get(kind)))
            .collect()
    }

    fn rules_of<'a>(ruleset: &'a [Value], chain: &str) -> Vec<&'a Value> {
        added(ruleset, "rule")
            .into_iter()
            .filter(|rule| rule["chain"] == chain)
            .collect()
    }

    fn set_elements(ruleset: &[Value], kind: &str, name: &str) -> Value {
        added(ruleset, kind)
            .into_iter()
            .find(|object| object["name"] == name)
            .map(|object| object.get("elem").cloned().unwrap_or(Value::Null))
            .unwrap()
    }

    fn mentions(rule: &Value, text: &str) -> bool {
        rule.to_string().contains(text)
    }

    #[test]
    fn static_world_ruleset() {
        let desired = nft(&fixtures::static_world());
        assert!(desired.forwarding);
        assert_eq!(desired.wan_if, BTreeSet::from(["p0".to_owned()]));
        assert_eq!(desired.lan_if, BTreeSet::from(["br-lan0".to_owned()]));
        assert_eq!(
            desired.ruleset[..3],
            [
                json!({"add": {"table": {"family": "inet", "name": "openfeo"}}}),
                json!({"delete": {"table": {"family": "inet", "name": "openfeo"}}}),
                json!({"add": {"table": {"family": "inet", "name": "openfeo"}}}),
            ]
        );
        assert_eq!(
            set_elements(&desired.ruleset, "set", "wan_if"),
            json!(["p0"])
        );
        assert_eq!(
            set_elements(&desired.ruleset, "set", "lan_same"),
            json!([{"concat": ["br-lan0", "br-lan0"]}])
        );
        assert_eq!(
            set_elements(&desired.ruleset, "map", "fwd_tcp"),
            json!([[2222, {"concat": ["192.168.1.2", 8080]}]])
        );
        assert_eq!(
            set_elements(&desired.ruleset, "map", "fwd_udp"),
            Value::Null
        );
        let chains: Vec<&str> = added(&desired.ruleset, "chain")
            .iter()
            .map(|chain| chain["name"].as_str().unwrap())
            .collect();
        assert_eq!(chains, ["rpfilter", "input", "forward", "dstnat", "srcnat"]);
        assert!(
            rules_of(&desired.ruleset, "input")
                .iter()
                .any(|rule| mentions(rule, "echo-request")),
            "wan_ping = true in the fixture"
        );
        insta::assert_yaml_snapshot!(desired);
    }

    #[test]
    fn first_boot_ruleset_forwards_nothing() {
        let desired = nft(&fixtures::first_boot_world());
        assert!(!desired.forwarding);
        assert!(desired.wan_if.is_empty());
        assert_eq!(desired.lan_if, BTreeSet::from(["br-lan0".to_owned()]));
        assert_eq!(set_elements(&desired.ruleset, "set", "wan_if"), Value::Null);
        assert_eq!(
            set_elements(&desired.ruleset, "map", "fwd_tcp"),
            Value::Null
        );
        let input = rules_of(&desired.ruleset, "input");
        assert!(
            input
                .iter()
                .any(|rule| mentions(rule, "@lan_if") && mentions(rule, "\"dport\"")),
            "LAN -> router services stay accepted"
        );
        assert!(
            !input.iter().any(|rule| mentions(rule, "echo-request")),
            "wan_ping defaults to off"
        );
        insta::assert_yaml_snapshot!(desired);
    }

    #[test]
    fn to_port_zero_means_same_port_and_udp_goes_to_its_map() {
        let mut world = fixtures::static_world();
        let mut config = (*world.config).clone();
        let firewall = config.firewall.as_mut().unwrap();
        firewall.port_forwards.push(openfeo_config::PortForward {
            name: "game".into(),
            proto: "udp".into(),
            port: 27015,
            to: "192.168.1.9".into(),
            to_port: 0,
        });
        world.config = std::sync::Arc::new(config);
        let desired = nft(&world);
        assert_eq!(
            set_elements(&desired.ruleset, "map", "fwd_udp"),
            json!([[27015, {"concat": ["192.168.1.9", 27015]}]])
        );
    }
}
