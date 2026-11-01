// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The firewall and NAT ruleset (SPEC §7.4 reverse-path filtering, §7.5, §9) as the libnftables
//! JSON `nftables` array for one `table inet openfeo`, regenerated from the World. The batch
//! begins `add table; delete table; add table` so applying it replaces the table atomically and
//! idempotently. Zones and the policy between them are named sets of interface names (`wan_if`,
//! `lan_if`, the private and DHCP-served public LANs, `lan_to_wan`, the `lan_pairs` a LAN may
//! initiate into), the translated sources a set of subnets (`nat_nets`), port forwards maps
//! (`fwd_tcp`, `fwd_udp` on the router's own addresses, `fwd_pub_tcp`, `fwd_pub_udp` on
//! public-block addresses), and `[[firewall.rules]]` concatenated interval sets (`rules_tcp`,
//! `rules_udp`, `rules_other`, `rules_any`): rule counts never grow with the configuration.
//!
//! Chains: `rpfilter` (prerouting -300: strict reverse-path on LAN, loose on WAN, DHCP exempt),
//! `input` (drop; LAN→router services by LAN kind, WAN→router only the DHCPv4 client's replies
//! and, when `wan_ping`, rate-limited echo requests), `forward` (drop; translated flows from a
//! WAN or along an allowed pair, the rules, LAN→WAN for LANs that reach it, the allowed pairs),
//! `dstnat` (port forwards from WAN and, by hairpin, from LAN clients reaching the forward's
//! address), `srcnat` (masquerade of private LAN subnets on WAN; hairpinned flows masqueraded to
//! the router's LAN address).

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use openfeo_config::Firewall;
use openfeo_config::rules::{self as rule_syntax, Target};
use openfeo_world::World;
use serde::Serialize;
use serde_json::{Value, json};

use crate::{TABLE, bridge_name, public, wan_ifname};

/// The table's family: one ruleset for IPv4 and IPv6 (SPEC §9).
pub const FAMILY: &str = "inet";
/// LAN→router UDP services: DNS, DHCP, NTP.
pub const LAN_UDP_SERVICES: [u16; 3] = [53, 67, 123];
/// LAN→router TCP services: DNS, HTTP, HTTPS.
pub const LAN_TCP_SERVICES: [u16; 3] = [53, 80, 443];
/// Echo requests accepted on the WAN per second, when `wan_ping` is on (SPEC §7.5).
pub const ECHO_RATE: u32 = 50;
/// The burst the echo limit tolerates.
pub const ECHO_BURST: u32 = 100;

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
/// Port forwards on public-block addresses: (address, port) → (LAN address, LAN port).
type PubForwards = BTreeMap<(Ipv4Addr, u16), (Ipv4Addr, u16)>;

/// The zones and the policy between them (SPEC §7.5), as set contents.
#[derive(Default)]
struct Zones {
    /// WAN interfaces.
    wan_if: BTreeSet<String>,
    /// Every LAN bridge.
    lan_if: BTreeSet<String>,
    /// Private LANs: the router's services and masquerade apply.
    lan_priv_if: BTreeSet<String>,
    /// Public LANs that run the DHCP server: DHCP, DNS and NTP from the router.
    lan_pub_dhcp_if: BTreeSet<String>,
    /// LANs whose `reaches` includes the WAN.
    lan_to_wan: BTreeSet<String>,
    /// (source LAN, destination LAN) pairs a LAN may initiate into, itself included.
    lan_pairs: BTreeSet<(String, String)>,
    /// The private LANs' subnets: the masqueraded sources.
    nat_nets: Vec<Ipv4Net>,
}

/// The four port-forward maps.
#[derive(Default)]
struct ForwardMaps {
    tcp: Forwards,
    udp: Forwards,
    pub_tcp: PubForwards,
    pub_udp: PubForwards,
}

/// The `[[firewall.rules]]` as set elements, by protocol.
#[derive(Default)]
struct RuleSets {
    tcp: Vec<Value>,
    udp: Vec<Value>,
    other: Vec<Value>,
    any: Vec<Value>,
}

/// The ruleset the World calls for. A WAN whose port the map does not know contributes no
/// interface; a forward or rule whose text does not parse is left out (validation already
/// rejected it).
#[must_use]
pub fn nft(world: &World) -> DesiredNft {
    let zones = zones(world);
    let firewall = world.config.firewall.as_ref();
    let wan_ping = firewall.is_some_and(|f| f.wan_ping);
    let forwards = forwards(firewall);
    let rules = rule_sets(firewall, &zones.wan_if);

    let mut ruleset = vec![
        json!({"add": {"table": table()}}),
        json!({"delete": {"table": table()}}),
        json!({"add": {"table": table()}}),
        ifname_set("wan_if", &zones.wan_if),
        ifname_set("lan_if", &zones.lan_if),
        ifname_set("lan_priv_if", &zones.lan_priv_if),
        ifname_set("lan_pub_dhcp_if", &zones.lan_pub_dhcp_if),
        ifname_set("lan_to_wan", &zones.lan_to_wan),
        ifname_pair_set("lan_same", &zones.lan_if),
        pair_set("lan_pairs", &zones.lan_pairs),
        ipv4_set("nat_nets", &zones.nat_nets),
        forward_map("fwd_tcp", &forwards.tcp),
        forward_map("fwd_udp", &forwards.udp),
        pub_forward_map("fwd_pub_tcp", &forwards.pub_tcp),
        pub_forward_map("fwd_pub_udp", &forwards.pub_udp),
        concat_set(
            "rules_tcp",
            &["ifname", "ipv4_addr", "inet_service"],
            rules.tcp,
        ),
        concat_set(
            "rules_udp",
            &["ifname", "ipv4_addr", "inet_service"],
            rules.udp,
        ),
        concat_set(
            "rules_other",
            &["ifname", "ipv4_addr", "inet_proto"],
            rules.other,
        ),
        concat_set("rules_any", &["ifname", "ipv4_addr"], rules.any),
    ];
    ruleset.extend(rpfilter_chain());
    ruleset.extend(input_chain(wan_ping));
    ruleset.extend(forward_chain());
    ruleset.extend(dstnat_chain());
    ruleset.extend(srcnat_chain());

    DesiredNft {
        ruleset,
        forwarding: !zones.wan_if.is_empty() && !zones.lan_if.is_empty(),
        wan_if: zones.wan_if,
        lan_if: zones.lan_if,
    }
}

/// Zones from the config: WAN interfaces, every LAN, the private and DHCP-served public LANs,
/// and each LAN's `reaches` as the WAN set and the pair set (absent means the WAN alone, `none`
/// means nothing beyond the LAN itself).
fn zones(world: &World) -> Zones {
    let config = &world.config;
    let mut zones = Zones {
        wan_if: config
            .wans
            .iter()
            .filter(|wan| world.ports.id_of(&wan.port).is_some())
            .map(wan_ifname)
            .collect(),
        ..Zones::default()
    };
    let blocks = public::blocks(config);
    for lan in &config.lans {
        let bridge = bridge_name(&lan.name);
        zones.lan_if.insert(bridge.clone());
        if public::lan_is_public(lan, &blocks) {
            if lan.dhcp.is_some() {
                zones.lan_pub_dhcp_if.insert(bridge.clone());
            }
        } else {
            zones.lan_priv_if.insert(bridge.clone());
            zones.nat_nets.extend(public::lan_subnet(lan));
        }
        zones.lan_pairs.insert((bridge.clone(), bridge.clone()));
        let reaches: Vec<&str> = if lan.reaches.is_empty() {
            vec!["wan"]
        } else {
            lan.reaches.iter().map(String::as_str).collect()
        };
        for zone in reaches {
            match zone {
                "wan" => {
                    zones.lan_to_wan.insert(bridge.clone());
                }
                "none" => {}
                other => {
                    zones.lan_pairs.insert((bridge.clone(), bridge_name(other)));
                }
            }
        }
    }
    zones
}

fn forwards(firewall: Option<&Firewall>) -> ForwardMaps {
    let mut maps = ForwardMaps::default();
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
        let address = if forward.address.is_empty() {
            None
        } else if let Ok(address) = forward.address.parse::<Ipv4Addr>() {
            Some(address)
        } else {
            continue;
        };
        match (forward.proto.as_str(), address) {
            ("tcp", None) => {
                maps.tcp.insert(port, (to, to_port));
            }
            ("udp", None) => {
                maps.udp.insert(port, (to, to_port));
            }
            ("tcp", Some(address)) => {
                maps.pub_tcp.insert((address, port), (to, to_port));
            }
            ("udp", Some(address)) => {
                maps.pub_udp.insert((address, port), (to, to_port));
            }
            _ => {}
        }
    }
    maps
}

/// `[[firewall.rules]]` as elements of the four rules sets: one element per interface the zone
/// `from` stands for (every WAN interface for `wan`, the bridge for a LAN), per target, and per
/// port range for tcp/udp.
fn rule_sets(firewall: Option<&Firewall>, wan_if: &BTreeSet<String>) -> RuleSets {
    let mut sets = RuleSets::default();
    for rule in firewall.into_iter().flat_map(|f| &f.rules) {
        let Some(target) = rule_syntax::parse_target(&rule.to) else {
            continue;
        };
        let target = target_element(target);
        let ifnames: Vec<String> = if rule.from == "wan" {
            wan_if.iter().cloned().collect()
        } else {
            vec![bridge_name(&rule.from)]
        };
        for ifname in ifnames {
            match rule.proto.as_str() {
                "tcp" | "udp" => {
                    let Some(ports) = rule_syntax::parse_ports(&rule.ports) else {
                        continue;
                    };
                    let bucket = if rule.proto == "tcp" {
                        &mut sets.tcp
                    } else {
                        &mut sets.udp
                    };
                    for (first, last) in &ports {
                        let port = if first == last {
                            json!(first)
                        } else {
                            json!({"range": [first, last]})
                        };
                        bucket.push(json!({"concat": [ifname, target, port]}));
                    }
                }
                "icmp" => sets.other.push(json!({"concat": [ifname, target, "icmp"]})),
                "any" => sets.any.push(json!({"concat": [ifname, target]})),
                _ => {}
            }
        }
    }
    sets
}

/// A rule's target as a set element: an address, a `range`, or a `prefix`.
fn target_element(target: Target) -> Value {
    match target {
        Target::Addr(addr) => json!(addr.to_string()),
        Target::Range(first, last) => json!({"range": [first.to_string(), last.to_string()]}),
        Target::Net(net) => prefix_element(net),
    }
}

/// `{"prefix": {"addr": …, "len": …}}`.
fn prefix_element(net: Ipv4Net) -> Value {
    json!({"prefix": {"addr": net.network().to_string(), "len": net.prefix_len()}})
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

/// `set <name> { type ifname . ifname; elements = { a . b, … } }` for the given pairs.
fn pair_set(name: &str, pairs: &BTreeSet<(String, String)>) -> Value {
    let mut set = json!({
        "family": FAMILY, "table": TABLE, "name": name, "type": ["ifname", "ifname"]
    });
    if !pairs.is_empty() {
        let elements: Vec<Value> = pairs
            .iter()
            .map(|(from, to)| json!({"concat": [from, to]}))
            .collect();
        set["elem"] = Value::Array(elements);
    }
    json!({"add": {"set": set}})
}

/// `set <name> { type ipv4_addr; flags interval; elements = { net, … } }`.
fn ipv4_set(name: &str, nets: &[Ipv4Net]) -> Value {
    let mut set = json!({
        "family": FAMILY, "table": TABLE, "name": name, "type": "ipv4_addr", "flags": ["interval"]
    });
    if !nets.is_empty() {
        set["elem"] = Value::Array(nets.iter().copied().map(prefix_element).collect());
    }
    json!({"add": {"set": set}})
}

/// `set <name> { type <a> . <b> …; flags interval; elements = … }`: the rules sets.
fn concat_set(name: &str, types: &[&str], elements: Vec<Value>) -> Value {
    let mut set = json!({
        "family": FAMILY, "table": TABLE, "name": name, "type": types, "flags": ["interval"]
    });
    if !elements.is_empty() {
        set["elem"] = Value::Array(elements);
    }
    json!({"add": {"set": set}})
}

/// `map <name> { type ipv4_addr . inet_service : ipv4_addr . inet_service }`: forwards on
/// public-block addresses, keyed by the address and port they listen on.
fn pub_forward_map(name: &str, forwards: &PubForwards) -> Value {
    let mut map = json!({
        "family": FAMILY, "table": TABLE, "name": name,
        "type": ["ipv4_addr", "inet_service"], "map": ["ipv4_addr", "inet_service"]
    });
    if !forwards.is_empty() {
        let elements: Vec<Value> = forwards
            .iter()
            .map(|((address, port), (to, to_port))| {
                json!([
                    {"concat": [address.to_string(), port]},
                    {"concat": [to.to_string(), to_port]}
                ])
            })
            .collect();
        map["elem"] = Value::Array(elements);
    }
    json!({"add": {"map": map}})
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
    dnat_lookup(payload(protocol, "dport"), map)
}

/// `dnat ip addr . port to ip daddr . <proto> dport map @<map>`: forwards on public addresses.
fn dnat_pub_map(protocol: &str, map: &str) -> Value {
    dnat_lookup(
        object(vec![(
            "concat",
            Value::Array(vec![payload("ip", "daddr"), payload(protocol, "dport")]),
        )]),
        map,
    )
}

fn dnat_lookup(key: Value, map: &str) -> Value {
    let lookup = object(vec![("key", key), ("data", json!(format!("@{map}")))]);
    object(vec![(
        "dnat",
        object(vec![
            ("family", json!("ip")),
            ("addr", object(vec![("map", lookup)])),
            ("type_flags", json!(["concat"])),
        ]),
    )])
}

/// `<exprs concatenated> @<set>`.
fn concat_in(exprs: Vec<Value>, set: &str) -> Value {
    eq(
        object(vec![("concat", Value::Array(exprs))]),
        json!(format!("@{set}")),
    )
}

/// `limit rate <rate>/second burst <burst> packets`.
fn limit(rate: u32, burst: u32) -> Value {
    json!({"limit": {"rate": rate, "per": "second", "burst": burst}})
}

/// `meta nfproto ipv4`: the rule applies to IPv4 packets only.
fn ipv4_only() -> Value {
    eq(meta("nfproto"), json!("ipv4"))
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

/// Traffic to the router itself: default drop (SPEC §9). A private LAN gets DHCP, DNS, HTTP(S),
/// NTP and ICMP; a public LAN gets ICMP, and DHCP, DNS and NTP only when it runs the DHCP server;
/// the WAN gets the DHCPv4 client's replies and, when asked, rate-limited echo.
fn input_chain(wan_ping: bool) -> Vec<Value> {
    let mut rules = vec![
        chain("input", "filter", "input", 0, "drop"),
        rule(
            "input",
            vec![ct_state(json!(["established", "related"])), accept()],
        ),
        rule("input", vec![ct_state(json!("invalid")), drop()]),
        rule("input", vec![eq(meta("iif"), json!("lo")), accept()]),
        service_rule("lan_priv_if", "udp", json!({"set": LAN_UDP_SERVICES})),
        service_rule("lan_pub_dhcp_if", "udp", json!({"set": LAN_UDP_SERVICES})),
        service_rule("lan_priv_if", "tcp", json!({"set": LAN_TCP_SERVICES})),
        service_rule("lan_pub_dhcp_if", "tcp", json!(53)),
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
                limit(ECHO_RATE, ECHO_BURST),
                accept(),
            ],
        ));
    }
    rules
}

/// `iifname @<set> <proto> dport <ports> accept`.
fn service_rule(set: &str, protocol: &str, ports: Value) -> Value {
    rule(
        "input",
        vec![
            iifname_in(set),
            eq(payload(protocol, "dport"), ports),
            accept(),
        ],
    )
}

/// Forwarded traffic: default drop. Translated flows from a WAN, and from a LAN only along an
/// allowed pair; the rules; LAN→WAN for the LANs that reach it; the allowed LAN pairs (every LAN
/// with itself, plus its `reaches`).
fn forward_chain() -> Vec<Value> {
    vec![
        chain("forward", "filter", "forward", 0, "drop"),
        rule(
            "forward",
            vec![ct_state(json!(["established", "related"])), accept()],
        ),
        rule("forward", vec![ct_state(json!("invalid")), drop()]),
        rule(
            "forward",
            vec![ct_status_dnat(), iifname_in("wan_if"), accept()],
        ),
        rule(
            "forward",
            vec![ct_status_dnat(), iif_oif_pair_in("lan_pairs"), accept()],
        ),
        rule(
            "forward",
            vec![
                concat_in(
                    vec![
                        meta("iifname"),
                        payload("ip", "daddr"),
                        payload("tcp", "dport"),
                    ],
                    "rules_tcp",
                ),
                accept(),
            ],
        ),
        rule(
            "forward",
            vec![
                concat_in(
                    vec![
                        meta("iifname"),
                        payload("ip", "daddr"),
                        payload("udp", "dport"),
                    ],
                    "rules_udp",
                ),
                accept(),
            ],
        ),
        rule(
            "forward",
            vec![
                concat_in(
                    vec![meta("iifname"), payload("ip", "daddr"), meta("l4proto")],
                    "rules_other",
                ),
                accept(),
            ],
        ),
        rule(
            "forward",
            vec![
                concat_in(vec![meta("iifname"), payload("ip", "daddr")], "rules_any"),
                accept(),
            ],
        ),
        rule(
            "forward",
            vec![iifname_in("lan_to_wan"), oifname_in("wan_if"), accept()],
        ),
        rule("forward", vec![iif_oif_pair_in("lan_pairs"), accept()]),
    ]
}

/// Port forwards: on the router's own addresses (`fib daddr type local`, so a forward there
/// never answers on a public-block address) and on public-block addresses, from the WAN and, by
/// hairpin, from LAN clients reaching the same address.
fn dstnat_chain() -> Vec<Value> {
    let mut rules = vec![chain("dstnat", "nat", "prerouting", -100, "accept")];
    for zone in ["wan_if", "lan_if"] {
        for protocol in ["tcp", "udp"] {
            rules.push(rule(
                "dstnat",
                vec![
                    iifname_in(zone),
                    fib_daddr_local(),
                    dnat_map(protocol, &format!("fwd_{protocol}")),
                ],
            ));
            rules.push(rule(
                "dstnat",
                vec![
                    iifname_in(zone),
                    dnat_pub_map(protocol, &format!("fwd_pub_{protocol}")),
                ],
            ));
        }
    }
    rules
}

/// IPv4 masquerade of the private LANs' subnets on WAN zones (a public LAN leaves with its own
/// addresses); hairpinned flows within one LAN are masqueraded to the router's LAN address so the
/// reply comes back through the router (SPEC §7.5). Every rule matches `meta nfproto ipv4`
/// first: in an `inet` table a bare `masquerade` would translate IPv6 too, and §7.5 says no IPv6
/// NAT.
fn srcnat_chain() -> Vec<Value> {
    vec![
        chain("srcnat", "nat", "postrouting", 100, "accept"),
        rule(
            "srcnat",
            vec![
                ipv4_only(),
                eq(payload("ip", "saddr"), json!("@nat_nets")),
                oifname_in("wan_if"),
                masquerade(),
            ],
        ),
        rule(
            "srcnat",
            vec![
                ipv4_only(),
                iif_oif_pair_in("lan_same"),
                ct_status_dnat(),
                masquerade(),
            ],
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

    fn position(rules: &[&Value], text: &str) -> usize {
        rules
            .iter()
            .position(|rule| mentions(rule, text))
            .unwrap_or_else(|| panic!("no rule mentions {text}: {rules:?}"))
    }

    #[test]
    fn reaches_builds_the_pairs_and_the_wan_set() {
        let d = nft(&fixtures::vlans_world());
        assert_eq!(
            set_elements(&d.ruleset, "set", "lan_to_wan"),
            json!(["br-guest", "br-lan0", "br-trusted"])
        );
        let pairs = set_elements(&d.ruleset, "set", "lan_pairs");
        let pairs = pairs.as_array().unwrap();
        assert!(pairs.contains(&json!({"concat": ["br-trusted", "br-lan0"]})));
        assert!(pairs.contains(&json!({"concat": ["br-trusted", "br-guest"]})));
        assert!(pairs.contains(&json!({"concat": ["br-guest", "br-guest"]})));
        assert!(!pairs.contains(&json!({"concat": ["br-lan0", "br-trusted"]})));
        assert_eq!(pairs.len(), 5, "{pairs:?}");
        assert_eq!(
            set_elements(&d.ruleset, "set", "lan_same")
                .as_array()
                .unwrap()
                .len(),
            3,
            "the hairpin masquerade keeps its self pairs"
        );
    }

    #[test]
    fn translated_flows_follow_the_policy() {
        let d = nft(&fixtures::vlans_world());
        let forward = rules_of(&d.ruleset, "forward");
        let dnat: Vec<&&Value> = forward
            .iter()
            .filter(|rule| mentions(rule, "\"dnat\""))
            .collect();
        assert_eq!(dnat.len(), 2, "{forward:?}");
        assert!(mentions(dnat[0], "@wan_if") && !mentions(dnat[0], "lan_pairs"));
        assert!(mentions(dnat[1], "@lan_pairs"));
    }

    #[test]
    fn a_lan_reaching_none_is_in_no_set_but_its_own_pair() {
        let mut world = fixtures::vlans_world();
        let mut config = (*world.config).clone();
        config.lans[1].reaches = vec!["none".into()];
        world.config = std::sync::Arc::new(config);
        let d = nft(&world);
        assert_eq!(
            set_elements(&d.ruleset, "set", "lan_to_wan"),
            json!(["br-lan0", "br-trusted"])
        );
        let pairs = set_elements(&d.ruleset, "set", "lan_pairs");
        assert!(
            pairs
                .as_array()
                .unwrap()
                .contains(&json!({"concat": ["br-guest", "br-guest"]}))
        );
    }

    #[test]
    fn public_lans_are_not_translated_and_get_fewer_services() {
        let d = nft(&fixtures::public_world());
        assert_eq!(
            set_elements(&d.ruleset, "set", "nat_nets"),
            json!([{"prefix": {"addr": "192.168.1.0", "len": 24}}])
        );
        assert_eq!(
            set_elements(&d.ruleset, "set", "lan_priv_if"),
            json!(["br-lan0"])
        );
        assert_eq!(
            set_elements(&d.ruleset, "set", "lan_pub_dhcp_if"),
            Value::Null,
            "the DMZ runs no DHCP"
        );
        assert_eq!(
            set_elements(&d.ruleset, "set", "lan_if"),
            json!(["br-dmz", "br-lan0"])
        );
        let srcnat = rules_of(&d.ruleset, "srcnat");
        assert!(mentions(srcnat[0], "@nat_nets"), "{srcnat:?}");
        let input = rules_of(&d.ruleset, "input");
        assert!(
            input
                .iter()
                .any(|rule| mentions(rule, "@lan_pub_dhcp_if") && mentions(rule, "\"dport\""))
        );
        assert!(
            !input
                .iter()
                .any(|rule| mentions(rule, "@lan_if") && mentions(rule, "\"dport\"")),
            "services are per LAN kind, ICMP alone is for every LAN"
        );
        insta::assert_yaml_snapshot!(d);
    }

    #[test]
    fn wan_address_forwards_match_only_local_addresses_and_public_ones_match_their_address() {
        let d = nft(&fixtures::public_world());
        let dstnat = rules_of(&d.ruleset, "dstnat");
        assert!(
            mentions(dstnat[0], "@wan_if")
                && mentions(dstnat[0], "\"local\"")
                && mentions(dstnat[0], "@fwd_tcp"),
            "{:?}",
            dstnat[0]
        );
        assert_eq!(
            set_elements(&d.ruleset, "map", "fwd_pub_tcp"),
            json!([[{"concat": ["192.0.2.249", 443]}, {"concat": ["192.168.1.2", 8080]}]])
        );
        assert_eq!(
            set_elements(&d.ruleset, "map", "fwd_tcp"),
            json!([[2222, {"concat": ["192.168.1.2", 8080]}]])
        );
        assert!(
            dstnat
                .iter()
                .any(|rule| mentions(rule, "@lan_if") && mentions(rule, "@fwd_pub_tcp")),
            "hairpin by the public address"
        );
    }

    #[test]
    fn rules_land_in_their_sets_one_element_per_wan_interface() {
        let d = nft(&fixtures::public_world());
        assert_eq!(
            set_elements(&d.ruleset, "set", "rules_tcp"),
            json!([{"concat": ["p0", {"range": ["192.0.2.234", "192.0.2.238"]}, 80]}])
        );
        assert_eq!(set_elements(&d.ruleset, "set", "rules_udp"), Value::Null);
        let forward = rules_of(&d.ruleset, "forward");
        assert!(position(&forward, "@rules_tcp") < position(&forward, "@lan_to_wan"));
        assert!(position(&forward, "@wan_if") < position(&forward, "@rules_tcp"));
    }

    #[test]
    fn wan_echo_is_rate_limited() {
        let d = nft(&fixtures::static_world());
        let input = rules_of(&d.ruleset, "input");
        let echo = input
            .iter()
            .find(|rule| mentions(rule, "echo-request"))
            .unwrap();
        assert!(
            mentions(echo, "\"limit\"") && mentions(echo, "\"rate\":50"),
            "{echo}"
        );
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
                .any(|rule| mentions(rule, "@lan_priv_if") && mentions(rule, "\"dport\"")),
            "LAN -> router services stay accepted (the first-boot LAN is private)"
        );
        assert!(
            !input.iter().any(|rule| mentions(rule, "echo-request")),
            "wan_ping defaults to off"
        );
        insta::assert_yaml_snapshot!(desired);
    }

    /// SPEC §7.5: IPv4 masquerade per WAN, no IPv6 NAT. In an `inet` table a bare `masquerade`
    /// translates both families, so every masquerade rule must match `meta nfproto ipv4`.
    #[test]
    fn masquerade_is_ipv4_only() {
        let desired = nft(&fixtures::static_world());
        let srcnat = rules_of(&desired.ruleset, "srcnat");
        let masquerades: Vec<&&Value> = srcnat
            .iter()
            .filter(|rule| mentions(rule, "\"masquerade\""))
            .collect();
        assert_eq!(masquerades.len(), 2, "{srcnat:?}");
        let ipv4_guard =
            json!({"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}});
        for rule in masquerades {
            let expr = rule["expr"].as_array().unwrap();
            assert_eq!(
                expr[0], ipv4_guard,
                "masquerade without an IPv4 guard: {rule}"
            );
        }
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
            address: String::new(),
        });
        world.config = std::sync::Arc::new(config);
        let desired = nft(&world);
        assert_eq!(
            set_elements(&desired.ruleset, "map", "fwd_udp"),
            json!([[27015, {"concat": ["192.168.1.9", 27015]}]])
        );
    }
}
