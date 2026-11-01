# M2 Part 1: LAN VLANs, Public IPv4 Blocks and Zone Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A LAN member may be a tagged VLAN on a port, a LAN may be numbered from a declared public block the ISP routes to the router (no translation, inbound by rule), each LAN says which zones it reaches, and firewall rules open single holes; all IPv4, all proven in the harness.

**Architecture:** The schema grows four things (`pN.V` members and an honoured `Wan.vlan`, `[[public_ipv4]]`, `Lan.reaches`, `[[firewall.rules]]` and `PortForward.address`) and validation learns their rules. The netlink crate gains a VLAN link primitive and blackhole routes; the links reconciler produces VLAN sub-interfaces as bridge members and the WAN's interface name becomes `pN.V` when tagged; routing adds a blackhole per block; the nft generator grows named sets for the policy (`lan_to_wan`, `lan_pairs`), the private subnets that are translated (`nat_nets`), public-address forwards (`fwd_pub_*`), rules (`rules_*`) and public LANs' reduced services; the DNS reconciler separates the rebinding guard from the reverse zones. The lab gains an opt-in second LAN namespace, VLAN client namespaces, a tagged ISP side and routed blocks, and a new `m2` QEMU suite.

**Tech Stack:** Rust stable 2024, prost/pbjson, rtnetlink 0.23 (`LinkVlan`, `RouteMessageBuilder::kind`), netlink-packet-route 0.33, libnftables JSON, insta, cargo-fuzz; the lab (QEMU, Kea, busybox udhcpc, python3 http.server).

**Spec:** `docs/superpowers/specs/2026-11-01-m2-part1-lan-vlans-public-blocks-zone-rules-design.md` (the design, approved 2026-11-01), arguing from `SPEC.md` §7.1, §7.2, §7.4, §7.5, §7.7, §8.2, §11, §12. Task 1 amends the SPEC and adds ADR-0017; the anchors used below are from `main` at 3fb43e8.

## Global Constraints

- Every source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton` (TOML and YAML with `#`).
- `#![forbid(unsafe_code)]` everywhere except `openfeo-init`, `openfeo-nft` and `openfeo-net` (ADR-0013). No new `unsafe` in this plan.
- Pure crates (`openfeo-proto-*`, `openfeo-reconcile`, `openfeo-world`, `openfeo-config`) stay pure; `scripts/check-deps.sh` enforces it.
- Rust stable, edition 2024; `clippy -D warnings` with pedantic on (functions under 100 lines); no `unwrap`/`expect` outside tests; `thiserror` in libraries, `anyhow` only in `crates/openfeo` and `harness/`.
- Commits: `git commit -s`, subject `<area>: <summary>`, trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_0116otzXyvDbuXkw4CsR8ExV`.
- Protobuf: new fields only, numbers never reused (`buf breaking` runs against `origin/main` in `scripts/check-proto.sh`); `config_version` stays 1; `pbjson` reads a repeated string field as strings only.
- Console lines are a contract with the harness: every existing line keeps its text; new lines are listed in their task.
- `export OPENFEO_NFT_SRC=$PWD/build/nft/src OPENFEO_UAPI_INCLUDE=$PWD/build/kernel/headers/include` before a bare `cargo` command; QEMU scenarios need `make kernel` (which embeds the binary) and `OPENFEO_KERNEL=$PWD/build/bzImage`; `make test-harness FILTER=<substring>` matches scenario names, not suite names.
- The fuzz crate sits outside the workspace: after any change to a struct a fuzz target builds, run `cargo check --manifest-path fuzz/Cargo.toml --bins` (the dns_forwarder target broke this way on 2026-11-01; `make lint` gains that check in the `fix-fuzz-dns-forwarder` branch).
- Documentation ranges in fixtures: the ISP side is 203.0.113.0/24 and 198.51.100.0/24 (ISP B, `www.isp.example`, Kea's classless route); public blocks in this plan come from 192.0.2.0/24 only.
- The branch is `m2-1` from `main` at `3fb43e8`; the design is commit `72eb6f1`.

## Review Focus

1. A guest or DMZ host reaching a main-LAN host's forwarded port through the WAN address or a public address: the hairpin must follow the policy, not bypass it. Test `translated_flows_follow_the_policy` (Task 7) and the hairpin check in `tagged_guest_leases_from_its_own_lan_and_reaches_only_the_internet` (Task 9).
2. A WAN packet addressed to a public-block address on a port that a WAN-address forward uses (2222 on `192.0.2.249`) must not be translated by the WAN-address forward: `fib daddr type local` guards those rules. Test `wan_address_forwards_match_only_local_addresses` (Task 7).
3. A LAN numbered from global space that nobody declared under `[[public_ipv4]]` must be refused with a message naming the fix, never translated silently. Test `a_lan_in_global_space_must_be_inside_a_declared_block` (Task 3).
4. A tagged frame for a VLAN no LAN wants must not leak into the port's untagged LAN. Test `a_vlan_nobody_wants_is_dropped_by_the_untagged_bridge` (Task 9).
5. A reverse lookup for a DMZ host must go upstream (the ISP owns that zone), while a private LAN's reverse zone stays local. Test `public_lans_leave_the_guard_and_the_reverse_zones_unless_they_run_dhcp` (Task 8).

---

### Task 1: SPEC amendments and ADR-0017

**Files:**
- Modify: `SPEC.md` (§1.2 L36, §2 L54, §7.1 L240-244, §7.2 L260, §7.4 L279-285, §7.5 L287-294, §7.7 L304-305, §8.2 L333-400, §11 L451, §12 L463-464 and L470)
- Create: `docs/adr/0017-lan-vlans-are-8021q-sub-interfaces-bridged-per-lan.md`
- Modify: `docs/adr/README.md` if an index exists (check `ls docs/adr`)

**Interfaces:** none (documents). Later tasks quote the SPEC's exact words for console text and validation messages where given here.

- [ ] **Step 1: Amend the SPEC**

Write, in the spec's voice, these changes:
- §1.2 L36: "LAN VLANs and multiple LAN zones" → configurable in the file from M2 part 1, not in the MVP panel.
- §2 L54: VLAN filtering "reserved for later LAN VLANs" → "on; LAN VLANs are 802.1Q sub-interfaces of a port bridged into their LAN (ADR-0017)".
- §7.1: a LAN member is a port untagged (`p6`) or a tagged VLAN on a port (`p6.224`, id 1..=4094); a port is untagged in at most one LAN and tagged in any number; a physical port is a WAN or carries LANs, not both.
- §7.2 L260: the VLAN-tagged WAN runs on `pN.V`, where `vlan = V` on the WAN.
- §7.4: every declared public block gets a blackhole route (protocol 200, metric 1000) in `main`; M6 pins a block's egress to the WANs of the account that routes it.
- §7.5: zones gain public LANs; the policy is per LAN (`reaches`, default `["wan"]`, `"none"` for a LAN that initiates into nothing; within one LAN always); translated flows are accepted from a WAN, and from a LAN only when the pair is allowed; rules (`from`, `to`, `proto`, `ports`) open holes and never translate, held in concatenated sets; masquerade covers private LAN subnets only; a public LAN reaches the router for ICMP, and for DHCP, DNS and NTP only when it runs DHCP, never for HTTP(S); echo on the WAN is rate limited at 50/second, burst 100.
- §7.7 L304-305: reverse zones are the private LANs' subnets plus public LANs that run DHCP; the rebinding guard covers the private LANs' subnets and the router's addresses.
- §8.2 example: add `reaches = ["wan"]` to `[[lans]]`, a second LAN with `ports = ["p3.223"]`, `[[public_ipv4]]` with `prefix = "192.0.2.232/29"`, `address = "192.0.2.249"` on a forward (commented "omitted = the WAN address"), and one `[[firewall.rules]]` with `ports = ["80", "443"]`.
- §11 L451: "and `p3` = a second LAN namespace `lan1`, created only by scenarios that need two LANs".
- §12: M2's row gains "part 1: LAN VLANs, routed public IPv4 blocks, per-LAN policy and rules, 802.1Q WAN"; M3's row drops "802.1Q WAN"; the post-MVP sentence keeps "LAN VLANs in the panel".

- [ ] **Step 2: Write ADR-0017**

Header as ADR-0015's plain form (`# 0017 — LAN VLANs are 802.1Q sub-interfaces bridged per LAN`, `Status: Accepted (1 November 2026)`), sections Context, Decision, Consequences with the content of the design's "ADR" section; Consequences also name the M7 revisit (switch-chip offload prefers one VLAN-aware bridge).

- [ ] **Step 3: Check and commit**

Run: `scripts/check-spdx.sh && git diff --stat`
Expected: SPDX clean; `SPEC.md` and the new ADR listed.

```bash
git add SPEC.md docs/adr/0017-lan-vlans-are-8021q-sub-interfaces-bridged-per-lan.md
git commit -s -m "docs: SPEC and ADR-0017 for LAN VLANs, public IPv4 blocks and zone rules"
```

---

### Task 2: Schema and port/VLAN validation

**Files:**
- Modify: `proto/openfeo/v1/config.proto` (Config L11-21, Lan L150-157, Firewall L38-42, PortForward L46-58)
- Modify: `crates/openfeo-config/src/lib.rs:18-22` (re-exports), `crates/openfeo-config/src/validate.rs` (Code L18-73 + `as_str` L136-166, `validate` L198-306, LAN loop L266-286, WAN loop L227-264)
- Create: `crates/openfeo-config/src/portname.rs`
- Modify exhaustive literals: `crates/openfeo-config/src/lib.rs:32`, `load.rs:56-76`, `validate.rs:840-845`, `validate.rs:1078-1084`, `validate.rs:1089-1092`, `crates/openfeo-reconcile/src/nft.rs:584-590`, `harness/tests/netlink.rs:624-629`
- Test: `crates/openfeo-config/src/portname.rs` tests, `validate.rs` `mod tests`

**Interfaces:**
- Produces:

```rust
// proto: Config.public_ipv4 = 8 (repeated PublicIpv4 { string prefix = 1; }),
//        Lan.reaches = 5 (repeated string), Firewall.rules = 3 (repeated Rule),
//        Rule { string name = 1; string from = 2; string to = 3; string proto = 4; repeated string ports = 5; },
//        PortForward.address = 6 (string; "" = the WAN address).
// crates/openfeo-config/src/portname.rs
/// `pN` or `pN.V`: the physical port and, when tagged, the VLAN id (1..=4094).
pub struct PortRef<'a> { pub port: &'a str, pub vlan: Option<u16> }
pub fn parse_port_ref(text: &str) -> Option<PortRef<'_>>;   // None for "p1a", "p1.", "p1.0", "p1.4095", "p1.1.2"
pub fn vlan_ifname(port: &str, vlan: u16) -> String;        // "p1.101"
// validate.rs: new Code variants InvalidVlan, PortRoleConflict (a port both WAN and LAN member)
```

- [ ] **Step 1: Write the failing tests**

```rust
// portname.rs
#[test]
fn port_refs_parse_untagged_and_tagged_names() {
    assert_eq!(parse_port_ref("p1").map(|r| (r.port, r.vlan)), Some(("p1", None)));
    assert_eq!(parse_port_ref("p12.4094").map(|r| (r.port, r.vlan)), Some(("p12", Some(4094))));
    for bad in ["p1.", "p1.0", "p1.4095", "p1.1.2", "p1a", "br-lan0", ".5", "p1.01x"] {
        assert!(parse_port_ref(bad).is_none(), "{bad}");
    }
    assert_eq!(vlan_ifname("p1", 101), "p1.101");
}
// validate.rs tests (helpers base(), lan(), found() exist)
#[test]
fn a_tagged_member_is_accepted_and_its_port_may_carry_other_lans() {
    let mut cfg = base();                                   // lan0 on p1, p2
    cfg.lans.push(lan("guest", &["p1.223", "p2.223"], "192.168.2.1/24"));
    cfg.lans.push(lan("trusted", &["p1.224"], "192.168.3.1/24"));
    assert_eq!(found(&cfg), vec![]);
}
#[test]
fn a_tagged_member_is_refused_twice_and_with_a_bad_vlan() {
    let mut cfg = base();
    cfg.lans.push(lan("guest", &["p1.223"], "192.168.2.1/24"));
    cfg.lans.push(lan("more", &["p1.223"], "192.168.4.1/24"));
    cfg.lans.push(lan("bad", &["p2.4095"], "192.168.5.1/24"));
    let codes: Vec<Code> = found(&cfg).into_iter().map(|(_, c)| c).collect();
    assert!(codes.contains(&Code::PortUsedTwice) && codes.contains(&Code::InvalidVlan), "{codes:?}");
}
#[test]
fn a_wan_port_may_not_carry_a_lan_and_a_wan_vlan_is_checked() {
    let mut cfg = base();                                   // wan0 on p0
    cfg.lans.push(lan("side", &["p0.10"], "192.168.6.1/24"));
    cfg.wans[0].vlan = 4095;
    let codes: Vec<Code> = found(&cfg).into_iter().map(|(_, c)| c).collect();
    assert!(codes.contains(&Code::PortRoleConflict) && codes.contains(&Code::InvalidVlan), "{codes:?}");
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p openfeo-config port_refs a_tagged a_wan_port 2>&1 | tail -20`
Expected: compile errors (`portname` missing, `Code::InvalidVlan` missing).

- [ ] **Step 3: Add the proto fields, re-exports and literal updates; implement `portname.rs` and the validation**

In `validate()`: `used_ports` keeps "untagged or WAN" ownership by physical port; a new `used_tagged: BTreeSet<(&str, u16)>` holds `(port, vlan)`; the WAN loop checks `wan.vlan` (0 or 1..=4094, else `InvalidVlan` "{vlan} is not a VLAN id (1-4094)") and records `(port, vlan)` when tagged; the LAN loop parses each member with `parse_port_ref` (unparseable → the existing `UnknownPort` path via `report.port`, since `live.id_of("p1a")` is none; keep that message), checks the physical port is in the live map, `vlan` in range, then: untagged → `report.port(&mut used_ports, …)` as today; tagged → `PortRoleConflict` ("{port:?} is a WAN port and may not carry a LAN") if the port is any WAN's port, `PortUsedTwice` ("{member:?} is already assigned") if `(port, vlan)` is taken. A WAN whose port is an untagged LAN member keeps today's `PortUsedTwice`. Default `reaches` handling waits for Task 3.

- [ ] **Step 4: Run the tests and the whole config crate**

Run: `cargo test -p openfeo-config 2>&1 | tail -5 && cargo check --manifest-path fuzz/Cargo.toml --bins`
Expected: all pass; fuzz targets compile.

- [ ] **Step 5: Lint and commit**

Run: `make lint 2>&1 | tail -5` (`buf breaking` must accept the additions)
Expected: clean.

```bash
git add proto/openfeo/v1/config.proto crates/openfeo-config crates/openfeo-reconcile/src/nft.rs harness/tests/netlink.rs
git commit -s -m "config: pN.V LAN members and WAN vlan validated; schema fields for public blocks, reaches and rules"
```

---

### Task 3: Validation for public blocks, forward addresses, `reaches` and rules

**Files:**
- Create: `crates/openfeo-config/src/rules.rs`
- Modify: `crates/openfeo-config/src/validate.rs` (`validate` L198-306, `port_forwards` L582-642, Code enum), `crates/openfeo-config/src/lib.rs` (`pub mod rules;`, `pub mod portname;`)
- Modify: `fuzz/fuzz_targets/config_toml.rs` (call `validate` with a four-port map)
- Test: `validate.rs` `mod tests`, `rules.rs` tests

**Interfaces:**
- Produces:

```rust
// crates/openfeo-config/src/rules.rs (pure parsers shared with the nft generator)
pub enum Target { Addr(Ipv4Addr), Range(Ipv4Addr, Ipv4Addr), Net(Ipv4Net) }
pub fn parse_target(text: &str) -> Option<Target>;          // "a", "a-b" (a <= b), "a/n"
impl Target { pub fn within(&self, net: Ipv4Net) -> bool; pub fn bounds(&self) -> (Ipv4Addr, Ipv4Addr); }
pub fn parse_ports(entries: &[String]) -> Option<Vec<(u16, u16)>>;  // "80" → (80,80); "1000-1010"; 1..=65535; a <= b
pub const PROTOS: [&str; 4] = ["tcp", "udp", "icmp", "any"];
pub fn is_global_unicast_v4(net: Ipv4Net) -> bool;          // not RFC 1918, 100.64/10, 127/8, 169.254/16, 224/4, 240/4, 0/8
// validate.rs: Code variants InvalidPublicBlock, UndeclaredPublicLan, InvalidForwardAddress, InvalidZone, InvalidRuleTarget, InvalidRulePorts
// Zone names: "wan", "none", or a LAN name.
```

- [ ] **Step 1: Write the failing tests**

```rust
// rules.rs
#[test]
fn targets_and_ports_parse_in_their_three_shapes() {
    assert!(matches!(parse_target("192.0.2.234"), Some(Target::Addr(_))));
    assert!(matches!(parse_target("192.0.2.234-192.0.2.238"), Some(Target::Range(_, _))));
    assert!(matches!(parse_target("192.0.2.232/29"), Some(Target::Net(_))));
    assert!(parse_target("192.0.2.238-192.0.2.234").is_none());
    assert!(parse_target("192.0.2.234-192.0.2.238").unwrap().within("192.0.2.232/29".parse().unwrap()));
    assert_eq!(parse_ports(&["80".into(), "1000-1010".into()]), Some(vec![(80, 80), (1000, 1010)]));
    for bad in [vec!["0".to_string()], vec!["70000".to_string()], vec!["90-80".to_string()], vec!["a".to_string()], vec![]] {
        assert!(parse_ports(&bad).is_none(), "{bad:?}");
    }
}
// validate.rs tests; helper `public(prefixes: &[&str]) -> Vec<PublicIpv4>`, `rule(name, from, to, proto, ports) -> Rule`
#[test]
fn a_public_lan_is_accepted_inside_a_declared_block() {
    let mut cfg = base();
    cfg.public_ipv4 = public(&["192.0.2.232/29", "192.0.2.248/29"]);
    cfg.lans.push(lan("dmz", &["p2"], "192.0.2.233/29"));        // p2 taken by lan0: PortUsedTwice is the only finding
    cfg.lans[0].ports = vec!["p1".into()];
    assert_eq!(found(&cfg), vec![]);
}
#[test]
fn a_lan_in_global_space_must_be_inside_a_declared_block() {
    let mut cfg = base();
    cfg.lans[0].ipv4 = "192.0.2.233/29".into();
    let v = &validate(&cfg, &live())[0];
    assert_eq!(v.code, Code::UndeclaredPublicLan);
    assert!(v.message.contains("[[public_ipv4]]"), "{}", v.message);
}
#[test]
fn public_blocks_must_be_global_and_disjoint_from_each_other_and_from_private_lans() {
    let mut cfg = base();
    cfg.public_ipv4 = public(&["10.9.0.0/29", "192.0.2.232/29", "192.0.2.232/30", "192.168.1.0/24"]);
    let codes: Vec<Code> = found(&cfg).into_iter().map(|(_, c)| c).collect();
    assert_eq!(codes.iter().filter(|c| **c == Code::InvalidPublicBlock).count(), 3, "{codes:?}");
}
#[test]
fn a_forward_address_comes_from_an_unclaimed_block_and_joins_the_duplicate_key() {
    let mut cfg = with_forwards(vec![forward("a", "tcp", 443, "192.168.1.2", 0), forward("b", "tcp", 443, "192.168.1.3", 0)]);
    cfg.public_ipv4 = public(&["192.0.2.248/29"]);
    cfg.firewall.as_mut().unwrap().port_forwards[1].address = "192.0.2.249".into();
    assert_eq!(found(&cfg), vec![], "same port on two addresses is two forwards");
    cfg.firewall.as_mut().unwrap().port_forwards[0].address = "192.0.2.249".into();
    assert!(found(&cfg).iter().any(|(_, c)| *c == Code::DuplicateForward));
    for bad in ["192.0.2.248", "192.0.2.255", "192.168.1.9", "203.0.113.77", "nope"] {
        cfg.firewall.as_mut().unwrap().port_forwards[0].address = bad.into();
        assert!(found(&cfg).iter().any(|(_, c)| *c == Code::InvalidForwardAddress), "{bad}");
    }
}
#[test]
fn reaches_names_wan_none_or_another_lan() {
    let mut cfg = base();
    cfg.lans.push(lan("guest", &["p1"], "192.168.2.1/24"));
    cfg.lans[0].ports = vec!["p2".into()];
    cfg.lans[0].reaches = vec!["wan".into(), "guest".into()];
    assert_eq!(found(&cfg), vec![]);
    for bad in [vec!["lan0"], vec!["wan", "wan"], vec!["none", "wan"], vec!["dmz"]] {
        cfg.lans[0].reaches = bad.iter().map(|s| (*s).to_owned()).collect();
        assert!(found(&cfg).iter().any(|(_, c)| *c == Code::InvalidZone), "{bad:?}");
    }
}
#[test]
fn rules_name_a_zone_a_target_inside_another_lan_a_proto_and_ports() {
    let mut cfg = base();
    cfg.lans.push(lan("dmz", &["p1"], "192.0.2.233/29"));
    cfg.lans[0].ports = vec!["p2".into()];
    cfg.public_ipv4 = public(&["192.0.2.232/29"]);
    let fw = cfg.firewall.get_or_insert_with(Default::default);
    fw.rules = vec![rule("dmz-web", "wan", "192.0.2.234-192.0.2.238", "tcp", &["80", "443"]),
                    rule("ping-dmz", "lan0", "192.0.2.232/29", "icmp", &[])];
    assert_eq!(found(&cfg), vec![]);
    let cases = [("x", "wan", "192.0.2.234", "tcp", vec![], Code::InvalidRulePorts),
                 ("y", "wan", "192.0.2.234", "icmp", vec!["80"], Code::InvalidRulePorts),
                 ("z", "wan", "192.0.2.234", "gre", vec![], Code::InvalidProto),
                 ("w", "dmz", "192.0.2.234", "tcp", vec!["80"], Code::InvalidRuleTarget),   // to inside from
                 ("v", "wan", "203.0.113.5", "tcp", vec!["80"], Code::InvalidRuleTarget),    // inside no LAN
                 ("u", "nowhere", "192.0.2.234", "tcp", vec!["80"], Code::InvalidZone),
                 ("dmz-web", "wan", "192.0.2.234", "tcp", vec!["80"], Code::DuplicateName)];
    for (name, from, to, proto, ports, code) in cases {
        let mut c = cfg.clone();
        c.firewall.as_mut().unwrap().rules.push(rule(name, from, to, proto, &ports));
        assert!(found(&c).iter().any(|(_, k)| *k == code), "{name}: {:?}", found(&c));
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p openfeo-config rules targets a_public a_lan_in public_blocks a_forward_address reaches_names 2>&1 | tail -20`
Expected: compile errors for the missing module and codes.

- [ ] **Step 3: Implement `rules.rs` and the checks in `validate.rs`**

`validate()` collects `blocks: Vec<(String, Ipv4Net)>` from `public_ipv4` (`report.cidr`, then `is_global_unicast_v4`, else `InvalidPublicBlock` "{prefix:?} is not global unicast space"; overlap with an earlier block, a WAN static subnet or a private LAN → `InvalidPublicBlock` "{prefix} overlaps {other} ({other_path})"); each LAN's subnet (`net.trunc()`) that is global unicast must lie within one block, else `UndeclaredPublicLan` "{ipv4} is public space that no [[public_ipv4]] block declares; declare the block the ISP routes to this router, or use private space"; `lan_public: Vec<bool>` is computed for the firewall checks. `reaches`: empty allowed; each entry `"wan"`, `"none"` or another LAN's name (`InvalidZone` "{entry:?} is not \"wan\", \"none\" or another LAN"), `"none"` alone ("\"none\" stands alone"), no duplicates ("{entry:?} is listed twice"). Port forwards: `forwarded` keyed `(address, proto, port)` with `""` for the WAN address; `address` when set must parse, lie inside a block, outside every LAN subnet, and be neither network nor broadcast of its block (`InvalidForwardAddress`, one message each). Rules: `Report::name` with `MAX_FORWARD_NAME` and their own name set; `from` a zone (`"wan"` or a LAN name; `InvalidZone`); `to` parses and lies within exactly one LAN subnet that is not `from` (`InvalidRuleTarget`); `proto` in `PROTOS` (`InvalidProto` message extended to list the four); `ports` required and valid for tcp/udp, forbidden otherwise (`InvalidRulePorts`). Split the function if `validate()` nears 100 lines (`fn public_blocks(...)`, `fn rules(...)`).

The fuzz target `config_toml.rs`: after `parse`, call `openfeo_config::validate::validate(&config, &ports)` with a fixed `PortMap` of `p0..p3` (build it with the crate's constructor; `parse_portmap` stays).

- [ ] **Step 4: Run the config crate, clippy and the fuzz check**

Run: `cargo test -p openfeo-config 2>&1 | tail -5 && cargo clippy -p openfeo-config --all-targets -- -D warnings && cargo check --manifest-path fuzz/Cargo.toml --bins`
Expected: all pass, clean.

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-config fuzz/fuzz_targets/config_toml.rs
git commit -s -m "config: public blocks, forward addresses, reaches and rules validated; the fuzz target validates too"
```

---

### Task 4: Netlink: VLAN links and blackhole routes

**Files:**
- Modify: `crates/openfeo-netlink/src/types.rs` (`LinkKind` L23-30, `Link` L34-51, `Route` L66-81), `apply.rs` (new `link_add_vlan`, `route_message_builder` L285-318, `describe` L256-272), `monitor.rs` (`link_from` L227-265, `route_from` L287-316), `lib.rs` re-exports
- Modify: `crates/openfeo-apply/src/lib.rs:132-137` (`is_managed`), `crates/openfeo-apply/src/routing.rs:94-120` (route construction), `harness/tests/netlink.rs:290-298` (exhaustive `Route`), `crates/openfeo/src/router.rs:369-387` only if `LinkFact` changes (it does not)
- Test: `harness/tests/netlink.rs` (two new sandbox scenarios), `crates/openfeo-apply/src/lib.rs` tests L144-160

**Interfaces:**
- Produces:

```rust
// types.rs
pub enum LinkKind { Bridge, Veth, Vlan, Other(String) }
pub struct Link { …, /// IFLA_LINK: the lower device of a VLAN or other upper.
                  pub parent: Option<u32>, /// The 802.1Q id of a VLAN link.
                  pub vlan_id: Option<u16> }
pub enum RouteKind { Unicast, Blackhole }
pub struct Route { …, pub kind: RouteKind }      // Unicast for every route today; oif None allowed for Blackhole
// apply.rs
pub async fn link_add_vlan(&self, parent: u32, id: u16, name: &str) -> Result<(), Error>;  // rtnetlink LinkVlan::new(name, parent, id)
// describe(): "blackhole 192.0.2.248/29 proto 200 metric 1000" for a blackhole
// openfeo-apply: pub fn is_managed(ifname: &str) -> bool also matches `p<digits>.<digits>`
```

- [ ] **Step 1: Write the failing tests**

```rust
// crates/openfeo-apply/src/lib.rs tests
#[test]
fn managed_interfaces_include_vlan_sub_interfaces() {
    assert!(is_managed("p0.101") && is_managed("p12.4094"));
    assert!(!is_managed("p0.") && !is_managed("eth0.5") && !is_managed("p1a"));
}
// harness/tests/netlink.rs (FakePorts, Rig, block_on, wait_until exist; add "p1.223" to FakePorts cleanup)
/// A VLAN sub-interface is created on a fake port, seen by the monitor with its parent and id,
/// enslaved to a bridge, and deleted.
fn vlan_link_primitive_and_facts(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let (nl, mut rx) = connect().await?;            // the existing way a scenario gets a Netlink + watch
        let p1 = nl.link_index("p1").await?.context("p1")?;
        nl.link_add_vlan(p1, 223, "p1.223").await?;
        let cache = wait_until(&mut rx, "p1.223 appears", |c| c.link_by_name("p1.223").is_some()).await?;
        let link = cache.link_by_name("p1.223").unwrap();
        ensure!(link.kind == Some(LinkKind::Vlan) && link.parent == Some(p1) && link.vlan_id == Some(223), "{link:?}");
        nl.link_add_bridge("br-lan0", true).await?;
        let br = nl.link_index("br-lan0").await?.context("br")?;
        nl.link_set_master(link.index, Some(br)).await?;
        wait_until(&mut rx, "enslaved", |c| c.link_by_name("p1.223").is_some_and(|l| l.master == Some(br))).await?;
        nl.link_del(link.index).await?;
        wait_until(&mut rx, "gone", |c| c.link_by_name("p1.223").is_none()).await?;
        anyhow::Ok(())
    })?
}
/// A blackhole route is added with its kind, cached with its kind, and deleted.
fn blackhole_route_primitive_and_facts(_lab: &mut Lab) -> anyhow::Result<()> {
    let _ports = FakePorts::create()?;
    block_on(async {
        let (nl, mut rx) = connect().await?;
        let route = Route { v6: false, table: TABLE_MAIN, dst: Some("192.0.2.248/29".parse()?), gateway: None,
                            oif: None, protocol: RTPROT_OPENFEO, priority: 1000, kind: RouteKind::Blackhole };
        nl.route_add(&route).await?;
        wait_until(&mut rx, "blackhole cached", |c| c.routes.contains(&route)).await?;
        ensure!(describe(&route) == "blackhole 192.0.2.248/29 proto 200 metric 1000");
        nl.route_del(&route).await?;
        wait_until(&mut rx, "blackhole gone", |c| !c.routes.contains(&route)).await?;
        anyhow::Ok(())
    })?
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p openfeo-apply managed 2>&1 | tail -5; cargo test -p openfeo-harness --test netlink vlan_link blackhole_route 2>&1 | tail -15`
Expected: `is_managed("p0.101")` false; the sandbox scenarios fail to compile (`LinkKind::Vlan`, `RouteKind`, `link_add_vlan`).

- [ ] **Step 3: Implement**

`monitor::link_from` reads `LinkAttribute::Link(parent)` and `LinkInfo::Data(InfoData::Vlan(v))` → `InfoVlan::Id`, maps `InfoKind::Vlan` → `LinkKind::Vlan`; `route_from` maps `msg.header.kind == RouteType::BlackHole` → `RouteKind::Blackhole` (everything else `Unicast`); `route_message_builder` adds `.kind(RouteType::BlackHole)` and leaves scope universe (no `.output_interface`) for blackholes, keeping today's link scope only for gateway-less unicast routes; `describe` prints `blackhole <dst> proto <p> metric <m>`. `apply::routing` resolves an interface only for unicast routes (Task 6 changes `DesiredRoute`; here keep the applier compiling by constructing `kind: RouteKind::Unicast`). `is_managed` matches `p<digits>` optionally followed by `.<digits>`. Update the exhaustive `Route` literals (monitor.rs L293, apply/routing.rs L104, harness/tests/netlink.rs L290).

- [ ] **Step 4: Run the sandbox suite and unit tests**

Run: `cargo test -p openfeo-apply 2>&1 | tail -3 && cargo test -p openfeo-harness --test netlink 2>&1 | tail -8`
Expected: all unit tests pass; netlink suite lists the two new scenarios as passed (the host must have `8021q`; if the VLAN scenario skips for a missing module, see Task 7 Step 5 for `check-env`).

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-netlink crates/openfeo-apply harness/tests/netlink.rs
git commit -s -m "netlink: VLAN sub-interfaces and blackhole routes as primitives and facts"
```

---

### Task 5: Links: VLAN members, stray sub-interfaces, the tagged WAN

**Files:**
- Modify: `crates/openfeo-reconcile/src/lib.rs` (new `wan_ifname`), `crates/openfeo-reconcile/src/links.rs` (`DesiredPort` L33-43, `links()` L59-130), `crates/openfeo-apply/src/links.rs` (`bridges`/strays L70-89, `membership` L119-151, new `vlans` step before `membership`)
- Modify WAN-ifname sites: `crates/openfeo-reconcile/src/routing.rs:71,82,95,118`, `nft.rs:57-58`, `sysctl.rs:36-37`, `crates/openfeo/src/dhcp4.rs:233,264,289,305,318`
- Test: `links.rs` tests + snapshots, `crates/openfeo/src/dhcp4.rs` tests if any name the port, `harness/tests/netlink.rs` (one scenario)

**Interfaces:**
- Produces:

```rust
// crates/openfeo-reconcile/src/lib.rs
/// The kernel interface a WAN runs on: its port, or `pN.V` when `vlan` is set (SPEC §7.2).
pub fn wan_ifname(wan: &openfeo_config::Wan) -> String;
// links.rs
pub enum PortKind { Physical, Vlan { parent: String, id: u16 } }
pub struct DesiredPort { pub name: String, pub kind: PortKind, pub up: bool, pub master: Option<String>, pub mtu: Option<u32> }
// The applier: creates missing Vlan ports (`nl.link_add_vlan(parent_index, id, name)`, op "add vlan {name}"),
// deletes links with kind Vlan whose name matches `p<digits>.<digits>` and is not desired (op "del vlan {name}").
```

- [ ] **Step 1: Write the failing tests**

```rust
// links.rs tests (fixtures::world, static_world exist; add a fixture `vlans_world()` from a TOML with
// lan0 on ["p2"], guest on ["p2.223", "p1.223"], trusted on ["p1"] and a WAN on p0 with vlan = 101)
#[test]
fn tagged_members_become_vlan_ports_enslaved_to_their_lan() {
    let desired = links(&fixtures::vlans_world());
    let guest = &desired.ports["p2.223"];
    assert_eq!(guest.kind, PortKind::Vlan { parent: "p2".into(), id: 223 });
    assert_eq!(guest.master.as_deref(), Some("br-guest"));
    assert!(guest.up);
    assert_eq!(desired.bridges["br-guest"].members, ["p1.223", "p2.223"].into_iter().map(String::from).collect());
    assert_eq!(desired.ports["p2"].master.as_deref(), Some("br-lan0"));
    assert_eq!(desired.ports["p1"].master.as_deref(), Some("br-trusted"));
    insta::assert_yaml_snapshot!(desired);
}
#[test]
fn a_tagged_wan_runs_on_its_sub_interface() {
    let desired = links(&fixtures::vlans_world());
    let wan = &desired.ports["p0.101"];
    assert_eq!(wan.kind, PortKind::Vlan { parent: "p0".into(), id: 101 });
    assert!(wan.up && wan.master.is_none());
    assert!(desired.ports["p0"].up, "the parent is up for its upper");
    assert_eq!(wan_ifname(&fixtures::vlans_world().config.wans[0]), "p0.101");
}
// harness/tests/netlink.rs: extend `foreign_state_is_untouched` or add
/// A `p1.223` nobody wants is deleted; a `vlan7` that is not ours is left alone.
fn stray_vlan_sub_interfaces_are_removed(_lab: &mut Lab) -> anyhow::Result<()> { … ensure ops.0 == 1 … }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p openfeo-reconcile links:: 2>&1 | tail -15`
Expected: compile error (`PortKind`, `wan_ifname`, `vlans_world`).

- [ ] **Step 3: Implement**

`links()`: parse every LAN member with `openfeo_config::portname::parse_port_ref`; a tagged member whose physical port is known becomes a `Vlan` port named `vlan_ifname(port, id)`, up, with `master = br-<lan>`; its parent is `up`. A WAN with `vlan != 0` becomes a `Vlan` port named `wan_ifname(wan)`, up, no master, carrying the DHCP MTU rule instead of the parent; the parent is up. The bridge MAC uses `world.mac_of(parent)` for a Vlan member. The applier gains `vlans()` between `bridges()` and `membership()`: create missing (resolve the parent via `resolve`), delete strays (`link.kind == Some(LinkKind::Vlan) && is_vlan_port_name(&link.name) && !desired.ports.contains_key(&link.name)`); membership and up/down treat Vlan ports like physical ones. Replace every `wan.port`-as-ifname site listed above with `wan_ifname(wan)` (the known-port check `world.ports.id_of(&wan.port)` stays on the physical port). `dhcp4.rs`'s `wait_for_link` waits for the sub-interface by name, which the monitor reports like any link.

- [ ] **Step 4: Run reconcile, apply, the router crate and the netlink suite**

Run: `INSTA_UPDATE=always cargo test -p openfeo-reconcile 2>&1 | tail -3 && git status --short crates/openfeo-reconcile/src/snapshots && cargo test -p openfeo-apply -p openfeo 2>&1 | tail -3 && cargo test -p openfeo-harness --test netlink 2>&1 | tail -5`
Expected: pass; only the new snapshot file appears (no `.snap.new`); netlink suite green.

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-reconcile crates/openfeo-apply crates/openfeo/src/dhcp4.rs harness/tests/netlink.rs
git commit -s -m "links: tagged LAN members and tagged WANs as 802.1Q sub-interfaces, strays removed"
```

---

### Task 6: Routing: blackhole routes for public blocks; public-LAN helpers

**Files:**
- Modify: `crates/openfeo-reconcile/src/lib.rs` (new `public` module re-exports), create `crates/openfeo-reconcile/src/public.rs`, modify `routing.rs` (`DesiredRoute` L29-42, `routing()` L55-133), `crates/openfeo-apply/src/routing.rs:94-120`
- Test: `routing.rs` tests + snapshots, `public.rs` tests, `harness/tests/netlink.rs` (routing applier scenario)

**Interfaces:**
- Produces:

```rust
// crates/openfeo-reconcile/src/public.rs
/// Declared public blocks that parse (validation already refused the rest).
pub fn blocks(config: &Config) -> Vec<Ipv4Net>;
/// A LAN's subnet (`ipv4` truncated), when it parses.
pub fn lan_subnet(lan: &Lan) -> Option<Ipv4Net>;
/// Whether the LAN is numbered from a declared block.
pub fn lan_is_public(lan: &Lan, blocks: &[Ipv4Net]) -> bool;
/// Private LANs' subnets: the masquerade sources and the rebinding guard.
pub fn private_subnets(config: &Config) -> Vec<Ipv4Net>;
/// Blackhole metric for a declared block (a connected route for a LAN inside it wins at 0).
pub const BLOCK_METRIC: u32 = 1000;
// routing.rs
pub struct DesiredRoute { pub ifname: Option<String>, pub dst: Option<IpNet>, pub gateway: Option<IpAddr>,
                          pub table: u32, pub protocol: u8, pub priority: u32, pub kind: RouteKind }
// Console (applier op, via describe): "add route blackhole 192.0.2.248/29 proto 200 metric 1000"
```

- [ ] **Step 1: Write the failing tests**

```rust
// routing.rs tests (fixture `public_world()` from a TOML: static WAN, lan0 192.168.1.1/24 on p2,
// dmz 192.0.2.233/29 on p3, public_ipv4 192.0.2.232/29 and 192.0.2.248/29)
#[test]
fn every_declared_block_gets_a_blackhole_and_the_dmz_gets_its_address() {
    let desired = routing(&fixtures::public_world());
    let blackholes: Vec<_> = desired.routes.iter().filter(|r| r.kind == RouteKind::Blackhole).collect();
    assert_eq!(blackholes.iter().map(|r| r.dst.unwrap().to_string()).collect::<Vec<_>>(), ["192.0.2.232/29", "192.0.2.248/29"]);
    assert!(blackholes.iter().all(|r| r.ifname.is_none() && r.priority == BLOCK_METRIC && r.table == TABLE_MAIN && r.protocol == RTPROT_OPENFEO));
    assert!(desired.addrs.iter().any(|a| a.ifname == "br-dmz" && a.net.to_string() == "192.0.2.233/29"));
    insta::assert_yaml_snapshot!(desired);
}
// public.rs
#[test]
fn public_helpers_tell_a_dmz_from_a_private_lan() {
    let cfg = fixtures::public_world().config;
    let blocks = blocks(&cfg);
    assert_eq!(blocks.len(), 2);
    assert!(lan_is_public(&cfg.lans[1], &blocks) && !lan_is_public(&cfg.lans[0], &blocks));
    assert_eq!(private_subnets(&cfg), vec!["192.168.1.0/24".parse::<Ipv4Net>().unwrap()]);
}
// harness/tests/netlink.rs
/// The routing applier adds a declared block's blackhole once, keeps it on a second pass, and
/// removes it when the block leaves the config.
fn routing_applier_owns_block_blackholes(_lab: &mut Lab) -> anyhow::Result<()> { … }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p openfeo-reconcile routing:: public:: 2>&1 | tail -10`
Expected: compile errors.

- [ ] **Step 3: Implement**

`routing()` appends one `DesiredRoute { ifname: None, dst: Some(block), gateway: None, table: TABLE_MAIN, protocol: RTPROT_OPENFEO, priority: BLOCK_METRIC, kind: Blackhole }` per block; existing routes get `kind: Unicast` and `ifname: Some(..)`. The applier resolves `ifname` only when present and builds `Route { kind, oif }` accordingly; deletion of unwanted protocol-200 routes already covers blackholes. Update snapshot tests that print `DesiredRoute`.

- [ ] **Step 4: Run tests and the netlink suite**

Run: `INSTA_UPDATE=always cargo test -p openfeo-reconcile 2>&1 | tail -3 && cargo test -p openfeo-apply 2>&1 | tail -3 && cargo test -p openfeo-harness --test netlink routing_applier 2>&1 | tail -5`
Expected: pass; snapshots updated with no `.snap.new` left.

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-reconcile crates/openfeo-apply harness/tests/netlink.rs
git commit -s -m "routing: a blackhole per declared public block; public-LAN helpers"
```

---

### Task 7: The ruleset: policy, translated flows, public addresses, rules, services, echo limit

**Files:**
- Modify: `crates/openfeo-reconcile/src/nft.rs` (`nft()` L52-92, `forwards()` L94-113, objects L117-160, expressions L178-291, chains L300-454, tests L456-598)
- Modify: `harness/src/nftprobe.rs:19-47` (probe `limit` and an interval concatenation set with an `ifname` field), `harness/src/main.rs` `check()` L165-234 (report the probe), `.github/workflows/ci.yml:77` (add `nft_limit 8021q`), `harness/tests/nft.rs` (one scenario)
- Test: `nft.rs` tests + snapshots, `harness/tests/nft.rs`

**Interfaces:**
- Consumes: `openfeo_reconcile::public::{blocks, lan_is_public, private_subnets}`, `wan_ifname`, `openfeo_config::rules::{parse_target, parse_ports, Target}`.
- Produces: sets and maps named `wan_if`, `lan_if`, `lan_priv_if`, `lan_pub_dhcp_if`, `lan_to_wan`, `lan_pairs`, `lan_same`, `nat_nets`, `fwd_tcp`, `fwd_udp`, `fwd_pub_tcp`, `fwd_pub_udp`, `rules_tcp`, `rules_udp`, `rules_other`, `rules_any`. Chains and rule order:
  - `rpfilter`: unchanged.
  - `input`: 1-3 unchanged; `iifname @lan_priv_if udp dport {53,67,123} accept`; `iifname @lan_pub_dhcp_if udp dport {53,67,123} accept`; `iifname @lan_priv_if tcp dport {53,80,443} accept`; `iifname @lan_pub_dhcp_if tcp dport 53 accept`; `iifname @lan_if meta l4proto {icmp, icmpv6} accept`; DHCP replies unchanged; `iifname @wan_if icmp type echo-request limit rate 50/second burst 100 packets accept` when `wan_ping`.
  - `forward`: `ct state {established, related} accept`; `ct state invalid drop`; `ct status dnat iifname @wan_if accept`; `ct status dnat iifname . oifname @lan_pairs accept`; `iifname . ip daddr . tcp dport @rules_tcp accept`; same udp; `iifname . ip daddr . meta l4proto @rules_other accept`; `iifname . ip daddr @rules_any accept`; `iifname @lan_to_wan oifname @wan_if accept`; `iifname . oifname @lan_pairs accept`.
  - `dstnat`: `iifname @wan_if fib daddr type local dnat ip to tcp dport map @fwd_tcp`; same udp; `iifname @wan_if dnat ip to ip daddr . tcp dport map @fwd_pub_tcp`; same udp; the two LAN hairpin rules as today plus two LAN rules on `@fwd_pub_*`.
  - `srcnat`: `meta nfproto ipv4 ip saddr @nat_nets oifname @wan_if masquerade`; hairpin rule unchanged (`lan_same`).
  - Set shapes: `lan_pairs` type `ifname . ifname` (self pairs + `reaches` pairs); `nat_nets` type `ipv4_addr` flags `interval`; `fwd_pub_*` type `ipv4_addr . inet_service` map to `ipv4_addr . inet_service`; `rules_tcp`/`rules_udp` type `ifname . ipv4_addr . inet_service` flags `interval`; `rules_other` type `ifname . ipv4_addr . inet_proto` flags `interval`; `rules_any` type `ifname . ipv4_addr` flags `interval`. A rule from `wan` contributes one element per WAN interface. A set with no elements is still declared.

- [ ] **Step 1: Write the failing tests**

```rust
// nft.rs tests (helpers added/rules_of/set_elements/mentions exist; fixtures vlans_world, public_world)
#[test]
fn reaches_builds_the_pairs_and_the_wan_set() {
    let d = nft(&fixtures::vlans_world());            // lan0 reaches ["wan"], guest default, trusted ["wan","lan0","guest"]
    assert_eq!(set_elements(&d.ruleset, "lan_to_wan"), json!(["br-guest", "br-lan0", "br-trusted"]));
    let pairs = set_elements(&d.ruleset, "lan_pairs");
    assert!(pairs.as_array().unwrap().contains(&json!({"concat": ["br-trusted", "br-lan0"]})));
    assert!(!pairs.as_array().unwrap().contains(&json!({"concat": ["br-lan0", "br-trusted"]})));
    assert_eq!(set_elements(&d.ruleset, "lan_same").as_array().unwrap().len(), 3);
}
#[test]
fn translated_flows_follow_the_policy() {
    let rules = rules_of(&nft(&fixtures::vlans_world()).ruleset, "forward");
    let dnat: Vec<_> = rules.iter().filter(|r| mentions(r, "dnat")).collect();
    assert_eq!(dnat.len(), 2);
    assert!(mentions(dnat[0], "wan_if") && mentions(dnat[1], "lan_pairs"), "{dnat:?}");
}
#[test]
fn a_lan_reaching_none_is_in_no_set_but_its_own_pair() {
    let mut world = fixtures::vlans_world(); Arc::make_mut(&mut world.config).lans[1].reaches = vec!["none".into()];
    let d = nft(&world);
    assert!(!set_elements(&d.ruleset, "lan_to_wan").as_array().unwrap().contains(&json!("br-guest")));
    assert!(set_elements(&d.ruleset, "lan_pairs").as_array().unwrap().contains(&json!({"concat": ["br-guest", "br-guest"]})));
}
#[test]
fn public_lans_are_not_translated_and_get_fewer_services() {
    let d = nft(&fixtures::public_world());
    assert_eq!(set_elements(&d.ruleset, "nat_nets"), json!([{"prefix": {"addr": "192.168.1.0", "len": 24}}]));
    assert_eq!(set_elements(&d.ruleset, "lan_priv_if"), json!(["br-lan0"]));
    assert_eq!(set_elements(&d.ruleset, "lan_pub_dhcp_if"), Value::Null, "the DMZ runs no DHCP");
    assert_eq!(set_elements(&d.ruleset, "lan_if"), json!(["br-dmz", "br-lan0"]));
    let srcnat = rules_of(&d.ruleset, "srcnat");
    assert!(mentions(&srcnat[0], "nat_nets"), "{srcnat:?}");
}
#[test]
fn wan_address_forwards_match_only_local_addresses_and_public_ones_match_their_address() {
    let d = nft(&fixtures::public_world());             // lan-http 2222 (WAN address), pub-https 192.0.2.249:443
    let dstnat = rules_of(&d.ruleset, "dstnat");
    assert!(mentions(&dstnat[0], "wan_if") && mentions(&dstnat[0], "local") && mentions(&dstnat[0], "fwd_tcp"));
    assert_eq!(set_elements(&d.ruleset, "fwd_pub_tcp"), json!([[{"concat": ["192.0.2.249", 443]}, {"concat": ["192.168.1.2", 8080]}]]));
    assert_eq!(set_elements(&d.ruleset, "fwd_tcp"), json!([[2222, {"concat": ["192.168.1.2", 8080]}]]));
}
#[test]
fn rules_land_in_their_sets_one_element_per_wan_interface() {
    let d = nft(&fixtures::public_world());             // dmz-web: from wan to 192.0.2.234-192.0.2.238 tcp ["80"]
    assert_eq!(set_elements(&d.ruleset, "rules_tcp"),
               json!([{"concat": ["p0", {"range": ["192.0.2.234", "192.0.2.238"]}, 80]}]));
    assert_eq!(set_elements(&d.ruleset, "rules_udp"), Value::Null);
    let forward = rules_of(&d.ruleset, "forward");
    assert!(forward.iter().position(|r| mentions(r, "rules_tcp")).unwrap() < forward.iter().position(|r| mentions(r, "lan_to_wan")).unwrap());
}
#[test]
fn wan_echo_is_rate_limited() {
    let input = rules_of(&nft(&fixtures::static_world()).ruleset, "input");
    let echo = input.iter().find(|r| mentions(r, "echo-request")).unwrap();
    assert!(mentions(echo, "limit") && mentions(echo, "\"rate\":50") || mentions(echo, "\"rate\": 50"), "{echo}");
}
// harness/tests/nft.rs
/// The public-world ruleset, with its interval concatenations, rules sets, public forwards and
/// the echo limit, is accepted by the pinned libnftables and this kernel; every set is listed.
fn generated_public_ruleset_is_accepted_by_libnftables(_lab: &mut Lab) -> anyhow::Result<()> { … for set in [all 16 names] ensure listed … }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p openfeo-reconcile nft:: 2>&1 | tail -15`
Expected: the new tests fail (sets missing, two dnat accepts not found, no `limit`).

- [ ] **Step 3: Implement the generator**

Add helpers: `ipv4_set(name, nets: &[Ipv4Net]) -> Value` (flags interval, elements `{"prefix": {"addr", "len"}}`), `concat_set(name, types: &[&str], elems: Vec<Value>, interval: bool)`, `pub_forward_map(name, forwards: &PubForwards)`, `rules_sets(config, wan_if, lans) -> [Value; 4]`, `limit(rate: u32, burst: u32) -> Value` (`{"limit": {"rate": 50, "per": "second", "burst": 100, "burst_unit": "packets"}}`), `concat_in(exprs: Vec<Value>, set: &str)`. `forwards()` returns WAN-address maps and public maps separately (`address` empty vs set). Private/public LAN sets from `public::{blocks, lan_is_public}`; `lan_pub_dhcp_if` = public LANs with `dhcp.is_some()`. Element ranges: `{"range": [a, b]}` for `Target::Range`, `{"prefix": ..}` for `Net`, a plain string for `Addr`; ports `(a, b)` → `{"range": [a, b]}` when `a != b`.

- [ ] **Step 4: Prove the set shapes in the sandbox; teach the probe and CI**

`nftprobe::probe_ruleset` adds a rule with `limit` and a set `type ifname . ipv4_addr . inet_service; flags interval` with one element, so `require_expressions()` skips on a kernel without `nft_limit` or interval-concatenation support; `check-env` prints what the probe found; `ci.yml:77` becomes `sudo modprobe nf_conntrack nft_ct nft_fib_inet nft_nat nft_masq nft_chain_nat nft_limit 8021q`.

Run: `cargo test -p openfeo-harness --test nft 2>&1 | tail -8`
Expected: `generated_public_ruleset_is_accepted_by_libnftables` passes (or skips with a reason on this host, in which case run it with the modules loaded before committing: a skip here is an unrun proof). If libnftables refuses the `ifname` interval concatenation, fall back to one `forward` rule per configured rule, record the ruling, and amend the design's Rules section and SPEC §7.5 wording in the same commit.

- [ ] **Step 5: Run everything that reads the ruleset**

Run: `INSTA_UPDATE=always cargo test -p openfeo-reconcile 2>&1 | tail -3 && cargo test -p openfeo 2>&1 | tail -3 && cargo test -p openfeo-harness --test netlink nft_applier 2>&1 | tail -3`
Expected: pass; updated snapshots only.

- [ ] **Step 6: Commit**

```bash
git add crates/openfeo-reconcile harness/src/nftprobe.rs harness/src/main.rs harness/tests/nft.rs .github/workflows/ci.yml
git commit -s -m "nft: per-LAN policy, gated translated flows, public addresses and blocks, rules sets, echo limit"
```

---

### Task 8: DNS: the guard and the reverse zones part ways

**Files:**
- Modify: `crates/openfeo-proto-dns/src/forwarder.rs` (`Config` L44-63, `is_internal_v4` L574-589), `crates/openfeo-reconcile/src/dns.rs` (`desired` L70-150, `forwarder_config` L158-196, `DesiredDns` L39-64), `fuzz/fuzz_targets/dns_forwarder.rs`, `harness/tests/dns.rs` (Config literal)
- Test: `forwarder.rs` tests, `dns.rs` tests + snapshots

**Interfaces:**
- Consumes: `openfeo_reconcile::public::{blocks, lan_is_public, lan_subnet}`.
- Produces: `forwarder::Config.guard_subnets: Vec<Ipv4Net>` (the rebinding guard; `lan_subnets` keeps only its reverse-zone meaning); `DesiredDns.guard_subnets`.

- [ ] **Step 1: Write the failing tests**

```rust
// forwarder.rs tests (a Config helper exists in the test module)
#[test]
fn the_guard_reads_guard_subnets_not_the_reverse_zones() {
    let mut cfg = config();
    cfg.lan_subnets = vec!["192.0.2.232/29".parse().unwrap()];       // a reverse zone the forwarder owns
    cfg.guard_subnets = vec!["192.168.1.0/24".parse().unwrap()];
    let fwd = Forwarder::new(cfg);
    assert!(!fwd.is_internal_v4(Ipv4Addr::new(192, 0, 2, 234)), "public space is a valid answer");
    assert!(fwd.is_internal_v4(Ipv4Addr::new(192, 168, 1, 9)));
}
// reconcile dns.rs tests
#[test]
fn public_lans_leave_the_guard_and_the_reverse_zones_unless_they_run_dhcp() {
    let d = desired(&fixtures::public_world());                         // dmz without dhcp
    assert_eq!(d.guard_subnets, vec!["192.168.1.0/24".parse::<Ipv4Net>().unwrap()]);
    assert_eq!(d.lan_subnets, vec!["192.168.1.0/24".parse::<Ipv4Net>().unwrap()]);
    let mut world = fixtures::public_world();
    Arc::make_mut(&mut world.config).lans[1].dhcp = Some(LanDhcp { range: vec!["192.0.2.234".into(), "192.0.2.238".into()], ..Default::default() });
    let d = desired(&world);
    assert_eq!(d.lan_subnets.len(), 2, "a DHCP-served public LAN names its hosts, so its reverse zone is local");
    assert_eq!(d.guard_subnets.len(), 1);
    insta::assert_yaml_snapshot!(forwarder_config(&d));
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p openfeo-proto-dns the_guard 2>&1 | tail -5; cargo test -p openfeo-reconcile dns:: 2>&1 | tail -5`
Expected: compile errors (`guard_subnets`).

- [ ] **Step 3: Implement, then fix every `Config` literal**

`is_internal_v4` uses `guard_subnets`; `local_answer` keeps `lan_subnets`. `desired()`: `guard_subnets` = private LANs; `lan_subnets` = private LANs plus public LANs with `dhcp`. Update `forwarder_config`, the fuzz target and `harness/tests/dns.rs` literals (`guard_subnets: vec![..]` mirroring their `lan_subnets`).

- [ ] **Step 4: Run the DNS crates, the dns suite and the fuzz check**

Run: `INSTA_UPDATE=always cargo test -p openfeo-proto-dns -p openfeo-reconcile 2>&1 | tail -3 && cargo test -p openfeo-harness --test dns 2>&1 | tail -3 && cargo check --manifest-path fuzz/Cargo.toml --bins`
Expected: pass; dns suite 10 passed; fuzz targets compile.

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-proto-dns crates/openfeo-reconcile fuzz/fuzz_targets/dns_forwarder.rs harness/tests/dns.rs
git commit -s -m "dns: the rebinding guard is the private LANs; reverse zones follow who names the hosts"
```

---

### Task 9: Lab: a second LAN, VLAN hosts, a tagged ISP; the VLAN and policy scenarios

**Files:**
- Modify: `harness/src/lab.rs` (`MACS` L35-39 → four, `Lab` L52-75 gains `pub lan1: Option<NetNs>`, `new` L83-108, `boot_with` L217-231, `start_kea` L132), `harness/src/netns.rs` (new `add_vlan`, `move_link`), `harness/src/daemons.rs` (`kea_dhcp4` interface stays a parameter), `harness/src/main.rs` (banner L151-156, `check()` tries a VLAN sub-interface), `harness/Cargo.toml` (`[[test]] m2`), `Makefile:40` (`--test m2`), `README.md` harness paragraph, `CLAUDE.md` Harness paragraph (one sentence)
- Create: `harness/fixtures/vm-vlans.toml`, `harness/tests/m2.rs`
- Test: `crates/openfeo-config/src/validate.rs` `mod lan_dhcp_tests` (fixture validity with a four-port map), the scenarios

**Interfaces:**
- Produces:

```rust
// lab.rs
pub const MACS: [&str; 4];                                     // 52:54:00:fe:00:00 .. :03
pub fn add_lan1(&mut self) -> Result<()>;                      // before boot: namespace `<name>-lan1`, tap `lan1`, router p3
pub fn vlan_host(&self, base: &NetNs, parent: &str, vid: u16, ns: &str) -> Result<NetNs>;
    // `ip link add link <parent> name <parent>.<vid> type vlan id <vid>` in `base`, moved into a new namespace, up
pub fn isp0_tagged(&mut self, vid: u16) -> Result<String>;     // ISP0_ADDR moves from wan0 to wan0.<vid>; returns the ifname; Kea/http use it
pub fn start_kea_on(&mut self, iface: &str) -> Result<()>;
pub fn host(ns: &NetNs, ifname: &str, addr_cidr: &str, gateway: &str) -> Result<()>;   // generalises lan_side_host
pub fn isp_route_block(&self, block: &str) -> Result<()>;      // isp0: route replace <block> via WAN_ADDR
```

Fixture `vm-vlans.toml`: `[[wans]] wan0 port p0 vlan 101 [wans.dhcp]`; `main` ports `["p2"]` `192.168.1.1/24` dhcp pool `.100-.200`; `guest` ports `["p2.223"]` `192.168.2.1/24` dhcp pool `.100-.200`; `trusted` ports `["p2.224", "p3"]` `192.168.3.1/24` `reaches = ["wan", "main", "guest"]`; `[[firewall.rules]] admin-web from main to 192.168.3.2 tcp ["8080"]`; `[[firewall.port_forwards]] lan-http tcp 2222 → 192.168.1.2:8080`; `wan_ping = true`.

- [ ] **Step 1: Write the scenarios (they fail until the lab helpers exist)**

```rust
const SCENARIOS: &[Scenario] = &[
    Scenario { name: "tagged_wan_leases_and_nats", run: tagged_wan_leases_and_nats },
    Scenario { name: "tagged_guest_leases_from_its_own_lan_and_reaches_only_the_internet", run: tagged_guest_… },
    Scenario { name: "trusted_reaches_main_and_nothing_initiates_into_trusted_except_a_rule", run: trusted_… },
    Scenario { name: "a_vlan_nobody_wants_is_dropped_by_the_untagged_bridge", run: a_vlan_nobody_wants_… },
];
/// Boot vm-vlans.toml: isp0 serves Kea on wan0.101, lan0 is the main host 192.168.1.2, lan1 the
/// trusted host 192.168.3.2; returns the console cursor after `ready`.
fn boot_vlans(lab: &mut Lab) -> anyhow::Result<Cursor> { lab.add_lan1()?; let tagged = lab.isp0_tagged(101)?; lab.start_kea_on(&tagged)?; lab.with_config(VM_VLANS)?; … wait READY … Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?; Lab::host(lab.lan1.as_ref().unwrap(), "lan1", "192.168.3.2/24", "192.168.3.1")?; Ok(cursor) }

fn tagged_wan_leases_and_nats(lab) { boot_vlans; console shows `wan wan0 dhcp lease 203\.0\.113\.\d+` (the existing lease line, see m1.rs L648-696 for its regex) ; lan0 http_get ISP_HTTP == ISP_HTTP_BODY }
fn tagged_guest_…(lab) {
    boot_vlans; let guest = lab.vlan_host(&lab.lan0, "lan0", 223, "guest")?;
    let events = lanclient::udhcpc(&guest, "lan0.223", &lab.run_dir, &[], UDHCPC_TIMEOUT)?;   // address in 192.168.2.100-200
    ensure!(udhcpc_env(&events, "ip").starts_with("192.168.2."));
    guest.ip(&["route", "replace", "default", "via", "192.168.2.1"])?;
    let main_server = http_target(lab, &lab.lan0, "192.168.1.2", LAN_HTTP_BODY)?;
    ensure!(lanclient::http_get(&guest, ISP_HTTP.parse()?, "/", HTTP_TIMEOUT)? == ISP_HTTP_BODY, "guest reaches the internet");
    ensure!(lanclient::http_get(&guest, LAN_HTTP.parse()?, "/", SHORT)?.is_err(), "guest must not reach main");
    ensure!(lanclient::http_get(&guest, "203.0.113.<lease>:2222", "/", SHORT).is_err(), "hairpin follows the policy");
    ensure!(main_server.log.count(&re("^192\\.168\\.2\\.")) == 0);
}
fn trusted_…(lab) {
    boot_vlans; let trusted_hits = http_target(lab, lab.lan1.as_ref().unwrap(), "192.168.3.2", "trusted")?;
    let other = daemons::http_server(lab.lan1…, "192.168.3.2", 8081, …, "other")?;
    ensure!(http_get(lan1 → LAN_HTTP) == LAN_HTTP_BODY, "trusted reaches main");
    ensure!(http_get(lan0 → 192.168.3.2:8080) == "trusted", "the rule opens 8080");
    ensure!(http_get(lan0 → 192.168.3.2:8081, SHORT).is_err(), "nothing else initiates into trusted");
    let guest = vlan_host(.., 223, "guest2"); udhcpc; default route; ensure!(http_get(guest → 192.168.3.2:8080, SHORT).is_err(), "the rule is from main only");
}
fn a_vlan_nobody_wants_…(lab) {
    boot_vlans; let stray = lab.vlan_host(&lab.lan0, "lan0", 999, "stray")?;
    Lab::host(&stray, "lan0.999", "192.168.1.77/24", "192.168.1.1")?;
    ensure!(ping(&stray, "192.168.1.1").is_err(), "a tagged frame for VLAN 999 never reaches br-main");
    ensure!(ping(&lab.lan0, "192.168.1.1").is_ok(), "untagged still works");
}
```

Also add to `validate.rs` `mod lan_dhcp_tests`: `fn m2_fixtures_are_valid()` parsing `vm-vlans.toml` (and, after Task 10, `vm-public.toml`) against a four-port live map, expecting no violations.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p openfeo-config m2_fixtures 2>&1 | tail -5; cargo test -p openfeo-harness --test m2 --no-run 2>&1 | tail -5`
Expected: the fixture test fails (file missing), the suite does not compile (helpers missing).

- [ ] **Step 3: Implement the lab helpers, the fixture, the suite registration**

`add_lan1` pushes the fourth tap; `boot_with` zips four MACs; `vlan_host` creates the sub-interface in `base`, `ip link set <ifname> netns <ns>` and brings it up in the new namespace (NetNs owns the namespace; the sub-interface dies with it); `isp0_tagged` creates `wan0.<vid>`, flushes `wan0`'s address onto it; `check()` tries creating and deleting a VLAN sub-interface on a dummy link so a host without `8021q` is reported. `Makefile` `test-harness` gains `--test m2`; `harness/Cargo.toml` gains the `[[test]]`.

- [ ] **Step 4: Build the kernel with the new binary and run the suite**

Run: `make kernel 2>&1 | tail -2 && OPENFEO_KERNEL=$PWD/build/bzImage cargo test -p openfeo-harness --test m2 2>&1 | tail -12 && cargo test -p openfeo-harness --test m0 --test m1 2>&1 | tail -6`
Expected: four m2 scenarios pass; m0 and m1 still pass (three-port scenarios untouched).

- [ ] **Step 5: Commit**

```bash
git add harness Makefile README.md CLAUDE.md crates/openfeo-config/src/validate.rs
git commit -s -m "harness: a second LAN, VLAN hosts and a tagged ISP; the tagged WAN, VLAN and policy scenarios"
```

---

### Task 10: Public-block scenarios

**Files:**
- Create: `harness/fixtures/vm-public.toml`
- Modify: `harness/tests/m2.rs` (four scenarios), `crates/openfeo-config/src/validate.rs` (`m2_fixtures_are_valid` covers both fixtures), `README.md` Status paragraph (one sentence on part 1)

**Interfaces:**
- Consumes: Task 9's helpers. Fixture `vm-public.toml`: static WAN as `vm-static.toml`; `lan0` as `vm-static.toml` (ports `["p2"]`, dhcp, reservation); `dmz` ports `["p3"]` `ipv4 = "192.0.2.233/29"`, no dhcp; `[[public_ipv4]]` `192.0.2.232/29` and `192.0.2.248/29`; `[[firewall.rules]] dmz-web from wan to 192.0.2.234-192.0.2.238 tcp ["80"]`; forwards `lan-http` (2222, WAN address) and `pub-https` (`address = "192.0.2.249"`, 443 → 192.168.1.2:8080); `wan_ping = true`.

- [ ] **Step 1: Write the scenarios**

```rust
/// Boot vm-public.toml: lan0 the main host, lan1 the DMZ host 192.0.2.234/29 via .233, isp0 routing both blocks to WAN_ADDR.
fn boot_public(lab: &mut Lab) -> anyhow::Result<Cursor> { lab.add_lan1()?; lab.with_config(VM_PUBLIC)?; … READY …; lan hosts; lab.isp_route_block("192.0.2.232/29")?; lab.isp_route_block("192.0.2.248/29")?; Ok(cursor) }

fn dmz_host_is_reached_from_the_isp_only_through_a_rule(lab) {
    boot_public; let web = daemons::http_server(lan1, "192.0.2.234", 80, dir, "dmz web")?; let other = daemons::http_server(lan1, "192.0.2.234", 8080, dir, "dmz other")?;
    ensure!(http_get(isp0 → 192.0.2.234:80) == "dmz web");
    ensure!(http_get(isp0 → 192.0.2.234:8080, SHORT).is_err(), "no rule opens 8080");
    ensure!(lanclient::ping_loop(&lab.isp0, "192.0.2.234", 2, …)?.received == 0, "no rule opens ICMP");
    ensure!(web.log.count(&re("^203\\.0\\.113\\.1 - - ")) == 1, "the DMZ server sees the ISP host, untranslated");
}
fn dmz_host_leaves_without_translation(lab) {
    boot_public; let isp = http_target(lab, &lab.isp0, "203.0.113.1", ISP_HTTP_BODY)?;
    ensure!(http_get(lan1 → ISP_HTTP) == ISP_HTTP_BODY);
    ensure!(isp.log.count(&re("^192\\.0\\.2\\.234 - - ")) == 1, "{:?}", isp.log.tail(5));
}
fn a_public_address_forwards_to_a_lan_host(lab) {
    boot_public; let server = http_target(lab, &lab.lan0, "192.168.1.2", LAN_HTTP_BODY)?;
    ensure!(http_get(isp0 → 192.0.2.249:443) == LAN_HTTP_BODY && server.log.count(&re("^203\\.0\\.113\\.1 - - ")) == 1);
    ensure!(http_get(lan0 → 192.0.2.249:443) == LAN_HTTP_BODY && server.log.count(&re("^192\\.168\\.1\\.1 - - ")) == 1, "hairpin by the public address");
    ensure!(http_get(isp0 → 192.0.2.249:2222, SHORT).is_err(), "the WAN-address forward does not answer on a public address");
}
fn an_unused_public_address_is_blackholed(lab) {
    let cursor = boot_public;
    console.wait_for(&mut cursor, &re(r"openfeo: add route blackhole 192\.0\.2\.248/29 proto 200 metric 1000"), SOON)?;
    let out = netns::run(lab.isp0.command("ping")?.args(["-c", "2", "-W", "1", "192.0.2.250"]));   // ping exits 1 on no reply: capture output regardless
    ensure!(out.contains(" 0 received") && !out.to_lowercase().contains("unreachable"), "{out}");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p openfeo-config m2_fixtures 2>&1 | tail -3; OPENFEO_KERNEL=$PWD/build/bzImage cargo test -p openfeo-harness --test m2 dmz_host 2>&1 | tail -8`
Expected: fixture missing; scenarios fail before the fixture exists.

- [ ] **Step 3: Write the fixture, finish the scenarios, add the README sentence**

- [ ] **Step 4: Run the m2 suite and then the whole CI set**

Run: `OPENFEO_KERNEL=$PWD/build/bzImage cargo test -p openfeo-harness --test m2 2>&1 | tail -12 && make ci 2>&1 | tail -15`
Expected: eight m2 scenarios pass; `make ci` green end to end (lint, unit, kernel, every harness suite).

- [ ] **Step 5: Commit**

```bash
git add harness/fixtures/vm-public.toml harness/tests/m2.rs crates/openfeo-config/src/validate.rs README.md
git commit -s -m "harness: the DMZ is reached only by rule and leaves untranslated; public forwards and blackholes"
```

---

## Self-review notes

- Spec coverage: VLAN members and tagged WAN (Tasks 2, 4, 5, 9); public blocks, blackholes, no translation, reduced services, guard exemption, forward addresses (Tasks 3, 6, 7, 8, 10); `reaches` with `"none"` and gated translated flows (Tasks 3, 7, 9); rules in sets with the sandbox proof and fallback (Tasks 3, 7); echo limit (Task 7); SPEC and ADR (Task 1); lab, fixtures, eight QEMU scenarios, sandbox additions, snapshots, validation, fuzz (Tasks 4, 6, 7, 9, 10, 3). The design's seven scenarios became eight: the "guest cannot reach main" and the tagged-WAN checks split into their own scenarios and the stray-VLAN check was added from Review Focus 4.
- Type consistency: `PortRef`, `parse_port_ref`, `vlan_ifname` (Task 2) used by Task 5; `Target`, `parse_target`, `parse_ports` (Task 3) used by Task 7; `LinkKind::Vlan`, `RouteKind`, `link_add_vlan` (Task 4) used by Tasks 5 and 6; `wan_ifname` and `public::*` (Tasks 5, 6) used by Tasks 7 and 8; `guard_subnets` (Task 8) in three literals.
- Known cost: Task 7 is the largest; if the generator's `nft()` nears 100 lines, split set construction into `fn sets(world) -> Vec<Value>`.
