# Router Deferred Minors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the fifteen router-side issues deferred from the M2 and M3 reviews (#15, #16, #18, #27, #32, #35, #37, #38, #39, #40, #41, #42, #43, #44, #45), each fixed test-first, in one branch and one PR, so M4 builds on a router whose published state is right.

**Architecture:** Nothing new is designed. Each task owns one crate group and fixes its issues in the existing modules, keeping every interface the router task, the reconcilers and the harness consume unless the issue is the interface (named in the task's Interfaces block). The one mechanism added is address lifetimes end to end (Task 9): the RA client carries a prefix's preferred and valid lifetimes, the World fact carries them as it already does for DHCPv6, the routing reconciler desires them, and the netlink crate hands them to the kernel as `IFA_CACHEINFO` and reads them back, so the kernel deprecates the WAN's SLAAC address on time. Behaviour a LAN device or the console can see gets a scenario or a contract line; the rest is unit tests.

**Tech Stack:** As the branch stands: Rust stable 2024, tokio, nix, rtnetlink 0.23 / netlink-packet-route 0.33 in the kernel crates, prost/pbjson, insta, cargo-fuzz; the lab unchanged (Kea, radvd, dnsmasq, QEMU).

**Spec:** `SPEC.md` §7.1 (ports), §7.3 (IPv6: SLAAC lifetimes "under the two-hour rule", DHCPv6 per RFC 8415, the stateless responder answering "a link-local source", RA lifetimes), §7.5 (ULA never crosses a WAN), §7.7 (learned resolvers "joining only once its default route exists"), §8.2 (config spellings), ADR-0019 (the route gate). The issues' own text is the requirement where SPEC is silent; each task names its issues.

**Left out, and why:** #35's optional "one shape for `ForwardFailed` and `Unreachable`" (two cores, two drivers, no bug; a refactor for its own sake). A QEMU scenario for #32 (a classless-only Kea template is a second lab template for one unit-testable gate). Kernel lifetimes for the router's own loopback and LAN addresses (they are typed or derived, and infinite by design).

## Global Constraints

- Every source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton` (`#` in TOML and shell).
- `#![forbid(unsafe_code)]` everywhere except `openfeo-init`, `openfeo-nft` and `openfeo-net` (ADR-0013). Pure crates (`openfeo-proto-*`, `openfeo-reconcile`, `openfeo-world`) stay pure; `scripts/check-deps.sh` enforces it. `openfeo-config` is pure in practice (its tree has no tokio, libc, nix or socket2) and `openfeo-apply` may depend on it (Task 2).
- Rust stable, edition 2024; `clippy -D warnings` with pedantic on; no `unwrap`/`expect` outside tests; `thiserror` in libraries, `anyhow` only in `crates/openfeo` and `harness/`.
- No protobuf change. Console lines are a contract with the harness: every existing line keeps its text; new lines are listed in their task and pinned in that module's `lines_follow_the_contract` test.
- Documentation ranges only: `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`, `2001:db8::/32`, `fd12:3456:789a::/48`.
- Snapshots: when a task says a snapshot changes, run the test, read the `.snap.new` diff against the task's expectation, then accept it (`cargo insta accept` if installed, else move the file over); a snapshot never changes in a task that does not say so.
- Commits: `git commit -s`, subject `<area>: <summary>`, trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Each commit closes its issues in the body (`Closes #NN`).
- `export OPENFEO_NFT_SRC=$PWD/build/nft/src OPENFEO_UAPI_INCLUDE=$PWD/build/kernel/headers/include` before a bare `cargo` command; QEMU scenarios need `OPENFEO_KERNEL=$PWD/build/bzImage` (`make kernel` once, after Task 9's binary change at the latest); a single harness suite is `cargo test -q -p openfeo-harness --test <suite>`.
- The branch is `router-minors` from `main` at `d20b3c4`.

## Review Focus

1. An ISP that deprecates the WAN's link prefix (preferred 0, valid still running) must leave the router with an address it no longer prefers for new flows, and one the kernel drops when valid runs out, never an address that stays preferred for a day: test `a_deprecating_advertisement_keeps_the_address_with_preferred_zero` (Task 9) and the netlink scenario `an_address_with_lifetimes_is_deprecated_by_the_kernel_on_time` (Task 9).
2. A DHCPv4 lease carrying only classless routes and a resolver inside one of them must give the household DNS: test `a_classless_only_lease_opens_the_gate_for_a_covered_resolver` (Task 5).
3. A home whose first router advertisement after boot fails with `ENETUNREACH` must still advertise within two seconds, with the restored delegation's live lifetimes, so no host deprecates its address for the second the WAN takes to come up: the `transient_send_errors_are_retried_a_second_later` unit test (Task 7), the `a_restored_delegation_is_live_until_the_rebind_is_answered_or_times_out` test (Task 7), and the `m2pd` reboot scenario asserting no `ra .*: send:` warning (Task 7).
4. A renewal whose Reply omits one held prefix (an ISP that answers only what changed) must not deprecate that prefix on the LAN: test `a_renewal_that_omits_a_held_prefix_leaves_it_unchanged` (Task 8).
5. A reboot inside a deprecation window that no Reply followed must still advertise the old prefix deprecated: tests `a_file_with_only_a_deprecated_list_restores_it` and `dropping_the_binding_keeps_the_deprecated_list_on_disk` (Task 8).

---

### Task 1: Config spellings and `pd_hint` beside a typed prefix (#18, #43)

**Files:**
- Modify: `crates/openfeo-config/src/rules.rs:160-162` (`parse_port`), `crates/openfeo-config/src/portname.rs:39-48` (`parse_vlan`), `crates/openfeo-config/src/validate.rs:638-643` (the ports message), `crates/openfeo-config/src/validate.rs:884-906` (`pd_hint`)
- Test: `rules.rs` `mod tests`, `portname.rs` `mod tests`, `validate.rs` `mod tests` and `mod ipv6_tests`

**Interfaces:**
- Produces: `rules::parse_ports` and `portname::parse_vlan` keep their signatures and accept only canonical decimal (digits, no leading `+`, no leading zero; `"0"` alone is still refused as before). New validation code `Code::PdHintBesidePrefix` (`as_str` `"pd_hint_beside_prefix"`) at path `wans[i].ipv6.pd_hint`.

- [ ] **Step 1: Failing tests.** In `rules.rs` `targets_and_ports_parse_in_their_three_shapes`, add to the bad list `vec!["+80"]`, `vec!["0080"]`, `vec!["80-0090"]`. In `portname.rs` `port_refs_parse_untagged_and_tagged_names`, add `p1.0101` and `p1.+1` (already there) to the `None` cases and keep `p1.101` as `Some(101)`. In `validate.rs` `mod ipv6_tests`, add:

```rust
#[test]
fn pd_hint_beside_a_typed_prefix_is_refused() {
    let cfg = config("[wans.ipv6]\nprefix = \"2001:db8:1::/48\"\npd_hint = 56\n", LAN0_V6, "");
    assert_eq!(found(&cfg), vec![("wans[0].ipv6.pd_hint".to_owned(), Code::PdHintBesidePrefix)]);
    let cfg = config("[wans.ipv6]\nprefix = \"2001:db8:1::/48\"\n", LAN0_V6, "");
    assert!(found(&cfg).is_empty(), "{:?}", found(&cfg));
}
```

Also a validate test `a_port_list_entry_is_quoted_when_refused`: a tcp rule with ports `["+80"]` yields `Code::InvalidRulePorts` whose message contains `"+80"` (use `validate(&cfg, &live())` and check `v.message.contains("\"+80\"")`).

- [ ] **Step 2: Run** `cargo test -p openfeo-config` → the four fail (`PdHintBesidePrefix` does not compile: add the variant first, then run).
- [ ] **Step 3: Implement.** `parse_port`: refuse an empty string, a non-digit byte, or a leading `'0'` when `len > 1`, then parse. `parse_vlan`: the same leading-zero rule before the range check. The ports message becomes `format!("{entry:?} is not a port (1-65535) or an \"a-b\" range")` for the first entry `parse_port_range` refuses (loop the entries in `firewall_rules`, report the first bad one). `pd_hint`: inside `if ipv6.pd_hint != 0`, `if !ipv6.prefix.is_empty()` push `Code::PdHintBesidePrefix` with message `"a typed prefix asks for no delegation, so pd_hint would describe nothing; drop one of them"`. Doc the new code beside `InvalidPdHint` (validate.rs:107).
- [ ] **Step 4: Run** `cargo test -p openfeo-config` → pass; `cargo fuzz run config_toml -- -max_total_time=30` (the target runs validation) → no crash.
- [ ] **Step 5: Commit** `config: canonical port and VLAN spellings; pd_hint beside a typed prefix is refused` (Closes #18, #43).

### Task 2: One port-name grammar (#16)

**Files:**
- Modify: `crates/openfeo-apply/Cargo.toml` (add `openfeo-config = { path = "../openfeo-config" }`), `crates/openfeo-apply/src/lib.rs:131-163`
- Test: `lib.rs` `mod tests`

**Interfaces:**
- Produces: `openfeo_apply::is_managed(ifname: &str) -> bool` and `pub fn is_vlan_port_name(ifname: &str) -> bool` keep their signatures; both are now defined over `openfeo_config::portname::{is_port_name, parse_port_ref}`; the private copies `is_port_name` and the digit loop in `is_vlan_port_name` are deleted.

- [ ] **Step 1: Failing test.** Extend `managed_interfaces_include_vlan_sub_interfaces`: `p1.0`, `p1.4095`, `p1.01` are **not** managed; `p1.4094` is. Add `the_grammar_is_openfeo_configs`: `for name in ["p0", "p12.101", "p1.4095", "p1.01", "px", "p1.5a"] { assert_eq!(is_vlan_port_name(name) || openfeo_config::portname::is_port_name(name), openfeo_config::portname::parse_port_ref(name).is_some(), "{name}") }`.
- [ ] **Step 2: Run** `cargo test -p openfeo-apply is_managed` → `p1.0` and `p1.4095` fail.
- [ ] **Step 3: Implement.** `is_vlan_port_name(ifname)` = `parse_port_ref(ifname).is_some_and(|r| r.vlan.is_some())`; `is_managed` uses `openfeo_config::portname::is_port_name`. Run `scripts/check-deps.sh` → still clean.
- [ ] **Step 4: Run** `cargo test -p openfeo-apply && make lint` → pass.
- [ ] **Step 5: Commit** `apply: port names come from openfeo-config's one grammar` (Closes #16).

### Task 3: `arp_ignore`, and the IPv6 MTU behind the lease MTU (#15, #38)

**Files:**
- Modify: `crates/openfeo-init/src/sysctl.rs:9` (`CORE`), `crates/openfeo-reconcile/src/links.rs` (new `pub fn wan_port_mtu`), `crates/openfeo-reconcile/src/sysctl.rs:52-63`
- Create: `harness/fixtures/vm-trunk.toml`
- Test: `openfeo-init` `table_has_no_duplicates_or_leading_slashes`, `crates/openfeo-reconcile/src/sysctl.rs` tests, `harness/tests/m2.rs` (new scenario)

**Interfaces:**
- Produces: `openfeo_reconcile::links::wan_port_mtu(world: &World, wan: &Wan) -> Option<u32>`: the MTU the links reconciler desires for the WAN's port (the lease MTU or `DEFAULT_MTU` for DHCP, `PPPOE_PORT_MTU` for PPPoE, `None` for static), extracted from `wan_interfaces` (links.rs:225-231) so both callers share it.

- [ ] **Step 1: Failing tests.** (a) `openfeo-init/src/sysctl.rs`: add `arp_ignore_is_on_for_every_interface`: `CORE` contains `("net/ipv4/conf/all/arp_ignore", "1")`. (b) `reconcile/sysctl.rs`: add `the_ipv6_mtu_never_exceeds_the_lease_mtu`: `fixtures::pd_world()` with `world.dhcp4 = Arc::new(BTreeMap::from([("wan0".to_owned(), { let mut f = fixtures::dhcp_fact(); f.mtu = Some(1400); f })]))` and the link fact still at 1500 → `entries["net/ipv6/conf/p0/mtu"] == "1400"`; with `f.mtu = None` → `"1500"`.

  Ruling written into the plan: the issue proposes a per-interface `arp_ignore` plus `conf/default`; `net/ipv4/conf/all/arp_ignore=1` is the same guarantee in one line (the kernel takes the maximum of `all` and the interface's), present from PID 1 before any interface exists, and no reconciler walk. Cost if wrong: none for the router's own addresses (every one sits on the interface that receives its ARP: a bridge, a WAN port or a PPP unit that has no ARP).
- [ ] **Step 2: Run** `cargo test -p openfeo-init -p openfeo-reconcile sysctl` → both fail.
- [ ] **Step 3: Implement.** `CORE` gains the line beside `default/rp_filter`. `wan_port_mtu` as above; in `sysctl.rs` the `mtu` is the minimum of the advertised, the link's and `wan_port_mtu(world, wan)` (fold the `Some`s with `min`).
- [ ] **Step 4: Run** → pass. The `sysctl_follows_forwarding` snapshot is unchanged (static WAN: `wan_port_mtu` is `None`).
- [ ] **Step 5: The scenario.** `harness/fixtures/vm-trunk.toml`: `vm-vlans.toml` with `lan0`'s `ports = ["p3"]` and `guest` as the only LAN on `p2` (`ports = ["p2.223"]`), no `trusted`; the WAN untagged on `p0`. In `m2.rs` add:

```rust
/// A port carrying only tagged LANs answers no untagged ARP for the router's addresses
/// (arp_ignore): a host on its native VLAN learns nothing (#15).
fn a_pure_trunk_port_answers_no_untagged_arp(lab: &mut Lab) -> anyhow::Result<()> {
    vlanprobe::require_vlan_links()?;
    lab.add_lan1()?;                       // lan0 lives on p3 now; p2 carries only guest's tag
    lab.start_kea()?;                      // the WAN is untagged in this fixture
    lab.with_config(VM_TRUNK)?;            // include_str!("../fixtures/vm-trunk.toml")
    lab.boot("")?;
    let c = lab.console()?;
    let mut cur = Cursor::default();
    c.wait_for(&mut cur, &re(READY), BOOT_TIMEOUT)?;
    Lab::host(&lab.lan0, "lan0", "192.168.1.2/24", "192.168.1.1")?;   // the untagged side of p2
    let _ = ping_once(&lab.lan0, "192.168.1.1")?;                      // forces an ARP request
    let neigh = lab.lan0.ip(&["neigh", "show", "192.168.1.1"])?;
    ensure!(!neigh.contains("lladdr"), "the trunk answered the untagged ARP: {neigh}");
    Ok(())
}
```

Register it in `SCENARIOS`. Prove it RED by running once with the `CORE` line commented out (the router answers: `lladdr` present), then GREEN.
- [ ] **Step 6: Run** `make bin && make kernel`, then `OPENFEO_KERNEL=build/bzImage cargo test -q -p openfeo-harness --test m2` → pass, and `--test m1` (the DHCP WAN MTU scenario, `openfeo: set p0 mtu 1400`) → no `apply sysctl failed` line.
- [ ] **Step 7: Commit** `sysctl: arp_ignore for every interface; the WAN's IPv6 MTU never exceeds the lease MTU` (Closes #15, #38).

### Task 4: ULA in the router's own output (#45)

**Files:**
- Modify: `crates/openfeo-reconcile/src/nft.rs:160-164` (chain list), new `fn output_chain() -> Vec<Value>` beside `forward_chain`
- Test: `nft.rs` `ula_never_crosses_a_wan` and the five ruleset snapshots; `harness/tests/nft.rs` `ula_toward_the_wan_is_rejected_with_no_route`

- [ ] **Step 1: Failing test.** Extend `ula_never_crosses_a_wan`: the ruleset has a chain `output` (`type filter hook output priority 0; policy accept`) with exactly two rules mentioning `fc00::`/`len 7`: `oifname @wan_if ip6 saddr fc00::/7 reject icmpv6 no-route`, then the same for `daddr`.
- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile ula_never` → fails.
- [ ] **Step 3: Implement.** `output_chain()` = `chain("output", "filter", "output", 0, "accept")` plus the two rules with the existing helpers (`oifname_in`, `ula`, `reject_no_route`); append it after `forward_chain` in `nft()`.
- [ ] **Step 4: Run** `cargo test -p openfeo-reconcile nft` → `ula_never_crosses_a_wan` passes; the five snapshots show only the new chain and two rules; accept them. Extend the harness scenario: `nftlist::match_rights(&ruleset, "output", &ip6_field)` finds both, `count_verdict(&ruleset, "output", "reject") == 2`; `cargo test -q -p openfeo-harness --test nft` → pass.
- [ ] **Step 5: Commit** `nft: the router's own ULA-sourced or ULA-bound output toward a WAN is refused` (Closes #45).

### Task 5: The route gate covers a resolver (#32)

**Files:**
- Modify: `crates/openfeo-world/src/ipv6.rs:40-46`, `crates/openfeo-world/src/world.rs:57-94`, `crates/openfeo-world/src/lib.rs:26`, `crates/openfeo/src/router.rs:452-472` (+ its test at 645), `crates/openfeo-reconcile/src/fixtures.rs` (4 sites), `crates/openfeo-reconcile/src/dns.rs:241-286`, `crates/openfeo-reconcile/src/ra.rs:259` (test)
- Test: `world.rs`, `dns.rs`, `router.rs` tests

**Interfaces:**
- Produces: `openfeo_world::KernelRoute { pub v6: bool, pub ifname: String, pub dst: Option<IpNet> }` replaces `DefaultRoute` (`dst: None` is a default route); `World.routes: Arc<BTreeSet<KernelRoute>>` holds every unicast route of table `main` with an output interface. `World::has_default(v6, ifname)` keeps its meaning (`dst.is_none()`); new `World::reaches(&self, addr: IpAddr, ifname: &str) -> bool`: a route of `addr`'s family through `ifname` whose `dst` is `None` or contains `addr`.
- Consumers: `dns::wan_dns` gates each learned IPv4 resolver (DHCP and IPCP arms) with `world.reaches(resolver, &ifname)` instead of `has_default(false, ..)`; the IPv6 arm likewise uses `reaches`. `lan6::wan_usable` and the RA lifetime keep `has_default(true, ..)` (SPEC §7.3: a usable IPv6 *default* route).

- [ ] **Step 1: Failing tests.** `world.rs`: `reaches_needs_a_covering_or_default_route` (routes `{v4 p0 dst None}`, `{v4 p1 dst 198.51.100.0/24}`: `reaches(192.0.2.53, "p0")` true, `reaches(198.51.100.53, "p1")` true, `reaches(192.0.2.53, "p1")` false, `reaches(2001:db8::53, "p0")` false). `dns.rs`: `a_classless_only_lease_opens_the_gate_for_a_covered_resolver`: `dhcp_world()` with the lease's routes `[(198.51.100.0/24, 203.0.113.1)]`, `gateway: None`, `dns: [198.51.100.53, 192.0.2.53]`, and `world.routes = {KernelRoute v4 p0 dst Some(198.51.100.0/24)}` → `wan_upstreams == [198.51.100.53]`; with `world.routes` empty → `[]`.
- [ ] **Step 2: Run** `cargo test -p openfeo-world -p openfeo-reconcile` → compile errors (rename), then the two tests fail.
- [ ] **Step 3: Implement.** Rename the type (every user listed above; `sed` is fine), add `dst`, `reaches`; `router.rs::default_routes` → `kernel_routes(cache)`: keep every `Unicast` route in `TABLE_MAIN` with an `oif` the cache can name, `dst` carried over; its test renamed `kernel_routes_from_the_cache_name_their_interface_and_skip_other_tables` and extended with one prefixed route that is kept. Fixtures gain `dst: None` on their entries.
- [ ] **Step 4: Run** `cargo test -p openfeo-world -p openfeo-reconcile -p openfeo` → pass; `make lint`.
- [ ] **Step 5: Commit** `world: the route gate opens for a resolver any kernel route through the WAN covers` (Closes #32).

### Task 6: DNS forwarder retries (#35)

**Files:**
- Modify: `crates/openfeo-proto-dns/src/forwarder.rs:559-571` (due retries), `crates/openfeo-net/src/dns.rs:82-101` (`Incoming`), `:221-240` (`step`), `:348-356`, `:638-657` (`upstream_tcp`), `fuzz/fuzz_targets/dns_forwarder.rs`
- Test: `forwarder.rs` tests; `openfeo-net/src/dns.rs` tests

**Interfaces:**
- Produces: `Incoming::UpstreamTcpFailed { upstream: IpAddr, bytes: Vec<u8> }`, fed to the core as `Input::ForwardFailed { upstream, transport: Transport::Tcp, bytes }`. `async fn upstream_tcp(to: SocketAddr, query: Vec<u8>, inbox: mpsc::Sender<Incoming>)` (the port in the address, so a test can aim at a closed local port); a connect or write error sends `UpstreamTcpFailed`; a read error or the 3 s timeout still sends nothing (the core's timer owns silence).
- Core: a due retry whose upstream `is_down` moves to `pick_upstream(now, Some(down))`, bumps `attempts`, takes a fresh id and resets `retry_at`/`retried`, exactly as `timeout`'s failover does; when nothing else is up it resends as before.

- [ ] **Step 1: Failing tests (core).** `a_failed_tcp_forward_is_retried_soon`: after `truncated_udp_replies_are_fetched_again_over_tcp`'s setup, feed `ForwardFailed { transport: Tcp, bytes }` at `now`, assert `next_timeout() == Some(now + FORWARD_RETRY)`, then `Timeout` at that time yields one `Forward` to the same upstream over `Tcp` with the same id, and nothing is marked down after `UPSTREAM_TIMEOUT`. `a_due_retry_moves_to_an_upstream_that_is_up`: two upstreams; query 1 to `.1` times out silently (marks `.1` down); query 2 had been forwarded to `.1` with a failed send → at its retry the `Forward` goes to `.2` with `attempts == 2` and a new id (`forwards(&out)[0].0 == ipa("203.0.113.2")`).
- [ ] **Step 2: Run** `cargo test -p openfeo-proto-dns` → both fail.
- [ ] **Step 3: Implement the core change** in `timeout`'s retry loop.
- [ ] **Step 4: Run** → pass. Extend the fuzz target: after the TCP switch (feed a truncated reply), feed `ForwardFailed { transport: Tcp }` and drive to `next_timeout()`; `cargo fuzz run dns_forwarder -- -max_total_time=30` → no crash.
- [ ] **Step 5: Failing test (driver).** In `openfeo-net/src/dns.rs` tests, `#[tokio::test] a_refused_tcp_upstream_reports_the_failure`: bind a `TcpListener` on `127.0.0.1:0`, take its port, drop it; `upstream_tcp(SocketAddr::new(127.0.0.1, port), vec![0, 7], tx).await` → `rx.recv()` is `Incoming::UpstreamTcpFailed { upstream: 127.0.0.1, bytes: [0, 7] }`.
- [ ] **Step 6: Implement the driver change**; `perform_round` passes `SocketAddr::new(upstream, DNS_PORT)`; `step` maps the new variant. Run `cargo test -p openfeo-net dns` → pass.
- [ ] **Step 7: Commit** `dns: a failed TCP forward is retried like a UDP one; a due retry leaves a downed upstream` (Closes #35).

### Task 7: The first advertisement, and a restored delegation (#37, #44)

**Files:**
- Modify: `crates/openfeo-net/src/ndp.rs:150-202` (`tentative_link_local` → `transient_send_error`, `Resend::retry`), `crates/openfeo/src/{ra.rs:228,ipv6.rs:330,dhcp6.rs:530,551}` (callers), `crates/openfeo-proto-dhcp6/src/client.rs:186-199` (`Note`), `:561-566`, `crates/openfeo/src/dhcp6.rs` (`Run.restored`, `fact_from`, `publish`, `bound`, note line), `crates/openfeo-world/src/dhcp6.rs:37-53`, `crates/openfeo-reconcile/src/lan6.rs:178-191`, `harness/tests/m2pd.rs:634` (the reboot scenario)
- Test: new `mod tests` in `openfeo-net/src/ndp.rs`; `dhcp6` core tests; `crates/openfeo/src/dhcp6.rs` tests; `lan6.rs` tests

**Interfaces:**
- Produces: `openfeo_net::ndp::transient_send_error(err: &DriverError) -> bool`: `EADDRNOTAVAIL` (tentative link-local) or `ENETUNREACH` (no usable source yet); `Resend::retry` re-arms on it. `Note::RebindUnanswered` from the DHCPv6 core when a `Start { binding: Some }` Rebind reaches `CNF_MAX_RD` without a Reply (`client.rs:561-566`). `WanDhcp6Fact.restored: bool`: published from disk and not yet confirmed; `fact_from(binding, deprecated, restored: bool)`. `lan6::prefixes`: a delegation is `State::Live` when `usable || fact.restored`; `wan_usable` and the router lifetime are unchanged. Console: `dhcp6 {wan} rebind unanswered: binding kept until it lapses` (new, pinned in `lines_follow_the_contract`).

- [ ] **Step 1: Failing tests.** `ndp.rs`: `transient_send_errors_are_retried_a_second_later`: `DriverError::Io { what: "send ICMPv6", source: io::Error::from_raw_os_error(n) }` for `n` in `[libc::EADDRNOTAVAIL, libc::ENETUNREACH]` → true; `[libc::ENETDOWN, libc::EPERM]` → false. Core: `an_unanswered_rebind_after_start_says_so`: `start_with_a_binding_rebinds_first`'s setup, then `Timeout` at `CNF_MAX_RD` → `notes(&out)` contains `Note::RebindUnanswered` and the state is `Bound` (no `Gone`, no `Bound` output). `lan6.rs`: `a_restored_delegation_is_live_until_the_rebind_is_answered_or_times_out`: `pd_world()` with empty routes and `fact.restored = true` → the delegation is `State::Live { .. }`, `wan_usable` still false; `restored = false` → `Stale`. `crates/openfeo/src/dhcp6.rs`: `fact_from_carries_the_restored_flag`, and the contract line.
- [ ] **Step 2: Run** the four crates' tests → fail (compile first for the new names).
- [ ] **Step 3: Implement.** Rename and widen the predicate; the `Run` gains `restored: bool`, set when `read_binding` gives a binding, cleared in `bound()` and on `Note::RebindUnanswered` (both followed by `publish()`); `publish` passes it to `fact_from`.
- [ ] **Step 4: Run** → pass; `make lint`.
- [ ] **Step 5: Scenario.** In `m2pd.rs` `a_rebooted_router_keeps_its_delegation`, after the reboot's READY assert `c.count(&re(r"openfeo: ra \S+: send:")) == 0` (`Lines::count` on the console, as the scenario's other counts) (the ENETUNREACH warning is gone: a debug line now). Run `OPENFEO_KERNEL=build/bzImage cargo test -q -p openfeo-harness --test m2pd` → pass, including the scenario's existing "never deprecated" poll, which is what pins #44 live now that the first advertisement succeeds.
- [ ] **Step 6: Commit** `ra, dhcp6: the first advertisement retries ENETUNREACH; a restored delegation is live until the rebind answers` (Closes #37, #44).

### Task 8: DHCPv6 client and task (#39, #40, #41, #42)

**Files:**
- Modify: `crates/openfeo-proto-dhcp6/src/client.rs:834-842` (`reply`), `crates/openfeo-proto-dhcp6/src/server.rs:34` (`reply` gains `from`), `crates/openfeo/src/dhcp6.rs:181-345` (file functions), `:558-655` (`bound`, `gone`, `purge`, `drop_binding`), `crates/openfeo/src/dhcp6_server.rs:144-152`, `harness/tests/dhcp6.rs:629`, `fuzz/fuzz_targets/dhcp6_server.rs:10`
- Test: the two cores' tests, `crates/openfeo/src/dhcp6.rs` tests

**Interfaces:**
- Produces: `server::reply(config: &Config, from: Ipv6Addr, request: &[u8]) -> Option<Vec<u8>>`: `None` unless `from.is_unicast_link_local()`. `binding_file(wan, mac, binding: Option<&Binding>, deprecated, now_unix, now_ms) -> Dhcp6Lease`; `binding_from_file(file, wan, mac, now_unix, now_ms) -> Result<Restored, &'static str>` with `pub struct Restored { pub binding: Option<Binding>, pub deprecated: Vec<Deprecated> }` and the reasons `"for another WAN"`, `"for another port"`, `"server DUID is not hex"`, `"lapsed"` (no lease left and no deprecation still running). `read_binding` logs `dhcp6 {wan} {path}: {why}; ignoring it` (one `warn!`, replacing the two lines at 305-314). `save_binding(path, wan, mac, binding: Option<&Binding>, deprecated)`; `gone`, `purge` and `drop_binding` become `async fn` and save after every change; `drop_binding` removes the file only when the deprecated list is empty too.
- Core `reply`: a lease the old binding holds inside an IA the Reply mentions, that the Reply neither lists nor zeroes, stays in the new binding with its lifetimes reduced by the seconds since `old.bound_at` (dropped as `gone` only when that leaves no valid time), per RFC 8415 §18.2.10.1.

- [ ] **Step 1: Failing tests (client core).** `a_renewal_that_omits_a_held_prefix_leaves_it_unchanged`: bind with an `IaPd` of two prefixes (`PREFIX` and `NEW_PREFIX`, valid 60, as `a_reply_that_replaces_the_prefix_reports_the_old_one_gone` builds one), renew at T1 (`15_000`), answer with an `IaPd` listing only `NEW_PREFIX` → `gone_output(&out).is_none()`, the bound binding holds both nets, and the omitted one's `valid == 60 - 10` (the 10 s between 5_000 and 15_000). Keep `a_reply_that_replaces_the_prefix_reports_the_old_one_gone` green (it zeroes the old prefix explicitly).
- [ ] **Step 2: Run** `cargo test -p openfeo-proto-dhcp6` → fails. **Implement** in `reply` (replace the 834-842 block: carry over, do not push to `gone`). Run → pass; `cargo fuzz run dhcp6_client -- -max_total_time=30` → no crash.
- [ ] **Step 3: Failing test (server core).** `a_request_from_a_global_source_is_ignored`: `reply(&config(), "2001:db8::5".parse().unwrap(), &information_request(..))` is `None`; from `fe80::5` it is `Some`. Update the two other callers and the fuzz target (`from` = `fe80::1`). Run → pass.
- [ ] **Step 4: Failing tests (task file).** `a_file_with_only_a_deprecated_list_restores_it`: `binding_file("wan0", MAC, None, &[deprecated(..)], ..)` round-trips to `Restored { binding: None, deprecated: [..] }`. `a_corrupt_server_duid_rejects_the_file`: `file.server_duid = "zz"` → `Err("server DUID is not hex")`. `a_lapsed_or_foreign_binding_is_ignored` adapts to the `Err` reasons. `dropping_the_binding_keeps_the_deprecated_list_on_disk`: a `#[tokio::test]` on the file functions: `save_binding(&path, "wan0", MAC, None, &[deprecated])` then `read_binding` → the list (this is what `drop_binding` now calls); with an empty list the file is removed.
- [ ] **Step 5: Run** `cargo test -p openfeo dhcp6` → fail; **implement**; run → pass. `lines_follow_the_contract` gains the `ignoring it` line through a `fn ignored_line(wan, path, why) -> String`.
- [ ] **Step 6: Run** `cargo test -q -p openfeo-harness --test dhcp6` and `OPENFEO_KERNEL=build/bzImage cargo test -q -p openfeo-harness --test m2pd` → pass (the stateless scenarios' udhcpc6 sends from link-local).
- [ ] **Step 7: Commit** `dhcp6: an omitted lease is left unchanged; the deprecated list is always on disk; a corrupt DUID rejects the file; link-local sources only` (Closes #39, #40, #41, #42).

### Task 9: Address lifetimes end to end (#27)

**Files:**
- Modify: `crates/openfeo-proto-ndp/src/client.rs:88-103,137,308-321,359-393,423-427`; `crates/openfeo-world/src/ipv6.rs:20-38`; `crates/openfeo/src/ipv6.rs:333-359,373` (`fact_from`, `learned_lines`); `crates/openfeo-reconcile/src/routing.rs:38-47,388-410`; `crates/openfeo-netlink/Cargo.toml` (+ `openfeo-runtime`), `crates/openfeo-netlink/src/types.rs:64-76`, `crates/openfeo-netlink/src/monitor.rs:223-231,354`, `crates/openfeo-netlink/src/apply.rs:220-232`; `crates/openfeo-apply/src/routing.rs:114-176`; `harness/tests/netlink.rs`
- Test: each crate's tests; the routing snapshots; one new netlink scenario

**Interfaces:**
- `openfeo_proto_ndp::client::LearnedAddress { pub net: Ipv6Net, pub preferred: u32, pub valid: u32 }` (seconds remaining when the `Learned` was emitted; `u32::MAX` infinite). `Learned.addresses: Vec<LearnedAddress>`. The core keeps `addresses: BTreeMap<Ipv6Net, (Ipv6Addr, Expiry, Expiry)>` (preferred, valid); the two-hour rule applies to valid only (RFC 4862 §5.5.3(e)); preferred 0 keeps the entry. A `Learned` is emitted when it differs, lifetimes included (one per advertisement, which is the ISP's cadence).
- `openfeo_world::WanIpv6Fact.addresses: Vec<Lifetimed>` (the DHCPv6 type: `net`, `obtained_ms`, `preferred_secs`, `valid_secs`); `fact_from(learned, now_ms)` fills `obtained_ms`. `learned_lines` compares nets, not lifetimes, so `wan {wan} ipv6 address {addr}` prints once per address.
- `openfeo_reconcile::routing::DesiredAddr` gains `pub lifetimes: Option<Lifetimes>` with `pub struct Lifetimes { pub preferred_until_ms: Option<u64>, pub valid_until_ms: Option<u64> }` (`None` = infinite), `Serialize`, derived for the WAN's SLAAC addresses and the DHCPv6 IA_NA addresses (`obtained_ms + secs * 1000`); every other address has `lifetimes: None`.
- `openfeo_netlink::Addr` gains `pub preferred_until_ms: Option<u64>` and `pub valid_until_ms: Option<u64>` from `IFA_CACHEINFO` (`0xffff_ffff` → `None`; else `openfeo_runtime::clock::uptime_ms() + secs * 1000` at receipt); `apply_addr` removes by `(ifindex, net, peer)` before inserting, so a lifetime refresh replaces the entry and a `DelAddr` with other numbers still removes it. `Netlink::addr_add_with_lifetimes(index, net, preferred_secs: Option<u32>, valid_secs: Option<u32>)` sends `IFA_CACHEINFO` (`AddressAttribute::CacheInfo`) with `NLM_F_REPLACE` (`.replace()`), so it both adds and refreshes.
- `openfeo_apply::routing::addresses`: a desired address with lifetimes is sent with `addr_add_with_lifetimes` when absent, or when either cached deadline differs from the desired one by more than `LIFETIME_TOLERANCE_MS = 5_000` (two deadlines both in the past count as equal); the op line is `set {net} dev {ifname} lifetimes {preferred}/{valid}`.

- [ ] **Step 1: Core.** Failing test `a_deprecating_advertisement_keeps_the_address_with_preferred_zero`: `pio("2001:db8:ffff::/64", true, true, 3600, 1800)` then at `1_000` the same prefix with `preferred 0` → `learned(&out)` has one address with `preferred == 0`, `valid == 3600 - 1`; `next_timeout()` is still the valid expiry. Adapt `a_prefix_with_a_and_l_yields_an_address_and_an_on_link_route` to the new type (`addresses[0].net`, `preferred == 1800`, `valid == 3600`). Run → fail; implement; run `cargo test -p openfeo-proto-ndp` → pass; `cargo fuzz run ndp_client -- -max_total_time=30` → no crash.
- [ ] **Step 2: World and driver.** Change the fact; `fact_from_carries_every_learned_field` becomes `fact_from(&learned, 7_000)` with `fact.addresses == [Lifetimed { net, obtained_ms: 7_000, preferred_secs: 1800, valid_secs: 3600 }]`; new `learned_lines_name_an_address_once_whatever_its_lifetimes`. Run `cargo test -p openfeo-world -p openfeo` → pass.
- [ ] **Step 3: Reconcile.** Failing test in `routing.rs`: `the_wan_address_carries_its_lifetimes`: `ipv6_world()` with `fact.addresses = [Lifetimed { .., obtained_ms: 10_000, preferred_secs: 1800, valid_secs: u32::MAX }]` → the `DesiredAddr` for it has `lifetimes == Some(Lifetimes { preferred_until_ms: Some(1_810_000), valid_until_ms: None })`; the IA_NA address in `pd_world()` likewise; `br-lan0`'s address has `None`. Implement; the routing snapshots gain `lifetimes: ~` on every address and the two values on the WAN ones: accept. Run `cargo test -p openfeo-reconcile` → pass.
- [ ] **Step 4: Netlink.** Add the dependency (`cargo tree -p openfeo-runtime | grep -c openfeo-netlink` → 0 first). Unit test in `monitor.rs` (or `types.rs`): `cacheinfo_becomes_deadlines_and_infinite_is_none`: build an `AddressMessage` with `CacheInfo { ifa_preferred: 600, ifa_valid: 0xffff_ffff, .. }` → `addr_from` gives `preferred_until_ms` within 100 ms of `uptime_ms() + 600_000` and `valid_until_ms == None`. Implement `addr_from`, `apply_addr`, `addr_add_with_lifetimes`. Run `cargo test -p openfeo-netlink` → pass.
- [ ] **Step 5: Applier.** Implement the compare-and-replace in `addresses`. Unit test of the decision as a pure fn `fn lifetimes_differ(desired: &Lifetimes, cached: (Option<u64>, Option<u64>), now_ms: u64) -> bool`: within tolerance false, beyond true, both past false, `None` vs `Some` true.
- [ ] **Step 6: Scenario.** `harness/tests/netlink.rs`, `an_address_with_lifetimes_is_deprecated_by_the_kernel_on_time`: on a veth, `addr_add_with_lifetimes(idx, 2001:db8:ffff::1/64, Some(2), Some(6))`; `wait_until` the cache shows the address with `preferred_until_ms` about 2 s out; after 3 s `ip -6 addr show dev rv0` contains `deprecated`; `addr_add_with_lifetimes(.., Some(600), Some(1200))` → `deprecated` gone from `ip`'s output and the cache's deadline moved; after the valid lifetime of a third call with `Some(0), Some(2)` the address leaves the cache. Register it; run `cargo test -q -p openfeo-harness --test netlink` → pass.
- [ ] **Step 7: Whole gate for the task.** `make bin && make kernel`, `OPENFEO_KERNEL=build/bzImage cargo test -q -p openfeo-harness --test m2` (`a_link_prefix_from_the_isp_gives_the_wan_a_stable_address` still passes with radvd's lifetimes now in the kernel: `ip -6 addr` in the VM is not read, so the console line is the check) → pass; `make lint && make test`.
- [ ] **Step 8: Commit** in two: `netlink: address lifetimes read from and written as IFA_CACHEINFO` and `ipv6: the PIO's preferred lifetime reaches the kernel, so a deprecated address is deprecated` (Closes #27).

### Task 10: The full gate and the progress entry

**Files:**
- Modify: `docs/progress.md` ("Tooling and process" is the wrong section: add a paragraph under `## M3 PPPoE`'s end or a new `## Follow-ups` section after it: `**<date>, [#NN](...), deferred minors.** ...` listing the fifteen issues closed by area, in the style of #8's entry)

- [ ] **Step 1:** `make lint && make test && OPENFEO_NO_SKIP=1 make test-harness` → every suite passes, nothing skipped (the host loads every module after `sudo ./setup-dev-ppp.sh`). Each parser touched fuzzed 30 s (Tasks 1, 6, 8, 9 say which).
- [ ] **Step 2:** The entry, with the PR number once the PR exists. **Step 3:** Commit `docs: progress entry for the router minors sweep`.

---

## Self-review notes

- Coverage: #18, #43 (1); #16 (2); #15, #38 (3); #45 (4); #32 (5); #35 (6); #37, #44 (7); #39–#42 (8); #27 (9). Fifteen issues, every one named in a task's commit.
- Interfaces: `KernelRoute` (5) is consumed only inside the task; `transient_send_error` (7) replaces one name at four call sites; `WanDhcp6Fact.restored` (7) is read by `lan6` only; `Lifetimed` (9) is the existing DHCPv6 type; `DesiredAddr.lifetimes` (9) is read by the applier only; `server::reply`'s `from` (8) has three callers, all listed.
- Review Focus: each line names its pinning test and task.
- Proportion: the plan decides names, types, values and tests; bodies are left to the implementer except the retry-loop semantics (6) and the §18.2.10.1 rule (8), which the signatures do not determine.
- Rulings taken here rather than left to the executor: `all/arp_ignore` in PID 1 (3); the RFC reading of an omitted lease (8); the router lifetime stays 0 for a restored binding without a default route, only the PIO lifetimes get the grace (7); `Learned` emits per advertisement (9). Each is written with its cost in the task.
