# M2 Part 3: IPv6 Delegated Prefixes, ULA and Deprecation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** IPv6 for an ISP that delegates a prefix by DHCPv6: the WAN client (IA_PD, IA_NA), per-LAN /64s by index from every delegated prefix and from a persisted ULA /48, RA lifetimes derived from the delegation, prefix deprecation answered with ICMPv6 unreachable through policy rules, the stateless DHCPv6 responder, and the renumbering case proven in the lab against Kea.

**Architecture:** A new pure crate `openfeo-proto-dhcp6` (wire codec, client core, stateless responder) driven by UDP sockets in `openfeo-net` from two new tasks in `crates/openfeo`; one pure function `reconcile::lan6::prefixes` tells every reconciler what each LAN carries; the netlink crate learns policy rules and unreachable routes; the routing, RA, nft and DNS reconcilers consume the new facts; the harness gains Kea's DHCPv6 server, a `dhcp6` sandbox suite and a `m2pd` QEMU suite.

**Tech Stack:** Rust stable edition 2024, tokio, rtnetlink 0.23 / netlink-packet-route 0.33, nix, libnftables JSON, insta snapshots, cargo-fuzz with `dhcproto` 0.15 as the DHCPv6 oracle; Kea `kea-dhcp6` 2.4.1 (CI) / 3.x (dev), radvd, busybox `udhcpc6`, rdisc6 in the lab.

**Spec:** `docs/superpowers/specs/2026-11-06-m2-part3-ipv6-delegated-prefixes-design.md` (the design; its "Calls made for the maintainer" are binding), under `SPEC.md` §7.3, §7.4, §7.5, §7.7, §12.

## Global Constraints

- Every new source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton` (CLAUDE.md).
- `clippy -D warnings` with pedantic as warnings; no `unwrap`/`expect` outside tests; `thiserror` in libraries; `#![forbid(unsafe_code)]` in every crate touched here (no new `unsafe`: the UDP sockets use nix and the standard library).
- `openfeo-proto-dhcp6` is pure: no tokio, libc, nix or socket2 in its dependency tree (`scripts/check-deps.sh`, part of `make lint`, enforces it). `dhcproto` is a dev-dependency only.
- Every parser gets a fuzz target in the task that adds it (`fuzz/fuzz_targets/`, registered in `fuzz/Cargo.toml` after the pattern of `ndp_wire`).
- Routes, addresses and rules carry `RTPROT_OPENFEO` (200); the applier touches only what carries it.
- The World is pure and clockless: lifetimes travel as the moment they were obtained, in milliseconds on the process's monotonic clock (`openfeo_runtime::clock::uptime_ms`, added in Task 10), plus seconds; only the persisted binding file carries wall-clock time.
- Commits: `git -c user.name='Andrew Newton' -c user.email='andy@vitri.ltd' commit -s -F <msgfile>`, subject `<area>: <summary>`, body ending with the two attribution lines of the session (`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_0116otzXyvDbuXkw4CsR8ExV`); the message file lives in the scratchpad, never in the repo.
- All repo text is public writing: documentation ranges only (`2001:db8::/32`, `fd12:3456:789a::/48` for ULA examples, TEST-NET addresses); no personal paths.
- `make lint` and `make test` are the per-task gates; `make test-harness FILTER=<name>` for sandbox and QEMU suites (locally the nft-module and VLAN scenarios skip; CI runs them all).
- Console lines are a contract: every new line has a unit test in the module that prints it, and the harness matches the tested text.

## Review Focus

1. A Renew answered with the old prefix at lifetime 0 and a new prefix in the same Reply: the LAN must end up with the new /64 live and the old deprecated, never both live. Pinned in Task 4 (`a_reply_that_replaces_the_prefix_reports_the_old_one_gone`) and Task 20 (the renumbering scenario).
2. A delegation shorter than an index needs (a /60 with `ipv6_index = 20`): the LAN gets no /64 from it, nothing panics, one console line. Pinned in Task 7 (`a_short_delegation_leaves_a_high_index_lan_out`).
3. A Reply with an IA_PD whose status is NoPrefixAvail and an IA_NA with an address: the address is kept, the next Renew asks for the prefix again, no LAN is renumbered to nothing. Pinned in Task 4 (`no_prefix_available_keeps_the_address_and_asks_again_at_renew`).
4. Carrier loss during deprecation: the deprecated list keeps its deadline, the live prefixes go stale (preferred 0), and carrier back Rebinds without wiping the deprecated list. Pinned in Task 13 (`carrier_loss_keeps_the_deprecated_list`).
5. A configuration with `[wans.ipv6]` and a routed prefix only (part 2's fixture): every part 2 scenario still passes, and the only additions are the ULA /64 and O = 1. Pinned in Task 20 (the amended part 2 scenarios) and Task 7 (`a_routed_prefix_world_gains_only_the_ula`).

---

### Task 1: SPEC amendments

**Files:**
- Modify: `SPEC.md` (§5.2 line 132, §7.3 lines 264–282, §7.4 line 286 and 292, §7.5, §7.7 line 310, §8.2 lines 367–410, §11 line 494, §13 line 528 and the fuzz list at line 493)
- Modify: `docs/superpowers/specs/2026-11-06-m2-part3-ipv6-delegated-prefixes-design.md` only if an amendment reveals a contradiction (ledger it)

- [ ] **Step 1: Amend `SPEC.md`** per the design's "SPEC amendments" section, one bullet each, copying the design's wording where it is already spec-grade:
  - §5.2: `identity/` reads `(DUID, DHCPv4 client-id, the IPv6 stable-privacy secret, the ULA prefix, port map)`; a sentence after the table: the secret and the ULA are identity a backup restores and a reinstall regenerates (#33); `leases/` names `dhcp4-<wan>.toml`, `dhcp4-server-<lan>.toml` and `dhcp6-<wan>.toml`.
  - §7.3 "Two ways a prefix reaches the router": the delegated path paragraph: `pd_hint`, the DHCPv6 client beside the RA client on a WAN without a typed `prefix`, the assignment index `ipv6_index` (default position, index 0 the router's loopback address, single-/64 and short-delegation rules), `ipv6 = "none"`, ULA on every LAN once a WAN carries `[wans.ipv6]`.
  - §7.3 "DHCPv6" bullet: the message, timing and status handling of the design's "WAN DHCPv6 client"; Rebind after a flap and after a reboot from `leases/dhcp6-<wan>.toml`; the two-hour drop of a carrier-less binding; a preferred-lapsed address leaves the port.
  - §7.3 "LAN IPv6": PIO lifetimes per state (routed and ULA constants; delegated remaining and capped; stale and deprecated 0/7200); O = 1; RDNSS ULA first; the ULA route information option; deprecation as the client task's two-hour list.
  - §7.4 "Tables" bullet: rule `1500 from all lookup main suppress_prefixlength 0`; the IPv6 half of the per-WAN table and the `2000` source rules land in M2 part 3 (IPv4 half M6); `from <deprecated prefix> unreachable`; `FRA_PROTOCOL` 200. "IPv6" bullet: a blackhole per delegated prefix.
  - §7.5: ULA never crosses a WAN (reject out with no-route, drop in); UDP 546 accepted on the WAN input; UDP 547 a LAN service on advertising LANs; a rule's IPv6 target may be a ULA address.
  - §7.7 "Upstreams": DHCPv6-learned resolvers join under the gate; the router's AAAA and listeners cover every address a LAN carries.
  - §8.2 example: `pd_hint = 56               # M2 part 3` keeps its line with the comment `# the delegation length asked for; absent = 56`; `lan0` gains `ipv6_index = 1  # this LAN's /64 in every delegated prefix and in the ULA; absent = position`; the `guest` LAN gains `ipv6 = "none"  # IPv4 only`.
  - §11: Kea's DHCPv6 server (IA_NA and IA_PD) on the ISP side, `udhcpc6` the stateless reference client, the prefix-change scenario by restarting Kea with another pool.
  - §13: `openfeo-proto-dhcp6  sans-IO client (NA/PD) + stateless server (fuzz: dhcp6_message, dhcp6_differential against dhcproto, dhcp6_client, dhcp6_server)`; `openfeo-netlink` line already says rules.
- [ ] **Step 2: Check the diff reads as spec, not design** (no "the builder", no task numbers).

Run: `git diff --stat SPEC.md && grep -c 'ipv6_index' SPEC.md`
Expected: SPEC.md changed; the count is at least 2.

- [ ] **Step 3: Commit**

```bash
git add SPEC.md
git commit  # subject: "spec: M2 part 3, delegated prefixes, ULA, deprecation and policy rules"
```

---

### Task 2: Config schema and validation

**Files:**
- Modify: `proto/openfeo/v1/config.proto` (`Ipv6Wan`, `Lan`, new `Dhcp6Lease`, `Dhcp6Binding`)
- Modify: `crates/openfeo-config/src/validate.rs` (codes, `ipv6_wan`, `lan_ipv6`, `rule_target`, the `ra` rule)
- Modify: `crates/openfeo-config/src/lib.rs` if the new messages need re-exports (follow `Dhcp4Lease`)
- Test: `crates/openfeo-config/src/validate.rs` tests module; the TOML fixtures under `crates/openfeo-config/tests/` or inline strings as the existing IPv6 tests do

**Interfaces:**
- Produces: `Ipv6Wan.pd_hint: u32` (0 = absent), `Lan.ipv6_index: u32` (0 = absent), `Lan.ipv6 == "none"` meaning IPv4 only, messages `Dhcp6Lease { wan, mac, server_duid, prefixes: Vec<Dhcp6Binding>, addresses: Vec<Dhcp6Binding>, t1_secs, t2_secs, dns, search, obtained_unix, deprecated: Vec<Dhcp6Deprecated> }`, `Dhcp6Binding { net: String, preferred_secs: u32, valid_secs: u32 }` and `Dhcp6Deprecated { net: String, until_unix: u64 }`; validation `Code::{InvalidPdHint, InvalidIpv6Index, Ipv6IndexTwice, Ipv6None}` with snake-case strings; `pub fn lan_is_ipv4_only(lan: &Lan) -> bool` (`ipv6 == "none"`) and `pub fn pd_hint(ipv6: &Ipv6Wan) -> u8` (56 when 0) in `crates/openfeo-config/src/rules.rs`.

- [ ] **Step 1: Write the failing validation tests** in `validate.rs`'s tests module, each a TOML string through `validate(&config, &portmap)` asserting the code list:
  - `pd_hint_outside_48_to_64_is_refused` (`pd_hint = 47` and `65` → `InvalidPdHint`; `56` and absent → clean)
  - `ipv6_index_zero_or_above_65535_is_refused` (`InvalidIpv6Index`)
  - `two_lans_with_one_ipv6_index_are_refused` (`Ipv6IndexTwice` on the second)
  - `ipv6_none_refuses_ra_and_an_index` (`Ipv6None` twice)
  - `disabled_mode_refuses_a_gateway_and_a_pd_hint` (#30; `Ipv6Disabled` once per field)
  - `ra_is_allowed_on_a_lan_without_a_routed_prefix_when_a_wan_has_ipv6` (clean) and `ra_without_any_ipv6_is_still_refused` (`RaWithoutIpv6`)
  - `a_rule_may_target_a_ula_address` (`to = "fd12:3456:789a:1::10"` → clean) and `a_rule_to_an_unknown_global_ipv6_target_is_still_refused`
- [ ] **Step 2: Run them**

Run: `cargo test -p openfeo-config validate -- pd_hint ipv6_index ipv6_none disabled_mode ra_is ra_without ula`
Expected: FAIL (no such fields; prost build fails first, which counts).

- [ ] **Step 3: Add the proto fields and messages** (`uint32 pd_hint = 4;` on `Ipv6Wan` with the doc comment from the design; `uint32 ipv6_index = 8;` on `Lan`; `Dhcp6Lease` numbers 1–11 as the Interfaces say; `Dhcp6Binding` 1–3; `Dhcp6Deprecated` 1–2), then the validation: `pd_hint` 0 or 48..=64; `ipv6_index` 0 or 1..=65535, and the effective index (typed, or the LAN's 1-based position counting every LAN) unique among the LANs that are not `none`, a clash flagged on the later LAN in configuration order; `ipv6 = "none"` refuses `ra` and `ipv6_index`; `Ipv6Disabled` also for a non-empty `gateway` or non-zero `pd_hint`; `RaWithoutIpv6` only when no WAN has `[wans.ipv6]` in mode auto and the LAN has no routed /64, or the LAN is `none`; `rule_target` accepts a target inside `fc00::/7` without a LAN match (the IPv6 branch's "inside one LAN" check is skipped for ULA space; the overlap check still runs within the family).
- [ ] **Step 4: Run the tests and the crate's suite**

Run: `cargo test -p openfeo-config`
Expected: PASS, including the existing IPv6 tests and the TOML round-trip snapshots (update a snapshot only when its change is the new field).

- [ ] **Step 5: `make lint`** (buf lint and breaking run in CI; `make lint` covers fmt, clippy, deny, SPDX)

Expected: exit 0.

- [ ] **Step 6: Commit** `config: pd_hint, ipv6_index, ipv6 = "none" and the DHCPv6 binding file (SPEC §8.2)`

---

### Task 3: `openfeo-proto-dhcp6` wire codec

**Files:**
- Create: `crates/openfeo-proto-dhcp6/Cargo.toml` (deps: `thiserror`, `ipnet`; dev: `dhcproto`), `src/lib.rs` (`#![forbid(unsafe_code)]`, `pub type Timestamp = u64;` milliseconds, `pub mod wire; pub mod client; pub mod server; pub mod iaid;` with `client`, `server`, `iaid` added by later tasks), `src/wire.rs`
- Create: `fuzz/fuzz_targets/dhcp6_message.rs`, `fuzz/fuzz_targets/dhcp6_differential.rs`; register both in `fuzz/Cargo.toml`; add the crate to `fuzz/Cargo.toml` dependencies and to the workspace `Cargo.toml` members
- Modify: `docs/third-party.md` only if a new third-party crate appears (none expected)

**Interfaces:**
- Produces, in `openfeo_proto_dhcp6::wire`: `pub const CLIENT_PORT: u16 = 546; pub const SERVER_PORT: u16 = 547; pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = ff02::1:2;` `pub enum MessageType { Solicit, Advertise, Request, Confirm, Renew, Rebind, Reply, Release, Decline, Reconfigure, InformationRequest, Other(u8) }` with `From<u8>`/`u8::from`; `pub enum StatusCode { Success, UnspecFail, NoAddrsAvail, NoBinding, NotOnLink, UseMulticast, NoPrefixAvail, Other(u16) }`; `pub enum Dhcp6Option { ClientId(Vec<u8>), ServerId(Vec<u8>), IaNa { iaid: u32, t1: u32, t2: u32, options: Vec<Dhcp6Option> }, IaAddr { addr: Ipv6Addr, preferred: u32, valid: u32, options: Vec<Dhcp6Option> }, Oro(Vec<u16>), ElapsedTime(u16), StatusCode { code: StatusCode, message: String }, RapidCommit, DnsServers(Vec<Ipv6Addr>), DomainList(Vec<String>), IaPd { iaid: u32, t1: u32, t2: u32, options: Vec<Dhcp6Option> }, IaPrefix { prefix: Ipv6Net, preferred: u32, valid: u32, options: Vec<Dhcp6Option> }, InformationRefreshTime(u32), SolMaxRt(u32), Unknown { code: u16, data: Vec<u8> } }`; `pub struct Message { pub kind: MessageType, pub xid: u32, pub options: Vec<Dhcp6Option> }` with `pub fn decode(bytes: &[u8]) -> Result<Message, Error>` and `pub fn encode(&self) -> Vec<u8>`; `pub enum Error { Truncated, BadOption { code: u16 }, TooMany }` via thiserror; helpers `impl Message { pub fn option(&self, pred) ...; pub fn client_id(&self) -> Option<&[u8]>; pub fn server_id(&self) -> Option<&[u8]>; pub fn status(&self) -> Option<(StatusCode, &str)> }`.
- Limits: at most 64 top-level options, 16 options inside an IA, nesting depth 2 (IA → IAADDR/IAPREFIX → STATUS), 16 DNS servers, 16 domain names of at most 255 bytes, a domain label of at most 63 bytes; anything beyond is `Error::TooMany`; an option whose length overruns the message is `Truncated`; an unknown option is kept as `Unknown` and round-trips.

- [ ] **Step 1: Write the failing tests** in `wire.rs` tests module:
  - `a_solicit_round_trips` (Client ID, IA_PD with an IAPREFIX hint of `::/56`, IA_NA, ORO [23, 24, 82], Elapsed Time, Rapid Commit; `decode(encode(m)) == m`; the first byte is 1; bytes 1..4 are the xid)
  - `a_reply_from_the_rfc_shapes_decodes` (a hand-built Reply with Server ID, Client ID, IA_PD{IAPREFIX{2001:db8:100::/56, 40, 60}}, IA_NA{IAADDR{2001:db8:ffff::1a4, 40, 60}}, DNS servers [2001:db8:ffff::1], Domain list ["isp.example"], SOL_MAX_RT 3600; the domain list is wire-format labels `03 69 73 70 07 65 78 61 6d 70 6c 65 00`)
  - `a_status_inside_an_ia_decodes` (IA_PD{STATUS NoPrefixAvail "no prefix"})
  - `an_overrunning_option_is_truncated` and `too_many_options_is_too_many`
  - `an_unknown_option_round_trips`
  - `a_three_byte_message_is_truncated`
- [ ] **Step 2: Run** `cargo test -p openfeo-proto-dhcp6` → Expected: FAIL to compile (no crate / no items).
- [ ] **Step 3: Implement `wire.rs`** per the Interfaces (RFC 8415 §8 header: type, 3-byte xid; §21 options: code u16, len u16; IA_NA 12-byte header; IA_PD 12-byte; IAADDR 24; IAPREFIX 25; DNS 16n; domain list as DNS labels; Elapsed Time u16; SOL_MAX_RT u32; Information Refresh Time u32).
- [ ] **Step 4: Run** `cargo test -p openfeo-proto-dhcp6` → Expected: PASS.
- [ ] **Step 5: Fuzz targets**: `dhcp6_message` (decode arbitrary bytes; on `Ok(m)` assert `decode(&m.encode()) == Ok(m)`), `dhcp6_differential` (decode with ours and with `dhcproto::v6::Message::decode`; when both succeed, compare message type, xid and the set of top-level option codes; when ours fails, dhcproto may still succeed only for inputs beyond our limits, i.e. `Error::TooMany`). Register in `fuzz/Cargo.toml` with `path`, `test = false`, `doc = false`, `bench = false` as the others.

Run: `cargo +nightly fuzz build dhcp6_message dhcp6_differential 2>&1 | tail -3` (skip with a ledger note if the nightly toolchain is absent locally; CI's fuzz job builds them)
Expected: builds, or the note.

- [ ] **Step 6: `make lint`** → exit 0 (check-deps.sh must list the crate as pure: add it to the script's pure-crate list if it enumerates them).
- [ ] **Step 7: Commit** `dhcp6: the wire codec of openfeo-proto-dhcp6 with its fuzz targets (SPEC §13)`

---

### Task 4: DHCPv6 client core and IAID derivation

**Files:**
- Create: `crates/openfeo-proto-dhcp6/src/client.rs`, `crates/openfeo-proto-dhcp6/src/iaid.rs`
- Modify: `crates/openfeo-proto-dhcp6/Cargo.toml` (dep `openfeo-proto-ndp` for `sha256::digest`; it is pure)
- Create: `fuzz/fuzz_targets/dhcp6_client.rs` (+ register)

**Interfaces:**
- Consumes: Task 3's `wire`.
- Produces, in `client`: `pub struct Config { pub duid: Vec<u8>, pub iaid_pd: u32, pub iaid_na: u32, pub pd_hint: u8 }`; `pub struct Lease6 { pub net: Ipv6Net, pub preferred: u32, pub valid: u32 }` (seconds from `bound_at`); `pub struct Binding { pub server: Vec<u8>, pub prefixes: Vec<Lease6>, pub addresses: Vec<Lease6>, pub t1: u32, pub t2: u32, pub dns: Vec<Ipv6Addr>, pub search: Vec<String>, pub bound_at: Timestamp }`; `pub enum Input { Start { binding: Option<Binding> }, Packet(Vec<u8>), Timeout, LinkUp, LinkDown }`; `pub enum Output { Send(Vec<u8>), Bound { binding: Binding, renewed: bool }, Gone(Vec<Ipv6Net>), Note(Note) }`; `pub enum Note { Soliciting, Requesting, Renewing, Rebinding, NoPrefixAvailable, NoAddressAvailable, Restarting(&'static str), Ignored(&'static str) }`; `pub enum State { Init, Soliciting, Requesting, Bound, Renewing, Rebinding }`; `pub struct Client` with `pub fn new(config: Config, seed: u64) -> Client`, `pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output>`, `pub fn next_timeout(&self) -> Option<Timestamp>`, `pub fn state(&self) -> State`, `pub fn binding(&self) -> Option<&Binding>`, `pub fn last_sent(&self) -> Option<MessageType>` (for the sandbox assertions). Constants: `SOL_TIMEOUT = 1_000`, `SOL_MAX_RT = 3_600_000`, `REQ_TIMEOUT = 1_000`, `REQ_MAX_RT = 30_000`, `REQ_MAX_RC = 10`, `REN_TIMEOUT = 10_000`, `REN_MAX_RT = 600_000`, `REB_TIMEOUT = 10_000`, `REB_MAX_RT = 600_000`, `CNF_TIMEOUT = 1_000`, `CNF_MAX_RT = 4_000`, `CNF_MAX_RD = 10_000` (ms; the last three time the Rebind after a link change, RFC 8415 §18.2.12), `MAX_PREFIXES = 8`, `MAX_ADDRESSES = 8`. With only the address bound, every Renew and Rebind carries an empty IA_PD with the hint, so a prefix is asked for again at each T1 (RFC 8415 §18.2.4).
- Produces, in `iaid`: `pub fn iaid(kind: &str, wan: &str) -> u32` = big-endian first four bytes of `sha256::digest(format!("{kind}:{wan}"))`; `pub const PD: &str = "pd"; pub const NA: &str = "na";`.
- `Gone(nets)` lists prefixes and addresses that left the binding since the last `Bound` (lifetime 0 in a Reply, missing from a Reply that renews the IA, valid lifetime expired, or NoBinding); a `Bound` that follows carries only what is live.

- [ ] **Step 1: Write the failing tests** (`client.rs` tests; build Replies with `wire::Message::encode`):
  - `start_solicits_with_pd_hint_na_oro_and_rapid_commit` (first Output is `Send` decoding to a Solicit with those options; `Note::Soliciting`; `next_timeout` within 900..=1100 ms)
  - `solicit_retransmits_with_doubling_capped_at_sol_max_rt`
  - `a_rapid_commit_reply_binds_at_once` (`Bound { renewed: false }` with prefixes, address, dns, search; state Bound; `next_timeout` at T1)
  - `an_advertise_then_request_then_reply_binds` (no Rapid Commit in the Advertise; the Request carries the Server ID)
  - `renew_at_t1_and_rebind_at_t2` (Renew unicast message with Server ID; at T2 a Rebind without it; `Note::Rebinding`)
  - `a_reply_that_replaces_the_prefix_reports_the_old_one_gone` (Review Focus 1)
  - `no_prefix_available_keeps_the_address_and_asks_again_at_renew` (Review Focus 3: `Bound` with the address and no prefix, `Note::NoPrefixAvailable` once, the Renew at T1 carries an IA_PD) and `no_prefix_and_no_address_keeps_soliciting_at_the_cap`
  - `no_binding_on_renew_restarts_with_request` and `unspec_fail_restarts_with_solicit`
  - `link_down_stops_timers_and_link_up_rebinds_the_binding` (after LinkUp the message is Rebind containing both IAs, retransmitted with Confirm's timing; ten seconds of silence keep the binding and its T1/T2 as they were)
  - `start_with_a_binding_rebinds_first`
  - `a_valid_lifetime_expiry_is_gone` (Timeout at `bound_at + valid` → `Gone`)
  - `a_server_id_mismatch_on_reply_is_ignored` (`Note::Ignored`)
  - `iaid_is_stable_and_differs_per_kind` (`iaid::iaid("pd","wan0") != iaid::iaid("na","wan0")`, equal across calls)
- [ ] **Step 2: Run** `cargo test -p openfeo-proto-dhcp6 client` → Expected: FAIL (module missing).
- [ ] **Step 3: Implement** `client.rs` and `iaid.rs` (retransmission per RFC 8415 §15 with ±10 % jitter from an xorshift on `seed`; Elapsed Time from the start of the current exchange in centiseconds capped at `u16::MAX`; T1/T2 defaults 0.5/0.8 of the shortest preferred lifetime when the IA says 0; Advertise ranked by the Preference option when present, else first; status handling per the design).
- [ ] **Step 4: Run** `cargo test -p openfeo-proto-dhcp6` → Expected: PASS.
- [ ] **Step 5: Fuzz target `dhcp6_client`**: arbitrary bytes split into a sequence of `Packet`s and `Timeout`s (first byte selects), `Start { binding: None }` first; assert no panic and `next_timeout().map_or(true, |t| t >= now)`.
- [ ] **Step 6: `make lint`** → exit 0. **Commit** `dhcp6: the client core: solicit, rapid commit, renew, rebind, status codes, link flap (SPEC §7.3)`

---

### Task 5: Stateless responder core

**Files:**
- Create: `crates/openfeo-proto-dhcp6/src/server.rs`; `fuzz/fuzz_targets/dhcp6_server.rs` (+ register)

**Interfaces:**
- Produces: `pub struct Config { pub duid: Vec<u8>, pub dns: Vec<Ipv6Addr>, pub domains: Vec<String>, pub refresh_secs: u32 }` with `pub const INFORMATION_REFRESH_TIME: u32 = 86_400;` and `pub fn reply(config: &Config, request: &[u8]) -> Option<Vec<u8>>`: `Some(Reply)` for an Information-Request (Server ID, the Client ID echoed when present, DNS servers, Domain list, Information Refresh Time), `None` for every other message type, a request that names another server, or undecodable bytes.

- [ ] **Step 1: Failing tests**: `an_information_request_gets_dns_domain_and_refresh_time`, `a_solicit_is_ignored`, `a_request_for_another_server_is_ignored`, `garbage_is_ignored`, `the_reply_keeps_the_xid`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Fuzz target `dhcp6_server`** (arbitrary bytes into `reply` with a fixed config; no panic).
- [ ] **Step 6: `make lint`; commit** `dhcp6: the stateless responder core (SPEC §7.3)`

---

### Task 6: World facts and reconcile `lan6`

**Files:**
- Create: `crates/openfeo-world/src/dhcp6.rs`; modify `crates/openfeo-world/src/lib.rs` (`pub mod dhcp6; pub use dhcp6::{WanDhcp6Fact, Lifetimed, Deprecated};`), `crates/openfeo-world/src/world.rs` (`pub dhcp6: Arc<BTreeMap<String, WanDhcp6Fact>>`, `pub ula: Option<Ipv6Net>`, both in `new`)
- Create: `crates/openfeo-reconcile/src/lan6.rs`; modify `crates/openfeo-reconcile/src/lib.rs` (`pub mod lan6;`), `crates/openfeo-reconcile/src/fixtures.rs` (`pd_world()`, `pd_world_with(…)` builders)

**Interfaces:**
- Produces (world): `pub struct Lifetimed { pub net: Ipv6Net, pub obtained_ms: u64, pub preferred_secs: u32, pub valid_secs: u32 }` (monotonic milliseconds), `pub struct Deprecated { pub net: Ipv6Net, pub until_ms: u64 }`, `pub struct WanDhcp6Fact { pub prefixes: Vec<Lifetimed>, pub addresses: Vec<Lifetimed>, pub deprecated: Vec<Deprecated>, pub dns: Vec<Ipv6Addr>, pub search: Vec<String>, pub server: Vec<u8> }` (all `Debug, Clone, PartialEq, Eq, Default`).
- Produces (reconcile `lan6`): `pub enum Source { Routed, Delegated { wan: String, parent: Ipv6Net }, Ula }`; `pub enum State { Static, Live { obtained_ms: u64, preferred_secs: u32, valid_secs: u32 }, Stale { obtained_ms: u64, valid_secs: u32 }, Deprecated { until_ms: u64 } }`; `pub struct LanPrefix { pub lan: String, pub ifname: String, pub net: Ipv6Net, pub router: Ipv6Addr, pub source: Source, pub state: State }`; `pub struct Lan6 { pub prefixes: Vec<LanPrefix>, pub loopback: Vec<Ipv6Addr>, pub pref_src: Option<Ipv6Addr>, pub left_out: Vec<(Ipv6Net, String)> }`; `pub fn prefixes(world: &World) -> Lan6`; `pub fn subnet(parent: Ipv6Net, index: u32) -> Option<Ipv6Net>`; `pub fn lan_index(lan: &Lan, position: usize) -> u32`; `pub fn ipv6_wan(world: &World) -> Option<&Wan>` (the WAN with `[wans.ipv6]` in mode auto whose port the map knows); `pub fn wan_usable(world: &World, wan: &Wan) -> bool` (carrier and an IPv6 default through it: the part 2 gate, moved here from `ra.rs`). All `Serialize` for snapshots.
- Rules: order per LAN: routed, delegated (per fact prefix in order), ULA, deprecated; a LAN with `ipv6 = "none"` has none; without `ipv6_wan` the result is empty; a single-/64 delegation goes to the lowest-index LAN whole with `router = <net>::1` and no loopback entry; `loopback` holds `<delegated>::1` per multi-/64 delegation and `<ula>::1`; `pref_src` is the routed prefix's `::1` (part 2) else the first delegation's loopback address; `left_out` names (delegation, lan) pairs whose index did not fit.

- [ ] **Step 1: Failing tests** in `lan6.rs`:
  - `subnet_places_the_index_below_the_prefix` (`subnet(2001:db8:100::/56, 1) == 2001:db8:100:1::/64`; index 256 → `None`; `subnet(fd12:3456:789a::/48, 2) == fd12:3456:789a:2::/64`)
  - `a_delegation_and_the_ula_give_every_lan_two_prefixes` (on `pd_world()`: lan0 index 1, lan1 index 2; routers `::1`; loopback has both; `pref_src` is `2001:db8:100::1`)
  - `a_routed_prefix_world_gains_only_the_ula` (Review Focus 5; `ipv6_world()` with `ula` set: the DMZ gets its routed /64 and a ULA /64; `pref_src` stays `2001:db8:1::1`)
  - `a_short_delegation_leaves_a_high_index_lan_out` (Review Focus 2; a /60 and `ipv6_index = 20`)
  - `a_single_64_goes_whole_to_the_lowest_index_lan`
  - `a_stale_wan_marks_delegated_prefixes_stale_and_leaves_the_ula_static`
  - `deprecated_prefixes_are_listed_last_with_their_deadline`
  - `ipv6_none_gets_nothing` and `no_ipv6_wan_gives_nothing`
  - `pd_world_lan6_snapshot` (insta)
- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile lan6` → FAIL.
- [ ] **Step 3: Implement** the world types, the fixtures (`pd_world()`: the Task 20 fixture's TOML as a string constant here, link facts for p0, br-lan0, br-lan1 with carrier, an IPv6 default through p0, `ula = Some(fd12:3456:789a::/48)`, a `WanDhcp6Fact` with prefix `2001:db8:100::/56` obtained at 10_000 ms, preferred 40, valid 60, address `2001:db8:ffff::1a4/128`, dns `[2001:db8:ffff::1]`, search `["isp.example"]`), and `lan6.rs`.
- [ ] **Step 4: Run** `cargo test -p openfeo-reconcile lan6 && cargo test -p openfeo-world` → PASS (accept the new snapshot with `cargo insta accept` after reading it).
- [ ] **Step 5: `make lint`; commit** `world, reconcile: the DHCPv6 fact, the ULA, and lan6::prefixes (SPEC §7.3)`

---

### Task 7: Identity: DUID, secret and ULA loaders

**Files:**
- Create: `crates/openfeo/src/identity.rs` (move `load_or_create_duid`, `DUID_PATH`, `hex` from `dhcp4.rs`; move `load_or_create_ipv6_secret`, `random_secret`, `IPV6_SECRET_PATH` from `ipv6.rs`; add `ULA_PATH = "/state/identity/ula"`, `pub fn load_or_create_ula(path: &Path) -> io::Result<(Ipv6Net, bool)>`, `pub fn ula_line(net: Ipv6Net, created: bool) -> String` = `identity: ula fd12:3456:789a::/48 (created|loaded)`)
- Modify: `crates/openfeo/src/{dhcp4.rs, ipv6.rs, router.rs, main.rs}` (imports; `router.rs` loads the ULA after the secret and sets `world.ula` in the first `publisher.update`)

- [ ] **Step 1: Failing tests** in `identity.rs`: `a_new_ula_is_fd00_8_with_48_bits_and_is_kept` (file round trip; `net.prefix_len() == 48`; first byte `0xfd`; second call returns `(same, false)`), `a_corrupt_ula_file_is_replaced_and_reported` (returns `created == true`), `ula_line_follows_the_contract`.
- [ ] **Step 2: Run** `cargo test -p openfeo identity` → FAIL. **Step 3: Implement** (random bytes from `random_secret`'s source; mode `STATE_FILE_MODE`; atomic write). **Step 4: Run** `cargo test -p openfeo` → PASS (moved functions keep their tests).
- [ ] **Step 5: `make lint`; commit** `identity: the ULA /48 beside the DUID and the secret (SPEC §5.2)`

---

### Task 8: Netlink policy rules and unreachable routes

**Files:**
- Modify: `crates/openfeo-netlink/src/types.rs` (`RouteKind::Unreachable`; `pub enum RuleAction { ToTable(u32), Unreachable }`; `pub struct Rule { pub v6: bool, pub priority: u32, pub src: Option<IpNet>, pub action: RuleAction, pub suppress_prefixlen: Option<u8>, pub protocol: u8 }` (`Ord`, `Hash`); `Cache.rules: BTreeSet<Rule>`; `pub const RULE_PRIORITY_MAIN_SUPPRESS: u32 = 1500; pub const RULE_PRIORITY_SOURCE: u32 = 2000;`)
- Modify: `crates/openfeo-netlink/src/monitor.rs` (join `RTNLGRP_IPV6_RULE` and `RTNLGRP_IPV4_RULE`; dump rules at start; `apply_rule`, `rule_from` reading `RuleAttribute::{Source, Table, Priority, SuppressPrefixLen, Protocol}` and `header.action`), `crates/openfeo-netlink/src/apply.rs` (`pub async fn rule_add(&self, rule: &Rule)`, `pub async fn rule_del(&self, rule: &Rule)`, `route_message` emitting `RouteType::Unreachable` with no oif for `RouteKind::Unreachable`; `describe` says `unreachable default …`; `pub fn describe_rule(rule: &Rule) -> String` = `rule 2000 from 2001:db8:100::/56 lookup 100 proto 200` / `… unreachable` / `rule 1500 from all lookup main suppress_prefixlength 0`)
- Modify: `crates/openfeo-netlink/src/lib.rs` exports
- Test: `harness/tests/netlink.rs` (sandbox scenarios)

**Interfaces:**
- Produces: the types above and `Netlink::{rule_add, rule_del}`; `Cache.rules`.

- [ ] **Step 1: Failing sandbox scenarios** in `harness/tests/netlink.rs` after the existing route scenarios' shape (a dummy link in the sandbox namespace): `a_suppress_main_rule_and_a_source_rule_are_added_dumped_and_removed` (add rule 1500 suppress 0 and rule 2000 from `2001:db8:100::/56` to table 100, both proto 200; the cache shows both with every field; `ip -6 rule` text contains `suppress_prefixlength 0` and `lookup 100`; delete both; cache empty of proto-200 rules), `an_unreachable_rule_answers_with_no_route` (rule 2000 from `2001:db8:200::/56` unreachable; `ip -6 route get 2001:db8:ffff::1 from 2001:db8:200::1 iif <dummy>` reports `unreachable`), `an_unreachable_default_in_table_100_is_added_and_dumped` (`RouteKind::Unreachable`, table 100, proto 200; cache has it; `ip -6 route show table 100` says `unreachable default`), `a_rule_added_behind_the_monitors_back_is_cached` (added with `ip -6 rule add … protocol 200`, seen in the cache within a second).
- [ ] **Step 2: Run** `make test-harness FILTER=rule` → FAIL to compile.
- [ ] **Step 3: Implement** in the netlink crate (rtnetlink 0.23's `handle.rule().add()`/`.del()` with `RuleMessage` attributes; `FRA_PROTOCOL` via `RuleAttribute::Protocol`; the monitor's initial dump via `handle.rule().get(IpVersion::V6)` and V4).
- [ ] **Step 4: Run** `make test-harness FILTER=netlink` → PASS (the four new ones plus every existing netlink scenario). Also `cargo test -p openfeo-netlink`.
- [ ] **Step 5: `make lint`; commit** `netlink: policy rules with suppress_prefixlength and unreachable, unreachable routes (SPEC §7.4)`

---

### Task 9: Routing reconciler and applier: tables, rules, prefixes

**Files:**
- Modify: `crates/openfeo-reconcile/src/routing.rs` (`DesiredRule { v6: bool, priority: u32, src: Option<IpNet>, action: DesiredRuleAction, suppress_prefixlen: Option<u8> }`, `DesiredRuleAction { ToTable(u32), Unreachable }`, `DesiredRouting.rules: BTreeSet<DesiredRule>`, `RouteKind::Unreachable`; `pub fn wan_table(index: usize) -> u32` = `100 + index`; the IPv6 part rewritten over `lan6::prefixes`: bridge `::1/64` addresses for every listed prefix (deprecated included), `lo` addresses from `Lan6.loopback` (routed `::1/128` as before), the default's `pref_src` from `Lan6.pref_src`, the WAN table's default or unreachable default, rules per the design, a blackhole per delegated prefix (the fact's `prefixes` and `deprecated` both), IA_NA addresses on the port as `/128`… use the fact's `net` as given (Kea hands `/128`), `ipv6_owned` unchanged)
- Modify: `crates/openfeo-apply/src/routing.rs` (rules diffed by protocol 200 after routes: add missing, delete unwanted; `Report` counts them)
- Test: snapshots `routing` on `pd_world()`; unit tests

- [ ] **Step 1: Failing tests** in `routing.rs`: `pd_world_installs_the_wan_table_rules_and_lan_addresses` (expect: rule 1500 suppress; rule 2000 from `2001:db8:100::/56` → table 100; a default in table 100 via `fe80::1` dev p0 with pref_src `2001:db8:100::1`; `2001:db8:100::1/128` and `fd12:3456:789a::1/128` on `lo`; `2001:db8:100:1::1/64` and `fd12:3456:789a:1::1/64` on br-lan0, `…:2::1/64` twins on br-lan1; `2001:db8:ffff::1a4/128` on p0; a blackhole `2001:db8:100::/56`), `a_deprecated_prefix_gets_an_unreachable_rule_and_keeps_its_bridge_address`, `a_wan_without_an_ipv6_default_gets_an_unreachable_default_in_its_table`, `a_routed_prefix_world_has_no_rules_beyond_suppress` (part 2 world + ULA: the 1500 rule and the ULA addresses only; the existing part 2 assertions unchanged), `pd_world_routing_snapshot`.
- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile routing` → FAIL. **Step 3: Implement** reconciler and applier. **Step 4: Run** `cargo test -p openfeo-reconcile && cargo test -p openfeo-apply` → PASS; existing routing snapshots unchanged except `ipv6_world_*` gaining the ULA lines and the 1500 rule (read each accepted diff).
- [ ] **Step 5: `make lint`; commit** `routing: the WAN's IPv6 table, source rules, deprecation rules and per-LAN prefixes from lan6 (SPEC §7.4)`

---

### Task 10: RA server: many prefixes, lifetimes by state, O flag, ULA route

**Files:**
- Modify: `crates/openfeo-proto-ndp/src/server.rs` (`Config` becomes `{ prefixes: Vec<Pio>, mac, rdnss: Vec<Ipv6Addr>, mtu, domain, router_lifetime, other: bool, routes: Vec<Rio> }` with `pub struct Pio { pub prefix: Ipv6Net, pub valid: u32, pub preferred: u32 }` and `pub struct Rio { pub prefix: Ipv6Net, pub lifetime: u32, pub preference: Preference }`; the advertisement carries one PIO per entry, RDNSS with every address, O from `other`, one RIO per route; `PIO_VALID`/`PIO_PREFERRED` stay as the constants callers use)
- Modify: `crates/openfeo-reconcile/src/ra.rs` (`DesiredRa { ifname, wan, lan, prefixes: Vec<DesiredPio>, rdnss: Vec<Ipv6Addr>, mac, mtu, domain, router_lifetime, other: bool, routes: Vec<Ipv6Net> }` (the ULA /48 and every live delegated prefix, RFC 7084 L-3), `DesiredPio { prefix: Ipv6Net, source: lan6::Source, lifetimes: PioLifetimes }`, `PioLifetimes { Static, FromDelegation { obtained_ms, preferred_secs, valid_secs }, Stale { obtained_ms, valid_secs }, Deprecated { until_ms } }`; `desired` over `lan6::prefixes`: every LAN with at least one prefix and `ra != Some(false)`; `other = true`; RDNSS = the LAN's router addresses ULA first; `routes` = the ULA /48 then the live delegated prefixes; router lifetime per part 2's gate through `lan6::wan_usable`)
- Create: `crates/openfeo-runtime/src/clock.rs` (`pub fn uptime_ms() -> u64`: milliseconds since the first call, from one `OnceLock<Instant>`; `pub mod clock;` in `lib.rs`)
- Modify: `crates/openfeo/src/ra.rs` (`server_config(ra, mac, now_ms)` with `now_ms = openfeo_runtime::clock::uptime_ms()` maps `PioLifetimes` to seconds: Static → 2592000/604800; FromDelegation → `min(remaining, cap)` each, 0 when lapsed; Stale → preferred 0, valid `min(remaining valid, 7200)`; Deprecated → preferred 0, valid the seconds left to `until_ms`, counting down at every advertisement (RFC 7084 L-13); the task re-sends `Configure` on every `DesiredRa` change as today; #28: a LAN whose watch is set to `None` is awaited to finish and removed, and `run` aborts every handle on its own exit; console lines: `ra br-lan0 advertising 2001:db8:100:1::/64 (wan0 delegation), fd12:3456:789a:1::/64 (ula) lifetime 1800` and `ra br-lan0 deprecating 2001:db8:100:1::/64`)
- Test: `ra` snapshot on `pd_world()`; server core unit tests; `crates/openfeo/src/ra.rs` contract tests
- Modify: `harness/tests/ndp.rs` only to adapt `server_config` to the new `Config` shape (same behaviour)

- [ ] **Step 1: Failing tests**: in `server.rs`: `an_advertisement_carries_every_prefix_rdnss_the_o_flag_and_the_ula_route` (decode the bytes with `wire::Message::decode`; two PIOs with their lifetimes; `other == true`; RDNSS two addresses; two RIOs, the /48 and the /56, medium, 1800); in `reconcile/ra.rs`: `pd_world_advertises_delegated_and_ula_prefixes_with_o_set`, `a_stale_delegation_is_advertised_deprecated_while_the_ula_stays_static`, `rdnss_puts_the_ula_address_first`, `routes_name_the_ula_and_every_live_delegation`, `pd_world_ra_snapshot`; in `crates/openfeo/src/ra.rs`: `delegation_lifetimes_are_remainders_capped_and_never_negative`, `a_deprecated_prefix_counts_down_to_its_deadline` and the line contract tests.
- [ ] **Step 2: Run** `cargo test -p openfeo-proto-ndp server && cargo test -p openfeo-reconcile ra && cargo test -p openfeo ra` → FAIL.
- [ ] **Step 3: Implement.** **Step 4: Run** the three plus `cargo test -p openfeo-proto-ndp` (fuzz-adjacent unit tests) → PASS; `ipv6_world_ra_snapshot` changes only by the ULA PIO, `other: true`, the RDNSS list and the RIO (read the diff).
- [ ] **Step 5: `make lint`; commit** `ra: every LAN prefix with lifetimes by state, O = 1, the ULA route, and the task aborts its LAN handles (SPEC §7.3; closes #28)`

---

### Task 11: DHCPv6 UDP drivers and the NDP first-send patience (#34)

**Files:**
- Create: `crates/openfeo-net/src/dhcp6.rs` (`pub struct ClientSocket` with `pub fn open(ifindex: u32, ifname: &str) -> Result<Self, DriverError>` (UDP, `[::]:546`, `SO_REUSEADDR`, `SO_BINDTODEVICE`, `IPV6_V6ONLY`, `join_multicast_v6(ff02::1:2, ifindex)`, `IPV6_MULTICAST_IF` via `std`'s `set_multicast_if_v6`? no: the destination's scope id selects the interface), `pub async fn recv(&self, buf: &mut [u8]) -> Result<(Ipv6Addr, usize), DriverError>`, `pub fn send(&self, bytes: &[u8]) -> Result<(), DriverError>` to `[ff02::1:2%ifindex]:547`, `pub fn send_to(&self, to: Ipv6Addr, bytes)` for unicast Renew; `pub struct ServerSocket` with `open(ifindex, ifname)` on 547 joined to the group, `recv -> (SocketAddrV6, usize)`, `send_to(SocketAddrV6, bytes)`); built on `bound::bound_socket` plus the standard library's `UdpSocket::join_multicast_v6` after `from(fd)`
- Modify: `crates/openfeo-net/src/lib.rs` (`pub mod dhcp6;`)
- Modify: `crates/openfeo-net/src/ndp.rs` and `crates/openfeo/src/ipv6.rs` + `ra.rs` for #34: a send that fails with `EADDRNOTAVAIL` is retried after 1 s by the task (a `retry_at` timer in the task loop) up to five times, logged once at debug, not as a warning, because the link-local is tentative for about a second after link-up (RFC 4862 DAD)
- Test: `crates/openfeo-net/src/dhcp6.rs` unit test `open_fails_without_the_interface` (ifindex 0 → error, no panic); the behaviour is proven by the sandbox suite of Task 18

- [ ] **Step 1: Failing test**: the unit test above and, in `crates/openfeo/src/ipv6.rs`, `eaddrnotavail_schedules_a_retry_instead_of_a_warning` on the helper that decides (`pub(crate) fn send_retry(err: &DriverError) -> Option<Duration>`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `cargo test -p openfeo-net && cargo test -p openfeo` → PASS.
- [ ] **Step 5: `make lint`; commit** `net: DHCPv6 client and responder sockets; NDP waits out a tentative link-local (closes #34)`

---

### Task 12: The WAN DHCPv6 task

**Files:**
- Create: `crates/openfeo/src/dhcp6.rs`: `pub fn spawn_all(supervisor, publisher, world_rx)` for every WAN with `[wans.ipv6]` auto and empty `prefix`; task `run`: `wait_for_link`, DUID via `identity::load_or_create_duid`, `Client::new(Config { duid, iaid_pd: iaid(PD, wan), iaid_na: iaid(NA, wan), pd_hint })`, `ClientSocket::open`, `Input::Start { binding: read_binding(path, wan, mac) }`, the select loop of `ipv6.rs` (socket, timer, world carrier changes, deprecation timer, two-hour down timer); on `Bound` write `leases/dhcp6-<wan>.toml` through `state::write` and publish the fact (prefixes and addresses as `Lifetimed` with `obtained_ms` from the driver's `bound_at` on the process clock); on `Gone` move the nets to `deprecated` with `until_ms = now_ms + min(7200 s, the prefix's remaining valid lifetime)` (RFC 7084 L-13); purge on deadline; on two hours without carrier drop the binding into deprecation; `pub fn fact_from(binding: &Binding, deprecated: &[Deprecated]) -> WanDhcp6Fact`; `pub fn binding_file(wan, mac, &Binding, deprecated, now_unix, now_ms) -> Dhcp6Lease` (wall-clock seconds for the file, the deprecated deadlines included) and `pub fn binding_from_file(&Dhcp6Lease, wan, mac, now_unix, now_ms) -> Option<(Binding, Vec<Deprecated>)>` (None when lapsed or foreign; a file obtained after `now_unix`, the clock having gone backwards on an RTC-less board, is counted from now and left to the Rebind); console lines (contract tests): `dhcp6 wan0 soliciting`, `dhcp6 wan0 bound prefix 2001:db8:100::/56 (preferred 40 s, valid 60 s) address 2001:db8:ffff::1a4 from 00030001…`, `dhcp6 wan0 renewed`, `dhcp6 wan0 rebinding`, `dhcp6 wan0 prefix 2001:db8:100::/56 gone: deprecated for 55 s`, `dhcp6 wan0 no prefix available`, `dhcp6 wan0 no address available`, `dhcp6 wan0 binding restored from disk`, `dhcp6 wan0 resolvers 2001:db8:ffff::1 search isp.example`
- Modify: `crates/openfeo/src/router.rs` spawns `dhcp6::spawn_all`
- Test: `crates/openfeo/src/dhcp6.rs` tests: `fact_from_carries_lifetimes_relative_to_obtained`, `binding_file_round_trips_with_its_deprecated_list`, `a_lapsed_or_foreign_binding_is_ignored`, `a_future_binding_is_counted_from_now`, `a_gone_prefix_is_deprecated_for_the_lower_of_two_hours_and_its_remaining_valid_lifetime`, `carrier_loss_keeps_the_deprecated_list` (Review Focus 4, on the pure state helper `Deprecations { list, deadline }`), `lines_follow_the_contract`

- [ ] **Step 1: Failing tests** above. **Step 2: Run** `cargo test -p openfeo dhcp6` → FAIL. **Step 3: Implement.** **Step 4: Run** `cargo test -p openfeo` → PASS.
- [ ] **Step 5: `make lint`; commit** `dhcp6: the WAN client task: facts, the persisted binding, deprecation and the console (SPEC §7.3)`

---

### Task 13: The stateless responder task

**Files:**
- Create: `crates/openfeo-reconcile/src/dhcp6_server.rs` (`pub struct DesiredResponder { pub ifname: String, pub lan: String, pub dns: Vec<Ipv6Addr>, pub domain: String }`, `pub fn desired(world: &World) -> Vec<DesiredResponder>`: every LAN `reconcile::ra::desired` advertises, DNS = the LAN's router addresses ULA first), `crates/openfeo/src/dhcp6_server.rs` (one task per LAN after `ra.rs`'s watch pattern; DUID from identity; `server::reply`; line `dhcp6-server br-lan0 serving fd12:3456:789a:1::1 home.arpa`)
- Modify: `crates/openfeo-reconcile/src/lib.rs`, `crates/openfeo/src/router.rs`

- [ ] **Step 1: Failing tests**: `reconcile/dhcp6_server.rs`: `every_advertising_lan_gets_a_responder_with_the_ula_address_first`, `pd_world_dhcp6_server_snapshot`; `crates/openfeo/src/dhcp6_server.rs`: `lines_follow_the_contract`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `cargo test -p openfeo-reconcile dhcp6_server && cargo test -p openfeo dhcp6_server` → PASS.
- [ ] **Step 5: `make lint`; commit** `dhcp6: the stateless responder on every advertising LAN (SPEC §7.3)`

---

### Task 14: Firewall: ULA stays inside, DHCPv6 ports, ULA rule targets

**Files:**
- Modify: `crates/openfeo-reconcile/src/nft.rs` (forward chain: before the zone policy, `ip6 saddr fc00::/7 oifname @wan_if reject with icmpv6 type no-route` and the `daddr` twin; input chain: `iifname @wan_if ip6 saddr fc00::/7 drop` first among the WAN rules, `iifname @wan_if udp dport 546 accept`; `LAN_UDP_SERVICES` gains 547 for the private set and a `service_rule("lan_pub_ra_if", Some(ipv6_only()), "udp", json!(547))`; rule targets inside `fc00::/7` are placed by `lan6::prefixes` (the LAN whose ULA /64 contains the target), unplaced ones skipped with a `DesiredNft.notes` line `rule dmz-ula: fd12::… is in no LAN's ULA /64; skipped`)
- Test: `nft.rs` tests + snapshots; `harness/tests/nft.rs` sandbox: `ula_toward_the_wan_is_rejected_with_no_route` (apply the pd ruleset in the sandbox namespace with dummy `p0` and `br-lan0`; a packet from `fd12:3456:789a:1::10` out of `p0`… use the nft sandbox's existing probe shape: `nft list ruleset` contains both ULA rules and the 546/547 rules; the applier applies once then noops)

- [ ] **Step 1: Failing tests**: `ula_never_crosses_a_wan`, `the_wan_accepts_dhcpv6_replies_on_546`, `advertising_lans_serve_547`, `a_ula_rule_target_is_placed_on_its_lan`, `pd_world_ruleset_snapshot`; the sandbox scenario above.
- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile nft` → FAIL. **Step 3: Implement.** **Step 4: Run** `cargo test -p openfeo-reconcile && make test-harness FILTER=nft` → PASS (locally the nft sandbox may skip for missing modules: ledger it; CI runs it).
- [ ] **Step 5: `make lint`; commit** `nft: ULA never crosses a WAN, DHCPv6 on 546 and 547, ULA rule targets (SPEC §7.5)`

---

### Task 15: DNS: DHCPv6 resolvers, every LAN address

**Files:**
- Modify: `crates/openfeo-reconcile/src/dns.rs` (`wan_dns`: the `dhcp6` fact's `dns` joins under the same gate as RDNSS; `router_addrs` and the reverse zones from `lan6::prefixes` (routed, delegated, loopback, ULA last; deprecated excluded); `DesiredListener.address6: Vec<Ipv6Addr>` (was `Option`), every router address of the LAN; `learned_from` origin text `dhcp6` beside `rdnss` for the console line of `crates/openfeo/src/dns.rs` (`learned from wan0 dhcp6`))
- Modify: `crates/openfeo/src/dns.rs` (one `Listener` per IPv6 address; rebinding as the set changes is already how listeners are rebuilt on a `DesiredDns` change)
- Test: `dns.rs` tests + `pd_world` snapshot; `crates/openfeo/src/dns.rs` line tests

- [ ] **Step 1: Failing tests**: `dhcp6_resolvers_join_behind_the_ipv6_route`, `the_router_answers_aaaa_for_delegated_and_ula_addresses_and_not_deprecated_ones`, `every_lan_address_is_a_listener`, `pd_world_dns_snapshot`, `upstream_line_names_dhcp6`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `cargo test -p openfeo-reconcile dns && cargo test -p openfeo dns` → PASS.
- [ ] **Step 5: `make lint`; commit** `dns: DHCPv6-learned resolvers under the route gate; AAAA and listeners for every LAN address (SPEC §7.7)`

---

### Task 16: Sysctl and links follow-ups (#29, #31) and the router tie-break (#26)

**Files:**
- Modify: `crates/openfeo-reconcile/src/sysctl.rs` (#29: the WAN's IPv6 `mtu` entry is the link MTU when the fact carries none)
- Modify: `crates/openfeo-apply/src/links.rs` (#31: `accept_ra = 0`, `autoconf = 0` written with the stable-privacy writes before link-up for a WAN port with `[wans.ipv6]`; `DesiredLinks` already knows which ports those are via the secret path: extend the same spot)
- Modify: `crates/openfeo-proto-ndp/src/client.rs` (#26: `max_by_key((preference, seen))` becomes: keep the current router while a newcomer's preference is not higher; a refresh of the current router does not change the choice)
- Test: existing test modules

- [ ] **Step 1: Failing tests**: `sysctl.rs`: `the_ipv6_mtu_falls_back_to_the_link_mtu_when_no_advertisement_carries_one` (the `fact.mtu = None` case asserts the link MTU instead of absence); `links.rs` (apply crate unit test on the pure helper that lists the pre-up writes): `a_wan_with_ipv6_gets_accept_ra_and_autoconf_off_before_up`; `client.rs`: `an_equal_preference_newcomer_does_not_displace_the_current_router` and `a_higher_preference_newcomer_does`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `cargo test -p openfeo-reconcile sysctl && cargo test -p openfeo-apply && cargo test -p openfeo-proto-ndp` → PASS (update the sysctl snapshot if it changes; read the diff).
- [ ] **Step 5: `make lint`; commit** `ipv6: the WAN's knobs land before link-up, the MTU knob is restored, the router tie-break holds (closes #26, #29, #31)`

---

### Task 17: Lab: Kea DHCPv6, udhcpc6, check-env, CI and cloud

**Files:**
- Create: `harness/fixtures/kea-dhcp6.json.tmpl` (`Dhcp6`: `interfaces-config.interfaces ["{{IFACE}}"]`, `lease-database memfile persist false`, `renew-timer 10`, `rebind-timer 16`, `preferred-lifetime 40`, `valid-lifetime 60`, `rapid-commit true`, `subnet6 [{ id 1, subnet "2001:db8:ffff::/64", interface "{{IFACE}}", pools [{ pool "2001:db8:ffff::100 - 2001:db8:ffff::1ff" }], pd-pools [{ prefix "{{PD_PREFIX}}", prefix-len {{PD_LEN}}, delegated-len 56 }], option-data [{ name "dns-servers", data "2001:db8:ffff::1" }, { name "domain-search", data "isp.example" }] }]`)
- Modify: `harness/src/daemons.rs` (`pub struct Kea6Config { pub iface: String, pub pd_pool: Option<Ipv6Net>, pub long_lived: bool }` (`long_lived` renders T1 10, T2 16, preferred 400, valid 600 for the reboot scenario, through `{{RENEW}}`, `{{REBIND}}`, `{{PREFERRED}}`, `{{VALID}}` placeholders; the default is 10/16/40/60), `pub fn render_kea_dhcp6(config: &Kea6Config) -> String` (a `None` pool renders no `pd-pools`), `pub fn kea_dhcp6(ns, config, run_dir) -> Result<Daemon>` (`kea-dhcp6 -c`, env as the v4 one; ready on `DHCP6_STARTED`))
- Modify: `harness/src/lab.rs` (`pub const PD_POOL_A: &str = "2001:db8:100::/48"; pub const PD_POOL_B: &str = "2001:db8:200::/48";` `pub fn start_kea6(&mut self, config: &Kea6Config) -> Result<()>` on `wan0` (requires `start_radvd` first for the ISP's addresses; daemon name `kea-dhcp6`), `pub fn stop_kea6(&mut self) -> bool`, `pub fn restart_kea6(&mut self, config: &Kea6Config) -> Result<()>`, and `Kea6Config::isp(pool: Option<&str>) -> Kea6Config` for the usual short-lived one on `wan0`)
- Modify: `harness/src/lanclient.rs` (`pub struct Udhcpc6Info { pub dns: Vec<String>, pub search: Vec<String> }`, `pub fn udhcpc6_info(ns: &NetNs, ifname: &str, timeout: Duration) -> Result<Udhcpc6Info>`: `busybox udhcpc6 -f -q -n -l -i <if> -O dns -O search -s <script>` with a script that prints `dns=$dns` and `search=$search` on `bound`/`informed` events (udhcpc6's event for `-l` is `bound`); parse)
- Modify: `harness/src/main.rs` (`kea-dhcp6` in the bin list; `busybox udhcpc6 applet` via `busybox --list`; `kea-dhcp6 reads our config` with `kea-dhcp6 -t` and the AppArmor hint naming `usr.sbin.kea-dhcp6`)
- Modify: `.github/workflows/ci.yml` (`kea-dhcp6-server` in the apt line; `sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.kea-dhcp6 || true`), `scripts/cloud-setup.sh` (same package and unconfine), `CLAUDE.md` Harness paragraph (kea-dhcp6 and udhcpc6 named), `Makefile` (`--test dhcp6 --test m2pd` in `test-harness`), `harness/Cargo.toml` (`[[test]]` entries `dhcp6` and `m2pd`, `harness = false`)
- Test: `harness/src/daemons.rs` unit test `kea6_template_renders_the_pool_and_omits_it_when_none`; `make check-env` shows the new lines

- [ ] **Step 1: Failing test** `kea6_template_renders_the_pool_and_omits_it_when_none` (and the long-lived lifetimes when asked). **Step 2: Run** `cargo test -p openfeo-harness kea6` → FAIL. **Step 3: Implement** everything listed. **Step 4: Run** `cargo test -p openfeo-harness && make check-env` → PASS; check-env reports `kea-dhcp6 ok`, `busybox udhcpc6 applet ok`, `kea-dhcp6 reads our config ok` (the local Kea 3.x must accept the template; if it refuses a knob, change the template until both 3.x and the 2.4.1 of the container probe accept it: `docker run --rm -v <tmpl dir>:/t ubuntu:24.04 sh -c 'apt-get update -qq && apt-get install -qq -y kea-dhcp6-server >/dev/null && kea-dhcp6 -t /t/kea-dhcp6.json'`).
- [ ] **Step 5: `make lint`; commit** `harness: Kea's DHCPv6 server, udhcpc6, check-env, CI and cloud packages (SPEC §11)`

---

### Task 18: Sandbox `dhcp6` suite

**Files:**
- Create: `harness/tests/dhcp6.rs` after `harness/tests/dhcp4.rs`: veth `d60`/`d61`, the far end in a namespace with `2001:db8:ffff::1/64` and `fe80::1/64` (nodad) and Kea6 on it; the near end's driver is `ClientSocket` plus the `client::Client` core run by a small async loop in the test (the task's loop is in `crates/openfeo`, so the suite drives the core itself, as `ndp.rs` does); scenarios:
  - `client_binds_a_prefix_an_address_and_the_resolvers_from_kea` (Bound within 10 s; prefix inside `PD_POOL_A` with length 56; address in the pool; dns `2001:db8:ffff::1`; search `isp.example`; Kea's log has `DHCP6_PD_LEASE_ALLOC` or `DHCP6_LEASE_ALLOC`)
  - `client_renews_at_t1` (a second `Bound { renewed: true }` within 16 s; `last_sent() == Some(Renew)`)
  - `a_restarted_server_with_another_pool_replaces_the_prefix_and_deprecates_the_old` (restart Kea with `PD_POOL_B`; within 20 s `Gone([old])` and `Bound` with a prefix in pool B)
  - `a_link_flap_rebinds_instead_of_soliciting` (`LinkDown`, `LinkUp` → `last_sent() == Some(Rebind)`; `Bound { renewed: true }`)
  - `a_persisted_binding_is_rebound_at_start` (`Start { binding: Some(previous) }` → first message Rebind; Bound keeps the prefix)
  - `a_server_with_no_pd_pool_yields_no_prefix_and_keeps_the_address` (`Note::NoPrefixAvailable`; address bound)
  - `the_responder_answers_udhcpc6_with_the_resolver_and_the_search_list` (`ServerSocket` on `d60` with `server::Config { dns: [fd12:3456:789a:1::1], domains: ["home.arpa"] }`; `udhcpc6_info` in the far namespace on `d61` returns them)

- [ ] **Step 1: Write the suite** (every scenario fails first because the rig does not exist; the first run proves the file compiles and the scenarios run).
- [ ] **Step 2: Run** `make test-harness FILTER=dhcp6` → all seven PASS (local Kea 3.x). Expected output ends with `7 passed`.
- [ ] **Step 3: `make lint`; commit** `harness: the dhcp6 sandbox suite against Kea and udhcpc6 (SPEC §11)`

---

### Task 19: Fixture and QEMU scenarios

**Files:**
- Create: `harness/fixtures/vm-pd.toml` (the design's fixture: DHCPv4 WAN on p0 with `[wans.ipv6] pd_hint = 56`, `lan0` p2 `192.168.1.1/24` index 1 reaches `["wan", "lan1"]` with DHCP, `lan1` p3 `192.168.2.1/24` index 2 reaches `["wan", "lan0"]`, `dns.upstreams = []`)
- Create: `harness/tests/m2pd.rs` (`boot_pd(lab, pool)`: `add_lan1`, `start_radvd(RadvdConfig::isp("wan0")` with M and O flags on: `RadvdConfig` gains `managed: bool, other: bool` rendered as `AdvManagedFlag`/`AdvOtherConfigFlag`), `start_kea6(&Kea6Config::isp(Some(pool)))`, `start_dnsmasq`, `start_kea` (DHCPv4), `with_config(VM_PD)`, `boot("")`, `isp_route_block6(pool, link_local)` for both pools; the seven scenarios of the design with these assertions:
  - `a_lan_client_gets_a_gua_from_the_delegation_and_reaches_the_isp`: console `dhcp6 wan0 bound prefix (2001:db8:100:[0-9a-f:]*/56)`; lan0 host has an address in `<prefix index 1>` and in `fd..:1::/64`; fetches `http://[2001:db8:ffff::1]/`; `rdisc6` shows `Stateful other conf.* Yes` and the ULA router address as RDNSS; `isp0` pings the IA_NA address from the console line
  - `the_isp_changes_the_prefix_and_the_lan_is_renumbered_within_ten_seconds`: `restart_kea6(Some(PD_POOL_B))`; wait for the new `bound prefix (2001:db8:200…)` line; within 10 s the host has an address in the new /64 and `ip -6 addr` marks the old one `deprecated`; `ping -6 -c1 -W2 -I <old addr> 2001:db8:ffff::1` output contains `Destination unreachable`; console has `gone: deprecated for`; once the old prefix's remaining valid lifetime has run out (at most 60 s, Kea's valid lifetime, which is the deadline in the lab) the old /64 is absent from `rdisc6` output and from the host, and the console shows the router dropping it
  - `wan_ipv6_loss_deprecates_the_delegated_prefix_and_carrier_back_rebinds_it`: QMP `set_link` off on the WAN NIC; within 8 s no default route on the host and the delegated address deprecated while the ULA one is not; link on; console `dhcp6 wan0 rebinding` then `bound` with the same prefix; the delegated address preferred again
  - `ula_addresses_reach_the_other_lan_and_never_leave_the_wan`: lan1 host pings lan0 host's ULA address; `ping -6 -I <ula addr> 2001:db8:ffff::1` from lan0 gets `Destination unreachable` (the router's no-route) and `isp0`'s tcpdump-free check: dnsmasq's log or an `isp0` listener never sees a ULA source (use a UDP listener in `isp0` and a `nc`-free Rust UDP send… simpler: `ping` exit status and the reject text); a packet from `isp0` with a ULA source to the router's IA_NA address is not answered (`ping -I fd12::1`-style address added to isp0's wan0)
  - `stateless_dhcpv6_hands_out_the_resolver_and_the_search_list`: `udhcpc6_info` on lan0 → dns is the router's ULA address, search `home.arpa`; console `dhcp6-server br-lan0 serving`
  - `a_rebooted_router_keeps_its_delegation`: Kea started long-lived (`Kea6Config { long_lived: true, .. }`, valid 600 s, so a reboot under TCG cannot outlast the binding); `lab.with_state` from the first boot's state disk or reboot through QMP `system_reset`; console `binding restored from disk` and `rebinding`; the prefix line matches the first; the host's delegated address never shows `deprecated` during the reboot (poll)
  - `isp_resolvers_learned_over_dhcpv6_join_after_the_route`: `dig AAAA www.isp.example` at the router's ULA address from lan0 answers; console `dns upstreams … learned from wan0 dhcp6` after the IPv6 default line
- Modify: `harness/tests/m2.rs`: `lan_client_configures_itself_from_the_lan_prefix_and_reaches_the_isp_over_ipv6` also asserts a `fd` address on the host and `Stateful other conf.* Yes`; `dmz_host_ipv6_is_reached_from_the_isp_only_through_a_rule` keeps asserting no advertisements on the DMZ
- Modify: `harness/src/qmp.rs` only if `set_link` is missing (check first)

- [ ] **Step 1: Write the fixture and the suite.** **Step 2: Run** `make test-harness FILTER=m2pd` → all seven PASS (KVM, Kea 3.x locally). Then `make test-harness FILTER=m2` → the part 2 scenarios still PASS with their amendments.
- [ ] **Step 3: `make lint`; commit** `harness: vm-pd.toml and the m2pd QEMU scenarios: delegation, renumbering, deprecation, ULA, the responder, reboot (SPEC §12)`

---

### Task 20: Progress entry and the full gate

**Files:**
- Modify: `docs/progress.md` (M2 section: a `**2026-11-0N, [#<PR>](…), part 3: delegated prefixes, ULA and deprecation.**` paragraph in the style of the part 2 entry; the "Part 3 is scoped" line replaced by "M2 is complete; next is M3 (PPPoE)."; the PR number is filled in after `gh pr create` by a follow-up commit if unknown)

- [ ] **Step 1: Write the entry.** **Step 2: Run the whole gate**: `make lint && make test && make test-harness` (background, output to the workspace; read the tail) → every suite PASS or SKIP with a module reason; no FAIL.
- [ ] **Step 3: Commit** `docs: progress entry for M2 part 3`

---

## Self-review notes

- Spec coverage: §7.3 delegated path (Tasks 2, 4, 6, 9, 12), ULA (6, 7, 9, 10), responder (5, 13, 14), deprecation (9, 10, 12, 19), source rules (8, 9), DNS (15), harness (17–19), follow-ups #26 #27 #28 #29 #30 #31 #33 #34 (16, 12, 10, 16, 2, 16, 1, 11).
- Interfaces: `Lifetimed` (Task 6) is what Task 12's `fact_from` fills and Tasks 9, 10, 15 read; `lan6::Source` is reused by `DesiredPio`; `wan_usable` moves from `ra.rs` into `lan6` in Task 6 and `ra.rs` calls it from Task 10 on; `Config` of the RA server changes shape in Task 10, so `harness/tests/ndp.rs` adapts there.
- Review Focus: each of the five lines names its pinning test.
