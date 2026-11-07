# M3 Part 1: PPPoE Cores and the Router's Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Everything of M3 that can be proven on a machine without PPP in its kernel: the pure PPPoE and PPP cores with their fuzz targets, the `[wans.pppoe]` configuration, the session fact, the `ppp-<wan>` netdev in every reconciler and applier (point-to-point address, `dev` default, rename and MTU, the MSS clamp), the IPv6 tasks' survival of a new session, the discovery driver proven over a veth pair, and the task and session plumbing written against the cores and compiled in, to be proven live in part 2.

**Architecture:** A new pure crate `openfeo-proto-ppp` (discovery codec and client, PPP frames, the RFC 1661 automaton once, LCP, PAP, CHAP-MD5, IPCP, IPV6CP, a session orchestrator); `PppoeWan` in the config and `PppoeFact` in the World; `reconcile::wan_netdev` as the one name every IP consumer uses; the netlink crate learns a peer address, the links applier learns to rename and size a unit's netdev; `openfeo-net::pppoe` holds the `AF_PACKET` discovery socket (proven in the sandbox) and the `/dev/ppp` plumbing (compiled, proven in part 2); `crates/openfeo/src/pppoe.rs` runs it all per WAN.

**Tech Stack:** Rust stable edition 2024, tokio, nix (`AF_PACKET`, ioctls), rtnetlink 0.23 / netlink-packet-route 0.33, libnftables JSON, insta snapshots, cargo-fuzz; the harness's rootless sandbox (veth pairs) for the discovery driver and the applier scenarios.

**Spec:** `docs/superpowers/specs/2026-11-07-m3-pppoe-design.md` (the design; its "Calls made for the maintainer" are binding, its "Parts" section bounds this plan), under `SPEC.md` §7.2, §7.4, §7.5, §7.7, §8.2, §12.

## Global Constraints

- Every new source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton` (CLAUDE.md).
- `clippy -D warnings` with pedantic as warnings; no `unwrap`/`expect` outside tests; `thiserror` in libraries; `#![forbid(unsafe_code)]` everywhere but `openfeo-net`, whose `unsafe` stays in `sys.rs` with `// SAFETY:` comments (ADR-0013).
- `openfeo-proto-ppp` is pure: no tokio, libc, nix or socket2 in its dependency tree (`scripts/check-deps.sh`); it may depend on `openfeo-proto-ndp` for `iid` and `sha256` (pure).
- Every parser gets a fuzz target in the task that adds it (`fuzz/fuzz_targets/`, registered in `fuzz/Cargo.toml` after the `dhcp6_*` entries).
- The World is clockless: moments travel as milliseconds on the process monotonic clock; secrets (the password, the CHAP secret) never appear in a fact, a line or a snapshot.
- Nothing is desired for `ppp-<wan>` until `World.links` shows it (design, "The task").
- Commits: `git -c user.name='Andrew Newton' -c user.email='andy@vitri.ltd' commit -s -F <msgfile>`, subject `<area>: <summary>`, body ending with the session's two attribution lines; the message file lives outside the repo.
- All repo text is public writing: documentation ranges only; the fixture credentials are `openfeo@isp.example` / `example-secret`.
- `make lint` and `make test` are the per-task gates; a sandbox suite runs as `cargo test -q -p openfeo-harness --test <name>` with `OPENFEO_NFT_SRC` and `OPENFEO_UAPI_INCLUDE` set (the Makefile's `FILTER=` filters scenario names, not suites); the QEMU suites run as `make test-harness` at the end.
- Console lines are a contract: every new line has a unit test in the module that prints it.

## Review Focus

1. A PADO that carries our Host-Uniq but a service or AC the filters refuse, and a PADS with session id 0 or an error tag: no session, back to PADI after the retransmission schedule, never a stuck client. Pinned in Task 3 (`a_pado_the_filters_refuse_is_ignored_and_a_pads_with_session_zero_restarts`).
2. LCP where the AC Naks our MRU down (1500 → 1480) and where it requests an MRU above ours: we take the Nak and Nak its request to our size; neither loops past Max-Failure. Pinned in Task 5 (`mru_naks_converge_within_max_failure`).
3. A CHAP re-challenge in the Network phase is answered without touching the NCPs. Pinned in Task 8 (`a_rechallenge_in_network_phase_keeps_the_ncps_up`).
4. IPCP Naked five times with 0.0.0.0 while IPV6CP succeeds: IPv4 fails alone, the link stays, IPv6 is up; both failing ends the link with `no network protocol`. Pinned in Task 8 (`one_ncp_may_fail_alone_and_both_failing_ends_the_link`).
5. A frame with an unknown protocol (0x8099) and a Code-Reject of a code we need (Echo-Request): the first is Protocol-Rejected and ignored, the second ends the keepalive but not the link. Pinned in Task 8 (`unknown_protocols_are_rejected_and_a_rejected_echo_stops_the_keepalive`).

---

### Task 1: SPEC amendments and the two ADRs

**Files:**
- Modify: `SPEC.md` (§7.2 PPPoE bullets at lines 252–258, §7.5 the MSS sentence, §8.2 `[wans.pppoe]` lines 362–365, §11 line 497, §13 line 584)
- Create: `docs/adr/0022-in-tree-ppp-codecs.md`, `docs/adr/0023-the-ppp-unit-belongs-to-the-wan-task.md`

- [ ] **Step 1: Amend `SPEC.md`** per the design's "SPEC amendments": §7.2 kernel plumbing sentence → "LCP and the authentication protocols are read and written as frames on the channel fd, the network control protocols on the unit fd, both polled"; the port MTU 1508 for RFC 4638 and the offer withheld when the NIC refuses; the reconnect schedule (1 s doubling to 60 s, reset after a minute up, at once on carrier, 60 s after an authentication failure); the console lines of the design; `service` and `ac` filters in §8.2 with "absent = any"; §7.5's MSS sentence names the rule `tcp flags syn tcp option maxseg size set rt mtu` in both directions of every WAN whose netdev MTU is below 1500; §11 names `pppoe-server`, `pppd`, `/dev/ppp` and the `/etc/ppp` mount; §13 ticks the Kea-over-PPP item with "Kea, started on the ISP's PPP interface once the session is up (M3 design)".
- [ ] **Step 2: Write the ADRs** (Context, Decision, Consequences): 0022 after ADR-0018's shape (in-tree codecs; `ppproperly` as the differential oracle if `cargo deny` accepts its licence, else RFC vectors; the decision is made in Task 2 and recorded here); 0023: the WAN task creates the unit through `/dev/ppp` and owns the three descriptors; the links applier renames, sizes and raises the netdev like any link; nothing else touches them; the netdev's absence is a task mid-restart.
- [ ] **Step 3: Run** `scripts/check-spdx.sh` → ok. **Commit** `spec: PPPoE amendments and ADR-0022/0023 (M3 design)`.

---

### Task 2: `openfeo-proto-ppp`, the PPPoE discovery codec

**Files:**
- Create: `crates/openfeo-proto-ppp/Cargo.toml` (`[dependencies] ipnet, thiserror, openfeo-proto-ndp`; `[dev-dependencies]` the oracle if chosen), `crates/openfeo-proto-ppp/src/lib.rs` (`#![forbid(unsafe_code)]`, `pub mod pppoe; pub type Timestamp = u64; pub const MS: Timestamp = 1000;`), `crates/openfeo-proto-ppp/src/pppoe.rs`
- Create: `fuzz/fuzz_targets/pppoe_discovery.rs`; modify `fuzz/Cargo.toml`, `Cargo.toml` (workspace member), `scripts/check-deps.sh` needs nothing (the `openfeo-proto-.*` rule covers it)

**Interfaces:**
- Produces: `pub const ETH_P_PPP_DISC: u16 = 0x8863; pub const ETH_P_PPP_SES: u16 = 0x8864;` `pub enum Code { Padi, Pado, Padr, Pads, Padt }` (0x09, 0x07, 0x19, 0x65, 0xa7); `pub enum Tag { EndOfList, ServiceName(String), AcName(String), HostUniq(Vec<u8>), AcCookie(Vec<u8>), RelaySessionId(Vec<u8>), PppMaxPayload(u16), ServiceNameError(String), AcSystemError(String), GenericError(String), Unknown { kind: u16, data: Vec<u8> } }`; `pub struct Discovery { pub code: Code, pub session_id: u16, pub tags: Vec<Tag> }` with `pub fn decode(bytes: &[u8]) -> Result<Discovery, Error>` and `pub fn encode(&self) -> Vec<u8>`, `pub fn tag<T>(&self, pick: impl Fn(&Tag) -> Option<T>) -> Option<T>`; `pub enum Error { Truncated, Version(u8), Type(u8), Code(u8), TagLength { kind: u16 }, TooMany, Length { declared: u16, actual: usize } }`; limits `MAX_TAGS = 32`, `MAX_TAG_LEN = 1480`, strings as lossy UTF-8 of printable bytes (an error tag with bytes that are not UTF-8 is kept as `Unknown`).

- [ ] **Step 1: Write the failing tests** in `pppoe.rs`: `padi_round_trips_with_host_uniq_service_and_max_payload` (encode then decode equals; the bytes match RFC 2516 §5 byte for byte for a PADI with Service-Name "" and Host-Uniq 8 bytes: give the expected hex), `pado_from_the_rfc_example_decodes` (the RFC's PADO layout with AC-Name and AC-Cookie), `a_declared_length_longer_than_the_frame_is_an_error`, `a_tag_longer_than_its_frame_is_an_error`, `thirty_three_tags_are_too_many`, `an_unknown_tag_round_trips`.
- [ ] **Step 2: Run** `cargo test -p openfeo-proto-ppp` → FAIL (nothing exists).
- [ ] **Step 3: Implement** the codec. Encode writes version 1, type 1, code, session id, the length of the tags, then the tags (End-of-List last only when the caller gives it).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Fuzz target** `pppoe_discovery`: decode never panics; a decoded packet re-encodes to bytes that decode equal. Register in `fuzz/Cargo.toml`. Run `cd fuzz && cargo +nightly fuzz run pppoe_discovery -- -max_total_time=60` → no crash.
- [ ] **Step 6: Decide the oracle** for ADR-0022: `cargo add --dev ppproperly` and `cargo deny check` in the workspace; keep it only if deny passes and it decodes PADO/LCP packets; record the outcome in ADR-0022 (Task 1's file, amended here). **Commit** `proto-ppp: the PPPoE discovery codec with a fuzz target`.

---

### Task 3: The discovery client core

**Files:**
- Modify: `crates/openfeo-proto-ppp/src/pppoe.rs` (add `client` items) or create `crates/openfeo-proto-ppp/src/discovery.rs` (`pub mod discovery;`)

**Interfaces:**
- Produces: `pub struct Config { pub service: Option<String>, pub ac: Option<String>, pub max_payload: Option<u16> /* what to ask for; None asks nothing */ }`; `pub enum Input { Start, Packet { from: [u8; 6], bytes: Vec<u8> }, Timeout, Stop }`; `pub enum Output { Send { to: [u8; 6], bytes: Vec<u8> }, Session { id: u16, ac_mac: [u8; 6], ac_name: String, max_payload: Option<u16> }, Closed(Reason), Note(Note) }`; `pub enum Reason { Padt, Stopped }`; `pub enum Note { Padi, Pado { ac: String, service: String, refused: Option<&'static str> }, Padr, Refused(&'static str), Ignored(&'static str) }`; `pub struct Client` with `new(config, seed: u64)`, `handle(&mut self, Input, now: Timestamp) -> Vec<Output>`, `next_timeout(&self) -> Option<Timestamp>`, `state(&self) -> State`, `host_uniq(&self) -> [u8; 8]`; `pub enum State { Idle, Padi, Padr, Session, Closed }`; consts `PADI_TIMEOUTS: [Timestamp; 6] = [1, 2, 4, 8, 16, 32] × MS` then 32 s, `PADR_TIMEOUTS: [Timestamp; 3] = [1, 2, 4] × MS`, `BROADCAST: [u8; 6] = [0xff; 6]`.

- [ ] **Step 1: Write the failing tests**: `start_broadcasts_a_padi_with_host_uniq_and_max_payload`, `padi_retransmits_on_the_schedule_then_every_32_s`, `the_first_acceptable_pado_gets_a_padr_echoing_cookie_relay_id_and_max_payload`, `a_pado_the_filters_refuse_is_ignored_and_a_pads_with_session_zero_restarts` (Review Focus 1), `a_pado_without_our_host_uniq_is_ignored`, `max_payload_is_echoed_only_when_the_pado_offers_at_least_ours` (RFC 4638 §4), `pads_without_the_tag_means_none`, `padr_retransmits_three_times_then_padi_again`, `padt_from_the_ac_closes_and_stop_sends_padt`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `proto-ppp: the PPPoE discovery client`.

---

### Task 4: PPP frames and the RFC 1661 automaton

**Files:**
- Create: `crates/openfeo-proto-ppp/src/frame.rs`, `crates/openfeo-proto-ppp/src/fsm.rs`

**Interfaces:**
- `frame`: `pub const LCP: u16 = 0xc021; PAP = 0xc023; CHAP = 0xc223; IPCP = 0x8021; IPV6CP = 0x8057; IPV4 = 0x0021; IPV6 = 0x0057;` `pub struct Frame<'a> { pub protocol: u16, pub payload: &'a [u8] }` with `decode(&[u8]) -> Result<Frame, Error>` (two-byte protocol, no PFC) and `encode(protocol, payload) -> Vec<u8>`; `pub struct Packet { pub code: u8, pub id: u8, pub data: Vec<u8> }` (the LCP/NCP/auth header: code, identifier, length) with `decode`/`encode`; codes `CONFIGURE_REQUEST = 1 … DISCARD_REQUEST = 11`.
- `fsm`: `pub trait Options: Clone { type Opt: Clone + PartialEq; fn decode(data: &[u8]) -> Result<Vec<Self::Opt>, Error>; fn encode(opts: &[Self::Opt]) -> Vec<u8>; fn ours(&self) -> Vec<Self::Opt>; fn judge(&mut self, theirs: &[Self::Opt]) -> Judgement<Self::Opt> /* Ack | Nak(Vec) | Reject(Vec) */; fn naked(&mut self, suggested: &[Self::Opt]) -> bool /* false = give up */; fn rejected(&mut self, opts: &[Self::Opt]) -> bool; }`; `pub struct Fsm<O: Options>` with `new(options, seed)`, `pub fn handle(&mut self, Event, now) -> Vec<Action>`, `pub enum Event { Up, Down, Open, Close, Timeout, Receive(Packet) }`, `pub enum Action { Send(Packet), ThisLayerUp, ThisLayerDown, ThisLayerStarted, ThisLayerFinished, Unknown(Packet) /* a code the protocol must handle itself: echo, discard, protocol-reject */ }`, `pub enum State { Initial, Starting, Closed, Stopped, Closing, Stopping, RequestSent, AckReceived, AckSent, Opened }`, `next_timeout()`, `state()`; `MAX_CONFIGURE = 10`, `MAX_TERMINATE = 2`, `MAX_FAILURE = 5`, `RESTART_TIMER = 3 * MS`.

- [ ] **Step 1: Write the failing tests** on a toy `Options` (one u32 option): `open_then_up_sends_a_configure_request_and_acks_the_peers`, `both_acks_open_the_layer`, `a_nak_is_applied_and_a_new_request_sent_with_a_new_id`, `max_failure_naks_give_up_with_this_layer_finished`, `terminate_request_from_the_peer_is_acked_and_the_layer_goes_down`, `close_sends_two_terminate_requests_then_finishes`, `an_old_identifier_is_ignored`, `restart_timer_retransmits_up_to_max_configure`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** the automaton as the RFC's state table. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `proto-ppp: PPP frames and the RFC 1661 automaton`.

---

### Task 5: LCP

**Files:**
- Create: `crates/openfeo-proto-ppp/src/lcp.rs`; `fuzz/fuzz_targets/ppp_lcp.rs` (+ registration)

**Interfaces:**
- `pub enum Opt { Mru(u16), Auth(AuthProto), Magic(u32), Pfc, Acfc, Quality(u16), Callback(u8), Mrru(u16), Unknown { kind: u8, data: Vec<u8> } }`, `pub enum AuthProto { Pap, ChapMd5, Other { protocol: u16, algorithm: Option<u8> } }`; `pub struct Lcp { … } : Options`; `Lcp::new(mru: u16, seed)`, `pub fn negotiated(&self) -> Negotiated { mru_ours: u16, mru_theirs: u16, auth: Option<AuthProto>, magic_ours: u32, magic_theirs: u32 }`; `pub struct Keepalive` (`interval 10 s`, `misses 3`): `tick(now) -> Option<Packet>`, `reply(packet) -> bool`, `lost(&self) -> bool`; echo and discard handled by `Lcp::handle_unknown(packet) -> Vec<Packet>`.

- [ ] **Step 1: Failing tests**: `our_request_carries_mru_and_magic_only`, `pap_or_chap_md5_is_accepted_and_anything_else_naked_to_chap_then_pap_then_rejected`, `mru_naks_converge_within_max_failure` (Review Focus 2), `a_magic_equal_to_ours_is_naked`, `pfc_acfc_callback_and_mrru_are_rejected`, `echo_requests_carry_our_magic_and_three_misses_are_lost`, `the_peers_echo_request_is_answered_with_our_magic`.
- [ ] **Step 2–4**: FAIL, implement, PASS. **Step 5: fuzz** `ppp_lcp` (option decoder never panics; encode(decode) round trip). **Commit** `proto-ppp: LCP options, keepalive and termination`.

---

### Task 6: PAP, CHAP-MD5 and MD5

**Files:**
- Create: `crates/openfeo-proto-ppp/src/md5.rs`, `crates/openfeo-proto-ppp/src/pap.rs`, `crates/openfeo-proto-ppp/src/chap.rs`; `fuzz/fuzz_targets/ppp_auth.rs`

**Interfaces:**
- `md5::digest(&[u8]) -> [u8; 16]`.
- `pap::Client::new(username: &str, password: &[u8])`, `start(now) -> Vec<Output>`, `handle(Input::{Packet(Packet), Timeout}, now) -> Vec<Output>` with `Output::{Send(Packet), Ok, Failed(String)}`; retransmit 3 s, 10 tries.
- `chap::Client::new(name: &str, secret: &[u8])`, `handle(Packet) -> Vec<Output>` with `Output::{Send(Packet), Ok, Failed(String), Rechallenged}` (a Challenge after Success is answered and reported).
- Neither type implements `Debug` for its secret (a `Debug` impl prints `<redacted>`).

- [ ] **Step 1: Failing tests**: `md5_matches_rfc_1321_vectors` (the seven vectors), `pap_sends_the_credentials_and_acks_up`, `pap_nak_fails_with_the_message_and_no_retry`, `pap_retransmits_ten_times_then_fails`, `chap_md5_response_matches_rfc_1994_example` (compute against a known vector: id 1, secret "secret", challenge bytes → expected digest from an independent MD5 of `01 || "secret" || challenge`), `chap_failure_fails_and_a_rechallenge_after_success_is_answered`, `debug_output_never_shows_the_secret`.
- [ ] **Step 2–4**: FAIL, implement, PASS. **Step 5: fuzz** `ppp_auth` (PAP and CHAP packet decoders). **Commit** `proto-ppp: PAP, CHAP-MD5 and an in-tree MD5`.

---

### Task 7: IPCP and IPV6CP

**Files:**
- Create: `crates/openfeo-proto-ppp/src/ipcp.rs`, `crates/openfeo-proto-ppp/src/ipv6cp.rs`; `fuzz/fuzz_targets/ppp_ipcp.rs`, `fuzz/fuzz_targets/ppp_ipv6cp.rs`

**Interfaces:**
- `ipcp::Opt { Address(Ipv4Addr), PrimaryDns(Ipv4Addr), SecondaryDns(Ipv4Addr), Compression(Vec<u8>), Unknown{..} }`; `Ipcp::new()` : `Options`; `Ipcp::result() -> Option<Ipv4Up { local: Ipv4Addr, peer: Option<Ipv4Addr>, dns: Vec<Ipv4Addr> }>`; five Naks that leave the address 0.0.0.0 → `naked` returns false.
- `ipv6cp::Opt { InterfaceId(u64), Unknown{..} }`; `Ipv6cp::new(secret: &[u8; 16], wan: &str)` (identifier = `openfeo_proto_ndp::iid`'s function over `secret ‖ "ipv6cp" ‖ wan`, counter 0, re-derived with the counter on a conflict); `result() -> Option<Ipv6Up { local_iid: u64, peer_iid: u64 }>`.

- [ ] **Step 1: Failing tests**: `ipcp_requests_zero_address_and_dns_and_takes_the_nak`, `ipcp_accepts_the_peers_address_and_rejects_compression`, `ipcp_without_a_peer_address_is_unnumbered`, `five_zero_naks_give_up`, `ipv6cp_identifier_is_stable_for_a_secret_and_wan_and_never_zero`, `an_identifier_equal_to_the_peers_is_rederived`, `a_naked_identifier_is_taken`.
- [ ] **Step 2–4**: FAIL, implement, PASS. **Step 5: fuzz** both option decoders. **Commit** `proto-ppp: IPCP and IPV6CP`.

---

### Task 8: The session orchestrator

**Files:**
- Create: `crates/openfeo-proto-ppp/src/session.rs`; `fuzz/fuzz_targets/ppp_session.rs`

**Interfaces:**
- `pub struct Config { pub username: String, pub password: Vec<u8>, pub mru: u16, pub secret: [u8; 16], pub wan: String }`; `pub enum Input { Start, Frame { protocol: u16, payload: Vec<u8> }, Timeout, Stop, CarrierLost }`; `pub enum Output { Send { protocol: u16, payload: Vec<u8> }, Mru(u16), LcpUp { mru: u16, auth: Option<AuthProto> }, AuthOk(&'static str), Ipv4Up(Ipv4Up), Ipv4Down, Ipv6Up(Ipv6Up), Ipv6Down, Down { reason: Reason, uptime_ms: u64 }, Note(Note) }`; `pub enum Reason { KeepaliveLost, TerminatedByPeer, AuthFailed(String), NoNetworkProtocol, AuthProtocolUnsupported, LcpFailed, CarrierLost, Stopped }`; `pub enum Phase { Dead, Establish, Authenticate, Network, Terminate }`; `Session::new(config, seed)`, `handle(input, now) -> Vec<Output>`, `next_timeout()`, `phase()`.

- [ ] **Step 1: Failing tests** (drive with hand-built peer packets): `a_full_session_comes_up_with_chap_ipcp_and_ipv6cp`, `pap_is_used_when_the_ac_asks_for_it_and_no_auth_goes_straight_to_network`, `a_rechallenge_in_network_phase_keeps_the_ncps_up` (Review Focus 3), `one_ncp_may_fail_alone_and_both_failing_ends_the_link` (Review Focus 4), `unknown_protocols_are_rejected_and_a_rejected_echo_stops_the_keepalive` (Review Focus 5), `three_missed_echoes_end_the_session_with_keepalive_lost`, `a_terminate_request_from_the_peer_is_acked_and_the_session_is_down`, `stop_sends_two_terminate_requests_then_down`, `nothing_is_sent_after_down_until_start`, `uptime_counts_from_lcp_up`.
- [ ] **Step 2–4**: FAIL, implement, PASS. **Step 5: fuzz** `ppp_session` (random frames and timeouts; invariants: no `Send` after `Down`, `next_timeout() >= now`, at most `MAX_CONFIGURE` requests per exchange). **Commit** `proto-ppp: the PPP session orchestrator`.

---

### Task 9: Configuration

**Files:**
- Modify: `proto/openfeo/v1/config.proto` (`message PppoeWan { string username = 1; string password = 2; string service = 3; string ac = 4; }`, `PppoeWan pppoe = 8;` in `Wan.kind`), `crates/openfeo-config/src/validate.rs` (`pppoe_wan`: codes `PppoeUsername`, `PppoePassword`, `PppoeFilter`), `crates/openfeo-config/src/rules.rs` (`pub fn is_pppoe(wan) -> bool`, `pub fn ppp_ifname(wan_name) -> String` = `ppp-<name>`), `crates/openfeo-config/src/file.rs` only if the TOML needs it; `harness/fixtures/vm-pppoe.toml` (the design's example, lan0 as `vm-static.toml`), `harness/fixtures/vm-pppoe-pd.toml` (pd_hint 56)

- [ ] **Step 1: Failing tests** in `validate.rs`: `a_pppoe_wan_needs_a_username_and_a_password`, `pppoe_strings_are_at_most_255_bytes_without_nul`, `a_pppoe_wan_may_carry_ipv6_in_every_shape`, `the_pppoe_fixtures_validate`; in `rules.rs`: `ppp_ifname_is_ppp_dash_wan`.
- [ ] **Step 2–4**: FAIL, implement (`buf lint`/`check-proto.sh` for the proto), PASS. **Commit** `config: [wans.pppoe] (SPEC §8.2)`.

---

### Task 10: The fact and every reconciler

**Files:**
- Create: `crates/openfeo-world/src/pppoe.rs` (`PppoeFact`, `PppIpv4`, `PppIpv6` as the design), modify `crates/openfeo-world/src/{lib,world}.rs` (`World.pppoe`), `crates/openfeo-runtime` publisher (`set_pppoe(wan, Option<PppoeFact>)` after `set_dhcp6`'s pattern)
- Modify: `crates/openfeo-reconcile/src/lib.rs` (`pub fn wan_netdev(wan) -> String`), `links.rs` (`DesiredPpp`, `DesiredLinks.ppp`, port MTU 1508 and the parent's), `routing.rs` (`DesiredAddr.peer: Option<IpAddr>`; the PPPoE arm: address, `dev` default via the peer when known, `fe80::<iid>/64` and the peer's /128; gated on `world.links` having the netdev), `sysctl.rs` (netdev), `nft.rs` (`wan_if` by `wan_netdev`; `mss_clamp: Vec<String>` of netdevs with MTU < 1500 in `World.links`; the two rules per netdev in `forward`), `dns.rs` (IPCP resolvers behind the IPv4 gate; the gate by netdev), `lan6.rs` (`wan_usable` by netdev), `fixtures.rs` (`pppoe_world()`: `vm-pppoe.toml`, a `ppp-wan0` link fact at index 9 MTU 1492, a fact with ipv4 and ipv6)
- Snapshots: new `pppoe_world` snapshots for links, routing, nft, dns, sysctl; the `dhcp_world` nft snapshot gains the clamp lines (WAN MTU 1400)

- [ ] **Step 1: Failing tests**: `wan_netdev_is_the_port_or_ppp_dash_wan`, `a_pppoe_wan_desires_nothing_for_its_netdev_until_the_link_exists`, `a_pppoe_world_routes_a_point_to_point_address_and_a_dev_default`, `the_ipv6cp_identifiers_give_the_link_local_and_the_peer_route`, `a_sub_1500_wan_gets_the_mss_clamp_both_ways` (dhcp_world with MTU 1400 and pppoe_world), `ipcp_resolvers_join_behind_the_ipv4_route`, `a_tagged_pppoe_wan_raises_the_parent_to_1508_too`, plus the snapshot tests.
- [ ] **Step 2–4**: FAIL, implement, PASS (accept the snapshots after reading them). **Commit** `reconcile: the PPPoE WAN's netdev in every reconciler, the fact, the MSS clamp (SPEC §7.2, §7.5)`.

---

### Task 11: Netlink and the appliers

**Files:**
- Modify: `crates/openfeo-netlink/src/apply.rs` (`addr_add_peer(index, local: IpNet, peer: IpAddr)` setting `IFA_LOCAL` and `IFA_ADDRESS`; `addr_del` for it), `types.rs`/`monitor.rs` only if the cache needs the peer (it reads `IFA_LOCAL` already: check), `crates/openfeo-apply/src/routing.rs` (peer addresses; `is_managed` widened to configured `ppp-<wan>` names), `crates/openfeo-apply/src/links.rs` (`ppp` entries: rename `ppp<unit>` → name, MTU, up; a refused 1508 is a tolerated op), `harness/tests/netlink.rs` (scenarios `a_point_to_point_address_is_added_with_its_peer_and_removed`, `the_links_applier_renames_and_sizes_a_unit_netdev` on a dummy link created as `ppp7`, `a_refused_port_mtu_is_tolerated` if a veth refuses 1508, else skip with a note)

- [ ] **Step 1: Write the scenarios** (they fail: no such functions). **Step 2: Run** `cargo test -q -p openfeo-harness --test netlink` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `netlink, apply: point-to-point addresses and the unit netdev's rename, MTU and up`.

---

### Task 12: The discovery driver, proven; the session plumbing, compiled

**Files:**
- Create: `crates/openfeo-net/src/pppoe.rs` (`Discovery::open(ifindex, ifname) -> Result<Discovery, DriverError>`, `recv(&mut buf) -> (from: [u8; 6], len)`, `send(to, bytes)`; `Session::attach(port_ifindex, port_ifname, session_id, ac_mac) -> Result<Session, DriverError>`, `unit(&self) -> u32`, `recv(&mut buf) -> (protocol, len)` polling both fds, `send(protocol, payload)` by protocol class, `set_mru(u16)`); modify `sys.rs` (`AF_PPPOX`, `PX_PROTO_OE`, `sockaddr_pppox`, the ioctls with a unit test `ppp_ioctl_numbers_match_the_pinned_uapi_headers` parsing `$OPENFEO_UAPI_INCLUDE/linux/ppp-ioctl.h`), `harness/tests/pppoe.rs` (new suite, `[[test]]` + Makefile): `discovery_binds_a_session_against_a_scripted_ac` (the far end of a veth answers PADI with a codec-built PADO and PADR with a PADS, carrying Host-Uniq, AC-Cookie and PPP-Max-Payload; the client reports `Session{..}`), `a_padt_from_the_ac_closes_the_client`; `session_attach_is_skipped_without_dev_ppp` (a `Skip` naming the udev rule, so part 2 turns it into the live scenario)

- [ ] **Step 1–4**: scenarios first (FAIL), implement, PASS. **Step 5: Commit** `net: the PPPoE discovery socket, proven over a veth pair, and the /dev/ppp plumbing for part 2`.

---

### Task 13: The task, and the IPv6 tasks over a session

**Files:**
- Create: `crates/openfeo/src/pppoe.rs` (`spawn_all`, `WanTask { wan, port, username, password, service, ac }`, `run`, `Backoff` (pure: `next(now, up_for) -> Timestamp`), the console lines of the design with `lines_follow_the_contract`), modify `router.rs` (spawn), `main.rs` if the console init lists tasks
- Modify: `crates/openfeo/src/dhcp4.rs` (`wait_for_netdev(world_rx, name) -> Result<u32, TaskError>` beside `wait_for_link`), `ipv6.rs` and `dhcp6.rs` (the WAN's interface is `wan_netdev`; an index change is `LinkDown`, reopen, `LinkUp` in place: a pure `fn link_change(prev: Option<(u32, bool)>, now: Option<&LinkFact>) -> LinkChange { None, Down, Up, Reopen(u32) }` with unit tests; the DUID and the binding identity use the port's MAC), `crates/openfeo-proto-ndp/src/client.rs` (`Config.mac: Option<[u8; 6]>`, no SLLAO when `None`; the ndp sandbox suite adapts)

- [ ] **Step 1: Failing tests**: `backoff_doubles_to_sixty_and_resets_after_a_minute_up`, `auth_failure_waits_sixty_seconds_from_the_first`, `lines_follow_the_contract` (every console line of the design), `a_new_index_is_a_reopen_not_an_error`, `a_solicitation_without_a_mac_carries_no_source_link_layer_option` (ndp client).
- [ ] **Step 2–4**: FAIL, implement, PASS; `cargo test -q -p openfeo-harness --test ndp` still green.
- [ ] **Step 5: Commit** `openfeo: the PPPoE WAN task; the IPv6 tasks survive a session's new netdev`.

---

### Task 14: Progress entry and the full gate

**Files:**
- Modify: `docs/progress.md` (an `## M3 PPPoE` section with the part 1 paragraph: what is proven here, what part 2 proves live; the PR number filled in after the draft PR exists)

- [ ] **Step 1: Run the whole gate**: `make lint && make test && make test-harness` → every suite PASS or SKIP with a reason. **Step 2: Write the entry** (after the PR number). **Step 3: Commit** `docs: progress entry for M3 part 1`.

---

## Self-review notes

- Spec coverage: §7.2 discovery (2, 3), LCP/auth/NCPs (4–8), kernel plumbing (12, compiled; live in part 2), reconnect (13), facts (10), MSS clamp (10), console (13); §8.2 (9); §7.5 (10); §7.7 (10); §12's live proof is part 2's by the design's "Parts".
- Interfaces: `Frame`/`Packet` (4) are what 5–8 speak; `Options` (4) is what 5 and 7 implement; `session::Output` (8) is what 13 turns into facts and lines; `PppoeFact` (10) is what 11's applier and 13's publish share; `wan_netdev` (10) is read by 11 and 13.
- Review Focus: each line names its pinning test.
