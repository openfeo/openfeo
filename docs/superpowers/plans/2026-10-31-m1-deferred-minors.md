# M1 Deferred Minors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clear the review minors deferred across M0 and M1 parts 2b (DHCPv4 client), 3a (DHCPv4 server), 3b (DNS forwarder) and 3c (SNTP) that need no design change, each pinned by a test, in one branch and one PR.

**Architecture:** Nothing new is built. Each task owns one crate group (SNTP core; SNTP driver, clock and kernel; DNS core; DNS glue; DHCPv4 server; DHCPv4 client; PID 1) and fixes its items test-first in the existing modules, keeping every interface the router task and the harness consume unless the item is the interface (named in the task's Interfaces block). Behaviour the console or a LAN device can see gets a console line or a scenario check; the rest is unit tests. Some tests pin behaviour the reviews found untested rather than missing; those are marked "pin" and are expected to pass at once.

**Tech Stack:** As the branch stands: Rust stable 2024, tokio, nix 0.30, libc in the unsafe `sys` modules, prost/pbjson, insta, cargo-fuzz; the lab unchanged.

**Spec:** `SPEC.md` (§5.3 PID 1, §7.2 DHCPv4 client, §7.6 DHCPv4 server, §7.7 DNS, §7.10 Time, §13 pure crates). The items come from the whole-branch reviews of parts 3b and 3c, the PR bodies of #3 and #4, and the M0 follow-up notes. ADR-0016 is amended in Task 2.

**Left out, and why:** DNS qnames echoed lowercased (0x20 case preservation needs the codec to carry the original bytes: a design change, and no stub resolver we know of enforces it); `Cache::evict`'s O(n) scan (fine at the fixed 4096); a pipelined-TCP client test (dig cannot pipeline; a bespoke client for one test); the M0 container-supervisor details, `build.sh` checks, harness portability and `mountinfo` EBUSY handling (M5 and build tooling); per-interface `send_redirects` (already in `reconcile::sysctl`); `Dhcp4Fact.ntp` (landed in 3c); early-mount warnings "lost before the console opens" (moot: the initramfs carries a `/dev/console` node, `kernel/build.sh` line 47, so PID 1's stderr is the console from its first instruction); the single-upstream SERVFAIL policy and the xorshift ids (rulings, not minors).

## Global Constraints

- Every source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton`.
- `#![forbid(unsafe_code)]` everywhere except `openfeo-init`, `openfeo-nft` and `openfeo-net`, where `unsafe` lives in `sys.rs` with `// SAFETY:` comments (ADR-0013).
- Pure crates (`openfeo-proto-*`, `openfeo-reconcile`, `openfeo-world`) stay pure; `scripts/check-deps.sh` enforces it. `openfeo-config` may depend on `openfeo-proto-dhcp4` (both pure).
- Rust stable, edition 2024; `clippy -D warnings` with pedantic on; no `unwrap`/`expect` outside tests; `thiserror` in libraries, `anyhow` only in `crates/openfeo` and `harness/`.
- Commits: `git commit -s`, subject `<area>: <summary>`, trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_0116otzXyvDbuXkw4CsR8ExV`.
- No protobuf change. Console lines are a contract with the harness: every existing line keeps its text; new lines are listed in their task.
- `export OPENFEO_NFT_SRC=$PWD/build/nft/src OPENFEO_UAPI_INCLUDE=$PWD/build/kernel/headers/include` before a bare `cargo` command; QEMU scenarios need `OPENFEO_KERNEL=$PWD/build/bzImage`.
- The branch is `m1-minors` from `main` at `b14b194`.

## Review Focus

1. A public name answering with a 100.64.0.0/10 (CGNAT), 255.255.255.255 or LAN-subnet address must be refused like an RFC 1918 one: many homes sit behind CGNAT, and the rebinding guard is what stands between a hostile page and the printer. Test `rebinding_covers_shared_space_broadcast_lan_subnets_and_the_wan_address` (Task 3).
2. An upstream that answers REFUSED or SERVFAIL while another works must not take the household's DNS down with it: the next upstream is asked and the client still gets an answer. Test `an_upstream_error_fails_over_to_the_next_before_the_client_hears_it` (Task 3).
3. A time server that answers promptly but has no time (LI 3) is not "down": the console says it has no time, once, and the round moves on at once rather than after a timeout. Test `an_unsynchronised_answer_ends_the_request_and_is_reported_once` (Task 1).
4. A DHCP lease that expired while the WAN link was down is not confirmed with INIT-REBOOT when the link returns: the client discovers afresh. Test `a_lease_expired_while_the_link_was_down_discovers_on_link_up` (Task 6).
5. A LAN client renewing with our server identifier and its own `ciaddr` but no option 50 (seen in the wild) is acknowledged, not ignored. Test `a_renewing_request_with_our_server_id_and_ciaddr_is_acknowledged` (Task 5).

---

### Task 1: SNTP core

**Files:**
- Modify: `crates/openfeo-proto-sntp/src/client.rs`, `crates/openfeo-proto-sntp/src/responder.rs`
- Test: unit tests in both (helpers `config(&[..])`, `poll(c, mono_ms) -> (Ipv4Addr, Packet)`, `reply_to(&request, unix_ns, stratum) -> Vec<u8>`, `now(mono_ms, unix_ns)`, `sent(&out) -> Vec<(Ipv4Addr, Packet)>`, `ip`, `unix_at(mono_ms)`, `UNIX_2026` exist)

**Interfaces:**
- Produces (Task 2 consumes):

```rust
// client.rs
pub enum Input { Poll, Reply { .. }, Configure(Config),
    /// The driver could not send to the server (no route, say): the request is over; no failure counted.
    Unreachable { server: Ipv4Addr } }
pub enum Event { ..,
    /// The server answered without time (LI 3, stratum 16, a zero stamp or an unusable root distance);
    /// once per server until it answers properly.
    ServerUnsynced(Ipv4Addr) }
// responder.rs
/// RFC 5905 §11.2 PHI: the dispersion grows by this per second since the last sample.
pub const PHI_PPM: i64 = 15;
```

Items: (a) a reply rejected as `Unsynchronised` or `RootDistance` ends the pending request and the round moves on (as a kiss-of-death does), counting no failure, and emits `Event::ServerUnsynced(server)` the first time that server does it (a flag per `ServerState`, cleared by a valid sample); (b) `Input::Unreachable` drops the pending request for that server, counts no failure, moves the round on; (c) the responder's root dispersion is the upstream's plus `OWN_DISPERSION_NS` plus `PHI_PPM` µs per second since `last_sync_unix_secs` (now in seconds minus it, at least 0); (d) `noisy_transmit` randomises all 64 bits of the transmit stamp (the real T1 is `Pending.sent_unix_ns`); (e) `configure` keeps `round_start`/`round_active` when the pending request survives and sets `round_pos` to the pending server's new index + 1; (f) `Event::Refused`'s doc gets the era note (a time more than 68 years from the floor reads in the other era: a 2096 server is "1960").

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn an_unsynchronised_answer_ends_the_request_and_is_reported_once() {
    let mut c = Client::new(config(&["203.0.113.1", "203.0.113.2"]), 1);
    let (server, request) = poll(&mut c, 0);
    let mut unsynced = Packet::decode(&reply_to(&request, UNIX_2026, 2)).unwrap();
    unsynced.leap = LI_UNSYNCHRONISED;
    unsynced.stratum = STRATUM_UNSYNCHRONISED;
    let out = c.handle(Input::Reply { server, bytes: unsynced.encode().to_vec() }, now(5, UNIX_2026));
    assert!(out.contains(&Output::Event(Event::Rejected { server, reason: Reject::Unsynchronised })));
    assert!(out.contains(&Output::Event(Event::ServerUnsynced(server))));
    assert_eq!(sent(&out)[0].0, ip("203.0.113.2"), "the round moved on at once: {out:?}");
    c.handle(Input::Poll, now(5 + REPLY_TIMEOUT_MS, unix_at(5 + REPLY_TIMEOUT_MS)));   // .2 silent: round over
    let (again, request) = poll(&mut c, POLL_UNSYNCED_MS);
    assert_eq!(again, server, "an answer is not a silence: not held");
    let mut unsynced = Packet::decode(&reply_to(&request, unix_at(POLL_UNSYNCED_MS), 2)).unwrap();
    unsynced.leap = LI_UNSYNCHRONISED;
    let out = c.handle(Input::Reply { server, bytes: unsynced.encode().to_vec() }, now(POLL_UNSYNCED_MS + 5, unix_at(POLL_UNSYNCED_MS + 5)));
    assert!(!out.contains(&Output::Event(Event::ServerUnsynced(server))), "reported once: {out:?}");
}

#[test]
fn an_unreachable_server_is_skipped_without_a_failure() {
    let mut c = Client::new(config(&["203.0.113.1", "203.0.113.2"]), 1);
    let mut downs = 0;
    for round in 0..3u64 {
        let start = round * POLL_UNSYNCED_MS;
        let (first, _) = poll(&mut c, start);
        assert_eq!(first, ip("203.0.113.1"), "round {round}: asked again, never held");
        let out = c.handle(Input::Unreachable { server: first }, now(start + 1, unix_at(start + 1)));
        assert_eq!(sent(&out)[0].0, ip("203.0.113.2"), "moved on at once: {out:?}");
        let out = c.handle(Input::Unreachable { server: ip("203.0.113.2") }, now(start + 2, unix_at(start + 2)));
        downs += out.iter().filter(|o| matches!(o, Output::Event(Event::ServerDown(_)))).count();
    }
    assert_eq!(downs, 0);
}

/// Pin: `kiss()` already does this; the reviews found it untested.
#[test]
fn rate_holds_the_server_twice_as_long_and_rstr_retires_it() {
    let mut c = Client::new(config(&["203.0.113.1", "203.0.113.2"]), 1);
    let (server, request) = poll(&mut c, 0);
    let mut rate = Packet::decode(&reply_to(&request, UNIX_2026, 2)).unwrap();
    rate.stratum = STRATUM_KISS;
    rate.reference_id = *b"RATE";
    let out = c.handle(Input::Reply { server, bytes: rate.encode().to_vec() }, now(5, UNIX_2026));
    assert_eq!(sent(&out)[0].0, ip("203.0.113.2"), "{out:?}");
    c.handle(Input::Poll, now(5 + REPLY_TIMEOUT_MS, unix_at(5 + REPLY_TIMEOUT_MS)));
    let (next, _) = poll(&mut c, POLL_UNSYNCED_MS);
    assert_eq!(next, ip("203.0.113.2"), "RATE holds .1");
    let mut c = Client::new(config(&["203.0.113.1"]), 1);
    let (server, request) = poll(&mut c, 0);
    let mut rstr = Packet::decode(&reply_to(&request, UNIX_2026, 2)).unwrap();
    rstr.stratum = STRATUM_KISS;
    rstr.reference_id = *b"RSTR";
    let out = c.handle(Input::Reply { server, bytes: rstr.encode().to_vec() }, now(5, UNIX_2026));
    assert!(out.contains(&Output::Event(Event::ServerUnusable { server, code: *b"RSTR" })));
    assert_eq!(c.next_poll(), None, "nobody left to ask");
}

/// Pin: `next_usable()` already clears the earliest hold; the reviews found it untested.
#[test]
fn when_every_server_is_held_the_earliest_hold_is_cleared() {
    let mut c = Client::new(config(&["203.0.113.1", "203.0.113.2"]), 1);
    let mut downs = 0;
    while downs < 2 {
        let at = c.next_poll().unwrap();
        let out = c.handle(Input::Poll, now(at, unix_at(at)));
        downs += out.iter().filter(|o| matches!(o, Output::Event(Event::ServerDown(_)))).count();
    }
    let at = c.next_poll().unwrap();
    let out = c.handle(Input::Poll, now(at, unix_at(at)));
    assert_eq!(sent(&out).len(), 1, "asked anyway: {out:?}");
}

#[test]
fn configure_with_the_pending_server_kept_continues_the_round() {
    let mut c = Client::new(config(&["203.0.113.1", "203.0.113.2"]), 1);
    let (server, _) = poll(&mut c, 0);
    c.handle(Input::Configure(config(&["203.0.113.1", "203.0.113.2"])), now(1, unix_at(1)));
    assert_eq!(c.next_poll(), Some(REPLY_TIMEOUT_MS), "still waiting for {server}");
    let out = c.handle(Input::Poll, now(REPLY_TIMEOUT_MS, unix_at(REPLY_TIMEOUT_MS)));
    assert_eq!(sent(&out)[0].0, ip("203.0.113.2"), "the round moves on, not back to the start: {out:?}");
}

#[test]
fn the_transmit_stamp_is_random_and_still_matched() {
    let mut c = Client::new(config(&["203.0.113.1"]), 1);
    let (server, request) = poll(&mut c, 0);
    assert_ne!(request.transmit.0 >> 32, NtpTimestamp::from_unix_nanos(UNIX_2026).0 >> 32, "even the seconds are noise");
    let out = c.handle(Input::Reply { server, bytes: reply_to(&request, unix_at(5), 2) }, now(5, unix_at(5)));
    assert!(out.iter().any(|o| matches!(o, Output::Event(Event::Synced { .. }))), "{out:?}");
}

// responder.rs
#[test]
fn root_dispersion_ages_at_phi_since_the_last_sample() {
    let state = SyncState {
        synced: true, source: Some(ip("203.0.113.1")), stratum: 2, root_dispersion_ns: 5_000_000,
        last_sync_unix_secs: Some(1_793_448_000), ..SyncState::default()
    };
    let query = Packet { version: 4, mode: MODE_CLIENT, transmit: NtpTimestamp(0x1234_5678_9abc_def0), ..Packet::default() };
    let fresh = Packet::decode(&respond(&query.encode(), UNIX_2026, &state).unwrap()).unwrap();
    assert!((short_to_nanos(fresh.root_dispersion) - 6_000_000).abs() < 16_000, "5 ms + 1 ms own");
    let later = Packet::decode(&respond(&query.encode(), UNIX_2026 + 1_000 * NANOS_PER_SEC, &state).unwrap()).unwrap();
    assert!((short_to_nanos(later.root_dispersion) - 21_000_000).abs() < 16_000, "1000 s × 15 ppm = 15 ms more");
}
```

- [ ] **Step 2: Run `cargo test -q -p openfeo-proto-sntp`** — Expected: compile errors (`Unreachable`, `ServerUnsynced`, `PHI_PPM`); once stubbed, the non-pin tests fail on their assertions and the two pins pass.
- [ ] **Step 3: Implement items (a)–(f)**; `reply()` ends the request for `Unsynchronised`/`RootDistance` and calls `ask_next`; `handle(Input::Unreachable)` does the same without the event; `configure` recomputes `round_pos` from the pending server's index in the new list.
- [ ] **Step 4: Run `cargo test -q -p openfeo-proto-sntp`** — Expected: 26 passed, 1 ignored. **Clippy clean.**
- [ ] **Step 5: Commit**: `sntp: answers without time end the request and are said once, unreachable servers are not down, dispersion ages, 64-bit transmit noise, rounds survive a reconfiguration`

### Task 2: SNTP driver, clock, kernel option, documents

**Files:**
- Modify: `crates/openfeo-net/src/clock.rs`, `crates/openfeo-net/src/sys.rs`, `crates/openfeo-net/src/sntp.rs`, `crates/openfeo/src/time.rs`, `kernel/required.config`, `docs/adr/0016-clock-steering.md`
- Test: unit tests in `clock.rs` and `time.rs`; the sntp sandbox suite; `make kernel`

**Interfaces:**
- Consumes: Task 1's `Input::Unreachable`, `Event::ServerUnsynced`.
- Produces:

```rust
// clock.rs
pub trait Clock { .., /// `STA_UNSYNC` cleared (true) or set (false); the kernel keeps the RTC only while it is clear.
    fn set_synced(&self, synced: bool) -> io::Result<()>; }
impl Recording { pub fn synced_flags(&self) -> Vec<bool>; }
// sys.rs
/// `adjtimex(ADJ_STATUS | ADJ_MAXERROR | ADJ_ESTERROR)`: read the status (modes 0), write it back with
/// `STA_UNSYNC` cleared or set and `maxerror`/`esterror` reset (the kernel re-raises `STA_UNSYNC` when its own
/// `maxerror` passes 16 s, which it grows at 500 µs/s).
pub fn adjtimex_status(synced: bool) -> io::Result<()>;
```

Items: (a) the driver feeds `Input::Unreachable { server }` to the core when `try_send_to` fails (same step, after the throttled warn); (b) `Event::Synced` → `clock.set_synced(true)` (every sync; 17 minutes apart it is cheap and keeps the kernel's flag clear), `Event::LostSync` → `set_synced(false)`; a failure is logged through the existing clock-failure throttle; (c) `Event::ServerUnsynced(addr)` → console `time server {addr} has no time`; (d) one monotonic base: the poll deadline is `Instant::now() + (next_poll − clock.now().mono_ms)` instead of `start + next_poll`; (e) `CONFIG_RTC_SYSTOHC=y` after `CONFIG_RTC_HCTOSYS=y` in `kernel/required.config`; (f) ADR-0016 and the `adjtimex_slew` doc comment say whose bound the half second is: the kernel's single-shot path (`time_adjust`) takes any offset and corrects at 500 ppm (`MAX_TICKADJ`), glibc's `adjtime(3)` bounds it at ±2145 s, the PLL path (`ADJ_OFFSET`) clamps at `MAXPHASE` 500 ms, and ±500 ms is our own clamp because a half-second slew already takes 1000 s; and the RTC paragraph is corrected: `hctosys` reads whole seconds and sets the clock to the middle of one, so an RTC box arrives up to half a second off and most first syncs step (128 ms is RFC 5905's step threshold, kept because it is the standard, not because it spares a boot the step); Consequences add that the RTC is written back every 11 minutes once `STA_UNSYNC` is clear.

- [ ] **Step 1: Write the failing tests**

```rust
// clock.rs
#[test]
fn the_recording_clock_remembers_the_sync_flag() {
    let clock = Recording::new();
    clock.set_synced(true).unwrap();
    clock.set_synced(false).unwrap();
    assert_eq!(clock.synced_flags(), vec![true, false]);
}
// time.rs, in console_lines_follow_the_contract (or its sibling)
assert_eq!(event_line(&Event::ServerUnsynced(server)), Some("time server 203.0.113.1 has no time".to_owned()));
```

- [ ] **Step 2: Run `cargo test -q -p openfeo-net -p openfeo`** — Expected: compile errors; **implement (a)–(e); run again** — Expected: green.
- [ ] **Step 3: `make kernel`** — Expected: builds; `make kernel` verifies the required fragment against the resulting `.config`, so a refused `CONFIG_RTC_SYSTOHC=y` fails here.
- [ ] **Step 4: `cargo test -q -p openfeo-harness --test sntp`** — Expected: 6 passed. Add to the first-sync scenario: `recording.synced_flags().first() == Some(&true)`. **`make lint`.**
- [ ] **Step 5: Edit ADR-0016 and the `adjtimex_slew` doc as (f) says; commit**: `net, kernel: STA_UNSYNC follows the sync and RTC_SYSTOHC keeps the RTC, send failures are not down, one monotonic base; ADR-0016 says whose bound the half second is`

### Task 3: DNS core

**Files:**
- Modify: `crates/openfeo-proto-dns/src/name.rs`, `crates/openfeo-proto-dns/src/cache.rs`, `crates/openfeo-proto-dns/src/forwarder.rs`
- Test: unit tests in each (forwarder helpers `config()`, `q(name, qtype) -> Vec<u8>`, `client(id, transport, bytes) -> Input`, `reply(&out) -> Message`, `forwards(&out) -> Vec<(Ipv4Addr, Transport, Message)>`, `a`, `cname`, `upstream_answer(&fwd, &[Record]) -> Vec<u8>`, `ip`; cache helpers `key`, `answer(text, &[(rtype, ttl)])`, `nxdomain_with_soa(text, soa_ttl, minimum)`, `name`)

**Interfaces:**
- Produces (Task 4 consumes):

```rust
// forwarder.rs
pub enum Output { Reply { .. }, Forward { .. }, Event(Event),
    /// The query will never be answered (a response, or no header): the driver forgets the client.
    Drop { id: QueryId } }
// cache.rs
impl Cache { /// Evicts down to it. pub fn set_capacity(&mut self, capacity: usize); }
```

Items: (a) `Name`'s `Display` writes bytes outside `[A-Za-z0-9-_]` as RFC 1035 §5.1 `\DDD`, and `.`/`\` as `\.`/`\\`; (b) `reverse_addr` accepts an octet only as `0` or 1–3 decimal digits without a leading zero or sign; (c) `pick_upstream` returns `None` for an empty list before any modulo; (d) `is_internal_v4` also covers 100.64.0.0/10, 255.255.255.255 and every `lan_subnets` entry; (e) an upstream reply with rcode FORMERR, NOTIMP, REFUSED or SERVFAIL is a failed attempt: while `attempts < MAX_ATTEMPTS` and another upstream exists the query goes to the next one (no down mark), else the reply is relayed as today; (f) a timed-out TC→TCP retry marks nothing down (it fails over or SERVFAILs like any attempt); (g) `Output::Drop { id }` for a query the core will never answer, replacing the driver's pending-count heuristic; (h) `Configure` with a different `cache_capacity` calls `set_capacity`; (i) a negative entry keeps the response's answers (the CNAME chain) with TTLs capped at the negative TTL; (j) pins: qclass ANY local answer, SOA/NS/ANY at the apex, `MAX_PENDING` reached, `Configure` to no upstreams with queries pending.

- [ ] **Step 1: Write the failing tests**

```rust
// name.rs
#[test]
fn display_escapes_what_is_not_a_plain_label_byte() {
    let name = Name::from_labels(vec![b"a b".to_vec(), b"x\ny".to_vec(), b"c.d".to_vec(), b"ok-1".to_vec()]).unwrap();
    assert_eq!(name.to_string(), r"a\032b.x\010y.c\.d.ok-1.");
    assert_eq!("nas.home.arpa".parse::<Name>().unwrap().to_string(), "nas.home.arpa.");
}
#[test]
fn reverse_names_need_plain_decimal_octets() {
    assert_eq!(reverse_addr(&"10.1.168.192.in-addr.arpa".parse().unwrap()), Some(Ipv4Addr::new(192, 168, 1, 10)));
    assert_eq!(reverse_addr(&"0.1.168.192.in-addr.arpa".parse().unwrap()), Some(Ipv4Addr::new(192, 168, 1, 0)));
    for odd in ["010.1.168.192.in-addr.arpa", "+10.1.168.192.in-addr.arpa", "1.168.192.in-addr.arpa", "256.1.168.192.in-addr.arpa"] {
        assert_eq!(reverse_addr(&odd.parse().unwrap()), None, "{odd}");
    }
}
// cache.rs
#[test]
fn capacity_can_shrink_live_and_negative_entries_keep_their_cname_chain() {
    let mut cache = Cache::new(4);
    for i in 0..4u8 {
        let text = format!("h{i}.example");
        assert!(cache.store(key(&text, rtype::A), &answer(&text, &[(rtype::A, 60)]), 0));
    }
    cache.set_capacity(2);
    assert_eq!(cache.len(), 2);
    let mut nx = nxdomain_with_soa("alias.example", 3600, 60);
    nx.answers.push(Record { name: name("alias.example"), rtype: rtype::CNAME, class: CLASS_IN, ttl: 300, rdata: RData::Cname(name("gone.example")) });
    assert!(cache.store(key("alias.example", rtype::A), &nx, 0));
    let entry = cache.lookup(&key("alias.example", rtype::A), 1_000).unwrap();
    assert_eq!(entry.rcode, rcode::NXDOMAIN);
    assert_eq!(entry.answers.len(), 1, "the chain travels with the negative answer");
    assert_eq!(entry.answers[0].ttl, 59, "capped at the negative TTL and aged a second");
}
// forwarder.rs
#[test]
fn rebinding_covers_shared_space_broadcast_lan_subnets_and_the_wan_address() {
    let mut cfg = config();
    cfg.lan_subnets.push("198.18.0.0/15".parse().unwrap());   // a LAN numbered outside RFC 1918
    cfg.router_addrs.push(ip("203.0.113.10"));                // the WAN address, as Task 4 supplies it
    let mut f = Forwarder::new(cfg, 1);
    for (id, (name, addr)) in [("cgnat.isp.example", "100.64.1.2"), ("bcast.isp.example", "255.255.255.255"), ("lan.isp.example", "198.18.0.9"), ("wan.isp.example", "203.0.113.10")].into_iter().enumerate() {
        let out = f.handle(client(QueryId::try_from(id).unwrap() + 1, Transport::Udp, q(name, rtype::A)), 0);
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        let r = reply(&f.handle(Input::UpstreamReply { upstream, transport, bytes: upstream_answer(&fwd, &[a(name, 60, addr)]) }, 1));
        assert_eq!(r.header.rcode, rcode::REFUSED, "{name}");
    }
}
#[test]
fn an_upstream_error_fails_over_to_the_next_before_the_client_hears_it() {
    let mut cfg = config();
    cfg.upstreams = vec![ip("203.0.113.1"), ip("203.0.113.2")];
    let mut f = Forwarder::new(cfg, 1);
    let out = f.handle(client(1, Transport::Udp, q("www.isp.example", rtype::A)), 0);
    let (upstream, transport, fwd) = forwards(&out).remove(0);
    let out = f.handle(Input::UpstreamReply { upstream, transport, bytes: Message::reply_to(&fwd, rcode::REFUSED).encode() }, 10);
    assert!(!out.iter().any(|o| matches!(o, Output::Reply { .. })), "{out:?}");
    assert!(!out.contains(&Output::Event(Event::UpstreamDown(upstream))), "an answer is not a silence");
    let (second, transport, fwd) = forwards(&out).remove(0);
    assert_eq!(second, ip("203.0.113.2"));
    let r = reply(&f.handle(Input::UpstreamReply { upstream: second, transport, bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]) }, 20));
    assert_eq!(r.header.rcode, rcode::NOERROR);
    // Every upstream failing: the last answer is relayed.
    let out = f.handle(client(2, Transport::Udp, q("nope.isp.example", rtype::A)), 30);
    let (u1, t1, f1) = forwards(&out).remove(0);
    let out = f.handle(Input::UpstreamReply { upstream: u1, transport: t1, bytes: Message::reply_to(&f1, rcode::SERVFAIL).encode() }, 31);
    let (u2, t2, f2) = forwards(&out).remove(0);
    let r = reply(&f.handle(Input::UpstreamReply { upstream: u2, transport: t2, bytes: Message::reply_to(&f2, rcode::SERVFAIL).encode() }, 32));
    assert_eq!(r.header.rcode, rcode::SERVFAIL);
}
#[test]
fn a_tcp_retry_that_times_out_marks_nothing_down() {
    let mut f = Forwarder::new(config(), 1);
    let out = f.handle(client(1, Transport::Tcp, q("big.isp.example", rtype::TXT)), 0);
    let (upstream, _, fwd) = forwards(&out).remove(0);
    let mut tc = Message::decode(&upstream_answer(&fwd, &[])).unwrap();
    tc.header.truncated = true;
    f.handle(Input::UpstreamReply { upstream, transport: Transport::Udp, bytes: tc.encode() }, 10);
    let out = f.handle(Input::Timeout, 10 + UPSTREAM_TIMEOUT);
    assert!(!out.contains(&Output::Event(Event::UpstreamDown(upstream))), "{out:?}");
    assert_eq!(reply(&out).header.rcode, rcode::SERVFAIL, "one upstream: nothing else to try");
}
#[test]
fn queries_the_core_will_never_answer_are_dropped_explicitly() {
    let mut f = Forwarder::new(config(), 1);
    let mut response = Message::decode(&q("www.isp.example", rtype::A)).unwrap();
    response.header.response = true;
    assert_eq!(f.handle(client(7, Transport::Udp, response.encode()), 0), vec![Output::Drop { id: 7 }]);
    assert_eq!(f.handle(client(8, Transport::Udp, vec![1, 2, 3]), 0), vec![Output::Drop { id: 8 }], "no header at all");
}
/// Pins, unless one fails: then it is a finding and a fix in this task.
#[test]
fn apex_and_any_queries_are_answered_locally_and_full_queues_servfail() {
    let mut f = Forwarder::new(config(), 1);
    let r = reply(&f.handle(client(1, Transport::Udp, q("home.arpa", rtype::SOA)), 0));
    assert_eq!((r.header.authoritative, r.answers.len(), r.answers[0].rtype), (true, 1, rtype::SOA));
    let r = reply(&f.handle(client(2, Transport::Udp, q("home.arpa", rtype::NS)), 0));
    assert_eq!((r.header.rcode, r.answers.len(), r.authorities[0].rtype), (rcode::NOERROR, 0, rtype::SOA), "NODATA with the SOA");
    let r = reply(&f.handle(client(3, Transport::Udp, q("nas.home.arpa", rtype::ANY)), 0));
    assert_eq!(r.answers[0].rdata, RData::A(ip("192.168.1.10")));
    let mut any_class = Message::decode(&q("nas.home.arpa", rtype::A)).unwrap();
    any_class.questions[0].qclass = CLASS_ANY;
    assert_eq!(reply(&f.handle(client(4, Transport::Udp, any_class.encode()), 0)).answers[0].rdata, RData::A(ip("192.168.1.10")));
    for i in 0..MAX_PENDING {
        f.handle(client(100 + QueryId::try_from(i).unwrap(), Transport::Udp, q(&format!("h{i}.isp.example"), rtype::A)), 1);
    }
    assert_eq!(reply(&f.handle(client(9_999, Transport::Udp, q("one-more.isp.example", rtype::A)), 2)).header.rcode, rcode::SERVFAIL);
    let out = f.handle(Input::Configure(Config { upstreams: vec![], ..config() }), 3);
    assert_eq!(out.iter().filter(|o| matches!(o, Output::Reply { .. })).count(), MAX_PENDING, "every pending query gets SERVFAIL");
}
```

- [ ] **Step 2: Run `cargo test -q -p openfeo-proto-dns`** — Expected: compile errors (`Drop`, `set_capacity`), then assertion failures for (a)–(i); the pin passes or becomes a finding.
- [ ] **Step 3: Implement (a)–(i); run `cargo test -q -p openfeo-proto-dns`** — Expected: green. **`cd fuzz && cargo +nightly fuzz run dns_forwarder -- -max_total_time=30` and `dns_message`** — Expected: no crash.
- [ ] **Step 4: Commit**: `dns: escaped names on the console, strict reverse octets, failover on upstream errors, no down mark for a TCP retry, explicit drops, live cache capacity, negative answers keep their chain, wider rebinding ranges`

### Task 4: DNS glue: driver, reconcile, validation

**Files:**
- Modify: `crates/openfeo-net/src/dns.rs` (`Output::Drop { id }` → `self.clients.remove(&id)`; the `pending_before` heuristic at ~l.224 goes), `crates/openfeo-reconcile/src/dns.rs` (`router_addrs` also carries the active WAN's address: a static WAN's `address` or the DHCP lease's; snapshots re-accepted), `crates/openfeo-config/src/validate.rs` (`dns.upstreams[i]`: `InvalidAddress` also for loopback, multicast, unspecified, broadcast, 0.0.0.0/8 and a LAN's own router address, with a message saying which)
- Test: `reconcile::dns` and `validate` unit tests (the dns test module's `live()`/`codes()`/`file::parse`); the dns sandbox suite

**Interfaces:**
- Consumes: Task 3's `Output::Drop`.

- [ ] **Step 1: Write the failing tests**

```rust
// reconcile dns.rs
#[test]
fn the_wan_address_is_never_a_valid_answer() {
    let d = desired(&fixtures::static_world());
    assert!(d.router_addrs.contains(&Ipv4Addr::new(203, 0, 113, 10)), "{:?}", d.router_addrs);
    let d = desired(&fixtures::dhcp_world());
    assert!(d.router_addrs.contains(&Ipv4Addr::new(203, 0, 113, 100)), "{:?}", d.router_addrs);
    assert!(!desired(&fixtures::dhcp_world_without_lease()).router_addrs.contains(&Ipv4Addr::new(203, 0, 113, 100)));
}
// validate.rs (dns module)
#[test]
fn local_addresses_are_not_upstreams() {
    for bad in ["127.0.0.1", "224.0.0.251", "0.0.0.0", "0.1.2.3", "255.255.255.255", "192.168.1.1"] {
        let config = file::parse(&format!("config_version = 1\n[[lans]]\nname = \"lan0\"\nports = [\"p0\"]\nipv4 = \"192.168.1.1/24\"\n[dns]\nupstreams = [\"{bad}\"]\n")).unwrap();
        assert_eq!(codes(&validate(&config, &live())), vec![("dns.upstreams[0]".to_owned(), Code::InvalidAddress)], "{bad}");
    }
    let fine = file::parse("config_version = 1\n[[lans]]\nname = \"lan0\"\nports = [\"p0\"]\nipv4 = \"192.168.1.1/24\"\n[dns]\nupstreams = [\"192.168.1.53\"]\n").unwrap();
    assert_eq!(codes(&validate(&fine, &live())), vec![], "a resolver on the LAN is fine; the router itself is not");
}
```

- [ ] **Step 2: Run them, watch them fail; implement; `INSTA_UPDATE=always cargo test -q -p openfeo-reconcile -p openfeo-config -p openfeo-net`** (review the snapshot diff: only `router_addrs` grows) **; `cargo test -q -p openfeo-harness --test dns`** — Expected: 12 passed **; `make lint`**
- [ ] **Step 3: Commit**: `dns: the WAN address joins the rebinding guard, local addresses are refused as upstreams, the driver drops what the core drops`

### Task 5: DHCPv4 server, its task and validation

**Files:**
- Modify: `crates/openfeo-proto-dhcp4/src/server.rs`, `crates/openfeo/src/dhcp4_server.rs`, `crates/openfeo-config/src/validate.rs`, `crates/openfeo-config/Cargo.toml` (dep `openfeo-proto-dhcp4`)
- Test: unit tests in each (server helpers `config()`, `discover(mac, xid, options) -> Vec<u8>`, `request(mac, xid, ciaddr, options) -> Vec<u8>`, `sends(&out) -> Vec<(Destination, Message)>`, `events(&out)`, `offered(&mut s, mac, now) -> Ipv4Addr`, `MAC_A`, `MAC_NAS`, `MAC_SQUATTER`, `ip`); the dhcp4_server sandbox suite

**Interfaces:**
- Produces:

```rust
// server.rs
pub enum ServerEvent { ..,
    /// A reservation's address answered the probe from another host; the client gets no offer.
    ReservationInUse { address: Ipv4Addr, mac: [u8; 6], by: [u8; 6] } }
// MIN_LEASE_SECS and MAX_LABEL are already pub here; validate.rs stops duplicating them.
// dhcp4_server.rs
/// The records that fit, and one line per entry dropped saying why.
pub fn records_from_file(file: &Dhcp4ServerLeases, lan: &str, now: Timestamp, unix_now: u64) -> (Vec<LeaseRecord>, Vec<String>);
```

Items: (a) when the probes of a *reserved* address run out, `ReservationInUse { address, mac: the client, by: the last answering host }` instead of `Exhausted`; console `lan lan0 dhcp reservation 192.168.1.10 for 52:54:00:fe:10:10 in use by 02:00:00:00:00:99` (throttled like `conflict`); (b) `Offer.discover` keeps only what `reply()`, `destination()` and `requested_address()` read: the header fields, options 50 and 61; `sname`/`file` zeroed and every other option dropped (a refactor under the existing tests plus the pin below); (c) a REQUEST carrying our server identifier and a `ciaddr` but no option 50 is a renewal of `ciaddr`; (d) an empty option 61 is not echoed; (e) `records_from_file` reports what it dropped and the task logs each as `lan {lan} dhcp ignoring lease {address}: {why}`; (f) the task saves the lease database before returning the bridge-index error when a save is pending; (g) `validate.rs` takes `MIN_LEASE_SECS` and `MAX_LABEL` from `openfeo_proto_dhcp4::server` (its own consts go); (h) duplicate static hostnames within one LAN (case-insensitive) are `DuplicateStatic` on the later entry's `hostname`.

- [ ] **Step 1: Write the failing tests**

```rust
// server.rs
#[test]
fn a_squatted_reservation_is_reported_as_in_use_not_exhausted() {
    let mut s = Server::new(config(), vec![], 0);
    s.handle(Input::Packet(discover(MAC_NAS, 1, vec![])), 0);
    let mut out = Vec::new();
    for i in 0..MAX_PROBES {
        out = s.handle(Input::ProbeReply { address: ip("192.168.1.10"), mac: MAC_SQUATTER }, Timestamp::from(i));
    }
    assert!(events(&out).contains(&ServerEvent::ReservationInUse { address: ip("192.168.1.10"), mac: MAC_NAS, by: MAC_SQUATTER }), "{out:?}");
    assert!(!events(&out).iter().any(|e| matches!(e, ServerEvent::Exhausted { .. })));
}
#[test]
fn a_renewing_request_with_our_server_id_and_ciaddr_is_acknowledged() {
    let mut s = Server::new(config(), vec![], 0);
    let address = offered(&mut s, MAC_A, 0);
    s.handle(Input::Packet(request(MAC_A, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::ServerIdentifier(ip("192.168.1.1")), DhcpOption::RequestedIpAddress(address)])), 2);
    let out = s.handle(Input::Packet(request(MAC_A, 2, address, vec![DhcpOption::ServerIdentifier(ip("192.168.1.1"))])), 100);
    assert_eq!(sends(&out)[0].1.message_type(), Some(MessageType::Ack), "{out:?}");
}
#[test]
fn an_empty_client_identifier_is_not_echoed() {
    let mut s = Server::new(config(), vec![], 0);
    s.handle(Input::Packet(discover(MAC_A, 1, vec![DhcpOption::ClientIdentifier(vec![])])), 0);
    let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.option(61), None, "{out:?}");
}
/// Pin for item (b): what a slimmed offer must still carry.
#[test]
fn offers_keep_the_requested_address_and_the_client_identifier() {
    let mut s = Server::new(config(), vec![], 0);
    let id = vec![0xff, 1, 2, 3, 4];
    s.handle(Input::Packet(discover(MAC_A, 1, vec![DhcpOption::ClientIdentifier(id.clone()), DhcpOption::RequestedIpAddress(ip("192.168.1.150")), DhcpOption::Unknown { code: 43, data: vec![1; 200] }])), 0);
    let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
    let offer = &sends(&out)[0].1;
    assert_eq!((offer.yiaddr, offer.option(61)), (ip("192.168.1.150"), Some(&DhcpOption::ClientIdentifier(id))));
}
// dhcp4_server.rs
#[test]
fn dropped_lease_entries_are_reported() {
    let lease = |mac: &str, address: &str, expires_unix| Dhcp4ServerLease { mac: mac.into(), address: address.into(), expires_unix, ..Default::default() };
    let file = Dhcp4ServerLeases { lan: "lan0".into(), leases: vec![lease("nope", "192.168.1.12", 1_800_009_000), lease("52:54:00:fe:10:13", "192.168.1.113", 1_800_000_000)] };
    let (records, dropped) = records_from_file(&file, "lan0", 50, 1_800_000_100);
    assert_eq!(records, Vec::new());
    assert_eq!(dropped.len(), 2, "{dropped:?}");
    assert!(dropped[0].contains("192.168.1.12") && dropped[1].contains("expired"), "{dropped:?}");
}
// validate.rs (dhcp module)
#[test]
fn duplicate_static_hostnames_are_refused() {
    let bad = format!("{RANGE}[[lans.dhcp.static]]\nmac = \"52:54:00:fe:10:10\"\nip = \"192.168.1.10\"\nhostname = \"nas\"\n[[lans.dhcp.static]]\nmac = \"52:54:00:fe:10:11\"\nip = \"192.168.1.11\"\nhostname = \"NAS\"\n");
    assert_eq!(codes(&validate(&with_dhcp(&bad), &live())), vec![("lans[0].dhcp.static[1].hostname".to_owned(), Code::DuplicateStatic)]);
}
```

- [ ] **Step 2: Run `cargo test -q -p openfeo-proto-dhcp4 -p openfeo-config -p openfeo`** — Expected: compile errors, then assertion failures; the pin passes. **Implement (a)–(h)**; the `records_from_file` callers (`read_leases`, three tests) take the tuple; `console_lines_follow_the_contract` gains the new line; `three_conflicts_exhaust_one_discover` keeps `Exhausted` (a pool address). **Run again** — Expected: green.
- [ ] **Step 3: `cargo test -q -p openfeo-harness --test dhcp4_server`** — Expected: 10 passed. **`cd fuzz && cargo +nightly fuzz run dhcp4_server -- -max_total_time=30`; `make lint`** (check-deps: config → proto-dhcp4 is pure → pure).
- [ ] **Step 4: Commit**: `dhcp4 server: a squatted reservation is named, renewals with our id and ciaddr acknowledged, no empty client-id echo, slimmer offers, dropped lease entries logged, a save before exit, one copy of the constants, duplicate hostnames refused`

### Task 6: DHCPv4 client, its tasks, the driver, the links reconciler

**Files:**
- Modify: `crates/openfeo-proto-dhcp4/src/client.rs`, `crates/openfeo-proto-dhcp4/Cargo.toml` and the root `Cargo.toml` (drop `proptest`; `Cargo.lock` follows), `crates/openfeo-net/src/dhcp4.rs` (one receive buffer in the driver struct instead of `vec![0u8; RECEIVE_BUFFER]` per step, l.179), `crates/openfeo/src/dhcp4.rs` and `crates/openfeo/src/dhcp4_server.rs` (`save_lease`/`save_leases` write through `tokio::task::spawn_blocking`, awaited, errors logged as today), `crates/openfeo-reconcile/src/links.rs` (`pub const DEFAULT_MTU: u32 = 1500;` a DHCP WAN port without a lease MTU gets `Some(DEFAULT_MTU)`, so a lease's MTU is undone when the lease goes; snapshots re-accepted)
- Test: unit tests in `client.rs` (helpers `client()`, `bound() -> (Client, Lease)`, `sent(&out) -> (src, dst, Message)`, `reply(&request, MessageType, options) -> Vec<u8>` with `yiaddr = OFFERED`, `lease_options()`, `has(&out, pred)`, `SEC`) and `links.rs`; the dhcp4 sandbox suite; `make test-harness FILTER=dhcp`

Items: (a) an ACK in RENEWING or REBINDING whose `yiaddr` differs from the bound address is ignored (the lease stays; a server that insists gets its way at expiry); (b) a reply carrying option 61 that differs from ours is ignored (RFC 6842; the equal case is `echoed_client_id_in_replies_is_accepted`); (c) the BOUND→RENEWING and RENEWING→REBINDING transitions take a fresh `xid` (retransmissions keep it); (d) `MAX_REQUEST_SENDS` 3 → 4: four REQUESTs over 4+8+16+32 s, about a minute, before REQUESTING or REBOOTING gives up, because a cable modem's CMTS relay can take 30 s after link-up to answer; (e) `LinkUp` with a lease whose expiry has passed emits `Unbound(Expired)` and discovers instead of rebooting; (f) `DEFAULT_MTU` as above.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_renewal_ack_for_another_address_is_ignored() {
    let (mut c, lease) = bound();
    let at = SEC + Timestamp::from(lease.t1_secs) * SEC;
    let out = c.handle(Input::Timeout, at);
    let (_, _, request) = sent(&out);
    let mut other = Message::decode(&reply(&request, MessageType::Ack, lease_options())).unwrap();
    other.yiaddr = Ipv4Addr::new(203, 0, 113, 77);
    let out = c.handle(Input::Packet(other.encode()), at + 1);
    assert_eq!(out, Vec::new());
    assert_eq!((c.state(), c.lease().map(|l| l.address)), (State::Renewing, Some(lease.address)));
}
#[test]
fn a_reply_echoing_another_client_identifier_is_ignored() {
    let mut c = client();
    let out = c.handle(Input::Start { lease: None }, 0);
    let (_, _, discover) = sent(&out);
    let mut offer = Message::decode(&reply(&discover, MessageType::Offer, lease_options())).unwrap();
    offer.options.push(DhcpOption::ClientIdentifier(vec![0xff, 9, 9, 9, 9]));
    assert_eq!(c.handle(Input::Packet(offer.encode()), 1), Vec::new());
    assert_eq!(c.state(), State::Selecting);
}
#[test]
fn renewing_and_rebinding_take_fresh_transaction_ids() {
    let mut c = client();
    let out = c.handle(Input::Start { lease: None }, 0);
    let (_, _, discover) = sent(&out);
    let out = c.handle(Input::Packet(reply(&discover, MessageType::Offer, lease_options())), 500);
    let (_, _, request) = sent(&out);
    assert_eq!(request.xid, discover.xid, "one transaction from DISCOVER to ACK");
    c.handle(Input::Packet(reply(&request, MessageType::Ack, lease_options())), SEC);
    let out = c.handle(Input::Timeout, SEC + 20 * SEC);
    let (_, _, renew) = sent(&out);
    assert_ne!(renew.xid, request.xid);
    let out = c.handle(Input::Timeout, SEC + 40 * SEC);
    let (_, _, rebind) = sent(&out);
    assert_ne!(rebind.xid, renew.xid);
}
#[test]
fn a_lease_expired_while_the_link_was_down_discovers_on_link_up() {
    let (mut c, lease) = bound();
    c.handle(Input::LinkDown, 10 * SEC);
    let out = c.handle(Input::LinkUp, SEC + (Timestamp::from(lease.lease_secs) + 1) * SEC);
    assert!(out.contains(&Output::Unbound(Unbound::Expired)), "{out:?}");
    assert!(has(&out, |o| matches!(o, Output::Discover)));
    assert_eq!((c.state(), c.lease()), (State::Selecting, None));
}
// Existing tests changed, not added: `requesting_gives_up_after_three_sends_and_discovers_again` and
// `reboot_times_out_after_three_sends_then_discovers` become `..._four_sends_...`: the retransmit loop
// runs `0..3`, and the reboot test also asserts the last timeout is 60 s ± JITTER after the start.
// links.rs: `dhcp_wan_port_takes_the_lease_mtu` asserts `before.ports["p0"].mtu == Some(DEFAULT_MTU)`
// ("no lease: the default, so a lease's MTU is undone") instead of `None`.
```

- [ ] **Step 2: Run `cargo test -q -p openfeo-proto-dhcp4 -p openfeo-reconcile`** — Expected: the four new tests and the three changed ones fail on their assertions. **Implement (a)–(f) and the buffer/spawn_blocking items; run `cargo test -q -p openfeo-proto-dhcp4 -p openfeo-reconcile -p openfeo-net -p openfeo`** (`INSTA_UPDATE=always` for the links snapshot; review it) — Expected: green.
- [ ] **Step 3: `cargo test -q -p openfeo-harness --test dhcp4 --test dhcp4_server`** — Expected: 5 and 10 passed. **`make test-harness FILTER=dhcp`** — Expected: the dhcp scenarios of `m1` pass. **`cd fuzz && cargo +nightly fuzz run dhcp4_message -- -max_total_time=30`; `make lint`** (cargo-deny sees proptest gone).
- [ ] **Step 4: Commit**: `dhcp4 client: a changed address or a foreign client-id in a reply is ignored, fresh xids on renew, a minute before giving up a reboot, an expired lease discovers on link up; links: a lease MTU is undone; lease files written off the runtime`

### Task 7: PID 1

**Files:**
- Modify: `crates/openfeo-init/src/lib.rs` (`pub(crate) mod sys;` keeping its `#[allow(unsafe_code)]`; `read_cmdline` logs each `cmdline.warnings` line), `crates/openfeo-init/src/cmdline.rs` (`parse(s: &str) -> Cmdline`, infallible: an unknown `openfeo.mode` or `openfeo.slot` leaves that field `None` and pushes the `Error`'s text onto `pub warnings: Vec<String>`; `Error` stays for the two `FromStr` impls), `crates/openfeo-init/src/watchdog.rs` (`Hardware` gains `set_error: Option<String>`, the error when `wdt_set_timeout` failed; `describe()` appends ` (driver's; setting 60s failed: {err})` when set)
- Test: unit tests in `cmdline.rs` and `watchdog.rs`

- [ ] **Step 1: Write the failing tests**

```rust
// cmdline.rs: `unknown_mode_is_an_error` and `unknown_slot_is_an_error` become these two
#[test]
fn an_unknown_mode_is_a_warning_and_the_slot_survives() {
    let c = parse("openfeo.mode=weird openfeo.slot=b");
    assert_eq!((c.mode, c.slot), (None, Some(Slot::B)));
    assert_eq!(c.warnings, vec!["unknown openfeo.mode `weird` (expected metal, vm, container, installer or rescue)".to_owned()]);
}
#[test]
fn an_unknown_slot_is_a_warning_and_the_mode_survives() {
    let c = parse("openfeo.mode=vm openfeo.slot=c");
    assert_eq!((c.mode, c.slot), (Some(Mode::Vm), None));
    assert_eq!(c.warnings, vec!["unknown openfeo.slot `c` (expected a or b)".to_owned()]);
}
// watchdog.rs
#[test]
fn describe_says_when_the_driver_kept_its_own_timeout() {
    let wd = Watchdog::Hardware { dev: File::open("/dev/null").unwrap(), timeout: 30, identity: "iTCO_wdt".to_owned(), set_error: Some("EINVAL".to_owned()) };
    assert_eq!(wd.describe(), "/dev/watchdog0 timeout=30s identity=\"iTCO_wdt\" (driver's; setting 60s failed: EINVAL)");
}
```

- [ ] **Step 2: Run `cargo test -q -p openfeo-init`** — Expected: compile errors (`parse` returns `Result`, no `warnings`, no `set_error`). **Implement; run `cargo test -q -p openfeo-init -p openfeo`** — Expected: green (the other `parse(..).unwrap()` call sites in the tests lose their `unwrap`).
- [ ] **Step 3: `make kernel`** (the binary is embedded) **; `make test-harness FILTER=m0`** — Expected: 5 passed (`WATCHDOG_LINE` still matches: the VM's i6300ESB takes 60 s).
- [ ] **Step 4: Commit**: `init: sys is crate-private, a kept watchdog timeout is said, an unknown mode or slot is a warning that spares the other`

### Task 8: Whole-tree verification and notes

- [ ] **Step 1: `make ci`** — Expected: green. Scenario counts: dhcp4 5, dhcp4_server 10, dns 12, sntp 6, m0 5, m1 26, netlink 17, nft 5 (on this host one netlink and one nft scenario skip for the missing nft modules; CI's `OPENFEO_NO_SKIP=1` runs them).
- [ ] **Step 2: Docs**: `docs/third-party.md` unchanged (proptest was never listed); README and `CLAUDE.md` unchanged.
- [ ] **Step 3: Nothing left to commit; the whole-branch review follows.**

---

## Self-review notes

- Coverage: every item of the inventory is in a task or named under "Left out, and why".
- Type consistency: `Output::Drop { id: QueryId }` (Task 3) is what Task 4's driver matches; `Input::Unreachable { server }` and `Event::ServerUnsynced(Ipv4Addr)` (Task 1) are what Task 2's driver and task use; `Clock::set_synced` (Task 2) is implemented by both clocks; `ServerEvent::ReservationInUse` and the new `records_from_file` shape (Task 5) are internal to that task; `DEFAULT_MTU` (Task 6) and `Cmdline.warnings` (Task 7) are internal.
- Review Focus: lines 1 and 2 → Task 3, line 3 → Task 1, line 4 → Task 6, line 5 → Task 5.
- Pins are named as such (Task 1: two; Task 3: one; Task 5: one), so a pass at once is the expected result, not a finding about the test.
- Proportion: tests and signatures only; the prose decides the policies (failover rcodes, PHI ageing, the four sends, the infallible command line).
