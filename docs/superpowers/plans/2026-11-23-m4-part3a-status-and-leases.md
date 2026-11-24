# M4 part 3a: status and leases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The dashboard opens with the last hour of each WAN drawn and the newest leases listed,
and a Leases page shows every device that took an address, newest first, with Reserve.

**Architecture:** The DHCPv4 server's core keeps when each lease's device first took its
address, the driver writes it to the lease file and publishes it as a fact, and a pure function
of the World turns the facts into a table that the API serves as a call and a coalesced topic.
The telemetry task reads the counters every second whether or not anyone watches and keeps an
hour of them in memory, served by a call. The client gains the calls and plain functions from
samples to rates over time; `@openfeo/ui` gains a chart, a segmented choice and an empty state;
the panel's live store, dashboard and a new Leases page join them.

**Tech Stack:** Rust (prost, tonic, axum, tokio), protobuf, TypeScript 6, Vue 3.5, vitest 5,
Playwright, the QEMU harness.

**Spec:** `docs/superpowers/specs/2026-11-23-m4-part3-remaining-pages-design.md` ("Part 3a",
"Proven", "SPEC amendments", "Calls made for the maintainer"). The milestone's rules are in
`docs/superpowers/specs/2026-11-10-m4-api-and-panel-design.md`.

## Global Constraints

- Branch `m4-3a`. Commits are `git commit -s` as the repository's identity, subject
  `<area>: <summary>`. Nothing is pushed and no pull request is opened but on the maintainer's
  word; the branch is swept before any push.
- `clippy -D warnings`, pedantic as warnings. No `unwrap`/`expect` outside tests. `thiserror` in
  libraries. No `std::process::Command` outside `harness/`.
- `openfeo-proto-dhcp4`, `openfeo-reconcile` and `openfeo-world` stay pure: no tokio, libc, nix
  or socket2 in their trees (`scripts/check-deps.sh`).
- Every source file starts with `SPDX-License-Identifier: GPL-2.0-or-later` and
  `Copyright (C) 2026 Andrew Newton`.
- No password, token or hash reaches a log line, an error or a `Debug` output.
- `web/client` imports no Vue and uses no DOM beyond `fetch` and `WebSocket`; `web/ui` knows
  nothing of the API; `web/panel` reaches protobuf only through `@openfeo/client` and holds no
  CSS beyond page layout. The page's content security policy allows no inline script, no
  `style` attribute and no `data:` URL.
- The design system's copies under `web/ui` (`tokens.json`, `ofo.css`, fonts, logos, `docs/`)
  are not edited. What they lack goes in `web/ui/additions.css` and is said in
  `web/ui/docs/gaps.md`.
- Addresses in tests and fixtures are documentation ranges (RFC 5737, RFC 3849) or the RFC 1918
  ranges the fixtures already use; hardware addresses are locally administered (`02:00:00:…`)
  or QEMU's (`52:54:00:…`).
- No new config field, and no new plain HTTP call: the new calls are on the WebSocket and on
  gRPC.
- A table of leases holds at most 4096. The history is one hour at one second. A frame is at
  most 1 MiB.
- Rust commands need `OPENFEO_NFT_SRC=$PWD/build/nft/src` and
  `OPENFEO_UAPI_INCLUDE=$PWD/build/kernel/headers/include` (the `make` targets set them).
  A harness scenario is `make test-harness FILTER=<name>` after `make kernel`.

## Review Focus

What the design implies and a person will meet, most likely first. Each has its test in the
task that owns the code.

1. **A browser whose clock is wrong.** Ages on the Leases page and the dashboard are counted
   against the router's clock (`Leases.time_unix`, carried on by the time since it arrived),
   never against the browser's. Test in Task 9 (`ages are counted on the router's clock`).
2. **The router restarts under an open page.** Its boot clock starts again, so the samples the
   page kept are of another boot. They are dropped, and the chart starts from the new history.
   Test in Task 10 (`samples of an earlier boot are dropped`).
3. **The socket is lost and comes back.** The history is asked for again and joined to what
   was kept, with no sample twice and the time away filled from the router. Test in Task 10
   (`a reconnect fills the time away and repeats nothing`).
4. **A joined time ahead of the clock** (a file written under a right clock, read under the
   build's). It reads "just now", never a negative age. Test in Task 9 (`a time ahead of the
   clock is just now`).
5. **Reserve pressed twice, or a filter of `.*`.** The draft holds one reservation, and the
   filter is plain text, not a pattern. Tests in Task 9 (`reserving twice adds one`, `the
   filter is text, not a pattern`).

---

## File Structure

| File | Responsibility |
|---|---|
| `SPEC.md` | §7.6, §8.3, §8.4, §10, §12 as amended |
| `proto/openfeo/v1/config.proto` | `Dhcp4ServerLease.joined_unix` |
| `proto/openfeo/v1/state.proto` | `Lease`, `Leases`, `LinkHistory` |
| `proto/openfeo/v1/api.proto` | `GetLeases`, `GetHistory`, the `leases` push |
| `crates/openfeo-proto-dhcp4/src/server.rs` | `Joined`, kept by the core |
| `crates/openfeo/src/dhcp4_server.rs` | file and fact conversions, the steady wall clock |
| `crates/openfeo-world/src/leases.rs` | `LeaseFact.joined_unix` |
| `crates/openfeo-reconcile/src/leases.rs` (new) | the table from the World |
| `crates/openfeo-api/src/{envelope,ws,grpc,server,limits}.rs` | topic, calls |
| `crates/openfeo-api/src/telemetry.rs` | always reading; the hour |
| `harness/src/apiclient.rs`, `harness/tests/m4.rs` | the Rust client's calls, scenarios, the `join` verb |
| `web/client/src/history.ts` (new) | samples to rates over time, bucket averages |
| `web/client/src/{router,socket,messages,index}.ts` | calls, topic, exports |
| `web/ui/src/chart.ts` (new) | the chart's geometry, pure |
| `web/ui/src/components/{OfoChart,OfoSegmented,OfoEmpty}.vue` (new) | the three components |
| `web/ui/src/components/{OfoStatTile,OfoDataTable}.vue` | foot beside a sparkline; a row's key and class |
| `web/panel/src/model/leases.ts` (new) | order, filter, ages, Reserve |
| `web/panel/src/model/chart.ts` (new) | series, peak, markers, ticks |
| `web/panel/src/live.ts` | leases, samples, events kept |
| `web/panel/src/pages/Dashboard.vue`, `pages/Leases.vue` (new) | the pages |
| `web/panel/e2e/leases.spec.ts` (new) | the browser run |

---

### Task 1: SPEC amendments

**Files:**
- Modify: `SPEC.md` (§7.6, §8.3, §8.4, §10, §12)

- [ ] **Step 1: Amend the five places.**

  - **§7.6**, appended to its paragraph: "Each lease records when its device first took the
    address it holds (its joined time). A renewal keeps it, and so does a device that asks
    again for the address it still holds; a lease that ran out or was released and is taken
    again, or a device moved to another address, has joined anew. The joined time is in the
    lease database and in the published fact."
  - **§8.3**, a new bullet after "Topics in M4 part 1": "M4 part 3a: `StateService` gains
    `GetLeases` (every LAN's DHCPv4 leases, at most 4096, the newest by joined time when there
    are more, with the router's clock) and `GetHistory` (the last hour of the named links'
    byte counters, at most eight links a call); and the topic `leases`: the whole table when
    subscribed and whenever a lease in it changes, coalesced as `state` is."
  - **§8.4**: in the navigation sentence, `LAN & DHCP, Firewall` becomes
    `LAN & DHCP, Leases, Firewall`. A new paragraph after "How the panel changes config":
    "Status and leases (M4 part 3a): the dashboard draws each WAN's download and upload for
    the last five minutes or the last hour, marks where the WAN came back, says the hour's
    peak, and lists the five newest leases. Leases is a page of its own: every LAN's leases,
    newest first, filtered by name, address or MAC, with ages counted on the router's clock;
    Reserve on a row adds a reservation to the draft."
  - **§10**: "Interface counters and the conntrack count are read once a second and only while
    a subscriber wants them; the router keeps no history and computes no rates." becomes
    "Interface counters and the conntrack count are read once a second. The last hour of each
    link's byte counters is kept in memory, so that a chart opens with it; nothing else is
    kept, and the router computes no rates."
  - **§12**, M4 row: "Part 3: the remaining pages (firewall, DNS, leases, routes, ports, logs,
    system)." becomes "Part 3 (the remaining pages, in three slices, each with its router
    work): 3a status and leases (the joined time of a lease, leases and an hour of counters
    over the API, the dashboard's chart and newest leases, the Leases page); 3b the settings
    pages (Firewall, DNS, System, restarting); 3c the views (Routes, Ports, Logs)." In the
    proof column, before "Part 4:": "Part 3: Playwright: a device that joins appears on the
    dashboard and on Leases without reloading, and the chart is drawn back to before the page
    was opened (3a); a port forward is added, applied and confirmed, and Restart ends at the
    login screen (3b); the ISP is cut and its log line appears without reloading (3c)."

- [ ] **Step 2: Commit.** `spec: the joined time, leases and an hour of counters over the API (M4 part 3a)`

---

### Task 2: The joined time in the server's core

**Files:**
- Modify: `crates/openfeo-proto-dhcp4/src/server.rs`
- Modify (constructors only): every other place that builds a `LeaseRecord`
  (`crates/openfeo-net`, `crates/openfeo/src/dhcp4_server.rs`, `harness/`, `fuzz/`)

**Interfaces:**
- Produces:

```rust
/// When a lease's device first took the address it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Joined {
    /// Before this server started: the wall-clock time a lease file gave, kept as written.
    Unix(u64),
    /// While this server ran: on its own clock, like every other time in the record.
    At(Timestamp),
}

pub struct LeaseRecord { /* as now, and: */ pub joined: Joined }
```

- [ ] **Step 1: Write the failing tests** in `server.rs`'s test module, with the helpers the
  neighbouring tests use:

  - `a_renewal_keeps_the_joined_time`: a client is granted at 3 (`joined == Joined::At(3)`),
    renews at 21 603 by `ciaddr`: the event is `Renewed`, `granted_at == 21_603`,
    `joined == Joined::At(3)`.
  - `a_fresh_ask_for_the_address_still_held_keeps_the_joined_time`: granted at 3; at 100 the
    same client sends DISCOVER and REQUEST again and is given the same address, and then at
    200 an INIT-REBOOT REQUEST for it: both end `Renewed` with `Joined::At(3)`.
  - `a_lease_taken_again_after_it_ran_out_has_joined_anew`: granted at 3, expired by a
    `Timeout`, granted again at `t`: `Granted` with `Joined::At(t)`.
  - `a_client_moved_to_another_address_has_joined_anew`: a client holding one address is
    acknowledged on another at `t`: `Granted` with `Joined::At(t)`.
  - `a_restored_lease_keeps_what_its_file_gave`: `Server::new` with a record whose `joined` is
    `Joined::Unix(1_700_000_000)` keeps it, and keeps it through a renewal; a record with
    `Joined::At(50)` restored at `now == 10` has `Joined::At(10)`.

- [ ] **Step 2: Run them.** `cargo test -p openfeo-proto-dhcp4 joined` fails to compile: no
  `Joined`.

- [ ] **Step 3: Implement.** `ack` gives `previous_lease`'s `joined` when the address is the
  one it held, `Joined::At(now)` otherwise. `Server::new` caps `At(t)` at `now` as it caps
  `granted_at`, and leaves `Unix` alone. Every other constructor in the workspace gets a
  `joined`: `Joined::At(<its granted_at>)` in tests, and in the driver's `record_from`
  `Joined::Unix(lease.granted_unix)` until Task 3.

- [ ] **Step 4: Run.** `cargo test -p openfeo-proto-dhcp4` and `cargo test --workspace` pass;
  `cargo fuzz build` (or `make lint`'s check of the fuzz crate) still builds.

- [ ] **Step 5: Commit.** `dhcp4: the server's core keeps when a device first took its address`

---

### Task 3: The joined time in the lease file and the fact

**Files:**
- Modify: `proto/openfeo/v1/config.proto` (`Dhcp4ServerLease`)
- Modify: `crates/openfeo/src/dhcp4_server.rs`
- Modify: `crates/openfeo-world/src/leases.rs`, `crates/openfeo-reconcile/src/fixtures.rs`
- Modify: `crates/openfeo-config/src/file.rs` (the round-trip test's fixture)

**Interfaces:**
- Consumes: `Joined`, `LeaseRecord.joined` (Task 2).
- Produces:

```proto
message Dhcp4ServerLease {
  // …as now…
  // When the device first took this address (wall clock, seconds). 0 in a file written
  // before the field existed: `granted_unix` stands in.
  uint64 joined_unix = 7;
}
```

```rust
// crates/openfeo-world/src/leases.rs
pub struct LeaseFact { /* as now, and: */ pub joined_unix: u64 }

// crates/openfeo/src/dhcp4_server.rs
/// A joined time on the wall clock: as written when a file gave it, stamped now otherwise.
pub fn joined_unix(joined: Joined, now: Timestamp, unix_now: u64) -> u64;

/// The wall clock's lead over the driver's clock, held still while the two keep step.
#[derive(Debug, Default)]
pub struct Wall { lead: Option<u64> }
impl Wall {
    /// The wall clock at the driver's `now`. The two clocks are read a moment apart and
    /// rounded opposite ways, so their difference wobbles by a second: a lead within a
    /// second of the last one used is taken to be that one, and a larger difference is the
    /// wall clock stepped (SNTP), which is followed.
    pub fn unix(&mut self, now: Timestamp, unix_now: u64) -> u64;
}
```

- [ ] **Step 1: Write the failing tests** beside the driver's existing pure tests:

  - `a_file_without_a_joined_time_reads_its_granted_time`: an entry with `joined_unix: 0`,
    `granted_unix: 1_800_000_000` reads as `Joined::Unix(1_800_000_000)`.
  - `the_joined_time_goes_to_the_file_and_back_as_written`: a record with
    `Joined::Unix(1_799_990_000)` is written with that number whatever `unix_now` is (also
    one earlier than it: a boot on the build's clock), and reads back equal.
  - `a_lease_joined_before_the_clock_was_set_is_right_once_it_is`: a record `Joined::At(5)` at
    driver time 100: with `unix_now = 1_700_000_000` its fact and file say `1_699_999_905`;
    with `unix_now = 1_800_000_000` they say `1_799_999_905`.
  - `the_wall_clock_is_held_still_within_a_second_and_follows_a_step`: `Wall::unix(10, 1_010)`
    is `1_010`; then `unix(11, 1_012)` is `1_011` and `unix(12, 1_011)` is `1_012` (the lead
    of 1000 is kept); then `unix(13, 5_013)` is `5_013` (a step).
  - `an_entry_set_aside_keeps_its_joined_time`: `file_with` writes an aside entry's
    `joined_unix` as it was, and its `granted_unix` when it had none.
  - In `facts_from`'s existing test: each fact carries `joined_unix`.

- [ ] **Step 2: Run.** `cargo test -p openfeo dhcp4_server` fails to compile.

- [ ] **Step 3: Implement.** `record_from` reads `joined_unix`, or `granted_unix` when it is
  0. `file_from_records` and `facts_from` write `joined_unix(...)`. `run` owns one `Wall`,
  and `publish_facts` and `save_leases` take the wall clock from it instead of from
  `unix_now()` alone. The fixtures' two `LeaseFact`s gain a `joined_unix`.

- [ ] **Step 4: Run.** `cargo test -p openfeo -p openfeo-config -p openfeo-reconcile
  -p openfeo-world` passes; `make lint` passes.

- [ ] **Step 5: Commit.** `dhcp4: the joined time in the lease file and the fact, on a wall clock held still`

---

### Task 4: The lease table from the World

**Files:**
- Modify: `proto/openfeo/v1/state.proto`
- Create: `crates/openfeo-reconcile/src/leases.rs`; modify `crates/openfeo-reconcile/src/lib.rs`

**Interfaces:**
- Consumes: `LeaseFact.joined_unix` (Task 3).
- Produces: the messages `Lease` and `Leases` exactly as the design's "Leases on the wire" has
  them, in `state.proto`, and:

```rust
/// The most leases one table holds: it fits a frame with room to spare.
pub const MAX_LEASES: usize = 4096;

/// Every LAN's leases that have not run out at `now_unix_ms`: by LAN in config order, then
/// by address. More than [`MAX_LEASES`] leaves the newest by joined time and says so.
#[must_use]
pub fn leases(world: &World, now_unix_ms: u64) -> Leases;
```

- [ ] **Step 1: Write the failing tests** in `leases.rs`, on `fixtures::static_world_with_leases`
  and Worlds built from it:

  - `the_table_is_by_lan_in_config_order_then_by_address`: two LANs given in the World's map
    in the other order come out in the config's; `time_unix == now_unix_ms / 1000`; a lease
    with no name has `hostname == ""`; the MAC is the fact's own text.
  - `a_lease_that_has_run_out_is_left_out_as_the_count_leaves_it_out`: at a `now` past one
    expiry, the table has what `state(&world, &system).lans[0].leases` counts.
  - `a_lan_the_config_no_longer_has_is_not_listed`.
  - `beyond_the_most_the_newest_by_joined_time_are_kept_and_it_says_so`: 4100 leases with
    rising `joined_unix`: 4096 come out, the four with the lowest are absent, `truncated`,
    and the order is still by address. 4096 exactly is not `truncated`.

- [ ] **Step 2: Run.** `cargo test -p openfeo-reconcile leases` fails to compile.

- [ ] **Step 3: Implement** `leases` (expiry by the rule `lan_state` uses:
  `expires_unix * 1000 > now_unix_ms`).

- [ ] **Step 4: Run.** `cargo test -p openfeo-reconcile` and `scripts/check-deps.sh` pass.

- [ ] **Step 5: Commit.** `reconcile: the lease table, a pure function of the World`

---

### Task 5: `GetLeases` and the `leases` topic

**Files:**
- Modify: `proto/openfeo/v1/api.proto`
- Modify: `crates/openfeo-api/src/{envelope,ws,grpc,server}.rs`
- Modify: `harness/src/apiclient.rs`, `harness/tests/m4.rs`

**Interfaces:**
- Consumes: `openfeo_reconcile::leases::leases` (Task 4).
- Produces:

```proto
message GetLeasesRequest {}
message GetLeasesResponse { Leases leases = 1; }
// Request.get_leases = 9; Response.get_leases = 9;
// Telemetry.leases = 4; SubscribeResponse.leases = 4;
// service StateService { rpc GetLeases(GetLeasesRequest) returns (GetLeasesResponse); }
```

```rust
// envelope.rs
pub enum Topic { State, Leases, Counters, Events }      // "leases" on the wire
impl Conn {
    /// The lease table; replaces one not yet sent. Dropped unless subscribed, and dropped
    /// when its leases are those of the last table taken: the clock alone is no change.
    pub fn push_leases(&mut self, leases: &Leases);
}
// server.rs
impl Shared { pub fn leases(&self) -> Leases; }          // on the clock `state()` uses
// harness/src/apiclient.rs
impl Ws {
    pub fn leases(&mut self) -> Result<Leases>;
    /// The next `leases` push that satisfies `wanted`, as `state_where` waits for a state.
    pub fn leases_where(&mut self, timeout: Duration, wanted: impl Fn(&Leases) -> bool) -> Result<Leases>;
}
```

`next_out` sends replies, word of lost events, the state, the leases, the counters, then
events. Unsubscribing from `leases` forgets the unsent table and the last one taken.

- [ ] **Step 1: Write the failing tests.**

  - `envelope.rs`: `a_lease_table_is_coalesced_and_an_unchanged_one_is_not_sent_again` (two
    different tables pushed before a read: one frame, the later; the same leases with a
    later `time_unix` pushed after: no frame; after an unsubscribe and a subscribe the same
    table is sent again); `"leases"` in the test that parses every topic name.
  - `ws.rs`: `a_lease_is_pushed_to_a_subscriber_and_answered_to_a_call`: with the test API,
    a socket subscribes to `leases` and is sent the table as it stands; a `LeaseFact` is
    published into the World and the next push holds it; a World change that touches no
    lease sends nothing; `GetLeases` answers the same table.
  - `grpc.rs`: `leases_over_grpc_need_a_session_and_stream`: `GetLeases` without a token is
    `UNAUTHENTICATED`, with one it answers; `Subscribe` with `topics: ["leases"]` yields a
    `leases` body first.

- [ ] **Step 2: Run.** `cargo test -p openfeo-api leases` fails to compile.

- [ ] **Step 3: Implement.** In `ws.rs` the driver follows the World while the connection
  wants `state` or `leases`, pushes each that it wants, and pushes the table as it stands
  when `leases` is newly subscribed (`Feeds::follow` says which topics are new). `grpc.rs`'s
  `feed` does the same and `stream_item` maps the body. `perform` answers `GetLeases`.

- [ ] **Step 4: Run.** `cargo test -p openfeo-api` passes.

- [ ] **Step 5: Add the harness scenario**
  `a_lease_is_listed_and_keeps_its_joined_time` to `m4.rs` and `SCENARIOS`:

  1. `boot_claimed`; a socket subscribes to `leases` and the first table is empty with a
     `time_unix` within 5 s of the state's clock.
  2. `lanclient::udhcpc` on `lan0` with a hostname (`-x hostname:plug-kitchen`). The next
     table has one lease: `lan == "lan0"`, the address udhcpc was given, `hostname ==
     "plug-kitchen"`, a `mac` of six colon-separated pairs, `joined_unix` within 5 s of
     `time_unix`, `expires_unix > time_unix`. `Ws::leases()` answers the same lease.
  3. Two seconds later the same client asks again for the address it holds (`-r <ip>`): the
     next table's `expires_unix` is later and its `joined_unix` is **equal**.
  4. A reservation for another MAC is applied at once (`with_reservation`), which restarts
     the LAN's server: after `lan lan0 dhcp restored 1 leases`, `Ws::leases()` has the same
     `joined_unix`.
  5. `no_task_failed`.

- [ ] **Step 6: Run.** `make kernel` then
  `make test-harness FILTER=a_lease_is_listed_and_keeps_its_joined_time` passes.

- [ ] **Step 7: Commit.** `api: GetLeases and the leases topic`

---

### Task 6: Counters all the time, and the last hour

**Files:**
- Modify: `proto/openfeo/v1/state.proto` (`LinkHistory`), `proto/openfeo/v1/api.proto`
- Modify: `crates/openfeo-api/src/{telemetry,limits,ws,grpc}.rs`
- Modify: `harness/src/apiclient.rs`, `harness/tests/m4.rs`

**Interfaces:**
- Produces: `LinkHistory` in `state.proto` and `GetHistoryRequest`, `GetHistoryResponse` in
  `api.proto`, exactly as the design's "Counters, all the time" has them;
  `Request.get_history = 10`, `Response.get_history = 10`,
  `rpc GetHistory(GetHistoryRequest) returns (GetHistoryResponse)` on `StateService`; and:

```rust
// limits.rs
/// The most links one `GetHistory` names: an hour of each of eight fits a frame.
pub const MAX_HISTORY_LINKS: usize = 8;
// telemetry.rs
/// How long the history reaches back.
pub const HISTORY: Duration = Duration::from_secs(3600);
impl Telemetry {
    /// The samples kept of each of `links` that has any, in the order asked, each once,
    /// oldest first.
    #[must_use]
    pub fn history(&self, links: &[String]) -> Vec<LinkHistory>;
}
// harness/src/apiclient.rs
impl Ws { pub fn history(&mut self, links: &[&str]) -> Result<Result<Vec<LinkHistory>, Error>>; }
```

A sample is a link's `monotonic_ms`, `rx_bytes` and `tx_bytes`. A link keeps at most 3600
and none older than an hour before the newest sample read; a link with none left is
forgotten. A read that fails records nothing. `GetHistory` with no link, or with more than
`MAX_HISTORY_LINKS`, is `INVALID_ARGUMENT`. `subscribe` and `CountersSub` stay as they are
to their callers; the count of subscribers goes.

- [ ] **Step 1: Write the failing tests** in `telemetry.rs` (paused time, the `Counting`
  source extended to report links), replacing the two that assert nothing is read unwatched:

  - `the_counters_are_read_each_second_with_nobody_watching`: ten seconds with no subscriber
    is ten or eleven reads, and `history(["p0"])` holds them a second apart.
  - `the_history_holds_an_hour_and_no_more`: after 3700 s there are 3600 samples and the
    oldest is the 101st read.
  - `a_link_that_was_away_has_a_gap_and_one_gone_an_hour_is_forgotten`: a link absent from
    the source for 30 s has no samples for those 30 s; one absent for over an hour is not in
    the answer.
  - `a_read_that_fails_is_a_gap`.
  - `the_history_answers_what_was_asked_in_the_order_asked`: `["p1", "nope", "p0", "p1"]`
    answers `p1` then `p0`.
  - `a_subscriber_is_still_sent_each_sample` (the second of the old tests, without its count
    of reads at rest).

  And in `ws.rs`: `the_history_is_answered_and_its_request_is_bounded` (one link answered;
  none, and nine, refused with `INVALID_ARGUMENT`); in `grpc.rs` the same call with a token.

- [ ] **Step 2: Run.** `cargo test -p openfeo-api telemetry` fails.

- [ ] **Step 3: Implement.** `run` ticks every `INTERVAL` from its start. The history is
  behind a `std::sync::Mutex` that is never held across an `await`. The module's and
  `Counters`'s comments say what §10 now says.

- [ ] **Step 4: Run.** `cargo test -p openfeo-api` passes.

- [ ] **Step 5: Add the harness scenario**
  `an_hour_of_counters_is_kept_with_nobody_watching`: `boot_claimed`, the ISP's HTTP target,
  five fetches from the LAN over about five seconds with no socket open; then a socket asks
  `history(&["p0", "nope"])`: one link, `p0`; at least five samples; each 800 to 2500 ms
  after the one before; `rx_bytes` never falls and grew by at least five bodies across them.
  `history(&[])` is refused with `INVALID_ARGUMENT`. `no_task_failed`.

- [ ] **Step 6: Run.** `make test-harness FILTER=an_hour_of_counters_is_kept_with_nobody_watching`
  and `FILTER=counters_rise_while_the_lan_fetches_from_the_isp` pass.

- [ ] **Step 7: Commit.** `api: counters are read all the time and the last hour is kept; GetHistory`

---

### Task 7: The client

**Files:**
- Create: `web/client/src/history.ts`, `web/client/test/history.test.ts`
- Modify: `web/client/src/{router,socket,messages,index,rates}.ts`
- Modify: `web/client/test/{socket,reconnect}.test.ts`, `web/client/test/scripted.ts`
- Modify: `web/client/itest/lab.test.ts`, `web/scripts/labctl.mjs` (its list of verbs),
  `harness/tests/m4.rs` (`lab_verb`)

**Interfaces:**
- Consumes: the messages of Tasks 4 to 6, generated by `make web-gen`.
- Produces:

```ts
// router.ts: named as `state()` and `config()` are
leases(): Promise<Leases>
/** At most eight links a call; a link the router has no samples of is absent. */
history(links: string[]): Promise<LinkHistory[]>
subscribe(topic: 'leases', onPush: (leases: Leases) => void): Subscription

// history.ts
export interface LinkSample { /** On the router's boot clock. */ atMs: number; rxBytes: bigint; txBytes: bigint }
export interface RatePoint { /** When the later of its two samples was read. */ atMs: number; rxBitsPerSec: number; txBitsPerSec: number }
/** Samples further apart than this have no rate between them: it is a gap. */
export const GAP_MS = 5_000
export function samplesOf(history: LinkHistory): LinkSample[]
/** A rate for each sample after the first, by the rule `rates` uses. None across a gap, none where time did not move on, none where a counter went backwards (an interface made anew). */
export function ratesOver(samples: readonly LinkSample[]): RatePoint[]
/** The mean of the points in each bucket that has any, at the bucket's end; buckets are aligned to multiples of `bucketMs`. */
export function averaged(points: readonly RatePoint[], bucketMs: number): RatePoint[]
```

`messages.ts` exports the types `Lease`, `Leases`, `LinkHistory` and their schemas;
`index.ts` exports `history.ts`'s. `Topic` gains `'leases'`, resubscribed after a reconnect
as `state` is.

A new lab verb, `join <hostname>`: the harness's own DHCP client
(`lanclient::dhcp_client`) takes a lease on `lan0` with that name, and the verb fails
unless it was bound. It puts no address on the interface, so the test's own address stays.

- [ ] **Step 1: Write the failing tests.**

  - `history.test.ts`: `a rate for each sample after the first, by the live rule` (three
    samples a second apart: two points equal to `rates()` of the same pairs);
    `no rate across a gap` (samples 6 s apart: no point there, points either side);
    `no rate where a counter went backwards`; `no rate where time stood still`;
    `buckets are aligned and averaged, and an empty one is absent` (points at 1 s over
    0 to 25 s with 12 to 19 missing, `bucketMs` 10 000: points at 10 000 and 30 000, each
    the mean of its own); `samplesOf zips the three lists`.
  - `socket.test.ts`: `leases are pushed to a subscriber` and, in `reconnect.test.ts`,
    `leases are subscribed again on the new socket`.
  - A router test with the scripted socket: `leases()` and `history(['p0'])` send
    `getLeases` and `getHistory` and hand back the bodies; an answer of another kind is a
    `RouterError`.

- [ ] **Step 2: Run.** `npm test -w @openfeo/client` (from `web/`) fails.

- [ ] **Step 3: Implement.** The comment at the top of `rates.ts` says what §10 now says.

- [ ] **Step 4: Run.** `npm test -w @openfeo/client` and `make web-lint` pass.

- [ ] **Step 5: Extend the lab run** (`web/client/itest/lab.test.ts`), after its counters
  test: `the history reaches back before this test asked` (the default WAN's interface has
  at least three samples, each 800 to 2500 ms after the one before, and `ratesOver` of them
  gives a point for each but the first); `a device that joins is pushed` (a `leases`
  subscription, `ask('join plug-kitchen')`, a push whose leases include that name, and
  `leases()` agrees). `lab_verb` gains `["join", hostname]`.

- [ ] **Step 6: Run.** `make test-harness FILTER=the_javascript_client_works_from_the_lan`
  passes.

- [ ] **Step 7: Commit.** `client: leases, the history, and rates over time`

---

### Task 8: The components

**Files:**
- Create: `web/ui/src/chart.ts`, `web/ui/src/components/{OfoChart,OfoSegmented,OfoEmpty}.vue`
- Modify: `web/ui/src/components/{OfoStatTile,OfoDataTable}.vue`, `web/ui/src/index.ts`,
  `web/ui/src/icons.ts`, `web/ui/additions.css`, `web/ui/docs/gaps.md`
- Test: `web/ui/test/components.test.ts`, `web/ui/test/chart.test.ts` (new)

**Interfaces:**
- Produces:

```ts
// chart.ts: pure, in a `0 0 720 220` box with the plot between x 0 and 672 and y 12 and 196
export interface ChartPoint { at: number; rx: number; tx: number }
export interface ChartMark { at: number; label: string }
export interface ChartTick { at: number; label: string }
/** A round top for the scale at or above `max`: 1, 2 or 5 times a power of ten; 1 for nothing. */
export function ceiling(max: number): number
/** Five values from 0 to `top`. */
export function levels(top: number): number[]
/** One `M … L …` for each run, in order; a run of one point is a short level stroke. Straight segments only. */
export function linePath(runs: readonly (readonly ChartPoint[])[], series: 'rx' | 'tx', from: number, to: number, top: number): string
/** The same runs closed down to the axis, for the fill. */
export function areaPath(runs: readonly (readonly ChartPoint[])[], series: 'rx' | 'tx', from: number, to: number, top: number): string
```

```ts
// OfoChart.vue (ThroughputChart.md): class names are the guideline's
defineProps<{
  title: string
  /** What the picture is, for a reader who cannot see it. */
  label: string
  /** Unbroken runs of points; a gap lies between two runs. */
  runs: ChartPoint[][]
  from: number
  to: number
  unit: string
  /** The legend's current values, as text. */
  now: { rx: string; tx: string }
  marks?: ChartMark[]
  ticks?: ChartTick[]
  /** Said under the head when there is something to say (no history could be read). */
  note?: string
}>()
// slot `range`: the Segmented, at the head's end

// OfoSegmented.vue (Segmented.md): role="group", aria-pressed on the chosen button
defineProps<{ label: string; options: { value: string; label: string; count?: number }[]; modelValue: string }>()
defineEmits<{ 'update:modelValue': [value: string] }>()

// OfoEmpty.vue (EmptyState.md): the lattice mark, a title, a line, and a default slot for an action
defineProps<{ title: string; text?: string }>()

// OfoDataTable.vue gains
rowKey?: string                                           // the row's field that keys it
rowClass?: (row: Record<string, string>) => string | undefined
```

`OfoStatTile` shows its foot under its sparkline when it has both. `additions.css` gains
`.ofo-table__row--new td:first-child` (the mockup's oxide edge) and `.ofo-chart__note`;
`gaps.md` says both, and that a stat tile here may have a sparkline and a foot, and that a
segment may carry a count (drawn with `ofo-tabs__count`). `icons.ts` gains one Lucide icon,
`monitor-smartphone`, for the Leases entry.

- [ ] **Step 1: Write the failing tests.**

  - `chart.test.ts`: `ceiling` (0 gives 1; 918.2 gives 1000; 104 gives 200; 38.2 gives 50;
    1 gives 1); `levels(1000)` is `[0, 250, 500, 750, 1000]`; `linePath` of two runs has two
    `M` and no curve command, puts `from` at x 0 and `to` at x 672, `top` at y 12 and 0 at
    y 196, and leaves the gap undrawn; a value above `top` is drawn at the top; a point
    outside `from..to` is not drawn; `areaPath` closes each run to y 196.
  - `components.test.ts`: `OfoChart` has `role="img"` and its label, the legend's two
    values, five grid lines, one `g.event` per mark with its text, the note when given, the
    slot's content in the head, and no `style` attribute anywhere; `OfoSegmented` marks the
    chosen option `aria-pressed="true"`, emits the pressed option's value, and shows a
    count; `OfoEmpty` shows the title, the text and its slot; `OfoStatTile` with a
    sparkline and a foot shows both; `OfoDataTable` puts `rowClass`'s answer on the row.
    Each new component is added to the test that every component passes the policy.

- [ ] **Step 2: Run.** `npm test -w @openfeo/ui` fails.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** `npm test -w @openfeo/ui` and `make web-lint` pass.
- [ ] **Step 5: Commit.** `ui: a chart, a segmented choice and an empty state`

---

### Task 9: The panel's models

**Files:**
- Create: `web/panel/src/model/leases.ts`, `web/panel/src/model/chart.ts`
- Modify: `web/panel/src/model/dashboard.ts` (`tiles`), `web/panel/src/model/format.ts`
- Test: `web/panel/test/leases-model.test.ts`, `web/panel/test/chart-model.test.ts` (new),
  `web/panel/test/dashboard.test.ts`

**Interfaces:**
- Consumes: `LinkSample`, `RatePoint`, `ratesOver`, `averaged`, `GAP_MS`, `Lease`, `Leases`
  (Task 7); `ChartPoint`, `ChartMark`, `ChartTick`, `ceiling` (Task 8).
- Produces:

```ts
// model/leases.ts
/** Newest first: by joined time, then by LAN and address so that the order is steady. */
export function newestFirst(leases: readonly Lease[]): Lease[]
/** Whether `filter` is in the lease's address, name or MAC, without regard to case. Plain text. An empty filter matches all. */
export function matches(lease: Lease, filter: string): boolean
/** How many leases each LAN has, for the LANs given, in their order. */
export function perLan(leases: readonly Lease[], lans: readonly string[]): { lan: string; count: number }[]
/** "just now" under a minute and for a time ahead of the clock; then "2 min ago", "5 h ago", "2 d ago". */
export function ago(secs: number): string
/** "in under a minute", "in 4 min", "in 11 h 58 min", "in 7 h 02 min", "in 3 d"; "expired" at 0 or less. */
export function until(secs: number): string
/** What identifies a lease's row on screen. */
export function leaseKey(lease: Lease): string            // `${lan} ${mac} ${address}`
export type Reserved = 'no' | 'draft' | 'applied' | 'unavailable'
/**
 * 'applied': the router's config and the draft both reserve this address for this MAC in
 * this LAN. 'draft': only the draft does. 'unavailable': the draft has no such LAN or no
 * DHCP server on it, or reserves this MAC or this address otherwise. 'no': Reserve is offered.
 */
export function reserved(lease: Lease, base: Config | null, draft: Config | null): Reserved
/** Add the reservation to the draft: the MAC, the address, and the name when there is one. Nothing when `reserved` is not 'no'. */
export function reserve(draft: Config, base: Config | null, lease: Lease): void

// model/chart.ts
export type Range = '5m' | '1h'
export const RANGES: readonly { value: Range; label: string; ms: number; bucketMs: number }[]
//   '5m': '5 min', 300 000, 1 000 (each second);  '1h': '1 h', 3 600 000, 10 000
export const OPENING: Range = '1h'
export interface Drawn { runs: ChartPoint[][]; from: number; to: number; unit: RateUnit; now: { rx: string; tx: string } }
/** A link's samples as the chart draws them over `range` ending at `toMs`: rates, averaged for the hour, cut into runs at gaps (more than GAP_MS apart at a second, more than one bucket apart otherwise), scaled to one unit chosen from the largest value. `at` is seconds. */
export function drawn(samples: readonly LinkSample[], range: Range, toMs: number, live: LinkRate | undefined): Drawn
/** The highest ten-second average of the hour ending at `toMs`; undefined with no rate in it. */
export function peak(samples: readonly LinkSample[], toMs: number): { rx: number; tx: number } | undefined
/** A mark where `wan` came up inside the range: "reconnected 14:12" when its going down is among the events, "up 14:12" otherwise; the time only when the clock is set. `at` is seconds, as `drawn`'s is. */
export function marks(events: readonly Event[], wan: string, fromMs: number, toMs: number, synced: boolean): ChartMark[]
/** Clock times along the range: each minute for five, each ten for the hour, `at` in seconds. `sinceBootMs` and `now` place the boot clock on the browser's. */
export function ticks(range: Range, toMs: number, sinceBootMs: number, now: Date): ChartTick[]
/** The last minute's rates, for a tile's sparkline. */
export function lastMinute(samples: readonly LinkSample[]): { rx: number[]; tx: number[] }
```

`tiles` takes one more thing in `Live`, `peak?: { rx: number; tx: number }`, and gives the
Download and Upload tiles the foot `peak 918.2 Mbit/s in the last hour` (the unit is said:
SPEC §8.4 gives every number its unit, and the peak's may differ from the rate's).

- [ ] **Step 1: Write the failing tests.**

  - `leases-model.test.ts`: order (newest first, steady for equal times); `matches` by
    address, by name, by MAC in either case; `a device with no name is not found by "none"`;
    `the filter is text, not a pattern` (`.*` matches nothing, `1.14` does not match
    `192.168.1.143` unless that text is in it); `perLan`; `ago` at 0, 59, 60, 119, 3 599,
    3 600, 86 399, 86 400 and 3 d; `a time ahead of the clock is just now` (`ago(-30)`);
    `until` at 0, 30, 240, 43 080 ("in 11 h 58 min"), 25 320 ("in 7 h 02 min"), 3 d;
    `ages are counted on the router's clock` (a lease joined 120 s before `time_unix`, read
    with a router clock carried 5 s on, is "2 min ago" whatever `Date.now()` says: the
    function takes the router's seconds and no `Date`); `reserved` in each of its four
    answers, with a MAC in another case, a LAN the draft removed, a LAN with DHCP off, the
    MAC reserved for another address, the address reserved for another MAC; `reserve` puts
    MAC, address and name into that LAN's `dhcp.static` and nowhere else; `reserving twice
    adds one`.
  - `chart-model.test.ts`: `drawn` for five minutes is one point a second and for the hour
    one a ten seconds; a 30 s hole gives two runs in both; the unit follows the largest
    value and `now` is the live rate in that unit, a dash without one; `peak` is the highest
    ten-second mean, not the highest second, and is what `drawn(…, '1h', …)`'s largest point
    is; `marks` (an up after a down: "reconnected 14:12"; an up alone: "up 14:12"; another
    WAN's: none; outside the range: none; clock not set: no time); `ticks` count and labels;
    `lastMinute` is the last sixty rates.
  - `dashboard.test.ts`: the tiles' feet with a peak, and without.

- [ ] **Step 2: Run.** `npm test -w panel` (from `web/`; `panel` is the package's name) fails.
- [ ] **Step 3: Implement.** `format.ts` gains what the two models share with it.
- [ ] **Step 4: Run.** The panel's tests and `make web-lint` pass.
- [ ] **Step 5: Commit.** `panel: the models of the lease table and the chart`

---

### Task 10: What the panel watches

**Files:**
- Modify: `web/panel/src/live.ts`, `web/panel/src/session.ts` (`PanelRouter`)
- Modify: `web/panel/test/live.test.ts`, `web/panel/test/fake-router.ts`

**Interfaces:**
- Consumes: `Router.leases/history/subscribe('leases')`, `samplesOf` (Task 7); `lastMinute`
  (Task 9).
- Produces, in `LiveData`:

```ts
/** The lease table as last pushed; `null` until it first is. */
leases: Ref<Leases | null>
/** The router's wall clock by now, in seconds: what the table said, carried on by the time since it arrived. */
routerClock: ComputedRef<number | undefined>
/** The last hour of each WAN interface's counters, oldest first, by the link's name. */
samples: Ref<Map<string, LinkSample[]>>
/** The history could not be read: the chart says so and draws from now. */
historyFailed: Ref<boolean>
/** The most recent events, newest first: as many as the router keeps (256). */
events: Ref<Event[]>
```

`history` (the default WAN's last minute) stays, now made from `samples`. `RECENT` moves to
the dashboard, which shows the first eight events.

Rules:
- The links wanted are the `interface` of each WAN in the state that has one.
- The history is asked for when a wanted link has not been asked for since the socket last
  opened, in calls of at most eight links; its samples are joined to what is kept by time,
  with no sample twice.
- Each counters push appends a sample for each wanted link in it, and samples over an hour
  older than the newest are dropped.
- A sample older than the newest kept is of another boot: what was kept for every link is
  dropped and the history is asked for again.
- When the socket is lost the samples stay; when it opens anew the history is asked again.

- [ ] **Step 1: Write the failing tests** in `live.test.ts` with the fake router (which gains
  `leases`, `history` and the `leases` topic):

  - `the lease table is kept and its clock carried on`.
  - `the history is asked for once the state names a WAN, and the live samples follow it`.
  - `a history that cannot be read is said, and the live samples still gather`.
  - `a reconnect fills the time away and repeats nothing`.
  - `samples of an earlier boot are dropped`.
  - `a WAN with no interface is not asked about`, and `nine WANs are asked about in two calls`.
  - `the sparkline is filled from the history at once`.
  - `as many events are kept as the router keeps`.

- [ ] **Step 2: Run.** The panel's tests fail.
- [ ] **Step 3: Implement.** The comment at the top of `live.ts` says what the router now keeps.
- [ ] **Step 4: Run.** The panel's tests and `make web-lint` pass.
- [ ] **Step 5: Commit.** `panel: the shell hears the leases and keeps the hour`

---

### Task 11: The dashboard

**Files:**
- Modify: `web/panel/src/pages/Dashboard.vue`, `web/panel/src/layout.css`
- Modify: `web/panel/test/page.test.ts` (or the dashboard's own page test), `web/panel/test/fixtures.ts`

**Interfaces:**
- Consumes: Tasks 8 to 10; `PAGES.leases` (added here to `routes.ts` as `'/leases'`, with
  the page itself in Task 12).

From the top: the tiles; a chart for each WAN in config order, titled by its name; the
interface cards; a card "Newest leases"; then Ports, Addresses and Recent events as they are.

- One range for the page, `1 h` at first, chosen by an `OfoSegmented` in each chart's head
  (label "Range").
- A chart's label: "Download and upload on wan0 over the last hour" (or "the last five
  minutes"). Its note, when the history failed: "The last hour could not be read from the
  router. The line starts from when this page was opened."
- A WAN with no interface, or no sample in the range, draws an empty plot and its legend
  shows dashes.
- Newest leases: the first five of `newestFirst`, columns Joined, Address, Name, MAC, LAN;
  Joined is `ago` on `routerClock` with the exact time as the cell's title; a name not given
  reads "none given", muted; a row that joined under a minute ago is marked new. The card's
  head has the link "All _n_ leases" to the Leases page. With no lease: "No device has taken
  an address yet." Until the table first arrives: skeletons.
- The peak under the Download and Upload tiles is `peak` of the default WAN's samples.

- [ ] **Step 1: Write the failing tests:** `a chart for each WAN, in config order`;
  `the range is one choice for every chart` (pressing `5 min` in one changes both labels);
  `the newest five leases, and a link to them all`; `no lease yet says so`;
  `a failed history is said in the chart`; `a row that has just joined is marked`;
  `the tiles say the hour's peak`.
- [ ] **Step 2: Run.** The panel's tests fail.
- [ ] **Step 3: Implement.** Layout only in `layout.css`.
- [ ] **Step 4: Run.** The panel's tests and `make web-lint` pass.
- [ ] **Step 5: Commit.** `panel: the dashboard draws the hour and lists the newest leases`

---

### Task 12: The Leases page

**Files:**
- Create: `web/panel/src/pages/Leases.vue`, `web/panel/test/leases.test.ts`
- Modify: `web/panel/src/routes.ts`, `web/panel/src/Shell.vue`, `web/panel/src/layout.css`,
  `web/panel/test/{routes,shell}.test.ts`

**Interfaces:**
- Consumes: `LIVE` (`leases`, `routerClock`, `state`), `CONFIG` (`base`, `draft`, `edit`,
  `readOnly`), Task 9's functions, `OfoDataTable`, `OfoSegmented`, `OfoEmpty`, `OfoInput`.

- The route is `leases`; the sidebar entry "Leases" follows "LAN & DHCP" under Network. The
  shell counts it among the `settings` pages, so the save bar and the dialog serve it.
- Title "Leases", sub "Devices that took an address from the router, newest first."
- A filter box (placeholder "Filter by name, address or MAC") and, with more than one LAN in
  the state that has a DHCP server, an `OfoSegmented` (label "LAN"): "All LANs", then each
  LAN with its count.
- Columns Joined, Address, Name, MAC, LAN, Expires, and the action. Joined and Expires are
  `ago` and `until` on `routerClock`, each with the exact time in the browser's zone as its
  title; Address and MAC in mono, MAC muted; "none given" muted.
- The action by `reserved`: 'no' is a small ghost button "Reserve" (absent while the store is
  read-only); 'draft' is an info pill "Reserved, not applied yet"; 'applied' is an info pill
  "Reserved"; 'unavailable' is nothing. Reserve calls `store.edit` with `reserve`.
- A lease first seen while the page is open is marked new for a minute. Those in the first
  table the page sees are not.
- No lease at all: `OfoEmpty`, "No leases yet", "A device appears here when it takes an
  address from the router, such as a phone joining the Wi-Fi." A filter that leaves none: a
  row "No leases match `<filter>`".
- Under the table: "A new row appears by itself when a device joins. A device with a name is
  also found as `name.<domain>`. Reserve keeps this address for the device: it joins your
  other changes, to apply when you are ready. IPv6 devices choose their own addresses, so
  they are not listed." (`<domain>` is the router's.) When the table was cut: "Showing the
  4096 newest of more leases."

- [ ] **Step 1: Write the failing tests** in `leases.test.ts`: `every LAN's leases, newest
  first`; `the filter narrows the rows as it is typed`; `a filter that finds nothing says
  what it looked for`; `the LAN choice shows with two LANs and not with one, with counts`;
  `ages follow the router's clock as it is carried on`; `Reserve puts a reservation in the
  draft and the row says so`; `a reservation the router has reads Reserved`; `no Reserve on a
  router that takes no changes`; `a lease that arrives is marked new, and those there at
  first are not`; `no lease yet`; `a cut table says so`. In `routes.test.ts` and
  `shell.test.ts`: the address, the entry's place, and the save bar on the page.
- [ ] **Step 2: Run.** The panel's tests fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** The panel's tests, `make web-lint` and `make panel` pass.
- [ ] **Step 5: Commit.** `panel: the Leases page, with Reserve`

---

### Task 13: The browser run, and the record

**Files:**
- Create: `web/panel/e2e/leases.spec.ts`
- Modify: `harness/tests/m4.rs` (a scenario), `CLAUDE.md` (Harness), `docs/progress.md`

- [ ] **Step 1: Write the spec**, with `support.ts`'s `watch` and `shots`, one test, "the hour
  and the leases, from the dashboard to a reservation":

  1. Log in and choose `5 min`. The chart titled `wan0` has a line that began before the page
     was opened: its path spans at least fifteen seconds of the plot's width (the scenario
     waits 20 s after the router is up before it starts the browser). Screenshot
     `status-dashboard`.
  2. "Newest leases" says no device has taken an address. `ask('join plug-kitchen')`: a row
     with `plug-kitchen` appears without a reload, marked new, and the link reads
     "All 1 leases". Follow it.
  3. On Leases the row is there with an address in the pool. Typing `kitchen` keeps it and
     `zzz` says "No leases match zzz". Screenshot `leases`.
  4. Reserve: the pill reads "Reserved, not applied yet" and the save bar counts one change.
     Apply, confirm in the dialog and the countdown as `config.spec.ts` does; the pill reads
     "Reserved". Screenshot `leases-reserved`.
  5. Back on the dashboard: `ask('wan-down')`, wait for the WAN to read down, `ask('wan-up')`,
     wait for up: the chart has a mark whose text begins "reconnected". Screenshot
     `status-dashboard-reconnected`.
  6. `expect(problems).toEqual([])`.

- [ ] **Step 2: Add the scenario** `the_panel_shows_the_hour_and_the_leases_in_a_browser`,
  as `the_panel_changes_config_in_a_browser` is (its skips, its resolver rule, `settle`,
  `openfeo.confirm_secs=40`), naming `leases.spec`, with `lab_verb` serving `join`.

- [ ] **Step 3: Run.** `make test-harness FILTER=the_panel_shows_the_hour_and_the_leases_in_a_browser`
  passes and leaves the screenshots in both themes; look at each.

- [ ] **Step 4: Run everything.** `make lint`, `make test` and the whole of
  `make test-harness`; all pass.

- [ ] **Step 5: Write the record.** `CLAUDE.md`'s Harness section: the three new `m4`
  scenarios, the `join` verb, the fifth spec file's name. `docs/progress.md`: the entry for
  this part under M4, naming the pull request by the number it will have.

- [ ] **Step 6: Commit.** `harness, docs: the browser run for status and leases, and the record`
