# M4 part 3c: views Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The panel shows the routes the kernel holds, the ports with their counters, and the
router's log as it is written, by level and by text; the API gains the route dump, and the log
as a call and as a feed.

**Architecture:** The log ring keeps each line as a record (a number that only grows, the time
since boot, the level, the text) and can be waited on. A reader follows the ring by number, so a
feed holds no queue of its own: the ring is the queue, and a reader that falls too far behind is
moved up and told. `SystemService.Logs` reads the ring backwards under one rule for level and
text, which `@openfeo/client` has again in TypeScript, held to it by shared cases. The netlink
cache learns the two kinds of route it folded into unicast, and `DiagnosticsService.DumpRoutes`
answers the cache through a trait in `ApiDeps`, as counters are read. The three pages are built
as Leases was: what a page works out is a plain function in `model/`, the page joins it to the
live store, and nothing is edited.

**Tech Stack:** Rust (prost, tonic, axum, tokio, tracing), protobuf, TypeScript 6, Vue 3.5,
vitest 5, Playwright, the QEMU harness.

**Spec:** `docs/superpowers/specs/2026-11-23-m4-part3-remaining-pages-design.md` ("Part 3c",
"Proven", "SPEC amendments", "What is left to the builder", "Calls made for the maintainer"
19 to 22). The milestone's rules are in
`docs/superpowers/specs/2026-11-10-m4-api-and-panel-design.md`. The words on the three pages are
those of the mockup the maintainer approved; they are written out in Tasks 11 to 13.

## Global Constraints

- Branch `m4-3c`, cut from `main` once the minors of part 3b are in it (#134), and on top of
  that branch until then. Commits are `git commit -s` as the repository's identity, subject
  `<area>: <summary>`. Nothing is pushed and no pull request is opened but on the maintainer's
  word; the branch is swept before any push, and linted with the newest stable Rust as well as
  the dev host's (`RUSTUP_TOOLCHAIN=1.100.0 cargo clippy --workspace --all-targets
  --all-features -- -D warnings`).
- `clippy -D warnings`, pedantic as warnings. No `unwrap`/`expect` outside tests. `thiserror` in
  libraries. No `std::process::Command` outside `harness/`.
- Only `openfeo-netlink`, `openfeo-nft`, `openfeo-net`, `openfeo-platform` and `openfeo-init`
  call the kernel. `openfeo-api` does not depend on `openfeo-netlink`: what it needs of the
  cache comes through a trait that `crates/openfeo` implements.
- Every source file starts with `SPDX-License-Identifier: GPL-2.0-or-later` and
  `Copyright (C) 2026 Andrew Newton`.
- No password, token or hash reaches a log line, an error, a `Debug` output or a log sent to
  the panel. No field of a new message has a name holding `pass`, `token`, `secret`, `hash`,
  `key`, `psk`, `credential` or `cookie` (`crates/openfeo-config/build.rs` reads those as
  secrets).
- Sending log lines to a subscriber writes no log line, on the WebSocket and on gRPC.
- `web/client` imports no Vue and uses no DOM beyond `fetch` and `WebSocket`; `web/ui` knows
  nothing of the API; `web/panel` reaches protobuf only through `@openfeo/client` and holds no
  CSS beyond page layout. The page's content security policy allows no inline script, no
  `style` attribute and no `data:` URL, and is not changed.
- The design system's copies under `web/ui` (`tokens.json`, `ofo.css`, fonts, logos, `docs/`)
  are not edited. What they lack goes in `web/ui/additions.css` and is said in
  `web/ui/docs/gaps.md`.
- Addresses in tests and fixtures are documentation ranges (RFC 5737, RFC 3849) or the RFC 1918
  ranges the fixtures already use; hardware addresses are locally administered or QEMU's.
- No new config field and no new plain HTTP call. The three pages edit nothing and show no
  save bar.
- The numbers: a line is at most 16 KiB (`MAX_LINE`); one `Logs` answer holds at most 1000
  lines (`MAX_LOG_LINES`) and 512 KiB of text (`MAX_LOG_BYTES`); a push on `logs` holds at most
  256 lines (`LOG_BATCH`) and the same bytes, and one leaves at most every 100 ms (`LOG_PACE`);
  a reader may be 1024 lines behind (`LOG_QUEUE`). The Logs page shows at most 2000 lines
  (`KEPT_LINES`), asks for 200 at a time (`PAGE_LINES`) and waits 300 ms after the last key
  before it asks for a typed text.
- Rust commands need `OPENFEO_NFT_SRC=$PWD/build/nft/src` and
  `OPENFEO_UAPI_INCLUDE=$PWD/build/kernel/headers/include` (the `make` targets set them). The
  unit gate is `make test`, never `cargo test --workspace` (that runs the QEMU suites). A
  harness scenario is `make test-harness FILTER=<name>`; no source is edited while one runs.

## Review Focus

What the design implies and a person will meet, most likely first. Each has its test in the
task that owns the code.

1. **A line with something odd in it.** A device's name with a newline or an escape sequence in
   a lease's line, markup in a hostname, a line of several megabytes. A line stays one line: a
   control character is written as its escape, a line over 16 KiB is cut and says so with `…`,
   and the page shows text as text. Tests in Task 2
   (`a_line_is_cut_at_its_limit_and_keeps_to_one_line`), Task 10 (`text is text`) and Task 13
   (`the file has one line for each line`).
2. **A flood, and a page left paused.** A storm of DEBUG lines, or Pause pressed and the tab
   left for an hour. The router's feed batches, moves a reader up when it is 1024 lines behind
   and says so; the page never holds more than 2000 lines, shown or waiting, and marks where
   lines were skipped. Tests in Task 5 (`a_reader_too_far_behind_is_moved_up_and_told`) and
   Task 13 (`what waits while paused is bounded, and its gap is marked`).
3. **A filter changed while an answer is on its way.** Typing quickly, or pressing a level
   twice: an answer to a question since changed is dropped, and a line that arrives between the
   subscription and the answer is shown once. Tests in Task 13 (`an answer to a filter since
   changed is dropped`, `a line that came by both roads is shown once`).
4. **A clock that was set after the line was written.** The router boots in 1970 or at its
   build's time and SNTP sets the clock a minute later: a line from before shows the time it
   was truly written, on the page and in the downloaded file. Tests in Task 13 (`a line's time
   is counted back from the router's two clocks`).
5. **A route through an interface that has gone.** A PPPoE session that came back is a new
   interface, and the kernel drops the old one's routes without saying so: the dump does not
   list them, and the Routes page with nothing to show for a family says so instead of an empty
   table. Tests in Task 3 (`a_removed_link_takes_its_routes_out_of_the_cache`), Task 8
   (`a_route_through_a_link_the_cache_does_not_have_is_left_out`) and Task 11 (`a family with
   no routes says so`).

---

## File Structure

| File | Responsibility |
|---|---|
| `SPEC.md` | §8.3, §8.4, §10 as amended |
| `crates/openfeo-runtime/src/log.rs` | the ring: lines as records, the waiter, reading on and reading back, the rule |
| `web/client/test/log-rule.cases.json` (new) | the rule's cases, read by the Rust test and the TypeScript one |
| `crates/openfeo-netlink/src/{types,monitor,apply}.rs`, `crates/openfeo-apply/src/routing.rs` | two more kinds of route; a removed link's routes |
| `docs/adr/0027-…md` (new, if Task 3 finds the quirk) | the routes the kernel drops with a link |
| `proto/openfeo/v1/api.proto` | `Logs`, the `logs` push, `DiagnosticsService`, `Error.topic` |
| `crates/openfeo-config/src/lib.rs` | the new messages, re-exported |
| `crates/openfeo-api/src/logs.rs` (new) | levels on the wire, a line on the wire, `LogFeed` |
| `crates/openfeo-api/src/{lib,limits,server,envelope,ws,grpc,listener,testing}.rs` | `ApiDeps.log`, `ApiDeps.routes`, the calls, the topic |
| `crates/openfeo/src/routes.rs` (new) | the cache's routes as the wire says them |
| `crates/openfeo/src/{router,api}.rs` | the ring and the cache handed to the API |
| `harness/src/apiclient.rs`, `harness/tests/{netlink,m4}.rs` | the calls from the LAN side; the scenarios |
| `web/client/src/{router,socket,messages,index}.ts`, `log-rule.ts` (new) | `dumpRoutes()`, `logs()`, `subscribe('logs')`, the rule |
| `web/client/itest/views.test.ts` (new) | the client against the VM |
| `web/ui/src/components/OfoCode.vue` (new), `icons.ts`, `index.ts`, `additions.css`, `docs/gaps.md` | the code block; three icons |
| `web/panel/src/model/{routes,ports,logs}.ts` (new), `model/format.ts` | what each page works out; bytes in words |
| `web/panel/src/pages/{Routes,Ports,Logs}.vue` (new), `save.ts` (new) | the pages; a file handed to the browser |
| `web/panel/src/{routes.ts,Shell.vue,live.ts,session.ts,layout.css}`, `test/fake-router.ts` | addresses, nav, the last counters, the fake's new calls |
| `web/panel/e2e/views.spec.ts` (new) | the browser run |
| `CLAUDE.md`, `docs/progress.md` | the harness notes; the log's entry |

---

### Task 1: SPEC amendments

**Files:**
- Modify: `SPEC.md` (§8.3, §8.4, §10)

- [ ] **Step 1: Amend the three places.**

  - **§8.3**, a new bullet after "M4 part 3b": "M4 part 3c: `DiagnosticsService` begins with
    `DumpRoutes`: every route the kernel holds, both families and every table, each with its
    table by name (`main`, `local`, a WAN's name for that WAN's own), its interface by name and
    who installed it. `SystemService` gains `Logs`: the newest lines of the log that match a
    level (it and everything more serious) and a text (anywhere in the line, without regard to
    ASCII case), at most 1000 a call, with whether older lines match and the router's two
    clocks; a caller reaches further back by the number of the oldest line it has. The topic
    `logs` sends every line written after the subscription, in batches of at most 256 lines and
    at most ten a second. It is queued as `events` is: a reader more than 1024 lines behind is
    moved up to there, is told so (`DATA_LOSS`, which now names the topic it is about) and keeps
    receiving. Sending the log writes no line of it."
  - **§8.4**, a new paragraph after "The settings pages (M4 part 3b)": "The views (M4 part 3c):
    Routes lists the main table and each WAN's own, one family at a time, each route with the
    WAN or LAN it belongs to, and leaves out the kernel's local table and the link-local and
    multicast entries every interface has. Ports is the port strip and a table of each port's
    link, what uses it, its MAC, its bus path and the bytes it has received and sent since the
    router started. Logs follows the log as it is written: a level shows itself and everything
    more serious, a text filters, Pause holds the view, Earlier lines reaches back and Download
    saves the whole log. A line's time is counted back from the router's two clocks, so a line
    written before the clock was set shows the time it was written. None of the three edits
    anything."
  - **§10**, in the first bullet, after "(default 8 MiB)": ", each line with a number that only
    grows, the time since the kernel booted and its level. The router's own lines are kept from
    DEBUG up and other crates' from INFO up; a line is at most 16 KiB and stays one line, a
    control character in it written as its escape. The ring is". The clause about `/state/log`
    stands as it is (the design's call 17).

- [ ] **Step 2: Commit** `spec: the views of M4 part 3c`.

---

### Task 2: The ring keeps records

**Files:**
- Modify: `crates/openfeo-runtime/src/log.rs`
- Create: `web/client/test/log-rule.cases.json`
- Modify: the two tests that read `Ring::tail` (`crates/openfeo/src/dhcp4.rs`,
  `crates/openfeo-api/src/config.rs`), for the text without its lead

**Interfaces:**
- Produces:

```rust
/// The most text one line holds; a longer one is cut on a character and ends with `…`.
pub const MAX_LINE: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Only grows; the first line written is 1.
    pub seq: u64,
    /// `clock::boot_ms()` when it was written.
    pub boot_ms: u64,
    pub level: Level,
    /// `message key=value`: no priority, and not the `openfeo:` the console's copy begins with.
    pub text: Arc<str>,
}

/// The rule of SPEC §8.3: this level and everything more serious, and this text anywhere in
/// the line without regard to ASCII case. `None` and the empty text match every line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter { pub level: Option<Level>, pub contains: String }
impl Filter { #[must_use] pub fn matches(&self, level: Level, text: &str) -> bool }

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page { /* oldest first */ pub lines: Vec<Line>, /* older lines match */ pub earlier: bool }

impl Ring {
    pub fn push(&self, level: Level, text: &str);          // replaces push(String)
    #[must_use] pub fn newest(&self) -> u64;                // 0 while nothing was written
    #[must_use] pub fn follow(&self) -> watch::Receiver<u64>; // the newest number, as it grows
    /// The lines after `seq`, oldest first: at most `lines` of them and `bytes` of text, and
    /// always one when there is one. A number the ring no longer holds reads on from its oldest.
    #[must_use] pub fn after(&self, seq: u64, lines: usize, bytes: usize) -> Vec<Line>;
    /// The newest lines that match and are before `before` (0: before nothing), within the
    /// same two bounds.
    #[must_use] pub fn page(&self, filter: &Filter, before: u64, lines: usize, bytes: usize) -> Page;
    #[must_use] pub fn tail(&self, n: usize) -> Vec<String>; // the texts of the last n
}
```

  `tracing::Level` orders the more serious as the lesser (`ERROR < WARN < INFO < DEBUG`), as
  the layer already relies on.

- [ ] **Step 1: Write the shared cases** in `web/client/test/log-rule.cases.json`. `wanted` is
  the level asked for, empty for every line.

```json
[
  { "level": "error", "text": "sntp: no answer from 203.0.113.1", "wanted": "error", "contains": "", "matches": true },
  { "level": "warn", "text": "pppoe wan0: 3 echoes unanswered", "wanted": "error", "contains": "", "matches": false },
  { "level": "warn", "text": "pppoe wan0: 3 echoes unanswered", "wanted": "warn", "contains": "", "matches": true },
  { "level": "error", "text": "x", "wanted": "info", "contains": "", "matches": true },
  { "level": "debug", "text": "x", "wanted": "info", "contains": "", "matches": false },
  { "level": "debug", "text": "x", "wanted": "debug", "contains": "", "matches": true },
  { "level": "debug", "text": "x", "wanted": "", "contains": "", "matches": true },
  { "level": "info", "text": "link p0 down", "wanted": "info", "contains": "P0 DOWN", "matches": true },
  { "level": "info", "text": "link p0 down", "wanted": "info", "contains": "p1", "matches": false },
  { "level": "info", "text": "link p0 down", "wanted": "info", "contains": " ", "matches": true },
  { "level": "info", "text": "link p0 down", "wanted": "error", "contains": "p0", "matches": false },
  { "level": "info", "text": "dhcp lan0: leased to Küche", "wanted": "info", "contains": "küche", "matches": true },
  { "level": "info", "text": "dhcp lan0: leased to Küche", "wanted": "info", "contains": "KÜCHE", "matches": false }
]
```

- [ ] **Step 2: Write the failing tests** in `log.rs`'s `tests`:

  - `numbers_only_grow_and_start_at_one`: three pushes are 1, 2, 3; in a ring of 64 bytes ten
    30-byte lines leave `newest() == 10` and `after(0, 99, usize::MAX)` beginning above 1.
  - `a_waiter_is_woken_by_the_next_line` (`#[tokio::test]`): `follow()` taken, a push, then
    `changed().await` returns and the value borrowed is 1.
  - `a_line_carries_its_level_and_the_time_since_boot`: an INFO and a DEBUG push keep their
    levels; the second's `boot_ms` is not less than the first's.
  - `the_ring_keeps_the_text_and_the_console_the_whole_line`: through the layer,
    `info!(mtu = 1500, "link up")` leaves the ring's text `link up mtu=1500` and the kmsg
    writer `<6>openfeo: link up mtu=1500\n`.
  - `reading_on_from_a_number_has_no_gap_and_no_repeat`: of ten lines, `after(4, 3, MAX)` is
    5, 6, 7; `after(7, 99, MAX)` is 8, 9, 10; `after(10, …)` is empty; after the ring has
    dropped 1 to 4, `after(2, …)` begins at 5.
  - `reading_on_stops_at_its_bytes_and_still_gives_a_line`: of 100-byte lines, 250 bytes give
    two and 10 bytes give one.
  - `a_page_is_the_newest_that_match_oldest_first`: of
    `[info a, warn b, debug c, error d, info e, warn f]`, level WARN and two lines give
    `[d, f]` with `earlier`; then `before` = d's number gives `[b]` without it. Level `None`
    in pages of four, each `before` the first of the one before, gives every line once, in
    order when the pages are laid oldest first.
  - `the_rule_is_held_to_the_shared_cases`: every case of the JSON file
    (`include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/client/test/log-rule.cases.json"))`)
    gives its `matches`.
  - `a_line_is_cut_at_its_limit_and_keeps_to_one_line`: 20 KiB of `ü` is kept as at most
    `MAX_LINE` bytes and `…`, cut on a character; `"a\nb\u{1b}[31m"` is kept as
    `a\nb\u{1b}[31m` spelled out (the backslash forms, as `char::escape_default` writes them),
    and `Küche` is kept as it is.
  - `another_crates_line_below_info_is_not_kept`: through the layer,
    `debug!(target: "h2::codec::framed_write", "send")` leaves the ring empty, the same at
    `info!` is kept, and `debug!(target: "openfeo_api::ws", "x")` is kept.

- [ ] **Step 3: Run** `cargo test -p openfeo-runtime --lib log::` and see them fail to compile
  on the new names.

- [ ] **Step 4: Implement.** The ring holds `VecDeque<Line>` whose numbers have no gaps, so the
  line of a number is found by its distance from the first; the bound still counts the bytes of
  text alone. `push` stamps the number and `clock::boot_ms()`, cuts and escapes the text,
  releases the lock and only then moves the watch (`send_replace`), so that a waiter is never
  woken with the lock held and nothing in the path logs. The layer's `enabled` admits DEBUG and
  more serious for a target that begins with `openfeo`, and INFO and more serious for any
  other. `format_line` goes on writing the console's line; the ring is given the text alone.
  The existing three tests and the two outside the crate are brought to the new text.

- [ ] **Step 5: Run** `cargo test -p openfeo-runtime --lib`, `cargo test -p openfeo
  --all-features dhcp4::` and `cargo test -p openfeo-api --lib --all-features config::`: pass.

- [ ] **Step 6: Commit** `runtime: the log ring keeps each line with a number, a time and a level`.

---

### Task 3: The kinds of route, and a link that goes

**Files:**
- Modify: `crates/openfeo-netlink/src/types.rs` (`RouteKind`), `monitor.rs` (`route_from`,
  `apply_link`), `apply.rs` (`describe`, `route_message`)
- Modify: `crates/openfeo-apply/src/routing.rs` (the two matches on the kind)
- Test: `crates/openfeo-netlink/src/monitor.rs`, `harness/tests/netlink.rs`
- Create, if Step 2 fails as expected: `docs/adr/0027-the-kernel-does-not-announce-the-routes-it-drops-with-a-link.md`

**Interfaces:**
- Produces: `RouteKind::{Unicast, Blackhole, Unreachable, Prohibit, Local}`, the two new ones
  added after the three that exist so that the order of those is unchanged. `Local` is
  `RTN_LOCAL`, `RTN_BROADCAST`, `RTN_ANYCAST` and `RTN_MULTICAST`: the kernel's own entries for
  its addresses. Any other kind is `Unicast`, as now. A route keeps its `oif` when it is
  `Unicast` or `Local`; ADR-0020's clearing applies to the three that refuse.

- [ ] **Step 1: Write the failing unit tests** in `monitor.rs`:

  - `the_kernels_own_entries_are_local_and_keep_their_interface`: a route message of kind
    Local, one of Broadcast and one of Multicast, each with an output interface, parse as
    `RouteKind::Local` with `oif` kept.
  - `a_prohibit_route_is_its_own_kind_and_has_no_interface`.
  - `a_link_that_goes_takes_its_routes_with_it`: a cache with link 7, a route through 7 and a
    route through 8; `RTM_DELLINK` for 7 leaves only the route through 8, and says the cache
    changed.

- [ ] **Step 2: Write the sandbox test** `a_removed_link_takes_its_routes_out_of_the_cache` in
  `harness/tests/netlink.rs`, registered as the suite's others are. On a VLAN sub-interface
  made as `vlan_link_primitive_and_facts` makes one: `192.0.2.1/24` on it, the link up, and the
  route `198.51.100.0/24 via 192.0.2.2` with protocol 200. Wait until the cache holds the
  route; remove the link; wait until the cache has no such link; then for two seconds the
  cache must hold no route whose `oif` is the removed index, else fail with "the cache still
  holds 198.51.100.0/24 through a link that is gone".

- [ ] **Step 3: Run** the unit tests (they fail: no such variants; the route through 7 stays)
  and `make test-harness FILTER=a_removed_link_takes_its_routes_out_of_the_cache`. The kernel
  is expected to say nothing of the IPv4 routes it drops with a link, so the sandbox test is
  expected to fail with its message. **If it passes**, this kernel does announce them: keep the
  test, leave `apply_link` as it is, drop the third unit test, write no ADR, and say so in the
  ledger.

- [ ] **Step 4: Implement.** The two variants, their parsing, and the four matches: `describe`
  says `prohibit ` and `local ` as it says `blackhole `; `route_message` writes
  `RouteType::Prohibit` and `RouteType::Local`; the two matches in `openfeo-apply` treat the
  new kinds as kinds the router never installs. `apply_link`, on a removal, also drops every
  route whose `oif` is the removed index: whatever was routed through a link is gone with it,
  in both families, and the IPv6 deletions the kernel does announce then find nothing.

- [ ] **Step 5: Write ADR-0027** (Context: what the sandbox test saw, on which kernel; Decision:
  the monitor drops a removed link's routes itself; Consequences: a link that is set down and
  kept loses its IPv4 routes as silently and is not covered, the router sets no link down that
  it keeps, and a change to that needs a fresh dump of the routes).

- [ ] **Step 6: Run** `cargo test -p openfeo-netlink --lib`, `cargo test -p openfeo-apply
  --lib` and the sandbox test: pass. Run `make test-harness FILTER=routing` to see that the
  routing scenarios that read the cache still pass.

- [ ] **Step 7: Commit** `netlink: the kernel's own routes are their own kind, and a link that goes takes its routes`.

---

### Task 4: `SystemService.Logs`

**Files:**
- Modify: `proto/openfeo/v1/api.proto`, `crates/openfeo-config/src/lib.rs` (re-exports)
- Create: `crates/openfeo-api/src/logs.rs`
- Modify: `crates/openfeo-api/src/{lib,limits,server,ws,grpc,listener,testing}.rs`,
  `crates/openfeo-api/src/config.rs` (its two `SharedParts`), `crates/openfeo/src/api.rs`
- Regenerate: `web/client/src/gen` (`make web-gen`)

**Interfaces:**
- Consumes: Task 2's `Ring`, `Line`, `Filter`, `Page`.
- Produces: in `api.proto`, `LogLevel`, `LogLine`, `LogsRequest` and `LogsResponse` exactly as
  the design gives them ("The log on the wire"), `rpc Logs(LogsRequest) returns (LogsResponse)`
  in `SystemService`, and `logs = 12` in both `Request.body` and `Response.body`.
  `ApiDeps.log: Arc<Ring>` ("the log the router keeps"), carried into `Shared`.
  In `limits.rs`: `MAX_LOG_LINES: usize = 1000`, `MAX_LOG_BYTES: usize = 512 * 1024`. In
  `logs.rs`:

```rust
/// The level a request names: `Ok(None)` for unspecified, `Err` for a number that is no level.
pub fn level_of(wire: i32) -> Result<Option<Level>, NoSuchLevel>;
pub fn to_pb(line: &Line) -> LogLine;
```

  In `server.rs`: `Shared::clocks(&self) -> (u64, u64)` (the time since boot and the wall
  clock steadied as `state()` steadies it) and
  `Shared::logs(&self, ask: &LogsRequest) -> Result<LogsResponse, Error>`.

- [ ] **Step 1: Add the messages and the call to the schema**, re-export them, regenerate the
  web client's code, and give every constructor of `ApiDeps` and `SharedParts` a ring: the
  testing rig one of its own, which its tests write to (`Rig::log`), and `crates/openfeo` for
  now a ring that nothing writes to, which Task 8 replaces with the router's.

- [ ] **Step 2: Write the failing tests** (in `logs.rs`, through the rig on the WebSocket
  unless it says gRPC):

  - `logs_answers_the_newest_that_match_with_the_two_clocks`: the rig's ring holds an INFO, a
    WARN and a DEBUG line; level INFO answers the first two, oldest first, each with its
    number, level and text; `uptime_ms` is not less than the newest line's and `time_unix_ms`
    is not 0. The same call over gRPC answers the same lines.
  - `logs_filters_by_text_whatever_its_case`: `contains: "P0 DOWN"` finds `link p0 down`.
  - `logs_reaches_back_without_a_gap_or_a_repeat`: thirty lines read seven at a time, each
    call's `before_seq` the first number of the answer before, are the thirty once; the last
    answer says no `earlier`, the others say it.
  - `logs_answers_at_most_a_thousand_lines`: of 1500 lines, `limit: 0` and `limit: 5000` each
    answer the newest 1000 and say `earlier`.
  - `logs_answers_at_most_its_bytes`: of 100 lines of 16 KiB, one answer holds no more than
    `MAX_LOG_BYTES` of text and says `earlier`.
  - `logs_refuses_a_level_that_is_none`: level 9 is `INVALID_ARGUMENT`, "no such level".
  - `logs_needs_a_session` (gRPC): without a token, `Unauthenticated`.

- [ ] **Step 3: Run** `cargo test -p openfeo-api --lib --all-features logs::`: they fail (the
  call answers nothing yet).

- [ ] **Step 4: Implement** `level_of`, `to_pb`, `Shared::clocks`, `Shared::logs` (a limit of 0
  or above the cap is the cap), the arm in `ws::perform` and `SystemService::logs` in
  `grpc.rs`, which needs a session as `reboot` does.

- [ ] **Step 5: Run** the crate's tests, `scripts/check-proto.sh` and `make web-lint`: pass.

- [ ] **Step 6: Commit** `api: SystemService.Logs reads the log by level and text`.

---

### Task 5: The topic `logs`

**Files:**
- Modify: `proto/openfeo/v1/api.proto`, `crates/openfeo-config/src/lib.rs`
- Modify: `crates/openfeo-api/src/{logs,limits,envelope,ws,grpc,server}.rs`
- Regenerate: `web/client/src/gen`

**Interfaces:**
- Consumes: Task 4's `to_pb`, `Shared::clocks`; Task 2's `Ring::{follow, after, newest}`.
- Produces, in `api.proto`:

```proto
// Lines of the log written since the subscription, or since the batch before.
message LogBatch {
  // Oldest first.
  repeated LogLine lines = 1;
  // The router's two clocks now, as in LogsResponse.
  uint64 uptime_ms = 2;
  uint64 time_unix_ms = 3;
}
```

  `LogBatch logs = 6` in `ServerMsg.body` (queued, beside `event`; `Telemetry` stays the
  coalesced pushes), `LogBatch logs = 5` in `SubscribeResponse.body`, and in `Error`:
  `// With DATA_LOSS on a subscription: the topic whose pushes were dropped.` `string topic = 4;`
  `Subscribe.topic`'s comment names `logs`. In `limits.rs`: `LOG_BATCH: usize = 256`,
  `LOG_QUEUE: u64 = 1024`, `LOG_PACE: Duration = Duration::from_millis(100)`. In `logs.rs`:

```rust
/// One reader's place in the ring. It holds no lines: the ring is the queue.
pub struct LogFeed { /* the ring, its watch, the last number sent, when the last batch left */ }
pub struct Batch { pub lines: Vec<Line>, /* lines were skipped before these */ pub lost: bool }
impl LogFeed {
    /// From the line after the newest there is now.
    pub fn from_now(ring: &Arc<Ring>) -> Self;
    /// The next lines, once there are some and `LOG_PACE` has passed since the last batch.
    /// Cancel-safe: it moves its place only as it returns.
    pub async fn next(&mut self) -> Batch;
}
```

  In `envelope.rs`: `Topic::Logs` (`"logs"`), `Conn::push_logs(&mut self, batch: LogBatch,
  lost: bool)`. A loss on `logs` is told once, before the batch that follows the gap, as
  `Error { code: DataLoss, message: "log lines were dropped: this reader fell behind", topic:
  "logs" }`; the notice for events keeps its words and gains `topic: "events"`.
  In `server.rs`: `Shared::log_batch(&self, lines: &[Line]) -> LogBatch`.

- [ ] **Step 1: Add the message, the three fields and the constants**; re-export; regenerate.

- [ ] **Step 2: Write the failing tests.**

  In `logs.rs` (time paused where a pace is measured):
  - `a_feed_begins_after_what_was_already_written`.
  - `lines_written_between_two_reads_come_once_and_in_order`.
  - `a_batch_holds_at_most_256_lines`: 600 written, then batches of 256, 256 and 88, none
    `lost`.
  - `a_reader_too_far_behind_is_moved_up_and_told`: 1524 written while nobody reads; the
    first batch is `lost` and begins 1023 before the newest; the batches after are not `lost`
    and run on without a gap to the newest.
  - `a_ring_that_dropped_what_was_not_read_is_a_loss_too`: a small ring turns over twice
    between two reads; the batch is `lost` and begins at the oldest line the ring holds.
  - `batches_leave_at_most_ten_a_second`: a line written 10 ms after a batch left is given
    100 ms after that batch, not before.
  - `a_wait_that_is_dropped_loses_no_line`: `next()` raced against a branch that is ready and
    dropped, a line written, and the next `next()` gives it.

  In `envelope.rs`:
  - `logs_is_a_topic_by_name`; `a_batch_is_not_sent_to_a_reader_that_did_not_ask`;
    `a_loss_on_logs_is_told_once_before_the_batch_and_names_logs`;
    `a_loss_on_events_names_events`.

  Through the rig, each on a current-thread runtime with the rig's ring behind
  `tracing::subscriber::set_default(subscriber("openfeo", ring, None))`, so that whatever the
  server writes while it sends lands in that ring:
  - `a_subscriber_is_sent_what_is_written_after_it_subscribed` (WebSocket): a line written
    before is not sent; `info!("one line")` after arrives in a `logs` push with its number, its
    level, the text `one line` and the two clocks.
  - `sending_the_log_writes_no_line` (WebSocket): after that push is read and half a second
    more, the ring's `newest()` is still the number of `one line`.
  - `sending_the_log_over_grpc_writes_no_line`: the same through `StateService.Subscribe` with
    the topic `logs`.
  - `a_grpc_stream_that_fell_behind_ends_with_data_loss`: as it does for events.

- [ ] **Step 3: Run** `cargo test -p openfeo-api --lib --all-features`: the new ones fail.

- [ ] **Step 4: Implement.** `LogFeed::next` waits on the watch and on the pace, then reads
  `ring.after(last, LOG_BATCH, MAX_LOG_BYTES)`; a newest number more than `LOG_QUEUE` past the
  last one sent moves the place to `LOG_QUEUE` behind the newest, and that, or a first line
  that is not the one after the last sent, is a loss. `Feeds` in `ws.rs` gains the feed,
  started and dropped by `follow` as the counters' subscription is, and `drive` an arm that
  hands a batch to the connection. `grpc::feed` does the same, and `stream_item` carries a
  batch as `subscribe_response::Body::Logs`. Nothing on these paths logs at any level.

- [ ] **Step 5: Run** the crate's tests, `scripts/check-proto.sh`, `make web-lint`: pass.

- [ ] **Step 6: Commit** `api: the topic logs sends what is written, in batches`.

---

### Task 6: `DiagnosticsService.DumpRoutes`

**Files:**
- Modify: `proto/openfeo/v1/api.proto`, `crates/openfeo-config/src/lib.rs`
- Modify: `crates/openfeo-api/src/{lib,server,ws,grpc,listener,testing}.rs`,
  `crates/openfeo-api/src/config.rs`, `crates/openfeo/src/api.rs`
- Regenerate: `web/client/src/gen`

**Interfaces:**
- Produces: in `api.proto`, `RouteKind`, `Route`, `DumpRoutesRequest` and `DumpRoutesResponse`
  exactly as the design gives them ("Routes on the wire"),
  `service DiagnosticsService { rpc DumpRoutes(DumpRoutesRequest) returns (DumpRoutesResponse); }`
  and `dump_routes = 13` in both `Request.body` and `Response.body`. In `lib.rs`, beside
  `Restarter`:

```rust
/// Where the routes are read from: the router's view of the kernel's tables.
pub trait RouteSource: Send + Sync {
    /// Every route, as the wire says it.
    fn routes(&self) -> Vec<Route>;
}
```

  and `ApiDeps.routes: Arc<dyn RouteSource>`. The generated `Route` is re-exported from
  `openfeo_config::api` beside the firewall's `Rule`.

- [ ] **Step 1: Add the schema**, re-export, regenerate, and give every constructor a source:
  the rig one whose routes a test sets (`Rig::routes`), `crates/openfeo` for now one that has
  none, which Task 8 replaces.

- [ ] **Step 2: Write the failing tests** through the rig:
  - `dump_routes_answers_what_the_source_has`: two routes set, answered in order with every
    field, on the WebSocket and over gRPC.
  - `dump_routes_needs_a_session` (gRPC): without a token, `Unauthenticated`.

- [ ] **Step 3: Run** them: fail. **Step 4: Implement** the arm in `ws::perform`,
  `impl DiagnosticsService for Grpc`, and its `route_service` line in `lib.rs::routes`.

- [ ] **Step 5: Run** the crate's tests, `scripts/check-proto.sh`, `make web-lint`: pass.

- [ ] **Step 6: Commit** `api: DiagnosticsService begins with DumpRoutes`.

---

### Task 7: The harness asks, and is not yet answered

**Files:**
- Modify: `harness/src/apiclient.rs`, `harness/tests/m4.rs`

**Interfaces:**
- Produces, on `Ws`:

```rust
pub fn routes(&mut self) -> Result<Vec<Route>>;
pub fn logs(&mut self, ask: LogsRequest) -> Result<Result<LogsResponse, Error>>;
/// The next line pushed on `logs` whose text matches; a DATA_LOSS that names `logs` is an error.
pub fn log_line(&mut self, timeout: Duration, wanted: &Regex) -> Result<LogLine>;
/// Every line the ring holds up to its newest now, oldest first, read back in pages of `page`.
pub fn whole_log(&mut self, page: u32) -> Result<Vec<LogLine>>;
```

  and on `Api`: `grpc_dump_routes(&self, token: Option<&str>) -> Result<Result<Vec<Route>,
  tonic::Status>>`, `grpc_logs(&self, token: Option<&str>, ask: LogsRequest) ->
  Result<Result<LogsResponse, tonic::Status>>`.

- [ ] **Step 1: Write the client's methods and three scenarios**, registered as the suite's
  others are, each ending with `no_task_failed` and `password_never_logged`:

  - `the_routes_dump_has_the_default_route_and_each_lans_subnet`: on `vm-dhcp.toml`, once
    `wan0` is up. In the table `main` there is an IPv4 default (empty destination) of kind
    UNICAST whose gateway and interface are the state's `gateway4` and `interface` for `wan0`,
    installed by `openfeo`; and `192.168.1.0/24` with no gateway, through `br-lan0`, installed
    by `kernel`. In the table `local` there is an entry of kind LOCAL for `192.168.1.1/32`.
    The gRPC call answers the same routes, and without a token is `Unauthenticated`. With
    `p0`'s carrier taken and `wan0` down in the state, the dump agrees with the state's
    `default4`: `main` has an IPv4 default of kind UNICAST through `wan0`'s interface exactly
    when the state says `wan0` carries one. With the carrier given back and `wan0` up, it has
    one again.
  - `the_log_is_read_by_level_and_text_and_followed`: after a login, `Logs` at INFO with
    `contains: "ADMIN: LOGIN FROM"` answers at least one line and each holds
    `admin: login from`; at ERROR every line answered is an error. `whole_log(5)` and
    `whole_log(1000)`, cut at the same newest number, are the same lines, their numbers
    rising by one. A socket then subscribes to `logs`, `p0`'s carrier is taken, and
    `log_line(SOON, ^link p0 down$)` arrives at INFO with a number above the newest read
    before; `Logs` with `contains: "link p0 down"` answers a line of that number. `grpc_logs`
    answers the same line.
  - `no_line_in_the_log_holds_a_password_or_a_token`: the first password is set, a login with
    `lab-wrong-password` is refused and one with the lab's password is not, a socket is opened
    and a gRPC call made with the token. `whole_log(1000)` then has a line holding
    `admin: login from` and one holding `admin: login refused from`, and no line holding the
    lab's password, the wrong one, or either token.

- [ ] **Step 2: Run** `make test-harness FILTER=the_routes_dump`, `FILTER=the_log_is_read` and
  `FILTER=no_line_in_the_log`. Each fails for want of an answer: no default route in an empty
  dump, no login line in an empty log (twice). Keep the three failures' words in the ledger.

- [ ] **Step 3: Commit** `harness: the routes and the log, asked from the LAN`.

---

### Task 8: The router answers

**Files:**
- Create: `crates/openfeo/src/routes.rs`
- Modify: `crates/openfeo/src/{router,api,main}.rs`

**Interfaces:**
- Consumes: Task 6's `RouteSource`; Task 3's kinds; `openfeo_netlink::{Cache, TABLE_MAIN,
  RTPROT_OPENFEO}`.
- Produces:

```rust
/// The cache's routes as the wire says them. `wans` are the WANs' names in config order: the
/// table `100 + n` is the nth one's own.
pub fn routes_of(cache: &Cache, wans: &[String]) -> Vec<Route>;
pub struct RouterRoutes { /* the cache's receiver, the World's */ }
impl RouteSource for RouterRoutes { … }
```

  `init_logging() -> Arc<Ring>`, and `api::spawn` takes the ring and the cache's receiver.

- [ ] **Step 1: Write the failing tests** in `routes.rs`:
  - `a_table_is_said_by_name`: 254 is `main`, 255 is `local`; with WANs `[wan0, wan1]`, 100 is
    `wan0`, 101 is `wan1` and 102 is `102`.
  - `the_default_route_has_no_destination`, and a route to `2001:db8:1::/48` says it so.
  - `a_route_says_its_gateway_and_its_interface_by_name`, each empty when there is none.
  - `a_route_through_a_link_the_cache_does_not_have_is_left_out`.
  - `who_installed_it_is_a_word_or_the_number`: 2 is `kernel`, 200 is `openfeo`, 9 is `ra`,
    16 is `16`.
  - `each_kind_is_said`: the five kinds, and the metric is the priority.

- [ ] **Step 2: Run** `cargo test -p openfeo --all-features routes::`: fail.

- [ ] **Step 3: Implement** `routes_of` and `RouterRoutes` (the WANs' names from the World's
  config), have `init_logging` return the ring it gives the subscriber, and hand that ring and
  `cache_rx` to `api::spawn` in place of Task 4's and Task 6's stand-ins.

- [ ] **Step 4: Run** `make test` and the three scenarios of Task 7: pass.

- [ ] **Step 5: Commit** `router: the API is given the log and the kernel's routes`.

---

### Task 9: The client

**Files:**
- Modify: `web/client/src/{router,socket,messages,index}.ts`
- Create: `web/client/src/log-rule.ts`, `web/client/test/logs.test.ts`,
  `web/client/itest/views.test.ts`
- Modify: `web/client/test/socket.test.ts`, `harness/tests/m4.rs`

**Interfaces:**
- Produces:

```ts
// router.ts
dumpRoutes(): Promise<Route[]>
logs(ask?: { level?: LogLevel; contains?: string; beforeSeq?: bigint; limit?: number }): Promise<LogsResponse>
subscribe(topic: 'logs', onPush: (batch: LogBatch) => void, options?: { onLost?: () => void }): Subscription

// log-rule.ts: the router's rule (SPEC §8.3), for a line that arrives live.
export function logMatches(line: { level: LogLevel; text: string }, level: LogLevel, contains: string): boolean
```

  `Topic` gains `'logs'`. Exported beside what is there: `logMatches`, the enums `RouteKind`
  and `LogLevel`, the types `Route`, `LogLine`, `LogBatch`, `LogsResponse`.

- [ ] **Step 1: Write the failing tests.**

  `test/logs.test.ts`:
  - `the rule is held to the shared cases`: every case of `log-rule.cases.json` gives its
    `matches` (the last pair is why the text is folded by ASCII alone, and not by
    `toLowerCase`).
  - `logs asks with what it was given and answers the lines`, `dumpRoutes answers the routes`,
    each against the scripted socket, the request's fields read back.

  `test/socket.test.ts`:
  - `a batch pushed on logs reaches its listeners`.
  - `a loss that names logs is told to the logs listeners and not the events ones`, and the
    other way about; a loss that names nothing is the events', as it was.
  - `a logs subscription made again after a reconnect says lines may have passed`: `onLost`
    once, after the new socket has subscribed.

- [ ] **Step 2: Run** `make web-test`: the new ones fail. **Step 3: Implement.**
  **Step 4: Run** `make web-test` and `make web-lint`: pass.

- [ ] **Step 5: Write the client's run against the VM**, `itest/views.test.ts`:
  - `the routes have the default route and the LAN`: as the harness scenario reads them.
  - `the log is read back, and a cut WAN is pushed as its line`: `logs({ level: LogLevel.INFO,
    contains: 'admin: login' })` has a line; a subscription to `logs`, then the lab's
    `wan-down`, and a batch arrives holding `link p0 down`, which `logMatches` at INFO and
    does not at ERROR; `wan-up` after.

  and the scenario `the_javascript_client_reads_the_routes_and_the_log_from_the_lan` in
  `harness/tests/m4.rs`, made as `the_javascript_client_works_from_the_lan` is, naming
  `views.test`. Run it: pass.

- [ ] **Step 6: Commit** `client: the routes, the log and its feed`.

---

### Task 10: `OfoCode`, and three icons

**Files:**
- Create: `web/ui/src/components/OfoCode.vue`
- Modify: `web/ui/src/{index.ts,icons.ts}`, `web/ui/additions.css`, `web/ui/docs/gaps.md`
- Test: `web/ui/test/components.test.ts`

**Interfaces:**
- Produces:

```ts
// OfoCode (CodeBlock.md): lines in mono on the sunken surface, in the four tones and no other.
defineProps<{
  lines: { key: string; parts: { text: string; tone?: 'dim' | 'ok' | 'warn' | 'err' }[] }[]
  /** What the block holds, for assistive tech. */
  label: string
  /** Lines are added as they happen: announced politely, as a log. */
  live?: boolean
  /** A long line wraps instead of running off to the right. */
  wrap?: boolean
}>()
```

  Icons `route`, `ethernet-port` and `file-text`, from `lucide-static` as the others are.

- [ ] **Step 1: Write the failing tests**:
  - `OfoCode draws each line's parts in their tones`: a `pre.ofo-code` whose text is the lines
    joined by newlines; a part with a tone is a span of `ofo-code__<tone>`, one without is
    bare text.
  - `text is text`: a part `<b>x</b>` is shown as those seven characters and makes no element.
  - `a live block is a log to assistive tech`: `role="log"` and `aria-live="polite"` with
    `live`, neither without; the label is its `aria-label`.
  - `a block told to wrap has the class that wraps`.
  - `route`, `ethernet-port` and `file-text` are icons with shapes.

- [ ] **Step 2: Run, fail. Step 3: Implement.** The copy of `ofo.css` has the block and its
  tones; what it lacks (wrapping a long line) goes in `additions.css` as `.ofo-code--wrap` and
  is said in `docs/gaps.md`, with the three icons.

- [ ] **Step 4: Run** `make web-test` and `make web-lint`: pass.

- [ ] **Step 5: Commit** `ui: OfoCode, and icons for routes, ports and logs`.

---

### Task 11: The Routes page

**Files:**
- Create: `web/panel/src/model/routes.ts`, `web/panel/src/pages/Routes.vue`,
  `web/panel/test/routes-model.test.ts`, `web/panel/test/routes-page.test.ts`
- Modify: `web/panel/src/{routes.ts,Shell.vue,session.ts}`, `web/panel/test/{fake-router.ts,shell.test.ts}`

**Interfaces:**
- Consumes: the client's `dumpRoutes()`, `Route`, `RouteKind`; `LIVE`'s `state`.
- Produces:

```ts
// model/routes.ts
export interface RouteRow { key: string; destination: string; via: string; how: 'gateway' | 'link' | 'refused'; interface: string; belongsTo: string }
/** The routes of one family that a person reads: what the page shows, in its order. */
export function routeRows(routes: Route[], state: State, v6: boolean): RouteRow[]
```

  `PAGES` gains `routes: '/routes'`, `ports: '/ports'` and `logs: '/logs'` (the last two for
  Tasks 12 and 13). `PanelRouter` picks `dumpRoutes` and `logs`. The fake router gains
  `routesNow: Route[] | RouterError`, `calls.dumpRoutes` and `holdCall('dumpRoutes')`.

- [ ] **Step 1: Write the failing model tests** (`routes-model.test.ts`):
  - `the page shows main and the WANs' own tables, and not the kernel's`: a route in `local`,
    one of kind LOCAL, and ones to `fe80::/64`, `ff00::/8` and `224.0.0.0/4` are left out;
    only the family asked for is shown.
  - `the default route is called default, and main comes first`: main's rows, then each
    WAN's own table in the state's order of WANs, then any other table; inside a table the
    default first and the rest as the router sent them.
  - `via is the gateway, the link, or a refusal`: a gateway as it is; none, `on the link`;
    UNREACHABLE, BLACKHOLE and PROHIBIT, `refused`.
  - `a route belongs to whoever's interface it leaves by`: `ppp-wan0` is `wan0`, `br-iot` is
    `iot`.
  - `a route in a WAN's own table belongs to that WAN, and says the table`: `wan0, its own
    table`.
  - `a refused block inside a WAN's prefix is the part no LAN uses`: a blackhole for
    `2001:db8:1::/48` with `wan0`'s `ipv6Prefixes` holding it is `wan0, the part of its prefix
    no LAN uses`.
  - `a route that is nobody's says so with a dash`: `—`.

- [ ] **Step 2: Write the failing page tests** (`routes-page.test.ts`, mounted as the Leases
  page's are):
  - `the page reads the routes when it opens and shows the IPv4 ones`: header `Routes`, `Where
    the router sends traffic for each destination, as it is now.`; the choice `IPv4 | IPv6`
    named `Family`; columns `Destination`, `Via`, `Interface`, `Belongs to`; under the table
    `A view: the routes follow from the WAN and LAN settings, and there is nothing to edit
    here.`
  - `choosing IPv6 shows the other family without asking again`.
  - `a family with no routes says so`: `No IPv6 routes.`, and no table.
  - `the routes are read again when the state changes`: a pushed state with another
    generation makes one more call, and the table follows its answer.
  - `an older answer does not replace a newer one`: two calls held, answered in the wrong
    order.
  - `a dump that fails says so and can be tried again`: `The routes could not be read from the
    router.` with `Try again`; routes read before stay on screen.
  - in `shell.test.ts`: the navigation reads Dashboard; Network: WAN, LAN & DHCP, Leases,
    Firewall, DNS, Routes; Router: Ports, Logs, System; and none of the three new pages shows
    the save bar.

- [ ] **Step 3: Run** `make web-test`: fail. **Step 4: Implement** the model, the page (a
  skeleton until the first answer; `page__wide` is not needed for four columns), the three
  addresses and the three navigation entries (`route`, `ethernet-port`, `file-text`), with the
  pages of Tasks 12 and 13 as their routes once they exist.

- [ ] **Step 5: Run** `make web-test` and `make web-lint`: pass.

- [ ] **Step 6: Commit** `panel: the Routes page`.

---

### Task 12: The Ports page

**Files:**
- Create: `web/panel/src/model/ports.ts`, `web/panel/src/pages/Ports.vue`,
  `web/panel/test/ports-model.test.ts`, `web/panel/test/ports.test.ts`
- Modify: `web/panel/src/{live.ts,routes.ts}`, `web/panel/src/model/format.ts`,
  `web/panel/test/{format.test.ts,live.test.ts}`

**Interfaces:**
- Consumes: `model/dashboard.ts`'s `ports(state)` for the strip; `portSpeed`.
- Produces:

```ts
// live.ts
/** The counters as the router last read them; `null` until it first has. */
counters: Ref<Counters | null>

// model/format.ts: a count of bytes in words, by thousands: `0 B`, `999 B`, `1.0 kB`, `412.8 GB`.
export function bytes(count: bigint): string

// model/ports.ts
export interface PortRow {
  name: string; up: boolean
  /** `2500 Mbit/s`; empty when the link is down or the driver does not say. */
  speed: string
  uses: { to: string; name: string; tag: number }[]
  mac: string; hardware: string
  /** Bytes in words, or `—` until a sample has come. */
  received: string; sent: string
}
export function portRows(state: State, counters: Counters | null): PortRow[]
```

- [ ] **Step 1: Write the failing tests.**
  - `format.test.ts`, `bytes are said by thousands with one decimal`: `0n` is `0 B`, `999n` is
    `999 B`, `1000n` is `1.0 kB`, `412_800_000_000n` is `412.8 GB`, `2_500_000_000_000_000n`
    is `2500.0 TB`.
  - `ports-model.test.ts`: `a row for each port, in port order`; `a use is a link to its WAN's
    or LAN's page, with its tag` (`/wan/wan0` and tag 911, `/lan/iot` and tag 20, tag 0 for
    none); `the counters are the port's own link's`, by name; `no sample yet is a dash`; `a
    port the counters do not name is a dash`.
  - `live.test.ts`: `the last counters are kept as they came`.
  - `ports.test.ts`: `the page shows the strip and a row for each port`: header `Ports`, `The
    sockets on the box, in the order they are on it.`; columns `Port`, `Link`, `Used by`,
    `MAC`, `Hardware`, `Received`, `Sent`; a port that is up says `Up` in the ok tone with its
    speed beside it, one that is not says `No cable`; a port nothing uses says `Not in use`;
    uses are links, `wan0, tag 911`, two of them joined by ` · `; under the table `A view: a
    port is given to a WAN or a LAN on that WAN's or LAN's own page. Received and Sent count
    from when the router started.` `the counters move as samples come`: a pushed sample
    changes Received without a call being made.

- [ ] **Step 2: Run, fail. Step 3: Implement** (the table takes `page__wide`; MAC, Hardware,
  Received and Sent are mono, the last two numeric). **Step 4: Run** `make web-test` and
  `make web-lint`: pass.

- [ ] **Step 5: Commit** `panel: the Ports page`.

---

### Task 13: The Logs page

**Files:**
- Create: `web/panel/src/model/logs.ts`, `web/panel/src/pages/Logs.vue`,
  `web/panel/src/save.ts`, `web/panel/test/logs-model.test.ts`, `web/panel/test/logs.test.ts`
- Modify: `web/panel/src/{routes.ts,layout.css}`, `web/panel/test/fake-router.ts`

**Interfaces:**
- Consumes: the client's `logs()`, `subscribe('logs')`, `logMatches`; `OfoCode`,
  `OfoSegmented`, `OfoInput`, `OfoButton`.
- Produces:

```ts
// model/logs.ts
export const KEPT_LINES = 2000
export const PAGE_LINES = 200
export const TYPING_MS = 300
export type Row = { kind: 'line'; line: LogLine } | { kind: 'gap'; key: string }
export interface Clocks { uptimeMs: bigint; timeUnixMs: bigint }
/** What to show once the router has answered: its lines, then those that came live and are newer. */
export function joined(answer: LogLine[], live: LogLine[]): Row[]
/** `rows` with `lines` after them: no line twice, and the oldest dropped beyond `kept`. */
export function appended(rows: Row[], lines: LogLine[], kept?: number): Row[]
/** `rows` with a mark that lines were skipped here; never two marks together. */
export function gapped(rows: Row[]): Row[]
/** When a line was written, by the router's clocks as it last gave them. */
export function writtenAt(line: LogLine, clocks: Clocks): Date
export function levelWord(level: LogLevel): 'error' | 'warn' | 'info' | 'debug'
/** `<router>-log-20261128-143312.txt`, the time in the browser's zone. */
export function fileName(hostname: string, at: Date): string
/** `2026-11-28T14:33:12.000Z info  api: login from 192.168.1.142`: UTC, the level padded to five. */
export function fileLine(line: LogLine, clocks: Clocks): string

// save.ts: the one place a file is handed to the browser (a Blob and a link with `download`).
export function saveText(name: string, text: string): void
export const SAVE: InjectionKey<typeof saveText>
```

  The fake router gains `logsNow: (ask) => LogsResponse | RouterError`, `calls.logs`,
  `push('logs', batch)`, `lose('logs')` and `holdCall('logs')`.

- [ ] **Step 1: Write the failing model tests** (`logs-model.test.ts`):
  - `a line that came by both roads is shown once`: `joined` of an answer ending at 40 and
    live lines 39, 40, 41 is the answer and 41; with an empty answer, every live line.
  - `lines are appended once, and the oldest go beyond the bound`: a repeat by number is
    dropped; with `kept` 5, a sixth line drops the first; a gap mark left at the top is
    dropped with it.
  - `a gap is marked once`.
  - `a line's time is counted back from the router's two clocks`: clocks of
    `{ uptimeMs: 600_000n, timeUnixMs: T }` put a line of `uptimeMs: 540_000n` at `T` less a
    minute, whatever the wall clock was when it was written.
  - `the file is named for the router and the time`, and `the file has one line for each
    line`: time in UTC, the level padded, the text as it is.

- [ ] **Step 2: Write the failing page tests** (`logs.test.ts`, timers faked):
  - `the page opens at Info, following`: header `Logs`, `What the router wrote down, as it
    writes it.`; `Show` with `Errors | Warnings | Info | Debug` and Info chosen; a box `Filter
    by text`; buttons `Pause` and `Download`; one call with level INFO, no text and limit 200,
    made after the subscription to `logs`; each line is its time (dim, `14:12:03`, the
    browser's zone), its level as a word and its text, a warning in the warn tone and an error
    in the err tone and nothing else coloured; under the lines `Following: new lines appear at
    the bottom. Pause holds the view still while you read. The router keeps about the last
    8 MiB in memory, so a restart clears it.`
  - `a line that arrives is shown if it matches`: at Info a pushed debug line is not shown and
    a pushed warning is; with `p0` typed, only lines holding it.
  - `choosing a level asks the router again`: at once, for the newest that match.
  - `typed text is asked for after a pause`: three keys inside 300 ms make one call, with the
    text trimmed; a change that is only spaces at its ends asks nothing.
  - `an answer to a filter since changed is dropped`: two calls held, the first answered last,
    and the page shows the second's lines.
  - `Earlier lines fetches the ones before`: shown when the answer says `earlier`; the call
    carries `beforeSeq` of the oldest line shown; its lines go on top; the button goes when an
    answer says no more, and at 2000 lines shown it is replaced by `Download has the rest.`
  - `Pause holds the view and counts what arrives`: pushed lines are not shown, the button
    says `Follow (2 new)`, and pressing it shows them and says `Pause` again.
  - `what waits while paused is bounded, and its gap is marked`: 2500 lines pushed while
    paused leave 2000 waiting; on Follow a mark `Some lines were skipped here.` stands before
    them.
  - `a loss told by the router is marked where it happened`: `lose('logs')` between two pushes
    puts the mark between their lines.
  - `Download saves the whole log whatever the filter`: with a level and a text chosen, calls
    with no level, no text and limit 0, each `beforeSeq` the oldest of the one before, until
    one says no `earlier`; `saveText` is given the file's name and the lines oldest first.
    While it runs the button is held and says `Downloading…`; a call that fails says `The log
    could not be downloaded.` and saves nothing.
  - `a log that cannot be read says so`: `The log could not be read from the router.` with
    `Try again`.
  - `nothing matches`: `No lines match.`
  - `leaving the page ends the subscription`.

- [ ] **Step 3: Run** `make web-test`: fail. **Step 4: Implement.** The page subscribes
  first and asks second, and holds live lines aside until the answer comes (`joined`). The
  clocks are those of the newest answer or batch. The view is a `div` in `layout.css`
  (`.logs__view`: a bounded height that scrolls) around `OfoCode` with `live` and `wrap`;
  while following, the `div` is scrolled to its end after each change. `saveText` is provided
  to the page (`SAVE`) so that a test gives its own.

- [ ] **Step 5: Run** `make web-test` and `make web-lint`: pass.

- [ ] **Step 6: Commit** `panel: the Logs page`.

---

### Task 14: The pages in a browser

**Files:**
- Create: `web/panel/e2e/views.spec.ts`
- Modify: `harness/tests/m4.rs`

- [ ] **Step 1: Write the spec** (one test, `the routes, the ports and the log`, with the
  helpers of `e2e/support.ts`; navigation by `getByRole('navigation', { name: 'Pages' })`):
  1. Log in. **Routes**: the row `default` has the WAN's interface and `wan0` under Belongs
     to; the row `192.168.1.0/24` says `on the link`, `br-lan0`, `lan0`. Screenshots
     `routes`. IPv6: `No IPv6 routes.`
  2. **Ports**: `p0` says `Up` and `1000 Mbit/s` and is used by `wan0`, a link that leads to
     the WAN page and back; in the row of the port `lan0` uses that is up, Received is not
     `0 B` and is another value a few seconds later (the browser's own traffic crosses it).
     Screenshots `ports`.
  3. **Logs**: lines are shown. The lab's `wan-down`: `link p0 down` appears without a
     reload. `Errors`: it is not shown. `Info` and `P0 DOWN` typed: it is. Screenshots
     `logs`. `Pause`, then the lab's `wan-up`: `link p0 up` is not shown and the button
     counts; `Follow`: it is. The box cleared, `Download`: the browser's download is a file
     named for the router whose text has a line ending `link p0 down`.

- [ ] **Step 2: Write the scenario**
  `the_panel_shows_the_routes_the_ports_and_the_log_in_a_browser`, made as
  `the_panel_shows_the_hour_and_the_leases_in_a_browser` is without its wait and its confirm
  window, naming `views.spec`, ending with `no_task_failed` and `password_never_logged`.

- [ ] **Step 3: Run** `make test-harness FILTER=the_panel_shows_the_routes`: pass. Look at
  each of the six screenshots, both themes, at the width they were taken.

- [ ] **Step 4: Commit** `panel: the views in a browser, against the VM`.

---

### Task 15: The notes, and the whole gate

**Files:**
- Modify: `CLAUDE.md` (Harness), `docs/progress.md`

- [ ] **Step 1: `CLAUDE.md`**: after the paragraph on part 3b's scenarios, part 3c's five: the
  three that ask from the LAN (the dump with the WAN cut and returned; the log by level and
  text, read back in pages and followed through a cut WAN; the whole ring read for the lab's
  passwords and tokens), the client's (`views.test`) and the browser's (`views.spec`); the
  count of web scenarios that name their own file becomes eight, with the two new names; and
  the sandbox test in the `netlink` suite with what it found.

- [ ] **Step 2: Run the whole gate** on the final tree: `make lint`, the same under Rust
  1.100.0, `make test`, `make bin FEATURES=`, `make kernel`, `make check-env`, and
  `OPENFEO_NO_SKIP=1 make test-harness`.

- [ ] **Step 3: `docs/progress.md`**: the M4 row and an entry for this part, with the counts
  the gate gave, written once the review and its fix pass are done.

- [ ] **Step 4: Commit** `docs: part 3c in the harness notes and the progress log`.

---

## Calls made on the design's behalf

The design left these to the builder, or did not foresee them. Each is the author's, with what
it costs if wrong; they are reported again, with what the build found, when the branch is done.

1. **Other crates' lines are kept from INFO up, the router's own from DEBUG up.** The HTTP/2
   library writes a DEBUG line for every frame it sends and reads, so a gRPC stream of the log
   would have fed itself, and the panel's own traffic was already pushing the router's lines
   out of the ring. Cost: a fault that only a library's DEBUG lines explain is not in the log.
2. **A line's text leaves out the `openfeo:` the console's copy begins with**, as the mockup
   has it: in the ring every line is the router's. Cost: a line copied from the page is not
   the console's line byte for byte.
3. **A reader follows the ring by number and has no queue of its own**; one more than 1024
   lines behind is moved up to there. Cost: none seen against a queue of the same depth, which
   would hold a copy for each socket.
4. **`DATA_LOSS` names its topic** (`Error.topic`), now that two topics can lose. Cost: one
   field; without it a log that fell behind would be told to the dashboard as events lost.
5. **A batch of the log is its own message on the socket, beside an event**, and not a
   `Telemetry`, which is the coalesced pushes. Cost: one more case for a client to read.
6. **A line is at most 16 KiB and stays one line**, a control character written as its
   escape. Cost: the end of a longer line is not kept; a device's name with a newline in it
   reads `\n`.
7. **A removed link's routes are dropped from the cache by the monitor**, if the sandbox finds
   that the kernel does not announce them (ADR-0027). Cost: if the kernel one day announces
   them too, nothing; a link set down and kept is not covered.
8. **A route whose interface the cache cannot name is left out of the dump.** Cost: for the
   instant between a route's arrival and its link's, a dump lacks that route.
9. **A route in a WAN's own table says so beside the WAN** (`wan0, its own table`), since it
   otherwise reads as a repeat of main's; a route that is nobody's shows a dash. Cost: words
   the mockup did not have.
10. **Earlier lines stops at 2000 lines shown**, and Download has the rest. Cost: reading far
    back is done in the file, not on the page.
11. **The downloaded file's times are UTC**, and the page's are the browser's zone. Cost: the
    two differ by the zone; a file sent with a bug report reads the same wherever it is opened.
12. **Bytes on the Ports page are by thousands** (kB, MB, GB), as the mockup's `412.8 GB`.
    Cost: none seen; rates are already said in decimal units.
13. **A level that is no level is refused**, and not read as every line. Cost: a client built
    against a later schema with one more level is told so by an old router.
