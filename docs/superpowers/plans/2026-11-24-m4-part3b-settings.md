# M4 part 3b: settings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The panel edits the firewall, the DNS settings and the router's name and time servers,
changes the password and restarts the router; a restart asked for stops in order first; and one
file carries the notices of everything in the binary.

**Architecture:** The state gains the resolvers the forwarder is asking, taken from the function
the forwarder itself is configured by. A family manager learns to stop its instances for good
(a halt); the router's restart task waits a second, halts the PPPoE sessions and the DHCPv4
servers together, and has the heartbeat task, which owns the control pipe, send `Msg::Reboot`.
The API reaches that task through a trait in `ApiDeps`, behind a new `SystemService.Reboot`.
`make panel` runs `cargo about` and the notices script joins its output, the C libraries' texts
and the npm and font notices into `/licences.txt`. The panel gains three settings pages built
like WAN and LAN & DHCP (draft, fields by the router's path, the save bar and dialog), with the
password and the restart as calls of their own outside the draft.

**Tech Stack:** Rust (prost, tonic, axum, tokio), protobuf, `cargo about`, TypeScript 6, Vue 3.5,
vitest 5, Playwright, the QEMU harness.

**Spec:** `docs/superpowers/specs/2026-11-23-m4-part3-remaining-pages-design.md` ("Part 3b",
"Proven", "SPEC amendments", "What is left to the builder", "Calls made for the maintainer"
10 to 18). The milestone's rules are in
`docs/superpowers/specs/2026-11-10-m4-api-and-panel-design.md`. The words on the three pages are
those of the mockup the maintainer approved; they are written out in Tasks 11 to 14.

## Global Constraints

- Branch `m4-3b`. Commits are `git commit -s` as the repository's identity, subject
  `<area>: <summary>`. Nothing is pushed and no pull request is opened but on the maintainer's
  word; the branch is swept before any push, and linted with the newest stable Rust as well as
  the dev host's (`RUSTUP_TOOLCHAIN=1.100.0 cargo clippy --workspace --all-targets
  --all-features -- -D warnings`).
- `clippy -D warnings`, pedantic as warnings. No `unwrap`/`expect` outside tests. `thiserror` in
  libraries. No `std::process::Command` outside `harness/`.
- `openfeo-reconcile` and `openfeo-world` stay pure: no tokio, libc, nix or socket2 in their
  trees (`scripts/check-deps.sh`).
- Every source file starts with `SPDX-License-Identifier: GPL-2.0-or-later` and
  `Copyright (C) 2026 Andrew Newton`.
- No password, token or hash reaches a log line, an error or a `Debug` output. The three
  password fields of the System page are in no draft, no store and no storage; they are emptied
  when the change is made and when the page is left.
- `web/client` imports no Vue and uses no DOM beyond `fetch` and `WebSocket`; `web/ui` knows
  nothing of the API; `web/panel` reaches protobuf only through `@openfeo/client` and holds no
  CSS beyond page layout. The page's content security policy allows no inline script, no
  `style` attribute and no `data:` URL.
- The design system's copies under `web/ui` (`tokens.json`, `ofo.css`, fonts, logos, `docs/`)
  are not edited. What they lack goes in `web/ui/additions.css` and is said in
  `web/ui/docs/gaps.md`.
- Addresses in tests and fixtures are documentation ranges (RFC 5737, RFC 3849) or the RFC 1918
  ranges the fixtures already use; hardware addresses are locally administered or QEMU's.
- No new config field, and no new plain HTTP call. The pages send back the whole config with
  only their own fields changed: `dns.blocklists` and `system.timezone` are carried untouched.
- A stopped task is given 3 s (`STOP_GRACE`). A restart begins 1 s after it is asked and waits
  3.5 s at most for the goodbyes.
- Rust commands need `OPENFEO_NFT_SRC=$PWD/build/nft/src` and
  `OPENFEO_UAPI_INCLUDE=$PWD/build/kernel/headers/include` (the `make` targets set them). The
  unit gate is `make test`, never `cargo test --workspace` (that runs the QEMU suites). A
  harness scenario is `make test-harness FILTER=<name>`.

## Review Focus

What the design implies and a person will meet, most likely first. Each has its test in the
task that owns the code.

1. **A LAN whose "may reach" is empty in the file.** Empty means the internet alone. The grid
   shows the internet ticked, opening the page changes nothing, unticking the last tick writes
   `none`, and ticking back to what the router has puts back what the router has. Tests in
   Task 10 (`an empty list is the internet alone, and stays empty`).
2. **Ports as people type them.** `80, 443`, `1000-1010`, ` 22 `, `0`, `65536`, `90-80`,
   `http`; an empty To port is the same port; ports typed on a rule that is then made ICMP.
   Tests in Task 10 (`ports as they are typed`).
3. **Restart with work in hand.** A draft with changes, or a change waiting to be confirmed.
   The dialog says what is lost and what goes back; the restart applies and confirms nothing.
   Tests in Task 14 (`the dialog says what a restart loses`) and Task 5
   (`a_restart_asked_while_a_change_is_pending_comes_back_on_the_confirmed_config`).
4. **A wrong current password, and the wait it earns.** Said at the Current field with the
   seconds counting down, the button held meanwhile; a double press sends one call; nothing
   typed is in the draft, the store or storage. Tests in Task 14.
5. **The router comes back and the session does not.** After Restart the page says the router
   is restarting, and is at the login screen once the router answers; a router that stays away
   is said to be away since when; a restart asked twice is one restart. Tests in Task 14
   (`after a restart the page waits and then asks for the password`) and Task 6
   (`asking_twice_is_asking_once`).

---

## File Structure

| File | Responsibility |
|---|---|
| `SPEC.md` | §6.3, §8.3, §8.4, §13 as amended |
| `proto/openfeo/v1/state.proto` | `DnsState`, `DnsResolver`, `State.dns` |
| `proto/openfeo/v1/api.proto` | `SystemService`, `RebootRequest`, `RebootResponse` |
| `crates/openfeo-reconcile/src/{dns,state}.rs` | the resolvers in use |
| `crates/openfeo/src/family.rs` | `Halt` |
| `crates/openfeo/src/restart.rs` (new) | the delay, the goodbyes, the word to PID 1 |
| `crates/openfeo/src/{heartbeat,router,api}.rs` | the pipe's `Msg::Reboot`; wiring |
| `crates/openfeo-init/src/ctl.rs` | `CtlPipe` from a file, for a test |
| `crates/openfeo-api/src/{lib,server,ws,grpc,listener,testing}.rs` | `Restarter`, `Reboot` |
| `about.toml`, `about.hbs` (new) | what `cargo about` accepts and writes |
| `scripts/rust-notices.sh` (new) | the pinned `cargo about`, run |
| `web/scripts/notices.mjs`, `web/scripts/c-notices.json` (new) | one file of notices |
| `Makefile`, `.github/workflows/ci.yml`, `scripts/cloud-setup.sh`, `harness/src/main.rs` | the tool, installed and reported |
| `harness/src/apiclient.rs`, `harness/tests/m4.rs` | `reboot`, the scenarios |
| `web/client/src/{router,messages,index}.ts` | `reboot()`, the schemas the pages make |
| `web/ui/src/{icons.ts,components/OfoChoice.vue,components/OfoSelect.vue}`, `additions.css` | three icons, a tick with no visible label, a small select |
| `web/panel/src/model/{firewall,dns,system}.ts` (new) | what each page works out |
| `web/panel/src/model/{changes,lan}.ts` | names for the new settings; blockers as links |
| `web/panel/src/pages/{Firewall,Dns,System}.vue` (new) | the pages |
| `web/panel/src/parts/{SettingCell,ApplyDialog}.vue`, `Shell.vue`, `routes.ts`, `live.ts`, `session.ts` | a choice in a cell; a rename in the dialog; nav, save bar, restarting |
| `web/panel/e2e/settings.spec.ts` (new) | the browser run |

---

### Task 1: SPEC amendments

**Files:**
- Modify: `SPEC.md` (§6.3, §8.3, §8.4, §13)

- [ ] **Step 1: Amend the four places.**

  - **§6.3**, appended to the paragraph that ends "begins with a DISCOVER.": "A restart asked
    for through the API (`SystemService.Reboot`) first stops what has a goodbye to say: every
    PPPoE session and every LAN's DHCPv4 server are asked at once and given the same 3 s,
    nothing is started in their place, and the router then asks PID 1 to restart whether or not
    they finished. The DHCPv4 client is left running, so that the router comes back to the
    address it had. A watchdog reset, a power cut and a router process that died are as they
    were."
  - **§8.3**, a new bullet after "M4 part 3a": "M4 part 3b: `State` says which resolvers the
    forwarder is asking, in the order it asks, each with the WAN it was learned from, or none
    when the owner typed it. `SystemService` begins with `Reboot`: it needs a session, answers,
    and about a second later begins the restart of §6.3. It makes no event, and is logged with
    the address it was asked from."
  - **§8.4**, a new paragraph after "Status and leases (M4 part 3a)": "The settings pages (M4
    part 3b): Firewall is a grid of which LAN may start connections to the internet and to each
    other LAN, port forwards and rules as tables edited in place, and whether the router
    answers ping from the internet. DNS is the owner's resolvers and whether the WAN's are used
    too, with the resolvers in use now; local names; and, under Advanced, the names let through
    the rebinding guard. System is the hostname and domain, the time servers and whether the
    clock is set, the password, restarting, and the version, uptime, certificate fingerprint
    and notices. A change of password and a restart are not part of the draft: each is a call
    of its own, made at once. A LAN that a forward, a rule or another LAN's tick points into
    can be removed once the draft has none of them."
  - **§13**: "Third-party notices generated by `cargo about` into the image and the panel's
    About page. The npm packages and the fonts the panel bundles carry theirs in
    `/licences.txt`, written by the panel's build and served without a login." becomes
    "Third-party notices are one file, `/licences.txt`, written by the panel's build and served
    without a login: the Rust crates in the binary (by `cargo about`, against the licences of
    §14), the C libraries linked into it, the npm packages the panel bundles and its fonts.
    System's About links to it."

- [ ] **Step 2: Commit.** `spec: the resolvers in use, a restart that stops in order, the settings pages, one file of notices (M4 part 3b)`

---

### Task 2: The resolvers in use

**Files:**
- Modify: `proto/openfeo/v1/state.proto`
- Modify: `crates/openfeo-reconcile/src/dns.rs`, `crates/openfeo-reconcile/src/state.rs`
- Modify: `crates/openfeo-config/src/lib.rs` (re-exports)
- Modify: `harness/tests/m4.rs`

**Interfaces:**
- Produces:

```proto
// In State: what the forwarder is asking.
DnsState dns = 7;

message DnsState {
  // In the order the forwarder asks them.
  repeated DnsResolver resolvers = 1;
}

message DnsResolver {
  string address = 1;
  // The WAN it was learned from; empty when it is one the owner typed.
  string wan = 2;
}
```

```rust
// crates/openfeo-reconcile/src/dns.rs
/// One upstream the forwarder asks, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolver {
    pub address: IpAddr,
    /// The WAN it was learned from; `None` for one typed into `[dns] upstreams`.
    pub wan: Option<String>,
}

/// The forwarder's upstreams, in the order it asks them: exactly `desired(world).upstreams`.
#[must_use]
pub fn resolvers(world: &World) -> Vec<Resolver>
```

- [ ] **Step 1: Write the failing tests** in `dns.rs`'s test module, on the World fixtures its
  neighbours use (a DHCP WAN whose lease gives `203.0.113.53` and `203.0.113.54`, with its
  default route):

  - `the_wans_resolvers_are_in_use_in_order_and_name_their_wan`: both, each `wan == Some("wan0")`.
  - `a_typed_resolver_comes_first_and_names_no_wan`: `[dns] upstreams = ["198.51.100.53"]`
    gives it first with `wan == None`, then the WAN's two.
  - `with_the_switch_off_only_the_typed_are_in_use`: `use_wan_dns = false`.
  - `a_resolver_both_typed_and_learned_is_listed_once_as_typed`: `upstreams =
    ["203.0.113.54"]` gives `.54` (`None`), then `.53` (`Some("wan0")`).
  - `a_wan_with_no_lease_gives_none`: an empty list.
  - `the_list_is_what_the_forwarder_is_given`: for every fixture above,
    `resolvers(&world)`'s addresses equal `desired(&world).upstreams`.

  And in `state.rs`: `the_state_says_which_resolvers_are_in_use`: `state(&world, &facts).dns`
  holds the typed one with `wan == ""` and the learned ones with `wan == "wan0"`.

- [ ] **Step 2: Run them.** `cargo test -p openfeo-reconcile resolver` fails to compile: no
  `resolvers`.

- [ ] **Step 3: Implement.** `resolvers` and `desired` take their upstreams from one private
  function, so the two cannot differ; an address is typed when it parses out of
  `[dns] upstreams`, whatever else also offers it. `state()` fills `dns`. Re-export `DnsState`
  and `DnsResolver` from `openfeo_config::state`.

- [ ] **Step 4: Run.** `cargo test -p openfeo-reconcile` passes once the `insta` snapshots of
  `State` that gained the field are reviewed and accepted (`cargo insta review`; no `.snap.new`
  is left behind). `make lint` passes (`scripts/check-proto.sh`: the change adds, and breaks
  nothing).

- [ ] **Step 5: The harness scenario** `the_state_says_which_resolvers_are_in_use` in
  `harness/tests/m4.rs`, added to `SCENARIOS`: after `boot_claimed`, the state's resolvers are
  `[("203.0.113.1", "wan0")]` (the lab's Kea gives that one). An immediate apply of the same
  config with `dns.upstreams = ["198.51.100.53"]` makes them `[("198.51.100.53", ""),
  ("203.0.113.1", "wan0")]` (`state_where`, within `SOON`); one more with
  `use_wan_dns = Some(false)` leaves the typed one alone. It ends with `no_task_failed`.
  Run: `make test-harness FILTER=the_state_says_which_resolvers_are_in_use`; expected: 1 passed.

- [ ] **Step 6: Commit.** `reconcile, api: the state says which resolvers the forwarder is asking`

---

### Task 3: A family can be halted

**Files:**
- Modify: `crates/openfeo/src/family.rs`

**Interfaces:**
- Produces:

```rust
/// Stops a family for good, for a restart of the router.
#[derive(Debug, Clone)]
pub struct Halt { /* private */ }

impl Halt {
    /// Have the manager stop every instance, each as any stop is (its goodbye, `STOP_GRACE` at
    /// most), start nothing after, and leave what they published in the World. Returns once
    /// they have stopped or been dropped. A manager that is not running has nothing to stop.
    pub async fn halt(&self)
}

/// As [`spawn`], and the family can be halted.
pub fn spawn_haltable<F: Family>(
    family: F,
    supervisor: &Supervisor,
    publisher: &Arc<Publisher>,
    world_rx: &WorldRx,
) -> Halt
```

  `spawn` stays as it is for the families that are never halted.

- [ ] **Step 1: Write the failing tests** beside the manager's own, with its `Fake` family
  (give the fake a way to record that an instance was asked to stop and said goodbye, and one
  to ignore the ask):

  - `a_halt_stops_every_instance_with_its_goodbye_and_starts_none`: two instances running;
    after `halt().await` both have said goodbye; the World still wants them and a further
    change of the World starts nothing (the count of runs stays 2).
  - `a_halt_withdraws_nothing`: what the instances published is still in the World after the
    halt (`withdraw` was not called).
  - `an_instance_that_will_not_stop_is_dropped_at_the_limit` (paused time): `halt()` has not
    returned at 2.9 s and has at 3.1 s.
  - `a_halt_reaches_only_its_own_family`: two managers; halting one leaves the other's
    instances running and still managed (a change of the World that wants a third starts it).
  - `a_manager_that_starts_again_after_a_halt_starts_nothing`: the manager's task is made to
    fail after the halt and is restarted by the supervisor; no instance runs.

- [ ] **Step 2: Run them.** `cargo test -p openfeo --all-features family::` fails to compile:
  no `spawn_haltable`.

- [ ] **Step 3: Implement.** `manage` gains an arm for the halt: it stops every running
  instance together (`join_all`, as it does for those that leave), answers, and waits for ever.
  That the family is halted is kept outside the manager's future, so one that the supervisor
  starts again sees it.

- [ ] **Step 4: Run.** `cargo test -p openfeo --all-features family::` passes.

- [ ] **Step 5: Commit.** `router: a family manager can be halted for a restart`

---

### Task 4: `SystemService.Reboot`

**Files:**
- Modify: `proto/openfeo/v1/api.proto`
- Modify: `crates/openfeo-config/src/lib.rs` (re-exports)
- Modify: `crates/openfeo-api/src/{lib,server,ws,grpc,listener,testing}.rs`
- Modify: `crates/openfeo/src/api.rs` (a restarter that does nothing, until Task 6)

**Interfaces:**
- Produces:

```proto
message RebootRequest {}
message RebootResponse {}

// The router itself (SPEC §8.3).
service SystemService {
  // Restart the router. Answers at once; the restart begins about a second later (SPEC §6.3).
  rpc Reboot(RebootRequest) returns (RebootResponse);
}
// Request.body and Response.body: `reboot = 11`.
```

```rust
// crates/openfeo-api/src/lib.rs
/// How the API has the router restart (SPEC §6.3). `restart` returns at once; the router
/// stops what has a goodbye to say and asks PID 1 in its own time. Asking twice is asking once.
pub trait Restarter: Send + Sync {
    fn restart(&self);
}
pub struct ApiDeps { /* as now, and: */ pub restarter: Arc<dyn Restarter> }

// crates/openfeo-api/src/server.rs
impl Shared {
    /// Have the router restart, and say so in the log with who asked.
    pub fn reboot(&self, from: IpAddr) -> RebootResponse
}
/// `system: restart asked from 192.168.1.50`.
pub(crate) fn line_restart_asked(from: IpAddr) -> String
```

  The test API (`testing.rs`) is given a restarter that counts, read as `api.restarts()`.

- [ ] **Step 1: Write the failing tests.**

  - `ws.rs`, `a_restart_is_asked_of_the_router_and_answered`: an authenticated socket asks
    `Reboot`; the answer is a `Response` whose body is `Reboot`; `api.restarts() == 1`.
  - `ws.rs`, `a_restart_is_not_refused_while_a_change_is_pending`: with a change applied and
    unconfirmed (as the `ChangePassword` test sets one up), `Reboot` is answered and counted.
  - `grpc.rs`, `a_restart_over_grpc_needs_a_session`: with no token the status is
    `Unauthenticated` and `api.restarts() == 0`; with one it is `Ok` and 1.
  - `server.rs`, `the_restart_line_names_who_asked_and_nothing_else`:
    `line_restart_asked("192.168.1.50".parse()?)` is exactly `system: restart asked from
    192.168.1.50`.

- [ ] **Step 2: Run them.** `cargo test -p openfeo-api --lib --all-features restart` fails to
  compile: no `RebootRequest`.

- [ ] **Step 3: Implement** along the road `GetLeases` took: the proto, the re-exports in
  `openfeo_config::api`, `ws::perform`, `impl SystemService for Grpc` with its
  `route_service` in `routes()`, `Shared::reboot` (an INFO line, then `restarter.restart()`),
  and `restarter` through `ApiDeps`, `SharedParts` and both test builders. In
  `crates/openfeo/src/api.rs` the router passes a restarter that logs `restart: asked, and
  nothing here does it yet` until Task 6.

- [ ] **Step 4: Run.** `cargo test -p openfeo-api --lib --all-features` passes; `make lint`
  passes (`buf lint`: the service has the suffix and each call its own messages).

- [ ] **Step 5: Commit.** `api: SystemService.Reboot asks the router to restart`

---

### Task 5: The restart, as the LAN will see it

**Files:**
- Modify: `harness/src/apiclient.rs`, `harness/tests/m4.rs`

**Interfaces:**
- Consumes: `SystemService.Reboot` (Task 4). The scenarios are written before the router can
  restart, so that each is seen to fail first; Task 6 makes them pass.
- Produces:

```rust
impl Ws {
    /// Ask the router to restart.
    pub fn reboot(&mut self) -> Result<Result<(), Error>>
}
impl Api {
    /// `SystemService.Reboot` over gRPC, with a token or without: the status it was given.
    pub fn grpc_reboot(&self, token: Option<&str>) -> Result<Result<(), tonic::Status>>
}
```

  Console lines the scenarios read: `openfeo: system: restart asked from 192\.168\.1\.`,
  `openfeo-init: reboot requested by child`, and those `m4.rs` already names
  (`LAN0_DHCP_STOPPED`, `WAN0_DHCP_STOPPED`, `PPPOE_STOPPED`, `PPPOE_UP`, `DISCARDED`,
  `LISTENING`).

- [ ] **Step 1: Write the four scenarios**, each added to `SCENARIOS`.

  - `a_restart_asked_over_the_api_stops_in_order_and_keeps_the_leases`: after `boot_claimed`,
    `grpc_reboot(None)` is `Unauthenticated` and the console has no restart line. Two devices
    join one after the other (`join`), so that the second lease's write to the file is still
    owed; the leases, the uptime and the config's tag are read; `ws.reboot()` is `Ok`. The
    console then has, in this order, the restart line, `LAN0_DHCP_STOPPED` and `reboot
    requested by child`, with no `WAN0_DHCP_STOPPED` between the first and the last
    (`count_since`); then `LISTENING` again. The old token is refused. After a new login the
    uptime is smaller, the tag is the same, both leases are in the table with the joined times
    they had, and `wan0` has the address it had.
  - `a_restart_ends_the_pppoe_session_first` (`boot_pppoe`; skips as the PPPoE scenarios do):
    after `ws.reboot()` the console has `PPPOE_STOPPED` before `reboot requested by child`,
    the concentrator's `pppd` log shows `LCP terminated by peer` (`pppd_log_shows`), and after
    the restart `PPPOE_UP` comes again.
  - `a_restart_does_not_wait_for_a_concentrator_that_says_nothing` (`boot_pppoe`): the
    concentrator is killed (`kill_pppoe_server`) and the restart asked at once; `reboot
    requested by child` comes within 6 s of the answer, after `task pppoe-wan0 did not stop in
    3s; dropped`; then `LISTENING` again.
  - `a_restart_asked_while_a_change_is_pending_comes_back_on_the_confirmed_config`: a change
    that moves nothing (`firewall.wan_ping` turned over) is applied with a window of 600 s and
    left unconfirmed; `ws.reboot()`; after the restart the console has `DISCARDED`, the tag is
    the one from before the apply, `wan_ping` is as it was, and `config.discarded` is among the
    events.

- [ ] **Step 2: Run each.** `make test-harness FILTER=a_restart` runs the four; expected: each
  fails waiting for `openfeo-init: reboot requested by child`, because the router's restarter
  does nothing yet (the two PPPoE ones skip with their reason on a host with no access
  concentrator, as the `m3` suite does).

- [ ] **Step 3: No commit yet.** The scenarios are committed with Task 6, passing.

---

### Task 6: The router restarts in order

**Files:**
- Create: `crates/openfeo/src/restart.rs`
- Modify: `crates/openfeo/src/{heartbeat,router,api,main}.rs`
- Modify: `crates/openfeo-init/src/ctl.rs`

**Interfaces:**
- Consumes: `Halt`, `spawn_haltable` (Task 3); `openfeo_api::Restarter` (Task 4).
- Produces:

```rust
// crates/openfeo/src/restart.rs
/// How long after it is asked a restart begins: time for the answer to reach whoever asked.
pub const DELAY: Duration = Duration::from_secs(1);
/// How long the goodbyes are waited for in all: a stop's 3 s, and half a second to be told.
pub const LIMIT: Duration = Duration::from_millis(3_500);

/// Asks for a restart. Asking twice is asking once.
#[derive(Debug, Clone)]
pub struct Restarts { /* private */ }
/// The other end: what [`run`] waits on.
pub struct Asked { /* private */ }
impl openfeo_api::Restarter for Restarts { fn restart(&self) }

/// The families with a goodbye to say before a restart, and no others (SPEC §6.3).
pub struct Goodbyes { pub pppoe: Halt, pub dhcp4_servers: Halt }
impl Goodbyes {
    /// Halt both, together.
    pub async fn say(self)
}

pub fn channel() -> (Restarts, Asked)

/// Wait to be asked; then `DELAY`; then the goodbyes, for `LIMIT` at most; then tell `pid1`.
/// A second ask changes nothing.
pub async fn run<G>(asked: Asked, goodbyes: impl FnOnce() -> G, pid1: watch::Sender<bool>)
where G: Future<Output = ()>

// crates/openfeo/src/heartbeat.rs: one more argument.
pub async fn run(ctl: Option<CtlPipe>, health: HealthTracker, hung: Arc<AtomicBool>,
                 view: watch::Sender<HealthView>, restart: watch::Receiver<bool>)

// crates/openfeo-init/src/ctl.rs
impl From<std::fs::File> for CtlPipe
```

  `spawn_families` in `router.rs` returns the `Goodbyes`: the PPPoE and DHCPv4-server managers
  are spawned with `spawn_haltable`, every other family with `spawn` as now.

- [ ] **Step 1: Write the failing tests.** In `restart.rs` (paused time):

  - `nothing_is_stopped_before_the_delay`: asked at 0; at 0.9 s the goodbyes have not begun; at
    1.1 s they have.
  - `pid1_is_told_once_the_goodbyes_are_said`: goodbyes that take 2 s; `pid1` is false at
    2.9 s and true at 3.1 s.
  - `goodbyes_that_do_not_end_are_not_waited_for_past_the_limit`: goodbyes that never end;
    `pid1` is true at `DELAY + LIMIT` and was false just before.
  - `asking_twice_is_asking_once`: two asks; the goodbyes ran once.
  - `the_goodbyes_are_the_pppoe_sessions_and_the_dhcp_servers_and_no_other`: three fake
    families through the real managers, the first two in a `Goodbyes`; after `say()` their
    instances have stopped with their goodbyes and the third family's still runs.

  In `heartbeat.rs`: `a_restart_is_passed_up_the_pipe`: the task runs with a `CtlPipe` made
  from the write end of `std::io::pipe()`; when `restart` turns true, the read end holds a
  byte that `ctl::decode` gives as `Msg::Reboot`. And `a_restart_is_passed_up_while_heartbeats_are_withheld`:
  the same with a health that withholds the heartbeat (a dead task): the restart still goes up,
  and no heartbeat does.

- [ ] **Step 2: Run them.** `cargo test -p openfeo --all-features restart` fails to compile:
  no `restart` module.

- [ ] **Step 3: Implement.** `run` logs `restart: stopping the PPPoE sessions and the DHCPv4
  servers` when the delay is over and `restart: not waiting for them any longer` when the limit
  ends the wait. The heartbeat task waits on its tick or on `restart`: with a pipe it sends
  `Msg::Reboot` (a failed send ends the process as a failed heartbeat does); with none it warns
  `restart: no PID 1 above this process; exiting` and exits 0. `router.rs` makes the channel
  before the heartbeat is spawned, hands `Restarts` to `api::spawn` in place of Task 4's
  stand-in, and spawns `restart::run` once the families are up. Container mode is untouched:
  PID 1 there ends itself on `Msg::Reboot`, as it already does.

- [ ] **Step 4: Run.** `cargo test -p openfeo --all-features` and `cargo test -p openfeo-init`
  pass.

- [ ] **Step 5: The scenarios of Task 5.** `make test-harness FILTER=a_restart`; expected: 4
  passed.

- [ ] **Step 6: See the goodbyes matter.** With the goodbyes left out on purpose (the router
  hands `restart::run` goodbyes that do nothing), run the four again: the first fails for want
  of `LAN0_DHCP_STOPPED` or of its second lease, and the PPPoE one for want of `PPPOE_STOPPED`.
  Put the goodbyes back and see the four pass.

- [ ] **Step 7: Commit**, the scenarios with it. `router: a restart asked for stops the PPPoE sessions and the DHCPv4 servers first`

---

### Task 7: One file of notices

**Files:**
- Create: `about.toml`, `about.hbs`, `scripts/rust-notices.sh`, `web/scripts/c-notices.json`,
  `web/scripts/licence-texts/musl.txt`
- Modify: `web/scripts/notices.mjs`, `web/scripts/notices.test.mjs`,
  `web/scripts/check-licences.test.mjs`
- Modify: `Makefile`, `.github/workflows/ci.yml`, `scripts/cloud-setup.sh`,
  `harness/src/main.rs` (`check`), `harness/tests/m4.rs`
- Modify: `docs/third-party.md`, `CLAUDE.md` (Commands)

**Interfaces:**
- Produces:

```
make panel            # now also: nft-src, the Rust notices, and one licences.txt
scripts/rust-notices.sh <version> <out-file> [features]
node web/scripts/notices.mjs --rust <file> --c <nft-src-dir> <out-file>
```

```js
// web/scripts/notices.mjs
/** The whole file: a header, then four parts, each under its own title. */
export function notices({ rust, c, packages, fonts })   // rust: string; c: { name, version, licence, text }[]
/** The C libraries' notices: every entry of c-notices.json with its text and its version. */
export function cNotices(entries, sources, srcDir)       // sources: nft/sources.txt's text
```

  `c-notices.json` is a list of `{ name, source?, licence, file? | comment? | kept? }`: `file`
  is a path inside the library's source tree, `comment` a source file whose leading comment is
  the notice, `kept` a text under `web/scripts/licence-texts/`. Its entries: nftables
  (`GPL-2.0-only`, `COPYING`), libnftnl (`GPL-2.0-only`, `COPYING`), libmnl
  (`LGPL-2.1-or-later`, `COPYING`), jansson (`MIT`, `LICENSE`), mini-gmp in nftables
  (`LGPL-3.0-or-later OR GPL-2.0-or-later`, comment `src/mini-gmp.c`) and musl libc (`MIT`,
  kept). mimalloc and `ring`'s C come with their crates, by `cargo about`.

- [ ] **Step 1: Write the failing tests.** In `notices.test.mjs`:

  - `the file covers the binary, in four parts`: `notices(...)` starts `OpenFeO: third-party
    notices\n` and has the titles `The router: Rust crates`, `The router: C libraries`,
    `The panel: npm packages`, `The panel: fonts`, in that order; the Rust part is the text it
    was given, unchanged.
  - `a C library has its version from the sources and its text from the tree`: with a fixture
    tree, the entry reads `nftables 1.1.7` / `GPL-2.0-only` / its `COPYING`.
  - `a notice kept in a comment is the comment`: the leading block comment of the named file,
    its comment marks removed, and nothing after it.
  - `a library in the sources with no entry fails by name`, and `an entry whose text is not
    there fails by name`.
  - `every library the binary builds has an entry`: against the real `nft/sources.txt` and the
    real `c-notices.json`.

  In `check-licences.test.mjs`: `cargo about accepts what deny.toml accepts`: `about.toml`'s
  `accepted`, sorted, equals `deny.toml`'s `allow`, sorted.

- [ ] **Step 2: Run them.** `cd web && node --test scripts/notices.test.mjs
  scripts/check-licences.test.mjs` fails: no `cNotices`, no `about.toml`.

- [ ] **Step 3: Implement.**

  - `about.toml`: `accepted` as `deny.toml`'s `allow`; the target
    `x86_64-unknown-linux-musl`; build and dev dependencies left out; the workspace's own
    crates left out; nothing fetched from clearlydefined.io (the build asks no service what a
    licence is). Confirm each key's spelling against `cargo about generate --help` and the
    tool's README for the pinned version.
  - `about.hbs` writes plain text in the shape `notices.mjs` uses: for each licence text, a
    rule of 78 `=`, a line `name version` for each crate under it, the licence's SPDX id, a
    rule, a blank line, the text.
  - `scripts/rust-notices.sh` refuses to run with any `cargo about` but the pinned version,
    saying how to install it, and runs `cargo about generate --locked` for `crates/openfeo`
    with the features given, into the out-file.
  - `Makefile`: `CARGO_ABOUT_VERSION` (the version on the dev host today, `0.9.2`);
    `panel` depends on `nft-src` too, runs the script into `$(BUILD)/notices/rust.txt` with
    `$(FEATURES)`, and passes `--rust` and `--c $(OPENFEO_NFT_SRC)` to `notices.mjs`.
  - `musl.txt` is the `COPYRIGHT` file of the musl release the Rust musl target links (confirm
    which: the target is self-contained and brings its own `libc.a`), named with its version in
    `docs/third-party.md`, which also gains mimalloc and says that `/licences.txt` now carries
    every text.
  - A bare `cargo build` embeds what it did, the placeholder page: cargo never runs
    `cargo about` (ADR-0025's rule for npm, kept for this tool).
  - CI: both jobs install the pinned `cargo-about` (`taiki-e/install-action@v2`,
    `tool: cargo-about@<version>`). `scripts/cloud-setup.sh` installs the same version and
    lists it among its facts. `make check-env` reports `cargo about` with its version, and
    its absence as MISSING. `CLAUDE.md`'s Commands say `make panel` needs it.

- [ ] **Step 4: Run.** The tests of Step 1 pass; `make web-test` and `make web-lint` pass;
  `make panel` writes `$(BUILD)/panel/licences.txt`, and a second `make panel` leaves the file
  untouched (its time does not change). The whole panel directory is under the 8 MiB the build
  allows: `du -sb $(BUILD)/panel` says how far.

- [ ] **Step 5: The harness.** `the_panel_and_its_files_are_served` also needs, each at the
  start of a line: `tokio ` (a Rust crate), `nftables ` (a C library) and `musl libc`; and
  still `SIL OPEN FONT LICENSE`, `@bufbuild/protobuf` and `vue `. Run:
  `make test-harness FILTER=the_panel_and_its_files_are_served`; expected: 1 passed.

- [ ] **Step 6: Commit.** `build: /licences.txt carries the Rust crates' and the C libraries' notices`

---

### Task 8: The client

**Files:**
- Modify: `web/client/src/{router,messages,index}.ts`
- Modify: `web/client/test/socket.test.ts`, `web/client/itest/lab.test.ts`

**Interfaces:**
- Consumes: `SystemService.Reboot` (Task 4), `State.dns` (Task 2).
- Produces:

```ts
// Router
/** Restart the router. It answers first and begins about a second later; every session ends with it. */
async reboot(): Promise<void>

// messages.ts, and so the package's index
export { FirewallSchema, PortForwardSchema, RuleSchema, DnsSchema, RecordSchema, SystemSchema }
export type { Firewall, Dns, System, DnsState, DnsResolver }
```

- [ ] **Step 1: Write the failing tests.** In `socket.test.ts`, beside `changePassword`'s:
  `reboot asks for a restart and resolves when it is answered` (the scripted socket sees a
  request whose case is `reboot`), and `a refused reboot is a RouterError`. In the same file or
  the index's own test: `the schemas a settings page makes are exported` (`create` of each of
  the six from `../src/index.js` gives a message of its type). In `itest/lab.test.ts`:
  `the state says which resolvers are in use` (`(await router.state()).dns?.resolvers` is
  `[{ address: '203.0.113.1', wan: 'wan0' }]`, compared by those two fields).

- [ ] **Step 2: Run.** `cd web && npm test -w @openfeo/client` fails: no `reboot`, no
  `FirewallSchema`.

- [ ] **Step 3: Implement** after `changePassword` and the exports beside it. A restart is not
  asked in the Node run: it would take the router from under the tests beside it; the browser
  run asks it (Task 15).

- [ ] **Step 4: Run.** The package's tests pass; `make web-lint` passes; `make test-harness
  FILTER=the_javascript_client_works_from_the_lan` passes.

- [ ] **Step 5: Commit.** `client: reboot, and the messages the settings pages make`

---

### Task 9: What the pages need of the design system in code

**Files:**
- Modify: `web/ui/src/icons.ts`, `web/ui/src/components/{OfoChoice,OfoSelect}.vue`
- Modify: `web/ui/additions.css`, `web/ui/docs/gaps.md`
- Test: `web/ui/test/` (the files that hold the tests of the choice, the select and the icons)

**Interfaces:**
- Produces:
  - `IconName` gains `shield` (Firewall), `text` (DNS: the three lines the mockup drew; the
    icon is `align-left` in a `lucide-static` that has no `text`) and `settings` (System).
  - `OfoChoice` gains `bare?: boolean`: the label is given to assistive technology
    (`aria-label`) and not shown, for a tick that its row and column already name.
  - `OfoSelect` gains `small?: boolean`, the height `OfoInput small` has, for a table cell.

- [ ] **Step 1: Write the failing tests:** `a bare choice shows no label and is still named`
  (no visible label text; the input's accessible name is the label; ticking emits as before);
  `a small select is the small control`; `the three icons are there` (each name renders an
  `svg`).

- [ ] **Step 2: Run.** `cd web && npm test -w @openfeo/ui` fails on the three.

- [ ] **Step 3: Implement.** The two classes (`ofo-choice--bare`, `ofo-select--sm`) go in
  `additions.css`, each with why it is there; `gaps.md` gains three entries: a tick with no
  visible label, a small select, and that the design system documents no grid of ticks (the
  Firewall page's is a plain `ofo-table` of bare choices).

- [ ] **Step 4: Run.** The package's tests pass, `policy.test.ts` among them; `make web-lint`
  passes.

- [ ] **Step 5: Commit.** `ui: three icons, a tick named but not labelled, a small select`

---

### Task 10: What the Firewall page works out

**Files:**
- Create: `web/panel/src/model/firewall.ts`
- Modify: `web/panel/src/model/{changes,lan}.ts`
- Test: `web/panel/test/firewall-model.test.ts` (new), `changes.test.ts`, `lan-model.test.ts`

**Interfaces:**
- Consumes: the schemas of Task 8; `check.ts`, `ip.ts`.
- Produces:

```ts
// model/firewall.ts
/** `reaches`' word for the internet. */
export const INTERNET = 'wan'
export interface ReachCell { to: string; label: string; ticked: boolean; own: boolean }
export interface ReachRow { lan: string; cells: ReachCell[] }
/** A row per LAN, a cell for the internet and for each LAN; a LAN's own cell is `own` and has no tick. */
export function reachGrid(config: Config): ReachRow[]
/**
 * Tick or untick `to` for `lan`. No tick left is `none`; what the router has (`base`) is put
 * back as the router has it when the ticks come to mean the same, so that an empty list stays
 * empty; otherwise the internet first, then LANs in the config's order. A name the grid does
 * not show is kept.
 */
export function setReach(lan: Lan, to: string, on: boolean, config: Config, base: Lan | undefined): void

export const FORWARD_PROTOCOLS: { value: string; label: string }[]   // tcp TCP, udp UDP
export const RULE_PROTOCOLS: { value: string; label: string }[]      // tcp, udp, icmp ICMP, any Any
export function fromOptions(config: Config): { value: string; label: string }[]  // Internet, then each LAN
export function newForward(): PortForward     // proto 'tcp'
export function newRule(): Rule               // from 'wan', proto 'tcp'
export function publicBlocks(config: Config): boolean
/** A rule's ports as one field: "80, 443, 1000-1010". */
export function portsText(ports: readonly string[]): string
export function parsePorts(text: string): string[]
/** What the page can know is wrong with row `n`, by field: name, port, to, to_port, address. */
export function forwardProblems(forwards: readonly PortForward[], n: number): Record<string, string>
/** By field: name, to, ports. */
export function ruleProblems(rules: readonly Rule[], n: number): Record<string, string>

// model/lan.ts
export interface Blocker { text: string; kind: 'forward' | 'rule' | 'reach' }
export function blockers(config: Config, lan: Lan): Blocker[]
```

  The page's words for what is wrong: `Give it a name.`; `Another forward has this name.` /
  `Another rule has this name.`; `A port from 1 to 65535.`; `An IPv4 address.`; `An address, a
  range such as 192.168.1.10-192.168.1.20, or a block such as 192.168.1.0/28.`; `Ports are
  numbers from 1 to 65535, or ranges such as 1000-1010.`; `Ports go with TCP and UDP only.`

  In `changes.ts` the firewall's settings get names in place of paths, matched between the
  router's config and the draft by name (a renamed forward is one removed and one added):

  | Setting | Subject | What |
  |---|---|---|
  | a forward added or removed | `port forward <name>` | (empty), `added: TCP 2222 to 192.168.1.10:22` / `removed` |
  | a forward's fields | `port forward <name>` | `protocol`, `port`, `target`, `target port`, `listens on` |
  | a rule added or removed | `rule <name>` | (empty), `added: …` / `removed` |
  | a rule's fields | `rule <name>` | `from`, `target`, `protocol`, `ports` |
  | `lans[].reaches` | the LAN's name | `may reach`, in words: `the internet`, LAN names, `nothing` |
  | `firewall.wan_ping` | `The router` | `answers ping from the internet`, `yes` / `no` |

- [ ] **Step 1: Write the failing tests.**

  `firewall-model.test.ts`:
  - `the grid has a row for each LAN and no tick for a LAN's own cell`, on `routerConfig()`.
  - `an empty list is the internet alone, and stays empty` (Review Focus 1): a LAN whose
    `reaches` is `[]` shows the internet ticked; unticking it writes `['none']`; ticking it
    again writes `[]`; `changes` of the two configs is then empty.
  - `ticks are written the internet first, then LANs in the config's order`; `no tick is
    none`; `a name the grid does not show is kept`; `a list that says wan stays as it says`
    (base `['wan']`, a LAN ticked and unticked: back to `['wan']`).
  - `ports as they are typed` (Review Focus 2): `parsePorts('80, 443 ,1000-1010')` is
    `['80', '443', '1000-1010']`; `portsText` is its inverse; a rule with `0`, `65536`,
    `90-80` or `http` among its ports has the ports message; a rule that is `icmp` or `any`
    with ports has `Ports go with TCP and UDP only.`; a forward's port `0` or `65536` has the
    port message and a To port of `0` has none (it is the same port).
  - `a name is needed and is its own`: empty, and one used by another row, each for forwards
    and for rules; a row is not told it clashes with itself.
  - `a rule's target is an address, a range or a block, of either family`:
    `192.168.1.10`, `192.168.1.10-192.168.1.20`, `192.168.1.0/28`, `2001:db8:1:1::10`,
    `2001:db8:1::/64` pass; `192.168.1`, `10-20`, `host` do not.
  - `a forward listens on an address only when there is a public block`.

  `changes.test.ts`: one test for each row of the table above (a forward added, removed,
  renamed, each field changed; the same for a rule; `may reach` in words, with `[]` and
  `['wan']` not a change of each other's meaning but still listed if the text differs;
  `wan_ping`). `nothing an apply would alter is left out` still passes.

  `lan-model.test.ts`: `what stands in the way says where it is`: a forward into the LAN is
  `kind: 'forward'`, a rule into or from it `'rule'`, another LAN's tick `'reach'`, with the
  texts as now.

- [ ] **Step 2: Run.** `cd web && npx vitest run --root panel test/firewall-model.test.ts
  test/changes.test.ts test/lan-model.test.ts` fails: no `model/firewall`.

- [ ] **Step 3: Implement.** `blockers`' comment no longer says the pages are not here.

- [ ] **Step 4: Run.** The three files pass; `renumber.test.ts` still passes (no string field
  was added).

- [ ] **Step 5: Commit.** `panel: the firewall's grid, forwards and rules as a model, and their names among the changes`

---

### Task 11: The Firewall page, and removing a LAN

**Files:**
- Create: `web/panel/src/pages/Firewall.vue`
- Modify: `web/panel/src/parts/SettingCell.vue`, `web/panel/src/{routes.ts,Shell.vue,layout.css}`
- Modify: `web/panel/src/pages/Lan.vue`
- Test: `web/panel/test/firewall.test.ts` (new), `lan.test.ts`, `routes.test.ts`,
  `shell.test.ts`, `apply.test.ts`, `pending.test.ts`

**Interfaces:**
- Consumes: Tasks 9 and 10.
- Produces: `PAGES.firewall = '/firewall'`, the route `firewall`, the nav entry `Firewall`
  (icon `shield`) after `Leases`, the save bar on that page, and `SettingCell`'s
  `options?: { value: string; label: string }[]` (a choice in a cell, by `OfoSelect small`).

  The page, in the order and the words of the mockup:

  - Header: `Firewall`, `What may reach what. Nothing on the internet gets in unless you say
    so here.`
  - **Between networks**: `A tick lets devices on the row's LAN start connections to the
    column. Replies always get back.` A table: `From`, `Internet`, then each LAN's name; a
    LAN's own cell is a dash. Each tick is a bare choice named `<lan> may reach <the internet |
    lan>`. Its path is `lans[<n>].reaches`.
  - **Port forwards**: `A port on the router's internet address that leads to one device. It
    works from inside your network too.` Columns `Name`, `Protocol`, `Port`, `To address`,
    `To port`, and `Listens on` when the config has a public block; `Remove` on each row; `Add
    forward`. To port's placeholder is the row's port. Beneath: `To port: leave empty for the
    same port.` and, with a public block, `Listens on: an address of your public block; empty
    for the WAN's own.` Paths are `firewall.port_forwards[<n>].<field>`.
  - **Rules**: `A way in with no address translation: for a device's IPv6 address, for a LAN
    with public addresses, or from one LAN to one device on another.` Columns `Name`, `From`,
    `To`, `Protocol`, `Ports`; `Remove`; `Add rule`. Beneath: `To: one address, a range such as
    192.168.1.10-192.168.1.20, or a block such as 192.168.1.0/28. Ports: one, several, or a
    range such as 1000-1010.` Paths are `firewall.rules[<n>].<field>`.
  - **The router itself**: `What the router answers from the internet.` A toggle, `Answer ping
    from the internet`.

- [ ] **Step 1: Write the failing tests.**

  `firewall.test.ts` (mounted as `lan.test.ts` mounts its page, on `routerConfig()`):
  - `the page is in the navigation and has the save bar`.
  - `the grid shows what each LAN may reach, and a tick is one change`: `store().changes` is
    `[iot may reach …]` after ticking `iot may reach lan0`.
  - `opening the page changes nothing` (Review Focus 1): with a LAN whose `reaches` is `[]`,
    no save bar; ticking and unticking leaves none.
  - `a forward is added, filled in and removed`: the draft has it; an empty To port is `0`;
    Remove takes it and what was said of its row away (`forgetFrom`).
  - `what is wrong is said when the field is left, not while it is typed`.
  - `what the router refuses is said at the cell it names`: a violation at
    `firewall.port_forwards[0].port` is under that cell; one at `firewall.rules[1]` with no
    field is in the list above the tables.
  - `a rule's From offers the internet and each LAN`; `ports on a rule made ICMP are said to
    be wrong, not thrown away`.
  - `with a public block a forward says which address it listens on`, and without one the
    column is not there.
  - `the toggle writes wan_ping`.
  - `a config the router refused is shown and cannot be changed` (the banner; every control
    disabled).

  `lan.test.ts`:
  - `what stands in the way of removing a LAN is a link to where it is removed`: each blocker
    is a link to `/firewall`.
  - `a LAN can be removed once the draft has nothing pointing into it`: the forward is
    removed in the draft, Remove is offered, and the dialog's changes list the forward's
    removal and the LAN's.
  - `May reach` names the Firewall page as a link; the banner for addresses a renumbering
    could not place names the page each is on (`Firewall` for forwards and rules, `DNS` for
    records) in place of "pages this panel does not have yet".

  `routes.test.ts`, `shell.test.ts`, `apply.test.ts`, `pending.test.ts`: the page is among
  `PAGES`, the navigation, the pages with a save bar and the pages that show a pending change.

- [ ] **Step 2: Run.** `cd web && npx vitest run --root panel test/firewall.test.ts` fails: no
  route.

- [ ] **Step 3: Implement.** The page is built as `Lan.vue` is (its root has the class `page`;
  `pageFields`; `RefusedList` for what no field claims; the read-only banner). Its tables are
  plain `ofo-table`s of `SettingCell`s, as the reservations are; what `layout.css` gains is
  layout only (the grid's ticks centred, the tables' column widths).

- [ ] **Step 4: Run.** `make web-test` and `make web-lint` pass.

- [ ] **Step 5: Commit.** `panel: the Firewall page, and a LAN removed once nothing points into it`

---

### Task 12: The DNS page

**Files:**
- Create: `web/panel/src/model/dns.ts`, `web/panel/src/pages/Dns.vue`
- Modify: `web/panel/src/model/changes.ts`, `web/panel/src/{routes.ts,Shell.vue,layout.css}`
- Test: `web/panel/test/dns-model.test.ts`, `dns.test.ts` (new), `changes.test.ts`, the four
  tests that count pages

**Interfaces:**
- Consumes: `State.dns` (Task 8's types), Task 9's icon, `SettingCell` (Task 11).
- Produces: `PAGES.dns = '/dns'`, the nav entry `DNS` (icon `text`) after `Firewall`.

```ts
// model/dns.ts (`DnsRecord` is the client's `Record` message, imported under that name)
export const DEFAULT_DOMAIN = 'home.arpa'
/** `[system] domain`, lower-case, or the default: what a name with no dot is put under. */
export function domainOf(config: Config): string
/** What a local name becomes: `www` is `www.home.arpa`; a name with a dot stands, and gives null. */
export function becomes(name: string, domain: string): string | null
/** By field: name, address. A name may have one address of each family. */
export function recordProblems(records: readonly DnsRecord[], n: number): Record<string, string>
/** Whether the WAN's resolvers are used too: on when the config does not say. */
export function usesWan(dns: Dns | undefined): boolean
/** Set it; what the router has is put back as the router has it (not said stays not said). */
export function setUsesWan(config: Config, on: boolean, base: Config | null): void
/** The resolvers in use, grouped by where they came from, in order: `yours`, or a WAN's name. */
export function inUse(dns: DnsState | undefined): { addresses: string[]; from: string }[]
```

  Among the changes: `DNS` / `your own resolvers`; `DNS` / `the WAN's resolvers too` (`yes`,
  `no`, `not set`); `DNS` / `names let through`; a record is `DNS record <name>`, matched by
  its name and its address's family, `added: <address>` / `removed`, its field `address`.

  The page, in the order and the words of the mockup:

  - Header: `DNS`, `How names are looked up for every device on your network.`
  - **Resolvers**: `Where the router sends the questions it cannot answer itself.` A field,
    `Your own resolvers` (`dns.upstreams`, addresses separated by commas): `Asked first, in
    this order. Leave empty to use only the ones the WAN gives.` A toggle, `Also use the
    resolvers the WAN gives`. Then `In use now:` and each group, the addresses in mono and
    `yours` or `from <wan>` after them; with none, `In use now: none. Names outside your
    network cannot be looked up.`; while the state is not known, nothing.
  - **Local names**: `Names the router answers itself. A device that gives a name with its
    lease, and every reservation with a name, is already found without a row here.` A table of
    `Name` and `Address` with `Remove` and `Add name`. Beneath: `A name with no dot is under
    <domain>: <name> is <name>.<domain>.` (the first row's name with no dot, or `www`) `One
    name may have an IPv4 and an IPv6 address.` Paths are `dns.records[<n>].<field>`.
  - **Protection**: `The router drops answers from outside that point at addresses inside your
    network.` Under Advanced (open when the list has anything, or something is wrong in it):
    `Names let through` (`dns.rebind_allow`, separated by commas): `A name here, and everything
    under it, may answer with a private address.`

  The page's words for what is wrong: `Give it a name.`; `An IPv4 or IPv6 address.`; `This
  name already has an IPv4 address.` / `… an IPv6 address.`; for the resolvers,
  `check.ts`'s `addressList`.

- [ ] **Step 1: Write the failing tests.**

  `dns-model.test.ts`: `a name with no dot is under the domain, and one with a dot stands`
  (with the default domain, a set one, upper case, a trailing dot); `one name may have an
  address of each family and no more`; `the switch is on when the config does not say, and
  what is not said stays not said`; `the resolvers in use are grouped by where they came from,
  in order` (typed, then two from `wan0`; all typed; none; no state).

  `dns.test.ts`: `the page is in the navigation and has the save bar`; `the resolvers are a
  list typed with commas`; `the toggle is one change, and putting it back is none`; `in use
  now says each resolver and where it came from`, and follows a new state without a reload;
  `a local name is added, filled in and removed`; `the note says what the first name
  becomes`; `Advanced is open when a name is let through`; `what the router refuses is said
  at the cell it names` (`dns.records[0].address`); `dns.blocklists is sent back as it came`
  (a config that has one, edited elsewhere on the page, keeps it); read-only.

  `changes.test.ts`: one test for each name above; `nothing an apply would alter is left
  out` still passes, with `dns.use_wan_dns` spelt out as `false` among its cases.

- [ ] **Step 2: Run.** `cd web && npx vitest run --root panel test/dns-model.test.ts
  test/dns.test.ts` fails: no `model/dns`.

- [ ] **Step 3: Implement**, the page as Task 11's was.

- [ ] **Step 4: Run.** `make web-test` and `make web-lint` pass.

- [ ] **Step 5: Commit.** `panel: the DNS page`

---

### Task 13: The System page: name, time and about

**Files:**
- Create: `web/panel/src/model/system.ts`, `web/panel/src/pages/System.vue`
- Modify: `web/panel/src/model/changes.ts`, `web/panel/src/parts/ApplyDialog.vue`,
  `web/panel/src/{routes.ts,Shell.vue,layout.css}`
- Test: `web/panel/test/system-model.test.ts`, `system.test.ts` (new), `changes.test.ts`,
  `apply.test.ts`, the four tests that count pages

**Interfaces:**
- Consumes: Task 9's icon; `model/dns.ts` (`DEFAULT_DOMAIN`).
- Produces: `PAGES.system = '/system'`; the nav group `Router` with the entry `System` (icon
  `settings`) after the Network group; the save bar on that page.

```ts
// model/system.ts
export const DEFAULT_HOSTNAME = 'openfeo'
/** `<hostname>.<domain>`, lower-case, with the router's defaults for what is not set. */
export function routerName(config: Config): string
/** The router's name now and once `draft` is applied, when the two differ. */
export function renamedTo(base: Config | null, draft: Config): { from: string; to: string } | null
/** By field: hostname, domain, ntp_servers. */
export function systemProblems(system: System | undefined): Record<string, string>
/** About's rows: Version, Running for, Certificate. */
export function about(state: State, sinceBootMs: number | undefined): { label: string; value: string; mono: boolean }[]
```

  `ApplyDialog` gains `renamed?: { from: string; to: string } | undefined`, given by the shell
  from `renamedTo`.

  Among the changes: `The router` / `hostname`, `domain`, `time servers`. `system.timezone`
  stays listed by its path: no page edits it.

  The page (Password and Restart are Task 14's):

  - Header: `System`, `The router's name, clock, password and software.`
  - **Name**: `The panel is at <routerName of the router's config>. Changing either gives the
    router a new certificate, so your browser will ask about it once more.` Fields `Hostname`
    (`system.hostname`) and `Domain` (`system.domain`, help `Every local name is under it.`).
    What the page checks is the shape the router's own validation of `[system]` asks
    (`crates/openfeo-config`): read it, and say the same in the page's words (`Letters, digits
    and hyphens, 63 at most.`; `Names separated by dots, such as home.arpa.`).
  - **Time**: `The panel shows times in your browser's time zone.` A pill and a sentence:
    `Synced` (ok), `The router's clock was set from the internet.`; or `Not set yet` (warn),
    `The router has not had the time from the internet yet. Times from before it has are
    counted from when the router started.` A field, `Time servers` (`system.ntp_servers`):
    `Names or addresses, separated by commas.`
  - **About**: `Version`, `Running for` (as the top bar writes it), `Certificate` (`SHA-256`
    and the fingerprint in mono), `Licences` with the link `Open-source notices` to
    `/licences.txt`.

  The dialog, when the draft renames the router, has one more block: title `This renames the
  router`, text `It will answer at https://<new name> and no longer at https://<old name>,
  and its certificate is issued again, so the browser will ask about it once more. This page
  goes on working until it is closed or reloaded: confirm the change here, then open the new
  name.` When the router said where it will be on the caller's LAN (`caller.routerAfter`), the
  block ends `It is also at https://<address>.`

- [ ] **Step 1: Write the failing tests.**

  `system-model.test.ts`: `the router's name is its hostname under its domain, with the
  defaults for what is not set`; `a draft that changes either renames the router, and one
  that changes neither does not` (nor one that spells out the default); `what the page knows
  of a name` (the cases the router's validation has); `about says the version, how long it has
  run and the fingerprint`.

  `system.test.ts`: `the page is in the navigation under Router and has the save bar`; `the
  name section says where the panel is`; `hostname and domain are settings like any other`
  (one change each, named as above); `the pill says whether the clock was set`, in both
  states and following a new state; `the time servers are a list typed with commas`; `about
  links to the notices`; `system.timezone is sent back as it came`; read-only.

  `apply.test.ts`: `a rename says where the router will be found` (the block, with the new and
  the old name, and the address when the router gave one), and `a change that renames nothing
  has no such block`.

- [ ] **Step 2: Run.** `cd web && npx vitest run --root panel test/system-model.test.ts
  test/system.test.ts` fails: no `model/system`.

- [ ] **Step 3: Implement**, the page as Task 11's was.

- [ ] **Step 4: Run.** `make web-test` and `make web-lint` pass.

- [ ] **Step 5: Commit.** `panel: the System page's name, time and about`

---

### Task 14: The System page: the password and a restart

**Files:**
- Modify: `web/panel/src/pages/System.vue`, `web/panel/src/{session.ts,live.ts,Shell.vue}`
- Modify: `web/panel/test/fake-router.ts`
- Test: `web/panel/test/system.test.ts`, `shell.test.ts`, `live.test.ts`

**Interfaces:**
- Consumes: `Router.changePassword` (there since part 1), `Router.reboot` (Task 8).
- Produces:
  - `PanelRouter` also picks `changePassword` and `reboot`; `FakeRouter` answers them
    (`changeAnswer: RouterError | null`, `rebootAnswer: RouterError | null`, both counted in
    `calls`, and held by `holdCall('changePassword' | 'reboot')`).
  - `LiveData.restarting: Ref<Date | null>` and `restart(): void`, which sets it; it is cleared
    when the socket is open again after having been lost.

  The two sections, in the words of the mockup:

  - **Password**: `Changing it takes effect at once and logs out every other session.` Fields
    `Current password`, `New password` (help `At least 12 characters.`) and `New password
    again`; a button, `Change password`. The fields are the page's own: they are in no draft,
    and the save bar does not count them.
    - What the page knows is said when a field is left: `session.ts`'s `lengthProblem` at the
      new password, `The two passwords differ.` at the second.
    - What the router refuses: a wrong current password is `That is not the current
      password.` at Current; a wait (`RESOURCE_EXHAUSTED` with `retryAfterSecs`) is `Too many
      tries. Wait <n> s.` at Current, counting down as the login screen's does, with the
      button held until it is over; anything else is said under the button with the router's
      own words.
    - While a change of config waits to be confirmed the button is held and the section says
      `A change of config is waiting to be confirmed. Confirm or revert it first.`
    - On success the three fields are emptied and a notice says `The password was changed.
      Every other session was logged out.`
  - **Restart**: `Everything goes offline for about a minute. You log in again when it is
    back.` A danger button, `Restart the router`. It opens a dialog, `Restart <router's name>?`:
    `Every device loses the internet for about a minute.`; with a change waiting to be
    confirmed, `The change that is waiting to be confirmed goes back to how it was.`; with
    changes in the draft, `<n> changes that are not applied yet are lost.` (`1 change … is
    lost.`). Its buttons are `Cancel` and, danger, `Restart`.
    - Restart calls `reboot()`; answered, the dialog closes and `live.restart()` is called. A
      refusal is said in the dialog with the router's own words, and nothing is marked.
    - While `live.restarting` is set, the shell says `The router is restarting. You log in
      again when it is back.` in place of the words for a lost connection; if the router has
      not answered two minutes on, it says `The router was asked to restart at <time> and has
      not answered since.` The session ends when the router answers (its sessions are in
      memory), and the login screen follows as for any ended session.

- [ ] **Step 1: Write the failing tests** in `system.test.ts`:

  - `the password is changed by a call of its own`: the three fields filled, the button
    pressed: one `changePassword` with the two values; then the fields are empty, the notice
    is there, and `store().changes` is empty with no save bar.
  - `what is typed for a password is kept nowhere`: after typing, nothing in the draft, in
    `store()`'s refs, in `sessionStorage` or in `localStorage` holds any of the three texts;
    after leaving the page and coming back the fields are empty.
  - `what the page knows of a new password is said when its field is left`.
  - `a wrong current password is said at its field, and the others are left as typed`
    (Review Focus 4).
  - `a wait is counted down at the field and the button is held for it`: `retryAfterSecs: 4`;
    at 4 s the button is offered again.
  - `a double press sends one call` (the call held).
  - `while a change waits to be confirmed the password cannot be changed, and the page says
    why`.
  - `the dialog says what a restart loses` (Review Focus 3): nothing in hand; a draft with two
    changes; one change; a pending change; both.
  - `Cancel asks nothing of the router`.
  - `after a restart the page waits and then asks for the password` (Review Focus 5):
    answered, the shell says the router is restarting; the socket is lost and the words stay
    the same; the session ends and the screen is the login screen.
  - `a restart the router refuses is said and nothing is marked`.

  `shell.test.ts`: `a router that was asked to restart and stays away is said to be away`
  (the second sentence, after two minutes). `live.test.ts`: `restarting is forgotten once the
  socket is open again after it was lost`, and is not forgotten by an open socket that was
  never lost.

- [ ] **Step 2: Run.** `cd web && npx vitest run --root panel test/system.test.ts` fails on
  the new tests.

- [ ] **Step 3: Implement.** The password's three texts are refs of the page and are emptied
  when it is unmounted.

- [ ] **Step 4: Run.** `make web-test` and `make web-lint` pass.

- [ ] **Step 5: Commit.** `panel: changing the password and restarting, from the System page`

---

### Task 15: The browser run, and the record

**Files:**
- Create: `web/panel/e2e/settings.spec.ts`
- Modify: `web/panel/e2e/support.ts`, `web/panel/e2e/config.spec.ts` (the navigation it
  names), `harness/tests/m4.rs`
- Modify: `CLAUDE.md` (Harness), `docs/progress.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the scenario `the_panel_changes_the_settings_and_restarts_the_router` in
  `SCENARIOS`, booted as the config run is (`openfeo.confirm_secs=40`), with the lab's second
  password in `OPENFEO_NEW_PASSWORD`; screenshots `settings-firewall`, `settings-dns`,
  `settings-system` and `settings-restart` in both themes.

- [ ] **Step 1: Write the spec**, one run in this order, each change applied and confirmed as
  `config.spec.ts` does it:

  1. Log in. The navigation is `Network` (`WAN`, `LAN & DHCP`, `Leases`, `Firewall`, `DNS`)
     and `Router` (`System`).
  2. **Firewall**: the grid has `lan0` with the internet ticked. A forward `e2e-ssh` (TCP
     2222 to `192.168.1.50`, To port 22) is added; the dialog lists `port forward e2e-ssh`;
     applied and confirmed.
  3. **A LAN that something points into**, all in one draft: a LAN `iot` at `192.168.20.1/24`
     is added on LAN & DHCP; a forward `iot-cam` to `192.168.20.5` on Firewall; on `iot`,
     Remove is not offered and the reason is a link; the link leads to Firewall, where the
     forward is removed; back on `iot`, Remove is offered and pressed; no change is left to
     apply.
  4. **DNS**: In use now names `203.0.113.1` and `from wan0`. A local name `nas` at
     `192.168.1.50` is added; the note says `nas is nas.home.arpa`; applied and confirmed.
  5. **System**: About has a version and a fingerprint, and its link opens `/licences.txt`,
     which names `tokio`. A wrong current password is said at its field. With the right one
     the password becomes `OPENFEO_NEW_PASSWORD`; after Log out the old one is refused and the
     new one logs in.
  6. **Restart**: the dialog; Restart; the page says the router is restarting; the login
     screen comes back within two minutes; the new password logs in and the top bar's uptime
     is under two minutes.

  No new lab verb is needed. `support.ts`'s `watch` is told that the router goes away for the restart, as it is told
  that the router moves (`routerMoves`); if that allowance does not fit a router that is gone
  for a while, it gains `routerRestarts()` in the same shape. The run ends with
  `expect(problems).toEqual([])`.

- [ ] **Step 2: Write the scenario.** After the browser run the Rust side finds: the old
  password refused and the new one taken; `e2e-ssh` among the config's forwards and `nas`
  among its records; a LAN host resolving `nas.home.arpa` to `192.168.1.50` at the router (by
  the helper the DNS scenarios use); on the console, `reboot requested by child` once and the
  kernel's banner twice.

- [ ] **Step 3: Run.** `make test-harness
  FILTER=the_panel_changes_the_settings_and_restarts_the_router`; expected: 1 passed. Look at
  each of the eight screenshots in `$(BUILD)/panel-shots`.

- [ ] **Step 4: The record.** `CLAUDE.md`'s Harness section gains the five scenarios of Tasks
  2 and 5 and this run (six web scenarios, each naming its own file), and `cargo about` among
  what building needs. `docs/progress.md` gains part 3b's entry and its place in the table.

- [ ] **Step 5: The whole gate.** `make lint` (and clippy under Rust 1.100.0), `make test`,
  `make bin FEATURES=`, and the whole of `make test-harness`: expected 210 scenarios, none
  failed, none skipped.

- [ ] **Step 6: Commit.** `harness, docs: the browser run for the settings pages, and the record`
