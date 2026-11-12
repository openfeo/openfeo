# M4 part 2a: the router takes a new config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A running router takes a new config over its API, restarts only what the change touches, and holds the change as pending for 120 s unless it is confirmed or was applied immediately.

**Architecture:** The five task families that are started once from the boot config (DHCPv4 client, PPPoE, RA client, DHCPv6 client, DHCPv4 server) each get a manager that compares, per instance, the slice of the config it depends on and stops, starts or restarts tasks to match; the slices and what a change does (`effects`) are pure functions in `openfeo-reconcile`. A keeper in `openfeo-api` (a sans-IO core with a thin driver on `Shared`, as sessions and backoff are) owns the confirmed and the pending config, the two files and the window's timer, and publishes a config by swapping `world.config`. A `ConfigService` on the WebSocket envelope and gRPC talks to the keeper.

**Tech Stack:** Rust stable 2024, tokio, `prost`/`pbjson`/`tonic` as in part 1a, `sha2` (already in the workspace). No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-11-m4-part2-changing-config-design.md` (everything under "Part 2a: the router", "Proven" as far as the Rust API client, "SPEC amendments", "ADRs"). SPEC §5.5, §6.3, §8.3, §10, §12.

**Not in this plan (part 2b):** `@openfeo/client`'s config calls, the draft, the WAN and LAN & DHCP pages, the apply dialog and the banner, the new components, the rule that carries addresses along with a renumbered LAN (it lives in the panel's draft), Playwright.

## Global Constraints

- Every source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton` (`//` in `.proto`, `#` in TOML and sh).
- Documentation ranges only: `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`, `2001:db8::/32`; LANs are RFC 1918 as the fixtures have them (`192.168.1.1/24`, and `192.168.2.1/24` for a second or a moved subnet). The lab's password is `lab-admin-password`; the lab's PPPoE account is the one `harness/fixtures/vm-pppoe.toml` uses.
- `clippy -D warnings` with pedantic; no `unwrap`/`expect` outside tests; `thiserror` in libraries, `anyhow` only in `crates/openfeo` and `harness/`; no `std::process::Command` outside `harness/`.
- `openfeo-reconcile` and `openfeo-world` stay pure (no tokio, libc, nix, socket2 in their trees); `openfeo-api` calls no kernel; `openfeo-config` gains no tokio. `scripts/check-deps.sh` enforces it.
- **A secret never reaches a log line, an error, an answer or a `Debug` output**: the admin's password hash, a PPPoE password. A type that holds one implements `Debug` by hand.
- **The numbers are the design's:** the window defaults to `120` s and a request may name one from `10` to `600` s (`0` means the default); a task asked to stop is given `3` s; while a change is pending a touched LAN's leases are no longer than the window.
- **The window runs on the monotonic clock** (milliseconds since the kernel booted, `openfeo_runtime::clock::boot_ms`), never the wall clock: SNTP may step the wall clock by years after boot.
- The files are `/state/config.toml` and `/state/config.pending.toml`. Every write of either is whole: a temporary file in the same directory, synced, renamed over, the directory synced.
- Console lines are a contract: each new line gets a line in a contract test in the module that prints it. The new lines are exactly:
  `config: applied; confirm within <n> s`, `config: applied immediately`, `config: effect <subject> <what>`, `config: confirmed`, `config: reverted (asked)`, `config: reverted (not confirmed in <n> s)`, `config: an unconfirmed change was discarded`, and per family `<prefix> <key> stopped` where a family has no such line yet (`pppoe wan0 stopped` exists).
- Events (SPEC §10), topic and fields: `config.applied` {`mode`: `pending` or `immediate`, `effects`: count, `window_secs`}, `config.confirmed` {}, `config.reverted` {`why`: `asked` or `timeout`}, `config.discarded` {}.
- After any change under `proto/`, run `make web-gen` and commit what it changes under `web/client/src/gen/`: `make lint` checks the generated TypeScript is up to date.
- Cargo needs `OPENFEO_NFT_SRC=$PWD/build/nft/src OPENFEO_UAPI_INCLUDE=$PWD/build/kernel/headers/include` for anything that builds `openfeo-nft` (`-p openfeo`, `-p openfeo-harness`, `--workspace`); the QEMU suites also need `OPENFEO_KERNEL=$PWD/build/bzImage`. A harness scenario runs against the image: `make kernel` first, then `OPENFEO_NO_SKIP=1 make test-harness FILTER=<name>`.
- A helper a test below calls and no task defines (`world_with`, `config_of`, `spawn_api`, `fake_family`, …) is that test module's own to write, as small as the test needs. `openfeo_reconcile::fixtures` has Worlds for the lab's configs.
- Commits `git commit -s`, identity `Andrew Newton <andy@vitri.ltd>`, subject `<area>: <summary>`. Nothing is pushed and no PR opened without a sweep; never merged.

## Calls this plan makes beyond the design

Each is the plan's, to be reported with the executor's rulings.

1. **The request's field is `immediate`, not `commit_confirm`.** A protobuf `bool` left out is `false`; a script that leaves the field out must get the countdown, not the path with no way back. SPEC §8.3 is amended to say so. Cost: the spec's own word for it changes.
2. **The keeper lives in `openfeo-api`**, a sans-IO core with its driver on `Shared`, beside sessions and the password, which already writes `config.toml` and publishes into the World from there. Cost: the API crate owns more than the wire.
3. **A refused apply is an error (`INVALID_ARGUMENT`) whose text names up to five violations;** the full list comes from `ValidateConfig`. Cost: a script that wants every violation asks twice.
4. **The tag is a digest of the config without its secrets** (the first 16 bytes of SHA-256 over the rendered, redacted config, in hex). A revert brings the old tag back, so a draft made before the change still applies; two configs that differ only in a PPPoE password share a tag, and the one that typed nothing keeps the other's password. Cost: none found.
5. **The lease database keeps the records it cannot use.** A record outside the server's subnet is carried through every write until it expires, so a revert finds the confirmed config's leases where it left them. No second lease file. Cost: a renumbered LAN's old records sit in the file for up to one lease time.
6. **The cap on leases rides in the server's desired state**, so the server is restarted once more when the change is confirmed. A restart reads the database back and no client sees it. Cost: one invisible restart.
7. **What is pending is a fact in the World** (`world.pending`), so that the state stays a pure function of the World and the DHCP server reads the cap like any other input.
8. **DHCPv4 gains a release; DHCPv6 sends none** and the RA client has nothing to say. Cost: a delegated prefix's binding lingers at the ISP until it expires, as it does today when the router is switched off.
9. **File facts are proven through the console's lines and through reboots,** not by reading the state disk from outside (QEMU holds it open with `cache=unsafe`).
10. **Removing a VLAN tag is proven by the sub-interface going away,** not by the WAN coming up: the lab's ISP is on one side of the tag at a time.
11. **A changed hostname or domain is an effect** (`RouterRenamed`): the certificate is reissued and the browser will warn.

## Review Focus

1. **Power lost between writing a file and its rename.** A reboot at any instant must come up on a whole `config.toml`, never a truncated one. Pinned by `a_write_is_whole_or_absent` (Task 11) and `a_restart_during_the_window_discards_the_change` (Task 18).
2. **Nobody connected when the window ends.** The apply's own connection died with the address it moved; the timer must still fire and the revert must not need a client. Pinned by `the_window_runs_out_with_nobody_listening` (Task 14) and `a_subnet_change_not_confirmed_is_reverted` (Task 18).
3. **A task that will not stop,** or is asleep in its restart backoff when it is told to. The manager must not wait for ever and must never leave two instances on one WAN. Pinned by `a_task_that_ignores_stop_is_dropped_after_the_grace` and `a_task_waiting_out_its_backoff_stops_at_once` (Task 2), and `an_instance_is_gone_before_its_replacement_starts` (Task 5).
4. **The wall clock stepping during the window** when SNTP first answers. Pinned by `the_window_is_counted_on_the_boot_clock_alone` (Task 13: the core takes `now_boot_ms` and nothing else).
5. **A WAN that changes type under the same name.** The new type must not inherit the old one's facts (a DHCP lease's address and routes under a PPPoE WAN). Pinned by `a_stopped_instance_takes_its_facts_with_it` (Task 5) and `a_wan_changes_type_while_running` (Task 19).

---

### Task 1: SPEC amendments and ADR-0026

**Files:**
- Modify: `SPEC.md` (§1.2, §2, §5.5, §6.3, §8.3, §10, §12)
- Create: `docs/adr/0026-commit-confirm-waits-120-seconds.md`

No code.

- [ ] **Step 1: Write ADR-0026** (Context: SPEC §2 fixes a 60 s default; a change that moves the router's address needs the client to take a new lease and return to the panel inside the window, by hand. Decision: 120 s by default; a request may name 10 to 600 s. Consequences: an unconfirmed mistake stands a minute longer; the design's "Leases across a change" keeps that minute from stranding clients).
- [ ] **Step 2: Amend SPEC.md.**
  - §1.2: "LAN VLANs and multiple LAN zones in the panel" becomes LAN VLANs only; LANs are added, removed and edited in the panel (M4 part 2).
  - §2: the Config row's default reads 120 s (ADR-0026).
  - §5.5: the window and its bounds; the immediate apply; a second apply and a password change are refused while one is pending; any start of the router process discards a pending file; an apply is refused on a router running on defaults over a refused file; a touched LAN's leases are capped at the window while pending, and a revert finds the confirmed config's leases.
  - §6.3: the five families follow the config through a manager each; what stopping a task means (asked, takes its facts, not a failure).
  - §8.3: `ConfigService` with `GetConfig`, `ValidateConfig`, `ApplyConfig{immediate, timeout_secs, tag}`, `ConfirmConfig`, `RevertConfig`; the tag; write-only secrets; what a validation says of effects and of the caller; `Backup` and `Restore` stay with M5.
  - §10: the `config.*` events and their fields; the state's pending change.
  - §12: M4's part 2 as 2a (this plan; acceptance "LAN subnet changed without confirming → reverted", "confirmed from the new address", "a LAN change leaves a PPPoE session alone") and 2b.
- [ ] **Step 3: Verify and commit.** Run: `make lint` → Expected: exit 0. `git commit -s -m "docs: SPEC amendments for changing config and ADR-0026, the 120-second window"`

---

### Task 2: A task can be stopped

**Files:**
- Modify: `crates/openfeo-runtime/src/supervise.rs`, `crates/openfeo-runtime/src/lib.rs` (re-exports)

**Interfaces:**
- Produces, in `openfeo_runtime::supervise` (re-exported at the crate root):
  - `pub const STOP_GRACE: Duration = Duration::from_secs(3);`
  - `#[derive(Debug, Clone)] pub struct Stop` with `pub async fn requested(&mut self)` (returns once a stop was asked, at once if it already was) and `pub fn is_requested(&self) -> bool`.
  - `#[derive(Debug)] pub struct Stoppable` with `pub async fn stop(self)`: ask, wait up to `STOP_GRACE` for the task to return, then abort it. Dropping a `Stoppable` aborts its task at once.
  - `impl Supervisor { pub fn spawn_stoppable<F, Fut>(&self, name: impl Into<String>, factory: F) -> Stoppable where F: Fn(Stop) -> Fut + Send + 'static, Fut: Future<Output = Result<(), TaskError>> + Send + 'static }`: as `spawn` (restart with backoff, dead after `MAX_RESTARTS`), except that once a stop is asked the task is never restarted, a backoff sleep ends at once, and nothing is reported to health.

- [ ] **Step 1: Write the failing tests** in `supervise.rs`'s `tests`, all `#[tokio::test(start_paused = true)]`:
  - `a_stopped_task_ends_and_is_not_restarted`: a factory whose task awaits `stop.requested()` then returns `Ok(())`; after `stop().await` the factory has been called exactly once and 60 s later still once.
  - `a_task_that_ignores_stop_is_dropped_after_the_grace`: a task that sleeps for ever; `stop().await` returns after `STOP_GRACE` (not before, not more than a second after) and a flag the task would set on drop is set.
  - `a_task_waiting_out_its_backoff_stops_at_once`: a task that fails immediately; after its first failure, `stop().await` returns within a millisecond of virtual time and the factory is not called again.
  - `a_stop_is_not_a_death`: a task that returns `Err` when asked to stop; after `stop().await`, `health.report(now)` names no dead task.
  - `a_task_that_fails_unasked_is_still_restarted`: fails once, then waits; the factory is called twice.
  - `dropping_the_handle_ends_the_task`.
- [ ] **Step 2: Run** `cargo test -p openfeo-runtime supervise` → Expected: FAIL to compile (`spawn_stoppable` not found).
- [ ] **Step 3: Implement** `Stop` over a `tokio::sync::watch::Receiver<bool>` and the loop of `spawn` with the stop raced against the running task and against the backoff sleep.
- [ ] **Step 4: Run** `cargo test -p openfeo-runtime` → Expected: PASS, the six new tests among them.
- [ ] **Step 5: Commit.** `git commit -s -m "runtime: a supervised task can be asked to stop"`

---

### Task 3: Slices: what each instance depends on

**Files:**
- Create: `crates/openfeo-reconcile/src/slices.rs`
- Modify: `crates/openfeo-reconcile/src/lib.rs` (`pub mod slices;`)

**Interfaces:**
- Produces, in `openfeo_reconcile::slices`, each type `Clone + PartialEq + Eq`, keyed by WAN name in config order:
  - `pub struct Dhcp4ClientSlice { pub port: String, pub hostname: Option<String>, pub vendor_class: Option<Vec<u8>> }`, `pub fn dhcp4_clients(config: &Config) -> BTreeMap<String, Dhcp4ClientSlice>` (a WAN of kind DHCP).
  - `pub struct PppoeSlice { pub port: String, pub username: String, pub password: Vec<u8>, pub service: Option<String>, pub ac: Option<String> }` with `Debug` by hand (the password prints as `<redacted>`), `pub fn pppoe_clients(config: &Config) -> BTreeMap<String, PppoeSlice>`.
  - `pub struct RaClientSlice { pub port: String, pub netdev: String, pub gateway: Option<Ipv6Addr> }`, `pub fn ra_clients(config: &Config) -> BTreeMap<String, RaClientSlice>` (a WAN with `[wans.ipv6]` whose mode is not `disabled`).
  - `pub struct Dhcp6ClientSlice { pub port: String, pub netdev: String, pub pd_hint: u8 }`, `pub fn dhcp6_clients(config: &Config) -> BTreeMap<String, Dhcp6ClientSlice>` (as the RA client, and no typed `prefix`).
  - `port` is `wan_ifname(wan)`, `netdev` is `wan_netdev(wan)`, `pd_hint` is `openfeo_config::rules::pd_hint`. These are the fields the `WanTask` structs in `crates/openfeo/src/{dhcp4,pppoe,ipv6,dhcp6}.rs` copy today; the conditions are those of each `spawn_all`.

- [ ] **Step 1: Write the failing tests** in `slices.rs`:
  - `a_wan_of_each_kind_is_in_its_own_families`: from `fixtures`' DHCP, PPPoE and IPv6 configs, which maps hold `wan0`.
  - `a_vlan_tag_changes_every_slice_of_its_wan`: `vlan = 101` gives `port == "p0.101"` in each.
  - `a_change_elsewhere_changes_no_slice`: change a WAN's `priority`, add a reservation to `lan0`, add a port forward, change the hostname: all four maps are equal before and after.
  - `a_pppoe_wan_keeps_its_port_as_the_ra_clients_port_and_ppp_as_its_netdev`: `netdev == "ppp-wan0"`, `port == "p0"`.
  - `a_typed_prefix_means_no_dhcp6_client`; `ipv6_disabled_means_neither`.
  - `a_pppoe_slice_never_prints_its_password`: `format!("{slice:?}")` contains `<redacted>` and not the password.
- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile slices` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p openfeo-reconcile` → Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -s -m "reconcile: the slice of the config each WAN task depends on"`

---

### Task 4: Effects, and what is pending as a fact

**Files:**
- Create: `crates/openfeo-world/src/pending.rs`, `crates/openfeo-reconcile/src/effects.rs`
- Modify: `crates/openfeo-world/src/world.rs` (`pub pending: Option<Arc<PendingFact>>`, `None` in `World::new`), `crates/openfeo-world/src/lib.rs`, `crates/openfeo-reconcile/src/lib.rs`, `crates/openfeo-reconcile/src/dhcp.rs`

**Interfaces:**
- Consumes: Task 3's slice functions.
- Produces:
  - `openfeo_world::{Effect, EffectKind, PendingFact}`:
    `pub enum EffectKind { WanAdded, WanRemoved, WanReconnects, LanAdded, LanRemoved, LanAddressMoves, LanDhcpStarts, LanDhcpStops, LanDhcpRestarts, RouterRenamed }` with `pub fn what(self) -> &'static str` giving `is added`, `is removed`, `reconnects`, `is added`, `is removed`, `address moves`, `dhcp starts`, `dhcp stops`, `dhcp restarts`, `is renamed`;
    `pub struct Effect { pub subject: String, pub kind: EffectKind }`;
    `pub struct PendingFact { pub applied_boot_ms: u64, pub reverts_boot_ms: u64, pub window_secs: u32, pub effects: Vec<Effect>, pub lans: BTreeSet<String> }` (`lans`: the LANs the change touches).
  - `openfeo_reconcile::dhcp::servers_of(config: &Config) -> BTreeMap<String, DesiredDhcpServer>` (what `servers` computes today, which reads only the config); `servers(world)` is `servers_of(&world.config)` with `lease_cap` set. `DesiredDhcpServer` gains `pub lease_cap: Option<u32>`: `Some(pending.window_secs)` for a LAN in `world.pending`'s `lans`, else `None`. `server_config` gives the core `lease_secs.min(cap)`.
  - `openfeo_reconcile::effects::effects(old: &Config, new: &Config) -> Vec<Effect>` and `pub fn touched_lans(old: &Config, new: &Config) -> BTreeSet<String>`.
- The rules of `effects`, in this order of output: WANs in `new`'s order, then WANs only in `old`; LANs likewise; then the router.
  - A WAN only in `new`: `WanAdded`. Only in `old`: `WanRemoved`. In both, and any of its four slices differs (one present and the other absent counts): `WanReconnects`.
  - A LAN only in `new`: `LanAdded`. Only in `old`: `LanRemoved`. In both: `ipv4` differs → `LanAddressMoves` and nothing more for that LAN's DHCP; else its `servers_of` entry absent → present `LanDhcpStarts`, present → absent `LanDhcpStops`, both and unequal `LanDhcpRestarts`.
  - `system.hostname` or `system.domain` differs (after their defaults) → `RouterRenamed` with the new `<hostname>.<domain>` as its subject.
  - `touched_lans`: every LAN of `new` or `old` whose `ipv4` or `servers_of` entry differs between the two, or that is in only one.

- [ ] **Step 1: Write the failing tests.** In `effects.rs`:
  - `the_same_config_has_no_effects`: for every config in `fixtures`, `effects(c, c)` is empty and `touched_lans(c, c)` is empty.
  - `a_change_outside_every_slice_has_no_effects`: a WAN's priority, a port forward, a DNS record, a LAN's `reaches`.
  - `each_change_names_its_effect`: a table of one change and the exact `Vec<Effect>`: PPPoE username → `[wan0 WanReconnects]`; DHCP to PPPoE → `[wan0 WanReconnects]`; a second WAN → `[wan1 WanAdded]`; `lan0`'s `ipv4` `192.168.1.1/24` to `192.168.2.1/24` with its pool moved → `[lan0 LanAddressMoves]`; a reservation added → `[lan0 LanDhcpRestarts]`; `[lans.dhcp]` removed → `[lan0 LanDhcpStops]`; a LAN removed → `[guest LanRemoved]`; hostname `openfeo` to `edge` → `[edge.home.arpa RouterRenamed]`.
  - `effects_come_wans_then_lans_then_the_router`.
  - `an_unchanged_slice_never_yields_an_effect`: for each pair of fixture configs, a WAN whose four slices are equal in both is the subject of no effect.
  In `dhcp.rs`: `a_pending_change_caps_the_leases_of_a_lan_it_touches` (a World with `pending { window_secs: 120, lans: {lan0} }`: `servers(world)["lan0"].lease_cap == Some(120)`, `server_config(..).lease_secs == 120` where the config says 43200, and a LAN not in `lans` has `None`); `a_cap_longer_than_the_lease_changes_nothing`.
- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile effects dhcp` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.** Every construction of `World` and of `DesiredDhcpServer` in the workspace gains the new field.
- [ ] **Step 4: Run** `OPENFEO_NFT_SRC=… OPENFEO_UAPI_INCLUDE=… cargo test --workspace --exclude openfeo-harness` → Expected: PASS (the snapshots of `openfeo-reconcile`'s state tests are unchanged: nothing reads `pending` yet).
- [ ] **Step 5: Commit.** `git commit -s -m "reconcile, world: what a change of config does, and a pending change as a fact"`

---

### Task 5: The family manager

**Files:**
- Create: `crates/openfeo/src/family.rs`
- Modify: `crates/openfeo/src/main.rs` (`mod family;`)

**Interfaces:**
- Consumes: `Supervisor::spawn_stoppable`, `Stop`, `Stoppable` (Task 2).
- Produces, in `crate::family`:
  ```rust
  pub trait Family: Send + Sync + 'static {
      type Slice: Clone + PartialEq + Send + Sync + 'static;
      /// Task names are `<PREFIX>-<key>`, as they are today.
      const PREFIX: &'static str;
      /// The instances the World asks for.
      fn wanted(&self, world: &World) -> BTreeMap<String, Self::Slice>;
      /// One instance. It returns `Ok(())` soon after `stop` is asked, having said goodbye.
      fn run(&self, key: &str, slice: &Self::Slice, publisher: Arc<Publisher>, world_rx: WorldRx, stop: Stop) -> BoxedTask;
      /// Take what an instance published out of the World.
      fn withdraw(&self, key: &str, world: &mut World);
  }
  pub fn spawn<F: Family>(family: F, supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx);
  ```
  `spawn` starts one supervised task named `<PREFIX>-manager`. On every World it compares `wanted` with what runs: an instance no longer wanted, or wanted with a different slice, is stopped (`Stoppable::stop`), then `withdraw` is published for it, and only then is its replacement started. Instances whose slice is equal are not touched. Stops of different keys run together; the manager does not look at the next World until they are done.

- [ ] **Step 1: Write the failing tests** in `family.rs` with a `fake_family` whose instances record `started <key> <slice>` and `stopped <key>` into a shared log and publish `world.dhcp4[key]` as their fact, and whose `wanted` reads a map the test puts into the World's config (a WAN per key, the slice its `priority`). All `#[tokio::test(start_paused = true)]`:
  - `the_instances_the_config_asks_for_are_started`.
  - `an_unchanged_instance_is_left_alone_when_another_changes`: change `wan1`'s slice; the log has no `stopped wan0` and `wan0` was started once.
  - `a_changed_instance_is_restarted_with_its_new_slice`.
  - `an_instance_no_longer_wanted_is_stopped`.
  - `an_instance_is_gone_before_its_replacement_starts`: the fake takes 2 s to stop; the log's `stopped wan0` precedes the second `started wan0`.
  - `a_stopped_instance_takes_its_facts_with_it`: after a stop, `publisher.current().dhcp4` has no entry for the key, and it had one before.
  - `a_world_that_changes_only_in_its_facts_restarts_nothing`: publish a link fact; nothing in the log.
  - `the_manager_dying_takes_its_instances_with_it` (dropping the manager's map aborts them).
- [ ] **Step 2: Run** `OPENFEO_NFT_SRC=… OPENFEO_UAPI_INCLUDE=… cargo test -p openfeo family` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the same → Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -s -m "router: a manager that keeps a family of tasks in step with the config"`

---

### Task 6: The DHCPv4 client releases its lease and follows the config

**Files:**
- Modify: `crates/openfeo-proto-dhcp4/src/client.rs` (`Input::Release`), `crates/openfeo-net/src/dhcp4.rs` (`Driver::release`), `crates/openfeo/src/dhcp4.rs`, `crates/openfeo/src/router.rs` (this family's `spawn_all` call becomes `family::spawn(Dhcp4Clients, …)`), `fuzz/fuzz_targets/dhcp4_differential.rs` only if it enumerates `Input`

**Interfaces:**
- Consumes: `Family` (Task 5), `slices::{Dhcp4ClientSlice, dhcp4_clients}` (Task 3).
- Produces:
  - `openfeo_proto_dhcp4::client::Input::Release`: in `Bound`, `Renewing` or `Rebinding` the client emits one `Output::Send` of a DHCPRELEASE (RFC 2131 §4.4.4: unicast to the server, `ciaddr` the leased address, option 54 the server, the client identifier, no requested-address option) and goes to `Init` with no lease; in any other state it emits nothing.
  - `openfeo_net::dhcp4::Driver::release(&mut self) -> Result<Vec<Event>, DriverError>`.
  - `crate::dhcp4::Dhcp4Clients` implementing `Family` with `PREFIX = "dhcp4"`, `Slice = Dhcp4ClientSlice`; `spawn_all` is removed. `withdraw` removes `world.dhcp4[key]` and clears `world.wan_status[key].cause`.
  - The console line `dhcp4 <wan> stopped` (in the module's contract test). The lease file is left: a WAN given back its DHCP type starts from it.

- [ ] **Step 1: Write the failing tests.**
  - `client.rs`: `a_bound_client_releases_its_lease_to_its_server` (the packet's type is RELEASE, `ciaddr` is the leased address, `dst` is the server, option 50 is absent; afterwards `state() == State::Init` and `lease()` is `None`); `a_client_with_no_lease_releases_nothing` (in `Selecting`: no output).
  - `crates/openfeo/src/dhcp4.rs`: `a_task_waiting_for_its_port_stops_at_once` (a World whose port has no carrier; `stop` asked; `run` returns `Ok(())` within a millisecond of paused time); `the_family_wants_one_client_per_dhcp_wan`; `withdrawing_takes_the_lease_and_the_cause`.
- [ ] **Step 2: Run** `cargo test -p openfeo-proto-dhcp4 release` and `… cargo test -p openfeo dhcp4` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.** `run` takes `(wan: &str, slice: &Dhcp4ClientSlice, …, stop: Stop)`; every await that can wait without bound (`wait_for_link`, the driver's step, the World) is raced against `stop.requested()`; on a stop the driver releases, the line is printed, and `run` returns `Ok(())`.
- [ ] **Step 4: Run** `cargo test -p openfeo-proto-dhcp4`, `… cargo test -p openfeo-net dhcp4`, `… cargo test -p openfeo dhcp4` → Expected: PASS. Run `OPENFEO_NO_SKIP=1 make test-harness FILTER=dhcp4` (the sandbox suite against Kea) → Expected: every scenario ok.
- [ ] **Step 5: Commit.** `git commit -s -m "dhcp4: the client releases its lease when stopped and follows the config"`

---

### Task 7: PPPoE follows the config

**Files:**
- Modify: `crates/openfeo/src/pppoe.rs`, `crates/openfeo/src/router.rs` (this family's call site; the secret is `ipv6_secret.unwrap_or([0; 16])` as today)

**Interfaces:**
- Consumes: `Family`, `slices::{PppoeSlice, pppoe_clients}`; the session core's `Input::Stop` (it exists: a Terminate-Request in order, then `Down` with `Reason::Stopped`).
- Produces: `crate::pppoe::PppoeClients { pub secret: [u8; 16] }` implementing `Family` with `PREFIX = "pppoe"`, `Slice = PppoeSlice`; `spawn_all` and `WanTask` are removed (the slice and the family's `secret` replace them). `withdraw` removes `world.pppoe[key]` and clears the cause.

- [ ] **Step 1: Write the failing tests** in `pppoe.rs`: `a_task_waiting_for_its_port_stops_at_once`; `a_task_discovering_stops_at_once_and_sends_no_padt` (no session yet: nothing to end); `a_stop_during_a_session_ends_it_in_order` (with the module's existing session fakes: the session core is given `Input::Stop`, the cause is `Cause::Session(Reason::Stopped)`, our PADT is sent, and `run` returns `Ok(())` without waiting out a backoff); `the_family_wants_one_client_per_pppoe_wan`; `withdrawing_takes_the_session`.
- [ ] **Step 2: Run** `… cargo test -p openfeo pppoe` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.** `run`, `discover` and `run_session` race `stop.requested()`; a stopped session prints `pppoe <wan> stopped` (the line exists).
- [ ] **Step 4: Run** `… cargo test -p openfeo pppoe` → PASS; `OPENFEO_NO_SKIP=1 make test-harness FILTER=pppoe` → every scenario ok.
- [ ] **Step 5: Commit.** `git commit -s -m "pppoe: a session is ended in order when its WAN's config changes"`

---

### Task 8: The RA client and the DHCPv6 client follow the config

**Files:**
- Modify: `crates/openfeo/src/ipv6.rs`, `crates/openfeo/src/dhcp6.rs`, `crates/openfeo/src/router.rs` (both call sites)

**Interfaces:**
- Produces: `crate::ipv6::RaClients { pub secret: [u8; 16] }` (`PREFIX = "ipv6"`, `Slice = RaClientSlice`, `withdraw` removes `world.ipv6[key]`) and `crate::dhcp6::Dhcp6Clients` (`PREFIX = "dhcp6"`, `Slice = Dhcp6ClientSlice`, `withdraw` removes `world.dhcp6[key]`); both `spawn_all`s and `WanTask`s are removed. Lines `ipv6 <wan> stopped`, `dhcp6 <wan> stopped`. Neither sends anything on a stop (plan call 8); the DHCPv6 binding file is left.

- [ ] **Step 1: Write the failing tests** in each: `a_task_waiting_for_its_netdev_stops_at_once`; `a_running_task_stops_at_once`; `the_family_wants_…` (the conditions of Task 3); `withdrawing_takes_…`. In `dhcp6.rs` also `a_withdrawn_delegation_is_deprecated_on_the_lans` if no test already holds that the RA server deprecates a prefix whose `world.dhcp6` entry went (it is the mechanism the design's IPv6 sentence leans on; find the existing test in `openfeo-reconcile::ra` and name it in the ledger instead when there is one).
- [ ] **Step 2: Run** `… cargo test -p openfeo ipv6 dhcp6` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `… cargo test -p openfeo` → PASS; `OPENFEO_NO_SKIP=1 make test-harness FILTER=dhcp6` and `FILTER=ndp` → every scenario ok.
- [ ] **Step 5: Commit.** `git commit -s -m "ipv6, dhcp6: the WAN's IPv6 clients follow the config"`

---

### Task 9: The DHCPv4 server follows the config; leases across a change

**Files:**
- Modify: `crates/openfeo/src/dhcp4_server.rs`, `crates/openfeo/src/router.rs` (its call site)

**Interfaces:**
- Consumes: `dhcp::servers(world)` with `lease_cap` (Task 4), `Family`.
- Produces: `crate::dhcp4_server::Dhcp4Servers` (`PREFIX = "dhcp4-server"`, `Slice = DesiredDhcpServer`, `wanted` is `servers(world)`, `withdraw` removes `world.leases[key]`); `spawn_all` is removed. The lease database: `read_leases` returns the records inside the server's subnet for the driver and the rest apart ("foreign"); every save writes both; a foreign record is dropped once its expiry has passed. On a stop a save still owed is written before `run` returns. Line `lan <lan> dhcp stopped`.

- [ ] **Step 1: Write the failing tests** in `dhcp4_server.rs`:
  - `a_record_outside_the_subnet_is_kept_in_the_file_and_out_of_the_server`: a file with leases in `192.168.1.0/24` read by a server of `192.168.2.1/24`: the driver gets none; after a grant and a save the file holds the old records and the new one.
  - `a_foreign_record_past_its_time_is_dropped_at_the_next_save`.
  - `going_back_finds_the_leases_where_they_were`: the same file read again by a server of `192.168.1.1/24` gives the driver the old records and holds the `192.168.2.0/24` one as foreign.
  - `a_capped_server_grants_no_longer_than_the_cap`: `lease_cap: Some(20)` with `lease_secs: 43200`: the ACK's option 51 is 20.
  - `a_save_owed_is_written_before_a_stopped_server_returns`.
  - `the_family_wants_one_server_per_lan_with_dhcp`; `withdrawing_takes_the_lan_s_leases`.
- [ ] **Step 2: Run** `… cargo test -p openfeo dhcp4_server` → Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `… cargo test -p openfeo dhcp4_server` → PASS; `OPENFEO_NO_SKIP=1 make test-harness FILTER=dhcp4_server` → every scenario ok.
- [ ] **Step 5: Commit.** `git commit -s -m "dhcp4 server: follows the config, caps leases while a change is pending, keeps the records it cannot use"`

---

### Task 10: The rest follow

**Files:**
- Modify: `crates/openfeo/src/dns.rs` (`spawn` always starts the task; with no LAN to listen on it waits for a World that has one), and whichever of `ra.rs`, `dhcp6_server.rs`, `time.rs`, `router.rs`, `crates/openfeo-api/src/listener.rs` a test below shows took something from the config once

**Interfaces:**
- Produces: nothing new. The five families are on managers since Tasks 6 to 9; after this task, replacing `world.config` through the publisher is enough to reconfigure the whole router.

- [ ] **Step 1: Write the failing tests**, one per follower, each publishing a second config into a World and asking what the task now wants:
  - `dns.rs`: `a_router_with_no_lan_starts_dns_when_one_is_added` (today `spawn` returns before starting anything); `a_lan_added_later_gets_a_listener` (`desired` of the second World names `br-lan1`).
  - `ra.rs`, `dhcp6_server.rs`, `time.rs`: `the_task_s_desired_state_follows_a_changed_config` (a LAN's `ra = false`; a changed domain; a WAN removed), asserting on `desired(&world)`.
  - `ra.rs`: `a_prefix_the_config_takes_off_a_lan_is_deprecated_to_its_hosts` (a LAN's typed `ipv6` changed to another /64, then to `none`: the next advertisement carries the old prefix with zero lifetimes, as a withdrawn delegation's does).
  - `openfeo-api`: `a_renamed_router_is_reissued_a_certificate_and_takes_its_new_name` (the certificate loop, on a World whose `system.hostname` changed, decides `Action::Reissue(Why::Names)`, and `Shared::names()` gives the new name).
  - `router.rs`: `the_appliers_follow_a_changed_config`: `links`, `routing` and `nft` computed from a World after `config` is swapped for one with a second LAN name `br-lan1` and its zone.
- [ ] **Step 2: Run** `… cargo test -p openfeo` and `cargo test -p openfeo-api` → Expected: the DNS test FAILS (no task is started); the others say which followers need work. A follower whose test passes untouched is recorded in the ledger as already following.
- [ ] **Step 3: Implement** what failed.
- [ ] **Step 4: Run** `make lint && make test` → exit 0. `make kernel && OPENFEO_NO_SKIP=1 make test-harness` → every suite ok: the router behaves as before when the config never changes.
- [ ] **Step 5: Commit.** `git commit -s -m "router: every task family follows the config in the World"`

---

### Task 11: Secrets, the tag and whole files

**Files:**
- Create: `crates/openfeo-config/src/secrets.rs`
- Modify: `crates/openfeo-config/src/lib.rs`, `crates/openfeo-config/src/file.rs` or `admin.rs` (the atomic write, shared with `write_password_hash`), `crates/openfeo-config/Cargo.toml` (`sha2`)

**Interfaces:**
- Produces, in `openfeo_config`:
  - `secrets::redact(config: &Config) -> Config`: `admin.password_hash` and every `wans[].pppoe.password` empty; nothing else changed.
  - `secrets::carry(running: &Config, proposed: &mut Config)`: `proposed.admin` becomes `running.admin` whatever it held; a PPPoE WAN of `proposed` whose password is empty takes the password of the WAN of the same name in `running` when that one is PPPoE.
  - `secrets::tag(config: &Config) -> String`: 32 lowercase hex characters, the first 16 bytes of SHA-256 over `file::render(&redact(config))`.
  - `pub const PENDING_FILE: &str = "config.pending.toml";` and `pub fn pending_path(config_path: &Path) -> PathBuf` (beside it).
  - `file::write_whole(path: &Path, text: &str) -> Result<(), ConfigError>`: the write Global Constraints describes.

- [ ] **Step 1: Write the failing tests** in `secrets.rs` and beside `write_whole`:
  - `redact_blanks_every_secret_and_nothing_else` (a config with a hash and two PPPoE WANs; the result differs from the input in exactly those three strings).
  - `an_empty_pppoe_password_keeps_the_running_one`; `a_typed_password_replaces_it`; `an_empty_password_on_a_wan_that_was_not_pppoe_stays_empty` (validation then refuses it); `a_renamed_wan_does_not_inherit_a_password`.
  - `the_hash_is_never_taken_from_a_proposal` (a proposal carrying another hash, and one carrying none, both end with the running hash).
  - `two_configs_that_differ_only_in_a_secret_share_a_tag`; `any_other_difference_changes_the_tag`; `the_tag_is_32_hex_characters`.
  - `a_write_is_whole_or_absent`: after `write_whole` the file holds the text and no temporary file is left; a write into a directory that does not exist is an error and creates nothing; a write over an existing file whose temporary file cannot be renamed (the target is a directory) leaves the target as it was.
- [ ] **Step 2: Run** `cargo test -p openfeo-config secrets write_whole` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p openfeo-config` → PASS; `scripts/check-deps.sh` → exit 0.
- [ ] **Step 5: Commit.** `git commit -s -m "config: secrets kept out of answers, a tag for a config, and whole-file writes"`

---

### Task 12: The schema

**Files:**
- Modify: `proto/openfeo/v1/api.proto`, `proto/openfeo/v1/state.proto`, `web/client/src/gen/` (generated)

**Interfaces:**
- Produces (field numbers are the implementer's; names are fixed):
  - `state.proto`: `enum ConfigEffectKind` with the ten kinds of Task 4 (`CONFIG_EFFECT_KIND_WAN_ADDED` …); `message ConfigEffect { string subject; ConfigEffectKind kind; }`; `message PendingConfig { uint64 applied_uptime_ms; uint64 reverts_uptime_ms; uint32 window_secs; repeated ConfigEffect effects; }`; `SystemState` gains `optional PendingConfig pending_config`.
  - `api.proto`: `GetConfigRequest {}`; `GetConfigResponse { Config config; string tag; uint32 confirm_secs; }`; `ValidateConfigRequest { Config config; }`; `message Caller { bool connection_drops; bool lan_changes; string lan; string router_after; }`; `ValidateConfigResponse { repeated ConfigViolation violations; repeated ConfigEffect effects; Caller caller; }`; `ApplyConfigRequest { Config config; string tag; bool immediate; uint32 timeout_secs; }`; `ApplyConfigResponse { string tag; }`; `ConfirmConfigRequest {}`, `ConfirmConfigResponse {}`, `RevertConfigRequest {}`, `RevertConfigResponse {}`; `service ConfigService` with `GetConfig`, `ValidateConfig`, `ApplyConfig`, `ConfirmConfig`, `RevertConfig`; `Request.body` and `Response.body` each gain the five (`get_config`, `validate_config`, `apply_config`, `confirm_config`, `revert_config`).

- [ ] **Step 1: Write the failing test** in `crates/openfeo-config/src/lib.rs`'s tests: `a_request_that_says_nothing_asks_for_the_countdown`: `api::ApplyConfigRequest::default().immediate == false` and `timeout_secs == 0`; and the JSON name of `pending_config` is `pendingConfig`.
- [ ] **Step 2: Run** `cargo test -p openfeo-config a_request_that_says_nothing` → Expected: FAIL to compile.
- [ ] **Step 3: Write the messages; run `make web-gen`.**
- [ ] **Step 4: Run** `cargo test -p openfeo-config` → PASS; `make lint` → exit 0 (`buf lint`, the generated TypeScript up to date).
- [ ] **Step 5: Commit.** `git commit -s -m "proto: ConfigService, a pending change in the state, and the effects of a change"`

---

### Task 13: The keeper's core

**Files:**
- Create: `crates/openfeo-api/src/keeper.rs`
- Modify: `crates/openfeo-api/src/lib.rs`

**Interfaces:**
- Consumes: `effects`, `touched_lans` (Task 4); `secrets::{carry, tag}` (Task 11); `validate::validate`; `ConfigState`.
- Produces, in `openfeo_api::keeper`, with no clock, file or channel of its own:
  ```rust
  pub const DEFAULT_WINDOW_SECS: u32 = 120;
  pub const WINDOW_SECS: RangeInclusive<u32> = 10..=600;
  pub enum Refusal { Invalid(Vec<Violation>), StaleTag, ChangePending, NothingPending, FileRefused, Window }
  pub enum Why { Asked, TimedOut }
  pub struct Accepted { /* the config to run, whether it is immediate, the PendingFact if not */ }
  impl Accepted { pub fn config(&self) -> &Arc<Config>; pub fn pending(&self) -> Option<&PendingFact>; pub fn effects(&self) -> &[Effect]; }
  pub struct Keeper { /* confirmed, pending, default window, whether the file was refused */ }
  impl Keeper {
      pub fn new(confirmed: Arc<Config>, state: &ConfigState, default_window_secs: u32) -> Keeper;
      pub fn running(&self) -> &Arc<Config>;
      pub fn confirmed(&self) -> &Arc<Config>;
      pub fn pending(&self) -> Option<&PendingFact>;
      pub fn default_window_secs(&self) -> u32;
      /// A proposal with the running secrets carried in, or its violations.
      pub fn check(&self, proposed: Config, ports: &PortMap) -> Result<(Config, Vec<Effect>), Refusal>;
      /// Decide an apply. Changes nothing.
      pub fn accept(&self, proposed: Config, tag: &str, immediate: bool, timeout_secs: u32, ports: &PortMap, now_boot_ms: u64) -> Result<Accepted, Refusal>;
      /// The files are written: take it.
      pub fn commit(&mut self, accepted: Accepted);
      /// The pending config becomes the confirmed one. Returns it.
      pub fn confirm(&mut self) -> Result<Arc<Config>, Refusal>;
      /// Back to the confirmed config. Returns it.
      pub fn revert(&mut self) -> Result<Arc<Config>, Refusal>;
      /// Whether the window has run out.
      pub fn due(&self, now_boot_ms: u64) -> bool;
      /// The password changed: every config held takes the new hash.
      pub fn set_hash(&mut self, hash: &str);
  }
  ```
  `accept` refuses in this order: `FileRefused` (`ConfigState::Refused`), `ChangePending`, `Window` (`timeout_secs` neither 0 nor in `WINDOW_SECS`), `StaleTag` (`tag != secrets::tag(running)`), `Invalid`. The effects are those from the running config to the proposal; the fact's `lans` are `touched_lans` of the same pair; `reverts_boot_ms` is `now_boot_ms + window * 1000`. An accepted proposal equal to the running config is accepted with no effects.

- [ ] **Step 1: Write the failing tests** in `keeper.rs`:
  - `an_apply_is_pending_until_confirmed`: after `accept` and `commit`, `running()` is the proposal, `confirmed()` the old config, `pending()` has `window_secs == 120` and `reverts_boot_ms == now + 120_000`; after `confirm`, `confirmed()` is the proposal and `pending()` is `None`.
  - `a_revert_brings_back_the_confirmed_config_and_its_tag`.
  - `an_immediate_apply_is_confirmed_at_once` (`pending()` is `None`, `confirmed()` is the proposal).
  - `the_refusals_come_in_order`: one case each, and a case holding two faults that names the earlier.
  - `a_window_of_nine_or_six_hundred_and_one_is_refused_and_ten_and_six_hundred_are_not`; `zero_means_the_default`.
  - `the_window_is_counted_on_the_boot_clock_alone`: `due(now)` is false one millisecond before `reverts_boot_ms` and true at it; the core has no other source of time (the test is the signature: nothing but `now_boot_ms` goes in).
  - `nothing_pending_means_nothing_to_confirm_or_revert`.
  - `a_proposal_takes_the_running_secrets` (an empty PPPoE password and a foreign hash in; the accepted config holds the running ones).
  - `a_new_password_reaches_every_config_held` (`set_hash` while pending: after a revert and after a confirm the hash is the new one).
  - `a_refused_file_refuses_every_apply_and_still_checks` (`check` answers).
  - `the_effects_and_the_touched_lans_are_those_of_the_change`.
- [ ] **Step 2: Run** `cargo test -p openfeo-api keeper` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p openfeo-api keeper` → PASS.
- [ ] **Step 5: Commit.** `git commit -s -m "api: the keeper of the config, as a core with no clock or file of its own"`

---

### Task 14: The keeper at work: files, the World, events, the window

**Files:**
- Modify: `crates/openfeo-api/src/server.rs` (`Shared`, `SharedParts`), `crates/openfeo-api/src/listener.rs` (the window's task, the discard at start), `crates/openfeo-api/src/testing.rs`

**Interfaces:**
- Consumes: `Keeper` (Task 13); `file::{render, write_whole}`, `pending_path` (Task 11); `PendingFact` (Task 4).
- Produces:
  - `SharedParts` gains `pub default_window_secs: u32` (every construction sets it: `keeper::DEFAULT_WINDOW_SECS` in the binary until Task 17). `Shared` holds the keeper behind one async lock, made from the World's config and `config_state` as `Shared::new` finds them; the password change takes the same lock and calls `set_hash`.
  - `impl Shared`:
    `pub async fn config_view(&self) -> GetConfigResponse` (the running config redacted, its tag, the default window);
    `pub async fn check_config(&self, proposed: Config) -> Result<(Config, Vec<Effect>), Vec<ConfigViolation>>`;
    `pub async fn apply_config(&self, request: ApplyConfigRequest) -> Result<ApplyConfigResponse, ApiError>`;
    `pub async fn confirm_config(&self) -> Result<(), ApiError>`;
    `pub async fn revert_config(&self, why: Why) -> Result<(), ApiError>`.
  - The order of an apply: `accept`; write `config.pending.toml` (or, immediate, `config.toml`); `commit`; publish (`world.config` and `world.pending` in one `Publisher::update`); the lines; the event. A write that fails is `INTERNAL`, and nothing was committed or published. Confirm: rename the pending file over `config.toml`, sync the directory, `confirm`, publish `pending = None`, line, event. Revert: `revert`, publish the confirmed config with `pending = None`, delete the pending file, line, event.
  - Codes: `Refusal::Invalid` → `INVALID_ARGUMENT` with text `the config has <n> violations: <path>: <message>; …` (five at most, then `and <k> more`); `Window` → `INVALID_ARGUMENT`; `StaleTag`, `ChangePending`, `NothingPending`, `FileRefused` → `FAILED_PRECONDITION`, each with its own sentence. `change_password` while a change is pending → `FAILED_PRECONDITION`.
  - The first time a config is written over a `config.toml` whose text is not what the router would render for it, that file is first copied to `config.toml.orig` (never overwritten once it exists).
  - `pub async fn keep_window(shared: Arc<Shared>)`: a task of `serve`'s, beside the sweep: it sleeps until the pending change is due (woken when one appears or goes) and then calls `revert_config(Why::TimedOut)`.
  - At `serve`'s start, after the events recorder has subscribed: a `config.pending.toml` found is deleted, the line `config: an unconfirmed change was discarded` printed and `config.discarded` emitted.
  - The lines and events of Global Constraints, the effects one line each after `config: applied…`.

- [ ] **Step 1: Write the failing tests** in `server.rs` and `listener.rs`, on a temporary directory, with `#[tokio::test(start_paused = true)]` where time passes:
  - `an_apply_writes_the_pending_file_and_publishes_the_config`: `config.toml` is untouched, `config.pending.toml` parses to the proposal, the World's config is the proposal and `world.pending` is set.
  - `a_confirm_promotes_the_file`; `a_revert_republishes_the_old_config_and_deletes_the_file`.
  - `the_window_runs_out_with_nobody_listening`: apply with `timeout_secs: 10`, drop every handle but the task's, advance 10 s: the World's config is the old one, the pending file is gone, and an event `config.reverted` with `why` `timeout` was emitted.
  - `a_confirm_just_before_the_window_ends_stands`.
  - `an_immediate_apply_writes_the_config_file_and_no_pending_one`.
  - `an_apply_whose_file_cannot_be_written_changes_nothing` (the directory made read-only: `INTERNAL`, the World and the keeper as before).
  - `a_refused_apply_names_its_violations_and_changes_nothing` (six violations: the text names five and says `and 1 more`).
  - `a_second_apply_and_a_password_change_wait_for_the_first`.
  - `a_hand_written_file_is_kept_beside_the_first_apply_over_it` (a `config.toml` with a comment: after an immediate apply, `config.toml.orig` holds it; after a second apply it is unchanged).
  - `a_pending_file_found_at_start_is_discarded_and_said` (the file gone, `config.discarded` in `shared.backlog(8)`).
  - `the_config_lines_are_the_contract` (each line of Global Constraints, built by its function).
  - `no_line_and_no_error_carries_a_secret` (an apply of a PPPoE config, valid and then invalid: neither the lines' functions nor any `ApiError`'s `Debug` or text contain the password or the hash).
- [ ] **Step 2: Run** `cargo test -p openfeo-api` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p openfeo-api` → PASS.
- [ ] **Step 5: Commit.** `git commit -s -m "api: applying, confirming and reverting a config, and the window that reverts by itself"`

---

### Task 15: Whether a change moves the caller

**Files:**
- Modify: `crates/openfeo-api/src/gate.rs`, `crates/openfeo-api/src/listener.rs` (the accepted stream's own address travels beside `Peer`)

**Interfaces:**
- Produces:
  - `pub struct Local(pub SocketAddr)`, an extension set where `Peer` is, from the accepted stream's `local_addr()`, made canonical as `Peer` is (an IPv4-mapped address is its IPv4 self).
  - `gate::caller_lan(world: &World, peer: IpAddr, local: IpAddr) -> Option<String>`: the LAN whose bridge holds `local` (`world.addresses`), else the LAN whose IPv4 subnet holds `peer`.
  - `gate::caller(running: &Config, proposed: &Config, lan: Option<&str>, local: IpAddr) -> api::Caller`: `lan_changes` when the caller's LAN is absent from `proposed` or its `ipv4` differs; `connection_drops` when the LAN is absent from `proposed`, or `local` is the LAN's IPv4 address in `running` and `proposed` has another, or `local` is the address of the LAN's typed `ipv6` in `running` and `proposed` has another; `lan` the LAN's name; `router_after` the address of the LAN's `ipv4` in `proposed` (empty when the LAN is gone). With no LAN found, everything is false and empty.

- [ ] **Step 1: Write the failing tests** in `gate.rs`:
  - `a_subnet_change_asked_from_that_lan_moves_the_caller`: local `192.168.1.1`, `lan0` to `192.168.2.1/24`: both true, `lan == "lan0"`, `router_after == "192.168.2.1"`.
  - `over_ipv6_by_name_the_lan_changes_and_the_connection_stays`: local the bridge's ULA address, the same change: `lan_changes` true, `connection_drops` false.
  - `asked_from_another_lan_nothing_moves`.
  - `removing_the_callers_lan_drops_the_connection_and_names_no_address`.
  - `a_change_that_leaves_the_lan_alone_moves_nobody` (a reservation added).
  - `the_caller_s_lan_is_found_by_the_address_it_arrived_at_and_then_by_its_own` (a link-local `local` on `br-guest`; a mapped IPv4 peer).
- [ ] **Step 2: Run** `cargo test -p openfeo-api gate` → Expected: FAIL to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test -p openfeo-api gate` → PASS.
- [ ] **Step 5: Commit.** `git commit -s -m "api: whether a change of config moves the one who asks"`

---

### Task 16: The service on the WebSocket and gRPC, and the state

**Files:**
- Modify: `crates/openfeo-api/src/ws.rs` (`act`), `crates/openfeo-api/src/grpc.rs` (`ConfigService`), `crates/openfeo-api/src/listener.rs` (the service added to the router), `crates/openfeo-reconcile/src/state.rs` (`pending_config` from `world.pending`), `fuzz/corpus/api_envelope/` (a seed per new request)

**Interfaces:**
- Consumes: Tasks 12, 14, 15.
- Produces: the five calls answer on both transports from the same `Shared` methods, each needing a session. `ValidateConfig` answers violations alone when there are any, else the effects and the caller. `SystemState.pending_config` is filled from `world.pending` (the two times as they are; the effects mapped kind for kind).

- [ ] **Step 1: Write the failing tests**:
  - `openfeo-reconcile/src/state.rs`: `a_pending_change_is_in_the_state` (the four fields); the existing snapshots gain no `pendingConfig` key.
  - `openfeo-api` (with the crate's `testing` helpers, over a real listener): `a_config_is_read_without_its_secrets_over_the_socket_and_over_grpc` (the same tag on both; no hash, no PPPoE password); `validate_says_the_effects_and_the_caller` (a subnet change from `127.0.0.1` on a World whose `lan0` holds it); `validate_of_a_bad_config_says_only_what_is_wrong`; `an_apply_over_the_socket_is_confirmed_over_grpc`; `the_state_pushed_to_a_subscriber_carries_the_pending_change_and_then_does_not`; `the_config_calls_need_a_session` (gRPC without a token: `UNAUTHENTICATED`; the envelope refuses them before `Auth` as it does every request).
  - `fuzz`: `cargo +nightly fuzz run api_envelope -- -max_total_time=61` → no crash (as part 1a ran it).
- [ ] **Step 2: Run** `cargo test -p openfeo-api` and `cargo test -p openfeo-reconcile state` → Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `make lint && make test` → exit 0; the fuzz run above.
- [ ] **Step 5: Commit.** `git commit -s -m "api: ConfigService on the WebSocket and gRPC, and the pending change in the state"`

---

### Task 17: The harness's knob and client calls

**Files:**
- Create: `crates/openfeo/src/confirm_secs.rs` (as `panel_host.rs`: a real reader under the `harness` feature, `None` without it)
- Modify: `crates/openfeo/src/api.rs` (`Boot` gains the window; `SharedParts.default_window_secs`), `crates/openfeo/src/router.rs`, `harness/src/apiclient.rs`

**Interfaces:**
- Produces:
  - `crate::confirm_secs::KEY = "openfeo.confirm_secs"`, `from_cmdline(&Cmdline) -> Option<u32>`: a number in `10..=600`, anything else ignored with a warning; `None` in a build without the `harness` feature whatever the command line says.
  - `harness::apiclient::Ws`: `pub fn config(&mut self) -> Result<GetConfigResponse>`, `pub fn validate(&mut self, config: &Config) -> Result<ValidateConfigResponse>`, `pub fn apply(&mut self, config: &Config, tag: &str, immediate: bool, timeout_secs: u32) -> Result<Result<String, Error>>` (the new tag, or the router's error), `pub fn confirm(&mut self) -> Result<Result<(), Error>>`, `pub fn revert(&mut self) -> Result<Result<(), Error>>`, each over `Ws::ask`.

- [ ] **Step 1: Write the failing tests**: `confirm_secs.rs`: `a_harness_build_reads_the_window_and_a_release_build_does_not` (as `panel_host.rs` tests its own: `Some(15)` for `openfeo.confirm_secs=15`, `None` for `5`, `601` and `soon`; the `cfg(not(feature = "harness"))` half asserts `None`).
- [ ] **Step 2: Run** `… cargo test -p openfeo confirm_secs` → FAIL to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `make lint && make test && make bin FEATURES=` → exit 0 (the release build carries no knob).
- [ ] **Step 5: Commit.** `git commit -s -m "harness: a shorter window for a harness build, and the config calls in the API client"`

---

### Task 18: Scenarios: commit-confirm

**Files:**
- Modify: `harness/tests/m4.rs` (the scenarios, and their names in `SCENARIOS`)

All boot `vm-dhcp.toml` as the suite's `boot` does, claim the password, and drive the API from the LAN namespace. "The moved config" is `GetConfig`'s with `lans[0].ipv4 = "192.168.2.1/24"`, the pool `192.168.2.100` to `192.168.2.200` and the port forward's `to` `192.168.2.2`. The LAN host is moved with `Lab::host(&lab.lan0, "lan0", "192.168.2.2/24", "192.168.2.1")` and back with `lan_side_host`. An API on the new address is `Api::on(&lab.lan0, "192.168.2.1:443", HOST)`.

- [ ] **Step 1: Write the scenarios.**
  - `a_subnet_change_not_confirmed_is_reverted` (SPEC §12): apply the moved config with `timeout_secs: 15`; the console shows `config: applied; confirm within 15 s` and `config: effect lan0 address moves`; move the LAN host: the router answers at `192.168.2.1`, the state's `pendingConfig` is there, and the lab's forward test (as m1's forward scenario fetches through the WAN address) reaches the LAN host at its new address; within 20 s the console shows `config: reverted (not confirmed in 15 s)`; move the host back: the router answers at `192.168.1.1`, the events hold `config.reverted` with `why` `timeout`; after `reset_and_wait` the console has no `an unconfirmed change was discarded` and the router is at `192.168.1.1`.
  - `a_subnet_change_is_confirmed_from_the_new_address`: the same apply; move the host; a new socket to the new address, by the router's name, with the token from before; `confirm`; the console shows `config: confirmed`; after `reset_and_wait` the router is at `192.168.2.1`.
  - `an_immediate_apply_stands_at_once`: apply a reservation with `immediate`; no `confirm within` line; `reset_and_wait` straight away; `GetConfig` has the reservation and the console no `discarded` line.
  - `a_restart_during_the_window_discards_the_change`: apply the moved config with `timeout_secs: 600`; `reset_and_wait`; the console shows `config: an unconfirmed change was discarded`; the router is at `192.168.1.1`; a backlog of 16 holds `config.discarded`.
  - `what_the_router_refuses_changes_nothing`: a config with a pool outside its subnet → `INVALID_ARGUMENT` naming the path, and `GetConfig`'s tag unchanged; an apply with yesterday's tag (apply a reservation immediately, then apply with the old tag) → `FAILED_PRECONDITION`; with one pending, a second apply and a `ChangePassword` → `FAILED_PRECONDITION`; `revert`; `confirm` with nothing pending → `FAILED_PRECONDITION`; a window of 9 → `INVALID_ARGUMENT`.
  - `a_router_on_defaults_over_a_refused_file_takes_no_apply`: boot as `a_refused_config_keeps_its_password` does; `GetConfig` answers; an apply → `FAILED_PRECONDITION`; after `reset_and_wait` the same config problem is still reported (the file is untouched).
  - `a_validation_says_who_it_moves`: `validate` of the moved config from the LAN: `lan_changes` and `connection_drops`, `router_after` `192.168.2.1`, effects `[lan0 address moves]`; on `vm-ipv6.toml`, reached by name over IPv6 as `the_api_answers_by_name_over_ipv6` does: `lan_changes` and not `connection_drops`.
  - `no_secret_comes_back`: on `vm-pppoe.toml` with the lab's concentrator (as the `m3` suite boots it; skipped with m3's reason where `/dev/ppp` is missing): `GetConfig` has an empty PPPoE password and no hash; apply it back unchanged but for a reservation, immediately: the console shows no `pppoe wan0 stopped` and the session line count is what it was; `password_never_logged` holds, and the PPPoE password is nowhere on the console.
- [ ] **Step 2: Run** `make kernel && OPENFEO_NO_SKIP=1 make test-harness FILTER=m4` → Expected: every `m4` scenario ok, the eight new ones among them. A scenario that fails is debugged with superpowers:systematic-debugging; a fault it finds in an earlier task is fixed there, test first.
- [ ] **Step 3: Commit.** `git commit -s -m "harness: a config applied, confirmed, reverted and refused, from the LAN"`

---

### Task 19: Scenarios: only what changed

**Files:**
- Modify: `harness/tests/m4.rs`; `harness/src/` where a helper of `m3.rs` has to be shared

- [ ] **Step 1: Write the scenarios.**
  - `a_lan_change_leaves_a_dhcp_wan_alone`: note the WAN's `up_since` and the count of `wan wan0 dhcp bound` lines; subscribe to events; apply a reservation immediately; the console shows `config: effect lan0 dhcp restarts` and `lan lan0 dhcp stopped`; 5 s later `up_since` and the count are the same and no event's topic begins `wan.`.
  - `a_lan_change_leaves_a_pppoe_session_alone`: on `vm-pppoe.toml` with the concentrator: the same change; the count of `pppoe wan0 session 0x` lines is the same and `pppd`'s log shows no second session.
  - `a_wan_changes_type_while_running`: `vm-dhcp.toml` with the concentrator also started on ISP A's `wan0`; apply `wan0` as PPPoE with the lab's account, immediately: the console shows `dhcp4 wan0 stopped`, Kea's log a DHCPRELEASE, then `pppoe wan0 ipcp up`; the state's WAN is PPPoE and up, and holds nothing of the lease (no DHCP address among its addresses); apply it back: `pppoe wan0 stopped`, `pppd`'s log shows the session terminated by the peer, `wan wan0 dhcp bound`, and the state holds no session.
  - `a_vlan_tag_moves_the_wan`: the lab's ISP A moved onto `wan0.101` before boot (`isp0_tagged(101)`, Kea started on it); boot `vm-dhcp.toml`: the WAN does not bind; apply `vlan = 101`: `wan wan0 dhcp bound` and the state's WAN is on `p0.101`; apply `vlan = 0`: the state has no `p0.101` and the WAN is not up.
  - `a_lan_is_added_and_removed_while_running`: `add_lan1` before boot; apply a second LAN `lan1` on `p3` at `192.168.2.1/24` with a pool, immediately: a `udhcpc` in the `lan1` namespace is given an address in the pool, and `dig` there resolves the router's name to `192.168.2.1`; apply the config without it: the state has no `lan1` and no `br-lan1`, and the console shows `lan lan1 dhcp stopped`.
  - `leases_survive_a_change_that_is_taken_back`: the LAN host takes a lease with `udhcpc`; apply the moved config with `timeout_secs: 30`; a second `udhcpc` run (a new client identifier) is given an address in `192.168.2.0/24` with a lease time of at most 30; after the revert the first client renews and has the address it had, and the console showed `lan lan0 dhcp restored` with at least one lease when the server came back.
- [ ] **Step 2: Run** `make kernel && OPENFEO_NO_SKIP=1 make test-harness FILTER=m4` → Expected: every `m4` scenario ok.
- [ ] **Step 3: Commit.** `git commit -s -m "harness: a change of config restarts only what it touches"`

---

### Task 20: The documents and the whole gate

**Files:**
- Modify: `CLAUDE.md` (the Harness section: the `m4` suite's config scenarios, the concentrator in `m4`, `openfeo.confirm_secs=`), `docs/progress.md` (the entry for part 2a, and the table's row), `docs/superpowers/specs/2026-11-11-m4-part2-changing-config-design.md` (an "After part 2a" section: what building it changed or settled, the plan's calls among them)

- [ ] **Step 1: Write the documents.** The pull request's number in `docs/progress.md` is the next free one; a commit corrects it if it differs when the PR is opened.
- [ ] **Step 2: Run the whole gate:** `make lint && make test && make bin FEATURES= && make kernel && make check-env && OPENFEO_NO_SKIP=1 make test-harness` → Expected: exit 0 from each; every suite ok, none failed, none skipped.
- [ ] **Step 3: Commit.** `git commit -s -m "docs: M4 part 2a in the progress log, the harness notes and the design"`
