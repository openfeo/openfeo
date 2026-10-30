# OpenFeO M1 part 1 — Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The router child becomes a real control plane: on tokio, it checks the kernel, names the ports, loads a proto-defined config from `/state`, publishes a World, and makes the kernel match it (LAN bridge, static WAN address and default route) through a netlink monitor and tagged appliers, heartbeating only while healthy; the harness delivers `/state` on a disk and proves it in QEMU.

**Architecture:** Seven new library crates follow SPEC §13: `openfeo-platform` (atomic writes, kernel-option check, sysfs port enumeration), `openfeo-config` (prost/pbjson types from `proto/`, TOML load, migrations, validation), `openfeo-world` (pure World, facts, port-map assignment, health types), `openfeo-runtime` (watch-based publisher, health tracker, task supervisor, `tracing` ring + `/dev/kmsg`), `openfeo-netlink` (rtnetlink monitor cache and apply primitives), `openfeo-reconcile` (pure `World -> Desired`, snapshot-tested), `openfeo-apply` (diff desired against the monitor cache, own only what is tagged). The `openfeo` binary wires them in the router child; PID 1 learns to mount `/dev/vda` as `/state` in `vm` mode; the harness gains a state disk built with `mkfs.ext4 -d`, a QMP client for link flaps and resets, and the M1 part 1 scenarios. Netlink and apply code is integration-tested against veth pairs inside the existing rootless sandbox, without QEMU.

**Tech Stack:** Rust 1.99 edition 2024, musl; tokio 1, tracing 0.1, rtnetlink 0.23 / netlink-packet-route 0.33, prost 0.14 + pbjson 0.9 + protox 0.10 (no protoc), toml 1, serde_json 1, ipnet 2, flate2 (Rust backend), mimalloc 0.1, insta 1 (yaml), proptest 1, libfuzzer-sys via cargo-fuzz (nightly); buf CLI for proto lint/breaking; e2fsprogs and QEMU 11 (QMP) on the harness host.

**Spec:** `SPEC.md` — §2 (Interface identity, LAN model, Config, Build, Async runtime, Kernel), §4.2, §5.2, §5.3, §5.6 (first-boot LAN), §6.2, §6.3, §7.1, §7.2 (Static), §8.1, §8.2, §10 (logging), §11, §12 row M1, §13.

## Global Constraints

- Rust stable, edition 2024; the image binary targets `x86_64-unknown-linux-musl`, statically linked, with **mimalloc** as the global allocator (SPEC §2 Build). `musl-gcc` is a build dependency from this plan on.
- `#![forbid(unsafe_code)]` in every crate except `openfeo-init` (`sys.rs` only). No `unwrap`/`expect` outside tests; `thiserror` in libraries, `anyhow` only in `crates/openfeo` and `harness/`. `clippy -D warnings` (pedantic as warnings), `cargo fmt --check`, `cargo deny check` clean.
- `std::process::Command` only in `harness/` and `image/`. Only `openfeo-netlink`, `openfeo-nft`, `openfeo-net`, `openfeo-platform` and `openfeo-init` may call the kernel. `openfeo-proto-*` and `openfeo-reconcile` MUST NOT depend on `tokio`, `libc`, `nix`, `socket2` or anything that opens sockets or reads clocks (SPEC §13); `scripts/check-deps.sh` enforces both rules in `make lint`.
- Every parser gets a fuzz target in the PR that adds it (SPEC §13): the config TOML parser gets one here.
- Every `.rs`, `.sh`, `.proto`, `.c`, `.h` file and every `Makefile` starts with `SPDX-License-Identifier: GPL-2.0-or-later` and `Copyright (C) 2026 Andrew Newton`.
- Commits: `git commit -s` (identity `Andrew Newton <andy@vitri.ltd>`), subject `<area>: <imperative summary>`, trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_0116otzXyvDbuXkw4CsR8ExV`. The repository is public: nothing private in files or messages.
- Config: the protobuf schema in `proto/openfeo/v1/` is the single source of truth; on disk `/state/config.toml` keyed by proto field names (snake_case) parsed through pbjson; `config_version` top-level integer, `migrate(n → n+1)` at load with the original kept as `config.toml.bak.<n>`; validation is structured `(path, code, message)`. Durable writes are temp-file + `fsync` + `rename` + directory `fsync`, mode 0600 (SPEC §5.2).
- First boot without a config: all ports form one LAN `lan0` at `192.168.1.1/24`, nothing is forwarded (SPEC §5.6). Hostname `openfeo`, domain `home.arpa`.
- Identity: ports named by bus path, renamed `p0…pN` in path order while down; names are sticky per identity in `/state/identity/portmap`; a new or missing port is reported, roles are never guessed (SPEC §7.1).
- LAN = bridge `br-<lan>`, `vlan_filtering` on, default PVID 1, STP off, bridge MAC = lowest member MAC (SPEC §7.1). Logical names (`wan0`, `lan0`) never reach the kernel.
- Ownership: routes carry `RTPROT_OPENFEO = 200`; appliers never delete kernel-originated state (link-local addresses, connected routes, anything on interfaces we do not manage); an apply failure never kills a task: capped exponential backoff, `degraded` health, retry on the next World (SPEC §6.2).
- Health (SPEC §5.3): the child heartbeats every 5 s only while supervised tasks are alive and no applier has been in flight for more than 30 s. Supervised tasks restart with backoff 1 s doubling to 30 s; 3 restarts within 10 minutes marks the task dead.
- Logging (SPEC §10): `tracing` into an 8 MiB in-memory ring and `/dev/kmsg` as `<pri>openfeo: message key=value`; INFO and above reach kmsg, DEBUG and above the ring. Existing M0 console lines keep their exact text.
- Kernel-option check (SPEC §4.2): `kernel/required.config` is compiled into the binary and compared with `/proc/config.gz`; a missing option refuses router services and logs exactly which.
- Kernel 6.18.59 and the M0 kernel fragments are unchanged. VM command line unchanged.

## Review Focus

1. A config whose WAN or LAN names a port not in the live port map (`ports = ["p7"]`): the whole file is rejected with `unknown_port` at `lans[0].ports[0]`, the console says so, and the box comes up on first-boot defaults instead of half-applied. Test in Task 4 (`unknown_port_is_a_violation`), console contract in Task 14.
2. A typo in a TOML key (`ipv4_addr = …`): rejected naming the unknown key, never silently ignored. Test in Task 4 (`unknown_key_is_rejected_with_its_name`).
3. Two subnets that overlap (a LAN inside the static WAN's subnet, or two LANs): `overlap` on the second one. Test in Task 4 (`overlapping_subnets_are_a_violation`).
4. `/proc/config.gz` unreadable (container mode, or a kernel without `IKCONFIG_PROC`): a warning in container mode, a refusal elsewhere, never a panic. Test in Task 14 (`kernel_decision_*`).
5. The router child restarts on a kernel that already carries `br-lan0`, enslaved ports, addresses and routes from the previous child: everything is adopted, nothing is torn down, both appliers report zero operations. Test in Task 11 (`reapply_is_a_noop`) and scenario `child_restart_converges_without_changes` in Task 15.

---

## File structure

```
openfeo/
  Cargo.toml                       + members, workspace deps, exclude = ["fuzz"]
  Makefile                         lint += check-deps, check-proto; test-harness runs netlink + m0 + m1; run --config; fuzz
  scripts/check-deps.sh            SPEC §13 dependency rules over `cargo tree`
  scripts/check-proto.sh           buf lint + buf breaking against origin/main
  proto/buf.yaml  proto/openfeo/v1/config.proto
  fuzz/Cargo.toml  fuzz/fuzz_targets/config_toml.rs
  crates/openfeo-platform/src/     lib.rs atomic.rs kconfig.rs ports.rs
  crates/openfeo-config/           build.rs (protox → prost-build → pbjson-build)
    src/                           lib.rs gen.rs file.rs migrate.rs validate.rs load.rs
  crates/openfeo-world/src/        lib.rs world.rs mac.rs portmap.rs rename.rs health.rs
  crates/openfeo-runtime/src/      lib.rs world.rs health.rs supervise.rs log.rs
  crates/openfeo-netlink/src/      lib.rs types.rs monitor.rs apply.rs
  crates/openfeo-reconcile/src/    lib.rs links.rs routing.rs  (+ snapshots/)
  crates/openfeo-apply/src/        lib.rs links.rs routing.rs
  crates/openfeo/src/              main.rs cli.rs version.rs chaos.rs router.rs boot.rs heartbeat.rs  (ports.rs moves to platform)
  crates/openfeo-init/src/mounts.rs  STATE_VM
  harness/src/                     + statedisk.rs qmp.rs; qemu.rs lab.rs main.rs changed
  harness/fixtures/vm-static.toml
  harness/tests/netlink.rs  harness/tests/m1.rs
  docs/adr/0009-runtime-crate-keeps-reconcile-pure.md
  docs/adr/0010-harness-state-disk.md
  .github/workflows/ci.yml  .github/workflows/fuzz.yml
```

---

### Task 1: Workspace plumbing, dependency-rule script, version marker

**Files:**
- Modify: `Cargo.toml`, `Makefile`, `.github/workflows/ci.yml`, `CLAUDE.md`, `README.md`, `crates/openfeo/src/version.rs`
- Create: `scripts/check-deps.sh`
- Already present: `docs/superpowers/plans/2026-10-30-m1a-foundations.md` (commit it here). All work happens on branch `m1a` from `main`; `main` is protected, so the branch lands through a pull request at the end.

**Interfaces:**
- Produces: workspace dependency entries every later task uses by `name.workspace = true`; `scripts/check-deps.sh` (exit 1 naming the offending crate and dependency); `version()` ending in `.harness` under the `harness` feature.

- [ ] **Step 1: Failing test for the version marker**

In `version.rs` tests:

```rust
#[test]
fn harness_builds_are_marked() {
    let v = version();
    assert_eq!(v.ends_with(".harness"), cfg!(feature = "harness"), "{v}");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p openfeo --features harness version`
Expected: FAIL (`0.1.0+<id>` has no marker).

- [ ] **Step 3: Implement**

`version()` returns `{pkg}+{build_id}` and appends `.harness` when `cfg!(feature = "harness")`.

- [ ] **Step 4: Run both ways**

Run: `cargo test -p openfeo --features harness version && cargo test -p openfeo version`
Expected: PASS twice.

- [ ] **Step 5: Workspace dependencies**

Add to `[workspace.dependencies]`: `tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time", "io-util", "net"] }`, `tracing = "0.1"`, `tracing-subscriber = { version = "0.3", default-features = false, features = ["registry", "std"] }`, `futures = "0.3"`, `rtnetlink = "0.23"`, `netlink-packet-route = "0.33"`, `netlink-packet-core = "0.9"`, `netlink-sys = { version = "0.9", features = ["tokio"] }`, `prost = "0.14"`, `prost-types = "0.14"`, `prost-build = "0.14"`, `protox = "0.10"`, `pbjson = "0.9"`, `pbjson-types = "0.9"`, `pbjson-build = "0.9"`, `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`, `toml = "1"`, `ipnet = { version = "2", features = ["serde"] }`, `flate2 = { version = "1", default-features = false, features = ["rust_backend"] }`, `mimalloc = "0.1"`, `insta = { version = "1", features = ["yaml"] }`, `proptest = "1"`. Add `exclude = ["fuzz"]` to `[workspace]`. If `cargo update` reports prost/pbjson/protox disagreeing on `prost` versions, pin the newest mutually compatible releases and note them in the ledger.

- [ ] **Step 6: `scripts/check-deps.sh`**

`#!/usr/bin/env bash`, `set -euo pipefail`, SPDX header. Two rules, both over `cargo tree -e normal --prefix none -f '{p}'`:
- PURE crates (`openfeo-reconcile`, `openfeo-world`, every `openfeo-proto-*` present in `crates/`): the full tree must contain none of `tokio libc nix socket2 rtnetlink netlink-sys netlink-proto`.
- KERNEL crates allowed `libc nix rtnetlink netlink-sys netlink-proto netlink-packet-route netlink-packet-core` as direct deps (`--depth 1`): only `openfeo-netlink openfeo-nft openfeo-net openfeo-platform openfeo-init`; every other workspace member must not list them directly. `openfeo-harness` is exempt (SPEC §13: harness tooling may use anything).
Print `dependency rule violated: <crate> -> <dep>` per offence, exit 1. Skip crates that do not exist yet.

- [ ] **Step 7: Verify the script passes and fails**

Run: `scripts/check-deps.sh && echo PASS` → `PASS`.
Run: add `tokio.workspace = true` under `[dependencies]` of a temporary `crates/openfeo-reconcile/Cargo.toml` stub (package `openfeo-reconcile`, empty `src/lib.rs` with header) and run again → `dependency rule violated: openfeo-reconcile -> tokio`, exit 1. Remove the stub.

- [ ] **Step 8: Makefile, CI, docs**

`lint:` adds `scripts/check-deps.sh` after `scripts/check-spdx.sh`. `ci.yml` `lint-and-unit`: `sudo apt-get install -y musl-tools e2fsprogs` before the Rust steps; `kernel-and-harness` apt line adds `musl-tools e2fsprogs iputils-ping`. `CLAUDE.md` Commands section unchanged; Rules gain one line: `openfeo-world`, `openfeo-reconcile` and `openfeo-proto-*` are pure (no tokio/libc/nix/socket2); `scripts/check-deps.sh` enforces §13. README prerequisites add `musl-gcc` (package `musl` on Arch, `musl-tools` on Debian/Ubuntu), `buf`, `mkfs.ext4`.

- [ ] **Step 9: Lint and commit**

Run: `make lint` → exit 0.
Commit: `build: workspace deps for M1, dependency-rule check, harness version marker`.

---

### Task 2: `openfeo-platform`: atomic writes, kernel-option check, port enumeration

**Files:**
- Create: `crates/openfeo-platform/Cargo.toml` (deps: `thiserror`, `flate2`; no `libc`: `openfeo-config` and therefore `openfeo-world` sit on top of this crate and must stay libc-free), `src/lib.rs`, `src/atomic.rs`, `src/kconfig.rs`
- Move: `crates/openfeo/src/ports.rs` → `crates/openfeo-platform/src/ports.rs` (tests included; `tempfile` dev-dep)
- Modify: `crates/openfeo/src/main.rs`, `router.rs` (use `openfeo_platform::ports`)

**Interfaces:**
- Produces: `openfeo_platform::atomic::write(path: &Path, data: &[u8], mode: u32) -> io::Result<()>`; `openfeo_platform::kconfig::{REQUIRED_FRAGMENT: &str, Requirement { symbol: String, want: Want }, Want::{Yes, Value(String), Unset}, parse_fragment(fragment: &str) -> Vec<Requirement>, check(running: &str, fragment: &str) -> Result<usize, Missing>, Missing(Vec<String>) (Display: space-separated `SYMBOL(want=…,have=…)`), read_running() -> io::Result<String>}`; `openfeo_platform::ports::{Port, Skipped, Inventory, identity, enumerate}` unchanged from M0.

- [ ] **Step 1: Failing tests for `atomic::write`**

`writes_new_file_with_mode_0600`, `replaces_existing_file_atomically` (content swapped, no `.tmp` sibling left), `parent_missing_is_an_error`.

- [ ] **Step 2: Run** → FAIL (module missing).

- [ ] **Step 3: Implement `atomic::write`**

Temp name `.<file>.tmp.<pid>` in the same directory, `OpenOptions` create_new with `mode`, `write_all`, `sync_all`, `rename`, then open the directory and `sync_all` it.

- [ ] **Step 4: Run** → PASS.

- [ ] **Step 5: Failing tests for `kconfig`**

`parses_yes_value_and_not_set` (fragment lines `CONFIG_A=y`, `CONFIG_PANIC_TIMEOUT=10`, `# CONFIG_MODULES is not set`, comments and blanks ignored); `check_passes_and_counts` (returns `Ok(3)`); `check_reports_missing_and_mismatched` (`CONFIG_A` absent, `CONFIG_PANIC_TIMEOUT=5`, `CONFIG_MODULES=y` → `Missing` lists exactly those three, in fragment order, Display `CONFIG_A(want=y,have=unset) CONFIG_PANIC_TIMEOUT(want=10,have=5) CONFIG_MODULES(want=unset,have=y)`); `required_fragment_is_the_checked_in_file` (`REQUIRED_FRAGMENT` contains `CONFIG_BRIDGE_VLAN_FILTERING=y` and `# CONFIG_MODULES is not set`).

- [ ] **Step 6: Run** → FAIL.

- [ ] **Step 7: Implement `kconfig`**

`REQUIRED_FRAGMENT = include_str!("../../../kernel/required.config")`. `check` indexes the running config into `BTreeMap<symbol, value>` (`# X is not set` ⇒ absent). `read_running` gunzips `/proc/config.gz` with `flate2::read::GzDecoder`.

- [ ] **Step 8: Run** → PASS.

- [ ] **Step 9: Move `ports.rs`**

`git mv`, fix paths, `openfeo` depends on `openfeo-platform`; M0 tests run unchanged.

- [ ] **Step 10: Verify and commit**

Run: `cargo test -p openfeo-platform && cargo test -p openfeo && scripts/check-deps.sh` → PASS.
Commit: `platform: atomic writes, kernel-option check, sysfs port enumeration`.

---

### Task 3: Proto schema and `openfeo-config` generated types

**Files:**
- Create: `proto/buf.yaml`, `proto/openfeo/v1/config.proto`, `scripts/check-proto.sh`, `crates/openfeo-config/Cargo.toml`, `build.rs`, `src/lib.rs`, `src/gen.rs`
- Modify: `Makefile` (`lint` += `scripts/check-proto.sh`), `.github/workflows/ci.yml` (install buf: `uses: bufbuild/buf-action@v1` with `setup_only: true`, `fetch-depth: 0` on checkout), `SPEC.md` §8.2

**Interfaces:**
- Produces: `openfeo_config::{Config, System, PortMapEntry, PortMap, Wan, wan::Kind, StaticWan, DhcpWan, Lan}` (prost types with pbjson `Serialize`/`Deserialize` using proto field names).

- [ ] **Step 1: `config.proto`**

```proto
syntax = "proto3";
package openfeo.v1;

// The whole router configuration (SPEC §8). On disk as TOML keyed by these field names.
message Config {
  uint32 config_version = 1;
  System system = 2;
  repeated PortMapEntry ports = 3;
  repeated Wan wans = 4;
  repeated Lan lans = 5;
}
message System {
  string hostname = 1;
  string domain = 2;
  string timezone = 3;
  repeated string ntp_servers = 4;
}
// identity -> kernel name; also the file format of /state/identity/portmap.
message PortMapEntry {
  string id = 1;    // "pci-0000:02:00.0"
  string name = 2;  // "p0"
}
message PortMap {
  repeated PortMapEntry ports = 1;
}
message Wan {
  string name = 1;
  string port = 2;
  uint32 vlan = 3;      // 0 = untagged
  uint32 priority = 4;  // lower wins
  oneof kind {
    StaticWan static = 5;
    DhcpWan dhcp = 6;
  }
}
message StaticWan {
  string address = 1;       // "203.0.113.10/24"
  string gateway = 2;       // "203.0.113.1"
  repeated string dns = 3;
}
message DhcpWan {}          // options arrive with the DHCPv4 client (M1 part 2)
message Lan {
  string name = 1;
  repeated string ports = 2;
  string ipv4 = 3;          // "192.168.1.1/24"
}
```

`buf.yaml` v2: module `.`, lint `STANDARD`, breaking `FILE`. Headers as `//` comments.

- [ ] **Step 2: `build.rs`**

`protox::compile(["openfeo/v1/config.proto"], ["../../proto"])` → `FileDescriptorSet`; write its bytes to `$OUT_DIR/descriptors.bin`; `prost_build::Config::new().file_descriptor_set_path(..).compile_fds(fds)`; `pbjson_build::Builder::new().register_descriptors(&bytes)?.preserve_proto_field_names().build(&[".openfeo.v1"])`. `gen.rs` includes `openfeo.v1.rs` and `openfeo.v1.serde.rs`; `lib.rs` re-exports the types. `cargo:rerun-if-changed=../../proto`.

- [ ] **Step 3: Failing test**

```rust
#[test]
fn json_uses_proto_field_names_and_round_trips() {
    let cfg = Config { config_version: 1, lans: vec![Lan { name: "lan0".into(), ports: vec!["p2".into()], ipv4: "192.168.1.1/24".into() }], ..Default::default() };
    let json = serde_json::to_value(&cfg).unwrap();
    assert_eq!(json["config_version"], 1);
    assert_eq!(json["lans"][0]["ipv4"], "192.168.1.1/24");
    assert_eq!(serde_json::from_value::<Config>(json).unwrap(), cfg);
}
```

- [ ] **Step 4: Run** → FAIL (crate does not build / types missing); fix until PASS. `cargo test -p openfeo-config`.

- [ ] **Step 5: `scripts/check-proto.sh`**

`buf lint proto`; then, if `git cat-file -e origin/main:proto/buf.yaml 2>/dev/null`, `buf breaking proto --against '.git#branch=origin/main,subdir=proto'`; else print `buf breaking: no baseline on origin/main yet; skipped`. Add to `make lint`.

- [ ] **Step 6: SPEC §8.2**

In the example, replace `kind = "pppoe"             # dhcp | static | pppoe` with a comment line `# exactly one of [wans.static], [wans.dhcp], [wans.pppoe] selects the WAN type` and keep `[wans.pppoe]`. Add `[wans.static]` with `address`, `gateway`, `dns` as a second commented example. Note under the file: “The TOML is the pbjson JSON mapping of `Config`; enum-like choices are `oneof` tables.”

- [ ] **Step 7: Verify and commit**

Run: `make lint && cargo test -p openfeo-config` → PASS; `buf lint proto` → no output.
Commit: `config: proto schema, prost/pbjson types, buf checks`.

---

### Task 4: `openfeo-config`: TOML file format, migrations, validation, loading, fuzz target

**Files:**
- Create: `src/file.rs`, `src/migrate.rs`, `src/validate.rs`, `src/load.rs`, `fuzz/Cargo.toml`, `fuzz/fuzz_targets/config_toml.rs`
- Modify: `Cargo.toml` (deps `toml`, `serde_json`, `ipnet`, `thiserror`, `openfeo-platform`), `Makefile` (`fuzz` target), `.github/workflows/fuzz.yml`

**Interfaces:**
- Produces: `openfeo_config::file::{parse(text: &str) -> Result<Config, ConfigError>, render(config: &Config) -> Result<String, ConfigError>, parse_portmap(text: &str) -> Result<PortMap, ConfigError>, render_portmap(map: &PortMap) -> Result<String, ConfigError>}`; `openfeo_config::migrate::{CURRENT_VERSION: u32 = 1, run(doc: toml::Table) -> Result<(toml::Table, Vec<u32>), ConfigError>, run_with(doc, migrations: &[Migration]) -> …, type Migration = fn(&mut toml::Table)}`; `openfeo_config::validate::{validate(config: &Config, ports: &PortMap) -> Vec<Violation>, Violation { path: String, code: Code, message: String }, Code::{InvalidCidr, InvalidAddress, DuplicateName, UnknownPort, PortUsedTwice, Overlap, GatewayOutsideSubnet, MissingKind, EmptyPorts, PortMapMismatch}}` (`Code` Display is the snake_case name, e.g. `unknown_port`); `openfeo_config::load::{load(path: &Path, ports: &PortMap) -> Result<Loaded, ConfigError>, Loaded { config: Config, source: Source, migrated_from: Option<u32> }, Source::{File, FirstBootDefaults}}`; `Config::first_boot(ports: &PortMap) -> Config`; `PortMap::{name_of(&self, id: &str) -> Option<&str>, id_of(&self, name: &str) -> Option<&str>, names(&self) -> impl Iterator<Item = &str>}`; `ConfigError::{Io { path: PathBuf, source: io::Error }, Toml(String), Shape(String), MissingVersion, TooNew { found: u32, supported: u32 }, Invalid(Vec<Violation>)}`.

- [ ] **Step 1: Failing tests for `file`**

`parses_the_spec_shaped_file` (the §8.2-style TOML with `[[wans]]` + `[wans.static]` and `[[lans]]` → `Config` with `wan.kind == Some(Kind::Static(..))`, `priority == 10`), `render_then_parse_round_trips`, `unknown_key_is_rejected_with_its_name` (`ipv4_addr = "…"` under `[[lans]]` → `Err(ConfigError::Shape(msg))` with `msg.contains("ipv4_addr")`), `portmap_file_round_trips`.

- [ ] **Step 2: Run** → FAIL.

- [ ] **Step 3: Implement `file`**

TOML → `toml::Table` → `serde_json::Value` (via `serde_json::to_value`) → `Config` (pbjson Deserialize); render is the reverse. `parse` does not look at `config_version` (that is `load`'s job).

- [ ] **Step 4: Run** → PASS.

- [ ] **Step 5: Failing tests for `migrate`**

`current_version_passes_through` (returns the doc unchanged, `vec![]`), `current_version_matches_migration_count` (`CURRENT_VERSION == MIGRATIONS.len() + 1`), `missing_version_is_an_error`, `newer_than_supported_is_too_new` (`config_version = 2` → `TooNew { found: 2, supported: 1 }`), `run_with_applies_each_step_and_bumps` (doc at version 1, one test migration that inserts `migrated = true`, `CURRENT` taken as 2 inside `run_with` by `migrations.len() + 1` → result has `migrated` and `config_version = 2`, steps `[1]`).

- [ ] **Step 6: Run** → FAIL; implement (`MIGRATIONS: &[Migration] = &[]`; `run` = `run_with(doc, MIGRATIONS)`); **Step 7: Run** → PASS.

- [ ] **Step 8: Failing tests for `validate`** (one per code, each asserting `path` and `code`)

`unknown_port_is_a_violation` (`lans[0].ports[0]`), `port_used_twice` (same port in a WAN and a LAN; WANs are checked before LANs, each list in index order, and the second occurrence is flagged: `lans[0].ports[0]`), `duplicate_names` (`lans[1].name`), `invalid_cidr_and_address` (`lans[0].ipv4`, `wans[0].static.address`, `wans[0].static.gateway`, `wans[0].static.dns[1]`), `overlapping_subnets_are_a_violation` (LAN `192.168.1.1/24` and static WAN `192.168.1.10/16` → `wans[0].static.address` flagged `overlap`; two LANs same subnet → second LAN), `gateway_outside_subnet` (`wans[0].static.gateway`), `missing_kind` (`wans[0].kind`), `empty_lan_ports` (`lans[0].ports`), `portmap_mismatch` (config `ports` says `pci-…:03.0 → p1` but live map has `p0` → `ports[0]`), `valid_config_has_no_violations`.

- [ ] **Step 9: Run** → FAIL; implement with `ipnet::{Ipv4Net}` and `Ipv4Addr` parsing, `IpNet::contains`/overlap by `addr().is_… || other.contains(net.addr())` on the network addresses; **Step 10: Run** → PASS.

- [ ] **Step 11: Failing tests for `load` and `first_boot`**

`first_boot_has_one_lan_with_every_port` (3 ports → `lans == [lan0: ports p0,p1,p2, ipv4 192.168.1.1/24]`, hostname `openfeo`, domain `home.arpa`, `config_version == CURRENT_VERSION`, `wans` empty), `absent_file_gives_first_boot_defaults` (`Source::FirstBootDefaults`), `valid_file_loads` (`Source::File`, `migrated_from == None`), `invalid_file_is_invalid` (`Err(Invalid(v))` with `v.len() == 1`), `migrated_file_is_backed_up_and_rewritten` (use `load_with(path, ports, migrations)` with a test migration from version 1 → 2: afterwards `config.toml.bak.1` holds the original text, `config.toml` parses at version 2, `migrated_from == Some(1)`, both mode 0600).

- [ ] **Step 12: Run** → FAIL; implement `load` = read (ENOENT → defaults) → `toml::Table` → migrate → if migrated: `atomic::write` backup then rewritten file → `file::parse` → `validate`; **Step 13: Run** → PASS.

- [ ] **Step 14: Fuzz target**

`fuzz/Cargo.toml` (package `openfeo-config-fuzz`, `publish = false`, deps `libfuzzer-sys = "0.4"`, `openfeo-config = { path = "../crates/openfeo-config" }`, `[[bin]] name = "config_toml" path = "fuzz_targets/config_toml.rs" test = false doc = false bench = false`, `[workspace]` empty table so it is its own workspace). Target: `fuzz_target!(|data: &[u8]| { if let Ok(s) = std::str::from_utf8(data) { let _ = openfeo_config::file::parse(s); } });` with SPDX header. `Makefile`: `fuzz: ; cd fuzz && cargo +nightly fuzz run $(FUZZ_TARGET) -- -max_total_time=$(FUZZ_SECS)` with `FUZZ_TARGET ?= config_toml`, `FUZZ_SECS ?= 60`. `fuzz.yml`: `on: schedule: cron '17 3 * * *'` and `workflow_dispatch`; ubuntu-24.04; nightly toolchain; `taiki-e/install-action@cargo-fuzz`; runs every target for 300 s.

- [ ] **Step 15: Fuzz builds and runs briefly**

Run: `rustup toolchain list | grep -q nightly || echo "NEED nightly"`; then `make fuzz FUZZ_SECS=20`
Expected: the target builds and runs 20 s with no crash. If nightly is missing, record it in the ledger and ask for `rustup toolchain install nightly` at the end; the target still must compile with `cargo +nightly` once installed.

- [ ] **Step 16: Verify and commit**

Run: `cargo test -p openfeo-config && make lint` → PASS (`check-spdx` covers `fuzz/fuzz_targets/*.rs`).
Commit: `config: TOML load, migrations, validation, first-boot defaults, fuzz target`.

---

### Task 5: `openfeo-world`: World, facts, port-map assignment, rename plan, health types

**Files:**
- Create: `crates/openfeo-world/Cargo.toml` (deps `openfeo-config`, `ipnet`, `thiserror`; no tokio), `src/lib.rs`, `src/world.rs`, `src/mac.rs`, `src/portmap.rs`, `src/rename.rs`, `src/health.rs`

**Interfaces:**
- Produces: `openfeo_world::{World { generation: u64, config: Arc<Config>, ports: Arc<PortMap>, links: Arc<BTreeMap<String, LinkFact>> }, LinkFact { index: u32, name: String, up: bool, carrier: bool, mac: Option<MacAddr>, mtu: u32 }, MacAddr([u8; 6]) (Display `aa:bb:…`, FromStr, Ord)}`; `openfeo_world::portmap::{PresentPort { id: String, ifname: String, mac: MacAddr }, Assignment { map: PortMap, added: Vec<PortMapEntry>, missing: Vec<PortMapEntry>, names: BTreeMap<String /*ifname*/, String /*pN*/> }, assign(known: &PortMap, present: &[PresentPort]) -> Assignment}`; `openfeo_world::rename::{Rename { index: u32, to: String }, plan(current: &[(u32, String)], wanted: &BTreeMap<String, String>) -> Vec<Rename>}`; `openfeo_world::health::{Subsystem::{Netlink, Links, Routing, Config, Supervisor}, Status::{Ok, Degraded(String)}, HealthReport { subsystems: BTreeMap<Subsystem, Status>, dead_tasks: Vec<String>, wedged: Vec<Subsystem> } with fn is_healthy(&self) -> bool}` (healthy ⇔ `dead_tasks` and `wedged` empty; `Degraded` alone is still healthy).

- [ ] **Step 1: Failing tests**

`mac_parses_formats_and_orders`; `first_boot_assigns_in_path_order` (present ids `pci-0000:00:06.0, pci-0000:00:04.0, pci-0000:00:05.0` → `p0` is `:04.0`, `p1` `:05.0`, `p2` `:06.0`; all `added`); `known_ports_keep_their_names_new_ones_take_the_lowest_free` (known `:04.0 → p0`, `:06.0 → p2`; present adds `:05.0` → it becomes `p1`; nothing missing); `missing_ports_are_reported_and_kept` (known 3, present 2 → `missing` has one entry, `map` still has 3); `rename_plan_is_empty_when_names_match`; `rename_plan_swaps_through_temporary_names` (current `eth0`→wants `p1`, `eth1`→wants `p0`? no conflict: direct; current `p0`→`p1` and `p1`→`p0` → first both to `rn<index>`, then to targets: 4 renames, temporaries first); `health_is_unhealthy_only_for_dead_or_wedged`.

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** Temporary names are `rn{index}` (≤ 15 chars). **Step 4: Run** → PASS; `scripts/check-deps.sh` → PASS.

- [ ] **Step 5: Commit** `world: World and facts, sticky port-map assignment, rename plan, health report`.

---

### Task 6: `openfeo-runtime`: publisher, health tracker, task supervisor; ADR-0009

**Files:**
- Create: `crates/openfeo-runtime/Cargo.toml` (deps `openfeo-world`, `tokio`, `tracing`, `thiserror`; supervised tasks return `Result<(), TaskError>`), `src/lib.rs`, `src/world.rs`, `src/health.rs`, `src/supervise.rs`, `docs/adr/0009-runtime-crate-keeps-reconcile-pure.md`
- Modify: `SPEC.md` §13 (crate list: `openfeo-world` = pure World/facts/health types; new `openfeo-runtime` = publisher, health tracker, supervisor runtime, log ring)

**Interfaces:**
- Produces: `openfeo_runtime::world::{Publisher, WorldRx = tokio::sync::watch::Receiver<Arc<World>>}` with `Publisher::new(initial: World) -> (Publisher, WorldRx)`, `fn update(&self, f: impl FnOnce(&mut World))` (clones the current World, applies `f`, sets `generation += 1`, sends), `fn current(&self) -> Arc<World>`; `openfeo_runtime::health::{HealthTracker (Clone, Arc inside), WEDGE_AFTER: Duration = 30 s}` with `new()`, `set(&self, Subsystem, Status)`, `begin(&self, Subsystem) -> InFlight` (guard; drop ends), `task_dead(&self, name: &str)`, `report(&self, now: Instant) -> HealthReport`, `is_healthy(&self, now: Instant) -> bool`; `openfeo_runtime::supervise::{Supervisor, TaskError = Box<dyn std::error::Error + Send + Sync>, MAX_RESTARTS: usize = 3, WINDOW: Duration = 600 s, MAX_BACKOFF: Duration = 30 s}` with `Supervisor::new(health: HealthTracker) -> Self`, `fn spawn<F, Fut>(&self, name: &'static str, factory: F) -> tokio::task::JoinHandle<()> where F: Fn() -> Fut + Send + 'static, Fut: Future<Output = Result<(), TaskError>> + Send + 'static` (restarts on `Err`, on panic (`JoinError`), and on a task that returns `Ok` while it should run forever is treated as finished, not restarted; logs `task <name> failed: <err>; restart in <d>` and `task <name> dead after 3 restarts in 10 min`).

- [ ] **Step 1: Failing tests** (all `#[tokio::test(start_paused = true)]`)

`update_bumps_generation_and_notifies`; `in_flight_apply_over_30s_is_wedged` (begin, advance 31 s → `report().wedged == [Links]`, drop guard → healthy); `degraded_is_still_healthy`; `supervisor_restarts_with_doubling_backoff` (factory fails twice then runs forever: observe restarts at +1 s and +3 s via a shared counter; `report().dead_tasks` empty); `supervisor_gives_up_after_three_restarts` (always fails → after the 4th failure `dead_tasks == ["t"]` and `is_healthy == false`).

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.

- [ ] **Step 5: ADR-0009**

Context: §13 puts the supervisor runtime in `openfeo-world`, and forbids `openfeo-reconcile` from depending on tokio while reconcilers take `&World`. Decision: `openfeo-world` is tokio-free (types only); runtime pieces live in `openfeo-runtime`. Consequences: one extra crate; `check-deps.sh` keeps `openfeo-world` pure. Update §13 accordingly.

- [ ] **Step 6: Commit** `runtime: world publisher, health tracker with wedge detection, task supervisor (ADR-0009)`.

---

### Task 7: `openfeo-runtime::log`: tracing ring and `/dev/kmsg` layer

**Files:**
- Create: `crates/openfeo-runtime/src/log.rs`; deps `tracing-subscriber`

**Interfaces:**
- Produces: `openfeo_runtime::log::{Ring::new(capacity_bytes: usize), Ring::push(&self, line: String), Ring::tail(&self, n: usize) -> Vec<String>, Ring::bytes(&self) -> usize, DEFAULT_RING_BYTES: usize = 8 MiB, format_line(level: Level, prefix: &str, message: &str, fields: &[(&str, String)]) -> String (`<pri>prefix: message k=v k2=v2`; pri ERROR 3, WARN 4, INFO 6, DEBUG/TRACE 7), init(prefix: &'static str, ring: Arc<Ring>, kmsg: Option<Box<dyn Write + Send>>)}` (installs a global subscriber: a Layer that formats each event once, pushes DEBUG+ to the ring, writes INFO+ to `kmsg` or, when `None`, to stderr; the `message` field first, remaining fields in declaration order).

- [ ] **Step 1: Failing tests**

`format_line_matches_kmsg_style` (`format_line(Level::INFO, "openfeo", "renamed", &[("port", "p0".into())]) == "<6>openfeo: renamed port=p0"`); `ring_evicts_oldest_when_full` (capacity 40 bytes, push 5 × 10-byte lines → `tail(10).len() == 4`, first is the second pushed); `layer_routes_info_to_kmsg_and_debug_to_ring_only` (install a subscriber with `tracing::subscriber::with_default` using a `Vec<u8>` sink behind `Arc<Mutex>>`: `info!(port = "p0", "renamed")` appears in the sink and the ring; `debug!("x")` only in the ring).

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (`tracing_subscriber::registry().with(layer)`; the layer visits fields with a `Visit` impl collecting `message` and others as `Display`/`Debug` strings; lines ≤ 1000 bytes to kmsg, truncated with `…`). **Step 4: Run** → PASS.

- [ ] **Step 5: Commit** `runtime: tracing ring and kmsg layer`.

---

### Task 8: `openfeo-netlink`: connection and monitor cache, sandboxed integration test

**Files:**
- Create: `crates/openfeo-netlink/Cargo.toml` (deps `rtnetlink`, `netlink-packet-route`, `netlink-packet-core`, `netlink-sys`, `tokio`, `futures`, `tracing`, `thiserror`, `ipnet`), `src/lib.rs`, `src/types.rs`, `src/monitor.rs`, `harness/tests/netlink.rs` (`harness = false`, in `harness/Cargo.toml` `[[test]]`), harness dev-deps `tokio`, `openfeo-netlink`
- Modify: `Makefile` (`test-harness` runs `--test netlink --test m0`)

**Interfaces:**
- Produces: `openfeo_netlink::{Netlink (Clone), Monitor, Cache, Link, LinkKind::{Bridge, Veth, Other(String)}, Addr, Route, Error, RTPROT_OPENFEO: u8 = 200, TABLE_MAIN: u32 = 254}`; `Netlink::connect() -> Result<(Netlink, Monitor), Error>` (memberships `RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE` added before the connection task is spawned; initial dumps of links, addresses, routes fill the cache before `connect` returns); `Monitor::subscribe(&self) -> watch::Receiver<Arc<Cache>>`; `Monitor::run(self) -> impl Future<Output = Result<(), Error>>` (applies notifications until the socket closes); `Cache { links: BTreeMap<u32, Link>, addrs: BTreeSet<Addr>, routes: BTreeSet<Route> }`, `Cache::link_by_name(&self, name: &str) -> Option<&Link>`; `Link { index: u32, name: String, kind: Option<LinkKind>, master: Option<u32>, up: bool, carrier: bool, mac: Option<[u8; 6]>, mtu: u32 }`; `Addr { ifindex: u32, net: IpNet, scope: u8 }` (`scope` is `RT_SCOPE_*`; link-local v6 is scope 253); `Route { table: u32, dst: Option<IpNet>, gateway: Option<IpAddr>, oif: Option<u32>, protocol: u8, priority: u32, v6: bool }`.

- [ ] **Step 1: Failing integration test** in `harness/tests/netlink.rs`

Own runner like `m0.rs`: `sandbox::enter()` first, then a tokio runtime per scenario. All interfaces live in the sandbox's own network namespace, which outlives the scenarios: every scenario uses interface names unique to it and deletes them on exit (and ignores a failing delete on entry). Scenario `monitor_sees_veth_addr_and_route`: `ip link add veth0 type veth peer name veth1`; `Netlink::connect()`; cache has `veth0` with `kind == Some(Veth)` and `up == false`; `ip link set veth0 up` and `veth1 up` → within 2 s `up == true`; `ip addr add 10.0.0.1/24 dev veth0` → `Addr { net: 10.0.0.1/24 }` present; `ip route add 10.9.0.0/24 via 10.0.0.2 proto 200` → `Route { dst: 10.9.0.0/24, gateway: 10.0.0.2, protocol: 200, table: 254 }` present; `ip route del …` → gone within 2 s. Waiting is `tokio::time::timeout(2 s, rx.changed())` loops.

- [ ] **Step 2: Run** `OPENFEO_KERNEL= cargo test -p openfeo-harness --test netlink` → FAIL (crate missing). (`veth` must be available on the host kernel; the Ubuntu runner has it.)

- [ ] **Step 3: Implement** (`rtnetlink::new_connection`, `connection.socket_mut().socket_mut().add_membership(group)` for each group, `tokio::spawn(connection)`, dumps via `handle.link().get().execute()`, `address().get()`, `route().get(IpVersion::V4 | V6)`; notifications parsed from `RouteNetlinkMessage::{NewLink, DelLink, NewAddress, DelAddress, NewRoute, DelRoute}`; `carrier` from `IFF_LOWER_UP`/`IFF_RUNNING`, `up` from `IFF_UP`).

- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `netlink: monitor cache over rtnetlink with sandboxed veth test`.

---

### Task 9: `openfeo-netlink`: apply primitives

**Files:**
- Create: `crates/openfeo-netlink/src/apply.rs`; extend `harness/tests/netlink.rs`

**Interfaces:**
- Produces on `Netlink`: `async fn link_add_bridge(&self, name: &str, vlan_filtering: bool) -> Result<(), Error>`, `link_set_master(&self, index: u32, master: Option<u32>)`, `link_set_up(&self, index: u32, up: bool)`, `link_set_name(&self, index: u32, name: &str)`, `link_set_mac(&self, index: u32, mac: [u8; 6])`, `link_del(&self, index: u32)`, `addr_add(&self, index: u32, net: IpNet)`, `addr_del(&self, index: u32, net: IpNet)`, `route_add(&self, route: &Route)` (sets `protocol`, `table`, `priority`, `oif`, `gateway`, `dst`), `route_del(&self, route: &Route)`; `Error::Netlink { op: &'static str, errno: i32 }` with Display `… (EEXIST)` style names for the common errnos.

- [ ] **Step 1: Failing scenarios** in `netlink.rs`

`bridge_with_vlan_filtering_enslave_rename` (`link_add_bridge("br-t0", true)` → `ip -d link show br-t0` contains `vlan_filtering 1`; `link_set_master(veth0, Some(br))` → cache `master == Some(br)`; `link_set_name(veth1, "t1")` → `cache.link_by_name("t1")`; `link_set_mac(br, 02:…)` → cache mac; `link_del(br)` → gone); `addr_and_route_primitives` (`addr_add` then `ip -4 addr show veth0` has it; `route_add` default via `10.0.0.2` proto 200 → `ip route show` has `default via 10.0.0.2 dev veth0 proto 200`; `route_del` → gone; adding the same route twice → `Err(Netlink { errno: EEXIST })`).

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (bridge creation via `LinkBridge::new(name).build()` plus `InfoBridge::VlanFiltering(1)` in the link info data). **Step 4: Run** → PASS.

- [ ] **Step 5: Commit** `netlink: link, address and route apply primitives`.

---

### Task 10: `openfeo-reconcile`: links and routing as pure functions with snapshots

**Files:**
- Create: `crates/openfeo-reconcile/Cargo.toml` (deps `openfeo-world`, `openfeo-config`, `ipnet`, `serde` for snapshot types; dev `insta`), `src/lib.rs`, `src/links.rs`, `src/routing.rs`, `src/snapshots/*.snap`, `src/fixtures.rs` (test-only World builders), `harness/fixtures/vm-static.toml` (first consumer is the snapshot test here; Task 13 boots it)

- [ ] **Step 0: Fixture** `harness/fixtures/vm-static.toml`

```toml
config_version = 1

[system]
hostname = "openfeo"
domain = "home.arpa"

[[wans]]
name = "wan0"
port = "p0"
priority = 10
[wans.static]
address = "203.0.113.10/24"
gateway = "203.0.113.1"
dns = ["203.0.113.1"]

[[lans]]
name = "lan0"
ports = ["p2"]
ipv4 = "192.168.1.1/24"
```

(No `[[ports]]` section: the live map assigns `p0..p2` in PCI order, which is QEMU's device order. `p1` has no role.)

**Interfaces:**
- Produces: `openfeo_reconcile::links::{links(world: &World) -> DesiredLinks, DesiredLinks { bridges: BTreeMap<String, DesiredBridge>, ports: BTreeMap<String, DesiredPort> }, DesiredBridge { name: String, vlan_filtering: bool (always true), mac: Option<MacAddr> (lowest member MAC from link facts, None if no member fact), members: BTreeSet<String>, up: bool (true) }, DesiredPort { name: String, up: bool, master: Option<String> }}` — every port in `world.ports` appears; `up` is true iff it has a role (WAN or LAN member); `openfeo_reconcile::routing::{routing(world: &World) -> DesiredRouting, DesiredRouting { addrs: BTreeSet<DesiredAddr>, routes: BTreeSet<DesiredRoute> }, DesiredAddr { ifname: String, net: IpNet }, DesiredRoute { ifname: String, dst: Option<IpNet>, gateway: Option<IpAddr>, table: u32 (254), protocol: u8 (200), priority: u32 }}` — a LAN contributes its `ipv4` on `br-<lan>`; a static WAN contributes its address on the port and a default route via its gateway with `priority = wan.priority`; a WAN whose port is unknown contributes nothing (validation already rejected it).

- [ ] **Step 1: Failing snapshot tests**

`first_boot_bridges_every_port` (3 ports, defaults → one bridge `br-lan0` with members p0,p1,p2, mac = lowest of the three link facts, all ports up with master); `static_wan_and_one_lan` (fixture = `harness/fixtures/vm-static.toml` contents parsed with `openfeo_config::file::parse`; p1 has no role → `up: false`, no master; routes = one default via `203.0.113.1` on `p0` priority 10; addrs = `203.0.113.10/24` on p0, `192.168.1.1/24` on `br-lan0`); `missing_link_fact_gives_no_bridge_mac`. Each `insta::assert_yaml_snapshot!`.

- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile` → FAIL (no snapshots; `INSTA_UPDATE=always` on the first green run writes them, then review `cargo insta`-free by reading the `.snap` files). **Step 3: Implement.** **Step 4: Run** → PASS, snapshots committed; `scripts/check-deps.sh` → PASS.

- [ ] **Step 5: Commit** `reconcile: links and routing as pure World -> Desired with snapshots`.

---

### Task 11: `openfeo-apply`: links and routing appliers

**Files:**
- Create: `crates/openfeo-apply/Cargo.toml` (deps `openfeo-netlink`, `openfeo-reconcile`, `openfeo-world`, `tokio`, `tracing`, `thiserror`, `ipnet`), `src/lib.rs`, `src/links.rs`, `src/routing.rs`; scenarios in `harness/tests/netlink.rs` (harness dev-deps `openfeo-apply`, `openfeo-reconcile`, `openfeo-world`, `openfeo-config`)

**Interfaces:**
- Produces: `openfeo_apply::{Report { ops: usize }, ApplyError (wraps `openfeo_netlink::Error` with the op description)}`; `openfeo_apply::links::LinksApplier::new() -> Self`, `async fn apply(&mut self, desired: &DesiredLinks, observed: &Cache, nl: &Netlink) -> Result<Report, ApplyError>`; `openfeo_apply::routing::RoutingApplier` likewise with `&DesiredRouting`. Each operation logs one INFO line: `add bridge br-lan0`, `enslave p2 -> br-lan0`, `release p1 from br-lan0`, `del bridge br-x`, `set p0 up`, `set p1 down`, `set br-lan0 mac 52:54:00:fe:00:02`, `add addr 192.168.1.1/24 dev br-lan0`, `del addr … dev …`, `add route default via 203.0.113.1 dev p0 proto 200 metric 10`, `del route …`. Ownership: bridges named `br-*` are ours (undesired ones deleted); a port whose master is a `br-*` bridge is released when not desired; on managed interfaces (desired bridges, ports with a role) every address with `scope == 0` (global) not in desired is deleted, link-local and other scopes never; routes with `protocol == 200` not in desired are deleted, other protocols never touched. Order inside `links`: create bridges, set bridge MACs, enslave/release, set up/down. A failure returns after the failed op (ops so far are kept); the caller retries.

- [ ] **Step 1: Failing scenarios** in `netlink.rs`

Set-up helper: veth pairs named `p0`,`p1`,`p2` (peers `h0`,`h1`,`h2`), World from `vm-static.toml` with a PortMap p0..p2 and link facts from the cache. `apply_builds_bridge_addrs_routes` (after `links` then `routing` apply: `ip -d link show br-lan0` has `vlan_filtering 1`, `p2` master `br-lan0`, `p0` up, `p1` down, `ip -4 addr show br-lan0` has `192.168.1.1/24`, `ip route show default` has `via 203.0.113.1 dev p0 proto 200 metric 10`; bridge MAC equals p2's MAC). `reapply_is_a_noop` (second apply of both → `ops == 0`). `config_change_moves_the_lan_address` (World with `ipv4 = 192.168.5.1/24` → old deleted, new added, `ops == 2`). `foreign_state_is_untouched` (`ip addr add fe80::1/64 dev br-lan0` is scope link and stays; `ip route add 10.77.0.0/16 via 203.0.113.1 dev p0 proto static` stays; `ip link add br-zz type bridge` is deleted on the next links apply because it is ours by name).

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.

- [ ] **Step 5: Commit** `apply: links and routing appliers that own only tagged state`.

---

### Task 12: PID 1 mounts the state disk in `vm` mode; ADR-0010

**Files:**
- Modify: `crates/openfeo-init/src/mounts.rs`, `src/lib.rs`
- Create: `docs/adr/0010-harness-state-disk.md`

**Interfaces:**
- Produces: `mounts::STATE_VM: MountSpec { source: "/dev/vda", target: "/state", fstype: "ext4", flags: MS_NOATIME | MS_NODEV | MS_NOSUID | MS_NOEXEC, data: "", required: false }`; `mounts::state_plan(mode: Mode) -> &'static [MountSpec]` (`Vm` → `[STATE_VM, STATE_FALLBACK]`, every other mode → `[STATE_FALLBACK]` until M5); `mounts::mount_state_with(plan: &[MountSpec], mount: &mut dyn FnMut(&MountSpec) -> io::Result<()>) -> Result<&'static MountSpec, MountError>` (tries each in order, returns the first that mounted or was already mounted, skips optional absences, fails on anything else); `mounts::mount_state(mode: Mode) -> Result<&'static MountSpec, MountError>` (uses `sys::mount`, and in `Vm` mode first waits up to 3 s in 100 ms steps for `/dev/vda` to appear, since devtmpfs may populate after PID 1 starts). PID 1 logs `state: ext4 /dev/vda` or keeps the M0 text `state: volatile tmpfs until persistent storage lands in M5`.

- [ ] **Step 1: Failing tests** `vm_plan_tries_the_disk_first` (`state_plan(Vm)` sources `["/dev/vda", "tmpfs"]`), `metal_plan_is_fallback_only_until_m5`, `disk_absent_falls_back` (fake mounter returns `ENXIO` for `/dev/vda`, `Ok` for tmpfs → attempts both, returns `STATE_FALLBACK`), `disk_present_stops_there` (fake returns `Ok` first → one attempt, `STATE_VM`), `disk_error_other_than_absence_is_fatal` (`EIO` → `Err`), `enoent_and_enxio_on_an_optional_spec_are_skipped` (`classify`).

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (`classify` treats `ENXIO` like `ENOENT` for optional specs). **Step 4: Run** `cargo test -p openfeo-init` → PASS.

- [ ] **Step 5: ADR-0010**

Context: scenarios need a config in `/state` and persistence across a reset; the initramfs is read-only by design. Decision: the harness builds an ext4 image labelled `openfeo-state` with `mkfs.ext4 -d` (no root) and attaches it as virtio-blk; in `vm` mode PID 1 mounts `/dev/vda` on `/state` with the §5.2 options, falling back to tmpfs. Consequences: `e2fsprogs` on the harness host; M5 generalises the mount to the labelled partition on metal.

- [ ] **Step 6: Commit** `init: mount /dev/vda as /state in vm mode (ADR-0010)`.

---

### Task 13: Harness: state disk, QMP client, config fixture, `run --config`

**Files:**
- Create: `harness/src/statedisk.rs`, `harness/src/qmp.rs`
- Uses: `harness/fixtures/vm-static.toml` from Task 10
- Modify: `harness/src/qemu.rs` (`VmSpec { state_disk: Option<PathBuf>, qmp_socket: Option<PathBuf> }`), `lab.rs`, `main.rs`, `lib.rs`, `harness/Cargo.toml` (dep `serde_json`), `Makefile` (`run` passes `--config harness/fixtures/vm-static.toml`)

**Interfaces:**
- Produces: `statedisk::create(image: &Path, files: &[(&str, &[u8])]) -> Result<()>` (writes a staging dir next to `image`, every file mode 0600 and parent dirs created, `truncate` to 64 MiB, `mkfs.ext4 -q -F -L openfeo-state -E root_owner=0:0 -d <staging> <image>`); `qmp::Qmp::connect(socket: &Path) -> Result<Qmp>` (negotiates `qmp_capabilities`), `fn set_link(&mut self, netdev: &str, up: bool) -> Result<()>`, `fn system_reset(&mut self) -> Result<()>`, `fn quit(&mut self) -> Result<()>` (each sends one JSON command and reads lines until a `return` or `error` object; events are skipped); `Lab::with_state(&mut self, files: &[(&str, &[u8])]) -> Result<()>` (before boot; creates `<run_dir>/state.img`), `Lab::with_config(&mut self, toml: &str) -> Result<()>` = `with_state(&[("config.toml", toml)])`, `Lab::qmp(&self) -> Result<Qmp>`; `qemu::build_args` adds `-drive file=<img>,if=virtio,format=raw,cache=unsafe` and `-qmp unix:<sock>,server=on,wait=off` when set; `Lab::boot` always sets `qmp_socket = <run_dir>/qmp.sock`. `openfeo-harness run --config <toml>` (default `harness/fixtures/vm-static.toml`; `--no-config` boots without a disk). `check` reports `mkfs.ext4` and `ping` on PATH.

- [ ] **Step 1: Failing unit tests** `args_include_state_drive_and_qmp_socket` (in `qemu.rs`), `statedisk_image_has_the_label_and_files` (in `statedisk.rs`: create with `config.toml` and `identity/portmap`, then `debugfs -R "ls -l /" image` or `e2ls`? Use `debugfs -R 'cat /config.toml' <image>` via `Command` and compare bytes; `blkid`-free label check via `debugfs -R stats` containing `Filesystem volume name:   openfeo-state`), `qmp_handshake_and_set_link` (a fake QMP server on a temp unix socket in a thread: greets, answers `qmp_capabilities` and `set_link` with `{"return": {}}`, interleaving one `{"event": …}` line; the client succeeds).

- [ ] **Step 2: Run** `cargo test -p openfeo-harness --lib` → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.

- [ ] **Step 5: `run --config` and check-env**

Run: `cargo run -q -p openfeo-harness -- check` → lists `mkfs.ext4` and `ping` as `ok`.

- [ ] **Step 6: Commit** `harness: state disk via mkfs.ext4 -d, QMP client, run --config`.

---

### Task 14: The router child on tokio: boot sequence, health-gated heartbeat, logging, chaos

**Files:**
- Modify: `crates/openfeo/Cargo.toml` (deps `tokio`, `tracing`, `mimalloc`, `openfeo-platform`, `openfeo-config`, `openfeo-world`, `openfeo-runtime`, `openfeo-netlink`, `openfeo-reconcile`, `openfeo-apply`, `ipnet`), `src/main.rs` (`#[global_allocator] static GLOBAL: mimalloc::MiMalloc`), `src/router.rs`, `src/chaos.rs`
- Create: `src/boot.rs`, `src/heartbeat.rs`

**Interfaces:**
- `router::run(mode, cmdline, version) -> anyhow::Result<()>` builds a multi-thread runtime (2 workers) and blocks on `router::main_async`.
- `boot.rs` pure decisions, unit-tested: `KernelDecision::{Proceed(usize), Refuse(String), SkipContainer(String)}`, `fn kernel_decision(read: io::Result<String>, mode: Mode) -> KernelDecision` (`Err` in `Container` → `SkipContainer`, `Err` elsewhere → `Refuse("cannot read /proc/config.gz: …")`, `Ok(text)` → `check` → `Proceed(n)` or `Refuse(missing.to_string())`); `ConfigDecision::{Use(Loaded), Defaults { reason: String, violations: Vec<Violation> }}`, `fn config_decision(result: Result<Loaded, ConfigError>, ports: &PortMap) -> ConfigDecision` (`Invalid` → defaults with violations; `Io`/`Toml`/`Shape`/`MissingVersion`/`TooNew` → defaults with the error text; `Ok` → `Use`).
- Console contract (exact prefixes; the harness depends on them): `router mode={mode} version={v}`; `kernel: all {n} required options present` | `kernel: {reason}; refusing to start router services` | `kernel: {reason}; check skipped in container mode`; per port `port {pN} {ifname} id={id} mac={mac} ({new|known})`, `port missing {pN} id={id}`, `ports total={n}`; `portmap: recorded {k} new ports in /state/identity/portmap` | `portmap: unchanged ({n} ports)`; `renamed {ifname} -> {pN}`; `config: loaded /state/config.toml version={v}` | `config: migrated from version {n}` | `config: none at /state/config.toml; first-boot defaults (all ports in lan0 192.168.1.1/24)` | `config: invalid ({n} errors); using first-boot defaults` followed by `config: error path={path} code={code} {message}` per violation | `config: {error}; using first-boot defaults`; `link {name} {up|down}` on carrier changes (from the link-fact task); applier lines from Task 11; `apply {links|routing} generation={g} ops={n}` (INFO when `ops > 0`, DEBUG otherwise); `ready generation={g}` the first time both subsystems have applied the same generation; `apply {sub} failed: {err}; retry in {d}`; `heartbeat withheld: {reason}` once per transition to unhealthy, `heartbeat resumed` on recovery; `chaos …` lines unchanged from M0.
- Sequence in `main_async`: `log::init("openfeo", ring 8 MiB, /dev/kmsg or stderr)` → banner → chaos task → kernel decision (`Refuse` ⇒ heartbeat task only, then park) → `Netlink::connect` and monitor under the `Supervisor` as task `netlink-monitor` → `platform::ports::enumerate` → load `/state/identity/portmap` (absent ⇒ empty; create `/state/identity`) → `portmap::assign` → rename plan executed with `link_set_up(false)` first when a link is up → persist the map when `added` is non-empty (via `openfeo_platform::atomic::write`, mode 0600) → config decision → `Publisher::new(World { generation: 0, … })` → tasks under the supervisor: `link-facts` (cache rx → `publisher.update` of `links`, logs `link … up/down`), `apply-links`, `apply-routing` (each: wait for World change, `desired = reconcile(..)`, `observed = cache_rx.borrow().clone()`, `let _g = health.begin(sub)`, apply, `health.set(sub, Ok)`, send `(sub, generation)` to the ready reporter; on error `health.set(sub, Degraded)`, backoff 1 s doubling to 30 s, loop without waiting for a new World), `ready` reporter, `heartbeat` (every 5 s, `CtlPipe::send(Heartbeat)` iff `health.is_healthy(now)` and not hung) → `futures::future::pending().await`.
- Chaos: `child-exit:<s>` exits 3 after `<s>` seconds (unchanged); `child-hang:<s>` sets an `AtomicBool hung` the heartbeat task honours (same `chaos child-hang: heartbeats stopped` line).
- Container mode: no rename when zero ports; `/state` missing ⇒ `portmap: cannot read /state/identity/portmap: …; starting empty` warning and no persistence attempt beyond one failed `create_dir_all` warning.

- [ ] **Step 1: Failing unit tests** `kernel_decision_refuses_on_missing_options`, `kernel_decision_skips_in_container_when_unreadable`, `kernel_decision_refuses_when_unreadable_on_metal`, `config_decision_falls_back_on_invalid_with_violations`, `config_decision_uses_a_valid_file`.

- [ ] **Step 2: Run** `cargo test -p openfeo` → FAIL. **Step 3: Implement `boot.rs`.** **Step 4: Run** → PASS.

- [ ] **Step 5: Implement `router.rs`, `heartbeat.rs`, `main.rs` allocator, `chaos.rs` on tokio**

The M0 unit tests of `chaos` keep passing; `make bin` and `make bin FEATURES=` both link statically (`file target/x86_64-unknown-linux-musl/release/openfeo` says static).

- [ ] **Step 6: Smoke in the lab**

Run: `make kernel && cargo run -q -p openfeo-harness -- run` and read the console: the port lines, `portmap: recorded 3 new ports`, `config: loaded /state/config.toml version=1`, `add bridge br-lan0`, `enslave p2 -> br-lan0`, `add addr …`, `add route default …`, `ready generation=…`; Ctrl-A x.
Expected: those lines, no `apply … failed`, no `heartbeat withheld`.

- [ ] **Step 7: M0 scenarios still pass**

Run: `make test-harness FILTER=` → `m0` 5 passed (the `boots_and_logs` port regex still matches: `port p0 eth0 id=pci-… mac=… (new)` keeps the M0 prefix).

- [ ] **Step 8: Commit** `openfeo: router child on tokio: kernel check, port naming, config, World, appliers, health-gated heartbeat`.

---

### Task 15: M1 part 1 scenarios, Makefile, CI, README status

**Files:**
- Create: `harness/tests/m1.rs` (`harness = false`)
- Modify: `harness/Cargo.toml`, `Makefile` (`test-harness` runs `--test netlink --test m0 --test m1`), `README.md` (Status: M1 part 1 done: LAN bridge and static WAN from a config file), `.github/workflows/ci.yml` (nothing new beyond Task 1 and 3 unless a scenario needs a package)

**Scenarios** (each boots its own lab; `ready` waits use `BOOT_TIMEOUT`, follow-ups `SOON`):
- `first_boot_defaults_bridge_all_ports`: `lab.boot("")` (no disk) → `config: none at /state/config.toml; first-boot defaults …`, `add bridge br-lan0`, three `enslave p{0,1,2} -> br-lan0`, `ready generation=`; then `lab.lan0.ip(["addr","add","192.168.1.2/24","dev","lan0"])` and `ping -c 1 -W 2 192.168.1.1` from `lab.lan0` succeeds.
- `static_wan_and_lan_from_config`: `lab.with_config(include_str!("../fixtures/vm-static.toml"))`, boot → `kernel: all \d+ required options present`, `config: loaded /state/config.toml version=1`, `portmap: recorded 3 new ports`, port lines map `p0`→`52:54:00:fe:00:00`, `p1`→`…:01`, `p2`→`…:02`, `add addr 203.0.113.10/24 dev p0`, `add addr 192.168.1.1/24 dev br-lan0`, `add route default via 203.0.113.1 dev p0 proto 200 metric 10`, `set p1 down` or no `set p1 up`, `ready`; ping `192.168.1.1` from `lan0` (after addressing the tap) and ping `203.0.113.10` from `isp0` both succeed; `count("apply .* failed") == 0`.
- `child_restart_converges_without_changes`: config disk + `openfeo.chaos=child-exit:20`; wait `ready`, then `chaos child-exit`, `child started` (second pid), second `ready`; between the second `router mode=` line and the second `ready` there is no `add bridge`, `add addr`, `add route`, `del ` or `enslave` line (`Lines::count` on a cursor-bounded slice: add `Lines::count_since(&self, cursor: &Cursor, re) -> usize` to `lines.rs`), and `apply links generation=\d+ ops=0` appears at DEBUG? No: assert on the absence of op lines only. Ping `192.168.1.1` still succeeds.
- `wan_link_flap_recovers`: config disk; `ready`; `lab.qmp()?.set_link("p0", false)` → `link p0 down`; `set_link("p0", true)` → `link p0 up`; ping `203.0.113.10` from `isp0` succeeds within 5 s; no `apply … failed`.
- `portmap_persists_across_reset`: config disk; `portmap: recorded 3 new ports`; `lab.qmp()?.system_reset()`; second `Linux version` banner; `portmap: unchanged (3 ports)` and `config: loaded` again; `ready`.

- [ ] **Step 1: Write the scenarios** (they fail until the binary and harness pieces are complete; here they are the acceptance run).

- [ ] **Step 2: Run** `make test-harness` → `netlink` scenarios pass, `m0` 5 passed, `m1` 5 passed.

- [ ] **Step 3: Full gate**

Run: `make ci` → exit 0 (lint incl. check-deps and check-proto, unit tests across the workspace, kernel config check, all harness scenarios).

- [ ] **Step 4: Commit** `harness: M1 part 1 scenarios (defaults, static WAN+LAN, restart convergence, link flap, port-map persistence)`.

---

## Decisions this plan makes (for the ledger)

- `openfeo-runtime` exists so `openfeo-reconcile` can take `&World` without tokio (ADR-0009).
- The WAN type is a protobuf `oneof` selected by which `[wans.<kind>]` table is present; the §8.2 `kind = "…"` string is dropped (pbjson cannot map lowercase enum names).
- `/state` in the VM is a virtio-blk ext4 image built by the harness with `mkfs.ext4 -d`; PID 1 mounts `/dev/vda` in `vm` mode (ADR-0010).
- Address ownership on managed interfaces is by scope (global addresses are ours), so a restarted child converges without persisted bookkeeping; routes are owned by protocol 200; bridges by the `br-` prefix.
- The kernel-option check compares only `kernel/required.config` (the platform fragment is build-time only).
- Fuzzing starts with the config TOML parser; the nightly fuzz workflow is scheduled, not part of `make ci`.
- An invalid config at boot falls back to first-boot defaults (reachable at 192.168.1.1) rather than applying part of it.
- Forwarding stays off in part 1; the firewall and NAT of part 2 turn it on. Per-interface `send_redirects=0` (an M0 deferred minor) also belongs with part 2's zones.
- `/state` is mounted by PID 1 only from `/dev/vda` in `vm` mode; metal keeps the tmpfs fallback until M5 decides the partition lookup.
