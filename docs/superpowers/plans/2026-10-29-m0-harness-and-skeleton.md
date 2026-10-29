# OpenFeO M0 — Harness and Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A bootable OpenFeO VM image (Linux 6.18.59 with the static `openfeo` binary as its built-in initramfs) whose PID 1 mounts, supervises a heartbeating child and arms the watchdog, plus a rootless QEMU/netns harness whose M0 scenarios pass under `make ci`.

**Architecture:** One cargo workspace. `openfeo-init` holds the PID 1 logic (std + libc, no async; `unsafe` confined to `sys.rs`). `openfeo` is the single binary: it runs `openfeo_init::main` when `getpid() == 1` and the router child otherwise; test-only chaos knobs exist only under the `harness` cargo feature. `openfeo-harness` builds a rootless lab (user + mount + net namespaces, one named netns per ISP/LAN, tap devices handed to QEMU as inherited fds) and drives the VM through its serial console with regex expectations. `kernel/build.sh` builds 6.18.59 from `allnoconfig` plus two checked-in fragments and embeds the binary through a `gen_init_cpio` list; a `Makefile` is the single entry point for humans and CI.

**Tech Stack:** Rust stable (1.99) edition 2024, target `x86_64-unknown-linux-musl`; `libc`, `thiserror`, `anyhow`; harness only: `nix`, `regex`, `clap`. QEMU 11 (q35, KVM or TCG, i6300esb watchdog), Linux 6.18.59, Kea 3.2, iproute2, GNU make, bash.

**Spec:** `SPEC.md` — §4.2 kernel policy, §5.3 health protocol, §6.1 PID 1, §11 harness, §12 row M0, §13 layout and working rules, §14 licensing.

## Global Constraints

- Rust stable, edition 2024; the image binary is built for `x86_64-unknown-linux-musl` and must be statically linked (`file` says "statically linked").
- `#![forbid(unsafe_code)]` in every crate except `openfeo-init`, where `unsafe` lives only in `src/sys.rs` and every `unsafe` block carries a `// SAFETY:` comment.
- No `unwrap`/`expect` outside tests; `thiserror` in libraries, `anyhow` only in the binary and the harness.
- `std::process::Command` is banned everywhere except `harness/` and `image/` (clippy `disallowed_methods`).
- `cargo clippy --all-targets --all-features -- -D warnings` clean, with `clippy::pedantic` as warnings; `cargo fmt --check` clean; `cargo deny check` clean against the §14 allow-list.
- Every `.rs`, `.sh`, `.c`, `.h` file and every `Makefile` starts with `SPDX-License-Identifier: GPL-2.0-or-later` and `Copyright (C) 2026 Andrew Newton`.
- Every commit is signed off (`git commit -s`, repo-local identity `Andrew Newton <andy@vitri.ltd>`) and ends with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_0116otzXyvDbuXkw4CsR8ExV`. Subject style: `<area>: <imperative summary>`.
- Kernel: upstream LTS **6.18.59** (sha256 `53a55ac9863a5547e292b8e381d4e4c2240dd1127d5428a7c44dbc550be23963`), `CONFIG_MODULES` unset, config built from `allnoconfig` + fragments, never from a distro defconfig. VM command line: `console=ttyS0,115200 openfeo.mode=vm panic=10 printk.devkmsg=on`.
- Initramfs contents, nothing else: `/init` (the binary), `/dev/console` node, empty `/dev /proc /sys /run /state /boot /tmp`.
- Health protocol numbers: watchdog timeout **60 s**; child heartbeat every **5 s**; PID 1 pets only if a heartbeat arrived within the last **20 s**; after **3 restarts within 10 minutes** PID 1 stops petting; with no watchdog device PID 1 reboots itself in its place.
- Prefer the simplest mechanism that satisfies a requirement.

## Review Focus

1. A `--mode` flag that disagrees with `openfeo.mode=` on the kernel command line: the flag wins (SPEC §2 process model). Test in Task 5 (`cli::resolve_mode`).
2. Several control-pipe bytes arriving in one `read` (a burst of heartbeats, or a heartbeat followed by a reboot request) plus an unknown byte: every valid message is processed, the unknown byte is skipped. Test in Task 4 (`ctl::decode`).
3. A mount that is already present (`EBUSY`, e.g. devtmpfs auto-mounted) or an optional filesystem a VM lacks (`efivarfs`, `pstore` → `ENODEV`/`ENOENT`) must not stop boot; a required mount failing must. Test in Task 4 (`mounts::classify`).
4. A netdev without a PCI ancestor (`lo`, a platform or USB device, a virtual interface) is skipped with a log line, never a panic or a bogus `pci-` id. Test in Task 5 (`ports::enumerate`).
5. Kernel command lines with a repeated key (last wins), a double-quoted value, tabs and runs of spaces, and bare flags without `=`. Test in Task 2 (`cmdline::parse`).

---

## File structure

```
openfeo/
  Makefile                      entry point: bin, kernel, run, test, test-harness, lint, ci
  Cargo.toml                    workspace, shared deps, lints, release profile
  rust-toolchain.toml  clippy.toml  deny.toml  .gitignore  LICENSE  CLAUDE.md  SPEC.md
  docs/adr/NNNN-*.md            decisions (0001–0008 in M0)
  docs/superpowers/plans/       this plan
  scripts/check-spdx.sh         SPDX header check (part of `make lint`)
  kernel/
    required.config             options every target must have (verified at build; at boot from M1)
    x86_64.config               x86/QEMU/N100 platform fragment
    linux-6.18.59.sha256        pinned tarball hash
    build.sh                    fetch | config | check | build | all
  crates/openfeo-init/src/
    lib.rs                      `pub fn main(version) -> !` orchestration; `#[allow(unsafe_code)] mod sys;`
    cmdline.rs  heartbeat.rs  restart.rs   pure, unit-tested policy and parsing
    ctl.rs                      PID 1 ↔ child pipe protocol (both sides)
    log.rs                      "<6>prefix: msg" to /dev/kmsg, stderr fallback
    mounts.rs  sysctl.rs  watchdog.rs      early mounts, core sysctls, /dev/watchdog0 + software fallback
    supervisor.rs               the PID 1 loop: poll(signalfd, ctl pipe), restart, pet
    sys.rs                      the only unsafe module: libc wrappers
  crates/openfeo/src/
    main.rs  cli.rs  version.rs  ports.rs  chaos.rs  router.rs
  harness/
    Cargo.toml  clippy.toml     package openfeo-harness; Command allowed here
    src/lib.rs  sandbox.rs  netns.rs  tun.rs  lines.rs  qemu.rs  lab.rs  daemons.rs  scenario.rs
    src/main.rs                 `openfeo-harness run|check`
    fixtures/kea-dhcp4.json.tmpl
    tests/m0.rs                 harness = false; the M0 scenarios
  .github/workflows/ci.yml
```

---

### Task 1: Governance files, first ADRs, spec confirmations

**Files:**
- Create: `LICENSE`, `.gitignore`, `CLAUDE.md`, `scripts/check-spdx.sh`, `docs/adr/0001-record-architecture-decisions.md` … `0007-test-hooks-only-under-the-harness-feature.md`
- Modify: `SPEC.md` (§2 ⚠ CONFIRM rows, §15 open items, status line)
- Already present: `docs/superpowers/plans/2026-10-29-m0-harness-and-skeleton.md` (commit it here)

**Interfaces:**
- Produces: `scripts/check-spdx.sh` (exit 0 when every tracked `*.rs *.sh *.c *.h Makefile` carries the SPDX line within its first 3 lines; prints offenders and exits 1 otherwise), used by `make lint` from Task 2 on.

- [ ] **Step 1: LICENSE**

Run: `curl -sSfL https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt -o LICENSE && head -2 LICENSE && wc -l LICENSE`
Expected: `GNU GENERAL PUBLIC LICENSE` / `Version 2, June 1991`; about 339 lines.

- [ ] **Step 2: `.gitignore`**

Exactly: `/target`, `/build`.

- [ ] **Step 3: `scripts/check-spdx.sh`**

`#!/usr/bin/env bash`, `set -euo pipefail`. Files = `git ls-files -- '*.rs' '*.sh' '*.c' '*.h' 'Makefile' '**/Makefile'`. For each, `head -n 3 "$f" | grep -q 'SPDX-License-Identifier: GPL-2.0-or-later'` else record it. Print `missing SPDX header: <file>` per offender; exit 1 if any. The script itself carries the header (lines 2–3). `chmod +x`.

- [ ] **Step 4: Verify the check both passes and fails**

Run: `scripts/check-spdx.sh && echo PASS` → `PASS`.
Run: `printf 'fn main() {}\n' > tmp_bad.rs && git add -N tmp_bad.rs && scripts/check-spdx.sh; echo "exit=$?"; git rm -q --cached tmp_bad.rs; rm tmp_bad.rs`
Expected: `missing SPDX header: tmp_bad.rs` and `exit=1`.

- [ ] **Step 5: `CLAUDE.md`**

Content (keep to this; SPEC.md is the source of truth, this file only summarises):

```markdown
# OpenFeO — working rules for Claude Code sessions

`SPEC.md` is the source of truth. Build only what §§1–11 say, in the milestone order of §12.
Any deviation from §2 needs an ADR in `docs/adr/` before code; kernel and protocol quirks found in
the harness get ADRs too (`docs/adr/NNNN-title.md`: Context, Decision, Consequences).

## Commands
- `make bin`           static musl binary (`--features harness` by default; `FEATURES=` for a release build)
- `make kernel`        fetch/verify/build Linux (see `kernel/`) with the binary embedded → `build/bzImage`
- `make run`           boot the VM in the rootless lab with the serial console on your terminal (Ctrl-A x quits)
- `make test`          unit tests; `make test-harness` runs the QEMU scenarios (`FILTER=name` to pick one)
- `make lint`          fmt, clippy (-D warnings), cargo-deny, SPDX headers
- `make ci`            everything CI runs, in CI's order
- `make check-env`     is this machine able to run the harness?

## Rules
- Rust stable, edition 2024, musl targets. `clippy -D warnings`, pedantic as warnings. No `unwrap`/`expect`
  outside tests. `thiserror` in libraries, `anyhow` only in `crates/openfeo` and `harness/`.
- `#![forbid(unsafe_code)]` everywhere except `openfeo-init` (and later `openfeo-nft`), where `unsafe` is
  confined to `sys.rs` with `// SAFETY:` comments.
- No shelling out: `std::process::Command` is banned outside `harness/` and `image/` (clippy enforces it).
- Only `openfeo-netlink`, `openfeo-nft`, `openfeo-net`, `openfeo-platform` and `openfeo-init` may call the kernel;
  `openfeo-proto-*` and `openfeo-reconcile` never depend on tokio, libc, nix or socket2.
- Every parser gets a fuzz target in the PR that adds it.
- Every source file starts with `SPDX-License-Identifier: GPL-2.0-or-later` and `Copyright (C) 2026 Andrew Newton`.
- Commits: `git commit -s` (DCO, identity `Andrew Newton <andy@vitri.ltd>`, set repo-locally), subject `<area>: <summary>`.
- Test hooks (`openfeo.chaos=`) exist only under the `harness` cargo feature; release builds carry none.

## Harness
Rootless: user + mount + net namespaces, no sudo. Needs `/dev/kvm` (falls back to TCG) and `/dev/net/tun`
readable, and unprivileged user namespaces enabled. Host-side `pppd` (M3) additionally needs `/dev/ppp`
group-accessible via a udev rule.
```

- [ ] **Step 6: ADRs**

Format for every ADR: `# NNNN — Title`, `Status: Accepted`, `Date: 2026-10-29`, then `## Context`, `## Decision`, `## Consequences`. Context and consequences come from the matching §2 row's rationale and the M0 facts below; one to three short paragraphs each.

| # | File | Decision |
|---|---|---|
| 0001 | `0001-record-architecture-decisions.md` | Decisions in SPEC §2 are changed only through an ADR in this directory; kernel and protocol quirks discovered in the harness are recorded here too. |
| 0002 | `0002-licence-gpl-2.0-or-later.md` | Project code is GPL-2.0-or-later, no CLA, DCO sign-off. Because libnftables is GPL-2.0-only the shipped binary is GPLv2, so `cargo deny` rejects GPL-3.0*, LGPL-3.0*, AGPL-* (this excludes `rustables`). |
| 0003 | `0003-firewall-via-libnftables-in-process.md` | libnftables linked statically and driven through its JSON API; the whole `table inet openfeo` is regenerated and applied as one batch. |
| 0004 | `0004-boot-systemd-boot-with-boot-assessment-and-watchdog.md` | systemd-boot at the ESP fallback path, `+tries` boot assessment between two EFI-stub kernel slots, watchdog armed from boot and petted only while the child is healthy. |
| 0005 | `0005-copyright-holder.md` | The copyright notice is `Copyright (C) 2026 Andrew Newton` in every file, consistently. |
| 0006 | `0006-harness-runs-rootless-in-user-namespaces.md` | The harness enters a user + mount + net namespace itself, never needs sudo. Verified on the dev host: veth/tap creation, nested `ip netns`, nft tables, net sysctls, AF_PACKET and `/dev/kvm` all work inside. Consequences: Ubuntu 24.04 runners need `kernel.apparmor_restrict_unprivileged_userns=0`; the host-side `pppd` for M3 needs a udev rule making `/dev/ppp` group-accessible. |
| 0007 | `0007-test-hooks-only-under-the-harness-feature.md` | Fault injection the harness needs (`openfeo.chaos=child-exit:<s>`, `child-hang:<s>`) is parsed only when the binary is built with `--features harness`; release images contain no test hooks. |

- [ ] **Step 7: SPEC.md confirmations**

In §2 remove the four `⚠ CONFIRM` marks (Licence, Firewall backend, Boot, Copyright notice) and make the copyright row read `Copyright (C) 2026 Andrew Newton`. In §15 tick the first item and "Write `CLAUDE.md` and the first ADRs from §2". Change the status line to `Draft 0.3, 29 October 2026`.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -s -m "repo: licence, CLAUDE.md, first ADRs, SPDX check, M0 plan" \
  -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" \
  -m "Claude-Session: https://claude.ai/code/session_0116otzXyvDbuXkw4CsR8ExV"
```

---

### Task 2: Workspace, lint configuration and `openfeo-init::cmdline`

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `clippy.toml`, `deny.toml`, `Makefile` (lint and test targets only), `crates/openfeo-init/Cargo.toml`, `crates/openfeo-init/src/lib.rs`, `crates/openfeo-init/src/cmdline.rs`

**Interfaces:**
- Produces (`openfeo_init::cmdline`):
  - `pub enum Mode { Metal, Vm, Container, Installer, Rescue }` — `FromStr` (lowercase names), `Display` (lowercase), `Default = Metal`, `Copy, Eq`.
  - `pub enum Slot { A, B }` — `FromStr` ("a"/"b"), `Display`.
  - `#[derive(Default)] pub struct Cmdline { pub mode: Option<Mode>, pub slot: Option<Slot>, params: Vec<(String, Option<String>)> }` with `pub fn get(&self, key: &str) -> Option<&str>` (value of the **last** occurrence; `None` for a bare flag or absent key).
  - `pub fn parse(s: &str) -> Result<Cmdline, Error>`; `#[derive(thiserror::Error)] pub enum Error { UnknownMode(String), UnknownSlot(String) }`.

- [ ] **Step 1: Workspace files**

`Cargo.toml`:
```toml
[workspace]
resolver = "3"
members = ["crates/*", "harness"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "GPL-2.0-or-later"
rust-version = "1.99"

[workspace.dependencies]
libc = "0.2"
thiserror = "2"
anyhow = "1"
nix = { version = "0.30", features = ["sched", "mount", "user", "fs", "process", "signal"] }
regex = "1"
clap = { version = "4", features = ["derive"] }
tempfile = "3"

[workspace.lints.rust]
unsafe_code = "deny"
[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
disallowed_methods = "deny"

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
```
`members` includes `harness` now; create `harness/Cargo.toml` as an empty library package (`openfeo-harness`, `publish = false`, `src/lib.rs` with the SPDX header only) so the workspace resolves; Task 7 fills it. Every crate's `Cargo.toml` carries `[lints] workspace = true` (workspace lints are opt-in per crate). Non-init crates add `#![forbid(unsafe_code)]`; `openfeo-init` uses `#[allow(unsafe_code)] mod sys;` (Task 4).

`rust-toolchain.toml`: `channel = "stable"`, `components = ["clippy", "rustfmt"]`, `targets = ["x86_64-unknown-linux-musl"]`.

`clippy.toml` (root): `allow-unwrap-in-tests = true`, `allow-expect-in-tests = true`, `disallowed-methods = [{ path = "std::process::Command::new", reason = "no shelling out (SPEC §2 Build); only harness/ and image/ may spawn processes" }]`. `harness/clippy.toml`: `allow-unwrap-in-tests = true`, `allow-expect-in-tests = true` and no `disallowed-methods` (clippy uses the nearest `clippy.toml` above the crate root).

`deny.toml` (cargo-deny v2 schema): `[graph] all-features = true`; `[licenses] allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "Zlib", "Unicode-3.0", "Unicode-DFS-2016", "LGPL-2.1-or-later", "GPL-2.0-only", "GPL-2.0-or-later", "CC0-1.0", "Unlicense"]`, `confidence-threshold = 0.9`; `[advisories] yanked = "deny"`; `[bans] multiple-versions = "warn"`, `wildcards = "deny"`; `[sources] unknown-registry = "deny"`, `unknown-git = "deny"`.

`Makefile` (initial; later tasks add targets — keep the variable block at the top):
```make
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
KERNEL_VERSION ?= 6.18.59
TARGET         ?= x86_64-unknown-linux-musl
PROFILE        ?= release
FEATURES       ?= harness
BUILD          ?= $(CURDIR)/build
BUILD_ID       := $(shell git describe --always --dirty 2>/dev/null || echo dev)
FILTER         ?=

.PHONY: lint test
lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo deny check
	scripts/check-spdx.sh
test:
	cargo test --workspace --lib --bins --all-features
```

- [ ] **Step 2: Write the failing tests** in `crates/openfeo-init/src/cmdline.rs` (`#[cfg(test)] mod tests`)

```rust
#[test] fn parses_mode_and_slot() {
    let c = parse("console=ttyS0,115200 openfeo.mode=vm openfeo.slot=a panic=10").unwrap();
    assert_eq!(c.mode, Some(Mode::Vm)); assert_eq!(c.slot, Some(Slot::A)); assert_eq!(c.get("panic"), Some("10"));
}
#[test] fn missing_mode_is_none_and_defaults_to_metal() {
    let c = parse("console=ttyS0").unwrap(); assert_eq!(c.mode, None); assert_eq!(c.mode.unwrap_or_default(), Mode::Metal);
}
#[test] fn unknown_mode_is_an_error() { assert!(matches!(parse("openfeo.mode=bogus"), Err(Error::UnknownMode(m)) if m == "bogus")); }
#[test] fn last_occurrence_wins() { assert_eq!(parse("openfeo.mode=vm openfeo.mode=rescue").unwrap().mode, Some(Mode::Rescue)); }
#[test] fn quotes_tabs_and_bare_flags() {
    let c = parse("quiet\t openfeo.chaos=\"child-exit:3\"   ro").unwrap();
    assert_eq!(c.get("openfeo.chaos"), Some("child-exit:3")); assert_eq!(c.get("quiet"), None); assert_eq!(c.get("ro"), None); assert_eq!(c.get("nope"), None);
}
#[test] fn mode_round_trips_through_display() { for m in [Mode::Metal, Mode::Vm, Mode::Container, Mode::Installer, Mode::Rescue] { assert_eq!(m.to_string().parse::<Mode>().unwrap(), m); } }
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p openfeo-init` → compile errors (`parse`, `Mode` not found).

- [ ] **Step 4: Implement `cmdline.rs`**

Tokeniser: iterate chars, split on ASCII whitespace outside double quotes, strip the quotes from values. Then `key=value` → `(key, Some(value))`, else `(key, None)`. `mode`/`slot` are set from the last `openfeo.mode`/`openfeo.slot` params via `FromStr`.

- [ ] **Step 5: Run tests and lint**

Run: `cargo test -p openfeo-init` → all pass. Run: `make lint` → clean (fix pedantic warnings rather than allowing them).

- [ ] **Step 6: Commit**

`workspace: cargo workspace, lint config, kernel command-line parsing`

---

### Task 3: Supervisor policy — `heartbeat.rs`, `restart.rs`

**Files:**
- Create: `crates/openfeo-init/src/heartbeat.rs`, `crates/openfeo-init/src/restart.rs`

**Interfaces:**
- Produces:
  - `pub const GRACE: Duration = 20 s`; `pub struct Heartbeat`; `Heartbeat::new(now: Instant) -> Self` (treats boot/spawn as a heartbeat); `record(&mut self, now)`; `healthy(&self, now) -> bool` (`now - last < GRACE`).
  - `pub const WINDOW: Duration = 600 s; pub const MAX_RESTARTS: usize = 3; pub const MAX_DELAY: Duration = 30 s`; `pub enum Decision { RestartAfter(Duration), GiveUp }`; `pub struct RestartPolicy` (`Default`); `on_exit(&mut self, now: Instant) -> Decision`: drop recorded restarts older than `WINDOW`; if `restarts_in_window >= MAX_RESTARTS` → `GiveUp` (nothing recorded); else record and return `RestartAfter(min(2^n s, MAX_DELAY))` where `n` is the number of restarts already in the window (1 s, 2 s, 4 s).

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn heartbeat_healthy_within_grace() {
    let t0 = Instant::now(); let hb = Heartbeat::new(t0);
    assert!(hb.healthy(t0 + Duration::from_secs(19))); assert!(!hb.healthy(t0 + Duration::from_secs(20)));
}
#[test] fn heartbeat_record_extends() { let t0 = Instant::now(); let mut hb = Heartbeat::new(t0); hb.record(t0 + Duration::from_secs(15)); assert!(hb.healthy(t0 + Duration::from_secs(34))); }
#[test] fn backoff_then_give_up() {
    let t0 = Instant::now(); let mut p = RestartPolicy::default();
    assert_eq!(p.on_exit(t0), Decision::RestartAfter(Duration::from_secs(1)));
    assert_eq!(p.on_exit(t0 + Duration::from_secs(10)), Decision::RestartAfter(Duration::from_secs(2)));
    assert_eq!(p.on_exit(t0 + Duration::from_secs(20)), Decision::RestartAfter(Duration::from_secs(4)));
    assert_eq!(p.on_exit(t0 + Duration::from_secs(30)), Decision::GiveUp);
}
#[test] fn window_forgets_old_restarts() {
    let t0 = Instant::now(); let mut p = RestartPolicy::default();
    for i in 0..3 { p.on_exit(t0 + Duration::from_secs(i)); }
    assert_eq!(p.on_exit(t0 + Duration::from_secs(601)), Decision::RestartAfter(Duration::from_secs(1)));
}
```

- [ ] **Step 2: Run to verify they fail** — `cargo test -p openfeo-init` → compile errors.
- [ ] **Step 3: Implement** both modules (`Vec<Instant>` of restart times is enough).
- [ ] **Step 4: Run tests and lint** — `cargo test -p openfeo-init && make lint` → pass.
- [ ] **Step 5: Commit** — `init: heartbeat window and restart backoff policy`

---

### Task 4: `sys.rs`, `log.rs`, `ctl.rs`, `mounts.rs`, `sysctl.rs`, `watchdog.rs`

**Files:**
- Create: `crates/openfeo-init/src/{sys,log,ctl,mounts,sysctl,watchdog}.rs`; add `#[allow(unsafe_code)] mod sys;` and `pub mod` lines to `lib.rs`.

**Interfaces:**
- Produces (`sys`, the only unsafe module; each wrapper maps `-1` to `io::Error::last_os_error()`):
  - `pub fn mount(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> io::Result<()>`
  - `pub fn sethostname(name: &str) -> io::Result<()>`; `pub fn loopback_up() -> io::Result<()>` (AF_INET socket, `SIOCGIFFLAGS`/`SIOCSIFFLAGS` on `lo`, set `IFF_UP`)
  - `pub fn reopen_console() -> io::Result<()>` (open `/dev/console` O_RDWR, `dup2` onto 0, 1, 2)
  - `pub enum RebootCmd { Restart, PowerOff }`; `pub fn reboot(cmd: RebootCmd) -> io::Result<()>` (calls `libc::sync()` first)
  - `pub fn wdt_set_timeout(dev: &File, secs: u32) -> io::Result<u32>` (ioctl `WDIOC_SETTIMEOUT = 0xC004_5706`, returns the value the driver kept); `pub fn wdt_keepalive(dev: &File) -> io::Result<()>` (`WDIOC_KEEPALIVE = 0x8004_5705`)
  - `pub fn signalfd(signals: &[libc::c_int]) -> io::Result<File>` (blocks them with `sigprocmask`, `SFD_NONBLOCK | SFD_CLOEXEC`); `pub fn read_signal(fd: &File) -> io::Result<Option<libc::c_int>>` (`None` on `EAGAIN`)
  - `pub struct PollFd { pub fd: RawFd, pub readable: bool }`; `pub fn poll(fds: &mut [PollFd], timeout: Duration) -> io::Result<usize>`
  - `pub fn pipe() -> io::Result<(File, File)>` (O_CLOEXEC); `pub fn spawn(exe: &CStr, argv: &[CString], envp: &[CString], ctl_fd: RawFd) -> io::Result<libc::pid_t>` (fork; child: `dup2(ctl_fd, 3)`, `execve`, `_exit(127)` on failure)
  - `pub enum ExitStatus { Exited(i32), Signaled(i32) }` with `Display` → `exit(3)` / `signal(9)` and `pub fn from_wait_status(raw: i32) -> ExitStatus`; `pub fn reap() -> io::Result<Option<(libc::pid_t, ExitStatus)>>` (`waitpid(-1, WNOHANG)`); `pub fn kill(pid, sig) -> io::Result<()>`; `pub fn file_from_fd(fd: RawFd) -> File`
- Produces (`log`): `pub struct Log` (`Log::new(prefix: &'static str) -> Log` opens `/dev/kmsg` write-only if possible, else stderr; `reopen(&mut self)` retries kmsg; `info/warn/error(&self, msg: &str)`); `pub fn format_line(level: u8, prefix: &str, msg: &str) -> String` → `"<6>openfeo-init: msg\n"` for kmsg (stderr gets `"openfeo-init: msg\n"`). Levels: info 6, warn 4, error 3.
- Produces (`ctl`): `pub const CTL_FD_ENV: &str = "OPENFEO_CTL_FD"; pub const CHILD_CTL_FD: RawFd = 3; pub const HEARTBEAT_INTERVAL: Duration = 5 s`; `pub enum Msg { Heartbeat, Reboot, Poweroff }` ↔ bytes `b'H'`, `b'R'`, `b'P'` (`to_byte`, `from_byte -> Option<Msg>`); `pub fn decode(buf: &[u8]) -> Vec<Msg>` (skips unknown bytes); `pub struct CtlPipe(File)` with `from_env() -> Option<CtlPipe>` (reads `CTL_FD_ENV`, `sys::file_from_fd`) and `send(&mut self, msg: Msg) -> io::Result<()>`.
- Produces (`mounts`): `pub struct MountSpec { pub source, pub target, pub fstype: &'static str, pub flags: libc::c_ulong, pub data: &'static str, pub required: bool }`; `pub const EARLY: &[MountSpec]` in this order — `proc→/proc`, `sysfs→/sys`, `devtmpfs→/dev (mode=0755)`, `tmpfs→/run (mode=0755)`, `tmpfs→/tmp (mode=1777)`, `cgroup2→/sys/fs/cgroup (nsdelegate, optional)`, `efivarfs→/sys/firmware/efi/efivars (optional)`, `pstore→/sys/fs/pstore (optional)`; all with `MS_NOSUID|MS_NODEV|MS_NOEXEC` except devtmpfs (`MS_NOSUID` only); `pub const STATE_FALLBACK: MountSpec` = `tmpfs→/state (mode=0700, required)`; `pub enum Outcome { Mounted, AlreadyMounted, Skipped }`; `pub fn classify(err: &io::Error, required: bool) -> Result<Outcome, MountError>` (`EBUSY` → `AlreadyMounted`; optional and `ENODEV|ENOENT` → `Skipped`; otherwise `Err`); `pub fn mount_all(specs: &[MountSpec], log: &Log) -> Result<(), MountError>` (logs `mount <target> skipped: <err>` for `Skipped`); `#[derive(thiserror::Error)] pub enum MountError { #[error("mount {target} ({fstype}): {source}")] Failed { target: &'static str, fstype: &'static str, source: io::Error } }`.
- Produces (`sysctl`): `pub const CORE: &[(&str, &str)]` = `kernel/sysrq=0`, `kernel/panic_on_oops=1`, `net/ipv4/ip_forward=1`, `net/ipv6/conf/all/forwarding=1`, `net/ipv6/conf/default/forwarding=1`, `net/ipv6/conf/all/accept_ra=0`, `net/ipv6/conf/default/accept_ra=0`, `net/ipv6/conf/all/autoconf=0`, `net/ipv6/conf/default/autoconf=0`, `net/ipv4/conf/all/rp_filter=0`, `net/ipv4/conf/default/rp_filter=0`, `net/ipv4/conf/all/send_redirects=0`, `net/ipv4/conf/default/send_redirects=0`, `net/ipv4/conf/all/accept_redirects=0`, `net/ipv4/conf/default/accept_redirects=0`, `net/ipv6/conf/all/accept_redirects=0`, `net/ipv6/conf/default/accept_redirects=0`, `net/ipv4/tcp_mtu_probing=1` (SPEC §7.3 WAN autoconf off, §7.4 rp_filter 0, §7.9 mtu probing; redirects off is standard router hygiene — plan's call); `pub fn apply(log: &Log)` writes each to `/proc/sys/<key>`, warns on failure, never fails.
- Produces (`watchdog`): `pub const TIMEOUT_SECS: u32 = 60; pub const PET_INTERVAL: Duration = 5 s`; `pub enum Watchdog { Hardware { dev: File, timeout: u32 }, Software { last_pet: Instant, timeout: Duration } }`; `Watchdog::open(now) -> Watchdog` (`/dev/watchdog0` O_WRONLY|O_CLOEXEC then `wdt_set_timeout(60)`; any failure → `Software`); `pet(&mut self, now) -> io::Result<()>`; `expired(&self, now) -> bool` (Software: `now - last_pet >= timeout`; Hardware: `false`); `describe(&self) -> String` → `/dev/watchdog0 timeout=60s` or `none, software fallback timeout=60s`.

- [ ] **Step 1: Write the failing tests**

```rust
// sys.rs
#[test] fn wait_status_decodes() { assert_eq!(ExitStatus::from_wait_status(3 << 8).to_string(), "exit(3)"); assert_eq!(ExitStatus::from_wait_status(9).to_string(), "signal(9)"); }
#[test] fn pipe_round_trip() { let (mut r, mut w) = pipe().unwrap(); w.write_all(b"H").unwrap(); let mut b = [0u8; 1]; r.read_exact(&mut b).unwrap(); assert_eq!(&b, b"H"); }
// log.rs
#[test] fn kmsg_line_format() { assert_eq!(format_line(6, "openfeo-init", "start version=1"), "<6>openfeo-init: start version=1\n"); }
// ctl.rs
#[test] fn decode_burst_skips_unknown() { assert_eq!(decode(b"HHxR"), vec![Msg::Heartbeat, Msg::Heartbeat, Msg::Reboot]); }
#[test] fn byte_round_trip() { for m in [Msg::Heartbeat, Msg::Reboot, Msg::Poweroff] { assert_eq!(Msg::from_byte(m.to_byte()), Some(m)); } }
// mounts.rs
fn e(code: i32) -> io::Error { io::Error::from_raw_os_error(code) }
#[test] fn busy_means_already_mounted() { assert!(matches!(classify(&e(libc::EBUSY), true), Ok(Outcome::AlreadyMounted))); }
#[test] fn optional_nodev_is_skipped() { assert!(matches!(classify(&e(libc::ENODEV), false), Ok(Outcome::Skipped))); }
#[test] fn required_nodev_is_fatal() { assert!(classify(&e(libc::ENODEV), true).is_err()); }
#[test] fn optional_eacces_is_fatal() { assert!(classify(&e(libc::EACCES), false).is_err()); }
#[test] fn early_mount_order_starts_with_proc_sys_dev() { let t: Vec<_> = EARLY.iter().map(|m| m.target).collect(); assert_eq!(&t[..3], &["/proc", "/sys", "/dev"]); }
// sysctl.rs
#[test] fn table_has_no_duplicates_or_leading_slashes() { let mut seen = HashSet::new(); for (k, _) in CORE { assert!(!k.starts_with('/')); assert!(seen.insert(k)); } }
// watchdog.rs
#[test] fn software_watchdog_expires_after_timeout_without_pets() {
    let t0 = Instant::now(); let mut wd = Watchdog::Software { last_pet: t0, timeout: Duration::from_secs(TIMEOUT_SECS as u64) };
    assert!(!wd.expired(t0 + Duration::from_secs(59))); assert!(wd.expired(t0 + Duration::from_secs(60)));
    wd.pet(t0 + Duration::from_secs(30)).unwrap(); assert!(!wd.expired(t0 + Duration::from_secs(89)));
}
#[test] fn describe_software() { let wd = Watchdog::Software { last_pet: Instant::now(), timeout: Duration::from_secs(60) }; assert_eq!(wd.describe(), "none, software fallback timeout=60s"); }
```

- [ ] **Step 2: Run to verify they fail** — `cargo test -p openfeo-init` → compile errors.
- [ ] **Step 3: Implement the six modules.** `sys.rs` is the only file with `unsafe`; every block gets a `// SAFETY:` line. Document the two WDIOC constants' derivation (`_IOWR('W', 6, int)`, `_IOR('W', 5, int)`) in a comment.
- [ ] **Step 4: Run tests and lint** — `cargo test -p openfeo-init && make lint` → pass; confirm `grep -rl "unsafe" crates/openfeo-init/src` lists only `sys.rs`.
- [ ] **Step 5: Commit** — `init: syscall wrappers, kmsg logger, control pipe, mounts, sysctls, watchdog`

---

### Task 5: The PID 1 loop and the `openfeo` binary

**Files:**
- Create: `crates/openfeo-init/src/supervisor.rs`; `crates/openfeo/Cargo.toml`, `crates/openfeo/src/{main,cli,version,ports,chaos,router}.rs`
- Modify: `crates/openfeo-init/src/lib.rs` (add `pub fn main(version: &str) -> !` and `pub fn fatal(log: &Log, msg: &str) -> !`)

**Interfaces:**
- Consumes: everything from Tasks 2–4.
- Produces (`openfeo_init`):
  - `pub fn main(version: &str) -> !`: `Log::new("openfeo-init")` → `mounts::mount_all(EARLY)` (`fatal` on `Err`) → `sys::reopen_console()` and `log.reopen()` → parse `/proc/cmdline` (warn and use defaults on error) → `log.info("start version={version} mode={mode} slot={slot|none}")` → `sethostname("openfeo")`, `loopback_up()` (warn on failure) → `sysctl::apply` → `mount_all(&[STATE_FALLBACK])` then `warn("state: volatile tmpfs until persistent storage lands in M5")` → `Watchdog::open` and `info("watchdog {describe}")` → `supervisor::run(mode, &mut log, wd)`.
  - `pub fn fatal(log, msg) -> !`: `error(msg)`, sleep 10 s, `sys::reboot(Restart)`; if that fails, `std::process::exit(1)`.
  - `supervisor::run(mode: Mode, log: &mut Log, wd: Watchdog) -> !`. Child spawn: exe `/proc/self/exe`, argv `["openfeo", "--mode", <mode>]`, envp `["OPENFEO_CTL_FD=3"]`, a fresh `sys::pipe()` per spawn (write end to the child as fd 3, closed in the parent after fork). Loop: `poll` on the signalfd (SIGCHLD, SIGTERM, SIGINT) and the ctl read end with timeout = min(time to next pet, time to pending restart). Ctl bytes → `ctl::decode`: `Heartbeat` → `hb.record(now)`; `Reboot` → `info("reboot requested by child")`, `sys::reboot(Restart)`; `Poweroff` likewise. EOF on the pipe → close it. SIGCHLD → `reap()` until `None`; when the child's pid is reaped: `policy.on_exit(now)` → `RestartAfter(d)`: `info("child exited status={status} restart_in={d}s restarts={n}")` and schedule; `GiveUp`: `error("child exited status={status}; giving up after 3 restarts in 10min; awaiting watchdog reset")`, `gave_up = true`. When the restart time arrives: spawn, `hb.record(now)`, `info("child started pid={pid}")`. Every `PET_INTERVAL`: if `!gave_up && hb.healthy(now)` → `wd.pet(now)` (and `info("heartbeat restored")` if it had been lost); else log `warn("heartbeat lost; watchdog no longer petted")` once per loss. If `wd.expired(now)` (software fallback) → `error("software watchdog expired; rebooting")`, `sys::reboot(Restart)`. Signals: `Container` mode: SIGTERM/SIGINT → `kill(child, SIGTERM)`, wait up to 5 s, `exit(0)`; other modes: SIGINT → `sys::reboot(Restart)`, SIGTERM ignored with a warn. Log lines above are matched verbatim by the harness.
- Produces (`openfeo` binary, `#![forbid(unsafe_code)]`, deps `openfeo-init`, `anyhow`; dev-dep `tempfile`; `[features] harness = []`):
  - `cli`: `pub struct Cli { pub mode: Option<Mode>, pub print_version: bool }`; `pub fn parse(args: impl Iterator<Item = String>) -> Result<Cli, CliError>` (`--mode <m>`, `--version`; anything else → `CliError::Unknown(arg)`); `pub fn resolve_mode(flag: Option<Mode>, cmdline: Option<Mode>) -> Mode` = `flag.or(cmdline).unwrap_or_default()`.
  - `version`: `pub fn version() -> String` = `"{CARGO_PKG_VERSION}+{OPENFEO_BUILD_ID or "dev"}"` via `option_env!`.
  - `ports`: `pub struct Port { pub ifname: String, pub id: String, pub mac: String }`; `pub fn pci_id_from_device_path(canonical: &Path) -> Option<String>` (the last path component shaped `DDDD:BB:DD.F` → `pci-DDDD:BB:DD.F`); `pub fn enumerate(sysfs_class_net: &Path) -> io::Result<Vec<Port>>` (for each entry with a `device` symlink: canonicalize it, derive the id, read `address`; skip entries with no `device` or no PCI ancestor; sort by `id`).
  - `chaos`: `pub enum Chaos { ChildExit { after: Duration }, ChildHang { after: Duration } }`; `pub fn parse(value: &str) -> Result<Chaos, ChaosError>` (`child-exit:<secs>`, `child-hang:<secs>`); `pub fn from_cmdline(c: &Cmdline) -> Option<Chaos>` — `#[cfg(feature = "harness")]` reads `openfeo.chaos`; `#[cfg(not(feature = "harness"))]` always `None`.
  - `router`: `pub fn run(mode: Mode, cmdline: &Cmdline, version: &str) -> anyhow::Result<()>`: `Log::new("openfeo")`; `info("router mode={mode} version={version}")`; for each port (index `i` in sorted order) `info("port p{i} {ifname} id={id} mac={mac}")`, then `info("ports total={n}")`; if a chaos knob is set, `info("chaos {child-exit|child-hang} after={secs}s")`; then loop: send `Msg::Heartbeat` on `CtlPipe::from_env()` if present, apply chaos when due (`ChildExit` → `info("chaos child-exit: exiting with status 3")`, `process::exit(3)`; `ChildHang` → `info("chaos child-hang: heartbeats stopped")`, then sleep forever), sleep until the next heartbeat.
  - `main`: `if std::process::id() == 1 { openfeo_init::main(&version::version()) }`; else parse args, honour `--version` (prints `openfeo <version>`), read `/proc/cmdline` (empty `Cmdline` if unreadable), `resolve_mode`, `router::run`.

- [ ] **Step 1: Write the failing tests**

```rust
// cli.rs
#[test] fn flag_beats_cmdline() { assert_eq!(resolve_mode(Some(Mode::Vm), Some(Mode::Rescue)), Mode::Vm); }
#[test] fn cmdline_used_without_flag_and_default_is_metal() { assert_eq!(resolve_mode(None, Some(Mode::Vm)), Mode::Vm); assert_eq!(resolve_mode(None, None), Mode::Metal); }
#[test] fn parses_mode_flag_and_rejects_unknown() {
    assert_eq!(parse(["--mode".to_string(), "vm".to_string()].into_iter()).unwrap().mode, Some(Mode::Vm));
    assert!(parse(["--frob".to_string()].into_iter()).is_err());
}
// ports.rs  (build a fake sysfs in a tempdir: devices/pci0000:00/0000:00:04.0/virtio1, devices/pci0000:00/0000:00:03.0/virtio0,
//            devices/platform/fakenic; class/net/{eth0,eth1,eth2,lo}; device symlinks eth0→…/0000:00:04.0/virtio1,
//            eth1→…/0000:00:03.0/virtio0, eth2→…/platform/fakenic; lo has no device; address files hold MACs)
#[test] fn enumerates_pci_ports_sorted_by_bus_path_and_skips_the_rest() {
    let p = enumerate(&fake.join("class/net")).unwrap();
    assert_eq!(p.iter().map(|p| (&p.ifname[..], &p.id[..])).collect::<Vec<_>>(),
               vec![("eth1", "pci-0000:00:03.0"), ("eth0", "pci-0000:00:04.0")]);
    assert_eq!(p[0].mac, "52:54:00:fe:00:01");
}
#[test] fn pci_id_requires_a_bdf_component() {
    assert_eq!(pci_id_from_device_path(Path::new("/sys/devices/pci0000:00/0000:00:03.0/virtio0")), Some("pci-0000:00:03.0".into()));
    assert_eq!(pci_id_from_device_path(Path::new("/sys/devices/platform/fakenic")), None);
}
// chaos.rs
#[test] fn parses_knobs() { assert_eq!(parse("child-exit:3").unwrap(), Chaos::ChildExit { after: Duration::from_secs(3) }); assert_eq!(parse("child-hang:10").unwrap(), Chaos::ChildHang { after: Duration::from_secs(10) }); }
#[test] fn rejects_garbage() { assert!(parse("bogus").is_err()); assert!(parse("child-exit:x").is_err()); }
#[cfg(feature = "harness")] #[test] fn cmdline_knob_is_read_with_feature() { assert!(from_cmdline(&cmdline::parse("openfeo.chaos=child-exit:3").unwrap()).is_some()); }
#[cfg(not(feature = "harness"))] #[test] fn cmdline_knob_is_ignored_without_feature() { assert!(from_cmdline(&cmdline::parse("openfeo.chaos=child-exit:3").unwrap()).is_none()); }
```

- [ ] **Step 2: Run to verify they fail** — `cargo test -p openfeo --all-features` → compile errors.
- [ ] **Step 3: Implement** `supervisor.rs`, `lib.rs::main`, and the six binary modules.
- [ ] **Step 4: Run tests both ways and lint** — `cargo test -p openfeo --features harness && cargo test -p openfeo && make lint` → pass.
- [ ] **Step 5: Build the image binary and check it is static**

Add to `Makefile`:
```make
BIN := target/$(TARGET)/$(PROFILE)/openfeo
.PHONY: bin
bin:
	OPENFEO_BUILD_ID=$(BUILD_ID) cargo build -p openfeo --$(PROFILE) --target $(TARGET) $(if $(FEATURES),--features $(FEATURES))
```
Run: `make bin && file $(BIN) && ls -la $(BIN) && ./target/x86_64-unknown-linux-musl/release/openfeo --version`
Expected: `statically linked`; a few MB; `openfeo 0.1.0+<git hash>`.

- [ ] **Step 6: Host smoke** — `timeout 7 ./target/x86_64-unknown-linux-musl/release/openfeo --mode vm; echo "exit=$?"` → lines `openfeo: router mode=vm version=…`, one `port pN … id=pci-…` per physical NIC of the dev box, `ports total=N`; `exit=124` (killed by timeout while heartbeating into nothing).
- [ ] **Step 7: Commit** — `init+openfeo: PID 1 supervisor loop, router child with port map and chaos knobs`

---

### Task 6: Kernel 6.18.59 build with the embedded initramfs

**Files:**
- Create: `kernel/required.config`, `kernel/x86_64.config`, `kernel/linux-6.18.59.sha256`, `kernel/build.sh`, `docs/adr/0008-kernel-6.18-config-symbol-corrections.md`
- Modify: `Makefile` (kernel targets), `SPEC.md` §4.2 (symbol corrections, see Step 6)

**Interfaces:**
- Consumes: `make bin` → `target/x86_64-unknown-linux-musl/release/openfeo`.
- Produces: `build/bzImage` (EFI-stub bzImage with the initramfs built in); `kernel/build.sh {fetch|config|check|build|all} <binary>` driven by `make kernel`; `build/kernel/out/.config` for inspection.

- [ ] **Step 1: `kernel/linux-6.18.59.sha256`** — one line: `53a55ac9863a5547e292b8e381d4e4c2240dd1127d5428a7c44dbc550be23963  linux-6.18.59.tar.xz`.

- [ ] **Step 2: `kernel/required.config`** (universal; header comment: "Options every OpenFeO kernel must have. Verified by kernel/build.sh at build time and by the binary at boot (M1). Target-specific required options live in <arch>.config.")

```
# Boot, image, filesystems
CONFIG_BLK_DEV_INITRD=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_TMPFS=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_BINFMT_ELF=y
CONFIG_BLK_DEV=y
CONFIG_EXT4_FS=y
CONFIG_VFAT_FS=y
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_ISO8859_1=y
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
CONFIG_PSTORE=y
CONFIG_PRINTK_TIME=y
CONFIG_PANIC_ON_OOPS=y
CONFIG_PANIC_TIMEOUT=10
# Watchdog and clock
CONFIG_WATCHDOG=y
CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y
CONFIG_WATCHDOG_NOWAYOUT=y
CONFIG_RTC_CLASS=y
CONFIG_RTC_INTF_DEV=y
CONFIG_RTC_HCTOSYS=y
CONFIG_HW_RANDOM=y
CONFIG_HW_RANDOM_VIRTIO=y
# Networking core
CONFIG_NET=y
CONFIG_PACKET=y
CONFIG_UNIX=y
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_IP_ADVANCED_ROUTER=y
CONFIG_IP_MULTIPLE_TABLES=y
CONFIG_IPV6_MULTIPLE_TABLES=y
CONFIG_IPV6_SUBTREES=y
CONFIG_SYN_COOKIES=y
CONFIG_NETDEVICES=y
CONFIG_NET_CORE=y
CONFIG_ETHERNET=y
CONFIG_ETHTOOL_NETLINK=y
CONFIG_BRIDGE=y
CONFIG_BRIDGE_IGMP_SNOOPING=y
CONFIG_BRIDGE_VLAN_FILTERING=y
CONFIG_VLAN_8021Q=y
CONFIG_PPP=y
CONFIG_PPPOE=y
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_BLK=y
# Netfilter
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_NETFILTER_INGRESS=y
CONFIG_NETFILTER_NETLINK=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_CONNTRACK_MARK=y
CONFIG_NF_CONNTRACK_EVENTS=y
CONFIG_NF_CT_NETLINK=y
CONFIG_NF_NAT=y
CONFIG_NF_NAT_MASQUERADE=y
CONFIG_NF_LOG_SYSLOG=y
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
CONFIG_NF_TABLES_IPV4=y
CONFIG_NF_TABLES_IPV6=y
CONFIG_NFT_CT=y
CONFIG_NFT_NAT=y
CONFIG_NFT_MASQ=y
CONFIG_NFT_REDIR=y
CONFIG_NFT_FIB_IPV4=y
CONFIG_NFT_FIB_IPV6=y
CONFIG_NFT_FIB_INET=y
CONFIG_NFT_FLOW_OFFLOAD=y
CONFIG_NF_FLOW_TABLE=y
CONFIG_NF_FLOW_TABLE_INET=y
CONFIG_NFT_REJECT=y
CONFIG_NFT_REJECT_INET=y
CONFIG_NFT_LOG=y
CONFIG_NFT_LIMIT=y
CONFIG_NFT_QUOTA=y
CONFIG_NFT_HASH=y
CONFIG_NFT_NUMGEN=y
# NFT_COUNTER is not a symbol since 5.19: counters are part of the nf_tables core (ADR-0008).
# QoS
CONFIG_NET_SCHED=y
CONFIG_NET_SCH_CAKE=y
CONFIG_NET_SCH_FQ_CODEL=y
CONFIG_NET_SCH_DEFAULT=y
CONFIG_DEFAULT_FQ_CODEL=y
# Isolation primitives for post-MVP sidecars (cheap to keep)
CONFIG_CGROUPS=y
CONFIG_NAMESPACES=y
CONFIG_NET_NS=y
CONFIG_PID_NS=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_SECURITY=y
CONFIG_SECURITY_LANDLOCK=y
# Hardening
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_FORTIFY_SOURCE=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
# Nothing loadable, nothing pokeable
# CONFIG_MODULES is not set
# CONFIG_DEVMEM is not set
# CONFIG_KEXEC is not set
# CONFIG_MAGIC_SYSRQ is not set
# CONFIG_DEBUG_FS is not set
# CONFIG_PROC_KCORE is not set
```

- [ ] **Step 3: `kernel/x86_64.config`** (x86-required options from SPEC §4.2 plus the platform plumbing QEMU q35 and the N100 need)

```
# Architecture and platform
CONFIG_64BIT=y
CONFIG_SMP=y
CONFIG_PCI=y
CONFIG_PCI_MSI=y
CONFIG_PCI_MMCONFIG=y
CONFIG_PCIEPORTBUS=y
CONFIG_ACPI=y
CONFIG_ACPI_PROCESSOR=y
CONFIG_CPU_IDLE=y
CONFIG_HYPERVISOR_GUEST=y
CONFIG_PARAVIRT=y
CONFIG_KVM_GUEST=y
CONFIG_HIGH_RES_TIMERS=y
CONFIG_NO_HZ_IDLE=y
CONFIG_JUMP_LABEL=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_RANDOMIZE_MEMORY=y
CONFIG_MITIGATION_RETPOLINE=y
CONFIG_LEGACY_VSYSCALL_NONE=y
# Console
CONFIG_TTY=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_VT=y
CONFIG_VT_CONSOLE=y
# Firmware interfaces
CONFIG_EFI=y
CONFIG_EFI_STUB=y
CONFIG_EFIVAR_FS=y
CONFIG_EFI_VARS_PSTORE=y
CONFIG_RTC_DRV_CMOS=y
# Watchdogs: N100 (iTCO) and QEMU (i6300esb)
CONFIG_ITCO_WDT=y
CONFIG_I6300ESB_WDT=y
# NICs: Intel igc/igb/e1000e, Realtek r8169 (selects FW_LOADER; no firmware files are shipped), virtio
CONFIG_NET_VENDOR_INTEL=y
CONFIG_IGC=y
CONFIG_IGB=y
CONFIG_E1000E=y
CONFIG_NET_VENDOR_REALTEK=y
CONFIG_R8169=y
CONFIG_VIRTIO_PCI=y
# CONFIG_VIRTIO_PCI_LEGACY is not set
# Telemetry
CONFIG_HWMON=y
CONFIG_SENSORS_CORETEMP=y
# Compression of the kernel and the built-in initramfs
CONFIG_KERNEL_ZSTD=y
CONFIG_RD_ZSTD=y
CONFIG_INITRAMFS_COMPRESSION_ZSTD=y
# CONFIG_RD_GZIP is not set
# CONFIG_RD_BZIP2 is not set
# CONFIG_RD_LZMA is not set
# CONFIG_RD_XZ is not set
# CONFIG_RD_LZO is not set
# CONFIG_RD_LZ4 is not set
# Identity
CONFIG_LOCALVERSION="-openfeo"
# CONFIG_LOCALVERSION_AUTO is not set
CONFIG_DEFAULT_HOSTNAME="openfeo"
# Not wanted
# CONFIG_IA32_EMULATION is not set
# CONFIG_MICROCODE is not set
# CONFIG_SWAP is not set
```
Deferred on purpose (noted in a trailing comment): framebuffer console, USB/HID, NVMe/AHCI/eMMC, cpufreq arrive with M5's metal boot.

- [ ] **Step 4: `kernel/build.sh`**

`set -euo pipefail`; `ROOT` = repo root; inputs from env with defaults `KERNEL_VERSION=6.18.59`, `BUILD=$ROOT/build`; derived `SRC=$BUILD/kernel/linux-$KERNEL_VERSION`, `OUT=$BUILD/kernel/out`, `TARBALL=$BUILD/kernel/linux-$KERNEL_VERSION.tar.xz`, `URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz`. Subcommands:
- `fetch`: download `TARBALL` if absent (`curl -fL --retry 3`); `(cd $BUILD/kernel && sha256sum -c $ROOT/kernel/linux-$KERNEL_VERSION.sha256)`; extract into `$BUILD/kernel` if `$SRC/Makefile` is absent.
- `config <binary>`: write `$OUT/initramfs.list` with absolute paths:
  ```
  dir /dev 0755 0 0
  nod /dev/console 0600 0 0 c 5 1
  dir /proc 0755 0 0
  dir /sys 0755 0 0
  dir /run 0755 0 0
  dir /state 0700 0 0
  dir /boot 0755 0 0
  dir /tmp 1777 0 0
  file /init <absolute path of binary> 0755 0 0
  ```
  write `$OUT/local.config` containing `CONFIG_INITRAMFS_SOURCE="$OUT/initramfs.list"`; then `(cd $SRC && ARCH=x86_64 scripts/kconfig/merge_config.sh -n -O $OUT $ROOT/kernel/required.config $ROOT/kernel/x86_64.config $OUT/local.config)`; then run `check`.
- `check`: for every non-comment line `CONFIG_X=<v>` in the two fragments require the identical line in `$OUT/.config`; for every `# CONFIG_X is not set` line require that `$OUT/.config` has no `CONFIG_X=y|m`. Print `kernel config: <line> requested but not in final .config (check its dependencies)` per miss; exit 1 if any.
- `build`: `make -C $SRC O=$OUT ARCH=x86_64 CC="ccache gcc" HOSTCC="ccache gcc" KBUILD_BUILD_USER=openfeo KBUILD_BUILD_HOST=openfeo KBUILD_BUILD_TIMESTAMP="$(date -u -d @${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)})" -j$(nproc) bzImage`; copy `$OUT/arch/x86/boot/bzImage` to `$BUILD/bzImage`.
- `all <binary>`: fetch, config, build.

Makefile additions:
```make
.PHONY: kernel-src kernel
kernel-src:
	KERNEL_VERSION=$(KERNEL_VERSION) BUILD=$(BUILD) kernel/build.sh fetch
kernel: bin kernel-src
	KERNEL_VERSION=$(KERNEL_VERSION) BUILD=$(BUILD) kernel/build.sh config $(CURDIR)/$(BIN)
	KERNEL_VERSION=$(KERNEL_VERSION) BUILD=$(BUILD) kernel/build.sh build
```

- [ ] **Step 5: Run the config step and make the check pass**

Run: `make bin kernel-src && KERNEL_VERSION=6.18.59 BUILD=$PWD/build kernel/build.sh config $PWD/target/x86_64-unknown-linux-musl/release/openfeo`
Expected: `merge_config.sh` prints no "Value requested for … not in final .config" and `check` exits 0. For each miss: open `scripts/kconfig/merge_config.sh`'s warning for the symbol, find its `depends on` in the Kconfig (`grep -rn "^config SYMBOL" -A8 build/kernel/linux-6.18.59`), add the missing dependency to the appropriate fragment, re-run. A symbol that no longer exists in 6.18 is removed from the fragment and recorded in Step 6.

- [ ] **Step 6: ADR-0008 and SPEC §4.2 corrections**

`docs/adr/0008-kernel-6.18-config-symbol-corrections.md`: SPEC §4.2 lists `NFT_COUNTER` (merged into the nf_tables core in 5.19) and `RANDOM_TRUST_CPU` (removed in 6.2; the kernel trusts the CPU RNG by default, `random.trust_cpu=off` disables it) plus anything Step 5 turned up. Decision: `required.config` is authoritative; §4.2's non-exhaustive list is corrected to match. Update §4.2 accordingly.

- [ ] **Step 7: Build and smoke-boot**

Run: `make kernel && ls -la build/bzImage` → a bzImage of roughly 10–15 MiB (first build takes a few minutes; `ccache` makes rebuilds fast; a binary-only change relinks in well under a minute).
Run:
```bash
timeout 60 qemu-system-x86_64 -nodefaults -display none -machine q35,accel=kvm -cpu host -smp 2 -m 128M \
  -kernel build/bzImage -append "console=ttyS0,115200 openfeo.mode=vm panic=10 printk.devkmsg=on" \
  -serial stdio -monitor none -device i6300esb -action watchdog=reset -device virtio-rng-pci \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 | tee build/smoke.log
```
Expected in order: `Linux version 6.18.59-openfeo`, `openfeo-init: start version=0.1.0+… mode=vm slot=none`, `openfeo-init: watchdog /dev/watchdog0 timeout=60s`, `openfeo-init: child started pid=`, `openfeo: router mode=vm version=`, `openfeo: port p0 eth0 id=pci-0000:00:0?.0 mac=`, `openfeo: ports total=1`; no `child exited`; QEMU killed by `timeout` after 60 s with no watchdog reset having happened (only one `Linux version` line).
Debugging guide: no output at all → serial console options; `No working init found` → initramfs list or `BINFMT_ELF`; `Attempted to kill init` → the binary is not static or crashed (add `-no-reboot` to keep the panic on screen); `watchdog none, software fallback` → `I6300ESB_WDT`/PCI.

- [ ] **Step 8: Commit** — `kernel: 6.18.59 from allnoconfig + fragments, built-in initramfs, build.sh and make targets` (the `build/` tree is ignored; only `kernel/`, `Makefile`, the ADR and SPEC change are committed).

---

### Task 7: Harness core — sandbox, netns, taps, lab, scenario runner

**Files:**
- Modify: `harness/Cargo.toml` (deps `anyhow`, `nix`, `libc`, `regex`, `clap`; `[[test]] name = "m0" path = "tests/m0.rs" harness = false`)
- Create: `harness/src/{lib,sandbox,netns,tun,lab,scenario}.rs`, `harness/tests/m0.rs`

**Interfaces:**
- Produces:
  - `sandbox::enter() -> anyhow::Result<()>`: idempotent (returns `Ok` if `OPENFEO_HARNESS_SANDBOXED=1`); must be called before any thread exists. `unshare(CLONE_NEWUSER)`; write `0 <euid> 1` to `/proc/self/uid_map`, `deny` to `/proc/self/setgroups`, `0 <egid> 1` to `/proc/self/gid_map`; `unshare(CLONE_NEWNS | CLONE_NEWNET)`; `mount(None, "/", None, MS_REC | MS_PRIVATE, None)`; mount `tmpfs` on `/run` (`mode=0755`); create `/run/netns`, `/run/kea`, `/run/openfeo-harness`; `ip link set lo up`; set the env var. `sandbox::hint(err: &nix::Error) -> Option<&'static str>`: `EPERM`/`EACCES` → text naming `/proc/sys/user/max_user_namespaces` and `kernel.apparmor_restrict_unprivileged_userns` (Ubuntu); otherwise `None`.
  - `netns::NetNs { pub name: String }`: `NetNs::create(name: &str) -> Result<NetNs>` (`ip netns add`, then `ip -n <name> link set lo up`); `path(&self) -> PathBuf` (`/run/netns/<name>`); `ip(&self, args: &[&str]) -> Result<String>` (runs `ip -n <name> <args>`, returns stdout, error text includes stderr); `command(&self, program: &str) -> Command` (with `pre_exec` doing `setns(open(path), CloneFlags::CLONE_NEWNET)`); `add_tap(&self, ifname: &str, addr_cidr: Option<&str>) -> Result<OwnedFd>` (`ip -n … tuntap add <ifname> mode tap vnet_hdr`; optional `addr add`; `link set <ifname> up`; then `tun::open_in_netns`); `Drop` → `ip netns del <name>`, errors ignored.
  - `tun::open_in_netns(ns_path: &Path, ifname: &str) -> Result<OwnedFd>`: on a scoped thread: `setns`, open `/dev/net/tun` (`O_RDWR | O_CLOEXEC`), `ioctl(TUNSETIFF)` with `ifr_name = ifname`, `ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR`; return the fd (fds are process-wide; the thread's netns dies with it). The only `unsafe` in the harness lives here.
  - `lab::Lab { pub isp0: NetNs, pub isp1: NetNs, pub lan0: NetNs, pub run_dir: PathBuf, taps: Vec<OwnedFd>, name: String }` (Task 8 adds `pub vm: Option<qemu::Vm>`, Task 10 adds `pub daemons: Vec<daemons::Daemon>`); constants `ISP0_ADDR = "203.0.113.1/24"`, `ISP1_ADDR = "198.51.100.1/24"`, `MACS = ["52:54:00:fe:00:00", "52:54:00:fe:00:01", "52:54:00:fe:00:02"]`, `BOOT_TIMEOUT = 90 s`; `Lab::new(name: &str) -> Result<Lab>` creates netns `<name>-isp0`, `<name>-isp1`, `<name>-lan0`, taps `wan0` (isp0, `ISP0_ADDR`), `wan1` (isp1, `ISP1_ADDR`), `lan0` (lan0, no address), `run_dir = /run/openfeo-harness/<name>`; `Lab::kernel_path() -> Result<PathBuf>` (`OPENFEO_KERNEL` env, else `<workspace root>/build/bzImage`; error text `kernel image not found at …; run \`make kernel\` first`). `boot` is added in Task 8.
  - `scenario::Scenario { pub name: &'static str, pub run: fn(&mut Lab) -> anyhow::Result<()> }`; `scenario::select<'a>(all: &'a [Scenario], filter: Option<&str>) -> Vec<&'a Scenario>` (substring match on name; `None` → all); `scenario::run_all(all: &[Scenario], filter: Option<&str>) -> ExitCode`: for each selected scenario, `Lab::new("lab")`, run, print `scenario <name> ... ok (<secs>s)` or `... FAILED`, on failure print the error chain and, once Tasks 8 and 10 add them, the last 80 console lines and each daemon's last 20 log lines; finish with `result: ok|FAILED. <n> passed; <m> failed`.
  - `tests/m0.rs`: `fn main() -> ExitCode { if let Err(e) = sandbox::enter() { eprintln!("{e:#}"); return ExitCode::FAILURE } run_all(&SCENARIOS, std::env::args().nth(1).as_deref()) }` with `SCENARIOS` starting as `[lab_topology]`.

- [ ] **Step 1: Write the failing unit tests** (`sandbox.rs`, `scenario.rs`)

```rust
#[test] fn eperm_gets_a_userns_hint() { assert!(sandbox::hint(&nix::Error::EPERM).unwrap().contains("user namespaces")); assert!(sandbox::hint(&nix::Error::ENOENT).is_none()); }
#[test] fn select_filters_by_substring() {
    fn noop(_: &mut Lab) -> anyhow::Result<()> { Ok(()) }
    let all = [Scenario { name: "boots_and_logs", run: noop }, Scenario { name: "lab_topology", run: noop }];
    assert_eq!(select(&all, Some("topo")).iter().map(|s| s.name).collect::<Vec<_>>(), ["lab_topology"]);
    assert_eq!(select(&all, None).len(), 2);
}
```

- [ ] **Step 2: Run to verify they fail** — `cargo test -p openfeo-harness --lib` → compile errors.
- [ ] **Step 3: Implement** the five modules and `tests/m0.rs` with the `lab_topology` scenario:

```rust
fn lab_topology(lab: &mut Lab) -> anyhow::Result<()> {
    anyhow::ensure!(lab.isp0.ip(&["-4", "addr", "show", "wan0"])?.contains("203.0.113.1/24"));
    anyhow::ensure!(lab.isp1.ip(&["-4", "addr", "show", "wan1"])?.contains("198.51.100.1/24"));
    anyhow::ensure!(lab.lan0.ip(&["link", "show", "lan0"])?.contains("lan0"));
    Ok(())
}
```

- [ ] **Step 4: Run** — `cargo test -p openfeo-harness --lib` → pass; `cargo test -p openfeo-harness --test m0` → `scenario lab_topology ... ok`, exit 0; afterwards `ip netns list` on the host shows nothing (the lab lived in the sandbox's own namespaces). `make lint` → clean, which also proves `harness/clippy.toml` lifts the `Command` ban for this crate.
- [ ] **Step 5: Commit** — `harness: rootless sandbox, named netns with taps, lab topology, scenario runner`

---

### Task 8: Harness — console capture, QEMU, `boots_and_logs`

**Files:**
- Create: `harness/src/lines.rs`, `harness/src/qemu.rs`
- Modify: `harness/src/lab.rs` (`boot`), `harness/tests/m0.rs`

**Interfaces:**
- Produces:
  - `lines::Lines` (cloneable handle over a thread that reads a `Read` line by line): `Lines::capture(reader: impl Read + Send + 'static, tee_prefix: Option<String>) -> Lines` (echoes lines to stderr with the prefix when `tee_prefix` is `Some` or `OPENFEO_HARNESS_VERBOSE=1`); `pub struct Cursor(usize)` (`Default`); `pub struct Match { pub line: String, pub groups: Vec<Option<String>> }`; `wait_for(&self, cur: &mut Cursor, re: &Regex, timeout: Duration) -> anyhow::Result<Match>` (scans from the cursor, advances it past the matching line; error text includes the pattern and the last 20 lines on timeout); `count(&self, re: &Regex) -> usize`; `tail(&self, n: usize) -> Vec<String>`.
  - `qemu::BASE_CMDLINE = "console=ttyS0,115200 openfeo.mode=vm panic=10 printk.devkmsg=on"`; `qemu::Nic { pub id: String, pub tap: OwnedFd, pub mac: String }`; `qemu::ConsoleMode { Captured, Interactive }`; `qemu::VmSpec { pub kernel: PathBuf, pub cmdline: String, pub mem_mib: u32, pub cpus: u32, pub nics: Vec<Nic>, pub console: ConsoleMode }`; `qemu::accel() -> &'static str` (`"kvm"` if `/dev/kvm` opens read-write, else `"tcg"`); `qemu::build_args(spec: &VmSpec) -> Vec<OsString>`: `-nodefaults -display none -machine q35,accel=<accel> -cpu <host|max> -smp <cpus> -m <mem>M -kernel <kernel> -append <cmdline> -serial stdio -monitor none -device i6300esb -action watchdog=reset -device virtio-rng-pci` then per NIC `i`: `-netdev tap,id=<id>,fd=<3+i> -device virtio-net-pci,netdev=<id>,mac=<mac>`; Interactive uses `-serial mon:stdio` instead of `-serial stdio -monitor none`; `qemu::Vm { child: Child, pub console: Option<Lines> }`; `Vm::start(spec: VmSpec) -> Result<Vm>` (`pre_exec` dup2s each tap onto `3+i`; Captured pipes stdout into `Lines::capture(.., Some("[vm]".into()))` only when verbose, otherwise `None` prefix; Interactive inherits stdio); `kill(&mut self)`; `wait(&mut self) -> Result<ExitStatus>`; `Drop` kills.
  - `Lab::boot(&mut self, extra_cmdline: &str) -> Result<&qemu::Vm>`: error if already booted; dups the three taps into `Nic`s with `MACS`, `cmdline = BASE_CMDLINE + " " + extra`, `mem_mib = 128`, `cpus = 2`, Captured; `Lab::console(&self) -> Result<&Lines>`.

- [ ] **Step 1: Write the failing unit tests**

```rust
// lines.rs
#[test] fn wait_for_captures_and_advances() {
    let (r, mut w) = std::io::pipe().unwrap(); let lines = Lines::capture(r, None); let mut cur = Cursor::default();
    w.write_all(b"noise\n[    0.5] openfeo-init: start version=0.1.0+abc mode=vm slot=none\n").unwrap();
    let m = lines.wait_for(&mut cur, &Regex::new(r"openfeo-init: start version=(\S+) mode=(\w+)").unwrap(), Duration::from_secs(2)).unwrap();
    assert_eq!(m.groups[0].as_deref(), Some("0.1.0+abc")); assert_eq!(m.groups[1].as_deref(), Some("vm"));
    assert!(lines.wait_for(&mut cur, &Regex::new("openfeo-init: start").unwrap(), Duration::from_millis(100)).is_err());
    w.write_all(b"openfeo-init: start again\n").unwrap();
    assert!(lines.wait_for(&mut cur, &Regex::new("openfeo-init: start").unwrap(), Duration::from_secs(2)).is_ok());
    assert_eq!(lines.count(&Regex::new("openfeo-init: start").unwrap()), 2);
}
// qemu.rs
#[test] fn args_include_watchdog_and_inherited_tap_fds() {
    let (a, _b) = std::io::pipe().unwrap(); let (c, _d) = std::io::pipe().unwrap();
    let spec = VmSpec { kernel: "k".into(), cmdline: BASE_CMDLINE.into(), mem_mib: 128, cpus: 2, console: ConsoleMode::Captured,
        nics: vec![Nic { id: "p0".into(), tap: a.into(), mac: "52:54:00:fe:00:00".into() }, Nic { id: "p1".into(), tap: c.into(), mac: "52:54:00:fe:00:01".into() }] };
    let args: Vec<String> = build_args(&spec).iter().map(|s| s.to_string_lossy().into_owned()).collect();
    assert!(args.windows(2).any(|w| w == ["-action", "watchdog=reset"]));
    assert!(args.contains(&"tap,id=p0,fd=3".to_string())); assert!(args.contains(&"tap,id=p1,fd=4".to_string()));
    assert!(args.contains(&"virtio-net-pci,netdev=p1,mac=52:54:00:fe:00:01".to_string()));
}
```

- [ ] **Step 2: Run to verify they fail** — compile errors.
- [ ] **Step 3: Implement** `lines.rs`, `qemu.rs`, `Lab::boot`, and the scenario:

```rust
fn boots_and_logs(lab: &mut Lab) -> anyhow::Result<()> {
    lab.boot("")?; let c = lab.console()?; let mut cur = Cursor::default();
    let m = c.wait_for(&mut cur, &re(r"openfeo-init: start version=(\S+) mode=vm slot=none"), BOOT_TIMEOUT)?;
    anyhow::ensure!(m.groups[0].as_deref().is_some_and(|v| v.starts_with("0.1.0+")));
    c.wait_for(&mut cur, &re(r"openfeo-init: watchdog /dev/watchdog0 timeout=60s"), Duration::from_secs(10))?;
    c.wait_for(&mut cur, &re(r"openfeo-init: child started pid=\d+"), Duration::from_secs(10))?;
    c.wait_for(&mut cur, &re(r"openfeo: router mode=vm version=0\.1\.0\+"), Duration::from_secs(10))?;
    c.wait_for(&mut cur, &re(r"openfeo: ports total=3"), Duration::from_secs(10))?;
    anyhow::ensure!(c.count(&re(r"openfeo: port p[0-2] eth\d id=pci-0000:00:[0-9a-f]{2}\.0 mac=52:54:00:fe:00:0[0-2]")) == 3);
    anyhow::ensure!(c.count(&re(r"openfeo-init: child exited")) == 0);
    Ok(())
}
```
Add it to `SCENARIOS`.

- [ ] **Step 4: Run** — `cargo test -p openfeo-harness --lib` → pass; `make kernel && cargo test -p openfeo-harness --test m0` → `lab_topology` and `boots_and_logs` ok; `OPENFEO_HARNESS_VERBOSE=1 cargo test -p openfeo-harness --test m0 boots` streams the VM console. `make lint` clean.
- [ ] **Step 5: Commit** — `harness: serial console expectations, QEMU driver, boots_and_logs scenario`

---

### Task 9: Chaos scenarios — child restart and watchdog reset

**Files:**
- Modify: `harness/tests/m0.rs`

**Interfaces:**
- Consumes: `openfeo.chaos=child-exit:<s>|child-hang:<s>` (Task 5, `harness` feature), supervisor log lines (Task 5), `Lab::boot(extra)` (Task 8).

- [ ] **Step 1: Add the two scenarios**

```rust
fn child_restart_after_exit(lab: &mut Lab) -> anyhow::Result<()> {
    lab.boot("openfeo.chaos=child-exit:3")?; let c = lab.console()?; let mut cur = Cursor::default();
    let first = c.wait_for(&mut cur, &re(r"openfeo-init: child started pid=(\d+)"), BOOT_TIMEOUT)?.groups[0].clone();
    c.wait_for(&mut cur, &re(r"openfeo: chaos child-exit: exiting with status 3"), Duration::from_secs(15))?;
    c.wait_for(&mut cur, &re(r"openfeo-init: child exited status=exit\(3\) restart_in=1s restarts=1"), Duration::from_secs(10))?;
    let second = c.wait_for(&mut cur, &re(r"openfeo-init: child started pid=(\d+)"), Duration::from_secs(10))?.groups[0].clone();
    anyhow::ensure!(first != second, "restarted child must have a new pid");
    c.wait_for(&mut cur, &re(r"openfeo: router mode=vm"), Duration::from_secs(10))?;
    Ok(())
}
fn watchdog_resets_when_heartbeat_stops(lab: &mut Lab) -> anyhow::Result<()> {
    lab.boot("openfeo.chaos=child-hang:3")?; let c = lab.console()?; let mut cur = Cursor::default();
    c.wait_for(&mut cur, &re(r"openfeo: chaos child-hang: heartbeats stopped"), BOOT_TIMEOUT)?;
    c.wait_for(&mut cur, &re(r"openfeo-init: heartbeat lost; watchdog no longer petted"), Duration::from_secs(30))?;
    c.wait_for(&mut cur, &re(r"Linux version 6\.18\.59-openfeo"), Duration::from_secs(120))?;   // the second boot banner
    c.wait_for(&mut cur, &re(r"openfeo-init: start version="), BOOT_TIMEOUT)?;
    anyhow::ensure!(c.count(&re(r"Linux version 6\.18\.59-openfeo")) == 2);
    Ok(())
}
```

- [ ] **Step 2: Run** — `cargo test -p openfeo-harness --test m0` → four scenarios ok. The watchdog scenario legitimately takes about two minutes (3 s hang + 20 s grace + up to 60 s until the i6300esb fires + reboot).
- [ ] **Step 3: Commit** — `harness: child restart and watchdog reset scenarios`

---

### Task 10: ISP reference daemon — Kea DHCPv4 in the ISP namespace

**Files:**
- Create: `harness/src/daemons.rs`, `harness/fixtures/kea-dhcp4.json.tmpl`
- Modify: `harness/src/lib.rs`, `harness/tests/m0.rs`

**Interfaces:**
- Produces: `daemons::Daemon { pub name: String, child: Child, pub log: Lines }`; `Daemon::spawn(ns: &NetNs, name: &str, cmd: Command) -> Result<Daemon>` (stdout and stderr piped into one `Lines` with tee prefix `[<name>]` when verbose); `is_running(&mut self) -> bool`; `Drop` → SIGTERM, 2 s grace, SIGKILL. `daemons::kea_dhcp4(ns: &NetNs, iface: &str, run_dir: &Path) -> Result<Daemon>`: renders the template (`{{IFACE}}` → iface) to `<run_dir>/kea-dhcp4.json`, env `KEA_LOCKFILE_DIR=<run_dir>`, `KEA_PIDFILE_DIR=<run_dir>`, command `kea-dhcp4 -c <file>` in `ns`. Template:

```json
{ "Dhcp4": {
  "interfaces-config": { "interfaces": [ "{{IFACE}}" ] },
  "lease-database": { "type": "memfile", "persist": false },
  "valid-lifetime": 600, "renew-timer": 300, "rebind-timer": 450,
  "subnet4": [ { "id": 1, "subnet": "203.0.113.0/24",
    "pools": [ { "pool": "203.0.113.100 - 203.0.113.200" } ],
    "option-data": [ { "name": "routers", "data": "203.0.113.1" },
                     { "name": "domain-name-servers", "data": "203.0.113.1" } ] } ]
} }
```
No `loggers` block: Kea's default is stdout at INFO, and the block's key name differs between Kea 2.4 (Ubuntu runners) and 3.2 (the dev host).

- [ ] **Step 1: Write the failing unit test** — `#[test] fn template_renders_iface() { assert!(render_kea_dhcp4("wan0").contains("\"interfaces\": [ \"wan0\" ]")); }` (`pub fn render_kea_dhcp4(iface: &str) -> String` over `include_str!`).
- [ ] **Step 2: Run to verify it fails**, then implement `daemons.rs`.
- [ ] **Step 3: Add the scenario**

```rust
fn isp_kea_dhcp4_starts(lab: &mut Lab) -> anyhow::Result<()> {
    let run_dir = lab.run_dir.clone();
    let mut d = daemons::kea_dhcp4(&lab.isp0, "wan0", &run_dir)?; let mut cur = Cursor::default();
    d.log.wait_for(&mut cur, &re(r"DHCP4_STARTED"), Duration::from_secs(15))?;
    anyhow::ensure!(d.is_running(), "kea-dhcp4 exited after announcing start");
    lab.daemons.push(d);
    Ok(())
}
```

- [ ] **Step 4: Run** — `cargo test -p openfeo-harness --lib && cargo test -p openfeo-harness --test m0 kea` → ok. If Kea refuses to start inside the user namespace, its stdout (printed on failure) says why; the expected fixes are a missing `/run/kea` directory or lock-file path, both owned by the sandbox.
- [ ] **Step 5: Commit** — `harness: Kea DHCPv4 reference server in the ISP namespace`

---

### Task 11: `openfeo-harness` binary, `make run`, `make test-harness`, `make ci`

**Files:**
- Create: `harness/src/main.rs`
- Modify: `Makefile`, `CLAUDE.md` if any command name changed

**Interfaces:**
- Produces: `openfeo-harness run [--kernel <path>] [--chaos <spec>]` — `sandbox::enter`, `Lab::new("run")`, Kea in `isp0`, boot with `ConsoleMode::Interactive` and the extra cmdline `openfeo.chaos=<spec>` when given, wait for QEMU to exit (Ctrl-A x), clean up. `openfeo-harness check` — prints one line per requirement with `ok`/`MISSING`: `/dev/kvm` writable (else "tcg fallback"), `/dev/net/tun`, `qemu-system-x86_64`, `ip`, `kea-dhcp4` on `PATH`, unprivileged user namespaces (`sandbox::enter` in a forked child via `nix::unistd::fork`, reporting its exit status), the kernel image path; exits 1 if anything other than KVM is missing.

Makefile additions:
```make
.PHONY: run test-harness check-env ci
run: kernel
	cargo run -q -p openfeo-harness -- run --kernel $(BUILD)/bzImage
test-harness: kernel
	OPENFEO_KERNEL=$(BUILD)/bzImage cargo test -p openfeo-harness --test m0 -- $(FILTER)
check-env:
	cargo run -q -p openfeo-harness -- check
ci: lint test kernel test-harness
```

- [ ] **Step 1: Implement `main.rs` with clap derive** (`Cli { #[command(subcommand)] cmd: Cmd }`, `Cmd::Run { kernel: Option<PathBuf>, chaos: Option<String> }`, `Cmd::Check`).
- [ ] **Step 2: Verify** — `make check-env` → all `ok`. `timeout 30 make run` → the VM boots on your terminal and prints the `openfeo-init:` and `openfeo:` lines; exit by timeout is fine. `make test-harness FILTER=topology` → runs only `lab_topology`.
- [ ] **Step 3: Lint and commit** — `make lint`; `harness: interactive run and environment check; make run/test-harness/ci`

---

### Task 12: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `make lint`, `make test`, `make kernel`, `make test-harness`, `kernel/build.sh` cache layout (`build/kernel/linux-6.18.59.tar.xz`, `~/.cache/ccache`).

- [ ] **Step 1: Write the workflow**

```yaml
name: ci
on: { push: { branches: [main] }, pull_request: {} }
jobs:
  lint-and-unit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: x86_64-unknown-linux-musl, components: "clippy, rustfmt" }
      - uses: taiki-e/install-action@cargo-deny
      - run: make lint
      - run: make test
  kernel-and-harness:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: x86_64-unknown-linux-musl }
      - run: sudo apt-get update && sudo apt-get install -y qemu-system-x86 kea-dhcp4-server iproute2 bc flex bison libelf-dev libssl-dev ccache zstd cpio
      - name: allow KVM and user namespaces for the runner user
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' | sudo tee /etc/udev/rules.d/99-kvm4all.rules
          sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm
          sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
      - uses: actions/cache@v4
        with:
          path: |
            build/kernel/linux-6.18.59.tar.xz
            ~/.cache/ccache
          key: kernel-${{ hashFiles('kernel/**') }}
          restore-keys: kernel-
      - run: make kernel
      - run: make check-env
      - run: make test-harness
```

- [ ] **Step 2: Verify locally** — `python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/ci.yml"))'` parses; `make ci` runs lint, unit tests, kernel and all five scenarios green from a clean `build/` (`rm -rf build target` first; note the wall time). Running it on GitHub needs the repository pushed to the organisation still to be chosen (SPEC §15); until then `make ci` is the acceptance gate.
- [ ] **Step 3: Commit** — `ci: GitHub Actions workflow mirroring make ci`

---

## Self-review notes

- Spec coverage for M0 (§12): workspace ✔ (T2), CI ✔ (T12), `required.config` ✔ (T6), x86 kernel build ✔ (T6), initramfs ✔ (T6), PID 1 mounts/watchdog/supervisor/console log ✔ (T4–T5), harness with one ISP namespace and a LAN namespace ✔ (T7, T10 populates the ISP namespace), `openfeo.mode=vm` ✔ (T2, T5). Acceptance: boots to PID 1 and logs version and port map ✔ (T8), child restart after kill ✔ (T9), watchdog reboot when heartbeats stop ✔ (T9). "In CI" is satisfied by `make ci` locally and the workflow file; the hosted run waits on the GitHub organisation decision.
- Interface names are used consistently: `Mode`, `Cmdline::get`, `Heartbeat::{new,record,healthy}`, `RestartPolicy::on_exit`, `Decision`, `ctl::{Msg,decode,CtlPipe}`, `mounts::{EARLY,STATE_FALLBACK,classify}`, `Watchdog::{open,pet,expired,describe}`, `openfeo_init::main`, `cli::resolve_mode`, `ports::enumerate`, `chaos::from_cmdline`, `Lines::{capture,wait_for,count,tail}`, `Cursor`, `qemu::{build_args,VmSpec,Nic,Vm}`, `Lab::{new,boot,console,kernel_path}`, `daemons::kea_dhcp4`, `scenario::{Scenario,select,run_all}`.
- The five Review Focus items each have a named test in T2, T4, T4, T5, T5.
- Plan's own calls (not the user's): `/state` is a volatile tmpfs until M5; `/tmp` is mounted by PID 1; the core sysctl table; `Heartbeat::new` treats boot and each spawn as a heartbeat; give-up means no further restart as well as no petting; version string `0.1.0+<git describe>`; MACs `52:54:00:fe:00:0N`; TEST-NET addresses for the ISP sides; 128 MiB / 2 vCPUs for the lab VM; hardening and platform options added to the fragments beyond §4.2's list.
