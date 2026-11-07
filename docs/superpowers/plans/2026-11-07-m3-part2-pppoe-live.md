# M3 part 2: PPPoE live Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the PPPoE WAN of M3 part 1 live, end to end, against `pppoe-server` and `pppd` in the lab: the sandbox suite's PPP scenarios over a real kernel session, the `m3` QEMU suite on `vm-pppoe.toml`, and the environment (check-env, CI, the cloud setup) that runs them.

**Architecture:** Nothing of the router changes shape in this part: the cores, drivers, task, facts and reconcilers of part 1 stay as they are, and every fix this part finds is a bug fix with a test that failed first. What is built is the lab's access concentrator (rp-pppoe's `pppoe-server` spawning `pppd` per session, with its secrets on a tmpfs over `/etc/ppp` inside the sandbox), the harness helpers around it, and the scenarios the design and SPEC §12's M3 row name. Where the design hedges (whether `pppd` runs as the sandbox's mapped root, whether Kea's DHCPv6 server binds a PPP interface), a task starts with the spike that settles it and both branches are written down.

**Tech Stack:** Rust stable 2024, the harness crate (`openfeo-harness`), rp-pppoe 4.0 (`pppoe-server`, `pppoe`) and ppp 2.5.4 (`pppd`) on the host and `ppp`/`pppoe` packages on Ubuntu 24.04 (CI), QEMU, Kea DHCPv6 and radvd as in M2.

**Spec:** `docs/superpowers/specs/2026-11-07-m3-pppoe-design.md` (its Harness, Console, Parts and "After the whole-branch review" sections), SPEC §7.2, §11, §12 (the M3 row), §13; ADR-0023.

## Global Constraints

- Every source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton` (TOML/sh: `#`).
- Documentation ranges only: the ISP is `203.0.113.1`, the pool starts at `203.0.113.100`, IPv6 `2001:db8::/32`, ULA `fd12:3456:789a::/48`; the credentials are `openfeo@isp.example` / `example-secret` and nothing else.
- `std::process::Command` only in `harness/` and `image/`; no `unwrap`/`expect` outside tests; clippy `-D warnings` with pedantic as warnings (so effectively errors).
- The router's crates change only by a bug fix with a failing test first; no new console line without a line added to that module's contract test.
- Every scenario that needs `/dev/ppp` or the PPP modules skips with the udev rule in its reason where they are missing (`openfeo_net::pppoe::dev_ppp_unavailable`), and CI runs with `OPENFEO_NO_SKIP=1`, so it must not skip there.
- Commits `git commit -s`, identity `Andrew Newton <andy@vitri.ltd>`, subject `<area>: <summary>`; nothing is pushed and no PR is opened without the maintainer's word.
- Timings the scenarios rely on: the session core's `ECHO_INTERVAL` is 10 s and `ECHO_MISSES` 3 (`openfeo-proto-ppp::lcp`), so keepalive loss shows within 40 s; the task's backoff is 1 s doubling to 60 s (`crates/openfeo/src/pppoe.rs::Backoff`); `pppd`'s `lcp-echo-interval 5` and `lcp-echo-failure 3` make the ISP notice a dead router within 15 s.

## Review Focus

1. A session whose `pppd` ends with a Terminate-Request while IPCP is still negotiating (the ISP restarting mid-handshake): the task must report `terminated by peer`, withdraw nothing it never published, and retry on the ladder; pinned by `pppoe_server_stopped_by_sigterm_is_terminated_by_peer` run against a server that is stopped right after the PADS (Task 3, second variant).
2. The kernel's `pppoe` module tearing the session down on the AC's PADT before the task's discovery socket sees the frame: the console must say `padt from ac` or `session lost`, never spend a supervisor restart; pinned by `a_padt_from_the_ac_ends_the_session` asserting the fact is withdrawn and the next attempt begins (Task 3).
3. A port that loses carrier during discovery rather than during a session: the task waits for carrier and discovers again with a fresh Host-Uniq, no stale PADR; pinned by `carrier_loss_during_discovery_restarts_discovery` (Task 6).
4. The LAN host's TCP through the clamp when the ISP target's MTU is 1500 and the PPP MTU 1492: a 64 KiB body arrives intact with no fragmentation needed; pinned by `a_large_body_crosses_the_mss_clamp` (Task 5).
5. The password: no console line, no `pppd` log line the harness copies, no scenario message may carry `example-secret`; pinned by the `boot_pppoe` helper's final grep in every `m3` scenario (Task 5) and the sandbox bench's assertion on the session core's `Debug` output (Task 2).

---

### Task 1: The lab's access concentrator

**Files:**
- Modify: `harness/src/sandbox.rs` (a tmpfs over `/etc/ppp` when the directory exists, in `enter()` after the `/run` mount; `/run/pppd` added to `RUN_DIRS`)
- Modify: `harness/src/daemons.rs` (`PppoeServerConfig`, `Auth`, `render_pppd_options`, `write_ppp_secrets`, `pppoe_server`)
- Modify: `harness/src/lab.rs` (`start_pppoe_server`, `stop_pppoe_server`, `kill_pppoe_server`, `restart_pppoe_server`, `isp_ppp_ifname`, `pppd_log`)
- Modify: `harness/tests/pppoe.rs` (scenario `pppoe_server_answers_discovery_in_the_sandbox`)

**Interfaces:**
- Consumes: `Daemon::spawn(name, Command)`, `Daemon.log: Lines`, `NetNs::command`, `Lab.run_dir`, `Lab.isp0`, `Lab.daemons`, `openfeo_net::pppoe::Discovery` and `openfeo_proto_ppp::discovery::Client` as `harness/tests/pppoe.rs` already drives them.
- Produces:
  ```rust
  pub enum Auth { None, Pap, Chap }
  pub struct PppoeServerConfig {
      pub iface: String,        // "wan0" on isp0, "e1" in the sandbox
      pub ac_name: String,      // "isp"
      pub service: String,      // "" = any
      pub auth: Auth,
      pub mtu: u16,             // 1492 (the default) or 1500
      pub ipv6: bool,           // +ipv6 with ipv6 ::1,::2
      pub echo_interval_secs: u8, // 5
  }
  impl PppoeServerConfig { pub fn isp(iface: &str, auth: Auth) -> Self }   // ac "isp", service "", mtu 1492, ipv6 true, echo 5
  pub fn render_pppd_options(config: &PppoeServerConfig, log: &Path) -> String
  pub fn write_ppp_secrets(username: &str, password: &str) -> Result<()>   // /etc/ppp/pap-secrets and chap-secrets, 0600, "<user> * \"<password>\" *"; an empty /etc/ppp/options
  pub fn pppoe_server(ns: &NetNs, config: &PppoeServerConfig, run_dir: &Path) -> Result<Daemon>
  impl Lab {
      pub fn start_pppoe_server(&mut self, config: &PppoeServerConfig) -> Result<()>  // writes the secrets, spawns, waits for the server's own "listening on <iface>" line (or 1 s without one: rp-pppoe prints little), daemon name "pppoe-server-<iface>"
      pub fn stop_pppoe_server(&mut self) -> bool      // SIGTERM to the server and every pppd it spawned: Terminate-Request and PADT go out
      pub fn kill_pppoe_server(&mut self) -> bool      // SIGKILL to both: nothing goes out
      pub fn restart_pppoe_server(&mut self, config: &PppoeServerConfig) -> Result<()>
      pub fn pppd_log(&self) -> PathBuf                // <run_dir>/pppd-<iface>.log
      pub fn isp_ppp_ifname(&self, timeout: Duration) -> Result<String>   // "ppp<N>" from the log's "Using interface pppN" line, the last one
  }
  ```
- `render_pppd_options` produces exactly these lines, one per line, in this order: `nodetach`, `debug`, `logfile <log>`, `noauth` | `require-pap` | `require-chap`, `ms-dns 203.0.113.1`, `lcp-echo-interval <n>`, `lcp-echo-failure 3`, `mtu <mtu>`, `mru <mtu>`, `noipdefault`, `+ipv6` and `ipv6 ::1,::2` when `ipv6`, `nodefaultroute`, `proxyarp` omitted. The server command is `pppoe-server -F -I <iface> -C <ac_name> -S <service> -L 203.0.113.1 -R 203.0.113.100 -N 4 -O <options file> -X <pid file>` (an empty `-S` is omitted). `pppoe-server` forks `pppd` per session and `pppd` forks the `pppoe` helper: `stop_pppoe_server` sends SIGTERM to the server's process group, which it made with `Command::process_group(0)`, and `kill_pppoe_server` SIGKILL to the same group; both wait for the group to be gone (poll `kill(-pgid, 0)` for up to 5 s).
- The sandbox mounts `tmpfs` on `/etc/ppp` (mode 0755) when `/etc/ppp` exists, so `pppd` reads the lab's secrets and never the host's; `pppd`'s pid files go to `/run/pppd`? No: `pppd` writes `/var/run/ppp<N>.pid` and `/run` is the sandbox's tmpfs already, which is why nothing more is mounted; `/run/pppd` is dropped from `RUN_DIRS` if `pppd` 2.5.4 does not use it (check `strace -f -e openat` once in the spike; keep what it wants).

- [ ] **Step 1: Write the failing scenario** in `harness/tests/pppoe.rs`:

```rust
/// rp-pppoe's server runs as the sandbox's mapped root on the far veth end and answers our
/// discovery: the spike that part 2 rests on, and the proof that the lab's concentrator exists.
fn pppoe_server_answers_discovery_in_the_sandbox(lab: &mut Lab) -> anyhow::Result<()> {
    require_dev_ppp()?;                     // Skip with the udev rule where /dev/ppp cannot be opened
    let rig = Rig::create()?;               // e0 (client) / e1 (server), both up
    let config = PppoeServerConfig::isp(AC_IF, Auth::None);
    let server = daemons::pppoe_server_in_sandbox(&config, &lab.run_dir)?;   // same namespace: NetNs is not needed, so a variant without `ns`
    runtime()?.block_on(async {
        let mut bench = Bench::start_client_only(&rig, None)?;   // the near socket and the core; no scripted AC
        let outputs = bench.run_until(SOON, is_session).await?;
        let Some(Output::Session { id, ac_mac, ac_name, max_payload }) = outputs.last() else { anyhow::bail!("{outputs:?}") };
        ensure!(*ac_mac == rig.ac.1 && ac_name == "isp" && *id != 0 && max_payload.is_none(), "{outputs:?}");
        ensure!(server.log.count(&re("PADS")) >= 0);   // the server's own account, when it prints one
        anyhow::Ok(())
    })
}
```
`require_dev_ppp()` opens `/dev/ppp` read-write and returns `Err(Skip(...))` naming the udev rule on `PermissionDenied`/`NotFound`. `Bench::start_client_only` is `Bench::start` without the far socket (make `far: Option<Discovery>`).

- [ ] **Step 2: Run it**: `cargo test -q -p openfeo-harness --test pppoe -- pppoe_server` → FAIL: `pppoe_server_in_sandbox` and `PppoeServerConfig` do not exist.
- [ ] **Step 3: Implement** `daemons.rs` (the config, the renderers, `pppoe_server` and `pppoe_server_in_sandbox` sharing one `fn pppoe_server_command(cmd: Command, ...)`), `sandbox.rs` (the `/etc/ppp` tmpfs), `lab.rs` (the six methods). Unit tests in `daemons.rs`: `pppd_options_render_in_a_fixed_order` (the exact text for `Auth::Chap`, mtu 1500, ipv6 true) and `secrets_quote_the_password` (`"openfeo@isp.example" * "example-secret" *`). A unit test in `lab.rs` (or `daemons.rs`): `the_ppp_interface_comes_from_the_last_using_interface_line` over a two-session log excerpt.
- [ ] **Step 4: Run** `cargo test -q -p openfeo-harness --test pppoe` → PASS (4 scenarios, the new one live), and `cargo test -q -p openfeo-harness --lib` → the three unit tests PASS. If the server does not answer, read `pppd`'s and the server's logs with `OPENFEO_TRACE=1`: the likely causes are `pppoe-server` refusing to run unprivileged (it checks `geteuid() == 0`, which the mapped root satisfies) and the `pppoe` helper's raw socket (CAP_NET_RAW in the user namespace, which the sandbox has). Ruling if neither can be made to work: the scenario skips with the reason and the QEMU suite (Task 5 on) carries the proof; record it in the ledger.
- [ ] **Step 5: Commit** `harness: pppoe-server and pppd as the lab's access concentrator`.

---

### Task 2: The session over `pppd` in the sandbox

**Files:**
- Modify: `harness/tests/pppoe.rs` (`PppBench`, scenarios `lcp_pap_and_ipcp_bring_ipv4_up_over_pppd`, `chap_authenticates_too`)

**Interfaces:**
- Consumes: `openfeo_net::pppoe::Session::{attach, unit, recv, send, set_mru}`; `openfeo_proto_ppp::session::{Session, Config, Input, Output, Reason}`; `lanclient::ping_loop`; the `Bench` of Task 1 for discovery.
- Produces:
  ```rust
  struct PppBench { kernel: openfeo_net::pppoe::Session, core: openfeo_proto_ppp::session::Session, near: Discovery, dclient: discovery::Client, start: Instant, pending: Vec<Output>, buf: Vec<u8>, dbuf: Vec<u8> }
  impl PppBench {
      async fn connect(rig: &Rig, auth_config: session::Config) -> anyhow::Result<PppBench>   // discovery to Session{..}, attach, Input::Start
      async fn run_until(&mut self, timeout: Duration, done: impl FnMut(&Output) -> bool) -> anyhow::Result<Vec<Output>>   // as dhcp6.rs's Driver: Send → kernel.send, Mru → set_mru, frames in, timer, discovery socket for a PADT (fed as Input::CarrierLost, remembered as `padt_seen`)
      fn ifname(&self) -> String   // "ppp<unit>"
  }
  fn session_config(username: &str, password: &str, mru: u16) -> session::Config   // secret [7; 16], wan "wan0"
  fn is_ipv4_up(output: &Output) -> bool
  fn down_reason(outputs: &[Output]) -> Option<&Reason>
  ```

- [ ] **Step 1: Failing scenarios**:

```rust
/// PADS, LCP (MRU 1492, our magic), PAP, IPCP: IPv4 up with the pool's first address, the ISP's
/// address as peer and its resolver; the kernel's ppp<N> carries a ping to the ISP once the test
/// gives it the address the applier would.
fn lcp_pap_and_ipcp_bring_ipv4_up_over_pppd(lab: &mut Lab) -> anyhow::Result<()> {
    require_dev_ppp()?;
    let rig = Rig::create()?;
    let _server = daemons::pppoe_server_in_sandbox(&PppoeServerConfig::isp(AC_IF, Auth::Pap), &lab.run_dir)?;
    runtime()?.block_on(async {
        let mut bench = PppBench::connect(&rig, session_config("openfeo@isp.example", "example-secret", 1492)).await?;
        let outputs = bench.run_until(Duration::from_secs(20), is_ipv4_up).await?;
        ensure!(has(&outputs, |o| matches!(o, Output::LcpUp { mru: 1492, auth: Some(AuthProto::Pap), .. })), "{outputs:?}");
        ensure!(has(&outputs, |o| *o == Output::AuthOk("pap")), "{outputs:?}");
        let Some(Output::Ipv4Up(up)) = outputs.last() else { anyhow::bail!("{outputs:?}") };
        ensure!(up.local == "203.0.113.100".parse::<Ipv4Addr>()? && up.peer == Some("203.0.113.1".parse()?) && up.dns == vec!["203.0.113.1".parse::<Ipv4Addr>()?], "{up:?}");
        ensure!(!format!("{:?}", bench.core).contains("example-secret"), "the core's Debug redacts");
        netns::ip(&["addr", "add", "203.0.113.100", "peer", "203.0.113.1/32", "dev", &bench.ifname()])?;
        netns::ip(&["link", "set", &bench.ifname(), "up"])?;
        let stats = lanclient::ping_loop(&sandbox_ns(), "203.0.113.1", 3, Duration::from_millis(200))?;   // a helper that runs `ping` in the current namespace; add `lanclient::ping_here` if `ping_loop` insists on a NetNs
        ensure!(stats.received >= 1, "{stats:?}");
        anyhow::Ok(())
    })
}

/// The same with `require-chap`: Challenge, Response, Success, `auth chap ok`.
fn chap_authenticates_too(lab: &mut Lab) -> anyhow::Result<()> { /* Auth::Chap; assert AuthOk("chap") and LcpUp auth Some(ChapMd5) */ }
```
The core's session runs on the kernel descriptors while `pppd` runs LCP against it; the kernel's `ppp<N>` is born down and the test raises it and gives it the address (the applier is not in the sandbox suite).

- [ ] **Step 2: Run** → FAIL (no `PppBench`).
- [ ] **Step 3: Implement** `PppBench` after `Bench`; keep the output loop one `select!` over `kernel.recv`, `near.recv`, the timer. The `pppd` log is read on failure: `run_until`'s timeout message appends the last 20 lines of `<run_dir>/pppd-e1.log`.
- [ ] **Step 4: Run** → PASS for both. Expected wall time under 5 s each.
- [ ] **Step 5: Commit** `harness: the PPP session over pppd in the sandbox, PAP and CHAP`.

---

### Task 3: The ways a session ends

**Files:**
- Modify: `harness/tests/pppoe.rs` (scenarios `a_wrong_password_is_auth_failed_with_pppds_message`, `pppoe_server_killed_is_keepalive_lost_within_forty_seconds`, `pppoe_server_stopped_by_sigterm_is_terminated_by_peer`, `a_padt_from_the_ac_ends_the_session`)

**Interfaces:** consumes `PppBench`, `Lab::kill_pppoe_server`/`stop_pppoe_server` (the sandbox variants take the `Daemon` directly: `daemons::signal_group(&daemon, Signal)`), `openfeo_proto_ppp::pppoe::{Discovery as Packet, Code}` for the injected PADT.

- [ ] **Step 1: Failing scenarios**:
  - `a_wrong_password_is_auth_failed_with_pppds_message`: `Auth::Pap`, password `"not-the-secret"`; `run_until(10 s, |o| matches!(o, Output::Down{..}))`; assert `down_reason == Some(AuthFailed(msg))` with `msg` non-empty (pppd 2.5 sends "Login incorrect"), and that no `Output::Send` follows the `Down`. Also a CHAP variant inside the same scenario (second rig): reason `AuthFailed` with pppd's CHAP failure text.
  - `pppoe_server_killed_is_keepalive_lost_within_forty_seconds`: after `is_ipv4_up`, `signal_group(SIGKILL)`; `run_until(45 s, down)`; reason `KeepaliveLost`; the time from the kill to the `Down` is between 30 s and 41 s (three echo intervals; record it in the failure message).
  - `pppoe_server_stopped_by_sigterm_is_terminated_by_peer`: after `is_ipv4_up`, `signal_group(SIGTERM)`; `run_until(10 s, down)`; reason `TerminatedByPeer`; `Ipv4Down` precedes `Down`. Second variant in the same scenario: SIGTERM right after `LcpUp` and before `Ipv4Up` (the Review Focus 1 shape): reason `TerminatedByPeer`, no `Ipv4Up`/`Ipv4Down` at all.
  - `a_padt_from_the_ac_ends_the_session`: after `is_ipv4_up`, send a PADT for the session id from the far veth end (a `Discovery` on `e1`, as part 1's scripted AC did); `run_until(5 s, down)`; the bench saw the PADT (`padt_seen`) and the core reported `Down { reason: CarrierLost, .. }` from the bench's `CarrierLost` (or `TerminatedByPeer` if `pppd` managed a Terminate-Request first; accept either and assert which happened in the message).
- [ ] **Step 2: Run** → FAIL (scenarios absent).
- [ ] **Step 3: Implement** the four, plus `daemons::signal_group(daemon: &Daemon, signal: nix::sys::signal::Signal) -> Result<()>` (the daemon's pid is its process group's id; `Daemon` gains `pub fn pid(&self) -> i32`).
- [ ] **Step 4: Run** → PASS; the keepalive scenario takes about 40 s, the others under 10 s.
- [ ] **Step 5: Commit** `harness: wrong password, keepalive loss, terminate and padt over pppd`.

---

### Task 4: IPV6CP and the RFC 4638 fallback

**Files:**
- Modify: `harness/tests/pppoe.rs` (scenarios `ipv6cp_brings_the_identifiers_up_and_the_peer_answers_a_ping`, `without_rfc_4638_the_session_runs_at_1492`)
- Modify (only if the spike says so): `docs/superpowers/specs/2026-11-07-m3-pppoe-design.md` (one sentence in "Harness" recording what `pppoe-server` 4.0 can and cannot offer)

**Interfaces:** consumes `PppBench`, `Output::Ipv6Up { local_iid, peer_iid }`, `m2pd.rs`'s `ping6` shape (copy it: `ping -6 -c 1 -W 1 <target>%<ifname>`).

- [ ] **Step 1: Failing scenarios**:
  - `ipv6cp_brings_the_identifiers_up_and_the_peer_answers_a_ping`: `PppoeServerConfig::isp(AC_IF, Auth::None)` (ipv6 on); `run_until(20 s, |o| matches!(o, Output::Ipv6Up(_)))`; assert `peer_iid == 2` (pppd's `ipv6 ::1,::2`: ours is naked to `::1`? No: `pppd`'s `ipv6 ::1,::2` names its own identifier `::1` and suggests `::2` for us by Nak; the core takes a different identifier as is, so `local_iid == 2` and `peer_iid == 1`; assert exactly that, and if `pppd` 2.5.4 instead accepts our RFC 7217 identifier, assert `peer_iid == 1` and `local_iid != 0` and record which in the ledger); then `ip -6 addr add fe80::<local_iid>/64 dev ppp<N>` (format the identifier as `openfeo`'s `iid_text`, colon-grouped), `ip link set up`, and `ping -6 -c 1 fe80::1%ppp<N>` answers.
  - `without_rfc_4638_the_session_runs_at_1492`: `PppoeServerConfig { mtu: 1500, .. }` and a client config asking `max_payload: Some(1500)`; the PADS carries no PPP-Max-Payload (rp-pppoe 4.0's server has no RFC 4638 switch: its usage shows none), so the bench's discovery reports `max_payload: None`, the session's `LcpUp { mru: 1492, .. }`, and `pppd`'s own request for MRU 1500 is naked down to 1492 (assert `mru_theirs == 1492` in the same `LcpUp`).
- [ ] **Step 2: Run** → FAIL (absent).
- [ ] **Step 3: Implement**; if the first scenario shows `pppd` refusing IPV6CP without `ipv6cp-accept-local`, add that option to `render_pppd_options` behind `ipv6` and fix the renderer's unit test.
- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `harness: ipv6cp over pppd and the 1492 fallback without RFC 4638`.

---

### Task 5: The `m3` QEMU suite: boot, NAT and the clamp

**Files:**
- Create: `harness/tests/m3.rs`
- Modify: `harness/Cargo.toml` (`[[test]] name = "m3"`, `harness = false`), `Makefile` (`--test m3` after `--test m2pd`)

**Interfaces:**
- Consumes: `Lab::{start_pppoe_server, isp_ppp_ifname, start_dnsmasq, with_config, boot, console, qmp, lan0, isp0, run_dir}`, `m2pd.rs`'s `re`, `group`, `wait_until`, `http_target`, `fetch` (copy them; the harness has no shared test-helper module and the other suites copy too), `lanclient::http_get`.
- Produces:
  ```rust
  const VM_PPPOE: &str = include_str!("../fixtures/vm-pppoe.toml");
  const VM_PPPOE_PD: &str = include_str!("../fixtures/vm-pppoe-pd.toml");
  const DISCOVERING: &str = r"openfeo: pppoe wan0 discovering on p0 \(service any, max payload 1492\)";
  const SESSION: &str = r"openfeo: pppoe wan0 session 0x([0-9a-f]{4}) with ([0-9a-f:]{17}) ac \"isp\" max payload 1492 \(no RFC 4638\)";
  const LCP_UP: &str = r"openfeo: pppoe wan0 lcp up mru 1492 auth (chap|pap|none)";
  const AUTH_OK: &str = r"openfeo: pppoe wan0 auth (chap|pap) ok as openfeo@isp\.example";
  const IPCP_UP: &str = r"openfeo: pppoe wan0 ipcp up (203\.0\.113\.\d+) peer 203\.0\.113\.1 dns 203\.0\.113\.1";
  const IPV6CP_UP: &str = r"openfeo: pppoe wan0 ipv6cp up local ([0-9a-f:]{19}) peer ([0-9a-f:]{19})";
  const DOWN: &str = r"openfeo: pppoe wan0 down: (.*?) after \d+ s(; retry in (\d+) s)?";
  struct Booted { cur: Cursor, session_id: u16, address: Ipv4Addr, local_iid: String }
  fn boot_pppoe(lab: &mut Lab, server: &PppoeServerConfig, config: &str) -> anyhow::Result<Booted>
  // start_pppoe_server on isp0 "wan0", start_dnsmasq, with_config, boot(""), wait READY then DISCOVERING, SESSION, LCP_UP, AUTH_OK, IPCP_UP, IPV6CP_UP (each from the previous cursor, SOON each), then Lab::host for lan0; at the end of every scenario `no_password_on_the_console(lab)` greps the whole console and the pppd log the harness copied for "example-secret"
  ```
- [ ] **Step 1: Failing scenarios**:
  - `lan_fetches_isp_http_through_nat_over_ppp`: `http_target` on `isp0` at `203.0.113.1:8080`; the LAN host `fetch`es it; the ISP sees the request from the PPP address (`IPCP_UP`'s capture): the target's log line carries `203.0.113.100`.
  - `a_large_body_crosses_the_mss_clamp`: the target body is 64 KiB (`"x".repeat(65536)`), the ISP's `wan0` MTU stays 1500; the LAN host's fetch returns all 65536 bytes within `HTTP_TIMEOUT`; `ip -s link show wan0` in `isp0` shows no growth in... (keep it to the body length; the sandbox `nft` scenario already proves the rule's shape).
  - `the_console_never_shows_the_password`: boots and asserts `no_password_on_the_console` alone (the same check runs in every other scenario's helper, so this one is the named proof).
- [ ] **Step 2: Run** `make kernel` once, then `OPENFEO_KERNEL=build/bzImage target/debug/deps/m3-<hash>` after `cargo test -q -p openfeo-harness --test m3 --no-run` → FAIL (file absent at first, then each scenario as written).
- [ ] **Step 3: Implement**; `boot_pppoe` waits `BOOT_TIMEOUT` for READY and `SOON` for each PPP line.
- [ ] **Step 4: Run** → PASS, three scenarios, each under 60 s. **Step 5: Commit** `harness: the m3 suite boots vm-pppoe.toml and fetches through NAT over PPP`.

---

### Task 6: Loss and recovery, PAP, the tagged WAN

**Files:**
- Create: `harness/fixtures/vm-pppoe-vlan.toml` (as `vm-pppoe.toml` with `vlan = 101` on `wan0`)
- Modify: `harness/tests/m3.rs` (scenarios `pppoe_server_killed_is_keepalive_lost_and_the_session_returns`, `carrier_loss_is_reported_and_the_session_returns_within_ten_seconds`, `carrier_loss_during_discovery_restarts_discovery`, `pap_authenticates_too`, `the_tagged_wan_runs_pppoe_over_a_vlan`), `crates/openfeo-config` snapshot/validation tests only if the new fixture must be listed where `vm-pppoe.toml` is (grep `vm-pppoe.toml` first)

**Interfaces:** consumes `Lab::{kill_pppoe_server, restart_pppoe_server, isp0_tagged}`, `Qmp::set_link`, `vlanprobe::require_vlan_links`.

- [ ] **Step 1: Failing scenarios**:
  - `pppoe_server_killed_is_keepalive_lost_and_the_session_returns`: after `boot_pppoe`, `kill_pppoe_server`; wait `DOWN` with group 1 == `keepalive lost (3 echoes)` within 45 s; `restart_pppoe_server`; wait `SESSION` then `IPCP_UP` within 70 s (the ladder's first waits are 1, 2, 4 s; the server is back before the second attempt); the retry text `retry in 1 s` appears on the first `DOWN`.
  - `carrier_loss_is_reported_and_the_session_returns_within_ten_seconds`: `qmp.set_link("p0", false)`; wait `DOWN` with `carrier lost` (no retry text); `set_link("p0", true)`; `SESSION` within 10 s of the `set_link`.
  - `carrier_loss_during_discovery_restarts_discovery`: boot with the server **not** started (`boot` then wait `DISCOVERING`); `set_link("p0", false)` then `true`; the console shows a second `DISCOVERING` after the link returns; then `start_pppoe_server` and `IPCP_UP` within 40 s (the PADI ladder's 1, 2, 4, 8, 16 s).
  - `pap_authenticates_too`: `Auth::Pap`; `AUTH_OK` captures `pap`.
  - `the_tagged_wan_runs_pppoe_over_a_vlan`: `require_vlan_links()?`; `lab.isp0_tagged(101)` returns the ISP's tagged interface; `PppoeServerConfig::isp(&tagged, Auth::Chap)`; `VM_PPPOE_VLAN`; `DISCOVERING` names `p0.101`; the NAT fetch as in Task 5.
- [ ] **Step 2–4**: FAIL, implement, PASS (the keepalive scenario is the slowest, about 90 s).
- [ ] **Step 5: Commit** `harness: keepalive loss, carrier loss, PAP and the tagged WAN over PPPoE`.

---

### Task 7: IPv6 over PPP

**Files:**
- Modify: `harness/tests/m3.rs` (scenario `ipv6_over_ppp_gives_the_lan_a_gua_and_reaches_the_isp`), `harness/src/lab.rs` (`start_radvd_on(&mut self, iface: &str, config: &RadvdConfig)` generalising `start_radvd`'s address setup for a PPP interface, where the link-local comes from IPV6CP and no `addr_gen_mode` write is needed), `harness/src/daemons.rs` (`RadvdConfig::isp` already takes the interface; nothing unless radvd refuses a point-to-point interface, in which case `AdvSendAdvert on` plus `UnicastOnly`? No: radvd multicasts fine on PPP; record what happened)

**Interfaces:** consumes `boot_pppoe`'s `local_iid` (the router's link-local on `ppp-wan0` is `fe80::<local_iid>`), `Lab::isp_route_block6(ROUTED_PREFIX6, &via)`, `m2pd.rs`'s `lan_ready`, `host_addr_in`, `fetch` over IPv6.

- [ ] **Step 1: Failing scenario**: `boot_pppoe` with `VM_PPPOE` (the routed `/48`); `let ppp = lab.isp_ppp_ifname(SOON)?`; `lab.start_radvd_on(&ppp, &RadvdConfig::isp(&ppp))` with managed/other off; `lab.isp_route_block6(ROUTED_PREFIX6, &format!("fe80::{}", booted.local_iid))` on `ppp`; the console shows `wan wan0 ipv6 router fe80::1 (learned)` and the `DEFAULT6_INSTALLED` shape of `m2pd.rs` with `dev ppp-wan0`; the LAN host (`lan0` down/up as `boot_pd` does) gets a GUA in `2001:db8:1:222::/64` and fetches `http_target` on `isp0` at `[2001:db8:ffff::1]:8080` over IPv6.
- [ ] **Step 2–4**: FAIL, implement, PASS. If `radvd` refuses the interface ("no link-local address" because `pppd` adds `fe80::1` only after IPV6CP), `start_radvd_on` waits for `ip -6 addr show dev <ppp> scope link` to show `fe80::1` first (up to 10 s).
- [ ] **Step 5: Commit** `harness: IPv6 over PPP, radvd on the ISP's ppp interface`.

---

### Task 8: Prefix delegation over PPP and a reboot

**Files:**
- Modify: `harness/tests/m3.rs` (scenarios `pd_over_ppp_binds_a_prefix_and_the_lan_takes_a_gua_from_it`, `a_reboot_comes_back_with_a_fresh_session_and_the_same_prefix`), `harness/src/lab.rs` (`start_kea6_on(&mut self, iface: &str, config: &Kea6Config)` if `Kea6Config.iface` alone is not enough: it is, since `kea_dhcp6` takes the config's `iface`; keep `start_kea6` and pass `Kea6Config { iface: ppp.clone(), ..Kea6Config::isp(Some(pool)) }`)

**Interfaces:** consumes `boot_pppoe` with `VM_PPPOE_PD`, `start_radvd_on` (Task 7) with managed/other on (`isp_radvd()` of `m2pd.rs`), `Kea6Config`, `m2pd.rs`'s `BOUND`, `Qmp::system_reset`.

- [ ] **Step 1: Failing scenarios**:
  - `pd_over_ppp_binds_a_prefix_and_the_lan_takes_a_gua_from_it`: the spike first: Kea DHCPv6 on a PPP interface. `Kea6Config { iface: ppp, .. }` and `start_kea6`; Kea 2.4/3.2 on an interface without a hardware address logs `DHCPSRV_...` or refuses `interfaces-config`? Expected to work (Kea opens a UDP socket per interface and needs only a link-local address). If Kea refuses: `"dhcp-socket-type": "udp"` in the rendered config for the PPP case, and if it still refuses, the ruling is to run Kea on `wan0` behind a relay... no: record the finding, mark the scenario a reasoned skip naming Kea's error, and file the issue; the sandbox has no other DHCPv6 server. Then: `BOUND` on the console (`dhcp6 wan0 bound prefix 2001:db8:100:...:/56`), `lab.isp_route_block6(PD_POOL_A, via fe80::<local_iid>)` on `ppp`, the LAN host's GUA in the delegation's first `/64`, a fetch over IPv6 as in Task 7.
  - `a_reboot_comes_back_with_a_fresh_session_and_the_same_prefix`: after the first scenario's state, `lab.qmp()?.system_reset()`; wait READY, `SESSION` with a different session id (the server allocates the next), and `BOUND` with the same prefix (Kea remembers the DUID; the binding file on the state disk is restored or re-requested: the console shows either `dhcp6 wan0 restored` then `renewed`, or `bound` again; assert the prefix, not the path).
- [ ] **Step 2–4**: FAIL, implement, PASS.
- [ ] **Step 5: Commit** `harness: prefix delegation over PPP and a reboot`.

---

### Task 9: check-env, CI and the cloud setup

**Files:**
- Modify: `harness/src/main.rs` (`check()`: `pppd` and `pppoe-server` in the tool list; a `/dev/ppp` line reported like `/dev/kvm`, `ok` when it opens read-write, otherwise `no (M3 scenarios skip; udev: KERNEL=="ppp", GROUP="<group>", MODE="0660")`, not fatal; and a `ppp modules` line that opens an `AF_PPPOX` socket through `openfeo_net`? No: `openfeo-net`'s `pppox_socket` is private to the crate; the attach scenario is the probe, so check-env only reports the device)
- Modify: `.github/workflows/ci.yml` (`ppp pppoe` in the harness job's apt line; the module step already loads the PPP modules and opens `/dev/ppp`)
- Modify: `scripts/cloud-setup.sh` (`ppp pppoe` in the package list; `ppp_generic pppox pppoe ppp_async` in the modprobe loop; `chmod 0666 /dev/ppp` beside the kvm chmod, each `|| true`; the facts it prints gain `/dev/ppp`)
- Modify: `CLAUDE.md` (the Harness paragraph: `pppd` and `pppoe-server` as the ISP's PPP side, `/dev/ppp` group-accessible via the udev rule, the `m3` suite), `README`/docs only where the tool list is repeated (grep `rdisc6` across `docs/` and the top-level files)

- [ ] **Step 1**: `make check-env` on this host → the two tools `ok` and `/dev/ppp ok`; with `/dev/ppp` made `0600` for a moment (`sudo chmod`) → the `no (...)` line and exit 0. CI: push nothing; the workflow change is proven by the PR's own run.
- [ ] **Step 2: Commit** `harness, ci: pppd, pppoe-server and /dev/ppp in check-env, CI and the cloud setup`.

---

### Task 10: Progress entry and the full gate

**Files:**
- Modify: `docs/progress.md` (the M3 section's second paragraph: `**<date>, [#NN](...), part 2: live.** ...`, what the sandbox suite and the `m3` suite prove, SPEC §12's M3 row met, and "M3 is complete; next is M4 (API and panel)")

- [ ] **Step 1: The whole gate**: `make lint && make test && make test-harness` → every suite PASS, no SKIP on this host now that the modules load (`OPENFEO_NO_SKIP=1 make test-harness` is the honest form here). Expected: the `pppoe` suite about 2 min (the keepalive scenario), `m3` about 8 min.
- [ ] **Step 2: Write the entry** (the PR number after the draft PR exists, on the maintainer's word). **Step 3: Commit** `docs: progress entry for M3 part 2`.

---

## Self-review notes

- Spec coverage against the design's Harness section: tools and secrets (1), `pppoe_server` and the `Lab` methods (1), the sandbox suite's nine scenarios (1–4: discovery against the real server, PAP+IPCP+ping, CHAP, wrong password, SIGKILL, SIGTERM, PADT, IPV6CP+ping6, RFC 4638 fallback), the `m3` suite (5–8: console, NAT, clamp, keepalive loss and return, carrier loss, PAP, tagged, IPv6 over PPP, PD over PPP, reboot, no password), check-env/CI/cloud (9), the progress entry (10). SPEC §12's M3 row: "v4 and v6 over PPP against pppoe-server/pppd at MTU 1492 and 1500" is met at 1492 and recorded at 1500 by the core's tests and Task 4's note, since rp-pppoe 4.0 cannot offer RFC 4638 (the design foresaw this); "AC-initiated PADT and LCP echo failure both recover" (3, 6); "a wrong password backs off and is reported" (3, and the backoff by the task's unit tests of part 1); "prefix delegation over PPP works" (8).
- Interfaces: `PppoeServerConfig`/`Auth` (1) are what 2–8 pass; `PppBench` (2) is what 3 and 4 drive; `boot_pppoe`'s `Booted.local_iid` (5) is what 7 and 8 route to; `start_radvd_on` (7) is what 8 reuses.
- Review Focus: each line names its pinning scenario.
- Proportion: this plan is shorter than the design's Harness section it transcribes; code blocks are signatures and assertions.
- The spikes: Task 1 (the server rootless in the sandbox), Task 4 (IPV6CP identifiers and RFC 4638), Task 8 (Kea on a PPP interface) each name both outcomes.
