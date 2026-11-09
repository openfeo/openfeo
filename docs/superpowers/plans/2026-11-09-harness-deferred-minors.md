# Harness Deferred Minors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the ten harness and environment minors from the M3 part 2 review (#48–#57), tightening the `pppoe` suite's proofs and the lab's daemons, in one branch and one PR.

**Architecture:** Nothing of the router changes; nothing of the lab's shape changes. Four tasks each own one file group: check-env and the cloud setup; the `pppoe` sandbox suite's assertions and its bench; the daemons module; one new `m3` scenario. A harness change is proven by the suite that runs it, a helper by a unit test in the harness lib where one is possible.

**Tech Stack:** The harness crate as it stands (Rust stable 2024, nix, tokio; rp-pppoe, pppd, dnsmasq, dig, QEMU); `scripts/cloud-setup.sh` is POSIX shell checked with `bash -n`.

**Spec:** `SPEC.md` §11 (test strategy: the lab proves what the unit tests cannot) and the issues' own text (#48–#57), each filed from the review of PR #47.

## Global Constraints

- Every source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton`.
- `std::process::Command` only in `harness/` and `image/`; `anyhow` is allowed here; `clippy -D warnings` with pedantic on; no `unwrap`/`expect` outside tests.
- Scenario names are sentences; a scenario skips with a reason where the host lacks a tool or a device, and CI runs with `OPENFEO_NO_SKIP=1`.
- Commits: `git commit -s`, subject `harness: <summary>` (or `check-env:`, `cloud-setup:`), trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, `Closes #NN` lines in the body.
- `export OPENFEO_NFT_SRC=$PWD/build/nft/src OPENFEO_UAPI_INCLUDE=$PWD/build/kernel/headers/include` before a bare `cargo`; the `pppoe` suite is `cargo test -q -p openfeo-harness --test pppoe` (needs `/dev/ppp` group-accessible: `sudo ./setup-dev-ppp.sh` after a reboot); `m3` needs `OPENFEO_KERNEL=build/bzImage`.
- The branch is `harness-minors` from `main` at `d20b3c4` (or from `router-minors`' merge if that lands first; the two touch no common file).

## Review Focus

1. A session that dies while a scenario waits for something else (IPCP, say) must fail that scenario at once with the reason, not spin until the deadline: `PppBench::run_until` returning an error on a `Down` the predicate did not ask for (Task 2), proven by the wrong-password scenario waiting on `is_ipv4_up` in a one-off RED run.
2. The wrong-password scenario must prove the core goes quiet after `auth failed`: `run_for` seeing no `Send` (Task 2).
3. A developer running `make check-env` on a host without user namespaces must see one clear "no" for `/dev/ppp` after the row that explains it, not errors before it (Task 1; there is no knob to deny user namespaces to the harness here, so this is verified by the row order in a normal run and by reading).
4. A `pppoe-server` restarted mid-scenario must leave the first session's pppd log for a failure message: `rotate_log` keeping `.1` (Task 3).
5. The IPCP resolver must carry a real query over PPP: `dig` from the LAN host through the router's forwarder to dnsmasq on the ISP, answered (Task 4).

---

### Task 1: check-env row order and the cloud facts (#48, #56)

**Files:**
- Modify: `harness/src/main.rs:176-262` (`check`), `:378-394` (`report_ppp`), `scripts/cloud-setup.sh:171-175`

**Interfaces:**
- `fn report_ppp(sandbox_ok: bool) -> Result<()>`: called right after the "unprivileged user namespaces" row (main.rs:245-253); when `sandbox_ok` is false it prints `/dev/ppp   no (needs unprivileged user namespaces; see above)` and never calls `probe_in_child`.

- [ ] **Step 1:** Move the call (main.rs:194) below the user-namespace row; thread `sandbox_works()?`'s value (compute it once into a `let`). The plugin row stays in `report_ppp`.
- [ ] **Step 2:** `make check-env` → the `/dev/ppp` and plugin rows now come after `unprivileged user namespaces`, every row as before. Exit status unchanged.
- [ ] **Step 3:** `cloud-setup.sh`: the facts loop lists `nf_conntrack nft_ct nft_fib_inet nft_nat nft_masq nft_chain_nat nft_limit 8021q ppp_generic pppox pppoe ppp_async`, the same list the modprobe loop uses (lines 115-118): put the list in one variable `MODULES` used by both loops. `bash -n scripts/cloud-setup.sh` → clean.
- [ ] **Step 4: Commit** `check-env, cloud-setup: the PPP probe follows the user-namespace row; the facts list every module loaded` (Closes #48, #56).

### Task 2: The `pppoe` suite's proofs and the bench (#49, #50, #51, #52)

**Files:**
- Modify: `harness/tests/pppoe.rs:551-567` (`PppBench`), `:602-662` (`run_until`), `:828-846`, `:874-920`, `:952-977`

**Interfaces:**
- `PppBench::run_until(timeout, done)` returns `Err` as soon as a `PppOutput::Down` is seen that `done` did not accept (message: `session went down ({reason:?}) while waiting; outputs: {seen:?}`), and a kernel recv error is fed as `CarrierLost` once, then the kernel socket is no longer polled (`self.kernel_dead = true`).
- `PppBench::run_for(&mut self, window: Duration) -> anyhow::Result<Vec<PppOutput>>`: drives the bench for `window` and returns every output seen; it never times out (the window ending is success) and still errors on a kernel recv error after the session is down.

- [ ] **Step 1 (#52):** Implement the `Down`-not-asked-for error and `kernel_dead`. RED proof: temporarily make the wrong-password scenario wait on `is_ipv4_up`; it now fails within a second with `auth failed`, where before it spun to the 20 s deadline; revert the predicate.
- [ ] **Step 2 (#49):** In the second variant of `pppoe_server_stopped_by_sigterm_is_terminated_by_peer`, replace `ensure!(down_reason(&outputs).is_some(), ..)` with `matches!(down_reason(&outputs), Some(PppReason::TerminatedByPeer | PppReason::CarrierLost))` and print the reason in the message (`"{:?}: {outputs:?}", down_reason(&outputs)`).
- [ ] **Step 3 (#50):** In `a_padt_from_the_ac_ends_the_session`, delete the `sent.elapsed() < 5 s` assertion; assert `bench.down_at.is_some_and(|at| at.duration_since(sent) < Duration::from_secs(2))` with the message `"the PADT ends the session at once, not by keepalive: {:?}", bench.down_at.map(|at| at.duration_since(sent))`.
- [ ] **Step 4 (#51):** In `a_wrong_password_is_auth_failed_with_pppds_message`, after the `AuthFailed` check: `let after = bench.run_for(Duration::from_secs(1)).await?; ensure!(!after.iter().any(|o| matches!(o, PppOutput::Send { .. })), "{auth:?}: the core keeps talking after auth failed: {after:?}")` (the bench is `_bench` today: name it).
- [ ] **Step 5:** `cargo test -q -p openfeo-harness --test pppoe` → 12 passed.
- [ ] **Step 6: Commit** `harness: the pppoe suite pins the Down reason, the PADT timing and the silence after auth failed; the bench fails fast on a Down` (Closes #49, #50, #51, #52).

### Task 3: The daemons module (#53, #54, #57)

**Files:**
- Modify: `harness/src/daemons.rs:512-532` (doc), `:535-552` (`write_ppp_secrets`), `:647-660` (`pppoe_server_command`); new `fn rotate_log(path: &Path)`
- Test: `daemons.rs` `mod tests`

**Interfaces:**
- `write_ppp_secrets` returns `Err` with `"not inside the sandbox: /etc/ppp would be the host's"` unless `sandbox::is_inside()`.
- `fn rotate_log(path: &Path)`: renames `<path>` to `<path>.1` when it exists (replacing an older `.1`); `pppoe_server_command` calls it instead of `remove_file` (line 655).
- The `render_pppd_options` doc says: `nodetach` keeps pppd a direct child of the server so the `/proc` walk in `Daemon::signal` finds it (pppd `setsid()`s regardless); a pppd forked between the walk and the kill survives, which no scenario has met.

- [ ] **Step 1: Failing tests.** `secrets_are_refused_outside_the_sandbox`: `write_ppp_secrets("u", "p")` from the test process (not inside) → `Err` whose `{:#}` contains `sandbox`. `a_rotated_log_keeps_one_predecessor`: tempdir, write `pppd-x.log` = "a", `rotate_log` → `.1` = "a" and the log is gone; write "b", rotate → `.1` = "b".
- [ ] **Step 2:** Run `cargo test -p openfeo-harness --lib daemons` → fail; implement; run → pass. Fix the doc comment.
- [ ] **Step 3:** `cargo test -q -p openfeo-harness --test pppoe` → 12 passed (the server still writes its secrets inside the sandbox); after `pppoe_server_killed_is_keepalive_lost_within_forty_seconds` the run dir holds `pppd-<if>.log.1` where a scenario restarted the server (the `m3` keepalive scenario; check once in Task 4's run).
- [ ] **Step 4: Commit** `harness: secrets only inside the sandbox; the pppd log is rotated, not removed; the nodetach doc tells the truth` (Closes #53, #54, #57).

### Task 4: A name resolved over PPP (#55)

**Files:**
- Modify: `harness/tests/m3.rs` (new scenario, `SCENARIOS` list; imports `lanclient::{self, DigAnswer}`)

**Interfaces:**
- Consumes: `Lab::start_dnsmasq()` (lab.rs:499; dnsmasq on isp0's `wan0` at `203.0.113.1`, authoritative for `isp.example`: `www` → `198.51.100.10`), `lanclient::dig(ns, server, name, qtype, extra, timeout)` (lanclient.rs:843), `boot_pppoe` (m3.rs:212).

- [ ] **Step 1: The scenario.**

```rust
/// The IPCP resolver carries a real query: the LAN host asks the router, the forwarder asks
/// the ISP's resolver over the PPP session, and `www.isp.example` comes back (#55).
fn the_lan_resolves_a_name_through_the_ipcp_resolver_over_ppp(lab: &mut Lab) -> anyhow::Result<()> {
    lab.start_dnsmasq()?;
    let booted = boot_pppoe(lab, &PppoeServerConfig::isp("wan0", Auth::Chap), VM_PPPOE)?;
    let mut cur = booted.cur;
    let c = lab.console()?;
    c.wait_for(&mut cur, &re(r"openfeo: dns upstreams 203\.0\.113\.1 \(learned from wan0\)"), SOON)?;   // m1's UPSTREAMS_LEARNED
    let answer = lanclient::dig(&lab.lan0, "192.168.1.1".parse()?, "www.isp.example", "A", &[], Duration::from_secs(6))?;
    ensure!(answer.status == "NOERROR", "{answer:?}");
    ensure!(answer.answers.iter().any(|(_, _, t, v)| t == "A" && v == "198.51.100.10"), "{answer:?}");
    let dnsmasq = lab.daemons.iter().find(|d| d.name == "dnsmasq").context("dnsmasq")?;
    ensure!(dnsmasq.log.count(&re(r"auth\[A\] www\.isp\.example from 203\.0\.113\.100")) >= 1, "the query reached the ISP over PPP: {:?}", dnsmasq.log.tail(8));
    Ok(())
}
```

The upstreams line is `m1.rs`'s `UPSTREAMS_LEARNED` (line 191), the same text. If dnsmasq's `--bind-interfaces --interface=wan0` does not answer a query arriving over `ppp<N>` for `203.0.113.1` (it binds the address, so it should), the fix is in `daemons::dnsmasq`: add `--interface=ppp+`? No: ppp interfaces come and go; bind the address instead (`--listen-address=203.0.113.1` without `--bind-interfaces`), and say so in the commit.
- [ ] **Step 2:** `OPENFEO_KERNEL=build/bzImage cargo test -q -p openfeo-harness --test m3` → 13 passed.
- [ ] **Step 3: Commit** `harness: a name resolved through the IPCP resolver over PPP` (Closes #55).

### Task 5: Gate and progress

- [ ] `make lint && make test && OPENFEO_NO_SKIP=1 make test-harness` → every suite passes, nothing skipped. A one-line entry under the M3 section of `docs/progress.md` (`**<date>, [#NN](...), harness minors.** ...`) once the PR number exists; commit `docs: progress entry for the harness minors sweep`.

---

## Self-review notes

- Coverage: #48, #56 (1); #49–#52 (2); #53, #54, #57 (3); #55 (4). Ten issues.
- Interfaces: `run_for` and the fail-fast `run_until` (2) are consumed only by the suite; `rotate_log` (3) by `pppoe_server_command`; the scenario (4) consumes existing helpers only.
- Review Focus item 3 admits its verification is by reading: there is no knob to deny user namespaces to the harness on this host.
- Proportion: four small tasks; the one code block is the scenario, whose shape the implementer could not infer from the issue.
