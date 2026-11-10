# Third Minors Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three deferred minors from the reviews of PRs #58 and #59 that change what the software or the gate does: a DHCPv6 binding that stays "restored" after the exchange restarts, an `m3` scenario that reads a daemon's log without waiting for it, and the `netlink` suite's one-in-six flake.

**Architecture:** Nothing of the router's shape or the lab's shape changes. One task per minor, each owning one file group: the DHCPv6 WAN driver; the `m3` and `dns` suites' log assertions; the `netlink` suite's stable-privacy scenario. The driver change is proven by a unit test on the predicate the driver uses; a harness change by the suite that runs it, repeated until the flake would have shown.

**Tech Stack:** The workspace as it stands (Rust stable 2024; tokio and rtnetlink in the harness; dnsmasq, QEMU).

**Spec:** `SPEC.md` §7.6 (the WAN's DHCPv6 binding, #44: a restored binding is advertised live until confirmed or given up), §11 (the lab proves what unit tests cannot; a flaky scenario proves nothing), and the deferred-minor lists in the first comments of PRs #58 and #59.

## Global Constraints

- Every source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton`.
- `clippy -D warnings` with pedantic on; no `unwrap`/`expect` outside tests; `anyhow` only in `crates/openfeo` and `harness/`.
- Commits: `git commit -s`, subject `<area>: <summary>`, trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_0116otzWsJaMkBGiFuKrNFDQ`.
- `export OPENFEO_NFT_SRC=$PWD/build/nft/src OPENFEO_UAPI_INCLUDE=$PWD/build/kernel/headers/include OPENFEO_KERNEL=$PWD/build/bzImage` before a bare `cargo`; `cargo fmt --all` before every commit.
- The branch is `minors-3` from `main` at `f2d7b37` (#59's merge).
- Only documentation address ranges in tests and fixtures.

## Review Focus

1. A router whose restored DHCPv6 binding is answered by the ISP with NoBinding, a failure status, or silence through the Requests must stop advertising the restored prefix as live once the exchange restarts (Task 1): the predicate test, and a read of `Run::act` showing `publish()` follows the clearing.
2. A restored binding whose Rebind is answered normally must still clear the flag in `bound()` (unchanged; Task 1's test asserts the predicate is false for `Rebinding` so the flag is cleared by the Bound, not early).
3. A slow CI runner must not fail the `m3` resolver scenario because dnsmasq's log line is a few ms behind `dig`'s answer (Task 2): `wait_for` with a bounded timeout replaces `count`.
4. The `netlink` stable-privacy scenario must pass on a loaded host (Task 3): the failing wait is named from a reproduced failure and the fix is proven by 20 consecutive passes under load, not by a wider window chosen blind.
5. A fix to the scenario that merely widens a window hides a cache bug if the cache is what is late (Task 3): the diagnosis step says which it was.

---

### Task 1: `restored` is cleared when the exchange restarts (PR #58 review)

**Files:**
- Modify: `crates/openfeo/src/dhcp6.rs:562-583` (`Run::act`), tests at the end of the file

**Interfaces:**
- Produces: `fn ends_restored(note: &Note) -> bool` in `crates/openfeo/src/dhcp6.rs`, true for `Note::RebindUnanswered` and `Note::Restarting(_)`, false for every other note. `Run::act` clears `self.restored` and publishes when it is true (today it tests `note == Note::RebindUnanswered` inline).

- [ ] **Step 1: Write the failing test** in `mod tests`:

```rust
#[test]
fn a_restored_binding_stops_being_restored_when_the_exchange_restarts() {
    assert!(ends_restored(&Note::RebindUnanswered));
    assert!(ends_restored(&Note::Restarting("the server has no binding for us")));
    assert!(ends_restored(&Note::Restarting("the server reported a failure")));
    assert!(ends_restored(&Note::Restarting("no reply to the request")));
    for note in [Note::Soliciting, Note::Requesting, Note::Renewing, Note::Rebinding,
                 Note::NoPrefixAvailable, Note::NoAddressAvailable, Note::Ignored("x")] {
        assert!(!ends_restored(&note), "{note:?}");
    }
}
```

- [ ] **Step 2:** `cargo test -q -p openfeo --lib dhcp6::tests::a_restored_binding_stops` → FAIL: `ends_restored` not found.
- [ ] **Step 3:** Add `fn ends_restored(note: &Note) -> bool` with a doc line (`/// After these the binding restored from disk is either confirmed, kept on its own timers, or being replaced: it no longer counts as unconfirmed (#44).`) and use it in `act`: `if self.restored && ends_restored(&note) { self.restored = false; self.publish(); }`.
- [ ] **Step 4:** the test → PASS; `cargo test -q -p openfeo` → all pass; `cargo clippy -p openfeo --all-targets -- -D warnings` → clean.
- [ ] **Step 5: Commit** `dhcp6: a restored binding stops being restored when the exchange restarts`.

### Task 2: the `m3` resolver scenario waits for dnsmasq's line (PR #59 review)

**Files:**
- Modify: `harness/tests/m3.rs:289-302`, `harness/tests/dns.rs:396-399`

**Interfaces:**
- Consumes: `Log::wait_for(&self, cursor: &mut Cursor, re: &Regex, timeout: Duration) -> Result<Match>` (`harness/src/lines.rs:85`); `Cursor::default()` starts at the first line.

- [ ] **Step 1 (RED):** the race has no deterministic reproduction; the RED proof is the shape: `count(..) >= 1` read right after `dig` returns. Note in the ledger that this task's RED is by inspection (the dns suite's `from {WAN6}` check at `dns.rs:397` has the same shape and gets the same change under a ruling).
- [ ] **Step 2:** `m3.rs`: replace the `ensure!(dnsmasq.log.count(..) >= 1, ..)` with
  `dnsmasq.log.wait_for(&mut Cursor::default(), &re(&format!(r"auth\[A\] www\.isp\.example from {}", regex_escape(&booted.address.to_string()))), Duration::from_secs(5)).context("the query reached the ISP over PPP")?;` — this also closes #64 (the literal `203\.0\.113\.100`), since the pattern is built from `booted.address` as the HTTP scenario's is. `dns.rs:397`: `rig.dnsmasq.log.wait_for(&mut Cursor::default(), &Regex::new(&format!("from {WAN6}"))?, Duration::from_secs(5)).context("dnsmasq saw the query arrive over IPv6")?;`.
- [ ] **Step 3:** `cargo test -q -p openfeo-harness --test dns` → all pass; `cargo test -q -p openfeo-harness --test m3 -- the_lan_resolves_a_name_through_the_ipcp_resolver_over_ppp` → ok; `cargo clippy -p openfeo-harness --all-targets -- -D warnings` → clean.
- [ ] **Step 4: Commit** `harness: the resolver scenarios wait for dnsmasq's log line` (Closes #64).

### Task 3: the `netlink` stable-privacy scenario's flake (PR #58 review)

**Files:**
- Modify: `harness/tests/netlink.rs:521-591` (the scenario) or `harness/tests/netlink.rs:608-630` (`wait_until`), or `crates/openfeo-netlink/src/monitor.rs` if the cache is what is late.

**Interfaces:**
- Consumes: `wait_until(rx, what, pred)` with `SETTLE = 2 s`; `link_local_of(cache, name)`; `LinksApplier::with_ipv6_secret`.

- [ ] **Step 1 (reproduce):** `FILTER=a_stable_privacy_link_local_is_the_same_across_two_bounces` in a loop of 20 runs with the output kept; then 20 more under load (`cargo build -p openfeo --release --target x86_64-unknown-linux-musl` or an equivalent CPU hog running alongside). Expected: at least one FAILED with its message. Time box: if 40 runs show no failure, stop, record the runs in the ledger, and file the flake as an issue with the evidence (the gate run's line, the 40 clean runs) under a ruling; the task ends there.
- [ ] **Step 2 (diagnose):** from the message, name the wait or `ensure!` that failed and what the cache held. Use superpowers:systematic-debugging: the kernel's order of events (`ip monitor` alongside a failing run if needed) against the cache's. Write the cause in the ledger before any change.
- [ ] **Step 3 (RED):** the reproduction loop is the RED: the failure rate before the fix, recorded.
- [ ] **Step 4 (fix):** the smallest change that removes the cause: a wait whose predicate was wrong, a kernel event the scenario did not account for, or a monitor update that is dropped or reordered. A wider `SETTLE` alone is not a fix unless Step 2 shows the kernel itself takes longer than 2 s on a loaded host, in which case the window is set from the measured time and the reason is in a comment.
- [ ] **Step 5 (GREEN):** 20 consecutive passes under the same load as Step 1's second half; `cargo test -q -p openfeo-harness --test netlink` → all pass; clippy clean.
- [ ] **Step 6: Commit** `harness: <what the stable-privacy scenario got wrong>`.

### Task 4: progress entry

- [ ] **Step 1:** append the PR's entry under `## Follow-ups` in `docs/progress.md` (the three fixes, the issue numbers filed for the rest: #60–#66) and update the M3 row's follow-ups list.
- [ ] **Step 2: Commit** `docs: progress entry for the third minors sweep`.
