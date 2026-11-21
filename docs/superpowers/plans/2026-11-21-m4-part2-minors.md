# M4 part 2: the minors that should not wait Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Of the minors and follow-ups that the reviews of M4 part 2a (#101) and part 2b (#103) left, fix the ten that a person can meet today or that break one of the repository's own rules; the other twenty are issues #104 to #123.

**Architecture:** No new shape. One change in `openfeo-config` (the wire types that carry a secret print none in `Debug`), the rest in the panel: the config store, the renumbering rule, and the two settings pages.

**Tech Stack:** as part 2b. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-11-m4-part2-changing-config-design.md` ("Part 2b: the web", "After part 2b"); `CLAUDE.md` (the rule that a password, token or hash never reaches a log, an error or `Debug` output); SPEC §8.4.

**What is fixed here, and why now**

| | Where it came from | Why it does not wait |
|---|---|---|
| 1 | #101: `Config`'s and `World`'s derived `Debug` print secrets | The repository's rule is about `Debug` output, not only about what is printed today |
| 2 | #103: a session that ends while an apply is in flight leaves what was sent in the store | Call 7: the draft goes when the session ends; what was sent may hold a typed password |
| 3 | #103: every read replaces a draft that has no changes | A reconnect or a config event wipes an address that is half typed |
| 4 | #103: `unfit` is replaced by each renumbering, a no-op included | Retyping the same address clears the marks of addresses that still have no place |
| 5 | #103: `apply`, `confirm` and `revert` have no guard of their own | Only a disabled button stands between a double press and two requests |
| 6 | #103: the save bar is not held while an apply awaits the router's word | Pressing Apply then replaces "The router is moving" with a refusal |
| 7 | #103: swapping two LANs' subnets scrambles addresses | A LAN's own pool and reservations were carried by a move of another LAN |
| 8 | #103: a pool can come out inverted from a move and nothing says so | It is said only when Apply is pressed |
| 9 | #103: violations and "left" flags are keyed by index | Removing a row, a WAN or a LAN leaves them pointing at the wrong one |
| 10 | #103: a 135-character doc line in `effects.rs` | It costs nothing |

## Global Constraints

- Everything in part 2b's plan's Global Constraints stands: SPDX headers, documentation address ranges, the layering rule, the content security policy, the copies of the design system untouched, and above all **a typed PPPoE password lives in the draft, in the tab's memory, and nowhere else**.
- **A password, a token or a hash never reaches `Debug` output.** After Task 1 that holds for every wire type, by construction and by test.
- The words on screen do not change, with one addition (Task 4): while an apply awaits the router's word, the bar says `Waiting to hear from the router what became of the change that was sent.`
- Every gate is run through a command that fails when any step fails: `make lint`, `make test`, and for one package `cd web && npm test -w panel -- <filter>` with its exit status read, never through a pipe.
- Rust: `clippy -D warnings` with pedantic, no `unwrap`/`expect` outside tests; `openfeo-config` stays as pure as it is. `make lint` also passes under the newest stable installed here (`RUSTUP_TOOLCHAIN=1.100.0 CARGO_TARGET_DIR=$PWD/build/target-1.100 make lint`).
- Commits `git commit -s`, identity `Andrew Newton <andy@vitri.ltd>`, subject `<area>: <summary>`. Nothing is pushed without a sweep; never merged.

## Review Focus

1. **A secret in `Debug` by another road.** A message that holds one of the seven inside it (`Config` holds `Admin`; `Request` holds `ChangePasswordRequest`; `World` holds a `Config`) must print none either, and a message added later that carries a secret must not slip past. Pinned by `no_wire_type_prints_a_secret` and `a_field_that_holds_a_secret_is_named_here` (Task 1).
2. **The session ends at each await of the store.** Review, apply, confirm and revert each wait on the router; whichever is in flight when the session ends must leave nothing behind. Pinned by `nothing_is_left_when_the_session_ends_while_the_router_is_being_asked` (Task 2).
3. **A read that must still replace the draft.** Keeping the draft when the config read equals it must not keep one that differs (another session's change, a revert). Pinned by the existing "followed silently" and "goes back" tests staying green, and `a_read_that_brings_what_the_draft_already_is_leaves_the_draft_alone` (Task 2).
4. **Leftovers of an earlier renumbering that now fit.** An address that had no place, and has one after the next move, must stop being marked. Pinned by `what_had_no_place_is_still_marked_after_a_move_that_gives_it_none` and its second half (Task 2).
5. **Another LAN's servers that sit on this LAN.** Carrying only the owner's own pool must still carry a DNS or NTP server that another LAN hands out and that sits on the LAN being moved. Pinned by `a_lans_own_pool_follows_only_its_own_move` (Task 3).

---

### Task 1: No wire type prints a secret in `Debug`

**Files:**
- Modify: `crates/openfeo-config/build.rs`, `crates/openfeo-config/src/secrets.rs`
- Test: `crates/openfeo-config/src/secrets.rs` (`tests`), `crates/openfeo-reconcile/src/state.rs` or `fixtures.rs` (`tests`: a World)

**Interfaces:**
- Produces: hand-written `Debug` for the seven messages that carry a secret: `Admin` (`password_hash`), `PppoeWan` (`password`), `api::Auth` (`token`), `api::Session` (`token`), `api::LoginRequest` (`password`), `api::SetInitialPasswordRequest` (`password`), `api::ChangePasswordRequest` (`old_password`, `new_password`). Each prints its other fields as the derive would and the secret as `"<redacted>"`, or `""` when it is empty (so that "no password is set" still reads). `prost-build` is told to derive none for those seven (`skip_debug`).

- [ ] **Step 1: Write the failing tests.**

```rust
// openfeo-config, secrets.rs
#[test] fn no_wire_type_prints_a_secret() {
    // A Config with an admin hash and a PPPoE password; each of the five API messages with its secret set;
    // and the messages that hold them (ClientMsg with Auth, Request with ChangePassword, LoginResponse with a Session).
    // format!("{:?}") and format!("{:#?}") of each contain none of the secrets, and do contain "<redacted>".
}
#[test] fn an_empty_secret_reads_as_empty() { /* Admin::default() prints password_hash: "" */ }
#[test] fn a_field_that_holds_a_secret_is_named_here() {
    // Walk the file descriptor set (descriptors.bin): every string or bytes field whose name contains
    // "password", "token", "secret" or "hash" belongs to one of the seven messages; `tls_fingerprint` and
    // `tag` are not secrets and are named as exceptions. A field added later fails this until it is handled.
}
// openfeo-reconcile
#[test] fn the_debug_of_a_world_prints_no_secret() { /* fixtures::pppoe_world(): "example-secret" is not in {:?} */ }
```

- [ ] **Step 2: Run them.** `cargo test -p openfeo-config secrets:: && cargo test -p openfeo-reconcile the_debug_of_a_world` Expected: the first and the last FAIL (the secret is printed); the third fails or passes according to the list.
- [ ] **Step 3: Implement.** `skip_debug` for the seven in `build.rs`; the seven `impl fmt::Debug` in `secrets.rs`, each a `debug_struct` over every field.
- [ ] **Step 4: Run.** `cargo test -p openfeo-config -p openfeo-reconcile -p openfeo-api` Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -s -m "config: no wire type prints a secret in Debug"`

### Task 2: The config store

**Files:**
- Modify: `web/panel/src/config.ts`, `web/panel/test/config.test.ts`, `web/panel/test/lan.test.ts`

**Interfaces:**
- `ConfigStore` gains `awaiting: ComputedRef<boolean>`: an apply had no answer and the router has not yet said whether it took it.
- `setLanAddress(lan, ipv4)`: setting the address it already has does nothing. Otherwise `unfit` becomes what this renumbering could not place, and before it whatever an earlier one could not place that is still where it was left and is still not an address a device can have in this LAN's new subnet.

- [ ] **Step 1: Write the failing tests** in `config.test.ts`:

```ts
test('nothing is left when the session ends while the router is being asked')
  // for each of review, apply (answered, and not), confirm and revert: hold the call, end the session, let it go:
  // base and draft are null, notice is null, violations are empty; a later state push restores nothing
test('a read that brings what the draft already is leaves the draft alone')
  // the same object before and after; a read that brings another config still replaces it
test('what had no place is still marked after a move that gives it none')
  // /24 → /26: the pool's two ends are unfit; the same address set again: still both;
  // the router moved within the /26: still both; back to a /24: neither
test('a second ask while one is under way is not sent')
  // apply twice in one tick: one call; likewise confirm and revert
test('an apply that awaits the router says so')
  // awaiting is false, true after an unanswered apply, false once it is settled either way
```

and in `lan.test.ts`:

```ts
test('an address that is half typed outlives a read of the config')
  // type "192.168.9" into Router address without leaving it; a config event comes; the field still shows it
```

- [ ] **Step 2: Run them.** `cd web && npm test -w panel -- test/config.test test/lan.test` Expected: the six FAIL.
- [ ] **Step 3: Implement.** A counter that `forget()` advances; each of the four calls reads it before its await and returns at once after it when it has moved. `took` replaces a draft that has no changes only when it differs from the config read. `busy` guards the four calls.
- [ ] **Step 4: Run.** `cd web && npm test -w panel` Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -s -m "panel: the store when the session ends mid-ask, and a draft that is left alone"`

### Task 3: A LAN's own pool follows only its own move

**Files:**
- Modify: `web/panel/src/model/renumber.ts`, `web/panel/src/config.ts` (passes the LAN's name), `web/panel/test/renumber.test.ts`

**Interfaces:**
- `renumber(config, from, to, owner?: string)`: with `owner` (a LAN's name), a field classified `own` is carried only under that LAN. `STRING_FIELDS` gains the kind `own` for `lans.dhcp.range` and `lans.dhcp.static.ip`; `lans.dhcp.dns` and `lans.dhcp.ntp` stay `carried` (a server on this LAN that another LAN hands out follows this LAN). Without `owner` every `own` field is carried, as before.

- [ ] **Step 1: Write the failing tests:**

```ts
test("a LAN's own pool follows only its own move")
  // lan0 192.168.1.1/24 and guest 192.168.3.1/24, each with a pool and a reservation; guest hands out a DNS server on lan0.
  // lan0 → 192.168.3.1/24 (owner lan0): lan0's pool and reservation move, guest's stay, guest's DNS server follows.
  // guest → 192.168.1.1/24 (owner guest): guest's own move; lan0's, now also in 192.168.3.0/24, stay.
test('every string field of the config is classified')   // extended: `own` is exactly the two
```

- [ ] **Step 2: Run them.** Expected: FAIL (lan0's pool is carried by guest's move).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** `cd web && npm test -w panel` Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -s -m "panel: a LAN's own pool follows only its own move"`

### Task 4: The pages and the bar

**Files:**
- Modify: `web/panel/src/pages/Lan.vue`, `web/panel/src/pages/Wan.vue`, `web/panel/src/Shell.vue`, `web/panel/src/fields.ts`
- Test: `web/panel/test/lan.test.ts`, `web/panel/test/wan.test.ts`, `web/panel/test/apply.test.ts`

**Interfaces:**
- `fields.ts`: `forgetUnder(fields: PageFields, store: ConfigStore, path: string): void` drops the violations, the "left" flags and the typed text at or beneath `path`.
- After a LAN's address or size is taken, the fields a renumbering carries on that LAN (the pool's two ends, each reservation's address, the DNS and NTP servers) count as left.
- The shell's bar: `held` is `Confirm or revert the change that is waiting first.` while a change is pending, else `Waiting to hear from the router what became of the change that was sent.` while `awaiting`.

- [ ] **Step 1: Write the failing tests:**

```ts
// lan.test.ts
test('a pool that a move left the wrong way round says so at once')
  // 192.168.1.1/24 → 192.168.1.129/25: Pool start shows "The pool starts after it ends." with no field left by hand
test('removing a reservation takes what was said of the rows with it')
  // a violation at lans[0].dhcp.static[1].ip; remove row 0: no row shows it, the tab has no pill
test('removing a LAN takes what was said of the LANs with it')
// wan.test.ts
test('removing a WAN takes what was said of the WANs with it')
// apply.test.ts
test('while an apply awaits the router the bar says so and offers none')
```

- [ ] **Step 2: Run them.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** `cd web && npm test -w panel && make web-lint` Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -s -m "panel: a move's inverted pool, what was said of a removed row, and the bar while an apply waits"`

### Task 5: The documents and the whole gate

**Files:**
- Modify: `crates/openfeo-reconcile/src/effects.rs` (the long doc line), `docs/progress.md`, `docs/superpowers/specs/2026-11-11-m4-part2-changing-config-design.md` ("After part 2b": what this sweep changed)

- [ ] **Step 1: The doc line** is wrapped at the file's width.
- [ ] **Step 2: `docs/progress.md`** gains the sweep's entry under M4 and its number in M4's row as a follow-up.
- [ ] **Step 3: The design's "After part 2b"** says what changed: `renumber` takes the owner; `ConfigStore.awaiting`; the store when the session ends.
- [ ] **Step 4: The whole gate.** `make lint && make test && make bin FEATURES= && make kernel && make check-env && OPENFEO_NO_SKIP=1 make test-harness`, and `make lint` under the newest stable. Expected: all green, no scenario skipped, the count of scenarios as on `main`.
- [ ] **Step 5: Commit.** `git commit -s -m "docs: the part 2 minors sweep in the progress log and the design"`
