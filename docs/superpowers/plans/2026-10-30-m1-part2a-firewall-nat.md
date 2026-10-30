# OpenFeO M1 part 2a — Firewall and NAT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The router forwards and NATs: libnftables linked in-process applies one `table inet openfeo` generated from the World (zones, input and forward policy, masquerade, port forwards with hairpin, reverse-path filtering), forwarding is switched on only together with that ruleset, and the harness proves a LAN client fetching HTTP through NAT, a port forward reached from the WAN and via hairpin, a WAN that is blocked by default, and a router-child crash that does not interrupt forwarding.

**Architecture:** `openfeo-nft` builds nftables, libnftnl, libmnl and jansson statically (for musl and for the host) in its build script from tarballs pinned by sha256 under `nft/`, using Linux UAPI headers installed from our own kernel tree, and exposes a safe `Nft` wrapper over the libnftables JSON API (ADR-0012). The configuration gains `[firewall]` (port forwards, `wan_ping`). `reconcile::nft` and `reconcile::sysctl` are pure `World -> Desired` with snapshot tests; `apply::nft` replaces the whole table atomically when the desired ruleset changes and `apply::sysctl` writes `ip_forward` and per-interface `send_redirects` only after the ruleset is in place. The router's `apply` task runs links, routing, nft, sysctl in that order. The harness gains HTTP targets (`python3 -m http.server` in a namespace), a Rust in-namespace HTTP client, and a ping-loop helper.

**Tech Stack:** nftables 1.1.7, libnftnl 1.3.2, libmnl 1.0.5, jansson 2.15.1 (autotools, `musl-gcc` and host `cc`, `pkg-config`, `bison`, `flex`); Rust FFI in `openfeo-nft/src/sys.rs`; serde_json for rulesets; insta snapshots; existing harness (rootless sandbox, QEMU, QMP, `python3`, `ping`).

**Spec:** `SPEC.md` — §2 (Firewall backend; ADR-0003), §4.2 (netfilter options), §6.2 (reconcile/apply), §7.4 (reverse-path filtering in nft), §7.5 (firewall and NAT), §7.9 (forwarding lever), §8.2 (`[firewall]`), §9 (default deny inbound on WAN), §11, §12 row M1, §13 (crate rules: `openfeo-nft` may hold `unsafe` in a small module; C code built in `openfeo-nft/build.rs` with `--with-json --with-mini-gmp --without-cli --without-xtables`), §14 (GPL-2.0-only libnftables makes the shipped binary GPLv2).

## Global Constraints

- Everything in the M1 part 1 plan's Global Constraints still holds (identity, commits and trailers, lints, SPDX headers, pure crates, no `std::process::Command` outside `harness/` and `image/` except where this plan says so for a build script, every parser gets a fuzz target).
- `unsafe` is allowed in `openfeo-nft` only inside `src/sys.rs`, every block with a `// SAFETY:` comment (SPEC §9, CLAUDE.md).
- The ruleset is one `table inet openfeo`, regenerated from the World and applied as a single libnftables batch beginning `add table inet openfeo; delete table inet openfeo;` followed by the full definition (SPEC §7.5). Named sets and maps hold port-forward targets so rule counts never grow with list sizes.
- Zone policy (SPEC §7.5, §9): LAN→WAN accept; WAN→LAN drop; LAN↔LAN accept within a LAN; WAN→router drop except the DHCPv4 client's replies (UDP 68 from 67; the ICMPv6 and DHCPv6 items are M2) and ICMP echo when `wan_ping` is on; LAN→router: DHCP (UDP 67), DNS (53 UDP and TCP), HTTPS (443) and HTTP (80), NTP (UDP 123), ICMP. Default deny inbound on WAN, IPv6 exactly as safe as IPv4 (the `inet` table applies to both).
- NAT: IPv4 masquerade per WAN; port forwards as `dnat` maps with hairpin (a LAN client reaching a forwarded port on a router address is DNATed and SNATed to the router); no IPv6 NAT (SPEC §7.5).
- Reverse-path filtering in nft, not sysctl: `fib saddr . iif oif missing drop` on LAN zones, `fib saddr oif missing drop` on WAN zones; kernel `rp_filter` stays 0 (SPEC §7.4).
- `net.ipv4.ip_forward` is 1 only while a ruleset with at least one WAN and one LAN is applied; first-boot defaults forward nothing (SPEC §5.6). `send_redirects=0` per managed interface (an M0 deferred minor).
- Vendored C sources are fetched from the URLs and verified against the sha256 values in `nft/sources.txt` and nowhere else; a mismatch deletes the file and fails. Kernel UAPI headers come from `make headers_install` of our pinned kernel, never from the host.
- Licences: nftables and libnftnl GPL-2.0-only, libmnl LGPL-2.1-or-later, jansson MIT; the resulting binary is a GPLv2 work (SPEC §14, ADR-0002). Record them in `docs/third-party.md`.

## Review Focus

1. A port forward whose target is not inside any LAN subnet (`to = "10.9.9.9"`): rejected with `forward_target_outside_lan`, never a DNAT into nowhere. Test in Task 3 (`forward_target_must_be_in_a_lan`).
2. A port forward on a port the router itself serves on the WAN side (53, 67, 68, 80, 123, 443): rejected with `reserved_port`, because the DNAT would silently hijack the router's own service. Test in Task 3 (`reserved_ports_are_rejected`).
3. No WAN configured (first boot): forwarding stays off, no masquerade and no WAN rules, yet LAN→router services are still accepted. Test in Task 4 (`first_boot_ruleset_forwards_nothing`).
4. libnftables rejects the ruleset (a kernel without an expression, a malformed object): the nft subsystem goes Degraded with the kernel's own error text, and the sysctl applier does not run, so `ip_forward` stays 0. Tests in Task 2 (`rejected_ruleset_reports_the_error`) and Task 6 (ordering assertion in `apply_task`).
5. A router-child crash while traffic flows: at most 2 lost pings out of about 125 across the restart. Test in Task 8 (`child_crash_does_not_interrupt_forwarding`).

---

## File structure

```
openfeo/
  nft/sources.txt  nft/fetch.sh            pinned tarballs, sha256-verified fetch and extract into build/nft/src/
  kernel/build.sh                          + `headers`: make headers_install into build/kernel/headers
  Makefile                                 + kernel-headers, nft-src; bin/lint/test depend on them; exports OPENFEO_UAPI_INCLUDE, OPENFEO_NFT_SRC
  crates/openfeo-nft/                      build.rs (autotools builds), src/lib.rs (Nft), src/sys.rs (FFI)
  crates/openfeo-platform/src/sysctl.rs    read/write under /proc/sys
  crates/openfeo-config/                   proto Firewall/PortForward; validate codes
  crates/openfeo-reconcile/src/nft.rs      DesiredNft; src/sysctl.rs DesiredSysctl; snapshots
  crates/openfeo-apply/src/nft.rs          NftApplier; src/sysctl.rs SysctlApplier
  crates/openfeo-world/src/health.rs       Subsystem::{Nft, Sysctl}
  crates/openfeo/src/router.rs             apply order links, routing, nft, sysctl
  harness/src/daemons.rs                   http_server; src/lanclient.rs http_get, ping_loop; lab.rs helpers
  harness/tests/nft.rs                     sandboxed libnftables tests; tests/m1.rs + 5 scenarios
  harness/fixtures/vm-static.toml          + [firewall] with wan_ping = true and one port forward
  docs/adr/0012-libnftables-built-from-pinned-sources.md  docs/third-party.md
  .github/workflows/ci.yml                 pkg-config; make kernel-src kernel-headers nft-src in both jobs; cache build/nft/dl
```

---

### Task 1: Vendored sources and kernel UAPI headers in the build pipeline

**Files:**
- Create: `nft/sources.txt`, `nft/fetch.sh`
- Modify: `kernel/build.sh` (`headers` verb), `Makefile`, `.github/workflows/ci.yml`, `harness/src/main.rs` (`check` lists `musl-gcc`, `pkg-config`, `bison`, `flex`, `python3`), `README.md`, `CLAUDE.md`

**Interfaces:**
- Produces: `build/nft/src/{jansson-2.15.1,libmnl-1.0.5,libnftnl-1.3.2,nftables-1.1.7}/` (extracted, verified), `build/kernel/headers/include/` (UAPI headers), and for every cargo invocation from `make` the environment `OPENFEO_NFT_SRC=$(BUILD)/nft/src` and `OPENFEO_UAPI_INCLUDE=$(BUILD)/kernel/headers/include`.

- [ ] **Step 1: `nft/sources.txt`** (fields: name, version, url, sha256; `#` comments allowed)

```
nftables 1.1.7 https://www.netfilter.org/pub/nftables/nftables-1.1.7.tar.xz a6fbf060d8d4fff001517a2b94f356bb4366bfbf0ba366366f9d27cc38caa58f
libnftnl 1.3.2 https://www.netfilter.org/pub/libnftnl/libnftnl-1.3.2.tar.xz c97abc3409f8fa396b4462b2bb7f147a3a47a4ddc97cfa0b2f18890c9cfde8b0
libmnl 1.0.5 https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2 274b9b919ef3152bfb3da3a13c950dd60d6e2bcd54230ffeca298d03b40d0525
jansson 2.15.1 https://github.com/akheron/jansson/releases/download/v2.15.1/jansson-2.15.1.tar.gz 0c7114dc0b2d22a670724a1f95922029d7077c19dbf79a584cb8084d2f267f2f
```

(The netfilter sums come from the project's `.sha256sum` files; jansson publishes none, so its sum is the one recorded on 2026-10-30 and pinned here.)

- [ ] **Step 2: `nft/fetch.sh`** (`set -euo pipefail`, SPDX header; `BUILD` from the environment, default `build`)

For each line: download to `$BUILD/nft/dl/<file>` with `curl -sSfL` unless present; `sha256sum -c` against the pinned value, deleting the file and exiting 1 on mismatch (`nft: <file>: sha256 mismatch`); extract into `$BUILD/nft/src/<name>-<version>/` unless that directory exists. Prints one `nft: <name>-<version> ok` line each. Idempotent.

- [ ] **Step 3: Verify fetch, idempotence and tamper detection**

Run: `BUILD=build nft/fetch.sh && BUILD=build nft/fetch.sh | wc -l` → 4 `ok` lines twice; `ls build/nft/src` → the four directories.
Run: `cp build/nft/dl/libmnl-1.0.5.tar.bz2 /tmp/x && printf 'x' >> build/nft/dl/libmnl-1.0.5.tar.bz2 && BUILD=build nft/fetch.sh; echo "exit=$?"; cp /tmp/x build/nft/dl/libmnl-1.0.5.tar.bz2` → `nft: libmnl-1.0.5.tar.bz2: sha256 mismatch`, `exit=1`, and the tampered file is gone before the restore.

- [ ] **Step 4: `kernel/build.sh headers`**

`make -C "$SRC" O="$OUT" ARCH=x86_64 INSTALL_HDR_PATH="$BUILD/kernel/headers" headers_install` (same `SRC`/`OUT` variables the `build` verb uses). Run: `KERNEL_VERSION=6.18.59 BUILD=$PWD/build kernel/build.sh headers && ls build/kernel/headers/include/linux/netfilter/nf_tables.h` → the file exists.

- [ ] **Step 5: Makefile**

`export OPENFEO_NFT_SRC := $(BUILD)/nft/src` and `export OPENFEO_UAPI_INCLUDE := $(BUILD)/kernel/headers/include` at the top. Targets: `kernel-headers: kernel-src` runs `kernel/build.sh headers`; `nft-src` runs `BUILD=$(BUILD) nft/fetch.sh`; `bin`, `lint` and `test` depend on `kernel-headers nft-src`; `.PHONY` updated. `check-env` and `run` unchanged.

- [ ] **Step 6: CI**

Both jobs: apt adds `pkg-config` (lint job also `bc flex bison libelf-dev libssl-dev` for `headers_install`... `headers_install` needs only `make` and `rsync`-free kernel tooling: add `bison flex` to be safe); cache `build/kernel/linux-6.18.59.tar.xz` and `build/nft/dl` (key `sources-${{ hashFiles('kernel/linux-6.18.59.sha256', 'nft/sources.txt') }}`); run `make kernel-src kernel-headers nft-src` before `make lint`/`make test`/`make kernel`.

- [ ] **Step 7: Docs and check-env**

README prerequisites add `pkg-config` and note that `make` fetches and builds nftables and friends; CLAUDE.md Commands: `make nft-src kernel-headers` are implied by `make bin/lint/test` and a bare `cargo build` needs `OPENFEO_NFT_SRC` and `OPENFEO_UAPI_INCLUDE`. `check` lists the five tools.

- [ ] **Step 8: Verify and commit**

Run: `make lint` → exit 0 (nothing consumes the variables yet). Commit: `build: pin and fetch nftables, libnftnl, libmnl, jansson; install kernel UAPI headers`.

---

### Task 2: `openfeo-nft`: static libnftables build, FFI, safe `Nft`, sandbox tests, ADR-0012

**Files:**
- Create: `crates/openfeo-nft/Cargo.toml` (deps `serde_json`, `thiserror`; `publish = false`; `[lints] workspace = true`), `build.rs`, `src/lib.rs`, `src/sys.rs`, `harness/tests/nft.rs` (`harness = false`), `docs/adr/0012-libnftables-built-from-pinned-sources.md`, `docs/third-party.md`
- Modify: `harness/Cargo.toml` (`[[test]] nft`, dev-dep `openfeo-nft`), `Makefile` (`test-harness` adds `--test nft`), `scripts/check-deps.sh` (`openfeo-nft` is already in the KERNEL set)

**Interfaces:**
- Produces: `openfeo_nft::Nft` with `Nft::new() -> Result<Nft, NftError>`, `fn apply(&mut self, ruleset: &[serde_json::Value]) -> Result<(), NftError>` (sends `{"nftables": ruleset}` as one buffer: atomic), `fn list_ruleset(&mut self) -> Result<serde_json::Value, NftError>` (the `nftables` array of the JSON output), `fn run(&mut self, command: &str) -> Result<String, NftError>` (raw: the output buffer), `impl Drop`, `unsafe impl Send` (one task uses it at a time; documented); `NftError::{Init, Rejected { message: String } (the error buffer, trimmed), Output(String) (output not JSON)}`.
- Context flags: `nft_ctx_new(NFT_CTX_DEFAULT)`, input `NFT_CTX_INPUT_JSON | NFT_CTX_INPUT_NO_DNS`, output `NFT_CTX_OUTPUT_JSON | NFT_CTX_OUTPUT_NUMERIC_ALL`, both buffers on. `nft_run_cmd_from_buffer` returns 0 on success; anything else is `Rejected` with the error buffer.

- [ ] **Step 1: Failing sandbox scenarios** in `harness/tests/nft.rs` (runner like `netlink.rs`, `sandbox::enter()` first; no tokio needed)

`applies_and_lists_a_table` (apply `[add table inet t0, add chain {name: "input", type: "filter", hook: "input", prio: 0, policy: "accept"}, add rule {expr: [{"accept": null}]}]` → `Ok`; `list_ruleset()` contains an object with `"table"` named `t0` and a `"chain"` named `input`), `replace_is_idempotent` (apply the same `add table; delete table; add table; …` batch twice → both `Ok`, exactly one table `t0` listed), `rejected_ruleset_reports_the_error` (a rule with `{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "nosuchfield"}}, "right": 1}}` → `Err(NftError::Rejected { message })` with `message` non-empty, and no table added when the batch was the first command), `init_works_without_capabilities_until_used` (`Nft::new()` is `Ok` even outside root; the first `apply` in a plain user namespace without a netns still works because the sandbox has `CAP_NET_ADMIN`). Each scenario deletes its table afterwards (`delete table inet t0`, ignoring errors).

- [ ] **Step 2: Run** `cargo test -p openfeo-harness --test nft` → FAIL (crate missing).

- [ ] **Step 3: `build.rs`**

`#![allow(clippy::disallowed_methods)] // build-time only: configure and make of the vendored C libraries`. Reads `OPENFEO_NFT_SRC` and `OPENFEO_UAPI_INCLUDE` (panic with `set them or run make` when absent). `CC = musl-gcc` and `--host=x86_64-linux-musl` when `TARGET` contains `musl`, else `cc`. For each of jansson, libmnl, libnftnl, nftables (in that order): out-of-tree configure in `$OUT_DIR/build/<name>` (`<src>/configure --prefix=$OUT_DIR/prefix --disable-shared --enable-static` plus for nftables `--with-mini-gmp --with-json --without-cli --disable-man-doc --disable-python`), environment `CFLAGS="-O2 -fPIC -isystem $OPENFEO_UAPI_INCLUDE"`, `PKG_CONFIG_LIBDIR=$OUT_DIR/prefix/lib/pkgconfig`, `PKG_CONFIG_PATH` and `PKG_CONFIG_SYSROOT_DIR` removed; `make -j$NUM_JOBS install`. Skip a library whose `.a` is already in `prefix/lib`. Emit `cargo:rustc-link-search=native=$OUT_DIR/prefix/lib`, `rustc-link-lib=static=nftables`, `static=nftnl`, `static=mnl`, `static=jansson`, `rerun-if-env-changed` for both variables, `rerun-if-changed=build.rs`.

- [ ] **Step 4: `src/sys.rs`** (`#![allow(unsafe_code)]`; the only module with `unsafe`)

Opaque `nft_ctx`, the nine `unsafe extern "C"` declarations from `include/nftables/libnftables.h` (`nft_ctx_new`, `nft_ctx_free`, `nft_ctx_input_set_flags`, `nft_ctx_output_set_flags`, `nft_ctx_buffer_output`, `nft_ctx_buffer_error`, `nft_ctx_get_output_buffer`, `nft_ctx_get_error_buffer`, `nft_run_cmd_from_buffer`), the flag constants above, and safe-ish wrappers taking `NonNull<nft_ctx>`.

- [ ] **Step 5: `src/lib.rs`**: `Nft` as in Interfaces; `#![forbid(unsafe_code)]` is NOT possible here, so `#![deny(unsafe_code)]` at the crate root with `#[allow(unsafe_code)]` on `mod sys` (as `openfeo-init` does).

- [ ] **Step 6: Run** `cargo test -p openfeo-harness --test nft` → 4 passed. Then `make bin FEATURES=` → the musl binary links (nothing uses the crate yet; add `openfeo-nft` to `crates/openfeo/Cargo.toml` so the static link is exercised) and `file` says static.

- [ ] **Step 7: ADR-0012 and third-party notices**

ADR: context (ADR-0003 chose libnftables in-process; the harness classifier blocked ad-hoc builds of downloaded code, so the build lives in the repository's pipeline like the kernel's), decision (pinned tarballs in `nft/sources.txt`, verified fetch, out-of-tree static builds in `build.rs` for host and musl, UAPI headers from our kernel), consequences (build time, `pkg-config`/`bison`/`flex`/`musl-gcc` as build dependencies, GPLv2 binary). `docs/third-party.md`: the four libraries with version, licence, URL.

- [ ] **Step 8: Commit** `nft: libnftables built statically from pinned sources, safe Nft wrapper (ADR-0012)`.

---

### Task 3: `[firewall]` schema and validation

**Files:**
- Modify: `proto/openfeo/v1/config.proto`, `crates/openfeo-config/src/validate.rs`, `crates/openfeo-config/src/file.rs` (tests), `harness/fixtures/vm-static.toml`, `SPEC.md` §8.2 example
- Reconcile fixtures use the fixture file, so their snapshots change in Task 4, not here.

**Interfaces:**
- Produces (proto): `Config.firewall = 6` of type `Firewall { repeated PortForward port_forwards = 1; bool wan_ping = 2; }`, `PortForward { string name = 1; string proto = 2 ("tcp"|"udp"); uint32 port = 3; string to = 4; uint32 to_port = 5 (0 = same as port); }`. New `Code`s: `InvalidProto`, `InvalidPort`, `ForwardTargetOutsideLan`, `ReservedPort`; `pub const RESERVED_WAN_PORTS: [u16; 6] = [53, 67, 68, 80, 123, 443]`; paths `firewall.port_forwards[i].{name,proto,port,to,to_port}`.

- [ ] **Step 1: Failing tests**

In `validate.rs`: `port_forward_valid_passes` (fixture-shaped forward 2222/tcp → 192.168.1.2:8080 with LAN 192.168.1.1/24 → no violations), `forward_target_must_be_in_a_lan` (`to = "10.9.9.9"` → `(firewall.port_forwards[0].to, ForwardTargetOutsideLan)`), `reserved_ports_are_rejected` (each of 53, 67, 68, 80, 123, 443 → `ReservedPort` at `.port`), `invalid_proto_and_ports` (`proto = "sctp"` → `InvalidProto`; `port = 0` and `to_port = 70000` → `InvalidPort`; `to = "nonsense"` → `InvalidAddress`), `duplicate_forward_names` (`firewall.port_forwards[1].name`, `DuplicateName`). In `file.rs`: `parses_firewall_section` (TOML with `[firewall]` `wan_ping = true` and one `[[firewall.port_forwards]]` → `cfg.firewall.unwrap().port_forwards[0].to_port == 8080`).

- [ ] **Step 2: Run** → FAIL (no field). **Step 3: Implement** (proto, `validate`, codes). **Step 4: Run** `cargo test -p openfeo-config` → PASS; `buf lint proto` clean; `scripts/check-proto.sh` passes (`origin/main` has the Task-3-less schema: adding a field is not breaking).

- [ ] **Step 5: Fixture and spec**

`vm-static.toml` gains:

```toml
[firewall]
wan_ping = true                 # the lab pings the WAN address from the ISP side

[[firewall.port_forwards]]
name = "lan-http"
proto = "tcp"
port = 2222
to = "192.168.1.2"
to_port = 8080
```

SPEC §8.2: replace `[firewall]\n# zone policies, port forwards, rules` with the same shape (`wan_ping = false` in the spec's example) and a comment that zone policies stay as §7.5 defines until the panel (M4).

- [ ] **Step 6: Commit** `config: firewall section with port forwards and wan_ping, validation`.

---

### Task 4: `reconcile::nft` and `reconcile::sysctl` with snapshots

**Files:**
- Create: `crates/openfeo-reconcile/src/nft.rs`, `src/sysctl.rs`, snapshots
- Modify: `src/lib.rs` (mods, `pub const TABLE: &str = "openfeo"`), `Cargo.toml` (`serde_json`), `harness/tests/nft.rs` (one scenario applying the generated ruleset through libnftables)

**Interfaces:**
- Produces: `openfeo_reconcile::nft::{nft(world: &World) -> DesiredNft, DesiredNft { ruleset: Vec<serde_json::Value>, forwarding: bool, wan_if: BTreeSet<String>, lan_if: BTreeSet<String> }}` (`forwarding = !wan_if.is_empty() && !lan_if.is_empty()`; `ruleset` is the complete `nftables` array, starting with add/delete/add of `table inet openfeo`); `openfeo_reconcile::sysctl::{sysctl(world: &World, forwarding: bool) -> DesiredSysctl, DesiredSysctl { entries: BTreeMap<String, String> }}` with `net/ipv4/ip_forward` = `1`/`0` and `net/ipv4/conf/<if>/send_redirects = 0` for every WAN port with a role and every LAN bridge.
- Ruleset objects, in order (nft syntax given; the JSON is the libnftables-json(5) rendering, which Step 3 below lets you take from `nft -j` in a user namespace):
  - `add table inet openfeo`, `delete table inet openfeo`, `add table inet openfeo`
  - sets `wan_if` and `lan_if` of `type ifname` with the zone interfaces as elements (omit `elem` when empty); maps `fwd_tcp` and `fwd_udp` of `type inet_service : ipv4_addr . inet_service` with one element per port forward (`to_port` defaults to `port`)
  - chain `rpfilter` (`type filter hook prerouting priority -300; policy accept`): `iifname @lan_if fib saddr . iif oif missing drop`; `iifname @wan_if fib saddr oif missing drop`
  - chain `input` (`type filter hook input priority 0; policy drop`): `ct state established,related accept`; `ct state invalid drop`; `iif lo accept`; `iifname @lan_if udp dport { 53, 67, 123 } accept`; `iifname @lan_if tcp dport { 53, 80, 443 } accept`; `iifname @lan_if meta l4proto icmp accept`; `iifname @wan_if udp sport 67 udp dport 68 accept`; when `wan_ping`: `iifname @wan_if icmp type echo-request accept`
  - chain `forward` (`type filter hook forward priority 0; policy drop`): `ct state established,related accept`; `ct state invalid drop`; `ct status dnat accept`; `iifname @lan_if oifname @wan_if accept`; `iifname @lan_if oifname @lan_if accept`
  - chain `dstnat` (`type nat hook prerouting priority -100; policy accept`): `iifname @wan_if dnat ip addr . port to tcp dport map @fwd_tcp`; the udp twin; `iifname @lan_if fib daddr type local dnat ip addr . port to tcp dport map @fwd_tcp` (hairpin, also when the client used the router's LAN address); the udp twin
  - chain `srcnat` (`type nat hook postrouting priority 100; policy accept`): `oifname @wan_if masquerade`; `iifname @lan_if oifname @lan_if ct status dnat masquerade`
  - Without any WAN: the WAN-dependent rules and maps are still emitted with empty sets (so the structure is stable) but `forwarding` is false.

- [ ] **Step 1: Failing snapshot tests**

`static_world_ruleset` (snapshot of `nft(&static_world())`; plus assertions: `forwarding`, `wan_if == {p0}`, `lan_if == {br-lan0}`, the `fwd_tcp` map has one element `2222 → 192.168.1.2 . 8080`, the input chain has an `echo-request` rule because the fixture sets `wan_ping`), `first_boot_ruleset_forwards_nothing` (`forwarding == false`, no masquerade rule carries a non-empty set, LAN→router rules present; snapshot), `sysctl_follows_forwarding` (`sysctl(&static_world(), true)` → `ip_forward = 1`, `send_redirects` for `p0` and `br-lan0` only (not `p1`); with `false` → `ip_forward = 0`).

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (build each object with `serde_json::json!`; to get the exact JSON shape of a rule, run `unshare -Urn nft -j -f -` on the host with the nft-syntax rule and copy the structure; the host's `nft` is 1.1.7, the vendored version). **Step 4: Run** with `INSTA_UPDATE=always` then plain → PASS; read the `.snap` files.

- [ ] **Step 5: Failing sandbox scenario** in `harness/tests/nft.rs`: `generated_ruleset_is_accepted_by_libnftables` (build `static_world()` the way `netlink.rs` does, `Nft::new()?.apply(&nft(&world).ruleset)` → `Ok`; `list_ruleset()` shows table `openfeo` with chains `rpfilter`, `input`, `forward`, `dstnat`, `srcnat`; apply again → `Ok`). Run → FAIL until the JSON is right → PASS.

- [ ] **Step 6: Commit** `reconcile: nft ruleset and sysctl as pure World -> Desired with snapshots`.

---

### Task 5: `platform::sysctl`, `apply::nft`, `apply::sysctl`, health subsystems

**Files:**
- Create: `crates/openfeo-platform/src/sysctl.rs`, `crates/openfeo-apply/src/nft.rs`, `crates/openfeo-apply/src/sysctl.rs`
- Modify: `crates/openfeo-world/src/health.rs` (`Subsystem::Nft`, `Subsystem::Sysctl`, `as_str` `nft`, `sysctl`), `crates/openfeo-apply/Cargo.toml` (deps `openfeo-nft`, `openfeo-platform`, `serde_json`), `src/lib.rs` (`ApplyError::Nft(String)`, `ApplyError::Io { path, source }`), `harness/tests/netlink.rs` (scenarios)

**Interfaces:**
- Produces: `openfeo_platform::sysctl::{read(key: &str) -> io::Result<String>, write(key: &str, value: &str) -> io::Result<()>}` (`key` like `net/ipv4/ip_forward`, under `/proc/sys`; `read` trims); `openfeo_apply::nft::NftApplier::new(nft: Nft) -> Self`, `fn apply(&mut self, desired: &DesiredNft) -> Result<Report, ApplyError>` (applies when the ruleset differs from the last applied one in this process; `ops` 1 when applied; logs `ruleset applied: {chains} chains, {rules} rules`); `openfeo_apply::sysctl::SysctlApplier::new() -> Self`, `fn apply(&mut self, desired: &DesiredSysctl) -> Result<Report, ApplyError>` (reads each key, writes when different, logs `sysctl {key}={value}`, best-effort with the first error at the end).

- [ ] **Step 1: Failing sandbox scenarios** in `netlink.rs`

`nft_applier_applies_once_then_noops` (fresh `Nft`, `NftApplier::apply(&nft(&world))` → `ops == 1`; again → `ops == 0`; a changed `wan_ping` → `ops == 1`; `list_ruleset` shows the echo-request rule come and go), `sysctl_applier_turns_forwarding_on_and_off` (in the sandbox netns `ip_forward` starts at 0; apply `{ip_forward: 1, conf/br-lan0/send_redirects: 0}` after the static rig built `br-lan0` → `ops == 2`, `sysctl::read("net/ipv4/ip_forward") == "1"`; apply again → `ops == 0`; apply `ip_forward: 0` → `ops == 1`), `sysctl_for_a_missing_interface_is_reported_last` (`conf/nosuchif/send_redirects` → `Err(Io)` but `ip_forward` in the same desired set was written).

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** `cargo test -p openfeo-harness --test netlink` → all scenarios pass (now 12).

- [ ] **Step 5: Commit** `apply: nft and sysctl appliers`.

---

### Task 6: Router wiring: links, routing, nft, sysctl in order

**Files:**
- Modify: `crates/openfeo/src/router.rs` (`apply_task`), `crates/openfeo/Cargo.toml`, `harness/tests/m1.rs` (regex for the new lines where a scenario asserts "no operations after restart": `ruleset applied` is expected once per child start and is excluded from the no-op assertion)

**Interfaces:**
- Console contract additions: `ruleset applied: N chains, M rules`, `apply nft generation=G ops=1`, `sysctl net/ipv4/ip_forward=1`, `sysctl net/ipv4/conf/p0/send_redirects=0`, `apply sysctl generation=G ops=K`, and on failure `apply nft failed: <libnftables error>; retry in Ns`.
- Order inside one pass: links, routing, nft, sysctl; sysctl runs only when nft succeeded in this pass (so forwarding is never on without the ruleset); `ready` keeps its meaning (a zero-op pass after work across all four).

- [ ] **Step 1: Failing unit test** in `router.rs`: the ordering is a const `APPLY_ORDER: [Subsystem; 4] = [Links, Routing, Nft, Sysctl]` and the gating a pure `fn may_run(subsystem: Subsystem, nft_ok_this_pass: bool) -> bool`; test `sysctl_waits_for_nft` (`may_run(Sysctl, false) == false`, `may_run(Sysctl, true)`, every other subsystem true either way) and `apply_order_ends_with_sysctl`.

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (`NftApplier::new(Nft::new()?)` created in the task factory so a restart gets a fresh context; `SysctlApplier`; the loop iterates `APPLY_ORDER` with `may_run`). **Step 4: Run** `cargo test -p openfeo --features harness` → PASS.

- [ ] **Step 5: Image and existing scenarios**

Run: `make kernel && make test-harness` → `netlink` 12 passed, `nft` 5 passed, `m0` 5 passed, `m1` 5 passed (the static fixture now carries `wan_ping = true`, so the ISP-side pings still succeed; `child_restart_converges_without_changes` must still see no `add|del|enslave|release|set` lines: `ruleset applied` and `sysctl` lines are allowed).

- [ ] **Step 6: Commit** `openfeo: apply nft and sysctl after links and routing; forwarding only with a ruleset`.

---

### Task 7: Harness: HTTP targets, in-namespace HTTP client, ping loop

**Files:**
- Create: `harness/src/lanclient.rs`
- Modify: `harness/src/daemons.rs`, `harness/src/lab.rs`, `harness/src/lib.rs`, `harness/src/main.rs` (`check` lists `python3`; `run` starts the ISP HTTP target too)

**Interfaces:**
- Produces: `daemons::http_server(ns: &NetNs, bind: &str, port: u16, dir: &Path, body: &str) -> Result<Daemon>` (writes `index.html` = `body` into `dir`, runs `python3 -m http.server <port> --bind <bind> --directory <dir>` in `ns`; its `log` shows request lines like `203.0.113.10 - - [...] "GET / HTTP/1.0" 200 -`); `lanclient::http_get(ns: &NetNs, addr: SocketAddr, path: &str, timeout: Duration) -> Result<String>` (a scoped thread enters the namespace with `setns` like `tun::open_in_netns`, connects with `TcpStream::connect_timeout`, sends `GET <path> HTTP/1.0\r\nHost: x\r\n\r\n`, returns the body after the blank line; errors on connect failure or timeout); `lanclient::ping_loop(ns: &NetNs, target: &str, count: usize, interval: Duration) -> Result<PingStats { sent: usize, received: usize }>` (`ping -c <count> -i <interval> -W 1 <target>`, parsed from the summary line); `Lab::lan_side_host(&self) -> Result<()>` (`lan0`: up, `192.168.1.2/24`, default route via `192.168.1.1`); `Lab::isp_route_to_lan(&self) -> Result<()>` (`isp0`: `192.168.1.0/24 via 203.0.113.10`); constants `ISP_HTTP_BODY = "openfeo isp target"`, `LAN_HTTP_BODY = "openfeo lan target"`.

- [ ] **Step 1: Failing unit tests** in `lanclient.rs`: `parses_ping_summary` (`"5 packets transmitted, 4 received, 20% packet loss"` → `sent 5, received 4`), `http_body_after_headers` (a `fn body_of(response: &[u8]) -> Option<&str>` helper: `"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc"` → `Some("abc")`). Sandbox scenario in `netlink.rs`: `http_get_reaches_a_server_in_the_sandbox` (`http_server` on `lo` 127.0.0.1:8081 in the sandbox's own namespace via a `NetNs` handle for the current namespace, `http_get(…, "/")` returns the body).

- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `cargo run -q -p openfeo-harness -- check` lists `python3`.

- [ ] **Step 5: Commit** `harness: HTTP targets, in-namespace HTTP client, ping loop`.

---

### Task 8: Scenarios, full gate, docs

**Files:**
- Modify: `harness/tests/m1.rs`, `README.md` (status), `CLAUDE.md`

**Scenarios** (each with the static fixture unless said; `lan_side_host()` after `ready`):
- `lan_fetches_isp_http_through_nat`: `http_server(isp0, "203.0.113.1", 8080, …, ISP_HTTP_BODY)`; `http_get(lan0, 203.0.113.1:8080, "/")` → `ISP_HTTP_BODY`; the server log contains `203.0.113.10 - -` (the WAN address: NAT happened) and never `192.168.1.2`.
- `port_forward_from_wan_and_hairpin`: `http_server(lan0, "192.168.1.2", 8080, …, LAN_HTTP_BODY)`; `http_get(isp0, 203.0.113.10:2222, "/")` → `LAN_HTTP_BODY`; `http_get(lan0, 203.0.113.10:2222, "/")` → `LAN_HTTP_BODY` (hairpin); the LAN server log shows `203.0.113.1` for the first and `192.168.1.1` for the hairpinned request (SNAT to the router's LAN address).
- `wan_is_blocked_by_default`: fixture with `wan_ping = true` replaced by `wan_ping = false`; `isp_route_to_lan()`; `http_server(lan0, …)`; `http_get(isp0, 192.168.1.2:8080, "/", 3 s)` → `Err` (forward drop; every other `http_get` in these scenarios uses `HTTP_TIMEOUT = 5 s`); `ping(isp0, "203.0.113.10")` → `Err` (input drop); `http_get(isp0, 203.0.113.10:2222)` still works (the forward is explicit).
- `child_crash_does_not_interrupt_forwarding`: boot with `openfeo.chaos=child-exit:20`; after `ready`, `http_server(isp0, …)`; start `ping_loop(lan0, "203.0.113.1", 125, 200 ms)` on a thread; meanwhile wait for `chaos child-exit`, the second `child started`, the second `ready`; join the loop → `received >= sent - 2`; `http_get` through NAT works afterwards; the restarted child logged `ruleset applied` and no `add|del|enslave|release|set \S+ (up|down|mac)` lines.
- `first_boot_forwards_nothing`: no state disk; after `ready`, `count("sysctl net/ipv4/ip_forward=1") == 0` and `count("ruleset applied") == 1` (the ruleset exists, without WAN rules).

- [ ] **Step 1: Write the scenarios.** **Step 2: Run** `make test-harness` → `m1` 10 passed (and the others unchanged). **Step 3: `make ci`** → exit 0. **Step 4: README status** (NAT, port forwards, hairpin, forwarding gated on the ruleset); CLAUDE.md Harness section notes `python3` and `pkg-config`. **Step 5: Commit** `harness: M1 part 2a scenarios (NAT fetch, port forward and hairpin, WAN blocked, crash keeps forwarding)`.

---

## Decisions this plan makes (for the ledger)

- The C libraries are built by `openfeo-nft/build.rs` from tarballs pinned in `nft/sources.txt`, for both the host (sandbox tests) and musl, with UAPI headers from our own kernel tree; the build script is the one place outside `harness/` and `image/` allowed to spawn processes.
- The firewall section is `wan_ping` plus port forwards; zone policies are the SPEC §7.5 defaults until the panel (M4) exposes them.
- Hairpin matches `fib daddr type local`, so a LAN client reaching a forwarded port through the router's LAN address is forwarded too.
- Ports 53, 67, 68, 80, 123 and 443 cannot be port-forwarded (the router's own services).
- The lab's static fixture answers ping on the WAN (`wan_ping = true`) so the part 1 scenarios keep working; a dedicated scenario proves the default-off behaviour.
- The ruleset is applied once per child start and again only when it changes; restart convergence tolerates the single `ruleset applied` line.
- Forwarding is a sysctl written only after the ruleset applied in the same pass.
