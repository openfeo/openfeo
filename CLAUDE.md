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
  `openfeo-proto-*`, `openfeo-reconcile` and `openfeo-world` are pure: no tokio, libc, nix or socket2 anywhere in
  their dependency trees. `scripts/check-deps.sh` (part of `make lint`) enforces both rules.
- Every parser gets a fuzz target in the PR that adds it.
- Every source file starts with `SPDX-License-Identifier: GPL-2.0-or-later` and `Copyright (C) 2026 Andrew Newton`.
- Commits: `git commit -s` (DCO, identity `Andrew Newton <andy@vitri.ltd>`, set repo-locally), subject `<area>: <summary>`.
- Test hooks (`openfeo.chaos=`) exist only under the `harness` cargo feature; release builds carry none.

## Harness
Rootless: user + mount + net namespaces, no sudo. Needs `/dev/kvm` (falls back to TCG) and `/dev/net/tun`
readable, and unprivileged user namespaces enabled. Host-side `pppd` (M3) additionally needs `/dev/ppp`
group-accessible via a udev rule.
