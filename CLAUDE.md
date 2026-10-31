# OpenFeO — working rules for Claude Code sessions

`SPEC.md` is the source of truth. Build only what §§1–11 say, in the milestone order of §12.
Any deviation from §2 needs an ADR in `docs/adr/` before code; kernel and protocol quirks found in
the harness get ADRs too (`docs/adr/NNNN-title.md`: Context, Decision, Consequences).

## Commands
- `make bin`           static musl binary (`--features harness` by default; `FEATURES=` for a release build)
- `make kernel`        fetch/verify/build Linux (see `kernel/`) with the binary embedded → `build/bzImage`
- `make run`           boot the VM in the rootless lab with the serial console on your terminal (Ctrl-A x quits);
                       `CONFIG=harness/fixtures/vm-dhcp.toml` boots with a DHCP WAN served by the lab's Kea
- `make test`          unit tests; `make test-harness` runs the QEMU scenarios (`FILTER=name` to pick one)
- `make lint`          fmt, clippy (-D warnings), cargo-deny, SPDX headers
- `make ci`            everything CI runs, in CI's order
- `make check-env`     is this machine able to run the harness?
- `make bin`, `lint` and `test` first run `make kernel-headers nft-src` (kernel UAPI headers, pinned nftables sources;
  ADR-0012) and export `OPENFEO_NFT_SRC` and `OPENFEO_UAPI_INCLUDE`; a bare `cargo build` needs both set.

## Rules
- Rust stable, edition 2024, musl targets. `clippy -D warnings`, pedantic as warnings. No `unwrap`/`expect`
  outside tests. `thiserror` in libraries, `anyhow` only in `crates/openfeo` and `harness/`.
- `#![forbid(unsafe_code)]` everywhere except `openfeo-init`, `openfeo-nft` and `openfeo-net` (ADR-0013), where `unsafe` is
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
group-accessible via a udev rule. Tools: `qemu-system-x86_64`, `ip`, `kea-dhcp4`, `busybox` (`udhcpc`, the reference
DHCP client), `dnsmasq` (the upstream resolver), `dig` (the DNS client), `mkfs.ext4`, `ping`, `python3` (HTTP targets);
building needs `musl-gcc`, `pkg-config`, `bison`, `flex`. The sandboxed nft scenarios need the
kernel to load the `ct`/`fib`/`nat` nft modules; a host that cannot (upgraded, not rebooted) makes them skip with
a reason, `make check-env` says so, and CI sets `OPENFEO_NO_SKIP=1` so a skip fails there. The `dhcp4` sandbox
suite runs the DHCPv4 client against Kea over a veth pair, no QEMU, and the `dhcp4_server` suite runs the
DHCPv4 server driver against the LAN-side clients (our own as the hidden `openfeo-harness dhcp-client`
subcommand, busybox `udhcpc` as the reference; `OPENFEO_TRACE=1` shows their and the driver's account of a
run); the `dns` suite runs the forwarder driver between a LAN host running `dig` and dnsmasq in
authoritative mode for `isp.example` (the same dnsmasq serves as the upstream on isp0 in the QEMU
scenarios); the `sntp` suite runs the time driver on a recording clock between a LAN host (busybox
`ntpd` and raw queries) and the lab's Python SNTP server (`harness/fixtures/sntp-server.py`), whose
clock offset each scenario dials (the same server sits on isp0 at 203.0.113.1 in the QEMU
scenarios, and `Lab::set_rtc_base` starts the VM with a wrong clock); `make bin` bakes
`OPENFEO_BUILD_EPOCH` (the commit's time, or `SOURCE_DATE_EPOCH`) into the binary as its clock
floor; Kea's one template serves 60-second leases
renewing at 20 s to every lab run, so a renewal is observable within a scenario. CI runs Ubuntu 24.04's Kea
2.4.1, so the template uses only what that version accepts (option 121 is given by code as RFC 3442 bytes);
`make check-env` tests the template against the installed Kea and prints Kea's own error when it refuses.
