# OpenFeO — working rules for Claude Code sessions

`SPEC.md` is the source of truth. Build only what §§1–11 say, in the milestone order of §12.
Any deviation from §2 needs an ADR in `docs/adr/` before code; kernel and protocol quirks found in
the harness get ADRs too (`docs/adr/NNNN-title.md`: Context, Decision, Consequences).

## Commands
- `make bin`           static musl binary (`--features harness` by default; `FEATURES=` for a release build);
                       builds the panel first and embeds it (a bare `cargo build` embeds a placeholder page: ADR-0025)
- `make panel`         the web panel into `$(BUILD)/panel` with its notices (Node 22; `web/` is an npm workspace)
- `make web-lint`, `make web-test`  the web workspace's own checks (type-check, ESLint, the layering and licence
                       gates, generated files up to date; vitest); `make lint` and `make test` run them
- `make kernel`        fetch/verify/build Linux (see `kernel/`) with the binary embedded → `build/bzImage`
- `make run`           boot the VM in the rootless lab with the serial console on your terminal (Ctrl-A x quits);
                       `CONFIG=harness/fixtures/vm-dhcp.toml` boots with a DHCP WAN served by the lab's Kea;
                       `PANEL=<address>:<port>` relays the router's panel to that address of this machine, so a
                       browser outside the lab can open it (the certificate is the router's own)
- `make panel-browser` install the Chromium the panel's Playwright run drives (into Playwright's own cache)
- `make test`          unit tests; `make test-harness` runs the QEMU scenarios (`FILTER=name` to pick one)
- `make lint`          fmt, clippy (-D warnings), cargo-deny, SPDX headers
- `make ci`            everything CI runs, in CI's order
- `make check-env`     is this machine able to run the harness? (fetches the headers and sources first, like `bin`)
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
- `web/` is three npm packages with a rule between them (SPEC §8.4), checked by `web/scripts/check-layering.mjs`:
  `web/client` (`@openfeo/client`, the wire) imports no Vue and uses no DOM beyond `fetch` and `WebSocket`;
  `web/ui` (`@openfeo/ui`, the design system in code) knows nothing of the API; `web/panel` reaches the wire only
  through the client and holds no CSS beyond page layout. npm installs from the lockfile without running any
  package's scripts (`npm ci --ignore-scripts`); a package that can reach the page must pass
  `web/scripts/check-licences.mjs` (the list is `deny.toml`'s). The page's content security policy allows no inline
  script, no `style` attribute and no `data:` URL. The design system's own files under `web/ui` (`tokens.json`,
  `ofo.css`, fonts, logos, `docs/`) are copies: a change is made in the design system first (`web/ui/docs/SOURCE.md`).
- Every source file starts with `SPDX-License-Identifier: GPL-2.0-or-later` and `Copyright (C) 2026 Andrew Newton`.
- Commits: `git commit -s` (DCO, identity `Andrew Newton <andy@vitri.ltd>`, set repo-locally), subject `<area>: <summary>`.
- Test hooks (`openfeo.chaos=`) exist only under the `harness` cargo feature; release builds carry none.

## Process
- Milestone work follows the superpowers plugin's process (enabled for this project in `.claude/settings.json`):
  brainstorm, then a design under `docs/superpowers/specs/`, then a plan under `docs/superpowers/plans/`, then
  execution. Plans run inline: the executor works every task itself, test-first, keeps a ledger, does not stop to
  check in between tasks, and reports the rulings it made on the plan's behalf together at the end, each with what
  it costs if wrong; one fresh whole-branch review follows, then one fix pass. Minors it defers and follow-ups it
  finds become GitHub issues, not chat memory. A PR that lands milestone work appends its entry to
  `docs/progress.md` in the same PR; `SPEC.md` carries no status.
- Nothing is pushed, no PR opened, no branch force-pushed or deleted except on the maintainer's explicit word. Before
  every push the branch is swept: author and committer are the DCO identity above, and no personal paths, employer
  addresses, scratch or temp paths appear in files or messages.
- Every word in the repo is public writing: documentation ranges (RFC 5737, RFC 3849) in examples and fixtures, and
  no real addresses, accounts or ISP details beyond what `SPEC.md` already names.

## Harness
Rootless: user + mount + net namespaces, no sudo. Needs `/dev/kvm` (falls back to TCG) and `/dev/net/tun`
readable, and unprivileged user namespaces enabled. Host-side `pppd` (M3) additionally needs `/dev/ppp`
group-accessible via a udev rule. Tools: `qemu-system-x86_64`, `ip`, `kea-dhcp4` and `kea-dhcp6` (the ISP's servers),
`busybox` (`udhcpc`, the reference DHCP client; `udhcpc6`, the stateless DHCPv6 one), `dnsmasq` (the upstream resolver), `dig` (the DNS client), `ntpdate` (the reference time client), `mkfs.ext4`,
`ping`, `python3` (HTTP targets and the lab's SNTP server);
building needs `musl-gcc`, `pkg-config`, `bison`, `flex` and `rsync` (the kernel's `headers_install`). The sandboxed nft scenarios need the
kernel to load the `ct`/`fib`/`nat`/`limit` nft modules, and every VLAN scenario (sandbox and QEMU alike: the
ISP and LAN sides tag with the host kernel's `8021q`) needs that module; a host that cannot load them (upgraded,
not rebooted) makes them skip with a reason, `make check-env` says so, and CI loads the modules and sets
`OPENFEO_NO_SKIP=1` so a skip fails there. Scenarios that need two LANs call `Lab::add_lan1` for a `lan1`
namespace on the router's `p3`; a VLAN client is a sub-interface of a LAN tap moved into its own namespace
(`Lab::vlan_host`); `Lab::isp0_tagged` moves ISP A onto `wan0.<vid>` for the tagged WAN. The `dhcp4` sandbox
suite runs the DHCPv4 client against Kea over a veth pair, no QEMU, and the `dhcp4_server` suite runs the
DHCPv4 server driver against the LAN-side clients (our own as the hidden `openfeo-harness dhcp-client`
subcommand, busybox `udhcpc` as the reference; `OPENFEO_TRACE=1` shows their and the driver's account of a
run); the `dhcp6` suite runs the DHCPv6 client core against Kea's DHCPv6 server over a veth pair (a second
pool stands in for the ISP changing the prefix) and the stateless responder against busybox `udhcpc6`; the `dns` suite runs the forwarder driver between a LAN host running `dig` and dnsmasq in
authoritative mode for `isp.example` (the same dnsmasq serves as the upstream on isp0 in the QEMU
scenarios); the `sntp` suite runs the time driver on a recording clock between a LAN host (`ntpdate -q`
and raw queries) and the lab's Python SNTP server (`harness/fixtures/sntp-server.py`), whose
clock offset each scenario dials (the same server sits on isp0 at 203.0.113.1 in the QEMU
scenarios, and `Lab::set_rtc_base` starts the VM with a wrong clock); the `ndp` suite runs the
router-advertisement client driver against `radvd` and the server driver against a namespace's
own kernel (the SLAAC reference client) with `rdisc6` (package `ndisc6`) reading the
advertised options, both over veth pairs (the same radvd advertises on isp0's `wan0` in the
IPv6 QEMU scenarios, where `Lab::isp_route_block6` routes `2001:db8:1::/48` to the router); `make bin` bakes
`OPENFEO_BUILD_EPOCH` (the commit's time, or `SOURCE_DATE_EPOCH`) into the binary as its clock
floor; Kea's one template serves 60-second leases
renewing at 20 s to every lab run, so a renewal is observable within a scenario. CI runs Ubuntu 24.04's Kea
2.4.1, so the template uses only what that version accepts (option 121 is given by code as RFC 3442 bytes);
`make check-env` tests the template against the installed Kea and prints Kea's own error when it refuses. The ISP's PPP side (M3)
is rp-pppoe's `pppoe-server` in kernel mode (`-k`, since its user-mode helper cannot drop privileges with one uid
mapped) pointed at pppd's own PPPoE plugin (`-g`; `daemons::pppd_plugin` finds it), spawning `pppd` per session with
the lab's account on a tmpfs the sandbox mounts over `/etc/ppp`; `pppd` calls `setsid()`, so the daemon handle stops a
server by its descendants in `/proc`, not its process group. The `pppoe` sandbox suite runs the session core against
it over a veth pair (the server's end in a namespace of its own); the `m3` QEMU suite boots `vm-pppoe*.toml` against
it on isp0, with radvd and Kea's DHCPv6 server on the session's `ppp<N>` (`Lab::start_radvd_on`; Kea needs a plain
`fe80::1/64` there, not pppd's point-to-point one). `make check-env` reports `/dev/ppp` and the plugin. The `m4` QEMU suite (M4 part 1a) boots
`vm-dhcp.toml` and drives the router's API from the LAN namespace through `harness::apiclient`: plain HTTPS
calls, the WebSocket envelope and gRPC, each on a thread that has entered the namespace, trusting whatever
certificate is presented and handing it back for the scenario to judge; QEMU gives `p0` a link speed
(`speed=1000`) so the API has one to report, and the lab's one password is `lab-admin-password`. Two `m4`
scenarios run the web side inside the LAN namespace against the VM (`harness::web`; M4 part 1b):
`@openfeo/client`'s own tests under Node (`web/client/itest`, by the LAN address) and the panel in Playwright's
Chromium (`web/panel/e2e`, by the router's name through a resolver rule), from first visit to a cut WAN. Each
asks the lab to take a port's carrier away and give it back through a control directory (`harness::web::LabCtl`,
`web/scripts/labctl.mjs`). They need Node 22.12 or later with `web/node_modules` installed, and the browser run
needs `make panel-browser`; without them they skip with the reason and `make check-env` says which. The browser
run leaves a screenshot of each screen in both themes in `$(BUILD)/panel-shots`.

## Cloud sandbox
`scripts/cloud-setup.sh` is the setup script for an ephemeral Ubuntu 24.04 sandbox (a Claude Code on the web
environment: about 4 vCPUs, root, no shell of your own). It does to the VM what `.github/workflows/ci.yml` does to
a runner (packages, the Rust toolchain, `buf`, `cargo-deny`, the pinned sources and UAPI headers, the kernel knobs
the harness wants where the VM allows them) and prints the sandbox's facts. It builds nothing, to stay within the
five-minute budget that gets the filesystem snapshotted for later sessions; sources and build products live in
`BUILD=/opt/openfeo/build`, outside the clone, and the environment sets the same `BUILD` so every `make` reuses
them. In such a session run `make check-env` before trusting the harness: without `/dev/kvm` QEMU runs under TCG
(about 1.2x the KVM wall time, not broken), without the nft and `8021q` modules those scenarios skip with a reason,
and `OPENFEO_NO_SKIP` stays unset (it is CI's assertion); the script installs Node 22 from nodejs.org and no
browser, so the Playwright scenario skips there and the client's own tests run, and the environment's network
list has to allow nodejs.org and the npm registry. `make kernel` and `make test-harness` outlast a
foreground command there, so run them in the background; build the kernel once per session and only when a QEMU
scenario is needed, since `make lint` and `make test` do not need it.
