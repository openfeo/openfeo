# Progress against SPEC §12

What has landed against the milestones of [`SPEC.md`](../SPEC.md) §12, one entry per change, in
the order it landed. The spec says what OpenFeO must do and carries no status; this page says what
is done, and the pull request each entry names holds the detail: the plan it executed, what it
added, how it was verified, and the review minors it deferred. A PR that lands milestone work
appends its entry here in the same PR (`CLAUDE.md`, Process).

| Milestone | State | Landed through |
|---|---|---|
| M0 Harness and skeleton | done, 2026-10-30 | commits on `main`, before the repository took pull requests |
| M1 IPv4 router | done, 2026-10-31 | #1, #2, #3, #4, #6, #7; follow-up #8 |
| M2 IPv6 | part 1 done, 2026-11-01; parts 2 and 3 to come | #10 |
| M3 to M7 | not started | |

## M0 Harness and skeleton

**2026-10-29 to 2026-10-30, committed to `main` directly.** The cargo workspace, lint and CI,
`kernel/required.config` and the x86 kernel built from `allnoconfig` plus checked-in fragments
with the binary as its initramfs (§4.2), PID 1 with its mounts, sysctls, watchdog, supervisor and
console log (§6.1), the first ADRs, and the rootless QEMU harness with one ISP namespace and one
LAN namespace, booting the VM with `openfeo.mode=vm` (§11). Acceptance: the VM boots to PID 1 in
CI and logs its version and port map; a child restart is observed after a kill; the watchdog
reboot is observed when heartbeats stop. Its deferred review minors were cleared in #8.

## M1 IPv4 router

**2026-10-30, [#1](https://github.com/openfeo/openfeo/pull/1), part 1: foundations.** The router
child on tokio: the kernel checked against `required.config`, ports named by bus path with a
sticky map under `/state/identity` (§7.1), the protobuf-defined configuration loaded and validated
from `/state/config.toml` with first-boot defaults (§8.2), the immutable `World`, the netlink
monitor and the appliers that own only what they tag (§6.2), the LAN bridge with VLAN filtering,
the static WAN and its default route (§7.2, §7.4). Heartbeats to PID 1 stop when a supervised task
dies or an applier stays in failure.

**2026-10-30, [#2](https://github.com/openfeo/openfeo/pull/2), part 2a: firewall and NAT.**
libnftables, libnftnl, libmnl and jansson pinned, built from source and linked in-process
(ADR-0012); the one `table inet openfeo` ruleset generated from the configuration and applied as a
single batch (§7.5): zones as named sets, default deny inbound on the WAN, masquerade, port
forwards with hairpin, reverse-path filtering in nft. Forwarding is switched on only together with
the ruleset, and a router-process crash does not interrupt traffic.

**2026-10-31, [#3](https://github.com/openfeo/openfeo/pull/3), part 2b: WAN DHCPv4 client.** Our
own wire format and sans-IO client (§7.2, §13): a packet socket until bound and UDP after, the
lease and DUID persisted under `/state`, INIT-REBOOT after a reboot, classless static routes and
the MTU carried into the `World`; the LAN is never held back when no server answers.

**2026-10-31, [#4](https://github.com/openfeo/openfeo/pull/4), part 3a: LAN DHCPv4 server.** A
sans-IO server core per `[lans.dhcp]` LAN (§7.6): pool and static reservations, DHCPINFORM, an ARP
probe before every offer, authoritative NAKs, the lease database on the state disk and the leases
published as facts; two LAN-side reference clients in the lab.

**2026-10-31, [#5](https://github.com/openfeo/openfeo/pull/5), nightly fuzzing.** A nightly CI job
runs every fuzz target with cargo-fuzz and fails when it fuzzes nothing (§11).

**2026-10-31, [#6](https://github.com/openfeo/openfeo/pull/6), part 3b: DNS forwarder.** Our own
codec and sans-IO core (§7.7): the local zone from reservations, leases and the router itself,
upstreams typed in or learned from the WAN, a TTL cache with negative caching, EDNS0, truncation to
TCP, failover and rebinding protection; a UDP and TCP driver per LAN; dnsmasq and dig in the lab.

**2026-10-31, [#7](https://github.com/openfeo/openfeo/pull/7), part 3c: SNTP.** Our own codec and
sans-IO client with the build time as the clock floor and steering per ADR-0016 (§7.10), a LAN
responder the leases point at, `adjtimex` behind a `Clock` trait, and the lab's SNTP server. With
this merged every item of the M1 row is in.

**2026-11-01, [#8](https://github.com/openfeo/openfeo/pull/8), follow-up.** The deferred review
minors of M0 and of parts 2b, 3a, 3b and 3c, cleared in one pass.

**2026-11-01, [#9](https://github.com/openfeo/openfeo/pull/9), fuzz hotfix.** The forwarder's
fuzz target followed a configuration change it had missed, and `make lint` now type-checks the
fuzz crate so a target cannot break unseen.

## M2 IPv6

**2026-11-01, [#10](https://github.com/openfeo/openfeo/pull/10), part 1: IPv4 groundwork.** LAN
members may be tagged VLANs on a port, 802.1Q sub-interfaces bridged per LAN (ADR-0017), and a WAN
may be tagged (§7.1, §7.2); `[[public_ipv4]]` declares the blocks the ISP routes to the router, a
LAN numbered from one is a public LAN that is never translated and is reached only through rules,
every block gets a blackhole route, and a port forward may listen on a public address (§7.4,
§7.5); each LAN says which zones it `reaches`, `[[firewall.rules]]` open single holes, and WAN echo
is rate limited (§7.5); the DNS rebinding guard is the private LANs only (§7.7). Follow-up found
while timing the harness without KVM: [#12](https://github.com/openfeo/openfeo/issues/12), a query
forwarded before the WAN route exists holds the only upstream down.

Parts 2 and 3 are scoped in SPEC §12: a statically routed prefix as the first-class path, then
DHCPv6 and the other-ISP cases.

## Tooling and process

**2026-11-01, [#11](https://github.com/openfeo/openfeo/pull/11).** A setup script that prepares an
ephemeral cloud sandbox the way CI prepares a runner, `make check-env` fetching its prerequisites
and finding the kernel under `BUILD`, and `rsync` listed everywhere a fresh machine needs it.

**2026-11-01, [#13](https://github.com/openfeo/openfeo/pull/13).** The superpowers process enabled
for the project in `.claude/settings.json`, the boundary between M2 parts 2 and 3 written into
SPEC §12, and the working rules for agent sessions in `CLAUDE.md`.
