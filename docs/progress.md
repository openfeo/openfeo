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
| M2 IPv6 | done, 2026-11-07 | #10, #22, #36; follow-up #20 |
| M3 PPPoE | done, 2026-11-09 | #46, #47; follow-ups #58, #59, #67 |
| M4 to M7 | not started | |

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

**2026-11-02, [#20](https://github.com/openfeo/openfeo/pull/20), follow-up.** The fix for
[#12](https://github.com/openfeo/openfeo/issues/12): a forward the driver could not send (no
route to the upstream yet) is sent again a quarter of a second later under the same id and never
counts as a silence, and an attempt in which a send failed marks no upstream down. The m1
learned-upstream scenario passes under TCG, where it failed.

**2026-11-04, [#22](https://github.com/openfeo/openfeo/pull/22), part 2: IPv6 with a statically
routed prefix.** `[wans.ipv6]` names the prefix the ISP routes to the router and, when the ISP
does not advertise itself, the gateway; the WAN runs a router-advertisement client of its own
(`openfeo-proto-ndp`, a pure codec and two cores, with smoltcp as the test oracle: ADR-0018),
learns its default router and resolvers and, from a link prefix, a stable address (RFC 7217 from a
secret under `/state/identity/`), and takes a stable-privacy link-local before the port comes up;
each LAN names its /64 inside the prefix and advertises it, with router lifetime 0 the moment the
WAN's IPv6 default is gone and `ra = false` for a LAN placed by hand; the router sources from
`<prefix>::1` on `lo`, blackholes the prefix (ADR-0020 for what the kernel reports back), and acts
on a learned resolver or advertises a lifetime only once the kernel shows the default route
(ADR-0019); the `inet` ruleset mirrors the IPv4 zones for IPv6 with RFC 4890's ICMPv6 lists, and
rules, records and upstreams take addresses of either family; the DNS forwarder listens, forwards
and answers AAAA over IPv6 (§7.3, §7.5, §7.7). The lab gains radvd, rdisc6 and an `ndp` sandbox
suite; eight QEMU scenarios prove the part.

**2026-11-07, [#36](https://github.com/openfeo/openfeo/pull/36), part 3: delegated prefixes,
ULA and deprecation.** A WAN with `[wans.ipv6]` and no typed prefix runs a DHCPv6 client
(`openfeo-proto-dhcp6`, a pure codec with dhcproto as the fuzz oracle, and a client core in the
odhcp6c mould): Solicit with Rapid Commit for an IA_PD of `pd_hint` bits and an IA_NA, Renew at T1,
Rebind at T2, and Rebind on Confirm's timing after a link flap or a reboot from the binding
persisted in `leases/dhcp6-<wan>.toml`; each LAN takes the /64 at its `ipv6_index` (the typed
value, or its position) inside every delegated prefix and inside a per-router ULA /48 generated
once under `identity/ula`, and the router answers Information-Requests on every LAN with its
addresses there (ULA first) and the search domain, so hosts that ignore RDNSS still find it;
a prefix the ISP takes back, or whose WAN loses carrier or its IPv6 default, is advertised with
preferred lifetime 0 for the lower of two hours and its own remaining valid lifetime, traffic from
it is answered unreachable by a policy rule, and the list survives a reboot; every delegated
prefix gets a source rule into its WAN's table, the main table is consulted first with its default
suppressed, and the ULA never crosses a WAN (rejected with no route outward, dropped inward);
resolvers learned over DHCPv6 join behind the IPv6 route like RDNSS ones (§7.3, §7.5, §7.7, §8.2).
Lifetimes live on the process monotonic clock in the World and on the wall clock only in the file.
The lab gains Kea's DHCPv6 server, busybox `udhcpc6` and a `dhcp6` sandbox suite; seven QEMU
scenarios on `vm-pd.toml` prove the part, among them the ISP changing its prefix and the LAN
renumbered within ten seconds. Fixed on the way: [#26](https://github.com/openfeo/openfeo/issues/26),
[#28](https://github.com/openfeo/openfeo/issues/28), [#29](https://github.com/openfeo/openfeo/issues/29),
[#30](https://github.com/openfeo/openfeo/issues/30), [#31](https://github.com/openfeo/openfeo/issues/31),
[#33](https://github.com/openfeo/openfeo/issues/33) and [#34](https://github.com/openfeo/openfeo/issues/34);
[#27](https://github.com/openfeo/openfeo/issues/27) (an address leaving the port when its preferred
lifetime lapses) stays open, as the whole-branch review found and the design now records.

M2 is complete; M3 (PPPoE) follows.

## M3 PPPoE

**2026-11-07, [#46](https://github.com/openfeo/openfeo/pull/46), part 1: the cores and the
wiring.** Everything of PPPoE (§7.2) that can be proven without PPP in the kernel, in the pure crate
`openfeo-proto-ppp`: the discovery codec and client (RFC 2516, RFC 4638), the PPP frame, the RFC 1661
automaton once over an `Options` trait, LCP with keepalives, PAP and CHAP-MD5, IPCP and IPV6CP (its
identifier from the stable-privacy secret, RFC 7217) and the session orchestrator, with seven fuzz
targets and no external codec (ADR-0022). Around it: `[wans.pppoe]` in the schema, the `PppoeFact`,
`wan_netdev` as the name every reconciler reads for a WAN's IP interface, the links reconciler asking
1508 on a PPPoE port and desiring `ppp-<wan>` for the kernel's unit (ADR-0023), point-to-point
addresses with their peer through netlink and the routing applier, the links applier's rename, MTU and
raise of the unit's netdev, a TCP MSS clamp on every WAN netdev below 1500 (§7.5), the discovery
socket and the `/dev/ppp` plumbing in `openfeo-net` with the ioctl numbers checked against the pinned
UAPI header, the WAN task with the design's console lines and backoff, and the `ipv6` and `dhcp6`
tasks taking a session's new netdev as a flap in place rather than a restart. Proven here: the
reconciler snapshots, the `netlink` scenarios for the point-to-point address, the rename and a refused
port MTU, and the new `pppoe` sandbox suite, whose discovery runs against a scripted access
concentrator over a veth pair and whose session attach makes a unit netdev wherever `/dev/ppp` is at
hand (CI loads the PPP modules and opens it; a host without them skips with the udev rule to add).
Part 2 proves the session live: `pppoe-server` in the lab, the `pppoe` suite's PPP scenarios, the `m3`
QEMU suite, check-env and the cloud setup.

**2026-11-09, [#47](https://github.com/openfeo/openfeo/pull/47), part 2: live.** The session proven end to
end against rp-pppoe's `pppoe-server` and `pppd` in the lab. The lab's access concentrator runs in kernel
mode through pppd's own PPPoE plugin with its secrets on a tmpfs over `/etc/ppp`, and radvd and Kea's
DHCPv6 server start on the ISP's `ppp<N>`. The `pppoe` sandbox suite runs the session core over a real
kernel session on a veth pair: LCP, PAP and CHAP, IPCP with the pool address and resolver and a ping over
the unit, a wrong password reported with pppd's message, the server killed as `keepalive lost`, stopped
as `terminated by peer`, an injected PADT ending the session, IPV6CP and a ping6, and the 1492 fallback
(rp-pppoe cannot offer RFC 4638; the 1500 path rests on the core's tests). The `m3` QEMU suite boots
`vm-pppoe.toml` and `vm-pppoe-pd.toml`: the console contract, HTTP through NAT over PPP, the MSS clamp
measured at the server's socket, the server killed and the session returning, carrier loss during a
session and during discovery, PAP, the tagged `wan0.101`, IPv6 over PPP, prefix delegation over PPP, a
reboot keeping the prefix, the concentrator ending the session, and the password nowhere on the console.
The live session found three router bugs, each fixed test first: a resolver named twice by IPCP, the
first discovery running before the port's MTU was raised (the router now asks 1500 on a 1508 port), and
ENXIO read as "no PPP" for a session the kernel refused. `make check-env` reports `pppd`, `pppoe-server`
and `/dev/ppp`; CI and the cloud setup install and open them. SPEC §12's M3 row is met. M3 is complete;
next is M4.

## Follow-ups

**2026-11-10, [#58](https://github.com/openfeo/openfeo/pull/58), router deferred minors.** The fifteen
router-side issues deferred from the M2 and M3 reviews, each fixed test-first in one branch. The
kernel now deprecates and drops the WAN's SLAAC address on the ISP's lifetimes: the RA client carries
a prefix's preferred lifetime, the World fact and the routing reconciler carry both lifetimes as
deadlines, and the netlink crate writes and reads them as `IFA_CACHEINFO`, for DHCPv6 addresses too
(#27). A learned IPv4 resolver joins the forwarder once any kernel route through the WAN reaches it,
so a classless-only lease with no router option opens ADR-0019's gate (#32). The first router
advertisement after boot retries `ENETUNREACH` a second later instead of being lost, and a delegation
restored from disk is advertised live until its Rebind is answered or gives up (#37, #44). DHCPv6
follows RFC 8415 §18.2.10.1 for a lease a Reply omits, keeps the deprecated list on disk through an
expiry or a dropped binding, rejects a lease file whose server DUID is corrupt, and answers
Information-Requests from link-local sources only (#39 to #42). The forwarder retries a failed TCP
connect and moves a due retry off a downed upstream (#35); `arp_ignore` is on for every interface so a
pure trunk port answers no untagged ARP, proven by a new m2 scenario (#15); the WAN's IPv6 MTU never
exceeds the lease MTU set in the same pass (#38); the router's own ULA-sourced or ULA-bound output
toward a WAN is refused (#45); port and VLAN spellings are canonical and `pd_hint` beside a typed
prefix is refused (#18, #43); the applier reads port names from openfeo-config's one grammar (#16).

**2026-11-10, [#59](https://github.com/openfeo/openfeo/pull/59), harness deferred minors.** The ten
harness minors from #47's review: the `pppoe` bench fails a wait at once when the session dies and
drives for a window, so the suite pins the Down reason, the PADT timing and the silence after `auth
failed`; a new `m3` scenario resolves a name through the IPCP resolver over PPP; the lab's secrets are
written only inside the sandbox and the pppd log is rotated across a server restart; `make check-env`
probes `/dev/ppp` after the user-namespace row and the cloud setup's facts list every module it loads.

**2026-11-10, [#67](https://github.com/openfeo/openfeo/pull/67), third minors sweep.** The three
deferred minors from #58's and #59's reviews that change what the router or the gate does: a DHCPv6
binding restored from disk stops counting as restored when the exchange restarts, not only when its
Rebind is answered or gives up (#44); the resolver scenarios wait for dnsmasq's log line instead of
counting it the moment `dig` returns (#64); the `netlink` suite waits up to five seconds for a
kernel-generated link-local, which the kernel announces only once duplicate address detection
completes, up to two seconds after the port comes up, so the stable-privacy scenario no longer fails
on a loaded host. The other seven minors are filed as #60 to #63, #65 and #66.

## Tooling and process

**2026-11-01, [#11](https://github.com/openfeo/openfeo/pull/11).** A setup script that prepares an
ephemeral cloud sandbox the way CI prepares a runner, `make check-env` fetching its prerequisites
and finding the kernel under `BUILD`, and `rsync` listed everywhere a fresh machine needs it.

**2026-11-01, [#13](https://github.com/openfeo/openfeo/pull/13).** The superpowers process enabled
for the project in `.claude/settings.json`, the boundary between M2 parts 2 and 3 written into
SPEC §12, and the working rules for agent sessions in `CLAUDE.md`.
