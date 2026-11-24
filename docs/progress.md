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
| M4 API and panel | parts 1 and 2 of 5, and 3a, 2026-11-23 | #68, #81, #101, #103, #128; follow-ups #124, #129 |
| M5 to M7 | not started | |

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

## M4 API and panel

**2026-11-10, [#68](https://github.com/openfeo/openfeo/pull/68), part 1a: the API.** The design
for the whole milestone (API, then a JavaScript client, then the panel on it; five parts) and the
first half of part 1, everything in Rust. A new crate `openfeo-api` serves HTTPS on the private
LANs with a certificate the router makes for itself (ECDSA P-256, 825 days, reissued with its
key; ADR-0024), redirects port 80, and carries a few plain HTTP calls, a binary WebSocket
envelope and gRPC on one listener. A first password is set once from the LAN and logs that client
in; a wrong password makes its source wait 1 s doubling to 5 minutes; sessions are bearer tokens
kept in memory; a request must call the router by its own name or address, and a WebSocket
upgrade from another origin is refused. The API reports what is derived, not collected: the
World gained addresses, link speed and a status per WAN (its phase, since when, and why it last
went down, which the DHCP and PPPoE tasks now publish), the publisher derives that status and the
events of every change inside each publish, and the state snapshot is a pure view of the World
with `insta` snapshots like the reconcilers. Counters are read once a second and only while
someone is subscribed. A refused config keeps its admin password. Proven by the `m4` QEMU suite
(15 scenarios from the LAN side, among them SPEC §12's "a WS upgrade with a foreign `Origin` is
refused"), a sandbox scenario for the link counters, and fuzz targets for the envelope and the
host check. The page at `/` is a placeholder until part 1b embeds the panel; part 1b is the
client, the component package, the panel's three screens and Playwright.

**2026-11-11, [#81](https://github.com/openfeo/openfeo/pull/81), part 1b: the web workspace.** A
booted router now serves its real panel. `web/` is an npm workspace of three packages with a
checked rule between them: `@openfeo/client` (the wire: plain calls, the socket's envelope,
subscriptions, reconnecting, typed errors; no Vue, and it runs in Node as well as a browser),
`@openfeo/ui` (the maintainer's design system in code: its tokens, stylesheet, fonts and logos
copied in, and seventeen Vue components over them) and the panel, which joins the two in three
screens: set the admin password, log in, and a live read-only dashboard (the WAN and since when,
rates with a minute of history, clients, tracked connections, a card per WAN and LAN, the port
strip, every address and where it came from, recent events). `make panel` builds it and
`openfeo-api`'s `build.rs` embeds the result, compressed and tagged, when `make bin` names the
directory; cargo never runs npm, and a bare `cargo build` embeds a placeholder page (ADR-0025).
The notices of what the page bundles are served at `/licences.txt`. The status call gained
`config_unreadable`, so the panel can tell a refused config whose password still works from a
file nobody can log in over. The client probes a socket that has gone silent and gives a
connection attempt a time limit, so a laptop that slept or a link that died without a close
shows as lost within a minute instead of freezing the numbers. `make run PANEL=<address>:<port>`
relays the real panel out of the lab for a person to look at. Proven by 205 unit tests on the
web side, 13 on the embedded files with a fuzz target, and three new `m4` scenarios (18 in all):
the client's own tests run under Node from the LAN side, and Playwright's Chromium, inside the
LAN namespace and reaching the router by name, goes from first visit (the fingerprint on the
page is the console's) through setting the password, a reload, logging out and in, to the WAN's
carrier lost and returned with the page left as it stood. CI gains Node and Chromium and keeps
the run's screenshots. Parts 2 to 5 (changing config, the remaining pages, diagnostics, first
boot) follow.

**2026-11-12, [#101](https://github.com/openfeo/openfeo/pull/101), part 2a: changing config, the
router.** The design for part 2 and its router half; the two pages that use it are part 2b. A
running router now takes a new config and restarts only what the change touches. `ConfigService`
has five calls on the WebSocket and gRPC: get (without its secrets, with a tag), validate (what
is wrong, or what the change interrupts and whether it moves whoever asks), apply, confirm and
revert. An apply is pending for 120 s (ADR-0026; 10 s to 600 s on request) and is reverted by
itself unless confirmed; "apply immediately" has no window; a router that restarts inside the
window comes up on the confirmed config and says the change was discarded; a stale tag, a second
change while one is pending, a password change while one is, and any apply on a router running
on defaults over a file it refused are all refused whole. Secrets are write-only: a PPPoE
password that is not sent is the one kept. One keeper in `openfeo-api` holds the confirmed and
the pending config, as a core with no clock or file of its own. The five kinds of task that
exist once per WAN or LAN (the DHCPv4 client, PPPoE, the router-advertisement client, the DHCPv6
client, the DHCPv4 server) are each kept by a manager that compares the slice of the config an
instance depends on, and stops, starts or restarts it; a stop is asked for, takes the task's
facts out of the World and counts as no failure, and on the way out a DHCP lease is released
and a PPPoE session ended with Terminate-Request and PADT. One pure function over the same
slices says what a change does, for the log and for the validation. DNS and time bind again in
place when the LANs change, and serve a LAN whose cable is out; a prefix taken off a LAN is
advertised deprecated before it goes. While a change is pending the DHCP server hands out
leases no longer than the window, and after a revert it has the leases it had: the lease file
keeps the records it cannot use. The state says what is pending and when it reverts; the events
are `config.applied`, `config.confirmed`, `config.reverted` and `config.discarded`. SPEC §1.2 now
lets LANs be added and removed in the panel. Proven by fifteen new `m4` scenarios from the LAN
side (33 in all), among them SPEC §12's "a subnet change not confirmed is reverted", a subnet
change confirmed from the address it moved the router to, a WAN changed from DHCP to PPPoE and
back with Kea seeing the release and `pppd` the Terminate-Request, a tag moved, a LAN added and
removed, and leases across a change that is taken back; by a `dhcp4` and a `dns` sandbox
scenario; and by the keeper's, the managers' and the slices' unit tests. The scenarios found
what the unit tests could not: a pending file whose removal was not synced and came back after a
power cut, the forwarder binding again before its old listener had closed, the port's MTU
changing under a PPPoE session that was saying goodbye, and the console telling a change's
consequences before the change. The whole-branch review found more at the edges, fixed in the
same pull request: an API task restarted inside the window lost the revert; an apply or confirm
whose caller went away mid-write could leave the file and the running config apart; a restarted
DHCP server reported every lease released and granted again, and lost its leases to a clock
that SNTP had stepped; and a DHCP client asked again for the lease it had just given back. Left
open and written into the design: an apply that takes away the address it arrived at may not be
answered, and a WAN that is removed, or moved to another port or tag, loses its link before its
old task has said goodbye. Part 2b is the client's calls, the
draft, and the WAN and LAN & DHCP pages.

**2026-11-19, [#103](https://github.com/openfeo/openfeo/pull/103), part 2b: changing config, the
web.** The router's config can now be changed from the panel. `@openfeo/client` gains the five
config calls; an apply or a revert that is not answered (a change that moves the router's
address takes the answer's way home with it) is a result, not an error, and is never sent
twice. `@openfeo/ui` gains the components a settings page is made of: form sections, choices, a
toggle, a select, the Advanced disclosure, tabs, the save bar, the dialog and the list of
changes. The panel gains a shell that every page behind the login sits in, which listens to the
router once; one draft of the whole config in the tab's memory, never stored, so what no page
shows is sent back as it was; and two pages in the approved mockup's words. **WAN**: a tab per
WAN, its type as three choices each with its own fields, the port with its link and where it is
in use, the VLAN tag, the priority, IPv6, and Add and Remove. **LAN & DHCP**: the router's
address and the subnet's size, the ports as ticks, the DHCP server with its pool and lease
time, reservations edited in place, IPv6, and Add and Remove (refused, with what is in the
way, while a forward or a rule still points into the LAN). Changing a LAN's address or size
carries along every address in the config that lay in its subnet, each field saying what it
was and one that found no place saying so. A field is checked when it is left; what the router
refuses is shown at the field its path names, and what has no field is listed, so nothing
refused is silent. One bar counts the changes of every page, and one dialog lists them before
and after, with what the router says they interrupt, a warning with the router's name and new
address when the change moves whoever is asking, the router's own window, and the box "Apply
immediately, no confirmation countdown", clear every time. While a change is pending every
page of every session counts down on the router's clock with Confirm and Revert now; a change
that goes back leaves its changes as a draft in the tab that made it, a typed password
included, and the tab says why. `effects` now says that a static WAN whose address, gateway,
port or tag changes drops and comes back. Proven by 383 unit tests on the web side (among them
one that alters every leaf of the config's schema and finds each in the list of changes, and
one that holds the renumbering rule to every string field the schema has) and by two new `m4`
scenarios (35 in all): the client's config calls under Node, ending with a change that moves
the router, which the test follows and confirms from the new address; and Playwright's
Chromium, with the window shortened to 40 s, editing the pool and adding a reservation,
applying and confirming, reverting a WAN change by hand, letting a window run out with the page
open and finding the draft still there, adding and removing a LAN with no going back, and
moving the LAN's subnet from under itself: the page says where the router went, and the test
logs in at the new address and confirms there. The whole-branch review found what the tests
had not asked, fixed in the same pull request: an apply sent the draft and the tag of the
moment, so a config changed from elsewhere while the dialog was open was overwritten unseen
(it now sends what the dialog showed, against the config it was shown for); what was typed
while a change waited was lost when the change went back; a change that was answered and
never seen pending, because the address went first, was forgotten in silence; a refusal on a
tab that was not open left Apply changes looking dead; a flag that can be left unset was
missing from the list of changes when it was spelt out; and a reservation matched by client
identifier was never shown as one, because the router wants a MAC on those too. Left open and
written into the design: the countdown is a second coarse and trusts the browser's clock
between the router's words, what was typed for a type that was switched away from is kept only
while its page is open, and no test against a real router meets an apply that is not answered.
Part 3 is the remaining pages.

**2026-11-23, [#128](https://github.com/openfeo/openfeo/pull/128), part 3a: status and leases.**
The first of part 3's three slices, each with its router work and its web work (the design is
`docs/superpowers/specs/2026-11-23-m4-part3-remaining-pages-design.md`): what the panel's owner
opens it for, which is finding the address of a device just plugged in and seeing whether the
line is up and has been full. A lease now records when its device first took the address it
holds, its joined time: a renewal keeps it, and so does a device that asks again for what it
still holds; a lease taken again after it ran out, or on another address, has joined anew. It
is in the lease file (a file from before reads its last renewal), in the published fact, and in
a lease table the API serves as `GetLeases` and as the topic `leases`, pushed whole when a lease
in it changes; the table holds at most 4096, the newest, and carries the router's clock so that
ages are counted against that and not the reader's. The counters are now read every second
whether or not anyone is subscribed, and the last hour of each link's bytes is kept in memory
and served by `GetHistory`; the router still computes no rates (SPEC §10 changes by that
sentence). `@openfeo/client` gains the two calls, the topic, and functions from a link's
history to its rates over time by the rule the live samples are read by, with no rate across
a gap. `@openfeo/ui` gains a chart, a segmented choice and an empty state from the design
system's guidelines. The dashboard draws each WAN's download and upload over the last five
minutes or the last hour, back to before the page was opened, with a gap drawn as a gap and a
mark where the WAN came back; the rate tiles say the hour's peak, the highest ten-second
average; and a card lists the five newest leases. **Leases** is a page of its own under
Network: every LAN's leases, newest first, filtered by name, address or MAC, a row that arrives
marked for a minute, and Reserve on a row, which puts the reservation among the changes the
save bar counts. Proven by 1101 unit tests on the Rust side and 506 on the web side, and
by three new `m4` scenarios (38 in all) and three extended: a lease listed with its joined time,
which stays to the second when its client asks again and when the LAN's server restarts and
reads it back from the file; traffic that passed with no socket open found in the history
afterwards, a sample a second; the client's calls under Node, with a device that joins pushed
to a subscriber; and Playwright's Chromium, started twenty seconds after the router, finding
the chart already drawn into that time, a device that joins appearing without a reload, the
reservation made from the Leases page applied and confirmed, and the mark where the ISP was
cut and came back. The whole-branch review found two things the tests had not asked, fixed in
the same pull request. Lease facts were stamped on the wall clock once and not again when it
stepped, so on a router whose clock starts at the build's the lease table was empty after its
first time sync until the next lease on that LAN: they are now stamped again at a step and the
file rewritten, and the scenario that steps the clock a year finds the lease still listed, a
few minutes old. And the Leases page said nothing when the router refused the draft, so Apply
changes looked dead: it lists every refusal, and a new reservation leaves out a name another
on its LAN already has. Slices 3b (the settings pages) and 3c (the views) follow.

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
on a loaded host. The six minors left are filed as #60 to #63, #65 and #66.

**2026-11-21, [#124](https://github.com/openfeo/openfeo/pull/124), M4 part 2 minors.** Of the minors
and follow-ups that the reviews of #101 and #103 left, the ten that a person can meet today or that
broke one of the repository's own rules; the other twenty are filed as #104 to #123. No wire type
prints a secret in `Debug`: the seven messages that carry a password, a token or a hash have theirs
written by hand, so neither they nor a config, a World or a request that holds one can put a secret
into a log line or an error; the build gives no derived `Debug` to any message with a field that is
a secret by its name, so one added later does not compile until its own is written. Two hand-written
types that held the admin's hash and a PAP request's password no longer print them either. In the
panel's store, an ask that is answered after the session ended leaves nothing behind (an apply used
to put back what it had sent, a typed password included); a read that brings what the draft already
is no longer wipes a field that is half typed; what a renumbering could not place stays marked across
the next one; no ask is sent a second time by a double press; and the bar offers no other apply while
one awaits the router's word. Swapping two LANs' subnets no longer scrambles them: a LAN's own pool
and reservations follow that LAN alone, and in a subnet that two LANs share for a moment anything
else stays with the LAN it points into as the router has it. A pool that a move left the wrong way
round is said at once, and what was said of a reservation, a WAN or a LAN goes with it when it is
removed, together with what was said of those after it, whose places changed, and with what was
typed for it and kept under its name.

**2026-11-24, [#129](https://github.com/openfeo/openfeo/pull/129), M4 part 3a minors.** Nine of the
twelve minors that the review of #128 left. The hour's line and the hour's peak leave out ten seconds
of which under half was read: where the line had just come back, or the router had just booted, a
second or two used to stand for ten, so a one-second burst could be said as the hour's peak. On the
dashboard a lease is marked as new when it joined within a minute of the router's clock, on either
side of it; leases far ahead of the clock (a lease file read while the clock is still the build's)
are no longer all marked until the clock is set. A read of the counters that fails is logged when
the failing begins and when it ends, not each second of it, now that they are read all the time. Two
tests can now fail on what they claim: the page tests set the router's clock a day behind the
browser's, so a page that counted a lease's age on the browser's clock is caught, and the socket
test tells the change that touches no lease from the one after it by the state that is sent between
them. Three comments say rightly that a PPPoE WAN's interface is named all the while and is there
only during a session; the limit in `GetHistory`'s refusal comes from its constant; a field is named
for what it holds; and `@openfeo/ui` no longer exports a function that only it uses. Of the other
three, one needed nothing, and two wait: the lease table is built on every change of the World for
sockets that follow only the state, and a new subscriber to the counters waits up to a second for
its first sample.

## Tooling and process

**2026-11-01, [#11](https://github.com/openfeo/openfeo/pull/11).** A setup script that prepares an
ephemeral cloud sandbox the way CI prepares a runner, `make check-env` fetching its prerequisites
and finding the kernel under `BUILD`, and `rsync` listed everywhere a fresh machine needs it.

**2026-11-01, [#13](https://github.com/openfeo/openfeo/pull/13).** The superpowers process enabled
for the project in `.claude/settings.json`, the boundary between M2 parts 2 and 3 written into
SPEC §12, and the working rules for agent sessions in `CLAUDE.md`.
