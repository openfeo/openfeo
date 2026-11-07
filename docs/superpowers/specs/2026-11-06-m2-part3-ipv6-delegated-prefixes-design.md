# M2 part 3: IPv6 for the other ISPs: delegated prefixes, ULA, deprecation

Design for the third of three M2 parts (SPEC §12). Part 2 brought IPv6 for the line where the
ISP routes a fixed prefix; part 3 brings it for every other line: the ISP hands out a prefix by
DHCPv6 prefix delegation and may take it back or change it. It adds what SPEC §7.3 lists for
this part: DHCPv6 IA_PD and IA_NA, a per-router ULA, the stateless DHCPv6 responder, prefix
deprecation, and source-based routing rules.

The maintainer skipped the brainstorm for this part ("your calls"); every choice below that
SPEC §7.3 does not already make is the author's, listed under "Calls made for the maintainer"
at the end with what each costs if wrong.

## Intent

Most residential lines, and the dogfooding line once M3 puts PPP under it, do not route a fixed
prefix. The ISP's DHCPv6 server delegates one (a /56 or a /48, sometimes only a /64) with
lifetimes, the router renews it, and on a bad day the ISP hands out a different one. Hosts on the
LAN then hold addresses the ISP no longer routes; a router that keeps advertising them leaves
every dual-stack site stalled, and one that drops them without a word leaves hosts with no
explanation either. The CE router rules (RFC 7084, RFC 8415) and the SPEC say what must happen:
the LAN is renumbered at once, the old prefix is advertised as deprecated so hosts stop choosing
it, and traffic that still leaves from it is answered with ICMPv6 unreachable so applications
fail fast and fall back.

Beside the delegated prefix every LAN gets a ULA /64 from a per-router /48 (RFC 4193): addresses
that never change when the ISP's do, for the router's own services and for traffic between LANs.
Hosts that ignore RDNSS learn the resolver through the stateless DHCPv6 responder SPEC §7.3 asks
for, which part 2 deferred by advertising O = 0.

After part 2 OpenFeO forwards IPv6 for a routed prefix only. Part 3 makes a delegation work end
to end, including the day the prefix changes, and leaves the routing in the shape M6's
"a prefix follows its WAN" needs.

## Goals

- A DHCPv6 client per WAN with `[wans.ipv6]` and no typed `prefix`, in the odhcp6c mould (SPEC
  §7.3): Solicit with IA_PD (hint length `pd_hint`, default 56) and IA_NA, Rapid Commit, the
  options DNS servers, domain list and SOL_MAX_RT; T1/T2 renew and rebind; Rebind after a link
  flap and after a reboot from a persisted binding; delegated prefixes and addresses published
  as facts with their lifetimes.
- Each LAN carries one /64 from every delegated prefix, cut by a per-LAN assignment index that
  is stable across reboots, plus one /64 from the router's ULA /48, beside the routed /64 part
  2 gave it. The router takes `::1` in each.
- The RA server advertises every prefix a LAN carries with lifetimes derived from the
  delegation and capped, advertises O = 1, and, when a prefix disappears or its WAN goes down,
  advertises it with preferred lifetime 0 and valid lifetime 7200 for two hours, then drops it.
- Traffic from a prefix the router no longer holds is answered with ICMPv6 destination
  unreachable, not forwarded and not dropped silently.
- Source-based routing: a rule per delegated prefix sends its traffic through the table of the
  WAN that delegated it; a down WAN's table holds an unreachable default (SPEC §7.3, §7.4).
- The stateless DHCPv6 responder: Information-Request answered with the router as resolver and
  the system domain as search list, on every LAN that advertises.
- ULA traffic never crosses a WAN, in either direction.
- The resolvers an ISP hands out over DHCPv6 join the forwarder's upstreams under the route
  gate of ADR-0019, as RDNSS resolvers do.
- The renumbering case proven in the harness: the ISP changes the prefix and the LAN is
  renumbered within 10 s, the old prefix deprecated, traffic from it answered with ICMPv6
  unreachable (SPEC §12's acceptance for this part).
- The IPv6 follow-ups filed from part 2 that touch the code this part rewrites are fixed here:
  #26 (router tie-break), #27 (PIO preferred lifetime), #28 (RA task handles), #29 (the IPv6 MTU
  knob), #30 (`mode = "disabled"` beside a gateway), #31 (WAN knobs before link-up), #33 (SPEC
  §5.2 identity wording) and #34 (EADDRNOTAVAIL while the link-local is tentative).

## Non-goals

- Two WANs with IPv6 (M6). Validation keeps refusing a second `[wans.ipv6]`. The tables and
  rules are built per WAN so that M6 adds a second WAN without reshaping them.
- DHCPv6 over PPP (M3). The client runs on any netdev; M3 plugs the PPP interface in.
- Reconfigure messages (SPEC §7.3 says unsupported), Release on shutdown, Decline, Confirm. A
  link flap or a reboot is answered with Rebind for every binding, which every server handles.
- DHCPv6 relay, authentication (RFC 8415 §20), leasequery.
- Stateful address assignment on the LAN (IA_NA from the router). The responder is stateless;
  hosts take SLAAC addresses, as SPEC §7.3 says.
- Temporary addresses, DAD-failure recovery, neighbour snooping, SNTP over IPv6, NPTv6: part
  2's non-goals stand.
- Typed firewall targets inside a delegated prefix. A rule's IPv6 `to` names a routed-prefix
  address (part 2) or a ULA address; delegated addresses change under the owner's feet.
- The remaining part 2 follow-ups: #32 (the route gate and classless-only leases) and #35 (the
  forwarder's retry gaps) are not IPv6 work and come in a branch of their own.
- The panel (M4).

## Anti-goals

- A host left holding addresses the ISP no longer routes without being told. The old prefix is
  advertised as deprecated the moment the router learns of the change, not at the next periodic
  advertisement.
- Traffic from a gone prefix dropped silently, or forwarded to an ISP that will drop it. It is
  answered with ICMPv6 unreachable at the router.
- A ULA address seen on a WAN, or a packet to one forwarded out of a WAN.
- A LAN renumbered by a configuration edit that inserts a LAN above it, when the owner pinned
  indexes. With `ipv6_index` set, a LAN's /64 is a function of the prefix and the index alone.
- Any change in behaviour for a configuration that mentions no IPv6 (no `[wans.ipv6]`): no ULA,
  no responder, no rules, no new addresses.
- A WAN's routed prefix (part 2) behaving differently because this part exists. Every part 2
  scenario still passes unchanged.
- Breaking any M0, M1 or M2 part 1 scenario.

## Constraints

- Everything in `CLAUDE.md`: `openfeo-proto-dhcp6` is pure (no tokio, libc, nix or socket2 in
  its tree), no shelling out, `clippy -D warnings`, every parser fuzzed, SPDX headers, DCO
  commits, a `docs/progress.md` entry in the PR.
- The DHCPv6 codec is in-tree with `dhcproto`'s v6 module as the differential oracle (the
  pattern of DHCPv4 in M1 and of ADR-0018 for NDP); `dhcproto` stays a dev and fuzz dependency.
- The ruleset stays one `table inet openfeo` applied as one batch; the new rules and sets join
  it.
- Routes, addresses and policy rules carry `RTPROT_OPENFEO` (rules through `FRA_PROTOCOL`), so
  the applier owns exactly what it installed and leaves the kernel's own rules (`local`, `main`,
  `default`) alone.
- The World stays pure and clockless (ADR-0009): lifetimes travel as the moment they were
  obtained plus their seconds; whoever needs the remainder reads its own clock.
- The spec is the source of truth: the amendments below are the plan's first task.

## Design

### Config

```toml
[[wans]]
name = "wan0"
port = "p0"
priority = 10
[wans.dhcp]
[wans.ipv6]
mode = "auto"                        # auto | disabled; absent = auto
# prefix = "2001:db8:1::/48"         # part 2's routed prefix; with it, no delegation is asked for
pd_hint = 56                         # the delegation length asked for: 48 to 64; absent = 56

[[lans]]
name = "lan0"
ports = ["p2"]
ipv4 = "192.168.1.1/24"
ipv6_index = 1                       # this LAN's /64 in every delegated prefix and in the ULA
                                     # absent = the LAN's 1-based position among the LANs
[[lans]]
name = "lan1"
ports = ["p3"]
ipv4 = "192.168.2.1/24"
reaches = ["wan", "lan0"]
ipv6_index = 2

[[lans]]
name = "iot"
ports = ["p4"]
ipv4 = "192.168.3.1/24"
ipv6 = "none"                        # IPv4 only: no ULA, no delegated /64, no advertisements
```

**The router has IPv6** when one WAN carries `[wans.ipv6]` in mode `auto`. Then every LAN,
unless its `ipv6` is the word `none`, carries: the routed /64 its `ipv6` names (part 2), when it
names one; one /64 from every delegated prefix the WAN holds; and one /64 from the router's ULA
/48. Without `[wans.ipv6]` nothing of this exists, which keeps the anti-goal for configurations
that mention no IPv6.

**Delegation or routed prefix.** A WAN with a typed `prefix` runs the router-advertisement
client only, exactly as in part 2. A WAN with `[wans.ipv6]` and no `prefix` runs the DHCPv6
client beside it, asking for a delegation and an address. The two paths do not mix on one WAN:
an ISP that routes a prefix statically has told the owner so, and an ISP that delegates is asked.

**The index.** A LAN's /64 inside a prefix of length L is the prefix with subnet id
`ipv6_index` in the 64 − L bits below it: index 1 of `2001:db8:100::/56` is
`2001:db8:100:1::/64`, and of a ULA `fd12:3456:789a::/48` is `fd12:3456:789a:1::/64`. A LAN's
effective index is the typed one, or its 1-based position in `[[lans]]` counting every LAN,
`none` ones included, so a position never moves because a neighbour opted out; validation
computes the effective index of every LAN that carries IPv6 and refuses a clash, whether two
typed indexes meet or a typed one lands on another LAN's position. Index 0
is the router's: `<prefix>::1/128` sits on loopback for each delegated prefix and for the ULA,
the delegated one being the preferred source of the IPv6 default route, as the routed prefix's
is in part 2. A delegation that is a single /64 (an ISP that delegates no more) goes whole to
the LAN with the lowest index, with the router at `::1` on that bridge and no loopback address
from it. A delegation too short for an index (a /60 holds indexes 1 to 15) leaves that LAN
without a /64 from it, with one console line per delegation naming the LANs left out.

**Validation.** `pd_hint` is 48 to 64 (0 means absent, 56). `ipv6_index` is 1 to 65535 and
unique among the LANs that carry IPv6; it is refused beside `ipv6 = "none"`, as `ra` is. A LAN's
`ipv6` is the word `none`, empty, or the routed address part 2 validates. `ra` needs a LAN that
carries IPv6 (a routed /64, or the router having IPv6 at all), no longer `ipv6` specifically.
`mode = "disabled"` is refused beside `prefix`, `gateway` (#30), `pd_hint` or any LAN `ipv6`.
A rule's IPv6 `to` lies inside a routed /64 (part 2) or inside `fc00::/7`; a ULA target is
matched to a LAN at run time by the LAN's ULA /64, and one that matches none is left out of
the ruleset with a console line. Part 2's other rules stand.

### Identity

- `identity/duid`: the DUID-LL the DHCPv4 client keeps (DUID-LL from the lowest physical port
  MAC, RFC 8415 §11.4) is the DHCPv6 client's and the responder's DUID. The loader moves out of
  `dhcp4.rs` into `identity.rs` with the IPv6 secret's; nothing about the file changes.
- IAIDs are derived, not stored (SPEC §7.3): the first four bytes of SHA-256 over `pd:<wan>`
  for the IA_PD and `na:<wan>` for the IA_NA, over the SHA-256 `openfeo-proto-ndp` carries.
  The spec's §5.2 list drops "IAIDs" (#33 rewrites that line anyway).
- `identity/ula`: the ULA /48 as text, `fdxx:xxxx:xxxx::/48`, 40 random bits under `fd00::/8`
  (RFC 4193 §3.2.1), generated once and persisted next to the DUID. RFC 4193 §3.2.2's
  hash-of-time-and-EUI-64 construction exists to make the bits random; the kernel's random bytes
  already are. Console: `identity: ula fd12:3456:789a::/48 (created)` or `(loaded)`.
- `leases/dhcp6-<wan>.toml`: the last binding (below), the DHCPv6 twin of `dhcp4-<wan>.toml`.

### WAN DHCPv6 client

A sans-IO core in `openfeo-proto-dhcp6` (`client.rs`), one per WAN with `[wans.ipv6]` in mode
`auto` and no `prefix`, driven by a UDP socket in `openfeo-net`, alongside the RA client of part
2 on the same WAN. Both start on carrier; the DHCPv6 client does not wait for an advertisement's
M or O flag, since an ISP that delegates answers a Solicit whatever its flags say, and one that
does not answers nothing, which costs a few packets an hour.

**Messages and timing** follow RFC 8415 §15 and §18: Solicit (IRT 1 s, MRT 3600 s or the
server's SOL_MAX_RT, no MRC) with a Rapid Commit option, IA_PD with an IAPREFIX hint of length
`pd_hint`, IA_NA, an ORO for DNS servers (23), domain list (24) and SOL_MAX_RT (82), and
Elapsed Time; Advertise ranked by preference and taken after the first RT; Request (IRT 1, MRT
30, MRC 10); Reply, with Rapid Commit or after Request, binds. T1 and T2 come from the IA (the
server's choice; 0 means the client's, 0.5 and 0.8 of the shortest preferred lifetime); Renew
(IRT 10, MRT 600) at T1 to the server, Rebind (IRT 10, MRT 600) at T2 to the group; a Reply to
either refreshes the binding. Status NoAddrsAvail in the IA_NA keeps the delegation and drops the
address; NoPrefixAvail in the IA_PD is reported once; with nothing bound the client keeps soliciting at
the SOL_MAX_RT pace, and with an address bound it asks for the prefix again in every Renew and
Rebind for the address (RFC 8415 §18.2.4 and §18.2.5 let a client include an IA it holds no lease
for; Kea allocates on Renew), so there is one exchange schedule, never two; NoBinding on Renew or Rebind restarts with Request; UnspecFail or an unknown
status restarts with Solicit; UseMulticast resends to the group. A prefix or address whose
Reply carries valid lifetime 0, or whose valid lifetime runs out, leaves the binding.

**Carrier.** Loss of carrier stops the timers and keeps the binding. Carrier back sends Rebind
with every IA the binding holds, as RFC 8415 §18.2.12 asks for a prefix after a possible link
change, with Confirm's retransmission parameters (IRT 1 s, MRT 4 s, MRD 10 s) so that a silent
server costs ten seconds, not the lease; the Confirm message itself would cover the address
only and is not worth a second exchange. A Reply refreshes the binding; silence keeps it with
its timers as they were; NoBinding restarts with Request and any other failure with Solicit.

**Reboot.** The last binding is persisted in `leases/dhcp6-<wan>.toml` (server DUID, IAIDs,
the prefixes and addresses with their lifetimes, T1, T2, DNS, domains, the wall-clock moment it
was obtained) each time it changes, written through the state writer. At boot, a binding whose
valid lifetimes have not lapsed by the wall clock, held for this WAN and this port's MAC, is
published as the WAN's fact at once, so the LANs keep their prefixes through a reboot, and the
client sends Rebind for it on carrier instead of Solicit; the server's answer confirms or
replaces it. A lapsed or foreign binding is ignored. The clock floor `make bin` bakes in keeps
"obtained" from lying in 1970.

**Facts.** The task publishes `WanDhcp6Fact` (below) when its content changes: the delegated
prefixes with their lifetimes, the addresses, the resolvers and search names, the server. It is
keyed by WAN beside part 2's `WanIpv6Fact` and does not leave the World with the carrier: the
binding outlives a flap, and the RA server needs to know what to deprecate.

**Deprecation is the task's.** When a prefix leaves the binding (lifetime 0, replaced, or
expired) the task moves it to the fact's deprecated list with a deadline: the lower of two hours
and the prefix's own remaining valid lifetime (RFC 7084 L-13; a host already counts down the
valid lifetime it was last given, so advertising longer would keep the address alive past the
router's own drop), and removes it when the deadline passes; a prefix that comes back before
then leaves the list. When the WAN has had no carrier for two hours the task drops the binding
(SPEC §7.3's "then dropped") and the prefixes go through the same deprecation. The deprecated
list is persisted with the binding, so a reboot inside the window restores it and the hosts'
old addresses keep being answered rather than dropped by the reverse-path check. The World
sees lists; the task owns the clock.

### LAN prefixes

One pure function, `reconcile::lan6::prefixes(&World)`, is where every consumer learns what a
LAN carries: per LAN in configuration order, the routed /64 (from the configuration), one /64
per delegated prefix of the WAN (from `WanDhcp6Fact`, by index), the ULA /64 (from the identity
the World carries), and the deprecated /64s (from the fact's deprecated list, by index). Each
entry names the /64, the router's address in it, its source (routed, delegated by a WAN, ULA)
and its state: live with its lifetimes, stale (live but its WAN has no carrier or no IPv6
default route), or deprecated with its deadline. The routing, RA, responder, DNS and ruleset
reconcilers all read it; none derives a prefix on its own.

The ULA /48 reaches the World as an identity fact (`World.ula: Option<Ipv6Net>`), loaded with
the DUID and the secret before the World exists, as the port map is. Absent (the file could not
be written and the console said so) there is no ULA this boot.

### Routing

The routing reconciler gains, for the WAN with `[wans.ipv6]` (index `i` in the configuration):

- a table `100 + i` with the WAN's IPv6 default route (via the learned router or the typed
  gateway, preferred source the router's loopback address, as in `main`) while the WAN has one,
  and otherwise an `unreachable` default route, protocol 200, so traffic from the WAN's prefixes
  fails fast while it is down (SPEC §7.3). `main` keeps the default too, as SPEC §7.4 says;
- policy rules, IPv6 only, protocol 200: priority 1500 `from all lookup main
  suppress_prefixlength 0`, so traffic between LANs and to on-link destinations resolves in
  `main` while a default route found there is suppressed and the lookup continues; priority
  2000 `from <prefix> lookup 100 + i` per live or stale delegated prefix; priority 2000
  `from <prefix> unreachable` per deprecated prefix. The kernel answers a packet that hits an
  unreachable rule with ICMPv6 destination unreachable, no route (RFC 4443 §3.1), which is the
  acceptance's "traffic from it receives ICMPv6 unreachable". SPEC §7.4's rule list gains the
  1500 rule; the IPv4 side of the 2000 rules stays M6's;
- the router's addresses: `<delegated prefix>::1/128` and `<ula>::1/128` on `lo`; `::1/64` of
  every LAN /64 the function lists on the LAN's bridge, deprecated ones included for their two
  hours, which keeps the connected route the reverse-path check needs so a deprecated source is
  routed to the unreachable rule and answered, not dropped at the input hook;
- addresses the IA_NA gave, on the WAN port. The kernel is not told lifetimes for any of the
  router's own addresses: an address leaves the fact, and so the port, when its preferred
  lifetime lapses or a Reply or advertisement sets it to 0, which is the fix for #27 (the SLAAC
  address of part 2 follows the same rule in the RA client). The router's identity for its own
  traffic is the loopback address, so a deprecated WAN address has nothing to keep alive;
- a blackhole per delegated prefix (protocol 200, metric `BLOCK_METRIC`), as part 2 installs for
  the routed one, and none for the ULA (a ULA /64 no LAN uses is not reachable from anywhere
  that matters).

`DesiredRouting` grows a set of `DesiredRule`; the netlink crate gains rules (RTM_NEWRULE,
RTM_DELRULE, RTM_GETRULE; `FRA_SRC`, `FRA_TABLE`, `FRA_PRIORITY`, `FRA_SUPPRESS_PREFIXLEN`,
`FRA_PROTOCOL`; actions to-table and unreachable), the monitor caches them from the IPv6 rule
multicast group and a dump, the applier diffs them by protocol as it diffs routes, and
`RouteKind` gains `Unreachable`.

### RA server

`reconcile::ra::desired` now lists, per LAN with `ra` on, every prefix from `lan6::prefixes`
as a prefix information option (A = 1, L = 1) with lifetimes by state:

- routed: valid 2592000, preferred 604800 (part 2);
- ULA: the same two constants; it has no delegation to derive from and never goes away;
- delegated, live: the remaining valid and preferred lifetimes of the delegation, capped at
  those two constants (RFC 7084 L-13 forbids advertising longer than the delegation);
- delegated, stale (the WAN has no carrier or no IPv6 default route): preferred 0, valid the
  lower of the remaining valid lifetime and 7200;
- deprecated: preferred 0, valid the time left to the deadline, counted down at every
  advertisement (RFC 7084 L-13 and RFC 4862 §5.5.3: a host ignores an advertised valid lifetime
  shorter than two hours only below its own remainder, so the countdown is what makes the host
  and the router drop the prefix together), until the deadline drops it from the list.

The World carries lifetimes as the moment they were obtained plus seconds; `crates/openfeo/src/ra.rs`
turns them into remainders at each advertisement, so a Reply that extends a lease changes the
fact and the next advertisement, and nothing in `reconcile` reads a clock.

Also in the advertisement: O = 1 now that the responder exists (M stays 0); RDNSS with the
router's addresses in that LAN, ULA first because it survives renumbering; DNSSL as before; a
route information option (RFC 4191) for the ULA /48 and for every live delegated prefix via
this router, lifetime 1800, medium preference, as RFC 7084 L-3 asks, so hosts that honour it
(Windows, macOS; Linux only with `accept_ra_rt_info_max_plen` raised) reach the other LANs'
/64s even while the router lifetime is 0. The router lifetime keeps part 2's rule: 1800 while the WAN with `[wans.ipv6]`
has carrier and an IPv6 default route in the kernel, else 0; a LAN whose only live prefix is the
ULA follows the same rule, since a host with a ULA address and a default route tries IPv6 to
the world and the reject below fails it fast.

A change in the prefix list goes out at once under the 3 s floor (part 2's rule for any change
of contents), which is what makes renumbering reach hosts within seconds of the Reply. #28 is
fixed in passing: the per-LAN tasks are aborted when a LAN leaves the desired set, after the
final advertisements.

### Stateless DHCPv6 responder

A sans-IO core in `openfeo-proto-dhcp6` (`server.rs`), one per LAN that advertises, driven by a
UDP socket on port 547 bound to the bridge and joined to `ff02::1:2`. It answers an
Information-Request from a link-local source with a Reply carrying the Server Identifier (the
router's DUID), the Client Identifier echoed, DNS servers (the router's addresses in that LAN,
ULA first), the domain list (the system domain) and an Information Refresh Time of 86400 s
(RFC 8415 §21.23). It ignores Solicit, Request, Renew, Rebind, Confirm and Release: the
advertisement says M = 0, so a host that sends them is misconfigured, and silence is what RFC
8415 §18.3 permits a server with nothing to assign. `reconcile::dhcp6_server::desired(&World)`
gives each LAN's bridge, resolver addresses and domain; the task in
`crates/openfeo/src/dhcp6_server.rs` follows the pattern of `ra.rs`.

### Sysctls and links

Nothing new per interface. #31 moves the WAN port's `accept_ra = 0` and `autoconf = 0` into the
links applier, written with `addr_gen_mode` and the secret before the port comes up, so the
kernel never autoconfigures the WAN in the window between link-up and the sysctl pass; the
sysctl reconciler keeps declaring them, so a later change is still reconciled. #29 makes the
sysctl reconciler declare the WAN's IPv6 `mtu` as the link MTU when no advertisement carries
one, so a knob once set is restored.

### Firewall

- **ULA stays inside.** In the forward chain, before the zone policy: `ip6 saddr fc00::/7` or
  `ip6 daddr fc00::/7` with `oifname @wan_if` is rejected with ICMPv6 no-route, so a host that
  picked a ULA source for a global destination (it has no GUA yet, or the GUA is deprecated)
  gets an immediate failure and falls back. Input from a WAN with a ULA source is dropped; the
  loose reverse-path check would pass it, since the router has routes to its own ULA.
- **DHCPv6 on the WAN.** Input on the WAN port accepts UDP to port 546 (the client's replies
  arrive unicast from the server's link-local and conntrack does not pair them with the
  multicast Solicit), beside the DHCPv4 client's port 68 rule.
- **The responder.** UDP 547 joins the LAN service rules: the private-LAN service list, which is
  family-neutral (an IPv4 datagram to 547 reaches nothing and is harmless), and the public-LAN
  `lan_pub_ra_if` rule, which is IPv6 only.
- **Rule targets.** A rule whose `to` is a ULA address is placed on the LAN whose ULA /64 holds
  it, at run time, through `lan6::prefixes`; part 2's routed targets are unchanged.
- The rest of the IPv6 ruleset (RFC 4890 input list, link-local reverse-path exemption, rule
  sets) is part 2's and does not change.

### DNS

- The resolvers a WAN learned over DHCPv6 (option 23) join the upstreams after typed ones and
  beside RDNSS, under the route gate (ADR-0019), with the console origin `learned from wan0
  dhcp6`; the search names (option 24) are kept for the panel and not acted on, as DNSSL's are.
- The router's own names answer AAAA for every address `lan6::prefixes` lists for it, routed
  and delegated first, ULA last, and the loopback addresses; a deprecated /64's address is not
  answered.
- Listeners: the driver binds every router address a LAN carries, as part 2 binds the routed
  one, and rebinds as the set changes, so a query to the ULA address is answered from it.
- PTR for the router's own addresses and for typed records follows part 2; the ULA and
  delegated /64s join the zones the router answers for.

### Console

One line each, in the existing styles: the DHCPv6 client's state changes (`dhcp6 wan0
soliciting`, `dhcp6 wan0 bound prefix 2001:db8:100::/56 (valid 60 s) address 2001:db8:ffff::1a4
from <server duid>`, `dhcp6 wan0 renewed`, `dhcp6 wan0 rebinding`, `dhcp6 wan0 prefix
2001:db8:100::/56 gone: deprecated for 55 s` (the lower of two hours and its remaining valid
lifetime), `dhcp6 wan0 no prefix available`, `dhcp6 wan0
binding restored from disk`), the ULA identity, each LAN's /64s as they appear and leave
(`lan0 ipv6 2001:db8:100:1::1/64 from wan0 delegation`, `lan0 ipv6 fd12:3456:789a:1::1/64
ula`, `lan0 ipv6 2001:db8:100:1::/64 deprecated`), a LAN left out of a short delegation, the
rules and the WAN table as the routing applier installs them (in the applier's existing
describe style), the responder starting per LAN, resolvers learned by DHCPv6. The harness
asserts through these lines; the plan fixes the exact wording in the console contract tests.

### Schema

New fields: `Ipv6Wan.pd_hint` (`uint32`, 0 = absent = 56), `Lan.ipv6_index` (`uint32`, 0 =
absent = position), `Lan.ipv6` accepts the word `none`. New message `Dhcp6Lease` for
`leases/dhcp6-<wan>.toml` (wan, mac, server DUID as hex, the IA_PD and IA_NA bindings with
lifetimes, T1, T2, DNS, domains, obtained wall-clock seconds, and the deprecated prefixes with
their wall-clock deadlines). No existing field changes
meaning: a part 2 configuration loads and behaves as before, since without a delegation the
only addition is the ULA /64 and the responder on each LAN, which is what SPEC §7.3 promised
for part 3. `config_version` stays 1.

### Facts

`World` gains `dhcp6: BTreeMap<String, WanDhcp6Fact>` (keyed by WAN) and `ula: Option<Ipv6Net>`.
`WanDhcp6Fact` holds `prefixes: Vec<Delegated>` (`prefix: Ipv6Net`, `obtained_ms: u64`,
`preferred_secs: u32`, `valid_secs: u32`), `addresses: Vec<Delegated>` in the same shape for
the IA_NA, `deprecated: Vec<Deprecated>` (`prefix`, `until_ms`), `dns: Vec<Ipv6Addr>`,
`search: Vec<String>` and `server: Vec<u8>` (the DUID, for the console). Content only; the
task holds the timers. The moments are milliseconds on the process's monotonic clock
(`openfeo_runtime::clock::uptime_ms`, one `Instant` for the whole process), never the wall
clock: an RTC-less board sits at the build-epoch floor until SNTP steps its clock by weeks,
seconds after the first delegation binds, and a wall-clock remainder would then read as lapsed
on every LAN until the next Renew. Only the persisted binding file uses wall-clock seconds, and
a file obtained "in the future" (the clock went backwards: such a board after a reboot) is
counted from now and settled by the Rebind that follows.

### Crates and drivers

- `openfeo-proto-dhcp6` (SPEC §13 lists it): `wire.rs` (message type and transaction id;
  options 1, 2, 3, 5, 6, 8, 13, 14, 23, 24, 25, 26, 32, 82 decoded, nested IA options
  included, unknown options skipped by length; fuzz targets `dhcp6_message` for the round trip
  and `dhcp6_differential` against `dhcproto::v6`), `client.rs` (the state machine above, the
  `handle(Input, now) -> Vec<Output>` and `next_timeout` shape of the DHCPv4 and NDP cores;
  fuzz target `dhcp6_client` feeding arbitrary replies and every timeout), `server.rs` (the
  responder; fuzz target `dhcp6_server`), `iaid.rs` (the derivation above, over
  `openfeo_proto_ndp::sha256`).
- `openfeo-net/src/dhcp6.rs`: the client driver, a tokio UDP socket on `[::]:546` with
  `SO_BINDTODEVICE` on the WAN port and membership of `ff02::1:2` on its index through the
  standard library's `UdpSocket::join_multicast_v6` (safe, and it takes the interface index,
  which nix's membership request does not), sending to `[ff02::1:2%ifindex]:547` from the link-local
  the kernel picks; the responder driver, the same on port 547 bound to a bridge. Both wait out
  EADDRNOTAVAIL while the link-local is tentative, by retrying the send on the next timer, and
  #34 gives `ndp.rs` the same patience. No new `unsafe`.
- `crates/openfeo/src/dhcp6.rs` (the client task per WAN: driver, fact, persistence, console,
  the deprecation and two-hour timers), `crates/openfeo/src/dhcp6_server.rs` (the responders),
  `crates/openfeo/src/identity.rs` (DUID, secret, ULA loaders), `ra.rs` and `ipv6.rs` grown as
  above (#26's tie-break keeps the current router while an equal-preference newcomer merely
  refreshes).
- `openfeo-world/src/dhcp6.rs`; `openfeo-reconcile/src/lan6.rs`, `dhcp6_server.rs`, and the
  routing, ra, nft, dns, sysctl and links changes above; `openfeo-netlink` rules and
  `IFA_CACHEINFO`; `openfeo-config` schema and validation.

### Harness

**Lab.** `isp0` runs Kea's DHCPv6 server (`kea-dhcp6`, package `kea-dhcp6-server`; Ubuntu's
AppArmor profile `usr.sbin.kea-dhcp6` is unloaded in CI as the DHCPv4 one is, ADR-0006) on the
ISP side of the WAN tap, from a template beside the DHCPv4 one: the link subnet
`2001:db8:ffff::/64` with an IA_NA pool, a PD pool the scenario names (`2001:db8:100::/48`
delegating /56; a second pool `2001:db8:200::/48` for the change), `rapid-commit` on, DNS
servers pointing at dnsmasq's IPv6 address, domain search `isp.example`, and lifetimes that
make a scenario see a renewal: `renew-timer 10`, `rebind-timer 16`, `preferred-lifetime 40`,
`valid-lifetime 60`; a memfile lease database that does not persist, so a restart with the
other pool is an ISP that forgot the old delegation. The ISP side routes each PD pool via the
router's WAN link-local, which the lab reads from the console, as part 2's `isp_route_block6`
does for the routed prefix. radvd keeps advertising the link as in part 2, with the M and O
flags set in the PD scenarios. `kea-dhcp6` joins `check-env` (presence and "reads our config"),
the CI apt line and the cloud setup script. busybox's `udhcpc6` applet (present in Ubuntu's
`busybox-static` and Arch's `busybox`, checked by `check-env`) is the reference stateless
client: `udhcpc6 -l -i <if> -O dns -O search` (its names for options 23 and 24) with a script
that prints its environment.

**The prefix change.** `Lab::restart_kea6(pool)` stops Kea and starts it with the other pool.
The router's Renew at T1 then meets a server with no binding, which Kea answers by allocating
from the new pool and returning the old prefix with zero lifetimes when it lies outside every
pool (Kea's documented handling of a Renew for a prefix it does not know). Should the pinned Kea
answer NoBinding instead, the client's path through Request reaches the same place a round trip
later; either lands inside the acceptance's 10 s with T1 at 10 s. The scenario measures from
the console line that announces the new prefix.

**Fixture.** `harness/fixtures/vm-pd.toml`: the DHCPv4 WAN of `vm-dhcp.toml` plus `[wans.ipv6]`
with no prefix and `pd_hint = 56`; `lan0` on `p2` with `ipv6_index = 1`; `lan1` on `p3` with
`ipv6_index = 2` and `reaches = ["wan", "lan0"]` (and `lan0` reaching `lan1`), both advertising;
`dns.upstreams` empty so the DHCPv6-learned resolver is what answers.

**QEMU scenarios** (a sibling of `m2.rs`, `harness/tests/m2pd.rs`):

- `a_lan_client_gets_a_gua_from_the_delegation_and_reaches_the_isp`: the console shows the
  binding with a /56 from the first pool and an address from the IA_NA pool; the LAN host
  configures an address in that prefix's index-1 /64 and fetches the ISP's IPv6 HTTP target;
  `rdisc6` shows O = 1, the ULA /64 beside the delegated one, and the router's ULA address as
  RDNSS; the ISP side pings the router's IA_NA address.
- `the_isp_changes_the_prefix_and_the_lan_is_renumbered_within_ten_seconds`: after
  `restart_kea6` with the second pool, within 10 s of the console's new-prefix line the LAN host
  holds an address in the new /64 and its old address is marked deprecated by the kernel; a
  ping from the old address to the ISP target is answered with destination unreachable from the
  router; the console shows the deprecation line and the unreachable rule; once the old
  prefix's remaining valid lifetime has run out (at most Kea's 60 s, which is the deprecation
  deadline in the lab) the old /64 is gone from the host, the advertisement and the router.
- `wan_ipv6_loss_deprecates_the_delegated_prefix_and_carrier_back_rebinds_it`: carrier off on
  the WAN tap; within one advertisement interval the LAN host has no IPv6 default route and its
  delegated address is deprecated while its ULA address stays preferred; carrier back; the
  console shows `rebinding` and the same prefix bound again, and the host's address is
  preferred once more.
- `ula_addresses_reach_the_other_lan_and_never_leave_the_wan`: the `lan1` host pings the `lan0`
  host's ULA address through the router; a ping from a ULA source to the ISP target is answered
  with no-route by the router and never seen on `isp0`; a packet from `isp0` with a ULA source
  is dropped.
- `stateless_dhcpv6_hands_out_the_resolver_and_the_domain`: `udhcpc6 -l` in the LAN namespace
  receives the router's ULA address as DNS and `home.arpa` as the domain; the console shows the
  responder's line.
- `a_rebooted_router_keeps_its_delegation`: with Kea's long-lived template variant (T1 10 s,
  valid 600 s, so a reboot under TCG cannot outlast the binding) the VM reboots with its state
  disk; the console shows the binding restored from disk and `rebinding`, the prefix is the
  same, and the LAN host's address never leaves the preferred state.
- `isp_resolvers_learned_over_dhcpv6_join_after_the_route`: with empty upstreams, `dig AAAA
  www.isp.example` over IPv6 at the router's ULA address answers, and the console shows the
  DHCPv6-learned upstream joining only once the IPv6 default route exists.

Part 2's eight IPv6 scenarios keep running on `vm-ipv6.toml`; the routed line gains the ULA and
the responder, so `lan_client_configures_itself_from_the_lan_prefix_and_reaches_the_isp_over_ipv6`
also checks the ULA /64 and O = 1, and `dmz_host_ipv6_is_reached_from_the_isp_only_through_a_rule`
checks the DMZ still receives no advertisements.

**Sandbox scenarios.** A new `dhcp6` suite after the shape of `dhcp4` and `ndp`, over a veth
pair with no QEMU: the client driver solicits and binds a prefix, an address and the resolvers
from Kea with Rapid Commit; renews at T1 (Kea's log shows the renew); Kea restarted with the
other pool yields the new prefix and the old one deprecated within T1 plus a round trip; a link
flap makes the driver send Rebind, not Solicit (the driver's events name the message types
sent); a driver started with a persisted binding sends Rebind first and keeps the prefix; a
server with no PD pool yields the no-prefix line and solicitations at the SOL_MAX_RT pace; the
responder driver answers `udhcpc6 -l` with the resolver and the domain. `netlink`: a rule with
`suppress_prefixlength` and a to-table action, an unreachable rule, a route in table 100 and
an unreachable route, each added, dumped and removed. `nft`: the
ULA reject and drop rules and the 546/547 service rules apply on the pinned nftables; a packet
from a ULA source toward the WAN is rejected with no-route (the nft sandbox's probe shape).

**Unit, snapshot and fuzz.** Validation cases for every rule under Config; `lan6::prefixes` on a
World with a routed prefix, a delegation, a short delegation, a single-/64 delegation and a
deprecated prefix; `insta` snapshots for routing (rules and tables), ra, dhcp6_server, nft and
dns on the new fixture; the config fuzz target covers the new fields; the four DHCPv6 targets
run under the nightly job.

## SPEC amendments (the plan's first task)

- §5.2: `identity/` gains `ula`; "IAIDs" leaves the list (derived); the IPv6 stable-privacy
  secret and the ULA are named as identity a backup restores (#33); `leases/` gains
  `dhcp6-<wan>.toml`.
- §7.3: the delegated path as designed: `pd_hint`; the DHCPv6 client beside the RA client on a
  WAN without a typed prefix, its messages, timing and status handling; Rebind after a flap and
  a reboot from the persisted binding; the assignment index (`ipv6_index`, default position,
  index 0 the router's, the single-/64 and short-delegation rules); `ipv6 = "none"`; the ULA
  gated on the router having IPv6; PIO lifetimes per state; O = 1; the RDNSS order; the ULA
  route information option; deprecation as the client task's two-hour list; the two-hour drop
  of a carrier-less binding.
- §7.4: the 1500 `suppress_prefixlength 0` rule; the IPv6 half of the per-WAN table and the
  2000 rules land in M2 part 3, the IPv4 half stays M6; the unreachable rule for a deprecated
  prefix; the blackhole per delegated prefix; `FRA_PROTOCOL` ownership.
- §7.5: ULA never crosses a WAN (reject out, drop in); UDP 546 on the WAN input; UDP 547 as a
  LAN service; a rule's IPv6 target may be a ULA address.
- §7.7: DHCPv6-learned resolvers under the gate; the router's AAAA answers and listeners cover
  every address a LAN carries.
- §8.2: the example gains `pd_hint`, `ipv6_index` and `ipv6 = "none"`.
- §11: Kea's DHCPv6 server on the ISP side, `udhcpc6` as the stateless reference client, the
  prefix-change scenario as implemented.
- §13: `openfeo-proto-dhcp6` with its fuzz targets; `openfeo-netlink` rules.

## ADRs

None planned. Nothing here departs from SPEC §2; the choices are spec amendments. Kernel or
protocol quirks the harness turns up get their ADRs as found (CLAUDE.md), the likeliest being
Kea's exact answer to a Renew it has no binding for, and how the kernel reports a rule's
protocol in a dump.

## What is left to the builder

- Internal names and signatures; the fact and desired-state structs above are shapes, not
  names.
- The `Input`/`Output` vocabulary of the DHCPv6 core and how the driver surfaces message types
  for the sandbox assertions.
- Whether the responder shares `bound.rs` with the DNS listener or opens its own socket.
- How `crates/openfeo/src/ra.rs` turns obtained-plus-seconds into remainders without re-sending
  an advertisement every second: a lifetime is read at send time; a change in the fact, not in
  the clock, triggers an unscheduled advertisement.
- Where the single-/64 delegation's bridge address and the console line for a short
  delegation are produced (`lan6::prefixes` is the natural place; the console needs the diff).
- The Kea DHCPv6 template's exact knobs for the pinned 2.4.1 (CI) and the local 3.x, which the
  `check-env` test against the installed Kea settles as it did for DHCPv4.
- Whether `m2pd.rs` reuses `m2.rs`'s helpers through a shared module or copies the few it needs.

## Calls made for the maintainer

Each with what it costs if wrong.

1. **No DHCPv6 beside a typed `prefix`.** A WAN runs one path. Cost: an ISP that routes a prefix
   statically and also hands out an address or resolvers by DHCPv6 gets those from RDNSS and
   SLAAC instead; a later part can add an address-only mode.
2. **ULA and the responder on every LAN once the router has IPv6, `ipv6 = "none"` to opt out;
   nothing without `[wans.ipv6]`.** Cost: an owner who wanted ULA opt-in edits one line per LAN;
   an owner who wanted ULA without any WAN IPv6 waits for a knob.
3. **`ipv6_index` defaults to the LAN's position; index 0 is the router's.** Cost: a LAN
   inserted above another renumbers it unless indexes are pinned, which the field exists for.
4. **IA_NA is always requested; `pd_hint` 48 to 64, default 56.** Cost: an ISP that refuses a
   Solicit carrying an IA_NA (none known) would need a knob.
5. **Deprecation by policy rule (`from <prefix> unreachable`) with the router's address kept on
   the old /64 for two hours.** Cost: if the reverse-path interplay differs from the design's
   reading, the harness shows drops instead of unreachables and the fix is a `fib` exemption for
   deprecated prefixes, one rule.
6. **Policy rules now: 1500 suppress-main, 2000 per prefix, the WAN's IPv6 table, `main` keeps
   the default.** Cost: M6 may move the default out of `main`; the rules and the table are
   already in its shape.
7. **ULA never crosses a WAN: reject with no-route out, drop in.** Cost: none known.
8. **A route information option for the ULA /48.** Cost: Linux hosts ignore it by default; it
   is one option and harmless.
9. **Lifetimes in facts as moments on the process's monotonic clock plus seconds; only the
   persisted file uses the wall clock, and a file from the future is counted from now.** Cost:
   a binding restored on an RTC-less board may be trusted for up to its lifetime before the
   Rebind corrects it, which the Rebind does within seconds of carrier.
10. **Rebind for everything after a flap or a reboot, with Confirm's timing; no Confirm, no
    Release, no Decline.** Cost: an address kept across a move to a different link, which a
    router does not do.
11. **The ULA is 40 random bits.** Cost: none in practice; RFC 4193's construction aims at the
    same randomness.
12. **The IPv6 follow-ups #26, #27, #28, #29, #30, #31, #33 and #34 are fixed in this part;
    #32 and #35 are not.** Cost: a larger PR; each fix is a task of its own with its test.
13. **The responder ignores everything but Information-Request.** Cost: none while the
    advertisement says M = 0.
14. **The DHCPv6 client starts on carrier without waiting for an advertisement's M or O flag.**
    Cost: a few Solicits an hour on a line that never delegates and never advertises the flags.
15. **A deprecated prefix is advertised with its valid lifetime counting down to the lower of
    two hours and its own remaining lifetime, and the deprecated list survives a reboot.** Cost:
    none known; the constant SPEC §7.3 first described would have kept hosts' addresses up to
    two hours past the router's drop.
16. **The effective `ipv6_index` is the typed one or the LAN's position counting every LAN, and
    any clash among LANs that carry IPv6 is refused.** Cost: an owner who pins an index that is
    another LAN's position pins both.
17. **With only the address bound, the prefix is asked for again in each Renew and Rebind; the
    client keeps one exchange schedule.** Cost: a prefix that becomes available between renewals
    is learned at the next T1 rather than within SOL_MAX_RT.

## After the whole-branch review (2026-11-07)

- #27 is **not** fixed by this part after all: an address leaving the port when its preferred
  lifetime lapses (the sentence under *Routing* above, and the SLAAC half in the RA client) was not
  built, and installing addresses with kernel lifetimes is a day's work with its own failure modes.
  SPEC §7.3 now describes what is built (an address leaves with its valid lifetime or a lifetime of
  0) and #27 stays open.
- A Reply that binds nothing is followed by another Solicit after thirty seconds, doubling to
  `SOL_MAX_RT`, instead of one full `SOL_MAX_RT` later (SPEC §7.3 says so now): a subscriber the
  ISP provisions a moment after the first Solicit is served within a minute, not an hour.
- The client never sends straight out of a Reply: an answer that leaves T1 already due waits ten
  seconds, and `NoBinding` is followed by a Request on the timer, so a server sets the pace of
  nothing. T1 and T2 defaults skip leases with no preferred lifetime left. Only global unicast is
  taken from a server. T2 of `u32::MAX` means never Rebind.
- A binding restored from disk carries what is left of its lifetimes and counts from now, rather
  than being wound back to before boot.
- A delegation too short for a LAN's index is said once on the console
  (`dhcp6 wan0 prefix 2001:db8:100::/60 is too short for lan1 (index 20)`), as promised above.
- The RA and responder tasks start on the configuration, not on the facts at boot.
