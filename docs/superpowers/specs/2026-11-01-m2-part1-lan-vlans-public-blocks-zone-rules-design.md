# M2 part 1: LAN VLANs, routed public IPv4 blocks and zone rules

Design for the first of three M2 parts (SPEC §12). Part 1 is IPv4 only and testable in the
harness today; parts 2 and 3 bring IPv6 (SPEC §7.3) on top of what part 1 lays down.

## Intent

The dogfooding line, and many small-office lines, look like this: several LANs carried as 802.1Q
VLANs over a few trunk ports, one of them a DMZ numbered from a block of public IPv4 addresses
the ISP routes to the router, a second routed block kept for publishing LAN hosts on public
addresses, and a zone policy richer than "LAN out, nothing in": a trusted LAN that reaches
everything and that nothing may initiate into, a guest LAN that reaches only the internet, a DMZ
that reaches only the internet and is reached from the internet only on the ports its owner
opened.

OpenFeO after M1 bridges whole ports, translates every IPv4 packet leaving a WAN, forwards
WAN-to-LAN traffic only when a port forward translated it, and keeps LANs apart from each other
with no way to say otherwise. Part 1 adds the three things that setup needs, in a shape that
other setups fit too: a LAN member may be a tagged VLAN on a port; a LAN may be numbered from a
declared public block, which switches translation off for it and turns its inbound side into a
policy; and the forwarding policy becomes per LAN, with explicit rules for the holes.

IPv6 (parts 2 and 3) reuses all three: a routed /48 is carved into public per-LAN prefixes with
the same no-translation, rules-for-inbound semantics, and the VLAN members are shared.

## Goals

- A LAN's `ports` may name a port untagged (`p6`) or a tagged VLAN on a port (`p6.224`). A port
  may be untagged in one LAN and tagged in others (a trunk or hybrid port). The VLAN-tagged WAN
  that SPEC §7.2 already lists (`vlan = 101` on a WAN) works through the same primitive; today
  the field is accepted and ignored.
- `[[public_ipv4]]` declares a block the ISP routes to this router. A LAN whose `ipv4` lies
  within a declared block is a public LAN: its traffic is never translated, its hosts are reached
  from the WAN only through rules, the DNS rebinding guard leaves its subnet alone, and the
  router offers it fewer of its own services. Every declared block gets a blackhole route so that
  addresses nobody answers for are dropped at the router instead of looping back to the ISP.
- A port forward may listen on an address from a declared block that no LAN uses, with hairpin
  from the LANs exactly as for the WAN address.
- Each LAN says which zones it reaches (`reaches = ["wan", "guest"]`); the default is the WAN
  alone, which is SPEC §7.5's "LAN→WAN accept, LAN↔LAN drop". Traffic within one LAN is always
  forwarded. Nothing initiates into a LAN unless a source zone lists it.
- `[[firewall.rules]]` opens one hole: from a zone, to an address, address range or subnet
  inside a LAN, for a protocol and ports. It is how the DMZ's web ports are opened from the WAN
  and how one LAN reaches one host in another.
- ICMP echo on the WAN, when enabled, is rate limited.
- All of it proven in the harness: VLAN membership and stray cleanup in the sandbox, the
  policy, the rules, the untranslated DMZ, the public-address forward, the blackhole and the
  tagged WAN in QEMU.

## Non-goals

- IPv6 (parts 2 and 3). Part 1 must not make the IPv6 design harder: public LANs, rules and
  `reaches` are family-neutral concepts whose IPv4 half lands now.
- Multi-WAN semantics for public blocks (SPEC §7.4, M6): a block belongs to the ISP account that
  routes it, so its egress must stay on a WAN of that account. Part 1 records the need and
  leaves every block on the active WAN, which is right while every WAN is one account.
- Source NAT from a public address for a LAN host (one-to-one NAT). The data model leaves room
  (a block whose addresses forwards use), nothing is built.
- Static names for DMZ hosts in the local DNS zone. The local zone keeps coming from leases and
  reservations.
- Per-LAN control over which LANs may reach the router's management interface. That is M4's
  concern; part 1 only distinguishes public LANs from private ones.
- UPnP, which the spec does not have.
- A bogon-source filter on the WAN. It was in an earlier draft and the builder check showed its
  cost: a WAN behind a privately addressed modem or on a CGNAT ISP (the dogfooding line's own
  backup WANs lease from a 192.168 gateway) receives its DHCP replies, its gateway's ICMP and its
  forwards' clients from exactly those ranges, and the interface-based zones already keep a
  spoofed private source from reaching anything a WAN source may not. A per-WAN filter can come
  later as a knob that is off while the WAN's own address is private.
- Changing the bridge model to one VLAN-aware bridge with per-VLAN interfaces (the RouterOS and
  switch-chip-friendly shape). See the ADR below.

## Anti-goals

- A LAN in public space being translated or reachable by accident. A LAN numbered from global
  unicast space that is not inside a declared block is a validation error that names the fix,
  never a silently translated LAN.
- A hole that is wider than its rule. A rule names one zone, one destination set, one protocol
  and explicit ports; "any" protocol is spelled out, never implied.
- Rule counts that grow with the configuration. Rules land in a handful of concatenated sets,
  not one nft rule each (SPEC §7.5).
- Breaking any M0 or M1 scenario. The default configuration and the existing fixtures keep
  their behaviour exactly.

## Constraints

- Everything in `CLAUDE.md`: pure crates stay pure, no shelling out, `clippy -D warnings`, every
  parser fuzzed, SPDX headers, DCO commits.
- SPEC §7.1 names ports `pN`; the tagged form `pN.V` is the kernel's own 802.1Q naming and fits
  `IFNAMSIZ` for every valid id (`p99.4094` is eight characters).
- The ruleset stays one `table inet openfeo` applied as one atomic batch, with zones as named
  sets (SPEC §7.5).
- Reverse-path filtering stays in nft (SPEC §7.4) and must keep passing for public LANs: a
  packet from a DMZ host arrives on the DMZ bridge, which is where the fib says its source lives.
- The spec is the source of truth: the SPEC amendments below are the plan's first task, and the
  VLAN model gets an ADR before code.

## Design

### LAN VLANs

**Config.** A LAN member is `pN` (untagged) or `pN.V` (tagged, VLAN id `V` in 1..=4094). The WAN
field `vlan` keeps its meaning (`0` untagged, otherwise tagged) and is now honoured.

```toml
[[lans]]
name = "main"
ports = ["p5", "p7"]                 # untagged on both
reaches = ["wan", "guest", "dmz"]
ipv4 = "192.168.1.1/24"

[[lans]]
name = "guest"
ports = ["p5.223", "p7.223"]         # tagged 223 on the same two ports
ipv4 = "192.168.2.1/24"              # reaches defaults to ["wan"]

[[lans]]
name = "trusted"
ports = ["p6", "p5.224"]             # p6 is an access port, p5 carries it tagged
reaches = ["wan", "main", "guest", "dmz"]
ipv4 = "192.168.3.1/24"
```

**Model.** One bridge per LAN stays (`br-<lan>`, SPEC §7.1). A tagged member is an 802.1Q
sub-interface `pN.V` of the port, created by the router and enslaved to the LAN's bridge. The
kernel delivers a frame tagged `V` arriving on `pN` to `pN.V` before the bridge on `pN` sees it,
so a trunk port is simply a member of several bridges: untagged in one, through a sub-interface
in each of the others. A tagged frame for which no sub-interface exists reaches the port's
bridge, which drops it because VLAN filtering is on and the port only carries VLAN 1 there.

**Links.** `DesiredPort` grows a kind: a physical port or a VLAN sub-interface (parent port, id).
The links reconciler produces one `DesiredPort` per distinct `pN.V` named by any LAN, up and
enslaved to that LAN's bridge; the parent port is up whenever it has any role. The applier
creates missing sub-interfaces (`ip link add link pN name pN.V type vlan id V`, through the
netlink crate), deletes sub-interfaces named `pN.V` that no LAN wants (the same stray policy as
`br-*` bridges), and enslaves as today. The netlink monitor reports VLAN links with their parent
and id so the reconciler can tell a stray from a wanted one. The bridge MAC rule (lowest member
MAC) counts a sub-interface's MAC, which is its parent's.

**WAN VLAN.** A WAN with `vlan = V` runs on `pN.V`: the links reconciler produces the
sub-interface, and the WAN's interface name everywhere downstream (routing, the DHCP client,
nft's `wan_if`, the console) is `pN.V` instead of `pN`. The MTU rule for DHCP WANs applies to the
sub-interface.

**Validation.** `pN` untagged in at most one LAN; `pN.V` in at most one LAN; a WAN's port, and a
WAN's `pN.V`, in no LAN at all (one physical port is either a WAN or carries LANs, not both, in
this part); `V` in 1..=4094; every named `pN` present in the port map, as today. Messages name
the port and both owners.

### Public IPv4 blocks

**Config.**

```toml
[[public_ipv4]]
prefix = "192.0.2.232/29"         # routed to this router; the DMZ below uses it

[[public_ipv4]]
prefix = "192.0.2.248/29"         # routed to this router; port forwards use its addresses

[[lans]]
name = "dmz"
ports = ["p3"]
ipv4 = "192.0.2.233/29"           # inside a declared block: a public LAN
# no [lans.dhcp]: the servers are configured by hand

[[firewall.port_forwards]]
name = "lan-https"
address = "192.0.2.249"           # from the second block; omitted = the WAN address
proto = "tcp"
port = 443
to = "192.168.1.10"
to_port = 443
```

**Semantics.** A LAN is public when its `ipv4` lies within a declared block. For a public LAN:

- Source NAT skips it. The masquerade rule matches sources in a named set of the private LANs'
  subnets (`nat_nets`) instead of every IPv4 packet leaving a WAN, so a DMZ host leaves with its
  own address. Hairpin masquerade for translated flows within one LAN is unchanged.
- Inbound from the WAN follows the default policy (drop) plus rules, exactly like a private LAN.
  There is nothing special about a public LAN's inbound side; what makes it reachable is that its
  addresses are routed here and nothing translates them.
- The DNS rebinding guard excludes its subnet: the forwarder's `lan_subnets` carries only private
  LANs. The router's address in a public LAN stays one of the router's A records.
- The router offers it fewer services. A private LAN reaches the router for DHCP, DNS, HTTP(S),
  NTP and ICMP (SPEC §7.5). A public LAN reaches the router for ICMP always, and for DHCP, DNS and
  NTP only when it has `[lans.dhcp]` (then its hosts were told to use the router). It never
  reaches the router's HTTP(S): the panel is not served to a DMZ. This is the author's call,
  mirroring the "untrusted DMZ" stance of the line this is designed for; it is one set membership
  in the input chain and can be loosened later per LAN.
- DHCP is unchanged: a public LAN runs the server when `[lans.dhcp]` is present, with the usual
  pool rules.

**Routing.** Every declared block gets a blackhole route in the main table, protocol 200, with
a metric high enough that any connected route for a LAN inside the block wins while that LAN's
bridge is up. `DesiredRoute` gains a kind (unicast or blackhole) and the netlink crate sets the
route type. A block used by port forwards only has no other route: translated flows are
re-routed after DNAT to the LAN host, and everything else addressed into the block is dropped
silently, never sent back out the default route.

**Port forwards on public addresses.** `address` is optional and defaults to the WAN address
(today's behaviour, now matched as any local address of the router: the WAN-side rules gain
`fib daddr type local`, so a WAN-address forward never answers on a public-block address that
happens to share its port). With `address` set, the
forward is keyed on destination address and port in a second pair of maps (`fwd_pub_tcp`,
`fwd_pub_udp`, type `ipv4_addr . inet_service : ipv4_addr . inet_service`) consulted for packets
arriving on a WAN, and for hairpin from the LANs. Whether a translated flow is then forwarded is
decided by the zone policy below, not by the translation.

**Validation.** A block parses as an IPv4 prefix in global unicast space (not RFC 1918, not
100.64.0.0/10, not loopback, link-local, multicast, 0.0.0.0/8 or 240.0.0.0/4) and overlaps no
other block, no WAN static subnet and no private LAN. A LAN in global unicast space must lie
within exactly one block (message: declare it under `[[public_ipv4]]`, or use private space). Two
LANs may share a block with non-overlapping subnets. A forward's `address` lies within a block,
outside every LAN subnet, and is neither the block's network nor its broadcast address. The
existing `to` check (inside a LAN subnet) stands.

### Zone policy: `reaches`

Each LAN carries `reaches`, a list of zone names: `"wan"`, another LAN's name, or the one word
`"none"`. Absent or empty means `["wan"]` (the schema cannot tell an empty list from a missing
key, so the default is spelled by absence and "initiates into nothing" has its own word). A LAN
that is only ever reached, a camera or IoT LAN that the trusted LAN looks into, says `reaches =
["none"]`. Within one LAN traffic is always forwarded. Public LANs default the same way.

**Translated flows follow the policy.** Today the forward chain accepts every flow a port
forward translated, wherever it came from, which would let a guest or DMZ host reach a `main`
host's forwarded port by hairpin although neither lists `main`. A translated flow from a WAN is
accepted (a forward is by definition "the WAN may reach this host on this port"); a translated
flow from a LAN is accepted only when the pair (source LAN, destination LAN) is allowed by
`reaches`. The hairpin translation itself keeps matching every LAN; the forward chain is the one
place that decides.

nft keeps one rule per direction class, with sets:

- `lan_to_wan`: LAN bridges whose `reaches` contains `"wan"`; rule `iifname @lan_to_wan oifname
  @wan_if accept`.
- `lan_pairs`: `ifname . ifname` pairs, every LAN with itself plus (A, B) for each B in A's
  `reaches`; rule `iifname . oifname @lan_pairs accept`. It replaces `lan_same` in the forward
  chain; `lan_same` stays for the hairpin masquerade, which is about one LAN talking to itself.
- Translated flows: `ct status dnat iifname @wan_if accept` and `ct status dnat iifname .
  oifname @lan_pairs accept` replace the unconditional accept.

Validation: each entry is `"wan"`, `"none"` or an existing LAN name other than the LAN itself;
`"none"` stands alone; no duplicates.

### Rules

```toml
[[firewall.rules]]
name = "dmz-web"
from = "wan"
to = "192.0.2.234-192.0.2.238"  # address, a-b range, or CIDR, inside one LAN
proto = "tcp"                         # tcp | udp | icmp | any
ports = ["80", "443"]                 # tcp/udp only; strings, so "1000-1010" is a range

[[firewall.rules]]
name = "admin-ssh"
from = "main"
to = "192.168.3.200"
proto = "tcp"
ports = ["22"]
```

`ports` is a list of strings because the config travels TOML → JSON → protobuf and a repeated
field holds one type; a single port and a range then share one field and one parser, which is
permanent in the on-disk format.

A rule accepts new flows in the forward chain from zone `from` to the destination set, before
the policy rules. `from = "wan"` means every WAN interface. Rules never translate; they open.

nft: three concatenated sets with interval flags, `rules_tcp` and `rules_udp` of type `ifname .
ipv4_addr . inet_service`, `rules_other` of type `ifname . ipv4_addr . inet_proto`, where the
protocol element is ICMP for `icmp` and every protocol number for `any` would be unbounded, so
`any` lands in a fourth set `rules_any` of type `ifname . ipv4_addr`. Four rules consult them.
A WAN-sourced rule contributes one element per WAN interface. The builder proves in the nft
sandbox suite that the pinned nftables and the kernel accept interval concatenations with an
`ifname` field; if they refuse, one nft rule per configured rule is the documented fallback, and
the design's "rule counts never grow" line is amended to say so.

Validation: `name` is a label like a port forward's and unique among rules; `from` is `"wan"` or
a LAN name; `to` parses as an address, an `a-b` range with `a <= b`, or a CIDR, and lies inside
one LAN's subnet that is not `from`; `proto` is one of the four; `ports` is required for `tcp`
and `udp` (each entry a port in 1..=65535 or a range `a-b` with `a <= b`) and forbidden otherwise.

### WAN echo rate limit

ICMP echo on the WAN, when `wan_ping` is on, is limited (`limit rate 50/second burst 100
packets`). Nothing else about the input chain changes for WAN sources.

### Schema

New protobuf fields, named here so the TOML, the validation messages and the SPEC example agree:
`Config.public_ipv4` (`repeated PublicIpv4 { string prefix }`), `Lan.reaches` (`repeated
string`), `PortForward.address` (`string`, empty for the WAN address), `Firewall.rules`
(`repeated Rule { string name; string from; string to; string proto; repeated string ports }`).
`Lan.ports` entries and `Wan.vlan` keep their types. No existing field changes meaning, so
`config_version` stays 1.

### DNS

The forwarder's `lan_subnets` does two jobs today: the rebinding guard and the reverse zones it
answers for. They part ways. The guard (`guard_subnets`) is the private LANs' subnets: a DMZ
host's public address is a valid answer from upstream. The reverse zones (`lan_subnets`) are the
private LANs plus any public LAN that runs DHCP, since then the router is the one naming its
hosts; a public LAN without DHCP leaves its reverse zone to the ISP, where it lives. Everything
else is as after M1.

### Console

One line per declared block when its route is applied, in the routing applier's existing form
(`add route blackhole 192.0.2.248/29 proto 200 metric 1000`), and the existing
`ready generation=N` once converged. Validation failures use the existing
`config:` lines. The builder keeps the console contract tests in `crates/openfeo` current.

### Harness

**Lab.** Scenarios that need two LANs opt in to a second LAN namespace `lan1` with tap `lan1`,
the router's `p3`; every existing scenario keeps its three ports and its assertions. A VLAN client
is its own namespace: the sub-interface is created on the LAN tap and moved there, so the
existing client helpers work unchanged. The ISP side can move its address onto a tagged
sub-interface (`wan0.101`) for the tagged-WAN scenario, since Kea picks its subnet by the
receiving interface's address. Routed blocks are added on the ISP side as routes via the router's
WAN address. The ISP-side HTTP target already logs the client address, which is how "left
without translation" is asserted. Public blocks in fixtures come from 192.0.2.0/24: the lab
already uses 198.51.100.0/24 for ISP B, `www.isp.example` and Kea's classless route.

**CI and probes.** The CI runner loads `nft_limit` and `8021q` alongside the nft modules it
already loads, and the harness's nft probe tries a `limit` rule and an interval concatenation
set with an `ifname` field, so a host that cannot do either skips the new sandbox scenarios with
a reason and CI's `OPENFEO_NO_SKIP` fails them. The config fuzz target calls validation, since
the new parsers live there.

**New fixtures.** `harness/fixtures/vm-vlans.toml` (main untagged and guest tagged 223 on `p2`,
trusted on `p3`, policy as in the Intent, one pinhole rule) and `vm-public.toml` (static WAN,
DMZ public LAN on `p3` from `192.0.2.232/29`, a second block `192.0.2.248/29`, a rule
opening tcp 80 to the DMZ hosts, a forward on `192.0.2.249:443` to the `lan0` host).

**QEMU scenarios** (`harness/tests/m2.rs`):

- `tagged_wan_leases_and_nats`: `isp0` serves on `wan0.101`; a WAN with `vlan = 101` leases and
  the LAN fetches through it. The VLAN fixture's WAN is this one, so every VLAN scenario boots
  through it.
- `tagged_guest_leases_from_its_own_lan_and_reaches_only_the_internet`: a client on `lan0.223`
  leases from `guest`, reaches the ISP HTTP target through NAT, and cannot reach the main host,
  nor the main host's forwarded port by the WAN address (hairpin follows the policy).
- `trusted_reaches_main_and_nothing_initiates_into_trusted_except_a_rule`: `lan1` (trusted)
  fetches the `lan0` HTTP target; `lan0` reaches `lan1` only on the rule's port; a guest client
  does not reach it at all.
- `a_vlan_nobody_wants_is_dropped_by_the_untagged_bridge`: a client tagged with a VLAN no LAN
  carries cannot reach the main LAN's router address, while the untagged client still can.
- `dmz_host_is_reached_from_the_isp_only_through_a_rule`: from `isp0`, tcp 80 on the DMZ host
  answers, another port and ping do not.
- `dmz_host_leaves_without_translation`: the DMZ host fetches the ISP HTTP target and the
  target's log shows the DMZ host's own address.
- `a_public_address_forwards_to_a_lan_host`: from `isp0`, `192.0.2.249:443` returns the
  `lan0` target's body; the `lan0` host reaches it by the public address too (hairpin).
- `an_unused_public_address_is_blackholed`: the console shows the blackhole line and a probe
  from `isp0` to an unused address of the second block gets no reply and no ICMP error.

**Sandbox scenarios.** `netlink`: a VLAN sub-interface is created, enslaved, deleted when stray,
and a blackhole route is added and removed. `nft`: the new sets and maps apply on the pinned
nftables (the interval-concatenation proof above).

**Unit and snapshot tests.** Validation cases for every rule listed above (`openfeo-config`);
`insta` snapshots for the links, routing and nft reconcilers on the two new fixtures.

**Fuzz.** The config parser's fuzz target covers the new fields; the builder confirms it drives
validation, since the `pN.V`, `a-b` and `ports` parsers live there.

## SPEC amendments (the plan's first task)

- §7.1: a LAN member is a port untagged or a tagged VLAN on a port (`pN.V`); the bridge-per-LAN
  model with 802.1Q sub-interfaces; a port is a WAN or carries LANs, not both (for now).
- §7.2: the VLAN-tagged WAN is implemented as `pN.V`.
- §7.4: blackhole routes for declared public blocks; a note that M6 pins a block's egress to
  the WANs of the account that routes it.
- §7.5: public LANs (no translation, services as above), `reaches` with `"none"`, translated
  flows gated by the policy, rules, the echo rate limit; rule counts stay bounded by the sets.
- §7.7: the rebinding guard covers the private LAN subnets; the reverse zones are the private
  LANs plus public LANs that run DHCP.
- §8.2: the config example gains `[[public_ipv4]]`, `reaches`, tagged members, `address` on a
  port forward and `[[firewall.rules]]`.
- §11: the lab's `p3` is a second LAN namespace, created only by scenarios that need two LANs.
- §12: M2's scope row lists part 1 (including the 802.1Q WAN, which leaves M3's row); the
  post-MVP line keeps "LAN VLANs in the panel". §1.2 and §2 say that LAN VLANs are configurable
  in the file from M2 part 1.

## ADR

ADR-0017, "LAN VLANs are 802.1Q sub-interfaces bridged per LAN": Context (trunk ports carry
several LANs; one bridge per LAN is the M1 model and every zone, DHCP and DNS binding hangs off
a bridge name); Decision (sub-interfaces as members, not a VLAN-aware bridge with per-VLAN
interfaces); Consequences (nothing downstream of a bridge changes; a frame for an unknown VLAN
is dropped by the port's filtering bridge; switch-chip offload on the RB5009 (M7) prefers one
VLAN-aware bridge, so M7 revisits this with the DSA driver in hand).

## What is left to the builder

- Internal names and signatures: the `DesiredPort` kind, the route kind, the set and map names
  (the ones above are suggestions), the `World`-side representation of public blocks.
- How the nft generator derives "private LAN subnets" and the `nat_nets` set from the config
  and the declared blocks.
- The exact high metric for blackhole routes and whether `reconcile::routing` or a new module
  owns them.
- Whether `harness/tests/m2.rs` is one file or several, and how the `Lab` helpers are shaped.
- The console wording for the blackhole line within the existing style.
- The interval-concatenation proof and its fallback, as described under Rules.
