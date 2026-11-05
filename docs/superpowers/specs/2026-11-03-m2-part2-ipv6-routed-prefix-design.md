# M2 part 2: IPv6 with a statically routed prefix

Design for the second of three M2 parts (SPEC §12). Part 1 laid down LAN VLANs, public IPv4
blocks, per-LAN policy and rules; part 2 brings IPv6 (SPEC §7.3) for the line where the ISP
routes a fixed prefix to the router; part 3 adds DHCPv6, ULA and the renumbering cases.

## Intent

The dogfooding line, and every business or enthusiast line with a static allocation, looks like
this: the ISP routes a /48 to the router and says nothing more about it on the wire. The WAN link
itself carries only link-local addresses (a PPP session) or a /64 of its own (an Ethernet
handoff). The owner cuts the /48 by hand: one /64 per LAN, chosen to be memorable, the router
taking `::1` in each. Client LANs advertise their prefix and hosts configure themselves; a DMZ
does not advertise, its servers are placed by hand so they are stable targets for inbound rules.
The router's own global identity is an address from the /48 on its loopback, not a WAN address,
because the WAN may have none. Inbound is stateful default deny with holes per host and port,
exactly as for IPv4, and nothing is ever translated.

Clients prefer IPv6 whenever a name has an AAAA record. That sets the one thing that must never
happen: an advertised IPv6 path that is dead. A LAN that keeps a default router after the WAN has
lost IPv6 stalls on every dual-stack site. Loss of the WAN's IPv6 must reach the LAN within one
advertisement interval, so hosts fall back to IPv4 cleanly.

OpenFeO after part 1 forwards no IPv6 at all: no addresses, no advertisements, no rules. Part 2
makes the setup above work end to end, in a shape that a /56 or a /60 fits as well as a /48.

## Goals

- A WAN IPv6 client in the odhcp6c mould (SPEC §7.3): it solicits and processes the ISP's router
  advertisements on the WAN interface, with the kernel's own autoconfiguration off there. It
  learns the default router and its lifetime, a prefix for the link when the ISP advertises one
  (an address with an RFC 7217 stable identifier, an on-link route), the link MTU, RDNSS and
  DNSSL resolvers, and RFC 4191 route information, and publishes them as facts.
- `[wans.ipv6]` names the prefix the ISP routes to this router and, when the ISP's side is not
  discoverable, a typed default gateway.
- Each LAN names its own /64 inside that prefix, with the router's address in it, exactly as
  `ipv4` names the LAN's subnet today.
- An RA server per LAN (SPEC §7.3): prefix, MTU, the router as resolver, the system domain as
  search list, router lifetime 1800 while the WAN has a usable IPv6 default and 0 the moment it
  does not. Switchable off per LAN for hosts placed by hand.
- The router's own address: `::1` of the prefix's first /64, on loopback, preferred source of
  the IPv6 default route. The whole prefix gets a blackhole route, as public IPv4 blocks do.
- The firewall's IPv6 half: the same zones, `reaches` and rules; ICMPv6 per RFC 4890; no NAT.
- DNS over IPv6: AAAA for the router's names and for typed records, listeners on the LANs' IPv6
  addresses, IPv6 upstreams typed or learned from the WAN.
- Learned WAN facts take effect only once the kernel has the route they depend on. This closes
  the class of race behind issue #12 for both families instead of each service working around it.
- All of it proven in the harness: the client and server cores against radvd and the kernel's
  own SLAAC in the sandbox, the whole path in QEMU with the ISP side routing the prefix.

## Non-goals

- DHCPv6 in any form, ULA, stateless DHCPv6, prefix deprecation, source-based routing and the
  "prefix follows a WAN" semantics of multi-WAN IPv6 (part 3, M6). Part 2 allows `[wans.ipv6]`
  on one WAN; validation refuses a second until M6 says what two mean.
- PPP's IPV6CP, the interface identifier it negotiates and the link-local it yields (M3). Part
  2's WAN is Ethernet; the design keeps the PPP shape in view (a WAN with only a link-local, the
  default router discovered by advertisement or typed as the peer).
- Learning LAN hosts' IPv6 addresses for the local zone (neighbour snooping, DHCPv6
  registration). AAAA answers come from the router's own addresses and typed records only. The
  owner adds records by hand when a name must resolve to a client.
- Source-restricted rules (`from` a prefix rather than a zone). Wanted soon, for both families;
  it is a follow-up issue, not this part.
- SNTP over IPv6. The time client keeps using IPv4 servers.
- NPTv6, which SPEC §2 rules out, and any other IPv6 translation.
- Temporary (privacy) addresses on the router itself.
- DAD-failure recovery for the router's own addresses. A collision on a /64 the router controls
  is improbable; the monitor logs a failed address and the next advertisement retries.
- The panel (M4).

## Anti-goals

- An advertised IPv6 path that is dead. The router lifetime in every LAN advertisement is 0
  whenever the WAN has no usable IPv6 default route, and the change goes out at once, not at the
  next periodic advertisement.
- IPv6 that is translated or that is forwarded before the ruleset says so. Forwarding for both
  families is switched on only together with the ruleset, as today.
- A LAN host or a DMZ host reachable from the WAN without a rule.
- The kernel autoconfiguring the WAN behind the client's back, or the router accepting
  advertisements from a LAN.
- Advertisements leaving on a WAN port. The RA server runs on LAN bridges only.
- A /64 the WAN does not route being advertised. A LAN's `ipv6` must lie inside the declared
  prefix; there is no other source of LAN prefixes in this part.
- Breaking any M0, M1 or M2 part 1 scenario, or changing behaviour for a configuration that
  mentions no IPv6.

## Constraints

- Everything in `CLAUDE.md`: pure crates stay pure (the new `openfeo-proto-ndp` has no tokio,
  libc, nix or socket2 in its tree), no shelling out, `clippy -D warnings`, every parser fuzzed,
  SPDX headers, DCO commits, a `docs/progress.md` entry in the PR.
- The NDP codec is in-tree with smoltcp as the differential test oracle (ADR-0018 below), the
  pattern of ADR-0015 for DNS and of the DHCPv4 part for dhcproto.
- The ruleset stays one `table inet openfeo` applied as one batch; IPv6 is additional sets and
  rules in it, never a second table.
- Routes and addresses carry `RTPROT_OPENFEO`; the router never deletes kernel-originated
  link-local addresses or connected routes (SPEC §6.2).
- The spec is the source of truth: the amendments below are the plan's first task, together
  with the ADRs.

## Design

### Config

```toml
[[wans]]
name = "wan0"
port = "p0"
priority = 10
[wans.static]                        # the IPv4 side is unchanged
address = "203.0.113.10/24"
gateway = "203.0.113.1"
[wans.ipv6]
prefix = "2001:db8:1::/48"             # the block the ISP routes to this router
# gateway = "fe80::1"                # a typed default; absent = learned from the ISP's advertisements
# mode = "auto"                      # auto | disabled (SPEC §8.2); absent = auto

[[lans]]
name = "lan0"
ports = ["p2"]
ipv4 = "192.168.1.1/24"
ipv6 = "2001:db8:1:222::1/64"          # the router's address and the LAN's /64, inside the prefix

[[lans]]
name = "dmz"
ports = ["p3"]
ipv4 = "192.0.2.233/29"
ipv6 = "2001:db8:1:232::1/64"
ra = false                           # hosts here are placed by hand; absent = true

[dns]
upstreams = ["203.0.113.1", "2001:db8:ffff::53"]
[[dns.records]]                      # typed names, v4 or v6
name = "www"                         # a label under the system domain, or a full name
address = "2001:db8:1:232::10"

[[firewall.rules]]
name = "dmz-web6"
from = "wan"
to = "2001:db8:1:232::10"              # an address, an a-b range or a CIDR inside one LAN's /64
proto = "tcp"
ports = ["80", "443"]
```

`[wans.ipv6]` is the table SPEC §8.2 already names; `mode` keeps its meaning (`disabled` runs no
client and installs nothing, and is refused next to a `prefix` or any LAN `ipv6`, since those
would then describe nothing), `pd_hint` arrives with part 3. `prefix` is optional: a WAN with
`[wans.ipv6]` and no prefix gives the router IPv6 for itself (a link address if the ISP
advertises one, a default route, learned resolvers) and no LAN may name a /64. A LAN's `ipv6`
is the router's address with the LAN's prefix length, as `ipv4` is; part 2 accepts /64 only,
since SLAAC needs it (RFC 4862 §5.5.3) and nothing in this part makes a longer prefix useful.

**Validation.** `[wans.ipv6]` on at most one WAN (message: multi-WAN IPv6 comes with M6). `prefix`
parses as an IPv6 network in global unicast space (`2000::/3`), length at most 63 (its first /64
belongs to the router, below); `gateway` parses as an IPv6 address, link-local or global. A
LAN's `ipv6` parses as address/64 with the address a host in the /64, lies inside the one
declared prefix, is not the prefix's first /64, and overlaps no other LAN's; `ipv6` on a LAN
needs a WAN with a prefix (message naming `[wans.ipv6].prefix`); `ra` without `ipv6` is refused.
A record's `name` is a label (then under `system.domain`) or a full name; the pair (name,
address family) is unique among records, so a dual-stack name has one A and one AAAA record;
a record never names what the router already answers for (its own name, a reservation's). Its
`address` is any unicast IPv4 or IPv6 address. `dns.upstreams` entries are IPv4 or IPv6
addresses. A rule's `to` in IPv6 form follows the IPv4 checks per family: inside one LAN's /64
that is not `from`; the overlap rule between two rules applies within a family.
`[wans.static].dns` stays IPv4; being typed, its resolvers are never gated (below).

### Identity

`identity/ipv6-secret`: 16 random bytes, lowercase hex, generated once and persisted like the
DUID (SPEC §5.2's list gains it). It is the kernel's `stable_secret` for the WAN ports, so their
link-local addresses are stable-privacy addresses (SPEC §7.3) that survive a reboot, and it is
the secret of the RFC 7217 function the client uses for its SLAAC address on the WAN. The
DUID-LL that the DHCPv4 client already keeps at `identity/duid` is the DUID SPEC §7.3 asks for;
part 3's DHCPv6 reuses it unchanged.

### WAN IPv6 client

A sans-IO core in `openfeo-proto-ndp` (`client.rs`), one per WAN with `[wans.ipv6]` in mode
`auto`, driven by a raw ICMPv6 socket in `openfeo-net`. The kernel's own autoconfiguration is
off on the WAN interface (`accept_ra = 0`, `autoconf = 0`), so everything the WAN learns about
IPv6 passes through this core and lands in the World as a fact.

**Soliciting.** On carrier the core sends a Router Solicitation to `ff02::2` with a source
link-layer address option, three times four seconds apart (RFC 4861 §6.3.7), then keeps
soliciting with the exponential backoff of RFC 7559, capped at one hour, until an advertisement
arrives. Carrier loss clears every fact at once and the next carrier starts over.

**Processing.** An advertisement is accepted only when it arrived with hop limit 255, ICMP code
0, a link-local source and at least 16 bytes (RFC 4861 §6.1.2); the driver passes the source and
hop limit along with the bytes. From it the core keeps:

- the default router: the source address with the router lifetime; a lifetime of 0 removes it.
  Several routers rank by RFC 4191 preference, then recency; the fact carries one;
- prefix information: with the A flag, an address in the prefix whose interface identifier is
  RFC 7217's `F(prefix, ifname, secret)` (SHA-256, truncated to 64 bits, the reserved
  identifiers of RFC 5453 skipped by bumping the counter), with the option's lifetimes under the
  two-hour rule of RFC 4862 §5.5.3; with the L flag, an on-link route for the prefix. Only
  prefixes of length 64 yield an address;
- the MTU option: the WAN's IPv6 MTU. It is applied to the WAN interface's IPv6 MTU (the
  per-interface `mtu` under `net/ipv6/conf`, through the sysctl reconciler), never above the
  link MTU, which the DHCPv4 lease's option keeps setting through the links reconciler as
  today. IPv4 and the link follow DHCPv4; IPv6 follows the advertisement; a PPP link at 1492
  (M3) caps both. It is not what the LANs advertise: each LAN advertises its own bridge's MTU;
- RDNSS and DNSSL (RFC 8106) with their lifetimes. A link-local resolver address is dropped
  with a console line: the forwarder has no scope to bind it to in this part;
- route information options (RFC 4191): routes via the router with their preference.

Every item expires on its own lifetime, refreshed by each new advertisement; the core keeps the
expiries, as the DHCPv4 client keeps its timers, and the World never sees them. The core
publishes a `WanIpv6Fact` only when its content changes: router (`Option`, the link-local
address), addresses, on-link prefixes, routes, resolvers, search names, MTU. A refreshing
advertisement with the same content is no new World generation. The fact stays, with `router`
cleared, when the router's lifetime runs out or an advertisement withdraws it: a typed gateway
still wants the link address and the resolvers. The fact leaves the World when the WAN's
carrier drops.

**Typed gateway.** With `gateway` set the client still runs (for the link address and the
resolvers), but the default route is the typed one and the advertised router is ignored for
routing. An ISP that never advertises is served by this: the client keeps soliciting at the
RFC 7559 cap, one packet an hour, and the console says so once. A global gateway outside every
on-link prefix first gets a host route on the port, the rule IPv4 already follows for an
off-link gateway.

### Routing and the router's address

The routing reconciler gains, per WAN with `[wans.ipv6]`:

- the default route in `main`: via the learned router (link-local next hop on the WAN
  interface) or the typed gateway, metric the WAN's priority, protocol 200, with the router's
  own address as preferred source;
- the on-link routes and the route-information routes the client published, and the WAN's
  SLAAC address when the ISP advertised a prefix with the A flag;
- the router's own address `<prefix>::1/128` on `lo`, when a prefix is declared. The prefix's
  first /64 is reserved for it, which is why no LAN may use that /64. With no prefix the default
  route has no preferred source and the kernel's selection (RFC 6724) picks the WAN's address;
- a blackhole for the whole prefix, protocol 200, metric `BLOCK_METRIC`, so an address in a /64
  no LAN uses is dropped here and never sent back out the default route (the same route part 1
  installs per public IPv4 block);

and per LAN with `ipv6`, the router's address on the bridge, from which the kernel's connected
route for the /64 follows. `DesiredRoute` gains the preferred source; the netlink crate sets
`RTA_PREFSRC` and, for addresses, nothing new beyond the family it already handles.

### The route gate

Issue #12 came from a learned fact (the DHCPv4 lease's resolvers) being acted on before the
route it needs existed; the DNS forwarder now retries a send that failed, and SNTP moves on from
an unreachable server. Part 2 adds a second learned source (the WAN IPv6 client) and a consumer
with a sharper contract (the router lifetime). Instead of a third workaround, the World learns
what routes the kernel has.

The netlink monitor already caches routes. It publishes, as a fact, the default routes present
in `main`: family and output interface. Two consumers use it:

- `reconcile::dns`: the resolvers learned on a WAN (DHCPv4 today, RDNSS now) join the upstream
  list only while the kernel has a default route of their family through that WAN. Typed
  upstreams are never gated: the owner may have a route the router did not install.
- `reconcile::ra` (below): a LAN's advertised router lifetime is 1800 only while the WAN with the
  prefix has carrier and a default IPv6 route in the kernel, else 0.

Observed state comes from the monitor's cache, never a dump (SPEC §6.2), so the gate opens on
the kernel's own event for the route the applier added, which is the moment a send can succeed.
ADR-0019 records the rule for every future learned fact.

### LAN IPv6 and the RA server

A sans-IO core in `openfeo-proto-ndp` (`server.rs`), one per LAN with `ipv6` and `ra` on,
driven by a raw ICMPv6 socket on the LAN bridge (joined to `ff02::2`), fed by
`reconcile::ra::desired(&world)`: a `DesiredRa` per LAN with the prefix, the router's
addresses, the search domain, the MTU and the router lifetime the gate decided. The
advertisement carries (RFC 4861 §4.2, §4.6; RFC 8106):

- the LAN prefix with A = 1 and L = 1, valid lifetime 2592000 and preferred lifetime 604800
  (the RFC 4861 defaults; the prefix is static, so there is no delegation to derive them from);
- the MTU option with the bridge's MTU;
- the source link-layer address of the bridge;
- RDNSS with the router's address in that LAN and DNSSL with the system domain, lifetimes
  3 × MaxRtrAdvInterval (RFC 8106 §5.1);
- M = 0 and O = 0. SPEC §7.3 says O = 1 for the stateless DHCPv6 responder; until part 3 ships
  the responder, O = 1 would send every host an Information-Request nobody answers. The flag
  flips with part 3;
- router lifetime 1800 or 0, as the gate says; CurHopLimit 64; reachable time and retransmit
  timer 0 (unspecified).

Timing follows RFC 4861 §6.2: unsolicited advertisements every 200 to 600 seconds at random
(MinRtrAdvInterval and MaxRtrAdvInterval defaults); the first three after start at most 16
seconds apart; a solicitation answered within 0 to 500 ms, to the all-nodes group, at most one
every 3 seconds (MIN_DELAY_BETWEEN_RAS); any change of contents (the lifetime most of all)
sends an unsolicited advertisement at once, subject to the same 3-second spacing. When a LAN's
`ra` turns off or the LAN loses its `ipv6` while the process runs, the server sends its final
advertisements with router lifetime 0 (RFC 4861 §6.2.5) before it stops. A crash or restart of
the router process sends none: the LAN keeps the stale default for a few hundred milliseconds
until the restarted server's first advertisement, which is better than a lifetime 0 on every
supervisor restart.

The server ignores advertisements from other routers on the LAN (a second router on a LAN is a
misconfiguration this part does not police) and accepts solicitations only from link-local or
unspecified sources with hop limit 255.

### Sysctls

Per WAN port of a WAN with `[wans.ipv6]` in mode `auto`: `accept_ra = 0`, `autoconf = 0`,
`accept_redirects = 0`, the IPv6 `mtu` from the advertisement when there is one, and
stable-privacy addressing as below. Per LAN bridge: `accept_ra = 0`, `accept_redirects = 0`.
`net/ipv6/conf/all/forwarding` keeps following the ruleset. A WAN without `[wans.ipv6]` is
untouched: its link-local stays the kernel's EUI-64 one and nothing about its boot changes,
which keeps the anti-goal for configurations that mention no IPv6. SPEC §7.3's "stable-privacy
on Ethernet" is read as applying to WANs that run the client.

**Stable-privacy without a bounce.** The kernel generates a link-local address when a link comes
up, in the mode set at that moment, and in stable-privacy mode only if the interface's
write-only `stable_secret` is already set. The apply loop brings ports up in the links pass and
writes sysctls last, so the plain order would leave the WAN with an EUI-64 link-local or none,
and fixing it afterwards would bounce the link at every boot, which the DHCPv4 client and the
M1 scenarios would see. So the links applier itself writes `addr_gen_mode = 2` and the secret
for a WAN port it is about to bring up for a WAN with `[wans.ipv6]`, between creating a `pN.V`
sub-interface (or finding the port) and setting it up; the identity secret is loaded before the
World exists, next to the port map. The sysctl applier owns the rest. When a running router
gains `[wans.ipv6]` on a WAN by a configuration change, the links applier bounces that one
port once, with a console line, which is the one case where a bounce is the honest price. The
netlink sandbox proves the link-local is a stable-privacy address and the same across two
bounces.

### Firewall

The ruleset stays one `inet` table. The forward policy is already family-neutral (interfaces and
sets of interface names), so LAN→WAN and the allowed LAN pairs forward IPv6 the moment addresses
exist. What is added:

- **Zones.** The sets that hold LAN subnets gain IPv6 twins where a set has an address type
  (`lan6_nets` beside the private-LAN subnets set that masquerade uses, with no NAT consumer: it
  exists for the rebinding guard's and future rules' sake only if the builder finds a use; the
  builder may omit it). The masquerade and DNAT rules keep their `meta nfproto ipv4` guard;
  there is no IPv6 NAT and no IPv6 port forward.
- **Rules.** Twins of the rule sets with `ipv6_addr` elements (`rules6_tcp`, `rules6_udp`,
  `rules6_other`, `rules6_any`), consulted by four more rules in the forward chain; a rule's
  family is its `to`'s. `proto = "icmp"` means ICMP for an IPv4 target and ICMPv6 for an IPv6
  one.
- **ICMPv6 (RFC 4890).** Input from a WAN accepts: destination unreachable, packet too big, time
  exceeded and parameter problem (types 1 to 4); neighbour solicitation and advertisement (135,
  136) and router advertisement (134); MLD queries and reports (130 to 132, 143); echo request
  only with `wan_ping`, under the same limit as IPv4 echo. Everything else from a WAN, redirects
  included, stays dropped. Input from a LAN keeps accepting all ICMP and ICMPv6, as today.
  Forwarded ICMPv6 errors travel as `related` with the flow they belong to, which the existing
  established/related rule already accepts; NDP and MLD are link-scoped, untracked by conntrack
  and never forwarded. Echo through the router follows zone policy, like any other traffic.
- **Reverse path.** The loose WAN check (`fib saddr oif missing`) has no interface to resolve a
  link-local source against and would drop the ISP's advertisements and neighbour traffic.
  Link-local sources (`fe80::/10`) skip the WAN check; the strict LAN check keeps its `iif`. The
  builder proves in the nft sandbox that an advertisement from a link-local source passes and a
  spoofed global source still does not.
- **Services.** A private LAN keeps every service it has today on both families; its service
  rules are family-neutral and stay so, which is what lets a host placed by hand on a private
  LAN with `ra = false` still use the router's DNS over IPv6. A public LAN's services become
  per family: DHCP, DNS and NTP over IPv4 when it runs the DHCPv4 server (part 1's rule), DNS
  over IPv6 when it advertises (the router named itself as resolver), ICMP and ICMPv6 always,
  HTTPS never. That is one more interface set (`lan_pub_ra_if`) and a `meta nfproto` guard on
  the two public-LAN service rules; the private-LAN rules and their snapshots do not change.
  NTP and HTTPS over IPv6 come with their services (SNTP stays IPv4 in this part; the panel is
  M4).

### DNS

The forwarder's `Config` widens: `upstreams: Vec<IpAddr>`, `router_addrs: Vec<IpAddr>`
(every LAN's IPv6 address and the loopback address join the router's A and AAAA records), local
records from `[[dns.records]]` as A or AAAA by family. Listeners: the driver binds each LAN's
IPv6 address next to its IPv4 one (the `SO_BINDTODEVICE` listener of `bound.rs` gains the
family), and the upstream sockets gain an IPv6 twin bound to `[::]:0`, whose source the
preferred-source route decides. Learned IPv6 resolvers (RDNSS) follow typed upstreams and the
IPv4 lease's resolvers, through the route gate. The rebinding guard's IPv6 half is what SPEC
§7.7 lists (link-local, ULA, loopback, the router's own addresses): a LAN /64 cut from a routed
prefix is global space and a valid answer. Reverse zones: the router answers PTR for its own
IPv6 addresses and for typed records whose address lies in a LAN's /64; everything else in
`ip6.arpa` goes upstream. The console's `dns upstreams` line names IPv6 upstreams and their
origin (`learned from wan0 rdnss`) in its existing form.

### Console

One line each, in the existing styles, for: the WAN's link-local address once the kernel has it
(`wan0 ipv6 link-local fe80::…`), the learned router and lifetime, a learned link address, the
typed gateway in use, the loopback address, the blackhole, a LAN's advertisements starting and
their lifetime changing (`ra lan0 lifetime 0 (wan0 has no ipv6 route)`), resolvers learned and
dropped. The harness asserts through these lines; the builder keeps the console contract tests in
`crates/openfeo` current.

### Schema

New fields, named here so TOML, validation messages and the SPEC example agree: `Wan.ipv6`
(`Ipv6Wan { string mode; string prefix; string gateway }`, the table SPEC §8.2 names; `pd_hint`
is added by part 3), `Lan.ipv6` (`string`), `Lan.ra` (`optional bool`, absent = true, the
absence-as-default pattern of `reaches`), `Dns.records` (`repeated Record { string name; string
address }`). `Rule.to` and `Dns.upstreams` keep their types and accept IPv6 text. No existing
field changes meaning, so `config_version` stays 1.

### Facts

`World` gains `ipv6: BTreeMap<String, WanIpv6Fact>` (keyed by WAN name, content only, no
expiries) and `routes` (the default routes the kernel has, family and interface). `LinkFact` is
unchanged; the WAN's link-local address reaches the client core from the monitor's address
cache, which the driver needs only to log it.

### Crates and drivers

- `openfeo-proto-ndp` (SPEC §13 already lists it): `wire.rs` (RS and RA encode and decode with
  options 1, 3, 5, 24, 25 and 31; unknown options skipped by length; a fuzz target
  `ndp_wire`, and `ndp_differential` against smoltcp 0.14's `wire::ndisc` for the header and
  options 1 to 5), `client.rs`, `server.rs`, `iid.rs` (RFC 7217) over an in-tree SHA-256
  (`sha256.rs`, checked against the RFC 6234 vectors; it is no parser, so it needs no fuzz
  target). Nothing in the shipped binary hashes today, and the obvious crate, `sha2`, reaches
  `libc` through `cpufeatures` on the aarch64 target, which `scripts/check-deps.sh` cannot see
  from an x86 host; a hundred lines of SHA-256 keep the protocol crates pure on both targets.
  Fuzz targets `ndp_client` and `ndp_server` feed the cores arbitrary advertisements and
  solicitations and then every timeout.
- `openfeo-net/src/ndp.rs`: the driver: one raw ICMPv6 socket per interface
  (`SO_BINDTODEVICE`, hop limit 255 for unicast and multicast, `IPV6_RECVPKTINFO` and
  `IPV6_RECVHOPLIMIT`, an `ICMP6_FILTER` admitting only the types the core wants, membership of
  the all-nodes or all-routers group on that interface as the role needs). The kernel computes
  and checks ICMPv6 checksums on raw ICMPv6 sockets, so the codec carries none. nix 0.30 decodes
  the packet-info and hop-limit control messages safely; what it lacks is `ICMP6_FILTER` and an
  interface-scoped join, which are the new `unsafe` in `sys.rs` (ADR-0013 is amended to say so;
  the join may instead go through socket2's safe `join_multicast_v6` if the builder adds socket2
  to `openfeo-net`, which the dependency rules allow).
- `crates/openfeo/src/ipv6.rs` (the WAN client task per WAN, publishing the fact) and
  `crates/openfeo/src/ra.rs` (the LAN servers, reconfigured from `reconcile::ra` on every World
  change), after the pattern of `dns.rs` and `dhcp4.rs`.
- `smoltcp` joins `docs/third-party.md` as a test dependency; `0BSD` joins the `cargo deny`
  allow list for it.

### Harness

**Lab.** `isp0` runs radvd on the ISP's side of the WAN tap: `AdvDefaultLifetime 1800`,
`MinRtrAdvInterval 3` and `MaxRtrAdvInterval 4` (radvd's floor, so a scenario sees several
advertisements), RDNSS pointing at dnsmasq's IPv6 address, DNSSL `isp.example`, and in the
scenarios that want it a prefix for the link (`2001:db8:ffff::/64`, the ISP router at
`2001:db8:ffff::1` and `fe80::1`). The ISP side routes the prefix (`2001:db8:1::/48`) via the
router's WAN link-local address, which the harness reads from the console line the router
prints, or via the router's link address in the prefix scenario (`Lab::isp_route_block6`).
dnsmasq serves AAAA for `isp.example` names and listens on IPv6; the HTTP target binds an IPv6
address too. The LAN namespace is the SLAAC reference client: the kernel there accepts
advertisements and configures itself, and `rdisc6` (package `ndisc6`) solicits and prints an
advertisement's options for the assertions on RDNSS and DNSSL. A DMZ host is placed by hand with
`Lab::host` grown an IPv6 form. Packages: `radvd` and `ndisc6` join the CI apt line, the cloud
setup script and `check-env`.

**Fixtures.** `harness/fixtures/vm-ipv6.toml`: the static IPv4 WAN of `vm-static.toml` plus
`[wans.ipv6]` with the prefix and no gateway, `lan0` with `2001:db8:1:222::1/64`, a DMZ on `p3`
with `2001:db8:1:232::1/64` and `ra = false`, a rule opening tcp 80 to the DMZ host, a typed AAAA
record for it, one typed IPv6 upstream. A second fixture, or the same one with a `gateway`
line switched in by the scenario, covers the typed default.

**QEMU scenarios** (`harness/tests/m2.rs` or a sibling file):

- `lan_client_configures_itself_from_the_lan_prefix_and_reaches_the_isp_over_ipv6`: the LAN
  host gets an address in `2001:db8:1:222::/64`, its default router is the bridge's link-local,
  and it fetches the ISP's IPv6 HTTP target; `rdisc6` shows the router as RDNSS and
  `home.arpa` as DNSSL.
- `the_router_learns_its_default_from_the_isp_and_sources_from_its_loopback_address`: the
  console shows the learned router; a query from the router to the ISP's resolver arrives from
  `2001:db8:1::1` (dnsmasq's log shows the client address).
- `a_typed_gateway_replaces_the_learned_default`: with `gateway` set the console names it, the
  LAN host still reaches the ISP, and radvd's router lifetime is not what decides the route.
- `a_link_prefix_from_the_isp_gives_the_wan_a_stable_address`: with the link prefix advertised,
  the console shows the WAN's address in `2001:db8:ffff::/64`, the same one after a reboot of
  the VM (RFC 7217 with the persisted secret), and the ISP reaches the router on it.
- `dmz_host_ipv6_is_reached_from_the_isp_only_through_a_rule`: from `isp0`, tcp 80 on the DMZ
  host answers, another port and ping do not; the host's AAAA resolves through the router; the
  DMZ receives no advertisements (`rdisc6` times out).
- `wan_ipv6_loss_zeroes_the_router_lifetime_within_one_interval`: radvd stops (it sends final
  advertisements with lifetime 0) or the WAN tap loses carrier; within the LAN's advertisement
  interval the LAN host has no IPv6 default route, its IPv4 path still works, and the console
  shows the lifetime line; when radvd returns the host's default comes back.
- `an_unused_ipv6_subnet_is_blackholed`: a probe from `isp0` to an address in a /64 no LAN uses
  gets no reply and no ICMPv6 error, and the console shows the blackhole.
- `isp_names_resolve_to_aaaa_through_a_learned_ipv6_upstream`: with `upstreams` empty, `dig
  AAAA www.isp.example` over IPv6 at the router's LAN address answers, and the console shows the
  RDNSS-learned upstream joining only after the IPv6 default route exists.

**Sandbox scenarios.** A new `ndp` suite after the shape of `dns` and `sntp`, over a veth pair
with no QEMU: the client driver learns router, link prefix, MTU, RDNSS and DNSSL from radvd and
drops them when radvd stops or its lifetimes lapse; the server driver's advertisements configure
the peer namespace's kernel and `rdisc6` reads the options; a solicitation is answered within
the delay; a lifetime change goes out at once. `netlink`: an IPv6 address on a bridge, a /128 on
`lo`, a default route with a preferred source, an IPv6 blackhole, each added and removed, and
the stable-privacy link-local appearing once the secret is set. `nft`: the IPv6 rule sets apply
on the pinned nftables; the reverse-path proof above; the ICMPv6 type rules.

**Unit, snapshot and fuzz.** Validation cases for every rule under Config; `insta` snapshots for
routing, nft, dns, ra and sysctl on the new fixture; the config fuzz target covers the new
fields; the NDP targets above run under the nightly job.

## SPEC amendments (the plan's first task)

- §5.2: `identity/` gains the IPv6 stable secret.
- §7.3: the static routed prefix as the first-class path: `[wans.ipv6].prefix` typed, each LAN's
  /64 named by `ipv6` and validated inside it; the router's loopback address from the prefix's
  first /64; a typed `gateway`; O = 0 until the stateless responder exists; PIO lifetimes for a
  static prefix; the per-LAN assignment index stays for delegated prefixes (part 3). The ICMPv6
  type list of RFC 4890 as implemented. The route gate as the rule for learned facts.
- §7.4: the IPv6 default with its preferred source; the blackhole for the routed prefix.
- §7.5: the IPv6 half of zones and rules; `proto = "icmp"` per family; the WAN input list for
  ICMPv6; link-local sources and the loose reverse-path check; services over IPv6 per LAN.
- §7.7: AAAA for the router and typed records, `[[dns.records]]`, IPv6 listeners and upstreams,
  the IPv6 rebinding guard, reverse zones for IPv6.
- §8.2: the config example gains `prefix` and `gateway` under `[wans.ipv6]`, `ipv6` and `ra` on
  LANs, `[[dns.records]]`, an IPv6 upstream and an IPv6 rule.
- §9: the `unsafe` in `openfeo-net` covers the ICMPv6 socket options as well as AF_PACKET
  addresses (with ADR-0013).
- §11: radvd on the ISP side, `ndisc6` in the LAN namespace, the kernel as the SLAAC client.
- §13: `openfeo-proto-ndp` exists; the fuzz targets.

## ADRs

- **ADR-0018, "`openfeo-proto-ndp` parses NDP itself; smoltcp is the test oracle."** Context:
  SPEC §13 keeps protocol crates pure; no crate parses RDNSS, DNSSL or route information
  (smoltcp 0.14, pnet_packet 0.35 stop at the five options of RFC 4861; erbium's server is
  Apache-2.0 and bound to its runtime). Decision: in-tree codec; smoltcp (0BSD) as a dev and
  fuzz dependency for the header and options 1 to 5, differential fuzzing as for DNS and DHCPv4.
  Consequences: a parser we maintain and fuzz nightly; the oracle covers only part of the
  option space, so the RFC 8106 and RFC 4191 options rely on unit vectors from the RFCs and on
  radvd in the sandbox.
- **ADR-0019, "A learned fact is acted on once the kernel shows the route it needs."**
  Context: issue #12 and PR #20; SNTP's `Unreachable`; part 2's RA lifetime. Decision: the
  monitor publishes the kernel's default routes as a fact; reconcilers that consume learned
  resolvers or decide the advertised router lifetime require the route; typed configuration is
  never gated. Consequences: no service needs a send-failure workaround for a boot-time race
  (the DNS retry stays, since routes can vanish at any time); every future learned fact (IPCP,
  DHCPv6) follows the same rule.
- **ADR-0013 amended:** `sys.rs` also holds the ICMPv6 socket options named above.
- **One kernel-quirk ADR the builder writes** (CLAUDE.md asks for one per quirk the harness
  finds): the kernel reports an IPv6 blackhole route with `lo` as its device, where the IPv4
  one has none. The netlink crate normalises the dumped route so the applier's comparison
  holds; without that the applier would re-add the route every pass and never announce
  `ready`. The netlink sandbox scenario for the IPv6 blackhole is where this is proven.

## What is left to the builder

- Internal names and signatures: the fact structs, `DesiredRa`, the ICMPv6 socket helper, the
  set names above are suggestions.
- Where exactly in the links applier the stable-privacy writes go, and how the identity secret
  reaches it.
- How the monitor exposes default routes and addresses as facts without copying its whole cache
  into every World generation.
- Bridge multicast delivery: Linux bridges flood link-local-scope multicast, so advertisements
  reach every port and every VLAN member; if a scenario shows otherwise, `multicast_snooping`
  on the bridge is the first knob to look at.
- Whether the QEMU scenarios extend `m2.rs` or get their own file, and how the `Lab` helpers
  (`isp_route_block6`, an IPv6 `host`, radvd's config rendering) are shaped.
- The exact console wording within the existing style.
- The LAN /64 twin sets in nft, if any use turns up; otherwise none.
- Whether the sandbox or QEMU is the right place to prove the RFC 7217 address is stable across
  a reboot; one of them must.
