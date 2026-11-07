# M3: PPPoE, a full PPP client under the WAN

Design for milestone M3 (SPEC §12): the WAN type most residential lines in the UK and much of
Europe actually use. The router discovers an access concentrator over the port, brings up a PPP
session on it, authenticates, negotiates IPv4 and IPv6 over it, keeps it alive, and reconnects
when it falls. Everything that already works over a static or DHCP WAN (routing, the firewall,
DNS, the IPv6 of M2 part 2 and part 3) works over the PPP link, which is the dogfooding line's
shape: PPPoE with a statically routed /48 behind it.

The maintainer authorised this phase unattended ("begin the next phase also") after skipping
the brainstorm for M2 part 3 ("your calls"); the same mode is taken here, and every choice below
that SPEC §7.2 does not already make is the author's, listed under "Calls made for the
maintainer" at the end with what each costs if wrong.

## Intent

A PPPoE line hands the router nothing until it speaks PPP: no DHCP, no advertisements, no link
address. The ISP's access concentrator (AC) answers a discovery broadcast with a session id,
then PPP's link control protocol (LCP) settles the frame size and the authentication method,
PAP or CHAP proves the account, IPCP hands out an IPv4 address and resolvers, IPV6CP settles the
interface identifiers for the link-local addresses, and only then do the router advertisements
and DHCPv6 of M2 arrive over the link. The session has to be watched (LCP echoes), torn down
cleanly when the AC says so (PADT, Terminate) and brought back with backoff when it falls, and
the smaller frame (1492, or 1500 with RFC 4638) has to be hidden from the LAN by clamping TCP's
MSS.

SPEC §7.2 fixes the shape: a sans-IO core per protocol, the kernel's own PPP (`/dev/ppp` units
and channels over an `AF_PPPOX` socket) carrying the IP traffic through a `ppp-<wan>` netdev,
the control protocols as frames in userspace, facts published for the rest of the router.

## Goals

- `[wans.pppoe]` with `username` and `password` (and optional service and AC filters) brings a
  WAN up over PPPoE: discovery (PADI/PADO/PADR/PADS, Host-Uniq, RFC 4638 PPP-Max-Payload
  asking for 1500 and falling back to 1492), LCP (MRU, magic number, authentication,
  keepalive, terminate), PAP and CHAP-MD5, IPCP (address, peer address, primary and secondary
  DNS), IPV6CP (interface identifiers).
- The kernel plumbing of SPEC §7.2: an `AF_PPPOX` session socket, a `/dev/ppp` unit and a
  channel connected to it, the netdev named `ppp-<wan>`, its MTU and MRU from the negotiation,
  IPv4 and IPv6 flowing through the kernel.
- Everything downstream works over the link as it does over a port: NAT and the zones,
  DNS upstreams from IPCP behind the route gate, the IPv6 WAN client (RA, SLAAC on a link
  prefix, a typed or learned default) and the DHCPv6 client (IA_NA and IA_PD) on `ppp-<wan>`,
  a routed `[wans.ipv6].prefix` over it, the ULA, the LAN side unchanged.
- Keepalive (LCP Echo-Request every 10 s, three misses end the session), AC-initiated PADT
  and LCP Terminate-Request honoured, our own termination orderly (Terminate-Request, then
  PADT), reconnect with exponential backoff, at once when carrier returns.
- MSS clamping for every WAN whose netdev MTU is below 1500 (SPEC §7.2), PPPoE or not.
- Facts: session id, AC, addresses, resolvers, MTU, identifiers, up-since; console lines that
  are contracts.
- The lab's ISP runs `pppoe-server` with `pppd` (PAP, CHAP, IPCP with DNS, IPV6CP), optionally
  on a tagged WAN; radvd and Kea's DHCPv6 server then run on the ISP's end of the PPP link, so
  M2's IPv6 scenarios have a PPP variant; a `pppoe` sandbox suite exercises the driver against
  `pppoe-server` over a veth pair without QEMU; CI grants `/dev/ppp` and runs it all.

## Non-goals

- MS-CHAP, MS-CHAPv2, EAP, MPPE, compression (CCP, VJ), multilink (MRRU), PPPoE relay, the
  server side of anything; authenticating the peer (we never ask the AC to prove itself).
- PPPoA, PPTP, L2TP, PPP over serial.
- Shaping with the PPPoE overhead (M4's CAKE work; §7.8 already knows the netdev name).
- WAN failover between a PPPoE WAN and another (M6: the probe and the tables are M6's).
- A panel or API for the credentials (M4): they live in `config.toml` on `/state`, root-only.
- Recording the sanitised AAISP session pcap (SPEC §13 leaves it to the maintainer); the
  fixtures here are synthesised and the harness's own captures.

## Anti-goals

- A session that flaps or storms the AC: every retransmission backs off, every reconnect waits,
  a failing authentication is not retried faster than the AC would want (the account could be
  locked).
- Credentials on the console, in a fact, in a log line or in a support bundle: the username is
  shown, the password never, not even its length.
- A PPP link that silently carries 1492-byte frames into a LAN of 1500-byte hosts without the
  clamp: TCP stalls that look like a broken ISP.
- Reconnecting with stale state: a new session starts from Dead with fresh LCP state, a fresh
  Host-Uniq and a fresh magic number; the old unit and channel are closed first, so the old
  `ppp-<wan>` netdev is gone before the new one appears.
- Unsafe code outside `openfeo-net`'s `sys.rs` (ADR-0013), or a kernel call from a pure crate.

## Constraints

- SPEC §7.2 (PPPoE), §7.4 (WAN selection by priority; the probe is M6), §7.5 (zones, NAT, the
  MSS clamp), §7.7 (upstreams behind the route gate, ADR-0019), §8.2 (`[wans.pppoe]`),
  §11 (harness), §12 (M3 acceptance: "v4 and v6 over PPP against `pppoe-server`").
- `CLAUDE.md`: pure protocol crates, `unsafe` only in `sys.rs`, no `unwrap`/`expect` outside
  tests, a fuzz target per parser in the PR that adds it, SPDX headers, documentation ranges
  only, console lines as contracts, every quirk of the kernel or of `pppd` found in the harness
  gets an ADR.
- The kernel already carries `CONFIG_PPP=y` and `CONFIG_PPPOE=y` (`kernel/required.config`).
- The lab is rootless: `pppd` on the ISP side needs `/dev/ppp` readable and writable by the
  user, and reads its secrets from `/etc/ppp`, a path it cannot be told to change; the sandbox
  already owns a mount namespace.
- `pppd` 2.5 on the development host and in CI's Ubuntu 24.04 (2.5.0 there); `rp-pppoe`'s
  `pppoe-server` 4.0 on both.
- The dogfooding line is PPPoE with a statically routed /48 (M2 part 2's shape) and IPv6 RA
  over the link; it must come up from this milestone's code unchanged.

## Design

### Config

`[wans.pppoe]` selects the WAN type, exactly as `[wans.static]` and `[wans.dhcp]` do:

```toml
[[wans]]
name = "wan0"
port = "p0"
vlan = 0                    # 0 = untagged; a tagged line says 101 and runs over p0.101
priority = 10
[wans.pppoe]
username = "openfeo@isp.example"
password = "example-secret"
# service = ""              # a service name to insist on; absent = any (the usual case)
# ac = ""                   # an access-concentrator name to insist on; absent = any
[wans.ipv6]                 # as on any WAN: a routed prefix, a typed gateway, or a delegation
prefix = "2001:db8:1::/48"
```

Proto: `message PppoeWan { string username = 1; string password = 2; string service = 3;
string ac = 4; }`, field 8 of `Wan.kind` (7 is `ipv6`). Validation: `username` and `password`
present, 1 to 255 bytes each, no NUL (PAP carries them as byte strings of at most 255 bytes;
CHAP uses the password as the secret); `service` and `ac` at most 255 bytes, empty meaning
"any". Everything else about a WAN (`vlan`, `priority`, `[wans.ipv6]` in all three shapes,
`[wans.probe]` later) applies unchanged. Secrets stay in `config.toml` (mode 0600 on `/state`,
as today); nothing logs them.

### Names

A PPPoE WAN has two interfaces: the **port** (`pN` or `pN.V`, from `wan_ifname`), which carries
the PPPoE Ethernet frames and has no IP role, and the **netdev** `ppp-<wan>` (`ppp-wan0`), the
kernel's PPP unit renamed, which carries IP. `openfeo-reconcile` gains `wan_netdev(wan) ->
String`: `ppp-<name>` for a PPPoE WAN, `wan_ifname(wan)` otherwise. Every consumer that means
"the WAN's IP interface" moves to it: routing, sysctl, the DNS route gate, `lan6::wan_usable`,
the firewall's `wan_if` set, and the `ipv6` and `dhcp6` tasks' port. The links reconciler keeps
naming the port (it brings it up and sets its MTU) and learns the netdev as a thing to rename,
size and bring up. The console says `wan0` as always; where it names an interface it says which.

### Discovery (RFC 2516, RFC 4638)

`openfeo-proto-ppp::pppoe`: the discovery codec (version 1, type 1, codes PADI 0x09, PADO 0x07,
PADR 0x19, PADS 0x65, PADT 0xa7; tags Service-Name, AC-Name, Host-Uniq, AC-Cookie,
Relay-Session-Id, PPP-Max-Payload 0x0120, Service-Name-Error, AC-System-Error, Generic-Error;
the session header) with limits (at most 32 tags, a tag at most 1480 bytes, the payload length
checked against the frame), and `pppoe::Client`, a core driven by `Input::{Start, Packet{from,
bytes}, Timeout, Stop}` yielding `Output::{Send{to, bytes}, Session{id, ac_mac, ac_name,
max_payload: Option<u16>}, Closed(reason), Note}`:

- PADI broadcast with Service-Name (the configured one or empty), a fresh 8-byte Host-Uniq per
  attempt, and PPP-Max-Payload asking for `min(1500, port_mtu − 8)` when that is above 1492;
  retransmitted after 1, 2, 4, 8, 16, 32 s, then every 32 s (the driver keeps trying while the
  port has carrier).
- PADO accepted only with our Host-Uniq; filtered by `service` and `ac` when set; the first
  acceptable one wins (several ACs answer on some lines: the first to answer is the convention),
  its AC-Cookie and Relay-Session-Id echoed in the PADR, PPP-Max-Payload echoed only when the
  PADO carried it with a value at least ours (RFC 4638 §4).
- PADR unicast to the AC, retransmitted after 1, 2, 4 s, three times, then back to PADI.
- PADS with session id 0 or an error tag is a refusal (noted; back to PADI after the holdoff);
  otherwise the session is up: `Session{..}` with `max_payload` = the PADS's PPP-Max-Payload if
  present and at least 1492, else `None` (1492).
- PADT from the AC (matching session and MAC) closes; `Stop` sends our own PADT.

### PPP frames and the control protocols (RFC 1661, 1332, 1334, 1877, 1994, 5072)

`openfeo-proto-ppp::frame`: a PPP frame over PPPoE is `[protocol: u16][payload]`; no address or
control field, no protocol-field compression (we never offer PFC or ACFC and reject them if
offered). Protocols: LCP 0xc021, PAP 0xc023, CHAP 0xc223, IPCP 0x8021, IPV6CP 0x8057, IPv4
0x0021, IPv6 0x0057 (the last two never reach userspace).

`openfeo-proto-ppp::fsm`: the RFC 1661 option-negotiation automaton once, generic over an
`Options` trait that each control protocol implements: encode our Configure-Request, judge the
peer's request option by option (ack, nak with a suggestion, or reject), apply a Nak or Reject
to our own request, and say when the protocol is "up" (both sides acked). States Initial,
Starting, Closed, Stopped, Closing, Stopping, Request-Sent, Ack-Received, Ack-Sent, Opened;
events Up, Down, Open, Close, TO+, TO−, RCR+, RCR−, RCA, RCN, RTR, RTA, RUC, RXJ+, RXJ−, RXR;
Max-Configure 10, Max-Terminate 2, Max-Failure 5, Restart timer 3 s (RFC 1661 §4.6).
Code-Reject for unknown codes, Protocol-Reject handling (a rejected NCP stays down without
affecting the link; a rejected LCP code is fatal). The identifier of every request we send is
fresh; a reply with an unknown identifier is dropped.

- **LCP**: options we send: MRU (`max_payload` or 1492), Magic-Number (random, non-zero);
  options we accept from the peer: MRU (576 to our MTU), Authentication-Protocol (PAP, or CHAP
  with algorithm MD5; anything else naked to CHAP-MD5, then PAP; a third insistence is rejected
  and the link goes down with `auth protocol not supported`), Magic-Number (nak'd if it equals
  ours), Quality-Protocol, PFC, ACFC, Callback, MRRU and the rest rejected. Echo-Request every
  10 s once Opened, carrying our magic; three unanswered in a row take the link down with
  `keepalive lost`; the peer's Echo-Requests are answered; Discard-Request ignored.
  Terminate-Request from the peer: Terminate-Ack, then Down; ours: two Terminate-Requests one
  second apart, then Down whatever came back.
- **Authentication**: the LCP negotiation decides. PAP: Authenticate-Request with the peer-id
  and the password, retransmitted every 3 s up to 10 times; Ack is up, Nak is `auth failed`
  with the message (the console shows the first 80 printable bytes of it, never the password).
  CHAP-MD5: the Challenge's identifier and value are answered with `MD5(id ‖ secret ‖
  challenge)` and our name; Success is up, Failure is `auth failed`; a second Challenge during
  the session (rechallenge) is answered the same way without leaving the Network phase. MD5 is
  in-tree (RFC 1321's test vectors), as SHA-256 was for RFC 7217 in part 2.
- **IPCP**: we request IP-Address 0.0.0.0, Primary-DNS 0.0.0.0 and Secondary-DNS 0.0.0.0 and
  take what the Nak fills in (an address of 0.0.0.0 after the fifth Nak is a failure); the
  peer's own request gives its address (IP-Address; a peer that sends none is unnumbered and
  the default route goes through the netdev alone); IP-Compression-Protocol rejected. Up means
  `Ipv4 { local, peer: Option, dns: Vec }`.
- **IPV6CP**: Interface-Identifier, ours derived from the stable-privacy secret and the WAN name
  (RFC 7217's function over `secret ‖ "ipv6cp" ‖ wan`, never zero, never the peer's: a Nak
  with a different identifier is taken as is, a conflict with the peer's is resolved by the
  derivation with a counter); the peer's identifier comes from its request. Up means
  `Ipv6 { local_iid, peer_iid }`.
- **Session**: `openfeo-proto-ppp::session::Session` orchestrates the phases over the five
  cores: Dead → Establish (LCP) → Authenticate (as negotiated, or straight through when the AC
  asked for none) → Network (IPCP and IPV6CP opened together; either may fail or be
  Protocol-Rejected without ending the link, both failing ends it with `no network protocol`) →
  Terminate. Inputs: `Frame{protocol, payload}`, `Timeout`, `Start`, `Stop`, `CarrierLost`.
  Outputs: `Send(frame)`, `Mru(u16)` (for `PPPIOCSMRU` once LCP is up), `Ipv4Up{..}`,
  `Ipv4Down`, `Ipv6Up{..}`, `Ipv6Down`, `Down{reason, uptime_ms}`, `Note`. Every timer is a
  single `next_timeout()`; nothing is sent after `Down` until the next `Start`.

### Kernel plumbing (`openfeo-net::pppoe`, `sys.rs`)

- `Discovery`: an `AF_PACKET` datagram socket for `ETH_P_PPP_DISC` (0x8863) bound to the port,
  as the DHCPv4 driver's is for IPv4, sending to the broadcast or the AC's MAC and receiving
  with the source MAC. Session frames (`ETH_P_PPP_SES`, 0x8864) never reach it: they are the
  kernel's.
- `Session::attach(port_ifindex, port_ifname, session_id, ac_mac)`: `socket(AF_PPPOX,
  SOCK_STREAM, PX_PROTO_OE)` connected to `sockaddr_pppox { sa_family AF_PPPOX, sa_protocol
  PX_PROTO_OE, pppoe_addr { sid (network order), remote mac, dev } }`; `open("/dev/ppp",
  O_RDWR | O_NONBLOCK | O_CLOEXEC)` and `PPPIOCNEWUNIT` on it (the unit fd; the kernel names the
  netdev `pppN`, N returned); `PPPIOCGCHAN` on the PPPoX socket, a second `/dev/ppp` fd with
  `PPPIOCATTCHAN` (the channel fd) and `PPPIOCCONNECT(N)` on it at once, as `pppd` does.
  Control frames arrive where the kernel puts them: on the channel fd only while the channel is
  not connected to a unit, on the unit fd afterwards (`ppp_receive_nonmp_frame` queues every
  frame of a protocol that is not a network protocol to the unit's reader), so the driver reads
  and writes control frames on the unit fd and keeps the channel fd open for the channel's
  life; SPEC §7.2's sentence saying "the channel fd" is amended to say so. `PPPIOCSMRU` on the
  unit fd when LCP settles the MRU. Both fds are `AsyncFd`s; frames are read as `[protocol:
  u16 BE][payload]`. Dropping the `Session` closes the three descriptors, which the kernel
  answers by removing the unit and its netdev.
- `sys.rs` grows the `sockaddr_pppox` construction, the five ioctls (`PPPIOCNEWUNIT`,
  `PPPIOCGCHAN`, `PPPIOCATTCHAN`, `PPPIOCCONNECT`, `PPPIOCSMRU`, their numbers from
  `linux/ppp-ioctl.h` under a comment, with `libc`'s constants where it has them) and the
  `AF_PPPOX` socket, each behind a safe function with a `// SAFETY:` comment, as ADR-0013
  wants. Nothing else in the crate is `unsafe`.
- The port's MTU must carry 1508-byte frames before a 1500-byte PPP payload can: the links
  reconciler asks for MTU 1508 on every PPPoE WAN port (a NIC that refuses reports through the
  applier's pass and the port stays at 1500); the task reads the port's MTU from the World and
  offers PPP-Max-Payload only when it is at least 1508.

### The task (`crates/openfeo/src/pppoe.rs`)

One supervised task per `[wans.pppoe]` WAN, after the shape of the DHCPv4 and DHCPv6 tasks:

1. Wait for the port (up with carrier, from the World).
2. Discovery on the port until `Session{..}` (or carrier goes).
3. Attach the kernel session; publish `PppoeFact` with the unit number, the session id, the AC,
   the MTU to use (the negotiated max payload or 1492) and the port MTU the max payload needs;
   the links applier renames `pppN` to `ppp-<wan>`, sets its MTU and brings it up.
4. Run `session::Session` on the unit fd: frames in, frames out, `Mru` to `PPPIOCSMRU`,
   `Ipv4Up`/`Ipv6Up` into the fact (the routing applier adds the addresses and routes), their
   `Down`s out of it.
5. On `Down{reason, uptime}` (keepalive lost, PADT, Terminate, auth failed, carrier lost, no
   network protocol): the fact is withdrawn (the routes and addresses go with it), our PADT is
   sent when the session, not the AC, ended it, the kernel session is dropped (the netdev
   vanishes), and the task waits: 1 s, then doubling to 60 s between attempts, back to 1 s
   after a session that stayed up longer than a minute, at once when carrier returns after a
   loss. `auth failed` waits the full 60 s from the start (an AC may lock the account).
6. A configuration change to the WAN restarts the task (the supervisor's restart, as today).

The World's `LinkFact` for `ppp-<wan>` (up, carrier, MTU) is the truth the reconcilers read;
the fact carries what the kernel cannot show (addresses before they are applied, the peer, the
resolvers, the identifiers, the session, up-since on the process clock).

### Facts

```rust
pub struct PppoeFact {
    pub session_id: u16,
    pub ac_mac: [u8; 6],
    pub ac_name: String,
    /// The kernel's unit: its netdev is `ppp<unit>` until the applier renames it.
    pub unit: u32,
    /// The PPP payload size both ends settled on: 1500 with RFC 4638, else 1492.
    pub mtu: u32,
    pub ipv4: Option<PppIpv4>,   // local, peer: Option<Ipv4Addr>, dns: Vec<Ipv4Addr>
    pub ipv6: Option<PppIpv6>,   // local_iid: [u8; 8], peer_iid: [u8; 8]
    /// When the session came up, on the process monotonic clock.
    pub up_since_ms: u64,
}
```

`World.pppoe: Arc<BTreeMap<String, PppoeFact>>` keyed by WAN, beside `dhcp4`. A WAN counts as
up for SPEC §7.4's selection when its fact has `ipv4` (the probe of M6 refines it).

### Routing, links, sysctl

- **links**: the PPPoE WAN's port is a port with a role: up, no bridge, MTU 1508 wanted (1500
  when the NIC refuses), `ipv6_stable_privacy` false (no IPv6 on the port itself). `DesiredLinks`
  gains `ppp: BTreeMap<String, DesiredPpp { unit: u32, mtu: u32 }>` keyed by the netdev name;
  the applier renames `ppp<unit>` to it (`link_set_name`), sets the MTU and brings it up, and
  leaves a `ppp-*` link it does not desire alone (the task's drop removes it). No stray
  deletion: a `ppp-*` the World shows without a fact is a task mid-restart.
- **routing**: with `ipv4`: `local/32` on the netdev with the peer as the point-to-point address
  (`DesiredAddr` gains `peer: Option<IpAddr>`; the netlink applier sets `IFA_ADDRESS` to it), a
  default route `dev ppp-<wan>` (via the peer when known, metric the WAN's priority, protocol
  200) in `main`; the WAN's table (`100 + index`) gets the same default and the IPv6 one as
  part 3 laid out. With `ipv6`: `fe80::<local_iid>/64` on the netdev and the peer's
  `fe80::<peer_iid>/128` as an on-link route, so the RA client has a link-local to send from and
  the learned default via the peer's link-local resolves; everything else of M2 (the routed
  prefix's addresses, the loopback `::1`s, the blackhole, the delegated prefixes' rules) keys
  on `wan_netdev` and needs no change of substance.
- **sysctl**: the IPv6 knobs of part 2 (`accept_ra 0`, `autoconf 0`, `accept_redirects 0`,
  the MTU) on the netdev once it exists; the port keeps its defaults.
- The `ipv6` and `dhcp6` tasks of M2 take `wan_netdev` as the interface to wait for and bind
  to; their sockets are plain ICMPv6 and UDP and work over a PPP netdev. The RA client's
  `Config.mac` becomes `Option<[u8; 6]>`: a PPP link has no link-layer address, so the Source
  Link-Layer Address option is left out of solicitations (RFC 4861 §4.6.1 requires that on
  such links); the RFC 7217 input is the interface name and the secret, as today.

### Firewall

- `wan_if` holds the netdev (`ppp-wan0`), so the zones, NAT and the rules of §7.5 apply to the
  PPP link; the port carries no IP and needs no rule (PPPoE frames are not `inet`).
- **MSS clamp** (SPEC §7.2): for every WAN whose netdev the World shows with an MTU below 1500,
  a forward-chain rule `oifname <netdev> tcp flags syn tcp option maxseg size set rt mtu` and
  its mirror `iifname <netdev> …`. The lab's DHCP WAN (lease MTU 1400) gets it too, which is
  what the SPEC says; the `nft` snapshot tests show the two lines.

### DNS and time

IPCP's resolvers join the WAN's learned upstreams behind the IPv4 route gate, exactly as a
DHCPv4 lease's do; PPP gives no NTP servers and no domain.

### Console

Contracts, tested where they are printed and matched by the harness:

```
pppoe wan0 discovering on p0 (service any, max payload 1500)
pppoe wan0 session 0x0001 with 52:54:00:fe:00:01 ac "isp" max payload 1500
pppoe wan0 session 0x0001 with 52:54:00:fe:00:01 ac "isp" max payload 1492 (no RFC 4638)
pppoe wan0 lcp up mru 1500 auth chap
pppoe wan0 auth chap ok as openfeo@isp.example
pppoe wan0 auth pap failed: Login incorrect; retry in 60 s
pppoe wan0 ipcp up 203.0.113.100 peer 203.0.113.1 dns 203.0.113.1
pppoe wan0 ipv6cp up local 0000:0000:0000:0001 peer 0000:0000:0000:0002
pppoe wan0 down: keepalive lost (3 echoes) after 1234 s; retry in 1 s
pppoe wan0 down: padt from ac after 1234 s; retry in 1 s
pppoe wan0 down: terminated by peer after 1234 s; retry in 1 s
pppoe wan0 down: carrier lost after 1234 s
pppoe wan0 stopped
```

Nothing prints the password or the CHAP secret; a PADO or PADS the filters refused is a debug
line with the AC name and service.

### Schema and facts in the TOML

No new state file: a PPP session is not persisted (a reboot starts discovery afresh, which is
what every PPPoE client does and what the AC expects).

### Crates and drivers

- `crates/openfeo-proto-ppp`: pure (`#![forbid(unsafe_code)]`, no tokio, libc, nix, socket2):
  `pppoe` (codec, discovery client), `frame`, `fsm`, `lcp`, `pap`, `chap` (with `md5`), `ipcp`,
  `ipv6cp`, `session`, `iid` (the RFC 7217 derivation shared with `openfeo-proto-ndp`, moved
  to a tiny `openfeo-proto-iid` crate or re-exported; the builder picks the smaller change).
- `crates/openfeo-net/src/pppoe.rs` (the two drivers) and `sys.rs` (the ioctls and
  `sockaddr_pppox`).
- `crates/openfeo-world/src/pppoe.rs` (`PppoeFact`), `crates/openfeo-reconcile` (`wan_netdev`,
  links, routing, sysctl, nft, dns, lan6), `crates/openfeo-apply` (rename, peer address),
  `crates/openfeo-netlink` (`addr_add` with a peer; `IFA_ADDRESS` for a point-to-point address),
  `crates/openfeo/src/pppoe.rs` (the task) and `router.rs` (spawn), `crates/openfeo-config`
  (`PppoeWan`, validation).
- Fuzz targets: `pppoe_discovery` (decode/encode round trip, no panic), `ppp_lcp`, `ppp_ipcp`,
  `ppp_ipv6cp`, `ppp_auth` (the option and packet decoders), `ppp_session` (the whole session
  core fed random frames and timeouts with the invariants: nothing sent after `Down`, no timer
  in the past, at most Max-Configure requests per exchange). Oracle: `ppproperly` (the rsdsl
  PPP serialisation crate) as a dev-dependency differential target if its licence passes
  `cargo deny`; else hand-written vectors from the RFCs and the harness's captures (ADR-0022).

### Harness

- Tools: `pppoe-server` and `pppd` (the ISP's AC and PPP peer), `pppoe` (rp-pppoe's user-mode
  helper `pppoe-server` spawns per session). `make check-env` reports them and whether
  `/dev/ppp` can be opened; a scenario that needs it `Skip`s with the udev line to add
  (`KERNEL=="ppp", GROUP="<group>", MODE="0660"`), and CI and the cloud setup grant it
  (`sudo chmod 666 /dev/ppp`, since the runner has no reboot). `OPENFEO_NO_SKIP=1` makes the
  skip a failure there.
- Secrets: `pppd` reads `/etc/ppp/pap-secrets` and `chap-secrets` from a fixed path, so the
  sandbox (`harness/src/sandbox.rs`) mounts a tmpfs over `/etc/ppp` inside its mount namespace
  when the directory exists, and the lab writes the secrets (`"openfeo@isp.example" * "example-
  secret" *`), an empty `options`, and the `pppoe-server` options file there per run.
- `daemons::pppoe_server(ns, &PppoeServerConfig, run_dir)`: `pppoe-server -I <iface> -F -C
  <ac name> -S <service> -L 203.0.113.1 -R 203.0.113.100 -N 4 -O <options file> -X <pidfile>`
  with the options file carrying `require-pap` or `require-chap` (or `noauth`), `ms-dns
  203.0.113.1`, `lcp-echo-interval 5`, `lcp-echo-failure 3`, `+ipv6` with `ipv6 ::1,::2` when
  the scenario wants IPV6CP, `mtu`/`mru` 1492 (or 1500 for the RFC 4638 variant if this
  `pppoe-server` can offer PPP-Max-Payload; if it cannot, the 1500 path is proven by the
  discovery core's tests against a synthetic PADS and the scenario asserts the 1492 fallback),
  `debug` and `logfile <run_dir>/pppd-<iface>.log` (each session's `pppd` logs there: its
  `local IP address`, `remote IP address`, `Using interface pppN` lines are what the scenarios
  read). `Lab::start_pppoe_server`, `stop_pppoe_server` (SIGTERM makes `pppd` send
  Terminate-Request and `pppoe-server` PADT), `restart_pppoe_server`; the ISP's PPP interface
  name comes from the `pppd` log, and `Lab::isp_ppp_ifname()` returns it once up, so radvd and
  Kea's DHCPv6 server can be started on it (`RadvdConfig::isp(&ifname)`, `Kea6Config { iface
  }`), which resolves SPEC §13's open item: Kea, started on the PPP interface once the session
  is up (the ISP that is "always on" is the lab's ordering, not Kea's).
- `harness/fixtures/vm-pppoe.toml`: `wan0` on `p0` with `[wans.pppoe]` (the documentation
  credentials above), `[wans.ipv6] prefix = "2001:db8:1::/48"` (the dogfooding shape), lan0;
  `vm-pppoe-pd.toml` with `pd_hint = 56` instead of the prefix for the delegation-over-PPP
  scenario; a tagged variant is the fixture with `vlan = 101`.
- Sandbox suite `pppoe` (`harness/tests/pppoe.rs`, veth `e0`/`e1`, `pppoe-server` in the far
  namespace, our drivers on the near end, the session core run by the test as `dhcp6.rs` runs
  its core): discovery binds a session (PADI/PADO/PADR/PADS; Host-Uniq echoed; the session id
  and AC MAC match the server's log); LCP, PAP and IPCP bring IPv4 up with the pool address and
  the resolver, and `ping` from the near end to 203.0.113.1 over the new `pppN` answers; the
  CHAP variant; a wrong password gets `auth failed` with `pppd`'s message and no retry inside
  the holdoff; `pppoe-server` stopped by SIGKILL (no Terminate) is `keepalive lost` within
  three echo intervals plus one; stopped by SIGTERM is `terminated by peer` at once; a PADT
  injected by the test (a raw frame from the far end) is `padt from ac`; IPV6CP brings the
  identifiers up and `fe80::<peer iid>` answers a ping over the link; RFC 4638: the PADS's
  max payload is honoured when offered, the fallback is 1492 when not.
- QEMU suite `m3` (`harness/tests/m3.rs`): boot `vm-pppoe.toml` with `pppoe-server` on isp0's
  `wan0`: the console shows discovery, the session, `lcp up`, `auth chap ok`, `ipcp up` with
  the pool address and the resolver, and the LAN host fetches the ISP's HTTP target through
  NAT over the PPP link; `dig` at the router answers through the IPCP resolver; the firewall
  holds the clamp (`nft` sandbox scenario `the_ruleset_clamps_mss_for_a_wan_below_1500` proves
  the rule; the QEMU scenario proves a 64 KiB body fetched with the ISP target's MTU at 1500
  and no ICMP from the router, i.e. the clamp did its job); `pppoe-server` killed: `down:
  keepalive lost` within 20 s, the LAN host loses the ISP, the server restarted: `ipcp up` again
  with the retry line between; `set_link p0 off/on`: `down: carrier lost` and the session back
  within 10 s of carrier; PAP variant; the tagged variant on `wan0.101` (skips without
  `8021q`); IPv6 over PPP: `ipv6cp up`, radvd on the ISP's `pppN` gives the router its default,
  the LAN host configures itself from the routed `/48` and fetches the ISP target over IPv6
  (part 2's scenario over PPP); PD over PPP with `vm-pppoe-pd.toml` and Kea on the ISP's
  `pppN`: `dhcp6 wan0 bound prefix …` and a LAN host with a GUA from it (part 3's first
  scenario over PPP); a reboot (`system_reset`) comes back with a fresh session and the same
  routed prefix; the console never shows the password (a scenario greps for it).

## SPEC amendments (the plan's first task)

- §7.2 PPPoE: the control frames' fd (unit after connect); the port MTU 1508 for RFC 4638;
  the backoff schedule and the authentication holdoff; the console lines; `service` and `ac`.
- §8.2: `[wans.pppoe]` gains `service` and `ac`, with the comment that absent means any.
- §7.5: the MSS clamp names its rule and that it applies to every WAN whose netdev MTU is
  below 1500.
- §11: `pppoe-server`, `pppd`, `/dev/ppp` and the `/etc/ppp` mount in the harness paragraph;
  Kea on the ISP's PPP interface for delegation over PPP.
- §13: the "Kea or odhcpd for DHCPv6-PD over PPP" item ticked (Kea, started on the PPP
  interface once the session is up); the pcap item stays with the maintainer.

## ADRs

- ADR-0022: in-tree PPPoE and PPP codecs, with `ppproperly` as the differential oracle if its
  licence passes `cargo deny`, else RFC vectors (after ADR-0015 and ADR-0018).
- ADR-0023: the PPP unit is created by the WAN task through `/dev/ppp`, and its netdev is
  renamed, sized and brought up by the links applier like any link; the task owns the three
  descriptors and nothing else touches them.
- Any `pppd`, `pppoe-server` or kernel PPP quirk the harness finds (the control-frame fd is
  one already known and goes into the §7.2 amendment, not an ADR).

## What is left to the builder

- The exact `fsm` trait and whether `statig` buys anything over the enum machine (the
  enum machine is the default, matching the other cores).
- The MD5 module's placement (`openfeo-proto-ppp::md5`, 70 lines, RFC 1321 vectors).
- The ioctl constants: `libc` where it has them, otherwise the numbers from
  `linux/ppp-ioctl.h` (`_IOW('t', 56..)` family) with the header line quoted.
- How `DesiredAddr`'s `peer` reaches `rtnetlink`'s address builder (`IFA_LOCAL` ours,
  `IFA_ADDRESS` the peer) and how the cache compares a point-to-point address.
- Whether `pppoe-server` 4.0 can offer PPP-Max-Payload; the two scenario shapes are given above
  for either answer.
- The sandbox suite's way of injecting a PADT (a raw `ETH_P_PPP_DISC` frame from the far
  namespace, built with the codec).

## Calls made for the maintainer

1. **`service` and `ac` filters as config fields**, absent meaning any. Cost: two fields nobody
   uses on most lines; removing them later is a schema change.
2. **MD5 in-tree** rather than a RustCrypto dependency, as SHA-256 was. Cost: 70 lines to
   maintain against an algorithm that never changes.
3. **The port MTU is set to 1508 on every PPPoE WAN port**, so RFC 4638 can be offered; a NIC
   that refuses stays at 1500 and the offer is withheld. Cost: a NIC that accepts 1508 but
   drops such frames in hardware would see LCP fail at MRU 1500 and the session fall back only
   after the AC's PADS; a `max_payload` knob is the escape hatch if that ever happens.
4. **IPV6CP's interface identifier is derived from the stable-privacy secret and the WAN name**
   (RFC 7217 style), so the router's link-local on the PPP link is stable. Cost: none visible;
   a random identifier would be as correct.
5. **The channel is connected to the unit at once and control frames are read on the unit
   fd**, which is what the kernel does and what `pppd` does; SPEC §7.2's wording is amended.
   Cost: none; the alternative does not work.
6. **Termination order**: ours is LCP Terminate-Request twice, then PADT, then the session is
   dropped; a PADT from the AC drops the session without LCP. Cost: an AC that wanted a PADT
   before the Terminate-Ack sees one a second later.
7. **Backoff**: 1 s doubling to 60 s between attempts, reset after a minute up, at once when
   carrier returns; `auth failed` waits 60 s from the first failure. Cost: a line whose AC takes
   a minute to notice a dead session makes the first retries futile, which the doubling absorbs.
8. **The MSS clamp is derived from the netdev's kernel MTU for every WAN**, PPPoE or DHCP, as
   SPEC §7.2 says; the lab's DHCP WAN at 1400 gains the rule and part 1's `nft` snapshots
   change. Cost: a rule per sub-1500 WAN that costs a few cycles per SYN.
9. **IPCP's resolvers join behind the IPv4 route gate** like a DHCP lease's (ADR-0019). Cost:
   none; the alternative repeats #12.
10. **IPv6 over PPP reuses the M2 tasks on `ppp-<wan>` unchanged in substance**: the RA client
    without a link-layer option, the DHCPv6 client as is, the routed prefix and the delegation
    as is. Cost: an AC that expects DHCPv6 before any RA (some do) is served, since the DHCPv6
    client starts on carrier of the netdev without waiting for M or O (SPEC §7.3).
11. **Kea, not odhcpd, for delegation over PPP in the lab**, started on the ISP's PPP interface
    once the session is up. Cost: a scenario that restarts the session has to restart Kea; a
    helper does it.
12. **A tmpfs over `/etc/ppp` inside the sandbox's mount namespace** carries `pppd`'s secrets;
    nothing on the host is touched. Cost: a host without `/etc/ppp` (no `ppp` package) skips the
    PPP scenarios anyway for want of `pppd`.
13. **Scenarios that need `/dev/ppp` skip without it**, as the module scenarios do; CI grants it
    with a `chmod`. Cost: a developer without the udev rule runs no PPP scenario locally and
    learns from `make check-env`.
14. **We never authenticate the peer** and reject a request to be authenticated by anything but
    PAP or CHAP-MD5 after one Nak each way. Cost: an AC insisting on MS-CHAPv2 gets `auth
    protocol not supported` on the console and no session, which is the truthful outcome.
15. **LCP options we reject outright**: PFC, ACFC, compression, callback, MRRU, quality
    protocol. Cost: an AC that insists on PFC (none known) cannot negotiate; the console says
    which option.
16. **A PADS without PPP-Max-Payload means 1492**, whatever the PADO said (RFC 4638 §4). Cost:
    none; it is the RFC's rule.
17. **A PPPoE WAN is "up" for WAN selection when IPCP is up**; the probe is M6's. Cost: an
    AC that answers IPCP but forwards nothing is "up" until M6's probe says otherwise, as a
    DHCP WAN with a dead gateway is today.
18. **No persistence of the session across a reboot** (discovery afresh), unlike the DHCP
    leases. Cost: none; PPPoE has no notion of a resumable session.
