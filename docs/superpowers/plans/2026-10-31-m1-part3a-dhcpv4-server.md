# M1 Part 3a: LAN DHCPv4 Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every `[lans.dhcp]` LAN gets a DHCPv4 server that hands out pool addresses and static reservations with router, DNS and domain options, answers DHCPINFORM, refuses foreign addresses as an authoritative server, probes an address with ARP before offering it, keeps its lease database on the state disk, and publishes the leases as World facts for the DNS forwarder (part 3b) and the panel (M4).

**Architecture:** A sans-IO server core joins the client in `openfeo-proto-dhcp4` (`Server::handle(Input, now) -> Vec<Output>`, SPEC §6.3) and shares its wire format. A driver in `openfeo-net` owns one UDP socket per LAN bridge (`SO_BINDTODEVICE`) plus one packet socket bound to ARP, which sends the probes and the link-layer unicast replies that an unaddressed client needs (ISC dhcpd's way; no neighbour-table games). A pure reconciler `reconcile::dhcp` turns config into per-LAN server settings with insta snapshots (SPEC §6.2's `reconcile::dhcp_dns`). One supervised task per LAN in the binary runs the driver, logs the console contract, persists the lease database debounced to 5 s (SPEC §5.2) and publishes `World.leases`. The harness gains a Rust LAN-side DHCP client (a hidden `openfeo-harness dhcp-client` subcommand that runs our client in any namespace) and busybox `udhcpc` as the independent reference client, a sandbox suite against the driver over a veth pair, and QEMU acceptance.

**Tech Stack:** Rust stable 2024, tokio, nix 0.30 (`SO_BINDTODEVICE`, packet sockets through the existing `sys::link_addr`), prost/pbjson (config and lease file), insta, cargo-fuzz; harness: busybox `udhcpc` (Arch `busybox`, Ubuntu `busybox-static`), `ip`.

**Spec:** `SPEC.md` §7.6 (DHCPv4 server), §5.2 (storage, debounce), §6.2–6.3 (reconcile, sans-IO), §7.5 (`LAN_UDP_SERVICES` already admits 67), §8.2 (`[lans.dhcp]`), §10 (event vocabulary `lease.granted|released`), §11, §12 M1 ("LAN client gets a lease"), §13 (crate rules). Part 2b's plan `docs/superpowers/plans/2026-10-30-m1-part2b-dhcpv4-client.md` is the model for the driver and the task.

## Global Constraints

- Every source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton` (TOML/JSON/sh: `#` comments). Commits `git commit -s` as `Andrew Newton <andy@vitri.ltd>`, subject `<area>: <summary>`, trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_0116otzXyvDbuXkw4CsR8ExV`.
- `make lint` green: `cargo fmt`, clippy pedantic as `-D warnings` on all targets and features, cargo-deny, SPDX, `scripts/check-deps.sh` (pure crates `openfeo-proto-*`, `openfeo-world`, `openfeo-reconcile` carry no tokio/libc/nix/socket2/netlink anywhere; only kernel-facing crates and the harness depend on libc/nix/netlink directly), `scripts/check-proto.sh` (buf lint and breaking: only add fields).
- `#![forbid(unsafe_code)]` everywhere except `openfeo-init`, `openfeo-nft`, `openfeo-net` (ADR-0013). This plan adds no unsafe: the ARP packet socket reuses `openfeo_net::sys::link_addr(ifindex, protocol, dest)` with protocol `0x0806`.
- No `unwrap`/`expect` outside tests; `thiserror` in libraries, `anyhow` in `crates/openfeo` and `harness/`; `std::process::Command` only in `harness/`.
- Every parser gets a fuzz target in this PR: `dhcp4_server` (bytes into `Server::handle`) and `dhcp4_arp` (ARP decode), with checked-in seeds under `fuzz/corpus/<target>/seed-*.bin`.
- SPEC §5.2: durable writes are temp file + fsync + rename (`openfeo_platform::atomic::write(path, bytes, STATE_FILE_MODE)`), mode 0600, and lease-database writes happen at most once per 5 s.
- Time inside the cores is `Timestamp = u64` monotonic seconds from the driver's start (as the client core); wall-clock seconds appear only in the lease file (`granted_unix`, `expires_unix`) and the fact (`expires_unix`).
- Console line contract (every line is `openfeo: ` + text on the serial console; MACs lowercase colon-separated; `{reason}` is a `NakReason` display string):
  - `lan {lan} dhcp serving {network}/{prefix} pool {first}-{last} statics={n} lease={n}s`
  - `lan {lan} dhcp restored {n} leases` (only when n > 0)
  - `lan {lan} dhcp offer {addr} to {mac}`
  - `lan {lan} dhcp lease granted {addr} to {mac} host={hostname|-} lease={n}s`
  - `lan {lan} dhcp lease renewed {addr} to {mac}`
  - `lan {lan} dhcp nak {addr} to {mac} ({reason})`
  - `lan {lan} dhcp inform {addr} from {mac}`
  - `lan {lan} dhcp lease released {addr} by {mac}`
  - `lan {lan} dhcp declined {addr} by {mac}`
  - `lan {lan} dhcp lease expired {addr} of {mac}`
  - `lan {lan} dhcp conflict {addr} answered by {mac}`
  - `lan {lan} dhcp pool exhausted for {mac}`
- Reference tools: CI runs Ubuntu 24.04 (Kea 2.4.1, `busybox-static` 1.36); the dev host has busybox from the `busybox` package. `make check-env` lists `busybox`; a missing tool fails the check, never skips a scenario.
- Branch `m1-3a` from `main` at `03665aa` (the merge of PR #3); the plan is the first commit (`docs: M1 part 3a plan, the LAN DHCPv4 server`).

## Review Focus

Five conditions the spec implies that a person will meet and no task's tests would otherwise exercise; each has its test pinned to the task that owns the code.

1. A device that repeats DISCOVER every second without ever requesting (a broken IoT stack) must not drain the pool: repeated DISCOVERs from one identity reuse one pending offer. Test `repeated_discovers_from_one_client_reuse_one_offer` (Task 1).
2. A device with a reservation that still holds an address from the previous router (`nas` kept 192.168.1.150) must be NAKed when it reboots that lease and then offered its reserved address. Test `reserved_client_requesting_another_address_is_naked_then_offered_its_reservation` (Task 2).
3. Client hostnames like `Andy's iPhone`, `nas.local`, `  `, or 70 characters of `a` must become a valid DNS label or nothing, never a panic or an invalid name in the facts. Test `hostnames_are_sanitised_to_labels` (Task 2).
4. A lease file written by a previous boot whose entries have expired, or whose addresses lie outside the LAN's current subnet (the subnet was changed), must be dropped at load rather than served. Test `restored_leases_outside_the_subnet_or_expired_are_dropped` (Task 6).
5. Two DHCP servers on one LAN during the switchover: a REQUEST carrying the other server's identifier must be ignored, and our pending offer to that client forgotten so its address is free for others. Test `request_for_another_server_is_ignored_and_frees_the_offer` (Task 2).

---

### Task 1: Server core, part one: configuration, allocation, DISCOVER → probe → OFFER; ARP codec; fuzz targets

**Files:**
- Create: `crates/openfeo-proto-dhcp4/src/server.rs`
- Create: `crates/openfeo-proto-dhcp4/src/arp.rs`
- Modify: `crates/openfeo-proto-dhcp4/src/lib.rs` (add `pub mod arp; pub mod server;` and `pub use server::{Destination, LeaseRecord, NakReason, Reservation, Server, ServerConfig, ServerEvent};` — the server's `Input`/`Output` stay path-qualified, the client's keep the bare re-exports)
- Create: `fuzz/fuzz_targets/dhcp4_server.rs`, `fuzz/fuzz_targets/dhcp4_arp.rs`; Modify: `fuzz/Cargo.toml` (two `[[bin]]`), `fuzz/.gitignore` (add `!corpus/dhcp4_server/`, `corpus/dhcp4_server/*`, `!corpus/dhcp4_server/seed-*.bin`, and the same three lines for `dhcp4_arp`)
- Test: unit tests in both new modules

**Interfaces:**
- Consumes: `wire::{Message, DhcpOption, MessageType, Op, FLAG_BROADCAST}`, `client::Timestamp` (re-export it as `server::Timestamp`), `identity::hex`.
- Produces (used by Tasks 2, 4, 5, 6, 7):

```rust
// arp.rs
pub const ETH_P_ARP: u16 = 0x0806;
pub const ARP_LEN: usize = 28;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp { Request, Reply }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket { pub op: ArpOp, pub sender_mac: [u8; 6], pub sender_ip: Ipv4Addr, pub target_mac: [u8; 6], pub target_ip: Ipv4Addr }
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArpError { #[error("{0} bytes is too short for ARP")] TooShort(usize), #[error("not Ethernet/IPv4 ARP")] NotEthernetIpv4, #[error("unknown ARP operation {0}")] Op(u16) }
pub fn request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> ArpPacket; // target_mac zero
impl ArpPacket { pub fn encode(&self) -> [u8; ARP_LEN]; pub fn decode(bytes: &[u8]) -> Result<ArpPacket, ArpError>; }

// server.rs
pub use crate::client::Timestamp;
pub const DEFAULT_LEASE_SECS: u32 = 43_200;
pub const MIN_LEASE_SECS: u32 = 60;
pub const OFFER_HOLD: Timestamp = 60;
pub const PROBE_TIMEOUT: Timestamp = 1;
pub const CONFLICT_HOLD: Timestamp = 600;
pub const MAX_PROBES: u8 = 3;
pub const MAX_LABEL: usize = 63;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation { pub mac: [u8; 6], pub client_id: Option<Vec<u8>>, pub address: Ipv4Addr, pub hostname: Option<String> }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub server: Ipv4Addr,            // the LAN address: option 54, option 3, default option 6
    pub prefix: u8,
    pub pool: (Ipv4Addr, Ipv4Addr),  // inclusive, host addresses inside the subnet
    pub lease_secs: u32,
    pub dns: Vec<Ipv4Addr>,          // empty means [server]
    pub domain: Option<String>,
    pub reservations: Vec<Reservation>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRecord { pub address: Ipv4Addr, pub mac: [u8; 6], pub client_id: Option<Vec<u8>>, pub hostname: Option<String>, pub granted_at: Timestamp, pub expires_at: Timestamp }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input { Packet(Vec<u8>), ProbeReply { address: Ipv4Addr, mac: [u8; 6] }, Timeout }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination { Broadcast, Link { ip: Ipv4Addr, mac: [u8; 6] }, Unicast(Ipv4Addr) }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NakReason { WrongNetwork, OutsidePool, Reserved, InUse, WrongAddress, OfferMismatch }
// Display: "wrong network" | "outside pool" | "reserved for another client" | "in use by another client" | "not this client's address" | "not what was offered"
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    Offered { address: Ipv4Addr, mac: [u8; 6] },
    Granted(LeaseRecord),
    Renewed(LeaseRecord),
    Nak { address: Ipv4Addr, mac: [u8; 6], reason: NakReason },
    Informed { address: Ipv4Addr, mac: [u8; 6] },
    Released(LeaseRecord),
    Declined { address: Ipv4Addr, mac: [u8; 6] },
    Expired(LeaseRecord),
    Conflict { address: Ipv4Addr, mac: [u8; 6] },
    Exhausted { mac: [u8; 6] },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output { Send { to: Destination, payload: Vec<u8> }, Probe { address: Ipv4Addr }, Event(ServerEvent) }
#[derive(Debug)]
pub struct Server { /* config, leases: BTreeMap<Ipv4Addr, LeaseRecord>, offers, probes, abandoned */ }
impl Server {
    pub fn new(config: ServerConfig, leases: Vec<LeaseRecord>, now: Timestamp) -> Server; // keeps active leases inside the subnet, not on the server or reservation of another, drops the rest
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output>;
    pub fn next_timeout(&self) -> Option<Timestamp>;  // earliest of lease expiry, offer hold, probe deadline, abandon expiry
    pub fn leases(&self) -> Vec<LeaseRecord>;         // active, ascending by address
    pub fn config(&self) -> &ServerConfig;
}
pub fn sanitise_hostname(raw: &str) -> Option<String>;  // Task 2 implements; declared here so Task 2's tests compile against one name
```

Identity: the client identifier (option 61, non-empty) else `0x01 ++ chaddr[..6]`. A reservation with `client_id` matches by it, else by `mac` against `chaddr`.

Allocation for a DISCOVER (RFC 2131 §4.3.1), first match wins, each candidate must be inside the subnet and not the server address:
1. the identity's reservation;
2. the identity's active lease, unless its address is now reserved for another identity;
3. option 50 when inside the pool, not reserved, not abandoned, not actively leased or offered to another identity;
4. the lowest pool address never leased, skipping reserved, abandoned, leased or offered ones; else the one whose lease expired earliest;
5. none → `Event(Exhausted)`.

Probe: when the candidate is not the identity's own active lease, emit `Probe { address }`, remember the pending offer (identity, xid, address, deadline `now + PROBE_TIMEOUT`, probes so far) and no OFFER yet. `ProbeReply { address, mac }` with `mac` ≠ the client's chaddr → `Event(Conflict)`, abandon the address until `now + CONFLICT_HOLD`, try the next candidate (at most `MAX_PROBES` probes per DISCOVER, then `Exhausted`); with `mac` == chaddr → offer. `Timeout` past the deadline → offer. Offer: `Event(Offered)`, `Send(OFFER)`, hold the address for the identity until `now + OFFER_HOLD`. A new DISCOVER from an identity with a pending or held offer re-sends the same offer and refreshes the hold (Review Focus 1).

Reply construction (RFC 2131 Table 3): `op = BootReply`, `htype`, `hlen`, `xid`, `flags`, `giaddr`, `chaddr` copied; `hops = 0`, `secs = 0`, `siaddr = 0`; OFFER: `yiaddr` = address, `ciaddr = 0`; options `53`, `54 = server`, `51 = lease_secs`, `58 = lease_secs / 2`, `59 = lease_secs * 7 / 8`, `1 = mask of prefix`, `3 = [server]`, `6 = dns or [server]`, `15 = domain` when set, `28 = broadcast of the subnet`, `12 = reservation hostname` when the identity has one, `61` echoed when the client sent one (RFC 6842). Destination (§4.1): `ciaddr ≠ 0` → `Unicast(ciaddr)`; `FLAG_BROADCAST` set → `Broadcast`; else `Link { ip: yiaddr, mac: chaddr }`. Messages with `giaddr ≠ 0`, `op ≠ BootRequest`, `htype ≠ 1`, `hlen ≠ 6`, no option 53, a server-to-client type, or that do not decode produce no output.

- [ ] **Step 1: Write the failing ARP tests in `arp.rs`**

```rust
#[test]
fn request_round_trips_and_matches_the_wire_layout() {
    let p = request([0x52, 0x54, 0, 0xfe, 0, 2], "192.168.1.1".parse().unwrap(), "192.168.1.100".parse().unwrap());
    let bytes = p.encode();
    assert_eq!(&bytes[..8], &[0, 1, 8, 0, 6, 4, 0, 1], "htype 1, ptype 0x0800, hlen 6, plen 4, op 1");
    assert_eq!(&bytes[8..14], &[0x52, 0x54, 0, 0xfe, 0, 2]);
    assert_eq!(&bytes[14..18], &[192, 168, 1, 1]);
    assert_eq!(&bytes[18..24], &[0; 6]);
    assert_eq!(&bytes[24..28], &[192, 168, 1, 100]);
    assert_eq!(ArpPacket::decode(&bytes), Ok(p));
}
#[test]
fn decode_rejects_short_foreign_and_unknown_op() {
    assert_eq!(ArpPacket::decode(&[0; 27]), Err(ArpError::TooShort(27)));
    let mut ipx = request([1; 6], Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED).encode();
    ipx[2] = 0x81; ipx[3] = 0x37;
    assert_eq!(ArpPacket::decode(&ipx), Err(ArpError::NotEthernetIpv4));
    let mut op = request([1; 6], Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED).encode();
    op[7] = 9;
    assert_eq!(ArpPacket::decode(&op), Err(ArpError::Op(9)));
    let mut reply = op; reply[7] = 2;
    assert_eq!(ArpPacket::decode(&reply).map(|p| p.op), Ok(ArpOp::Reply));
    assert!(ArpPacket::decode(&[reply.as_slice(), &[0u8; 18]].concat()).is_ok(), "trailing padding is allowed");
}
```

- [ ] **Step 2: Run the ARP tests, watch them fail**

Run: `cargo test -p openfeo-proto-dhcp4 arp` (with `OPENFEO_NFT_SRC` and `OPENFEO_UAPI_INCLUDE` exported as `make test` does, or run through `make test`)
Expected: compile error, `arp` module missing.

- [ ] **Step 3: Implement `arp.rs` as the Interfaces block says**

- [ ] **Step 4: Run the ARP tests, watch them pass**

Expected: 2 passed.

- [ ] **Step 5: Write the failing server tests in `server.rs`** (a `tests` module with helpers `config() -> ServerConfig` for 192.168.1.1/24, pool 192.168.1.100–192.168.1.200, lease 43200, domain `home.arpa`, one reservation `52:54:00:fe:10:10` → 192.168.1.10 `nas`; `discover(mac, xid, options: Vec<DhcpOption>) -> Vec<u8>` building a DISCOVER with the wire codec; `decode(output: &Output) -> Message`; `sends(outputs) -> Vec<(Destination, Message)>`; `events(outputs) -> Vec<ServerEvent>`)

```rust
#[test]
fn discover_probes_the_first_free_pool_address_then_offers_it_after_the_timeout() {
    let mut s = Server::new(config(), vec![], 0);
    let out = s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
    assert_eq!(out, vec![Output::Probe { address: ip("192.168.1.100") }]);
    assert_eq!(s.next_timeout(), Some(PROBE_TIMEOUT));
    let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
    let (to, offer) = sends(&out).remove(0);
    assert_eq!(to, Destination::Link { ip: ip("192.168.1.100"), mac: MAC_A });
    assert_eq!(offer.op, Op::BootReply);
    assert_eq!(offer.message_type(), Some(MessageType::Offer));
    assert_eq!((offer.xid, offer.yiaddr, offer.ciaddr, offer.secs, offer.hops), (1, ip("192.168.1.100"), Ipv4Addr::UNSPECIFIED, 0, 0));
    assert_eq!(offer.option(54), Some(&DhcpOption::ServerIdentifier(ip("192.168.1.1"))));
    assert_eq!(offer.option(51), Some(&DhcpOption::AddressLeaseTime(43_200)));
    assert_eq!(offer.option(58), Some(&DhcpOption::Renewal(21_600)));
    assert_eq!(offer.option(59), Some(&DhcpOption::Rebinding(37_800)));
    assert_eq!(offer.option(1), Some(&DhcpOption::SubnetMask(ip("255.255.255.0"))));
    assert_eq!(offer.option(3), Some(&DhcpOption::Router(vec![ip("192.168.1.1")])));
    assert_eq!(offer.option(6), Some(&DhcpOption::DomainNameServer(vec![ip("192.168.1.1")])));
    assert_eq!(offer.option(15), Some(&DhcpOption::DomainName("home.arpa".into())));
    assert_eq!(offer.option(28), Some(&DhcpOption::BroadcastAddr(ip("192.168.1.255"))));
    assert_eq!(offer.option(12), None);
    assert_eq!(events(&out), vec![ServerEvent::Offered { address: ip("192.168.1.100"), mac: MAC_A }]);
}
#[test]
fn a_probe_reply_from_another_host_abandons_the_address_and_probes_the_next() {
    let mut s = Server::new(config(), vec![], 0);
    s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
    let out = s.handle(Input::ProbeReply { address: ip("192.168.1.100"), mac: MAC_SQUATTER }, 0);
    assert_eq!(out, vec![Output::Event(ServerEvent::Conflict { address: ip("192.168.1.100"), mac: MAC_SQUATTER }), Output::Probe { address: ip("192.168.1.101") }]);
    let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.101"));
    // .100 stays abandoned for CONFLICT_HOLD: a second client is probed at .102
    s.handle(Input::Packet(discover(MAC_B, 2, vec![])), 2);
    assert_eq!(s.next_timeout(), Some(2 + PROBE_TIMEOUT));
    let out = s.handle(Input::Timeout, 2 + PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.102"));
    let mut s2 = Server::new(config(), vec![], 0);
    s2.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
    let out = s2.handle(Input::ProbeReply { address: ip("192.168.1.100"), mac: MAC_A }, 0);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.100"), "a reply from the requester itself is not a conflict");
}
#[test]
fn three_conflicts_exhaust_one_discover() {
    let mut s = Server::new(config(), vec![], 0);
    s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
    let mut last = Vec::new();
    for n in 100..103u8 {
        last = s.handle(Input::ProbeReply { address: Ipv4Addr::new(192, 168, 1, n), mac: MAC_SQUATTER }, 0);
    }
    assert_eq!(last, vec![
        Output::Event(ServerEvent::Conflict { address: ip("192.168.1.102"), mac: MAC_SQUATTER }),
        Output::Event(ServerEvent::Exhausted { mac: MAC_A }),
    ], "the third conflict ends the attempt without a fourth probe");
    assert!(s.handle(Input::ProbeReply { address: ip("192.168.1.102"), mac: MAC_SQUATTER }, 0).is_empty(), "a stray reply is ignored");
    assert_eq!(s.next_timeout(), Some(CONFLICT_HOLD), "only the abandons remain");
}
#[test]
fn a_reservation_is_offered_without_consulting_the_pool() {
    let mut s = Server::new(config(), vec![], 0);
    let out = s.handle(Input::Packet(discover(MAC_NAS, 7, vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))])), 0);
    assert_eq!(out, vec![Output::Probe { address: ip("192.168.1.10") }]);
    let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
    let (_, offer) = sends(&out).remove(0);
    assert_eq!(offer.yiaddr, ip("192.168.1.10"));
    assert_eq!(offer.option(12), Some(&DhcpOption::HostName("nas".into())));
}
#[test]
fn a_requested_free_pool_address_is_honoured_and_a_held_one_is_not() {
    let mut s = Server::new(config(), vec![], 0);
    s.handle(Input::Packet(discover(MAC_A, 1, vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))])), 0);
    let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.150"));
    s.handle(Input::Packet(discover(MAC_B, 2, vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))])), 2);
    let out = s.handle(Input::Timeout, 2 + PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.100"), "B gets the lowest free address, not A's offer");
    let mut s = Server::new(config(), vec![], 0);
    s.handle(Input::Packet(discover(MAC_A, 1, vec![DhcpOption::RequestedIpAddress(ip("192.168.1.10"))])), 0);
    let out = s.handle(Input::Timeout, PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.100"), "a reserved address is never offered to another client");
}
#[test]
fn repeated_discovers_from_one_client_reuse_one_offer() {
    let mut s = Server::new(config(), vec![], 0);
    s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 0);
    s.handle(Input::Timeout, PROBE_TIMEOUT);
    for t in 2..40 {
        let out = s.handle(Input::Packet(discover(MAC_A, t, vec![])), t.into());
        let sent = sends(&out);
        assert_eq!(sent.len(), 1, "no probe, the offer is re-sent at once");
        assert_eq!(sent[0].1.yiaddr, ip("192.168.1.100"));
    }
    s.handle(Input::Packet(discover(MAC_B, 99, vec![])), 40);
    let out = s.handle(Input::Timeout, 40 + PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.101"), "A's offer still holds .100");
    let out = s.handle(Input::Timeout, 40 + OFFER_HOLD + 1);
    assert!(out.is_empty());
    s.handle(Input::Packet(discover(MAC_C, 5, vec![])), 40 + OFFER_HOLD + 2);
    let out = s.handle(Input::Timeout, 40 + OFFER_HOLD + 2 + PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.100"), "the expired hold frees .100");
}
#[test]
fn the_pool_is_walked_never_leased_first_then_longest_expired_then_exhausted() {
    // config_with_pool narrows the pool to 192.168.1.100-102
    let lease = |n: u8, mac: [u8; 6], expires_at| LeaseRecord { address: Ipv4Addr::new(192, 168, 1, n), mac, client_id: None, hostname: None, granted_at: 0, expires_at };
    let mut s = Server::new(config_with_pool(ip("192.168.1.100"), ip("192.168.1.102")), vec![lease(100, MAC_X, 50), lease(101, MAC_Y, 80), lease(102, MAC_Z, 10_000)], 0);
    let expired = events(&s.handle(Input::Timeout, 100));
    assert_eq!(expired.len(), 2, "both .100 and .101 expire by t=100: {expired:?}");
    s.handle(Input::Packet(discover(MAC_A, 1, vec![])), 100);
    let out = s.handle(Input::Timeout, 100 + PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.100"), "no never-leased address left: the one expired longest ago comes first");
    s.handle(Input::Packet(discover(MAC_B, 2, vec![])), 102);
    let out = s.handle(Input::Timeout, 102 + PROBE_TIMEOUT);
    assert_eq!(sends(&out)[0].1.yiaddr, ip("192.168.1.101"));
    let out = s.handle(Input::Packet(discover(MAC_C, 3, vec![])), 104);
    assert_eq!(out, vec![Output::Event(ServerEvent::Exhausted { mac: MAC_C })], ".102 is leased, .100 and .101 are held: nothing to probe");
}
#[test]
fn giaddr_relayed_foreign_op_and_server_messages_are_ignored() {
    let mut s = Server::new(config(), vec![], 0);
    let mut relayed = Message::decode(&discover(MAC_A, 1, vec![])).unwrap();
    relayed.giaddr = ip("10.0.0.1");
    assert!(s.handle(Input::Packet(relayed.encode()), 0).is_empty());
    let mut offer = Message::decode(&discover(MAC_A, 1, vec![])).unwrap();
    offer.options = vec![DhcpOption::MessageType(MessageType::Offer)];
    assert!(s.handle(Input::Packet(offer.encode()), 0).is_empty());
    assert!(s.handle(Input::Packet(vec![0u8; 10]), 0).is_empty());
    assert!(s.handle(Input::Packet(discover_with_hlen(MAC_A, 1, 16)), 0).is_empty());
}
#[test]
fn new_drops_leases_that_no_longer_fit_the_subnet_or_have_expired() {
    let good = LeaseRecord { address: ip("192.168.1.120"), mac: MAC_A, client_id: None, hostname: None, granted_at: 0, expires_at: 100 };
    let expired = LeaseRecord { address: ip("192.168.1.121"), mac: MAC_B, expires_at: 10, ..good.clone() };
    let elsewhere = LeaseRecord { address: ip("10.9.8.7"), mac: MAC_C, ..good.clone() };
    let on_reservation = LeaseRecord { address: ip("192.168.1.10"), mac: MAC_C, ..good.clone() };
    let s = Server::new(config(), vec![expired, elsewhere, on_reservation, good.clone()], 50);
    assert_eq!(s.leases(), vec![good]);
    assert_eq!(s.next_timeout(), Some(100));
}
```

- [ ] **Step 6: Run the server tests, watch them fail**

Run: `cargo test -p openfeo-proto-dhcp4 server`
Expected: compile error, `server` module missing.

- [ ] **Step 7: Implement `server.rs` for DISCOVER, probes, offers, holds, expiry bookkeeping and `new`, as specified above** (leave `handle` for REQUEST/RELEASE/DECLINE/INFORM returning `vec![]` with a `// Task 2` comment; `sanitise_hostname` may return `None` for now). Shared helpers worth naming: `fn identity(msg: &Message) -> Vec<u8>`, `fn in_subnet(&self, addr) -> bool`, `fn in_pool(&self, addr) -> bool`, `fn reservation_for(&self, identity, mac) -> Option<&Reservation>`, `fn reply(&self, request: &Message, kind: MessageType, yiaddr: Ipv4Addr, with_lease: bool) -> Message`, `fn destination(request: &Message, yiaddr) -> Destination`.

- [ ] **Step 8: Run the server tests, watch them pass**

Expected: 9 passed.

- [ ] **Step 9: Write the fuzz targets and seeds**

`fuzz/fuzz_targets/dhcp4_server.rs`: build `Server::new(config, two leases, 0)` with the test module's config values (duplicate them, the fuzz crate cannot see test code), then `server.handle(Input::Packet(data.to_vec()), 1)`, `server.handle(Input::ProbeReply { address: pool start, mac: [9; 6] }, 2)`, `server.handle(Input::Timeout, 5_000)`, and assert `server.leases().iter().all(|l| l.expires_at > 5_000)`. `fuzz/fuzz_targets/dhcp4_arp.rs`: `if let Ok(p) = ArpPacket::decode(data) { assert_eq!(ArpPacket::decode(&p.encode()), Ok(p)); }`. Add an `#[ignore = "writes the fuzz corpus seeds"]` test `write_server_fuzz_corpus` to `server.rs` writing `seed-discover.bin`, `seed-request.bin`, `seed-inform.bin`, `seed-release.bin` into `fuzz/corpus/dhcp4_server/` and an equivalent `write_arp_fuzz_corpus` writing `seed-request.bin`, `seed-reply.bin` into `fuzz/corpus/dhcp4_arp/`; run both once with `--ignored` and commit the seeds.

- [ ] **Step 10: Run both targets for 30 s each**

Run: `cd fuzz && cargo +nightly fuzz run dhcp4_server -- -max_total_time=30 && cargo +nightly fuzz run dhcp4_arp -- -max_total_time=30`
Expected: both end with `Done` and no crash artifacts under `fuzz/artifacts`.

- [ ] **Step 11: Commit**

```bash
git add crates/openfeo-proto-dhcp4 fuzz
git commit -s -m "dhcp4: server core allocates, probes and offers; ARP codec; fuzz targets"
```

### Task 2: Server core, part two: REQUEST in every client state, NAK, INFORM, RELEASE, DECLINE, expiry, hostnames

**Files:**
- Modify: `crates/openfeo-proto-dhcp4/src/server.rs`
- Test: unit tests in `server.rs`

**Interfaces:**
- Consumes: Task 1's `Server`, events, `NakReason`.
- Produces: the complete `handle`; `sanitise_hostname`; `LeaseRecord.hostname` populated as: the reservation's hostname when the identity has one, else `sanitise_hostname(option 12)`.

Behaviour (RFC 2131 §4.3.2), after the Task 1 ignore rules:
- REQUEST with option 54 (SELECTING): `54 ≠ server` → forget any offer held for the identity, no output (Review Focus 5). `54 == server`: ACK when option 50 is allocable to the identity (its reservation, its own active lease, or a pool address free of other leases, offers, abandons and reservations), else NAK `OfferMismatch`.
- REQUEST without 54, with 50, `ciaddr = 0` (INIT-REBOOT), and REQUEST without 54 and 50 with `ciaddr ≠ 0` (RENEWING/REBINDING, address = ciaddr): the address is checked in this order: not in subnet → NAK `WrongNetwork`; reserved for another identity → NAK `Reserved`; the identity has a reservation for a different address → NAK `WrongAddress`; actively leased or held by another identity → NAK `InUse`; outside the pool and not this identity's reservation → NAK `OutsidePool`; else ACK (authoritative: an unknown client whose address fits the pool is adopted).
- REQUEST with neither 50 nor ciaddr: ignored.
- ACK commits the lease (`expires_at = now + lease_secs`, `granted_at = now`), drops the identity's other lease and any offer hold, and emits `Granted` when the identity had no active lease on that address, else `Renewed`. The ACK carries the same options as an OFFER plus `ciaddr` copied from the request. `yiaddr` = the address.
- NAK: options 53, 54, 56 (the reason's display text), 61 echoed; `yiaddr = 0`, `ciaddr = 0`; destination always `Broadcast` (giaddr is 0). Event `Nak`.
- DHCPINFORM: `ciaddr ≠ 0` → ACK with `yiaddr = 0`, `ciaddr` copied, options 53, 54, 1, 3, 6, 15, 28 (and 12 for a reservation), never 51/58/59; destination `Unicast(ciaddr)`; event `Informed`. `ciaddr = 0` → ignored.
- DHCPRELEASE: when `54 == server` (or absent) and `ciaddr` is the identity's active lease → remove it, event `Released`. Otherwise ignored.
- DHCPDECLINE: when option 50 is leased or offered to the identity → remove that lease/offer, abandon the address for `CONFLICT_HOLD`, event `Declined`.
- `Timeout`: every lease with `expires_at <= now` is removed with `Expired`; expired offers, abandons and probe deadlines are processed as Task 1 says.
- `sanitise_hostname`: take the text before the first `.`, lowercase ASCII, map every run of characters outside `[a-z0-9-]` to one `-`, trim leading and trailing `-`, truncate to `MAX_LABEL` bytes (then trim `-` again); return `None` when empty.

- [ ] **Step 1: Write the failing tests** (helpers `request(mac, xid, ciaddr, options) -> Vec<u8>`, `inform`, `release`, `decline`, plus `offered(s, mac) -> Ipv4Addr` which runs DISCOVER + timeout and returns the offered address)

```rust
#[test]
fn selecting_request_for_our_offer_is_acked_and_granted() {
    let mut s = Server::new(config(), vec![], 0);
    let addr = offered(&mut s, MAC_A);
    let out = s.handle(Input::Packet(request(MAC_A, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::ServerIdentifier(ip("192.168.1.1")), DhcpOption::RequestedIpAddress(addr), DhcpOption::HostName("Andy's iPhone".into())])), 3);
    let (to, ack) = sends(&out).remove(0);
    assert_eq!(to, Destination::Link { ip: addr, mac: MAC_A });
    assert_eq!(ack.message_type(), Some(MessageType::Ack));
    assert_eq!(ack.yiaddr, addr);
    assert_eq!(ack.option(51), Some(&DhcpOption::AddressLeaseTime(43_200)));
    let record = LeaseRecord { address: addr, mac: MAC_A, client_id: None, hostname: Some("andy-s-iphone".into()), granted_at: 3, expires_at: 3 + 43_200 };
    assert_eq!(events(&out), vec![ServerEvent::Granted(record.clone())]);
    assert_eq!(s.leases(), vec![record]);
    assert_eq!(s.next_timeout(), Some(3 + 43_200));
}
#[test]
fn selecting_request_for_another_server_is_ignored_and_frees_the_offer() {
    let mut s = Server::new(config(), vec![], 0);
    let addr = offered(&mut s, MAC_A);
    let out = s.handle(Input::Packet(request(MAC_A, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::ServerIdentifier(ip("192.168.1.254")), DhcpOption::RequestedIpAddress(addr)])), 3);
    assert!(out.is_empty());
    assert_eq!(offered(&mut s, MAC_B), addr, "A's hold is gone");
}
#[test]
fn selecting_request_for_something_else_is_naked_broadcast() {
    let mut s = Server::new(config(), vec![], 0);
    let _ = offered(&mut s, MAC_A);
    let out = s.handle(Input::Packet(request(MAC_A, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::ServerIdentifier(ip("192.168.1.1")), DhcpOption::RequestedIpAddress(ip("192.168.1.10"))])), 3);
    let (to, nak) = sends(&out).remove(0);
    assert_eq!(to, Destination::Broadcast);
    assert_eq!(nak.message_type(), Some(MessageType::Nak));
    assert_eq!((nak.yiaddr, nak.ciaddr), (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED));
    assert_eq!(nak.option(51), None);
    assert_eq!(nak.option(56), Some(&DhcpOption::Message("reserved for another client".into())));
    assert_eq!(events(&out), vec![ServerEvent::Nak { address: ip("192.168.1.10"), mac: MAC_A, reason: NakReason::Reserved }]);
}
#[test]
fn init_reboot_is_adopted_inside_the_pool_and_naked_outside() {
    let mut s = Server::new(config(), vec![], 0);
    let out = s.handle(Input::Packet(request(MAC_A, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))])), 0);
    assert_eq!(sends(&out)[0].1.message_type(), Some(MessageType::Ack));
    assert!(matches!(events(&out)[0], ServerEvent::Granted(ref r) if r.address == ip("192.168.1.150")));
    let out = s.handle(Input::Packet(request(MAC_B, 2, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::RequestedIpAddress(ip("192.168.1.77"))])), 1);
    assert_eq!(events(&out), vec![ServerEvent::Nak { address: ip("192.168.1.77"), mac: MAC_B, reason: NakReason::OutsidePool }]);
    let out = s.handle(Input::Packet(request(MAC_B, 3, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::RequestedIpAddress(ip("10.0.0.5"))])), 2);
    assert_eq!(events(&out), vec![ServerEvent::Nak { address: ip("10.0.0.5"), mac: MAC_B, reason: NakReason::WrongNetwork }]);
    let out = s.handle(Input::Packet(request(MAC_B, 4, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))])), 3);
    assert_eq!(events(&out), vec![ServerEvent::Nak { address: ip("192.168.1.150"), mac: MAC_B, reason: NakReason::InUse }]);
}
#[test]
fn reserved_client_requesting_another_address_is_naked_then_offered_its_reservation() {
    let mut s = Server::new(config(), vec![], 0);
    let out = s.handle(Input::Packet(request(MAC_NAS, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::RequestedIpAddress(ip("192.168.1.150"))])), 0);
    assert_eq!(events(&out), vec![ServerEvent::Nak { address: ip("192.168.1.150"), mac: MAC_NAS, reason: NakReason::WrongAddress }]);
    assert_eq!(offered(&mut s, MAC_NAS), ip("192.168.1.10"));
}
#[test]
fn renewing_and_rebinding_are_acked_unicast_to_ciaddr_as_renewals() {
    let mut s = Server::new(config(), vec![], 0);
    let addr = offered(&mut s, MAC_A);
    s.handle(Input::Packet(request(MAC_A, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::ServerIdentifier(ip("192.168.1.1")), DhcpOption::RequestedIpAddress(addr)])), 3);
    let out = s.handle(Input::Packet(request(MAC_A, 2, addr, vec![])), 21_603);
    let (to, ack) = sends(&out).remove(0);
    assert_eq!(to, Destination::Unicast(addr));
    assert_eq!((ack.yiaddr, ack.ciaddr), (addr, addr));
    assert!(matches!(events(&out)[0], ServerEvent::Renewed(ref r) if r.expires_at == 21_603 + 43_200 && r.granted_at == 21_603));
    let mut broadcast = Message::decode(&request(MAC_A, 3, addr, vec![])).unwrap();
    broadcast.flags = FLAG_BROADCAST;
    let out = s.handle(Input::Packet(broadcast.encode()), 40_000);
    assert_eq!(sends(&out)[0].0, Destination::Unicast(addr), "ciaddr wins over the broadcast flag");
}
#[test]
fn restored_lease_is_renewed_not_granted_after_a_reboot() {
    let record = LeaseRecord { address: ip("192.168.1.120"), mac: MAC_A, client_id: None, hostname: Some("pc".into()), granted_at: 0, expires_at: 40_000 };
    let mut s = Server::new(config(), vec![record], 100);
    let out = s.handle(Input::Packet(request(MAC_A, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::RequestedIpAddress(ip("192.168.1.120"))])), 100);
    assert!(matches!(events(&out)[0], ServerEvent::Renewed(ref r) if r.hostname.as_deref() == Some("pc")));
}
#[test]
fn inform_is_acked_with_options_and_no_lease_time() {
    let mut s = Server::new(config(), vec![], 0);
    let out = s.handle(Input::Packet(inform(MAC_A, 9, ip("192.168.1.50"))), 0);
    let (to, ack) = sends(&out).remove(0);
    assert_eq!(to, Destination::Unicast(ip("192.168.1.50")));
    assert_eq!((ack.yiaddr, ack.ciaddr), (Ipv4Addr::UNSPECIFIED, ip("192.168.1.50")));
    assert_eq!(ack.option(6), Some(&DhcpOption::DomainNameServer(vec![ip("192.168.1.1")])));
    assert_eq!(ack.option(51), None);
    assert_eq!(events(&out), vec![ServerEvent::Informed { address: ip("192.168.1.50"), mac: MAC_A }]);
    assert!(s.leases().is_empty());
}
#[test]
fn release_frees_and_decline_abandons() {
    let mut s = Server::new(config(), vec![], 0);
    let addr = offered(&mut s, MAC_A);
    s.handle(Input::Packet(request(MAC_A, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::ServerIdentifier(ip("192.168.1.1")), DhcpOption::RequestedIpAddress(addr)])), 3);
    let out = s.handle(Input::Packet(release(MAC_A, 2, addr)), 10);
    assert!(matches!(events(&out)[0], ServerEvent::Released(ref r) if r.address == addr));
    assert!(s.leases().is_empty());
    let addr2 = offered(&mut s, MAC_B);
    assert_eq!(addr2, addr, "released addresses are free at once");
    let out = s.handle(Input::Packet(decline(MAC_B, 3, addr2)), 12);
    assert_eq!(events(&out), vec![ServerEvent::Declined { address: addr2, mac: MAC_B }]);
    assert_ne!(offered(&mut s, MAC_C), addr2, "a declined address is abandoned");
}
#[test]
fn leases_expire_on_timeout() {
    let mut s = Server::new(config(), vec![], 0);
    let addr = offered(&mut s, MAC_A);
    s.handle(Input::Packet(request(MAC_A, 1, Ipv4Addr::UNSPECIFIED, vec![DhcpOption::ServerIdentifier(ip("192.168.1.1")), DhcpOption::RequestedIpAddress(addr)])), 3);
    assert!(s.handle(Input::Timeout, 43_202).is_empty());
    let out = s.handle(Input::Timeout, 43_203);
    assert!(matches!(events(&out)[0], ServerEvent::Expired(ref r) if r.address == addr));
    assert!(s.leases().is_empty());
}
#[test]
fn client_identifiers_are_echoed_and_distinguish_clients_with_one_mac() {
    let mut s = Server::new(config(), vec![], 0);
    let id1 = DhcpOption::ClientIdentifier(vec![0xff, 1, 2, 3, 4, 0, 3, 0, 1, 1, 2, 3, 4, 5, 6]);
    let id2 = DhcpOption::ClientIdentifier(vec![0xff, 9, 9, 9, 9, 0, 3, 0, 1, 1, 2, 3, 4, 5, 6]);
    s.handle(Input::Packet(discover(MAC_A, 1, vec![id1.clone()])), 0);
    let a = sends(&s.handle(Input::Timeout, 1))[0].1.clone();
    assert_eq!(a.option(61), Some(&id1));
    s.handle(Input::Packet(discover(MAC_A, 2, vec![id2.clone()])), 2);
    let b = sends(&s.handle(Input::Timeout, 3))[0].1.clone();
    assert_ne!(a.yiaddr, b.yiaddr);
}
#[test]
fn hostnames_are_sanitised_to_labels() {
    assert_eq!(sanitise_hostname("Andy's iPhone"), Some("andy-s-iphone".into()));
    assert_eq!(sanitise_hostname("nas.local"), Some("nas".into()));
    assert_eq!(sanitise_hostname("  "), None);
    assert_eq!(sanitise_hostname("--x--"), Some("x".into()));
    assert_eq!(sanitise_hostname("Ünïcödé"), Some("n-c-d".into()));
    assert_eq!(sanitise_hostname(&"a".repeat(70)), Some("a".repeat(63)));
    assert_eq!(sanitise_hostname(&format!("{}-", "a".repeat(62))), Some("a".repeat(62)));
}
```

- [ ] **Step 2: Run them, watch them fail**

Run: `cargo test -p openfeo-proto-dhcp4 server`
Expected: the twelve new tests fail (no ACK/NAK produced, `sanitise_hostname` returns `None`); Task 1's still pass.

- [ ] **Step 3: Implement the REQUEST classification, NAK, INFORM, RELEASE, DECLINE, expiry and `sanitise_hostname`**

- [ ] **Step 4: Run the whole crate's tests, watch them pass**

Run: `cargo test -p openfeo-proto-dhcp4`
Expected: all pass (client tests untouched).

- [ ] **Step 5: Re-run the server fuzz target for 60 s with the new paths**

Run: `cd fuzz && cargo +nightly fuzz run dhcp4_server -- -max_total_time=60`
Expected: `Done`, no artifacts.

- [ ] **Step 6: Commit**

```bash
git add crates/openfeo-proto-dhcp4
git commit -s -m "dhcp4: server core acknowledges, refuses, informs, releases, declines and expires leases"
```

### Task 3: Configuration: `[lans.dhcp]`, static leases, the lease file, first-boot defaults, lab fixtures

**Files:**
- Modify: `proto/openfeo/v1/config.proto`, `crates/openfeo-config/src/lib.rs` (re-export `Dhcp4ServerLease, Dhcp4ServerLeases, LanDhcp, StaticLease`), `crates/openfeo-config/src/validate.rs`, `crates/openfeo-config/src/file.rs`, `crates/openfeo-config/src/load.rs`
- Modify: `harness/fixtures/vm-static.toml`, `harness/fixtures/vm-dhcp.toml`
- Test: unit tests in `validate.rs`, `file.rs`, `load.rs`

**Interfaces:**
- Produces:

```proto
message Lan { /* existing 1..3 */ LanDhcp dhcp = 4; }  // present = the LAN runs a DHCPv4 server
message LanDhcp {
  repeated string range = 1;       // exactly two host addresses of the LAN subnet, first <= last, the router outside
  uint32 lease_secs = 2;           // 0 means 43200; otherwise at least 60
  repeated StaticLease static = 3;
  repeated string dns = 4;         // DNS servers handed out; empty means the router
}
message StaticLease { string mac = 1; string ip = 2; string hostname = 3; string client_id = 4; }  // client_id: optional lowercase hex
message Dhcp4ServerLease { string mac = 1; string client_id = 2; string address = 3; string hostname = 4; uint64 granted_unix = 5; uint64 expires_unix = 6; }
message Dhcp4ServerLeases { string lan = 1; repeated Dhcp4ServerLease leases = 2; }
```

```rust
// validate.rs: new codes and their as_str
Code::InvalidRange => "invalid_range",            // not two addresses, unparsable, or first > last
Code::RangeOutsideSubnet => "range_outside_subnet", // an end is not a host address of the LAN subnet
Code::RouterInRange => "router_in_range",
Code::LeaseTooShort => "lease_too_short",          // 1..60
Code::InvalidMac => "invalid_mac",
Code::StaticOutsideSubnet => "static_outside_subnet", // not a host address of the subnet, or the router's
Code::DuplicateStatic => "duplicate_static",        // mac or ip used twice within one LAN
Code::InvalidClientId => "invalid_client_id",       // not hex of 1..=255 bytes
// hostname: Code::InvalidHostname with is_valid_label (one label, [A-Za-z0-9-]{1,63}, no leading/trailing hyphen)
pub fn is_valid_label(name: &str) -> bool;
pub fn parse_mac(text: &str) -> Option<[u8; 6]>;     // "aa:bb:cc:dd:ee:ff", case-insensitive
fn lan_dhcp(report: &mut Report, path: &str, net: Ipv4Net, dhcp: &LanDhcp);
// file.rs
pub fn parse_dhcp4_server_leases(text: &str) -> Result<Dhcp4ServerLeases, ConfigError>;
pub fn render_dhcp4_server_leases(leases: &Dhcp4ServerLeases) -> Result<String, ConfigError>;
// load.rs
pub const FIRST_BOOT_POOL: (&str, &str) = ("192.168.1.100", "192.168.1.250");
// Config::first_boot's LAN gets dhcp: Some(LanDhcp { range: [FIRST_BOOT_POOL.0, FIRST_BOOT_POOL.1], ..Default::default() })
```

Paths in violations: `lans[0].dhcp.range`, `lans[0].dhcp.lease_secs`, `lans[0].dhcp.static[1].mac`, `lans[0].dhcp.static[1].ip`, `lans[0].dhcp.static[1].hostname`, `lans[0].dhcp.static[1].client_id`, `lans[0].dhcp.dns[0]` (`Code::InvalidAddress`). When `lans[i].ipv4` itself is invalid, `lan_dhcp` is skipped.

Fixtures: both `vm-static.toml` and `vm-dhcp.toml` gain, after `ipv4 = "192.168.1.1/24"`:

```toml
[lans.dhcp]
range = ["192.168.1.100", "192.168.1.200"]
lease_secs = 43200
[[lans.dhcp.static]]
mac = "52:54:00:fe:10:10"
ip = "192.168.1.10"
hostname = "nas"
```

- [ ] **Step 1: Write the failing validation tests** (helpers: `with_dhcp(fragment) -> Config` parses `"config_version = 1\n[[lans]]\nname = \"lan0\"\nports = [\"p2\"]\nipv4 = \"192.168.1.1/24\"\n[lans.dhcp]\n{fragment}"`, a minimal config with no WANs so the only violations are the DHCP block's; `codes(violations) -> Vec<(String, Code)>`)

```rust
#[test]
fn fixture_dhcp_sections_are_valid() {
    for fixture in [VM_STATIC, VM_DHCP] { assert_eq!(validate(&file::parse(fixture).unwrap(), &portmap()), vec![]); }
}
#[test]
fn range_must_be_two_ordered_host_addresses_of_the_subnet_without_the_router() {
    assert_eq!(codes(&validate(&with_dhcp(r#"range = ["192.168.1.100"]"#), &portmap())), vec![("lans[0].dhcp.range".into(), Code::InvalidRange)]);
    assert_eq!(codes(&validate(&with_dhcp(r#"range = ["192.168.1.200", "192.168.1.100"]"#), &portmap())), vec![("lans[0].dhcp.range".into(), Code::InvalidRange)]);
    assert_eq!(codes(&validate(&with_dhcp(r#"range = ["192.168.1.0", "192.168.1.255"]"#), &portmap())), vec![("lans[0].dhcp.range".into(), Code::RangeOutsideSubnet)]);
    assert_eq!(codes(&validate(&with_dhcp(r#"range = ["192.168.2.10", "192.168.2.20"]"#), &portmap())), vec![("lans[0].dhcp.range".into(), Code::RangeOutsideSubnet)]);
    assert_eq!(codes(&validate(&with_dhcp(r#"range = ["192.168.1.1", "192.168.1.20"]"#), &portmap())), vec![("lans[0].dhcp.range".into(), Code::RouterInRange)]);
}
#[test]
fn lease_secs_zero_is_the_default_and_under_60_is_refused() {
    assert!(validate(&with_dhcp(r#"range = ["192.168.1.100", "192.168.1.200"]"#), &portmap()).is_empty());
    assert_eq!(codes(&validate(&with_dhcp("range = [\"192.168.1.100\", \"192.168.1.200\"]\nlease_secs = 30"), &portmap())), vec![("lans[0].dhcp.lease_secs".into(), Code::LeaseTooShort)]);
}
#[test]
fn statics_need_a_mac_a_host_address_a_label_and_no_duplicates() {
    let bad = "range = [\"192.168.1.100\", \"192.168.1.200\"]\n[[lans.dhcp.static]]\nmac = \"zz:00\"\nip = \"192.168.1.1\"\nhostname = \"nas.home\"\nclient_id = \"abc\"\n[[lans.dhcp.static]]\nmac = \"52:54:00:fe:10:10\"\nip = \"192.168.1.10\"\nhostname = \"nas\"\n[[lans.dhcp.static]]\nmac = \"52:54:00:FE:10:10\"\nip = \"192.168.1.11\"\nhostname = \"nas2\"\n[[lans.dhcp.static]]\nmac = \"52:54:00:fe:10:11\"\nip = \"192.168.1.10\"\nhostname = \"nas3\"\n";
    assert_eq!(codes(&validate(&with_dhcp(bad), &portmap())), vec![
        ("lans[0].dhcp.static[0].mac".into(), Code::InvalidMac),
        ("lans[0].dhcp.static[0].ip".into(), Code::StaticOutsideSubnet),
        ("lans[0].dhcp.static[0].hostname".into(), Code::InvalidHostname),
        ("lans[0].dhcp.static[0].client_id".into(), Code::InvalidClientId),
        ("lans[0].dhcp.static[2].mac".into(), Code::DuplicateStatic),
        ("lans[0].dhcp.static[3].ip".into(), Code::DuplicateStatic),
    ]);
}
#[test]
fn dns_entries_must_be_addresses() {
    assert_eq!(codes(&validate(&with_dhcp("range = [\"192.168.1.100\", \"192.168.1.200\"]\ndns = [\"1.1.1.1\", \"dns.example\"]"), &portmap())), vec![("lans[0].dhcp.dns[1]".into(), Code::InvalidAddress)]);
}
#[test]
fn labels_and_macs_parse() {
    assert!(is_valid_label("nas") && is_valid_label("Nas-2") && !is_valid_label("-nas") && !is_valid_label("nas.home") && !is_valid_label(&"a".repeat(64)));
    assert_eq!(parse_mac("52:54:00:FE:10:10"), Some([0x52, 0x54, 0, 0xfe, 0x10, 0x10]));
    assert_eq!(parse_mac("52-54-00-fe-10-10"), None);
}
```

And in `file.rs`:

```rust
#[test]
fn dhcp4_server_leases_round_trip() {
    let leases = Dhcp4ServerLeases { lan: "lan0".into(), leases: vec![Dhcp4ServerLease { mac: "52:54:00:fe:10:10".into(), client_id: String::new(), address: "192.168.1.10".into(), hostname: "nas".into(), granted_unix: 1_800_000_000, expires_unix: 1_800_043_200 }] };
    let text = render_dhcp4_server_leases(&leases).unwrap();
    assert!(text.contains("[[leases]]"), "{text}");
    assert_eq!(parse_dhcp4_server_leases(&text).unwrap(), leases);
    assert!(parse_dhcp4_server_leases("lan = \"lan0\"\nbogus = 1\n").is_err(), "unknown keys are refused");
}
```

And in `load.rs`:

```rust
#[test]
fn first_boot_serves_dhcp_on_the_temporary_lan() {
    let config = Config::first_boot(&portmap_of(["p0", "p1"]));
    let dhcp = config.lans[0].dhcp.as_ref().expect("DHCP on at first boot (SPEC §5.6)");
    assert_eq!(dhcp.range, vec!["192.168.1.100", "192.168.1.250"]);
    assert_eq!((dhcp.lease_secs, dhcp.r#static.len(), dhcp.dns.len()), (0, 0, 0));
    assert!(validate(&config, &portmap_of(["p0", "p1"])).is_empty());
}
```

- [ ] **Step 2: Run them, watch them fail**

Run: `cargo test -p openfeo-config`
Expected: compile errors (`LanDhcp`, `Code::InvalidRange`, `parse_dhcp4_server_leases` missing).

- [ ] **Step 3: Add the proto messages, regenerate, implement the validation, the file helpers, the first-boot default, and extend both fixtures**

- [ ] **Step 4: Run the config tests and the whole unit suite, watch them pass**

Run: `make test`
Expected: all pass. `openfeo-reconcile` snapshots are unchanged (links, routing and nft do not read `[lans.dhcp]`).

- [ ] **Step 5: Run lint**

Run: `make lint`
Expected: green, including `buf breaking`.

- [ ] **Step 6: Commit**

```bash
git add proto crates/openfeo-config harness/fixtures
git commit -s -m "config: [lans.dhcp] pool, lease time, static leases and DNS; DHCPv4 server lease file; DHCP on at first boot"
```

### Task 4: World lease facts and the pure `reconcile::dhcp`

**Files:**
- Create: `crates/openfeo-world/src/leases.rs`; Modify: `crates/openfeo-world/src/lib.rs` (`pub mod leases; pub use leases::LeaseFact;`), `crates/openfeo-world/src/world.rs` (`pub leases: Arc<BTreeMap<String, Vec<LeaseFact>>>`, initialised empty in `World::new`)
- Modify every `World { .. }` literal: `crates/openfeo-reconcile/src/fixtures.rs` (`world()`), `harness/tests/netlink.rs` (`world_from`)
- Create: `crates/openfeo-reconcile/src/dhcp.rs`; Modify: `crates/openfeo-reconcile/src/lib.rs` (`pub mod dhcp;`), `crates/openfeo-reconcile/Cargo.toml` (add `openfeo-proto-dhcp4 = { path = "../openfeo-proto-dhcp4" }`, pure)
- Create: snapshots under `crates/openfeo-reconcile/src/snapshots/`
- Test: unit tests in `dhcp.rs`

**Interfaces:**
- Consumes: `openfeo_config::{LanDhcp, StaticLease}`, `validate::parse_mac`, `server::{DEFAULT_LEASE_SECS, ServerConfig, Reservation}`, `load::DEFAULT_DOMAIN`.
- Produces:

```rust
// openfeo-world/src/leases.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseFact { pub address: Ipv4Addr, pub mac: MacAddr, pub hostname: Option<String>, pub expires_unix: u64 }
// openfeo-reconcile/src/dhcp.rs
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredReservation { pub mac: [u8; 6], pub client_id: Option<Vec<u8>>, pub address: Ipv4Addr, pub hostname: Option<String> }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredDhcpServer { pub ifname: String, pub server: Ipv4Addr, pub prefix: u8, pub pool: (Ipv4Addr, Ipv4Addr), pub lease_secs: u32, pub dns: Vec<Ipv4Addr>, pub domain: Option<String>, pub reservations: Vec<DesiredReservation> }
pub fn servers(world: &World) -> BTreeMap<String, DesiredDhcpServer>;   // keyed by LAN name; `ifname` is bridge_name(lan); LANs without `dhcp`, with unparsable `ipv4`/range/statics contribute nothing or skip the bad static (validation already refused them); lease_secs 0 → DEFAULT_LEASE_SECS; dns empty → [server]; domain = system.domain, else DEFAULT_DOMAIN
pub fn server_config(desired: &DesiredDhcpServer) -> ServerConfig;      // field copy
```

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn static_lan_serves_its_pool_with_the_nas_reservation() {
    let desired = servers(&fixtures::static_world());
    insta::assert_yaml_snapshot!(desired);
    let lan0 = &desired["lan0"];
    assert_eq!((lan0.ifname.as_str(), lan0.server, lan0.prefix), ("br-lan0", Ipv4Addr::new(192, 168, 1, 1), 24));
    assert_eq!(lan0.pool, (Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 1, 200)));
    assert_eq!((lan0.lease_secs, lan0.domain.as_deref()), (43_200, Some("home.arpa")));
    assert_eq!(lan0.dns, vec![Ipv4Addr::new(192, 168, 1, 1)]);
    assert_eq!(lan0.reservations, vec![DesiredReservation { mac: [0x52, 0x54, 0, 0xfe, 0x10, 0x10], client_id: None, address: Ipv4Addr::new(192, 168, 1, 10), hostname: Some("nas".into()) }]);
    let config = server_config(lan0);
    assert_eq!((config.server, config.pool, config.lease_secs, config.reservations.len()), (lan0.server, lan0.pool, 43_200, 1));
}
#[test]
fn first_boot_lan_serves_the_default_pool() {
    let desired = servers(&fixtures::first_boot_world());
    insta::assert_yaml_snapshot!(desired);
    assert_eq!(desired["lan0"].pool, (Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 1, 250)));
    assert_eq!(desired["lan0"].lease_secs, 43_200);
}
#[test]
fn a_lan_without_dhcp_serves_nothing() {
    let mut world = fixtures::static_world();
    Arc::make_mut(&mut world.config).lans[0].dhcp = None;
    assert!(servers(&world).is_empty());
}
#[test]
fn configured_dns_and_a_client_id_reservation_pass_through() {
    let mut world = fixtures::static_world();
    let dhcp = Arc::make_mut(&mut world.config).lans[0].dhcp.as_mut().unwrap();
    dhcp.dns = vec!["1.1.1.1".into(), "9.9.9.9".into()];
    dhcp.r#static.push(StaticLease { mac: "52:54:00:fe:10:11".into(), ip: "192.168.1.11".into(), hostname: String::new(), client_id: "ff01020304".into() });
    let lan0 = &servers(&world)["lan0"];
    assert_eq!(lan0.dns, vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)]);
    assert_eq!(lan0.reservations[1], DesiredReservation { mac: [0x52, 0x54, 0, 0xfe, 0x10, 0x11], client_id: Some(vec![0xff, 1, 2, 3, 4]), address: Ipv4Addr::new(192, 168, 1, 11), hostname: None });
}
```

- [ ] **Step 2: Run them, watch them fail**

Run: `cargo test -p openfeo-reconcile dhcp`
Expected: compile error, `dhcp` module missing.

- [ ] **Step 3: Implement `leases.rs`, the `World.leases` field (fix both literals), `dhcp.rs`**

- [ ] **Step 4: Run and accept the two snapshots, then run the workspace tests**

Run: `INSTA_UPDATE=always cargo test -p openfeo-reconcile && make test`
Expected: all pass; the two new `.snap` files exist and read as the assertions say.

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-world crates/openfeo-reconcile harness/tests/netlink.rs
git commit -s -m "world: LAN lease facts; reconcile: per-LAN DHCPv4 server settings from the config"
```

### Task 5: The server driver in `openfeo-net`

**Files:**
- Create: `crates/openfeo-net/src/dhcp4_server.rs`; Modify: `crates/openfeo-net/src/lib.rs` (`pub mod dhcp4_server;`), `crates/openfeo-net/src/dhcp4.rs` (`DriverError`, `socket_err`, `io_err`, `is_transient`, `wait_until`, `RECEIVE_BUFFER` become `pub(crate)`; `DriverError` gains `#[error("no address for the interface yet: {0}")] Unaddressed(std::io::Error)`? No: sends that fail are logged, see below)
- Test: unit tests in `dhcp4_server.rs` (pure helpers); the sockets are exercised by Task 7's sandbox suite

**Interfaces:**
- Consumes: Task 1/2's `server::{Server, ServerConfig, LeaseRecord, Input, Output, Destination, ServerEvent, Timestamp}`, `arp::{ArpPacket, ArpOp, request, ETH_P_ARP}`, `udp::encapsulate`, `sys::{link_addr, register}`.
- Produces:

```rust
pub struct ServerDriverConfig { pub ifname: String, pub ifindex: u32, pub mac: [u8; 6], pub server: ServerConfig, pub leases: Vec<LeaseRecord> }
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerStats { pub received: u32, pub sent: u32, pub probes: u32 }
pub struct ServerDriver { /* config, server: Server, udp: UdpSocket, packet: AsyncFd<OwnedFd>, start: Instant, stats, pending: Vec<ServerEvent> */ }
impl ServerDriver {
    pub fn new(config: ServerDriverConfig) -> Result<ServerDriver, DriverError>;  // inside a tokio runtime
    pub async fn step(&mut self) -> Result<Vec<ServerEvent>, DriverError>;
    pub fn now(&self) -> Timestamp;             // seconds since `new`
    pub fn leases(&self) -> Vec<LeaseRecord>;
    pub fn stats(&self) -> ServerStats;
}
pub(crate) fn probe_reply(frame: &[u8]) -> Option<Input>;   // ARP Reply → Input::ProbeReply { address: sender_ip, mac: sender_mac }; requests and junk → None
pub(crate) fn socket_target(to: Destination) -> Option<SocketAddrV4>;  // Broadcast → 255.255.255.255:68, Unicast(ip) → ip:68, Link → None (goes out the packet socket)
```

Sockets in `new`: UDP `AF_INET SOCK_DGRAM` non-blocking, `SO_REUSEADDR`, `SO_BROADCAST`, `SO_BINDTODEVICE ifname`, bound `0.0.0.0:67`, wrapped in `tokio::net::UdpSocket`; packet `AF_PACKET SOCK_DGRAM` non-blocking bound with `link_addr(ifindex, ETH_P_ARP, None)` and registered with `sys::register`. `step`: `select!` over UDP readable (`recv_from` into `RECEIVE_BUFFER`; datagrams whose source port is not 68 or 67 are still accepted, only the payload matters) → `Input::Packet`; packet readable (`recv` → `probe_reply`) → `Input::ProbeReply` when `Some`; `wait_until(next_timeout)` → `Input::Timeout`. Outputs: `Send { to: Link { ip, mac }, payload }` → `sendto(packet, udp::encapsulate(server, ip, 67, 68, payload), link_addr(ifindex, 0x0800, Some(mac)))` (the socket's bound protocol is ARP, the address's `sll_protocol` makes the frame IPv4); other `Send` → `udp.try_send_to(payload, socket_target(to))`; `Probe { address }` → `sendto(packet, arp::request(mac, server, address).encode(), link_addr(ifindex, ETH_P_ARP, Some([0xff; 6])))`; `Event(e)` → returned. Sends that fail log at `warn` (the LAN address may not be on the bridge yet; clients retransmit); receive errors that `is_transient` log at `warn` and wait 1 s; others are fatal.

- [ ] **Step 1: Write the failing unit tests**

```rust
#[test]
fn arp_replies_become_probe_inputs_and_requests_do_not() {
    let reply = ArpPacket { op: ArpOp::Reply, sender_mac: [9; 6], sender_ip: "192.168.1.100".parse().unwrap(), target_mac: [1; 6], target_ip: "192.168.1.1".parse().unwrap() };
    assert_eq!(probe_reply(&reply.encode()), Some(Input::ProbeReply { address: "192.168.1.100".parse().unwrap(), mac: [9; 6] }));
    assert_eq!(probe_reply(&arp::request([9; 6], "192.168.1.100".parse().unwrap(), "192.168.1.1".parse().unwrap()).encode()), None);
    assert_eq!(probe_reply(&[0; 5]), None);
}
#[test]
fn destinations_map_to_socket_targets() {
    assert_eq!(socket_target(Destination::Broadcast), Some(SocketAddrV4::new(Ipv4Addr::BROADCAST, 68)));
    assert_eq!(socket_target(Destination::Unicast("192.168.1.50".parse().unwrap())), Some(SocketAddrV4::new("192.168.1.50".parse().unwrap(), 68)));
    assert_eq!(socket_target(Destination::Link { ip: Ipv4Addr::UNSPECIFIED, mac: [0; 6] }), None);
}
```

- [ ] **Step 2: Run them, watch them fail**

Run: `cargo test -p openfeo-net dhcp4_server`
Expected: compile error, module missing.

- [ ] **Step 3: Implement `dhcp4_server.rs` as the Interfaces block says; make the shared items in `dhcp4.rs` `pub(crate)`**

- [ ] **Step 4: Run the crate's tests and lint**

Run: `cargo test -p openfeo-net && make lint`
Expected: pass; `scripts/check-deps.sh` still ok (no new dependencies).

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-net
git commit -s -m "net: DHCPv4 server driver on a bound UDP socket and an ARP packet socket"
```

### Task 6: The router's DHCP server task: facts, console lines, the lease database

**Files:**
- Create: `crates/openfeo/src/dhcp4_server.rs`; Modify: `crates/openfeo/src/main.rs` (`mod dhcp4_server;`), `crates/openfeo/src/router.rs` (call `crate::dhcp4_server::spawn_all(&supervisor, &publisher, &world_rx);` right after the client's `spawn_all`), `crates/openfeo/src/dhcp4.rs` (`LEASES_DIR` is already `pub`; make `mac_text` `pub(crate)`)
- Test: unit tests in `dhcp4_server.rs`

**Interfaces:**
- Consumes: `openfeo_reconcile::dhcp::{servers, server_config}`, `openfeo_net::dhcp4_server::{ServerDriver, ServerDriverConfig}`, `openfeo_config::{Dhcp4ServerLease, Dhcp4ServerLeases, file}`, `openfeo_world::LeaseFact`, `openfeo_platform::atomic`, `STATE_FILE_MODE`, `Publisher::update`, `Supervisor::spawn`, `TaskError`.
- Produces:

```rust
pub const SAVE_INTERVAL: Duration = Duration::from_secs(5);   // SPEC §5.2
pub fn server_lease_path(lan: &str) -> PathBuf;                 // /state/leases/dhcp4-server-<lan>.toml
pub fn records_from_file(file: &Dhcp4ServerLeases, lan: &str, now: Timestamp, unix_now: u64) -> Vec<LeaseRecord>;  // other LAN's file → empty; expires_unix <= unix_now → dropped; unparsable mac/address → dropped; expires_at = now + (expires_unix - unix_now); granted_at = now.saturating_sub(unix_now.saturating_sub(granted_unix))
pub fn file_from_records(lan: &str, records: &[LeaseRecord], now: Timestamp, unix_now: u64) -> Dhcp4ServerLeases; // inverse; client_id as lowercase hex, "" when none
pub fn facts_from(records: &[LeaseRecord], now: Timestamp, unix_now: u64) -> Vec<LeaseFact>;   // ascending by address
pub fn next_save(last: Option<Instant>, now: Instant) -> Instant;  // max(now, last + SAVE_INTERVAL)
pub fn spawn_all(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx);   // one task "dhcp4-server-<lan>" per key of servers(&publisher.current())
fn serving_line(lan: &str, desired: &DesiredDhcpServer) -> String;
fn event_line(lan: &str, event: &ServerEvent) -> String;   // the contract lines of Global Constraints, without the "openfeo: " prefix (tracing adds it)
```

Task flow (`async fn run(lan: String, publisher: &Publisher, world_rx: WorldRx) -> Result<(), TaskError>`): wait until `world.links[bridge_name(lan)]` is up (index, MAC), as `dhcp4::wait_for_link` does for a port (reuse it by making it `pub(crate)`); `desired = servers(&world)[lan]` (gone → return Ok, the task ends); read the lease file with `records_from_file` (a missing or unreadable file logs at `debug`/`warn` and means no leases); build the driver; log `serving_line` and, when records are not empty, `lan {lan} dhcp restored {n} leases`; loop `select!` over `driver.step()`, `world_rx.changed()` (restart the task when the bridge's index changes, as the client task does), and a save timer (`Some(deadline)` while dirty). For each event: `info!("{}", event_line(..))`; on `Granted | Renewed | Released | Expired`: publish `world.leases[lan] = facts_from(driver.leases(), ..)` and mark dirty with `next_save(last_save, Instant::now())`; the save writes `file::render_dhcp4_server_leases(&file_from_records(..))` through `atomic::write(path, bytes, STATE_FILE_MODE)` after `create_dir_all(LEASES_DIR)`; failures log at `warn` and keep the task alive.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn lease_file_round_trips_through_records_with_wall_clock_conversion() {
    let records = vec![LeaseRecord { address: ip("192.168.1.10"), mac: MAC, client_id: Some(vec![0xff, 1, 2]), hostname: Some("nas".into()), granted_at: 100, expires_at: 43_300 }];
    let file = file_from_records("lan0", &records, 200, 1_800_000_200);
    assert_eq!(file.lan, "lan0");
    assert_eq!(file.leases[0], Dhcp4ServerLease { mac: "52:54:00:fe:10:10".into(), client_id: "ff0102".into(), address: "192.168.1.10".into(), hostname: "nas".into(), granted_unix: 1_800_000_100, expires_unix: 1_800_043_300 });
    assert_eq!(records_from_file(&file, "lan0", 0, 1_800_000_200), vec![LeaseRecord { granted_at: 0, expires_at: 43_100, ..records[0].clone() }]);
}
#[test]
fn restored_leases_outside_the_subnet_or_expired_are_dropped() {
    let file = Dhcp4ServerLeases { lan: "lan0".into(), leases: vec![
        Dhcp4ServerLease { mac: "52:54:00:fe:10:10".into(), address: "192.168.1.10".into(), expires_unix: 1_800_000_000, ..Default::default() },
        Dhcp4ServerLease { mac: "52:54:00:fe:10:11".into(), address: "10.0.0.5".into(), expires_unix: 1_800_009_000, ..Default::default() },
        Dhcp4ServerLease { mac: "nope".into(), address: "192.168.1.12".into(), expires_unix: 1_800_009_000, ..Default::default() },
        Dhcp4ServerLease { mac: "52:54:00:fe:10:13".into(), address: "192.168.1.13".into(), expires_unix: 1_800_009_000, ..Default::default() },
    ] };
    let records = records_from_file(&file, "lan0", 50, 1_800_000_100);
    assert_eq!(records.iter().map(|r| r.address.to_string()).collect::<Vec<_>>(), vec!["10.0.0.5", "192.168.1.13"], "the file keeps what parses and has not expired; the subnet check is Server::new's");
    assert_eq!(Server::new(config(), records, 50).leases().len(), 1, "Server::new drops 10.0.0.5");
    assert!(records_from_file(&file, "lan1", 50, 1_800_000_100).is_empty(), "another LAN's file is ignored");
}
#[test]
fn saves_are_at_most_one_per_interval() {
    let t0 = Instant::now();
    assert_eq!(next_save(None, t0), t0);
    assert_eq!(next_save(Some(t0), t0 + Duration::from_secs(1)), t0 + SAVE_INTERVAL);
    assert_eq!(next_save(Some(t0), t0 + Duration::from_secs(9)), t0 + Duration::from_secs(9));
}
#[test]
fn console_lines_follow_the_contract() {
    let record = LeaseRecord { address: ip("192.168.1.100"), mac: MAC_A, client_id: None, hostname: None, granted_at: 0, expires_at: 43_200 };
    assert_eq!(event_line("lan0", &ServerEvent::Offered { address: ip("192.168.1.100"), mac: MAC_A }), "lan lan0 dhcp offer 192.168.1.100 to 02:00:00:00:00:0a");
    assert_eq!(event_line("lan0", &ServerEvent::Granted(record.clone())), "lan lan0 dhcp lease granted 192.168.1.100 to 02:00:00:00:00:0a host=- lease=43200s");
    assert_eq!(event_line("lan0", &ServerEvent::Granted(LeaseRecord { hostname: Some("nas".into()), ..record.clone() })), "lan lan0 dhcp lease granted 192.168.1.100 to 02:00:00:00:00:0a host=nas lease=43200s");
    assert_eq!(event_line("lan0", &ServerEvent::Renewed(record.clone())), "lan lan0 dhcp lease renewed 192.168.1.100 to 02:00:00:00:00:0a");
    assert_eq!(event_line("lan0", &ServerEvent::Nak { address: ip("192.168.1.77"), mac: MAC_A, reason: NakReason::OutsidePool }), "lan lan0 dhcp nak 192.168.1.77 to 02:00:00:00:00:0a (outside pool)");
    assert_eq!(event_line("lan0", &ServerEvent::Informed { address: ip("192.168.1.50"), mac: MAC_A }), "lan lan0 dhcp inform 192.168.1.50 from 02:00:00:00:00:0a");
    assert_eq!(event_line("lan0", &ServerEvent::Released(record.clone())), "lan lan0 dhcp lease released 192.168.1.100 by 02:00:00:00:00:0a");
    assert_eq!(event_line("lan0", &ServerEvent::Declined { address: ip("192.168.1.100"), mac: MAC_A }), "lan lan0 dhcp declined 192.168.1.100 by 02:00:00:00:00:0a");
    assert_eq!(event_line("lan0", &ServerEvent::Expired(record)), "lan lan0 dhcp lease expired 192.168.1.100 of 02:00:00:00:00:0a");
    assert_eq!(event_line("lan0", &ServerEvent::Conflict { address: ip("192.168.1.100"), mac: MAC_B }), "lan lan0 dhcp conflict 192.168.1.100 answered by 02:00:00:00:00:0b");
    assert_eq!(event_line("lan0", &ServerEvent::Exhausted { mac: MAC_A }), "lan lan0 dhcp pool exhausted for 02:00:00:00:00:0a");
    let desired = &servers(&fixtures::static_world())["lan0"];   // fixtures are pub in openfeo-reconcile
    assert_eq!(serving_line("lan0", desired), "lan lan0 dhcp serving 192.168.1.0/24 pool 192.168.1.100-192.168.1.200 statics=1 lease=43200s");
}
#[test]
fn facts_carry_wall_clock_expiry_sorted_by_address() {
    let records = vec![
        LeaseRecord { address: ip("192.168.1.120"), mac: MAC_B, client_id: None, hostname: None, granted_at: 0, expires_at: 300 },
        LeaseRecord { address: ip("192.168.1.10"), mac: MAC_A, client_id: None, hostname: Some("nas".into()), granted_at: 0, expires_at: 500 },
    ];
    let facts = facts_from(&records, 100, 1_800_000_000);
    assert_eq!(facts[0], LeaseFact { address: ip("192.168.1.10"), mac: MacAddr(MAC_A), hostname: Some("nas".into()), expires_unix: 1_800_000_400 });
    assert_eq!(facts[1].expires_unix, 1_800_000_200);
}
```

- [ ] **Step 2: Run them, watch them fail**

Run: `cargo test -p openfeo dhcp4_server`
Expected: compile error, module missing.

- [ ] **Step 3: Implement the module and wire it into `router.rs`**

- [ ] **Step 4: Run the binary's tests, then build the image**

Run: `cargo test -p openfeo && make kernel`
Expected: tests pass; `build/bzImage` rebuilt with the new binary.

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo
git commit -s -m "openfeo: DHCPv4 server task per LAN with lease facts, console contract and a debounced lease database"
```

### Task 7: Harness LAN-side clients and the sandbox suite against the driver

**Files:**
- Modify: `harness/Cargo.toml` (move `openfeo-net`, `openfeo-proto-dhcp4`, `tokio` from dev-dependencies to dependencies; add `[[test]] name = "dhcp4_server" path = "tests/dhcp4_server.rs" harness = false`), `Makefile` (`test-harness` adds `--test dhcp4_server`)
- Modify: `harness/src/main.rs` (hidden subcommand `DhcpClient`; `check-env` tool list gains `busybox`), `harness/src/lanclient.rs` (`link_info`, `dhcp_client`, `inform`, `udhcpc`, `Udhcpc`), `harness/tests/dhcp4.rs` (use `lanclient::link_info` instead of its own copy)
- Modify: `.github/workflows/ci.yml` (apt adds `busybox-static`), `README.md` and `CLAUDE.md` tool lists (busybox: Arch `busybox`, Debian/Ubuntu `busybox-static`)
- Create: `harness/tests/dhcp4_server.rs`
- Test: the new suite; `lanclient` unit tests for the two parsers

**Interfaces:**
- Consumes: `openfeo_net::dhcp4::{Driver, DriverConfig, Event}` and `openfeo_net::dhcp4_server::{ServerDriver, ServerDriverConfig}`, `openfeo_proto_dhcp4::{ClientConfig, Lease, identity::*, wire}`, `openfeo_reconcile::dhcp::{servers, server_config}` and `openfeo_reconcile::fixtures::static_world` (dev-dependency), `NetNs::{command, ip}`, `netns::ip`, `Lines`.
- Produces:

```rust
// lanclient.rs
pub fn link_info(ifname: &str) -> Result<(u32, [u8; 6])>;    // from `ip -o link show <ifname>` (the sandbox's /sys is the host's)
/// Run `<harness_bin> dhcp-client --iface <iface> <args>` inside `ns`; one JSON object per line on stdout.
pub fn dhcp_client(harness_bin: &str, ns: &NetNs, iface: &str, args: &[&str], timeout: Duration) -> Result<Vec<serde_json::Value>>;
pub fn parse_json_lines(stdout: &str) -> Result<Vec<serde_json::Value>>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdhcpcEvent { pub kind: String, pub env: BTreeMap<String, String> }   // kind: deconfig | bound | renew | nak | leasefail
pub fn udhcpc(ns: &NetNs, iface: &str, run_dir: &Path, args: &[&str], timeout: Duration) -> Result<Vec<UdhcpcEvent>>;
pub fn parse_udhcpc_output(stdout: &str) -> Vec<UdhcpcEvent>;
// main.rs subcommand (hidden)
DhcpClient { #[arg(long)] iface: String, #[arg(long)] request: Option<Ipv4Addr>, #[arg(long)] hostname: Option<String>, #[arg(long)] until_renewed: bool, #[arg(long)] inform: Option<Ipv4Addr>, #[arg(long, default_value_t = 15)] timeout_secs: u64 }
```

`dhcp-client` prints one line per driver event: `{"event":"discover"}`, `{"event":"offer","address":"..","server":".."}`, `{"event":"request","address":".."}`, `{"event":"init-reboot","address":".."}`, `{"event":"bound","address":"..","prefix":24,"server":"..","gateway":".."|null,"dns":[..],"domain":".."|null,"lease_secs":n,"t1_secs":n,"t2_secs":n,"renewed":false}`, `{"event":"nak","message":".."|null}`, `{"event":"expired"}`, `{"event":"reboot-timed-out"}`; exits 0 after `bound` (after `bound` with `renewed: true` under `--until-renewed`), 2 at `--timeout-secs`. `--request IP` seeds `initial_lease` with `Lease { address: IP, prefix: 24, server: 0.0.0.0, lease_secs: 3600, t1_secs: 1800, t2_secs: 3150, ..empty }` so the core starts in INIT-REBOOT. `--inform CIADDR` instead sends one DHCPINFORM (xid from the clock, `ciaddr`, `chaddr`, PRL `[1, 3, 6, 15, 28]`) from a `std::net::UdpSocket` bound to `CIADDR:68` to `255.255.255.255:67` with `SO_BROADCAST`, waits up to the timeout for an ACK with the same xid and prints `{"event":"ack","router":[..],"dns":[..],"domain":".."|null,"mask":".."}`. The subcommand builds the tokio runtime itself (`#[tokio::main]` is not used in this binary; use `tokio::runtime::Builder::new_current_thread().enable_all()`).

`udhcpc` runs `busybox udhcpc -i <iface> -f -n -q -t 4 -T 3 -s <run_dir>/udhcpc.sh <args>` in `ns`, where the script is

```sh
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
echo "udhcpc-event $1"
env | sed 's/^/udhcpc-env /'
```

written mode 0755; `parse_udhcpc_output` groups each `udhcpc-event <kind>` with the `udhcpc-env k=v` lines that follow it. The script configures nothing: scenarios that need the lease on the interface call `ns.ip(&["addr", "replace", ..])` themselves.

Sandbox rig (`tests/dhcp4_server.rs`, modelled on `tests/dhcp4.rs`): veth `s0` in the sandbox namespace with `192.168.1.1/24` up, `s1` moved into `NetNs::create("<lab>-lan")`, MAC set with `ip link set s1 address 02:00:00:00:00:01`, up; the server driver built inside `tokio::runtime::Builder::new_current_thread()` from `server_config(&servers(&static_world())["lan0"])` with `ifname = "s0"`, `(ifindex, mac) = link_info("s0")`; `fn serve_until(driver, rt, until: impl FnMut(&[ServerEvent]) -> bool, timeout) -> Result<Vec<ServerEvent>>` steps the driver while a client runs in a thread (`std::thread::spawn` around `lanclient::dhcp_client`/`udhcpc`). `const HARNESS_BIN: &str = env!("CARGO_BIN_EXE_openfeo-harness");`

- [ ] **Step 1: Write the failing parser tests in `lanclient.rs`**

```rust
#[test]
fn udhcpc_output_groups_env_under_events() {
    let out = "udhcpc-event deconfig\nudhcpc-env interface=s1\nudhcpc-event bound\nudhcpc-env ip=192.168.1.100\nudhcpc-env router=192.168.1.1\nudhcpc-env dns=192.168.1.1\nudhcpc-env domain=home.arpa\nudhcpc-env lease=43200\n";
    let events = parse_udhcpc_output(out);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].kind, "bound");
    assert_eq!(events[1].env["ip"], "192.168.1.100");
    assert_eq!(events[1].env["domain"], "home.arpa");
}
#[test]
fn json_lines_parse_and_reject_junk() {
    assert_eq!(parse_json_lines("{\"event\":\"discover\"}\n{\"event\":\"bound\",\"address\":\"192.168.1.100\"}\n").unwrap()[1]["address"], "192.168.1.100");
    assert!(parse_json_lines("not json\n").is_err());
}
```

- [ ] **Step 2: Run them, watch them fail**

Run: `cargo test -p openfeo-harness --lib lanclient`
Expected: compile error (functions missing).

- [ ] **Step 3: Implement `lanclient` helpers, the `dhcp-client` subcommand, the `busybox` check, the CI apt line and the docs' tool lists**

- [ ] **Step 4: Run the parser tests and `make check-env`**

Run: `cargo test -p openfeo-harness --lib lanclient && make check-env`
Expected: tests pass; `busybox` reported `ok` (install the `busybox` package first on the dev host).

- [ ] **Step 5: Write the sandbox scenarios** (each `fn name(lab: &mut Lab) -> anyhow::Result<()>`, registered in `SCENARIOS`; `LEASE_TIMEOUT = 15 s`)

- `rust_client_gets_a_pool_lease_with_options`: `dhcp_client(HARNESS_BIN, &rig.ns, "s1", &["--hostname", "lanhost"], ..)` → the `bound` line has `address` in `192.168.1.100..=200`, `prefix 24`, `server "192.168.1.1"`, `gateway "192.168.1.1"`, `dns ["192.168.1.1"]`, `domain "home.arpa"`, `lease_secs 43200`, `t1_secs 21600`, `t2_secs 37800`; the events list runs `discover, offer, request, bound`; server events contain `Offered` then `Granted` with `hostname == Some("lanhost")`; `driver.leases().len() == 1`.
- `udhcpc_gets_a_lease` (reference client): `udhcpc(.., &[], ..)` → a `bound` event with `ip` in the pool, `subnet 255.255.255.0`, `router 192.168.1.1`, `dns 192.168.1.1`, `domain home.arpa`, `lease 43200`, `serverid 192.168.1.1`.
- `reservation_gives_the_nas_its_address`: `ip link set s1 address 52:54:00:fe:10:10` → `udhcpc` bound `ip == 192.168.1.10` and `hostname == nas`; server `Granted` record hostname `nas`.
- `init_reboot_is_confirmed_from_restored_leases`: a lease via `dhcp_client`; `let kept = driver.leases()`; drop the driver and build a new one with `leases: kept`; `dhcp_client(.., &["--request", &addr], ..)` → events `init-reboot, bound` with the same address and no `discover`; server events contain `Renewed` and no `Offered`.
- `a_foreign_address_is_naked_then_a_pool_address_granted`: `dhcp_client(.., &["--request", "192.168.1.77"], ..)` → events `init-reboot, nak, discover, offer, request, bound` with `bound.address` in the pool; server events contain `Nak { address: 192.168.1.77, reason: OutsidePool }`.
- `a_squatted_address_is_skipped_after_the_probe`: in the client namespace `ip link add squat0 link s1 type macvlan mode bridge`, `ip link set squat0 address 02:00:00:00:00:99 up`, `ip addr add 192.168.1.100/24 dev squat0`; `dhcp_client` → `bound.address == 192.168.1.101`; server events contain `Conflict { address: 192.168.1.100, mac: 02:..:99 }`.
- `inform_is_answered_with_options`: `ip addr add 192.168.1.50/24 dev s1`; `dhcp_client(.., &["--inform", "192.168.1.50"], ..)` → an `ack` line with `dns ["192.168.1.1"]`, `domain "home.arpa"`, `router ["192.168.1.1"]`; server events contain `Informed`; `driver.leases()` empty.
- `release_frees_the_address`: `udhcpc(.., &["-R"], ..)` (release on quit) → server events contain `Granted` then `Released`; `driver.leases()` empty afterwards.
- `two_clients_get_distinct_addresses`: `udhcpc` on `s1` and `dhcp_client` on a macvlan `c2` (MAC `02:00:00:00:00:02`, up) → two different pool addresses; `driver.leases().len() == 2`.
- `renewal_is_acked_at_t1`: a driver with `lease_secs = 60` (T1 = 30 s); `dhcp_client(.., &["--until-renewed", "--timeout-secs", "45"], ..)` → a `bound` line with `renewed: true`; server events contain `Renewed`; the renewal REQUEST reached the server as unicast (assert the second `Granted|Renewed` is `Renewed`).

- [ ] **Step 6: Run the suite, watch the first scenario fail before the rig exists, then make them pass**

Run: `cargo test -p openfeo-harness --test dhcp4_server`
Expected (first run): compile errors or a failed rig; final run: `result: ok. 10 passed; 0 failed; 0 skipped`.

- [ ] **Step 7: Run the client suite still green and lint**

Run: `cargo test -p openfeo-harness --test dhcp4 && make lint`
Expected: `5 passed`; lint green (`openfeo-harness` may depend on anything).

- [ ] **Step 8: Commit**

```bash
git add harness Makefile .github/workflows/ci.yml README.md CLAUDE.md
git commit -s -m "harness: LAN-side DHCP clients (dhcp-client subcommand, udhcpc) and the dhcp4_server sandbox suite"
```

### Task 8: QEMU acceptance scenarios and docs

**Files:**
- Modify: `harness/tests/m1.rs` (four new scenarios, one extended), `README.md` (status paragraph), `CLAUDE.md` (harness paragraph: the `dhcp4_server` suite and the two LAN clients)
- Test: the m1 suite

**Interfaces:**
- Consumes: Task 7's `lanclient::{udhcpc, dhcp_client}` and `HARNESS_BIN`; `Lab::{boot, with_config, console, qmp, lan0}`; the console contract lines; `VM_STATIC` (now with `[lans.dhcp]`); `lanclient::http_get`; `ISP_HTTP`.

Helpers in `m1.rs`: `const LAN_POOL: &str = r"192\.168\.1\.(?:1\d\d|200)";` `const NAS_MAC: &str = "52:54:00:fe:10:10";` `const SERVING: &str = r"openfeo: lan lan0 dhcp serving 192\.168\.1\.0/24 pool 192\.168\.1\.100-192\.168\.1\.200 statics=1 lease=43200s";` `fn boot_static_dhcp_lan(lab) -> anyhow::Result<Cursor>` (boot `VM_STATIC`, wait `READY` and `SERVING`, bring `lan0` up in the namespace without an address: `ip link set lan0 up`); `fn lan_mac(lab) -> anyhow::Result<String>` (`ip -o link show lan0` in the namespace, lowercase).

- [ ] **Step 1: Write the scenarios**

- `lan_client_gets_a_lease_from_the_router`: `boot_static_dhcp_lan`; `udhcpc(&lab.lan0, "lan0", &lab.run_dir, &[], 20 s)` → bound `ip` matches `LAN_POOL`, `router == 192.168.1.1`, `dns == 192.168.1.1`, `domain == home.arpa`, `lease == 43200`; console shows `openfeo: lan lan0 dhcp offer {ip} to {mac}` then `openfeo: lan lan0 dhcp lease granted {ip} to {mac} host=- lease=43200s` (mac from `lan_mac`); then `ip addr replace {ip}/24 dev lan0`, `ip route replace default via 192.168.1.1`, start the ISP HTTP target and `http_get` through NAT → body `ISP_HTTP_BODY` (the lease is usable).
- `reservation_gives_the_nas_its_address`: `boot_static_dhcp_lan`; `lab.lan0.ip(&["link", "set", "lan0", "address", NAS_MAC])` (down, set, up); `udhcpc` → `ip == 192.168.1.10`, `hostname == nas`; console `openfeo: lan lan0 dhcp lease granted 192\.168\.1\.10 to 52:54:00:fe:10:10 host=nas lease=43200s`.
- `lan_lease_db_survives_reset`: `boot_static_dhcp_lan`; `udhcpc` → `ip`; `lab.qmp()?.system_reset()`; wait `Linux version 6\.18\.59-openfeo`, mark `after_reset`, wait `openfeo: lan lan0 dhcp restored 1 leases` and `READY`; `udhcpc(.., &["-r", &ip], ..)` → bound with the same `ip`; console `openfeo: lan lan0 dhcp lease renewed {ip} to {mac}`; `count_since(&after_reset, "openfeo: lan lan0 dhcp offer") == 0`.
- `a_foreign_lease_is_naked_on_the_new_router`: `boot_static_dhcp_lan`; `udhcpc(.., &["-r", "192.168.1.77"], ..)` → events contain `nak` then `bound` with `ip` matching `LAN_POOL`; console `openfeo: lan lan0 dhcp nak 192\.168\.1\.77 to {mac} \(outside pool\)`.
- `first_boot_defaults_bridge_all_ports` gains, before the ping: `c.wait_for(&mut cur, &re(r"openfeo: lan lan0 dhcp serving 192\.168\.1\.0/24 pool 192\.168\.1\.100-192\.168\.1\.250 statics=0 lease=43200s"), SOON)?;`

- [ ] **Step 2: Run the new scenarios, read every failure**

Run: `make test-harness FILTER=lan_` then `make test-harness FILTER=first_boot`
Expected: the four new scenarios and the extended one pass. A failure here is a finding about the server, the driver or the task, not the test, unless the console regex is wrong.

- [ ] **Step 3: Update README status and CLAUDE.md**

README's status paragraph gains one sentence after the DHCP WAN sentence: "Each `[lans.dhcp]` LAN runs a DHCPv4 server with a pool, static reservations, DHCPINFORM, ARP conflict probes, authoritative NAKs and a lease database under `/state/leases`, published as facts; still to come in M1: the DNS forwarder and SNTP." CLAUDE.md's harness paragraph names the `dhcp4_server` sandbox suite and the two LAN clients (`openfeo-harness dhcp-client`, busybox `udhcpc`).

- [ ] **Step 4: Run everything CI runs**

Run: `make ci`
Expected: green; harness counts: dhcp4 5, dhcp4_server 10, m0 5, m1 19, netlink 15 (+1 skipped locally), nft 4 (+1 skipped locally).

- [ ] **Step 5: Commit**

```bash
git add harness/tests/m1.rs README.md CLAUDE.md
git commit -s -m "harness: LAN DHCPv4 scenarios (lease and NAT, reservation, lease database across a reset, foreign lease NAKed); docs"
```

---

## Self-review notes

- Spec coverage (§7.6): pool range and lease time (Tasks 1, 3); static leases by MAC, optionally client-id, with hostnames (1, 3, 4); options router/DNS/domain (1); NTP and classless routes are optional in the spec and not configurable in 3a (a ruling for the executor to ledger); DHCPINFORM (2); ARP probe before offer (1, 5); lease DB persisted per §5.2 and published as facts (6); hostnames sanitised (2). §12 acceptance "LAN client gets a lease" (8). §5.6 "DHCP on" at first boot (3, 8).
- Type consistency: `ServerEvent`, `LeaseRecord`, `Destination`, `NakReason` are defined once in Task 1 and only consumed afterwards; `DesiredDhcpServer`/`server_config` in Task 4 feed Tasks 6 and 7; `lanclient::dhcp_client`'s JSON keys are fixed in Task 7 and read in Task 8.
- Proportion: code blocks are tests and signatures; the only algorithm text is the allocation order and the REQUEST classification, which the tests do not fully determine on their own.
