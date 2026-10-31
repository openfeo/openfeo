# M1 Part 3b: DNS Forwarder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The router answers DNS for its LANs: local names from the lease facts and reservations, everything else through upstream resolvers that are typed in or learned from the active WAN, with a TTL cache, negative caching, EDNS0, TCP, rebinding protection, and a policy slot where Rustik Block's lists will go.

**Architecture:** A pure crate `openfeo-proto-dns` holds our own wire format (names with compression, EDNS0 OPT), a TTL cache with RFC 2308 negative caching, and a sans-IO forwarder core, `Forwarder::handle(Input, now) -> Vec<Output>` (SPEC §6.3), that owns the query pipeline: validate, local zone, policy, cache, forward with failover and a TCP retry on truncation, rebinding check, reply. A driver in `openfeo-net` owns one UDP socket and one TCP listener per LAN bridge (`SO_BINDTODEVICE`, so the box is never an open resolver) and the upstream sockets, feeding the core through an inbox. A pure `reconcile::dns` turns `[dns]`, `[system]`, the LAN reservations, the lease facts and the active WAN's learned servers into the forwarder's settings, and one router task reconfigures the running forwarder whenever they change (the WAN lease comes and goes). hickory-proto is a dev and fuzz dependency only (ADR-0015). SNTP is part 3c.

**Tech Stack:** Rust stable 2024, tokio (UDP, TCP, mpsc, oneshot), nix 0.30 (`SO_BINDTODEVICE`), prost/pbjson, insta, cargo-fuzz with hickory-proto 0.25 as the differential oracle; harness: dnsmasq 2.9x in authoritative-zone mode as the upstream, `dig` (bind) as the LAN-side client.

**Spec:** `SPEC.md` §7.7 (DNS forwarder), §7.6 (lease facts), §8.2 (`[dns]`), §9 (security), §10, §11, §12 M1 ("resolves `nas.home.arpa`"), §13 (crate purity), §15 (ADR item "hickory-proto vs in-tree DNS parser"). RFCs: 1034/1035 (wire format, compression), 2181 §9 (TC), 2308 (negative caching), 6891 (EDNS0), 8375 (`home.arpa`). Brainstorm with Andy on 2026-10-31: typed upstreams plus the WAN's learned servers by default, `use_wan_dns = false` for typed alone; a policy slot for Rustik Block's block and allow lists, not built now; DNS-over-TLS waits for M4's rustls. Part 3a's plan is the model for every layer.

## Global Constraints

- Every source file starts with `// SPDX-License-Identifier: GPL-2.0-or-later` and `// Copyright (C) 2026 Andrew Newton` (TOML/sh: `#`). Commits `git commit -s` as `Andrew Newton <andy@vitri.ltd>`, subject `<area>: <summary>`, trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_0116otzXyvDbuXkw4CsR8ExV`.
- `make lint` green: fmt, clippy pedantic as `-D warnings` on all targets and features, cargo-deny, SPDX, `scripts/check-deps.sh` (`openfeo-proto-dns` is pure: no tokio, libc, nix, socket2 or netlink crates in its tree; hickory-proto, whose tree carries `libc`, `url` and `idna`, is dev and fuzz only), `scripts/check-proto.sh` (add fields only).
- `#![forbid(unsafe_code)]` everywhere; this plan adds no `unsafe` (the sockets are plain `AF_INET` ones, `SO_BINDTODEVICE` through nix's safe `setsockopt`).
- No `unwrap`/`expect` outside tests; `thiserror` in libraries, `anyhow` in `crates/openfeo` and `harness/`; `std::process::Command` only in `harness/`.
- Every parser gets a fuzz target in this PR: `dns_message` and `dns_differential`, with checked-in seeds.
- Time inside the core is `Timestamp = u64` milliseconds on the driver's monotonic clock (DNS timers are sub-second); TTLs are seconds.
- The forwarder serves only the LAN: listeners are bound to the LAN bridges, never to the WAN, and the nft `input` chain (part 2a) already admits UDP and TCP 53 from LAN zones only.
- Console line contract (MACs and addresses as the kernel prints them; `{source}` is `configured`, `learned from {wan}`, or `configured, learned from {wan}`):
  - `dns listening on {ifname}[, {ifname}...]`
  - `dns upstreams {addr}[ {addr}...] ({source})`
  - `dns no upstreams: only local names resolve`
  - `dns local names {n}`
  - `dns upstream {addr} down`
  - `dns upstream {addr} up`
  - `dns rebind dropped {name} -> {addr} for {client}` (throttled, one per 10 s with a count)
- Reference tools: dnsmasq (Arch `dnsmasq`, Ubuntu `dnsmasq-base`) and `dig` (Arch `bind`, Ubuntu `bind9-dnsutils`) join `make check-env` and CI's package list; CI runs Ubuntu 24.04's dnsmasq 2.90 and `dig` 9.18, so the dnsmasq invocation uses only flags both have (`--auth-zone`, `--auth-server`, `--auth-soa`, `--auth-ttl`, `--host-record`, `--txt-record`, `--log-queries`, `--log-facility=-`).
- Branch `m1-3b` from `main` after the merge of PR #4 (`d714b92`); the plan is the first commit (`docs: M1 part 3b plan, the DNS forwarder`).

## Review Focus

1. Client queries of an unexpected shape, a query with zero or two questions, class CHAOS, opcode UPDATE, a 64 KiB TCP message, a truncated header, must get FORMERR, NOTIMP or REFUSED, never a panic and never a forward. Test `odd_queries_are_answered_with_an_error_and_never_forwarded` (Task 3).
2. A name under `home.arpa` that matches nothing, and a reverse lookup inside a LAN subnet, must never reach an upstream (RFC 8375 and RFC 1918 reverse zones leak a household's names otherwise). Test `home_arpa_and_lan_reverse_zones_never_go_upstream` (Task 3).
3. A rebinding answer that arrives through a CNAME chain must be dropped like a direct one, and an allow-listed name must cover its subdomains. Test `rebinding_through_a_cname_is_dropped_and_allowed_names_cover_subdomains` (Task 4).
4. An upstream reply whose id matches a pending query but whose question or source does not (a spoof or a collision) must be ignored. Test `replies_that_do_not_match_the_pending_query_are_ignored` (Task 4).
5. With no upstreams (WAN down, nothing typed in) remote names must fail fast with SERVFAIL, local names must keep resolving, and the console must say so once. Test `without_upstreams_remote_names_fail_fast_and_local_names_still_resolve` (Task 4).

---

### Task 1: `openfeo-proto-dns`: names and the wire format, with fuzz targets and ADR-0015

**Files:**
- Create: `crates/openfeo-proto-dns/Cargo.toml` (deps `thiserror`; dev-deps `hickory-proto` via a workspace entry `hickory-proto = { version = "0.25", default-features = false, features = ["std"] }` with a comment "dev and fuzz oracle only, never shipped", `openfeo-proto-dns` added to the root workspace members), `crates/openfeo-proto-dns/src/lib.rs` (`#![forbid(unsafe_code)]`, `pub mod name; pub mod wire;`, `pub type Timestamp = u64;` documented as milliseconds, `pub use name::Name; pub use wire::{Header, Message, Question, RData, Record};`), `crates/openfeo-proto-dns/src/name.rs`, `crates/openfeo-proto-dns/src/wire.rs`
- Create: `docs/adr/0015-in-tree-dns-parser.md`; Modify: `SPEC.md` §15 (tick "M1: `hickory-proto` vs in-tree DNS parser (ADR)" with "ADR-0015, 31 October 2026"), `docs/third-party.md` (hickory-proto as a test and fuzz dependency)
- Create: `fuzz/fuzz_targets/dns_message.rs`, `fuzz/fuzz_targets/dns_differential.rs`; Modify: `fuzz/Cargo.toml` (deps `openfeo-proto-dns`, `hickory-proto` as above; two `[[bin]]`), `fuzz/.gitignore` (the three-line pattern for `dns_message` and `dns_differential`)
- Modify: `scripts/check-deps.sh` needs nothing (`openfeo-proto-.*` is already pure)
- Test: unit tests in `name.rs` and `wire.rs`

**Interfaces:**
- Produces:

```rust
// name.rs
pub const MAX_NAME: usize = 255;   // wire bytes
pub const MAX_LABEL: usize = 63;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name { /* labels, ASCII-lowercased at construction; the root is zero labels */ }
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError { #[error("empty label")] EmptyLabel, #[error("label over 63 bytes")] LabelTooLong, #[error("name over 255 bytes")] NameTooLong }
impl Name {
    pub fn root() -> Name;
    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Name, NameError>;
    pub fn labels(&self) -> &[Vec<u8>];
    pub fn is_root(&self) -> bool;
    pub fn wire_len(&self) -> usize;                 // sum of (1 + label) + 1
    pub fn ends_with(&self, suffix: &Name) -> bool;  // equal or a subdomain
    pub fn join(&self, parent: &Name) -> Result<Name, NameError>;  // self's labels then parent's
    pub fn parent(&self) -> Option<Name>;
}
impl FromStr for Name { type Err = NameError; }  // "nas.home.arpa" or "nas.home.arpa."; "." and "" are the root; lowercases
impl fmt::Display for Name { /* "nas.home.arpa." with the trailing dot; the root is "." */ }
pub fn reverse_name(addr: Ipv4Addr) -> Name;  // "10.1.168.192.in-addr.arpa"
pub fn reverse_addr(name: &Name) -> Option<Ipv4Addr>;  // the inverse; None when not a full in-addr.arpa name

// wire.rs
pub const CLASS_IN: u16 = 1;
pub const CLASS_ANY: u16 = 255;
pub mod rtype { pub const A: u16 = 1; pub const NS: u16 = 2; pub const CNAME: u16 = 5; pub const SOA: u16 = 6; pub const PTR: u16 = 12; pub const MX: u16 = 15; pub const TXT: u16 = 16; pub const AAAA: u16 = 28; pub const SRV: u16 = 33; pub const OPT: u16 = 41; pub const ANY: u16 = 255; }
pub mod rcode { pub const NOERROR: u8 = 0; pub const FORMERR: u8 = 1; pub const SERVFAIL: u8 = 2; pub const NXDOMAIN: u8 = 3; pub const NOTIMP: u8 = 4; pub const REFUSED: u8 = 5; }
pub const OPCODE_QUERY: u8 = 0;
pub const UDP_PAYLOAD_PLAIN: usize = 512;
pub const EDNS_UDP_PAYLOAD: u16 = 1232;    // SPEC §7.7
pub const MAX_MESSAGE: usize = 65_535;
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Header { pub id: u16, pub response: bool, pub opcode: u8, pub authoritative: bool, pub truncated: bool, pub recursion_desired: bool, pub recursion_available: bool, pub authentic_data: bool, pub checking_disabled: bool, pub rcode: u8 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question { pub name: Name, pub qtype: u16, pub qclass: u16 }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns { pub udp_payload: u16, pub extended_rcode: u8, pub version: u8, pub dnssec_ok: bool, pub options: Vec<(u16, Vec<u8>)> }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr), Aaaa(Ipv6Addr), Cname(Name), Ns(Name), Ptr(Name),
    Mx { preference: u16, exchange: Name },
    Soa { mname: Name, rname: Name, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    Txt(Vec<Vec<u8>>),
    Srv { priority: u16, weight: u16, port: u16, target: Name },
    Opt(Edns),
    Other(Vec<u8>),   // any other type: raw RDATA, never compressed (RFC 3597)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record { pub name: Name, pub rtype: u16, pub class: u16, pub ttl: u32, pub rdata: RData }
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message { pub header: Header, pub questions: Vec<Question>, pub answers: Vec<Record>, pub authorities: Vec<Record>, pub additionals: Vec<Record> }
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError { #[error("{0} bytes is too short for a header")] TooShort(usize), #[error("message ends inside {0}")] Truncated(&'static str), #[error("bad compression pointer")] Pointer, #[error("{0}")] Name(#[from] NameError), #[error("bad OPT record")] Opt }
impl Message {
    pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError>;  // pointers must point backwards; trailing bytes after the last section are ignored
    pub fn encode(&self) -> Vec<u8>;                               // names compressed against earlier names (owner names and the RDATA names of NS, CNAME, PTR, MX, SOA, SRV); unbounded size
    pub fn encode_within(&self, max: usize) -> Vec<u8>;            // drops additionals (keeping an OPT), then authorities, then answers until it fits; TC set when an answer or authority was dropped (RFC 2181 §9)
    pub fn question(&self) -> Option<&Question>;
    pub fn edns(&self) -> Option<&Edns>;                           // the OPT record among the additionals
    pub fn max_udp_payload(&self) -> usize;                        // the client's: OPT's udp_payload (at least 512), else 512
    pub fn reply_to(query: &Message, rcode: u8) -> Message;        // id, opcode, rd and cd copied, qr set, the question copied, nothing else
}
```

Decoding rules: a pointer that does not point strictly backwards is `Pointer`; a name longer than 255 wire bytes is `NameTooLong`; an OPT whose class or RDATA is malformed is `Opt`; RDATA of the typed types that is too short is `Truncated("rdata")`; `qdcount`, `ancount`, `nscount`, `arcount` are followed exactly. Encoding puts the OPT record last among the additionals.

- [ ] **Step 1: Write the failing name tests in `name.rs`**

```rust
#[test]
fn names_parse_lowercase_and_display_with_a_trailing_dot() {
    let name: Name = "NAS.Home.arpa".parse().unwrap();
    assert_eq!(name.to_string(), "nas.home.arpa.");
    assert_eq!(name.labels().len(), 3);
    assert_eq!("nas.home.arpa.".parse::<Name>().unwrap(), name);
    assert_eq!(".".parse::<Name>().unwrap(), Name::root());
    assert_eq!("".parse::<Name>().unwrap(), Name::root());
    assert_eq!(Name::root().to_string(), ".");
    assert_eq!(name.wire_len(), 1 + 3 + 1 + 4 + 1 + 4 + 1);
}
#[test]
fn names_refuse_empty_long_labels_and_long_names() {
    assert_eq!("a..b".parse::<Name>(), Err(NameError::EmptyLabel));
    assert_eq!(format!("{}.x", "a".repeat(64)).parse::<Name>(), Err(NameError::LabelTooLong));
    let long = std::iter::repeat_n("a".repeat(63), 5).collect::<Vec<_>>().join(".");
    assert_eq!(long.parse::<Name>(), Err(NameError::NameTooLong));
}
#[test]
fn suffixes_parents_and_joins() {
    let domain: Name = "home.arpa".parse().unwrap();
    let nas: Name = "nas.home.arpa".parse().unwrap();
    assert!(nas.ends_with(&domain) && domain.ends_with(&domain) && !domain.ends_with(&nas));
    assert!(!"nothome.arpa".parse::<Name>().unwrap().ends_with(&domain), "label boundaries matter");
    assert_eq!(nas.parent(), Some(domain.clone()));
    assert_eq!(Name::root().parent(), None);
    assert_eq!("nas".parse::<Name>().unwrap().join(&domain).unwrap(), nas);
}
#[test]
fn reverse_names_round_trip() {
    let addr = Ipv4Addr::new(192, 168, 1, 10);
    assert_eq!(reverse_name(addr).to_string(), "10.1.168.192.in-addr.arpa.");
    assert_eq!(reverse_addr(&reverse_name(addr)), Some(addr));
    assert_eq!(reverse_addr(&"1.168.192.in-addr.arpa".parse().unwrap()), None);
    assert_eq!(reverse_addr(&"nas.home.arpa".parse().unwrap()), None);
}
```

- [ ] **Step 2: Run them, watch them fail**

Run: `cargo test -p openfeo-proto-dns name` (with `OPENFEO_NFT_SRC` and `OPENFEO_UAPI_INCLUDE` exported as `make test` does)
Expected: compile error, the crate or module is missing.

- [ ] **Step 3: Create the crate and implement `name.rs`**

- [ ] **Step 4: Run the name tests, watch them pass**

Expected: 4 passed.

- [ ] **Step 5: Write the failing wire tests in `wire.rs`** (helper `query(name, qtype) -> Message` building a plain query with id 0x1234 and rd set; `hex` vectors written as byte arrays)

```rust
#[test]
fn a_query_encodes_to_the_rfc_1035_layout_and_back() {
    let q = query("nas.home.arpa", rtype::A);
    let bytes = q.encode();
    assert_eq!(&bytes[..12], &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[12..], &[3, b'n', b'a', b's', 4, b'h', b'o', b'm', b'e', 4, b'a', b'r', b'p', b'a', 0, 0, 1, 0, 1]);
    assert_eq!(Message::decode(&bytes), Ok(q));
}
#[test]
fn answers_compress_names_and_decode_pointers() {
    let mut m = Message::reply_to(&query("www.isp.example", rtype::A), rcode::NOERROR);
    m.answers.push(Record { name: "www.isp.example".parse().unwrap(), rtype: rtype::A, class: CLASS_IN, ttl: 60, rdata: RData::A(Ipv4Addr::new(198, 51, 100, 10)) });
    m.authorities.push(Record { name: "isp.example".parse().unwrap(), rtype: rtype::NS, class: CLASS_IN, ttl: 60, rdata: RData::Ns("ns.isp.example".parse().unwrap()) });
    let bytes = m.encode();
    assert_eq!(&bytes[12 + 21..12 + 21 + 2], &[0xc0, 0x0c], "the answer's owner is a pointer to the question's name");
    assert!(bytes.len() < 12 + 21 + 2 + 14 + 2 + 14 + 10, "the NS target reuses the suffix");
    assert_eq!(Message::decode(&bytes), Ok(m));
}
#[test]
fn every_typed_rdata_round_trips() {
    // one record of each: A, AAAA, CNAME, NS, PTR, MX, SOA, TXT (two strings, one empty), SRV, OPT (udp 1232, DO set, one option), Other(type 99, 3 bytes)
    let m = all_types_message();
    assert_eq!(Message::decode(&m.encode()), Ok(m.clone()));
    assert_eq!(m.edns().map(|e| (e.udp_payload, e.dnssec_ok)), Some((1232, true)));
    assert_eq!(m.max_udp_payload(), 1232);
    assert_eq!(query("x.example", rtype::A).max_udp_payload(), 512);
}
#[test]
fn decoding_refuses_forward_pointers_loops_and_short_messages() {
    assert_eq!(Message::decode(&[0; 11]), Err(DecodeError::TooShort(11)));
    let mut loop_name = query("a.example", rtype::A).encode();
    loop_name[12] = 0xc0; loop_name[13] = 12;  // the question's name points at itself
    assert_eq!(Message::decode(&loop_name), Err(DecodeError::Pointer));
    let mut forward = query("a.example", rtype::A).encode();
    forward[12] = 0xc0; forward[13] = 0x20;    // points past itself
    assert_eq!(Message::decode(&forward), Err(DecodeError::Pointer));
    let cut = query("a.example", rtype::A).encode();
    assert_eq!(Message::decode(&cut[..cut.len() - 1]), Err(DecodeError::Truncated("question")));
    let mut trailing = query("a.example", rtype::A).encode();
    trailing.extend_from_slice(&[0, 0, 0]);
    assert!(Message::decode(&trailing).is_ok(), "trailing bytes are ignored");
}
#[test]
fn encode_within_drops_sections_and_sets_tc() {
    let mut m = Message::reply_to(&query("big.isp.example", rtype::TXT), rcode::NOERROR);
    for _ in 0..3 { m.answers.push(Record { name: "big.isp.example".parse().unwrap(), rtype: rtype::TXT, class: CLASS_IN, ttl: 60, rdata: RData::Txt(vec![vec![b'x'; 250]]) }); }
    m.additionals.push(Record { name: Name::root(), rtype: rtype::OPT, class: 1232, ttl: 0, rdata: RData::Opt(Edns { udp_payload: 1232, extended_rcode: 0, version: 0, dnssec_ok: false, options: vec![] }) });
    assert!(m.encode().len() > 700);
    let small = Message::decode(&m.encode_within(512)).unwrap();
    assert!(small.header.truncated && small.answers.len() < 3 && small.edns().is_some());
    assert!(m.encode_within(512).len() <= 512);
    let whole = Message::decode(&m.encode_within(1232)).unwrap();
    assert!(!whole.header.truncated && whole.answers.len() == 3);
}
#[test]
fn reply_to_copies_only_what_rfc_1035_says() {
    let mut q = query("x.example", rtype::A);
    q.header.checking_disabled = true;
    let r = Message::reply_to(&q, rcode::NXDOMAIN);
    assert_eq!((r.header.id, r.header.response, r.header.recursion_desired, r.header.checking_disabled, r.header.rcode), (0x1234, true, true, true, rcode::NXDOMAIN));
    assert_eq!(r.questions, q.questions);
    assert!(r.answers.is_empty() && r.additionals.is_empty());
}
```

- [ ] **Step 6: Run the wire tests, watch them fail**

Expected: compile error, `wire` module missing.

- [ ] **Step 7: Implement `wire.rs`**

- [ ] **Step 8: Run the crate's tests, watch them pass**

Expected: 10 passed.

- [ ] **Step 9: Write ADR-0015, tick SPEC §15, note hickory-proto in `docs/third-party.md`**

ADR-0015 "`openfeo-proto-dns` parses DNS itself; hickory-proto is the test oracle": Context (SPEC §7.7 allows either; `cargo tree` of hickory-proto 0.25 with `default-features = false, features = ["std"]` is 63 crates including `libc` via `getrandom`, `url`, `idna` and the futures family, which SPEC §13 forbids in a pure crate and which would carry Unicode tables into a static binary that needs none of them; a forwarder needs a few record types and compression, under a thousand lines; part 2b's dhcproto precedent), Decision (own codec and core; hickory-proto as dev-dependency and differential fuzz oracle; the oracle's disagreements are findings about our decoder), Consequences (a parser we maintain and fuzz nightly; DNSSEC validation, should it ever come, would be a reason to revisit).

- [ ] **Step 10: Write the fuzz targets and seeds**

`dns_message`: `if let Ok(m) = Message::decode(data) { let again = Message::decode(&m.encode()).expect("our own encoding decodes"); assert_eq!(again, m); assert!(m.encode_within(512).len() <= 512.max(m.encode_within(512).len().min(512))); }` (simplify: assert the 512 encoding is at most 512 bytes when the question alone fits). `dns_differential`: decode with ours and with `hickory_proto::op::Message::from_bytes(data)`; when hickory decodes and we do not, panic (we must accept what real resolvers accept); when both decode, compare the header id, the rcode, `qdcount`/`ancount`/`nscount`/`arcount`, and each question's lowercased name text and type; when hickory fails and we succeed, do nothing. Seeds via an ignored test `write_dns_fuzz_corpus` in `wire.rs` writing `seed-query.bin`, `seed-answer.bin`, `seed-nxdomain.bin`, `seed-edns.bin` to `fuzz/corpus/dns_message/` and `fuzz/corpus/dns_differential/`.

- [ ] **Step 11: Run both targets for 60 s**

Run: `cd fuzz && cargo +nightly fuzz run dns_message -- -max_total_time=60 && cargo +nightly fuzz run dns_differential -- -max_total_time=60`
Expected: `Done`, no artifacts. A `dns_differential` artifact is a finding about our decoder (or, as with dhcproto, about the oracle: read the panic before deciding).

- [ ] **Step 12: Commit**

```bash
git add crates/openfeo-proto-dns Cargo.toml Cargo.lock fuzz docs/adr/0015-in-tree-dns-parser.md docs/third-party.md SPEC.md
git commit -s -m "dns: names and the wire format in openfeo-proto-dns, fuzz targets, ADR-0015"
```

### Task 2: The cache

**Files:**
- Create: `crates/openfeo-proto-dns/src/cache.rs`; Modify: `src/lib.rs` (`pub mod cache;`)
- Test: unit tests in `cache.rs`

**Interfaces:**
- Produces:

```rust
pub const DEFAULT_CAPACITY: usize = 4096;   // SPEC §7.7 "scales with RAM": fixed in M1, sized from /proc/meminfo later
pub const MAX_TTL: u32 = 86_400;
pub const MAX_NEGATIVE_TTL: u32 = 3_600;    // RFC 2308 §5
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key { pub name: Name, pub qtype: u16 }   // class IN only
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry { pub rcode: u8, pub answers: Vec<Record>, pub authorities: Vec<Record>, pub expires_at: Timestamp }
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats { pub hits: u64, pub misses: u64, pub stores: u64, pub evictions: u64 }
pub struct Cache { /* capacity, entries, least-recently-used order, stats */ }
impl Cache {
    pub fn new(capacity: usize) -> Cache;
    /// Store a response for `key` at `now`. Positive answers live min(answer TTLs) seconds (0 is not cached, over MAX_TTL is clamped); NXDOMAIN and NODATA live min(SOA TTL, SOA minimum) capped at MAX_NEGATIVE_TTL and only with an SOA in the authority section; SERVFAIL, REFUSED and truncated messages are not stored. Returns whether it was stored.
    pub fn store(&mut self, key: Key, response: &Message, now: Timestamp) -> bool;
    /// The entry with its TTLs reduced by the seconds elapsed since it was stored; expired entries are removed.
    pub fn lookup(&mut self, key: &Key, now: Timestamp) -> Option<Entry>;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn stats(&self) -> CacheStats;
}
```

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn positive_answers_live_their_smallest_ttl_and_count_down() {
    let mut c = Cache::new(8);
    let r = answer("www.isp.example", &[(rtype::A, 60), (rtype::A, 30)]);   // two A records, TTLs 60 and 30
    assert!(c.store(key("www.isp.example", rtype::A), &r, 1_000));
    let hit = c.lookup(&key("www.isp.example", rtype::A), 11_000).unwrap();
    assert_eq!(hit.answers.iter().map(|a| a.ttl).collect::<Vec<_>>(), vec![50, 20]);
    assert_eq!(hit.expires_at, 31_000);
    assert!(c.lookup(&key("www.isp.example", rtype::A), 31_000).is_none(), "expired at min TTL");
    assert_eq!(c.stats(), CacheStats { hits: 1, misses: 1, stores: 1, evictions: 0 });
}
#[test]
fn negative_answers_need_an_soa_and_live_its_minimum() {
    let mut c = Cache::new(8);
    assert!(!c.store(key("nx.isp.example", rtype::A), &nxdomain_without_soa("nx.isp.example"), 0));
    let nx = nxdomain_with_soa("nx.isp.example", 300 /* soa ttl */, 30 /* minimum */);
    assert!(c.store(key("nx.isp.example", rtype::A), &nx, 0));
    let hit = c.lookup(&key("nx.isp.example", rtype::A), 10_000).unwrap();
    assert_eq!((hit.rcode, hit.expires_at), (rcode::NXDOMAIN, 30_000));
    assert_eq!(hit.authorities[0].ttl, 20);
    let nodata = nodata_with_soa("www.isp.example", 60, 5_000);
    assert!(c.store(key("www.isp.example", rtype::AAAA), &nodata, 0));
    assert_eq!(c.lookup(&key("www.isp.example", rtype::AAAA), 0).unwrap().expires_at, 3_600_000, "capped at an hour");
}
#[test]
fn servfail_zero_ttl_and_truncated_answers_are_not_stored() {
    let mut c = Cache::new(8);
    assert!(!c.store(key("x", rtype::A), &Message::reply_to(&query("x", rtype::A), rcode::SERVFAIL), 0));
    assert!(!c.store(key("x", rtype::A), &answer("x", &[(rtype::A, 0)]), 0));
    let mut tc = answer("x", &[(rtype::A, 60)]);
    tc.header.truncated = true;
    assert!(!c.store(key("x", rtype::A), &tc, 0));
    assert!(c.is_empty());
}
#[test]
fn the_least_recently_used_entry_goes_first_and_big_ttls_are_clamped() {
    let mut c = Cache::new(2);
    c.store(key("a", rtype::A), &answer("a", &[(rtype::A, 1_000_000)]), 0);
    c.store(key("b", rtype::A), &answer("b", &[(rtype::A, 60)]), 0);
    assert_eq!(c.lookup(&key("a", rtype::A), 1_000).unwrap().expires_at, 86_400_000);
    c.store(key("c", rtype::A), &answer("c", &[(rtype::A, 60)]), 2_000);
    assert!(c.lookup(&key("b", rtype::A), 2_000).is_none(), "b was least recently used");
    assert!(c.lookup(&key("a", rtype::A), 2_000).is_some());
    assert_eq!(c.stats().evictions, 1);
}
```

- [ ] **Step 2: Run them, watch them fail** (compile error: `cache` missing)

- [ ] **Step 3: Implement `cache.rs`** (a `BTreeMap<Key, Entry>` plus a `BTreeMap<u64 /*last use*/, Key>` or a `VecDeque<Key>` for the order; either is fine at 4096 entries)

- [ ] **Step 4: Run the crate's tests, watch them pass** (14 passed)

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-proto-dns
git commit -s -m "dns: TTL cache with RFC 2308 negative caching"
```

### Task 3: The forwarder core, part one: validation, local zone, policy slot, cache, forwarding, replies, reconfiguration

**Files:**
- Create: `crates/openfeo-proto-dns/src/forwarder.rs`; Modify: `src/lib.rs` (`pub mod forwarder;`), `Cargo.toml` (dep `ipnet`, pure)
- Test: unit tests in `forwarder.rs`

**Interfaces:**
- Consumes: Task 1's `Name`, `Message`, `rtype`, `rcode`, `EDNS_UDP_PAYLOAD`; Task 2's `Cache`, `Key`.
- Produces (Task 4 completes `handle`; Tasks 5–8 consume these names):

```rust
pub const UPSTREAM_TIMEOUT: Timestamp = 2_000;
pub const MAX_ATTEMPTS: u8 = 3;
pub const UPSTREAM_DOWN_HOLD: Timestamp = 30_000;
pub const LOCAL_TTL: u32 = 60;
pub const LOCAL_NEGATIVE_TTL: u32 = 60;
pub const MAX_PENDING: usize = 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecord { pub name: Name, pub addr: Ipv4Addr }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub upstreams: Vec<Ipv4Addr>,          // in order of preference
    pub domain: Name,                       // home.arpa by default
    pub router_name: Option<Name>,          // <hostname>.<domain>
    pub router_addrs: Vec<Ipv4Addr>,        // the LAN addresses: the router's A records and never a valid upstream answer
    pub lan_subnets: Vec<Ipv4Net>,          // reverse zones we are authoritative for
    pub local: Vec<LocalRecord>,            // reservations first, then leases; the first match wins
    pub rebind_allow: Vec<Name>,            // names whose subdomains may resolve to private addresses
    pub cache_capacity: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport { Udp, Tcp }
pub type QueryId = u64;                     // the driver's token for one client query
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Query { id: QueryId, client: Ipv4Addr, transport: Transport, bytes: Vec<u8> },
    UpstreamReply { upstream: Ipv4Addr, transport: Transport, bytes: Vec<u8> },
    Timeout,
    Configure(Config),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Reply { id: QueryId, bytes: Vec<u8> },
    Forward { upstream: Ipv4Addr, transport: Transport, bytes: Vec<u8> },
    Event(Event),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Configured { upstreams: usize, local: usize },
    NoUpstreams,                                      // once per Configure that leaves none
    UpstreamDown(Ipv4Addr),
    UpstreamUp(Ipv4Addr),
    RebindDropped { name: Name, addr: IpAddr, client: Ipv4Addr },
    Blocked { name: Name, client: Ipv4Addr },         // reserved for the policy; never emitted in 3b
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict { Allow, Block }
/// The slot for Rustik Block's lists (SPEC §7.7): consulted after the local zone, before the cache. Allows everything in M1.
#[derive(Debug, Default, Clone)]
pub struct Policy;
impl Policy { pub fn decide(&self, name: &Name, qtype: u16, client: Ipv4Addr) -> Verdict; }
#[derive(Debug)]
pub struct Forwarder { /* config, policy, cache, pending by upstream id, down marks, round-robin cursor, rng, no-upstreams-announced flag */ }
impl Forwarder {
    pub fn new(config: Config, seed: u64) -> Forwarder;
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output>;
    pub fn next_timeout(&self) -> Option<Timestamp>;
    pub fn config(&self) -> &Config;
    pub fn cache_stats(&self) -> CacheStats;
    pub fn pending(&self) -> usize;
}
```

The pipeline for `Input::Query` (this task; Task 4 adds what happens after a forward):
1. Decode. A header that does not decode: no output. A message whose header decodes but the rest does not: FORMERR with the id. `opcode != QUERY`: NOTIMP. `questions.len() != 1`: FORMERR. `qclass` not IN or ANY: REFUSED. A response bit set: no output.
2. Local zone, `authoritative = true`, TTL `LOCAL_TTL`: the question's name equals or is under `domain`, or is a full `in-addr.arpa` name whose address lies in a `lan_subnets` entry. A: `router_name` → `router_addrs`; a `local` record → its address. PTR: a router address → `router_name`, a local address → its name. Any other type for a known name: NODATA. An unknown name: NXDOMAIN. Both negatives carry an SOA for `domain` in the authority section: `mname` = `router_name` or `domain`, `rname` = `hostmaster.<domain>`, serial 1, refresh 3600, retry 600, expire 86400, minimum `LOCAL_NEGATIVE_TTL`. For a reverse zone the SOA owner is the `in-addr.arpa` name of the subnet's network (e.g. `1.168.192.in-addr.arpa` for a /24; for other lengths, the first byte boundary covering the subnet).
3. `Policy::decide`: `Block` → NXDOMAIN without an SOA, `Event::Blocked`. (Allow always in M1.)
4. Cache: a hit replies with the entry's records, `authoritative = false`, `recursion_available = true`.
5. Forward: no upstreams → SERVFAIL (and `Event::NoUpstreams` once per `Configure`). Else pick an upstream (Task 4 decides which), build the upstream query: a fresh random id, the question, `recursion_desired`, `checking_disabled` copied, an OPT with `EDNS_UDP_PAYLOAD` and the client's DO bit (added even when the client sent none), over UDP; remember the pending query (client id, transport, question, client's max payload and whether it sent an OPT, upstream, attempts, deadline `now + UPSTREAM_TIMEOUT`). More than `MAX_PENDING` pending: SERVFAIL.
6. Every reply to a client: `reply_to` plus the records, `recursion_available = true`, the client's OPT echoed as ours with `EDNS_UDP_PAYLOAD` only when the client sent one, `encode_within(client max payload)` for UDP and `encode()` for TCP.
`Input::Configure`: replaces the config and policy inputs, keeps the cache, drops down marks for upstreams no longer listed, emits `Event::Configured`, and `Event::NoUpstreams` when the list is empty.

- [ ] **Step 1: Write the failing tests** (helpers: `config() -> Config` with upstreams `[203.0.113.1]`, domain `home.arpa`, router `openfeo.home.arpa` at `192.168.1.1`, subnet `192.168.1.0/24`, local `nas.home.arpa → 192.168.1.10` and `pc.home.arpa → 192.168.1.120`, `rebind_allow [allowed.isp.example]`, capacity 64; `q(name, qtype) -> Vec<u8>` a query with id 7 and rd; `q_edns(name, qtype, payload, dnssec_ok)`; `reply(outputs) -> Message` decoding the single `Reply`; `forwards(outputs) -> Vec<(Ipv4Addr, Transport, Message)>`; `upstream_answer(forwarded: &Message, records) -> Vec<u8>` building an answer with the forwarded id)

```rust
#[test]
fn local_names_answer_authoritatively_from_reservations_leases_and_the_router() {
    let mut f = Forwarder::new(config(), 1);
    let out = f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("NAS.home.arpa", rtype::A) }, 0);
    let r = reply(&out);
    assert_eq!((r.header.id, r.header.response, r.header.authoritative, r.header.recursion_available, r.header.rcode), (7, true, true, true, rcode::NOERROR));
    assert_eq!(r.answers, vec![Record { name: "nas.home.arpa".parse().unwrap(), rtype: rtype::A, class: CLASS_IN, ttl: LOCAL_TTL, rdata: RData::A(ip("192.168.1.10")) }]);
    assert!(forwards(&out).is_empty());
    assert_eq!(reply(&f.handle(Input::Query { id: 2, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("openfeo.home.arpa", rtype::A) }, 0)).answers[0].rdata, RData::A(ip("192.168.1.1")));
    let ptr = reply(&f.handle(Input::Query { id: 3, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("10.1.168.192.in-addr.arpa", rtype::PTR) }, 0));
    assert_eq!(ptr.answers[0].rdata, RData::Ptr("nas.home.arpa".parse().unwrap()));
}
#[test]
fn home_arpa_and_lan_reverse_zones_never_go_upstream() {
    let mut f = Forwarder::new(config(), 1);
    let nx = reply(&f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("printer.home.arpa", rtype::A) }, 0));
    assert_eq!((nx.header.rcode, nx.header.authoritative), (rcode::NXDOMAIN, true));
    assert!(matches!(nx.authorities[0].rdata, RData::Soa { ref mname, minimum, .. } if *mname == "openfeo.home.arpa".parse::<Name>().unwrap() && minimum == LOCAL_NEGATIVE_TTL));
    let nodata = reply(&f.handle(Input::Query { id: 2, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("nas.home.arpa", rtype::AAAA) }, 0));
    assert_eq!((nodata.header.rcode, nodata.answers.len(), nodata.authorities.len()), (rcode::NOERROR, 0, 1));
    let rev = reply(&f.handle(Input::Query { id: 3, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("200.1.168.192.in-addr.arpa", rtype::PTR) }, 0));
    assert_eq!(rev.header.rcode, rcode::NXDOMAIN);
    assert_eq!(rev.authorities[0].name, "1.168.192.in-addr.arpa".parse::<Name>().unwrap());
    assert_eq!(f.pending(), 0, "nothing was forwarded");
    let out = f.handle(Input::Query { id: 4, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("5.5.0.10.in-addr.arpa", rtype::PTR) }, 0);
    assert_eq!(forwards(&out).len(), 1, "a reverse name outside our subnets is forwarded");
}
#[test]
fn odd_queries_are_answered_with_an_error_and_never_forwarded() {
    let mut f = Forwarder::new(config(), 1);
    let at = |f: &mut Forwarder, bytes: Vec<u8>| f.handle(Input::Query { id: 9, client: ip("192.168.1.50"), transport: Transport::Tcp, bytes }, 0);
    assert_eq!(at(&mut f, vec![0; 5]), Vec::new(), "no header, no reply");
    let mut cut = q("x.example", rtype::A); cut.truncate(14);
    assert_eq!(reply(&at(&mut f, cut)).header.rcode, rcode::FORMERR);
    let mut two = Message::decode(&q("x.example", rtype::A)).unwrap(); two.questions.push(two.questions[0].clone());
    assert_eq!(reply(&at(&mut f, two.encode())).header.rcode, rcode::FORMERR);
    let mut none = Message::decode(&q("x.example", rtype::A)).unwrap(); none.questions.clear();
    assert_eq!(reply(&at(&mut f, none.encode())).header.rcode, rcode::FORMERR);
    let mut update = Message::decode(&q("x.example", rtype::A)).unwrap(); update.header.opcode = 5;
    assert_eq!(reply(&at(&mut f, update.encode())).header.rcode, rcode::NOTIMP);
    let mut chaos = Message::decode(&q("version.bind", rtype::TXT)).unwrap(); chaos.questions[0].qclass = 3;
    assert_eq!(reply(&at(&mut f, chaos.encode())).header.rcode, rcode::REFUSED);
    let mut response = Message::decode(&q("x.example", rtype::A)).unwrap(); response.header.response = true;
    assert_eq!(at(&mut f, response.encode()), Vec::new());
    assert_eq!(at(&mut f, vec![0xff; 65_535]).len(), 1, "a giant TCP message gets one FORMERR");
    assert_eq!(f.pending(), 0);
}
#[test]
fn remote_names_are_forwarded_with_edns_and_cached_on_the_way_back() {
    let mut f = Forwarder::new(config(), 1);
    let out = f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("www.isp.example", rtype::A) }, 0);
    let (upstream, transport, fwd) = forwards(&out).remove(0);
    assert_eq!((upstream, transport), (ip("203.0.113.1"), Transport::Udp));
    assert_ne!(fwd.header.id, 7, "a fresh id");
    assert_eq!(fwd.edns().map(|e| e.udp_payload), Some(EDNS_UDP_PAYLOAD));
    assert!(fwd.header.recursion_desired);
    assert_eq!(f.next_timeout(), Some(UPSTREAM_TIMEOUT));
    let out = f.handle(Input::UpstreamReply { upstream, transport, bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]) }, 100);
    let r = reply(&out);
    assert_eq!((r.header.id, r.header.rcode, r.header.authoritative, r.header.recursion_available), (7, rcode::NOERROR, false, true));
    assert_eq!(r.answers[0].rdata, RData::A(ip("198.51.100.10")));
    assert!(r.edns().is_none(), "the client sent no OPT, so it gets none");
    let out = f.handle(Input::Query { id: 2, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("WWW.isp.example", rtype::A) }, 10_100);
    assert!(forwards(&out).is_empty(), "served from the cache");
    assert_eq!(reply(&out).answers[0].ttl, 50);
    assert_eq!(f.cache_stats().hits, 1);
}
#[test]
fn clients_with_edns_get_an_opt_back_and_udp_replies_fit_their_buffer() {
    let mut f = Forwarder::new(config(), 1);
    let out = f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q_edns("big.isp.example", rtype::TXT, 512, true) }, 0);
    let (upstream, transport, fwd) = forwards(&out).remove(0);
    assert!(fwd.edns().unwrap().dnssec_ok, "DO passes through");
    let big = upstream_answer(&fwd, &[txt("big.isp.example", 60, 250), txt("big.isp.example", 60, 250), txt("big.isp.example", 60, 250)]);
    let r = reply(&f.handle(Input::UpstreamReply { upstream, transport, bytes: big }, 50));
    assert!(r.header.truncated && r.edns().map(|e| e.udp_payload) == Some(EDNS_UDP_PAYLOAD));
    let out = f.handle(Input::Query { id: 2, client: ip("192.168.1.50"), transport: Transport::Tcp, bytes: q_edns("big.isp.example", rtype::TXT, 512, false) }, 60);
    assert_eq!(reply(&out).answers.len(), 3, "over TCP the cached answer is whole");
}
#[test]
fn configure_switches_upstreams_and_local_names_live_and_keeps_the_cache() {
    let mut f = Forwarder::new(config(), 1);
    let out = f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("www.isp.example", rtype::A) }, 0);
    let (upstream, transport, fwd) = forwards(&out).remove(0);
    f.handle(Input::UpstreamReply { upstream, transport, bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]) }, 10);
    let mut changed = config();
    changed.upstreams = vec![ip("9.9.9.9")];
    changed.local.push(LocalRecord { name: "tv.home.arpa".parse().unwrap(), addr: ip("192.168.1.130") });
    let out = f.handle(Input::Configure(changed), 20);
    assert_eq!(out, vec![Output::Event(Event::Configured { upstreams: 1, local: 3 })]);
    assert!(forwards(&f.handle(Input::Query { id: 2, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("www.isp.example", rtype::A) }, 30)).is_empty(), "the cache survives");
    assert_eq!(forwards(&f.handle(Input::Query { id: 3, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("other.example", rtype::A) }, 40))[0].0, ip("9.9.9.9"));
    assert_eq!(reply(&f.handle(Input::Query { id: 4, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("tv.home.arpa", rtype::A) }, 50)).answers[0].rdata, RData::A(ip("192.168.1.130")));
}
```

- [ ] **Step 2: Run them, watch them fail** (compile error: `forwarder` missing)

- [ ] **Step 3: Implement the pipeline above**, with `handle`'s `UpstreamReply` arm doing only the happy path (match the pending id, reply, cache); Task 4 adds matching checks, TC, rebinding and timeouts

- [ ] **Step 4: Run the crate's tests, watch them pass** (20 passed)

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-proto-dns
git commit -s -m "dns: forwarder core answers local names, consults the policy slot and the cache, forwards with EDNS, reconfigures live"
```

### Task 4: The forwarder core, part two: failover, truncation, rebinding, reply matching, no upstreams

**Files:**
- Modify: `crates/openfeo-proto-dns/src/forwarder.rs`
- Test: unit tests in `forwarder.rs`

**Interfaces:**
- Consumes: Task 3.
- Produces: the complete `handle`:
  - Upstream choice: round robin over the upstreams not marked down (a down mark lasts `UPSTREAM_DOWN_HOLD`); when all are down, the next one anyway and its mark is cleared.
  - `Timeout`: a pending query past its deadline marks its upstream down (`Event::UpstreamDown` when it was up), and retries on the next upstream with a fresh id and deadline while `attempts < MAX_ATTEMPTS` and another upstream exists; otherwise the client gets SERVFAIL. `next_timeout` is the earliest pending deadline.
  - `UpstreamReply`: ignored unless its id is pending, it came from that pending query's upstream over that transport, and its question matches (name case-insensitively, type, class). A matching reply marks the upstream up (`Event::UpstreamUp` when it was down). A reply with TC over UDP is re-sent to the same upstream over TCP (new deadline, same pending entry); a TC reply over TCP is used as is. Rebinding check: any A or AAAA record in the answers (CNAME chains land there) whose address is RFC 1918, link-local (169.254/16), loopback, 0.0.0.0/8, IPv6 ULA (fc00::/7), link-local (fe80::/10), loopback, or one of `router_addrs`, when the question's name is not equal to or under a `rebind_allow` name → `Event::RebindDropped { name, addr, client }` and REFUSED to the client, nothing cached. Otherwise store in the cache (SERVFAIL from upstream is passed through, not cached) and reply.
  - A `Configure` that removes an upstream drops its pending queries with SERVFAIL.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_silent_upstream_is_retried_on_the_next_and_marked_down() {
    let mut cfg = config(); cfg.upstreams = vec![ip("203.0.113.99"), ip("203.0.113.1")];
    let mut f = Forwarder::new(cfg, 1);
    let out = f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("www.isp.example", rtype::A) }, 0);
    assert_eq!(forwards(&out)[0].0, ip("203.0.113.99"));
    let out = f.handle(Input::Timeout, UPSTREAM_TIMEOUT);
    assert!(out.contains(&Output::Event(Event::UpstreamDown(ip("203.0.113.99")))));
    let (upstream, transport, fwd) = forwards(&out).remove(0);
    assert_eq!(upstream, ip("203.0.113.1"));
    assert_eq!(reply(&f.handle(Input::UpstreamReply { upstream, transport, bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]) }, 2_100)).header.rcode, rcode::NOERROR);
    let out = f.handle(Input::Query { id: 2, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("other.example", rtype::A) }, 3_000);
    assert_eq!(forwards(&out)[0].0, ip("203.0.113.1"), "the down server is skipped");
    let out = f.handle(Input::Query { id: 3, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("third.example", rtype::A) }, 3_000 + UPSTREAM_DOWN_HOLD);
    assert_eq!(forwards(&out)[0].0, ip("203.0.113.99"), "and tried again after the hold");
}
#[test]
fn when_every_attempt_times_out_the_client_gets_servfail() {
    let mut f = Forwarder::new(config(), 1);
    f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("www.isp.example", rtype::A) }, 0);
    let out = f.handle(Input::Timeout, UPSTREAM_TIMEOUT);
    assert_eq!(reply(&out).header.rcode, rcode::SERVFAIL, "one upstream, no second attempt possible");
    assert_eq!(f.pending(), 0);
    assert_eq!(f.next_timeout(), None);
}
#[test]
fn truncated_udp_replies_are_fetched_again_over_tcp() {
    let mut f = Forwarder::new(config(), 1);
    let out = f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Tcp, bytes: q("big.isp.example", rtype::TXT) }, 0);
    let (upstream, _, fwd) = forwards(&out).remove(0);
    let mut tc = Message::decode(&upstream_answer(&fwd, &[])).unwrap(); tc.header.truncated = true;
    let out = f.handle(Input::UpstreamReply { upstream, transport: Transport::Udp, bytes: tc.encode() }, 10);
    let (upstream2, transport2, fwd2) = forwards(&out).remove(0);
    assert_eq!((upstream2, transport2), (upstream, Transport::Tcp));
    assert!(out.iter().all(|o| !matches!(o, Output::Reply { .. })));
    let full = upstream_answer(&fwd2, &[txt("big.isp.example", 60, 250), txt("big.isp.example", 60, 250), txt("big.isp.example", 60, 250)]);
    let r = reply(&f.handle(Input::UpstreamReply { upstream, transport: Transport::Tcp, bytes: full }, 20));
    assert_eq!((r.header.truncated, r.answers.len()), (false, 3));
}
#[test]
fn rebinding_through_a_cname_is_dropped_and_allowed_names_cover_subdomains() {
    let mut f = Forwarder::new(config(), 1);
    let out = f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("evil.isp.example", rtype::A) }, 0);
    let (upstream, transport, fwd) = forwards(&out).remove(0);
    let chain = upstream_answer(&fwd, &[cname("evil.isp.example", 60, "target.isp.example"), a("target.isp.example", 60, "192.168.1.5")]);
    let out = f.handle(Input::UpstreamReply { upstream, transport, bytes: chain }, 10);
    assert_eq!(reply(&out).header.rcode, rcode::REFUSED);
    assert!(out.contains(&Output::Event(Event::RebindDropped { name: "evil.isp.example".parse().unwrap(), addr: ip("192.168.1.5").into(), client: ip("192.168.1.50") })));
    assert_eq!(f.cache_stats().stores, 0);
    for (name, addr) in [("router.isp.example", "192.168.1.1"), ("ll.isp.example", "169.254.3.4"), ("lo.isp.example", "127.0.0.9")] {
        let out = f.handle(Input::Query { id: 2, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q(name, rtype::A) }, 20);
        let (upstream, transport, fwd) = forwards(&out).remove(0);
        assert_eq!(reply(&f.handle(Input::UpstreamReply { upstream, transport, bytes: upstream_answer(&fwd, &[a(name, 60, addr)]) }, 30)).header.rcode, rcode::REFUSED, "{name}");
    }
    let out = f.handle(Input::Query { id: 3, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("dev.allowed.isp.example", rtype::A) }, 40);
    let (upstream, transport, fwd) = forwards(&out).remove(0);
    let r = reply(&f.handle(Input::UpstreamReply { upstream, transport, bytes: upstream_answer(&fwd, &[a("dev.allowed.isp.example", 60, "192.168.1.6")]) }, 50));
    assert_eq!((r.header.rcode, r.answers[0].rdata.clone()), (rcode::NOERROR, RData::A(ip("192.168.1.6"))));
    let out = f.handle(Input::Query { id: 4, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("v6.isp.example", rtype::AAAA) }, 60);
    let (upstream, transport, fwd) = forwards(&out).remove(0);
    assert_eq!(reply(&f.handle(Input::UpstreamReply { upstream, transport, bytes: upstream_answer(&fwd, &[aaaa("v6.isp.example", 60, "fd00::1")]) }, 70)).header.rcode, rcode::REFUSED, "ULA");
}
#[test]
fn replies_that_do_not_match_the_pending_query_are_ignored() {
    let mut f = Forwarder::new(config(), 1);
    let out = f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("www.isp.example", rtype::A) }, 0);
    let (upstream, transport, fwd) = forwards(&out).remove(0);
    let spoofed_source = f.handle(Input::UpstreamReply { upstream: ip("203.0.113.66"), transport, bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "6.6.6.6")]) }, 10);
    assert_eq!(spoofed_source, Vec::new());
    let mut other_q = Message::decode(&upstream_answer(&fwd, &[a("www.isp.example", 60, "6.6.6.6")])).unwrap();
    other_q.questions[0].name = "www.other.example".parse().unwrap();
    assert_eq!(f.handle(Input::UpstreamReply { upstream, transport, bytes: other_q.encode() }, 11), Vec::new());
    let mut unknown_id = Message::decode(&upstream_answer(&fwd, &[])).unwrap(); unknown_id.header.id ^= 0x5555;
    assert_eq!(f.handle(Input::UpstreamReply { upstream, transport, bytes: unknown_id.encode() }, 12), Vec::new());
    assert_eq!(f.pending(), 1, "the real reply is still awaited");
    let r = reply(&f.handle(Input::UpstreamReply { upstream, transport, bytes: upstream_answer(&fwd, &[a("www.isp.example", 60, "198.51.100.10")]) }, 13));
    assert_eq!(r.answers[0].rdata, RData::A(ip("198.51.100.10")));
}
#[test]
fn without_upstreams_remote_names_fail_fast_and_local_names_still_resolve() {
    let mut cfg = config(); cfg.upstreams = Vec::new();
    let mut f = Forwarder::new(cfg, 1);
    let out = f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("www.isp.example", rtype::A) }, 0);
    assert_eq!(reply(&out).header.rcode, rcode::SERVFAIL);
    assert!(out.contains(&Output::Event(Event::NoUpstreams)));
    assert_eq!(f.next_timeout(), None, "nothing to wait for");
    let out = f.handle(Input::Query { id: 2, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("other.example", rtype::A) }, 1);
    assert!(!out.contains(&Output::Event(Event::NoUpstreams)), "announced once");
    assert_eq!(reply(&f.handle(Input::Query { id: 3, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("nas.home.arpa", rtype::A) }, 2)).header.rcode, rcode::NOERROR);
    let out = f.handle(Input::Configure(config()), 3);
    assert_eq!(out, vec![Output::Event(Event::Configured { upstreams: 1, local: 2 })]);
}
#[test]
fn pending_queries_to_a_removed_upstream_get_servfail() {
    let mut f = Forwarder::new(config(), 1);
    f.handle(Input::Query { id: 1, client: ip("192.168.1.50"), transport: Transport::Udp, bytes: q("www.isp.example", rtype::A) }, 0);
    let mut cfg = config(); cfg.upstreams = vec![ip("9.9.9.9")];
    let out = f.handle(Input::Configure(cfg), 1);
    assert_eq!(reply(&out).header.rcode, rcode::SERVFAIL);
    assert_eq!(f.pending(), 0);
}
```

- [ ] **Step 2: Run them, watch them fail** (seven fail on assertions; Task 3's pass)

- [ ] **Step 3: Implement failover, TC retry, rebinding, matching and the removed-upstream path**

- [ ] **Step 4: Run the crate's tests, watch them pass** (27 passed)

- [ ] **Step 5: Run the fuzz targets again for 60 s** (the core is not fuzzed directly; a `dns_forwarder` target is a Minor the reviewer may raise: bytes through `Input::Query` then `UpstreamReply` with the forwarded id, as `dhcp4_server` does. Add it here as a third target if Task 1's two were cheap: assert no panic and `pending() <= MAX_PENDING`.)

- [ ] **Step 6: Commit**

```bash
git add crates/openfeo-proto-dns fuzz
git commit -s -m "dns: upstream failover, TCP on truncation, rebinding protection, reply matching, no-upstream behaviour"
```

### Task 5: Configuration `[dns]`, validation, `reconcile::dns`

**Files:**
- Modify: `proto/openfeo/v1/config.proto` (`Config.dns = 7`, message `Dns`), `crates/openfeo-config/src/lib.rs` (re-export `Dns`), `crates/openfeo-config/src/validate.rs` (codes, `fn dns(report, dns)`), `crates/openfeo-config/src/load.rs` (nothing: first boot has no `[dns]`)
- Create: `crates/openfeo-reconcile/src/dns.rs`; Modify: `crates/openfeo-reconcile/src/lib.rs` (`pub mod dns;`), `Cargo.toml` (dep `openfeo-proto-dns`), `src/fixtures.rs` (`pub fn lease_facts() -> BTreeMap<String, Vec<LeaseFact>>` with `pc` at 192.168.1.120 on `lan0`, and `pub fn static_world_with_leases() -> World`)
- Test: unit tests in `validate.rs` and `dns.rs`, snapshots

**Interfaces:**
- Consumes: `World.dhcp4[wan].dns`, `World.leases`, `StaticWan.dns`, `Lan.dhcp.static`, `System.{hostname, domain}`, `load::{DEFAULT_HOSTNAME, DEFAULT_DOMAIN}`, Task 3's `forwarder::{Config, LocalRecord}`, `cache::DEFAULT_CAPACITY`.
- Produces:

```proto
message Config { /* 1..6 */ Dns dns = 7; }
// The DNS forwarder (SPEC §7.7; `[dns]` in §8.2).
message Dns {
  // Upstream resolvers, in order of preference; empty means the active WAN's learned servers alone.
  repeated string upstreams = 1;
  // Reserved for block lists (post-MVP); must be empty.
  repeated string blocklists = 2;
  // Also use the servers the active WAN learned (DHCPv4 now, PPPoE and IPv6 later), after `upstreams`. Absent means true.
  optional bool use_wan_dns = 3;
  // Names whose subdomains may resolve to private addresses (rebinding protection, SPEC §7.7).
  repeated string rebind_allow = 4;
}
```

```rust
// validate.rs
Code::BlocklistsUnsupported => "blocklists_unsupported",   // [dns] blocklists is not empty
// `dns.upstreams[i]`: InvalidAddress unless an IPv4 address; `dns.rebind_allow[i]`: InvalidHostname unless is_valid_hostname; `dns.blocklists`: BlocklistsUnsupported when non-empty
fn dns(report: &mut Report, dns: &Dns);

// reconcile/dns.rs
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredListener { pub ifname: String, pub address: Ipv4Addr }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredLocalName { pub name: String, pub addr: Ipv4Addr }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesiredDns {
    pub listeners: Vec<DesiredListener>,     // one per LAN: br-<lan> and its address
    pub upstreams: Vec<Ipv4Addr>,            // typed ones, then the active WAN's learned or static ones when use_wan_dns, deduplicated in order
    pub learned_from: Option<String>,        // the WAN whose servers were appended
    pub domain: String,                      // [system] domain or home.arpa
    pub router_name: String,                 // <hostname>.<domain>
    pub router_addrs: Vec<Ipv4Addr>,
    pub lan_subnets: Vec<Ipv4Net>,
    pub local: Vec<DesiredLocalName>,        // every LAN's reservations with a hostname, then lease facts with a hostname not already named
    pub rebind_allow: Vec<String>,
}
pub fn desired(world: &World) -> DesiredDns;
pub fn forwarder_config(desired: &DesiredDns) -> Option<openfeo_proto_dns::forwarder::Config>;  // None when a name does not parse (validation forbids it)
```

The active WAN is the configured WAN with the lowest `priority` whose port the map knows; its servers are `world.dhcp4[wan].dns` for a DHCP WAN (none until a lease) and `StaticWan.dns` for a static one.

- [ ] **Step 1: Write the failing validation tests**

```rust
#[test]
fn dns_upstreams_must_be_addresses_blocklists_must_be_empty_and_allow_names_valid() {
    let config = file::parse("config_version = 1\n[dns]\nupstreams = [\"9.9.9.9\", \"dns.quad9.net\"]\nblocklists = [\"hagezi\"]\nrebind_allow = [\"plex.direct\", \"-bad\"]\n").unwrap();
    assert_eq!(codes(&validate(&config, &live())), vec![
        ("dns.upstreams[1]".to_owned(), Code::InvalidAddress),
        ("dns.blocklists".to_owned(), Code::BlocklistsUnsupported),
        ("dns.rebind_allow[1]".to_owned(), Code::InvalidHostname),
    ]);
    let ok = file::parse("config_version = 1\n[dns]\nupstreams = [\"9.9.9.9\"]\nuse_wan_dns = false\n").unwrap();
    assert_eq!(validate(&ok, &live()), vec![]);
    assert_eq!(ok.dns.as_ref().and_then(|d| d.use_wan_dns), Some(false));
    assert_eq!(file::parse("config_version = 1\n[dns]\nupstreams = [\"9.9.9.9\"]\n").unwrap().dns.unwrap().use_wan_dns, None, "absent means the default, true");
}
```

- [ ] **Step 2: Write the failing reconcile tests** (`fixtures::static_world()` has a static WAN with `dns = ["203.0.113.1"]` and the `nas` reservation; `dhcp_world()` a lease fact with `dns = [203.0.113.1]`; `dhcp_world_without_lease()`)

```rust
#[test]
fn static_world_lists_the_lan_the_static_wan_dns_and_the_local_names() {
    let d = desired(&fixtures::static_world());
    insta::assert_yaml_snapshot!(d);
    assert_eq!(d.listeners, vec![DesiredListener { ifname: "br-lan0".into(), address: Ipv4Addr::new(192, 168, 1, 1) }]);
    assert_eq!((d.upstreams.clone(), d.learned_from.as_deref()), (vec![Ipv4Addr::new(203, 0, 113, 1)], Some("wan0")));
    assert_eq!((d.domain.as_str(), d.router_name.as_str()), ("home.arpa", "openfeo.home.arpa"));
    assert_eq!(d.local, vec![DesiredLocalName { name: "nas.home.arpa".into(), addr: Ipv4Addr::new(192, 168, 1, 10) }]);
    let cfg = forwarder_config(&d).unwrap();
    assert_eq!((cfg.upstreams, cfg.local.len(), cfg.cache_capacity), (vec![Ipv4Addr::new(203, 0, 113, 1)], 1, DEFAULT_CAPACITY));
}
#[test]
fn dhcp_world_learns_from_the_lease_and_has_nothing_before_it() {
    let with = desired(&fixtures::dhcp_world());
    insta::assert_yaml_snapshot!(with);
    assert_eq!(with.upstreams, vec![Ipv4Addr::new(203, 0, 113, 1)]);
    let without = desired(&fixtures::dhcp_world_without_lease());
    assert_eq!((without.upstreams.len(), without.learned_from), (0, None));
}
#[test]
fn typed_upstreams_come_first_and_use_wan_dns_false_leaves_the_wan_out() {
    let mut world = fixtures::static_world();
    Arc::make_mut(&mut world.config).dns = Some(Dns { upstreams: vec!["9.9.9.9".into(), "203.0.113.1".into()], ..Default::default() });
    let d = desired(&world);
    assert_eq!(d.upstreams, vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(203, 0, 113, 1)], "deduplicated");
    Arc::make_mut(&mut world.config).dns.as_mut().unwrap().use_wan_dns = Some(false);
    assert_eq!((desired(&world).upstreams, desired(&world).learned_from), (vec![Ipv4Addr::new(9, 9, 9, 9)], None));
}
#[test]
fn lease_facts_add_local_names_without_shadowing_reservations() {
    let d = desired(&fixtures::static_world_with_leases());
    assert_eq!(d.local, vec![
        DesiredLocalName { name: "nas.home.arpa".into(), addr: Ipv4Addr::new(192, 168, 1, 10) },
        DesiredLocalName { name: "pc.home.arpa".into(), addr: Ipv4Addr::new(192, 168, 1, 120) },
    ]);
}
```

- [ ] **Step 3: Run them, watch them fail** (compile errors: `Dns`, `Code::BlocklistsUnsupported`, `dns` module)

- [ ] **Step 4: Implement the proto, validation, fixtures and `dns.rs`; accept the snapshots with `INSTA_UPDATE=always cargo test -p openfeo-reconcile`, then run `make test` and `make lint`**

Expected: all green; `buf breaking` accepts the additions.

- [ ] **Step 5: Commit**

```bash
git add proto crates/openfeo-config crates/openfeo-reconcile
git commit -s -m "config: [dns] upstreams, use_wan_dns, rebind_allow; reconcile: the forwarder's settings from config, leases and the WAN"
```

### Task 6: The driver in `openfeo-net`

**Files:**
- Create: `crates/openfeo-net/src/dns.rs`; Modify: `src/lib.rs` (`pub mod dns;`), `Cargo.toml` (dep `openfeo-proto-dns`)
- Test: unit tests for the pure helpers; sockets are exercised by Task 8

**Interfaces:**
- Consumes: Task 3/4's `forwarder::{Forwarder, Config, Input, Output, Event, Transport, QueryId}`, `openfeo_proto_dns::Timestamp`; `crate::dhcp4::{DriverError, socket_err, io_err, is_transient, wait_until}`.
- Produces:

```rust
pub const UPSTREAM_SOCKETS: usize = 4;             // UDP sockets with kernel-chosen ports, one picked per query
pub const TCP_CLIENTS_MAX: usize = 64;
pub const TCP_IDLE: Duration = Duration::from_secs(10);
pub const TCP_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
#[derive(Debug, Clone)]
pub struct DnsDriverConfig { pub listeners: Vec<String> /* bridge names */, pub forwarder: forwarder::Config, pub seed: u64 }
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsStats { pub queries: u64, pub replies: u64, pub forwarded: u64 }
pub struct DnsDriver { /* forwarder, inbox rx, listeners (UdpSocket per bridge, TcpListener accept tasks), upstream UDP pool, client handles by QueryId, start, stats */ }
impl DnsDriver {
    pub fn new(config: DnsDriverConfig) -> Result<DnsDriver, DriverError>;   // inside a tokio runtime
    pub async fn step(&mut self) -> Result<Vec<Event>, DriverError>;
    pub fn configure(&mut self, config: forwarder::Config) -> Vec<Event>;
    pub fn stats(&self) -> DnsStats;
    pub fn cache_stats(&self) -> CacheStats;
}
pub(crate) fn client_v4(peer: SocketAddr) -> Option<Ipv4Addr>;           // the client's address; IPv6 peers are not served in M1
pub(crate) fn frame(message: &[u8]) -> Vec<u8>;                           // two-byte big-endian length prefix for TCP
pub(crate) fn unframe(buf: &[u8]) -> Option<(usize, &[u8])>;              // (consumed, message) when a whole message is there
```

Sockets in `new`: per bridge, a UDP socket `0.0.0.0:53` with `SO_REUSEADDR` and `SO_BINDTODEVICE`, and a TCP listener `0.0.0.0:53` with the same two options (nix `socket`/`setsockopt`/`bind`/`listen`, then `tokio::net::TcpListener::from_std`); `UPSTREAM_SOCKETS` UDP sockets bound to `0.0.0.0:0`. Tasks feed an `mpsc` inbox: one recv loop per listener UDP socket (`Incoming::Udp { listener, peer, bytes }`), one accept loop per TCP listener spawning a per-connection task bounded by a `Semaphore(TCP_CLIENTS_MAX)` that reads framed queries, sends `Incoming::Tcp { peer, bytes, reply: oneshot::Sender<Vec<u8>> }` and writes the framed reply, closing after `TCP_IDLE` without a query; one recv loop per upstream UDP socket (`Incoming::UpstreamUdp`). `step` selects over the inbox and `wait_until(next_timeout)`; outputs: `Reply` goes to the client handle (UDP `send_to` through the listener socket it arrived on; TCP through the oneshot); `Forward { Udp }` picks an upstream socket by the query's id and `send_to(upstream:53)`; `Forward { Tcp }` spawns a task that connects with `TCP_UPSTREAM_TIMEOUT`, writes the framed query, reads one framed reply and sends `Incoming::UpstreamTcp` (a failure sends nothing: the core's timer handles it). Transient errors as in the DHCP drivers.

- [ ] **Step 1: Write the failing helper tests**

```rust
#[test]
fn tcp_framing_round_trips_and_waits_for_whole_messages() {
    let framed = frame(&[1, 2, 3]);
    assert_eq!(framed, vec![0, 3, 1, 2, 3]);
    assert_eq!(unframe(&framed), Some((5, &[1u8, 2, 3][..])));
    assert_eq!(unframe(&framed[..4]), None);
    assert_eq!(unframe(&[0]), None);
    let two = [frame(&[9]), frame(&[8, 8])].concat();
    assert_eq!(unframe(&two), Some((3, &[9u8][..])));
}
#[test]
fn only_ipv4_clients_are_served_in_m1() {
    assert_eq!(client_v4("192.168.1.50:5353".parse().unwrap()), Some(Ipv4Addr::new(192, 168, 1, 50)));
    assert_eq!(client_v4("[fe80::1]:5353".parse().unwrap()), None);
}
```

- [ ] **Step 2: Run them, watch them fail** (compile error: `dns` missing)

- [ ] **Step 3: Implement `dns.rs`**

- [ ] **Step 4: Run the crate's tests and `make lint`** (green; dependency rules unchanged)

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo-net
git commit -s -m "net: DNS driver with per-LAN UDP and TCP listeners bound to the bridges and an upstream socket pool"
```

### Task 7: The router's DNS task

**Files:**
- Create: `crates/openfeo/src/dns.rs`, `crates/openfeo/src/throttle.rs` (move `Throttle` and `NOISY_WINDOW` out of `dhcp4_server.rs`, `pub(crate)`); Modify: `crates/openfeo/src/dhcp4_server.rs` (use `crate::throttle::Throttle`), `crates/openfeo/src/main.rs` (`mod dns; mod throttle;`), `crates/openfeo/src/router.rs` (`crate::dns::spawn(&supervisor, &publisher, &world_rx);` after the DHCP server's `spawn_all`), `Cargo.toml` (dep `openfeo-proto-dns`)
- Test: unit tests in `dns.rs`

**Interfaces:**
- Consumes: `reconcile::dns::{desired, forwarder_config, DesiredDns}`, `openfeo_net::dns::{DnsDriver, DnsDriverConfig}`, `forwarder::Event`, `crate::dhcp4::wait_for_link`, `crate::throttle::Throttle`.
- Produces:

```rust
pub fn spawn(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx);   // one task, "dns"
fn upstreams_line(desired: &DesiredDns) -> String;   // `dns upstreams 9.9.9.9 203.0.113.1 (configured, learned from wan0)` | `dns upstreams 203.0.113.1 (learned from wan0)` | `dns upstreams 9.9.9.9 (configured)` | `dns no upstreams: only local names resolve`
fn event_line(event: &Event) -> Option<String>;      // UpstreamDown/Up, RebindDropped (throttled by the caller), Blocked; Configured and NoUpstreams are logged through upstreams_line instead
```

Task flow: wait until every listener bridge in `desired(&world).listeners` is up (`wait_for_link` per bridge, remembering the indexes); build the driver; log `dns listening on br-lan0`, the upstreams line and `dns local names {n}`; loop: `driver.step()` events → lines (rebind dropped through a `Throttle`); `world_rx.changed()` → recompute `desired`; when it differs from the last, `driver.configure(forwarder_config)` and log the upstreams line and `dns local names {n}` again; a listener bridge whose index changed restarts the task.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn upstream_lines_follow_the_contract() {
    let mut d = desired(&static_world());   // World::new(file::parse(VM_STATIC), PortMap::default()), as 3a's tests do
    assert_eq!(upstreams_line(&d), "dns upstreams 203.0.113.1 (learned from wan0)");
    d.upstreams.insert(0, Ipv4Addr::new(9, 9, 9, 9));
    assert_eq!(upstreams_line(&d), "dns upstreams 9.9.9.9 203.0.113.1 (configured, learned from wan0)");
    d.learned_from = None; d.upstreams = vec![Ipv4Addr::new(9, 9, 9, 9)];
    assert_eq!(upstreams_line(&d), "dns upstreams 9.9.9.9 (configured)");
    d.upstreams.clear();
    assert_eq!(upstreams_line(&d), "dns no upstreams: only local names resolve");
}
#[test]
fn event_lines_follow_the_contract() {
    assert_eq!(event_line(&Event::UpstreamDown(Ipv4Addr::new(9, 9, 9, 9))), Some("dns upstream 9.9.9.9 down".into()));
    assert_eq!(event_line(&Event::UpstreamUp(Ipv4Addr::new(9, 9, 9, 9))), Some("dns upstream 9.9.9.9 up".into()));
    assert_eq!(event_line(&Event::RebindDropped { name: "evil.isp.example".parse().unwrap(), addr: Ipv4Addr::new(192, 168, 1, 5).into(), client: Ipv4Addr::new(192, 168, 1, 50) }), Some("dns rebind dropped evil.isp.example -> 192.168.1.5 for 192.168.1.50".into()));
    assert_eq!(event_line(&Event::Configured { upstreams: 1, local: 2 }), None);
}
```

- [ ] **Step 2: Run them, watch them fail** (compile error: `dns` module missing)

- [ ] **Step 3: Move `Throttle`, implement `dns.rs`, wire `router.rs`**

- [ ] **Step 4: Run `cargo test -p openfeo` and `make kernel`** (green; image rebuilt)

- [ ] **Step 5: Commit**

```bash
git add crates/openfeo
git commit -s -m "openfeo: DNS forwarder task following the WAN's servers and the leases live, console contract"
```

### Task 8: Harness: dnsmasq upstream, dig, the dns sandbox suite

**Files:**
- Modify: `harness/src/daemons.rs` (`dnsmasq`), `harness/src/lab.rs` (`start_dnsmasq`, `ISP_DNS_*` consts), `harness/src/lanclient.rs` (`dig`, `parse_dig`), `harness/src/main.rs` (`run` starts dnsmasq; `check-env` lists `dnsmasq` and `dig`), `harness/Cargo.toml` (`[[test]] dns`, dev-dep `openfeo-proto-dns`), `Makefile` (`--test dns`), `.github/workflows/ci.yml` (`dnsmasq-base bind9-dnsutils`), `README.md` and `CLAUDE.md` tool lists
- Create: `harness/tests/dns.rs`
- Test: `lanclient` unit test for `parse_dig`; the suite

**Interfaces:**
- Produces:

```rust
// lab.rs
pub const ISP_DNS_ZONE: &str = "isp.example";
pub const ISP_WWW_ADDR: &str = "198.51.100.10";      // www.isp.example
pub const ISP_EVIL_ADDR: &str = "192.168.1.5";       // evil.isp.example: a rebinding answer
pub const ISP_ALLOWED_ADDR: &str = "192.168.1.6";    // allowed.isp.example: private but allow-listed in tests
pub fn start_dnsmasq(&mut self) -> Result<()>;        // on isp0's wan0 at 203.0.113.1, daemon named "dnsmasq"
// daemons.rs
pub fn dnsmasq(ns: &NetNs, iface: &str, run_dir: &Path) -> Result<Daemon>;
// `dnsmasq --no-daemon --log-queries --log-facility=- --no-hosts --no-resolv --interface=<iface> --bind-interfaces --except-interface=lo --auth-zone=isp.example --auth-server=ns.isp.example,<iface> --auth-soa=1,hostmaster.isp.example,30,30,30 --auth-ttl=60 --host-record=ns.isp.example,203.0.113.1 --host-record=www.isp.example,198.51.100.10 --host-record=evil.isp.example,192.168.1.5 --host-record=allowed.isp.example,192.168.1.6 --txt-record=big.isp.example,<250 x>,<250 y>,<250 z>`; ready when its log says `started, version`
// lanclient.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigAnswer { pub status: String /* NOERROR, NXDOMAIN, REFUSED, SERVFAIL */, pub flags: Vec<String>, pub answers: Vec<(String /*name*/, u32 /*ttl*/, String /*type*/, String /*rdata*/)> }
pub fn dig(ns: &NetNs, server: Ipv4Addr, name: &str, qtype: &str, extra: &[&str], timeout: Duration) -> Result<DigAnswer>;   // `dig @<server> +time=2 +tries=1 +noall +comments +answer <extra> <name> <qtype>`; a dig that times out is Err
pub fn parse_dig(stdout: &str) -> Result<DigAnswer>;
```

dnsmasq log lines to count: `auth[A] www.isp.example from 203.0.113.10`, `auth[TXT] big.isp.example from ...`; a TCP query logs the same.

Sandbox rig (`tests/dns.rs`): veth `n0`/`n1`, `n0` here at `192.168.1.1/24` up, `n1` in `NetNs::create("<lab>-lanhost")` at `192.168.1.50/24` up; veth `u0`/`u1`, `u0` here at `203.0.113.10/24` up, `u1` in `NetNs::create("<lab>-upstream")` at `203.0.113.1/24` up with `daemons::dnsmasq(&ns, "u1", ..)`. The driver: `DnsDriverConfig { listeners: ["n0"], forwarder: forwarder::Config { upstreams: [203.0.113.1], domain: home.arpa, router_name: openfeo.home.arpa, router_addrs: [192.168.1.1], lan_subnets: [192.168.1.0/24], local: [nas → .10, pc → .120], rebind_allow: [allowed.isp.example], cache_capacity: 64 }, seed }`, stepped with the `serve_while` pattern of `tests/dhcp4_server.rs` while `dig` runs in the LAN host namespace.

- [ ] **Step 1: Write the failing `parse_dig` test**

```rust
#[test]
fn dig_output_parses_status_flags_and_answers() {
    let out = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41696\n;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1\n; EDNS: version: 0, flags:; udp: 1232\nwww.isp.example.\t60\tIN\tA\t198.51.100.10\n";
    let parsed = parse_dig(out).unwrap();
    assert_eq!(parsed.status, "NOERROR");
    assert_eq!(parsed.flags, vec!["qr", "aa", "rd"]);
    assert_eq!(parsed.answers, vec![("www.isp.example.".into(), 60, "A".into(), "198.51.100.10".into())]);
    assert!(parse_dig(";; connection timed out; no servers could be reached\n").is_err());
}
```

- [ ] **Step 2: Run it, watch it fail; implement `dig`, `parse_dig`, `dnsmasq`, `start_dnsmasq`, the tool checks, the CI line and the docs; run `make check-env`** (dnsmasq and dig `ok`)

- [ ] **Step 3: Write the sandbox scenarios** (`LOOKUP: Duration = 5 s`)

- `local_names_resolve_authoritatively_and_never_leave`: `dig nas.home.arpa A` → NOERROR, flags contain `aa`, answer `192.168.1.10` TTL 60; `dig 10.1.168.192.in-addr.arpa PTR` → `nas.home.arpa.`; `dig openfeo.home.arpa A` → `192.168.1.1`; `dig printer.home.arpa A` → NXDOMAIN with `aa`; dnsmasq log count of `auth[` is 0.
- `isp_names_resolve_through_the_upstream_once_and_then_from_the_cache`: `dig www.isp.example A` → `198.51.100.10`, flags contain `ra` and not `aa`; dnsmasq `auth[A] www.isp.example` count 1; a second dig → answered, count still 1, TTL ≤ the first.
- `negative_answers_are_cached`: `dig nx.isp.example A` twice → NXDOMAIN both times; dnsmasq count 1.
- `big_answers_truncate_over_udp_and_arrive_whole_over_tcp`: `dig big.isp.example TXT +bufsize=512` → dig retries over TCP by itself and the three strings arrive (assert 3 answers); dnsmasq log shows `auth[TXT] big.isp.example` at least twice (UDP truncated, then TCP); `dig +tcp www.isp.example A` works too.
- `rebinding_answers_are_refused_unless_allowed`: `dig evil.isp.example A` → REFUSED; `dig allowed.isp.example A` → `192.168.1.6`; the driver's events contain `RebindDropped` for `evil.isp.example` once.
- `a_dead_upstream_is_skipped_after_one_timeout`: configure upstreams `[203.0.113.99, 203.0.113.1]`; the first dig takes under 3.5 s and succeeds; the second under 0.5 s; events contain `UpstreamDown(203.0.113.99)`.
- `reconfiguration_takes_effect_live`: configure upstreams `[203.0.113.99]` → `dig other.isp.example` → SERVFAIL (dig's own timeout is 2 s, so use `+time=4`); configure back → NOERROR.
- `the_wan_side_is_not_served`: `dig @203.0.113.10 www.isp.example` from the upstream namespace → Err (timed out).
- `without_upstreams_local_names_still_resolve`: configure upstreams `[]` → `dig nas.home.arpa` NOERROR; `dig www.isp.example` SERVFAIL within 0.5 s; events contain `NoUpstreams` once.

- [ ] **Step 4: Run the suite until green**

Run: `cargo test -p openfeo-harness --test dns`
Expected: `result: ok. 9 passed; 0 failed; 0 skipped`.

- [ ] **Step 5: `make lint`, then commit**

```bash
git add harness Makefile .github/workflows/ci.yml README.md CLAUDE.md
git commit -s -m "harness: dnsmasq upstream, dig client, and the dns sandbox suite"
```

### Task 9: QEMU acceptance and docs

**Files:**
- Modify: `harness/tests/m1.rs` (three new scenarios, one extended), `README.md` (status paragraph), `CLAUDE.md` (harness paragraph)
- Test: the m1 suite

**Interfaces:**
- Consumes: Task 8's `lanclient::dig`, `Lab::start_dnsmasq`; the console contract.

Helpers in `m1.rs`: `const ROUTER_DNS: Ipv4Addr = 192.168.1.1`; `fn dig_lan(lab, name, qtype) -> Result<DigAnswer>` from `lab.lan0`.

- [ ] **Step 1: Write the scenarios**

- `lan_client_resolves_nas_home_arpa` (SPEC §12 M1): `boot_static_with_lan_host`; `lab.start_dnsmasq()` beforehand; `dig_lan("nas.home.arpa", "A")` → `192.168.1.10` with `aa`; `dig_lan("openfeo.home.arpa", "A")` → `192.168.1.1`; `dig_lan("printer.home.arpa", "A")` → NXDOMAIN; console shows `openfeo: dns listening on br-lan0` and `openfeo: dns upstreams 203\.0\.113\.1 \(learned from wan0\)` (the static WAN's `dns`), `openfeo: dns local names 1`.
- `lan_client_resolves_isp_names_through_the_learned_upstream`: `lab.start_dnsmasq()`, `boot_dhcp` (Kea hands out DNS 203.0.113.1); after `bound`, console `openfeo: dns upstreams 203\.0\.113\.1 \(learned from wan0\)`; `dig_lan("www.isp.example", "A")` → `198.51.100.10`; before the lease the console said `openfeo: dns no upstreams: only local names resolve` (count ≥ 1).
- `rebinding_answers_are_refused`: `boot_static_with_lan_host` with dnsmasq; `dig_lan("evil.isp.example", "A")` → REFUSED; console `openfeo: dns rebind dropped evil\.isp\.example -> 192\.168\.1\.5 for 192\.168\.1\.2`.
- Extend `dhcp_without_a_server_keeps_the_lan_working`: after the ping, `dig_lan("nas.home.arpa", "A")` → `192.168.1.10` (local names work with no WAN at all).

- [ ] **Step 2: Run the new scenarios**

Run: `make test-harness FILTER=resolves` then `FILTER=rebinding` then `FILTER=without_a_server`
Expected: all pass.

- [ ] **Step 3: README status and CLAUDE.md**

README gains, after the DHCP server sentence: "The router answers DNS on each LAN: `<hostname>.home.arpa` and reverse names from the leases and reservations, everything else through upstreams typed in or learned from the WAN, with a TTL cache, negative caching, EDNS0, TCP, and rebinding protection; block lists are the next thing to slot in. Still to come in M1: SNTP." CLAUDE.md's harness paragraph names the `dns` sandbox suite, dnsmasq in authoritative mode as the upstream on isp0, and `dig`.

- [ ] **Step 4: `make ci`**

Expected: green; harness counts dhcp4 5, dhcp4_server 10, dns 9, m0 5, m1 22, netlink 15 (+1 skipped locally), nft 4 (+1 skipped locally).

- [ ] **Step 5: Commit**

```bash
git add harness/tests/m1.rs README.md CLAUDE.md
git commit -s -m "harness: DNS scenarios (nas.home.arpa, names through the learned upstream, rebinding refused, local names without a WAN); docs"
```

---

## Self-review notes

- Spec coverage (§7.7): every LAN address over UDP and TCP 53 (Task 6; IPv6 in M2); TTL cache with negative caching (Task 2); EDNS0 at 1232 and truncation → TCP (Tasks 3, 4, 6); no recursion of our own, DNSSEC bits passed through, no validation (Task 3); cache size fixed in M1 with the note (Task 2); upstreams learned per WAN or configured (Task 5); DoT deferred to M4 (ruling for the executor); local zone with static leases resolving before they are active (Tasks 3, 5); rebinding protection with an allow-list (Tasks 4, 5); the block-list slot (Task 3's `Policy`, Task 5's reserved `blocklists`); the parser choice and its ADR (Task 1). §12: `resolves nas.home.arpa` (Task 9).
- Type consistency: `forwarder::Config`, `Input`, `Output`, `Event`, `Transport`, `QueryId` are defined in Task 3 and consumed unchanged by Tasks 4, 6, 7, 8; `DesiredDns` from Task 5 feeds Task 7; `DigAnswer` from Task 8 feeds Task 9.
- Proportion: code blocks are tests and signatures; the only prose algorithms are the query pipeline and the upstream choice, which the tests alone would not pin.
