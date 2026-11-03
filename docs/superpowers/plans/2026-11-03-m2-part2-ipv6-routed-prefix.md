# M2 Part 2: IPv6 with a Statically Routed Prefix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** IPv6 end to end for a router whose ISP routes a fixed prefix to it: a WAN client that learns the ISP's router and link facts from advertisements, per-LAN /64s named in config and advertised by an RA server whose router lifetime follows the kernel's default route, the IPv6 half of routing, firewall and DNS, and the route gate that makes every learned fact wait for its route.

**Architecture:** One new pure crate, `openfeo-proto-ndp` (wire codec, RA client core, RA server core, RFC 7217 identifiers over an in-tree SHA-256), driven by a raw ICMPv6 socket in `openfeo-net`. Facts flow into the `World` (a `WanIpv6Fact` per WAN, the kernel's default routes from the netlink monitor); the reconcilers for routing, sysctl, links, nft and dns grow their IPv6 halves and a new `reconcile::ra` decides each LAN's advertisement; two new service tasks in `crates/openfeo` run the WAN client and the LAN servers. The lab gains radvd on the ISP side, `rdisc6` on the LAN side and the kernel as the SLAAC client.

**Tech Stack:** Rust stable, edition 2024, musl; tokio in drivers only; nix for sockets with the two new `unsafe` calls in `openfeo-net/src/sys.rs`; rtnetlink/netlink-packet-route; libnftables JSON; insta snapshots; cargo-fuzz with smoltcp 0.14 as the NDP oracle; radvd, ndisc6, dnsmasq, python3 in the lab.

**Spec:** `docs/superpowers/specs/2026-11-03-m2-part2-ipv6-routed-prefix-design.md` (the design); `SPEC.md` §5.2, §7.3, §7.4, §7.5, §7.7, §8.2, §11, §12, §13 (the authority the design argues from).

## Global Constraints

- `CLAUDE.md` in full: `clippy -D warnings`, no `unwrap`/`expect` outside tests, `thiserror` in libraries, `anyhow` only in `crates/openfeo` and `harness/`, `#![forbid(unsafe_code)]` everywhere but `openfeo-init`, `openfeo-nft`, `openfeo-net` (there, `unsafe` only in `sys.rs` with `// SAFETY:`), `std::process::Command` banned outside `harness/` and `image/`, SPDX header and `Copyright (C) 2026 Andrew Newton` on every source file, commits `git commit -s` as `Andrew Newton <andy@vitri.ltd>` with subject `<area>: <summary>`.
- `openfeo-proto-ndp`, `openfeo-reconcile` and `openfeo-world` stay pure: no tokio, libc, nix, socket2, rtnetlink, netlink-sys or netlink-proto in their dependency trees (`scripts/check-deps.sh` enforces it). The one hash in the binary is in-tree SHA-256; no `sha2`, no `ring`.
- Every parser gets a fuzz target in this PR: `ndp_wire`, `ndp_differential`, `ndp_client`, `ndp_server`; the config target already drives validation.
- Routes and addresses the router owns carry `RTPROT_OPENFEO = 200`; the ruleset stays one `table inet openfeo` applied as one batch; nothing kernel-originated is ever deleted.
- Documentation ranges only in repo text: `2001:db8::/48` is the routed prefix, `2001:db8:ffff::/64` the ISP link, `2001:db8:222::/64` lan0, `2001:db8:232::/64` the DMZ, `203.0.113.0/24` and `192.0.2.0/24` as before.
- Existing behaviour for a configuration without IPv6 does not change: every existing `insta` snapshot stays byte-identical, every M0, M1 and M2 part 1 scenario keeps passing.
- Nothing is pushed and no PR is opened without Andy's word; the branch is `m2-2` from `main` `112d813`, design committed as `c6817b8`.

## Review Focus

Five conditions the design implies that a person would hit, each pinned by a test named in its owning task:

1. The ISP advertises a prefix with the A flag but a length other than 64: no address is made up, the on-link route still lands, nothing panics (Task 6, `a_prefix_that_is_not_a_slash_64_yields_no_address`).
2. An advertisement whose option length runs past the packet, or is zero: the decoder refuses it and the client learns nothing from it (Task 5, `an_option_running_past_the_end_or_of_length_zero_is_refused`; Task 6, `a_malformed_advertisement_is_ignored`).
3. The WAN loses carrier while LANs advertise: within one `MIN_DELAY_BETWEEN_RAS` every LAN hears router lifetime 0, and the default returns when carrier does (Task 13, `lifetime_follows_the_wan_carrier_and_route`; Task 16, `wan_ipv6_loss_zeroes_the_router_lifetime_within_one_interval`).
4. A LAN's `ipv6` lies outside the declared prefix or in its first /64: validation names the field and the fix (Task 2, `a_lan_prefix_outside_the_routed_prefix_is_refused`, `a_lan_may_not_take_the_prefixs_first_slash_64`).
5. A LAN host floods router solicitations: the server answers at most once per 3 seconds and never more than one advertisement per solicitation burst (Task 7, `a_burst_of_solicitations_gets_one_answer_per_three_seconds`).

---

## File structure

New:
- `crates/openfeo-proto-ndp/{Cargo.toml, src/lib.rs, src/sha256.rs, src/iid.rs, src/wire.rs, src/client.rs, src/server.rs}` — pure: codec, RFC 7217, the two cores.
- `crates/openfeo-net/src/ndp.rs` — the raw ICMPv6 socket driver; `sys.rs` grows two `unsafe` helpers.
- `crates/openfeo-world/src/ipv6.rs` — `WanIpv6Fact`, `DefaultRoute`.
- `crates/openfeo-reconcile/src/ra.rs` — `DesiredRa` per LAN.
- `crates/openfeo/src/ipv6.rs` — the identity secret and the WAN client task; `crates/openfeo/src/ra.rs` — the LAN server task.
- `fuzz/fuzz_targets/{ndp_wire, ndp_differential, ndp_client, ndp_server}.rs`.
- `harness/tests/ndp.rs` — the sandbox suite; `harness/fixtures/vm-ipv6.toml`.
- `docs/adr/0018-in-tree-ndp-codec.md`, `docs/adr/0019-learned-facts-wait-for-the-kernel-route.md`, `docs/adr/0020-ipv6-blackhole-routes-report-lo.md`.

Modified: `SPEC.md`, `proto/openfeo/v1/config.proto`, `crates/openfeo-config/src/{validate.rs, rules.rs}`, `crates/openfeo-world/src/{lib.rs, world.rs}`, `crates/openfeo-netlink/src/{types.rs, apply.rs, monitor.rs}`, `crates/openfeo-reconcile/src/{lib.rs, routing.rs, sysctl.rs, links.rs, nft.rs, dns.rs, fixtures.rs}`, `crates/openfeo-apply/src/{links.rs, routing.rs}`, `crates/openfeo-proto-dns/src/forwarder.rs`, `crates/openfeo-net/src/{lib.rs, bound.rs, dns.rs}`, `crates/openfeo/src/{main.rs or lib.rs, router.rs, dns.rs}`, `harness/src/{lab.rs, daemons.rs, lanclient.rs, main.rs}`, `harness/tests/{netlink.rs, nft.rs, dns.rs, m2.rs}`, `harness/Cargo.toml`, `Makefile`, `fuzz/Cargo.toml`, `deny.toml`, `docs/third-party.md`, `.github/workflows/ci.yml`, `scripts/cloud-setup.sh`, `CLAUDE.md`, `docs/progress.md`, `docs/adr/0013-*.md`.

---

### Task 1: SPEC amendments and the ADRs

**Files:**
- Modify: `SPEC.md` §5.2, §7.3, §7.4, §7.5, §7.7, §8.2, §9, §11, §13
- Modify: `docs/adr/0013-unsafe-for-packet-socket-addresses-in-openfeo-net.md` (a dated "Amended" paragraph)
- Create: `docs/adr/0018-in-tree-ndp-codec.md`, `docs/adr/0019-learned-facts-wait-for-the-kernel-route.md`
- Modify: `docs/third-party.md` (smoltcp as a test dependency), `deny.toml` (`"0BSD"` in `allow`)

**Interfaces:**
- Produces: the names every later task uses in text: `[wans.ipv6]` with `prefix`, `gateway`, `mode`; `Lan.ipv6`, `Lan.ra`; `[[dns.records]]` with `name`, `address`; `identity/ipv6-secret`; the ICMPv6 lists; the route gate rule.

- [ ] **Step 1: Amend SPEC.md** as the design's "SPEC amendments" section lists, one bullet per section, copying the design's wording where it already is spec-grade: §5.2 (the secret in `identity/`), §7.3 (static routed prefix first class; `prefix`, LAN `ipv6`, the loopback `::1` of the first /64, typed `gateway`, O = 0 until part 3, PIO lifetimes 2592000/604800, the RFC 4890 lists, the route gate), §7.4 (IPv6 default with preferred source; blackhole for the prefix), §7.5 (IPv6 half of zones and rules; `proto = "icmp"` per family; WAN input ICMPv6 list; link-local sources skip the loose check; public-LAN services per family), §7.7 (AAAA for the router and records; `[[dns.records]]`; IPv6 listeners, upstreams, guard, reverse zones), §8.2 (the example gains `prefix`/`gateway`, `ipv6`/`ra`, `[[dns.records]]`, an IPv6 upstream and rule), §9 (`openfeo-net`'s `unsafe` covers ICMPv6 socket options), §11 (radvd, `ndisc6`, the kernel as SLAAC client), §13 (fuzz targets for `openfeo-proto-ndp`).

- [ ] **Step 2: Write ADR-0018 and ADR-0019** in the format of ADR-0015 (title line, `Status: Accepted (3 November 2026)`, Context, Decision, Consequences), with the content of the design's "ADRs" section. Append to ADR-0013 a paragraph "Amended 3 November 2026: `sys.rs` also holds the `ICMP6_FILTER` option and the interface-scoped IPv6 multicast join of the NDP driver (ADR-0018)".

- [ ] **Step 3: third-party and deny.** Add to `docs/third-party.md`'s "Not in the binary" paragraph: smoltcp (0BSD) as a dev-dependency of `openfeo-proto-ndp` and a fuzz dependency, the oracle of the NDP codec (ADR-0018). Add `"0BSD"` to `deny.toml` `[licenses] allow`.

- [ ] **Step 4: Verify**

Run: `make lint 2>&1 | tail -n 5`
Expected: exit 0 (no code changed; the SPDX check passes; deny accepts the list).

- [ ] **Step 5: Commit**

```bash
git add SPEC.md docs/adr docs/third-party.md deny.toml
git commit -s -m "docs: SPEC amendments and ADRs for M2 part 2 (IPv6, routed prefix)"
```

---

### Task 2: Config schema and validation

**Files:**
- Modify: `proto/openfeo/v1/config.proto` (`Wan.ipv6`, `Lan.ipv6`, `Lan.ra`, `Dns.records`)
- Modify: `crates/openfeo-config/src/rules.rs` (IPv6 targets), `crates/openfeo-config/src/validate.rs`
- Create: `harness/fixtures/vm-ipv6.toml`
- Test: `crates/openfeo-config/src/validate.rs` (tests module), `crates/openfeo-config/src/rules.rs`

**Interfaces:**
- Produces (prost-generated, `openfeo_config::{Wan, Ipv6Wan, Lan, Dns, Record}`): `Wan.ipv6: Option<Ipv6Wan>`; `Ipv6Wan { mode: String, prefix: String, gateway: String }`; `Lan.ipv6: String`; `Lan.ra: Option<bool>`; `Dns.records: Vec<Record>`; `Record { name: String, address: String }`.
- Produces: `rules::Target6 { Addr(Ipv6Addr), Range(Ipv6Addr, Ipv6Addr), Net(Ipv6Net) }` with `within(&self, net: Ipv6Net) -> bool`, `rules::parse_target6(text: &str) -> Option<Target6>`, `rules::is_global_unicast_v6(net: Ipv6Net) -> bool` (`2000::/3`).
- Produces: `validate::Code::{InvalidIpv6Prefix, Ipv6WanTwice, LanPrefixOutsideRouted, LanPrefixReserved, LanPrefixWithoutRouted, RaWithoutIpv6, Ipv6Disabled, DuplicateRecord, RecordNameTaken}`; the fixture `vm-ipv6.toml`.

- [ ] **Step 1: Add the proto fields** with doc comments matching the design: `Ipv6Wan ipv6 = 7` on `Wan` (`// Present when the WAN carries IPv6 (SPEC §7.3): mode auto|disabled, the prefix the ISP routes here, a typed default gateway.`), `string ipv6 = 6` and `optional bool ra = 7` on `Lan`, `repeated Record records = 5` on `Dns` with `message Record { string name = 1; string address = 2; }`.

- [ ] **Step 2: Write the fixture** `harness/fixtures/vm-ipv6.toml`: `vm-static.toml` plus

```toml
[wans.ipv6]
prefix = "2001:db8::/48"
```
under the WAN, `ipv6 = "2001:db8:222::1/64"` on `lan0`, a second LAN `dmz` on `p3` with `ipv4 = "192.0.2.233/29"` inside a declared `[[public_ipv4]] prefix = "192.0.2.232/29"`, `ipv6 = "2001:db8:232::1/64"`, `ra = false`; `[dns] upstreams = ["203.0.113.1", "2001:db8:ffff::1"]`; `[[dns.records]] name = "www" address = "2001:db8:232::10"`; `[[firewall.rules]] name = "dmz-web6" from = "wan" to = "2001:db8:232::10" proto = "tcp" ports = ["80"]`; keep `wan_ping = true` and the `lan-http` forward. Header comment as the other fixtures.

- [ ] **Step 3: Write the failing validation tests** in `validate.rs`'s tests module, each loading a TOML string through the existing test helper and asserting on `Violation { path, code, .. }`:

```rust
#[test] fn the_ipv6_fixture_validates()                         // vm-ipv6.toml → no violations
#[test] fn a_second_ipv6_wan_is_refused()                       // wans[1].ipv6 → Ipv6WanTwice
#[test] fn an_ipv6_prefix_must_be_global_unicast_and_at_most_63_bits() // "fd00::/48" and "2001:db8::/64" → InvalidIpv6Prefix at wans[0].ipv6.prefix
#[test] fn a_typed_gateway_must_be_an_ipv6_address()            // "203.0.113.1" → InvalidAddress at wans[0].ipv6.gateway
#[test] fn mode_disabled_beside_a_prefix_or_a_lan_prefix_is_refused() // Ipv6Disabled at wans[0].ipv6.mode
#[test] fn a_lan_prefix_outside_the_routed_prefix_is_refused()  // "2001:db8:1:222::1/64" → LanPrefixOutsideRouted at lans[0].ipv6
#[test] fn a_lan_may_not_take_the_prefixs_first_slash_64()      // "2001:db8::1/64" → LanPrefixReserved
#[test] fn a_lan_prefix_must_be_a_slash_64_with_a_host_address() // "/56" and "2001:db8:222::/64" → InvalidCidr
#[test] fn a_lan_prefix_needs_a_routed_prefix()                 // no [wans.ipv6].prefix → LanPrefixWithoutRouted
#[test] fn two_lans_may_not_share_a_slash_64()                  // → Overlap at lans[1].ipv6
#[test] fn ra_without_ipv6_is_refused()                         // RaWithoutIpv6 at lans[0].ra
#[test] fn records_are_unique_per_name_and_family()             // two AAAA "www" → DuplicateRecord; "www" A + AAAA → ok
#[test] fn a_record_may_not_name_the_router_or_a_reservation()  // "openfeo" and "nas" → RecordNameTaken
#[test] fn an_ipv6_upstream_is_accepted_and_the_routers_own_lan_address_is_not() // "2001:db8:222::1" → InvalidAddress
#[test] fn an_ipv6_rule_target_lies_inside_one_lans_slash_64()  // "2001:db8:5::10" → InvalidRuleTarget; "2001:db8:232::10-2001:db8:232::20" ok
#[test] fn ipv6_rules_overlap_within_their_family_only()        // two overlapping v6 tcp 80 rules → OverlappingRules; a v4 and a v6 rule on port 80 → ok
```

and in `rules.rs`: `parse_target6_accepts_address_range_and_cidr`, `is_global_unicast_v6_excludes_ula_link_local_and_loopback`.

- [ ] **Step 4: Run them**

Run: `cargo test -p openfeo-config 2>&1 | tail -n 20`
Expected: compile errors for the missing fields and codes, then failures for each new test.

- [ ] **Step 5: Implement** `parse_target6`, `is_global_unicast_v6`, the codes, and the checks in `validate()`: the WAN pass records `(path, Ipv6Net)` of the one prefix in `Pools` (new fields `ipv6_prefix: Option<(String, Ipv6Net)>`, `lan_prefixes: Vec<(String, Ipv6Net)>`), the LAN pass checks `ipv6` (parse as `Ipv6Net` with host bits, prefix_len == 64, inside the routed prefix, not equal to `routed.trunc()`'s first /64, pairwise disjoint), `ra` only with `ipv6`; `dns()` takes the LAN IPv6 addresses for the "router's own address" check and validates records (`is_valid_label` or `is_valid_hostname` for `name`, `IpAddr` for `address`, uniqueness per `(name lowercase, family)`, name not the hostname and not a reservation hostname); `rule_target` tries `parse_target` then `parse_target6` and checks per family; `overlapping_rules` groups by family. Messages name the field and the fix as the existing ones do.

- [ ] **Step 6: Run again**

Run: `cargo test -p openfeo-config 2>&1 | tail -n 5` then `make lint 2>&1 | tail -n 3`
Expected: all pass; lint clean (the config fuzz target still compiles).

- [ ] **Step 7: Commit**

```bash
git add proto crates/openfeo-config harness/fixtures/vm-ipv6.toml
git commit -s -m "config: [wans.ipv6], LAN ipv6 and ra, dns.records, IPv6 rule targets"
```

---

### Task 3: The identity secret

**Files:**
- Create: `crates/openfeo/src/ipv6.rs` (module registered in `main.rs`/`lib.rs` beside `dhcp4`)
- Modify: `crates/openfeo/src/router.rs` (load it after `name_ports`)
- Test: `crates/openfeo/src/ipv6.rs`

**Interfaces:**
- Produces: `pub const IPV6_SECRET_PATH: &str = "/state/identity/ipv6-secret";` `pub fn load_or_create_ipv6_secret(path: &Path) -> io::Result<([u8; 16], bool)>` (hex file, mode 0600, `true` when just made; a file that is not 32 hex digits is replaced with a warning, as `load_or_create_duid` does); `pub fn random_secret() -> io::Result<[u8; 16]>` reading `/dev/urandom`.

- [ ] **Step 1: Write the failing tests** (tempfile):

```rust
#[test] fn a_missing_secret_is_made_persisted_and_read_back_unchanged()
#[test] fn a_corrupt_secret_file_is_replaced()
#[test] fn the_secret_file_is_mode_0600_and_32_hex_digits_plus_newline()
```

- [ ] **Step 2: Run** `cargo test -p openfeo ipv6:: 2>&1 | tail -n 8` — Expected: FAIL (module missing).

- [ ] **Step 3: Implement** with the same atomic write the DUID uses; in `router.rs` call it after `name_ports` and log `identity: ipv6 secret created` or `… loaded`; keep the value for Task 10's `LinksApplier`.

- [ ] **Step 4: Run** the same — Expected: PASS.

- [ ] **Step 5: Commit** `git commit -s -m "router: persist the IPv6 stable-privacy secret in identity/"`

---

### Task 4: `openfeo-proto-ndp`: SHA-256 and RFC 7217 identifiers

**Files:**
- Create: `crates/openfeo-proto-ndp/Cargo.toml` (deps: `ipnet`, `thiserror`; dev-deps: none yet), `src/lib.rs` (`#![forbid(unsafe_code)]`, `pub type Timestamp = u64;` milliseconds like the other cores), `src/sha256.rs`, `src/iid.rs`

**Interfaces:**
- Produces: `sha256::digest(data: &[u8]) -> [u8; 32]`; `iid::stable_address(prefix: Ipv6Net, ifname: &str, secret: &[u8; 16], dad_counter: u8) -> Ipv6Addr` (RFC 7217 §5: `F = SHA-256(prefix bytes || ifname || dad_counter || secret)`, the first 64 bits as the identifier, the counter bumped while the identifier is reserved by RFC 5453); `iid::is_reserved(iid: u64) -> bool`.

- [ ] **Step 1: Failing tests**

```rust
// sha256.rs
#[test] fn rfc_6234_vectors()   // "" → e3b0c442…b855, "abc" → ba7816bf…15ad, the 56-byte "abcdbcde…nopq" → 248d6a61…c3e5, one million 'a' → cdc76e5c…a2d9 (ignored unless --ignored? no: 1 MB hashes in ms; keep it)
// iid.rs
#[test] fn the_address_is_stable_for_the_same_inputs_and_differs_per_prefix_ifname_secret_and_counter()
#[test] fn reserved_identifiers_are_skipped_by_bumping_the_counter()  // is_reserved(0) and the RFC 5453 ranges; a crafted case via is_reserved
#[test] fn the_address_lies_in_the_prefix()
```

- [ ] **Step 2: Run** `cargo test -p openfeo-proto-ndp 2>&1 | tail -n 6` — Expected: FAIL (crate missing).

- [ ] **Step 3: Implement** the crate skeleton, `sha256.rs` (FIPS 180-4, no dependency) and `iid.rs`.

- [ ] **Step 4: Run** again, then `scripts/check-deps.sh` via `make lint` — Expected: PASS; the crate is listed pure.

- [ ] **Step 5: Commit** `git commit -s -m "proto-ndp: in-tree SHA-256 and RFC 7217 stable identifiers"`

---

### Task 5: NDP wire codec and its fuzz targets

**Files:**
- Create: `crates/openfeo-proto-ndp/src/wire.rs`; `fuzz/fuzz_targets/ndp_wire.rs`, `fuzz/fuzz_targets/ndp_differential.rs`
- Modify: `crates/openfeo-proto-ndp/Cargo.toml` (dev-dep `smoltcp = { version = "0.14", default-features = false, features = ["proto-ipv6", "medium-ethernet"] }`), `fuzz/Cargo.toml` (same smoltcp, two `[[bin]]`)

**Interfaces:**
- Produces: `wire::Message { RouterSolicitation { options: Vec<Option> }, RouterAdvertisement(RouterAdvertisement) }`; `RouterAdvertisement { cur_hop_limit: u8, managed: bool, other: bool, router_lifetime: u16, reachable_time: u32, retrans_timer: u32, preference: Preference, options: Vec<Option> }`; `Preference { Low, Medium, High }` (RFC 4191 §2.1, reserved 10 reads as Medium); `Option { SourceLinkLayer([u8; 6]), PrefixInformation { prefix: Ipv6Net, on_link: bool, autonomous: bool, valid: u32, preferred: u32 }, Mtu(u32), RouteInformation { prefix: Ipv6Net, preference: Preference, lifetime: u32 }, Rdnss { lifetime: u32, addrs: Vec<Ipv6Addr> }, Dnssl { lifetime: u32, names: Vec<String> }, Unknown { kind: u8, data: Vec<u8> } }`; `Message::decode(bytes: &[u8]) -> Result<Message, Error>` (type 133 or 134 only; code must be 0; length ≥ 8 for RS, ≥ 16 for RA; every option length ≥ 1 unit and within the packet; a prefix option with prefix length > 128, an RDNSS whose body is not 16n + 6, a DNSSL label over 63 bytes or running past its option: `Error::Malformed`); `Message::encode(&self) -> Vec<u8>` with the checksum field zero; `Error { Malformed(&'static str), NotNdp(u8) }`. DNSSL names are encoded as uncompressed DNS labels and padded to 8-byte units with zeros.

- [ ] **Step 1: Failing tests** in `wire.rs`:

```rust
#[test] fn an_advertisement_with_every_option_round_trips()   // SLLAO, PIO 2001:db8:ffff::/64 A+L 2592000/604800, MTU 1500, RouteInfo 2001:db8:1::/48 High 3600, RDNSS [2001:db8:ffff::1] 1800, DNSSL ["isp.example"] 1800: encode → decode == original, and the 16-byte header fields match RFC 4861 §4.2 byte positions
#[test] fn a_solicitation_round_trips_and_a_type_other_than_133_or_134_is_not_ndp()
#[test] fn an_option_running_past_the_end_or_of_length_zero_is_refused()
#[test] fn an_unknown_option_is_kept_and_re_encoded_verbatim()
#[test] fn dnssl_padding_and_rdnss_body_lengths_are_checked()
#[test] fn preference_10_reads_as_medium()
```

- [ ] **Step 2: Run** `cargo test -p openfeo-proto-ndp wire 2>&1 | tail -n 8` — Expected: FAIL.

- [ ] **Step 3: Implement** `wire.rs`.

- [ ] **Step 4: Run** again — Expected: PASS.

- [ ] **Step 5: Fuzz targets.** `ndp_wire`: `Message::decode(data)`; on `Ok(m)`, `Message::decode(&m.encode()) == Ok(m)`. `ndp_differential`: ours vs `smoltcp::wire::NdiscRepr::parse(&smoltcp::wire::Icmpv6Packet::new_checked(data)?)` with `ChecksumCapabilities::ignored()`: when smoltcp parses an RS or RA and we refuse, panic; when both parse an RA, `cur_hop_limit`, `router_lifetime`, `reachable_time`, `retrans_timer` and the M/O flags agree, and for each of our SLLAO, PIO and MTU options smoltcp's `NdiscRouterAdvert` fields (`lladdr`, `prefix_info`, `mtu`) agree where smoltcp exposes them (it keeps one of each); options 24, 25 and 31 are ours alone and are not compared. A packet we parse and smoltcp refuses is tolerated.

- [ ] **Step 6: Verify the targets build and run briefly**

Run: `cargo check --manifest-path fuzz/Cargo.toml --bins 2>&1 | tail -n 3` and `make fuzz FUZZ_TARGET=ndp_differential FUZZ_SECS=30 2>&1 | tail -n 5`
Expected: both build; 30 s of fuzzing without a crash (a panic is a finding to fix before moving on).

- [ ] **Step 7: Commit** `git commit -s -m "proto-ndp: RS/RA codec with RFC 8106 and 4191 options, fuzzed against smoltcp"`

---

### Task 6: The RA client core

**Files:**
- Create: `crates/openfeo-proto-ndp/src/client.rs`; `fuzz/fuzz_targets/ndp_client.rs`
- Test: `client.rs`

**Interfaces:**
- Consumes: Task 5's `wire`, Task 4's `iid`.
- Produces: `client::Client::new(config: Config) -> Client`; `Config { ifname: String, secret: [u8; 16], mac: [u8; 6] }`; `Input { LinkUp, LinkDown, Advertisement { from: Ipv6Addr, hop_limit: u8, bytes: Vec<u8> }, Timeout }`; `Output { Solicit(Vec<u8>) /* an RS with SLLAO, to ff02::2 */, Learned(Learned), Note(Note) }`; `Learned { router: Option<Ipv6Addr>, addresses: Vec<Ipv6Net>, on_link: Vec<Ipv6Net>, routes: Vec<Route>, dns: Vec<Ipv6Addr>, search: Vec<String>, mtu: Option<u32> }` (`#[derive(Default, PartialEq)]`, emitted only when it differs from the last one emitted); `Route { prefix: Ipv6Net, via: Ipv6Addr, preference: Preference }`; `Note { Ignored(&'static str), LinkLocalResolverDropped(Ipv6Addr), StillSoliciting }`; `Client::handle(&mut self, input: Input, now: Timestamp) -> Vec<Output>`; `Client::next_timeout(&self) -> Option<Timestamp>`; constants `RTR_SOLICITATION_INTERVAL = 4_000`, `MAX_RTR_SOLICITATIONS = 3`, `RS_BACKOFF_MAX = 3_600_000`, `TWO_HOURS = 7_200`.
- Behaviour pinned: a `LinkUp` sends an RS at once and schedules the next; after three, the interval doubles from 4 s to the cap (RFC 7559); `StillSoliciting` is noted once when the cap is first reached. An advertisement is ignored (with `Note::Ignored`) unless `hop_limit == 255` and `from` is in `fe80::/10` and decodes as an RA. Router: `router_lifetime > 0` sets it (highest `preference`, then most recent, among several); 0 or expiry clears it, leaving the rest. PIO: A flag and prefix length 64 → `iid::stable_address(prefix, ifname, secret, 0)` with the option's lifetimes, valid lifetime applied under RFC 4862 §5.5.3 (a cut below `TWO_HOURS` s remaining is clamped to two hours unless the advertised valid lifetime exceeds the remaining one); L flag → `on_link`; a prefix with length ≠ 64 contributes the on-link route only. RDNSS/DNSSL/RouteInformation with lifetimes, link-local RDNSS entries dropped with the note. Every lifetime is a timer; `Timeout` expires what is due and emits `Learned` if anything changed. `LinkDown` clears everything and emits `Learned::default()`.

- [ ] **Step 1: Failing tests**

```rust
#[test] fn link_up_solicits_three_times_four_seconds_apart_then_backs_off_to_an_hour()
#[test] fn an_advertisement_with_a_router_is_learned_and_expires_on_its_lifetime()
#[test] fn a_lifetime_zero_advertisement_withdraws_the_router_but_keeps_the_link_address()
#[test] fn a_prefix_with_a_and_l_yields_an_address_and_an_on_link_route()
#[test] fn a_prefix_that_is_not_a_slash_64_yields_no_address()
#[test] fn the_two_hour_rule_bounds_a_cut_valid_lifetime()
#[test] fn rdnss_dnssl_and_route_information_are_learned_and_a_link_local_resolver_is_dropped()
#[test] fn the_preferred_router_wins_and_recency_breaks_ties()
#[test] fn advertisements_below_hop_limit_255_or_from_a_global_source_are_ignored()
#[test] fn a_malformed_advertisement_is_ignored()
#[test] fn a_refresh_with_the_same_content_emits_nothing()
#[test] fn link_down_clears_everything_and_link_up_solicits_again()
```

- [ ] **Step 2: Run** `cargo test -p openfeo-proto-ndp client 2>&1 | tail -n 15` — Expected: FAIL.

- [ ] **Step 3: Implement** `client.rs`.

- [ ] **Step 4: Run** again — Expected: PASS.

- [ ] **Step 5: Fuzz target** `ndp_client`: `LinkUp`, then the input bytes as `Advertisement { from: fe80::1, hop_limit: 255 }` at 1, then `Timeout` at every `next_timeout()` up to `RS_BACKOFF_MAX * 2`, asserting `next_timeout() > now` whenever `Some`. Add the `[[bin]]`.

- [ ] **Step 6: Commit** `git commit -s -m "proto-ndp: the WAN router-advertisement client core"`

---

### Task 7: The RA server core

**Files:**
- Create: `crates/openfeo-proto-ndp/src/server.rs`; `fuzz/fuzz_targets/ndp_server.rs`

**Interfaces:**
- Produces: `server::Server::new(config: Config, seed: u64) -> Server`; `Config { prefix: Ipv6Net, mac: [u8; 6], router: Ipv6Addr, mtu: Option<u32>, domain: String, router_lifetime: u16 }`; `Input { Start, Configure(Config), Solicitation { from: Ipv6Addr, hop_limit: u8, bytes: Vec<u8> }, Timeout, Stop }`; `Output { Advertise(Vec<u8>) /* to ff02::1 */, Stopped }`; `Server::handle(&mut self, input: Input, now: Timestamp) -> Vec<Output>`; `Server::next_timeout(&self) -> Option<Timestamp>`; constants (ms) `MIN_RTR_ADV_INTERVAL = 200_000`, `MAX_RTR_ADV_INTERVAL = 600_000`, `MAX_INITIAL_RTR_ADVERT_INTERVAL = 16_000`, `MAX_INITIAL_RTR_ADVERTISEMENTS = 3`, `MAX_RA_DELAY_TIME = 500`, `MIN_DELAY_BETWEEN_RAS = 3_000`, `MAX_FINAL_RTR_ADVERTISEMENTS = 3`, and (s) `PIO_VALID = 2_592_000`, `PIO_PREFERRED = 604_800`, `RDNSS_LIFETIME = 1_800`.
- Behaviour pinned: the advertisement is PIO (A, L, the lifetimes), MTU when `Some`, SLLAO, RDNSS `[router]`, DNSSL `[domain]`, `cur_hop_limit 64`, M=0, O=0, `router_lifetime` from the config, reachable/retrans 0. `Start`: an advertisement at once, then the first three at most 16 s apart, then uniform random in [200, 600] s from the seed. A solicitation (valid: hop limit 255, source link-local or `::`) schedules an answer at `now + rand(0..=500)` unless one is already scheduled, never earlier than `last_sent + MIN_DELAY_BETWEEN_RAS`. `Configure` with any field changed advertises at once under the same 3-second floor. `Stop` with the lifetime set to 0 sends three final advertisements at `MIN_DELAY_BETWEEN_RAS` spacing, then `Stopped`.

- [ ] **Step 1: Failing tests**

```rust
#[test] fn start_advertises_at_once_then_three_within_16_s_then_between_200_and_600_s()
#[test] fn the_advertisement_carries_pio_mtu_sllao_rdnss_dnssl_and_clear_m_and_o()
#[test] fn a_solicitation_is_answered_within_half_a_second()
#[test] fn a_burst_of_solicitations_gets_one_answer_per_three_seconds()
#[test] fn a_solicitation_below_hop_limit_255_or_from_a_global_source_is_ignored()
#[test] fn a_configure_that_changes_the_lifetime_advertises_at_once()
#[test] fn stop_sends_three_final_advertisements_with_lifetime_0_then_stops()
```

- [ ] **Step 2: Run** `cargo test -p openfeo-proto-ndp server 2>&1 | tail -n 10` — Expected: FAIL.

- [ ] **Step 3: Implement** `server.rs` (a small xorshift from the seed, as the other cores do without `rand`).

- [ ] **Step 4: Run** again — Expected: PASS.

- [ ] **Step 5: Fuzz target** `ndp_server`: `Start`, the bytes as a `Solicitation` from `fe80::2` at 1, then every timeout for 2 × `MAX_RTR_ADV_INTERVAL`; `Stop`; assert `Stopped` arrives within 4 × `MIN_DELAY_BETWEEN_RAS` of it. Add the `[[bin]]`.

- [ ] **Step 6: Commit** `git commit -s -m "proto-ndp: the LAN router-advertisement server core"`

---

### Task 8: The ICMPv6 socket driver

**Files:**
- Create: `crates/openfeo-net/src/ndp.rs`; register in `lib.rs`
- Modify: `crates/openfeo-net/src/sys.rs` (two `unsafe` helpers)
- Test: `sys.rs` unit tests for the filter bitmap; the driver itself is proven by Task 15's sandbox suite.

**Interfaces:**
- Produces: `ndp::Role { Client, Server }`; `ndp::NdpSocket::open(ifindex: u32, ifname: &str, role: Role) -> Result<NdpSocket, DriverError>` — `AF_INET6/SOCK_RAW/IPPROTO_ICMPV6` non-blocking, `SO_BINDTODEVICE ifname`, `IPV6_MULTICAST_HOPS 255`, `IPV6_UNICAST_HOPS 255`, `IPV6_RECVPKTINFO`, `IPV6_RECVHOPLIMIT`, `ICMP6_FILTER` passing types `{134}` for `Client` and `{133}` for `Server`, joined to `ff02::1` (client) or `ff02::2` (server) on `ifindex`; `NdpSocket::recv(&mut self, buf: &mut [u8]) -> Result<Option<Received>, DriverError>` (`Received { from: Ipv6Addr, hop_limit: u8, len: usize }`, `None` when a datagram lacked its control messages); `NdpSocket::send(&self, to: Ipv6Addr, bytes: &[u8]) -> Result<(), DriverError>` via `sendmsg` with `Ipv6PacketInfo { ipi6_ifindex: ifindex, ipi6_addr: unspecified }` so the kernel chooses the interface's link-local source; `NdpSocket::readable(&self)` for `select!`.
- `sys.rs` gains `pub fn icmp6_filter(fd: BorrowedFd<'_>, pass: &[u8]) -> io::Result<()>` (a 256-bit bitmap where a set bit **blocks** a type, `ICMP6_FILTER` is `IPPROTO_ICMPV6` level option 1) and `pub fn join_multicast_v6(fd: BorrowedFd<'_>, group: Ipv6Addr, ifindex: u32) -> io::Result<()>` (`IPV6_JOIN_GROUP` with `ipv6_mreq`), each with `// SAFETY:`; a unit test `icmp6_filter_bitmap_blocks_everything_but_the_passed_types` on the pure bitmap builder `fn icmp6_filter_words(pass: &[u8]) -> [u32; 8]`. If nix 0.30 has no `SockProtocol` for ICMPv6, the socket is opened through `libc::socket` in `sys.rs` too, and ADR-0013's amendment names it.

- [ ] **Step 1: Failing test** for `icmp6_filter_words`.
- [ ] **Step 2: Run** `cargo test -p openfeo-net sys:: 2>&1 | tail -n 5` — Expected: FAIL.
- [ ] **Step 3: Implement** `sys.rs` helpers and `ndp.rs`.
- [ ] **Step 4: Run** again and `make lint` — Expected: PASS; clippy clean; `unsafe` only in `sys.rs`.
- [ ] **Step 5: Commit** `git commit -s -m "net: raw ICMPv6 socket driver for neighbour discovery"`

---

### Task 9: World facts and the kernel's default routes

**Files:**
- Create: `crates/openfeo-world/src/ipv6.rs`
- Modify: `crates/openfeo-world/src/{lib.rs, world.rs}`, `crates/openfeo/src/router.rs` (`link_facts_task` → `netlink_facts_task`)
- Test: `world.rs`, `router.rs`

**Interfaces:**
- Produces: `WanIpv6Fact { router: Option<Ipv6Addr>, addresses: Vec<Ipv6Net>, on_link: Vec<Ipv6Net>, routes: Vec<(Ipv6Net, Ipv6Addr, Preference)>, dns: Vec<Ipv6Addr>, search: Vec<String>, mtu: Option<u32> }` (`Preference` re-declared in the world crate: `Low | Medium | High`; `crates/openfeo` converts from the proto crate's); `DefaultRoute { v6: bool, ifname: String }`; `World.ipv6: Arc<BTreeMap<String, WanIpv6Fact>>`; `World.routes: Arc<BTreeSet<DefaultRoute>>`; `World::has_default(&self, v6: bool, ifname: &str) -> bool`.
- Router: `netlink_facts_task` publishes `links` and `routes` together from the cache: every cache `Route` with `table == TABLE_MAIN`, `dst == None`, `kind == Unicast`, whose `oif` names a link, regardless of protocol.

- [ ] **Step 1: Failing tests**: `world.rs`: `has_default_matches_family_and_interface`; `router.rs`: `default_routes_from_the_cache_name_their_interface_and_skip_other_tables` (build a `Cache` with a v4 default on p0 in main, a v6 default on p0 in main, a v6 default in table 100, a blackhole: expect the first two).
- [ ] **Step 2: Run** `cargo test -p openfeo-world && cargo test -p openfeo router:: 2>&1 | tail -n 8` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** again, and `cargo test -p openfeo-reconcile` (fixtures still build with the new fields defaulted) — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -s -m "world: WAN IPv6 facts and the kernel's default routes"`

---

### Task 10: Routing, sysctl and links for IPv6

**Files:**
- Modify: `crates/openfeo-netlink/src/{types.rs, apply.rs, monitor.rs}` (`Route.pref_src: Option<IpAddr>`; `RouteAttribute::PrefSource` set and parsed; a dumped IPv6 blackhole's `oif` normalised to `None`)
- Create: `docs/adr/0020-ipv6-blackhole-routes-report-lo.md`
- Modify: `crates/openfeo-reconcile/src/{routing.rs, sysctl.rs, links.rs, fixtures.rs}`, `crates/openfeo-apply/src/{routing.rs, links.rs}`, `crates/openfeo/src/router.rs` (pass the secret to `LinksApplier`)
- Test: reconcile unit and `insta` snapshots on `fixtures::ipv6_world()`; `harness/tests/netlink.rs` sandbox scenarios

**Interfaces:**
- Consumes: Task 9's facts, Task 3's secret, Task 2's config.
- Produces: `fixtures::ipv6_world()` (vm-ipv6.toml, ports p0..p3, links up with carrier, `ipv6["wan0"]` = router `fe80::1`, `dns [2001:db8:ffff::1]`, mtu `Some(1500)`, and `routes` holding both defaults on p0) and `fixtures::ipv6_world_without_route()` (same, `routes` empty); `DesiredRoute.pref_src: Option<IpAddr>`; `DesiredPort.ipv6_stable_privacy: bool`; `LinksApplier::with_ipv6_secret(secret: [u8; 16]) -> Self`; `reconcile::sysctl` keys `net/ipv6/conf/<wan>/{accept_ra,autoconf,accept_redirects}` = 0 and `net/ipv6/conf/<wan>/mtu` = the fact's MTU when present (capped at the link's MTU from `links`), `net/ipv6/conf/br-<lan>/{accept_ra,accept_redirects}` = 0 for LANs with `ipv6`; `reconcile::routing` emits for a WAN with `[wans.ipv6]`: the v6 default (`via` the fact's router or the typed gateway, `dev` the WAN, metric priority, `pref_src` = `<prefix>::1` when a prefix is declared), on-link routes and the fact's routes, the fact's addresses on the WAN, `<prefix>::1/128` on `lo`, a `Blackhole` for the prefix with `BLOCK_METRIC`, and each LAN's `ipv6` on its bridge; a typed global gateway outside every on-link prefix gets the host route first, as IPv4 does.

- [ ] **Step 1: Failing reconcile tests**

```rust
// routing.rs
#[test] fn ipv6_world_routes_default_via_the_learned_router_with_the_loopback_as_source()  // + insta snapshot
#[test] fn a_typed_gateway_replaces_the_learned_router_and_an_off_link_one_gets_a_host_route()
#[test] fn without_a_router_fact_there_is_no_ipv6_default_but_the_prefix_is_still_blackholed()
#[test] fn without_a_prefix_the_default_has_no_preferred_source_and_lo_gets_nothing()
#[test] fn an_ipv4_only_world_changes_nothing()   // routing(static_world()) equals the existing snapshot
// sysctl.rs
#[test] fn the_ipv6_wan_gets_its_knobs_and_the_advertised_mtu_capped_at_the_link()
#[test] fn lans_with_ipv6_refuse_advertisements()
// links.rs
#[test] fn only_the_ipv6_wan_port_asks_for_stable_privacy()
```

- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile 2>&1 | tail -n 12` — Expected: FAIL.
- [ ] **Step 3: Implement** netlink `pref_src` (both directions) and the blackhole normalisation with ADR-0020 (Context: the kernel reports `RTA_OIF` = `lo`'s index on IPv6 blackhole routes; Decision: the monitor drops `oif` on any route of kind `Blackhole`; Consequences: desired and observed compare equal, the applier converges), the reconcilers, the fixtures, `LinksApplier::with_ipv6_secret` writing `addr_gen_mode = 2` then `stable_secret` (the hex) through `openfeo_apply::sysctl`'s read/write helpers for a port with `ipv6_stable_privacy` that is about to go up, and bouncing (down, write, up, one `info!("set {port} down/up: ipv6 stable-privacy")` line) a port whose link is already up without the mode; the routing applier passes `pref_src` through.
- [ ] **Step 4: Run** again and `cargo insta test --accept -p openfeo-reconcile` only for the new snapshots; then `git diff --stat crates/openfeo-reconcile/src/snapshots` — Expected: only new snapshot files; existing ones untouched.
- [ ] **Step 5: Sandbox scenarios** in `harness/tests/netlink.rs` (the suite's existing shape): `an_ipv6_address_and_a_loopback_slash_128_are_added_and_removed`, `an_ipv6_default_route_carries_its_preferred_source` (dump shows `RTA_PREFSRC`), `an_ipv6_blackhole_route_round_trips_through_the_cache` (after `route_add`, the cache contains a `Route` equal to the desired one), `a_stable_privacy_link_local_is_the_same_across_two_bounces` (a veth, secret written, up/down/up: the `fe80::` address is identical and not EUI-64 of the MAC).
- [ ] **Step 6: Run** `make test-harness FILTER=ipv6 2>&1 | tail -n 12` and `FILTER=stable_privacy` — Expected: PASS (the blackhole scenario fails before the normalisation and passes after; note the RED in the ledger).
- [ ] **Step 7: Commit** `git commit -s -m "routing: IPv6 default, loopback address, blackhole and stable-privacy for the IPv6 WAN"`

---

### Task 11: The firewall's IPv6 half

**Files:**
- Modify: `crates/openfeo-reconcile/src/nft.rs`
- Test: `nft.rs` unit and snapshot tests; `harness/tests/nft.rs`

**Interfaces:**
- Consumes: Task 2's `Target6`, Task 9's World.
- Produces, in the ruleset: set `lan_pub_ra_if` (public LANs with `ipv6` and `ra` on); sets `rules6_tcp`, `rules6_udp` (`ifname . ipv6_addr . inet_service`), `rules6_other` (`ifname . ipv6_addr . inet_proto`), `rules6_any` (`ifname . ipv6_addr`), filled from rules whose `to` parses as `Target6`, with `"icmpv6"` as the protocol element for `proto = "icmp"`; four forward rules consulting them with `ip6 daddr`; input rules: `iifname @wan_if icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report } accept` and, with `wan_ping`, `iifname @wan_if icmpv6 type echo-request limit rate 50/second burst 100 packets accept`; the public-LAN service rules become `iifname @lan_pub_dhcp_if meta nfproto ipv4 udp dport {53,67,123} accept`, `… tcp dport 53 accept`, plus `iifname @lan_pub_ra_if meta nfproto ipv6 udp dport 53 accept` and `… tcp dport 53 accept`; the reverse-path chain gains `ip6 saddr fe80::/10 accept` before the WAN loose check. Private-LAN service rules, masquerade, DNAT and every IPv4 rule are unchanged, so the existing snapshots do not move.

- [ ] **Step 1: Failing tests**

```rust
#[test] fn ipv6_rules_land_in_the_rules6_sets_by_family_and_icmp_becomes_icmpv6()
#[test] fn the_wan_input_accepts_the_rfc_4890_icmpv6_types_and_echo_only_with_wan_ping()
#[test] fn public_lan_services_split_by_family_and_a_private_lan_keeps_both()
#[test] fn link_local_sources_skip_the_loose_reverse_path_check()
#[test] fn ipv6_world_ruleset_snapshot()     // insta on ipv6_world()
#[test] fn the_ipv4_fixtures_produce_the_same_ruleset_as_before()  // nft(static_world()), nft(public_world()), nft(vlans_world()) against their existing snapshots
```

- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile nft 2>&1 | tail -n 10` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** again; accept only the new snapshot — Expected: PASS, `git status` shows no changed existing snapshot.
- [ ] **Step 5: Sandbox**: in `harness/tests/nft.rs` add `the_ipv6_ruleset_applies_on_the_pinned_nftables` (apply `nft(ipv6_world())` through the applier and list it back: the `rules6_*` sets, `lan_pub_ra_if` and the `icmpv6 type` input rule are present; uses the existing `nftprobe::require_expressions` skip).
- [ ] **Step 6: Run** `make test-harness FILTER=ipv6_ruleset 2>&1 | tail -n 8` — Expected: PASS (or a skip with the host's nft-module reason, which CI's `OPENFEO_NO_SKIP` turns into a failure there).
- [ ] **Step 7: Commit** `git commit -s -m "nft: the IPv6 half of zones and rules, ICMPv6 per RFC 4890"`

---

### Task 12: DNS over IPv6

**Files:**
- Modify: `crates/openfeo-proto-dns/src/forwarder.rs` (`Config.upstreams: Vec<IpAddr>`, `Config.router_addrs: Vec<IpAddr>`, `Config.wan_addrs: Vec<IpAddr>`, `Input::Query.client: IpAddr`, `Output::Forward.upstream: IpAddr`, `Input::UpstreamReply.upstream`, `Input::ForwardFailed.upstream`, `Event::UpstreamDown/Up(IpAddr)`, `Event::RebindDropped.client: IpAddr`; local records already `IpAddr`; the router's name answers A for v4 and AAAA for v6 addresses; PTR for the router's IPv6 addresses and for records inside a LAN's /64 under `ip6.arpa`)
- Modify: `fuzz/fuzz_targets/dns_forwarder.rs` (types), `crates/openfeo-net/src/{bound.rs, dns.rs}`, `crates/openfeo-reconcile/src/dns.rs`, `crates/openfeo/src/dns.rs`
- Test: forwarder unit tests, `reconcile::dns` tests and snapshot, `harness/tests/dns.rs`

**Interfaces:**
- Consumes: Task 9's `World::has_default`, Task 2's records.
- Produces: `bound::bound_socket(device: Option<&str>, addr: IpAddr, port: u16, kind, protocol)` (`AF_INET6` with `IPV6_V6ONLY` for a v6 address); `DnsDriverConfig.listeners: Vec<Listener>` with `Listener { ifname: String, v6: bool }` (one entry per family per LAN); the driver's upstream sockets: one v4 (`0.0.0.0:0`) and one v6 (`[::]:0`), chosen by the upstream's family; `DesiredListener { ifname: String, address: Ipv4Addr, address6: Option<Ipv6Addr> }`; `DesiredDns.upstreams: Vec<IpAddr>`, `wan_upstreams: Vec<IpAddr>`, `router_addrs: Vec<IpAddr>` (every LAN's v4 and v6 address and the loopback address), `wan_addrs: Vec<IpAddr>`, `lan_prefixes6: Vec<Ipv6Net>` (the LANs' /64s, for PTR), `local: Vec<DesiredLocalName { name, addr: IpAddr }>` (reservations, then leases, then records); the route gate: a WAN's learned resolvers (the DHCPv4 lease's v4 ones, the IPv6 fact's v6 ones) join `upstreams` only when `world.has_default(family, wan_ifname)`; `[wans.static].dns` and `[dns].upstreams` are never gated; `learned_from` carries `" rdnss"` for v6 in the console line (`dns upstreams 203.0.113.1, 2001:db8:ffff::1 (learned from wan0)`).
- The forwarder's `guard_subnets` stay IPv4; the IPv6 guard is `is_internal_v6` as it stands (link-local, ULA, loopback) plus the router's own v6 addresses from `router_addrs`.

- [ ] **Step 1: Failing tests**

```rust
// forwarder.rs
#[test] fn the_router_name_answers_a_and_aaaa_from_its_addresses()
#[test] fn a_record_answers_aaaa_and_a_ptr_inside_a_lan_prefix()
#[test] fn an_ipv6_upstream_is_forwarded_to_and_failed_over_like_a_v4_one()
#[test] fn an_answer_with_the_routers_own_ipv6_address_is_rebinding()
// reconcile/dns.rs
#[test] fn learned_resolvers_join_only_once_their_familys_default_route_exists()   // ipv6_world() vs ipv6_world_without_route(); the DHCPv4 lease's resolvers likewise with routes empty
#[test] fn typed_upstreams_and_static_wan_dns_are_never_gated()
#[test] fn records_become_local_names_after_reservations_and_leases()
#[test] fn ipv6_world_dns_snapshot()
#[test] fn an_ipv4_only_world_keeps_its_snapshot()
```

- [ ] **Step 2: Run** `cargo test -p openfeo-proto-dns -p openfeo-reconcile dns 2>&1 | tail -n 12` — Expected: FAIL (type errors first).
- [ ] **Step 3: Implement** core, reconciler, driver (listeners per family on each bridge through `bound_socket`; `client_v4` becomes `client_ip`), the console line; update the `dns_forwarder` fuzz target and the `dns` sandbox suite for the type changes.
- [ ] **Step 4: Run** `cargo test -p openfeo-proto-dns -p openfeo-reconcile -p openfeo-net -p openfeo 2>&1 | tail -n 6`, `cargo check --manifest-path fuzz/Cargo.toml --bins` — Expected: PASS.
- [ ] **Step 5: Sandbox**: in `harness/tests/dns.rs` add `names_resolve_over_ipv6_and_an_ipv6_upstream_is_asked` (the rig's veths get `2001:db8:222::1/64` on the near LAN end and `2001:db8:ffff::1/64` on dnsmasq's end; dnsmasq already binds every address of its interface; `dig @2001:db8:222::1 AAAA www.isp.example` answers the AAAA dnsmasq serves after Task 15's host record, and `dig … nas.home.arpa AAAA` answers the record typed in the suite's config). Until Task 15 lands, use `--host-record=www.isp.example,198.51.100.10,2001:db8:ffff::10` added here to `daemons::dnsmasq`.
- [ ] **Step 6: Run** `make test-harness FILTER=over_ipv6 2>&1 | tail -n 8` — Expected: PASS.
- [ ] **Step 7: Commit** `git commit -s -m "dns: AAAA for the router and typed records, IPv6 listeners and upstreams, the route gate"`

---

### Task 13: `reconcile::ra` and the LAN advertisement task

**Files:**
- Create: `crates/openfeo-reconcile/src/ra.rs`, `crates/openfeo/src/ra.rs`
- Modify: `crates/openfeo-reconcile/src/lib.rs`, `crates/openfeo/src/router.rs` (spawn), console contract tests in `crates/openfeo`
- Test: `ra.rs` unit and snapshot tests

**Interfaces:**
- Consumes: Task 7's `server::{Server, Config, Input, Output}`, Task 8's `NdpSocket`, Task 9's facts.
- Produces: `reconcile::ra::DesiredRa { ifname: String, prefix: Ipv6Net, router: Ipv6Addr, mtu: Option<u32>, domain: String, router_lifetime: u16 }` and `reconcile::ra::desired(world: &World) -> Vec<DesiredRa>`: one per LAN with `ipv6` and `ra` not `Some(false)`, `mtu` from `world.links[br-<lan>].mtu` (`None` until the bridge is known), `router_lifetime` 1800 when the WAN that declares the prefix has carrier (`links[wan].carrier`) and `world.has_default(true, wan_ifname)`, else 0.
- The task (`crates/openfeo/src/ra.rs`, `pub fn spawn(...)` after `dns.rs`'s pattern): one supervised task `ra` that, per `DesiredRa`, waits for the bridge (`wait_for_link`), opens `NdpSocket::open(index, ifname, Role::Server)`, runs a `Server` with the bridge's MAC, and on each World change reconfigures (`Input::Configure`) or stops a server whose LAN left (`Input::Stop`, its three final advertisements sent, then the socket closed); console lines `ra br-lan0 advertising 2001:db8:222::/64 lifetime 1800`, `ra br-lan0 lifetime 0 (wan0 has no ipv6 route)`, `ra br-lan0 lifetime 1800`, `ra br-lan0 stopped`.

- [ ] **Step 1: Failing tests**

```rust
// reconcile/ra.rs
#[test] fn every_lan_with_ipv6_and_ra_on_gets_an_advertisement_and_the_dmz_does_not()
#[test] fn lifetime_follows_the_wan_carrier_and_route()   // ipv6_world(): 1800; without_route: 0; carrier false: 0
#[test] fn the_mtu_is_the_bridges()
#[test] fn ipv6_world_ra_snapshot()
// crates/openfeo console contract: the four lines above match the regexes the harness will use
```

- [ ] **Step 2: Run** `cargo test -p openfeo-reconcile ra:: 2>&1 | tail -n 8` — Expected: FAIL.
- [ ] **Step 3: Implement** both files; spawn after `dns::spawn`.
- [ ] **Step 4: Run** again and `cargo test -p openfeo` — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -s -m "ra: per-LAN router advertisements whose lifetime follows the WAN's IPv6 route"`

---

### Task 14: The WAN IPv6 client task

**Files:**
- Modify: `crates/openfeo/src/ipv6.rs` (the task beside the secret), `crates/openfeo/src/router.rs` (spawn), console contract tests

**Interfaces:**
- Consumes: Task 6's `client::{Client, Config, Input, Output, Learned}`, Task 8's `NdpSocket`, Task 9's `WanIpv6Fact`.
- Produces: `ipv6::spawn_all(supervisor, publisher, world_rx, secret: [u8; 16])`: one supervised task `ipv6-<wan>` per WAN with `[wans.ipv6]` whose `mode` is not `"disabled"`; it waits for the port (`wait_for_link`), opens `NdpSocket::open(index, ifname, Role::Client)`, feeds `LinkUp`/`LinkDown` from the World's carrier fact, feeds received advertisements, runs timers from `next_timeout`, sends `Solicit` to `ff02::2`, converts each `Learned` to `WanIpv6Fact` and publishes it under the WAN's name (removing the entry on `LinkDown`); `pub fn fact_from(learned: &Learned) -> WanIpv6Fact`.
- Console lines (contract): `wan0 ipv6 link-local fe80::…` (from the cache's address for the port, once known), `wan0 ipv6 router fe80::1 lifetime 1800 (learned)`, `wan0 ipv6 router none`, `wan0 ipv6 gateway 2001:db8:ffff::1 (configured)` when typed, `wan0 ipv6 address 2001:db8:ffff:0:…/64`, `wan0 ipv6 resolvers 2001:db8:ffff::1 (rdnss)`, `wan0 ipv6 still soliciting`, `wan0 ipv6 resolver fe80::53 dropped: link-local`.

- [ ] **Step 1: Failing tests**: `fact_from_carries_every_learned_field`, and the console contract tests for the lines above.
- [ ] **Step 2: Run** `cargo test -p openfeo ipv6:: 2>&1 | tail -n 8` — Expected: FAIL.
- [ ] **Step 3: Implement**; spawn before `dns::spawn` so the forwarder sees facts early (the gate decides when they count).
- [ ] **Step 4: Run** again — Expected: PASS.
- [ ] **Step 5: Commit** `git commit -s -m "ipv6: the WAN router-advertisement client task and its facts"`

---

### Task 15: Lab support and the `ndp` sandbox suite

**Files:**
- Modify: `harness/src/daemons.rs` (`radvd`, dnsmasq AAAA records, http on v6), `harness/src/lab.rs` (`start_radvd`, `host6`, `isp_route_block6`, ISP v6 addresses), `harness/src/lanclient.rs` (`rdisc6`), `harness/src/main.rs` (check-env: `radvd`, `rdisc6`), `harness/Cargo.toml` (`[[test]] ndp`), `Makefile` (`--test ndp`), `.github/workflows/ci.yml` and `scripts/cloud-setup.sh` (`radvd ndisc6` in the apt lines), `CLAUDE.md` (Harness paragraph)
- Create: `harness/tests/ndp.rs`

**Interfaces:**
- Produces: `daemons::RadvdConfig { iface: String, lifetime: u16, prefix: Option<Ipv6Net>, rdnss: Vec<Ipv6Addr>, dnssl: Vec<String>, min_interval: u16 /* 3 */, max_interval: u16 /* 4 */ }`; `daemons::radvd(ns: &NetNs, config: &RadvdConfig, run_dir: &Path) -> Result<Daemon>` (writes `radvd.conf` with `AdvSendAdvert on`, `AdvDefaultLifetime`, the prefix as `AdvOnLink on; AdvAutonomous on;`, `RDNSS … {}`, `DNSSL … {}`; runs `radvd -n -d 3 -m stderr -C <file> -p <pidfile>`; ready when its log says `sending` or after the first `version` line; stopping it sends the final lifetime-0 advertisements, which `Daemon`'s drop must allow by SIGTERM, not SIGKILL); `Lab::start_radvd(&mut self, config: RadvdConfig) -> Result<()>` on `isp0`'s `wan0` with `fe80::1` and `2001:db8:ffff::1/64` on that interface and `net.ipv6.conf.all.forwarding = 1` in the namespace; `Lab::host6(ns, ifname, addr_cidr, gateway)`; `Lab::isp_route_block6(&self, block: &str, via: &str) -> Result<()>` (`ip -6 route replace <block> via <via> dev wan0`); `lanclient::rdisc6(ns, ifname, timeout) -> Result<Rdisc6Report { router: Option<Ipv6Addr>, lifetime: Option<u32>, prefixes: Vec<Ipv6Net>, mtu: Option<u32>, rdnss: Vec<Ipv6Addr>, dnssl: Vec<String> }>` parsing `rdisc6 -1 -w <ms> <ifname>` (skip with a reason when `rdisc6` is not on the path, the `vlanprobe` pattern); dnsmasq gains `--host-record=www.isp.example,198.51.100.10,2001:db8:ffff::10` and the constant `ISP_WWW_ADDR6`; `daemons::http_server` accepts an IPv6 bind (python's `http.server` does).
- `harness/tests/ndp.rs` (`harness = false`, the `dns` suite's shape, two veth pairs in namespaces): scenarios
  - `the_client_learns_router_prefix_mtu_rdnss_and_dnssl_from_radvd`: the driver on the near end runs a `Client`; within 10 s `Learned` carries router `fe80::…` of the far end, an address in `2001:db8:ffff::/64`, the RDNSS and DNSSL;
  - `the_client_drops_the_router_when_radvd_stops_and_on_lifetime_expiry` (`lifetime: 4`, radvd stopped: router `None` within 5 s);
  - `the_server_configures_a_kernel_host_and_rdisc6_reads_its_options`: the driver runs a `Server` for `2001:db8:222::/64`; the far namespace's kernel gets a global address in the prefix and a default via the near end's link-local; `rdisc6` shows RDNSS = the router's address and DNSSL `home.arpa`;
  - `a_solicitation_is_answered_within_a_second`;
  - `a_lifetime_change_goes_out_at_once` (reconfigure to 0: `rdisc6` reports lifetime 0 within 4 s and the far kernel's default route is gone).

- [ ] **Step 1: Write the suite and helpers**, then run `make test-harness FILTER=ndp 2>&1 | tail -n 15`.
Expected: the three scenarios that need `rdisc6` skip on this host with `rdisc6 not found` (CI has `ndisc6`); the client scenarios pass against radvd (present here).
- [ ] **Step 2: check-env and packages.** Add `radvd` and `rdisc6` to `main.rs`'s tool list; `radvd ndisc6` to the CI and cloud apt lines; the CLAUDE.md Harness paragraph names radvd (the ISP's advertiser), `rdisc6` (reads advertisements on the LAN side) and the kernel as the SLAAC client.
- [ ] **Step 3: Run** `make check-env 2>&1 | grep -e radvd -e rdisc6` — Expected: `radvd ok`, `rdisc6 MISSING` on this host (both ok in CI).
- [ ] **Step 4: Commit** `git commit -s -m "harness: radvd, rdisc6 and the ndp sandbox suite"`

---

### Task 16: QEMU scenarios, the console proof and the progress entry

**Files:**
- Modify: `harness/tests/m2.rs` (eight scenarios, `VM_IPV6` fixture, helpers), `docs/progress.md`
- Test: the scenarios themselves

**Interfaces:**
- Consumes: everything above; the console lines of Tasks 13 and 14; `Lab::start_radvd`, `host6`, `isp_route_block6`, `rdisc6`.
- `boot_ipv6(lab, radvd: RadvdConfig, gateway: Option<&str>) -> Result<Cursor>`: `add_lan1`, dnsmasq, radvd, the fixture (with `gateway = "…"` spliced in when given), boot, wait for `ready`, `host` on lan0 (v4) and let the kernel autoconfigure v6 there (`sysctl net.ipv6.conf.lan0.accept_ra=1` in the namespace), `host6` the DMZ on lan1 (`2001:db8:232::10/64` via `2001:db8:232::1`), then read `wan0 ipv6 link-local fe80::…` from the console and `isp_route_block6("2001:db8::/48", that address)`; an IPv6 HTTP target on `isp0` at `[2001:db8:ffff::1]:8080`.

- [ ] **Step 1: Write the scenarios** named in the design, with these assertions:
  - `lan_client_configures_itself_from_the_lan_prefix_and_reaches_the_isp_over_ipv6`: within 10 s `ip -6 addr show lan0` in lan0 has `2001:db8:222:` scope global; `ip -6 route` has a default via `fe80::` on lan0; `http_get` to `[2001:db8:ffff::1]:8080` returns the ISP body; `rdisc6` (skipped if absent) shows RDNSS `2001:db8:222::1` and DNSSL `home.arpa`.
  - `the_router_learns_its_default_from_the_isp_and_sources_from_its_loopback_address`: console `wan0 ipv6 router fe80::1 lifetime 1800 (learned)`; a `dig AAAA www.isp.example` from lan0 at `2001:db8:222::1` answers `2001:db8:ffff::10`, and dnsmasq's log shows `from 2001:db8::1`.
  - `a_typed_gateway_replaces_the_learned_default`: with `gateway = "fe80::1"` the console says `wan0 ipv6 gateway fe80::1 (configured)`; radvd started with `lifetime: 0`; the LAN host still reaches the ISP over v6.
  - `a_link_prefix_from_the_isp_gives_the_wan_a_stable_address`: console `wan0 ipv6 address 2001:db8:ffff:0:…/64`; `ping -6` from isp0 to it answers; after `qmp system_reset` and a second `ready`, the same address line appears.
  - `dmz_host_ipv6_is_reached_from_the_isp_only_through_a_rule`: from isp0, `http_get` to `[2001:db8:232::10]:80` works, port 81 and `ping -6` do not; `dig AAAA www.home.arpa` at the router answers `2001:db8:232::10`; `rdisc6` on lan1 times out (no advertisements on the DMZ).
  - `wan_ipv6_loss_zeroes_the_router_lifetime_within_one_interval`: stop radvd; console `ra br-lan0 lifetime 0 (wan0 has no ipv6 route)` within 10 s; within 5 s more lan0's kernel has no v6 default route while `http_get` over v4 still works; start radvd again: console `ra br-lan0 lifetime 1800` and the default returns within 10 s.
  - `an_unused_ipv6_subnet_is_blackholed`: console shows `add route blackhole 2001:db8::/48`; `ping -6 2001:db8:5::1` from isp0 gets no reply and no error within 3 s.
  - `isp_names_resolve_to_aaaa_through_a_learned_ipv6_upstream`: fixture with `upstreams = []`; console `dns upstreams … 2001:db8:ffff::1 (learned from wan0)` appears only after `apply routing` of the generation carrying the v6 default (assert order by cursor); `dig AAAA www.isp.example` over v6 answers.
- [ ] **Step 2: Run** `make test-harness FILTER=ipv6 2>&1 | tail -n 20` then the whole `make test-harness 2>&1 | tail -n 30` — Expected: the new scenarios pass (rdisc6 assertions skipped here, run in CI); every existing scenario still passes; the VLAN and nft-module skips are this host's usual ones.
- [ ] **Step 3: Progress entry**: `docs/progress.md` M2 row → `parts 1 and 2 done, 2026-11-0N; part 3 to come | #10, #<this PR>; follow-up #20`, and a paragraph after the #20 entry in the existing style naming what landed.
- [ ] **Step 4: `make ci`** — Expected: lint, test, kernel, harness all green.
- [ ] **Step 5: Commit** `git commit -s -m "harness: M2 part 2 IPv6 scenarios; progress entry"`

---

## Final review

After Task 16: `review-package` over `main..HEAD`, one fresh whole-branch review on the most capable model with this plan's Review Focus verbatim and the ledger's rulings; re-grade; one fix pass with RED→GREEN per fix; then `superpowers:finishing-a-development-branch` (push and PR only on Andy's word).

