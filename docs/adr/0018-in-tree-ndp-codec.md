# 0018 — `openfeo-proto-ndp` parses neighbour discovery itself; smoltcp is the test oracle

Status: Accepted (3 November 2026)

## Context

SPEC §7.3 needs router solicitations and advertisements with the options of RFC 4861
(source link-layer address, prefix information, MTU), RFC 8106 (RDNSS, DNSSL) and RFC 4191
(route information, router preference). SPEC §13 keeps `openfeo-proto-*` pure: no tokio, libc,
nix or socket2 anywhere in their dependency trees, and every parser fuzzed.

No crate covers that option set. smoltcp 0.14 (`wire::ndisc`, `wire::ndiscoption`) and
pnet_packet 0.35 parse and emit the five options of RFC 4861 and nothing beyond; erbium-core
builds advertisements with RDNSS and DNSSL but is Apache-2.0 only, which the FSF deems
incompatible with the GPLv2 the shipped binary is under, and is bound to its own runtime.
ADR-0015 took the same decision for DNS, and the DHCPv4 part for dhcproto: an in-tree codec
with an independent implementation as the differential oracle.

## Decision

- `openfeo-proto-ndp` has its own codec (`wire.rs`), the WAN client core, the LAN server core
  and the RFC 7217 identifier function over an in-tree SHA-256 (`sha256.rs`, checked against
  the RFC 6234 vectors). The SHA-256 is in-tree because nothing in the binary hashes today
  and the usual crate, `sha2`, reaches `libc` through `cpufeatures` on the aarch64 target,
  which `scripts/check-deps.sh` cannot see from an x86 host.
- smoltcp (0BSD) is a dev-dependency and a fuzz dependency only, the oracle of the
  `ndp_differential` target for the message header and options 1 to 5: a packet smoltcp
  parses and we refuse is a finding about our decoder; where both parse, the header fields and
  the shared options must agree. A packet we parse and smoltcp refuses is tolerated.
- The RFC 8106 and RFC 4191 options rely on unit vectors from the RFCs and on radvd in the
  sandbox and QEMU suites, since the oracle does not carry them.
- `docs/third-party.md` lists smoltcp as a test dependency; it reaches no shipped binary.

## Consequences

- A parser we maintain and fuzz nightly (`ndp_wire`, `ndp_differential`, `ndp_client`,
  `ndp_server`), with the same obligations as the DHCPv4 and DNS ones.
- The oracle covers part of the option space; a change to the RDNSS, DNSSL or route
  information parsing is reviewed against the RFC text, not against a second implementation.
- Should a maintained crate grow the full option set under a GPLv2-compatible licence, this is
  the moment to revisit; the sans-IO cores would not change.
