# 0015 — `openfeo-proto-dns` parses DNS itself; hickory-proto is the test oracle

Status: Accepted (31 October 2026)

## Context

SPEC §7.7 lets the forwarder use `hickory-proto` for the wire format or an in-tree parser, and
§15 asks for the decision to be recorded. SPEC §13 keeps `openfeo-proto-*` pure: no tokio,
libc, nix or socket2 anywhere in their dependency trees.

`cargo tree` of hickory-proto 0.25.2 with `default-features = false, features = ["std"]`, its
smallest useful shape, is 63 crates. Among them are `libc` (through `rand` and `getrandom`),
`url` and `idna` with their Unicode tables, and the `futures` family. That breaks §13 for a
protocol crate, and it would carry into a static router binary code that a forwarder never
runs: a forwarder needs a dozen record types, name compression, EDNS0 and truncation, which is
a few hundred lines. Part 2b faced the same choice for DHCPv4 and took `dhcproto` as a
test-only oracle; its differential fuzz target found three panics in the oracle within a
minute, which is the kind of return an independent second implementation gives.

## Decision

- `openfeo-proto-dns` has its own codec (`name.rs`, `wire.rs`), cache and forwarder core.
- `hickory-proto` is a dev-dependency and a fuzz dependency only, the oracle of the
  `dns_differential` target: a message hickory decodes and we do not is a finding about our
  decoder; a message we decode and hickory does not is tolerated, since clients and upstreams
  produce messages stricter parsers reject.
- `docs/third-party.md` lists hickory-proto as a test dependency; it reaches no shipped binary.

## Consequences

- A parser we maintain and fuzz nightly, with the same obligations as the DHCPv4 one.
- DNSSEC validation, should it ever be wanted, would be the moment to revisit: it is where a
  library earns its weight.
