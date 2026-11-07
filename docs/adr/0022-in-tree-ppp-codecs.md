# 0022 — PPPoE and PPP codecs in-tree, with an oracle only if its licence passes

Status: Accepted (7 November 2026)

## Context

M3 needs codecs for PPPoE discovery (RFC 2516 with the RFC 4638 tag), the PPP frame and the
packets of LCP, PAP, CHAP, IPCP and IPV6CP (RFC 1661, 1334, 1994, 1332, 1877, 5072). They
parse what the access concentrator sends before authentication, on the WAN. ADR-0015 (DNS)
and ADR-0018 (NDP) chose in-tree codecs with strict limits and a fuzz target each, taking an
external crate only as a differential test oracle in a dev-dependency, because a codec in the
WAN path must be read, bounded and fuzzed by this project rather than trusted.

The candidate oracle is `ppproperly`, the PPP serialisation crate of the rsdsl project, whose
licence `cargo deny` has to accept; the alternative is the RFCs' own examples and the
harness's captures from `pppoe-server` and `pppd`.

## Decision

`openfeo-proto-ppp` holds the codecs, pure and bounded (at most 32 discovery tags of at most
1480 bytes, option lists checked against their packet length, two-byte protocol fields only).
Each parser has a fuzz target in the PR that adds it. No differential oracle: `ppproperly` is
not published on crates.io (checked 7 November 2026) and no other maintained Rust PPP codec
was found, so the tests pin the RFCs' own layouts byte for byte (RFC 2516 §5, RFC 1661 §5,
RFC 1994 §4, RFC 1332 §3, RFC 5072 §4) and the harness's captures from `pppoe-server` and
`pppd` once part 2 has them.

## Consequences

- No PPP crate joins the binary; the dependency list of `openfeo-proto-ppp` stays `ipnet`,
  `thiserror` and `openfeo-proto-ndp` (for the RFC 7217 identifier and SHA-256).
- The fuzz workflow gains `pppoe_discovery`, `ppp_lcp`, `ppp_auth`, `ppp_ipcp`, `ppp_ipv6cp`
  and `ppp_session`.
- An oracle that falls out of licence later costs the project nothing but a dev-dependency.
