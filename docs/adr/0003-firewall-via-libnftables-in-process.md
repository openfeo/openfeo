# 0003 — Firewall: libnftables linked in-process, driven through JSON

Status: Accepted
Date: 2026-10-29

## Context

The router needs the whole of nftables: flowtables, maps, interval sets, exthdr matching, NAT with
hairpin, per-zone chains. The candidates were an in-house netlink encoder, the `rustables` crate
(LGPL-3.0, excluded by ADR-0002), spawning the `nft` binary (forbidden: no shelling out, no
busybox), and libnftables itself.

## Decision

libnftables and its dependencies (libmnl, libnftnl, jansson, mini-gmp) are built statically in
`openfeo-nft/build.rs` (`--with-json --with-mini-gmp --without-cli --without-xtables`) and called over
FFI. The ruleset is generated as JSON from the World snapshot and applied as one batch:
`add table inet openfeo; delete table inet openfeo;` followed by the full definition in the same
buffer, which makes the replace idempotent and the batch atomic.

## Consequences

Complete coverage of nftables features with a mature implementation and no process spawn. The C
code is on the configuration path only: it parses JSON we produced, never packets from the network.
`openfeo-nft` is one of the two crates allowed `unsafe`, confined to small modules with `// SAFETY:`
comments. The shipped binary becomes a GPLv2 work (ADR-0002).
