# 0021 — Apache-2.0 components stay in the GPLv2 binary; prost is the first

Status: Accepted (5 November 2026); amends ADR-0002

## Context

ADR-0002 made the shipped binary a GPLv2 work by linking libnftables, and the pinned nftables
1.1.7 confirms the premise: its `COPYING` says the original author licensed the code under GPL
version 2 only and that new code moves to "or later", and twenty-five of the fifty-four files under
`src/` still carry the version-2-only header. ADR-0002 then listed Apache-2.0 among the
GPL-2.0-compatible dependency licences. The Free Software Foundation and the Apache Software
Foundation read it otherwise: Apache-2.0's patent-termination and indemnification terms are, in
their view, further restrictions that GPLv2 §6 forbids, so Apache-2.0 code combines with GPLv3 but
not with GPLv2-only code. That reading is contested and untested, and the combination is common
in shipped software, but a distribution that follows it declines the package, and licence
scanners report the pair.

An audit on 5 November 2026 found exactly one Apache-2.0-only crate linked into the binary:
`prost` 0.14, through `openfeo-config`, whose configuration types `prost-build` generates from the
protobuf schema (SPEC §8.1). It is linked because the generated structs derive `prost::Message`.
Nothing encodes or decodes protobuf at run time today: the TOML on disk is read through the serde
code `pbjson-build` generates, and `pbjson` is MIT. `prost-derive` is a proc-macro; `prost-build`,
`protox` and `pbjson-build` run only at build time; `insta` and `similar` are test-only; every other
run-time dependency is dual-licensed or otherwise compatible. M4 puts protobuf on the wire, and
`tonic`, the gRPC stack SPEC §8.3 plans for, is built around prost.

The alternatives were surveyed the same day. rust-protobuf (MIT) is mature but declares itself
approaching end of life. Google's official `protobuf` crate (BSD-3-Clause) is still a beta
release, carries a C kernel, pins `protoc` to its own version and offers no JSON codec. pilota
with volo-grpc (MIT or Apache-2.0) is a pure-Rust stack without prost, thinly documented. tonic's
codec is a trait and works without prost given another codec. quick-protobuf and micropb are
immature or embedded-only. The project's own licence cannot help: GPL-2.0-or-later already permits
the most, and a GPLv3-only licence would be incompatible with libnftables outright.

## Decision

`prost` stays, and Apache-2.0 remains an accepted licence for components of the binary. The
project distributes the binary under GPLv2 terms with Apache-2.0 components, meets Apache-2.0's
own conditions, and records here that it does so knowing the FSF's reading. SPEC §14's list is
the set of licences the project accepts in the binary, not a claim that each is GPLv2-compatible,
and `cargo deny` keeps enforcing it.

The decision is revisited when one of three things happens: a distributor or user objects; a
licence-clean codec of equal standing matures, Google's official crate leaving beta being the
likeliest; or M4's design chooses the wire codec. The exit is known and small today: the
configuration types can leave prost without a change to the file format, because pbjson carries
the serde side and nothing encodes protobuf at run time, so a build-time emitter of the same
structs replaces `prost-build` and every other crate compiles unchanged.

## Consequences

- Distributions applying the FSF reading may decline to package the binary, and compliance
  scanners will report the GPLv2 and Apache-2.0 pair. The project ships its own image and depends
  on neither today.
- Apache-2.0 asks that its licence text and notices travel with the work; the image gains a
  licence manifest generated from the lockfile when M5 builds the installer.
- The panel's protobuf-es is Apache-2.0 too. It ships as JavaScript assets served to browsers,
  not as code linked into the binary, which the project treats as aggregation.
- M4's codec choice is made with this record in front of it. Choosing prost and tonic there widens
  the Apache-2.0 footprint and is consistent with this decision; choosing a clean codec closes it.
