# 0009 — Runtime pieces live in `openfeo-runtime` so `openfeo-world` and `openfeo-reconcile` stay pure

Status: Accepted (30 October 2026)

## Context

SPEC §13 lists `openfeo-world` as "World, facts, health, event bus, supervisor runtime" and, in
the same section, requires that `openfeo-reconcile` MUST NOT depend on tokio or anything that
opens sockets or reads clocks. Reconcilers are `fn(&World) -> Desired`, so `openfeo-reconcile`
has to depend on whichever crate defines `World`. A `World` crate that also carries a
tokio-based supervisor and `watch` publisher would drag tokio into every reconciler's dependency
tree, and the dependency-rule check (`scripts/check-deps.sh`) would fail.

## Decision

`openfeo-world` holds only values: `World`, `LinkFact`, `MacAddr`, port-map assignment, rename
planning and the `HealthReport` types. It depends on `openfeo-config`, `serde` and `thiserror`
and nothing that touches a runtime, a socket or a clock.

A new crate, `openfeo-runtime`, holds the tokio side: the `watch`-based `Publisher`, the
`HealthTracker` with wedge detection (which reads `Instant`), the task `Supervisor`, and the
`tracing` log ring with its `/dev/kmsg` layer.

## Consequences

- One more crate than §13 lists; §13 is updated to name both.
- `openfeo-world` joins `openfeo-reconcile` and `openfeo-proto-*` in the pure set that
  `scripts/check-deps.sh` enforces.
- Appliers, services and the binary depend on both crates; reconcilers on `openfeo-world` only.
