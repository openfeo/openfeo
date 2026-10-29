# 0007 — Test hooks exist only under the `harness` cargo feature

Status: Accepted
Date: 2026-10-29

## Context

The M0 acceptance tests must observe a child restart after a crash and a watchdog reset after
heartbeats stop. The appliance has no shell, no SSH and no debug listener (SPEC §9), so the harness
cannot reach into the VM to kill a process. Something inside the image has to misbehave on request,
and nothing like that may exist in a shipped image.

## Decision

Fault injection is requested on the kernel command line (`openfeo.chaos=child-exit:<secs>`,
`openfeo.chaos=child-hang:<secs>`) and parsed only when the binary is compiled with
`--features harness`. Without the feature the parser is a constant `None`, so release images contain
no code path that reads the knob. The harness builds its images with the feature; `make bin
FEATURES=` builds a release binary.

## Consequences

Deterministic chaos in the harness with zero attack surface added to release builds. The cost is two
image flavours; the Makefile defaults to the test flavour because that is what every developer run
and every CI run needs, and release images are produced explicitly.
