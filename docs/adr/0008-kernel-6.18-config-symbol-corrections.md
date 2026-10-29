# 0008 — Kernel 6.18: config symbol corrections to SPEC §4.2

Status: Accepted
Date: 2026-10-29

## Context

SPEC §4.2 lists the kernel options every target must have. Building Linux 6.18.59 from
`allnoconfig` plus the checked-in fragments (`kernel/required.config`, `kernel/x86_64.config`) with
a strict check that every requested option survives Kconfig's dependency solving turned up:

- `CONFIG_NFT_COUNTER` is not a symbol any more. Counters moved into the nf_tables core in 5.19;
  `nft_counter` is always built with `NF_TABLES`.
- `CONFIG_RANDOM_TRUST_CPU` was removed in 6.2. The kernel trusts the CPU's RNG instruction by
  default; `random.trust_cpu=off` on the command line is the way to disable it.
- `CONFIG_PSTORE` is only offered under `MISC_FILESYSTEMS`, and `CONFIG_MITIGATION_RETPOLINE` only
  inside the `CPU_MITIGATIONS` block; neither gate is on in `allnoconfig`.

## Decision

`kernel/required.config` and `kernel/x86_64.config` are authoritative. The two dead symbols are
dropped from §4.2's non-exhaustive list; `MISC_FILESYSTEMS` and `CPU_MITIGATIONS` are added to the
fragments as the gates they are. `kernel/build.sh check` fails the build whenever a requested line is
missing from the final `.config`, so any future removal is caught at the first build against a new
kernel rather than at boot.

## Consequences

The boot-time check (M1) reads the same fragments, so there is one list, not two. Moving to the next
LTS means re-running the build and reading the check's output; symbol churn becomes an ADR like
this one rather than a surprise on hardware.
