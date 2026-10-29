# 0002 — Licence: GPL-2.0-or-later, DCO, no CLA

Status: Accepted
Date: 2026-10-29

## Context

The firewall backend (ADR-0003) is libnftables, which is GPL-2.0-only. Linking it statically into the
router binary makes the shipped binary a GPLv2 work whatever licence our own code carries, and rules
out linking anything that is only available under GPL-3.0 or LGPL-3.0 (this excludes the `rustables`
crate). The earlier design considered dual licensing with a CLA; that would have given nothing in
return for the paperwork once the binary is GPLv2 anyway.

## Decision

All project code is licensed GPL-2.0-or-later. There is no CLA; contributions carry a DCO
`Signed-off-by` line. `cargo deny` rejects GPL-3.0*, LGPL-3.0*, AGPL-* and every licence that is not
compatible with GPL-2.0. Permitted dependency licences: MIT, Apache-2.0, BSD-2/3-Clause, ISC, MPL-2.0,
Zlib, Unicode, LGPL-2.1-or-later, GPL-2.0(-or-later), CC0, Unlicense.

## Consequences

"Or later" keeps the option of moving to GPLv3 open should the libnftables dependency ever go. Every
source file carries `SPDX-License-Identifier: GPL-2.0-or-later`; CI enforces the header and the
dependency allow-list. The kernel's GPLv2 does not reach a userspace binary (syscall exception) and
systemd-boot (LGPL-2.1+) ships as a separate EFI binary, so neither constrains this choice further.
