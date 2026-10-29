# 0004 — Boot: systemd-boot with boot assessment, two EFI-stub slots, watchdog from boot

Status: Accepted
Date: 2026-10-29

## Context

Safe updates need A/B slots and automatic rollback on a box with no shell and no keyboard. The
earlier design relied on UEFI boot counting through `BootNext`/`BootOrder`, which many firmwares
mishandle, and on a UKI built with sd-stub. Rollback must not depend on NVRAM writes and must also
cover a kernel that boots but then hangs or crash-loops.

## Decision

systemd-boot is installed at the removable-media fallback path (`\EFI\BOOT\BOOTX64.EFI`), so no NVRAM
entries are required. Each slot is one EFI-stub `bzImage` with the initramfs built in. Boot
assessment (`+tries` entry names) selects between the two slots; OpenFeO blesses a slot by renaming
its entry once the health criteria of SPEC §5.3 hold. The hardware watchdog is opened by PID 1 at
boot with a 60 s timeout and petted only while the router child heartbeats; a hang or crash loop
therefore reboots, systemd-boot decrements the counter, and after three failed boots the other slot
boots.

## Consequences

Rollback works on firmware that mishandles boot variables and needs no NVRAM writes. There is no
root filesystem partition: the initramfs is the OS and an update is one file written to the inactive
slot. `WATCHDOG_NOWAYOUT` means the watchdog can never be disarmed once PID 1 opens it, which is the
behaviour an unattended appliance wants and must be remembered when debugging on real hardware.
