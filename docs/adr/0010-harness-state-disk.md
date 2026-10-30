# 0010 — The harness delivers `/state` as a virtio-blk ext4 image; PID 1 mounts `/dev/vda` in `vm` mode

Status: Accepted (30 October 2026)

## Context

From M1 the router reads `/state/config.toml` and keeps `/state/identity/portmap`, and scenarios
need to boot a VM with a given configuration and to see state survive a reset. The initramfs is
the whole OS and is read-only by design (SPEC §4.2), the kernel command line cannot carry a
configuration file, and M0 mounted `/state` as a tmpfs that forgets everything.

Two ways to deliver state were considered: QEMU's `fw_cfg` (a file exposed under
`/sys/firmware/qemu_fw_cfg`, read-only, VM-only, no persistence across a reset) and a block device
with the `openfeo-state` filesystem SPEC §5.2 describes.

## Decision

The harness builds a 64 MiB ext4 image labelled `openfeo-state` with `mkfs.ext4 -d <dir>`, which
populates the filesystem from a directory without root, and attaches it to QEMU as a virtio-blk
drive. In `vm` mode PID 1 waits briefly for `/dev/vda` to appear, mounts it on `/state` with
`noatime,nodev,nosuid,noexec` (SPEC §5.2), and falls back to the M0 tmpfs when there is no disk.
Other modes keep the tmpfs until M5 decides how the labelled partition is found on metal.

## Consequences

- `e2fsprogs` is a harness host dependency (`mkfs.ext4`, and `debugfs` for the unit test).
- State persists across a QEMU `system_reset`, so scenarios can prove port-map stickiness now and
  DUID and lease persistence in M2.
- `make run` boots with the lab's static configuration by default and `--no-config` reproduces
  the first-boot defaults.
- M5 generalises the mount to the `openfeo-state` partition found by label.
