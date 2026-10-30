# OpenFeO

A tiny Linux router: an upstream Linux kernel plus one static Rust binary, shipped as a single
bootable image. The kernel does all forwarding, NAT, filtering and shaping. The Rust binary is the
whole userspace: it is PID 1, and it configures the kernel over netlink, libnftables and syscalls.
No shell, no package manager, no SSH, no stray daemons.

FeO is iron(II) oxide, that is, rust.

## Status

Pre-alpha. Milestone M0 of [`SPEC.md`](SPEC.md) §12 is done: the kernel boots in QEMU to the
OpenFeO PID 1, which mounts the system, supervises the router process, and pets the hardware
watchdog only while that process reports healthy. Nothing routes yet; the IPv4 router is M1.

`SPEC.md` is the source of truth. `CLAUDE.md` holds the working rules, and every change to a
decision in SPEC §2 is recorded in [`docs/adr/`](docs/adr/).

## Layout

| Path | What |
|------|------|
| `kernel/` | Linux 6.18 LTS built from `allnoconfig` plus checked-in fragments, with the binary as its initramfs |
| `crates/openfeo` | The binary: argument parsing, port enumeration, the router process |
| `crates/openfeo-init` | PID 1: mounts, sysctls, watchdog, supervisor, console log |
| `harness/` | Rootless QEMU lab: network namespaces for a fake ISP and a LAN, reference daemons, scenario tests |

## Building and running the lab

Needs Rust stable with the `x86_64-unknown-linux-musl` target, a musl C compiler (`musl-gcc`:
package `musl` on Arch, `musl-tools` on Debian and Ubuntu), `cargo-deny`, `buf`, QEMU
(`qemu-system-x86_64`), `iproute2`, `ping`, Kea (`kea-dhcp4`), `mkfs.ext4` (e2fsprogs), `ccache`,
and the usual kernel build dependencies (`bc`, `flex`, `bison`, `libelf`, `libssl`, `zstd`, `cpio`). The lab runs without
root: it wants unprivileged user namespaces, read-write access to `/dev/net/tun`, and `/dev/kvm`
(falls back to TCG without it). On Ubuntu, Kea's stock AppArmor profile must be unloaded first
(see ADR-0006).

```sh
make check-env       # can this machine run the lab?
make kernel          # fetch, verify and build the kernel with the binary embedded -> build/bzImage
make run             # boot it with the serial console on your terminal (Ctrl-A x quits)
make test-harness    # the QEMU scenarios; FILTER=name picks one
make ci              # everything CI runs, in CI's order
```

## Licence

GPL-2.0-or-later. Copyright (C) 2026 Andrew Newton. Contributions are accepted under the
Developer Certificate of Origin: sign your commits off with `git commit -s`.
