# OpenFeO

A tiny Linux router: an upstream Linux kernel plus one static Rust binary, shipped as a single
bootable image. The kernel does all forwarding, NAT, filtering and shaping. The Rust binary is the
whole userspace: it is PID 1, and it configures the kernel over netlink, libnftables and syscalls.
No shell, no package manager, no SSH, no stray daemons.

FeO is iron(II) oxide, that is, rust.

## Status

Pre-alpha. Of the milestones in [`SPEC.md`](SPEC.md) §12, M0 (the harness and skeleton) and M1
(the IPv4 router: port identity, the LAN bridge, static and DHCPv4 WANs, the nftables ruleset with
NAT and port forwards, the DHCPv4 server, the DNS forwarder and SNTP) are done, and M2 (IPv6) is
under way with its IPv4 groundwork in: LAN VLANs, a tagged WAN, routed public blocks with DMZ LANs,
per-LAN reach policy and firewall rules. [`docs/progress.md`](docs/progress.md) is the log of what
has landed against the spec, one entry per change, and the pull requests it links hold the detail.

`SPEC.md` is the source of truth. `CLAUDE.md` holds the working rules, and every change to a
decision in SPEC §2 is recorded in [`docs/adr/`](docs/adr/).

## Layout

| Path | What |
|------|------|
| `kernel/` | Linux 6.18 LTS built from `allnoconfig` plus checked-in fragments, with the binary as its initramfs |
| `crates/openfeo` | The binary: argument parsing, port enumeration, the router process |
| `crates/openfeo-init` | PID 1: mounts, sysctls, watchdog, supervisor, console log |
| `harness/` | Rootless QEMU lab: network namespaces for two fake ISPs and one or two LANs (plus VLAN clients), reference daemons, scenario tests |
| `docs/` | ADRs (`adr/`), the design and plan documents each part was built from (`superpowers/`), third-party notes, and `progress.md`, the log of what has landed against SPEC §12 |

## Building and running the lab

Needs Rust stable with the `x86_64-unknown-linux-musl` target, a musl C compiler (`musl-gcc`:
package `musl` on Arch, `musl-tools` on Debian and Ubuntu), `pkg-config`, `cargo-deny`, `buf`, QEMU
(`qemu-system-x86_64`), `iproute2`, `ping`, `python3`, Kea (`kea-dhcp4`), busybox (`busybox` on Arch,
`busybox-static` on Debian and Ubuntu; its `udhcpc` is the lab's reference DHCP client), `dnsmasq`
(`dnsmasq-base` on Debian and Ubuntu; the lab's upstream resolver), `dig` (`bind` on Arch,
`bind9-dnsutils` on Debian and Ubuntu; the lab's DNS client), `ntpdate` (`ntp` on Arch,
`ntpsec-ntpdate` on Debian and Ubuntu; the lab's reference time client), `mkfs.ext4`
(e2fsprogs), `ccache`, and the usual kernel build dependencies (`bc`, `flex`, `bison`, `libelf`, `libssl`, `zstd`, `cpio`).
`make` fetches the pinned sources of nftables, libnftnl, libmnl and jansson (`nft/sources.txt`),
verifies them and builds them statically for the firewall backend, against the UAPI headers of
the pinned kernel (ADR-0012). The lab runs without
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
