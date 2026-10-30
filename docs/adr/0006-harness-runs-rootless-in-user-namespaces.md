# 0006 — The harness runs rootless in user namespaces

Status: Accepted
Date: 2026-10-29

## Context

The QEMU harness needs tap devices, several network namespaces, nftables tables, net sysctls, raw
sockets for the reference daemons (Kea, radvd, pppoe-server) and `/dev/kvm`. The obvious way is
`sudo`, which means a password prompt on every developer run and root-owned state on the host.

Probed on the development host (Arch, Linux 7.2): inside `unshare -Urnm`, creating veth pairs and
taps, nested `ip netns add`, `nft add table`, writing `net.ipv6.conf.*` sysctls, opening AF_PACKET
sockets and opening `/dev/kvm` all succeed. The one gap is `/dev/ppp` (mode 0600 root), which only the
host-side `pppd` needs from M3.

## Decision

The harness process enters a user namespace mapping its own uid to 0, then a mount namespace (private
`/run` tmpfs for `ip netns`) and a network namespace. Everything else — named namespaces, taps,
daemons, QEMU — is created inside. Tap devices live in their ISP or LAN namespace and are passed to
QEMU as inherited file descriptors. No step of a harness run uses `sudo`.

## Consequences

Developers and CI never need elevated privileges or a password. Ubuntu 24.04 runners must set
`kernel.apparmor_restrict_unprivileged_userns=0` before the harness runs, and must unload the
enforce-mode AppArmor profile Ubuntu's `isc-kea` ships (`apparmor_parser -R
/etc/apparmor.d/usr.sbin.kea-dhcp4`): it only lets `kea-dhcp4` read configs under `/etc/kea`, while
the harness writes them under `/run/openfeo-harness`. `make check-env` probes this with
`kea-dhcp4 -t` on a config outside `/etc/kea`. At M3 the host needs a udev rule making `/dev/ppp`
group-accessible, or that scenario runs privileged. Daemons that insist on dropping to another uid
may need flags to stay as (namespace) root.
