# 0017 — LAN VLANs are 802.1Q sub-interfaces bridged per LAN

Status: Accepted (1 November 2026)

## Context

SPEC §7.1 makes a LAN a bridge of ports, `br-<lan>`, and M1 built everything downstream of that
name: the firewall zones are sets of bridge names, the DHCPv4 server and the DNS forwarder bind
to the bridge, the reconcilers derive their desired state from it. Real LANs do not arrive one
port each. A trunk port to a managed switch carries a main LAN untagged and two more as tagged
802.1Q VLANs; an access port carries one of those VLANs untagged; a hybrid port carries the main
LAN untagged and one VLAN tagged. A port can be a member of only one bridge, so "a LAN is a set
of ports" cannot express a trunk.

Linux offers two shapes. One VLAN-aware bridge with `vlan_filtering` on, a VLAN table per port
(PVID, untagged, tagged) and a per-VLAN interface on the bridge (`br0.223`) as the LAN's layer-3
device: the shape RouterOS uses, and the one a switch chip offloads directly, since the chip's
own VLAN table mirrors the bridge's. Or one bridge per LAN whose members may be 802.1Q
sub-interfaces of a port (`p6.223`): the kernel hands a frame tagged 223 arriving on `p6` to
`p6.223` before the bridge on `p6` sees it, so a trunk is simply a member of several bridges,
untagged in one and through a sub-interface in each of the others.

## Decision

A LAN member is a port untagged (`p6`) or a tagged VLAN on a port (`p6.224`). The router creates
the sub-interface `pN.V`, enslaves it to the LAN's bridge and deletes sub-interfaces named that
way that no LAN wants, exactly as it does for stray `br-*` bridges. The bridge-per-LAN model and
the bridge name stay; nothing downstream of a bridge changes. A WAN with `vlan = V` runs on the
same kind of sub-interface. The port's own bridge keeps `vlan_filtering` on with only VLAN 1,
so a tagged frame for a VLAN no LAN carries is dropped there rather than flooded into the
untagged LAN. A physical port is a WAN or carries LANs, not both, until a need appears.

## Consequences

- The M1 design holds: zones, DHCP, DNS, routing and the console keep working off bridge names,
  and the change is confined to the links reconciler, the links applier and the netlink crate.
- Per-port VLAN translation falls out for free (a LAN may be tagged 223 on one port and 224 on
  another), which a VLAN-aware bridge would make awkward.
- Switch-chip offload on the RB5009 (M7, DSA) prefers one VLAN-aware bridge; bridging 802.1Q
  uppers of DSA ports is supported by recent kernels but is the less travelled path. M7 revisits
  this decision with the DSA driver in hand; the config syntax (`pN.V` in `ports`) does not have
  to change if the implementation does.
- The kernel's naming (`pN.V`) is the config's naming, so the console, `ip link` on a developer's
  box and the configuration agree without a translation table.
