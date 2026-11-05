# 0019 — A learned fact is acted on once the kernel shows the route it needs

Status: Accepted (3 November 2026)

## Context

Issue #12: the DHCPv4 client published the resolvers it learned, the DNS forwarder used them
at once, and the first query went out before the routing applier had installed the WAN's
address and default route. The send failed, the forwarder read the silence as a dead upstream
and held the only resolver down for thirty seconds. PR #20 taught the forwarder to retry a
send that failed; the SNTP client had already learned to move on from an unreachable server.
M2 part 2 adds a second learned source, the WAN IPv6 client, and a consumer with a sharper
contract: the router lifetime every LAN advertises must be 0 whenever the WAN has no usable
IPv6 default route (SPEC §7.3).

SPEC §6.2 says observed state comes from the netlink monitor's cache, never from a one-off
dump, so that an applier never races its own events. The same cache knows which default
routes the kernel has.

## Decision

- The netlink monitor publishes the kernel's default routes (table `main`, family, output
  interface) as a fact in the `World`, next to the link facts.
- A reconciler that consumes a resolver a WAN learned (DHCPv4 today, RDNSS now; IPCP and
  DHCPv6 later) uses it only while a default route of that family exists through that WAN.
  The RA reconciler advertises router lifetime 1800 only while the WAN that provides the
  prefix has carrier and an IPv6 default route in the kernel, else 0.
- Typed configuration is never gated: `[dns] upstreams` and `[wans.static] dns` are the
  owner's word, and the owner may have a route the router did not install.
- The forwarder's retry of a failed send stays: routes can vanish at any moment, not only at
  boot.

## Consequences

- No service needs a workaround for the boot-time race; the gate opens on the kernel's own
  event for the route the applier added, which is the moment a send can succeed.
- A learned resolver appears in the console's `dns upstreams` line only once its route exists;
  the m1 scenario that waits for that line keeps its meaning.
- Every future learned fact follows the same rule, and a reviewer may ask of any new consumer
  of a learned fact which route it waits for.
