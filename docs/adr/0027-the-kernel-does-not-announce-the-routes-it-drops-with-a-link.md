# 0027 — The kernel does not announce the routes it drops with a link; the monitor drops them

Status: Accepted (28 November 2026)

## Context

The netlink monitor keeps a cache of every link, address, route and rule the kernel holds: it
dumps them once and then follows the kernel's notifications (ADR-0011). The applier compares
what it wants with that cache, and from M4 part 3c the API answers the cache's routes whole
(`DiagnosticsService.DumpRoutes`), for a page that lists them.

When a link is removed, the kernel drops every route through it. For the IPv6 routes it sends
an `RTM_DELROUTE` each. For the IPv4 routes it sends none: they are flushed with the device,
and only a route deleted by request is announced. The netlink sandbox scenario
`a_removed_link_takes_its_routes_out_of_the_cache` shows it (found on Linux 7.2, the kernel of
the machine the sandbox ran on): a veth pair with `192.0.2.1/24` and a route to
`198.51.100.0/24` through it is deleted, `ip route` no longer shows the route, and the cache
went on holding three: the connected route, the route that was added, and the broadcast entry
of the local table, each through an interface index that names nothing.

A PPPoE session that ends and comes back is a new interface (ADR-0023), and so is a VLAN
sub-interface whose tag was changed. Each left its routes in the cache, where a dump would list
them: a default route through an interface that is gone, beside the one in use.

## Decision

The monitor drops a removed link's routes itself: on `RTM_DELLINK` it takes out of the cache
every route whose output interface is that link's index, and says the cache changed if it took
any. Whatever was routed through a link is gone with it, in both families; the deletions the
kernel does announce for the IPv6 routes then find nothing to remove.

The dump also leaves out a route whose interface the cache cannot name. Between a route's
notification and its link's that is an instant; it is not relied on for the case above.

## Consequences

- The sandbox scenario fails without the monitor's own removal, on a kernel that behaves as
  described, and passes on one that announces the routes too. It has not been run on the
  router's own kernel apart from the QEMU scenarios, none of which reads a removed link's
  routes; the removal is right either way.
- A link that is set down and kept loses its IPv4 routes as silently, and keeps its index, so
  this does not cover it. The router sets no link down that it keeps. If that changes, the
  routes have to be dumped afresh when a link goes down.
- The applier no longer finds, in the cache, routes of its own through a link that went.
