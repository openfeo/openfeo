# 0011 — The netlink monitor and the request path use separate sockets

Status: Accepted (30 October 2026)

## Context

SPEC §6.2 says appliers compare desired state against the netlink monitor's cache and never
against a one-off dump, so the cache has to reflect the appliers' own changes. The first
implementation used one rtnetlink socket for both the multicast subscription and the requests.
Links worked, addresses and routes did not: the sandboxed test saw the kernel acknowledge
`RTM_NEWADDR` yet the cache never gained the address.

The reason is in the kernel: `rtnl_notify()` passes the requesting socket's port id to
`netlink_broadcast()`, which excludes that socket from the multicast delivery. Address and route
changes (`rtmsg_ifa`, `rtmsg_fib`, and their IPv6 equivalents) are notified with the requester's
port id, so the requester never receives them; link changes (`rtmsg_ifinfo`) are notified with
port id 0, so everyone receives them. `ip` does not notice because it never monitors and
requests on the same socket.

## Decision

`openfeo_netlink::Netlink::connect` opens two connections. The monitor socket joins the link,
address and route multicast groups and performs the initial dumps; the request socket is what the
apply primitives send on. They have different port ids, so every change the appliers make reaches
the monitor as an ordinary notification.

## Consequences

- Two netlink file descriptors and two connection tasks per process.
- Dumps happen on the monitor socket, after the subscription, so nothing that changes during a
  dump is lost.
- The sandboxed `addr_and_route_primitives` scenario covers the behaviour: an address and a route
  added through the request path must appear in the cache.
- The monitor is not restarted when its stream ends (a reconnect would need a fresh dump
  republished onto the existing `watch` sender). Its death is reported to the health tracker as a
  dead task, which withholds the heartbeat, and the watchdog reboots the box within a minute
  (SPEC §5.3): the designed response to a control plane that can no longer see the kernel.
  Revisit with a reconnect-and-redump path if a notification burst (`ENOBUFS` on the
  multicast socket) ever triggers it in practice.
