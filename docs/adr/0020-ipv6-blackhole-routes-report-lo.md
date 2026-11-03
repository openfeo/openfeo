# 0020 — The kernel reports an IPv6 blackhole route on `lo`; the monitor drops the device

Status: Accepted (3 November 2026)

## Context

SPEC §7.4 gives every routed prefix a blackhole route: the IPv4 blocks since M2 part 1, the
IPv6 prefix from part 2. The applier compares the routes it wants with the netlink monitor's
cache and adds what is missing (SPEC §6.2). An IPv4 blackhole is dumped as the applier added
it: no output interface. An IPv6 blackhole comes back from the kernel with `RTA_OIF` set to the
loopback device: `ip -6 route` shows it as `blackhole 2001:db8:1::/48 dev lo`. The desired
route carries no interface, so the two never compare equal, the applier re-adds the route on
every pass (the kernel answers `EEXIST`, which the applier tolerates) and the console never
announces `ready`, since a pass with operations is not a converged one.

## Decision

The monitor's `route_from` clears `oif` on every route of kind blackhole, whichever family.
A blackhole has no interface in the model (`Route`, `DesiredRoute`), the kernel's `lo` is a
detail of how it implements the drop, and the applier's comparison holds.

## Consequences

- The netlink sandbox scenario for an IPv6 blackhole asserts that the cache holds a route equal
  to the one added; it fails without this normalisation.
- Should a future route kind come back with a device the model does not carry, the same place
  is where it is dropped.
