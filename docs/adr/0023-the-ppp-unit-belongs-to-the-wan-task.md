# 0023 — The PPP unit belongs to the WAN task; its netdev belongs to the links applier

Status: Accepted (7 November 2026)

## Context

A PPP session's netdev is not made by `ip link add`: the kernel creates `ppp<N>` when a
process does `PPPIOCNEWUNIT` on `/dev/ppp`, and removes it when that descriptor closes. The
project's rule (SPEC §6.2) is that tasks run protocols and publish facts while the appliers
own netlink and make the kernel match the World; a PPP unit sits across that line. SPEC §7.8
already names the netdev `ppp-<wan>`.

## Decision

The PPPoE WAN task opens `/dev/ppp`, creates the unit, attaches and connects the channel, and
owns the three descriptors (the `AF_PPPOX` socket, the unit fd, the channel fd) for the
session's life; it publishes the unit number in `PppoeFact`. The links reconciler desires
`ppp-<wan>` for that unit, and the links applier renames `ppp<N>` to it, sets its MTU and
brings it up, as it does for any link. Nothing is desired for the netdev until the World's
link facts show it. A `ppp-*` link the World shows without a fact is a task between sessions
and is left alone; no applier deletes one. The address applier treats `ppp-<wan>` of a
configured PPPoE WAN as its own to manage.

## Consequences

- Dropping the task's descriptors removes the netdev, so a session's end withdraws the fact
  first and the routes and addresses go with it before the kernel takes the link.
- Every session is a new unit and so a new interface index for the same name: the `ipv6` and
  `dhcp6` tasks treat the change as a link flap in place and never as a failure, so a line that
  retrains does not spend the supervisor's restart budget.
- The kernel's unit name (`ppp0`) is visible for a moment between creation and rename; the
  console never prints it, only `ppp-<wan>`.
