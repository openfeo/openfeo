# 0026 — Commit-confirm waits 120 seconds by default

Status: Accepted (12 November 2026)

## Context

A change of config is applied as pending and reverts by itself unless it is confirmed
(SPEC §5.5). SPEC §2 fixed the wait at 60 seconds by default.

The change that most needs the safety net is the one that moves the router's own address:
a LAN given another subnet. The person who made it is then on the wrong subnet. To confirm
they have to renew their DHCP lease or change a static address by hand, find the panel
again, perhaps pass the certificate warning at a new address and log in again, and press
Confirm. Sixty seconds is not enough for a person doing that for the first time, and a
window that runs out on a correct change teaches people to switch the safety net off.

## Decision

The window is 120 seconds by default. A request may name its own, from 10 to 600 seconds;
the panel always uses the default.

## Consequences

- An unconfirmed mistake stands for a minute longer before the router goes back.
- A client that renews its lease during the window would hold an address the router no
  longer honours after a revert, and with a longer window more clients do. While a change is
  pending, the DHCPv4 server of a LAN the change touches therefore grants no lease longer
  than the window (SPEC §5.5), so such a client asks again within a minute or two whichever
  way the change ends.
- A harness build can be told a shorter default on the kernel command line, so that a
  browser scenario does not wait two minutes. A release build has no such knob.
