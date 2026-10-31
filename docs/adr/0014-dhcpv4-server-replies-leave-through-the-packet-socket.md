# 0014 — The DHCPv4 server sends every reply through its packet socket

Status: Accepted (31 October 2026)

## Context

The LAN DHCPv4 server (SPEC §7.6) first sent its broadcast and `ciaddr` replies through a UDP
socket bound to the bridge, and only the replies to clients without an address as frames of its
own through its packet socket. In the sandbox suite (`harness/tests/dhcp4_server.rs`, a veth
pair) busybox `udhcpc` was served and our own client was not: the server logged every OFFER as
sent, the client, listening on a packet socket as DHCP clients must, never saw one.

The cause is checksum offload. A UDP datagram sent through the kernel's IP path over a veth,
and equally over virtio-net in a VM, leaves with `CHECKSUM_PARTIAL`: the UDP checksum field
carries the pseudo-header sum, and the real checksum is meant to be filled in by hardware that a
virtual link does not have. A client reading raw frames verifies the checksum and drops the
reply; `udhcpc` does so as well, and had only been served because it asks for no broadcast
reply and therefore got the frame path. Replies to clients that set the BROADCAST flag (ours),
every NAK (always broadcast, RFC 2131 §4.3.2) and the unicast ACKs of renewals were all
affected. Real NICs complete the checksum, so a deployment on hardware would have worked while
every VM, the lab included, would not; the well-known cure of switching transmit checksum
offload off is a workaround, not a fix.

ISC dhcpd and Kea send every reply as a frame with their own checksums for this reason.

## Decision

- The server driver (`openfeo-net::dhcp4_server`) sends every reply, broadcast or unicast,
  through its packet socket as an IPv4/UDP frame it builds with `openfeo_proto_dhcp4::udp`,
  checksums included. The UDP socket on port 67 only receives.
- The core's `Destination` has two forms: `Broadcast`, and `Link { ip, mac }` for the client's
  own hardware address, used both for a client without an address (`yiaddr`) and for one that
  speaks from an address (`ciaddr`, RFC 2131 §4.1). A relay (`giaddr`) is not served.

## Consequences

- No reply depends on the bridge having its address yet, nor on the kernel's routing of
  limited broadcasts from a bound socket.
- The harness runs the server against raw-socket clients on veth pairs and in QEMU without
  touching offload settings, and would catch a regression at once.
- The same hazard applies to any future service that must talk to raw-socket peers over
  virtual links; a UDP socket is fine only when the peer's kernel does the verifying.
- Replies go to the client's `chaddr`, not to the source address of the frame that carried the
  request (which the UDP receive path does not see): a client whose `chaddr` differs from its
  link address is not served. Kea uses the source address; ISC lets the kernel resolve
  `ciaddr`. On a flat LAN the two are the same address.
- A reply larger than the bridge's MTU is refused by the kernel (the frame carries DF) and
  logged as a failed send; replies are a few hundred bytes.
