# 0013 — `openfeo-net` holds one unsafe module, for AF_PACKET socket addresses

Status: Accepted (30 October 2026)

## Context

SPEC §9 allows `unsafe` only in `openfeo-init` and `openfeo-nft`, each confined to a small
module with `// SAFETY:` comments. The DHCPv4 client (SPEC §7.2) needs an AF_PACKET socket
while a WAN has no address: a server may unicast its OFFER and ACK to the address it is
offering, which the kernel's IP stack drops because the host does not own that address yet.
Such a socket must be bound to its interface. An unbound packet socket receives every IPv4
frame of every port, so a LAN moving traffic at line rate would be copied into userspace for
as long as a WAN stayed unaddressed, which with an ISP outage is indefinitely.
`SO_BINDTODEVICE` does not filter packet sockets; binding needs a `sockaddr_ll`, and nix 0.30
offers no safe constructor for one (`LinkAddr` has only an `unsafe fn from_raw`). socket2's
raw-address constructors are unsafe too.

## Decision

- `openfeo-net` is `#![deny(unsafe_code)]` with one `#[allow(unsafe_code)] mod sys` holding
  `link_addr(ifindex, protocol, dest) -> Option<LinkAddr>`: a fully initialised
  `libc::sockaddr_ll` handed to `LinkAddr::from_raw` with its exact length, under a
  `// SAFETY:` comment. It serves both `bind` (no destination) and `sendto` (the broadcast
  hardware address). The same module holds `register(OwnedFd) -> io::Result<AsyncFd<OwnedFd>>`:
  tokio 1.54 made `AsyncFd::register` an unsafe function so that the caller vouches the
  descriptor stays open while registered, which an owned descriptor moved into the `AsyncFd`
  guarantees.
- SPEC §9 and CLAUDE.md name `openfeo-net` beside `openfeo-init` and `openfeo-nft`.
- The packet socket exists only while the client is unaddressed (INIT, SELECTING, REQUESTING,
  REBOOTING); once bound the driver closes it and uses a UDP socket with `SO_BINDTODEVICE`,
  as SPEC §7.2 says.

## Consequences

- A review of `crates/openfeo-net/src/sys.rs` is part of every change to it; the module is a
  dozen lines and has a unit test for the address it builds.
- Should nix grow a safe `LinkAddr` constructor, the module goes and this ADR is superseded.
- The driver receives all IPv4 frames of one WAN port while unaddressed and filters UDP port
  68 in userspace; no BPF filter is attached (that would be another unsafe `setsockopt`), and
  a WAN without an address carries next to no traffic. INIT-REBOOT after a link flap, when the
  address is still configured and traffic may be flowing, stays on the UDP socket and asks for
  a unicast reply; the packet socket returns only once the lease is gone.
