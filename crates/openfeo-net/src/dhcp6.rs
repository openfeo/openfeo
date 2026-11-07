// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv6 sockets (SPEC §7.3): the WAN client's, bound to port 546 on its port and joined
//! to `ff02::1:2`, sending to that group from the link-local address the kernel picks; and the
//! stateless responder's, bound to port 547 on a LAN bridge the same way, answering hosts at
//! their link-local addresses. Plain UDP: the kernel checksums, no `unsafe`, nothing to filter.

use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket as StdUdpSocket};

use nix::sys::socket::{SockProtocol, SockType};
use openfeo_proto_dhcp6::wire::{ALL_DHCP_RELAY_AGENTS_AND_SERVERS, CLIENT_PORT, SERVER_PORT};
use tokio::net::UdpSocket;

use crate::bound::bound_socket;
use crate::dhcp4::{DriverError, io_err};

/// A UDP socket on `port`, bound to `ifname` and joined to the DHCPv6 group on `ifindex`.
fn group_socket(ifindex: u32, ifname: &str, port: u16) -> Result<UdpSocket, DriverError> {
    let fd = bound_socket(
        Some(ifname),
        Ipv6Addr::UNSPECIFIED.into(),
        port,
        SockType::Datagram,
        SockProtocol::Udp,
    )?;
    let socket = StdUdpSocket::from(fd);
    socket
        .join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, ifindex)
        .map_err(io_err("join the DHCPv6 group"))?;
    UdpSocket::from_std(socket).map_err(io_err("register DHCPv6 socket"))
}

/// The WAN client's socket.
#[derive(Debug)]
pub struct ClientSocket {
    socket: UdpSocket,
    ifindex: u32,
}

impl ClientSocket {
    /// Open the client's socket on interface `ifindex` (`ifname` for `SO_BINDTODEVICE`).
    ///
    /// # Errors
    ///
    /// When the socket cannot be opened or bound, or the group not joined (the interface
    /// does not exist or has no IPv6 yet).
    pub fn open(ifindex: u32, ifname: &str) -> Result<ClientSocket, DriverError> {
        Ok(ClientSocket {
            socket: group_socket(ifindex, ifname, CLIENT_PORT)?,
            ifindex,
        })
    }

    /// The interface the socket is bound to.
    #[must_use]
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// The next message into `buf`, with its source.
    ///
    /// # Errors
    ///
    /// When the socket fails.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(Ipv6Addr, usize), DriverError> {
        loop {
            let (len, from) = self
                .socket
                .recv_from(buf)
                .await
                .map_err(io_err("receive DHCPv6"))?;
            if let std::net::SocketAddr::V6(from) = from {
                return Ok((*from.ip(), len));
            }
        }
    }

    /// Send `bytes` to the servers and relays on the link.
    ///
    /// # Errors
    ///
    /// When the kernel refuses: the interface has no link-local address yet, or is down.
    pub fn send(&self, bytes: &[u8]) -> Result<(), DriverError> {
        self.send_to(ALL_DHCP_RELAY_AGENTS_AND_SERVERS, bytes)
    }

    /// Send `bytes` to one server's address on the link.
    ///
    /// # Errors
    ///
    /// As [`ClientSocket::send`].
    pub fn send_to(&self, to: Ipv6Addr, bytes: &[u8]) -> Result<(), DriverError> {
        self.socket
            .try_send_to(
                bytes,
                SocketAddrV6::new(to, SERVER_PORT, 0, self.ifindex).into(),
            )
            .map(drop)
            .map_err(io_err("send DHCPv6"))
    }
}

/// The stateless responder's socket on a LAN bridge.
#[derive(Debug)]
pub struct ServerSocket {
    socket: UdpSocket,
}

impl ServerSocket {
    /// Open the responder's socket on interface `ifindex` (`ifname` for `SO_BINDTODEVICE`).
    ///
    /// # Errors
    ///
    /// As [`ClientSocket::open`].
    pub fn open(ifindex: u32, ifname: &str) -> Result<ServerSocket, DriverError> {
        Ok(ServerSocket {
            socket: group_socket(ifindex, ifname, SERVER_PORT)?,
        })
    }

    /// The next request into `buf`, with the host's address and port to answer at.
    ///
    /// # Errors
    ///
    /// When the socket fails.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(SocketAddrV6, usize), DriverError> {
        loop {
            let (len, from) = self
                .socket
                .recv_from(buf)
                .await
                .map_err(io_err("receive DHCPv6"))?;
            if let std::net::SocketAddr::V6(from) = from {
                return Ok((from, len));
            }
        }
    }

    /// Answer `to` with `bytes`.
    ///
    /// # Errors
    ///
    /// When the kernel refuses the send.
    pub fn send_to(&self, to: SocketAddrV6, bytes: &[u8]) -> Result<(), DriverError> {
        self.socket
            .try_send_to(bytes, to.into())
            .map(drop)
            .map_err(io_err("send DHCPv6"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_fails_without_the_interface() {
        assert!(ClientSocket::open(0, "no-such-interface").is_err());
        assert!(ServerSocket::open(0, "no-such-interface").is_err());
    }
}
