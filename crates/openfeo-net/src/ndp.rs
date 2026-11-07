// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The ICMPv6 socket under the neighbour-discovery cores (SPEC §7.3): one raw socket per
//! interface, bound to it, hop limit 255 both ways, delivering only the one message type its
//! core wants (advertisements for the WAN client, solicitations for a LAN server) with the
//! source address and hop limit the core validates. The kernel fills the ICMPv6 checksum.

use std::ffi::OsString;
use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::time::Duration;

use nix::cmsg_space;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockaddrIn6, recvmsg, sendmsg, setsockopt,
    sockopt,
};
use tokio::io::unix::AsyncFd;

use crate::dhcp4::{DriverError, io_err, socket_err};
use crate::sys;

/// `ff02::1`, every node on the link: where advertisements go and clients listen.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// `ff02::2`, every router on the link: where solicitations go and servers listen.
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// ICMPv6 type of a router solicitation.
const ROUTER_SOLICITATION: u8 = 133;
/// ICMPv6 type of a router advertisement.
const ROUTER_ADVERTISEMENT: u8 = 134;

/// Which core the socket serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The WAN client: hears advertisements on the all-nodes group.
    Client,
    /// A LAN server: hears solicitations on the all-routers group.
    Server,
}

/// One received message, with what the cores validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// The IPv6 source.
    pub from: Ipv6Addr,
    /// The hop limit the packet arrived with (255 for genuine neighbour discovery).
    pub hop_limit: u8,
    /// The ICMPv6 message's length in the caller's buffer.
    pub len: usize,
}

/// A raw ICMPv6 socket on one interface.
#[derive(Debug)]
pub struct NdpSocket {
    fd: AsyncFd<OwnedFd>,
    ifindex: u32,
}

impl NdpSocket {
    /// Open the socket on interface `ifindex` (`ifname` for `SO_BINDTODEVICE`) for `role`.
    ///
    /// # Errors
    ///
    /// When the socket cannot be opened (no `CAP_NET_RAW`), an option refused, the group not
    /// joined (the interface has no IPv6 yet) or the descriptor not registered.
    pub fn open(ifindex: u32, ifname: &str, role: Role) -> Result<NdpSocket, DriverError> {
        let fd = sys::icmpv6_raw_socket().map_err(io_err("open ICMPv6 socket"))?;
        setsockopt(&fd, sockopt::BindToDevice, &OsString::from(ifname))
            .map_err(socket_err("SO_BINDTODEVICE"))?;
        setsockopt(&fd, sockopt::Ipv6MulticastHops, &255)
            .map_err(socket_err("IPV6_MULTICAST_HOPS"))?;
        setsockopt(&fd, sockopt::Ipv6Ttl, &255).map_err(socket_err("IPV6_UNICAST_HOPS"))?;
        setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true)
            .map_err(socket_err("IPV6_RECVPKTINFO"))?;
        setsockopt(&fd, sockopt::Ipv6RecvHopLimit, &true)
            .map_err(socket_err("IPV6_RECVHOPLIMIT"))?;
        let (pass, group) = match role {
            Role::Client => (ROUTER_ADVERTISEMENT, ALL_NODES),
            Role::Server => (ROUTER_SOLICITATION, ALL_ROUTERS),
        };
        sys::icmp6_filter(fd.as_fd(), &[pass]).map_err(io_err("ICMP6_FILTER"))?;
        sys::join_multicast_v6(fd.as_fd(), group, ifindex)
            .map_err(io_err("join multicast group"))?;
        Ok(NdpSocket {
            fd: sys::register(fd).map_err(io_err("register ICMPv6 socket"))?,
            ifindex,
        })
    }

    /// The interface the socket is bound to.
    #[must_use]
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// The next message into `buf`, with its source and hop limit. A datagram that arrives
    /// without its control messages (which the kernel never does once the options are set)
    /// is skipped.
    ///
    /// # Errors
    ///
    /// When the socket fails.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<Received, DriverError> {
        loop {
            let mut guard = self
                .fd
                .readable()
                .await
                .map_err(io_err("wait for ICMPv6 socket"))?;
            let result = guard.try_io(|inner| receive(inner.as_raw_fd(), buf));
            match result {
                Ok(Ok(Some(received))) => return Ok(received),
                Ok(Ok(None)) => {}
                Ok(Err(err)) => return Err(io_err("receive ICMPv6")(err)),
                Err(_would_block) => {}
            }
        }
    }

    /// Send `bytes` to `to` out of the interface, the kernel choosing the interface's
    /// link-local address as source (RFC 6724 rule 2 for a link-local destination) and
    /// filling the checksum.
    ///
    /// # Errors
    ///
    /// When the kernel refuses: the interface has no link-local address yet, or is down.
    pub fn send(&self, to: Ipv6Addr, bytes: &[u8]) -> Result<(), DriverError> {
        let info = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr { s6_addr: [0; 16] },
            ipi6_ifindex: self.ifindex,
        };
        let dest = SockaddrIn6::from(SocketAddrV6::new(to, 0, 0, self.ifindex));
        sendmsg::<SockaddrIn6>(
            self.fd.as_raw_fd(),
            &[IoSlice::new(bytes)],
            &[ControlMessage::Ipv6PacketInfo(&info)],
            MsgFlags::empty(),
            Some(&dest),
        )
        .map(drop)
        .map_err(socket_err("send ICMPv6"))
    }
}

/// How long a send refused while the interface's link-local address is tentative waits
/// before trying again (RFC 4862's duplicate address detection takes about a second), and
/// how many times it tries (#34).
pub const RESEND_AFTER: Duration = Duration::from_secs(1);
pub const RESEND_TRIES: u8 = 5;

/// Whether `err` is the kernel refusing to source from a link-local address it has not
/// finished checking (`EADDRNOTAVAIL`): the one send failure that answers itself in a second.
#[must_use]
pub fn tentative_link_local(err: &DriverError) -> bool {
    match err {
        DriverError::Socket { source, .. } => *source == nix::Error::EADDRNOTAVAIL,
        DriverError::Io { source, .. } => source.raw_os_error() == Some(libc::EADDRNOTAVAIL),
        DriverError::Address(_) | DriverError::Bind { .. } => false,
    }
}

/// A message to send again after a tentative failure.
#[derive(Debug)]
pub struct Resend {
    pub to: Ipv6Addr,
    pub bytes: Vec<u8>,
    pub tries_left: u8,
    /// When to try next.
    pub at: tokio::time::Instant,
}

impl Resend {
    /// The first retry of `bytes` to `to`, due in [`RESEND_AFTER`].
    #[must_use]
    pub fn new(to: Ipv6Addr, bytes: Vec<u8>) -> Resend {
        Resend {
            to,
            bytes,
            tries_left: RESEND_TRIES,
            at: tokio::time::Instant::now() + RESEND_AFTER,
        }
    }

    /// Try once more on `socket`: `Ok(None)` when sent, `Ok(Some)` when it failed tentatively
    /// again with tries left, `Err` when it failed for good or the tries ran out.
    ///
    /// # Errors
    ///
    /// The send error, when it is not tentative or no tries remain.
    pub fn retry(mut self, socket: &NdpSocket) -> Result<Option<Resend>, DriverError> {
        match socket.send(self.to, &self.bytes) {
            Ok(()) => Ok(None),
            Err(err) if tentative_link_local(&err) && self.tries_left > 1 => {
                self.tries_left -= 1;
                self.at = tokio::time::Instant::now() + RESEND_AFTER;
                Ok(Some(self))
            }
            Err(err) => Err(err),
        }
    }
}

/// One `recvmsg`: the payload into `buf`, the source from the address, the hop limit from the
/// control messages.
fn receive(fd: i32, buf: &mut [u8]) -> std::io::Result<Option<Received>> {
    let mut iov = [IoSliceMut::new(buf)];
    let mut cmsg = cmsg_space!(libc::in6_pktinfo, libc::c_int);
    let message = recvmsg::<SockaddrIn6>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
        .map_err(std::io::Error::from)?;
    let len = message.bytes;
    let from = message.address.map(|addr| addr.ip());
    let mut hop_limit = None;
    for control in message.cmsgs().map_err(std::io::Error::from)? {
        if let ControlMessageOwned::Ipv6HopLimit(limit) = control {
            hop_limit = u8::try_from(limit).ok();
        }
    }
    Ok(match (from, hop_limit) {
        (Some(from), Some(hop_limit)) => Some(Received {
            from,
            hop_limit,
            len,
        }),
        _ => None,
    })
}
