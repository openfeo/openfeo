// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A listening socket with `SO_REUSEADDR`, on one bridge (`SO_BINDTODEVICE`, so each hears its
//! own LAN and answers out of it) or on loopback for the box's own lookups. Every listener of
//! the DNS and SNTP drivers starts here, since a loopback socket next to a wildcard one on the
//! same port needs the option on both.

use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{
    AddressFamily, SockFlag, SockProtocol, SockType, SockaddrIn, SockaddrIn6, bind, setsockopt,
    socket, sockopt,
};

use crate::dhcp4::{DriverError, socket_err};

/// A non-blocking socket bound to `addr:port`, on `device` when given; an IPv6 address gets a
/// v6-only socket, so the two families on one port never collide.
pub(crate) fn bound_socket(
    device: Option<&str>,
    addr: IpAddr,
    port: u16,
    kind: SockType,
    protocol: SockProtocol,
) -> Result<OwnedFd, DriverError> {
    let family = match addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    let fd = socket(
        family,
        kind,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        protocol,
    )
    .map_err(socket_err("open listener socket"))?;
    setsockopt(&fd, sockopt::ReuseAddr, &true).map_err(socket_err("SO_REUSEADDR"))?;
    if let Some(device) = device {
        setsockopt(&fd, sockopt::BindToDevice, &OsString::from(device))
            .map_err(socket_err("SO_BINDTODEVICE"))?;
    }
    let bind_err = |source| DriverError::Bind {
        kind: if kind == SockType::Stream {
            "TCP"
        } else {
            "UDP"
        },
        addr: SocketAddr::new(addr, port),
        device: device.map(str::to_owned),
        source,
    };
    match addr {
        IpAddr::V4(addr) => bind(
            fd.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(addr, port)),
        )
        .map_err(bind_err)?,
        IpAddr::V6(addr) => {
            setsockopt(&fd, sockopt::Ipv6V6Only, &true).map_err(socket_err("IPV6_V6ONLY"))?;
            bind(
                fd.as_raw_fd(),
                &SockaddrIn6::from(SocketAddrV6::new(addr, port, 0, 0)),
            )
            .map_err(bind_err)?;
        }
    }
    Ok(fd)
}
