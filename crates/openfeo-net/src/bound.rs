// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A listening socket with `SO_REUSEADDR`, on one bridge (`SO_BINDTODEVICE`, so each hears its
//! own LAN and answers out of it) or on loopback for the box's own lookups. Every listener of
//! the DNS and SNTP drivers starts here, since a loopback socket next to a wildcard one on the
//! same port needs the option on both.

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{
    AddressFamily, SockFlag, SockProtocol, SockType, SockaddrIn, bind, setsockopt, socket, sockopt,
};

use crate::dhcp4::{DriverError, socket_err};

/// A non-blocking socket bound to `addr:port`, on `device` when given.
pub(crate) fn bound_socket(
    device: Option<&str>,
    addr: Ipv4Addr,
    port: u16,
    kind: SockType,
    protocol: SockProtocol,
) -> Result<OwnedFd, DriverError> {
    let fd = socket(
        AddressFamily::Inet,
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
    bind(
        fd.as_raw_fd(),
        &SockaddrIn::from(SocketAddrV4::new(addr, port)),
    )
    .map_err(|source| DriverError::Bind {
        kind: if kind == SockType::Stream {
            "TCP"
        } else {
            "UDP"
        },
        addr: SocketAddrV4::new(addr, port),
        device: device.map(str::to_owned),
        source,
    })?;
    Ok(fd)
}
