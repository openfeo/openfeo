// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The PPPoE drivers (SPEC §7.2, ADR-0023). [`Discovery`] is the discovery socket: an
//! `AF_PACKET` datagram socket for `ETH_P_PPP_DISC` bound to the WAN port, as the DHCPv4
//! driver's is for IPv4, sending to the broadcast or the access concentrator's MAC and
//! receiving with the source MAC; session frames (`ETH_P_PPP_SES`) never reach it, they are the
//! kernel's. [`Session`] is the kernel plumbing of one session, as `pppd` makes it: an
//! `AF_PPPOX` socket connected to the session, a `/dev/ppp` unit (the netdev `ppp<N>`) and a
//! `/dev/ppp` channel attached to the socket and connected to the unit. Control frames arrive
//! where the kernel puts them: protocols `0xc000` and above (LCP, PAP, CHAP) on the channel
//! descriptor, the network control protocols (IPCP, IPV6CP) on the unit descriptor once the
//! channel is connected; the driver polls both and writes each frame to the descriptor its
//! protocol class belongs to. Dropping the `Session` closes the three descriptors, which the
//! kernel answers by removing the unit and its netdev.

use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

use nix::sys::socket::{LinkAddr, MsgFlags, bind, recvfrom, sendto};
use nix::unistd::{read, write};
use openfeo_proto_ppp::pppoe::ETH_P_PPP_DISC;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tracing::warn;

use crate::dhcp4::{DriverError, io_err, is_transient, socket_err};
use crate::sys;

/// The device the PPP units and channels come from.
pub const DEV_PPP: &str = "/dev/ppp";
/// Protocols from this number up are link-layer control (LCP, PAP, CHAP): the channel's.
const CONTROL_PROTOCOLS: u16 = 0xc000;
/// How long a transient socket error (the port down or gone) rests before the next read.
const TRANSIENT_WAIT: Duration = Duration::from_secs(1);

/// The discovery socket of one WAN port.
#[derive(Debug)]
pub struct Discovery {
    fd: AsyncFd<OwnedFd>,
    ifindex: u32,
    ifname: String,
}

impl Discovery {
    /// Open the discovery socket on interface `ifindex` (`ifname` for the console).
    ///
    /// # Errors
    ///
    /// When the socket cannot be opened, bound or registered.
    pub fn open(ifindex: u32, ifname: &str) -> Result<Discovery, DriverError> {
        let fd = sys::packet_socket(ETH_P_PPP_DISC).map_err(io_err("open discovery socket"))?;
        let addr =
            sys::link_addr(ifindex, ETH_P_PPP_DISC, None).ok_or(DriverError::Address(ifindex))?;
        bind(fd.as_raw_fd(), &addr).map_err(socket_err("bind discovery socket"))?;
        let fd = sys::register(fd).map_err(io_err("register discovery socket"))?;
        Ok(Discovery {
            fd,
            ifindex,
            ifname: ifname.to_owned(),
        })
    }

    /// The interface the socket is bound to.
    #[must_use]
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// The next discovery frame's payload into `buf`, with the sender's MAC. A port that is
    /// down or gone is waited for, not failed on: the core's timers and the next link-up
    /// recover.
    ///
    /// # Errors
    ///
    /// When the socket fails for any other reason.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<([u8; 6], usize), DriverError> {
        loop {
            let mut guard = self
                .fd
                .readable()
                .await
                .map_err(io_err("wait for discovery socket"))?;
            match guard.try_io(|inner| {
                recvfrom::<LinkAddr>(inner.as_raw_fd(), buf).map_err(std::io::Error::from)
            }) {
                Ok(Ok((len, from))) => {
                    // A frame without a source hardware address is nobody's.
                    if let Some(mac) = from.and_then(|addr| addr.addr()) {
                        return Ok((mac, len));
                    }
                }
                Ok(Err(err)) if is_transient(&err) => {
                    warn!(
                        "pppoe {}: discovery socket: {err}; waiting for the link",
                        self.ifname
                    );
                    tokio::time::sleep(TRANSIENT_WAIT).await;
                }
                Ok(Err(err)) => return Err(io_err("receive on discovery socket")(err)),
                Err(_would_block) => {}
            }
        }
    }

    /// Send the discovery payload `bytes` to `to` (the broadcast address, or the access
    /// concentrator's MAC).
    ///
    /// # Errors
    ///
    /// When the kernel refuses (the port is down).
    pub fn send(&self, to: [u8; 6], bytes: &[u8]) -> Result<(), DriverError> {
        let addr = sys::link_addr(self.ifindex, ETH_P_PPP_DISC, Some(to))
            .ok_or(DriverError::Address(self.ifindex))?;
        sendto(self.fd.as_raw_fd(), bytes, &addr, MsgFlags::empty())
            .map(drop)
            .map_err(socket_err("send discovery frame"))
    }
}

/// The kernel side of one PPPoE session: the socket, the unit and the channel (ADR-0023). The
/// fields drop in this order: the channel detaches, the unit goes with its netdev, the socket
/// closes last.
#[derive(Debug)]
pub struct Session {
    /// The channel descriptor: the link-layer control frames.
    channel: AsyncFd<OwnedFd>,
    /// The unit descriptor: the network control frames and `PPPIOCSMRU`.
    unit_fd: AsyncFd<OwnedFd>,
    /// The PPPoE socket the channel is made of: held for the session's life, never read.
    _pppox: OwnedFd,
    unit: u32,
}

impl Session {
    /// Attach to session `session_id` with the access concentrator `ac_mac` on the port
    /// `port_ifname`: the PPPoE socket connected, a new unit (its netdev `ppp<unit>` is born
    /// down, for the links applier to rename, size and raise), the channel attached and
    /// connected. Call inside a tokio runtime: the descriptors register with it.
    ///
    /// # Errors
    ///
    /// When any of the calls fails; [`dev_ppp_unavailable`] tells a kernel without PPP from a
    /// refusal of this session.
    pub fn attach(
        port_ifname: &str,
        session_id: u16,
        ac_mac: [u8; 6],
    ) -> Result<Session, DriverError> {
        let pppox = sys::pppox_socket().map_err(io_err("open PPPoE socket"))?;
        sys::pppoe_connect(pppox.as_fd(), session_id, ac_mac, port_ifname)
            .map_err(io_err("connect PPPoE socket"))?;
        let unit_fd = open_dev_ppp()?;
        let unit = sys::ppp_new_unit(unit_fd.as_fd()).map_err(io_err("PPPIOCNEWUNIT"))?;
        let index = sys::ppp_channel_index(pppox.as_fd()).map_err(io_err("PPPIOCGCHAN"))?;
        let channel = open_dev_ppp()?;
        sys::ppp_attach_channel(channel.as_fd(), index).map_err(io_err("PPPIOCATTCHAN"))?;
        sys::ppp_connect_unit(channel.as_fd(), unit).map_err(io_err("PPPIOCCONNECT"))?;
        let channel = sys::register(channel).map_err(io_err("register channel descriptor"))?;
        let unit_fd = sys::register(unit_fd).map_err(io_err("register unit descriptor"))?;
        Ok(Session {
            channel,
            unit_fd,
            _pppox: pppox,
            unit,
        })
    }

    /// The kernel's unit number: the netdev is `ppp<unit>` until renamed.
    #[must_use]
    pub fn unit(&self) -> u32 {
        self.unit
    }

    /// The next control frame: its protocol, and its payload's length in `buf` (the payload
    /// starts at `buf[0]`). The channel is read before the unit, as `pppd` reads them: LCP
    /// comes in there.
    ///
    /// # Errors
    ///
    /// When a descriptor fails or the kernel closes it (the unit is gone).
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(u16, usize), DriverError> {
        loop {
            tokio::select! {
                biased;
                guard = self.channel.readable() => {
                    let guard = guard.map_err(io_err("wait for channel descriptor"))?;
                    if let Some(frame) = read_frame(guard, buf, "read channel descriptor")? {
                        return Ok(frame);
                    }
                }
                guard = self.unit_fd.readable() => {
                    let guard = guard.map_err(io_err("wait for unit descriptor"))?;
                    if let Some(frame) = read_frame(guard, buf, "read unit descriptor")? {
                        return Ok(frame);
                    }
                }
            }
        }
    }

    /// Write one frame: `protocol` and `payload` to the descriptor the protocol belongs to
    /// (`0xc000` and above to the channel, the rest to the unit).
    ///
    /// # Errors
    ///
    /// When the kernel refuses (the channel is gone).
    pub fn send(&self, protocol: u16, payload: &[u8]) -> Result<(), DriverError> {
        let mut frame = Vec::with_capacity(payload.len() + 2);
        frame.extend_from_slice(&protocol.to_be_bytes());
        frame.extend_from_slice(payload);
        let fd = if protocol >= CONTROL_PROTOCOLS {
            &self.channel
        } else {
            &self.unit_fd
        };
        write(fd.get_ref(), &frame)
            .map(drop)
            .map_err(socket_err("write PPP frame"))
    }

    /// `PPPIOCSMRU` on the unit, once LCP has settled the MRU.
    ///
    /// # Errors
    ///
    /// When the kernel refuses.
    pub fn set_mru(&self, mru: u16) -> Result<(), DriverError> {
        sys::ppp_set_mru(self.unit_fd.get_ref().as_fd(), mru).map_err(io_err("PPPIOCSMRU"))
    }
}

/// Whether `err` says this kernel offers no PPP to this process, rather than refusing one
/// session: `/dev/ppp` missing (no `ppp_generic`) or not openable (root-only; SPEC §11's udev
/// rule), or the `AF_PPPOX` family or the PPPoE protocol unknown (no `pppox` or `pppoe`
/// module). A scenario skips on it; the task says so once and waits.
#[must_use]
pub fn dev_ppp_unavailable(err: &DriverError) -> bool {
    match err {
        DriverError::Io { source, .. } => {
            matches!(
                source.kind(),
                ErrorKind::NotFound | ErrorKind::PermissionDenied
            ) || matches!(
                source.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ENXIO)
            )
        }
        _ => false,
    }
}

/// A fresh `/dev/ppp` descriptor, non-blocking and close-on-exec.
fn open_dev_ppp() -> Result<OwnedFd, DriverError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(DEV_PPP)
        .map(OwnedFd::from)
        .map_err(io_err("open /dev/ppp"))
}

/// One frame from a ready descriptor: `Some((protocol, payload length))` with the payload moved
/// to the front of `buf`, `None` when the readiness was stale or the frame too short to carry a
/// protocol.
fn read_frame(
    mut guard: AsyncFdReadyGuard<'_, OwnedFd>,
    buf: &mut [u8],
    what: &'static str,
) -> Result<Option<(u16, usize)>, DriverError> {
    match guard.try_io(|inner| read(inner.get_ref(), buf).map_err(std::io::Error::from)) {
        Ok(Ok(0)) => Err(io_err(what)(std::io::Error::from(ErrorKind::UnexpectedEof))),
        Ok(Ok(len)) if len >= 2 => {
            let protocol = u16::from_be_bytes([buf[0], buf[1]]);
            buf.copy_within(2..len, 0);
            Ok(Some((protocol, len - 2)))
        }
        Ok(Ok(_)) => Ok(None),
        Ok(Err(err)) => Err(io_err(what)(err)),
        Err(_would_block) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kernel_without_ppp_is_told_apart_from_a_refused_session() {
        let unavailable = |kind: ErrorKind| {
            dev_ppp_unavailable(&io_err("open /dev/ppp")(std::io::Error::from(kind)))
        };
        assert!(unavailable(ErrorKind::NotFound), "no ppp_generic");
        assert!(
            unavailable(ErrorKind::PermissionDenied),
            "root-only /dev/ppp"
        );
        assert!(
            dev_ppp_unavailable(&io_err("open PPPoE socket")(
                std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT)
            )),
            "no pppox"
        );
        assert!(
            !dev_ppp_unavailable(&io_err("connect PPPoE socket")(
                std::io::Error::from_raw_os_error(libc::EBUSY)
            )),
            "a session already connected is this session's problem"
        );
        assert!(!dev_ppp_unavailable(&DriverError::Address(7)));
    }

    #[test]
    fn control_protocols_go_to_the_channel_and_network_ones_to_the_unit() {
        for protocol in [0xc021u16, 0xc023, 0xc223, 0xc025] {
            assert!(
                protocol >= CONTROL_PROTOCOLS,
                "{protocol:#06x} is the channel's"
            );
        }
        for protocol in [0x8021u16, 0x8057, 0x0021, 0x0057] {
            assert!(
                protocol < CONTROL_PROTOCOLS,
                "{protocol:#06x} is the unit's"
            );
        }
    }
}
