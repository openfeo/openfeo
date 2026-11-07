// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The one unsafe module of this crate (ADR-0013): addresses for `AF_PACKET` sockets and the
//! sockets themselves for the Ethernet protocols nix does not name, the registration of an owned
//! descriptor with tokio, `adjtimex`, the three calls the ICMPv6 neighbour-discovery socket
//! needs that nix does not name (the raw ICMPv6 socket itself, the `ICMP6_FILTER` option and the
//! interface-scoped multicast join), and the PPP plumbing (SPEC §7.2): the `AF_PPPOX` socket,
//! its `sockaddr_pppox`, and the `/dev/ppp` ioctls that make a unit and a channel, whose
//! numbers come from the pinned `linux/ppp-ioctl.h` (a unit test reads them back from it). nix
//! offers no safe way to build a `sockaddr_ll`, and a packet socket not bound to its interface
//! would copy every IPv4 frame of every port to userspace; tokio makes the caller vouch that a
//! registered descriptor stays open, which an `OwnedFd` guarantees.

use std::io;
use std::mem::size_of;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd as _, OwnedFd};

use nix::sys::socket::{LinkAddr, SockaddrLike};
use tokio::io::unix::AsyncFd;

/// `ICMP6_FILTER` (RFC 3542 §3.2): the option number from `linux/icmpv6.h`, which libc lacks.
const ICMP6_FILTER: libc::c_int = 1;

/// `struct icmp6_filter`: 256 bits, one per ICMPv6 type; a set bit blocks the type.
#[repr(C)]
struct Icmp6Filter {
    words: [u32; 8],
}

/// `socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMPV6)`: nix names no
/// ICMPv6 protocol. The kernel computes and checks the ICMPv6 checksum on such a socket.
///
/// # Errors
///
/// When the kernel refuses (no `CAP_NET_RAW`).
pub fn icmpv6_raw_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) takes three integers and returns a descriptor or -1.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMPV6,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned open by the kernel and nothing else owns or closes it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The `ICMP6_FILTER` bitmap that passes exactly the types in `pass`: every bit set (blocked)
/// but theirs.
#[must_use]
pub fn icmp6_filter_words(pass: &[u8]) -> [u32; 8] {
    let mut words = [u32::MAX; 8];
    for &kind in pass {
        words[usize::from(kind >> 5)] &= !(1u32 << (kind & 31));
    }
    words
}

/// Have the socket deliver only the ICMPv6 types in `pass` (RFC 3542 §3.2).
///
/// # Errors
///
/// When the kernel refuses the option.
pub fn icmp6_filter(fd: BorrowedFd<'_>, pass: &[u8]) -> io::Result<()> {
    let filter = Icmp6Filter {
        words: icmp6_filter_words(pass),
    };
    setsockopt_raw(fd, libc::IPPROTO_ICMPV6, ICMP6_FILTER, &filter)
}

/// Join `group` on interface `ifindex` (`IPV6_ADD_MEMBERSHIP`). nix's request names only the
/// group, and the kernel then picks the interface by route rather than by the socket's device.
///
/// # Errors
///
/// When the kernel refuses: no such interface, or the group is already joined.
pub fn join_multicast_v6(fd: BorrowedFd<'_>, group: Ipv6Addr, ifindex: u32) -> io::Result<()> {
    let request = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr {
            s6_addr: group.octets(),
        },
        ipv6mr_interface: ifindex,
    };
    setsockopt_raw(fd, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, &request)
}

fn setsockopt_raw<T>(
    fd: BorrowedFd<'_>,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> io::Result<()> {
    let len = libc::socklen_t::try_from(size_of::<T>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `value` is a plain C struct that lives for the whole call and `len` is exactly its
    // size; the kernel copies the bytes and keeps no pointer to them.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            std::ptr::from_ref(value).cast::<libc::c_void>(),
            len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Register `fd` with the tokio reactor for readiness.
///
/// # Errors
///
/// When the reactor refuses the descriptor (no runtime, or it is not pollable).
pub fn register(fd: OwnedFd) -> std::io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: tokio asks the caller to guarantee that the descriptor stays open and is not
    // closed behind the reactor's back for as long as it is registered. `OwnedFd` owns the
    // descriptor outright and is moved into the `AsyncFd`, which deregisters it before the
    // `OwnedFd` drops and closes it; nothing else holds the descriptor.
    unsafe { AsyncFd::register(fd) }.map_err(std::io::Error::from)
}

/// A `sockaddr_ll` for interface `ifindex` and Ethernet `protocol` (host order, such as
/// `ETH_P_IP`), with `dest` as the destination hardware address for `sendto`, or none for
/// `bind`. `None` only when a value does not fit the kernel's field types.
#[must_use]
pub fn link_addr(ifindex: u32, protocol: u16, dest: Option<[u8; 6]>) -> Option<LinkAddr> {
    let mut sll_addr = [0u8; 8];
    if let Some(dest) = dest {
        sll_addr[..6].copy_from_slice(&dest);
    }
    let raw = libc::sockaddr_ll {
        sll_family: u16::try_from(libc::AF_PACKET).ok()?,
        sll_protocol: protocol.to_be(),
        sll_ifindex: i32::try_from(ifindex).ok()?,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: if dest.is_some() { 6 } else { 0 },
        sll_addr,
    };
    let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_ll>()).ok()?;
    let ptr = std::ptr::from_ref(&raw).cast::<libc::sockaddr>();
    // SAFETY: `raw` is a fully initialised `sockaddr_ll` that lives for the whole call, its
    // family is AF_PACKET and `len` is exactly its size; `from_raw` checks both before copying
    // the bytes into the returned value, which borrows nothing from `raw`.
    unsafe { LinkAddr::from_raw(ptr, Some(len)) }
}

/// `adjtimex(2)` with `ADJ_SETOFFSET | ADJ_NANO`: step the clock by `ns` nanoseconds.
///
/// # Errors
///
/// When the kernel refuses: no `CAP_SYS_TIME` (a container), or an offset it cannot take.
pub fn adjtimex_step(ns: i64) -> std::io::Result<()> {
    // SAFETY: `timex` is a plain C struct of integers; all zero is a valid value, and the
    // kernel reads only the fields whose mode bits are set.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = libc::ADJ_SETOFFSET | libc::ADJ_NANO;
    // Under ADJ_NANO the kernel wants the sub-second part in nanoseconds, non-negative.
    tx.time.tv_sec = libc::time_t::try_from(ns.div_euclid(1_000_000_000))
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    tx.time.tv_usec = libc::suseconds_t::try_from(ns.rem_euclid(1_000_000_000))
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    adjtimex(&mut tx)
}

/// `adjtimex(2)` with `ADJ_OFFSET_SINGLESHOT`: slew the clock `ns` nanoseconds. The kernel's
/// single-shot path takes any offset and corrects it at 500 parts per million (it is glibc's
/// `adjtime(3)` wrapper that bounds it, at about ±2145 s; the PLL path, `ADJ_OFFSET`, stops at
/// `MAXPHASE`, half a second). The half-second clamp here is our own (ADR-0016): half a second
/// already takes 1000 s to slew out, and the discipline steps anything larger.
///
/// # Errors
///
/// When the kernel refuses: no `CAP_SYS_TIME`.
pub fn adjtimex_slew(ns: i64) -> std::io::Result<()> {
    // SAFETY: as in `adjtimex_step`.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = libc::ADJ_OFFSET_SINGLESHOT;
    tx.offset = libc::c_long::try_from((ns / 1000).clamp(-500_000, 500_000))
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    adjtimex(&mut tx)
}

/// `adjtimex(2)` with `ADJ_STATUS | ADJ_MAXERROR | ADJ_ESTERROR`: tell the kernel whether the
/// clock is synchronised. The status word is read first (modes 0) and written back with only
/// `STA_UNSYNC` changed. `maxerror` and `esterror` are reset too: the kernel grows `maxerror` by
/// 500 µs every second and raises `STA_UNSYNC` itself once it passes 16 s, so a sync every
/// 17 minutes keeps the flag clear only if each one resets the error. While the flag is clear the
/// kernel writes the system time to the RTC every eleven minutes (`CONFIG_RTC_SYSTOHC`).
///
/// # Errors
///
/// When the kernel refuses: no `CAP_SYS_TIME`.
pub fn adjtimex_status(synced: bool) -> std::io::Result<()> {
    // SAFETY: as in `adjtimex_step`.
    let mut current: libc::timex = unsafe { std::mem::zeroed() };
    adjtimex(&mut current)?;
    // SAFETY: as in `adjtimex_step`.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = libc::ADJ_STATUS | libc::ADJ_MAXERROR | libc::ADJ_ESTERROR;
    tx.status = if synced {
        current.status & !libc::STA_UNSYNC
    } else {
        current.status | libc::STA_UNSYNC
    };
    // Microseconds: half a second of error after a sync, the kernel's own ceiling after a loss.
    let error_us = if synced { 500_000 } else { 16_000_000 };
    tx.maxerror = error_us;
    tx.esterror = error_us;
    adjtimex(&mut tx)
}

fn adjtimex(tx: &mut libc::timex) -> std::io::Result<()> {
    // SAFETY: `tx` is a valid, writable `timex` for the duration of the call; the kernel reads
    // the fields its modes name and writes the rest back.
    if unsafe { libc::adjtimex(std::ptr::from_mut(tx)) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `PX_PROTO_OE`: the PPPoE protocol of an `AF_PPPOX` socket (`linux/if_pppox.h`).
const PX_PROTO_OE: libc::c_int = 0;

/// `IFNAMSIZ`: the device name field of `pppoe_addr`, its NUL included.
const IFNAMSIZ: usize = 16;

/// `sizeof(struct sockaddr_pppox)` for PPPoE: `sa_family` (2), `sa_protocol` (4), `sid` (2),
/// `remote` (6), `dev` (16); the struct is packed.
const SOCKADDR_PPPOX_LEN: usize = 30;

/// The PPP ioctls' type byte, `'t'` (`linux/ppp-ioctl.h`).
const PPP_IOC_TYPE: u32 = 0x74;
/// `_IOC_WRITE` and `_IOC_READ` (`asm-generic/ioctl.h`).
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
/// `sizeof(int)`, the argument of every PPP ioctl used here.
const INT_SIZE: u32 = 4;

/// `_IOC(dir, type, nr, size)` as `asm-generic/ioctl.h` lays it out on every target this project
/// builds for: nr in bits 0..8, type in 8..16, size in 16..30, direction in 30..32.
const fn ioc(dir: u32, kind: u32, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | (kind << 8) | nr
}

/// `PPPIOCNEWUNIT`, `_IOWR('t', 62, int)`: make a unit, the number in and out.
pub(crate) const PPPIOCNEWUNIT: u32 = ioc(IOC_READ | IOC_WRITE, PPP_IOC_TYPE, 62, INT_SIZE);
/// `PPPIOCGCHAN`, `_IOR('t', 55, int)`: an `AF_PPPOX` socket's channel index.
pub(crate) const PPPIOCGCHAN: u32 = ioc(IOC_READ, PPP_IOC_TYPE, 55, INT_SIZE);
/// `PPPIOCATTCHAN`, `_IOW('t', 56, int)`: attach a `/dev/ppp` descriptor to a channel.
pub(crate) const PPPIOCATTCHAN: u32 = ioc(IOC_WRITE, PPP_IOC_TYPE, 56, INT_SIZE);
/// `PPPIOCCONNECT`, `_IOW('t', 58, int)`: connect a channel to a unit.
pub(crate) const PPPIOCCONNECT: u32 = ioc(IOC_WRITE, PPP_IOC_TYPE, 58, INT_SIZE);
/// `PPPIOCSMRU`, `_IOW('t', 82, int)`: a unit's maximum receive unit.
pub(crate) const PPPIOCSMRU: u32 = ioc(IOC_WRITE, PPP_IOC_TYPE, 82, INT_SIZE);

/// The raw ioctl functions nix generates from the numbers above; each is called from one safe
/// function below and nowhere else.
mod ioctl {
    nix::ioctl_readwrite_bad!(new_unit, super::PPPIOCNEWUNIT, libc::c_int);
    nix::ioctl_read_bad!(channel_index, super::PPPIOCGCHAN, libc::c_int);
    nix::ioctl_write_ptr_bad!(attach_channel, super::PPPIOCATTCHAN, libc::c_int);
    nix::ioctl_write_ptr_bad!(connect_unit, super::PPPIOCCONNECT, libc::c_int);
    nix::ioctl_write_ptr_bad!(set_mru, super::PPPIOCSMRU, libc::c_int);
}

/// `socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(protocol))` for an
/// Ethernet `protocol` nix does not name (PPPoE discovery): the kernel delivers that protocol's
/// frames with the Ethernet header stripped and the source address in the `sockaddr_ll`.
///
/// # Errors
///
/// When the kernel refuses (no `CAP_NET_RAW`).
pub fn packet_socket(protocol: u16) -> io::Result<OwnedFd> {
    // SAFETY: socket(2) takes three integers and returns a descriptor or -1.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::c_int::from(protocol.to_be()),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned open by the kernel and nothing else owns or closes it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `socket(AF_PPPOX, SOCK_STREAM | SOCK_CLOEXEC, PX_PROTO_OE)`: the PPPoE session socket. No
/// data of ours crosses it (frames go through the `/dev/ppp` descriptors), so it stays blocking.
///
/// # Errors
///
/// When the kernel refuses: `EAFNOSUPPORT` without the `pppox` module, `EPROTONOSUPPORT`
/// without `pppoe`.
pub fn pppox_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) takes three integers and returns a descriptor or -1.
    let fd = unsafe {
        libc::socket(
            libc::AF_PPPOX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            PX_PROTO_OE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned open by the kernel and nothing else owns or closes it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A `sockaddr_pppox` as the kernel reads it (`linux/if_pppox.h`, packed): `AF_PPPOX`,
/// `PX_PROTO_OE`, the session id in network order, the access concentrator's MAC and the port's
/// name NUL-padded to `IFNAMSIZ`. `None` when the name does not fit with its NUL.
pub(crate) fn pppox_address_bytes(
    session_id: u16,
    ac_mac: [u8; 6],
    dev: &str,
) -> Option<[u8; SOCKADDR_PPPOX_LEN]> {
    if dev.is_empty() || dev.len() >= IFNAMSIZ {
        return None;
    }
    let mut bytes = [0u8; SOCKADDR_PPPOX_LEN];
    bytes[..2].copy_from_slice(&u16::try_from(libc::AF_PPPOX).ok()?.to_ne_bytes());
    bytes[2..6].copy_from_slice(&u32::try_from(PX_PROTO_OE).ok()?.to_ne_bytes());
    bytes[6..8].copy_from_slice(&session_id.to_be_bytes());
    bytes[8..14].copy_from_slice(&ac_mac);
    bytes[14..14 + dev.len()].copy_from_slice(dev.as_bytes());
    Some(bytes)
}

/// The address bytes at the alignment `sockaddr` wants.
#[repr(C, align(4))]
struct PppoxAddress([u8; SOCKADDR_PPPOX_LEN]);

/// `connect(2)` the PPPoE socket to session `session_id` with `ac_mac` on the port `dev`: from
/// then on the kernel owns the session's frames (`ETH_P_PPP_SES`) on that port.
///
/// # Errors
///
/// When the name does not fit `IFNAMSIZ`, or the kernel refuses (`ENODEV` for a port it does
/// not know, `EBUSY` for a session already connected).
pub fn pppoe_connect(
    fd: BorrowedFd<'_>,
    session_id: u16,
    ac_mac: [u8; 6],
    dev: &str,
) -> io::Result<()> {
    let address = PppoxAddress(pppox_address_bytes(session_id, ac_mac, dev).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("port name {dev:?} does not fit IFNAMSIZ"),
        )
    })?);
    let len = libc::socklen_t::try_from(SOCKADDR_PPPOX_LEN)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `address` is the packed `sockaddr_pppox` the kernel expects for `AF_PPPOX`, `len`
    // is exactly its size, and it lives for the whole call; the kernel copies the bytes and
    // keeps no pointer to them.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
            len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `PPPIOCNEWUNIT` on a fresh `/dev/ppp` descriptor: the kernel makes a unit with any free
/// number, names its netdev `ppp<N>` and attaches the descriptor to it; `N`.
///
/// # Errors
///
/// When the kernel refuses (`ENOTTY` on a descriptor that is not `/dev/ppp`).
pub fn ppp_new_unit(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut unit: libc::c_int = -1;
    // SAFETY: `fd` is an open descriptor and `unit` is a live `c_int` the kernel reads (the
    // number asked for, -1 for any) and writes (the number given) within the call.
    unsafe { ioctl::new_unit(fd.as_raw_fd(), &raw mut unit) }.map_err(io::Error::from)?;
    u32::try_from(unit)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("unit number {unit}")))
}

/// `PPPIOCGCHAN` on a connected PPPoE socket: the kernel's index of its channel.
///
/// # Errors
///
/// When the kernel refuses (`ENOTCONN` before `connect`).
pub fn ppp_channel_index(fd: BorrowedFd<'_>) -> io::Result<libc::c_int> {
    let mut index: libc::c_int = 0;
    // SAFETY: `fd` is an open descriptor and `index` is a live `c_int` the kernel writes
    // within the call.
    unsafe { ioctl::channel_index(fd.as_raw_fd(), &raw mut index) }.map_err(io::Error::from)?;
    Ok(index)
}

/// `PPPIOCATTCHAN(index)` on a fresh `/dev/ppp` descriptor: it becomes the channel's, where the
/// link-layer control frames (protocols `0xc000` and above) are read and written.
///
/// # Errors
///
/// When the kernel refuses (`ENXIO` for an index that is not a channel).
pub fn ppp_attach_channel(fd: BorrowedFd<'_>, index: libc::c_int) -> io::Result<()> {
    // SAFETY: `fd` is an open descriptor and `index` lives for the whole call; the kernel reads
    // it and keeps no pointer.
    unsafe { ioctl::attach_channel(fd.as_raw_fd(), &raw const index) }
        .map(drop)
        .map_err(io::Error::from)
}

/// `PPPIOCCONNECT(unit)` on a channel descriptor: the channel's frames feed unit `unit`, and the
/// unit's network frames go out through it.
///
/// # Errors
///
/// When the kernel refuses (`ENXIO` for a unit that does not exist, `EALREADY` when connected).
pub fn ppp_connect_unit(fd: BorrowedFd<'_>, unit: u32) -> io::Result<()> {
    let unit = libc::c_int::try_from(unit)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("unit {unit}")))?;
    // SAFETY: `fd` is an open descriptor and `unit` lives for the whole call; the kernel reads
    // it and keeps no pointer.
    unsafe { ioctl::connect_unit(fd.as_raw_fd(), &raw const unit) }
        .map(drop)
        .map_err(io::Error::from)
}

/// `PPPIOCSMRU(mru)` on the unit descriptor: the largest frame the unit accepts.
///
/// # Errors
///
/// When the kernel refuses.
pub fn ppp_set_mru(fd: BorrowedFd<'_>, mru: u16) -> io::Result<()> {
    let mru = libc::c_int::from(mru);
    // SAFETY: `fd` is an open descriptor and `mru` lives for the whole call; the kernel reads it
    // and keeps no pointer.
    unsafe { ioctl::set_mru(fd.as_raw_fd(), &raw const mru) }
        .map(drop)
        .map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_addr_carries_interface_protocol_and_destination() {
        let bound = link_addr(7, 0x0800, None).unwrap();
        assert_eq!(bound.ifindex(), 7);
        assert_eq!(bound.protocol(), 0x0800u16.to_be());
        assert_eq!(bound.halen(), 0, "no destination for bind");

        let dest = link_addr(7, 0x0800, Some([0xff; 6])).unwrap();
        assert_eq!(dest.addr(), Some([0xff; 6]));
        assert_eq!(dest.halen(), 6);
    }
}

#[cfg(test)]
mod icmp6_tests {
    use super::*;

    #[test]
    fn icmp6_filter_bitmap_blocks_everything_but_the_passed_types() {
        let words = icmp6_filter_words(&[134]);
        assert_eq!(words[4], !(1u32 << 6), "134 = 4 * 32 + 6");
        for (i, word) in words.iter().enumerate() {
            if i != 4 {
                assert_eq!(*word, u32::MAX, "word {i} blocks all");
            }
        }
        let words = icmp6_filter_words(&[133, 134]);
        assert_eq!(words[4], !(1u32 << 5 | 1u32 << 6));
        assert_eq!(icmp6_filter_words(&[]), [u32::MAX; 8], "nothing passes");
        assert_eq!(icmp6_filter_words(&[0])[0], !1u32);
        assert_eq!(icmp6_filter_words(&[255])[7], !(1u32 << 31));
    }
}

#[cfg(test)]
mod ppp_tests {
    use super::*;

    /// `_IOC(dir, type, nr, size)` as `asm-generic/ioctl.h` lays it out (the layout musl's
    /// `x86_64` and `aarch64` share): nr in bits 0..8, type in 8..16, size in 16..30, direction in
    /// 30..32 with write 1 and read 2.
    fn ioc(dir: u32, kind: u8, nr: u32, size: u32) -> u32 {
        (dir << 30) | (size << 16) | (u32::from(kind) << 8) | nr
    }

    /// The request code a `#define NAME _IOxx('t', nr, int)` line of `linux/ppp-ioctl.h`
    /// names, parsed from the header's text.
    fn header_code(header: &str, name: &str) -> u32 {
        let line = header
            .lines()
            .find(|line| {
                let mut words = line.split_whitespace();
                words.next() == Some("#define") && words.next() == Some(name)
            })
            .unwrap_or_else(|| panic!("{name} is not defined in ppp-ioctl.h"));
        let macro_call = line
            .split_whitespace()
            .skip(2)
            .collect::<Vec<_>>()
            .join(" ");
        let (kind_name, args) = macro_call
            .split_once('(')
            .unwrap_or_else(|| panic!("{name}: no macro call in {line:?}"));
        let dir = match kind_name {
            "_IO" => 0,
            "_IOW" => 1,
            "_IOR" => 2,
            "_IOWR" => 3,
            other => panic!("{name}: unknown macro {other}"),
        };
        let args: Vec<&str> = args
            .split(')')
            .next()
            .unwrap()
            .split(',')
            .map(str::trim)
            .collect();
        assert_eq!(args[0], "'t'", "{name}: the type is 't'");
        let nr: u32 = args[1].parse().unwrap();
        let size = match args.get(2) {
            Some(&"int") => 4,
            None => 0,
            Some(other) => panic!("{name}: unexpected size type {other}"),
        };
        ioc(dir, b't', nr, size)
    }

    /// The numbers `sys.rs` hands to `ioctl(2)` are the ones the pinned UAPI header defines
    /// (ADR-0012): parsed from `linux/ppp-ioctl.h`, never trusted from memory.
    #[test]
    fn ppp_ioctl_numbers_match_the_pinned_uapi_headers() {
        let include = std::env::var("OPENFEO_UAPI_INCLUDE")
            .expect("OPENFEO_UAPI_INCLUDE is set by make (kernel UAPI headers, ADR-0012)");
        let header = std::fs::read_to_string(format!("{include}/linux/ppp-ioctl.h"))
            .expect("linux/ppp-ioctl.h under OPENFEO_UAPI_INCLUDE");
        for (name, ours) in [
            ("PPPIOCNEWUNIT", PPPIOCNEWUNIT),
            ("PPPIOCGCHAN", PPPIOCGCHAN),
            ("PPPIOCATTCHAN", PPPIOCATTCHAN),
            ("PPPIOCCONNECT", PPPIOCCONNECT),
            ("PPPIOCSMRU", PPPIOCSMRU),
        ] {
            assert_eq!(
                u64::from(header_code(&header, name)),
                u64::from(ours),
                "{name}"
            );
        }
    }

    /// `sockaddr_pppox` is packed: 2 + 4 + (2 + 6 + 16) = 30 bytes, the session id in network
    /// order right after the protocol, the device name NUL-padded (`linux/if_pppox.h`).
    #[test]
    fn the_pppox_address_is_laid_out_as_the_kernel_reads_it() {
        let bytes = pppox_address_bytes(0x1234, [0x02, 0, 0, 0, 0, 0x42], "p0").unwrap();
        assert_eq!(bytes.len(), 30);
        assert_eq!(&bytes[..2], &24u16.to_ne_bytes(), "AF_PPPOX");
        assert_eq!(&bytes[2..6], &0u32.to_ne_bytes(), "PX_PROTO_OE");
        assert_eq!(
            &bytes[6..8],
            &[0x12, 0x34],
            "the session id in network order"
        );
        assert_eq!(&bytes[8..14], &[0x02, 0, 0, 0, 0, 0x42]);
        assert_eq!(&bytes[14..16], b"p0");
        assert!(bytes[16..].iter().all(|b| *b == 0));
        assert!(
            pppox_address_bytes(1, [0; 6], "a-name-of-sixteen").is_none(),
            "a name that does not fit IFNAMSIZ with its NUL is refused"
        );
    }
}
