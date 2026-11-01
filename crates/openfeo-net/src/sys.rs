// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The one unsafe module of this crate (ADR-0013): addresses for `AF_PACKET` sockets, and the
//! registration of an owned descriptor with tokio. nix offers no safe way to build a
//! `sockaddr_ll`, and a packet socket not bound to its interface would copy every IPv4 frame of
//! every port to userspace; tokio makes the caller vouch that a registered descriptor stays
//! open, which an `OwnedFd` guarantees.

use std::mem::size_of;
use std::os::fd::OwnedFd;

use nix::sys::socket::{LinkAddr, SockaddrLike};
use tokio::io::unix::AsyncFd;

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
