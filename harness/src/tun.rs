// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Open an existing tap device that lives in another network namespace and hand back its fd.
//! A tap fd stays bound to the namespace the device lives in, so QEMU can use it from the
//! sandbox's own namespace. The only `unsafe` in the harness is the `TUNSETIFF` ioctl here.

#![allow(unsafe_code)]

use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use nix::sched::{CloneFlags, setns};

/// Attach to `ifname` inside the namespace at `ns_path` on a scoped thread (so this thread's
/// namespace is untouched) and return the descriptor.
///
/// # Errors
///
/// When the namespace or `/dev/net/tun` cannot be opened, or `TUNSETIFF` refuses the name.
pub fn open_in_netns(ns_path: &Path, ifname: &str) -> Result<OwnedFd> {
    let ns = File::open(ns_path).with_context(|| format!("open {}", ns_path.display()))?;
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> Result<OwnedFd> {
                setns(&ns, CloneFlags::CLONE_NEWNET).context("setns")?;
                let tun = File::options()
                    .read(true)
                    .write(true)
                    .open("/dev/net/tun")
                    .context("open /dev/net/tun")?;
                // SAFETY: ifreq is plain data for which all-zero is valid.
                let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
                let name = ifname.as_bytes();
                ensure!(
                    name.len() < ifr.ifr_name.len(),
                    "interface name too long: {ifname}"
                );
                for (dst, src) in ifr.ifr_name.iter_mut().zip(name) {
                    *dst = libc::c_char::from_ne_bytes([*src]);
                }
                ifr.ifr_ifru.ifru_flags =
                    libc::c_short::try_from(libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR)
                        .context("tap flags")?;
                // SAFETY: TUNSETIFF reads the ifreq we own; the pointer is valid for the call.
                let rc = unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF, &raw const ifr) };
                ensure!(
                    rc == 0,
                    "TUNSETIFF {ifname}: {}",
                    std::io::Error::last_os_error()
                );
                Ok(OwnedFd::from(tun))
            })
            .join()
            .map_err(|_| anyhow::anyhow!("tap thread panicked"))?
    })
}
