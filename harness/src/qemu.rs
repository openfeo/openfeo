// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Boot the router kernel in QEMU: q35, KVM when available, an i6300esb watchdog that resets the
//! machine, virtio-rng, and one virtio-net port per tap handed to us as an inherited fd.

#![allow(unsafe_code)] // Command::pre_exec; the closure only calls fcntl(2) and dup2(2)

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};

use anyhow::{Context, Result};

use crate::lines::Lines;

/// The VM's kernel command line (SPEC §4.2 for a VM: no `console=tty0`, mode `vm`).
pub const BASE_CMDLINE: &str = "console=ttyS0,115200 openfeo.mode=vm panic=10 printk.devkmsg=on";
/// The first port's tap arrives in QEMU as this descriptor; port `i` is `FIRST_NIC_FD + i`.
pub const FIRST_NIC_FD: usize = 3;
/// Set this in the environment to stream the console and daemon logs to stderr while running.
pub const VERBOSE_ENV: &str = "OPENFEO_HARNESS_VERBOSE";

/// One router port.
#[derive(Debug)]
pub struct Nic {
    /// QEMU netdev id.
    pub id: String,
    /// The tap, already attached (`TUNSETIFF`) in its namespace.
    pub tap: OwnedFd,
    /// MAC address for the guest.
    pub mac: String,
}

/// Where the serial console goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleMode {
    /// Piped into a [`Lines`] for scenarios.
    Captured,
    /// The user's terminal, with the QEMU monitor on Ctrl-A (`make run`).
    Interactive,
}

/// Everything needed to start one VM.
#[derive(Debug)]
pub struct VmSpec {
    /// The bzImage.
    pub kernel: PathBuf,
    /// Full kernel command line.
    pub cmdline: String,
    /// Guest RAM.
    pub mem_mib: u32,
    /// Guest vCPUs.
    pub cpus: u32,
    /// Ports in order.
    pub nics: Vec<Nic>,
    /// Console wiring.
    pub console: ConsoleMode,
    /// A raw ext4 image attached as virtio-blk, PID 1's `/state` (ADR-0010).
    pub state_disk: Option<PathBuf>,
    /// Where QEMU listens for QMP (`server=on,wait=off`).
    pub qmp_socket: Option<PathBuf>,
}

/// `kvm` when `/dev/kvm` is usable, else `tcg`.
#[must_use]
pub fn accel() -> &'static str {
    if File::options()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
    {
        "kvm"
    } else {
        "tcg"
    }
}

/// The QEMU argument list for `spec`.
#[must_use]
pub fn build_args(spec: &VmSpec) -> Vec<OsString> {
    let accel = accel();
    let mut args: Vec<OsString> = Vec::new();
    let mut push = |items: &[&str]| args.extend(items.iter().map(OsString::from));
    push(&[
        "-nodefaults",
        "-display",
        "none",
        "-machine",
        &format!("q35,accel={accel}"),
        "-cpu",
        if accel == "kvm" { "host" } else { "max" },
        "-smp",
        &spec.cpus.to_string(),
        "-m",
        &format!("{}M", spec.mem_mib),
        "-kernel",
    ]);
    args.push(spec.kernel.clone().into_os_string());
    let mut push = |items: &[&str]| args.extend(items.iter().map(OsString::from));
    push(&["-append", &spec.cmdline]);
    match spec.console {
        ConsoleMode::Captured => push(&["-serial", "stdio", "-monitor", "none"]),
        ConsoleMode::Interactive => push(&["-serial", "mon:stdio"]),
    }
    push(&[
        "-device",
        "i6300esb",
        "-action",
        "watchdog=reset",
        "-device",
        "virtio-rng-pci",
    ]);
    for (i, nic) in spec.nics.iter().enumerate() {
        push(&[
            "-netdev",
            &format!("tap,id={},fd={}", nic.id, FIRST_NIC_FD + i),
            "-device",
            &format!("virtio-net-pci,netdev={},mac={}", nic.id, nic.mac),
        ]);
    }
    if let Some(disk) = &spec.state_disk {
        push(&[
            "-drive",
            &format!("file={},if=virtio,format=raw,cache=unsafe", disk.display()),
        ]);
    }
    if let Some(socket) = &spec.qmp_socket {
        push(&[
            "-qmp",
            &format!("unix:{},server=on,wait=off", socket.display()),
        ]);
    }
    args
}

/// A running QEMU, killed on drop.
#[derive(Debug)]
pub struct Vm {
    child: Child,
    /// The serial console (`Captured` only).
    pub console: Option<Lines>,
    /// QEMU's own stderr (`Captured` only).
    pub qemu_errors: Option<Lines>,
}

impl Vm {
    /// Spawn QEMU with the taps installed at [`FIRST_NIC_FD`]… in the child.
    ///
    /// # Errors
    ///
    /// When QEMU cannot be spawned.
    pub fn start(spec: &VmSpec) -> Result<Self> {
        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.args(build_args(spec));
        let taps: Vec<RawFd> = spec.nics.iter().map(|n| n.tap.as_raw_fd()).collect();
        let mut staged = vec![0 as RawFd; taps.len()];
        // SAFETY: the closure runs in the forked child before exec and only calls fcntl(2) and
        // dup2(2) on descriptors opened before the fork; `staged` was allocated before the fork.
        unsafe {
            cmd.pre_exec(move || {
                // Two phases so a tap that already sits at a target number is not clobbered.
                let above = libc::c_int::try_from(FIRST_NIC_FD + taps.len())
                    .map_err(|_| io::Error::other("too many ports"))?;
                for (slot, &fd) in staged.iter_mut().zip(&taps) {
                    *slot = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, above);
                    if *slot < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                for (i, &fd) in staged.iter().enumerate() {
                    let target = libc::c_int::try_from(FIRST_NIC_FD + i)
                        .map_err(|_| io::Error::other("too many ports"))?;
                    if libc::dup2(fd, target) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        match spec.console {
            ConsoleMode::Captured => cmd
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
            ConsoleMode::Interactive => cmd
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit()),
        };
        let mut child = cmd.spawn().context("spawn qemu-system-x86_64")?;
        let verbose = std::env::var_os(VERBOSE_ENV).is_some();
        let console = child
            .stdout
            .take()
            .map(|out| Lines::capture(out, verbose.then(|| "[vm]".to_owned())));
        let qemu_errors = child
            .stderr
            .take()
            .map(|err| Lines::capture(err, verbose.then(|| "[qemu]".to_owned())));
        Ok(Self {
            child,
            console,
            qemu_errors,
        })
    }

    /// Kill QEMU and reap it.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Wait for QEMU to exit on its own (interactive runs).
    ///
    /// # Errors
    ///
    /// When waiting fails.
    pub fn wait(&mut self) -> Result<ExitStatus> {
        Ok(self.child.wait()?)
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_include_watchdog_and_inherited_tap_fds() {
        let (a, _b) = std::io::pipe().unwrap();
        let (c, _d) = std::io::pipe().unwrap();
        let spec = VmSpec {
            kernel: "k".into(),
            cmdline: BASE_CMDLINE.into(),
            mem_mib: 128,
            cpus: 2,
            console: ConsoleMode::Captured,
            nics: vec![
                Nic {
                    id: "p0".into(),
                    tap: a.into(),
                    mac: "52:54:00:fe:00:00".into(),
                },
                Nic {
                    id: "p1".into(),
                    tap: c.into(),
                    mac: "52:54:00:fe:00:01".into(),
                },
            ],
            state_disk: None,
            qmp_socket: None,
        };
        let args: Vec<String> = build_args(&spec)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(args.windows(2).any(|w| w == ["-action", "watchdog=reset"]));
        assert!(args.contains(&"tap,id=p0,fd=3".to_string()));
        assert!(args.contains(&"tap,id=p1,fd=4".to_string()));
        assert!(args.contains(&"virtio-net-pci,netdev=p1,mac=52:54:00:fe:00:01".to_string()));
        assert!(args.windows(2).any(|w| w == ["-append", BASE_CMDLINE]));
        assert!(args.windows(2).any(|w| w == ["-serial", "stdio"]));
        assert!(!args.iter().any(|a| a == "-drive" || a == "-qmp"));
    }

    #[test]
    fn args_include_state_drive_and_qmp_socket() {
        let spec = VmSpec {
            kernel: "k".into(),
            cmdline: BASE_CMDLINE.into(),
            mem_mib: 128,
            cpus: 2,
            console: ConsoleMode::Captured,
            nics: vec![],
            state_disk: Some("/run/x/state.img".into()),
            qmp_socket: Some("/run/x/qmp.sock".into()),
        };
        let args: Vec<String> = build_args(&spec)
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(args.windows(2).any(|w| w
            == [
                "-drive",
                "file=/run/x/state.img,if=virtio,format=raw,cache=unsafe"
            ]));
        assert!(
            args.windows(2)
                .any(|w| w == ["-qmp", "unix:/run/x/qmp.sock,server=on,wait=off"])
        );
    }
}
