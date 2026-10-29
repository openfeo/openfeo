// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Named network namespaces (`ip netns`) inside the sandbox, with tap devices for QEMU.

#![allow(unsafe_code)] // Command::pre_exec; the closure only calls setns(2)

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use nix::sched::{CloneFlags, setns};

/// Where `ip netns` keeps its handles (on the sandbox's private `/run`).
pub const NETNS_DIR: &str = "/run/netns";

/// A named network namespace, deleted on drop.
#[derive(Debug)]
pub struct NetNs {
    /// The `ip netns` name.
    pub name: String,
}

impl NetNs {
    /// `ip netns add`, with `lo` brought up.
    ///
    /// # Errors
    ///
    /// When `ip` fails (its stderr is in the error).
    pub fn create(name: &str) -> Result<Self> {
        ip(&["netns", "add", name])?;
        let ns = Self {
            name: name.to_owned(),
        };
        ns.ip(&["link", "set", "lo", "up"])?;
        Ok(ns)
    }

    /// The namespace handle `setns` can open.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        Path::new(NETNS_DIR).join(&self.name)
    }

    /// Run `ip -n <name> <args>` and return its stdout.
    ///
    /// # Errors
    ///
    /// When `ip` exits non-zero (its stderr is in the error).
    pub fn ip(&self, args: &[&str]) -> Result<String> {
        let mut cmd = Command::new("ip");
        cmd.args(["-n", &self.name]).args(args);
        run(&mut cmd)
    }

    /// A `Command` that will run `program` inside this namespace. The namespace fd is opened now,
    /// in the parent, so the child only has to call `setns` before `exec`.
    ///
    /// # Errors
    ///
    /// When the namespace handle cannot be opened.
    pub fn command(&self, program: &str) -> Result<Command> {
        let ns =
            File::open(self.path()).with_context(|| format!("open {}", self.path().display()))?;
        let mut cmd = Command::new(program);
        // SAFETY: the closure runs in the forked child before exec and does nothing but one
        // setns(2) on a descriptor opened before the fork: no allocation, no locks.
        unsafe {
            cmd.pre_exec(move || setns(&ns, CloneFlags::CLONE_NEWNET).map_err(io::Error::from));
        }
        Ok(cmd)
    }

    /// Create a tap device in this namespace, optionally address it, bring it up, and return a
    /// descriptor attached to it for QEMU.
    ///
    /// # Errors
    ///
    /// When `ip` or `TUNSETIFF` fails.
    pub fn add_tap(&self, ifname: &str, addr_cidr: Option<&str>) -> Result<OwnedFd> {
        self.ip(&["tuntap", "add", "dev", ifname, "mode", "tap", "vnet_hdr"])?;
        if let Some(addr) = addr_cidr {
            self.ip(&["addr", "add", addr, "dev", ifname])?;
        }
        self.ip(&["link", "set", ifname, "up"])?;
        crate::tun::open_in_netns(&self.path(), ifname)
    }
}

impl Drop for NetNs {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Run `ip <args>` in the sandbox's own namespace and return its stdout.
///
/// # Errors
///
/// When `ip` exits non-zero (its stderr is in the error).
pub fn ip(args: &[&str]) -> Result<String> {
    run(Command::new("ip").args(args))
}

/// Run a command to completion and return its stdout; a non-zero exit becomes an error carrying
/// the command line and its stderr.
///
/// # Errors
///
/// When the program cannot be spawned or exits non-zero.
pub fn run(cmd: &mut Command) -> Result<String> {
    let rendered = format!(
        "{} {}",
        cmd.get_program().to_string_lossy(),
        cmd.get_args()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("spawn `{rendered}`"))?;
    if !out.status.success() {
        bail!(
            "`{rendered}` exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
