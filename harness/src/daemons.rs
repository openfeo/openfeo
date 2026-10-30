// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Reference daemons on the ISP side (SPEC §11): started inside a namespace, their output
//! captured, killed when the lab goes.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use crate::lines::Lines;
use crate::netns::NetNs;
use crate::qemu::VERBOSE_ENV;

const KEA_DHCP4_TEMPLATE: &str = include_str!("../fixtures/kea-dhcp4.json.tmpl");
/// Time a daemon gets to leave after SIGTERM before SIGKILL.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// A daemon running in a lab namespace; SIGTERM then SIGKILL on drop.
#[derive(Debug)]
pub struct Daemon {
    /// For log prefixes and diagnostics.
    pub name: String,
    child: Child,
    /// stdout and stderr, merged.
    pub log: Lines,
}

impl Daemon {
    /// Spawn `cmd` (built with [`NetNs::command`] so it lands in the right namespace) with its
    /// stdout and stderr merged into one captured log.
    ///
    /// # Errors
    ///
    /// When the program cannot be spawned.
    pub fn spawn(name: &str, mut cmd: Command) -> Result<Self> {
        let (reader, writer) = std::io::pipe().context("pipe")?;
        cmd.stdin(Stdio::null())
            .stdout(Stdio::from(writer.try_clone().context("dup pipe")?))
            .stderr(Stdio::from(writer));
        let child = cmd.spawn().with_context(|| format!("spawn {name}"))?;
        let verbose = std::env::var_os(VERBOSE_ENV).is_some();
        let log = Lines::capture(reader, verbose.then(|| format!("[{name}]")));
        Ok(Self {
            name: name.to_owned(),
            child,
            log,
        })
    }

    /// Still alive?
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Ok(pid) = i32::try_from(self.child.id()) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
        }
        let deadline = Instant::now() + STOP_GRACE;
        while Instant::now() < deadline {
            if !self.is_running() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The Kea DHCPv4 config for one ISP interface.
#[must_use]
pub fn render_kea_dhcp4(iface: &str) -> String {
    KEA_DHCP4_TEMPLATE.replace("{{IFACE}}", iface)
}

/// Kea DHCPv4 serving `203.0.113.100-200` on `iface` inside `ns`; config, lock and pid files go
/// under `run_dir`.
///
/// # Errors
///
/// When the config cannot be written or `kea-dhcp4` cannot be spawned.
pub fn kea_dhcp4(ns: &NetNs, iface: &str, run_dir: &Path) -> Result<Daemon> {
    let config = run_dir.join("kea-dhcp4.json");
    std::fs::write(&config, render_kea_dhcp4(iface))
        .with_context(|| format!("write {}", config.display()))?;
    let mut cmd = ns.command("kea-dhcp4")?;
    cmd.arg("-c")
        .arg(&config)
        .env("KEA_LOCKFILE_DIR", run_dir)
        .env("KEA_PIDFILE_DIR", run_dir);
    Daemon::spawn("kea-dhcp4", cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_renders_iface() {
        let rendered = render_kea_dhcp4("wan0");
        assert!(
            rendered.contains("\"interfaces\": [ \"wan0\" ]"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("{{"),
            "unreplaced placeholder in {rendered}"
        );
    }
}
