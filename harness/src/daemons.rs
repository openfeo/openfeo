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

/// Kea's DHCPv4 config: 60 s leases renewing at 20 s and rebinding at 40 s, with routers, DNS,
/// domain, MTU, NTP and classless static routes. Option 121 is given by code as RFC 3442 bytes
/// (`00 CB007101` = 0.0.0.0/0 via 203.0.113.1, `18 C63364 CB007101` = 198.51.100.0/24 via
/// 203.0.113.1) because Kea 2.4.1 (Ubuntu 24.04, CI) has no definition for
/// `classless-static-route` and Kea 3.x refuses a user definition of it; the bytes work on both.
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

/// A static HTTP target in `ns`: `python3 -m http.server <port>` bound to `bind`, serving `dir`
/// whose `index.html` is `body`. Its log shows one line per request, with the client address
/// the server saw (`203.0.113.10 - - [...] "GET / HTTP/1.0" 200 -`), which is how scenarios
/// prove NAT and hairpin SNAT happened. Unbuffered, so `Serving HTTP on` appears at once.
///
/// # Errors
///
/// When `index.html` cannot be written or python3 cannot be spawned.
pub fn http_server(ns: &NetNs, bind: &str, port: u16, dir: &Path, body: &str) -> Result<Daemon> {
    std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let index = dir.join("index.html");
    std::fs::write(&index, body).with_context(|| format!("write {}", index.display()))?;
    let mut cmd = ns.command("python3")?;
    cmd.args([
        "-u",
        "-m",
        "http.server",
        &port.to_string(),
        "--bind",
        bind,
        "--directory",
    ])
    .arg(dir);
    Daemon::spawn(&format!("http-{}-{port}", ns.name), cmd)
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

    /// Ubuntu 24.04's Kea 2.4.1 (CI) has no definition for option 121 and refuses the option by
    /// name, while Kea 3.x refuses a user definition of it; every Kea accepts it by code as the
    /// RFC 3442 bytes.
    #[test]
    fn template_sends_classless_routes_by_code_as_rfc3442_bytes() {
        let rendered: serde_json::Value =
            serde_json::from_str(&render_kea_dhcp4("wan0")).expect("strict JSON");
        let options = rendered["Dhcp4"]["subnet4"][0]["option-data"]
            .as_array()
            .expect("option-data");
        assert!(
            options
                .iter()
                .all(|o| o["name"] != "classless-static-route"),
            "option 121 must be given by code, Kea 2.4.1 has no definition for it"
        );
        let route_option = options
            .iter()
            .find(|o| o["code"] == 121)
            .expect("option 121 by code");
        assert_eq!(route_option["csv-format"], false);
        let data = route_option["data"].as_str().expect("hex data");
        let bytes: Vec<u8> = (0..data.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&data[i..i + 2], 16).expect("hex"))
            .collect();
        // 0.0.0.0/0 via 203.0.113.1, then 198.51.100.0/24 via 203.0.113.1 (RFC 3442 §5).
        assert_eq!(bytes, [0, 203, 0, 113, 1, 24, 198, 51, 100, 203, 0, 113, 1]);
    }
}
