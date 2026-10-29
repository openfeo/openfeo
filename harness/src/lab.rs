// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The lab: two ISP namespaces and one LAN namespace, each with a tap that becomes a router port
//! (`p0` = WAN A, `p1` = WAN B, `p2` = LAN; SPEC §11).

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use crate::netns::NetNs;

/// ISP A's side of the WAN A link (TEST-NET-3).
pub const ISP0_ADDR: &str = "203.0.113.1/24";
/// ISP B's side of the WAN B link (TEST-NET-2).
pub const ISP1_ADDR: &str = "198.51.100.1/24";
/// The router's port MACs, in port order.
pub const MACS: [&str; 3] = [
    "52:54:00:fe:00:00",
    "52:54:00:fe:00:01",
    "52:54:00:fe:00:02",
];
/// How long a boot may take before a scenario gives up (TCG is slow).
pub const BOOT_TIMEOUT: Duration = Duration::from_secs(90);
/// Per-lab scratch directories live under here on the sandbox's private `/run`.
pub const RUN_ROOT: &str = "/run/openfeo-harness";

/// One lab: namespaces, taps, and (from Task 8) the VM.
#[derive(Debug)]
pub struct Lab {
    /// Scratch directory for configs and logs.
    pub run_dir: PathBuf,
    name: String,
    /// Port taps in port order: wan0 (isp0), wan1 (isp1), lan0 (lan0). Dropped before the
    /// namespaces so the namespaces can go.
    taps: Vec<OwnedFd>,
    /// ISP A.
    pub isp0: NetNs,
    /// ISP B.
    pub isp1: NetNs,
    /// The LAN side.
    pub lan0: NetNs,
}

impl Lab {
    /// Create namespaces `<name>-isp0`, `<name>-isp1`, `<name>-lan0` with their taps.
    ///
    /// # Errors
    ///
    /// When a namespace or tap cannot be created.
    pub fn new(name: &str) -> Result<Self> {
        let isp0 = NetNs::create(&format!("{name}-isp0"))?;
        let isp1 = NetNs::create(&format!("{name}-isp1"))?;
        let lan0 = NetNs::create(&format!("{name}-lan0"))?;
        let taps = vec![
            isp0.add_tap("wan0", Some(ISP0_ADDR))?,
            isp1.add_tap("wan1", Some(ISP1_ADDR))?,
            lan0.add_tap("lan0", None)?,
        ];
        let run_dir = Path::new(RUN_ROOT).join(name);
        std::fs::create_dir_all(&run_dir)
            .with_context(|| format!("mkdir {}", run_dir.display()))?;
        Ok(Self {
            run_dir,
            name: name.to_owned(),
            taps,
            isp0,
            isp1,
            lan0,
        })
    }

    /// The lab's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The port taps in port order.
    #[must_use]
    pub fn taps(&self) -> &[OwnedFd] {
        &self.taps
    }

    /// `$OPENFEO_KERNEL`, or `<workspace>/build/bzImage`.
    ///
    /// # Errors
    ///
    /// When the image does not exist.
    pub fn kernel_path() -> Result<PathBuf> {
        let path = std::env::var_os("OPENFEO_KERNEL")
            .map_or_else(|| workspace_root().join("build/bzImage"), PathBuf::from);
        ensure!(
            path.is_file(),
            "kernel image not found at {}; run `make kernel` first",
            path.display()
        );
        Ok(path)
    }
}

/// The repository root (the harness crate's parent directory).
#[must_use]
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
