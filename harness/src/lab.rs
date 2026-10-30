// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The lab: two ISP namespaces and one LAN namespace, each with a tap that becomes a router port
//! (`p0` = WAN A, `p1` = WAN B, `p2` = LAN; SPEC §11).

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use crate::daemons::Daemon;
use crate::lines::Lines;
use crate::netns::NetNs;
use crate::qemu::{BASE_CMDLINE, ConsoleMode, Nic, Vm, VmSpec};
use crate::qmp::Qmp;
use crate::statedisk;

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

/// Guest RAM for the lab VM (SPEC §4.3: boots and routes in 64 MiB; twice that for headroom).
pub const VM_MEM_MIB: u32 = 128;
/// Guest vCPUs for the lab VM.
pub const VM_CPUS: u32 = 2;

/// One lab: namespaces, taps, and the VM once booted.
#[derive(Debug)]
pub struct Lab {
    /// Scratch directory for configs and logs.
    pub run_dir: PathBuf,
    name: String,
    /// An explicit kernel image, instead of [`Lab::kernel_path`].
    kernel: Option<PathBuf>,
    /// The `/state` image for the VM, when a scenario supplied one (ADR-0010).
    state_disk: Option<PathBuf>,
    /// The router VM, after [`Lab::boot`]. Declared first so it dies before its taps.
    pub vm: Option<Vm>,
    /// Reference daemons started by scenarios; stopped before the namespaces go.
    pub daemons: Vec<Daemon>,
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
            kernel: None,
            state_disk: None,
            vm: None,
            daemons: Vec::new(),
            taps,
            isp0,
            isp1,
            lan0,
        })
    }

    /// Boot the router with the lab's three taps as ports `p0..p2` and the console captured.
    /// `extra_cmdline` is appended to [`BASE_CMDLINE`].
    ///
    /// # Errors
    ///
    /// When already booted, the kernel image is missing, or QEMU cannot start.
    pub fn boot(&mut self, extra_cmdline: &str) -> Result<&Vm> {
        self.boot_with(extra_cmdline, ConsoleMode::Captured)
    }

    /// As [`Lab::boot`], with the console on the caller's terminal instead.
    ///
    /// # Errors
    ///
    /// As [`Lab::boot`].
    pub fn boot_interactive(&mut self, extra_cmdline: &str) -> Result<&mut Vm> {
        self.boot_with(extra_cmdline, ConsoleMode::Interactive)?;
        self.vm.as_mut().context("VM vanished after boot")
    }

    fn boot_with(&mut self, extra_cmdline: &str, console: ConsoleMode) -> Result<&Vm> {
        ensure!(self.vm.is_none(), "lab {} already has a VM", self.name);
        let nics = self
            .taps
            .iter()
            .zip(MACS)
            .enumerate()
            .map(|(i, (tap, mac))| {
                Ok(Nic {
                    id: format!("p{i}"),
                    tap: tap.try_clone().context("dup tap")?,
                    mac: mac.to_owned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let cmdline = if extra_cmdline.is_empty() {
            BASE_CMDLINE.to_owned()
        } else {
            format!("{BASE_CMDLINE} {extra_cmdline}")
        };
        let kernel = match &self.kernel {
            Some(path) => {
                ensure!(
                    path.is_file(),
                    "kernel image not found at {}",
                    path.display()
                );
                path.clone()
            }
            None => Self::kernel_path()?,
        };
        let vm = Vm::start(&VmSpec {
            kernel,
            cmdline,
            mem_mib: VM_MEM_MIB,
            cpus: VM_CPUS,
            nics,
            console,
            state_disk: self.state_disk.clone(),
            qmp_socket: Some(self.qmp_socket_path()),
        })?;
        Ok(self.vm.insert(vm))
    }

    /// Give the VM a `/state` disk holding `files` (`(relative path, contents)`), before boot.
    ///
    /// # Errors
    ///
    /// When already booted or the image cannot be built.
    pub fn with_state(&mut self, files: &[(&str, &[u8])]) -> Result<()> {
        ensure!(self.vm.is_none(), "state disk must be set before boot");
        let image = self.run_dir.join("state.img");
        statedisk::create(&image, files)?;
        self.state_disk = Some(image);
        Ok(())
    }

    /// Give the VM a `/state` disk holding just `config.toml`.
    ///
    /// # Errors
    ///
    /// As [`Lab::with_state`].
    pub fn with_config(&mut self, toml: &str) -> Result<()> {
        self.with_state(&[("config.toml", toml.as_bytes())])
    }

    /// A QMP session to the booted VM.
    ///
    /// # Errors
    ///
    /// When no VM is booted or QEMU's socket cannot be reached.
    pub fn qmp(&self) -> Result<Qmp> {
        ensure!(self.vm.is_some(), "no VM booted");
        Qmp::connect(&self.qmp_socket_path())
    }

    fn qmp_socket_path(&self) -> PathBuf {
        self.run_dir.join("qmp.sock")
    }

    /// The captured serial console of the booted VM.
    ///
    /// # Errors
    ///
    /// When no VM is booted, or it was booted interactively.
    pub fn console(&self) -> Result<&Lines> {
        self.vm
            .as_ref()
            .and_then(|vm| vm.console.as_ref())
            .context("no captured console: VM not booted, or booted interactively")
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

    /// Boot this image instead of the default.
    pub fn set_kernel(&mut self, path: PathBuf) {
        self.kernel = Some(path);
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
