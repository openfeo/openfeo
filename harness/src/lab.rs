// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The lab: two ISP namespaces and one LAN namespace, each with a tap that becomes a router port
//! (`p0` = WAN A, `p1` = WAN B, `p2` = LAN; SPEC §11).

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};

use crate::daemons::{self, Daemon};
use crate::lines::{Cursor, Lines, Regex};
use crate::netns::NetNs;
use crate::qemu::{BASE_CMDLINE, ConsoleMode, Nic, Vm, VmSpec};
use crate::qmp::Qmp;
use crate::statedisk;

/// ISP A's side of the WAN A link (TEST-NET-3).
pub const ISP0_ADDR: &str = "203.0.113.1/24";
/// ISP B's side of the WAN B link (TEST-NET-2).
pub const ISP1_ADDR: &str = "198.51.100.1/24";
/// The LAN host's address (the LAN namespace's end of the LAN tap) on the router's LAN subnet.
pub const LAN_HOST_ADDR: &str = "192.168.1.2/24";
/// The router's LAN address, the LAN host's gateway.
pub const LAN_GATEWAY: &str = "192.168.1.1";
/// The router's static WAN address, as `isp0` sees it.
pub const WAN_ADDR: &str = "203.0.113.10";
/// What the ISP-side HTTP target serves.
pub const ISP_HTTP_BODY: &str = "openfeo isp target";
/// What the LAN-side HTTP target serves.
pub const LAN_HTTP_BODY: &str = "openfeo lan target";
/// The router's port MACs, in port order (`p3` exists only for labs with a second LAN).
pub const MACS: [&str; 4] = [
    "52:54:00:fe:00:00",
    "52:54:00:fe:00:01",
    "52:54:00:fe:00:02",
    "52:54:00:fe:00:03",
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
    /// The guest's clock at power-on (`-rtc base=`), when a scenario set one.
    rtc_base: Option<String>,
    /// The router VM, after [`Lab::boot`]. Declared first so it dies before its taps.
    pub vm: Option<Vm>,
    /// Reference daemons started by scenarios; stopped before the namespaces go.
    pub daemons: Vec<Daemon>,
    /// Port taps in port order: wan0 (isp0), wan1 (isp1), lan0 (lan0) and, after
    /// [`Lab::add_lan1`], lan1 (lan1). Dropped before the namespaces so the namespaces can go.
    taps: Vec<OwnedFd>,
    /// ISP A.
    pub isp0: NetNs,
    /// ISP B.
    pub isp1: NetNs,
    /// The LAN side.
    pub lan0: NetNs,
    /// A second LAN side on the router's `p3`, for the scenarios that ask for two LANs
    /// (SPEC §11); `None` until [`Lab::add_lan1`].
    pub lan1: Option<NetNs>,
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
            rtc_base: None,
            vm: None,
            daemons: Vec::new(),
            taps,
            isp0,
            isp1,
            lan0,
            lan1: None,
        })
    }

    /// Add the second LAN namespace `<name>-lan1` with its tap, the router's `p3`, before boot.
    ///
    /// # Errors
    ///
    /// When already booted or already added, or when the namespace or tap cannot be created.
    pub fn add_lan1(&mut self) -> Result<()> {
        ensure!(self.vm.is_none(), "lan1 must be added before boot");
        ensure!(self.lan1.is_none(), "lan1 already added");
        let lan1 = NetNs::create(&format!("{}-lan1", self.name))?;
        self.taps.push(lan1.add_tap("lan1", None)?);
        self.lan1 = Some(lan1);
        Ok(())
    }

    /// Make the LAN namespace a LAN host: `lan0` up at [`LAN_HOST_ADDR`] with the router as its
    /// default gateway.
    ///
    /// # Errors
    ///
    /// When `ip` fails.
    pub fn lan_side_host(&self) -> Result<()> {
        Self::host(&self.lan0, "lan0", LAN_HOST_ADDR, LAN_GATEWAY)
    }

    /// Make `ns` a host on `ifname`: up, at `addr_cidr`, with `gateway` as its default route.
    ///
    /// # Errors
    ///
    /// When `ip` fails.
    pub fn host(ns: &NetNs, ifname: &str, addr_cidr: &str, gateway: &str) -> Result<()> {
        ns.ip(&["link", "set", ifname, "up"])?;
        ns.ip(&["addr", "replace", addr_cidr, "dev", ifname])?;
        ns.ip(&["route", "replace", "default", "via", gateway])?;
        Ok(())
    }

    /// A VLAN client: the 802.1Q sub-interface `<parent>.<vid>` of a tap in `base`, moved into a
    /// namespace of its own (`<name>-<ns>`) and brought up, so every client helper works on it
    /// unchanged. The sub-interface dies with the namespace.
    ///
    /// # Errors
    ///
    /// When `ip` fails (a kernel without `8021q` cannot create the sub-interface).
    pub fn vlan_host(&self, base: &NetNs, parent: &str, vid: u16, ns: &str) -> Result<NetNs> {
        let ifname = format!("{parent}.{vid}");
        let vid = vid.to_string();
        base.ip(&[
            "link", "add", "link", parent, "name", &ifname, "type", "vlan", "id", &vid,
        ])?;
        let host = NetNs::create(&format!("{}-{ns}", self.name))?;
        base.ip(&["link", "set", &ifname, "netns", &host.name])?;
        host.ip(&["link", "set", &ifname, "up"])?;
        Ok(host)
    }

    /// Move ISP A onto the tagged sub-interface `wan0.<vid>`: [`ISP0_ADDR`] leaves `wan0` for
    /// it, so Kea (which picks its subnet by the receiving interface's address) and the HTTP
    /// target serve a WAN that tags its traffic (SPEC §7.2). Returns the sub-interface's name.
    ///
    /// # Errors
    ///
    /// When `ip` fails.
    pub fn isp0_tagged(&mut self, vid: u16) -> Result<String> {
        let ifname = format!("wan0.{vid}");
        let vid = vid.to_string();
        self.isp0.ip(&[
            "link", "add", "link", "wan0", "name", &ifname, "type", "vlan", "id", &vid,
        ])?;
        self.isp0.ip(&["addr", "flush", "dev", "wan0"])?;
        self.isp0.ip(&["addr", "add", ISP0_ADDR, "dev", &ifname])?;
        self.isp0.ip(&["link", "set", &ifname, "up"])?;
        Ok(ifname)
    }

    /// Teach the ISP namespace that a public block is routed to the router's WAN address, as
    /// the ISP of a `[[public_ipv4]]` block does (SPEC §7.4).
    ///
    /// # Errors
    ///
    /// When `ip` fails.
    pub fn isp_route_block(&self, block: &str) -> Result<()> {
        self.isp0
            .ip(&["route", "replace", block, "via", WAN_ADDR])?;
        Ok(())
    }

    /// Start Kea on ISP A's `wan0`, serving `203.0.113.100-200` with the lab's short lifetimes
    /// and options (`harness/fixtures/kea-dhcp4.json.tmpl`); returns once it announces itself.
    /// The daemon joins [`Lab::daemons`], named `kea-dhcp4`.
    ///
    /// # Errors
    ///
    /// When Kea cannot be started or does not come up within 15 s.
    pub fn start_kea(&mut self) -> Result<()> {
        self.start_kea_on("wan0")
    }

    /// As [`Lab::start_kea`], on another interface of ISP A (a tagged `wan0.<vid>`).
    ///
    /// # Errors
    ///
    /// As [`Lab::start_kea`].
    pub fn start_kea_on(&mut self, iface: &str) -> Result<()> {
        let kea = daemons::kea_dhcp4(&self.isp0, iface, &self.run_dir)?;
        kea.log.wait_for(
            &mut Cursor::default(),
            &Regex::new("DHCP4_STARTED").context("regex")?,
            Duration::from_secs(15),
        )?;
        self.daemons.push(kea);
        Ok(())
    }

    /// Start dnsmasq on ISP A's `wan0` at 203.0.113.1 as the authoritative resolver for
    /// `isp.example` (`daemons::dnsmasq`); returns once it announces itself. The daemon joins
    /// [`Lab::daemons`], named `dnsmasq`.
    ///
    /// # Errors
    ///
    /// When dnsmasq cannot be started or does not come up within 10 s.
    pub fn start_dnsmasq(&mut self) -> Result<()> {
        let dnsmasq = daemons::dnsmasq(&self.isp0, "wan0", &self.run_dir)?;
        dnsmasq.log.wait_for(
            &mut Cursor::default(),
            &Regex::new("started, version").context("regex")?,
            Duration::from_secs(10),
        )?;
        self.daemons.push(dnsmasq);
        Ok(())
    }

    /// Start the lab's SNTP server on ISP A's `wan0` at 203.0.113.1, stratum 2, its clock
    /// `offset_secs` from the host's (`daemons::sntp_server`); returns once it announces itself.
    /// The daemon joins [`Lab::daemons`], named `sntp-203.0.113.1`.
    ///
    /// # Errors
    ///
    /// When the server cannot be started or does not come up within 10 s.
    pub fn start_sntp(&mut self, offset_secs: i64) -> Result<()> {
        let server = daemons::sntp_server(&self.isp0, "203.0.113.1", offset_secs, 2)?;
        server.log.wait_for(
            &mut Cursor::default(),
            &Regex::new("sntp-server listening on").context("regex")?,
            Duration::from_secs(10),
        )?;
        self.daemons.push(server);
        Ok(())
    }

    /// The guest's clock at power-on, as QEMU's `-rtc base=<iso>` (`2006-06-17T16:01:21`): a
    /// box whose RTC is wrong or missing. Set before [`Lab::boot`].
    pub fn set_rtc_base(&mut self, iso: &str) {
        self.rtc_base = Some(iso.to_owned());
    }

    /// Teach the ISP namespace the way to the LAN subnet through the router's WAN address, so
    /// an ISP-side host can try to reach LAN hosts directly (which the firewall must refuse).
    ///
    /// # Errors
    ///
    /// When `ip` fails.
    pub fn isp_route_to_lan(&self) -> Result<()> {
        self.isp0
            .ip(&["route", "replace", "192.168.1.0/24", "via", WAN_ADDR])?;
        Ok(())
    }

    /// Boot the router with the lab's taps as ports `p0..p2` (and `p3` after [`Lab::add_lan1`])
    /// and the console captured. `extra_cmdline` is appended to [`BASE_CMDLINE`].
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
            rtc_base: self.rtc_base.clone(),
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
