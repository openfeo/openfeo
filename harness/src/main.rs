// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `openfeo-harness run`: boot the router in the rootless lab with the serial console on this
//! terminal. `openfeo-harness check`: can this machine run the harness at all?

#![forbid(unsafe_code)]

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use openfeo_harness::lab::{ISP0_ADDR, ISP1_ADDR, Lab, workspace_root};
use openfeo_harness::{daemons, qemu, sandbox};

#[derive(Parser)]
#[command(
    name = "openfeo-harness",
    about = "Rootless QEMU + netns lab for OpenFeO"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Boot the router in the lab with the serial console on this terminal (Ctrl-A x quits).
    Run {
        #[arg(
            long,
            help = "Kernel image (default: $OPENFEO_KERNEL or build/bzImage)"
        )]
        kernel: Option<PathBuf>,
        /// Fault to inject, e.g. `child-exit:3` or `child-hang:3` (harness builds only).
        #[arg(long)]
        chaos: Option<String>,
        /// Configuration for `/state/config.toml` (default: `harness/fixtures/vm-static.toml`).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Boot without a state disk: first-boot defaults (all ports in one LAN).
        #[arg(long)]
        no_config: bool,
    },
    /// Report whether this machine can run the harness.
    Check,
    /// Internal: exit 0 if the sandbox can be entered.
    #[command(hide = true)]
    CheckSandbox,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Run {
            kernel,
            chaos,
            config,
            no_config,
        } => run(kernel, chaos, config, no_config),
        Cmd::Check => check(),
        Cmd::CheckSandbox => sandbox::enter().map(|()| ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|err| {
        eprintln!("error: {err:#}");
        ExitCode::FAILURE
    })
}

fn run(
    kernel: Option<PathBuf>,
    chaos: Option<String>,
    config: Option<PathBuf>,
    no_config: bool,
) -> Result<ExitCode> {
    sandbox::enter()?;
    let mut lab = Lab::new("run")?;
    if let Some(kernel) = kernel {
        lab.set_kernel(kernel);
    }
    if !no_config {
        let path =
            config.unwrap_or_else(|| workspace_root().join("harness/fixtures/vm-static.toml"));
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        lab.with_config(&text)?;
        eprintln!("lab: /state/config.toml from {}", path.display());
    }
    let run_dir = lab.run_dir.clone();
    let kea = daemons::kea_dhcp4(&lab.isp0, "wan0", &run_dir)?;
    lab.daemons.push(kea);
    let extra = chaos.map_or_else(String::new, |c| format!("openfeo.chaos={c}"));
    eprintln!(
        "lab: p0 <-> isp0 wan0 {ISP0_ADDR} (kea-dhcp4), p1 <-> isp1 wan1 {ISP1_ADDR}, p2 <-> lan0; \
         serial console follows, Ctrl-A x quits"
    );
    let status = lab.boot_interactive(&extra)?.wait()?;
    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn check() -> Result<ExitCode> {
    let mut all_ok = true;
    let mut report = |name: &str, ok: bool, detail: &str| {
        println!("{name:<30} {}{detail}", if ok { "ok" } else { "MISSING" });
        all_ok &= ok;
    };
    let kvm = qemu::accel() == "kvm";
    println!(
        "{:<30} {}",
        "/dev/kvm",
        if kvm { "ok" } else { "no (tcg fallback: slow)" }
    );
    let tun = File::options()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .is_ok();
    report("/dev/net/tun", tun, "");
    for bin in [
        "qemu-system-x86_64",
        "ip",
        "kea-dhcp4",
        "mkfs.ext4",
        "ping",
        "python3",
        "musl-gcc",
        "pkg-config",
        "bison",
        "flex",
    ] {
        report(bin, on_path(bin), "");
    }
    report(
        "kea-dhcp4 reads our config",
        kea_config_check(),
        " (if MISSING on Ubuntu: unload /etc/apparmor.d/usr.sbin.kea-dhcp4; ADR-0006)",
    );
    report(
        "unprivileged user namespaces",
        sandbox_works()?,
        if sandbox::is_inside() {
            " (already inside one)"
        } else {
            ""
        },
    );
    match Lab::kernel_path() {
        Ok(path) => report("kernel image", true, &format!(" ({})", path.display())),
        Err(err) => report("kernel image", false, &format!(" ({err})")),
    }
    Ok(if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// `kea-dhcp4 -t` on a config written outside `/etc/kea`, as the harness does: fails under
/// Ubuntu's stock AppArmor profile for Kea.
fn kea_config_check() -> bool {
    let dir = std::env::temp_dir().join(format!("openfeo-harness-check-{}", std::process::id()));
    let config = dir.join("kea-dhcp4.json");
    let ok = std::fs::create_dir_all(&dir).is_ok()
        && std::fs::write(&config, daemons::render_kea_dhcp4("lo")).is_ok()
        && Command::new("kea-dhcp4")
            .arg("-t")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
    let _ = std::fs::remove_dir_all(&dir);
    ok
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(bin).is_file()))
}

/// Re-run ourselves with the hidden subcommand: entering a user namespace needs a
/// single-threaded process and is not reversible, so it is tried in a child.
fn sandbox_works() -> Result<bool> {
    let exe = std::env::current_exe().context("current_exe")?;
    let status = Command::new(exe)
        .arg("check-sandbox")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("spawn self")?;
    Ok(status.success())
}
