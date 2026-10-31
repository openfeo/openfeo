// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `openfeo-harness run`: boot the router in the rootless lab with the serial console on this
//! terminal. `openfeo-harness check`: can this machine run the harness at all?

#![forbid(unsafe_code)]

use std::fs::File;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use openfeo_harness::lab::{ISP_HTTP_BODY, ISP0_ADDR, ISP1_ADDR, Lab, workspace_root};
use openfeo_harness::lanclient::{self, DhcpClientArgs};
use openfeo_harness::{daemons, qemu, sandbox};
use openfeo_harness::{nftprobe, scenario};

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
    /// Internal: inside the sandbox, exit 0 if the kernel runs the nft ruleset's expressions,
    /// 3 if it cannot load their modules, 1 on any other error.
    #[command(hide = true)]
    ProbeNft,
    /// Internal: our DHCPv4 client on an interface of the current namespace, one JSON event per
    /// line; the LAN side of the DHCPv4 server scenarios.
    #[command(hide = true)]
    DhcpClient {
        #[arg(long)]
        iface: String,
        /// Start with INIT-REBOOT for this address.
        #[arg(long)]
        request: Option<Ipv4Addr>,
        /// Option 12 to send.
        #[arg(long)]
        hostname: Option<String>,
        /// Exit after the first renewal instead of the first lease.
        #[arg(long)]
        until_renewed: bool,
        /// Send one DHCPINFORM from this address instead of running the client.
        #[arg(long)]
        inform: Option<Ipv4Addr>,
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,
    },
}

/// Exit code of `probe-nft` for a kernel that cannot load the nft modules.
const PROBE_SKIP: u8 = 3;

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
        Cmd::ProbeNft => probe_nft(),
        Cmd::DhcpClient {
            iface,
            request,
            hostname,
            until_renewed,
            inform,
            timeout_secs,
        } => lanclient::run_dhcp_client(&DhcpClientArgs {
            iface,
            request,
            hostname,
            until_renewed,
            inform,
            timeout: Duration::from_secs(timeout_secs),
        }),
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
    lab.start_kea()?;
    lab.start_dnsmasq()?;
    let http = daemons::http_server(
        &lab.isp0,
        "203.0.113.1",
        8080,
        &run_dir.join("isp-http"),
        ISP_HTTP_BODY,
    )?;
    lab.daemons.push(http);
    let extra = chaos.map_or_else(String::new, |c| format!("openfeo.chaos={c}"));
    eprintln!(
        "lab: p0 <-> isp0 wan0 {ISP0_ADDR} (kea-dhcp4 60 s leases, dnsmasq for isp.example, \
         http :8080), p1 <-> isp1 wan1 {ISP1_ADDR}, p2 <-> lan0; --config \
         harness/fixtures/vm-dhcp.toml takes the WAN address from Kea; serial console follows, \
         Ctrl-A x quits"
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
        "busybox",
        "dnsmasq",
        "dig",
        "ntpdate",
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
    match kea_config_check() {
        Ok(()) => report("kea-dhcp4 reads our config", true, ""),
        Err(detail) => report(
            "kea-dhcp4 reads our config",
            false,
            &format!(
                " ({detail}; if Kea cannot open the file on Ubuntu: unload \
                 /etc/apparmor.d/usr.sbin.kea-dhcp4, ADR-0006)"
            ),
        ),
    }
    report(
        "unprivileged user namespaces",
        sandbox_works()?,
        if sandbox::is_inside() {
            " (already inside one)"
        } else {
            ""
        },
    );
    match nft_expressions_work()? {
        Ok(()) => report("nft ct/fib/nat expressions", true, ""),
        Err(detail) => report("nft ct/fib/nat expressions", false, &format!(" ({detail})")),
    }
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

/// `kea-dhcp4 -t` on the lab's config written outside `/etc/kea`, as the harness does. Fails
/// under Ubuntu's stock AppArmor profile for Kea, and on a Kea that rejects something in the
/// template; the error carries Kea's own message so the cause is on the console.
fn kea_config_check() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("openfeo-harness-check-{}", std::process::id()));
    let config = dir.join("kea-dhcp4.json");
    let result = (|| {
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        std::fs::write(&config, daemons::render_kea_dhcp4("lo"))
            .map_err(|e| format!("write {}: {e}", config.display()))?;
        let output = Command::new("kea-dhcp4")
            .arg("-t")
            .arg(&config)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .output()
            .map_err(|e| format!("run kea-dhcp4: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        Err(kea_error_line(&text))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// The message of Kea's first `ERROR` line without its timestamp and logger tag, else the first
/// non-empty line of the output.
fn kea_error_line(output: &str) -> String {
    let Some(line) = output
        .lines()
        .find(|line| line.contains(" ERROR "))
        .or_else(|| output.lines().find(|line| !line.trim().is_empty()))
    else {
        return "no output".to_owned();
    };
    let message = if line.contains(" ERROR ") {
        line.find("] ").map_or(line, |end| &line[end + 2..])
    } else {
        line
    };
    message.trim().to_owned()
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(bin).is_file()))
}

/// `probe-nft`: enter the sandbox and ask the kernel.
fn probe_nft() -> Result<ExitCode> {
    sandbox::enter()?;
    match nftprobe::require_expressions() {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(err) if err.downcast_ref::<scenario::Skip>().is_some() => {
            eprintln!("{err}");
            Ok(ExitCode::from(PROBE_SKIP))
        }
        Err(err) => Err(err),
    }
}

/// Re-run ourselves with `probe-nft` (the probe needs the sandbox, see [`sandbox_works`]):
/// `Ok(Ok(()))` when the kernel runs every expression the ruleset uses, `Ok(Err(reason))` when
/// it cannot load their modules (the sandboxed nft scenarios will skip), `Err` when the probe
/// itself broke.
fn nft_expressions_work() -> Result<Result<(), String>> {
    let exe = std::env::current_exe().context("current_exe")?;
    let output = Command::new(exe)
        .arg("probe-nft")
        .stdin(Stdio::null())
        .output()
        .context("spawn self")?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if output.status.success() {
        Ok(Ok(()))
    } else if output.status.code() == Some(i32::from(PROBE_SKIP)) {
        Ok(Err(stderr))
    } else {
        anyhow::bail!("nft probe failed: {stderr}")
    }
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

#[cfg(test)]
mod tests {
    use super::kea_error_line;

    #[test]
    fn kea_error_line_keeps_the_message_without_the_log_prefix() {
        let output = "2026-10-31 06:51:14.457 INFO  [kea-dhcp4.dhcp4/395.140188485249472] DHCP4_CONFIG_RECEIVED\n\
                      2026-10-31 06:51:14.458 ERROR [kea-dhcp4.dhcp4/395.140188485249472] DHCP4_PARSER_FAIL failed to create or run parser for configuration element subnet4: definition for the option 'dhcp4.classless-static-route' does not exist (/run/kea-dhcp4.json:19:21)\n";
        assert_eq!(
            kea_error_line(output),
            "DHCP4_PARSER_FAIL failed to create or run parser for configuration element subnet4: \
             definition for the option 'dhcp4.classless-static-route' does not exist \
             (/run/kea-dhcp4.json:19:21)"
        );
    }

    #[test]
    fn kea_error_line_falls_back_to_the_first_line_of_output() {
        assert_eq!(
            kea_error_line("\nkea-dhcp4: Permission denied\n"),
            "kea-dhcp4: Permission denied"
        );
        assert_eq!(kea_error_line(""), "no output");
    }
}
