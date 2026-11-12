// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Reference daemons on the ISP side (SPEC §11): started inside a namespace, their output
//! captured, killed when the lab goes.

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
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
const KEA_DHCP6_TEMPLATE: &str = include_str!("../fixtures/kea-dhcp6.json.tmpl");
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
    /// Whether the daemon leads a process group of its own (spawned with
    /// [`Daemon::spawn_group`]): it is then stopped with the processes it forked.
    group: bool,
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
            group: false,
        })
    }

    /// As [`Daemon::spawn`], with the daemon leading a process group of its own, so the
    /// processes it forks (`pppoe-server`'s `pppd` per session) are signalled and stopped with it.
    ///
    /// # Errors
    ///
    /// As [`Daemon::spawn`].
    pub fn spawn_group(name: &str, mut cmd: Command) -> Result<Self> {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
        let mut daemon = Self::spawn(name, cmd)?;
        daemon.group = true;
        Ok(daemon)
    }

    /// The daemon's process id (its group's id too, for one made by [`Daemon::spawn_group`]).
    #[must_use]
    pub fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap_or(i32::MAX)
    }

    /// Send `signal` to the daemon, and to every process it forked when it was spawned with
    /// [`Daemon::spawn_group`] (found through `/proc`, since `pppd` makes a session of its own
    /// with `setsid`, so a process-group signal misses it); after a signal that ends
    /// processes, wait up to five seconds for all of them to be gone.
    pub fn signal(&mut self, signal: Signal) {
        let mut pids = if self.group {
            descendants(self.pid())
        } else {
            Vec::new()
        };
        pids.push(self.pid());
        for pid in &pids {
            let _ = kill(Pid::from_raw(*pid), signal);
        }
        if matches!(signal, Signal::SIGTERM | Signal::SIGKILL) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                let _ = self.child.try_wait();
                if pids.iter().all(|pid| is_gone(*pid)) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

impl Daemon {
    /// Whether the daemon itself still runs.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// How the process ended, once it has: for a command that is run to its end, not a daemon.
    pub fn exit_status(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }
}

/// Every process below `pid`, children before their own children, from each thread's
/// `/proc/<pid>/task/<tid>/children`.
fn descendants(pid: i32) -> Vec<i32> {
    let mut found = Vec::new();
    let mut queue = vec![pid];
    while let Some(parent) = queue.pop() {
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{parent}/task")) else {
            continue;
        };
        for task in tasks.flatten() {
            let Ok(children) = std::fs::read_to_string(task.path().join("children")) else {
                continue;
            };
            for child in children.split_whitespace().filter_map(|c| c.parse().ok()) {
                found.push(child);
                queue.push(child);
            }
        }
    }
    found
}

/// Whether `pid` no longer runs: gone, or a zombie awaiting its parent.
fn is_gone(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z') || rest.starts_with('X')),
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.group {
            // Teardown needs no goodbye: a scenario that wants one stops the daemon itself.
            self.signal(Signal::SIGKILL);
            let _ = self.child.wait();
            return;
        }
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

/// What the lab's Kea DHCPv6 server hands out on one ISP interface (SPEC §11): an address from
/// the link's pool, and a /56 from `pd_pool` when there is one, with the lifetimes a scenario
/// can watch (T1 10 s, T2 16 s, preferred 40 s, valid 60 s), or ten times longer except T1 and
/// T2 when `long_lived`, for a scenario that reboots the router inside a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kea6Config {
    /// The interface in the ISP namespace.
    pub iface: String,
    /// The delegation pool, cut into /56s; `None` serves addresses only.
    pub pd_pool: Option<ipnet::Ipv6Net>,
    pub long_lived: bool,
}

impl Kea6Config {
    /// The usual server on ISP A's `wan0`, delegating from `pool` when given.
    #[must_use]
    pub fn isp(pool: Option<ipnet::Ipv6Net>) -> Self {
        Kea6Config {
            iface: "wan0".to_owned(),
            pd_pool: pool,
            long_lived: false,
        }
    }
}

/// The Kea DHCPv6 config for `config`.
#[must_use]
pub fn render_kea_dhcp6(config: &Kea6Config) -> String {
    let pd_pools = config.pd_pool.map_or_else(String::new, |pool| {
        format!(
            "{{ \"prefix\": \"{}\", \"prefix-len\": {}, \"delegated-len\": 56 }}",
            pool.network(),
            pool.prefix_len()
        )
    });
    let (preferred, valid) = if config.long_lived {
        ("400", "600")
    } else {
        ("40", "60")
    };
    KEA_DHCP6_TEMPLATE
        .replace("{{IFACE}}", &config.iface)
        .replace("{{PD_POOLS}}", &pd_pools)
        .replace("{{RENEW}}", "10")
        .replace("{{REBIND}}", "16")
        .replace("{{PREFERRED}}", preferred)
        .replace("{{VALID}}", valid)
}

/// Kea DHCPv6 serving `config` inside `ns`; config, lock and pid files go under `run_dir`.
/// Ready when it logs `DHCP6_STARTED`.
///
/// # Errors
///
/// When the config cannot be written or `kea-dhcp6` cannot be spawned.
pub fn kea_dhcp6(ns: &NetNs, config: &Kea6Config, run_dir: &Path) -> Result<Daemon> {
    let path = run_dir.join("kea-dhcp6.json");
    std::fs::write(&path, render_kea_dhcp6(config))
        .with_context(|| format!("write {}", path.display()))?;
    let mut cmd = ns.command("kea-dhcp6")?;
    cmd.arg("-c")
        .arg(&path)
        .env("KEA_LOCKFILE_DIR", run_dir)
        .env("KEA_PIDFILE_DIR", run_dir);
    Daemon::spawn("kea-dhcp6", cmd)
}

/// An HTTP target in `ns` serving `body` as `index.html` from `dir` on `bind:port`, either
/// family (`harness/fixtures/http-server.py`: the standard library's server without the reverse
/// lookup of its own address, which from a LAN namespace waits out the host's resolvers). Ready
/// when it logs `Serving HTTP on`; each request is logged as `<client> - - [<date>] "GET / …`.
///
/// # Errors
///
/// When the directory cannot be written or python3 cannot be spawned.
pub fn http_server(ns: &NetNs, bind: &str, port: u16, dir: &Path, body: &str) -> Result<Daemon> {
    std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let index = dir.join("index.html");
    std::fs::write(&index, body).with_context(|| format!("write {}", index.display()))?;
    let script = crate::lab::workspace_root().join("harness/fixtures/http-server.py");
    let mut cmd = ns.command("python3")?;
    cmd.args(["-I", "-u"])
        .arg(&script)
        .args(["--bind", bind, "--port", &port.to_string(), "--directory"])
        .arg(dir);
    Daemon::spawn(&format!("http-{}-{port}", ns.name), cmd)
}

/// The zone the lab's upstream resolver is authoritative for.
pub const ISP_DNS_ZONE: &str = "isp.example";
/// `www.isp.example`: an ordinary public answer.
pub const ISP_WWW_ADDR: &str = "198.51.100.10";
/// `www.isp.example`'s AAAA: on the ISP's IPv6 link.
pub const ISP_WWW_ADDR6: &str = "2001:db8:ffff::10";
/// `evil.isp.example`: a public name answering with a LAN address, the rebinding attack.
pub const ISP_EVIL_ADDR: &str = "192.168.1.5";
/// `allowed.isp.example`: private too, but allow-listed by the scenarios.
pub const ISP_ALLOWED_ADDR: &str = "192.168.1.6";
/// `big.isp.example` has this many TXT records of [`ISP_TXT_LEN`] bytes: over 1232 bytes in all,
/// so the upstream truncates over UDP and the forwarder must come back over TCP.
pub const ISP_TXT_RECORDS: usize = 6;
/// The length of each of `big.isp.example`'s TXT strings.
pub const ISP_TXT_LEN: usize = 250;

/// dnsmasq as the ISP's resolver on `iface` inside `ns`: authoritative for [`ISP_DNS_ZONE`]
/// alone (names outside it are refused, so it never forwards), logging every query as
/// `auth[A] www.isp.example from 203.0.113.10`. It reads no configuration file, so a host's own
/// `/etc/dnsmasq.conf` (its `server=` lines) stays out of the lab. It stays root: the sandbox
/// maps one user, so there is no `nobody` to drop to.
///
/// # Errors
///
/// When `dnsmasq` cannot be spawned.
pub fn dnsmasq(ns: &NetNs, iface: &str, run_dir: &Path) -> Result<Daemon> {
    let mut cmd = ns.command("dnsmasq")?;
    cmd.args([
        "--conf-file=/dev/null",
        "--no-daemon",
        "--log-queries",
        "--log-facility=-",
        "--no-hosts",
        "--no-resolv",
        "--user=root",
        "--group=root",
        "--pid-file=",
        "--bind-interfaces",
        "--except-interface=lo",
        &format!("--interface={iface}"),
        &format!("--auth-zone={ISP_DNS_ZONE}"),
        &format!("--auth-server=ns.{ISP_DNS_ZONE},{iface}"),
        &format!("--auth-soa=1,hostmaster.{ISP_DNS_ZONE},30,30,30"),
        "--auth-ttl=60",
        &format!("--host-record=ns.{ISP_DNS_ZONE},203.0.113.1"),
        &format!("--host-record=ntp.{ISP_DNS_ZONE},203.0.113.1"),
        &format!("--host-record=www.{ISP_DNS_ZONE},{ISP_WWW_ADDR},{ISP_WWW_ADDR6}"),
        &format!("--host-record=evil.{ISP_DNS_ZONE},{ISP_EVIL_ADDR}"),
        &format!("--host-record=allowed.{ISP_DNS_ZONE},{ISP_ALLOWED_ADDR}"),
    ]);
    for i in 0..ISP_TXT_RECORDS {
        let letter = char::from(b'a' + u8::try_from(i).unwrap_or(0));
        let text: String = std::iter::repeat_n(letter, ISP_TXT_LEN).collect();
        cmd.arg(format!("--txt-record=big.{ISP_DNS_ZONE},{text}"));
    }
    cmd.current_dir(run_dir);
    Daemon::spawn("dnsmasq", cmd)
}

/// What the lab's radvd advertises on one interface (SPEC §11): the ISP side of the WAN link.
#[derive(Debug, Clone)]
pub struct RadvdConfig {
    /// The interface in the ISP namespace.
    pub iface: String,
    /// `AdvDefaultLifetime`, seconds (at least `max_interval`); 0 advertises no default router.
    pub lifetime: u16,
    /// A prefix for the link itself, with the A and L flags, when the ISP numbers the link.
    pub prefix: Option<String>,
    /// RDNSS resolvers.
    pub rdnss: Vec<String>,
    /// DNSSL search names.
    pub dnssl: Vec<String>,
    /// `MinRtrAdvInterval`, seconds: radvd's floor is 3.
    pub min_interval: u16,
    /// `MaxRtrAdvInterval`, seconds.
    pub max_interval: u16,
    /// `AdvManagedFlag` (M): the ISP tells hosts to get addresses over DHCPv6.
    pub managed: bool,
    /// `AdvOtherConfigFlag` (O): the ISP tells hosts to get other configuration over DHCPv6.
    pub other: bool,
}

impl RadvdConfig {
    /// The ISP's usual advertisement: lifetime 1800, the lab's resolver and search domain, no
    /// link prefix, as fast as radvd allows so a scenario sees several.
    #[must_use]
    pub fn isp(iface: &str) -> Self {
        RadvdConfig {
            iface: iface.to_owned(),
            lifetime: 1800,
            prefix: None,
            rdnss: vec![ISP_RESOLVER6.to_owned()],
            dnssl: vec![ISP_DNS_ZONE.to_owned()],
            min_interval: 3,
            max_interval: 4,
            managed: false,
            other: false,
        }
    }

    /// `radvd.conf` for this configuration.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = format!(
            "interface {}\n{{\n    AdvSendAdvert on;\n    MinRtrAdvInterval {};\n    MaxRtrAdvInterval {};\n    AdvDefaultLifetime {};\n    AdvLinkMTU 1500;\n",
            self.iface, self.min_interval, self.max_interval, self.lifetime
        );
        if self.managed {
            text.push_str("    AdvManagedFlag on;\n");
        }
        if self.other {
            text.push_str("    AdvOtherConfigFlag on;\n");
        }
        // Writing to a `String` cannot fail; the results are dropped on purpose.
        if let Some(prefix) = &self.prefix {
            let _ = write!(
                text,
                "    prefix {prefix}\n    {{\n        AdvOnLink on;\n        AdvAutonomous on;\n    }};\n"
            );
        }
        for rdnss in &self.rdnss {
            let _ = write!(
                text,
                "    RDNSS {rdnss}\n    {{\n        AdvRDNSSLifetime 1800;\n    }};\n"
            );
        }
        for dnssl in &self.dnssl {
            let _ = write!(
                text,
                "    DNSSL {dnssl}\n    {{\n        AdvDNSSLLifetime 1800;\n    }};\n"
            );
        }
        text.push_str("};\n");
        text
    }
}

/// The ISP's IPv6 resolver and router address on the WAN link, the lab's `2001:db8:ffff::1`.
pub const ISP_RESOLVER6: &str = "2001:db8:ffff::1";

/// radvd on `config.iface` inside `ns`, in the foreground with its log on stderr at debug
/// level 3 (every advertisement is logged as `sending RA on <iface>`); ready when it logs its
/// version. Stopping it (SIGTERM on drop) makes it send its final advertisements with lifetime
/// 0, as the ISP's router would.
///
/// # Errors
///
/// When the config cannot be written or radvd cannot be spawned.
pub fn radvd(ns: &NetNs, config: &RadvdConfig, run_dir: &Path) -> Result<Daemon> {
    std::fs::create_dir_all(run_dir).with_context(|| format!("mkdir {}", run_dir.display()))?;
    let conf = run_dir.join(format!("radvd-{}.conf", config.iface));
    std::fs::write(&conf, config.render()).with_context(|| format!("write {}", conf.display()))?;
    std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", conf.display()))?;
    let pid = run_dir.join(format!("radvd-{}.pid", config.iface));
    let _ = std::fs::remove_file(&pid);
    let mut cmd = ns.command("radvd")?;
    cmd.args([
        "--nodaemon",
        "--debug",
        "3",
        "--logmethod",
        "stderr",
        "--config",
    ])
    .arg(&conf)
    .arg("--pidfile")
    .arg(&pid);
    Daemon::spawn(&format!("radvd-{}", config.iface), cmd)
}

/// How the lab's access concentrator wants the router authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    None,
    Pap,
    Chap,
}

/// The lab's access concentrator can run here, or the scenario skips with what is missing:
/// `/dev/ppp` openable (from the sandbox, where `ppp_generic`'s `CAP_NET_ADMIN` check passes)
/// and `pppd` and `pppoe-server` installed. CI sets `OPENFEO_NO_SKIP`, so a skip fails there.
///
/// # Errors
///
/// A [`Skip`](crate::scenario::Skip) that says what is missing.
pub fn require_access_concentrator() -> Result<()> {
    if let Err(err) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/ppp")
    {
        return Err(crate::scenario::Skip(format!(
            "/dev/ppp: {err}: load ppp_generic and make it group-accessible \
             (udev: KERNEL==\"ppp\", GROUP=\"<your group>\", MODE=\"0660\")"
        ))
        .into());
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for tool in ["pppd", "pppoe-server"] {
        if !std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()) {
            return Err(crate::scenario::Skip(format!(
                "{tool} is not installed (packages ppp and pppoe, or rp-pppoe)"
            ))
            .into());
        }
    }
    Ok(())
}

/// The lab's access concentrator (M3): rp-pppoe's `pppoe-server` spawning `pppd` per session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppoeServerConfig {
    /// The interface it listens on: isp0's `wan0`, or the sandbox suite's far veth end.
    pub iface: String,
    /// The access concentrator's name in its PADO.
    pub ac_name: String,
    /// The service name it advertises; empty for any.
    pub service: String,
    pub auth: Auth,
    /// `pppd`'s MTU and MRU: 1492, or 1500 to see the router's RFC 4638 fallback.
    pub mtu: u16,
    /// IPV6CP with the identifiers `::1` (the ISP) and `::2` (suggested to the router).
    pub ipv6: bool,
    /// `pppd`'s LCP echo interval; three missed echoes end its side of the session.
    pub echo_interval_secs: u8,
}

/// The ISP's address on the PPP link: the IPCP peer the router sees.
pub const PPP_ISP_ADDR: &str = "203.0.113.1";
/// The first address of the pool the ISP hands out.
pub const PPP_POOL_START: &str = "203.0.113.100";
/// The lab's PPP account: documentation credentials, nothing real.
pub const PPP_USERNAME: &str = "openfeo@isp.example";
/// The lab account's password.
pub const PPP_PASSWORD: &str = "example-secret";

impl PppoeServerConfig {
    /// The ISP as the lab runs it: access concentrator `isp`, any service, MTU 1492, IPV6CP on,
    /// echoes every 5 s.
    #[must_use]
    pub fn isp(iface: &str, auth: Auth) -> Self {
        Self {
            iface: iface.to_owned(),
            ac_name: "isp".to_owned(),
            service: String::new(),
            auth,
            mtu: 1492,
            ipv6: true,
            echo_interval_secs: 5,
        }
    }
}

/// The `pppd` options file the server passes to each session's `pppd` (`-O`). `nodetach` keeps
/// each `pppd` a direct child of the server, which is how the `/proc` walk in [`Daemon::signal`]
/// finds it (`pppd` calls `setsid()` regardless, so a process-group signal alone would miss it);
/// a `pppd` forked between the walk and the kill survives the kill, which no scenario has met.
#[must_use]
pub fn render_pppd_options(config: &PppoeServerConfig, log: &Path) -> String {
    let auth = match config.auth {
        Auth::None => "noauth",
        Auth::Pap => "require-pap",
        Auth::Chap => "require-chap",
    };
    let mut out = format!(
        "nodetach\ndebug\nlogfile {}\n{auth}\nms-dns {PPP_ISP_ADDR}\nlcp-echo-interval {}\nlcp-echo-failure 3\nmtu {}\nmru {}\n",
        log.display(),
        config.echo_interval_secs,
        config.mtu,
        config.mtu
    );
    out.push_str(if config.ipv6 {
        "+ipv6\nipv6 ::1,::2\n"
    } else {
        "noipv6\n"
    });
    out
}

/// `pap-secrets` and `chap-secrets` under `/etc/ppp` (the sandbox's own tmpfs, never the host's),
/// mode 0600, and an empty `options`, so `pppd` reads the lab's account and nothing else.
///
/// # Errors
///
/// Outside the sandbox (no tmpfs over `/etc/ppp`: it would be the host's, #54), or when
/// `/etc/ppp` cannot be written.
pub fn write_ppp_secrets(username: &str, password: &str) -> Result<()> {
    anyhow::ensure!(
        crate::sandbox::is_inside(),
        "not inside the sandbox: /etc/ppp would be the host's"
    );
    let line = secrets_line(username, password);
    for name in ["pap-secrets", "chap-secrets"] {
        let path = Path::new("/etc/ppp").join(name);
        std::fs::write(&path, &line).with_context(|| format!("write {}", path.display()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    std::fs::write("/etc/ppp/options", "").context("write /etc/ppp/options")?;
    Ok(())
}

/// One secrets line: the client, any server, the quoted secret, any address.
fn secrets_line(username: &str, password: &str) -> String {
    format!("\"{username}\" * \"{password}\" *\n")
}

/// `pppd`'s version from what `pppd --version` prints (`pppd version 2.5.4`).
#[must_use]
pub fn parse_pppd_version(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .skip_while(|word| *word != "version")
        .nth(1)
        .map(str::to_owned)
}

/// The PPPoE plugin of the installed `pppd`, for the server's kernel mode (`-g`): pppd's own,
/// since a plugin built for another pppd release is refused (rp-pppoe's on Arch is built for
/// 2.5.3). pppd 2.5 names it `pppoe.so`, Debian's and Ubuntu's 2.4 `rp-pppoe.so`.
///
/// # Errors
///
/// When `pppd` cannot be run or no plugin is found where distributions put them.
pub fn pppd_plugin() -> Result<PathBuf> {
    let output = Command::new("pppd")
        .arg("--version")
        .output()
        .context("run pppd --version")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let version = parse_pppd_version(&text)
        .with_context(|| format!("no version in `pppd --version`: {text:?}"))?;
    let mut tried = Vec::new();
    for root in [
        "/usr/lib/pppd",
        "/usr/lib/x86_64-linux-gnu/pppd",
        "/usr/lib64/pppd",
    ] {
        for name in ["pppoe.so", "rp-pppoe.so"] {
            let path = Path::new(root).join(&version).join(name);
            if path.exists() {
                return Ok(path);
            }
            tried.push(path.display().to_string());
        }
    }
    anyhow::bail!(
        "no PPPoE plugin for pppd {version}; tried {}",
        tried.join(", ")
    )
}

/// What `pppoe-server -h` prints (on stderr, with a non-zero exit).
fn pppoe_server_usage() -> String {
    Command::new("pppoe-server")
        .arg("-h")
        .output()
        .map(|out| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        })
        .unwrap_or_default()
}

/// Whether a usage text lists `option` as one of its own (`   -g path   -- ...`).
#[must_use]
pub fn usage_lists_option(usage: &str, option: &str) -> bool {
    usage
        .lines()
        .any(|line| line.split_whitespace().next() == Some(option))
}

/// Where each session's `pppd` logs (`logfile`): its `Using interface pppN` and `local IP
/// address` lines are what scenarios read.
#[must_use]
pub fn pppd_log_path(run_dir: &Path, iface: &str) -> PathBuf {
    run_dir.join(format!("pppd-{iface}.log"))
}

/// The last `Using interface pppN` of a `pppd` log: the ISP's side of the current session.
#[must_use]
pub fn last_ppp_ifname(log: &str) -> Option<String> {
    log.lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("Using interface "))
        .map(|name| name.trim().to_owned())
}

/// Keep one predecessor of `log` as `<log>.1` (#57): a scenario that restarts the server and
/// then fails still has the first session's account in the failure's diagnostics.
fn rotate_log(log: &Path) {
    if log.exists() {
        let kept = log.with_extension("log.1");
        let _ = std::fs::rename(log, kept);
    }
}

/// The server's command line, shared by the namespace and sandbox variants.
fn pppoe_server_command(
    mut cmd: Command,
    config: &PppoeServerConfig,
    run_dir: &Path,
) -> Result<Command> {
    std::fs::create_dir_all(run_dir).with_context(|| format!("mkdir {}", run_dir.display()))?;
    write_ppp_secrets(PPP_USERNAME, PPP_PASSWORD)?;
    let log = pppd_log_path(run_dir, &config.iface);
    rotate_log(&log);
    let options = run_dir.join(format!("pppd-{}.options", config.iface));
    std::fs::write(&options, render_pppd_options(config, &log))
        .with_context(|| format!("write {}", options.display()))?;
    let pid = run_dir.join(format!("pppoe-server-{}.pid", config.iface));
    let _ = std::fs::remove_file(&pid);
    // Kernel mode (`-k`): the user-mode `pppoe` helper cannot drop privileges in a user
    // namespace with one uid mapped, and kernel PPPoE is what the router speaks anyway.
    cmd.env("HOME", run_dir).arg("-k");
    // rp-pppoe 4 takes the plugin's path (`-g`); 3.x (Ubuntu 24.04's) has none and uses the
    // Debian path of pppd's own plugin, which is the right one there.
    if usage_lists_option(&pppoe_server_usage(), "-g") {
        cmd.arg("-g").arg(pppd_plugin()?);
    }
    cmd.args(["-F", "-I", &config.iface, "-C", &config.ac_name]);
    if !config.service.is_empty() {
        cmd.args(["-S", &config.service]);
    }
    cmd.args(["-L", PPP_ISP_ADDR, "-R", PPP_POOL_START, "-N", "4", "-O"])
        .arg(&options)
        .arg("-X")
        .arg(&pid);
    Ok(cmd)
}

/// The access concentrator inside `ns` (isp0's `wan0` for the QEMU suites).
///
/// # Errors
///
/// When the secrets or options cannot be written, no plugin is found, or the server cannot be
/// spawned or exits at once.
pub fn pppoe_server(ns: &NetNs, config: &PppoeServerConfig, run_dir: &Path) -> Result<Daemon> {
    let cmd = pppoe_server_command(ns.command("pppoe-server")?, config, run_dir)?;
    started(Daemon::spawn_group(
        &format!("pppoe-server-{}", config.iface),
        cmd,
    )?)
}

/// The access concentrator in the current namespace (the sandbox suite's far veth end).
///
/// # Errors
///
/// As [`pppoe_server`].
pub fn pppoe_server_in_sandbox(config: &PppoeServerConfig, run_dir: &Path) -> Result<Daemon> {
    let cmd = pppoe_server_command(Command::new("pppoe-server"), config, run_dir)?;
    started(Daemon::spawn_group(
        &format!("pppoe-server-{}", config.iface),
        cmd,
    )?)
}

/// `pppoe-server -F` prints nothing when it starts listening: a server still running after a
/// moment is up; one that exited at once says why on its output.
fn started(mut daemon: Daemon) -> Result<Daemon> {
    std::thread::sleep(Duration::from_millis(300));
    if daemon.is_running() {
        return Ok(daemon);
    }
    anyhow::bail!(
        "{} exited at once: {}",
        daemon.name,
        daemon.log.tail(20).join(" | ")
    )
}

/// The lab's SNTP server (`harness/fixtures/sntp-server.py`) on `bind:123` inside `ns`: every
/// mode 3 request is answered with mode 4, stratum `stratum`, reference id `LOCL` and this
/// host's clock shifted by `offset_secs`; each request is logged as `query from <addr>:<port>`;
/// ready when it logs `sntp-server listening on <bind>:123`.
///
/// # Errors
///
/// When python3 cannot be spawned.
pub fn sntp_server(ns: &NetNs, bind: &str, offset_secs: i64, stratum: u8) -> Result<Daemon> {
    let script = crate::lab::workspace_root().join("harness/fixtures/sntp-server.py");
    let mut cmd = ns.command("python3")?;
    cmd.args(["-I", "-u"]).arg(&script).args([
        "--bind",
        bind,
        "--port",
        "123",
        "--offset",
        &offset_secs.to_string(),
        "--stratum",
        &stratum.to_string(),
    ]);
    Daemon::spawn(&format!("sntp-{bind}"), cmd)
}

#[cfg(test)]
mod tests {
    #[test]
    fn pppd_options_render_in_a_fixed_order() {
        let config = PppoeServerConfig {
            mtu: 1500,
            ..PppoeServerConfig::isp("wan0", Auth::Chap)
        };
        assert_eq!(
            render_pppd_options(&config, Path::new("/run/x/pppd-wan0.log")),
            "nodetach\ndebug\nlogfile /run/x/pppd-wan0.log\nrequire-chap\nms-dns 203.0.113.1\nlcp-echo-interval 5\nlcp-echo-failure 3\nmtu 1500\nmru 1500\n+ipv6\nipv6 ::1,::2\n"
        );
        let plain = PppoeServerConfig {
            ipv6: false,
            ..PppoeServerConfig::isp("e1", Auth::None)
        };
        assert!(render_pppd_options(&plain, Path::new("l")).ends_with("noauth\nms-dns 203.0.113.1\nlcp-echo-interval 5\nlcp-echo-failure 3\nmtu 1492\nmru 1492\nnoipv6\n"));
    }

    #[test]
    fn secrets_quote_the_password() {
        assert_eq!(
            secrets_line("openfeo@isp.example", "example-secret"),
            "\"openfeo@isp.example\" * \"example-secret\" *\n"
        );
    }

    /// #54: the secrets go to `/etc/ppp` and rely on the sandbox's tmpfs over it; outside the
    /// sandbox that would be the host's directory, so the call is refused.
    #[test]
    fn secrets_are_refused_outside_the_sandbox() {
        if crate::sandbox::is_inside() {
            return; // the suite itself runs inside: nothing to refuse
        }
        let err = write_ppp_secrets("u", "p").expect_err("refused outside the sandbox");
        assert!(format!("{err:#}").contains("sandbox"), "{err:#}");
    }

    /// #57: a restarted server keeps its predecessor's pppd log as `.1` for a failure message.
    #[test]
    fn a_rotated_log_keeps_one_predecessor() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("pppd-x.log");
        rotate_log(&log);
        assert!(!log.with_extension("log.1").exists(), "nothing to rotate");
        std::fs::write(&log, "a").unwrap();
        rotate_log(&log);
        assert!(!log.exists());
        assert_eq!(
            std::fs::read_to_string(log.with_extension("log.1")).unwrap(),
            "a"
        );
        std::fs::write(&log, "b").unwrap();
        rotate_log(&log);
        assert_eq!(
            std::fs::read_to_string(log.with_extension("log.1")).unwrap(),
            "b"
        );
    }

    #[test]
    fn a_server_option_is_found_only_where_its_usage_lists_it() {
        let v4 = "Options:\n   -I if_name     -- Specify interface\n   -g path        -- Specify full path to plugin\n";
        let v3 = "Options:\n   -I if_name     -- Specify interface\n   -k             -- Use kernel-mode PPPoE.\n";
        assert!(usage_lists_option(v4, "-g"));
        assert!(!usage_lists_option(v3, "-g"));
        assert!(usage_lists_option(v3, "-k"));
        assert!(!usage_lists_option("   -gx  -- other", "-g"));
    }

    #[test]
    fn the_pppd_version_comes_from_its_banner() {
        assert_eq!(
            parse_pppd_version("pppd version 2.5.4\n").as_deref(),
            Some("2.5.4")
        );
        assert_eq!(
            parse_pppd_version("pppd version 2.4.9"),
            Some("2.4.9".to_owned())
        );
        assert_eq!(parse_pppd_version("nothing"), None);
    }

    #[test]
    fn the_ppp_interface_comes_from_the_last_using_interface_line() {
        let log = "using channel 1\nUsing interface ppp0\nConnect: ppp0 <--> e1\nConnection terminated.\nusing channel 2\nUsing interface ppp3\n";
        assert_eq!(last_ppp_ifname(log).as_deref(), Some("ppp3"));
        assert_eq!(last_ppp_ifname("Connect: nothing"), None);
    }

    use super::*;

    #[test]
    fn kea6_template_renders_the_pool_and_omits_it_when_none() {
        let config = Kea6Config::isp(Some("2001:db8:100::/48".parse().unwrap()));
        let text = render_kea_dhcp6(&config);
        assert!(text.contains("\"interfaces\": [ \"wan0\" ]"), "{text}");
        assert!(
            text.contains(
                "{ \"prefix\": \"2001:db8:100::\", \"prefix-len\": 48, \"delegated-len\": 56 }"
            ),
            "{text}"
        );
        assert!(
            text.contains("\"renew-timer\": 10,") && text.contains("\"valid-lifetime\": 60,"),
            "{text}"
        );
        let json: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(
            json["Dhcp6"]["subnet6"][0]["pd-pools"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        let none = render_kea_dhcp6(&Kea6Config::isp(None));
        let json: serde_json::Value = serde_json::from_str(&none).expect("valid JSON");
        assert_eq!(
            json["Dhcp6"]["subnet6"][0]["pd-pools"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
        let long = render_kea_dhcp6(&Kea6Config {
            long_lived: true,
            ..Kea6Config::isp(Some("2001:db8:100::/48".parse().unwrap()))
        });
        assert!(
            long.contains("\"valid-lifetime\": 600,")
                && long.contains("\"preferred-lifetime\": 400,"),
            "{long}"
        );
    }

    #[test]
    fn radvd_renders_the_m_and_o_flags_only_when_set() {
        let plain = RadvdConfig::isp("wan0").render();
        assert!(
            !plain.contains("AdvManagedFlag") && !plain.contains("AdvOtherConfigFlag"),
            "{plain}"
        );
        let delegating = RadvdConfig {
            managed: true,
            other: true,
            ..RadvdConfig::isp("wan0")
        }
        .render();
        assert!(
            delegating.contains("    AdvManagedFlag on;\n")
                && delegating.contains("    AdvOtherConfigFlag on;\n"),
            "{delegating}"
        );
    }

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
