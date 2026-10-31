// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The lab's hosts as clients: an HTTP GET made from inside a namespace (so a LAN or ISP host
//! fetches through the router, no proxy in between), a ping loop whose summary says how many
//! replies came back, and two DHCPv4 clients for the LAN side of the server scenarios (SPEC
//! §11): our own, run as the hidden `openfeo-harness dhcp-client` subcommand inside a namespace
//! and printing one JSON event per line, and busybox `udhcpc` as the independent reference.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufRead as _, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use nix::sched::{CloneFlags, setns};
use nix::sys::signal::{Signal, kill};
use nix::sys::socket::{setsockopt, sockopt};
use nix::unistd::Pid;
use openfeo_net::dhcp4::{Driver, DriverConfig, Event};
use openfeo_proto_dhcp4::identity::{client_id, duid_ll, iaid};
use openfeo_proto_dhcp4::wire::{CLIENT_PORT, DhcpOption, Message, MessageType, Op, SERVER_PORT};
use openfeo_proto_dhcp4::{ClientConfig, Lease, Unbound};
use openfeo_proto_sntp::{NtpTimestamp, Packet};
use serde_json::{Value, json};

use crate::netns::{self, NetNs};

/// What a ping loop saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingStats {
    /// Echo requests sent.
    pub sent: usize,
    /// Echo replies received.
    pub received: usize,
}

/// `GET <path> HTTP/1.0` to `addr` from inside `ns`; the response body. A thread enters the
/// namespace (`setns`, like the tap opener) so the connection is made from there.
///
/// # Errors
///
/// When the namespace cannot be entered, the connection is refused or times out (`timeout`
/// covers the connect and each read), or the response has no header/body separator.
pub fn http_get(ns: &NetNs, addr: SocketAddr, path: &str, timeout: Duration) -> Result<String> {
    let ns_file = File::open(ns.path()).with_context(|| format!("open {}", ns.path().display()))?;
    let path = path.to_owned();
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> Result<String> {
                setns(&ns_file, CloneFlags::CLONE_NEWNET).context("setns")?;
                let mut stream = TcpStream::connect_timeout(&addr, timeout)
                    .with_context(|| format!("connect {addr}"))?;
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                stream
                    .write_all(format!("GET {path} HTTP/1.0\r\nHost: x\r\n\r\n").as_bytes())
                    .context("send request")?;
                let mut response = Vec::new();
                stream
                    .read_to_end(&mut response)
                    .with_context(|| format!("read response from {addr}"))?;
                let body =
                    body_of(&response).with_context(|| format!("no HTTP response from {addr}"))?;
                Ok(body.to_owned())
            })
            .join()
            .map_err(|_| anyhow::anyhow!("http thread panicked"))?
    })
}

/// `ping -c <count> -i <interval> -W 1 <target>` from `ns`, whatever its exit status (lost
/// packets make ping exit non-zero), parsed from the summary line.
///
/// # Errors
///
/// When ping cannot be run or prints no summary.
pub fn ping_loop(ns: &NetNs, target: &str, count: usize, interval: Duration) -> Result<PingStats> {
    let mut cmd = ns.command("ping")?;
    cmd.args([
        "-c",
        &count.to_string(),
        "-i",
        &format!("{:.3}", interval.as_secs_f64()),
        "-W",
        "1",
        target,
    ])
    .stdin(Stdio::null());
    let output = cmd.output().context("run ping")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stats = parse_ping_summary(&stdout).with_context(|| {
        format!(
            "ping {target}: no summary; stderr: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })?;
    ensure!(stats.sent > 0, "ping {target} sent nothing");
    Ok(stats)
}

/// `5 packets transmitted, 4 received, 20% packet loss, time 804ms` → sent 5, received 4.
#[must_use]
pub fn parse_ping_summary(output: &str) -> Option<PingStats> {
    let line = output
        .lines()
        .find(|line| line.contains("packets transmitted"))?;
    let mut sent = None;
    let mut received = None;
    for part in line.split(',') {
        let part = part.trim();
        let number = part.split_whitespace().next()?.parse::<usize>().ok();
        if part.contains("transmitted") {
            sent = number;
        } else if part.contains("received") {
            received = number;
        }
    }
    Some(PingStats {
        sent: sent?,
        received: received?,
    })
}

/// The body after the blank line that ends the headers; `None` without one.
#[must_use]
pub fn body_of(response: &[u8]) -> Option<&str> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    std::str::from_utf8(&response[separator + 4..]).ok()
}

/// The kernel index and MAC of `ifname` in the current namespace, from `ip -o link show` (the
/// sandbox's `/sys` is the host's, so sysfs cannot be asked).
///
/// # Errors
///
/// When `ip` fails or prints no index or `link/ether`.
pub fn link_info(ifname: &str) -> Result<(u32, [u8; 6])> {
    parse_link_line(&netns::ip(&["-o", "link", "show", ifname])?)
}

/// [`link_info`] for an interface inside `ns`.
///
/// # Errors
///
/// As [`link_info`].
pub fn link_info_in(ns: &NetNs, ifname: &str) -> Result<(u32, [u8; 6])> {
    parse_link_line(&ns.ip(&["-o", "link", "show", ifname])?)
}

fn parse_link_line(line: &str) -> Result<(u32, [u8; 6])> {
    let index: u32 = line
        .split(':')
        .next()
        .and_then(|index| index.trim().parse().ok())
        .with_context(|| format!("no ifindex in {line:?}"))?;
    let mac_text = line
        .split_whitespace()
        .skip_while(|word| *word != "link/ether")
        .nth(1)
        .with_context(|| format!("no link/ether in {line:?}"))?;
    let bytes: Vec<u8> = mac_text
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<_, _>>()
        .with_context(|| format!("bad mac {mac_text:?}"))?;
    let mac: [u8; 6] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("mac {mac_text:?} is not six bytes"))?;
    Ok((index, mac))
}

/// What `openfeo-harness dhcp-client` is asked to do.
#[derive(Debug, Clone)]
pub struct DhcpClientArgs {
    pub iface: String,
    /// Start with INIT-REBOOT for this address instead of DISCOVER.
    pub request: Option<Ipv4Addr>,
    /// Option 12 to send.
    pub hostname: Option<String>,
    /// Exit after the first renewal rather than the first lease.
    pub until_renewed: bool,
    /// Send one DHCPINFORM from this address instead of running the client.
    pub inform: Option<Ipv4Addr>,
    pub timeout: Duration,
}

/// Exit status of `dhcp-client` when the goal event did not arrive in time.
pub const DHCP_CLIENT_TIMEOUT_EXIT: u8 = 2;

/// Run our DHCPv4 client (or one DHCPINFORM) on `args.iface` in the current namespace, printing
/// one JSON object per event on stdout: `discover`, `offer`, `request`, `init-reboot`,
/// `bound` (with the lease), `nak`, `expired`, `reboot-timed-out`, `ack` (INFORM). Exits 0 at
/// the goal event, [`DHCP_CLIENT_TIMEOUT_EXIT`] at the timeout.
///
/// # Errors
///
/// When the interface cannot be read or a socket cannot be opened.
pub fn run_dhcp_client(args: &DhcpClientArgs) -> Result<ExitCode> {
    if let Some(ciaddr) = args.inform {
        return inform_once(args, ciaddr);
    }
    let (ifindex, mac) = link_info(&args.iface)?;
    let duid = duid_ll(mac);
    let mut client = ClientConfig::new(mac, client_id(iaid(mac), &duid));
    client.hostname.clone_from(&args.hostname);
    let initial_lease = args.request.map(|address| Lease {
        address,
        prefix: 24,
        server: Ipv4Addr::UNSPECIFIED,
        gateway: None,
        routes: Vec::new(),
        dns: Vec::new(),
        domain: None,
        mtu: None,
        ntp: Vec::new(),
        broadcast: None,
        lease_secs: 3600,
        t1_secs: 1800,
        t2_secs: 3150,
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    runtime.block_on(async {
        let mut driver = Driver::new(DriverConfig {
            ifname: args.iface.clone(),
            ifindex,
            mac,
            client,
            initial_lease,
            seed: unix_nanos(),
        })
        .context("start the DHCP client")?;
        let deadline = tokio::time::Instant::now() + args.timeout;
        loop {
            let events = match tokio::time::timeout_at(deadline, driver.step()).await {
                Ok(events) => events.context("DHCP client step")?,
                Err(_) => return Ok(ExitCode::from(DHCP_CLIENT_TIMEOUT_EXIT)),
            };
            for event in events {
                print_json(&event_json(&event))?;
                if let Event::Bound { lease, renewed } = &event {
                    // As the applier would: the address goes on the interface, so renewals
                    // and traffic through the router work.
                    configure_address(&args.iface, lease.address, lease.prefix);
                    if *renewed || !args.until_renewed {
                        return Ok(ExitCode::SUCCESS);
                    }
                }
            }
        }
    })
}

fn configure_address(iface: &str, address: Ipv4Addr, prefix: u8) {
    let status = Command::new("ip")
        .args([
            "addr",
            "replace",
            &format!("{address}/{prefix}"),
            "dev",
            iface,
        ])
        .stdin(Stdio::null())
        .status();
    if !status.as_ref().is_ok_and(std::process::ExitStatus::success) {
        eprintln!("dhcp-client: cannot put {address}/{prefix} on {iface}: {status:?}");
    }
}

fn event_json(event: &Event) -> Value {
    match event {
        Event::Discover => json!({"event": "discover"}),
        Event::Offer { address, server } => json!({
            "event": "offer", "address": address.to_string(), "server": server.to_string(),
        }),
        Event::Request(address) => json!({"event": "request", "address": address.to_string()}),
        Event::Rebooting(address) => {
            json!({"event": "init-reboot", "address": address.to_string()})
        }
        Event::Bound { lease, renewed } => json!({
            "event": "bound",
            "address": lease.address.to_string(),
            "prefix": lease.prefix,
            "server": lease.server.to_string(),
            "gateway": lease.default_gateway().map(|gateway| gateway.to_string()),
            "dns": lease.dns.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "domain": lease.domain,
            "lease_secs": lease.lease_secs,
            "t1_secs": lease.t1_secs,
            "t2_secs": lease.t2_secs,
            "renewed": renewed,
        }),
        Event::Unbound(Unbound::Nak(message)) => json!({"event": "nak", "message": message}),
        Event::Unbound(Unbound::Expired) => json!({"event": "expired"}),
        Event::Unbound(Unbound::RebootTimedOut) => json!({"event": "reboot-timed-out"}),
    }
}

/// One DHCPINFORM from `ciaddr` (already on the interface), broadcast; prints the ACK's
/// options as `{"event":"ack","router":[..],"dns":[..],"domain":..,"mask":..}`.
fn inform_once(args: &DhcpClientArgs, ciaddr: Ipv4Addr) -> Result<ExitCode> {
    let (_, mac) = link_info(&args.iface)?;
    let socket = UdpSocket::bind(SocketAddrV4::new(ciaddr, CLIENT_PORT))
        .with_context(|| format!("bind {ciaddr}:{CLIENT_PORT}"))?;
    socket.set_broadcast(true)?;
    setsockopt(&socket, sockopt::BindToDevice, &OsString::from(&args.iface))
        .context("SO_BINDTODEVICE")?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    let xid = u32::try_from(unix_nanos() & 0xffff_ffff).unwrap_or(1);
    let mut hardware = [0u8; 16];
    hardware[..6].copy_from_slice(&mac);
    let inform = Message {
        op: Op::BootRequest,
        htype: 1,
        hlen: 6,
        hops: 0,
        xid,
        secs: 0,
        flags: 0,
        ciaddr,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: hardware,
        sname: [0; 64],
        file: [0; 128],
        options: vec![
            DhcpOption::MessageType(MessageType::Inform),
            DhcpOption::ParameterRequestList(vec![1, 3, 6, 15, 28]),
        ],
    };
    socket.send_to(
        &inform.encode(),
        SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT),
    )?;
    let deadline = Instant::now() + args.timeout;
    let mut buf = [0u8; 1500];
    while Instant::now() < deadline {
        let Ok((len, _)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let Ok(reply) = Message::decode(&buf[..len]) else {
            continue;
        };
        if reply.xid != xid || reply.message_type() != Some(MessageType::Ack) {
            continue;
        }
        let addrs = |code: u8| -> Vec<String> {
            match reply.option(code) {
                Some(DhcpOption::Router(list) | DhcpOption::DomainNameServer(list)) => {
                    list.iter().map(ToString::to_string).collect()
                }
                _ => Vec::new(),
            }
        };
        print_json(&json!({
            "event": "ack",
            "router": addrs(3),
            "dns": addrs(6),
            "domain": match reply.option(15) {
                Some(DhcpOption::DomainName(domain)) => Some(domain.clone()),
                _ => None,
            },
            "mask": match reply.option(1) {
                Some(DhcpOption::SubnetMask(mask)) => Some(mask.to_string()),
                _ => None,
            },
        }))?;
        return Ok(ExitCode::SUCCESS);
    }
    Ok(ExitCode::from(DHCP_CLIENT_TIMEOUT_EXIT))
}

fn print_json(value: &Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{value}")?;
    out.flush()?;
    Ok(())
}

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |since| u64::try_from(since.as_nanos()).unwrap_or(1))
}

/// Run `<harness_bin> dhcp-client --iface <iface> <args>` inside `ns` and return its JSON
/// events. The binary is the harness itself (`env!("CARGO_BIN_EXE_openfeo-harness")` in a
/// test), so our client runs in any namespace.
///
/// # Errors
///
/// When the process cannot be run, times out (plus a grace second), prints anything that is
/// not JSON, or exits with a status other than success or [`DHCP_CLIENT_TIMEOUT_EXIT`]; the
/// events seen so far are in the error text.
pub fn dhcp_client(
    harness_bin: &str,
    ns: &NetNs,
    iface: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Vec<Value>> {
    let mut cmd = ns.command(harness_bin)?;
    cmd.args(["dhcp-client", "--iface", iface])
        .args(["--timeout-secs", &timeout.as_secs().max(1).to_string()])
        .args(args);
    let output = run_with_timeout(&mut cmd, timeout + Duration::from_secs(2))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let events =
        parse_json_lines(&stdout).with_context(|| format!("dhcp-client output: {stdout}"))?;
    let code = output.status.code();
    ensure!(
        code == Some(0) || code == Some(i32::from(DHCP_CLIENT_TIMEOUT_EXIT)),
        "dhcp-client failed ({:?}): {}; events {events:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(events)
}

/// One JSON object per non-empty line.
///
/// # Errors
///
/// When a line is not JSON.
pub fn parse_json_lines(stdout: &str) -> Result<Vec<Value>> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).with_context(|| format!("not JSON: {line:?}")))
        .collect()
}

/// One call of the udhcpc script: the event (`deconfig`, `bound`, `renew`, `nak`, `leasefail`)
/// and the environment udhcpc set for it (`ip`, `subnet`, `router`, `dns`, `domain`, `lease`,
/// `serverid`, `hostname`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdhcpcEvent {
    pub kind: String,
    pub env: BTreeMap<String, String>,
}

const UDHCPC_SCRIPT: &str = "#!/bin/sh\n\
# SPDX-License-Identifier: GPL-2.0-or-later\n\
# Copyright (C) 2026 Andrew Newton\n\
# The lab's udhcpc script: report everything, put the leased address on the interface.\n\
echo \"udhcpc-event $1\"\n\
env | sed 's/^/udhcpc-env /'\n\
case \"$1\" in bound|renew) ip addr replace \"$ip/$mask\" dev \"$interface\" ;; esac\n";

/// busybox `udhcpc -i <iface> -f -n -q -t 4 -T 3 -s <script> <args>` inside `ns`, the
/// reference client. The script reports the events and udhcpc's environment, parsed into
/// [`UdhcpcEvent`]s, and puts the leased address on the interface (so a release or a fetch
/// through the router works); routes are the caller's.
///
/// # Errors
///
/// When the script cannot be written, busybox cannot be run or the run times out (the events
/// seen so far are in the error text). A lease not obtained is not an error here: the caller
/// reads the events.
pub fn udhcpc(
    ns: &NetNs,
    iface: &str,
    run_dir: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<Vec<UdhcpcEvent>> {
    let mut cmd = udhcpc_command(ns, iface, run_dir)?;
    cmd.arg("-q").args(args);
    let output = run_with_timeout(&mut cmd, timeout)?;
    trace_udhcpc(output.status, &output.stderr);
    Ok(parse_udhcpc_output(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// busybox `udhcpc -R` inside `ns`: get a lease, then release it. udhcpc is run without `-q`
/// (busybox 1.36's "quit after lease" leaves before the state its release path checks, so
/// `-q -R` never sends a RELEASE) and sent SIGTERM once the script has reported `bound`, which
/// makes it unicast the RELEASE and exit. Returns every event, `bound` among them.
///
/// # Errors
///
/// As [`udhcpc`], and when no lease arrives within `timeout`.
pub fn udhcpc_release(
    ns: &NetNs,
    iface: &str,
    run_dir: &Path,
    timeout: Duration,
) -> Result<Vec<UdhcpcEvent>> {
    let mut cmd = udhcpc_command(ns, iface, run_dir)?;
    cmd.arg("-R")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("spawn busybox udhcpc")?;
    let stdout = child.stdout.take().context("udhcpc stdout")?;
    let (lines_tx, lines_rx) = mpsc::channel::<String>();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            let _ = lines_tx.send(line.clone());
            lines.push(line);
        }
        lines
    });
    let deadline = Instant::now() + timeout;
    let mut bound = false;
    while !bound && Instant::now() < deadline {
        match lines_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => bound = line.trim() == "udhcpc-event bound",
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if bound {
        let pid = Pid::from_raw(i32::try_from(child.id()).context("udhcpc pid")?);
        kill(pid, Signal::SIGTERM).context("SIGTERM udhcpc")?;
    } else {
        let _ = child.kill();
    }
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline + Duration::from_secs(2) {
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let status = child.wait()?;
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_end(&mut stderr);
    }
    trace_udhcpc(status, &stderr);
    let lines = reader
        .join()
        .map_err(|_| anyhow::anyhow!("udhcpc reader thread panicked"))?;
    let events = parse_udhcpc_output(&lines.join("\n"));
    ensure!(
        bound,
        "udhcpc never bound within {timeout:?}: events {events:?}, stderr {}",
        String::from_utf8_lossy(&stderr).trim()
    );
    Ok(events)
}

/// `busybox udhcpc -v -i <iface> -f -n -t 4 -T 3 -s <script>` in `ns`, the script written to
/// `run_dir`; the caller adds `-q`, `-R`, `-r` and friends.
fn udhcpc_command(ns: &NetNs, iface: &str, run_dir: &Path) -> Result<Command> {
    let script = run_dir.join("udhcpc.sh");
    std::fs::write(&script, UDHCPC_SCRIPT)
        .with_context(|| format!("write {}", script.display()))?;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
    let mut cmd = ns.command("busybox")?;
    cmd.args([
        "udhcpc", "-v", "-i", iface, "-f", "-n", "-t", "4", "-T", "3", "-s",
    ])
    .arg(&script);
    Ok(cmd)
}

/// With `OPENFEO_TRACE` set, udhcpc's own account of the run goes to stderr.
fn trace_udhcpc(status: std::process::ExitStatus, stderr: &[u8]) {
    if std::env::var_os("OPENFEO_TRACE").is_some() {
        eprintln!(
            "udhcpc {status:?}: {}",
            String::from_utf8_lossy(stderr).trim()
        );
    }
}

/// Group `udhcpc-env k=v` lines under the `udhcpc-event <kind>` line before them.
#[must_use]
pub fn parse_udhcpc_output(stdout: &str) -> Vec<UdhcpcEvent> {
    let mut events: Vec<UdhcpcEvent> = Vec::new();
    for line in stdout.lines() {
        if let Some(kind) = line.strip_prefix("udhcpc-event ") {
            events.push(UdhcpcEvent {
                kind: kind.trim().to_owned(),
                env: BTreeMap::new(),
            });
        } else if let Some(pair) = line.strip_prefix("udhcpc-env ")
            && let Some((key, value)) = pair.split_once('=')
            && let Some(event) = events.last_mut()
        {
            event.env.insert(key.to_owned(), value.to_owned());
        }
    }
    events
}

/// Run `cmd` with captured output, killing it after `timeout`.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<std::process::Output> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let rendered = format!(
        "{} {}",
        cmd.get_program().to_string_lossy(),
        cmd.get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut child = cmd.spawn().with_context(|| format!("spawn {rendered}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output()?;
            bail!(
                "{rendered} timed out after {timeout:?}; stdout so far: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child
        .wait_with_output()
        .with_context(|| format!("collect {rendered}"))
}

/// What a reference SNTP client (`ntpdate -q`) reported about one server.
#[derive(Debug, Clone, PartialEq)]
pub struct NtpReply {
    pub server: Ipv4Addr,
    /// The server's clock minus the client's, in seconds.
    pub offset_s: f64,
    /// The round trip, when the client prints one (ntp.org's does, ntpsec's does not).
    pub delay_s: Option<f64>,
    pub stratum: u8,
}

/// `ntpdate -q <server>` inside `ns`: query only, never set the clock. Both implementations
/// are served, ntp.org's (`ntp` on Arch) and ntpsec's wrapper around `ntpdig`
/// (`ntpsec-ntpdate` on Debian and Ubuntu); each prints the server, its stratum and the offset,
/// and refuses an unsynchronised server (`no server suitable for synchronization found`),
/// which is an error here.
///
/// # Errors
///
/// When ntpdate cannot be run, outlives `timeout`, or prints no reply it accepted.
pub fn ntpdate_query(ns: &NetNs, server: Ipv4Addr, timeout: Duration) -> Result<NtpReply> {
    let mut cmd = ns.command("ntpdate")?;
    cmd.args(["-q", &server.to_string()]);
    let output = run_with_timeout(&mut cmd, timeout)?;
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_ntpdate(&text)
        .with_context(|| format!("ntpdate -q {server}: no reply parsed from: {}", text.trim()))
}

/// The reply line of either `ntpdate`: ntp.org's `server 192.168.1.1, stratum 3, offset
/// +7200.000003, delay 0.02567`, or ntpsec's (and `sntp`'s) `2026-10-31 23:29:30.681928 (+0000)
/// +7200.000020 +/- 0.000079 192.168.1.1 s3 no-leap`.
#[must_use]
pub fn parse_ntpdate(output: &str) -> Option<NtpReply> {
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("server ") {
            let mut parts = rest.split(',').map(str::trim);
            let server = parts.next()?.parse().ok()?;
            let (mut stratum, mut offset, mut delay) = (None, None, None);
            for part in parts {
                if let Some(value) = part.strip_prefix("stratum ") {
                    stratum = value.parse().ok();
                } else if let Some(value) = part.strip_prefix("offset ") {
                    offset = value.parse().ok();
                } else if let Some(value) = part.strip_prefix("delay ") {
                    delay = value.parse().ok();
                }
            }
            return Some(NtpReply {
                server,
                offset_s: offset?,
                delay_s: delay,
                stratum: stratum?,
            });
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = tokens.iter().position(|token| *token == "+/-")
            && pos >= 1
        {
            let offset_s = tokens[pos - 1].parse().ok()?;
            let server = tokens.get(pos + 2)?.parse().ok()?;
            let stratum = tokens.get(pos + 3)?.strip_prefix('s')?.parse().ok()?;
            return Some(NtpReply {
                server,
                offset_s,
                delay_s: None,
                stratum,
            });
        }
    }
    None
}

/// One raw SNTP request to `server` from inside `ns`, the reply decoded: the exact leap, stratum
/// and timestamps a client sees, which busybox hides.
///
/// # Errors
///
/// When the namespace cannot be entered, nothing comes back within `timeout`, or the reply is
/// not a packet.
pub fn sntp_query(ns: &NetNs, server: Ipv4Addr, timeout: Duration) -> Result<Packet> {
    let ns_file = File::open(ns.path()).with_context(|| format!("open {}", ns.path().display()))?;
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> Result<Packet> {
                setns(&ns_file, CloneFlags::CLONE_NEWNET).context("setns")?;
                let socket = UdpSocket::bind("0.0.0.0:0").context("bind")?;
                socket.set_read_timeout(Some(timeout))?;
                let request = Packet {
                    version: 4,
                    mode: 3,
                    transmit: NtpTimestamp(0x0102_0304_0506_0708),
                    ..Packet::default()
                };
                socket
                    .send_to(&request.encode(), SocketAddrV4::new(server, 123))
                    .context("send request")?;
                let mut buf = [0u8; 512];
                let (len, _) = socket
                    .recv_from(&mut buf)
                    .with_context(|| format!("no SNTP reply from {server}"))?;
                Packet::decode(&buf[..len]).context("decode reply")
            })
            .join()
            .map_err(|_| anyhow::anyhow!("sntp thread panicked"))?
    })
}

/// What `dig` reported: the status, the header flags, and the answer section as
/// `(name, ttl, type, rdata)` rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigAnswer {
    /// `NOERROR`, `NXDOMAIN`, `REFUSED`, `SERVFAIL`, ...
    pub status: String,
    /// `qr`, `aa`, `tc`, `rd`, `ra`, ... as dig prints them.
    pub flags: Vec<String>,
    pub answers: Vec<(String, u32, String, String)>,
}

/// `dig @<server> +time=2 +tries=1 +noall +comments +answer <extra> <name> <qtype>` from inside
/// `ns`. A dig that gets no answer at all (its own timeout) is an error, as is one that cannot
/// be run or outlives `timeout`.
///
/// # Errors
///
/// When dig cannot be run, times out, or prints no header.
pub fn dig(
    ns: &NetNs,
    server: Ipv4Addr,
    name: &str,
    qtype: &str,
    extra: &[&str],
    timeout: Duration,
) -> Result<DigAnswer> {
    let mut cmd = ns.command("dig")?;
    cmd.arg(format!("@{server}"))
        .args(["+time=2", "+tries=1", "+noall", "+comments", "+answer"])
        .args(extra)
        .args([name, qtype]);
    let output = run_with_timeout(&mut cmd, timeout)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_dig(&stdout).with_context(|| {
        format!(
            "dig {name} {qtype} @{server}: {}",
            if stdout.trim().is_empty() {
                String::from_utf8_lossy(&output.stderr).trim().to_owned()
            } else {
                stdout.trim().to_owned()
            }
        )
    })
}

/// dig's `+noall +comments +answer` output: the last header's status and flags (a TCP retry
/// prints two), and every answer row.
///
/// # Errors
///
/// When there is no header line (dig got no answer).
pub fn parse_dig(stdout: &str) -> Result<DigAnswer> {
    let mut status = None;
    let mut flags = Vec::new();
    let mut answers = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix(";; ->>HEADER<<-") {
            status = rest
                .split(',')
                .map(str::trim)
                .find_map(|part| part.strip_prefix("status: "))
                .map(str::to_owned);
            answers.clear();
        } else if let Some(rest) = line.strip_prefix(";; flags:") {
            flags = rest
                .split(';')
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_owned)
                .collect();
        } else if !line.starts_with(';') && !line.trim().is_empty() {
            // Fields are separated by runs of tabs (dig pads short names); the RDATA keeps its
            // own spacing (TXT strings).
            let mut rest = line;
            let (Some(name), Some(ttl), Some(_class), Some(rtype)) = (
                take_field(&mut rest),
                take_field(&mut rest),
                take_field(&mut rest),
                take_field(&mut rest),
            ) else {
                bail!("dig answer row has too few fields: {line:?}");
            };
            let ttl = ttl
                .parse::<u32>()
                .with_context(|| format!("dig answer row TTL: {line:?}"))?;
            answers.push((
                name.to_owned(),
                ttl,
                rtype.to_owned(),
                rest.trim().to_owned(),
            ));
        }
    }
    let status = status.with_context(|| format!("dig printed no header: {}", stdout.trim()))?;
    Ok(DigAnswer {
        status,
        flags,
        answers,
    })
}

/// The next whitespace-delimited field of `rest`, advancing past it; `None` when the line has
/// no further field followed by whitespace.
fn take_field<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let trimmed = rest.trim_start();
    let end = trimmed.find(char::is_whitespace)?;
    let (field, after) = trimmed.split_at(end);
    *rest = after;
    Some(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ping_summary() {
        let output = "PING 203.0.113.1 (203.0.113.1) 56(84) bytes of data.\n\
                      64 bytes from 203.0.113.1: icmp_seq=1 ttl=63 time=0.4 ms\n\n\
                      --- 203.0.113.1 ping statistics ---\n\
                      5 packets transmitted, 4 received, 20% packet loss, time 804ms\n";
        let stats = parse_ping_summary(output).unwrap();
        assert_eq!((stats.sent, stats.received), (5, 4));
        assert!(parse_ping_summary("no summary here").is_none());
    }

    #[test]
    fn http_body_after_headers() {
        assert_eq!(
            body_of(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc"),
            Some("abc")
        );
        assert_eq!(body_of(b"HTTP/1.0 200 OK\r\n\r\n"), Some(""));
        assert_eq!(body_of(b"HTTP/1.0 200 OK\r\nno blank line"), None);
    }
}

#[cfg(test)]
mod dhcp_client_tests {
    use super::*;

    #[test]
    fn udhcpc_output_groups_env_under_events() {
        let out = "udhcpc-event deconfig\nudhcpc-env interface=s1\nudhcpc-event bound\nudhcpc-env ip=192.168.1.100\nudhcpc-env router=192.168.1.1\nudhcpc-env dns=192.168.1.1\nudhcpc-env domain=home.arpa\nudhcpc-env lease=43200\n";
        let events = parse_udhcpc_output(out);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "deconfig");
        assert_eq!(events[1].kind, "bound");
        assert_eq!(events[1].env["ip"], "192.168.1.100");
        assert_eq!(events[1].env["domain"], "home.arpa");
        assert_eq!(events[1].env.len(), 5);
    }

    #[test]
    fn json_lines_parse_and_reject_junk() {
        let lines = parse_json_lines(
            "{\"event\":\"discover\"}\n{\"event\":\"bound\",\"address\":\"192.168.1.100\"}\n\n",
        )
        .unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["address"], "192.168.1.100");
        assert!(parse_json_lines("not json\n").is_err());
    }
}

#[cfg(test)]
mod dns_client_tests {
    use super::*;

    #[test]
    fn dig_output_parses_status_flags_and_answers() {
        let out = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41696\n;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1\n; EDNS: version: 0, flags:; udp: 1232\nwww.isp.example.\t60\tIN\tA\t198.51.100.10\n";
        let parsed = parse_dig(out).unwrap();
        assert_eq!(parsed.status, "NOERROR");
        assert_eq!(parsed.flags, vec!["qr", "aa", "rd"]);
        assert_eq!(
            parsed.answers,
            vec![(
                "www.isp.example.".into(),
                60,
                "A".into(),
                "198.51.100.10".into()
            )]
        );
        assert!(parse_dig(";; connection timed out; no servers could be reached\n").is_err());
    }

    /// dig that fell back to TCP prints two headers: the answer is the last one's.
    #[test]
    fn dig_output_keeps_the_last_header_and_joins_txt_strings() {
        let out = ";; Truncated, retrying in TCP mode.\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; flags: qr tc rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2\n;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\nbig.isp.example.\t60\tIN\tTXT\t\"aaa\" \"bbb\"\nbig.isp.example.\t60\tIN\tTXT\t\"ccc\"\n";
        let parsed = parse_dig(out).unwrap();
        assert_eq!(parsed.flags, vec!["qr", "rd", "ra"]);
        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.answers[0].3, "\"aaa\" \"bbb\"");
    }

    #[test]
    fn ntpdate_output_parses_both_the_classic_and_the_ntpsec_lines() {
        let classic = "server 192.168.1.1, stratum 3, offset +7200.000003, delay 0.02567\n31 Oct 21:30:43 ntpdate[1394612]: step time server 192.168.1.1 offset +7200.000003 sec\n";
        assert_eq!(
            parse_ntpdate(classic),
            Some(NtpReply {
                server: "192.168.1.1".parse().unwrap(),
                offset_s: 7_200.000_003,
                delay_s: Some(0.025_67),
                stratum: 3,
            })
        );
        let ntpsec =
            "2026-10-31 23:29:30.681928 (+0000) +7200.000020 +/- 0.000079 192.168.1.1 s3 no-leap\n";
        assert_eq!(
            parse_ntpdate(ntpsec),
            Some(NtpReply {
                server: "192.168.1.1".parse().unwrap(),
                offset_s: 7_200.000_02,
                delay_s: None,
                stratum: 3,
            })
        );
        assert_eq!(
            parse_ntpdate(
                "31 Oct 21:30:46 ntpdate[1394649]: no server suitable for synchronization found\n"
            ),
            None
        );
    }

    /// dig pads short owner names with a second tab.
    #[test]
    fn dig_output_rows_with_padded_names_parse() {
        let out = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3\n;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\nnas.home.arpa.\t\t60\tIN\tA\t192.168.1.10\n";
        let parsed = parse_dig(out).unwrap();
        assert_eq!(
            parsed.answers,
            vec![(
                "nas.home.arpa.".into(),
                60,
                "A".into(),
                "192.168.1.10".into()
            )]
        );
    }
}
