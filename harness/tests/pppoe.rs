// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The PPPoE drivers (`openfeo-net::pppoe`) inside the rootless sandbox, no QEMU: the discovery
//! core (`openfeo-proto-ppp::discovery`) over the discovery socket against a scripted access
//! concentrator on the far end of a veth pair (the same socket type, answering with
//! codec-built PADO and PADS frames), and the `/dev/ppp` plumbing where the kernel offers it
//! (CI loads the PPP modules and opens `/dev/ppp`; a host without them skips with the udev
//! rule to add). The real access concentrator (`pppoe-server`) and the session core over a
//! live unit are part 2's scenarios. `harness = false`: this binary is its own runner; an
//! optional first argument filters scenarios by substring.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use openfeo_harness::daemons::{self, Auth, PppoeServerConfig};
use openfeo_harness::lab::Lab;
use openfeo_harness::lanclient::{link_info, link_info_in};
use openfeo_harness::netns::{self, NetNs};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, Skip, run_all};
use openfeo_net::pppoe::{Discovery, Session, dev_ppp_unavailable};
use openfeo_proto_ppp::Timestamp;
use openfeo_proto_ppp::discovery::{Client, Config, Input, Output, Reason};
use openfeo_proto_ppp::lcp::AuthProto;
use openfeo_proto_ppp::pppoe::{self, BROADCAST, Code, Tag};
use openfeo_proto_ppp::session::{
    self, Input as PppInput, Output as PppOutput, Reason as PppReason,
};
use tokio::runtime::Runtime;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "discovery_binds_a_session_against_a_scripted_ac",
        run: discovery_binds_a_session_against_a_scripted_ac,
    },
    Scenario {
        name: "a_padt_from_the_ac_closes_the_client",
        run: a_padt_from_the_ac_closes_the_client,
    },
    Scenario {
        name: "session_attach_makes_a_unit_netdev",
        run: session_attach_makes_a_unit_netdev,
    },
    Scenario {
        name: "pppoe_server_answers_discovery_in_the_sandbox",
        run: pppoe_server_answers_discovery_in_the_sandbox,
    },
    Scenario {
        name: "lcp_pap_and_ipcp_bring_ipv4_up_over_pppd",
        run: lcp_pap_and_ipcp_bring_ipv4_up_over_pppd,
    },
    Scenario {
        name: "chap_authenticates_too",
        run: chap_authenticates_too,
    },
    Scenario {
        name: "a_wrong_password_is_auth_failed_with_pppds_message",
        run: a_wrong_password_is_auth_failed_with_pppds_message,
    },
    Scenario {
        name: "pppoe_server_killed_is_keepalive_lost_within_forty_seconds",
        run: pppoe_server_killed_is_keepalive_lost_within_forty_seconds,
    },
    Scenario {
        name: "pppoe_server_stopped_by_sigterm_is_terminated_by_peer",
        run: pppoe_server_stopped_by_sigterm_is_terminated_by_peer,
    },
    Scenario {
        name: "a_padt_from_the_ac_ends_the_session",
        run: a_padt_from_the_ac_ends_the_session,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("cannot enter the sandbox: {err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

/// The near end of the veth pair: the WAN port the client discovers on.
const CLIENT_IF: &str = "e0";
/// The far end, where the scripted access concentrator listens.
const AC_IF: &str = "e1";
const AC_NAME: &str = "ac.example";
const AC_COOKIE: &[u8] = b"cookie-0123456789";
const SESSION_ID: u16 = 0x0042;
const SOON: Duration = Duration::from_secs(10);

fn runtime() -> anyhow::Result<Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

fn millis(start: Instant) -> Timestamp {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The veth pair, both ends up, with each end's index and MAC.
struct Rig {
    client: (u32, [u8; 6]),
    ac: (u32, [u8; 6]),
    start: Instant,
    /// The ISP's namespace holding the far end, for the scenarios whose server runs a session.
    isp: Option<NetNs>,
}

impl Rig {
    fn create() -> anyhow::Result<Self> {
        let _ = netns::ip(&["link", "del", CLIENT_IF]);
        netns::ip(&[
            "link", "add", CLIENT_IF, "type", "veth", "peer", "name", AC_IF,
        ])?;
        netns::ip(&["link", "set", AC_IF, "up"])?;
        netns::ip(&["link", "set", CLIENT_IF, "up"])?;
        Ok(Rig {
            client: link_info(CLIENT_IF)?,
            ac: link_info(AC_IF)?,
            start: Instant::now(),
            isp: None,
        })
    }

    /// The pair with the far end moved into an ISP namespace of its own, so the ISP's PPP unit
    /// and address live apart from ours and traffic crosses the link.
    fn create_isp(lab: &Lab) -> anyhow::Result<Self> {
        let _ = netns::ip(&["link", "del", CLIENT_IF]);
        netns::ip(&[
            "link", "add", CLIENT_IF, "type", "veth", "peer", "name", AC_IF,
        ])?;
        let ns = NetNs::create(&format!("{}-pppoe", lab.name()))?;
        netns::ip(&["link", "set", AC_IF, "netns", &ns.name])?;
        ns.ip(&["link", "set", "lo", "up"])?;
        ns.ip(&["link", "set", AC_IF, "up"])?;
        netns::ip(&["link", "set", CLIENT_IF, "up"])?;
        Ok(Rig {
            client: link_info(CLIENT_IF)?,
            ac: link_info_in(&ns, AC_IF)?,
            start: Instant::now(),
            isp: Some(ns),
        })
    }

    /// The access concentrator on the far end, in the ISP namespace when there is one.
    fn server(&self, lab: &Lab, config: &PppoeServerConfig) -> anyhow::Result<daemons::Daemon> {
        match &self.isp {
            Some(ns) => daemons::pppoe_server(ns, config, &lab.run_dir),
            None => daemons::pppoe_server_in_sandbox(config, &lab.run_dir),
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = netns::ip(&["link", "del", CLIENT_IF]);
    }
}

/// What the scripted access concentrator saw and answered.
#[derive(Debug, Default)]
struct AcLog {
    padi: usize,
    padr: usize,
    /// The PPP-Max-Payload the PADI asked for.
    padi_max_payload: Option<u16>,
    /// Whether the PADR echoed our cookie, and the payload it echoed.
    padr_cookie_echoed: bool,
    padr_max_payload: Option<u16>,
    padr_host_uniq: Option<Vec<u8>>,
}

/// The access concentrator's answer to one discovery frame: a PADO to a PADI, a PADS to a PADR
/// that echoes the cookie, nothing to anything else.
fn ac_answer(log: &mut AcLog, packet: &pppoe::Discovery) -> Option<Vec<u8>> {
    let host_uniq = packet.tag(|tag| match tag {
        Tag::HostUniq(bytes) => Some(bytes.clone()),
        _ => None,
    })?;
    match packet.code {
        Code::Padi => {
            log.padi += 1;
            log.padi_max_payload = packet.tag(|tag| match tag {
                Tag::PppMaxPayload(size) => Some(*size),
                _ => None,
            });
            Some(
                pppoe::Discovery {
                    code: Code::Pado,
                    session_id: 0,
                    tags: vec![
                        Tag::ServiceName(String::new()),
                        Tag::AcName(AC_NAME.to_owned()),
                        Tag::HostUniq(host_uniq),
                        Tag::AcCookie(AC_COOKIE.to_vec()),
                        Tag::PppMaxPayload(1500),
                    ],
                }
                .encode(),
            )
        }
        Code::Padr => {
            log.padr += 1;
            log.padr_cookie_echoed = packet
                .tag(|tag| match tag {
                    Tag::AcCookie(bytes) => Some(bytes == AC_COOKIE),
                    _ => None,
                })
                .unwrap_or(false);
            log.padr_max_payload = packet.tag(|tag| match tag {
                Tag::PppMaxPayload(size) => Some(*size),
                _ => None,
            });
            log.padr_host_uniq = Some(host_uniq.clone());
            if !log.padr_cookie_echoed {
                return None;
            }
            Some(
                pppoe::Discovery {
                    code: Code::Pads,
                    session_id: SESSION_ID,
                    tags: vec![
                        Tag::ServiceName(String::new()),
                        Tag::HostUniq(host_uniq),
                        Tag::PppMaxPayload(1500),
                    ],
                }
                .encode(),
            )
        }
        _ => None,
    }
}

/// The client core on the near socket and the scripted access concentrator on the far one, run
/// together until `done` holds for a client output or `timeout` passes; the client outputs
/// seen, in order.
struct Bench {
    near: Discovery,
    /// The scripted access concentrator's socket; `None` when a real one answers.
    far: Option<Discovery>,
    client: Client,
    start: Instant,
    pending: Vec<Output>,
    log: AcLog,
    near_buf: Vec<u8>,
    far_buf: Vec<u8>,
}

impl Bench {
    /// Both sockets open and the client started (a PADI pending). Call inside the runtime.
    fn start(rig: &Rig, max_payload: Option<u16>) -> anyhow::Result<Self> {
        let far = Discovery::open(rig.ac.0, AC_IF)?;
        Self::with_far(rig, max_payload, Some(far))
    }

    /// The client alone: a real access concentrator answers on the far end.
    fn start_client_only(rig: &Rig, max_payload: Option<u16>) -> anyhow::Result<Self> {
        Self::with_far(rig, max_payload, None)
    }

    fn with_far(
        rig: &Rig,
        max_payload: Option<u16>,
        far: Option<Discovery>,
    ) -> anyhow::Result<Self> {
        let near = Discovery::open(rig.client.0, CLIENT_IF)?;
        let mut client = Client::new(
            Config {
                service: None,
                ac: None,
                max_payload,
            },
            0x5eed,
        );
        let pending = client.handle(Input::Start, millis(rig.start));
        Ok(Bench {
            near,
            far,
            client,
            start: rig.start,
            pending,
            log: AcLog::default(),
            near_buf: vec![0u8; 1600],
            far_buf: vec![0u8; 1600],
        })
    }

    fn feed(&mut self, input: Input) {
        let now = millis(self.start);
        let outputs = self.client.handle(input, now);
        self.pending.extend(outputs);
    }

    async fn run_until(
        &mut self,
        timeout: Duration,
        mut done: impl FnMut(&Output) -> bool,
    ) -> anyhow::Result<Vec<Output>> {
        let deadline = Instant::now() + timeout;
        let mut seen = Vec::new();
        loop {
            while !self.pending.is_empty() {
                let output = self.pending.remove(0);
                if let Output::Send { to, bytes } = &output {
                    self.near.send(*to, bytes)?;
                }
                let finished = done(&output);
                seen.push(output);
                if finished {
                    return Ok(seen);
                }
            }
            ensure!(
                Instant::now() < deadline,
                "timed out after {timeout:?}; outputs so far: {seen:?}; ac saw {:?}",
                self.log
            );
            let timer = self
                .client
                .next_timeout()
                .map_or(deadline, |at| self.start + Duration::from_millis(at))
                .min(deadline);
            tokio::select! {
                received = self.near.recv(&mut self.near_buf) => {
                    let (from, len) = received?;
                    let bytes = self.near_buf[..len].to_vec();
                    self.feed(Input::Packet { from, bytes });
                }
                received = recv_far(self.far.as_ref(), &mut self.far_buf) => {
                    let (from, len) = received?;
                    let packet = pppoe::Discovery::decode(&self.far_buf[..len])
                        .context("the ac decodes the client's frame")?;
                    if let Some(reply) = ac_answer(&mut self.log, &packet) {
                        self.far.as_ref().context("a scripted ac")?.send(from, &reply)?;
                    }
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(timer)) => {
                    self.feed(Input::Timeout);
                }
            }
        }
    }

    /// A PADT for the session from the access concentrator to the client.
    fn far_padt(&self, to: [u8; 6]) -> anyhow::Result<()> {
        let padt = pppoe::Discovery {
            code: Code::Padt,
            session_id: SESSION_ID,
            tags: vec![],
        }
        .encode();
        Ok(self
            .far
            .as_ref()
            .context("a scripted ac")?
            .send(to, &padt)?)
    }
}

/// The far socket's next frame, or never when there is no far socket.
async fn recv_far(
    far: Option<&Discovery>,
    buf: &mut [u8],
) -> Result<([u8; 6], usize), openfeo_net::dhcp4::DriverError> {
    match far {
        Some(far) => far.recv(buf).await,
        None => std::future::pending().await,
    }
}

/// `/dev/ppp` opens read-write, or the scenario skips with the udev rule to add.
fn require_dev_ppp() -> anyhow::Result<()> {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/ppp")
    {
        Ok(_) => Ok(()),
        Err(err) => Err(Skip(format!(
            "/dev/ppp: {err}: load ppp_generic and make it group-accessible \
             (udev: KERNEL==\"ppp\", GROUP=\"<your group>\", MODE=\"0660\")"
        ))
        .into()),
    }
}

fn is_session(output: &Output) -> bool {
    matches!(output, Output::Session { .. })
}

/// PADI (broadcast, with Host-Uniq and PPP-Max-Payload 1500), PADO from the far end with its
/// name, a cookie and the payload tag, PADR back with the cookie and the tag echoed, PADS with
/// the session id: the client reports the session with the far end's MAC, its name and the
/// payload it granted.
fn discovery_binds_a_session_against_a_scripted_ac(_lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create()?;
    runtime()?.block_on(async {
        let mut bench = Bench::start(&rig, Some(1500))?;
        let outputs = bench.run_until(SOON, is_session).await?;
        let session = outputs.last().context("a last output")?;
        ensure!(
            *session
                == Output::Session {
                    id: SESSION_ID,
                    ac_mac: rig.ac.1,
                    ac_name: AC_NAME.to_owned(),
                    max_payload: Some(1500),
                },
            "the session as reported: {session:?}"
        );
        let first_send = outputs.iter().find_map(|output| match output {
            Output::Send { to, .. } => Some(*to),
            _ => None,
        });
        ensure!(
            first_send == Some(BROADCAST),
            "the PADI goes to the broadcast address, not {first_send:?}"
        );
        ensure!(
            bench.log.padi == 1 && bench.log.padr == 1,
            "one PADI and one PADR: {:?}",
            bench.log
        );
        ensure!(
            bench.log.padi_max_payload == Some(1500),
            "the PADI asks for a 1500-byte payload: {:?}",
            bench.log
        );
        ensure!(bench.log.padr_cookie_echoed, "the PADR echoes the cookie");
        ensure!(
            bench.log.padr_max_payload == Some(1500),
            "the PADR echoes the payload tag the PADO allowed: {:?}",
            bench.log
        );
        ensure!(
            bench.log.padr_host_uniq.as_deref() == Some(&bench.client.host_uniq()[..]),
            "the PADR carries the client's Host-Uniq"
        );
        anyhow::Ok(())
    })
}

/// A PADT from the access concentrator for the bound session closes the client, which reports
/// `Closed(Padt)` and sends nothing more until started again.
fn a_padt_from_the_ac_closes_the_client(_lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create()?;
    runtime()?.block_on(async {
        let mut bench = Bench::start(&rig, None)?;
        bench.run_until(SOON, is_session).await?;
        bench.far_padt(rig.client.1)?;
        let outputs = bench
            .run_until(SOON, |output| matches!(output, Output::Closed(_)))
            .await?;
        ensure!(
            outputs.last() == Some(&Output::Closed(Reason::Padt)),
            "closed by the PADT: {outputs:?}"
        );
        ensure!(
            !outputs
                .iter()
                .any(|output| matches!(output, Output::Send { .. })),
            "nothing is sent in answer to a PADT: {outputs:?}"
        );
        anyhow::Ok(())
    })
}

/// Where `/dev/ppp` can be opened and the PPP modules are there, attaching a session makes the
/// kernel create a unit whose netdev is `ppp<unit>`, and dropping the session removes it
/// (ADR-0023). Elsewhere the scenario skips with the udev rule to add.
fn session_attach_makes_a_unit_netdev(_lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create()?;
    runtime()?.block_on(async {
        let session = match Session::attach(CLIENT_IF, SESSION_ID, rig.ac.1) {
            Ok(session) => session,
            Err(err) if dev_ppp_unavailable(&err) => {
                return Err(Skip(format!(
                    "{err}: load ppp_generic and pppoe and make /dev/ppp group-accessible \
                     (udev: KERNEL==\"ppp\", GROUP=\"<your group>\", MODE=\"0660\")"
                ))
                .into());
            }
            Err(err) => return Err(err.into()),
        };
        let name = format!("ppp{}", session.unit());
        let shown = netns::ip(&["-o", "link", "show", &name])
            .with_context(|| format!("the unit's netdev {name}"))?;
        ensure!(shown.contains(&name), "ip shows {shown}");
        drop(session);
        let deadline = Instant::now() + SOON;
        while netns::ip(&["-o", "link", "show", &name]).is_ok() {
            ensure!(
                Instant::now() < deadline,
                "{name} is still there after the session was dropped"
            );
            thread::sleep(Duration::from_millis(50));
        }
        anyhow::Ok(())
    })
}

/// rp-pppoe's server, as the sandbox's mapped root on the far veth end, answers our discovery
/// with a session: the lab's access concentrator exists and part 2 can rest on it.
fn pppoe_server_answers_discovery_in_the_sandbox(lab: &mut Lab) -> anyhow::Result<()> {
    require_dev_ppp()?;
    let rig = Rig::create()?;
    let config = PppoeServerConfig::isp(AC_IF, Auth::None);
    let _server = daemons::pppoe_server_in_sandbox(&config, &lab.run_dir)?;
    runtime()?.block_on(async {
        let mut bench = Bench::start_client_only(&rig, None)?;
        let outputs = bench.run_until(SOON, is_session).await?;
        let Some(Output::Session {
            id,
            ac_mac,
            ac_name,
            max_payload,
        }) = outputs.last()
        else {
            anyhow::bail!("no session: {outputs:?}");
        };
        ensure!(
            *ac_mac == rig.ac.1,
            "the session is with the far end: {outputs:?}"
        );
        ensure!(ac_name == "isp", "the server's name: {ac_name}");
        ensure!(*id != 0, "a session id");
        ensure!(
            max_payload.is_none(),
            "rp-pppoe offers no RFC 4638 payload: {max_payload:?}"
        );
        anyhow::Ok(())
    })
}

/// The session core on the kernel's PPP descriptors, run by the scenario against `pppd`: what
/// the WAN task in `crates/openfeo` does, without the World around it.
struct PppBench {
    kernel: Session,
    core: session::Session,
    near: Discovery,
    dclient: Client,
    start: Instant,
    pending: Vec<PppOutput>,
    buf: Vec<u8>,
    dbuf: Vec<u8>,
    /// The access concentrator's PADT arrived on the discovery socket.
    padt_seen: bool,
    /// When the session's `Down` came, if it has.
    down_at: Option<Instant>,
    /// The PPPoE session id discovery bound.
    session_id: u16,
    log: std::path::PathBuf,
}

impl PppBench {
    /// Discovery against the server until a session, the kernel session attached, PPP started.
    async fn connect(rig: &Rig, lab: &Lab, config: session::Config) -> anyhow::Result<Self> {
        let mut bench = Bench::start_client_only(rig, None)?;
        let outputs = bench.run_until(SOON, is_session).await?;
        let Some(Output::Session { id, ac_mac, .. }) = outputs.last() else {
            anyhow::bail!("no session: {outputs:?}");
        };
        let kernel = Session::attach(CLIENT_IF, *id, *ac_mac)?;
        let mut core = session::Session::new(config, 0x5eed);
        let start = Instant::now();
        let pending = core.handle(PppInput::Start, 0);
        Ok(PppBench {
            kernel,
            core,
            near: bench.near,
            dclient: bench.client,
            start,
            pending,
            buf: vec![0u8; 2048],
            dbuf: vec![0u8; 1600],
            padt_seen: false,
            down_at: None,
            session_id: *id,
            log: daemons::pppd_log_path(&lab.run_dir, AC_IF),
        })
    }

    fn feed(&mut self, input: PppInput) {
        let outputs = self.core.handle(input, millis(self.start));
        self.pending.extend(outputs);
    }

    /// Act on every output until `done` holds for one or `timeout` passes; the outputs seen.
    async fn run_until(
        &mut self,
        timeout: Duration,
        mut done: impl FnMut(&PppOutput) -> bool,
    ) -> anyhow::Result<Vec<PppOutput>> {
        let deadline = Instant::now() + timeout;
        let mut seen = Vec::new();
        loop {
            while !self.pending.is_empty() {
                let output = self.pending.remove(0);
                match &output {
                    PppOutput::Send { protocol, payload } => {
                        // A refused write is the core's to retransmit.
                        let _ = self.kernel.send(*protocol, payload);
                    }
                    PppOutput::Mru(mru) => self.kernel.set_mru(*mru)?,
                    PppOutput::Down { .. } => self.down_at = Some(Instant::now()),
                    _ => {}
                }
                let finished = done(&output);
                seen.push(output);
                if finished {
                    return Ok(seen);
                }
            }
            if Instant::now() >= deadline {
                let log = std::fs::read_to_string(&self.log).unwrap_or_default();
                let tail: Vec<&str> = log.lines().rev().take(20).collect();
                anyhow::bail!(
                    "timed out after {timeout:?}; outputs: {seen:?}; pppd's log, last lines first: {tail:?}"
                );
            }
            let timer = self
                .core
                .next_timeout()
                .map_or(deadline, |at| self.start + Duration::from_millis(at))
                .min(deadline);
            tokio::select! {
                received = self.kernel.recv(&mut self.buf) => match received {
                    Ok((protocol, len)) => {
                        let payload = self.buf[..len].to_vec();
                        self.feed(PppInput::Frame { protocol, payload });
                    }
                    Err(_) => self.feed(PppInput::CarrierLost),
                },
                received = self.near.recv(&mut self.dbuf) => {
                    let (from, len) = received?;
                    let bytes = self.dbuf[..len].to_vec();
                    let outputs = self.dclient.handle(Input::Packet { from, bytes }, millis(self.start));
                    if outputs.contains(&Output::Closed(Reason::Padt)) {
                        self.padt_seen = true;
                        self.feed(PppInput::CarrierLost);
                    }
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(timer)) => {
                    self.feed(PppInput::Timeout);
                }
            }
        }
    }

    /// The kernel's name for our unit.
    fn ifname(&self) -> String {
        format!("ppp{}", self.kernel.unit())
    }
}

fn session_config(username: &str, password: &str, mru: u16) -> session::Config {
    session::Config {
        username: username.to_owned(),
        password: password.as_bytes().to_vec(),
        mru,
        secret: [7; 16],
        wan: "wan0".to_owned(),
    }
}

fn has(outputs: &[PppOutput], what: impl Fn(&PppOutput) -> bool) -> bool {
    outputs.iter().any(what)
}

fn is_ipv4_up(output: &PppOutput) -> bool {
    matches!(output, PppOutput::Ipv4Up(_))
}

fn is_down(output: &PppOutput) -> bool {
    matches!(output, PppOutput::Down { .. })
}

fn down_reason(outputs: &[PppOutput]) -> Option<&PppReason> {
    outputs.iter().find_map(|output| match output {
        PppOutput::Down { reason, .. } => Some(reason),
        _ => None,
    })
}

/// `ping -c <count>` from this namespace out of `ifname`; how many answered.
fn ping_out(ifname: &str, target: &str, count: u32) -> anyhow::Result<u32> {
    let output = std::process::Command::new("ping")
        .args([
            "-n",
            "-c",
            &count.to_string(),
            "-W",
            "1",
            "-i",
            "0.2",
            "-I",
            ifname,
            target,
        ])
        .output()
        .context("run ping")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let received = text
        .lines()
        .find_map(|line| {
            let (_, rest) = line.split_once("transmitted, ")?;
            rest.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or(0);
    Ok(received)
}

/// Bring our unit up with the address IPCP gave, as the routing applier would, and ping the
/// ISP across it.
fn ping_across(bench: &PppBench, local: std::net::Ipv4Addr) -> anyhow::Result<u32> {
    let ifname = bench.ifname();
    netns::ip(&[
        "addr",
        "add",
        &local.to_string(),
        "peer",
        &format!("{}/32", daemons::PPP_ISP_ADDR),
        "dev",
        &ifname,
    ])?;
    netns::ip(&["link", "set", &ifname, "up"])?;
    ping_out(&ifname, daemons::PPP_ISP_ADDR, 3)
}

/// PADS, LCP (MRU 1492), PAP, IPCP: IPv4 up with the pool's first address, the ISP's as peer and
/// its resolver; the kernel's unit carries a ping to the ISP once it has the address.
fn lcp_pap_and_ipcp_bring_ipv4_up_over_pppd(lab: &mut Lab) -> anyhow::Result<()> {
    require_dev_ppp()?;
    let rig = Rig::create_isp(lab)?;
    let _server = rig.server(lab, &PppoeServerConfig::isp(AC_IF, Auth::Pap))?;
    runtime()?.block_on(async {
        let config = session_config(daemons::PPP_USERNAME, daemons::PPP_PASSWORD, 1492);
        let mut bench = PppBench::connect(&rig, lab, config).await?;
        let outputs = bench.run_until(Duration::from_secs(20), is_ipv4_up).await?;
        ensure!(
            has(&outputs, |o| matches!(
                o,
                PppOutput::LcpUp {
                    mru: 1492,
                    auth: Some(AuthProto::Pap),
                    ..
                }
            )),
            "{outputs:?}"
        );
        ensure!(
            has(&outputs, |o| *o == PppOutput::AuthOk("pap")),
            "{outputs:?}"
        );
        let Some(PppOutput::Ipv4Up(up)) = outputs.last() else {
            anyhow::bail!("{outputs:?}");
        };
        let isp: std::net::Ipv4Addr = daemons::PPP_ISP_ADDR.parse()?;
        ensure!(
            up.local == daemons::PPP_POOL_START.parse::<std::net::Ipv4Addr>()?,
            "{up:?}"
        );
        ensure!(up.peer == Some(isp) && up.dns == vec![isp], "{up:?}");
        ensure!(
            !format!("{:?}", bench.core).contains(daemons::PPP_PASSWORD),
            "the core's Debug redacts the password"
        );
        let answered = ping_across(&bench, up.local)?;
        ensure!(answered >= 1, "no echo reply across {}", bench.ifname());
        anyhow::Ok(())
    })
}

/// The same with `require-chap`: Challenge, Response, Success.
fn chap_authenticates_too(lab: &mut Lab) -> anyhow::Result<()> {
    require_dev_ppp()?;
    let rig = Rig::create_isp(lab)?;
    let _server = rig.server(lab, &PppoeServerConfig::isp(AC_IF, Auth::Chap))?;
    runtime()?.block_on(async {
        let config = session_config(daemons::PPP_USERNAME, daemons::PPP_PASSWORD, 1492);
        let mut bench = PppBench::connect(&rig, lab, config).await?;
        let outputs = bench.run_until(Duration::from_secs(20), is_ipv4_up).await?;
        ensure!(
            has(&outputs, |o| matches!(
                o,
                PppOutput::LcpUp {
                    auth: Some(AuthProto::ChapMd5),
                    ..
                }
            )),
            "{outputs:?}"
        );
        ensure!(
            has(&outputs, |o| *o == PppOutput::AuthOk("chap")),
            "{outputs:?}"
        );
        anyhow::Ok(())
    })
}

/// The session, as far as `until`: discovery, LCP, authentication with `password`, and on.
async fn up_over_pppd(
    rig: &Rig,
    lab: &Lab,
    password: &str,
    until: impl FnMut(&PppOutput) -> bool,
) -> anyhow::Result<(PppBench, Vec<PppOutput>)> {
    let config = session_config(daemons::PPP_USERNAME, password, 1492);
    let mut bench = PppBench::connect(rig, lab, config).await?;
    let outputs = bench.run_until(Duration::from_secs(20), until).await?;
    Ok((bench, outputs))
}

/// A wrong password: `pppd` refuses with its message, the session is down with
/// `auth failed: <message>`; PAP and CHAP both.
fn a_wrong_password_is_auth_failed_with_pppds_message(lab: &mut Lab) -> anyhow::Result<()> {
    require_dev_ppp()?;
    for auth in [Auth::Pap, Auth::Chap] {
        let rig = Rig::create_isp(lab)?;
        let mut server = rig.server(lab, &PppoeServerConfig::isp(AC_IF, auth))?;
        runtime()?.block_on(async {
            let (_bench, outputs) = up_over_pppd(&rig, lab, "not-the-secret", is_down).await?;
            let Some(PppReason::AuthFailed(message)) = down_reason(&outputs) else {
                anyhow::bail!("{auth:?}: not an auth failure: {outputs:?}");
            };
            ensure!(!message.is_empty(), "{auth:?}: pppd's message is carried");
            anyhow::Ok(())
        })?;
        server.signal(nix::sys::signal::Signal::SIGKILL);
    }
    Ok(())
}

/// The server and its `pppd` killed outright: nothing says goodbye, the router's three echoes go
/// unanswered, and the session is down with `keepalive lost` thirty to forty seconds later.
fn pppoe_server_killed_is_keepalive_lost_within_forty_seconds(lab: &mut Lab) -> anyhow::Result<()> {
    require_dev_ppp()?;
    let rig = Rig::create_isp(lab)?;
    let mut server = rig.server(lab, &PppoeServerConfig::isp(AC_IF, Auth::Pap))?;
    runtime()?.block_on(async {
        let (mut bench, _) = up_over_pppd(&rig, lab, daemons::PPP_PASSWORD, is_ipv4_up).await?;
        server.signal(nix::sys::signal::Signal::SIGKILL);
        let killed = Instant::now();
        let outputs = bench.run_until(Duration::from_secs(45), is_down).await?;
        let took = bench.down_at.map(|at| at - killed);
        ensure!(
            down_reason(&outputs) == Some(&PppReason::KeepaliveLost),
            "{outputs:?}"
        );
        ensure!(
            took.is_some_and(
                |took| took >= Duration::from_secs(25) && took <= Duration::from_secs(41)
            ),
            "keepalive lost after {took:?}"
        );
        anyhow::Ok(())
    })
}

/// SIGTERM to the server: `pppd` sends Terminate-Request, the session is down with `terminated
/// by peer`, IPv4 going down first; and when the ISP stops while IPCP is still negotiating, no
/// IPv4 is ever reported.
fn pppoe_server_stopped_by_sigterm_is_terminated_by_peer(lab: &mut Lab) -> anyhow::Result<()> {
    require_dev_ppp()?;
    let rig = Rig::create_isp(lab)?;
    let mut server = rig.server(lab, &PppoeServerConfig::isp(AC_IF, Auth::Pap))?;
    runtime()?.block_on(async {
        let (mut bench, _) = up_over_pppd(&rig, lab, daemons::PPP_PASSWORD, is_ipv4_up).await?;
        server.signal(nix::sys::signal::Signal::SIGTERM);
        let outputs = bench.run_until(Duration::from_secs(10), is_down).await?;
        ensure!(
            matches!(
                down_reason(&outputs),
                Some(PppReason::TerminatedByPeer | PppReason::CarrierLost)
            ),
            "{outputs:?}"
        );
        let down4 = outputs.iter().position(|o| *o == PppOutput::Ipv4Down);
        let down = outputs.iter().position(is_down);
        ensure!(
            down4.is_some() && down4 < down,
            "IPv4 goes down first: {outputs:?}"
        );
        anyhow::Ok(())
    })?;
    drop(server);
    drop(rig);
    let rig = Rig::create_isp(lab)?;
    let mut server = rig.server(lab, &PppoeServerConfig::isp(AC_IF, Auth::Pap))?;
    runtime()?.block_on(async {
        let (mut bench, before) = up_over_pppd(&rig, lab, daemons::PPP_PASSWORD, |o| {
            matches!(o, PppOutput::AuthOk(_))
        })
        .await?;
        server.signal(nix::sys::signal::Signal::SIGTERM);
        let outputs = bench.run_until(Duration::from_secs(10), is_down).await?;
        let all: Vec<&PppOutput> = before.iter().chain(&outputs).collect();
        ensure!(
            !all.iter()
                .any(|o| matches!(o, PppOutput::Ipv4Up(_) | PppOutput::Ipv4Down)),
            "nothing of IPv4 when IPCP never finished: {all:?}"
        );
        ensure!(down_reason(&outputs).is_some(), "{outputs:?}");
        anyhow::Ok(())
    })
}

/// A PADT for `session_id` from the ISP's end, as an access concentrator ending a session
/// without LCP (a raw frame sent from the ISP namespace; our codec builds it).
fn inject_padt(rig: &Rig, session_id: u16) -> anyhow::Result<()> {
    let ns = rig.isp.as_ref().context("an ISP namespace")?;
    let payload = pppoe::Discovery {
        code: Code::Padt,
        session_id,
        tags: vec![],
    }
    .encode();
    let mut frame = Vec::new();
    frame.extend_from_slice(&rig.client.1);
    frame.extend_from_slice(&rig.ac.1);
    frame.extend_from_slice(&pppoe::ETH_P_PPP_DISC.to_be_bytes());
    frame.extend_from_slice(&payload);
    let hex = frame.iter().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    });
    let mut cmd = ns.command("python3")?;
    cmd.args([
        "-c",
        "import socket,sys; s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((sys.argv[1], 0)); s.send(bytes.fromhex(sys.argv[2]))",
        AC_IF,
        &hex,
    ]);
    netns::run(&mut cmd)?;
    Ok(())
}

/// The access concentrator's PADT alone ends the session at once: the kernel's PPPoE tears its
/// side down and the session core is down, never waiting for the keepalive.
fn a_padt_from_the_ac_ends_the_session(lab: &mut Lab) -> anyhow::Result<()> {
    require_dev_ppp()?;
    let rig = Rig::create_isp(lab)?;
    let _server = rig.server(lab, &PppoeServerConfig::isp(AC_IF, Auth::Pap))?;
    runtime()?.block_on(async {
        let (mut bench, _) = up_over_pppd(&rig, lab, daemons::PPP_PASSWORD, is_ipv4_up).await?;
        inject_padt(&rig, bench.session_id)?;
        let sent = Instant::now();
        let outputs = bench.run_until(Duration::from_secs(5), is_down).await?;
        ensure!(
            matches!(
                down_reason(&outputs),
                Some(PppReason::CarrierLost | PppReason::TerminatedByPeer)
            ),
            "{outputs:?} (padt seen on the discovery socket: {})",
            bench.padt_seen
        );
        ensure!(
            sent.elapsed() < Duration::from_secs(5),
            "at once, not by keepalive"
        );
        anyhow::Ok(())
    })
}
