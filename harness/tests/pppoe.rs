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

use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use openfeo_harness::lab::Lab;
use openfeo_harness::lanclient::link_info;
use openfeo_harness::netns;
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, Skip, run_all};
use openfeo_net::pppoe::{Discovery, Session, dev_ppp_unavailable};
use openfeo_proto_ppp::Timestamp;
use openfeo_proto_ppp::discovery::{Client, Config, Input, Output, Reason};
use openfeo_proto_ppp::pppoe::{self, BROADCAST, Code, Tag};
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
        })
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
    far: Discovery,
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
        let near = Discovery::open(rig.client.0, CLIENT_IF)?;
        let far = Discovery::open(rig.ac.0, AC_IF)?;
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
                received = self.far.recv(&mut self.far_buf) => {
                    let (from, len) = received?;
                    let packet = pppoe::Discovery::decode(&self.far_buf[..len])
                        .context("the ac decodes the client's frame")?;
                    if let Some(reply) = ac_answer(&mut self.log, &packet) {
                        self.far.send(from, &reply)?;
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
        Ok(self.far.send(to, &padt)?)
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
