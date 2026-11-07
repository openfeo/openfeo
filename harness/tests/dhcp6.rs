// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv6 client core (`openfeo-proto-dhcp6`) over the WAN socket (`openfeo-net`) against
//! a real Kea DHCPv6 server inside the rootless sandbox, no QEMU, and the stateless responder
//! against busybox `udhcpc6`: a veth pair whose far end lives in a namespace of its own with
//! Kea (or the reference client) on it. The router's task loop lives in `crates/openfeo`, so
//! the suite drives the core itself, as the `ndp` suite does. `harness = false`: this binary is
//! its own runner; an optional first argument filters scenarios by substring.

use std::net::Ipv6Addr;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use ipnet::Ipv6Net;
use openfeo_harness::daemons::{self, Daemon, Kea6Config};
use openfeo_harness::lab::{Lab, PD_POOL_A, PD_POOL_B};
use openfeo_harness::lanclient::{self, link_info};
use openfeo_harness::lines::{Cursor, Regex};
use openfeo_harness::netns::{self, NetNs};
use openfeo_harness::sandbox;
use openfeo_harness::scenario::{Scenario, run_all};
use openfeo_net::dhcp6::{ClientSocket, ServerSocket};
use openfeo_proto_dhcp4::identity::duid_ll;
use openfeo_proto_dhcp6::client::{self, Binding, Client, Input, Note, Output, State};
use openfeo_proto_dhcp6::server::{self, INFORMATION_REFRESH_TIME};
use openfeo_proto_dhcp6::wire::MessageType;
use openfeo_proto_dhcp6::{Timestamp, iaid};
use tokio::runtime::Runtime;

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "client_binds_a_prefix_an_address_and_the_resolvers_from_kea",
        run: client_binds_a_prefix_an_address_and_the_resolvers_from_kea,
    },
    Scenario {
        name: "client_renews_at_t1",
        run: client_renews_at_t1,
    },
    Scenario {
        name: "a_restarted_server_with_another_pool_replaces_the_prefix_and_deprecates_the_old",
        run: a_restarted_server_with_another_pool_replaces_the_prefix_and_deprecates_the_old,
    },
    Scenario {
        name: "a_link_flap_rebinds_instead_of_soliciting",
        run: a_link_flap_rebinds_instead_of_soliciting,
    },
    Scenario {
        name: "a_persisted_binding_is_rebound_at_start",
        run: a_persisted_binding_is_rebound_at_start,
    },
    Scenario {
        name: "a_server_with_no_pd_pool_yields_no_prefix_and_keeps_the_address",
        run: a_server_with_no_pd_pool_yields_no_prefix_and_keeps_the_address,
    },
    Scenario {
        name: "the_responder_answers_udhcpc6_with_the_resolver_and_the_search_list",
        run: the_responder_answers_udhcpc6_with_the_resolver_and_the_search_list,
    },
];

fn main() -> ExitCode {
    if let Err(err) = sandbox::enter() {
        eprintln!("cannot enter the sandbox: {err:#}");
        return ExitCode::FAILURE;
    }
    run_all(SCENARIOS, std::env::args().nth(1).as_deref())
}

/// The near end of the veth pair, where the client (or the responder) runs.
const CLIENT_IF: &str = "d60";
/// The far end, in the ISP namespace, where Kea listens (or udhcpc6 asks).
const SERVER_IF: &str = "d61";
/// Kea's address on the link, and the resolver its template names.
const ISP_RESOLVER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1);
/// The WAN the client's IAIDs are derived for.
const WAN: &str = "wan0";
/// The delegation length asked for (SPEC §8.2's default).
const PD_HINT: u8 = 56;
/// What the LAN responder serves in the udhcpc6 scenario.
const LAN_RESOLVER: Ipv6Addr = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 1, 0, 0, 0, 1);
/// How long a scenario waits for the kernel, Kea or the far end.
const SOON: Duration = Duration::from_secs(10);
/// Kea's T1 is 10 s; a renewal must have happened by then.
const RENEW_TIMEOUT: Duration = Duration::from_secs(16);
/// A forgotten delegation is replaced at the Renew (T1, 10 s), or at the Rebind (T2, 16 s)
/// should the server's identity have changed with the restart.
const RENUMBER_TIMEOUT: Duration = Duration::from_secs(20);

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("bad test regex {pattern:?}: {err}"))
}

fn runtime() -> anyhow::Result<Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

fn millis(start: Instant) -> Timestamp {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Kea on the far end, delegating from `pool` when given.
fn kea_config(pool: Option<&str>) -> anyhow::Result<Kea6Config> {
    Ok(Kea6Config {
        iface: SERVER_IF.to_owned(),
        pd_pool: pool.map(str::parse).transpose()?,
        long_lived: false,
    })
}

/// A veth pair with the far end in its own namespace, Kea on it when asked. Fields drop in
/// order: Kea before its namespace, the pair last.
struct Rig {
    kea: Option<Daemon>,
    ns: NetNs,
    ifindex: u32,
    mac: [u8; 6],
    /// The clock every client in a scenario runs on, so a binding carried from one client to
    /// the next keeps its timers.
    start: Instant,
}

impl Rig {
    fn create(lab: &Lab, kea: Option<&Kea6Config>) -> anyhow::Result<Self> {
        let _ = netns::ip(&["link", "del", CLIENT_IF]);
        netns::ip(&[
            "link", "add", CLIENT_IF, "type", "veth", "peer", "name", SERVER_IF,
        ])?;
        let ns = NetNs::create(&format!("{}-dhcp6", lab.name()))?;
        netns::ip(&["link", "set", SERVER_IF, "netns", &ns.name])?;
        ns.ip(&[
            "-6",
            "addr",
            "add",
            &format!("{ISP_RESOLVER}/64"),
            "dev",
            SERVER_IF,
            "nodad",
        ])?;
        ns.ip(&["-6", "addr", "add", "fe80::1/64", "dev", SERVER_IF, "nodad"])?;
        ns.ip(&["link", "set", SERVER_IF, "up"])?;
        netns::ip(&["link", "set", CLIENT_IF, "up"])?;
        let (ifindex, mac) = link_info(CLIENT_IF)?;
        let mut rig = Rig {
            kea: None,
            ns,
            ifindex,
            mac,
            start: Instant::now(),
        };
        wait_for_link_local(None, CLIENT_IF)?;
        wait_for_link_local(Some(&rig.ns), SERVER_IF)?;
        if let Some(config) = kea {
            rig.start_kea(lab, config)?;
        }
        Ok(rig)
    }

    /// Kea serving `config`, in place of the one running (which is stopped first, taking its
    /// unpersisted leases with it: the ISP that forgot the delegation).
    fn start_kea(&mut self, lab: &Lab, config: &Kea6Config) -> anyhow::Result<()> {
        self.kea = None;
        let kea = daemons::kea_dhcp6(&self.ns, config, &lab.run_dir)?;
        kea.log.wait_for(
            &mut Cursor::default(),
            &re("DHCP6_STARTED"),
            Duration::from_secs(15),
        )?;
        self.kea = Some(kea);
        Ok(())
    }

    fn kea_log_count(&self, pattern: &str) -> usize {
        self.kea
            .as_ref()
            .map_or(0, |kea| kea.log.count(&re(pattern)))
    }

    fn now(&self) -> Timestamp {
        millis(self.start)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = netns::ip(&["link", "del", CLIENT_IF]);
    }
}

/// Until `ifname`'s link-local address is past duplicate address detection: the client's
/// source, and what Kea and udhcpc6 bind to on the far end.
fn wait_for_link_local(ns: Option<&NetNs>, ifname: &str) -> anyhow::Result<()> {
    let deadline = Instant::now() + SOON;
    loop {
        let args = ["-6", "addr", "show", "dev", ifname, "scope", "link"];
        let text = match ns {
            Some(ns) => ns.ip(&args)?,
            None => netns::ip(&args)?,
        };
        if text.contains("fe80:") && !text.contains("tentative") {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "no link-local address on {ifname}: {text}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

/// The client core on the WAN socket, run by the scenario: the task in `crates/openfeo` does
/// the same with the World and the lease file around it.
struct Driver {
    socket: ClientSocket,
    client: Client,
    start: Instant,
    /// Outputs not yet acted on.
    pending: Vec<Output>,
    buf: Vec<u8>,
}

impl Driver {
    /// A client started on the rig's link, Soliciting or Rebinding `binding`. Call inside the
    /// runtime: the socket registers with it.
    fn start(rig: &Rig, binding: Option<Binding>) -> anyhow::Result<Self> {
        let socket = ClientSocket::open(rig.ifindex, CLIENT_IF)?;
        let config = client::Config {
            duid: duid_ll(rig.mac),
            iaid_pd: iaid::iaid(iaid::PD, WAN),
            iaid_na: iaid::iaid(iaid::NA, WAN),
            pd_hint: PD_HINT,
        };
        let mut client = Client::new(config, 0x5eed);
        let pending = client.handle(Input::Start { binding }, rig.now());
        Ok(Driver {
            socket,
            client,
            start: rig.start,
            pending,
            buf: vec![0u8; 1500],
        })
    }

    fn feed(&mut self, input: Input) {
        let now = millis(self.start);
        let outputs = self.client.handle(input, now);
        self.pending.extend(outputs);
    }

    /// Act on every output (sends go out) until `done` holds for one, or `timeout` passes;
    /// the outputs seen, in order, the one that satisfied `done` last. What came after it in
    /// the same batch waits for the next run.
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
                if let Output::Send(bytes) = &output {
                    // A send the kernel refuses is retransmitted by the core on its timer.
                    let _ = self.socket.send(bytes);
                }
                let finished = done(&output);
                seen.push(output);
                if finished {
                    return Ok(seen);
                }
            }
            ensure!(
                Instant::now() < deadline,
                "timed out after {timeout:?}; outputs so far: {seen:?}"
            );
            let timer = self
                .client
                .next_timeout()
                .map_or(deadline, |at| self.start + Duration::from_millis(at))
                .min(deadline);
            tokio::select! {
                received = self.socket.recv(&mut self.buf) => {
                    let (_, len) = received?;
                    let packet = self.buf[..len].to_vec();
                    self.feed(Input::Packet(packet));
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(timer)) => {
                    self.feed(Input::Timeout);
                }
            }
        }
    }
}

fn is_bound(output: &Output) -> bool {
    matches!(output, Output::Bound { .. })
}

fn is_renewal(output: &Output) -> bool {
    matches!(output, Output::Bound { renewed: true, .. })
}

/// The last binding reported in `outputs`.
fn bound(outputs: &[Output]) -> anyhow::Result<&Binding> {
    outputs
        .iter()
        .rev()
        .find_map(|output| match output {
            Output::Bound { binding, .. } => Some(binding),
            _ => None,
        })
        .with_context(|| format!("no binding among {outputs:?}"))
}

fn noted(outputs: &[Output], note: &Note) -> bool {
    outputs
        .iter()
        .any(|output| matches!(output, Output::Note(seen) if seen == note))
}

/// Everything reported gone in `outputs`.
fn gone(outputs: &[Output]) -> Vec<Ipv6Net> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::Gone(nets) => Some(nets.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn nets(binding: &Binding) -> Vec<Ipv6Net> {
    binding.nets().collect()
}

/// The binding Kea's template gives: one /56 from `pool`, one address from the link's pool,
/// the resolver, the domain and the timers a scenario can watch.
fn check_binding(binding: &Binding, pool: &str) -> anyhow::Result<()> {
    let pool: Ipv6Net = pool.parse()?;
    ensure!(
        binding.prefixes.len() == 1,
        "prefixes {:?}",
        binding.prefixes
    );
    let prefix = &binding.prefixes[0];
    ensure!(
        pool.contains(&prefix.net) && prefix.net.prefix_len() == 56,
        "prefix {} is not a /56 inside {pool}",
        prefix.net
    );
    ensure!(
        (prefix.preferred, prefix.valid) == (40, 60),
        "prefix lifetimes {} {}",
        prefix.preferred,
        prefix.valid
    );
    ensure!(
        binding.addresses.len() == 1,
        "addresses {:?}",
        binding.addresses
    );
    let address = binding.addresses[0].net.addr().segments();
    ensure!(
        address[..7] == [0x2001, 0xdb8, 0xffff, 0, 0, 0, 0]
            && (0x100..=0x1ff).contains(&address[7]),
        "address {} outside Kea's pool",
        binding.addresses[0].net
    );
    ensure!(binding.dns == vec![ISP_RESOLVER], "dns {:?}", binding.dns);
    ensure!(
        binding.search == vec!["isp.example".to_owned()],
        "search {:?}",
        binding.search
    );
    ensure!(
        (binding.t1, binding.t2) == (10, 16),
        "timers {} {}",
        binding.t1,
        binding.t2
    );
    ensure!(!binding.server.is_empty(), "no server identifier");
    Ok(())
}

/// Solicit with Rapid Commit, Reply: a prefix from the pool, an address, the resolvers and
/// the search list, without a Request in between.
fn client_binds_a_prefix_an_address_and_the_resolvers_from_kea(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let rig = Rig::create(lab, Some(&kea_config(Some(PD_POOL_A))?))?;
    let rt = runtime()?;
    let (outputs, last_sent, state) = rt.block_on(async {
        let mut driver = Driver::start(&rig, None)?;
        let outputs = driver.run_until(SOON, is_bound).await?;
        anyhow::Ok((outputs, driver.client.last_sent(), driver.client.state()))
    })?;
    check_binding(bound(&outputs)?, PD_POOL_A)?;
    ensure!(noted(&outputs, &Note::Soliciting), "{outputs:?}");
    ensure!(
        !noted(&outputs, &Note::Requesting),
        "Kea commits rapidly; the client must not Request: {outputs:?}"
    );
    ensure!(
        last_sent == Some(MessageType::Solicit) && state == State::Bound,
        "last sent {last_sent:?}, state {state:?}"
    );
    ensure!(
        rig.kea_log_count("DHCP6_PD_LEASE_ALLOC") >= 1
            && rig.kea_log_count("DHCP6_LEASE_ALLOC") >= 1,
        "Kea logged {} prefix and {} address allocations",
        rig.kea_log_count("DHCP6_PD_LEASE_ALLOC"),
        rig.kea_log_count("DHCP6_LEASE_ALLOC")
    );
    Ok(())
}

/// At T1 the client Renews with the server that bound it; the Reply continues the binding.
fn client_renews_at_t1(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, Some(&kea_config(Some(PD_POOL_A))?))?;
    let rt = runtime()?;
    let (before, outputs, last_sent) = rt.block_on(async {
        let mut driver = Driver::start(&rig, None)?;
        let first = driver.run_until(SOON, is_bound).await?;
        let before = bound(&first)?.clone();
        let outputs = driver.run_until(RENEW_TIMEOUT, is_renewal).await?;
        anyhow::Ok((before, outputs, driver.client.last_sent()))
    })?;
    let after = bound(&outputs)?;
    ensure!(
        last_sent == Some(MessageType::Renew),
        "last sent {last_sent:?}"
    );
    ensure!(
        nets(after) == nets(&before),
        "the binding changed on renewal: {:?} -> {:?}",
        nets(&before),
        nets(after)
    );
    ensure!(
        after.bound_at >= before.bound_at + 10_000,
        "renewed {} ms after binding, before T1",
        after.bound_at - before.bound_at
    );
    ensure!(noted(&outputs, &Note::Renewing), "{outputs:?}");
    ensure!(
        !noted(&outputs, &Note::Soliciting) && gone(&outputs).is_empty(),
        "a renewal must neither solicit nor lose anything: {outputs:?}"
    );
    Ok(())
}

/// Kea restarted with another delegation pool has forgotten the binding: the Renew (or, had the
/// server's identity changed, the Rebind) gets a prefix from the new pool and the old one with
/// lifetimes 0, which the core reports gone, and the router deprecates.
fn a_restarted_server_with_another_pool_replaces_the_prefix_and_deprecates_the_old(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let mut rig = Rig::create(lab, Some(&kea_config(Some(PD_POOL_A))?))?;
    let rt = runtime()?;
    let pool_b: Ipv6Net = PD_POOL_B.parse()?;
    let mut driver = rt.block_on(async { Driver::start(&rig, None) })?;
    let first = rt.block_on(driver.run_until(SOON, is_bound))?;
    let before = bound(&first)?.clone();
    let old_prefix = before.prefixes[0].net;
    rig.start_kea(lab, &kea_config(Some(PD_POOL_B))?)?;
    let restarted = Instant::now();
    let outputs = rt.block_on(driver.run_until(RENUMBER_TIMEOUT, |output| {
        matches!(output, Output::Bound { binding, .. }
            if binding.prefixes.iter().any(|prefix| pool_b.contains(&prefix.net)))
    }))?;
    let took = restarted.elapsed();
    let after = bound(&outputs)?;
    ensure!(
        after.prefixes.len() == 1 && after.prefixes[0].net.prefix_len() == 56,
        "prefixes {:?}",
        after.prefixes
    );
    ensure!(
        gone(&outputs).contains(&old_prefix),
        "{old_prefix} must be reported gone: {outputs:?}"
    );
    ensure!(
        !noted(&outputs, &Note::Soliciting),
        "the client must not start over for a forgotten delegation: {outputs:?}"
    );
    ensure!(
        took < RENUMBER_TIMEOUT,
        "renumbered {took:?} after the restart"
    );
    Ok(())
}

/// Carrier lost and back: the client Rebinds on Confirm's timing rather than Soliciting, and the
/// Reply continues the binding.
fn a_link_flap_rebinds_instead_of_soliciting(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, Some(&kea_config(Some(PD_POOL_A))?))?;
    let rt = runtime()?;
    let (before, first_sent, outputs) = rt.block_on(async {
        let mut driver = Driver::start(&rig, None)?;
        let first = driver.run_until(SOON, is_bound).await?;
        let before = bound(&first)?.clone();
        driver.feed(Input::LinkDown);
        driver.feed(Input::LinkUp);
        let first_sent = driver.client.last_sent();
        let outputs = driver.run_until(SOON, is_renewal).await?;
        anyhow::Ok((before, first_sent, outputs))
    })?;
    ensure!(
        first_sent == Some(MessageType::Rebind),
        "after the flap the client sent {first_sent:?}"
    );
    let after = bound(&outputs)?;
    ensure!(
        nets(after) == nets(&before),
        "the binding changed across the flap: {:?} -> {:?}",
        nets(&before),
        nets(after)
    );
    ensure!(
        noted(&outputs, &Note::Rebinding) && !noted(&outputs, &Note::Soliciting),
        "{outputs:?}"
    );
    ensure!(gone(&outputs).is_empty(), "{outputs:?}");
    Ok(())
}

/// A client started with the binding the last run left on disk Rebinds it instead of
/// Soliciting, and keeps the prefix.
fn a_persisted_binding_is_rebound_at_start(lab: &mut Lab) -> anyhow::Result<()> {
    let rig = Rig::create(lab, Some(&kea_config(Some(PD_POOL_A))?))?;
    let rt = runtime()?;
    let (before, first_sent, outputs) = rt.block_on(async {
        let before = {
            let mut first = Driver::start(&rig, None)?;
            let outputs = first.run_until(SOON, is_bound).await?;
            bound(&outputs)?.clone()
        };
        let mut rebooted = Driver::start(&rig, Some(before.clone()))?;
        let first_sent = rebooted.client.last_sent();
        let outputs = rebooted.run_until(SOON, is_bound).await?;
        anyhow::Ok((before, first_sent, outputs))
    })?;
    ensure!(
        first_sent == Some(MessageType::Rebind),
        "the first message was {first_sent:?}"
    );
    ensure!(
        outputs.iter().any(is_renewal),
        "the binding must continue, not begin: {outputs:?}"
    );
    let after = bound(&outputs)?;
    ensure!(
        nets(after) == nets(&before),
        "the binding changed across the restart: {:?} -> {:?}",
        nets(&before),
        nets(after)
    );
    ensure!(!noted(&outputs, &Note::Soliciting), "{outputs:?}");
    Ok(())
}

/// Kea with no delegation pool: `NoPrefixAvail` in the `IA_PD`, noted once, and the address bound
/// all the same.
fn a_server_with_no_pd_pool_yields_no_prefix_and_keeps_the_address(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let rig = Rig::create(lab, Some(&kea_config(None)?))?;
    let rt = runtime()?;
    let outputs = rt.block_on(async {
        let mut driver = Driver::start(&rig, None)?;
        let (mut is_bound, mut no_prefix) = (false, false);
        driver
            .run_until(SOON, |output| {
                is_bound |= matches!(output, Output::Bound { .. });
                no_prefix |= matches!(output, Output::Note(Note::NoPrefixAvailable));
                is_bound && no_prefix
            })
            .await
    })?;
    let binding = bound(&outputs)?;
    ensure!(
        binding.prefixes.is_empty() && binding.addresses.len() == 1,
        "{binding:?}"
    );
    ensure!(binding.dns == vec![ISP_RESOLVER], "dns {:?}", binding.dns);
    ensure!(
        outputs
            .iter()
            .filter(|output| matches!(output, Output::Note(Note::NoPrefixAvailable)))
            .count()
            == 1,
        "{outputs:?}"
    );
    Ok(())
}

/// The responder on the near end answers while `client` runs on another thread; what the
/// client returned.
fn respond_while<T: Send>(
    rt: &Runtime,
    rig: &Rig,
    config: &server::Config,
    client: impl FnOnce() -> anyhow::Result<T> + Send,
) -> anyhow::Result<T> {
    thread::scope(|scope| {
        let (done_tx, done_rx) = mpsc::channel();
        let handle = scope.spawn(move || {
            let result = client();
            let _ = done_tx.send(());
            result
        });
        rt.block_on(async {
            let socket = ServerSocket::open(rig.ifindex, CLIENT_IF)?;
            let mut buf = vec![0u8; 1500];
            loop {
                if !matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                    break;
                }
                tokio::select! {
                    received = socket.recv(&mut buf) => {
                        let (from, len) = received?;
                        if let Some(answer) = server::reply(config, &buf[..len]) {
                            socket.send_to(from, &answer)?;
                        }
                    }
                    () = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
            }
            anyhow::Ok(())
        })?;
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("client thread panicked"))?
    })
}

/// busybox `udhcpc6 -l` on the far end, the stateless reference client, gets the resolver and
/// the search list from the responder on the near end.
fn the_responder_answers_udhcpc6_with_the_resolver_and_the_search_list(
    lab: &mut Lab,
) -> anyhow::Result<()> {
    let rig = Rig::create(lab, None)?;
    let config = server::Config {
        duid: duid_ll(rig.mac),
        dns: vec![LAN_RESOLVER],
        domains: vec!["home.arpa".to_owned()],
        refresh_secs: INFORMATION_REFRESH_TIME,
    };
    let rt = runtime()?;
    let run_dir = lab.run_dir.clone();
    let info = respond_while(&rt, &rig, &config, || {
        lanclient::udhcpc6_info(&rig.ns, SERVER_IF, &run_dir, Duration::from_secs(15))
    })?;
    ensure!(info.dns == vec![LAN_RESOLVER], "dns {:?}", info.dns);
    ensure!(
        info.search == vec!["home.arpa".to_owned()],
        "search {:?}",
        info.search
    );
    Ok(())
}
