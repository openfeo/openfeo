// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The WAN's DHCPv6 task (SPEC §7.3): one supervised task per WAN with `[wans.ipv6]` and no
//! typed prefix, running the `openfeo-proto-dhcp6` client core on the WAN port's DHCPv6
//! socket, publishing what it binds as the WAN's fact, keeping the binding and the prefixes
//! being deprecated in `/state/leases/dhcp6-<wan>.toml`, and owning the two clocks the World
//! never sees: a prefix that left the binding is deprecated for the lower of two hours and
//! its remaining valid lifetime, and a binding without carrier for two hours is dropped. Every
//! line logged here is a contract with the harness scenarios.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::Ipv6Net;
use openfeo_config::{Dhcp6Binding, Dhcp6Deprecated, Dhcp6Lease, file, rules};
use openfeo_net::dhcp6::ClientSocket;
use openfeo_net::ndp::{RESEND_AFTER, RESEND_TRIES, transient_send_error};
use openfeo_net::throttle::{NOISY_WINDOW, Throttle};
use openfeo_proto_dhcp4::identity::{duid_ll, from_hex, hex};
use openfeo_proto_dhcp6::client::{Binding, Client, Config, Input, Lease6, Note, Output};
use openfeo_proto_dhcp6::iaid;
use openfeo_reconcile::lan6;
use openfeo_runtime::clock;
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use openfeo_world::{Deprecated, Lifetimed, WanDhcp6Fact};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::dhcp4::{
    DUID_PATH, LEASES_DIR, LinkChange, link_change, load_or_create_duid, lowest_port_mac, mac_text,
    seed, wait_for_link, wait_for_netdev,
};
use crate::state;

/// The salt of the clock fallback of [`seed`].
const SEED_SALT: u64 = 0x0044_4836;
/// The DHCPv6 message buffer.
const RECEIVE_BUFFER: usize = 1500;
/// A prefix that left the binding is deprecated for at most this long (SPEC §7.3).
pub const DEPRECATION_SECS: u64 = 7200;
/// A binding whose WAN has had no carrier for this long is dropped (SPEC §7.3).
pub const CARRIERLESS_DROP: Duration = Duration::from_secs(7200);
const MS: u64 = 1000;

/// `/state/leases/dhcp6-<wan>.toml`.
#[must_use]
pub fn lease_path(wan: &str) -> PathBuf {
    Path::new(LEASES_DIR).join(format!("dhcp6-{wan}.toml"))
}

/// One task per WAN with `[wans.ipv6]` in mode `auto` and no typed prefix.
pub fn spawn_all(supervisor: &Supervisor, publisher: &Arc<Publisher>, world_rx: &WorldRx) {
    let config = publisher.current().config.clone();
    for wan in &config.wans {
        let Some(ipv6) = &wan.ipv6 else {
            continue;
        };
        if ipv6.mode == "disabled" || !ipv6.prefix.is_empty() {
            continue;
        }
        let task = WanTask {
            wan: wan.name.clone(),
            port: openfeo_reconcile::wan_ifname(wan),
            netdev: openfeo_reconcile::wan_netdev(wan),
            pd_hint: rules::pd_hint(ipv6),
        };
        let publisher = publisher.clone();
        let world_rx = world_rx.clone();
        supervisor.spawn(format!("dhcp6-{}", wan.name), move || {
            let task = task.clone();
            let publisher = publisher.clone();
            let world_rx = world_rx.clone();
            async move { run(&task, &publisher, world_rx).await }
        });
    }
}

#[derive(Debug, Clone)]
struct WanTask {
    wan: String,
    /// The WAN's port (or VLAN sub-interface): the binding's identity is its MAC.
    port: String,
    /// The interface the client runs on: the port, or `ppp-<wan>` over PPPoE (ADR-0023).
    netdev: String,
    pd_hint: u8,
}

/// The prefixes being deprecated, with their deadlines on the process clock.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Deprecations {
    pub list: Vec<Deprecated>,
}

impl Deprecations {
    /// Deprecate `net` until `until_ms`; a prefix already listed keeps its earlier deadline.
    pub fn add(&mut self, net: Ipv6Net, until_ms: u64) {
        if !self.list.iter().any(|gone| gone.net == net) {
            self.list.push(Deprecated { net, until_ms });
        }
    }

    /// Prefixes in `nets` came back: they are deprecated no more.
    pub fn revive(&mut self, nets: &[Ipv6Net]) {
        self.list.retain(|gone| !nets.contains(&gone.net));
    }

    /// Drop every entry whose deadline has passed, returning what went.
    pub fn purge(&mut self, now_ms: u64) -> Vec<Ipv6Net> {
        let (gone, kept): (Vec<_>, Vec<_>) = self
            .list
            .drain(..)
            .partition(|entry| entry.until_ms <= now_ms);
        self.list = kept;
        gone.into_iter().map(|entry| entry.net).collect()
    }

    /// The earliest deadline, when any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.list.iter().map(|entry| entry.until_ms).min()
    }
}

/// When a prefix that left the binding stops being advertised: the lower of two hours and
/// what was left of its valid lifetime (RFC 7084 L-13), from `now_ms`.
#[must_use]
pub fn deprecation_deadline(now_ms: u64, remaining_valid_ms: Option<u64>) -> u64 {
    let window = remaining_valid_ms.map_or(DEPRECATION_SECS * MS, |left| {
        left.min(DEPRECATION_SECS * MS)
    });
    now_ms.saturating_add(window)
}

/// What was left of `net`'s valid lifetime in `binding` at `now_ms`, or `None` when the
/// binding did not hold it.
fn remaining_valid_ms(binding: Option<&Binding>, net: Ipv6Net, now_ms: u64) -> Option<u64> {
    let lease = binding?
        .prefixes
        .iter()
        .chain(&binding?.addresses)
        .find(|lease| lease.net == net)?;
    if lease.valid == u32::MAX {
        return None;
    }
    Some(
        binding?
            .bound_at
            .saturating_add(u64::from(lease.valid) * MS)
            .saturating_sub(now_ms),
    )
}

/// The binding as the reconcilers see it, with the prefixes being deprecated, and whether it
/// was restored from disk and not yet confirmed (#44).
#[must_use]
pub fn fact_from(binding: &Binding, deprecated: &[Deprecated], restored: bool) -> WanDhcp6Fact {
    let lifetimed = |lease: &Lease6| Lifetimed {
        net: lease.net,
        obtained_ms: binding.bound_at,
        preferred_secs: lease.preferred,
        valid_secs: lease.valid,
    };
    WanDhcp6Fact {
        prefixes: binding.prefixes.iter().map(lifetimed).collect(),
        addresses: binding.addresses.iter().map(lifetimed).collect(),
        deprecated: deprecated.to_vec(),
        dns: binding.dns.clone(),
        search: binding.search.clone(),
        server: binding.server.clone(),
        restored,
    }
}

/// What a lease file gives back: the binding, when one is still valid, and the deprecations
/// still running. A file may hold a deprecated list and no binding (#40): a prefix that left
/// an expired binding is still advertised deprecated across a reboot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    pub binding: Option<Binding>,
    pub deprecated: Vec<Deprecated>,
}

/// The binding as its file keeps it: wall-clock seconds, so a reboot can judge what is left;
/// `None` writes the deprecated list alone.
#[must_use]
pub fn binding_file(
    wan: &str,
    mac: [u8; 6],
    binding: Option<&Binding>,
    deprecated: &[Deprecated],
    now_unix: u64,
    now_ms: u64,
) -> Dhcp6Lease {
    let lease = |lease: &Lease6| Dhcp6Binding {
        net: lease.net.to_string(),
        preferred_secs: lease.preferred,
        valid_secs: lease.valid,
    };
    let age_secs = binding.map_or(0, |b| now_ms.saturating_sub(b.bound_at) / MS);
    Dhcp6Lease {
        wan: wan.to_owned(),
        mac: mac_text(mac),
        server_duid: binding.map_or_else(String::new, |b| hex(&b.server)),
        prefixes: binding.map_or_else(Vec::new, |b| b.prefixes.iter().map(lease).collect()),
        addresses: binding.map_or_else(Vec::new, |b| b.addresses.iter().map(lease).collect()),
        t1_secs: binding.map_or(0, |b| b.t1),
        t2_secs: binding.map_or(0, |b| b.t2),
        dns: binding.map_or_else(Vec::new, |b| {
            b.dns.iter().map(ToString::to_string).collect()
        }),
        search: binding.map_or_else(Vec::new, |b| b.search.clone()),
        obtained_unix: now_unix.saturating_sub(age_secs),
        deprecated: deprecated
            .iter()
            .map(|gone| Dhcp6Deprecated {
                net: gone.net.to_string(),
                until_unix: now_unix.saturating_add(gone.until_ms.saturating_sub(now_ms) / MS),
            })
            .collect(),
    }
}

/// What a file holds, if it is this WAN's and this port's and parses: a binding whose valid
/// lifetime has not lapsed by the wall clock (its `bound_at` placed on the process clock so the
/// core's timers come out right; a file obtained after `now_unix`, the clock having gone
/// backwards on an RTC-less board, is counted from now and left to the Rebind), and the
/// deprecations whose deadline is still ahead. `Err` says why the file is ignored (#41): a
/// corrupt server DUID rejects it rather than yielding an empty Server Identifier.
///
/// # Errors
///
/// A static reason: another WAN or port, a server DUID that is not hex, or nothing left.
pub fn binding_from_file(
    file: &Dhcp6Lease,
    wan: &str,
    mac: [u8; 6],
    now_unix: u64,
    now_ms: u64,
) -> Result<Restored, &'static str> {
    if file.wan != wan {
        return Err("for another WAN");
    }
    if file.mac != mac_text(mac) {
        return Err("for another port");
    }
    let age_secs = now_unix.saturating_sub(file.obtained_unix);
    // What is left of a lifetime after the file's age; infinite stays infinite.
    let left = |secs: u32| -> u32 {
        if secs == u32::MAX {
            secs
        } else {
            u32::try_from(u64::from(secs).saturating_sub(age_secs)).unwrap_or(0)
        }
    };
    let lease = |entry: &Dhcp6Binding| -> Option<Lease6> {
        let net: Ipv6Net = entry.net.parse().ok()?;
        (left(entry.valid_secs) > 0).then_some(Lease6 {
            net,
            preferred: left(entry.preferred_secs),
            valid: left(entry.valid_secs),
        })
    };
    let prefixes: Vec<Lease6> = file.prefixes.iter().filter_map(lease).collect();
    let addresses: Vec<Lease6> = file.addresses.iter().filter_map(lease).collect();
    let deprecated: Vec<Deprecated> = file
        .deprecated
        .iter()
        .filter(|gone| gone.until_unix > now_unix)
        .filter_map(|gone| {
            Some(Deprecated {
                net: gone.net.parse().ok()?,
                until_ms: now_ms.saturating_add((gone.until_unix - now_unix) * MS),
            })
        })
        .collect();
    let binding = if prefixes.is_empty() && addresses.is_empty() {
        None
    } else {
        let Some(server) = from_hex(&file.server_duid) else {
            return Err("server DUID is not hex");
        };
        Some(Binding {
            server,
            prefixes,
            addresses,
            t1: left(file.t1_secs),
            t2: left(file.t2_secs),
            dns: file
                .dns
                .iter()
                .filter_map(|text| text.parse().ok())
                .collect(),
            search: file.search.clone(),
            // The lifetimes above already carry the age, so the binding counts from now: a
            // process clock a few seconds old cannot be wound back to before boot.
            bound_at: now_ms,
        })
    };
    if binding.is_none() && deprecated.is_empty() {
        return Err("lapsed");
    }
    Ok(Restored {
        binding,
        deprecated,
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// What the lease file holds for this WAN and port, if anything.
fn read_binding(path: &Path, wan: &str, mac: [u8; 6]) -> Option<Restored> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return None,
        Err(err) => {
            warn!("dhcp6 {wan} cannot read {}: {err}", path.display());
            return None;
        }
    };
    let file = match file::parse_dhcp6_lease(&text) {
        Ok(file) => file,
        Err(err) => {
            warn!("{}", ignored_line(wan, path, &err.to_string()));
            return None;
        }
    };
    match binding_from_file(&file, wan, mac, now_unix(), clock::uptime_ms()) {
        Ok(restored) => Some(restored),
        Err(why) => {
            warn!("{}", ignored_line(wan, path, why));
            None
        }
    }
}

/// `dhcp6 wan0 /state/leases/dhcp6-wan0.toml: for another port; ignoring it`
fn ignored_line(wan: &str, path: &Path, why: &str) -> String {
    format!("dhcp6 {wan} {}: {why}; ignoring it", path.display())
}

/// The file as the binding and the deprecated list stand (#40): with neither, the file goes.
async fn save_binding(
    path: &Path,
    wan: &str,
    mac: [u8; 6],
    binding: Option<&Binding>,
    deprecated: &[Deprecated],
) {
    if binding.is_none() && deprecated.is_empty() {
        if let Err(err) = fs::remove_file(path)
            && err.kind() != io::ErrorKind::NotFound
        {
            warn!("dhcp6 {wan} cannot remove {}: {err}", path.display());
        }
        return;
    }
    let file = binding_file(
        wan,
        mac,
        binding,
        deprecated,
        now_unix(),
        clock::uptime_ms(),
    );
    let result = match file::render_dhcp6_lease(&file) {
        Ok(text) => state::write(path, text).await,
        Err(err) => Err(io::Error::other(err.to_string())),
    };
    match result {
        Ok(()) => debug!("dhcp6 {wan} binding saved {}", path.display()),
        Err(err) => warn!(
            "dhcp6 {wan} cannot save the binding to {}: {err}",
            path.display()
        ),
    }
}

/// Everything the task keeps between inputs.
struct Run<'a> {
    task: &'a WanTask,
    publisher: &'a Publisher,
    socket: ClientSocket,
    mac: [u8; 6],
    path: PathBuf,
    sends: Throttle,
    binding: Option<Binding>,
    deprecations: Deprecations,
    /// A Solicit refused while the link-local address was tentative, to send again (#34).
    pending: Option<(Vec<u8>, u8, Instant)>,
    /// When carrier went, for the two-hour drop.
    down_since: Option<Instant>,
    /// Delegations too short for a LAN's index already said on the console.
    left_out_said: BTreeSet<(Ipv6Net, String)>,
    /// The binding came from disk and no Reply has confirmed it, nor has the Rebind's deadline
    /// passed (#44).
    restored: bool,
}

/// The task: wait for the port, restore the binding from disk, run the client on the port's
/// socket, publish what it binds, and keep the clocks.
#[allow(clippy::too_many_lines)]
async fn run(
    task: &WanTask,
    publisher: &Publisher,
    mut world_rx: WorldRx,
) -> Result<(), TaskError> {
    // The identity is the port's MAC even over PPPoE, whose netdev has none and comes and goes
    // with every session (ADR-0023).
    let (port_index, mac) = wait_for_link(&mut world_rx, &task.port).await?;
    let mut ifindex = if task.netdev == task.port {
        port_index
    } else {
        wait_for_netdev(&mut world_rx, &task.netdev).await?
    };
    let lowest = lowest_port_mac(&world_rx.borrow()).unwrap_or(mac);
    let duid = match load_or_create_duid(Path::new(DUID_PATH), lowest) {
        Ok((duid, _)) => duid,
        Err(err) => {
            warn!(
                "dhcp6 {}: cannot keep {DUID_PATH}: {err}; using an unsaved DUID",
                task.wan
            );
            duid_ll(lowest)
        }
    };
    let failed = |err: openfeo_net::dhcp4::DriverError| {
        TaskError::from(format!("dhcp6 {}: {err}", task.wan))
    };
    let socket = ClientSocket::open(ifindex, &task.netdev).map_err(failed)?;
    let path = lease_path(&task.wan);
    let mut run = Run {
        task,
        publisher,
        socket,
        mac,
        path,
        sends: Throttle::new(NOISY_WINDOW),
        binding: None,
        deprecations: Deprecations::default(),
        pending: None,
        down_since: None,
        left_out_said: BTreeSet::new(),
        restored: false,
    };
    let restored = read_binding(&run.path, &task.wan, mac);
    if let Some(Restored {
        binding,
        deprecated,
    }) = &restored
    {
        if let Some(binding) = binding {
            info!("{}", restored_line(&task.wan, binding));
            run.binding = Some(binding.clone());
            run.restored = true;
        }
        run.deprecations.list.clone_from(deprecated);
        run.publish();
    }
    let config = Config {
        duid,
        iaid_pd: iaid::iaid(iaid::PD, &task.wan),
        iaid_na: iaid::iaid(iaid::NA, &task.wan),
        pd_hint: task.pd_hint,
    };
    let mut client = Client::new(config.clone(), seed(SEED_SALT ^ u64::from(ifindex)));
    let mut carrier = true;
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    let mut outputs = client.handle(
        Input::Start {
            binding: restored.and_then(|restored| restored.binding),
        },
        clock::uptime_ms(),
    );
    loop {
        run.act(outputs).await;
        let timer = client
            .next_timeout()
            .map(|at| Instant::from_std(clock::instant_at(at)));
        let deprecation = run
            .deprecations
            .next_deadline()
            .map(|at| Instant::from_std(clock::instant_at(at)));
        let drop_at = run.down_since.map(|since| since + CARRIERLESS_DROP);
        outputs = tokio::select! {
            received = run.socket.recv(&mut buf) => {
                let (_, len) = received.map_err(failed)?;
                client.handle(Input::Packet(buf[..len].to_vec()), clock::uptime_ms())
            }
            () = wait_until(timer) => client.handle(Input::Timeout, clock::uptime_ms()),
            () = wait_until(deprecation) => {
                run.purge().await;
                Vec::new()
            }
            () = wait_until(drop_at) => {
                run.down_since = None;
                run.drop_binding("no carrier for two hours").await;
                client = Client::new(config.clone(), seed(SEED_SALT ^ u64::from(ifindex)));
                Vec::new()
            }
            () = wait_until(run.pending.as_ref().map(|(_, _, at)| *at)) => {
                run.resend();
                Vec::new()
            }
            changed = world_rx.changed() => {
                changed.map_err(|_| "world publisher gone")?;
                let change = link_change(
                    (ifindex, carrier),
                    world_rx.borrow_and_update().links.get(&task.netdev),
                );
                match change {
                    LinkChange::None => Vec::new(),
                    LinkChange::Down => {
                        carrier = false;
                        run.down_since = Some(Instant::now());
                        client.handle(Input::LinkDown, clock::uptime_ms())
                    }
                    LinkChange::Up => {
                        carrier = true;
                        run.down_since = None;
                        client.handle(Input::LinkUp, clock::uptime_ms())
                    }
                    LinkChange::Reopen(index) => {
                        // A new netdev under the same name (a PPP session's new unit): a flap in
                        // place, the binding kept.
                        let mut outputs = if carrier {
                            client.handle(Input::LinkDown, clock::uptime_ms())
                        } else {
                            Vec::new()
                        };
                        run.socket = ClientSocket::open(index, &task.netdev).map_err(failed)?;
                        ifindex = index;
                        carrier = true;
                        run.down_since = None;
                        outputs.extend(client.handle(Input::LinkUp, clock::uptime_ms()));
                        outputs
                    }
                }
            }
        };
    }
}

/// Sleep until `at`, or forever when there is no timer.
async fn wait_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

impl Run<'_> {
    /// Do what the core asked: send, bind, deprecate, tell the console.
    async fn act(&mut self, outputs: Vec<Output>) {
        for output in outputs {
            match output {
                Output::Send(bytes) => self.send(bytes),
                Output::Bound { binding, renewed } => self.bound(binding, renewed).await,
                Output::Gone(nets) => self.gone(&nets).await,
                Output::Note(note) => {
                    if let Some(line) = note_line(&self.task.wan, &note) {
                        info!("{line}");
                    } else {
                        debug!("dhcp6 {}: {note:?}", self.task.wan);
                    }
                    if self.restored && ends_restored(&note) {
                        self.restored = false;
                        self.publish();
                    }
                }
            }
        }
    }

    fn send(&mut self, bytes: Vec<u8>) {
        if let Err(err) = self.socket.send(&bytes) {
            if transient_send_error(&err) {
                debug!("dhcp6 {}: send: {err}; again in a second", self.task.wan);
                self.pending = Some((bytes, RESEND_TRIES, Instant::now() + RESEND_AFTER));
                return;
            }
            let line = format!("dhcp6 {}: send: {err}", self.task.wan);
            if let Some(line) = self.sends.line(Instant::now(), &line) {
                warn!("{line}");
            } else {
                debug!("{line}");
            }
        }
    }

    /// The Solicit refused a second ago, again (#34).
    fn resend(&mut self) {
        let Some((bytes, tries_left, _)) = self.pending.take() else {
            return;
        };
        match self.socket.send(&bytes) {
            Ok(()) => {}
            Err(err) if transient_send_error(&err) && tries_left > 1 => {
                self.pending = Some((bytes, tries_left - 1, Instant::now() + RESEND_AFTER));
            }
            Err(err) => warn!("dhcp6 {}: send: {err}", self.task.wan),
        }
    }

    async fn bound(&mut self, binding: Binding, renewed: bool) {
        self.restored = false;
        let nets: Vec<Ipv6Net> = binding.nets().collect();
        self.deprecations.revive(&nets);
        let same = self
            .binding
            .as_ref()
            .is_some_and(|old| old.nets().collect::<Vec<_>>() == nets);
        if renewed && same {
            info!("dhcp6 {} renewed", self.task.wan);
        } else {
            info!("{}", bound_line(&self.task.wan, &binding));
            info!("{}", resolvers_line(&self.task.wan, &binding));
        }
        save_binding(
            &self.path,
            &self.task.wan,
            self.mac,
            Some(&binding),
            &self.deprecations.list,
        )
        .await;
        self.binding = Some(binding);
        self.publish();
        self.say_left_out();
    }

    /// The file follows every change of the binding or the deprecated list (#40).
    async fn save(&self) {
        save_binding(
            &self.path,
            &self.task.wan,
            self.mac,
            self.binding.as_ref(),
            &self.deprecations.list,
        )
        .await;
    }

    /// A delegation too short for a LAN's index is said once per prefix and LAN (SPEC §7.3):
    /// the LAN keeps its other prefixes and the owner learns why this one gave it nothing.
    fn say_left_out(&mut self) {
        let world = self.publisher.current();
        let lan6 = lan6::prefixes(&world);
        let indexes: BTreeMap<String, u32> = world
            .config
            .lans
            .iter()
            .enumerate()
            .map(|(position, lan)| (lan.name.clone(), lan6::lan_index(lan, position + 1)))
            .collect();
        for line in left_out_lines(
            &self.task.wan,
            &lan6.left_out,
            &indexes,
            &mut self.left_out_said,
        ) {
            warn!("{line}");
        }
    }

    async fn gone(&mut self, nets: &[Ipv6Net]) {
        let now_ms = clock::uptime_ms();
        for net in nets {
            if net.prefix_len() == 128 {
                info!("dhcp6 {} address {} gone", self.task.wan, net.addr());
                continue;
            }
            let left = remaining_valid_ms(self.binding.as_ref(), *net, now_ms);
            let until = deprecation_deadline(now_ms, left);
            info!(
                "{}",
                gone_line(&self.task.wan, *net, until.saturating_sub(now_ms) / MS)
            );
            self.deprecations.add(*net, until);
        }
        if let Some(binding) = self.binding.as_mut() {
            binding.prefixes.retain(|lease| !nets.contains(&lease.net));
            binding.addresses.retain(|lease| !nets.contains(&lease.net));
        }
        self.save().await;
        self.publish();
    }

    /// Deprecations whose deadline passed are dropped.
    async fn purge(&mut self) {
        for net in self.deprecations.purge(clock::uptime_ms()) {
            info!("dhcp6 {} prefix {net} dropped", self.task.wan);
        }
        self.save().await;
        self.publish();
    }

    /// The binding is gone for `why`: everything it held goes through deprecation, and the
    /// file keeps the deprecated list (#40).
    async fn drop_binding(&mut self, why: &str) {
        info!("dhcp6 {} binding dropped: {why}", self.task.wan);
        if let Some(binding) = self.binding.take() {
            let nets: Vec<Ipv6Net> = binding.nets().collect();
            self.binding = Some(binding);
            self.gone(&nets).await;
            self.binding = None;
        }
        self.save().await;
        self.publish();
    }
    /// The World's view: the binding with the deprecations, or just the deprecations.
    fn publish(&self) {
        let fact = self.binding.as_ref().map_or_else(
            || WanDhcp6Fact {
                deprecated: self.deprecations.list.clone(),
                ..WanDhcp6Fact::default()
            },
            |binding| fact_from(binding, &self.deprecations.list, self.restored),
        );
        let wan = self.task.wan.clone();
        self.publisher.update(|world| {
            let facts = Arc::make_mut(&mut world.dhcp6);
            if fact == WanDhcp6Fact::default() {
                facts.remove(&wan);
            } else {
                facts.insert(wan.clone(), fact);
            }
        });
    }
}

fn lease_text(lease: &Lease6) -> String {
    format!(
        "{} (preferred {} s, valid {} s)",
        lease.net,
        lifetime_text(lease.preferred),
        lifetime_text(lease.valid)
    )
}

fn lifetime_text(secs: u32) -> String {
    if secs == u32::MAX {
        "infinite".to_owned()
    } else {
        secs.to_string()
    }
}

fn prefixes_text(binding: &Binding) -> String {
    if binding.prefixes.is_empty() {
        "prefix none".to_owned()
    } else {
        format!(
            "prefix {}",
            binding
                .prefixes
                .iter()
                .map(lease_text)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn addresses_text(binding: &Binding) -> String {
    if binding.addresses.is_empty() {
        "address none".to_owned()
    } else {
        format!(
            "address {}",
            binding
                .addresses
                .iter()
                .map(|lease| lease.net.addr().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// `dhcp6 wan0 bound prefix 2001:db8:100::/56 (preferred 40 s, valid 60 s) address
/// 2001:db8:ffff::1a4 t1=10s t2=16s from 000300010...`.
fn bound_line(wan: &str, binding: &Binding) -> String {
    format!(
        "dhcp6 {wan} bound {} {} t1={}s t2={}s from {}",
        prefixes_text(binding),
        addresses_text(binding),
        lifetime_text(binding.t1),
        lifetime_text(binding.t2),
        hex(&binding.server)
    )
}

/// `dhcp6 wan0 resolvers 2001:db8:ffff::1 search isp.example` (`none` for an empty list).
fn resolvers_line(wan: &str, binding: &Binding) -> String {
    let list = |items: Vec<String>| {
        if items.is_empty() {
            "none".to_owned()
        } else {
            items.join(",")
        }
    };
    format!(
        "dhcp6 {wan} resolvers {} search {}",
        list(binding.dns.iter().map(ToString::to_string).collect()),
        list(binding.search.clone())
    )
}

/// `dhcp6 wan0 binding restored from disk: prefix … address …`.
fn restored_line(wan: &str, binding: &Binding) -> String {
    format!(
        "dhcp6 {wan} binding restored from disk: {} {}",
        prefixes_text(binding),
        addresses_text(binding)
    )
}

/// `dhcp6 wan0 prefix 2001:db8:100::/56 gone: deprecated for 55 s`.
/// `dhcp6 wan0 prefix 2001:db8:100::/60 is too short for lan1 (index 20)`: once per prefix and
/// LAN while the prefix is held; one that leaves and comes back is said again.
fn left_out_lines(
    wan: &str,
    left_out: &[(Ipv6Net, String)],
    indexes: &BTreeMap<String, u32>,
    said: &mut BTreeSet<(Ipv6Net, String)>,
) -> Vec<String> {
    said.retain(|pair| left_out.contains(pair));
    left_out
        .iter()
        .filter(|pair| said.insert((*pair).clone()))
        .map(|(net, lan)| {
            format!(
                "dhcp6 {wan} prefix {net} is too short for {lan} (index {})",
                indexes.get(lan).copied().unwrap_or(0)
            )
        })
        .collect()
}

fn gone_line(wan: &str, net: Ipv6Net, secs: u64) -> String {
    format!("dhcp6 {wan} prefix {net} gone: deprecated for {secs} s")
}

/// The console line for a note, when it deserves one.
/// After these the binding restored from disk is either kept on its own timers (the Rebind went
/// unanswered, §18.2.12) or being replaced (the exchange restarts): it no longer counts as
/// unconfirmed, so the LAN stops advertising it on trust (#44). A Bound clears the flag itself.
fn ends_restored(note: &Note) -> bool {
    matches!(note, Note::RebindUnanswered | Note::Restarting(_))
}

fn note_line(wan: &str, note: &Note) -> Option<String> {
    Some(match note {
        Note::Soliciting => format!("dhcp6 {wan} soliciting"),
        Note::Requesting => format!("dhcp6 {wan} requesting"),
        Note::Renewing | Note::Ignored(_) => return None,
        Note::Rebinding => format!("dhcp6 {wan} rebinding"),
        Note::RebindUnanswered => {
            format!("dhcp6 {wan} rebind unanswered: binding kept until it lapses")
        }
        Note::NoPrefixAvailable => format!("dhcp6 {wan} no prefix available"),
        Note::NoAddressAvailable => format!("dhcp6 {wan} no address available"),
        Note::Restarting(why) => format!("dhcp6 {wan} restarting: {why}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    const MAC: [u8; 6] = [0x52, 0x54, 0, 0xfe, 0, 0];
    const SERVER: [u8; 10] = [0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn net(text: &str) -> Ipv6Net {
        text.parse().unwrap()
    }

    fn binding(bound_at: u64) -> Binding {
        Binding {
            server: SERVER.to_vec(),
            prefixes: vec![Lease6 {
                net: net("2001:db8:100::/56"),
                preferred: 40,
                valid: 60,
            }],
            addresses: vec![Lease6 {
                net: net("2001:db8:ffff::1a4/128"),
                preferred: 40,
                valid: 60,
            }],
            t1: 10,
            t2: 16,
            dns: vec!["2001:db8:ffff::1".parse().unwrap()],
            search: vec!["isp.example".to_owned()],
            bound_at,
        }
    }

    fn deprecated(until_ms: u64) -> Deprecated {
        Deprecated {
            net: net("2001:db8:200::/56"),
            until_ms,
        }
    }

    #[test]
    fn fact_from_carries_lifetimes_relative_to_obtained() {
        let fact = fact_from(&binding(10_000), &[deprecated(70_000)], false);
        assert_eq!(
            fact.prefixes,
            vec![Lifetimed {
                net: net("2001:db8:100::/56"),
                obtained_ms: 10_000,
                preferred_secs: 40,
                valid_secs: 60,
            }]
        );
        assert_eq!(fact.addresses[0].net, net("2001:db8:ffff::1a4/128"));
        assert_eq!(fact.deprecated, vec![deprecated(70_000)]);
        assert_eq!(
            fact.dns,
            vec!["2001:db8:ffff::1".parse::<std::net::Ipv6Addr>().unwrap()]
        );
        assert_eq!(fact.search, vec!["isp.example".to_owned()]);
        assert_eq!(fact.server, SERVER.to_vec());
    }

    #[test]
    fn binding_file_round_trips_with_its_deprecated_list() {
        // Bound 5 s ago on the process clock, at wall-clock second 1_800_000_000.
        let file = binding_file(
            "wan0",
            MAC,
            Some(&binding(10_000)),
            &[deprecated(70_000)],
            1_800_000_000,
            15_000,
        );
        assert_eq!(file.wan, "wan0");
        assert_eq!(file.mac, "52:54:00:fe:00:00");
        assert_eq!(file.server_duid, "00030001aabbccddeeff");
        assert_eq!(file.obtained_unix, 1_799_999_995);
        assert_eq!(file.prefixes[0].net, "2001:db8:100::/56");
        assert_eq!(
            (file.prefixes[0].preferred_secs, file.prefixes[0].valid_secs),
            (40, 60)
        );
        assert_eq!(file.addresses[0].net, "2001:db8:ffff::1a4/128");
        assert_eq!((file.t1_secs, file.t2_secs), (10, 16));
        assert_eq!(file.deprecated[0].net, "2001:db8:200::/56");
        assert_eq!(
            file.deprecated[0].until_unix, 1_800_000_055,
            "55 s ahead on both clocks"
        );
        let text = file::render_dhcp6_lease(&file).unwrap();
        let parsed = file::parse_dhcp6_lease(&text).unwrap();
        assert_eq!(parsed, file);
        // Read back 20 s later, on a process clock that has run a second and a half: the
        // leases lose the 25 s since the Reply (the LANs are told what is left, RFC 7084 L-13),
        // T1 and T2 are already due, the binding counts from now, and the deprecation keeps
        // its deadline.
        let Restored {
            binding: Some(restored),
            deprecated,
        } = binding_from_file(&parsed, "wan0", MAC, 1_800_000_020, 1_500).expect("restored")
        else {
            panic!("no binding");
        };
        assert_eq!(
            (restored.prefixes[0].preferred, restored.prefixes[0].valid),
            (15, 35)
        );
        assert_eq!(
            (restored.addresses[0].preferred, restored.addresses[0].valid),
            (15, 35)
        );
        assert_eq!(
            restored.bound_at, 1_500,
            "counted from now, not from before boot"
        );
        assert_eq!(
            (restored.t1, restored.t2),
            (0, 0),
            "25 s past a T1 of 10 and a T2 of 16"
        );
        assert_eq!(restored.server, SERVER.to_vec());
        assert_eq!(restored.dns, binding(0).dns);
        assert_eq!(
            deprecated,
            vec![Deprecated {
                net: net("2001:db8:200::/56"),
                until_ms: 36_500
            }]
        );
    }

    /// #40: a file holding a deprecated list and no binding (an expiry no Reply followed)
    /// restores the list, so the old prefix is still advertised deprecated after a reboot.
    #[test]
    fn a_file_with_only_a_deprecated_list_restores_it() {
        let file = binding_file(
            "wan0",
            MAC,
            None,
            &[deprecated(70_000)],
            1_800_000_000,
            15_000,
        );
        assert!(file.prefixes.is_empty() && file.addresses.is_empty());
        assert_eq!(file.server_duid, "");
        let text = file::render_dhcp6_lease(&file).unwrap();
        let parsed = file::parse_dhcp6_lease(&text).unwrap();
        let restored = binding_from_file(&parsed, "wan0", MAC, 1_800_000_020, 1_500).unwrap();
        assert_eq!(restored.binding, None);
        assert_eq!(
            restored.deprecated,
            vec![Deprecated {
                net: net("2001:db8:200::/56"),
                until_ms: 36_500
            }]
        );
        assert_eq!(
            binding_from_file(&parsed, "wan0", MAC, 1_800_000_060, 1_500),
            Err("lapsed"),
            "a deadline passed and no binding: nothing to restore"
        );
    }

    /// #41: a corrupt server DUID rejects the file instead of restoring a binding whose Renew
    /// would carry an empty Server Identifier.
    #[test]
    fn a_corrupt_server_duid_rejects_the_file() {
        let mut file = binding_file(
            "wan0",
            MAC,
            Some(&binding(10_000)),
            &[],
            1_800_000_000,
            15_000,
        );
        file.server_duid = "zz".to_owned();
        assert_eq!(
            binding_from_file(&file, "wan0", MAC, 1_800_000_001, 1),
            Err("server DUID is not hex")
        );
        assert_eq!(
            ignored_line(
                "wan0",
                Path::new("/state/leases/dhcp6-wan0.toml"),
                "server DUID is not hex"
            ),
            "dhcp6 wan0 /state/leases/dhcp6-wan0.toml: server DUID is not hex; ignoring it"
        );
    }

    /// #40: dropping the binding writes the deprecated list alone; an empty list removes the file.
    #[tokio::test]
    async fn dropping_the_binding_keeps_the_deprecated_list_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dhcp6-wan0.toml");
        let gone = Deprecated {
            net: net("2001:db8:200::/56"),
            until_ms: clock::uptime_ms() + 3_600_000,
        };
        save_binding(&path, "wan0", MAC, None, std::slice::from_ref(&gone)).await;
        let restored = read_binding(&path, "wan0", MAC).expect("the list is on disk");
        assert_eq!(restored.binding, None);
        assert_eq!(restored.deprecated.len(), 1);
        assert_eq!(restored.deprecated[0].net, gone.net);
        save_binding(&path, "wan0", MAC, None, &[]).await;
        assert!(!path.exists(), "nothing left to keep");
    }

    #[test]
    fn a_restored_binding_keeps_infinite_lifetimes_infinite() {
        let mut forever = binding(10_000);
        forever.prefixes[0].valid = u32::MAX;
        forever.prefixes[0].preferred = u32::MAX;
        forever.t1 = u32::MAX;
        forever.t2 = u32::MAX;
        let file = binding_file("wan0", MAC, Some(&forever), &[], 1_800_000_000, 15_000);
        let Restored {
            binding: Some(restored),
            deprecated: _,
        } = binding_from_file(&file, "wan0", MAC, 1_800_900_000, 2_000).expect("restored")
        else {
            panic!("no binding");
        };
        assert_eq!(
            (restored.prefixes[0].preferred, restored.prefixes[0].valid),
            (u32::MAX, u32::MAX)
        );
        assert_eq!((restored.t1, restored.t2), (u32::MAX, u32::MAX));
        assert!(
            restored.addresses.is_empty(),
            "the 60 s address lapsed ten days ago"
        );
    }

    #[test]
    fn a_short_delegation_is_said_once_per_lan() {
        let mut said = BTreeSet::new();
        let indexes = BTreeMap::from([("lan0".to_owned(), 1), ("lan1".to_owned(), 20)]);
        let short = net("2001:db8:100::/60");
        let left_out = vec![(short, "lan1".to_owned())];
        assert_eq!(
            left_out_lines("wan0", &left_out, &indexes, &mut said),
            vec!["dhcp6 wan0 prefix 2001:db8:100::/60 is too short for lan1 (index 20)".to_owned()]
        );
        assert!(
            left_out_lines("wan0", &left_out, &indexes, &mut said).is_empty(),
            "said once"
        );
        // The prefix left the binding and came back: said again.
        assert!(
            left_out_lines("wan0", &[], &indexes, &mut said).is_empty(),
            "nothing left out, nothing said"
        );
        assert_eq!(
            left_out_lines("wan0", &left_out, &indexes, &mut said).len(),
            1
        );
    }

    #[test]
    fn a_lapsed_or_foreign_binding_is_ignored() {
        let file = binding_file(
            "wan0",
            MAC,
            Some(&binding(10_000)),
            &[],
            1_800_000_000,
            15_000,
        );
        assert_eq!(
            binding_from_file(&file, "wan1", MAC, 1_800_000_001, 1),
            Err("for another WAN")
        );
        assert_eq!(
            binding_from_file(&file, "wan0", [1; 6], 1_800_000_001, 1),
            Err("for another port")
        );
        assert_eq!(
            binding_from_file(&file, "wan0", MAC, 1_800_000_100, 1),
            Err("lapsed"),
            "valid 60 s, obtained 105 s ago"
        );
        let Restored {
            binding: Some(kept),
            deprecated,
        } = binding_from_file(&file, "wan0", MAC, 1_800_000_050, 1).unwrap()
        else {
            panic!("no binding");
        };
        assert_eq!(kept.prefixes.len(), 1, "55 s old, 60 s valid: still there");
        assert_eq!(deprecated, vec![]);
        let mut old_deprecation = file.clone();
        old_deprecation.deprecated.push(Dhcp6Deprecated {
            net: "2001:db8:200::/56".to_owned(),
            until_unix: 1_800_000_010,
        });
        let Restored {
            binding: Some(_),
            deprecated,
        } = binding_from_file(&old_deprecation, "wan0", MAC, 1_800_000_020, 1).unwrap()
        else {
            panic!("no binding");
        };
        assert_eq!(
            deprecated,
            vec![],
            "a deadline already passed is not restored"
        );
    }

    #[test]
    fn a_future_binding_is_counted_from_now() {
        // Written at wall-clock 1_800_000_000; read on a board whose clock sits at its floor.
        let file = binding_file(
            "wan0",
            MAC,
            Some(&binding(10_000)),
            &[],
            1_800_000_000,
            10_000,
        );
        let Restored {
            binding: Some(restored),
            deprecated: _,
        } = binding_from_file(&file, "wan0", MAC, 1_700_000_000, 50_000).expect("restored")
        else {
            panic!("no binding");
        };
        assert_eq!(restored.bound_at, 50_000, "counted from now");
        assert_eq!(restored.prefixes[0].valid, 60);
    }

    #[test]
    fn a_gone_prefix_is_deprecated_for_the_lower_of_two_hours_and_its_remaining_valid_lifetime() {
        let bound = binding(10_000);
        // At 15 s, 55 s of the 60 s valid lifetime remain.
        let left = remaining_valid_ms(Some(&bound), net("2001:db8:100::/56"), 15_000);
        assert_eq!(left, Some(55_000));
        assert_eq!(deprecation_deadline(15_000, left), 70_000);
        assert_eq!(
            deprecation_deadline(15_000, Some(10 * 3600 * MS)),
            15_000 + DEPRECATION_SECS * MS,
            "a long lease is capped at two hours"
        );
        assert_eq!(
            deprecation_deadline(15_000, None),
            15_000 + DEPRECATION_SECS * MS
        );
        assert_eq!(
            remaining_valid_ms(Some(&bound), net("2001:db8:9::/56"), 15_000),
            None,
            "a prefix the binding never held"
        );
        assert_eq!(
            remaining_valid_ms(Some(&bound), net("2001:db8:100::/56"), 90_000),
            Some(0),
            "already lapsed"
        );
    }

    #[test]
    fn carrier_loss_keeps_the_deprecated_list() {
        let mut state = Deprecations::default();
        state.add(net("2001:db8:200::/56"), 70_000);
        state.add(net("2001:db8:300::/56"), 90_000);
        state.add(net("2001:db8:200::/56"), 99_000);
        assert_eq!(
            state.list.len(),
            2,
            "a prefix is listed once, with its first deadline"
        );
        assert_eq!(state.next_deadline(), Some(70_000));
        // Carrier comes and goes: nothing here reads the carrier, so the list stands.
        assert_eq!(state.purge(69_999), vec![]);
        assert_eq!(state.list.len(), 2);
        assert_eq!(state.purge(70_000), vec![net("2001:db8:200::/56")]);
        assert_eq!(state.next_deadline(), Some(90_000));
        state.revive(&[net("2001:db8:300::/56")]);
        assert_eq!(
            state.list,
            vec![],
            "a prefix that came back is deprecated no more"
        );
        assert_eq!(state.next_deadline(), None);
    }

    /// #44: the World knows a restored binding from a confirmed one.
    #[test]
    fn fact_from_carries_the_restored_flag() {
        let bound = binding(10_000);
        assert!(fact_from(&bound, &[], true).restored);
        assert!(!fact_from(&bound, &[], false).restored);
        assert_eq!(
            fact_from(&bound, &[], true).prefixes,
            fact_from(&bound, &[], false).prefixes
        );
    }

    #[test]
    fn lines_follow_the_contract() {
        let bound = binding(10_000);
        assert_eq!(
            bound_line("wan0", &bound),
            "dhcp6 wan0 bound prefix 2001:db8:100::/56 (preferred 40 s, valid 60 s) address 2001:db8:ffff::1a4 t1=10s t2=16s from 00030001aabbccddeeff"
        );
        assert_eq!(
            resolvers_line("wan0", &bound),
            "dhcp6 wan0 resolvers 2001:db8:ffff::1 search isp.example"
        );
        assert_eq!(
            restored_line("wan0", &bound),
            "dhcp6 wan0 binding restored from disk: prefix 2001:db8:100::/56 (preferred 40 s, valid 60 s) address 2001:db8:ffff::1a4"
        );
        let mut bare = bound.clone();
        bare.prefixes.clear();
        bare.addresses.clear();
        bare.dns.clear();
        bare.search.clear();
        assert_eq!(
            bound_line("wan0", &bare),
            "dhcp6 wan0 bound prefix none address none t1=10s t2=16s from 00030001aabbccddeeff"
        );
        assert_eq!(
            resolvers_line("wan0", &bare),
            "dhcp6 wan0 resolvers none search none"
        );
        assert_eq!(
            gone_line("wan0", net("2001:db8:100::/56"), 55),
            "dhcp6 wan0 prefix 2001:db8:100::/56 gone: deprecated for 55 s"
        );
        assert_eq!(
            note_line("wan0", &Note::Soliciting),
            Some("dhcp6 wan0 soliciting".to_owned())
        );
        assert_eq!(
            note_line("wan0", &Note::Requesting),
            Some("dhcp6 wan0 requesting".to_owned())
        );
        assert_eq!(
            note_line("wan0", &Note::Rebinding),
            Some("dhcp6 wan0 rebinding".to_owned())
        );
        assert_eq!(
            note_line("wan0", &Note::NoPrefixAvailable),
            Some("dhcp6 wan0 no prefix available".to_owned())
        );
        assert_eq!(
            note_line("wan0", &Note::NoAddressAvailable),
            Some("dhcp6 wan0 no address available".to_owned())
        );
        assert_eq!(
            note_line("wan0", &Note::Restarting("the binding expired")),
            Some("dhcp6 wan0 restarting: the binding expired".to_owned())
        );
        assert_eq!(
            note_line("wan0", &Note::RebindUnanswered),
            Some("dhcp6 wan0 rebind unanswered: binding kept until it lapses".to_owned())
        );
        assert_eq!(note_line("wan0", &Note::Ignored("x")), None);
        assert_eq!(note_line("wan0", &Note::Renewing), None);
        assert_eq!(
            lease_path("wan0").to_str(),
            Some("/state/leases/dhcp6-wan0.toml")
        );
    }

    #[test]
    fn a_restored_binding_stops_being_restored_when_the_exchange_restarts() {
        assert!(ends_restored(&Note::RebindUnanswered));
        assert!(ends_restored(&Note::Restarting(
            "the server has no binding for us"
        )));
        assert!(ends_restored(&Note::Restarting(
            "the server reported a failure"
        )));
        assert!(ends_restored(&Note::Restarting("no reply to the request")));
        for note in [
            Note::Soliciting,
            Note::Requesting,
            Note::Renewing,
            Note::Rebinding,
            Note::NoPrefixAvailable,
            Note::NoAddressAvailable,
            Note::Ignored("x"),
        ] {
            assert!(!ends_restored(&note), "{note:?}");
        }
    }
}
