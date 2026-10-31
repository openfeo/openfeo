// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The router child (SPEC §6): a tokio runtime that checks the kernel (§4.2), names the ports
//! (§7.1), loads the configuration (§8.2), publishes the World (§6.2) and runs the appliers that
//! make the kernel match it, heartbeating to PID 1 only while healthy (§5.3). Every line it logs
//! for the console is a contract with the harness scenarios.

use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use openfeo_apply::ApplyError;
use openfeo_apply::links::LinksApplier;
use openfeo_apply::nft::NftApplier;
use openfeo_apply::routing::RoutingApplier;
use openfeo_apply::sysctl::SysctlApplier;
use openfeo_config::load::{self, Source};
use openfeo_config::{Config, PortMap, file};
use openfeo_init::cmdline::{Cmdline, Mode};
use openfeo_init::ctl::CtlPipe;
use openfeo_netlink::{Cache, Netlink};
use openfeo_nft::Nft;
use openfeo_platform::{atomic, kconfig, ports};
use openfeo_reconcile::nft::DesiredNft;
use openfeo_runtime::log::{DEFAULT_RING_BYTES, Ring};
use openfeo_runtime::supervise::TaskError;
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{HealthTracker, Publisher, Supervisor};
use openfeo_world::health::{Status, Subsystem};
use openfeo_world::portmap::{PresentPort, assign};
use openfeo_world::{LinkFact, MacAddr, World, rename};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::boot::{ConfigDecision, KernelDecision, config_decision, kernel_decision};
use crate::chaos::{self, Chaos};
use crate::heartbeat;

/// The persistent configuration (SPEC §5.2).
pub const CONFIG_PATH: &str = "/state/config.toml";
/// The sticky port map (SPEC §7.1).
pub const PORTMAP_PATH: &str = "/state/identity/portmap";
const SYSFS_CLASS_NET: &str = "/sys/class/net";
const KMSG: &str = "/dev/kmsg";
/// How long to wait for renamed ports to show their new names in the cache.
const RENAME_SETTLE: Duration = Duration::from_secs(2);
/// Backoff between failed apply passes: 1 s doubling to this.
const MAX_APPLY_BACKOFF: Duration = Duration::from_secs(30);
/// The appliers of one pass, in order: links (bridges), routing (addresses, routes), nft (the
/// ruleset), sysctl (forwarding, which [`may_run`] gates on the ruleset).
const APPLY_ORDER: [Subsystem; 4] = [
    Subsystem::Links,
    Subsystem::Routing,
    Subsystem::Nft,
    Subsystem::Sysctl,
];

/// Whether `subsystem` runs in a pass where the nft applier has (`nft_ok_this_pass`) or has not
/// succeeded: forwarding is never switched on without the ruleset (SPEC §5.6, §7.9).
fn may_run(subsystem: Subsystem, nft_ok_this_pass: bool) -> bool {
    subsystem != Subsystem::Sysctl || nft_ok_this_pass
}

/// Whether a pass ends with `ready generation=N` on the console. `converging_ops` are the links
/// and routing operations of the pass: the cache has yet to show them, so a later pass decides.
/// `total_ops` includes the nft and sysctl ones, which are complete when they return (a
/// restarted child applies its ruleset once and is converged right there). `announced` is
/// whether the last converged pass already said so.
fn announce_ready(converging_ops: usize, total_ops: usize, announced: bool) -> bool {
    converging_ops == 0 && (total_ops > 0 || !announced)
}

/// Run until PID 1 goes away (or a chaos knob fires). Never returns `Ok` in practice.
///
/// # Errors
///
/// When the runtime cannot start or a boot step fails outright (netlink unavailable, no sysfs).
pub fn run(mode: Mode, cmdline: &Cmdline, version: &str) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("tokio runtime")?;
    runtime.block_on(main_async(mode, cmdline, version))
}

async fn main_async(mode: Mode, cmdline: &Cmdline, version: &str) -> anyhow::Result<()> {
    init_logging();
    info!("router mode={mode} version={version}");

    let hung = Arc::new(AtomicBool::new(false));
    if let Some(knob) = chaos::from_cmdline(cmdline) {
        info!("chaos {knob}");
        spawn_chaos(knob, hung.clone());
    }

    let health = HealthTracker::new();
    let supervisor = Supervisor::new(health.clone());
    let ctl = CtlPipe::from_env();
    if ctl.is_none() {
        warn!("no control pipe (not supervised by PID 1); heartbeats go nowhere");
    }
    tokio::spawn(heartbeat::run(ctl, health.clone(), hung));

    match kernel_decision(kconfig::read_running(), mode) {
        KernelDecision::Proceed(n) => info!("kernel: all {n} required options present"),
        KernelDecision::SkipContainer(reason) => {
            warn!("kernel: {reason}; check skipped in container mode");
        }
        KernelDecision::Refuse(reason) => {
            error!("kernel: {reason}; refusing to start router services");
            return std::future::pending().await;
        }
    }

    let (nl, monitor) = Netlink::connect().await.context("netlink")?;
    let cache_rx = monitor.subscribe();
    {
        let health = health.clone();
        tokio::spawn(async move {
            if let Err(err) = monitor.run().await {
                error!("netlink monitor stopped: {err}");
                health.task_dead("netlink-monitor");
            }
        });
    }

    let portmap = name_ports(&nl, &cache_rx).await?;
    let config = load_config(&portmap);

    let (publisher, world_rx) = Publisher::new(World::new(config, portmap));
    let publisher = Arc::new(publisher);
    publisher.update(|world| world.links = Arc::new(link_facts(&cache_rx.borrow())));

    {
        let publisher = publisher.clone();
        let cache_rx = cache_rx.clone();
        supervisor.spawn("link-facts", move || {
            link_facts_task(publisher.clone(), cache_rx.clone())
        });
    }
    crate::dhcp4::spawn_all(&supervisor, &publisher, &world_rx);
    crate::dhcp4_server::spawn_all(&supervisor, &publisher, &world_rx);
    crate::dns::spawn(&supervisor, &publisher, &world_rx);
    crate::time::spawn(&supervisor, &publisher, &world_rx);
    {
        let health = health.clone();
        supervisor.spawn("apply", move || {
            apply_task(
                world_rx.clone(),
                cache_rx.clone(),
                nl.clone(),
                health.clone(),
            )
        });
    }

    std::future::pending().await
}

/// `tracing` into the 8 MiB ring and `/dev/kmsg` (stderr when that is not openable).
fn init_logging() {
    let ring = Arc::new(Ring::new(DEFAULT_RING_BYTES));
    let kmsg = std::fs::OpenOptions::new()
        .write(true)
        .open(KMSG)
        .ok()
        .map(|file| Box::new(file) as Box<dyn std::io::Write + Send>);
    if let Err(err) = openfeo_runtime::log::init("openfeo", ring, kmsg) {
        let _ = writeln!(std::io::stderr(), "openfeo: logging: {err}");
    }
}

fn spawn_chaos(knob: Chaos, hung: Arc<AtomicBool>) {
    tokio::spawn(async move {
        tokio::time::sleep(knob.after()).await;
        match knob {
            Chaos::ChildExit { .. } => {
                info!("chaos child-exit: exiting with status 3");
                std::process::exit(3)
            }
            Chaos::ChildHang { .. } => {
                info!("chaos child-hang: heartbeats stopped");
                hung.store(true, Ordering::Relaxed);
            }
        }
    });
}

/// Enumerate the ports, give them sticky names, rename the kernel interfaces, persist the map.
async fn name_ports(
    nl: &Netlink,
    cache_rx: &watch::Receiver<Arc<Cache>>,
) -> anyhow::Result<PortMap> {
    let inventory = ports::enumerate(Path::new(SYSFS_CLASS_NET))
        .with_context(|| format!("ports: cannot read {SYSFS_CLASS_NET}"))?;
    for skipped in &inventory.skipped {
        debug!("port skipped {}: {}", skipped.ifname, skipped.reason);
    }
    let known = known_portmap();
    let present: Vec<PresentPort> = inventory
        .ports
        .iter()
        .map(|port| PresentPort {
            id: port.id.clone(),
            ifname: port.ifname.clone(),
            mac: port.mac.parse().unwrap_or(MacAddr([0; 6])),
        })
        .collect();
    let assignment = assign(&known, &present);
    for port in &inventory.ports {
        let name = assignment
            .names
            .get(&port.ifname)
            .map_or("?", String::as_str);
        let tag = if assignment.added.iter().any(|e| e.id == port.id) {
            "new"
        } else {
            "known"
        };
        info!(
            "port {name} {} id={} mac={} ({tag})",
            port.ifname, port.id, port.mac
        );
    }
    for missing in &assignment.missing {
        warn!("port missing {} id={}", missing.name, missing.id);
    }
    info!("ports total={}", inventory.ports.len());

    rename_ports(nl, cache_rx, &assignment.names).await?;

    if assignment.added.is_empty() {
        info!("portmap: unchanged ({} ports)", assignment.map.ports.len());
    } else {
        match persist_portmap(&assignment.map) {
            Ok(()) => info!(
                "portmap: recorded {} new ports in {PORTMAP_PATH}",
                assignment.added.len()
            ),
            Err(err) => warn!("portmap: cannot write {PORTMAP_PATH}: {err:#}"),
        }
    }
    Ok(assignment.map)
}

/// The persisted port map, or an empty one when there is none (first boot) or it is unreadable.
fn known_portmap() -> PortMap {
    match std::fs::read_to_string(PORTMAP_PATH) {
        Ok(text) => file::parse_portmap(&text).unwrap_or_else(|err| {
            warn!("portmap: {PORTMAP_PATH}: {err}; starting empty");
            PortMap::default()
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => PortMap::default(),
        Err(err) => {
            warn!("portmap: cannot read {PORTMAP_PATH}: {err}; starting empty");
            PortMap::default()
        }
    }
}

/// Rename the kernel interfaces to their `pN` names (down first, SPEC §7.1) and wait for the
/// cache to show the new names, so the first World carries facts under the right keys.
async fn rename_ports(
    nl: &Netlink,
    cache_rx: &watch::Receiver<Arc<Cache>>,
    names: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let cache = cache_rx.borrow().clone();
    let current: Vec<(u32, String)> = cache
        .links
        .values()
        .map(|link| (link.index, link.name.clone()))
        .collect();
    let plan = rename::plan(&current, names);
    for step in &plan {
        if cache.links.get(&step.index).is_some_and(|link| link.up) {
            nl.link_set_up(step.index, false)
                .await
                .with_context(|| format!("set link {} down before renaming", step.index))?;
        }
        nl.link_set_name(step.index, &step.to)
            .await
            .with_context(|| format!("rename link {} to {}", step.index, step.to))?;
        if !step.to.starts_with("rn") {
            let from = current
                .iter()
                .find(|(index, _)| *index == step.index)
                .map_or("?", |(_, name)| name.as_str());
            info!("renamed {from} -> {}", step.to);
        }
    }
    if plan.is_empty() {
        return Ok(());
    }
    let wanted: Vec<&String> = names.values().collect();
    let mut rx = cache_rx.clone();
    let settled = tokio::time::timeout(RENAME_SETTLE, async {
        loop {
            if wanted
                .iter()
                .all(|name| rx.borrow_and_update().link_by_name(name).is_some())
            {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await;
    if settled.is_err() {
        warn!("ports: renamed interfaces did not all appear in the cache within 2s");
    }
    Ok(())
}

fn persist_portmap(map: &PortMap) -> anyhow::Result<()> {
    let path = Path::new(PORTMAP_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic::write(
        path,
        file::render_portmap(map)?.as_bytes(),
        load::STATE_FILE_MODE,
    )?;
    Ok(())
}

/// Load `config.toml` against the live port map, falling back to first-boot defaults.
fn load_config(portmap: &PortMap) -> Config {
    match config_decision(load::load(Path::new(CONFIG_PATH), portmap)) {
        ConfigDecision::Use(loaded) => {
            match loaded.source {
                Source::File => {
                    if let Some(from) = loaded.migrated_from {
                        info!("config: migrated from version {from}");
                    }
                    info!(
                        "config: loaded {CONFIG_PATH} version={}",
                        loaded.config.config_version
                    );
                }
                Source::FirstBootDefaults => info!(
                    "config: none at {CONFIG_PATH}; first-boot defaults (all ports in lan0 192.168.1.1/24)"
                ),
            }
            loaded.config
        }
        ConfigDecision::Defaults { reason, violations } => {
            error!("config: {reason}; using first-boot defaults");
            for violation in violations {
                error!(
                    "config: error path={} code={} {}",
                    violation.path, violation.code, violation.message
                );
            }
            Config::first_boot(portmap)
        }
    }
}

/// Link facts from the cache, keyed by name.
fn link_facts(cache: &Cache) -> std::collections::BTreeMap<String, LinkFact> {
    cache
        .links
        .values()
        .map(|link| {
            (
                link.name.clone(),
                LinkFact {
                    index: link.index,
                    name: link.name.clone(),
                    up: link.up,
                    carrier: link.carrier,
                    mac: link.mac.map(MacAddr),
                    mtu: link.mtu,
                },
            )
        })
        .collect()
}

/// Publish a new World whenever the link facts change; log carrier transitions of our ports.
async fn link_facts_task(
    publisher: Arc<Publisher>,
    mut cache_rx: watch::Receiver<Arc<Cache>>,
) -> Result<(), TaskError> {
    loop {
        cache_rx.changed().await.map_err(|_| "netlink cache gone")?;
        let facts = link_facts(&cache_rx.borrow_and_update());
        if *publisher.current().links == facts {
            continue;
        }
        publisher.update(|world| {
            for (name, fact) in &facts {
                if !world.ports.names().any(|port| port == name) {
                    continue;
                }
                let before = world.links.get(name).map(|old| old.carrier);
                if before != Some(fact.carrier) && (before.is_some() || fact.carrier) {
                    info!("link {name} {}", if fact.carrier { "up" } else { "down" });
                }
            }
            world.links = Arc::new(facts);
        });
    }
}

/// The appliers of one child; a restarted child builds fresh ones (and a fresh libnftables
/// context), so its first pass applies the ruleset once and adopts everything else.
struct Appliers {
    links: LinksApplier,
    routing: RoutingApplier,
    nft: NftApplier,
    sysctl: SysctlApplier,
}

impl Appliers {
    fn new() -> Result<Self, TaskError> {
        Ok(Appliers {
            links: LinksApplier::new(),
            routing: RoutingApplier::new(),
            nft: NftApplier::new(
                Nft::new().map_err(|err| TaskError::from(format!("libnftables context: {err}")))?,
            ),
            sysctl: SysctlApplier::new(),
        })
    }

    /// One subsystem's pass; the operation count on success.
    async fn run(
        &mut self,
        subsystem: Subsystem,
        world: &World,
        cache: &Cache,
        nl: &Netlink,
        desired_nft: &DesiredNft,
    ) -> Result<usize, ApplyError> {
        let report = match subsystem {
            Subsystem::Links => {
                self.links
                    .apply(&openfeo_reconcile::links::links(world), cache, nl)
                    .await?
            }
            Subsystem::Routing => {
                self.routing
                    .apply(&openfeo_reconcile::routing::routing(world), cache, nl)
                    .await?
            }
            Subsystem::Nft => self.nft.apply(desired_nft)?,
            Subsystem::Sysctl => self.sysctl.apply(&openfeo_reconcile::sysctl::sysctl(
                world,
                desired_nft.forwarding,
            ))?,
            Subsystem::Netlink | Subsystem::Config | Subsystem::Supervisor => {
                openfeo_apply::Report::default()
            }
        };
        Ok(report.ops)
    }
}

/// The reconcile/apply loop (SPEC §6.2): on every World or cache change, one pass over
/// [`APPLY_ORDER`]; sysctl only after the ruleset applied in the same pass.
async fn apply_task(
    mut world_rx: WorldRx,
    mut cache_rx: watch::Receiver<Arc<Cache>>,
    nl: Netlink,
    health: HealthTracker,
) -> Result<(), TaskError> {
    let mut appliers = Appliers::new()?;
    let mut backoff = Duration::from_secs(1);
    let mut announced = false;
    loop {
        let world = world_rx.borrow_and_update().clone();
        let cache = cache_rx.borrow_and_update().clone();
        let generation = world.generation;
        let desired_nft = openfeo_reconcile::nft::nft(&world);
        let mut total_ops = 0;
        let mut converging_ops = 0;
        let mut failed = false;
        let mut nft_ok = false;
        for subsystem in APPLY_ORDER {
            if !may_run(subsystem, nft_ok) {
                debug!("apply {subsystem} skipped: ruleset not applied this pass");
                continue;
            }
            let result = {
                let _in_flight = health.begin(subsystem);
                appliers
                    .run(subsystem, &world, &cache, &nl, &desired_nft)
                    .await
            };
            match result {
                Ok(ops) => {
                    health.set(subsystem, Status::Ok);
                    nft_ok |= subsystem == Subsystem::Nft;
                    if ops > 0 {
                        info!("apply {subsystem} generation={generation} ops={ops}");
                    } else {
                        debug!("apply {subsystem} generation={generation} ops=0");
                    }
                    total_ops += ops;
                    if matches!(subsystem, Subsystem::Links | Subsystem::Routing) {
                        converging_ops += ops;
                    }
                }
                Err(err) => {
                    health.set(subsystem, Status::Degraded(err.to_string()));
                    warn!(
                        "apply {subsystem} failed: {err}; retry in {}s",
                        backoff.as_secs()
                    );
                    failed = true;
                }
            }
        }
        if failed {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_APPLY_BACKOFF);
            continue;
        }
        backoff = Duration::from_secs(1);
        if announce_ready(converging_ops, total_ops, announced) {
            info!("ready generation={generation}");
            announced = true;
        } else if converging_ops > 0 {
            announced = false;
        }
        tokio::select! {
            changed = world_rx.changed() => changed.map_err(|_| "world publisher gone")?,
            changed = cache_rx.changed() => changed.map_err(|_| "netlink cache gone")?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_waits_for_nft() {
        assert!(!may_run(Subsystem::Sysctl, false));
        assert!(may_run(Subsystem::Sysctl, true));
        for subsystem in [Subsystem::Links, Subsystem::Routing, Subsystem::Nft] {
            assert!(may_run(subsystem, false), "{subsystem}");
            assert!(may_run(subsystem, true), "{subsystem}");
        }
    }

    #[test]
    fn ready_follows_converged_passes() {
        // Nothing happened and ready was already said: silence.
        assert!(!announce_ready(0, 0, true));
        // Nothing happened after work in an earlier pass: ready.
        assert!(announce_ready(0, 0, false));
        // Only nft/sysctl work (a restarted child applying its ruleset once): the kernel is
        // converged, nothing more will arrive on the cache, say ready now.
        assert!(announce_ready(0, 1, true));
        assert!(announce_ready(0, 3, false));
        // Links or routing changed: the cache has yet to show it, a later pass decides.
        assert!(!announce_ready(2, 2, false));
        assert!(!announce_ready(1, 2, true));
    }

    #[test]
    fn apply_order_ends_with_sysctl() {
        assert_eq!(
            APPLY_ORDER,
            [
                Subsystem::Links,
                Subsystem::Routing,
                Subsystem::Nft,
                Subsystem::Sysctl
            ]
        );
        assert_eq!(APPLY_ORDER.last(), Some(&Subsystem::Sysctl));
    }
}
