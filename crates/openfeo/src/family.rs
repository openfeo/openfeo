// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Keeping a family of tasks in step with the config (SPEC §6.3). A family is the tasks that
//! exist once per WAN or LAN: the DHCPv4 client, PPPoE, the router-advertisement client, the
//! DHCPv6 client, the DHCPv4 server. Its manager watches the World and compares, for each
//! instance, the slice of the config that instance depends on: an instance whose slice is
//! unchanged is left alone, one whose slice changed is stopped and started again, one no
//! longer asked for is stopped. What a stopped instance had published leaves the World with
//! it, and its replacement is started only once it is gone.

use std::collections::BTreeMap;
use std::sync::Arc;

use openfeo_runtime::supervise::{BoxedTask, Stop, Stoppable, TaskError};
use openfeo_runtime::world::WorldRx;
use openfeo_runtime::{Publisher, Supervisor};
use openfeo_world::World;
use tracing::debug;

/// One family of per-WAN or per-LAN tasks.
pub trait Family: Send + Sync + 'static {
    /// What an instance is started with: the slice of the config it depends on.
    type Slice: Clone + PartialEq + Send + Sync + 'static;
    /// Task names are `<PREFIX>-<key>`.
    const PREFIX: &'static str;

    /// The instances the World asks for, by WAN or LAN name.
    fn wanted(&self, world: &World) -> BTreeMap<String, Self::Slice>;

    /// One instance. It returns `Ok(())` soon after `stop` is asked, having said goodbye.
    fn run(
        &self,
        key: &str,
        slice: &Self::Slice,
        publisher: Arc<Publisher>,
        world_rx: WorldRx,
        stop: Stop,
    ) -> BoxedTask;

    /// Take what an instance published out of the World.
    fn withdraw(&self, key: &str, world: &mut World);
}

/// Start `family`'s manager, a supervised task named `<PREFIX>-manager`.
pub fn spawn<F: Family>(
    family: F,
    supervisor: &Supervisor,
    publisher: &Arc<Publisher>,
    world_rx: &WorldRx,
) {
    let family = Arc::new(family);
    let instances = supervisor.clone();
    let publisher = publisher.clone();
    let world_rx = world_rx.clone();
    supervisor.spawn(format!("{}-manager", F::PREFIX), move || {
        manage(
            family.clone(),
            instances.clone(),
            publisher.clone(),
            world_rx.clone(),
        )
    });
}

/// The manager: on every World, stop the instances that are no longer wanted as they are, take
/// their facts out, and then start what is wanted and not running. Dropping this future ends
/// every instance.
async fn manage<F: Family>(
    family: Arc<F>,
    supervisor: Supervisor,
    publisher: Arc<Publisher>,
    mut world_rx: WorldRx,
) -> Result<(), TaskError> {
    let mut running: BTreeMap<String, (F::Slice, Stoppable)> = BTreeMap::new();
    loop {
        let wanted = family.wanted(&world_rx.borrow_and_update());
        let leaving: Vec<String> = running
            .iter()
            .filter(|(key, (slice, _))| wanted.get(*key) != Some(slice))
            .map(|(key, _)| key.clone())
            .collect();
        if !leaving.is_empty() {
            let stops: Vec<_> = leaving
                .iter()
                .filter_map(|key| running.remove(key))
                .map(|(_, task)| task.stop())
                .collect();
            futures::future::join_all(stops).await;
            debug!("{}: stopped {}", F::PREFIX, leaving.join(", "));
            publisher.update(|world| {
                for key in &leaving {
                    family.withdraw(key, world);
                }
            });
            // The World may have moved on while they stopped: look again before starting.
            continue;
        }
        for (key, slice) in wanted {
            if running.contains_key(&key) {
                continue;
            }
            let task = {
                let (family, publisher, world_rx) =
                    (family.clone(), publisher.clone(), world_rx.clone());
                let (key, slice) = (key.clone(), slice.clone());
                supervisor.spawn_stoppable(format!("{}-{key}", F::PREFIX), move |stop| {
                    family.run(&key, &slice, publisher.clone(), world_rx.clone(), stop)
                })
            };
            running.insert(key, (slice, task));
        }
        world_rx
            .changed()
            .await
            .map_err(|_| "world publisher gone")?;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use openfeo_config::{Config, PortMap, Wan};
    use openfeo_runtime::HealthTracker;
    use openfeo_world::LinkFact;

    use super::*;

    /// Says when it was dropped.
    struct Gone(Arc<AtomicBool>);

    impl Drop for Gone {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A family with an instance per WAN whose slice is the WAN's priority. An instance says
    /// when it starts and stops, and publishes an (empty) list of leases under its name.
    struct Fake {
        log: Arc<Mutex<Vec<String>>>,
        /// How long an instance takes to stop once asked.
        slow: Duration,
        /// Set when any instance's future is dropped.
        gone: Arc<AtomicBool>,
    }

    impl Family for Fake {
        type Slice = u32;
        const PREFIX: &'static str = "fake";

        fn wanted(&self, world: &World) -> BTreeMap<String, u32> {
            world
                .config
                .wans
                .iter()
                .map(|wan| (wan.name.clone(), wan.priority))
                .collect()
        }

        fn run(
            &self,
            key: &str,
            slice: &u32,
            publisher: Arc<Publisher>,
            _world_rx: WorldRx,
            mut stop: Stop,
        ) -> BoxedTask {
            let (key, slice, log, slow) = (key.to_owned(), *slice, self.log.clone(), self.slow);
            let held = Gone(self.gone.clone());
            Box::pin(async move {
                let _held = held;
                log.lock().unwrap().push(format!("started {key} {slice}"));
                publisher.update(|world| {
                    Arc::make_mut(&mut world.leases).insert(key.clone(), Vec::new());
                });
                stop.requested().await;
                tokio::time::sleep(slow).await;
                log.lock().unwrap().push(format!("stopped {key}"));
                Ok(())
            })
        }

        fn withdraw(&self, key: &str, world: &mut World) {
            Arc::make_mut(&mut world.leases).remove(key);
        }
    }

    fn config(wans: &[(&str, u32)]) -> Config {
        Config {
            wans: wans
                .iter()
                .map(|(name, priority)| Wan {
                    name: (*name).to_owned(),
                    priority: *priority,
                    ..Wan::default()
                })
                .collect(),
            ..Config::default()
        }
    }

    struct Rig {
        publisher: Arc<Publisher>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Rig {
        /// A manager over `wans`, with instances that take `slow` to stop.
        fn start(wans: &[(&str, u32)], slow: Duration) -> Rig {
            let (publisher, world_rx) =
                Publisher::new(World::new(config(wans), PortMap::default()));
            let publisher = Arc::new(publisher);
            let log = Arc::new(Mutex::new(Vec::new()));
            let supervisor = Supervisor::new(HealthTracker::new());
            spawn(
                Fake {
                    log: log.clone(),
                    slow,
                    gone: Arc::new(AtomicBool::new(false)),
                },
                &supervisor,
                &publisher,
                &world_rx,
            );
            Rig { publisher, log }
        }

        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }

        /// Publish another config and give the manager a moment.
        async fn reconfigure(&self, wans: &[(&str, u32)]) {
            let config = Arc::new(config(wans));
            self.publisher.update(|world| world.config = config);
            settle().await;
        }
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_instances_the_config_asks_for_are_started() {
        let rig = Rig::start(&[("wan0", 10), ("wan1", 20)], Duration::ZERO);
        settle().await;
        assert_eq!(rig.log(), ["started wan0 10", "started wan1 20"]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unchanged_instance_is_left_alone_when_another_changes() {
        let rig = Rig::start(&[("wan0", 10), ("wan1", 20)], Duration::ZERO);
        settle().await;
        rig.reconfigure(&[("wan0", 10), ("wan1", 30)]).await;
        let log = rig.log();
        assert!(!log.contains(&"stopped wan0".to_owned()), "{log:?}");
        assert_eq!(
            log.iter()
                .filter(|line| line.starts_with("started wan0"))
                .count(),
            1,
            "{log:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_changed_instance_is_restarted_with_its_new_slice() {
        let rig = Rig::start(&[("wan0", 10), ("wan1", 20)], Duration::ZERO);
        settle().await;
        rig.reconfigure(&[("wan0", 10), ("wan1", 30)]).await;
        assert_eq!(
            rig.log(),
            [
                "started wan0 10",
                "started wan1 20",
                "stopped wan1",
                "started wan1 30"
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_instance_no_longer_wanted_is_stopped() {
        let rig = Rig::start(&[("wan0", 10), ("wan1", 20)], Duration::ZERO);
        settle().await;
        rig.reconfigure(&[("wan0", 10)]).await;
        assert_eq!(
            rig.log(),
            ["started wan0 10", "started wan1 20", "stopped wan1"]
        );
        // And one asked for later is started.
        rig.reconfigure(&[("wan0", 10), ("wan2", 5)]).await;
        assert_eq!(rig.log().last().map(String::as_str), Some("started wan2 5"));
    }

    #[tokio::test(start_paused = true)]
    async fn an_instance_is_gone_before_its_replacement_starts() {
        let rig = Rig::start(&[("wan0", 10)], Duration::from_secs(2));
        settle().await;
        rig.reconfigure(&[("wan0", 11)]).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(rig.log(), ["started wan0 10"], "still stopping");
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(
            rig.log(),
            ["started wan0 10", "stopped wan0", "started wan0 11"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_config_that_changes_again_while_an_instance_stops_is_the_one_started() {
        let rig = Rig::start(&[("wan0", 10)], Duration::from_secs(2));
        settle().await;
        rig.reconfigure(&[("wan0", 11)]).await;
        rig.reconfigure(&[("wan0", 12)]).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            rig.log(),
            ["started wan0 10", "stopped wan0", "started wan0 12"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stopped_instance_takes_its_facts_with_it() {
        let rig = Rig::start(&[("wan0", 10), ("wan1", 20)], Duration::ZERO);
        settle().await;
        assert!(rig.publisher.current().leases.contains_key("wan1"));
        rig.reconfigure(&[("wan0", 10)]).await;
        let world = rig.publisher.current();
        assert!(!world.leases.contains_key("wan1"), "{:?}", world.leases);
        assert!(world.leases.contains_key("wan0"));
    }

    #[tokio::test(start_paused = true)]
    async fn the_facts_of_an_instance_being_replaced_are_gone_while_it_is_away() {
        let rig = Rig::start(&[("wan0", 10)], Duration::from_secs(2));
        settle().await;
        rig.reconfigure(&[("wan0", 11)]).await;
        // Asked to stop and not yet gone: what it published still stands.
        assert!(rig.publisher.current().leases.contains_key("wan0"));
        tokio::time::sleep(Duration::from_millis(2500)).await;
        // Replaced: the fact there now is the new instance's own.
        assert_eq!(
            rig.log(),
            ["started wan0 10", "stopped wan0", "started wan0 11"]
        );
        assert!(rig.publisher.current().leases.contains_key("wan0"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_world_that_changes_only_in_its_facts_restarts_nothing() {
        let rig = Rig::start(&[("wan0", 10), ("wan1", 20)], Duration::ZERO);
        settle().await;
        let before = rig.log();
        rig.publisher.update(|world| {
            Arc::make_mut(&mut world.links).insert(
                "p0".to_owned(),
                LinkFact {
                    index: 2,
                    name: "p0".to_owned(),
                    up: true,
                    carrier: true,
                    mac: None,
                    mtu: 1500,
                    link_local6: None,
                    speed_mbps: None,
                },
            );
        });
        settle().await;
        assert_eq!(rig.log(), before);
    }

    #[tokio::test(start_paused = true)]
    async fn the_manager_dying_takes_its_instances_with_it() {
        let (publisher, world_rx) =
            Publisher::new(World::new(config(&[("wan0", 10)]), PortMap::default()));
        let publisher = Arc::new(publisher);
        let gone = Arc::new(AtomicBool::new(false));
        let family = Arc::new(Fake {
            log: Arc::new(Mutex::new(Vec::new())),
            slow: Duration::ZERO,
            gone: gone.clone(),
        });
        let supervisor = Supervisor::new(HealthTracker::new());
        let manager = tokio::spawn(manage(family, supervisor, publisher, world_rx));
        settle().await;
        assert!(!gone.load(Ordering::SeqCst));
        manager.abort();
        settle().await;
        assert!(gone.load(Ordering::SeqCst));
    }
}
