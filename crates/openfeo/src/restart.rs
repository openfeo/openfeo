// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A restart asked for through the API (SPEC §6.3). It does not happen at once: the answer is
//! given a moment to reach whoever asked, then what has a goodbye to say is stopped (the PPPoE
//! sessions, so that the access concentrator knows; the LANs' DHCPv4 servers, so that the lease
//! files are written), and only then is PID 1 asked to restart, whether or not they finished.
//! The DHCPv4 client is left running: stopped on purpose it would release its lease, and the
//! router should come back to the address it had. A watchdog reset, a power cut and a router
//! process that died come nowhere near this.

use std::future::Future;
use std::time::Duration;

use openfeo_runtime::supervise::STOP_GRACE;
use tokio::sync::{mpsc, watch};
use tracing::info;

use crate::family::Halt;

/// How long after it is asked a restart begins: time for the answer to reach whoever asked.
pub const DELAY: Duration = Duration::from_secs(1);
/// How long the goodbyes are waited for in all: a stop's 3 s, and half a second to be told.
pub const LIMIT: Duration = STOP_GRACE.saturating_add(Duration::from_millis(500));

/// Asks for a restart. Asking twice is asking once.
#[derive(Debug, Clone)]
pub struct Restarts {
    ask: mpsc::Sender<()>,
}

impl openfeo_api::Restarter for Restarts {
    fn restart(&self) {
        // Full means an ask is already waiting, and gone means there is no router to restart:
        // either way there is nothing more to say.
        let _ = self.ask.try_send(());
    }
}

/// The other end: what [`run`] waits on.
#[derive(Debug)]
pub struct Asked {
    asks: mpsc::Receiver<()>,
}

/// The two ends of a restart: who asks, and who does it.
#[must_use]
pub fn channel() -> (Restarts, Asked) {
    let (ask, asks) = mpsc::channel(1);
    (Restarts { ask }, Asked { asks })
}

/// The families with a goodbye to say before a restart, and no others (SPEC §6.3).
#[derive(Debug)]
pub struct Goodbyes {
    /// Each session sends its Terminate-Requests and its PADT (SPEC §7.2).
    pub pppoe: Halt,
    /// Each server writes its lease file.
    pub dhcp4_servers: Halt,
}

impl Goodbyes {
    /// Halt both, together: each of their tasks has its own 3 s.
    pub async fn say(self) {
        tokio::join!(self.pppoe.halt(), self.dhcp4_servers.halt());
    }
}

/// Wait to be asked; then [`DELAY`]; then the goodbyes, for [`LIMIT`] at most; then tell
/// `pid1`, which the task that owns the control pipe is watching. A second ask changes
/// nothing. Never returns.
pub async fn run<G>(mut asked: Asked, goodbyes: impl FnOnce() -> G, pid1: watch::Sender<bool>)
where
    G: Future<Output = ()>,
{
    if asked.asks.recv().await.is_none() {
        // Nobody is left who could ask.
        return std::future::pending().await;
    }
    tokio::time::sleep(DELAY).await;
    info!("restart: stopping the PPPoE sessions and the DHCPv4 servers");
    if tokio::time::timeout(LIMIT, goodbyes()).await.is_err() {
        info!("restart: not waiting for them any longer");
    }
    pid1.send_replace(true);
    // What is asked from here on is asked of a router that is already restarting.
    while asked.asks.recv().await.is_some() {}
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use openfeo_api::Restarter as _;
    use openfeo_config::{Config, PortMap, Wan};
    use openfeo_runtime::supervise::{BoxedTask, Stop};
    use openfeo_runtime::world::WorldRx;
    use openfeo_runtime::{HealthTracker, Publisher, Supervisor};
    use openfeo_world::World;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;

    use super::*;
    use crate::family::{self, Family};

    async fn after(ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// A restart task whose goodbyes take `goodbyes` to say (`None`: they never end), with a
    /// count of how often they were begun.
    fn rig(goodbyes: Option<Duration>) -> (Restarts, Arc<AtomicUsize>, watch::Receiver<bool>) {
        let (restarts, asked) = channel();
        let (pid1, told) = watch::channel(false);
        let begun = Arc::new(AtomicUsize::new(0));
        let count = begun.clone();
        tokio::spawn(run(
            asked,
            move || async move {
                count.fetch_add(1, Ordering::SeqCst);
                match goodbyes {
                    Some(long) => tokio::time::sleep(long).await,
                    None => std::future::pending().await,
                }
            },
            pid1,
        ));
        (restarts, begun, told)
    }

    /// The answer to whoever asked is on its way before anything is stopped.
    #[tokio::test(start_paused = true)]
    async fn nothing_is_stopped_before_the_delay() {
        let (restarts, begun, told) = rig(Some(Duration::ZERO));
        after(5_000).await;
        assert_eq!(begun.load(Ordering::SeqCst), 0, "nobody asked");
        restarts.restart();
        after(900).await;
        assert_eq!(begun.load(Ordering::SeqCst), 0, "within the delay");
        assert!(!*told.borrow());
        after(200).await;
        assert_eq!(begun.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn pid1_is_told_once_the_goodbyes_are_said() {
        let (restarts, _begun, told) = rig(Some(Duration::from_secs(2)));
        restarts.restart();
        after(2_900).await;
        assert!(!*told.borrow(), "the goodbyes are still being said");
        after(200).await;
        assert!(*told.borrow());
    }

    /// SPEC §6.3: the restart goes ahead whether or not they finished.
    #[tokio::test(start_paused = true)]
    async fn goodbyes_that_do_not_end_are_not_waited_for_past_the_limit() {
        let (restarts, _begun, told) = rig(None);
        restarts.restart();
        // A tenth of a second short of the delay and the limit together.
        tokio::time::sleep(DELAY).await;
        tokio::time::sleep(LIMIT.saturating_sub(Duration::from_millis(100))).await;
        assert!(!*told.borrow(), "still within the limit");
        after(200).await;
        assert!(*told.borrow(), "the limit is the limit");
    }

    #[tokio::test(start_paused = true)]
    async fn asking_twice_is_asking_once() {
        let (restarts, begun, mut told) = rig(Some(Duration::from_secs(1)));
        restarts.restart();
        restarts.restart();
        after(500).await;
        restarts.restart();
        after(10_000).await;
        restarts.restart();
        after(10_000).await;
        assert_eq!(begun.load(Ordering::SeqCst), 1, "one restart");
        assert!(*told.borrow_and_update());
        assert!(!told.has_changed().unwrap(), "and PID 1 told once");
    }

    /// A family with one instance per WAN, which says when it has stopped.
    struct Named {
        name: &'static str,
        log: Arc<Mutex<Vec<String>>>,
        running: Arc<AtomicBool>,
    }

    impl Family for Named {
        type Slice = u32;
        const PREFIX: &'static str = "named";

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
            _key: &str,
            _slice: &u32,
            _publisher: Arc<Publisher>,
            _world_rx: WorldRx,
            mut stop: Stop,
        ) -> BoxedTask {
            let (name, log, running) = (self.name, self.log.clone(), self.running.clone());
            Box::pin(async move {
                running.store(true, Ordering::SeqCst);
                stop.requested().await;
                running.store(false, Ordering::SeqCst);
                log.lock().unwrap().push(format!("{name} said goodbye"));
                Ok(())
            })
        }

        fn withdraw(&self, _key: &str, _world: &mut World) {}
    }

    /// SPEC §6.3: the PPPoE sessions and the DHCPv4 servers, and nothing else. The DHCPv4
    /// client above all: stopped on purpose it gives its lease back.
    #[tokio::test(start_paused = true)]
    async fn the_goodbyes_are_the_pppoe_sessions_and_the_dhcp_servers_and_no_other() {
        let config = Config {
            wans: vec![Wan {
                name: "wan0".to_owned(),
                ..Wan::default()
            }],
            ..Config::default()
        };
        let (publisher, world_rx) = Publisher::new(World::new(config, PortMap::default()));
        let publisher = Arc::new(publisher);
        let supervisor = Supervisor::new(HealthTracker::new());
        let log = Arc::new(Mutex::new(Vec::new()));
        let named = |name: &'static str| {
            let running = Arc::new(AtomicBool::new(false));
            let family = Named {
                name,
                log: log.clone(),
                running: running.clone(),
            };
            (family, running)
        };
        let (pppoe, pppoe_running) = named("pppoe");
        let (servers, servers_running) = named("dhcp4-server");
        let (client, client_running) = named("dhcp4");
        let goodbyes = Goodbyes {
            pppoe: family::spawn_haltable(pppoe, &supervisor, &publisher, &world_rx),
            dhcp4_servers: family::spawn_haltable(servers, &supervisor, &publisher, &world_rx),
        };
        family::spawn(client, &supervisor, &publisher, &world_rx);
        after(10).await;
        assert!(
            pppoe_running.load(Ordering::SeqCst)
                && servers_running.load(Ordering::SeqCst)
                && client_running.load(Ordering::SeqCst)
        );
        goodbyes.say().await;
        let mut said = log.lock().unwrap().clone();
        said.sort();
        assert_eq!(said, ["dhcp4-server said goodbye", "pppoe said goodbye"]);
        assert!(client_running.load(Ordering::SeqCst), "left as it was");
    }
}
