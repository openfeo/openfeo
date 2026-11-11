// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Interface and connection counters (SPEC §10): read once a second, and only while someone is
//! subscribed. They stay out of the World: they change with every packet and must not bump its
//! generation or wake a reconciler. The router computes no rates and keeps no history; a
//! client takes two samples and their times.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use openfeo_config::state::Counters;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

/// How often the counters are read while someone wants them.
pub const INTERVAL: Duration = Duration::from_secs(1);

/// Where the counters come from: netlink and the conntrack sysctls in the router, a fake in
/// tests.
pub trait CounterSource: Send + Sync {
    /// The counters now; `None` when they could not be read this time.
    fn read(&self) -> Pin<Box<dyn Future<Output = Option<Counters>> + Send + '_>>;
}

/// The latest counters, for whoever subscribes; [`run`](Self::run) it as a task.
pub struct Telemetry {
    source: Arc<dyn CounterSource>,
    latest: watch::Sender<Option<Counters>>,
    subscribers: watch::Sender<usize>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry")
            .field("subscribers", &*self.subscribers.borrow())
            .finish_non_exhaustive()
    }
}

/// One subscription; dropping it unsubscribes.
#[derive(Debug)]
pub struct CountersSub {
    telemetry: Arc<Telemetry>,
    latest: watch::Receiver<Option<Counters>>,
}

impl Telemetry {
    /// Counters from `source`, read by nobody yet.
    #[must_use]
    pub fn new(source: Arc<dyn CounterSource>) -> Arc<Self> {
        Arc::new(Telemetry {
            source,
            latest: watch::Sender::new(None),
            subscribers: watch::Sender::new(0),
        })
    }

    /// Start wanting counters. The first sample after this is read at once if nobody else was
    /// subscribed, otherwise within a second.
    #[must_use]
    pub fn subscribe(self: &Arc<Self>) -> CountersSub {
        let latest = self.latest.subscribe();
        self.subscribers.send_modify(|count| *count += 1);
        CountersSub {
            telemetry: self.clone(),
            latest,
        }
    }

    /// Read the counters once a second while anyone is subscribed, and nothing at all while
    /// nobody is. Runs for ever.
    pub async fn run(self: Arc<Self>) {
        let mut subscribers = self.subscribers.subscribe();
        loop {
            // Parked: no reads until someone subscribes.
            if subscribers.wait_for(|count| *count > 0).await.is_err() {
                return;
            }
            let mut ticks = tokio::time::interval(INTERVAL);
            ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                if *self.subscribers.borrow() == 0 {
                    break;
                }
                if let Some(counters) = self.source.read().await {
                    self.latest.send_replace(Some(counters));
                }
            }
        }
    }
}

impl CountersSub {
    /// The next sample; `None` when the telemetry task is gone.
    pub async fn changed(&mut self) -> Option<Counters> {
        loop {
            self.latest.changed().await.ok()?;
            if let Some(counters) = self.latest.borrow_and_update().clone() {
                return Some(counters);
            }
        }
    }
}

impl Drop for CountersSub {
    fn drop(&mut self) {
        self.telemetry
            .subscribers
            .send_modify(|count| *count = count.saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    #[derive(Default)]
    struct Counting(AtomicU64);

    impl Counting {
        fn reads(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl CounterSource for Counting {
        fn read(&self) -> Pin<Box<dyn Future<Output = Option<Counters>> + Send + '_>> {
            Box::pin(async {
                let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
                Some(Counters {
                    monotonic_ms: n * 1_000,
                    ..Counters::default()
                })
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_read_until_someone_subscribes_and_reading_stops_when_they_leave() {
        let source = Arc::new(Counting::default());
        let telemetry = Telemetry::new(source.clone());
        tokio::spawn(telemetry.clone().run());
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(source.reads(), 0);
        let mut sub = telemetry.subscribe();
        assert_eq!(sub.changed().await.map(|c| c.monotonic_ms), Some(1_000));
        tokio::time::sleep(Duration::from_millis(3_500)).await;
        assert_eq!(source.reads(), 4, "at once, then each second");
        drop(sub);
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(source.reads(), 4);
        let mut again = telemetry.subscribe();
        assert_eq!(again.changed().await.map(|c| c.monotonic_ms), Some(5_000));
    }

    #[tokio::test(start_paused = true)]
    async fn two_subscribers_share_one_read_a_second() {
        let source = Arc::new(Counting::default());
        let telemetry = Telemetry::new(source.clone());
        tokio::spawn(telemetry.clone().run());
        let mut first = telemetry.subscribe();
        let mut second = telemetry.subscribe();
        assert!(first.changed().await.is_some());
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_eq!(source.reads(), 3);
        assert_eq!(second.changed().await.map(|c| c.monotonic_ms), Some(3_000));
        drop(first);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(source.reads(), 5, "one subscriber left: still reading");
    }
}
