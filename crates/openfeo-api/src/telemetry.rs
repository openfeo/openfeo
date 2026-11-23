// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Interface and connection counters (SPEC §10): read once a second, whether or not anyone is
//! subscribed, with the last hour of each link's byte counters kept in memory so that a chart
//! opens with the time before it was opened. They stay out of the World: they change with
//! every packet and must not bump its generation or wake a reconciler. The router computes no
//! rates: it keeps what it read, and a client takes two samples and their times.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use openfeo_config::state::{Counters, LinkHistory};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

/// How often the counters are read.
pub const INTERVAL: Duration = Duration::from_secs(1);

/// Where the counters come from: netlink and the conntrack sysctls in the router, a fake in
/// tests.
pub trait CounterSource: Send + Sync {
    /// The counters now; `None` when they could not be read this time.
    fn read(&self) -> Pin<Box<dyn Future<Output = Option<Counters>> + Send + '_>>;
}

/// How long the history reaches back.
pub const HISTORY: Duration = Duration::from_secs(3600);

/// One reading of a link's byte counters.
#[derive(Debug, Clone, Copy)]
struct Sample {
    monotonic_ms: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// The last hour of each link's byte counters, as they were read: at most one sample a second,
/// so at most 3600 a link, 24 bytes each. Nothing is computed from them here.
#[derive(Debug, Default)]
struct History {
    links: BTreeMap<String, VecDeque<Sample>>,
}

impl History {
    /// The most samples a link keeps: an hour at one a second.
    const MOST: usize = 3600;

    /// Keep `counters`' sample of each link it has, and drop what is now over an hour old. A
    /// link with nothing left is forgotten: an interface that went away (a PPPoE session's)
    /// does not stay for ever.
    fn record(&mut self, counters: &Counters) {
        for link in &counters.links {
            self.links
                .entry(link.name.clone())
                .or_default()
                .push_back(Sample {
                    monotonic_ms: counters.monotonic_ms,
                    rx_bytes: link.rx_bytes,
                    tx_bytes: link.tx_bytes,
                });
        }
        let reach = u64::try_from(HISTORY.as_millis()).unwrap_or(u64::MAX);
        let oldest = counters.monotonic_ms.saturating_sub(reach);
        self.links.retain(|_, samples| {
            while samples.len() > Self::MOST
                || samples
                    .front()
                    .is_some_and(|sample| sample.monotonic_ms < oldest)
            {
                samples.pop_front();
            }
            !samples.is_empty()
        });
    }

    fn of(&self, link: &str) -> Option<LinkHistory> {
        let samples = self.links.get(link)?;
        Some(LinkHistory {
            name: link.to_owned(),
            monotonic_ms: samples.iter().map(|sample| sample.monotonic_ms).collect(),
            rx_bytes: samples.iter().map(|sample| sample.rx_bytes).collect(),
            tx_bytes: samples.iter().map(|sample| sample.tx_bytes).collect(),
        })
    }
}

/// The latest counters, for whoever subscribes, and the last hour of them; [`run`](Self::run)
/// it as a task.
pub struct Telemetry {
    source: Arc<dyn CounterSource>,
    latest: watch::Sender<Option<Counters>>,
    history: Mutex<History>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry")
            .field("subscribers", &self.latest.receiver_count())
            .finish_non_exhaustive()
    }
}

/// One subscription; dropping it unsubscribes.
#[derive(Debug)]
pub struct CountersSub {
    latest: watch::Receiver<Option<Counters>>,
}

impl Telemetry {
    /// Counters from `source`, not yet read: [`run`](Self::run) reads them.
    #[must_use]
    pub fn new(source: Arc<dyn CounterSource>) -> Arc<Self> {
        Arc::new(Telemetry {
            source,
            latest: watch::Sender::new(None),
            history: Mutex::new(History::default()),
        })
    }

    /// Start hearing the counters: each sample from the next one on, which is within a second.
    #[must_use]
    pub fn subscribe(self: &Arc<Self>) -> CountersSub {
        CountersSub {
            latest: self.latest.subscribe(),
        }
    }

    /// The samples kept of each of `links` that has any, in the order asked, each link once,
    /// oldest first.
    #[must_use]
    pub fn history(&self, links: &[String]) -> Vec<LinkHistory> {
        let history = self.history.lock().unwrap_or_else(PoisonError::into_inner);
        let mut found: Vec<LinkHistory> = Vec::new();
        for link in links {
            if found.iter().all(|have| have.name != *link)
                && let Some(samples) = history.of(link)
            {
                found.push(samples);
            }
        }
        found
    }

    /// Read the counters once a second, keep them, and send each sample to whoever is
    /// subscribed. Runs for ever. A read that fails is a second with no sample.
    pub async fn run(self: Arc<Self>) {
        let mut ticks = tokio::time::interval(INTERVAL);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            if let Some(counters) = self.source.read().await {
                self.history
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .record(&counters);
                self.latest.send_replace(Some(counters));
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use openfeo_config::state::LinkCounters;

    use super::*;

    /// A source whose every read is a second later on its own clock, with a thousand bytes
    /// more received on each link it then has. `plan` says, for the nth read, which links
    /// there are, or `None` for a read that fails.
    struct Planned {
        reads: AtomicU64,
        plan: fn(u64) -> Option<&'static [&'static str]>,
    }

    impl Planned {
        fn new(plan: fn(u64) -> Option<&'static [&'static str]>) -> Arc<Self> {
            Arc::new(Planned {
                reads: AtomicU64::new(0),
                plan,
            })
        }

        fn reads(&self) -> u64 {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl CounterSource for Planned {
        fn read(&self) -> Pin<Box<dyn Future<Output = Option<Counters>> + Send + '_>> {
            Box::pin(async {
                let n = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
                let links = (self.plan)(n)?;
                Some(Counters {
                    monotonic_ms: n * 1_000,
                    links: links
                        .iter()
                        .map(|name| LinkCounters {
                            name: (*name).to_owned(),
                            rx_bytes: n * 1_000,
                            tx_bytes: n * 10,
                            ..LinkCounters::default()
                        })
                        .collect(),
                    ..Counters::default()
                })
            })
        }
    }

    fn running(source: &Arc<Planned>) -> Arc<Telemetry> {
        let telemetry = Telemetry::new(source.clone());
        tokio::spawn(telemetry.clone().run());
        telemetry
    }

    fn of(telemetry: &Telemetry, link: &str) -> Vec<u64> {
        telemetry
            .history(&[link.to_owned()])
            .first()
            .map_or_default(|history| history.monotonic_ms.clone())
    }

    /// SPEC §10: read once a second, whether or not anyone is subscribed, so that a chart
    /// opens with the time before it was opened.
    #[tokio::test(start_paused = true)]
    async fn the_counters_are_read_each_second_with_nobody_watching() {
        let source = Planned::new(|_| Some(&["p0"]));
        let telemetry = running(&source);
        tokio::time::sleep(Duration::from_millis(10_500)).await;
        assert_eq!(source.reads(), 11, "at once, then each second");
        let history = telemetry.history(&["p0".to_owned()]);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].name, "p0");
        assert_eq!(
            history[0].monotonic_ms,
            (1..=11).map(|n| n * 1_000).collect::<Vec<u64>>(),
            "oldest first"
        );
        assert_eq!(history[0].rx_bytes[10], 11_000);
        assert_eq!(history[0].tx_bytes[10], 110);
        assert_eq!(
            (history[0].rx_bytes.len(), history[0].tx_bytes.len()),
            (11, 11),
            "one of each per sample"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_history_holds_an_hour_and_no_more() {
        let source = Planned::new(|_| Some(&["p0"]));
        let telemetry = running(&source);
        tokio::time::sleep(Duration::from_millis(3_699_500)).await;
        assert_eq!(source.reads(), 3_700);
        let times = of(&telemetry, "p0");
        assert_eq!(times.len(), 3_600);
        assert_eq!(
            (times.first().copied(), times.last().copied()),
            (Some(101_000), Some(3_700_000)),
            "the hundred oldest went"
        );
    }

    /// A PPPoE interface exists only while its session does. What is not there is not
    /// sampled, and a reader sees the gap in the times.
    #[tokio::test(start_paused = true)]
    async fn a_link_that_was_away_has_a_gap_and_one_gone_an_hour_is_forgotten() {
        let source = Planned::new(|n| {
            Some(match n {
                1..=5 => &["p0", "ppp0", "old"],
                11..=40 => &["p0"],
                _ => &["p0", "ppp0"],
            })
        });
        let telemetry = running(&source);
        tokio::time::sleep(Duration::from_millis(60_500)).await;
        let times = of(&telemetry, "ppp0");
        assert_eq!(times.len(), 10 + 21);
        assert_eq!((times[9], times[10]), (10_000, 41_000), "the gap");
        assert_eq!(of(&telemetry, "old").len(), 5);
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        assert_eq!(
            telemetry.history(&["old".to_owned()]),
            Vec::new(),
            "its last sample is over an hour old: the link is forgotten"
        );
        assert_eq!(of(&telemetry, "p0").len(), 3_600);
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_that_fails_is_a_gap() {
        let source = Planned::new(|n| (!(5..=7).contains(&n)).then_some(&["p0"]));
        let telemetry = running(&source);
        tokio::time::sleep(Duration::from_millis(9_500)).await;
        assert_eq!(source.reads(), 10, "a failed read is still a read");
        assert_eq!(
            of(&telemetry, "p0"),
            [1_000, 2_000, 3_000, 4_000, 8_000, 9_000, 10_000]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_history_answers_what_was_asked_in_the_order_asked() {
        let source = Planned::new(|_| Some(&["p0", "p1", "p2"]));
        let telemetry = running(&source);
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        let asked: Vec<String> = ["p1", "nope", "p0", "p1"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        let names: Vec<String> = telemetry
            .history(&asked)
            .into_iter()
            .map(|history| history.name)
            .collect();
        assert_eq!(
            names,
            ["p1", "p0"],
            "each once, and not what the router has none of"
        );
        assert_eq!(telemetry.history(&[]), Vec::new());
    }

    #[tokio::test(start_paused = true)]
    async fn a_subscriber_is_still_sent_each_sample() {
        let source = Planned::new(|_| Some(&["p0"]));
        let telemetry = running(&source);
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_eq!(source.reads(), 3);
        let mut first = telemetry.subscribe();
        let mut second = telemetry.subscribe();
        assert_eq!(first.changed().await.map(|c| c.monotonic_ms), Some(4_000));
        assert_eq!(second.changed().await.map(|c| c.monotonic_ms), Some(4_000));
        assert_eq!(first.changed().await.map(|c| c.monotonic_ms), Some(5_000));
        drop(first);
        assert_eq!(second.changed().await.map(|c| c.monotonic_ms), Some(5_000));
        assert_eq!(source.reads(), 5, "one read a second, however many listen");
    }
}
