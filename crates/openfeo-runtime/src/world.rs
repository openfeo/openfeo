// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Publishing World generations (SPEC §6.2): fact sources call [`Publisher::update`], every
//! subscriber sees a new immutable `Arc<World>` with the generation bumped, and `watch`
//! coalesces bursts so a slow reconciler only ever sees the latest snapshot.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use openfeo_world::{Event, EventDraft, World};
use tokio::sync::{broadcast, watch};

use crate::clock;

/// What every reconciler loop holds: `borrow_and_update()` then `changed().await`.
pub type WorldRx = watch::Receiver<Arc<World>>;

/// The step run inside every publish (SPEC §6.2): given the current World, the next one and the
/// time since the kernel booted, it may complete the next World (the WAN status facts) and
/// returns the events of the change. `openfeo_reconcile::derive::derive` in the router.
pub type Derive = Box<dyn Fn(&World, &mut World, u64) -> Vec<EventDraft> + Send + Sync>;

/// How many events a subscriber may fall behind before it loses the oldest.
const EVENT_CAPACITY: usize = 1024;

/// The single writer of World generations, and of the events that go with them.
pub struct Publisher {
    tx: watch::Sender<Arc<World>>,
    derive: Option<Derive>,
    events: broadcast::Sender<Arc<Event>>,
    /// Held across a publish and the sending of its events, so events leave in generation
    /// order whichever task published.
    order: Mutex<()>,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publisher")
            .field("generation", &self.tx.borrow().generation)
            .field("derive", &self.derive.is_some())
            .finish_non_exhaustive()
    }
}

impl Publisher {
    /// Publish `initial` as generation 0 and hand back the first receiver.
    #[must_use]
    pub fn new(initial: World) -> (Self, WorldRx) {
        Self::build(initial, None)
    }

    /// As [`new`](Self::new), with the step to run inside every publish.
    #[must_use]
    pub fn with_derive(initial: World, derive: Derive) -> (Self, WorldRx) {
        Self::build(initial, Some(derive))
    }

    fn build(initial: World, derive: Option<Derive>) -> (Self, WorldRx) {
        let (tx, rx) = watch::channel(Arc::new(initial));
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let publisher = Publisher {
            tx,
            derive,
            events,
            order: Mutex::new(()),
        };
        (publisher, rx)
    }

    /// Produce the next generation: clone the current World, let `f` change it, run the derive
    /// step, bump the generation and notify every receiver (even when nothing else changed);
    /// then send the events of the change.
    pub fn update(&self, f: impl FnOnce(&mut World)) {
        let _order = self.order.lock().unwrap_or_else(PoisonError::into_inner);
        let mut drafts = Vec::new();
        self.tx.send_modify(|current| {
            let mut next = World::clone(current);
            f(&mut next);
            if let Some(derive) = &self.derive {
                drafts = derive(current, &mut next, clock::boot_ms());
            }
            next.generation += 1;
            *current = Arc::new(next);
        });
        for draft in drafts {
            self.send(draft);
        }
    }

    /// Send an event that is not a change of fact (health, later config and updates).
    pub fn emit(&self, draft: EventDraft) {
        let _order = self.order.lock().unwrap_or_else(PoisonError::into_inner);
        self.send(draft);
    }

    fn send(&self, draft: EventDraft) {
        let time_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        // No subscriber is not an error: nobody is listening yet.
        let _ = self.events.send(Arc::new(Event {
            time_unix_ms,
            boot_ms: clock::boot_ms(),
            topic: draft.topic,
            fields: draft.fields,
        }));
    }

    /// A receiver of every event from now on. One that falls more than 1024 behind loses the
    /// oldest and is told so by the channel.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<Arc<Event>> {
        self.events.subscribe()
    }

    /// The latest generation.
    #[must_use]
    pub fn current(&self) -> Arc<World> {
        self.tx.borrow().clone()
    }

    /// Another receiver, starting at the latest generation.
    #[must_use]
    pub fn subscribe(&self) -> WorldRx {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_config::{Config, PortMap};
    use openfeo_world::World;
    use std::sync::Arc;

    #[tokio::test(start_paused = true)]
    async fn update_bumps_generation_and_notifies() {
        let (publisher, mut rx) = Publisher::new(World::new(Config::default(), PortMap::default()));
        assert_eq!(rx.borrow().generation, 0);
        publisher.update(|world| {
            Arc::make_mut(&mut world.config).config_version = 7;
        });
        rx.changed().await.unwrap();
        let world = rx.borrow_and_update().clone();
        assert_eq!(world.generation, 1);
        assert_eq!(world.config.config_version, 7);
        assert_eq!(publisher.current().generation, 1);
        publisher.update(|_| {});
        assert_eq!(publisher.subscribe().borrow().generation, 2);
    }

    #[tokio::test]
    async fn a_change_and_its_reversal_both_reach_an_event_subscriber() {
        let derive: Derive = Box::new(|prev, next, _| {
            if prev.ula == next.ula {
                Vec::new()
            } else {
                vec![EventDraft::new(format!("ula.{}", next.ula.is_some()))]
            }
        });
        let (publisher, mut world_rx) =
            Publisher::with_derive(World::new(Config::default(), PortMap::default()), derive);
        let mut events = publisher.events();
        publisher.update(|world| world.ula = Some("fd12:3456:789a::/48".parse().unwrap()));
        publisher.update(|world| world.ula = None);
        assert_eq!(events.recv().await.unwrap().topic, "ula.true");
        assert_eq!(events.recv().await.unwrap().topic, "ula.false");
        // The watch receiver saw only the end state: this is why events are not derived by
        // watching it.
        assert_eq!(world_rx.borrow_and_update().ula, None);
        assert_eq!(publisher.current().generation, 2);
    }

    #[tokio::test]
    async fn the_derive_step_may_change_the_next_world() {
        let derive: Derive = Box::new(|_, next, boot_ms| {
            next.set_wan_cause("wan0", &format!("at {}", boot_ms > 0));
            Vec::new()
        });
        let (publisher, _rx) =
            Publisher::with_derive(World::new(Config::default(), PortMap::default()), derive);
        publisher.update(|_| {});
        assert!(publisher.current().wan_status.contains_key("wan0"));
    }

    #[tokio::test]
    async fn an_emitted_event_carries_both_clocks() {
        let (publisher, _rx) = Publisher::new(World::new(Config::default(), PortMap::default()));
        let mut events = publisher.events();
        let before = crate::clock::boot_ms();
        publisher.emit(EventDraft::new("health.ok").with("unhealthy", ""));
        let event = events.recv().await.unwrap();
        assert_eq!(event.topic, "health.ok");
        assert!(
            event.time_unix_ms > 1_600_000_000_000,
            "a wall clock, in milliseconds"
        );
        assert!(event.boot_ms >= before);
        assert_eq!(
            publisher.current().generation,
            0,
            "an emit is not a publish"
        );
    }
}
