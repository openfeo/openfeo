// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Publishing World generations (SPEC §6.2): fact sources call [`Publisher::update`], every
//! subscriber sees a new immutable `Arc<World>` with the generation bumped, and `watch`
//! coalesces bursts so a slow reconciler only ever sees the latest snapshot.

use std::sync::Arc;

use openfeo_world::World;
use tokio::sync::watch;

/// What every reconciler loop holds: `borrow_and_update()` then `changed().await`.
pub type WorldRx = watch::Receiver<Arc<World>>;

/// The single writer of World generations.
#[derive(Debug)]
pub struct Publisher {
    tx: watch::Sender<Arc<World>>,
}

impl Publisher {
    /// Publish `initial` as generation 0 and hand back the first receiver.
    #[must_use]
    pub fn new(initial: World) -> (Self, WorldRx) {
        let (tx, rx) = watch::channel(Arc::new(initial));
        (Publisher { tx }, rx)
    }

    /// Produce the next generation: clone the current World, let `f` change it, bump the
    /// generation and notify every receiver (even when nothing else changed).
    pub fn update(&self, f: impl FnOnce(&mut World)) {
        self.tx.send_modify(|current| {
            let mut next = World::clone(current);
            f(&mut next);
            next.generation += 1;
            *current = Arc::new(next);
        });
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
}
