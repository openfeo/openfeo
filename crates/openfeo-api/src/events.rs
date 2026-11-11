// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The recent events (SPEC §10): the last 256, kept so that a subscriber arriving later can
//! ask for a backlog. Nothing is kept on disk.

use std::collections::VecDeque;
use std::sync::Arc;

use crate::limits::EVENT_BACKLOG;

/// The last [`EVENT_BACKLOG`] events, oldest first.
#[derive(Debug, Default)]
pub struct Recent {
    events: VecDeque<Arc<openfeo_world::Event>>,
}

impl Recent {
    /// Remember `event`, forgetting the oldest beyond the limit.
    pub fn push(&mut self, event: Arc<openfeo_world::Event>) {
        if self.events.len() >= EVENT_BACKLOG {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// The last `n` events, oldest first.
    #[must_use]
    pub fn last(&self, n: usize) -> Vec<Arc<openfeo_world::Event>> {
        let skip = self.events.len().saturating_sub(n);
        self.events.iter().skip(skip).cloned().collect()
    }
}

/// An event as the wire carries it.
#[must_use]
pub fn to_pb(event: &openfeo_world::Event) -> openfeo_config::events::Event {
    openfeo_config::events::Event {
        time_unix_ms: event.time_unix_ms,
        uptime_ms: event.boot_ms,
        topic: event.topic.clone(),
        fields: event
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn event(n: u64) -> Arc<openfeo_world::Event> {
        Arc::new(openfeo_world::Event {
            time_unix_ms: 1_794_300_000_000 + n,
            boot_ms: n,
            topic: "health.ok".to_owned(),
            fields: BTreeMap::from([("n".to_owned(), n.to_string())]),
        })
    }

    #[test]
    fn the_last_256_are_kept_oldest_first() {
        let mut recent = Recent::default();
        for n in 0..300 {
            recent.push(event(n));
        }
        let all = recent.last(1_000);
        assert_eq!(all.len(), 256);
        assert_eq!((all[0].boot_ms, all[255].boot_ms), (44, 299));
        let two: Vec<u64> = recent.last(2).iter().map(|e| e.boot_ms).collect();
        assert_eq!(two, [298, 299]);
        assert_eq!(recent.last(0), Vec::new());
    }

    #[test]
    fn an_event_goes_on_the_wire_with_both_clocks_and_its_fields() {
        let wire = to_pb(&event(7));
        assert_eq!(wire.time_unix_ms, 1_794_300_000_007);
        assert_eq!(wire.uptime_ms, 7);
        assert_eq!(wire.topic, "health.ok");
        assert_eq!(wire.fields["n"], "7");
    }
}
