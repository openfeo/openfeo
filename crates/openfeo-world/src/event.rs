// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Events (SPEC §10): something that happened, named by a stable topic. A draft is what a pure
//! function of two Worlds produces; the publisher stamps it with the two clocks.

use std::collections::BTreeMap;

/// An event before it has a time: a topic (`wan.wan0.down`) and the values that go with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDraft {
    /// The stable topic name.
    pub topic: String,
    /// The values (`address`, `reason`, ...); a UI writes the sentence.
    pub fields: BTreeMap<String, String>,
}

impl EventDraft {
    /// A draft with no fields.
    #[must_use]
    pub fn new(topic: impl Into<String>) -> Self {
        EventDraft {
            topic: topic.into(),
            fields: BTreeMap::new(),
        }
    }

    /// The same draft with one more field.
    #[must_use]
    pub fn with(mut self, key: &str, value: impl Into<String>) -> Self {
        self.fields.insert(key.to_owned(), value.into());
        self
    }
}

/// An event as it is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Wall time in Unix milliseconds; the build's epoch plus uptime until SNTP has answered.
    pub time_unix_ms: u64,
    /// Milliseconds since the kernel booted.
    pub boot_ms: u64,
    /// The stable topic name.
    pub topic: String,
    /// The values.
    pub fields: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_collects_its_fields() {
        let draft = EventDraft::new("wan.wan0.down").with("reason", "no carrier");
        assert_eq!(draft.topic, "wan.wan0.down");
        assert_eq!(draft.fields["reason"], "no carrier");
    }
}
