// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The wait a wrong password earns (SPEC §9): 1 s after the first, doubling to 5 minutes, per
//! source, forgotten after 15 quiet minutes. A source is an IPv4 address or an IPv6 /64, since
//! a LAN client chooses the rest of its IPv6 address freely.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::limits::{BACKOFF_FIRST_MS, BACKOFF_FORGET_MS, BACKOFF_MAX_MS, BACKOFF_SOURCES};

/// Who is trying: an IPv4 address, or the /64 an IPv6 address is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Source {
    /// An IPv4 client.
    V4(Ipv4Addr),
    /// An IPv6 client's /64.
    V6([u8; 8]),
}

impl Source {
    /// The source of a peer address. An IPv4-mapped IPv6 address (how a dual-stack listener
    /// reports an IPv4 client) is its IPv4 self.
    #[must_use]
    pub fn of(peer: IpAddr) -> Source {
        match peer {
            IpAddr::V4(v4) => Source::V4(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
                || {
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&v6.octets()[..8]);
                    Source::V6(prefix)
                },
                Source::V4,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    failures: u32,
    last_failure_ms: u64,
    until_ms: u64,
}

/// The table of sources that have given a wrong password.
#[derive(Debug, Default)]
pub struct Backoff {
    entries: BTreeMap<Source, Entry>,
}

impl Backoff {
    /// Nobody waiting.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn live(&self, source: Source, now_ms: u64) -> Option<&Entry> {
        self.entries
            .get(&source)
            .filter(|entry| now_ms.saturating_sub(entry.last_failure_ms) <= BACKOFF_FORGET_MS)
    }

    /// How long `source` must still wait before it may try; 0 when it may try now.
    #[must_use]
    pub fn wait_ms(&self, source: Source, now_ms: u64) -> u64 {
        self.live(source, now_ms)
            .map_or(0, |entry| entry.until_ms.saturating_sub(now_ms))
    }

    /// Record a wrong password from `source` and return the wait that now applies: the n-th in
    /// a row waits `min(1 s << (n - 1), 5 min)`.
    pub fn failed(&mut self, source: Source, now_ms: u64) -> u64 {
        let failures = self
            .live(source, now_ms)
            .map_or(0, |entry| entry.failures)
            .saturating_add(1);
        let wait = BACKOFF_FIRST_MS
            .checked_shl(failures - 1)
            .filter(|wait| *wait >> (failures - 1) == BACKOFF_FIRST_MS)
            .map_or(BACKOFF_MAX_MS, |wait| wait.min(BACKOFF_MAX_MS));
        if !self.entries.contains_key(&source) && self.entries.len() >= BACKOFF_SOURCES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_failure_ms)
                .map(|(source, _)| *source);
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            source,
            Entry {
                failures,
                last_failure_ms: now_ms,
                until_ms: now_ms.saturating_add(wait),
            },
        );
        wait
    }

    /// The right password from `source`: it starts again from nothing.
    pub fn succeeded(&mut self, source: Source) {
        self.entries.remove(&source);
    }

    /// Sources remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nobody is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn the_wait_doubles_from_one_second_to_five_minutes_and_is_forgotten_after_fifteen() {
        let mut backoff = Backoff::new();
        let source = Source::of(ip("192.168.1.23"));
        let mut now = 0;
        for expected in [
            1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000, 300_000, 300_000,
        ] {
            assert_eq!(backoff.failed(source, now), expected);
            assert_eq!(backoff.wait_ms(source, now + expected - 1), 1);
            assert_eq!(backoff.wait_ms(source, now + expected), 0);
            now += expected;
        }
        assert_eq!(
            backoff.failed(source, now + 900_001),
            1_000,
            "forgotten after 15 quiet minutes"
        );
        backoff.succeeded(source);
        assert_eq!(backoff.wait_ms(source, now + 900_001), 0);
        assert!(backoff.is_empty());
    }

    #[test]
    fn a_hundred_failures_do_not_overflow() {
        let mut backoff = Backoff::new();
        let source = Source::of(ip("192.168.1.23"));
        for n in 0..100 {
            let wait = backoff.failed(source, n);
            assert!(wait <= 300_000);
        }
        assert_eq!(backoff.failed(source, 100), 300_000);
    }

    #[test]
    fn backoff_keys_a_mapped_address_as_ipv4_and_an_ipv6_client_by_its_64() {
        assert_eq!(
            Source::of(ip("::ffff:192.168.1.23")),
            Source::of(ip("192.168.1.23"))
        );
        assert_eq!(
            Source::of(ip("2001:db8:1:1::a")),
            Source::of(ip("2001:db8:1:1:ffff::b"))
        );
        assert_ne!(
            Source::of(ip("2001:db8:1:1::a")),
            Source::of(ip("2001:db8:1:2::a"))
        );
        let mut backoff = Backoff::new();
        backoff.failed(Source::of(ip("::ffff:192.168.1.23")), 0);
        assert_eq!(backoff.wait_ms(Source::of(ip("192.168.1.23")), 0), 1_000);
    }

    #[test]
    fn the_table_holds_1024_sources_and_drops_the_oldest() {
        let mut backoff = Backoff::new();
        for n in 0..1025u32 {
            backoff.failed(Source::V4(Ipv4Addr::from(n)), u64::from(n));
        }
        assert_eq!(backoff.len(), 1024);
        assert_eq!(
            backoff.failed(Source::V4(Ipv4Addr::from(0)), 1_025),
            1_000,
            "the oldest was dropped, so this is its first failure again"
        );
        assert_eq!(
            backoff.failed(Source::V4(Ipv4Addr::from(1024)), 1_025),
            2_000,
            "the newest was kept"
        );
        assert_eq!(backoff.len(), 1024);
    }
}
