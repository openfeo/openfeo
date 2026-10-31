// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The answer cache (SPEC §7.7): positive answers for their smallest TTL, NXDOMAIN and NODATA
//! for the SOA's minimum (RFC 2308 §5), least recently used out first.

use std::collections::BTreeMap;

use crate::Timestamp;
use crate::name::Name;
use crate::wire::{Message, RData, Record, rcode, rtype};

/// Entries kept in M1. SPEC §7.7 wants the size to scale with RAM; the figure comes from
/// `/proc/meminfo` later.
pub const DEFAULT_CAPACITY: usize = 4096;
/// The longest a positive answer is kept, whatever its TTL says.
pub const MAX_TTL: u32 = 86_400;
/// The longest a negative answer is kept (RFC 2308 §5 suggests at most a few hours).
pub const MAX_NEGATIVE_TTL: u32 = 3_600;

/// What a cached answer is for: class IN is implied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub name: Name,
    pub qtype: u16,
    /// The client's DO bit: a signed answer and an unsigned one are different answers.
    pub dnssec_ok: bool,
    /// The client's CD bit: an answer a validating upstream would otherwise have refused must
    /// not reach the clients that did not ask for it.
    pub checking_disabled: bool,
}

/// One cached answer, as [`Cache::lookup`] hands it back: TTLs already reduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub rcode: u8,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    /// The upstream's AD bit.
    pub authentic_data: bool,
    /// When the entry leaves the cache.
    pub expires_at: Timestamp,
}

/// Counters for diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub evictions: u64,
}

#[derive(Debug, Clone)]
struct Slot {
    entry: Entry,
    stored_at: Timestamp,
    /// The use counter's value at the last store or hit: the smallest is evicted first.
    last_used: u64,
}

/// The cache.
#[derive(Debug)]
pub struct Cache {
    capacity: usize,
    entries: BTreeMap<Key, Slot>,
    uses: u64,
    stats: CacheStats,
}

impl Cache {
    /// An empty cache holding at most `capacity` entries (at least one).
    #[must_use]
    pub fn new(capacity: usize) -> Cache {
        Cache {
            capacity: capacity.max(1),
            entries: BTreeMap::new(),
            uses: 0,
            stats: CacheStats::default(),
        }
    }

    /// Store `response` for `key` at `now`. A positive answer lives its smallest TTL (0 is not
    /// cached, over [`MAX_TTL`] is clamped); NXDOMAIN and NODATA live the smaller of the SOA's
    /// TTL and minimum, capped at [`MAX_NEGATIVE_TTL`], and only with an SOA in the authority
    /// section, whose TTL becomes that negative TTL; SERVFAIL, REFUSED and truncated messages
    /// are not stored. Returns whether it was stored.
    pub fn store(&mut self, key: Key, response: &Message, now: Timestamp) -> bool {
        if response.header.truncated {
            return false;
        }
        let entry = match response.header.rcode {
            rcode::NOERROR if !response.answers.is_empty() => {
                let ttl = response
                    .answers
                    .iter()
                    .map(|record| record.ttl)
                    .min()
                    .unwrap_or(0)
                    .min(MAX_TTL);
                if ttl == 0 {
                    return false;
                }
                Entry {
                    rcode: rcode::NOERROR,
                    answers: response
                        .answers
                        .iter()
                        .map(|record| Record {
                            ttl: record.ttl.min(MAX_TTL),
                            ..record.clone()
                        })
                        .collect(),
                    authorities: response.authorities.clone(),
                    authentic_data: response.header.authentic_data,
                    expires_at: now + Timestamp::from(ttl) * 1000,
                }
            }
            rcode::NOERROR | rcode::NXDOMAIN => {
                let Some(ttl) = negative_ttl(response) else {
                    return false;
                };
                Entry {
                    rcode: response.header.rcode,
                    answers: Vec::new(),
                    authorities: response
                        .authorities
                        .iter()
                        .map(|record| {
                            if record.rtype == rtype::SOA {
                                Record {
                                    ttl,
                                    ..record.clone()
                                }
                            } else {
                                record.clone()
                            }
                        })
                        .collect(),
                    authentic_data: response.header.authentic_data,
                    expires_at: now + Timestamp::from(ttl) * 1000,
                }
            }
            _ => return false,
        };
        self.uses += 1;
        self.stats.stores += 1;
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.evict();
        }
        self.entries.insert(
            key,
            Slot {
                entry,
                stored_at: now,
                last_used: self.uses,
            },
        );
        true
    }

    /// The answer for `key` with its TTLs reduced by the time since it was stored; an expired
    /// entry is removed and counts as a miss.
    pub fn lookup(&mut self, key: &Key, now: Timestamp) -> Option<Entry> {
        let Some(slot) = self.entries.get_mut(key) else {
            self.stats.misses += 1;
            return None;
        };
        if slot.entry.expires_at <= now {
            self.entries.remove(key);
            self.stats.misses += 1;
            return None;
        }
        self.uses += 1;
        slot.last_used = self.uses;
        self.stats.hits += 1;
        let elapsed = u32::try_from(now.saturating_sub(slot.stored_at) / 1000).unwrap_or(u32::MAX);
        let aged = |record: &Record| Record {
            ttl: record.ttl.saturating_sub(elapsed),
            ..record.clone()
        };
        Some(Entry {
            rcode: slot.entry.rcode,
            answers: slot.entry.answers.iter().map(aged).collect(),
            authorities: slot.entry.authorities.iter().map(aged).collect(),
            authentic_data: slot.entry.authentic_data,
            expires_at: slot.entry.expires_at,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.stats
    }

    fn evict(&mut self) {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, slot)| slot.last_used)
            .map(|(key, _)| key.clone());
        if let Some(key) = victim {
            self.entries.remove(&key);
            self.stats.evictions += 1;
        }
    }
}

/// RFC 2308 §5: the smaller of the SOA's TTL and its minimum field, capped; `None` without an
/// SOA in the authority section or when it comes to zero.
fn negative_ttl(response: &Message) -> Option<u32> {
    response
        .authorities
        .iter()
        .find_map(|record| match &record.rdata {
            RData::Soa { minimum, .. } if record.rtype == rtype::SOA => {
                let ttl = record.ttl.min(*minimum).min(MAX_NEGATIVE_TTL);
                (ttl > 0).then_some(ttl)
            }
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{CLASS_IN, Header, Question, rcode, rtype};
    use std::net::Ipv4Addr;

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    fn key(text: &str, qtype: u16) -> Key {
        Key {
            name: name(text),
            qtype,
            dnssec_ok: false,
            checking_disabled: false,
        }
    }

    fn query(text: &str, qtype: u16) -> Message {
        Message {
            header: Header {
                id: 1,
                recursion_desired: true,
                ..Header::default()
            },
            questions: vec![Question {
                name: name(text),
                qtype,
                qclass: CLASS_IN,
            }],
            ..Message::default()
        }
    }

    /// A NOERROR answer with one A record per `(rtype, ttl)` given.
    fn answer(text: &str, records: &[(u16, u32)]) -> Message {
        let mut m = Message::reply_to(&query(text, rtype::A), rcode::NOERROR);
        for (rtype, ttl) in records {
            m.answers.push(Record {
                name: name(text),
                rtype: *rtype,
                class: CLASS_IN,
                ttl: *ttl,
                rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            });
        }
        m
    }

    fn soa(ttl: u32, minimum: u32) -> Record {
        Record {
            name: name("isp.example"),
            rtype: rtype::SOA,
            class: CLASS_IN,
            ttl,
            rdata: RData::Soa {
                mname: name("ns.isp.example"),
                rname: name("hostmaster.isp.example"),
                serial: 1,
                refresh: 30,
                retry: 30,
                expire: 30,
                minimum,
            },
        }
    }

    fn nxdomain_without_soa(text: &str) -> Message {
        Message::reply_to(&query(text, rtype::A), rcode::NXDOMAIN)
    }

    fn nxdomain_with_soa(text: &str, soa_ttl: u32, minimum: u32) -> Message {
        let mut m = nxdomain_without_soa(text);
        m.authorities.push(soa(soa_ttl, minimum));
        m
    }

    fn nodata_with_soa(text: &str, soa_ttl: u32, minimum: u32) -> Message {
        let mut m = Message::reply_to(&query(text, rtype::AAAA), rcode::NOERROR);
        m.authorities.push(soa(soa_ttl, minimum));
        m
    }

    #[test]
    fn positive_answers_live_their_smallest_ttl_and_count_down() {
        let mut c = Cache::new(8);
        let r = answer("www.isp.example", &[(rtype::A, 60), (rtype::A, 30)]);
        assert!(c.store(key("www.isp.example", rtype::A), &r, 1_000));
        let hit = c.lookup(&key("www.isp.example", rtype::A), 11_000).unwrap();
        assert_eq!(
            hit.answers.iter().map(|a| a.ttl).collect::<Vec<_>>(),
            vec![50, 20]
        );
        assert_eq!(hit.expires_at, 31_000);
        assert!(
            c.lookup(&key("www.isp.example", rtype::A), 31_000)
                .is_none(),
            "expired at min TTL"
        );
        assert_eq!(
            c.stats(),
            CacheStats {
                hits: 1,
                misses: 1,
                stores: 1,
                evictions: 0
            }
        );
    }

    #[test]
    fn negative_answers_need_an_soa_and_live_its_minimum() {
        let mut c = Cache::new(8);
        assert!(!c.store(
            key("nx.isp.example", rtype::A),
            &nxdomain_without_soa("nx.isp.example"),
            0
        ));
        let nx = nxdomain_with_soa("nx.isp.example", 300, 30);
        assert!(c.store(key("nx.isp.example", rtype::A), &nx, 0));
        let hit = c.lookup(&key("nx.isp.example", rtype::A), 10_000).unwrap();
        assert_eq!((hit.rcode, hit.expires_at), (rcode::NXDOMAIN, 30_000));
        assert_eq!(
            hit.authorities[0].ttl, 20,
            "the SOA's TTL is the negative TTL"
        );
        let nodata = nodata_with_soa("www.isp.example", 7_200, 5_000);
        assert!(c.store(key("www.isp.example", rtype::AAAA), &nodata, 0));
        assert_eq!(
            c.lookup(&key("www.isp.example", rtype::AAAA), 0)
                .unwrap()
                .expires_at,
            3_600_000,
            "capped at an hour"
        );
    }

    #[test]
    fn servfail_zero_ttl_and_truncated_answers_are_not_stored() {
        let mut c = Cache::new(8);
        assert!(!c.store(
            key("x", rtype::A),
            &Message::reply_to(&query("x", rtype::A), rcode::SERVFAIL),
            0
        ));
        assert!(!c.store(key("x", rtype::A), &answer("x", &[(rtype::A, 0)]), 0));
        let mut tc = answer("x", &[(rtype::A, 60)]);
        tc.header.truncated = true;
        assert!(!c.store(key("x", rtype::A), &tc, 0));
        assert!(c.is_empty());
    }

    #[test]
    fn the_least_recently_used_entry_goes_first_and_big_ttls_are_clamped() {
        let mut c = Cache::new(2);
        c.store(
            key("a", rtype::A),
            &answer("a", &[(rtype::A, 1_000_000)]),
            0,
        );
        c.store(key("b", rtype::A), &answer("b", &[(rtype::A, 60)]), 0);
        assert_eq!(
            c.lookup(&key("a", rtype::A), 1_000).unwrap().expires_at,
            86_400_000
        );
        c.store(key("c", rtype::A), &answer("c", &[(rtype::A, 60)]), 2_000);
        assert!(
            c.lookup(&key("b", rtype::A), 2_000).is_none(),
            "b was least recently used"
        );
        assert!(c.lookup(&key("a", rtype::A), 2_000).is_some());
        assert_eq!(c.stats().evictions, 1);
        assert_eq!(c.len(), 2);
    }
}
