// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Sessions (SPEC §9): a token is 32 random bytes, base64url; the router keeps only its
//! SHA-256, in memory. A session lapses after 30 minutes with no request and no connected
//! socket; at most 16 are held.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use super::AuthError;
use crate::limits::{MAX_SESSIONS, SESSION_IDLE_MS};

#[derive(Clone, Copy)]
struct Entry {
    last_seen_ms: u64,
    sockets: u32,
}

/// The sessions held, by the hash of their token.
#[derive(Default)]
pub struct Sessions {
    entries: BTreeMap<[u8; 32], Entry>,
}

impl std::fmt::Debug for Sessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Not even the hashes: a count says all a log needs.
        f.debug_struct("Sessions")
            .field("held", &self.entries.len())
            .finish()
    }
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl Sessions {
    /// No sessions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lapsed(entry: &Entry, now_ms: u64) -> bool {
        entry.sockets == 0 && now_ms.saturating_sub(entry.last_seen_ms) > SESSION_IDLE_MS
    }

    /// A new session and its token (43 base64url characters). At the cap the session idle
    /// longest goes, one with no socket before one with.
    ///
    /// # Errors
    ///
    /// When the random source fails.
    pub fn issue(&mut self, now_ms: u64) -> Result<String, AuthError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|err| AuthError::Internal(format!("random source: {err}")))?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        if self.entries.len() >= MAX_SESSIONS {
            let idlest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| (entry.sockets > 0, entry.last_seen_ms))
                .map(|(hash, _)| *hash);
            if let Some(idlest) = idlest {
                self.entries.remove(&idlest);
            }
        }
        self.entries.insert(
            digest(&token),
            Entry {
                last_seen_ms: now_ms,
                sockets: 0,
            },
        );
        Ok(token)
    }

    /// Whether `token` names a live session; a yes is activity and refreshes it.
    pub fn check(&mut self, token: &str, now_ms: u64) -> bool {
        let hash = digest(token);
        match self.entries.get_mut(&hash) {
            Some(entry) if Self::lapsed(entry, now_ms) => {
                self.entries.remove(&hash);
                false
            }
            Some(entry) => {
                entry.last_seen_ms = now_ms;
                true
            }
            None => false,
        }
    }

    /// Whether `token` still names a session, without counting as activity: what an open
    /// socket asks after any revocation.
    #[must_use]
    pub fn is_live(&self, token: &str) -> bool {
        self.entries.contains_key(&digest(token))
    }

    /// A socket of this session opened (`+1`) or closed (`-1`) at `now_ms`. A session with a
    /// socket does not lapse; closing the last one starts its idle time.
    pub fn connected(&mut self, token: &str, delta: i32, now_ms: u64) {
        if let Some(entry) = self.entries.get_mut(&digest(token)) {
            entry.sockets = entry.sockets.saturating_add_signed(delta);
            entry.last_seen_ms = now_ms;
        }
    }

    /// End the session `token` names; whether there was one.
    pub fn revoke(&mut self, token: &str) -> bool {
        self.entries.remove(&digest(token)).is_some()
    }

    /// End every session but the one `keep` names; how many ended.
    pub fn revoke_others(&mut self, keep: &str) -> usize {
        let keep = digest(keep);
        let before = self.entries.len();
        self.entries.retain(|hash, _| *hash == keep);
        before - self.entries.len()
    }

    /// End every session; how many ended.
    pub fn revoke_all(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.clear();
        before
    }

    /// Drop the sessions that have lapsed at `now_ms`; how many did.
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| !Self::lapsed(entry, now_ms));
        before - self.entries.len()
    }

    /// Sessions held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether none is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_and_backoff_take_only_the_monotonic_clock() {
        // Every method takes `now_ms`; nothing here reads a clock, so a step of the wall clock
        // (SNTP's first answer) cannot lapse a session.
        let mut sessions = Sessions::new();
        let token = sessions.issue(1_000).unwrap();
        assert_eq!(token.len(), 43);
        assert!(
            sessions.check(&token, 1_000 + 1_800_000),
            "exactly idle: still good, and refreshed"
        );
        assert_eq!(sessions.sweep(1_000 + 1_800_000 + 1_800_000), 0);
        assert_eq!(
            sessions.sweep(1_000 + 1_800_000 + 1_800_001),
            1,
            "idle past 30 minutes"
        );
        assert!(!sessions.check(&token, 1_000 + 3_600_002));
        assert!(!sessions.is_live(&token));
    }

    #[test]
    fn a_lapsed_session_is_refused_even_before_a_sweep() {
        let mut sessions = Sessions::new();
        let token = sessions.issue(0).unwrap();
        assert!(!sessions.check(&token, 1_800_001));
        assert!(sessions.is_empty());
        assert!(!sessions.check("not-a-token", 0));
    }

    #[test]
    fn a_connected_socket_keeps_a_session_and_the_seventeenth_drops_the_idlest() {
        let mut sessions = Sessions::new();
        let held = sessions.issue(0).unwrap();
        sessions.connected(&held, 1, 0);
        assert_eq!(sessions.sweep(10_000_000), 0, "a socket is activity");
        let others: Vec<String> = (1..16).map(|n| sessions.issue(n).unwrap()).collect();
        let seventeenth = sessions.issue(100).unwrap();
        assert_eq!(sessions.len(), 16);
        assert!(sessions.check(&held, 101), "the one with a socket stays");
        assert!(
            !sessions.check(&others[0], 101),
            "the idlest without a socket went"
        );
        assert!(sessions.check(&seventeenth, 101));
        assert_eq!(sessions.revoke_others(&held), 15);
        assert!(sessions.is_live(&held));
        sessions.connected(&held, -1, 5_000);
        assert_eq!(
            sessions.sweep(5_000 + 1_800_000),
            0,
            "idle time starts at the close"
        );
        assert_eq!(sessions.sweep(5_000 + 1_800_001), 1);
    }

    #[test]
    fn revoking_ends_a_session() {
        let mut sessions = Sessions::new();
        let token = sessions.issue(0).unwrap();
        assert!(sessions.revoke(&token));
        assert!(!sessions.revoke(&token));
        assert!(!sessions.check(&token, 1));
        let _ = sessions.issue(0).unwrap();
        let _ = sessions.issue(0).unwrap();
        assert_eq!(sessions.revoke_all(), 2);
    }

    #[test]
    fn nothing_secret_is_in_debug() {
        let mut sessions = Sessions::new();
        let token = sessions.issue(0).unwrap();
        let shown = format!("{sessions:?}");
        assert!(!shown.contains(&token));
        assert_eq!(shown, "Sessions { held: 1 }");
    }
}
