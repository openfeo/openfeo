// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Every number the API holds itself to (SPEC §8.3, §9), in one place.

use std::time::Duration;

/// A WebSocket's first frame must be `Auth` within this long.
pub const AUTH_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest WebSocket frame accepted, in bytes.
pub const MAX_FRAME: usize = 1 << 20;
/// WebSockets open at once.
pub const MAX_SOCKETS: usize = 16;
/// Subscriptions on one WebSocket.
pub const MAX_SUBSCRIPTIONS: usize = 16;
/// Events queued for one socket before the oldest is dropped.
pub const EVENT_QUEUE: usize = 256;
/// Recent events kept for a subscriber's backlog.
pub const EVENT_BACKLOG: usize = 256;
/// The server pings an open WebSocket this often.
pub const PING_INTERVAL: Duration = Duration::from_secs(20);
/// Sessions held at once.
pub const MAX_SESSIONS: usize = 16;
/// A session with no request and no socket for this long lapses.
pub const SESSION_IDLE_MS: u64 = 1_800_000;
/// The wait after the first wrong password.
pub const BACKOFF_FIRST_MS: u64 = 1_000;
/// The longest wait a wrong password earns.
pub const BACKOFF_MAX_MS: u64 = 300_000;
/// A source quiet for this long is forgotten.
pub const BACKOFF_FORGET_MS: u64 = 900_000;
/// Sources remembered at once.
pub const BACKOFF_SOURCES: usize = 1024;
/// The shortest password, in characters.
pub const PASSWORD_MIN: usize = 12;
/// The longest password, in characters.
pub const PASSWORD_MAX: usize = 256;
/// The largest HTTP request body, in bytes.
pub const MAX_BODY: usize = 4096;
/// Connections open at once.
pub const MAX_CONNECTIONS: usize = 64;
/// A connection must finish its TLS handshake, and then send its request head, within this long.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The certificate's validity, in days (ADR-0024).
pub const CERT_DAYS: u32 = 825;
/// The certificate is reissued when fewer than this many days remain.
pub const CERT_RENEW_DAYS: u32 = 60;
/// Argon2id memory, in KiB (OWASP).
pub const ARGON2_M_KIB: u32 = 19_456;
/// Argon2id passes.
pub const ARGON2_T: u32 = 2;
/// Argon2id lanes.
pub const ARGON2_P: u32 = 1;
