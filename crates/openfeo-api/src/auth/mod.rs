// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Who may use the API (SPEC §9): one admin password, a wait that grows with each wrong one,
//! and sessions named by bearer tokens. The backoff table and the sessions take the time as an
//! argument, on the monotonic clock, so a step of the wall clock changes nothing here.

pub mod backoff;
pub mod password;
pub mod sessions;

pub use backoff::{Backoff, Source};
pub use password::{PolicyError, Verifier};
pub use sessions::Sessions;

/// Authentication could not be carried out (as opposed to being refused).
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The password is too short or too long.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// Argon2 or the random source failed.
    #[error("{0}")]
    Internal(String),
}
