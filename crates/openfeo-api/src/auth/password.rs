// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The admin password (SPEC §9): 12 to 256 characters and nothing else demanded of it, hashed
//! with Argon2id at OWASP's parameters into a PHC string. Hashing costs tens of milliseconds
//! of one core, so the [`Verifier`] runs one at a time, off the async threads.

use std::sync::Arc;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use tokio::sync::Semaphore;

use super::AuthError;
use crate::limits::{ARGON2_M_KIB, ARGON2_P, ARGON2_T, PASSWORD_MAX, PASSWORD_MIN};

/// Why a new password is not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Fewer than 12 characters.
    #[error("a password is 12 characters or more")]
    TooShort,
    /// More than 256 characters.
    #[error("a password is 256 characters or fewer")]
    TooLong,
}

/// Whether `password` may be set: its length in characters, nothing else.
///
/// # Errors
///
/// When it is shorter than 12 or longer than 256 characters.
pub fn check_policy(password: &str) -> Result<(), PolicyError> {
    match password.chars().count() {
        n if n < PASSWORD_MIN => Err(PolicyError::TooShort),
        n if n > PASSWORD_MAX => Err(PolicyError::TooLong),
        _ => Ok(()),
    }
}

fn argon2() -> Result<Argon2<'static>, AuthError> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, None)
        .map_err(|err| AuthError::Internal(format!("argon2 parameters: {err}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash a new password: the policy first, then Argon2id with a fresh random salt.
///
/// # Errors
///
/// When the policy refuses it, or the random source or Argon2 fails.
pub fn hash(password: &str) -> Result<String, AuthError> {
    check_policy(password)?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|err| AuthError::Internal(format!("random source: {err}")))?;
    let salt =
        SaltString::encode_b64(&salt).map_err(|err| AuthError::Internal(format!("salt: {err}")))?;
    argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| AuthError::Internal(format!("argon2: {err}")))
}

/// Whether `password` is the one `phc` was made from. False for a hash that does not parse,
/// and false without hashing for a password longer than any that could have been set.
#[must_use]
pub fn verify(password: &str, phc: &str) -> bool {
    if password.chars().count() > PASSWORD_MAX {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    // The hash carries its own parameters; the default instance reads them from it.
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Runs Argon2 one at a time on the blocking pool, so a flood of logins costs one core's worth
/// and no more, and never stalls the async threads.
#[derive(Debug, Clone)]
pub struct Verifier {
    turn: Arc<Semaphore>,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier {
    /// A verifier with one turn.
    #[must_use]
    pub fn new() -> Self {
        Verifier {
            turn: Arc::new(Semaphore::new(1)),
        }
    }

    /// Run `work` on the blocking pool when its turn comes; `None` if it could not be run.
    async fn turn<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let _turn = self.turn.acquire().await.ok()?;
        tokio::task::spawn_blocking(work).await.ok()
    }

    /// [`verify`], when its turn comes.
    pub async fn verify(&self, password: String, phc: String) -> bool {
        self.turn(move || verify(&password, &phc))
            .await
            .unwrap_or(false)
    }

    /// [`hash`], when its turn comes.
    ///
    /// # Errors
    ///
    /// As [`hash`].
    pub async fn hash(&self, password: String) -> Result<String, AuthError> {
        self.turn(move || hash(&password))
            .await
            .unwrap_or_else(|| Err(AuthError::Internal("the hashing task failed".to_owned())))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";

    #[test]
    fn a_password_outside_12_to_256_characters_is_refused_without_hashing() {
        assert_eq!(check_policy("elevenchars"), Err(PolicyError::TooShort));
        assert_eq!(check_policy("twelve chars"), Ok(()));
        assert_eq!(
            check_policy(&"é".repeat(256)),
            Ok(()),
            "characters, not bytes"
        );
        assert_eq!(check_policy(&"x".repeat(257)), Err(PolicyError::TooLong));
        assert!(matches!(
            hash("short"),
            Err(AuthError::Policy(PolicyError::TooShort))
        ));
        let started = Instant::now();
        assert!(!verify(&"x".repeat(10_000), PHC));
        assert!(
            started.elapsed() < Duration::from_millis(5),
            "no Argon2 run"
        );
    }

    #[test]
    fn a_hash_is_argon2id_with_owasps_parameters_and_verifies() {
        let phc = hash("lab-admin-password").unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(verify("lab-admin-password", &phc));
        assert!(!verify("lab-admin-passwore", &phc));
        assert!(!verify("lab-admin-password", "not a hash"));
        assert!(!verify("lab-admin-password", ""));
        assert_ne!(
            phc,
            hash("lab-admin-password").unwrap(),
            "a fresh salt each time"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_verifier_runs_one_at_a_time() {
        use std::sync::Mutex;
        let verifier = Verifier::new();
        let spans = Arc::new(Mutex::new(Vec::new()));
        let work = |verifier: Verifier, spans: Arc<Mutex<Vec<(Instant, Instant)>>>| async move {
            verifier
                .turn(move || {
                    let started = Instant::now();
                    std::thread::sleep(Duration::from_millis(20));
                    spans.lock().unwrap().push((started, Instant::now()));
                })
                .await
        };
        let all = (0..6).map(|_| tokio::spawn(work(verifier.clone(), spans.clone())));
        for task in all.collect::<Vec<_>>() {
            assert!(task.await.unwrap().is_some());
        }
        let mut spans = spans.lock().unwrap().clone();
        spans.sort();
        assert_eq!(spans.len(), 6);
        for pair in spans.windows(2) {
            assert!(pair[0].1 <= pair[1].0, "two pieces of work overlapped");
        }
        // And the real thing goes through the same turn.
        let phc = verifier
            .hash("lab-admin-password".to_owned())
            .await
            .unwrap();
        assert!(
            verifier
                .verify("lab-admin-password".to_owned(), phc.clone())
                .await
        );
        assert!(!verifier.verify("wrong-password-x".to_owned(), phc).await);
    }
}
