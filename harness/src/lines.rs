// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Line-oriented capture of a stream (a VM's serial console, a daemon's stdout) with "wait until
//! a line matches this pattern" on top: the expect(1) of the harness.

use std::io::{BufRead, BufReader, Read};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
pub use regex::Regex;

/// A cloneable handle on a stream being read line by line on a background thread.
#[derive(Clone, Debug)]
pub struct Lines {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct State {
    lines: Vec<String>,
    closed: bool,
}

/// Position in the stream; each [`Lines::wait_for`] resumes after its last match.
#[derive(Debug, Default, Clone, Copy)]
pub struct Cursor(usize);

/// A matching line and its capture groups (group 1 onwards).
#[derive(Debug, Clone)]
pub struct Match {
    /// The whole line.
    pub line: String,
    /// Capture groups 1.., `None` for groups that did not participate.
    pub groups: Vec<Option<String>>,
}

impl Lines {
    /// Start reading `reader` on a thread. With `tee_prefix`, every line is also echoed to stderr
    /// behind that prefix.
    pub fn capture<R: Read + Send + 'static>(reader: R, tee_prefix: Option<String>) -> Self {
        let inner = Arc::new(Inner {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        });
        let worker = Arc::clone(&inner);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let line = String::from_utf8_lossy(&buf)
                            .trim_end_matches(['\r', '\n'])
                            .to_owned();
                        if let Some(prefix) = &tee_prefix {
                            eprintln!("{prefix} {line}");
                        }
                        lock(&worker.state).lines.push(line);
                        worker.changed.notify_all();
                    }
                }
            }
            lock(&worker.state).closed = true;
            worker.changed.notify_all();
        });
        Self { inner }
    }

    /// Block until a line after `cursor` matches `re` (moving the cursor past it) or `timeout`
    /// passes.
    ///
    /// # Errors
    ///
    /// On timeout or end of stream; the error carries the pattern and the last 20 lines seen.
    pub fn wait_for(&self, cursor: &mut Cursor, re: &Regex, timeout: Duration) -> Result<Match> {
        let deadline = Instant::now() + timeout;
        let mut state = lock(&self.inner.state);
        loop {
            while cursor.0 < state.lines.len() {
                let line = &state.lines[cursor.0];
                cursor.0 += 1;
                if let Some(caps) = re.captures(line) {
                    return Ok(Match {
                        line: line.clone(),
                        groups: caps
                            .iter()
                            .skip(1)
                            .map(|g| g.map(|m| m.as_str().to_owned()))
                            .collect(),
                    });
                }
            }
            let now = Instant::now();
            if state.closed || now >= deadline {
                let why = if state.closed {
                    "stream closed"
                } else {
                    "timed out"
                };
                let tail = state
                    .lines
                    .iter()
                    .rev()
                    .take(20)
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");
                bail!("{why} after {timeout:?} waiting for /{re}/; last lines:\n{tail}");
            }
            let (guard, _) = self
                .inner
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner);
            state = guard;
        }
    }

    /// Lines seen so far that match `re`.
    #[must_use]
    pub fn count(&self, re: &Regex) -> usize {
        lock(&self.inner.state)
            .lines
            .iter()
            .filter(|l| re.is_match(l))
            .count()
    }

    /// Lines from `cursor` (as it stood when it was copied) onwards that match `re`.
    #[must_use]
    pub fn count_since(&self, cursor: &Cursor, re: &Regex) -> usize {
        lock(&self.inner.state)
            .lines
            .iter()
            .skip(cursor.0)
            .filter(|l| re.is_match(l))
            .count()
    }

    /// The last `n` lines seen so far.
    #[must_use]
    pub fn tail(&self, n: usize) -> Vec<String> {
        let state = lock(&self.inner.state);
        state.lines[state.lines.len().saturating_sub(n)..].to_vec()
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn re(s: &str) -> Regex {
        Regex::new(s).unwrap()
    }

    #[test]
    fn wait_for_captures_and_advances() {
        let (r, mut w) = std::io::pipe().unwrap();
        let lines = Lines::capture(r, None);
        let mut cur = Cursor::default();
        w.write_all(b"noise\n[    0.5] openfeo-init: start version=0.1.0+abc mode=vm slot=none\n")
            .unwrap();
        let m = lines
            .wait_for(
                &mut cur,
                &re(r"openfeo-init: start version=(\S+) mode=(\w+)"),
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(m.groups[0].as_deref(), Some("0.1.0+abc"));
        assert_eq!(m.groups[1].as_deref(), Some("vm"));
        assert!(
            lines
                .wait_for(
                    &mut cur,
                    &re("openfeo-init: start"),
                    Duration::from_millis(100)
                )
                .is_err()
        );
        w.write_all(b"openfeo-init: start again\n").unwrap();
        assert!(
            lines
                .wait_for(&mut cur, &re("openfeo-init: start"), Duration::from_secs(2))
                .is_ok()
        );
        assert_eq!(lines.count(&re("openfeo-init: start")), 2);
        assert_eq!(lines.tail(1), vec!["openfeo-init: start again".to_string()]);
    }
}
