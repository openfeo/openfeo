// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The control pipe between PID 1 and the router child (SPEC §5.3, §6.1): single-byte messages,
//! child → PID 1. Both ends live here so the protocol has one definition.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::RawFd;
use std::time::Duration;

/// Environment variable through which PID 1 tells the child which descriptor is the pipe.
pub const CTL_FD_ENV: &str = "OPENFEO_CTL_FD";
/// The descriptor number PID 1 installs the pipe's write end at in the child.
pub const CHILD_CTL_FD: RawFd = 3;
/// How often the child heartbeats while healthy.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// One message, one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Msg {
    /// `H`: the child's internal checks pass.
    Heartbeat,
    /// `R`: reboot the machine.
    Reboot,
    /// `P`: power the machine off.
    Poweroff,
}

impl Msg {
    /// Wire byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Msg::Heartbeat => b'H',
            Msg::Reboot => b'R',
            Msg::Poweroff => b'P',
        }
    }

    /// Decode one wire byte; `None` for anything unknown.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'H' => Some(Msg::Heartbeat),
            b'R' => Some(Msg::Reboot),
            b'P' => Some(Msg::Poweroff),
            _ => None,
        }
    }
}

/// Decode everything one `read` returned, skipping unknown bytes.
#[must_use]
pub fn decode(buf: &[u8]) -> Vec<Msg> {
    buf.iter().filter_map(|&b| Msg::from_byte(b)).collect()
}

/// The child's end of the pipe.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct CtlPipe(File);

impl CtlPipe {
    /// Adopt the descriptor named by [`CTL_FD_ENV`]; `None` when not running under PID 1.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let fd: RawFd = std::env::var(CTL_FD_ENV).ok()?.parse().ok()?;
        crate::sys::file_from_fd(fd).ok().map(Self)
    }

    /// Send one message.
    ///
    /// # Errors
    ///
    /// When PID 1 has closed its end (`EPIPE`).
    pub fn send(&mut self, msg: Msg) -> io::Result<()> {
        self.0.write_all(&[msg.to_byte()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_burst_skips_unknown() {
        assert_eq!(
            decode(b"HHxR"),
            vec![Msg::Heartbeat, Msg::Heartbeat, Msg::Reboot]
        );
    }

    #[test]
    fn byte_round_trip() {
        for m in [Msg::Heartbeat, Msg::Reboot, Msg::Poweroff] {
            assert_eq!(Msg::from_byte(m.to_byte()), Some(m));
        }
    }

    #[test]
    fn from_env_is_none_without_the_variable() {
        // The test binary never runs under PID 1 with the variable set.
        if std::env::var(CTL_FD_ENV).is_err() {
            assert!(CtlPipe::from_env().is_none());
        }
    }
}
