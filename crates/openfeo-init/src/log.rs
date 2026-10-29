// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Logging for PID 1 and the router child: `<level>prefix: message` lines written to `/dev/kmsg`
//! so they reach every console with kernel timestamps (SPEC §10), with stderr as the fallback
//! before devtmpfs is mounted or on a development host.

use std::fs::{File, OpenOptions};
use std::io::Write;

const KMSG: &str = "/dev/kmsg";
/// `KERN_INFO`.
pub const INFO: u8 = 6;
/// `KERN_WARNING`.
pub const WARN: u8 = 4;
/// `KERN_ERR`.
pub const ERR: u8 = 3;

/// A prefix plus a sink. Cheap to create; one per role (`openfeo-init`, `openfeo`).
#[derive(Debug)]
pub struct Log {
    prefix: &'static str,
    kmsg: Option<File>,
}

impl Log {
    /// Open `/dev/kmsg` if possible, otherwise log to stderr until [`Log::reopen`] succeeds.
    #[must_use]
    pub fn new(prefix: &'static str) -> Self {
        let mut log = Self { prefix, kmsg: None };
        log.reopen();
        log
    }

    /// Retry `/dev/kmsg` (call after devtmpfs is mounted).
    pub fn reopen(&mut self) {
        if self.kmsg.is_none() {
            self.kmsg = OpenOptions::new().write(true).open(KMSG).ok();
        }
    }

    /// Log at `KERN_INFO`.
    pub fn info(&self, msg: &str) {
        self.emit(INFO, msg);
    }

    /// Log at `KERN_WARNING`.
    pub fn warn(&self, msg: &str) {
        self.emit(WARN, msg);
    }

    /// Log at `KERN_ERR`.
    pub fn error(&self, msg: &str) {
        self.emit(ERR, msg);
    }

    fn emit(&self, level: u8, msg: &str) {
        if let Some(kmsg) = &self.kmsg
            && (&*kmsg)
                .write_all(format_line(level, self.prefix, msg).as_bytes())
                .is_ok()
        {
            return;
        }
        let _ = std::io::stderr().write_all(format!("{}: {msg}\n", self.prefix).as_bytes());
    }
}

/// The `/dev/kmsg` wire format: `<level>prefix: msg\n`.
#[must_use]
pub fn format_line(level: u8, prefix: &str, msg: &str) -> String {
    format!("<{level}>{prefix}: {msg}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kmsg_line_format() {
        assert_eq!(
            format_line(6, "openfeo-init", "start version=1"),
            "<6>openfeo-init: start version=1\n"
        );
    }
}
