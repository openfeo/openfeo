// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! PID 1 for OpenFeO (SPEC §6.1): mounts, reaper, supervisor, watchdog.
//! Blocking std + libc only; no async runtime. `unsafe` is confined to `sys`.

pub mod cmdline;
pub mod ctl;
pub mod heartbeat;
pub mod log;
pub mod mounts;
pub mod restart;
pub mod supervisor;
#[allow(unsafe_code)]
pub mod sys;
pub mod sysctl;
pub mod watchdog;

use std::time::{Duration, Instant};

use cmdline::Cmdline;
use log::Log;
use watchdog::Watchdog;

/// Everything PID 1 does, in order (SPEC §6.1), ending in the supervisor loop.
pub fn main(version: &str) -> ! {
    let mut log = Log::new("openfeo-init");
    if let Err(err) = mounts::mount_all(mounts::EARLY, &log) {
        fatal(&log, &err.to_string());
    }
    if let Err(err) = sys::reopen_console() {
        log.warn(&format!("reopen /dev/console: {err}"));
    }
    log.reopen();

    let cmdline = read_cmdline(&log);
    let mode = cmdline.mode.unwrap_or_default();
    let slot = cmdline
        .slot
        .map_or_else(|| "none".to_owned(), |s| s.to_string());
    log.info(&format!("start version={version} mode={mode} slot={slot}"));

    if let Err(err) = sys::sethostname("openfeo") {
        log.warn(&format!("sethostname: {err}"));
    }
    if let Err(err) = sys::loopback_up() {
        log.warn(&format!("loopback up: {err}"));
    }
    sysctl::apply(&log);
    match mounts::mount_all(&[mounts::STATE_FALLBACK], &log) {
        Ok(()) => log.warn("state: volatile tmpfs until persistent storage lands in M5"),
        Err(err) => log.warn(&err.to_string()),
    }

    let wd = Watchdog::open(Instant::now());
    log.info(&format!("watchdog {}", wd.describe()));
    supervisor::run(mode, &mut log, wd)
}

fn read_cmdline(log: &Log) -> Cmdline {
    match std::fs::read_to_string("/proc/cmdline") {
        Ok(text) => match cmdline::parse(&text) {
            Ok(cmdline) => cmdline,
            Err(err) => {
                log.warn(&format!("cmdline: {err}; using defaults"));
                Cmdline::default()
            }
        },
        Err(err) => {
            log.warn(&format!(
                "cmdline: cannot read /proc/cmdline: {err}; using defaults"
            ));
            Cmdline::default()
        }
    }
}

/// Log `msg`, wait ten seconds so it can be read on the console, and reboot. A PID 1 that
/// cannot continue must not exit (that panics the kernel with less to show for it).
pub fn fatal(log: &Log, msg: &str) -> ! {
    log.error(msg);
    log.error("fatal; rebooting in 10s");
    std::thread::sleep(Duration::from_secs(10));
    if let Err(err) = sys::reboot(sys::RebootCmd::Restart) {
        log.error(&format!("reboot: {err}"));
    }
    std::process::exit(1)
}
