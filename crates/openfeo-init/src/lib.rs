// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! PID 1 for OpenFeO (SPEC §6.1): mounts, reaper, supervisor, watchdog.
//! Blocking std + libc only; no async runtime. `unsafe` is confined to `sys`.

pub mod clock;
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

use cmdline::{Cmdline, Mode};
use log::Log;
use watchdog::Watchdog;

/// Everything PID 1 does, in order (SPEC §6.1), ending in the supervisor loop. `mode_flag` is
/// `--mode` from argv; `--mode container` skips every hardware duty (no mounts, sysctls or
/// watchdog: those belong to the host) and only supervises the child.
pub fn main(version: &str, mode_flag: Option<Mode>, build_epoch: u64) -> ! {
    let mut log = Log::new("openfeo-init");
    if mode_flag == Some(Mode::Container) {
        log.info(&format!("start version={version} mode=container slot=none"));
        let wd = Watchdog::software(Instant::now());
        log.info(&format!("watchdog {}", wd.describe()));
        supervisor::run(Mode::Container, &mut log, wd);
    }

    if let Err(err) = mounts::mount_all(mounts::EARLY, &log) {
        fatal(&log, &err.to_string());
    }
    if let Err(err) = sys::reopen_console() {
        log.warn(&format!("reopen /dev/console: {err}"));
    }
    log.reopen();

    let cmdline = read_cmdline(&log);
    let (mode, warning) = pid1_mode(mode_flag, cmdline.mode);
    if let Some(warning) = warning {
        log.warn(warning);
    }
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
    clock::floor(build_epoch, &log);
    sysctl::apply(&log);
    match mounts::mount_state(mode) {
        Ok(spec) if spec.fstype == "tmpfs" => {
            log.warn("state: volatile tmpfs until persistent storage lands in M5");
        }
        Ok(spec) => log.info(&format!("state: {} {}", spec.fstype, spec.source)),
        Err(err) => log.warn(&err.to_string()),
    }

    let wd = Watchdog::open(Instant::now());
    log.info(&format!("watchdog {}", wd.describe()));
    supervisor::run(mode, &mut log, wd)
}

/// The mode PID 1 runs in: `--mode` wins; `openfeo.mode=container` on a kernel command line is
/// meaningless for a real PID 1 and is replaced by `metal` with a warning.
#[must_use]
pub fn pid1_mode(flag: Option<Mode>, cmdline: Option<Mode>) -> (Mode, Option<&'static str>) {
    match (flag, cmdline) {
        (None, Some(Mode::Container)) => (
            Mode::Metal,
            Some(
                "openfeo.mode=container on the kernel command line means nothing to PID 1 \
                 (container mode comes from --mode); using metal",
            ),
        ),
        (Some(mode), _) | (None, Some(mode)) => (mode, None),
        (None, None) => (Mode::Metal, None),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_wins_for_pid1() {
        assert_eq!(
            pid1_mode(Some(Mode::Container), Some(Mode::Vm)),
            (Mode::Container, None)
        );
    }

    #[test]
    fn cmdline_container_is_refused_for_pid1() {
        let (mode, warning) = pid1_mode(None, Some(Mode::Container));
        assert_eq!(mode, Mode::Metal);
        assert!(warning.is_some_and(|w| w.contains("container")));
    }

    #[test]
    fn cmdline_mode_used_without_flag_and_default_is_metal() {
        assert_eq!(pid1_mode(None, Some(Mode::Vm)), (Mode::Vm, None));
        assert_eq!(pid1_mode(None, None), (Mode::Metal, None));
    }
}
