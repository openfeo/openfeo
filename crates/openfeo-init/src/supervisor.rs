// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The PID 1 loop (SPEC §5.3, §6.1): spawn the router child, read its heartbeats, pet the
//! watchdog while they arrive, restart the child with backoff when it dies, give up after three
//! restarts in ten minutes, and handle the signals PID 1 receives.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use crate::cmdline::Mode;
use crate::ctl::{self, Msg};
use crate::heartbeat::Heartbeat;
use crate::log::Log;
use crate::restart::{Decision, MAX_RESTARTS, RestartPolicy, WINDOW};
use crate::sys::{self, ExitStatus, PollFd, RebootCmd};
use crate::watchdog::{PET_INTERVAL, Watchdog};

/// The child is this very binary.
const EXE: &CStr = c"/proc/self/exe";
/// How long a child in container mode gets to exit after SIGTERM.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Run the supervisor forever.
pub fn run(mode: Mode, log: &mut Log, wd: Watchdog) -> ! {
    let signals = match sys::signalfd(&[libc::SIGCHLD, libc::SIGTERM, libc::SIGINT]) {
        Ok(fd) => fd,
        Err(err) => crate::fatal(log, &format!("signalfd: {err}")),
    };
    let now = Instant::now();
    let mut supervisor = Supervisor {
        mode,
        wd,
        signals,
        hb: Heartbeat::new(now),
        policy: RestartPolicy::default(),
        child: None,
        restart_at: Some(now),
        next_pet: now,
        gave_up: false,
        hb_lost: false,
    };
    loop {
        supervisor.step(log);
    }
}

struct Child {
    pid: libc::pid_t,
    /// `None` once the child closed its end.
    ctl_rx: Option<File>,
}

struct Supervisor {
    mode: Mode,
    wd: Watchdog,
    signals: File,
    hb: Heartbeat,
    policy: RestartPolicy,
    child: Option<Child>,
    restart_at: Option<Instant>,
    next_pet: Instant,
    gave_up: bool,
    hb_lost: bool,
}

impl Supervisor {
    fn step(&mut self, log: &Log) {
        let now = Instant::now();
        self.maybe_spawn(now, log);
        self.maybe_pet(now, log);
        let (signals_ready, ctl_ready) = self.wait(now, log);
        let now = Instant::now();
        if ctl_ready {
            self.drain_ctl(now, log);
        }
        if signals_ready {
            self.drain_signals(now, log);
        }
    }

    fn maybe_spawn(&mut self, now: Instant, log: &Log) {
        if self.child.is_some() || self.gave_up || self.restart_at.is_none_or(|t| now < t) {
            return;
        }
        self.restart_at = None;
        match spawn_child(self.mode) {
            Ok(child) => {
                self.hb.record(now);
                log.info(&format!("child started pid={}", child.pid));
                self.child = Some(child);
            }
            Err(err) => {
                log.error(&format!("spawn child: {err}"));
                self.restart_at = Some(now + Duration::from_secs(1));
            }
        }
    }

    fn maybe_pet(&mut self, now: Instant, log: &Log) {
        if now < self.next_pet {
            return;
        }
        self.next_pet = now + PET_INTERVAL;
        if !self.gave_up && self.hb.healthy(now) {
            if self.hb_lost {
                self.hb_lost = false;
                log.info("heartbeat restored");
            }
            if let Err(err) = self.wd.pet(now) {
                log.warn(&format!("watchdog pet: {err}"));
            }
        } else if !self.hb_lost {
            self.hb_lost = true;
            log.warn("heartbeat lost; watchdog no longer petted");
        }
        if self.wd.expired(now) {
            log.error("software watchdog expired; rebooting");
            self.reboot(log);
        }
    }

    /// Block until the next deadline, a signal or control-pipe data. Returns `(signals, ctl)`.
    fn wait(&mut self, now: Instant, log: &Log) -> (bool, bool) {
        let mut deadline = self.next_pet;
        if let Some(t) = self.restart_at {
            deadline = deadline.min(t);
        }
        let mut fds = vec![PollFd {
            fd: self.signals.as_raw_fd(),
            readable: false,
        }];
        if let Some(rx) = self.child.as_ref().and_then(|c| c.ctl_rx.as_ref()) {
            fds.push(PollFd {
                fd: rx.as_raw_fd(),
                readable: false,
            });
        }
        if let Err(err) = sys::poll(&mut fds, deadline.saturating_duration_since(now)) {
            log.error(&format!("poll: {err}"));
            std::thread::sleep(Duration::from_millis(100));
            return (false, false);
        }
        (fds[0].readable, fds.get(1).is_some_and(|p| p.readable))
    }

    fn drain_ctl(&mut self, now: Instant, log: &Log) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let Some(rx) = child.ctl_rx.as_mut() else {
            return;
        };
        let mut buf = [0u8; 64];
        match rx.read(&mut buf) {
            Ok(0) => child.ctl_rx = None,
            Ok(n) => {
                for msg in ctl::decode(&buf[..n]) {
                    match msg {
                        Msg::Heartbeat => self.hb.record(now),
                        Msg::Reboot => {
                            log.info("reboot requested by child");
                            self.reboot(log);
                        }
                        Msg::Poweroff => {
                            log.info("poweroff requested by child");
                            if let Err(err) = sys::reboot(RebootCmd::PowerOff) {
                                log.error(&format!("poweroff: {err}"));
                            }
                        }
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => {
                log.warn(&format!("control pipe: {err}"));
                child.ctl_rx = None;
            }
        }
    }

    fn drain_signals(&mut self, now: Instant, log: &Log) {
        while let Ok(Some(signal)) = sys::read_signal(&self.signals) {
            match signal {
                libc::SIGCHLD => self.reap_all(now, log),
                libc::SIGTERM | libc::SIGINT => self.on_terminate(signal, log),
                other => log.warn(&format!("unexpected signal {other}")),
            }
        }
    }

    fn reap_all(&mut self, now: Instant, log: &Log) {
        loop {
            match sys::reap() {
                Ok(Some((pid, status))) => {
                    if self.child.as_ref().is_some_and(|c| c.pid == pid) {
                        self.child = None;
                        self.on_child_exit(now, status, log);
                    } else {
                        log.info(&format!("reaped orphan pid={pid} status={status}"));
                    }
                }
                Ok(None) => return,
                Err(err) => {
                    log.warn(&format!("waitpid: {err}"));
                    return;
                }
            }
        }
    }

    fn on_child_exit(&mut self, now: Instant, status: ExitStatus, log: &Log) {
        match self.policy.on_exit(now) {
            Decision::RestartAfter(delay) => {
                log.info(&format!(
                    "child exited status={status} restart_in={}s restarts={}",
                    delay.as_secs(),
                    self.policy.restarts_in_window()
                ));
                self.restart_at = Some(now + delay);
            }
            Decision::GiveUp => {
                log.error(&format!(
                    "child exited status={status}; giving up after {MAX_RESTARTS} restarts in \
                     {}min; awaiting watchdog reset",
                    WINDOW.as_secs() / 60
                ));
                self.gave_up = true;
            }
        }
    }

    fn on_terminate(&mut self, signal: libc::c_int, log: &Log) {
        if self.mode == Mode::Container {
            log.info("shutdown requested; stopping child");
            if let Some(child) = &self.child {
                let _ = sys::kill(child.pid, libc::SIGTERM);
                let deadline = Instant::now() + SHUTDOWN_GRACE;
                while Instant::now() < deadline {
                    if matches!(sys::reap(), Ok(Some(_))) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = sys::kill(child.pid, libc::SIGKILL);
            }
            std::process::exit(0);
        }
        if signal == libc::SIGINT {
            log.info("SIGINT (ctrl-alt-del); rebooting");
            self.reboot(log);
        } else {
            log.warn("SIGTERM ignored outside container mode");
        }
    }

    /// Reboot, or exit in container mode where reboot(2) is not ours to call.
    fn reboot(&self, log: &Log) {
        if self.mode == Mode::Container {
            std::process::exit(1);
        }
        if let Err(err) = sys::reboot(RebootCmd::Restart) {
            log.error(&format!("reboot: {err}"));
            std::process::exit(1);
        }
    }
}

/// Fork and exec ourselves as the router child with a fresh control pipe.
fn spawn_child(mode: Mode) -> io::Result<Child> {
    let (rx, tx) = sys::pipe()?;
    let argv = [
        c"openfeo".to_owned(),
        c"--mode".to_owned(),
        CString::new(mode.as_str())?,
    ];
    let envp = [CString::new(format!(
        "{}={}",
        ctl::CTL_FD_ENV,
        ctl::CHILD_CTL_FD
    ))?];
    let pid = sys::spawn(EXE, &argv, &envp, tx.as_raw_fd())?;
    drop(tx);
    Ok(Child {
        pid,
        ctl_rx: Some(rx),
    })
}
