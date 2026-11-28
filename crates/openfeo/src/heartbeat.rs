// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The heartbeat to PID 1 (SPEC §5.3): every 5 s, but only while the health tracker says the
//! supervised tasks are alive and no applier is wedged. Withholding it is how a hung control
//! plane reaches the watchdog; `openfeo.chaos=child-hang` withholds it on purpose.
//!
//! This task owns the control pipe, so it is also the one that asks PID 1 for a restart when
//! the router has said its goodbyes (SPEC §6.3), healthy or not.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use openfeo_init::ctl::{CtlPipe, HEARTBEAT_INTERVAL, Msg};
use openfeo_runtime::HealthTracker;
use openfeo_world::health::HealthView;
use tokio::sync::watch;
use tracing::{error, info, warn};

/// Run forever. A broken control pipe ends the process (PID 1 is gone or has given up on us).
/// When `restart` turns true, PID 1 is asked to restart the machine.
pub async fn run(
    mut ctl: Option<CtlPipe>,
    health: HealthTracker,
    hung: Arc<AtomicBool>,
    view: watch::Sender<HealthView>,
    mut restart: watch::Receiver<bool>,
) {
    let mut ticks = tokio::time::interval(HEARTBEAT_INTERVAL);
    let mut withheld = false;
    // Until a restart was passed up, or nobody is left who could ask for one.
    let mut listening = true;
    loop {
        tokio::select! {
            _ = ticks.tick() => {}
            changed = restart.changed(), if listening => {
                if changed.is_err() {
                    listening = false;
                } else if *restart.borrow_and_update() {
                    listening = false;
                    pass_restart(ctl.as_mut());
                }
                continue;
            }
        }
        if hung.load(Ordering::Relaxed) {
            continue;
        }
        let now = Instant::now();
        // The API's stricter view of the same report (SPEC §10), sent only when it changes.
        let latest = health.report(now).view();
        view.send_if_modified(|current| {
            let changed = *current != latest;
            if changed {
                *current = latest;
            }
            changed
        });
        if health.is_healthy(now) {
            if withheld {
                info!("heartbeat resumed");
                withheld = false;
            }
            if let Some(pipe) = ctl.as_mut()
                && let Err(err) = pipe.send(Msg::Heartbeat)
            {
                error!("control pipe to PID 1: {err}; exiting");
                std::process::exit(2);
            }
        } else if !withheld {
            let reason = health.report(now).reason().unwrap_or_default();
            warn!("heartbeat withheld: {reason}");
            withheld = true;
        }
    }
}

/// Ask PID 1 to restart the machine: it syncs and reboots, and this process goes with it. With
/// no PID 1 above (run by hand) the process just ends.
fn pass_restart(ctl: Option<&mut CtlPipe>) {
    let Some(pipe) = ctl else {
        warn!("restart: no PID 1 above this process; exiting");
        std::process::exit(0);
    };
    info!("restart: asking PID 1");
    if let Err(err) = pipe.send(Msg::Reboot) {
        error!("control pipe to PID 1: {err}; exiting");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::os::fd::OwnedFd;

    use openfeo_init::ctl::decode;

    use super::*;

    /// The heartbeat task over a real pipe, and what arrives at the pipe's other end until
    /// `Msg::Reboot` does.
    async fn until_reboot(health: HealthTracker) -> Vec<Msg> {
        let (mut reader, writer) = std::io::pipe().unwrap();
        let ctl = CtlPipe::from(std::fs::File::from(OwnedFd::from(writer)));
        let (view, _viewed) = watch::channel(HealthView {
            healthy: true,
            unhealthy: Vec::new(),
        });
        let (restart, restarting) = watch::channel(false);
        let task = tokio::spawn(run(
            Some(ctl),
            health,
            Arc::new(AtomicBool::new(false)),
            view,
            restarting,
        ));
        // The first beat, or its withholding, is over before the restart is asked.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        restart.send_replace(true);
        let read = tokio::task::spawn_blocking(move || {
            let mut seen = Vec::new();
            let mut buf = [0u8; 16];
            while !seen.contains(&Msg::Reboot) {
                let n = reader.read(&mut buf).unwrap();
                assert!(
                    n > 0,
                    "the pipe closed before a restart came up it: {seen:?}"
                );
                seen.extend(decode(&buf[..n]));
            }
            seen
        });
        let seen = tokio::time::timeout(std::time::Duration::from_secs(5), read)
            .await
            .expect("no restart came up the pipe")
            .unwrap();
        task.abort();
        seen
    }

    /// SPEC §6.3: the task that owns the control pipe is the one that asks PID 1.
    #[tokio::test]
    async fn a_restart_is_passed_up_the_pipe() {
        let seen = until_reboot(HealthTracker::new()).await;
        assert_eq!(seen, [Msg::Heartbeat, Msg::Reboot]);
    }

    /// A router too unwell to be petted can still be told to restart.
    #[tokio::test]
    async fn a_restart_is_passed_up_while_heartbeats_are_withheld() {
        let health = HealthTracker::new();
        health.task_dead("a-task");
        let seen = until_reboot(health).await;
        assert_eq!(
            seen,
            [Msg::Reboot],
            "no heartbeat, and the restart all the same"
        );
    }
}
