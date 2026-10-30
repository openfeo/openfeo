// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The heartbeat to PID 1 (SPEC §5.3): every 5 s, but only while the health tracker says the
//! supervised tasks are alive and no applier is wedged. Withholding it is how a hung control
//! plane reaches the watchdog; `openfeo.chaos=child-hang` withholds it on purpose.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use openfeo_init::ctl::{CtlPipe, HEARTBEAT_INTERVAL, Msg};
use openfeo_runtime::HealthTracker;
use tracing::{error, info, warn};

/// Run forever. A broken control pipe ends the process (PID 1 is gone or has given up on us).
pub async fn run(mut ctl: Option<CtlPipe>, health: HealthTracker, hung: Arc<AtomicBool>) {
    let mut ticks = tokio::time::interval(HEARTBEAT_INTERVAL);
    let mut withheld = false;
    loop {
        ticks.tick().await;
        if hung.load(Ordering::Relaxed) {
            continue;
        }
        let now = Instant::now();
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
