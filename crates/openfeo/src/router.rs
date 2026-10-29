// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The router child in M0: log version and port map, heartbeat to PID 1, honour chaos knobs.

use std::path::Path;
use std::process;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context;
use openfeo_init::cmdline::{Cmdline, Mode};
use openfeo_init::ctl::{CtlPipe, HEARTBEAT_INTERVAL, Msg};
use openfeo_init::log::Log;

use crate::chaos::{self, Chaos};
use crate::ports;

const SYSFS_CLASS_NET: &str = "/sys/class/net";

/// Run until PID 1 goes away (or a chaos knob fires). Never returns `Ok` in practice.
///
/// # Errors
///
/// When the control pipe to PID 1 breaks.
pub fn run(mode: Mode, cmdline: &Cmdline, version: &str) -> anyhow::Result<()> {
    let log = Log::new("openfeo");
    log.info(&format!("router mode={mode} version={version}"));
    log_ports(&log);

    let chaos = chaos::from_cmdline(cmdline);
    if let Some(c) = chaos {
        log.info(&format!("chaos {c}"));
    }
    let mut ctl = CtlPipe::from_env();
    if ctl.is_none() {
        log.warn("no control pipe (not supervised by PID 1); heartbeats go nowhere");
    }

    let start = Instant::now();
    loop {
        if let Some(pipe) = ctl.as_mut() {
            pipe.send(Msg::Heartbeat).context("control pipe to PID 1")?;
        }
        if let Some(c) = chaos
            && start.elapsed() >= c.after()
        {
            fire(c, &log);
        }
        thread::sleep(sleep_for(start, chaos));
    }
}

fn log_ports(log: &Log) {
    match ports::enumerate(Path::new(SYSFS_CLASS_NET)) {
        Ok(list) => {
            for (i, p) in list.iter().enumerate() {
                log.info(&format!("port p{i} {} id={} mac={}", p.ifname, p.id, p.mac));
            }
            log.info(&format!("ports total={}", list.len()));
        }
        Err(err) => log.warn(&format!("ports: cannot read {SYSFS_CLASS_NET}: {err}")),
    }
}

fn fire(chaos: Chaos, log: &Log) -> ! {
    match chaos {
        Chaos::ChildExit { .. } => {
            log.info("chaos child-exit: exiting with status 3");
            process::exit(3)
        }
        Chaos::ChildHang { .. } => {
            log.info("chaos child-hang: heartbeats stopped");
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
        }
    }
}

/// The next heartbeat, or the chaos deadline if that comes first.
fn sleep_for(start: Instant, chaos: Option<Chaos>) -> Duration {
    let until_chaos = chaos.map(|c| c.after().saturating_sub(start.elapsed()));
    match until_chaos {
        Some(d) if d < HEARTBEAT_INTERVAL => d.max(Duration::from_millis(10)),
        _ => HEARTBEAT_INTERVAL,
    }
}
