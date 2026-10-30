// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The lab's hosts as clients: an HTTP GET made from inside a namespace (so a LAN or ISP host
//! fetches through the router, no proxy in between) and a ping loop whose summary says how
//! many replies came back.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use nix::sched::{CloneFlags, setns};

use crate::netns::NetNs;

/// What a ping loop saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingStats {
    /// Echo requests sent.
    pub sent: usize,
    /// Echo replies received.
    pub received: usize,
}

/// `GET <path> HTTP/1.0` to `addr` from inside `ns`; the response body. A thread enters the
/// namespace (`setns`, like the tap opener) so the connection is made from there.
///
/// # Errors
///
/// When the namespace cannot be entered, the connection is refused or times out (`timeout`
/// covers the connect and each read), or the response has no header/body separator.
pub fn http_get(ns: &NetNs, addr: SocketAddr, path: &str, timeout: Duration) -> Result<String> {
    let ns_file = File::open(ns.path()).with_context(|| format!("open {}", ns.path().display()))?;
    let path = path.to_owned();
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> Result<String> {
                setns(&ns_file, CloneFlags::CLONE_NEWNET).context("setns")?;
                let mut stream = TcpStream::connect_timeout(&addr, timeout)
                    .with_context(|| format!("connect {addr}"))?;
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                stream
                    .write_all(format!("GET {path} HTTP/1.0\r\nHost: x\r\n\r\n").as_bytes())
                    .context("send request")?;
                let mut response = Vec::new();
                stream
                    .read_to_end(&mut response)
                    .with_context(|| format!("read response from {addr}"))?;
                let body =
                    body_of(&response).with_context(|| format!("no HTTP response from {addr}"))?;
                Ok(body.to_owned())
            })
            .join()
            .map_err(|_| anyhow::anyhow!("http thread panicked"))?
    })
}

/// `ping -c <count> -i <interval> -W 1 <target>` from `ns`, whatever its exit status (lost
/// packets make ping exit non-zero), parsed from the summary line.
///
/// # Errors
///
/// When ping cannot be run or prints no summary.
pub fn ping_loop(ns: &NetNs, target: &str, count: usize, interval: Duration) -> Result<PingStats> {
    let mut cmd = ns.command("ping")?;
    cmd.args([
        "-c",
        &count.to_string(),
        "-i",
        &format!("{:.3}", interval.as_secs_f64()),
        "-W",
        "1",
        target,
    ])
    .stdin(Stdio::null());
    let output = cmd.output().context("run ping")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stats = parse_ping_summary(&stdout).with_context(|| {
        format!(
            "ping {target}: no summary; stderr: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })?;
    ensure!(stats.sent > 0, "ping {target} sent nothing");
    Ok(stats)
}

/// `5 packets transmitted, 4 received, 20% packet loss, time 804ms` → sent 5, received 4.
#[must_use]
pub fn parse_ping_summary(output: &str) -> Option<PingStats> {
    let line = output
        .lines()
        .find(|line| line.contains("packets transmitted"))?;
    let mut sent = None;
    let mut received = None;
    for part in line.split(',') {
        let part = part.trim();
        let number = part.split_whitespace().next()?.parse::<usize>().ok();
        if part.contains("transmitted") {
            sent = number;
        } else if part.contains("received") {
            received = number;
        }
    }
    Some(PingStats {
        sent: sent?,
        received: received?,
    })
}

/// The body after the blank line that ends the headers; `None` without one.
#[must_use]
pub fn body_of(response: &[u8]) -> Option<&str> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    std::str::from_utf8(&response[separator + 4..]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ping_summary() {
        let output = "PING 203.0.113.1 (203.0.113.1) 56(84) bytes of data.\n\
                      64 bytes from 203.0.113.1: icmp_seq=1 ttl=63 time=0.4 ms\n\n\
                      --- 203.0.113.1 ping statistics ---\n\
                      5 packets transmitted, 4 received, 20% packet loss, time 804ms\n";
        let stats = parse_ping_summary(output).unwrap();
        assert_eq!((stats.sent, stats.received), (5, 4));
        assert!(parse_ping_summary("no summary here").is_none());
    }

    #[test]
    fn http_body_after_headers() {
        assert_eq!(
            body_of(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc"),
            Some("abc")
        );
        assert_eq!(body_of(b"HTTP/1.0 200 OK\r\n\r\n"), Some(""));
        assert_eq!(body_of(b"HTTP/1.0 200 OK\r\nno blank line"), None);
    }
}
