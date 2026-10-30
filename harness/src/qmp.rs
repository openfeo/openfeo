// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A minimal QMP client (JSON lines over a unix socket) for the few things scenarios need from
//! QEMU itself: a link flap (`set_link`), a reset that keeps the state disk (`system_reset`), and
//! `quit`. Events QEMU emits in between are skipped.

use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

/// How long to wait for QEMU to create its socket after it was spawned.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one reply may take.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// One QMP session.
#[derive(Debug)]
pub struct Qmp {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Qmp {
    /// Connect to `socket` (retrying until [`CONNECT_TIMEOUT`] while QEMU is still starting),
    /// read the greeting and negotiate capabilities.
    ///
    /// # Errors
    ///
    /// When the socket never appears, the greeting is not QMP, or the handshake is refused.
    pub fn connect(socket: &Path) -> Result<Qmp> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let stream = loop {
            match UnixStream::connect(socket) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("connect to QMP socket {}", socket.display()));
                }
            }
        };
        stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
        let mut qmp = Qmp {
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
        };
        let greeting = qmp.read_line()?;
        ensure!(
            greeting.get("QMP").is_some(),
            "unexpected QMP greeting: {greeting}"
        );
        qmp.command(&json!({"execute": "qmp_capabilities"}))?;
        Ok(qmp)
    }

    fn read_line(&mut self) -> Result<Value> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).context("read from QMP")?;
        ensure!(n > 0, "QMP connection closed");
        serde_json::from_str(&line).with_context(|| format!("QMP sent {line:?}"))
    }

    /// Send one command and return its `return` value, skipping events.
    ///
    /// # Errors
    ///
    /// When QEMU answers with an `error` object or the connection fails.
    pub fn command(&mut self, request: &Value) -> Result<Value> {
        writeln!(self.writer, "{request}").context("write to QMP")?;
        loop {
            let reply = self.read_line()?;
            if let Some(value) = reply.get("return") {
                return Ok(value.clone());
            }
            if let Some(err) = reply.get("error") {
                bail!(
                    "QMP {}: {}",
                    err["class"].as_str().unwrap_or("error"),
                    err["desc"].as_str().unwrap_or("")
                );
            }
        }
    }

    /// Set the guest-visible link state of a netdev (`p0`, `p1`, `p2` in the lab).
    ///
    /// # Errors
    ///
    /// As [`Qmp::command`].
    pub fn set_link(&mut self, netdev: &str, up: bool) -> Result<()> {
        self.command(&json!({"execute": "set_link", "arguments": {"name": netdev, "up": up}}))
            .map(|_| ())
    }

    /// Reset the machine: the kernel boots again, the state disk keeps its contents.
    ///
    /// # Errors
    ///
    /// As [`Qmp::command`].
    pub fn system_reset(&mut self) -> Result<()> {
        self.command(&json!({"execute": "system_reset"}))
            .map(|_| ())
    }

    /// Ask QEMU to exit. The reply is read if it comes; QEMU may already be gone.
    ///
    /// # Errors
    ///
    /// When the request cannot be written.
    pub fn quit(&mut self) -> Result<()> {
        writeln!(self.writer, r#"{{"execute": "quit"}}"#).context("write to QMP")?;
        let _ = self.read_line();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    /// A fake QEMU: greets, acks capabilities, records `set_link` arguments, emits an event before
    /// one reply, and answers `system_reset`.
    fn fake_qemu(listener: UnixListener) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            writeln!(
                writer,
                r#"{{"QMP": {{"version": {{"qemu": {{"micro": 0, "minor": 1, "major": 11}}}}, "capabilities": ["oob"]}}}}"#
            )
            .unwrap();
            let mut recorded = Vec::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                match request["execute"].as_str().unwrap() {
                    "qmp_capabilities" => writeln!(writer, r#"{{"return": {{}}}}"#).unwrap(),
                    "set_link" => {
                        recorded.push(request["arguments"].clone());
                        writeln!(writer, r#"{{"event": "NIC_RX_FILTER_CHANGED", "data": {{}}, "timestamp": {{"seconds": 1, "microseconds": 2}}}}"#).unwrap();
                        writeln!(writer, r#"{{"return": {{}}}}"#).unwrap();
                    }
                    "system_reset" => {
                        writeln!(writer, r#"{{"return": {{}}}}"#).unwrap();
                        writeln!(writer, r#"{{"event": "RESET", "data": {{"guest": true}}, "timestamp": {{"seconds": 1, "microseconds": 3}}}}"#).unwrap();
                    }
                    "quit" => {
                        writeln!(writer, r#"{{"return": {{}}}}"#).unwrap();
                        break;
                    }
                    other => writeln!(
                        writer,
                        r#"{{"error": {{"class": "CommandNotFound", "desc": "{other} not found"}}}}"#
                    )
                    .unwrap(),
                }
            }
            recorded
        })
    }

    #[test]
    fn qmp_handshake_set_link_and_reset() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let server = fake_qemu(UnixListener::bind(&socket).unwrap());
        let mut qmp = Qmp::connect(&socket).unwrap();
        qmp.set_link("p0", false).unwrap();
        qmp.set_link("p0", true).unwrap();
        qmp.system_reset().unwrap();
        qmp.quit().unwrap();
        let recorded = server.join().unwrap();
        assert_eq!(
            recorded,
            vec![
                serde_json::json!({"name": "p0", "up": false}),
                serde_json::json!({"name": "p0", "up": true}),
            ]
        );
    }

    #[test]
    fn qmp_error_replies_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let _server = fake_qemu(UnixListener::bind(&socket).unwrap());
        let mut qmp = Qmp::connect(&socket).unwrap();
        let err = qmp
            .command(&serde_json::json!({"execute": "no_such_command"}))
            .unwrap_err();
        assert!(err.to_string().contains("CommandNotFound"), "{err}");
    }
}
