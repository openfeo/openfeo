// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Logging (SPEC §10): `tracing` events become `<pri>prefix: message key=value` lines, kept in an
//! in-memory ring (DEBUG and above, 8 MiB by default, exposed over the API in M4) and written to
//! `/dev/kmsg` (INFO and above) so the serial console shows them with the kernel's own messages.
//! Priorities follow syslog: ERROR 3, WARN 4, INFO 6, DEBUG 7.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};

/// Ring capacity unless configured otherwise (SPEC §10).
pub const DEFAULT_RING_BYTES: usize = 8 * 1024 * 1024;
/// Longest line handed to `/dev/kmsg` (the kernel truncates around 1024 bytes).
pub const KMSG_MAX_LINE: usize = 1000;

/// A bounded-by-bytes queue of formatted lines, oldest evicted first.
#[derive(Debug)]
pub struct Ring {
    inner: Mutex<RingInner>,
}

#[derive(Debug)]
struct RingInner {
    lines: VecDeque<String>,
    bytes: usize,
    capacity: usize,
}

impl Ring {
    /// An empty ring holding at most `capacity_bytes` of line text.
    #[must_use]
    pub fn new(capacity_bytes: usize) -> Self {
        Ring {
            inner: Mutex::new(RingInner {
                lines: VecDeque::new(),
                bytes: 0,
                capacity: capacity_bytes,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, RingInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Append `line`, evicting the oldest lines until it fits.
    pub fn push(&self, line: String) {
        let mut ring = self.lock();
        while ring.bytes + line.len() > ring.capacity {
            match ring.lines.pop_front() {
                Some(old) => ring.bytes -= old.len(),
                None => break,
            }
        }
        ring.bytes += line.len();
        ring.lines.push_back(line);
    }

    /// The last `n` lines, oldest first.
    #[must_use]
    pub fn tail(&self, n: usize) -> Vec<String> {
        let ring = self.lock();
        let skip = ring.lines.len().saturating_sub(n);
        ring.lines.iter().skip(skip).cloned().collect()
    }

    /// Bytes of line text currently held.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    /// Lines currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().lines.len()
    }

    /// No lines yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The syslog priority for a level: ERROR 3, WARN 4, INFO 6, DEBUG and TRACE 7.
#[must_use]
pub fn priority(level: Level) -> u8 {
    if level == Level::ERROR {
        3
    } else if level == Level::WARN {
        4
    } else if level == Level::INFO {
        6
    } else {
        7
    }
}

/// `<pri>prefix: message key=value key2=value2`.
#[must_use]
pub fn format_line(level: Level, prefix: &str, message: &str, fields: &[(&str, String)]) -> String {
    let mut line = format!("<{}>{prefix}: {message}", priority(level));
    for (key, value) in fields {
        let _ = write!(line, " {key}={value}");
    }
    line
}

/// Collects an event's `message` and the other fields in declaration order.
#[derive(Default)]
struct Visitor {
    message: String,
    fields: Vec<(&'static str, String)>,
}

impl Visitor {
    fn record(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.fields.push((field.name(), value));
        }
    }
}

impl Visit for Visitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, value.to_owned());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record(field, value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record(field, value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record(field, value.to_string());
    }
}

/// The layer: DEBUG and above into the ring, INFO and above to `kmsg` (or stderr).
struct KmsgLayer {
    prefix: &'static str,
    ring: Arc<Ring>,
    kmsg: Option<Mutex<Box<dyn Write + Send>>>,
}

impl KmsgLayer {
    fn emit(&self, line: &str) {
        let text = if line.len() > KMSG_MAX_LINE {
            let mut end = KMSG_MAX_LINE;
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}…", &line[..end])
        } else {
            line.to_owned()
        };
        match &self.kmsg {
            Some(writer) => {
                let mut writer = writer.lock().unwrap_or_else(PoisonError::into_inner);
                let _ = writeln!(writer, "{text}");
            }
            None => {
                let _ = writeln!(std::io::stderr(), "{text}");
            }
        }
    }
}

impl<S: Subscriber> Layer<S> for KmsgLayer {
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        *metadata.level() <= Level::DEBUG
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = Visitor::default();
        event.record(&mut visitor);
        let level = *event.metadata().level();
        let line = format_line(level, self.prefix, &visitor.message, &visitor.fields);
        if level <= Level::INFO {
            self.emit(&line);
        }
        self.ring.push(line);
    }
}

/// A subscriber writing to `ring` and `kmsg` (stderr when `None`), for `with_default` in tests
/// and [`init`] in the binary.
pub fn subscriber(
    prefix: &'static str,
    ring: Arc<Ring>,
    kmsg: Option<Box<dyn Write + Send>>,
) -> impl Subscriber + Send + Sync {
    tracing_subscriber::registry().with(KmsgLayer {
        prefix,
        ring,
        kmsg: kmsg.map(Mutex::new),
    })
}

/// Install [`subscriber`] as the process-wide default.
///
/// # Errors
///
/// When a global subscriber is already installed.
pub fn init(
    prefix: &'static str,
    ring: Arc<Ring>,
    kmsg: Option<Box<dyn Write + Send>>,
) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    tracing::subscriber::set_global_default(subscriber(prefix, ring, kmsg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing::{Level, debug, info};

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Sink {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn format_line_matches_kmsg_style() {
        assert_eq!(
            format_line(
                Level::INFO,
                "openfeo",
                "renamed",
                &[("port", "p0".to_owned())]
            ),
            "<6>openfeo: renamed port=p0"
        );
        assert_eq!(
            format_line(Level::ERROR, "openfeo", "boom", &[]),
            "<3>openfeo: boom"
        );
        assert_eq!(format_line(Level::WARN, "x", "w", &[]), "<4>x: w");
        assert_eq!(format_line(Level::DEBUG, "x", "d", &[]), "<7>x: d");
        assert_eq!(format_line(Level::TRACE, "x", "t", &[]), "<7>x: t");
    }

    #[test]
    fn ring_evicts_oldest_when_full() {
        let ring = Ring::new(40);
        for i in 0..5 {
            ring.push(format!("line{i}-----")); // 10 bytes each
        }
        let tail = ring.tail(10);
        assert_eq!(tail.len(), 4, "{tail:?}");
        assert_eq!(tail[0], "line1-----");
        assert_eq!(tail[3], "line4-----");
        assert_eq!(ring.bytes(), 40);
        assert_eq!(ring.tail(2), vec!["line3-----", "line4-----"]);
        assert_eq!(DEFAULT_RING_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn layer_routes_info_to_kmsg_and_debug_to_ring_only() {
        let ring = Arc::new(Ring::new(DEFAULT_RING_BYTES));
        let sink = Sink::default();
        let subscriber = subscriber("openfeo", ring.clone(), Some(Box::new(sink.clone())));
        tracing::subscriber::with_default(subscriber, || {
            info!(port = "p0", "renamed");
            debug!(ops = 3, "apply links");
            tracing::warn!("careful");
            tracing::trace!("noise");
        });
        assert_eq!(
            sink.text(),
            "<6>openfeo: renamed port=p0\n<4>openfeo: careful\n"
        );
        assert_eq!(
            ring.tail(10),
            vec![
                "<6>openfeo: renamed port=p0",
                "<7>openfeo: apply links ops=3",
                "<4>openfeo: careful",
            ]
        );
    }
}
