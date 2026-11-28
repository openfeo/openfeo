// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Logging (SPEC §10): `tracing` events become lines, `message key=value`. Each is kept in an
//! in-memory ring (8 MiB by default) with a number that only grows, the time since the kernel
//! booted and its level, and the ring can be read on from a number, read back under a rule, and
//! waited on (SPEC §8.3). The router's own lines are kept from DEBUG up and other crates' from
//! INFO up. INFO and above are also written to `/dev/kmsg` as `<pri>prefix: message key=value`,
//! so the serial console shows them with the kernel's own messages. Priorities follow syslog:
//! ERROR 3, WARN 4, INFO 6, DEBUG 7.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::watch;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};

use crate::clock;

/// Ring capacity unless configured otherwise (SPEC §10).
pub const DEFAULT_RING_BYTES: usize = 8 * 1024 * 1024;
/// Longest line handed to `/dev/kmsg` (the kernel truncates around 1024 bytes).
pub const KMSG_MAX_LINE: usize = 1000;
/// The most text one line holds in the ring; a longer one is cut on a character and ends
/// with `…`.
pub const MAX_LINE: usize = 16 * 1024;
/// The crates whose lines are kept from DEBUG up: the router's own.
const OWN_TARGETS: &str = "openfeo";

/// One line of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Only grows; the first line written is 1.
    pub seq: u64,
    /// Milliseconds since the kernel booted when it was written.
    pub boot_ms: u64,
    /// How serious it is.
    pub level: Level,
    /// `message key=value`: no priority, and not the prefix the console's copy begins with.
    pub text: Arc<str>,
}

/// The rule a reader picks lines by (SPEC §8.3): this level and everything more serious, and
/// this text anywhere in the line without regard to ASCII case. No level and the empty text
/// match every line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// The least serious level wanted.
    pub level: Option<Level>,
    /// Text the line must hold.
    pub contains: String,
}

impl Filter {
    /// Whether a line of `level` saying `text` is wanted.
    #[must_use]
    pub fn matches(&self, level: Level, text: &str) -> bool {
        // `tracing` orders the more serious as the lesser.
        self.level.is_none_or(|wanted| level <= wanted) && holds(text, &self.contains)
    }
}

/// Whether `text` holds `wanted`, letters of ASCII taken without regard to case.
fn holds(text: &str, wanted: &str) -> bool {
    wanted.is_empty()
        || text
            .as_bytes()
            .windows(wanted.len())
            .any(|window| window.eq_ignore_ascii_case(wanted.as_bytes()))
}

/// Lines read back from the ring.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    /// Oldest first.
    pub lines: Vec<Line>,
    /// Older lines that match exist.
    pub earlier: bool,
}

/// A queue of lines bounded by the bytes of their text, oldest evicted first.
#[derive(Debug)]
pub struct Ring {
    inner: Mutex<RingInner>,
    /// The newest line's number: what a waiter is woken by.
    newest: watch::Sender<u64>,
}

#[derive(Debug)]
struct RingInner {
    /// Their numbers have no gaps, so a line is found by its distance from the first.
    lines: VecDeque<Line>,
    bytes: usize,
    capacity: usize,
    /// The number the next line is given.
    next: u64,
}

impl RingInner {
    /// Where the line numbered `seq` is, or would be: 0 for one already dropped, the length for
    /// one not yet written.
    fn index_of(&self, seq: u64) -> usize {
        let first = self.lines.front().map_or(self.next, |line| line.seq);
        usize::try_from(seq.saturating_sub(first))
            .map_or(self.lines.len(), |at| at.min(self.lines.len()))
    }
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
                next: 1,
            }),
            newest: watch::Sender::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, RingInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Append a line, evicting the oldest lines until it fits. The text is kept as one line of
    /// at most [`MAX_LINE`] bytes: see [`kept`].
    pub fn push(&self, level: Level, text: &str) {
        let text: Arc<str> = kept(text).into();
        let seq = {
            let mut ring = self.lock();
            while ring.bytes + text.len() > ring.capacity {
                match ring.lines.pop_front() {
                    Some(old) => ring.bytes -= old.text.len(),
                    None => break,
                }
            }
            ring.bytes += text.len();
            let seq = ring.next;
            ring.next += 1;
            // The clock is read with the lock held, so that times rise with the numbers.
            ring.lines.push_back(Line {
                seq,
                boot_ms: clock::boot_ms(),
                level,
                text,
            });
            seq
        };
        // The lock is released before anyone is woken, and two writers cannot take the
        // number backwards.
        self.newest.send_if_modified(|newest| {
            let grew = seq > *newest;
            if grew {
                *newest = seq;
            }
            grew
        });
    }

    /// The number of the newest line written; 0 while none was.
    #[must_use]
    pub fn newest(&self) -> u64 {
        self.lock().next - 1
    }

    /// The newest line's number, as it grows: something to wait on for the next line.
    #[must_use]
    pub fn follow(&self) -> watch::Receiver<u64> {
        self.newest.subscribe()
    }

    /// The lines after the one numbered `seq`, oldest first: at most `lines` of them and
    /// `bytes` of text, and always one when there is one. A number the ring no longer holds
    /// reads on from the oldest line it does, and the reader sees the gap in the numbers.
    #[must_use]
    pub fn after(&self, seq: u64, lines: usize, bytes: usize) -> Vec<Line> {
        let ring = self.lock();
        let mut read = Vec::new();
        let mut size = 0usize;
        for line in ring
            .lines
            .range(ring.index_of(seq.saturating_add(1))..)
            .take(lines)
        {
            if !read.is_empty() && size.saturating_add(line.text.len()) > bytes {
                break;
            }
            size = size.saturating_add(line.text.len());
            read.push(line.clone());
        }
        read
    }

    /// The newest lines that match `filter` and were written before the one numbered `before`
    /// (0: before nothing), within the same two bounds as [`Ring::after`], oldest first.
    #[must_use]
    pub fn page(&self, filter: &Filter, before: u64, lines: usize, bytes: usize) -> Page {
        let ring = self.lock();
        let end = if before == 0 {
            ring.lines.len()
        } else {
            ring.index_of(before)
        };
        let mut page = Page::default();
        let mut size = 0usize;
        for line in ring.lines.range(..end).rev() {
            if !filter.matches(line.level, &line.text) {
                continue;
            }
            let full = page.lines.len() >= lines
                || (!page.lines.is_empty() && size.saturating_add(line.text.len()) > bytes);
            if full {
                page.earlier = true;
                break;
            }
            size = size.saturating_add(line.text.len());
            page.lines.push(line.clone());
        }
        page.lines.reverse();
        page
    }

    /// The texts of the last `n` lines, oldest first.
    #[must_use]
    pub fn tail(&self, n: usize) -> Vec<String> {
        let ring = self.lock();
        let skip = ring.lines.len().saturating_sub(n);
        ring.lines
            .range(skip..)
            .map(|line| line.text.to_string())
            .collect()
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

/// A line's text as the ring keeps it: one line, whatever a name taken from the network had in
/// it. A control character or a line separator is written as its escape (`\n`, `\u{1b}`), and
/// text beyond [`MAX_LINE`] bytes is cut on a character and said to be with `…`.
fn kept(text: &str) -> String {
    let mut kept = String::with_capacity(text.len().min(MAX_LINE));
    for c in text.chars() {
        let escaped = c.is_control() || matches!(c, '\u{2028}' | '\u{2029}');
        let size = if escaped {
            c.escape_default().len()
        } else {
            c.len_utf8()
        };
        if kept.len() + size > MAX_LINE {
            kept.push('…');
            break;
        }
        if escaped {
            kept.extend(c.escape_default());
        } else {
            kept.push(c);
        }
    }
    kept
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

/// `message key=value key2=value2`: a line's text.
fn text_of(message: &str, fields: &[(&str, String)]) -> String {
    let mut text = message.to_owned();
    for (key, value) in fields {
        let _ = write!(text, " {key}={value}");
    }
    text
}

/// `<pri>prefix: message key=value key2=value2`: a line as the console has it.
#[must_use]
pub fn format_line(level: Level, prefix: &str, message: &str, fields: &[(&str, String)]) -> String {
    format!(
        "<{}>{prefix}: {}",
        priority(level),
        text_of(message, fields)
    )
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

/// The layer: lines into the ring, INFO and above to `kmsg` (or stderr) as well.
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
                let _ = writer.write_all(format!("{text}\n").as_bytes());
            }
            None => {
                let _ = std::io::stderr().write_all(format!("{text}\n").as_bytes());
            }
        }
    }
}

impl<S: Subscriber> Layer<S> for KmsgLayer {
    /// The router's own lines from DEBUG up, any other crate's from INFO up: a library that
    /// writes a DEBUG line for every frame it sends would fill the ring with them, and a log
    /// sent over that library would feed itself (SPEC §8.3).
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        let level = *metadata.level();
        level <= Level::INFO
            || (level <= Level::DEBUG && metadata.target().starts_with(OWN_TARGETS))
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = Visitor::default();
        event.record(&mut visitor);
        let level = *event.metadata().level();
        if level <= Level::INFO {
            self.emit(&format_line(
                level,
                self.prefix,
                &visitor.message,
                &visitor.fields,
            ));
        }
        self.ring
            .push(level, &text_of(&visitor.message, &visitor.fields));
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

    /// A ring that keeps everything, and what the layer wrote to the console.
    fn logged(run: impl FnOnce()) -> (Arc<Ring>, String) {
        let ring = Arc::new(Ring::new(DEFAULT_RING_BYTES));
        let sink = Sink::default();
        let subscriber = subscriber("openfeo", ring.clone(), Some(Box::new(sink.clone())));
        tracing::subscriber::with_default(subscriber, run);
        (ring, sink.text())
    }

    fn numbers(lines: &[Line]) -> Vec<u64> {
        lines.iter().map(|line| line.seq).collect()
    }

    fn texts(lines: &[Line]) -> Vec<&str> {
        lines.iter().map(|line| &*line.text).collect()
    }

    fn level(word: &str) -> Option<Level> {
        match word {
            "" => None,
            "error" => Some(Level::ERROR),
            "warn" => Some(Level::WARN),
            "info" => Some(Level::INFO),
            "debug" => Some(Level::DEBUG),
            other => panic!("no such level in the cases: {other}"),
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
            ring.push(Level::INFO, &format!("line{i}-----")); // 10 bytes each
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
        let (ring, console) = logged(|| {
            info!(port = "p0", "renamed");
            debug!(ops = 3, "apply links");
            tracing::warn!("careful");
            tracing::trace!("noise");
        });
        assert_eq!(
            console,
            "<6>openfeo: renamed port=p0\n<4>openfeo: careful\n"
        );
        assert_eq!(
            ring.tail(10),
            vec!["renamed port=p0", "apply links ops=3", "careful"]
        );
    }

    #[test]
    fn numbers_only_grow_and_start_at_one() {
        let ring = Ring::new(DEFAULT_RING_BYTES);
        assert_eq!(ring.newest(), 0);
        for text in ["a", "b", "c"] {
            ring.push(Level::INFO, text);
        }
        assert_eq!(numbers(&ring.after(0, 99, usize::MAX)), vec![1, 2, 3]);
        // A ring that has dropped its oldest goes on counting from where it was.
        let small = Ring::new(64);
        for _ in 0..10 {
            small.push(Level::INFO, &"x".repeat(30));
        }
        assert_eq!(small.newest(), 10);
        assert_eq!(numbers(&small.after(0, 99, usize::MAX)), vec![9, 10]);
    }

    #[tokio::test]
    async fn a_waiter_is_woken_by_the_next_line() {
        let ring = Ring::new(DEFAULT_RING_BYTES);
        let mut seen = ring.follow();
        assert_eq!(*seen.borrow_and_update(), 0);
        ring.push(Level::INFO, "a line");
        tokio::time::timeout(std::time::Duration::from_secs(1), seen.changed())
            .await
            .expect("the waiter was not woken")
            .unwrap();
        assert_eq!(*seen.borrow(), 1);
    }

    #[test]
    fn a_line_carries_its_level_and_the_time_since_boot() {
        let ring = Ring::new(DEFAULT_RING_BYTES);
        ring.push(Level::INFO, "first");
        ring.push(Level::DEBUG, "second");
        let lines = ring.after(0, 99, usize::MAX);
        assert_eq!(
            lines.iter().map(|line| line.level).collect::<Vec<_>>(),
            vec![Level::INFO, Level::DEBUG]
        );
        assert!(lines[1].boot_ms >= lines[0].boot_ms, "{lines:?}");
    }

    #[test]
    fn the_ring_keeps_the_text_and_the_console_the_whole_line() {
        let (ring, console) = logged(|| info!(mtu = 1500, "link up"));
        assert_eq!(ring.tail(1), vec!["link up mtu=1500"]);
        assert_eq!(console, "<6>openfeo: link up mtu=1500\n");
    }

    #[test]
    fn reading_on_from_a_number_has_no_gap_and_no_repeat() {
        let ring = Ring::new(40);
        for i in 1..=4 {
            ring.push(Level::INFO, &format!("line-{i:05}")); // 10 bytes each
        }
        assert_eq!(numbers(&ring.after(1, 2, usize::MAX)), vec![2, 3]);
        assert_eq!(numbers(&ring.after(3, 99, usize::MAX)), vec![4]);
        assert_eq!(ring.after(4, 99, usize::MAX), Vec::new());
        assert_eq!(ring.after(99, 99, usize::MAX), Vec::new());
        // Six more push the first six out: a reader that was at 2 reads on from the oldest held.
        for i in 5..=10 {
            ring.push(Level::INFO, &format!("line-{i:05}"));
        }
        assert_eq!(numbers(&ring.after(2, 99, usize::MAX)), vec![7, 8, 9, 10]);
        assert_eq!(numbers(&ring.after(7, 3, usize::MAX)), vec![8, 9, 10]);
    }

    #[test]
    fn reading_on_stops_at_its_bytes_and_still_gives_a_line() {
        let ring = Ring::new(DEFAULT_RING_BYTES);
        for _ in 0..5 {
            ring.push(Level::INFO, &"x".repeat(100));
        }
        assert_eq!(ring.after(0, 99, 250).len(), 2);
        assert_eq!(ring.after(0, 99, 10).len(), 1);
        assert_eq!(ring.after(5, 99, 10), Vec::new());
    }

    #[test]
    fn a_page_is_the_newest_that_match_oldest_first() {
        let ring = Ring::new(DEFAULT_RING_BYTES);
        for (level, text) in [
            (Level::INFO, "a"),
            (Level::WARN, "b"),
            (Level::DEBUG, "c"),
            (Level::ERROR, "d"),
            (Level::INFO, "e"),
            (Level::WARN, "f"),
        ] {
            ring.push(level, text);
        }
        let serious = Filter {
            level: Some(Level::WARN),
            contains: String::new(),
        };
        let newest = ring.page(&serious, 0, 2, usize::MAX);
        assert_eq!(texts(&newest.lines), vec!["d", "f"]);
        assert!(newest.earlier);
        let before = ring.page(&serious, newest.lines[0].seq, 2, usize::MAX);
        assert_eq!(texts(&before.lines), vec!["b"]);
        assert!(!before.earlier);
        // Every line, four at a time, each page before the first of the one that came before.
        let every = Filter::default();
        let last = ring.page(&every, 0, 4, usize::MAX);
        let first = ring.page(&every, last.lines[0].seq, 4, usize::MAX);
        assert!(last.earlier && !first.earlier);
        let all: Vec<&str> = texts(&first.lines)
            .into_iter()
            .chain(texts(&last.lines))
            .collect();
        assert_eq!(all, vec!["a", "b", "c", "d", "e", "f"]);
        // The bytes bound a page as the lines do, and a page always holds a line.
        let tight = ring.page(&every, 0, 99, 2);
        assert_eq!(texts(&tight.lines), vec!["e", "f"]);
        assert!(tight.earlier);
        assert_eq!(texts(&ring.page(&every, 0, 99, 0).lines), vec!["f"]);
        // Nothing before the first line, and nothing in an empty ring.
        assert_eq!(ring.page(&every, 1, 4, usize::MAX), Page::default());
        assert_eq!(
            Ring::new(64).page(&every, 0, 4, usize::MAX),
            Page::default()
        );
    }

    #[test]
    fn the_rule_is_held_to_the_shared_cases() {
        let cases: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../web/client/test/log-rule.cases.json"
        )))
        .unwrap();
        let cases = cases.as_array().unwrap();
        assert!(cases.len() >= 13);
        for case in cases {
            let word = |key: &str| case[key].as_str().unwrap();
            let filter = Filter {
                level: level(word("wanted")),
                contains: word("contains").to_owned(),
            };
            assert_eq!(
                filter.matches(level(word("level")).unwrap(), word("text")),
                case["matches"].as_bool().unwrap(),
                "{case}"
            );
        }
    }

    #[test]
    fn a_line_is_cut_at_its_limit_and_keeps_to_one_line() {
        let ring = Ring::new(DEFAULT_RING_BYTES);
        // Two bytes a character, and an odd byte before them, so the limit falls inside one.
        ring.push(Level::INFO, &format!("x{}", "ü".repeat(10 * 1024)));
        ring.push(Level::INFO, "a\nb\u{1b}[31m\r\u{2028}");
        ring.push(Level::INFO, "leased to Küche");
        let kept = ring.tail(3);
        assert!(kept[0].ends_with('…'), "the cut is not said");
        let text = kept[0].trim_end_matches('…');
        assert!(
            text.len() <= MAX_LINE && text.len() > MAX_LINE - 2,
            "{}",
            text.len()
        );
        assert!(text[1..].chars().all(|c| c == 'ü'));
        assert_eq!(kept[1], "a\\nb\\u{1b}[31m\\r\\u{2028}");
        assert_eq!(kept[2], "leased to Küche");
        assert_eq!(MAX_LINE, 16 * 1024);
    }

    #[test]
    fn another_crates_line_below_info_is_not_kept() {
        let (ring, console) = logged(|| {
            debug!(target: "h2::codec::framed_write", "send");
            info!(target: "h2::codec::framed_write", "said aloud");
            debug!(target: "openfeo_api::ws", "ours");
        });
        assert_eq!(ring.tail(10), vec!["said aloud", "ours"]);
        assert_eq!(console, "<6>openfeo: said aloud\n");
    }
}
