// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The router's log on the wire (SPEC §8.3, §10): a line as a message, the levels by their
//! names, and one reader's place in the log as it is written.

use std::sync::Arc;

use openfeo_config::api::{LogLevel, LogLine};
use openfeo_runtime::log::{Line, Ring};
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::Level;

use crate::limits::{LOG_BATCH, LOG_PACE, LOG_QUEUE, MAX_LOG_BYTES};

/// One reader's place in the log, for the topic `logs`. It holds no lines: the ring is the
/// queue, so a slow reader costs nothing but its place, and one that falls more than
/// [`LOG_QUEUE`] lines behind is moved up to there and told.
///
/// Nothing here writes a log line, at any level: a line written for every batch sent would be
/// a batch to send.
#[derive(Debug)]
pub struct LogFeed {
    ring: Arc<Ring>,
    /// Woken when a line is written. The ring says which; this only says when to look.
    written: watch::Receiver<u64>,
    /// The number of the last line given.
    last: u64,
    /// When the last batch was given.
    left: Option<Instant>,
}

/// Lines for one reader of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    /// Oldest first; never empty.
    pub lines: Vec<Line>,
    /// Lines were skipped before these: the reader fell behind.
    pub lost: bool,
}

impl LogFeed {
    /// A reader of every line written from now on.
    #[must_use]
    pub fn from_now(ring: &Arc<Ring>) -> Self {
        // Listening before looking: a line written between the two is after `last`, and at
        // worst wakes the reader once for nothing.
        let written = ring.follow();
        LogFeed {
            ring: ring.clone(),
            written,
            last: ring.newest(),
            left: None,
        }
    }

    /// The next lines: once some were written, and no sooner than [`LOG_PACE`] after the last
    /// batch. Cancel-safe: the reader's place moves only as this returns, so a wait that is
    /// dropped loses nothing.
    pub async fn next(&mut self) -> Batch {
        loop {
            while self.ring.newest() <= self.last {
                if self.written.changed().await.is_err() {
                    // The ring is gone, and with it anything to read.
                    std::future::pending::<()>().await;
                }
            }
            if let Some(left) = self.left {
                tokio::time::sleep_until(left + LOG_PACE).await;
            }
            let newest = self.ring.newest();
            let behind = newest.saturating_sub(self.last) > LOG_QUEUE;
            let from = if behind {
                newest - LOG_QUEUE
            } else {
                self.last
            };
            let lines = self.ring.after(from, LOG_BATCH, MAX_LOG_BYTES);
            let (Some(oldest), Some(youngest)) = (lines.first(), lines.last()) else {
                // The ring holds nothing after all (one that keeps no line): nothing to give.
                self.last = newest;
                continue;
            };
            // The ring itself may have dropped what this reader had not yet been given.
            let lost = behind || oldest.seq != from + 1;
            self.last = youngest.seq;
            self.left = Some(Instant::now());
            return Batch { lines, lost };
        }
    }
}

/// A request named a level by a number that is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no such level")]
pub struct NoSuchLevel;

/// The level a request names: `None` when it names none, which is every line.
///
/// # Errors
///
/// When the number is not a level this router knows: a caller built against a later schema
/// is told so, and is not answered as if it had asked for everything.
pub fn level_of(wire: i32) -> Result<Option<Level>, NoSuchLevel> {
    match LogLevel::try_from(wire) {
        Ok(LogLevel::Unspecified) => Ok(None),
        Ok(LogLevel::Error) => Ok(Some(Level::ERROR)),
        Ok(LogLevel::Warn) => Ok(Some(Level::WARN)),
        Ok(LogLevel::Info) => Ok(Some(Level::INFO)),
        Ok(LogLevel::Debug) => Ok(Some(Level::DEBUG)),
        Err(_) => Err(NoSuchLevel),
    }
}

/// A line of the ring as the wire says it.
#[must_use]
pub fn to_pb(line: &Line) -> LogLine {
    let level = if line.level == Level::ERROR {
        LogLevel::Error
    } else if line.level == Level::WARN {
        LogLevel::Warn
    } else if line.level == Level::INFO {
        LogLevel::Info
    } else {
        LogLevel::Debug
    };
    LogLine {
        seq: line.seq,
        uptime_ms: line.boot_ms,
        level: level.into(),
        text: line.text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use openfeo_config::api::{
        Error, ErrorCode, LogBatch, LogLevel, LogLine, LogsRequest, LogsResponse, SubscribeRequest,
        request, response, server_msg, subscribe_response,
    };
    use openfeo_runtime::log::{DEFAULT_RING_BYTES, Ring};
    use tracing::{Level, info};

    use super::{Batch, LogFeed};

    use crate::limits::{
        LOG_BATCH, LOG_PACE, LOG_QUEUE, MAX_LOG_BYTES, MAX_LOG_CONTAINS, MAX_LOG_LINES,
    };
    use crate::pb::state_service_client::StateServiceClient;
    use crate::pb::system_service_client::SystemServiceClient;
    use crate::server::tests::PASSWORD;
    use crate::testing::{TestApi, Ws, with_token};

    async fn logs(ws: &mut Ws, ask: LogsRequest) -> Result<LogsResponse, Error> {
        match ws.ask(request::Body::Logs(ask)).await {
            server_msg::Body::Response(reply) => match reply.body {
                Some(response::Body::Logs(answer)) => Ok(answer),
                other => panic!("not the answer to Logs: {other:?}"),
            },
            server_msg::Body::Error(error) => Err(error),
            other => panic!("neither an answer nor an error: {other:?}"),
        }
    }

    fn texts(lines: &[LogLine]) -> Vec<&str> {
        lines.iter().map(|line| line.text.as_str()).collect()
    }

    fn numbers(lines: &[LogLine]) -> Vec<u64> {
        lines.iter().map(|line| line.seq).collect()
    }

    /// SPEC §8.3 (M4 part 3c): a level is itself and everything more serious, and the answer
    /// carries the router's two clocks, so a reader can say when each line was written.
    #[tokio::test]
    async fn logs_answers_the_newest_that_match_with_the_two_clocks() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        api.log.push(Level::INFO, "link p0 up");
        api.log.push(Level::WARN, "pppoe wan0: 3 echoes unanswered");
        api.log.push(Level::DEBUG, "apply links ops=3");
        let ask = LogsRequest {
            level: LogLevel::Info.into(),
            ..LogsRequest::default()
        };
        let mut ws = api.ws_with(&token).await;
        let answer = logs(&mut ws, ask.clone()).await.unwrap();
        assert_eq!(
            answer
                .lines
                .iter()
                .map(|line| (line.seq, line.level(), line.text.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (1, LogLevel::Info, "link p0 up"),
                (2, LogLevel::Warn, "pppoe wan0: 3 echoes unanswered"),
            ]
        );
        assert!(!answer.earlier);
        assert!(
            answer.uptime_ms >= answer.lines[1].uptime_ms && answer.lines[1].uptime_ms > 0,
            "{answer:?}"
        );
        assert!(answer.time_unix_ms > 1_700_000_000_000, "{answer:?}");
        // Every line, and the same over gRPC.
        let all = logs(&mut ws, LogsRequest::default()).await.unwrap();
        assert_eq!(all.lines.len(), 3);
        assert_eq!(all.lines[2].level(), LogLevel::Debug);
        let mut system = SystemServiceClient::new(api.channel().await);
        let over_grpc = system
            .logs(with_token(ask, &token))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(over_grpc.lines, answer.lines);
    }

    #[tokio::test]
    async fn logs_filters_by_text_whatever_its_case() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        api.log.push(Level::INFO, "link p0 down");
        api.log.push(Level::INFO, "link p1 up");
        let mut ws = api.ws_with(&token).await;
        let answer = logs(
            &mut ws,
            LogsRequest {
                contains: "P0 DOWN".to_owned(),
                ..LogsRequest::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(texts(&answer.lines), vec!["link p0 down"]);
    }

    /// A caller reaches back by the number of the oldest line it has.
    #[tokio::test]
    async fn logs_reaches_back_without_a_gap_or_a_repeat() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        for n in 1..=30 {
            api.log.push(Level::INFO, &format!("line {n}"));
        }
        let mut ws = api.ws_with(&token).await;
        let mut read: Vec<u64> = Vec::new();
        let mut before_seq = 0;
        loop {
            let answer = logs(
                &mut ws,
                LogsRequest {
                    before_seq,
                    limit: 7,
                    ..LogsRequest::default()
                },
            )
            .await
            .unwrap();
            assert!(answer.lines.len() <= 7);
            before_seq = answer.lines[0].seq;
            read.splice(0..0, numbers(&answer.lines));
            assert_eq!(answer.earlier, before_seq > 1, "at {before_seq}");
            if !answer.earlier {
                break;
            }
        }
        assert_eq!(read, (1..=30).collect::<Vec<u64>>());
    }

    #[tokio::test]
    async fn logs_answers_at_most_a_thousand_lines() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        for n in 1..=1500 {
            api.log.push(Level::INFO, &format!("line {n}"));
        }
        let mut ws = api.ws_with(&token).await;
        for limit in [0, 5000] {
            let answer = logs(
                &mut ws,
                LogsRequest {
                    limit,
                    ..LogsRequest::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(answer.lines.len(), MAX_LOG_LINES, "limit {limit}");
            assert_eq!(answer.lines[0].seq, 501);
            assert_eq!(answer.lines[999].seq, 1500);
            assert!(answer.earlier);
        }
        assert_eq!(MAX_LOG_LINES, 1000);
    }

    /// An answer fits a frame whatever the lines are.
    #[tokio::test]
    async fn logs_answers_at_most_its_bytes() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let long = "x".repeat(16 * 1024);
        for _ in 0..100 {
            api.log.push(Level::INFO, &long);
        }
        let mut ws = api.ws_with(&token).await;
        let answer = logs(&mut ws, LogsRequest::default()).await.unwrap();
        let bytes: usize = answer.lines.iter().map(|line| line.text.len()).sum();
        assert!(bytes <= MAX_LOG_BYTES, "{bytes}");
        assert_eq!(answer.lines.len(), 32);
        assert_eq!(
            answer.lines[31].seq, 100,
            "the newest are the ones answered"
        );
        assert!(answer.earlier);
        assert_eq!(MAX_LOG_BYTES, 512 * 1024);
    }

    #[tokio::test]
    async fn logs_refuses_a_level_that_is_none() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        api.log.push(Level::INFO, "a line");
        let mut ws = api.ws_with(&token).await;
        let refused = logs(
            &mut ws,
            LogsRequest {
                level: 9,
                ..LogsRequest::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);
        assert_eq!(refused.message, "no such level");
    }

    /// The text is looked for in every line with the ring held: it is kept short.
    #[tokio::test]
    async fn logs_refuses_a_text_longer_than_its_limit() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        api.log.push(Level::INFO, &"a".repeat(1024));
        let mut ws = api.ws_with(&token).await;
        let ask = |contains: String| LogsRequest {
            contains,
            ..LogsRequest::default()
        };
        let at_the_limit = logs(&mut ws, ask("a".repeat(MAX_LOG_CONTAINS)))
            .await
            .unwrap();
        assert_eq!(at_the_limit.lines.len(), 1);
        let refused = logs(&mut ws, ask("a".repeat(MAX_LOG_CONTAINS + 1)))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            refused.message,
            "the text to look for is longer than 256 bytes"
        );
        assert_eq!(MAX_LOG_CONTAINS, 256);
    }

    #[tokio::test]
    async fn logs_needs_a_session() {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        api.log.push(Level::INFO, "a line");
        let mut system = SystemServiceClient::new(api.channel().await);
        let refused = system
            .logs(with_token(LogsRequest::default(), ""))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Unauthenticated);
        let answer = system
            .logs(with_token(LogsRequest::default(), &token))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(texts(&answer.lines), vec!["a line"]);
    }

    fn ring_of(lines: u64) -> Arc<Ring> {
        let ring = Arc::new(Ring::new(DEFAULT_RING_BYTES));
        write(&ring, lines);
        ring
    }

    fn write(ring: &Ring, lines: u64) {
        for _ in 0..lines {
            ring.push(Level::INFO, "a line");
        }
    }

    fn seqs(batch: &Batch) -> Vec<u64> {
        batch.lines.iter().map(|line| line.seq).collect()
    }

    /// SPEC §8.3 (M4 part 3c): every line written after the subscription, and none from before.
    #[tokio::test(start_paused = true)]
    async fn a_feed_begins_after_what_was_already_written() {
        let ring = ring_of(3);
        let mut feed = LogFeed::from_now(&ring);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), feed.next())
                .await
                .is_err(),
            "there is nothing to give yet"
        );
        write(&ring, 1);
        let batch = feed.next().await;
        assert_eq!((seqs(&batch), batch.lost), (vec![4], false));
    }

    #[tokio::test(start_paused = true)]
    async fn lines_written_between_two_reads_come_once_and_in_order() {
        let ring = ring_of(0);
        let mut feed = LogFeed::from_now(&ring);
        write(&ring, 3);
        assert_eq!(seqs(&feed.next().await), vec![1, 2, 3]);
        write(&ring, 2);
        let batch = feed.next().await;
        assert_eq!((seqs(&batch), batch.lost), (vec![4, 5], false));
    }

    #[tokio::test(start_paused = true)]
    async fn a_batch_holds_at_most_256_lines() {
        let ring = ring_of(0);
        let mut feed = LogFeed::from_now(&ring);
        write(&ring, 600);
        let mut sizes = Vec::new();
        for _ in 0..3 {
            let batch = feed.next().await;
            assert!(!batch.lost);
            sizes.push(batch.lines.len());
        }
        assert_eq!(sizes, vec![LOG_BATCH, LOG_BATCH, 88]);
        assert_eq!(LOG_BATCH, 256);
        // And at most its bytes, whatever the lines are.
        let long = "x".repeat(16 * 1024);
        for _ in 0..40 {
            ring.push(Level::INFO, &long);
        }
        let batch = feed.next().await;
        assert_eq!(batch.lines.len(), 32);
    }

    /// The log's queue is the ring itself: a reader 1024 lines behind is as far behind as one
    /// may be, and is told when it is moved up.
    #[tokio::test(start_paused = true)]
    async fn a_reader_too_far_behind_is_moved_up_and_told() {
        let ring = ring_of(0);
        let mut feed = LogFeed::from_now(&ring);
        write(&ring, 1524);
        let first = feed.next().await;
        assert!(first.lost);
        assert_eq!(first.lines[0].seq, 1524 - 1023);
        let mut last = first.lines[first.lines.len() - 1].seq;
        while last < 1524 {
            let batch = feed.next().await;
            assert!(!batch.lost, "told once");
            assert_eq!(batch.lines[0].seq, last + 1, "no gap after the move");
            last = batch.lines[batch.lines.len() - 1].seq;
        }
        assert_eq!(LOG_QUEUE, 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn a_ring_that_dropped_what_was_not_read_is_a_loss_too() {
        // Ten lines of ten bytes are all it holds.
        let ring = Arc::new(Ring::new(100));
        let mut feed = LogFeed::from_now(&ring);
        for n in 1..=25 {
            ring.push(Level::INFO, &format!("line-{n:05}"));
        }
        let batch = feed.next().await;
        assert!(batch.lost);
        assert_eq!(seqs(&batch), (16..=25).collect::<Vec<u64>>());
    }

    #[tokio::test(start_paused = true)]
    async fn batches_leave_at_most_ten_a_second() {
        let ring = ring_of(0);
        let mut feed = LogFeed::from_now(&ring);
        write(&ring, 1);
        let started = tokio::time::Instant::now();
        feed.next().await;
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "the first leaves at once"
        );
        tokio::time::advance(Duration::from_millis(10)).await;
        write(&ring, 1);
        feed.next().await;
        assert_eq!(started.elapsed(), LOG_PACE, "the next, a pace after it");
        // A line written long after the last batch does not wait.
        tokio::time::advance(Duration::from_secs(1)).await;
        write(&ring, 1);
        let before = tokio::time::Instant::now();
        feed.next().await;
        assert_eq!(before.elapsed(), Duration::ZERO);
        assert_eq!(LOG_PACE, Duration::from_millis(100));
    }

    /// The driver waits for the log among other things, and drops the wait when one of them
    /// happens first.
    #[tokio::test(start_paused = true)]
    async fn a_wait_that_is_dropped_loses_no_line() {
        let ring = ring_of(0);
        let mut feed = LogFeed::from_now(&ring);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), feed.next())
                .await
                .is_err()
        );
        write(&ring, 1);
        assert_eq!(seqs(&feed.next().await), vec![1]);
        // Dropped while it waits out the pace, with a line in hand.
        write(&ring, 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), feed.next())
                .await
                .is_err()
        );
        write(&ring, 1);
        assert_eq!(seqs(&feed.next().await), vec![2, 3]);
    }

    /// The API with its log behind a subscriber of this thread: whatever the server writes
    /// while it serves lands in the ring the test reads.
    async fn logged() -> (TestApi, String, tracing::subscriber::DefaultGuard) {
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let guard = tracing::subscriber::set_default(openfeo_runtime::log::subscriber(
            "openfeo",
            api.log.clone(),
            Some(Box::new(std::io::sink())),
        ));
        (api, token, guard)
    }

    async fn pushed(ws: &mut Ws) -> LogBatch {
        loop {
            if let Some(server_msg::Body::Logs(batch)) = ws.msg().await.body {
                return batch;
            }
        }
    }

    #[tokio::test]
    async fn a_subscriber_is_sent_what_is_written_after_it_subscribed() {
        let (api, token, _guard) = logged().await;
        let mut ws = api.ws_with(&token).await;
        info!("written before");
        let before = api.log.newest();
        ws.subscribe("logs", 0).await;
        info!(port = "p0", "link down");
        let batch = pushed(&mut ws).await;
        assert_eq!(
            batch
                .lines
                .iter()
                .map(|line| (line.seq, line.level(), line.text.as_str()))
                .collect::<Vec<_>>(),
            vec![(before + 1, LogLevel::Info, "link down port=p0")]
        );
        assert!(
            batch.uptime_ms >= batch.lines[0].uptime_ms && batch.time_unix_ms > 1_700_000_000_000,
            "{batch:?}"
        );
    }

    /// SPEC §8.3 (M4 part 3c), the design's anti-goal: a log feed that feeds itself.
    #[tokio::test]
    async fn sending_the_log_writes_no_line() {
        let (api, token, _guard) = logged().await;
        let mut ws = api.ws_with(&token).await;
        ws.subscribe("logs", 0).await;
        info!("one line");
        let batch = pushed(&mut ws).await;
        let sent = batch.lines[batch.lines.len() - 1].seq;
        assert_eq!(batch.lines[batch.lines.len() - 1].text, "one line");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            api.log.newest(),
            sent,
            "sending wrote: {:?}",
            api.log.tail(8)
        );
    }

    #[tokio::test]
    async fn sending_the_log_over_grpc_writes_no_line() {
        use futures::StreamExt as _;
        let (api, token, _guard) = logged().await;
        let mut state = StateServiceClient::new(api.channel().await);
        let mut stream = state
            .subscribe(with_token(
                SubscribeRequest {
                    topics: vec!["logs".to_owned()],
                    backlog: 0,
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        // The stream is open; its feed takes its place in the log a moment after.
        tokio::time::sleep(Duration::from_millis(200)).await;
        info!("one line");
        let first = stream.next().await.unwrap().unwrap();
        let Some(subscribe_response::Body::Logs(batch)) = first.body else {
            panic!("not a batch of the log: {first:?}");
        };
        let sent = batch.lines[batch.lines.len() - 1].seq;
        assert_eq!(batch.lines[batch.lines.len() - 1].text, "one line");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            api.log.newest(),
            sent,
            "sending wrote: {:?}",
            api.log.tail(8)
        );
    }

    /// As for events: word of a loss ends a gRPC stream, and its caller subscribes again.
    #[tokio::test]
    async fn a_grpc_stream_that_fell_behind_ends_with_data_loss() {
        use futures::StreamExt as _;
        let (api, token) = TestApi::with_password(PASSWORD).await;
        let mut state = StateServiceClient::new(api.channel().await);
        let mut stream = state
            .subscribe(with_token(
                SubscribeRequest {
                    topics: vec!["logs".to_owned()],
                    backlog: 0,
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        tokio::time::sleep(Duration::from_millis(200)).await;
        write(&api.log, 1);
        assert!(stream.next().await.unwrap().is_ok());
        write(&api.log, 2000);
        let ended = loop {
            match stream.next().await {
                Some(Ok(_)) => {}
                Some(Err(status)) => break status,
                None => panic!("the stream ended without saying why"),
            }
        };
        assert_eq!(ended.code(), tonic::Code::DataLoss);
        assert_eq!(
            ended.message(),
            "log lines were dropped: this reader fell behind"
        );
        assert!(stream.next().await.is_none(), "and it is over");
    }
}
