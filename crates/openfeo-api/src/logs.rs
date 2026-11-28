// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The router's log on the wire (SPEC §8.3, §10): a line as a message, the levels by their
//! names, and what one answer may hold.

use openfeo_config::api::{LogLevel, LogLine};
use openfeo_runtime::log::Line;
use tracing::Level;

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
    use openfeo_config::api::{
        Error, ErrorCode, LogLevel, LogLine, LogsRequest, LogsResponse, request, response,
        server_msg,
    };
    use tracing::Level;

    use crate::limits::{MAX_LOG_BYTES, MAX_LOG_CONTAINS, MAX_LOG_LINES};
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
}
