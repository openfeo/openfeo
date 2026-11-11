// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A connection that is watched for silence (SPEC §9): its first bytes must arrive in good
//! time, and after that it may not go quiet for longer than the idle limit. A client that
//! finishes its TLS handshake and then says nothing, or stops part-way through a request,
//! is dropped and its place given back. Long-lived connections are kept talking by the
//! WebSocket's pings and HTTP/2's keep-alive.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// `inner`, read from under a deadline that each arrival of bytes pushes back. It carries
/// `held`, whatever the connection holds for as long as it exists (its place among the
/// connections allowed): the I/O outlives the task that accepted it when a request upgrades
/// to a WebSocket, so what is held must travel with the I/O.
pub struct Watched<T, H> {
    inner: T,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
    _held: H,
}

impl<T, H> Watched<T, H> {
    /// Watch `inner`: its first bytes within `first`, and never silent for `idle` after.
    pub fn new(inner: T, first: Duration, idle: Duration, held: H) -> Self {
        Watched {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(first)),
            _held: held,
        }
    }
}

impl<T: AsyncRead + Unpin, H: Unpin> AsyncRead for Watched<T, H> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if result.is_ok() && buf.filled().len() > before {
                    let next = Instant::now() + self.idle;
                    self.deadline.as_mut().reset(next);
                }
                Poll::Ready(result)
            }
            Poll::Pending => match self.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the client went quiet",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<T: AsyncWrite + Unpin, H: Unpin> AsyncWrite for Watched<T, H> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn what_a_connection_holds_is_given_back_when_its_io_is_dropped() {
        let held = std::sync::Arc::new(());
        let (_client, server) = tokio::io::duplex(64);
        let watched = Watched::new(
            server,
            Duration::from_secs(10),
            Duration::from_secs(60),
            held.clone(),
        );
        assert_eq!(std::sync::Arc::strong_count(&held), 2);
        // As when a request upgrades: the I/O moves to another task and lives on there.
        let elsewhere = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(watched);
        });
        assert_eq!(
            std::sync::Arc::strong_count(&held),
            2,
            "still held while the I/O lives"
        );
        elsewhere.await.unwrap();
        assert_eq!(std::sync::Arc::strong_count(&held), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn silence_before_the_first_byte_and_silence_later_both_end_the_read() {
        let (client, server) = tokio::io::duplex(64);
        let mut watched =
            Watched::new(server, Duration::from_secs(10), Duration::from_secs(60), ());
        let started = Instant::now();
        let mut byte = [0u8; 1];
        let err = watched.read(&mut byte).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(10),
            "nothing at all: the first limit"
        );
        drop(client);

        let (mut client, server) = tokio::io::duplex(64);
        let mut watched =
            Watched::new(server, Duration::from_secs(10), Duration::from_secs(60), ());
        client.write_all(b"a").await.unwrap();
        assert_eq!(watched.read(&mut byte).await.unwrap(), 1);
        let started = Instant::now();
        tokio::time::sleep(Duration::from_secs(59)).await;
        client.write_all(b"b").await.unwrap();
        assert_eq!(
            watched.read(&mut byte).await.unwrap(),
            1,
            "it spoke inside the idle limit"
        );
        let err = watched.read(&mut byte).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(59 + 60),
            "then went quiet"
        );
    }
}
