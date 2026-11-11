// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The lab's relay: `make run PANEL=<address>:<port>` puts the router's panel on an address
//! of the developer's machine, so the real panel can be opened from a browser outside the lab.
//!
//! The lab is a set of namespaces nothing outside can reach. The listening socket is bound
//! before the harness enters its sandbox, so it belongs to the host's network and stays there;
//! each connection it accepts is joined to one made from inside the LAN namespace to the
//! router. To the router the browser is a LAN host. Bytes are copied as they are: the TLS is
//! the router's own, end to end.

use std::fs::File;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use nix::sched::{CloneFlags, setns};

use crate::netns::NetNs;

/// How long a connection to the router may take to be made.
const CONNECT: Duration = Duration::from_secs(5);

/// A relay that is accepting; it runs until the process ends.
#[derive(Debug)]
pub struct Relay {
    addr: SocketAddr,
}

impl Relay {
    /// Where it listens.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Bind the listening socket. Call this before entering the sandbox: a socket belongs to the
/// network namespace it was made in.
///
/// # Errors
///
/// When the address cannot be bound.
pub fn bind(listen: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(listen).with_context(|| format!("bind {listen} for the panel relay"))
}

/// Copy one way until the reader ends, then tell the writer's far side there is no more.
fn pump(mut from: TcpStream, mut to: TcpStream) {
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}

/// Join an accepted connection to one `connect` makes. Runs on a thread of its own.
fn join(client: TcpStream, connect: &(dyn Fn() -> io::Result<TcpStream> + Send + Sync)) {
    // A target that cannot be reached closes the client: dropping it does.
    let Ok(target) = connect() else {
        return;
    };
    let (Ok(client_back), Ok(target_back)) = (client.try_clone(), target.try_clone()) else {
        return;
    };
    let up = std::thread::spawn(move || pump(client, target));
    pump(target_back, client_back);
    let _ = up.join();
}

/// Accept on `listener` and join each connection to one made by `connect`, which is called
/// on a thread of its own for each (so it may move that thread into another namespace).
///
/// # Errors
///
/// When the listener has no address or the accepting thread cannot be started.
pub fn start<C>(listener: TcpListener, connect: C) -> Result<Relay>
where
    C: Fn() -> io::Result<TcpStream> + Send + Sync + 'static,
{
    let addr = listener.local_addr().context("the relay's address")?;
    let connect = Arc::new(connect);
    std::thread::Builder::new()
        .name("panel-relay".to_owned())
        .spawn(move || {
            for client in listener.incoming() {
                let Ok(client) = client else {
                    continue;
                };
                let connect = connect.clone();
                std::thread::spawn(move || join(client, &*connect));
            }
        })
        .context("start the relay")?;
    Ok(Relay { addr })
}

/// A connector for [`start`] that reaches `target` from inside `ns`: the calling thread
/// enters the namespace and stays there.
pub fn into_ns(
    ns: &NetNs,
    target: SocketAddr,
) -> impl Fn() -> io::Result<TcpStream> + Send + Sync + use<> {
    let path = ns.path();
    move || {
        let handle = File::open(&path)?;
        setns(&handle, CloneFlags::CLONE_NEWNET).map_err(io::Error::from)?;
        TcpStream::connect_timeout(&target, CONNECT)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};

    use super::*;

    const SOON: Duration = Duration::from_secs(5);

    /// A target that sends back what it is sent until its client says it is done.
    fn echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let (mut from, mut to) = (stream.try_clone().unwrap(), stream);
                    let _ = io::copy(&mut from, &mut to);
                });
            }
        });
        addr
    }

    fn client(relay: &Relay) -> TcpStream {
        let stream = TcpStream::connect(relay.addr()).unwrap();
        stream.set_read_timeout(Some(SOON)).unwrap();
        stream
    }

    #[test]
    fn bytes_pass_both_ways_and_a_close_is_carried() {
        let target = echo();
        let relay = start(bind("127.0.0.1:0".parse().unwrap()).unwrap(), move || {
            TcpStream::connect(target)
        })
        .unwrap();
        let mut stream = client(&relay);
        stream.write_all(b"hello, router").unwrap();
        let mut back = [0u8; 13];
        stream.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello, router");
        // The client says it is done; the target hears it and ends, and that reaches the client.
        stream.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"");
    }

    #[test]
    fn two_clients_do_not_wait_for_each_other() {
        let target = echo();
        let relay = start(bind("127.0.0.1:0".parse().unwrap()).unwrap(), move || {
            TcpStream::connect(target)
        })
        .unwrap();
        let (mut first, mut second) = (client(&relay), client(&relay));
        second.write_all(b"second").unwrap();
        let mut back = [0u8; 6];
        second.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"second");
        first.write_all(b"first!").unwrap();
        first.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"first!");
    }

    #[test]
    fn a_target_that_refuses_closes_the_client() {
        let relay = start(bind("127.0.0.1:0".parse().unwrap()).unwrap(), || {
            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
        })
        .unwrap();
        let mut stream = client(&relay);
        let mut rest = Vec::new();
        let asked = std::time::Instant::now();
        let ended = stream.read_to_end(&mut rest);
        // The end of the stream, or a reset: the relay closed it. Not the client's own read
        // timeout running out, which is what a relay that left it open would look like.
        let closed = match &ended {
            Ok(0) => true,
            Err(err) => matches!(
                err.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ),
            Ok(_) => false,
        };
        assert!(closed, "{ended:?}");
        assert!(
            asked.elapsed() < SOON / 2,
            "closed only after {:?}",
            asked.elapsed()
        );
        assert_eq!(rest, b"");
    }
}
