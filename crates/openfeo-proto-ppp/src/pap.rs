// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The Password Authentication Protocol (RFC 1334 §2), the peer's side: an Authenticate-Request
//! with the credentials, repeated every three seconds up to ten times, answered with an Ack or
//! a Nak carrying the server's message. The password never appears in a `Debug` rendering.

use std::fmt;

use crate::frame::{Error, Packet};
use crate::{MS, Timestamp};

/// Authenticate-Request.
pub const REQUEST: u8 = 1;
/// Authenticate-Ack.
pub const ACK: u8 = 2;
/// Authenticate-Nak.
pub const NAK: u8 = 3;
/// The Authenticate-Request is repeated this often while unanswered.
pub const RETRY: Timestamp = 3 * MS;
/// This many requests without an answer is a failure.
pub const MAX_TRIES: u32 = 10;

/// A PAP packet's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Request {
        peer_id: Vec<u8>,
        password: Vec<u8>,
    },
    /// The server's message, bytes as sent (shown lossily, never round-tripped as text).
    Ack(Vec<u8>),
    Nak(Vec<u8>),
}

/// A length-prefixed field and what follows it.
fn counted(data: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (len, rest) = data.split_first().ok_or(Error::Truncated)?;
    rest.split_at_checked(usize::from(*len))
        .ok_or(Error::Truncated)
}

/// A length-prefixed field, at most 255 bytes of it.
fn put_counted(out: &mut Vec<u8>, data: &[u8]) {
    let data = &data[..data.len().min(255)];
    out.push(u8::try_from(data.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(data);
}

/// An Ack's or Nak's message: a counted field, or nothing at all (pppd sends none).
fn message_of(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let (text, _) = counted(data)?;
    Ok(text.to_vec())
}

impl Message {
    /// Decode a PAP packet.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] for a field that runs past the packet, [`Error::Length`] for a code
    /// that is not PAP's.
    pub fn decode(packet: &Packet) -> Result<Message, Error> {
        match packet.code {
            REQUEST => {
                let (peer_id, rest) = counted(&packet.data)?;
                let (password, _) = counted(rest)?;
                Ok(Message::Request {
                    peer_id: peer_id.to_vec(),
                    password: password.to_vec(),
                })
            }
            ACK => Ok(Message::Ack(message_of(&packet.data)?)),
            NAK => Ok(Message::Nak(message_of(&packet.data)?)),
            code => Err(Error::Length {
                declared: u16::from(code),
                actual: 0,
            }),
        }
    }

    /// The packet for this message under `id`.
    #[must_use]
    pub fn encode(&self, id: u8) -> Packet {
        let mut data = Vec::new();
        let code = match self {
            Message::Request { peer_id, password } => {
                put_counted(&mut data, peer_id);
                put_counted(&mut data, password);
                REQUEST
            }
            Message::Ack(text) => {
                put_counted(&mut data, text);
                ACK
            }
            Message::Nak(text) => {
                put_counted(&mut data, text);
                NAK
            }
        };
        Packet { code, id, data }
    }
}

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Packet(Packet),
    Timeout,
}

/// What the client wants done or known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Send(Packet),
    /// Authenticated.
    Ok,
    /// Not authenticated, with the server's message (or `no answer`).
    Failed(String),
}

/// Our side of PAP for one session.
#[derive(Clone, PartialEq, Eq)]
pub struct Client {
    username: Vec<u8>,
    password: Vec<u8>,
    id: u8,
    tries: u32,
    timeout: Option<Timestamp>,
    done: bool,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("pap::Client")
            .field("username", &String::from_utf8_lossy(&self.username))
            .field("password", &"<redacted>")
            .field("tries", &self.tries)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for `username` and `password`, idle until [`Client::start`].
    #[must_use]
    pub fn new(username: &str, password: &[u8]) -> Client {
        Client {
            username: username.as_bytes().to_vec(),
            password: password.to_vec(),
            id: 1,
            tries: 0,
            timeout: None,
            done: false,
        }
    }

    /// Send the first request at `now`.
    pub fn start(&mut self, now: Timestamp) -> Vec<Output> {
        self.done = false;
        self.tries = 0;
        vec![self.request(now)]
    }

    /// Feed one input at `now`.
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output> {
        if self.done {
            return Vec::new();
        }
        match input {
            Input::Packet(packet) => {
                if packet.id != self.id {
                    return Vec::new();
                }
                match Message::decode(&packet) {
                    Ok(Message::Ack(_)) => {
                        self.finish();
                        vec![Output::Ok]
                    }
                    Ok(Message::Nak(text)) => {
                        self.finish();
                        vec![Output::Failed(String::from_utf8_lossy(&text).into_owned())]
                    }
                    _ => Vec::new(),
                }
            }
            Input::Timeout => {
                if self.timeout.is_none_or(|due| due > now) {
                    return Vec::new();
                }
                if self.tries >= MAX_TRIES {
                    self.finish();
                    vec![Output::Failed("no answer".to_owned())]
                } else {
                    vec![self.request(now)]
                }
            }
        }
    }

    /// When to feed [`Input::Timeout`].
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        self.timeout
    }

    fn request(&mut self, now: Timestamp) -> Output {
        self.tries += 1;
        self.timeout = Some(now.saturating_add(RETRY));
        Output::Send(
            Message::Request {
                peer_id: self.username.clone(),
                password: self.password.clone(),
            }
            .encode(self.id),
        )
    }

    fn finish(&mut self) {
        self.done = true;
        self.timeout = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Packet, code};

    fn new_client() -> Client {
        Client::new("openfeo@isp.example", b"example-secret")
    }

    fn sent(out: &[Output]) -> Vec<Packet> {
        out.iter()
            .filter_map(|output| match output {
                Output::Send(packet) => Some(packet.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn messages_round_trip_and_short_ones_are_errors() {
        let request = Message::Request {
            peer_id: b"user".to_vec(),
            password: b"pw".to_vec(),
        };
        let packet = request.encode(7);
        assert_eq!(
            packet.code,
            code::CONFIGURE_REQUEST,
            "PAP's Authenticate-Request is code 1"
        );
        assert_eq!(packet.id, 7);
        assert_eq!(packet.data, b"\x04user\x02pw".to_vec());
        assert_eq!(Message::decode(&packet), Ok(request));
        let ack = Message::Ack(b"welcome".to_vec()).encode(7);
        assert_eq!(ack.data, b"\x07welcome".to_vec());
        assert_eq!(Message::decode(&ack), Ok(Message::Ack(b"welcome".to_vec())));
        let nak = Message::Nak(Vec::new()).encode(7);
        assert_eq!(nak.data, vec![0]);
        assert_eq!(Message::decode(&nak), Ok(Message::Nak(Vec::new())));
        let short = Packet {
            code: 1,
            id: 1,
            data: vec![5, b'u'],
        };
        assert!(Message::decode(&short).is_err());
        let bare_ack = Packet {
            code: 2,
            id: 1,
            data: vec![],
        };
        assert_eq!(
            Message::decode(&bare_ack),
            Ok(Message::Ack(Vec::new())),
            "pppd sends none"
        );
        let odd = Packet {
            code: 9,
            id: 1,
            data: vec![],
        };
        assert!(Message::decode(&odd).is_err());
    }

    #[test]
    fn a_nak_with_bytes_that_are_not_utf8_round_trips() {
        // Found by the ppp_auth fuzz target: a lossy text would grow past 255 bytes on the way
        // back and lose its tail; the wire carries bytes, so the message is bytes.
        let mut data = vec![0u8, 0xff];
        data.extend(std::iter::repeat_n(0x6e, 40));
        data.extend(std::iter::repeat_n(0xff, 200));
        let mut packet_data = vec![u8::try_from(data.len()).unwrap()];
        packet_data.extend_from_slice(&data);
        let packet = Packet {
            code: NAK,
            id: 3,
            data: packet_data,
        };
        let message = Message::decode(&packet).unwrap();
        assert_eq!(message, Message::Nak(data.clone()));
        assert_eq!(Message::decode(&message.encode(3)), Ok(Message::Nak(data)));
    }

    #[test]
    fn pap_sends_the_credentials_and_an_ack_is_ok() {
        let mut client = new_client();
        let out = client.start(1_000);
        let sends = sent(&out);
        assert_eq!(sends.len(), 1);
        assert_eq!(
            Message::decode(&sends[0]),
            Ok(Message::Request {
                peer_id: b"openfeo@isp.example".to_vec(),
                password: b"example-secret".to_vec(),
            })
        );
        assert_eq!(client.next_timeout(), Some(1_000 + RETRY));
        let ack = Message::Ack(b"ok".to_vec()).encode(sends[0].id);
        let out = client.handle(Input::Packet(ack), 1_200);
        assert_eq!(out, vec![Output::Ok]);
        assert_eq!(client.next_timeout(), None);
        let late = Message::Nak(b"no".to_vec()).encode(sends[0].id);
        assert!(
            client.handle(Input::Packet(late), 1_300).is_empty(),
            "done is done"
        );
    }

    #[test]
    fn pap_nak_fails_with_the_message_and_no_retry() {
        let mut client = new_client();
        let out = client.start(0);
        let id = sent(&out)[0].id;
        let wrong_id = Message::Nak(b"Login incorrect".to_vec()).encode(id.wrapping_add(1));
        assert!(
            client.handle(Input::Packet(wrong_id), 100).is_empty(),
            "another identifier is not ours"
        );
        let nak = Message::Nak(b"Login incorrect".to_vec()).encode(id);
        let out = client.handle(Input::Packet(nak), 200);
        assert_eq!(out, vec![Output::Failed("Login incorrect".to_owned())]);
        assert_eq!(client.next_timeout(), None);
        assert!(
            client.handle(Input::Timeout, 10_000).is_empty(),
            "no retry after a Nak"
        );
    }

    #[test]
    fn pap_retransmits_ten_times_then_fails() {
        let mut client = new_client();
        let out = client.start(0);
        let id = sent(&out)[0].id;
        let mut now = 0;
        for _ in 1..MAX_TRIES {
            now += RETRY;
            assert_eq!(client.next_timeout(), Some(now));
            let out = client.handle(Input::Timeout, now);
            let again = sent(&out);
            assert_eq!(again.len(), 1);
            assert_eq!(again[0].id, id, "the same request, the same identifier");
        }
        now += RETRY;
        let out = client.handle(Input::Timeout, now);
        assert_eq!(out, vec![Output::Failed("no answer".to_owned())]);
        assert_eq!(client.next_timeout(), None);
    }

    #[test]
    fn debug_output_never_shows_the_secret() {
        let client = new_client();
        let text = format!("{client:?}");
        assert!(text.contains("openfeo@isp.example"), "{text}");
        assert!(!text.contains("example-secret"), "{text}");
        assert!(!text.contains("14"), "not even the length: {text}");
    }
}
