// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The Challenge Handshake Authentication Protocol with MD5 (RFC 1994), the peer's side: every
//! Challenge is answered with `MD5(id ‖ secret ‖ challenge)` and our name, a Success is being
//! authenticated, a Failure is not, and a Challenge after a Success (a rechallenge) is answered
//! without further ado. The secret never appears in a `Debug` rendering.

use std::fmt;

use crate::frame::{Error, Packet};
use crate::md5;

pub const CHALLENGE_CODE: u8 = 1;
pub const RESPONSE_CODE: u8 = 2;
pub const SUCCESS_CODE: u8 = 3;
pub const FAILURE_CODE: u8 = 4;

/// A CHAP packet's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Challenge {
        value: Vec<u8>,
        name: Vec<u8>,
    },
    Response {
        value: Vec<u8>,
        name: Vec<u8>,
    },
    /// The server's message, bytes as sent (shown lossily, never round-tripped as text).
    Success(Vec<u8>),
    Failure(Vec<u8>),
}

impl Message {
    /// Decode a CHAP packet.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] for a value that runs past the packet, [`Error::Length`] for a
    /// code that is not CHAP's.
    pub fn decode(packet: &Packet) -> Result<Message, Error> {
        let valued = |data: &[u8]| -> Result<(Vec<u8>, Vec<u8>), Error> {
            let (len, rest) = data.split_first().ok_or(Error::Truncated)?;
            let (value, name) = rest
                .split_at_checked(usize::from(*len))
                .ok_or(Error::Truncated)?;
            Ok((value.to_vec(), name.to_vec()))
        };
        match packet.code {
            CHALLENGE_CODE => {
                let (value, name) = valued(&packet.data)?;
                Ok(Message::Challenge { value, name })
            }
            RESPONSE_CODE => {
                let (value, name) = valued(&packet.data)?;
                Ok(Message::Response { value, name })
            }
            SUCCESS_CODE => Ok(Message::Success(packet.data.clone())),
            FAILURE_CODE => Ok(Message::Failure(packet.data.clone())),
            code => Err(Error::Length {
                declared: u16::from(code),
                actual: 0,
            }),
        }
    }

    /// The packet for this message under `id`.
    #[must_use]
    pub fn encode(&self, id: u8) -> Packet {
        let valued = |value: &[u8], name: &[u8]| {
            let value = &value[..value.len().min(255)];
            let mut data = vec![u8::try_from(value.len()).unwrap_or(u8::MAX)];
            data.extend_from_slice(value);
            data.extend_from_slice(name);
            data
        };
        let (code, data) = match self {
            Message::Challenge { value, name } => (CHALLENGE_CODE, valued(value, name)),
            Message::Response { value, name } => (RESPONSE_CODE, valued(value, name)),
            Message::Success(text) => (SUCCESS_CODE, text.clone()),
            Message::Failure(text) => (FAILURE_CODE, text.clone()),
        };
        Packet { code, id, data }
    }
}

/// What the client wants done or known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Send(Packet),
    /// Authenticated.
    Ok,
    /// Not authenticated, with the server's message.
    Failed(String),
    /// A Challenge arrived after a Success and was answered.
    Rechallenged,
}

/// Our side of CHAP-MD5 for one session.
#[derive(Clone, PartialEq, Eq)]
pub struct Client {
    name: Vec<u8>,
    secret: Vec<u8>,
    authenticated: bool,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("chap::Client")
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("secret", &"<redacted>")
            .field("authenticated", &self.authenticated)
            .finish()
    }
}

impl Client {
    /// A client answering as `name` with `secret`.
    #[must_use]
    pub fn new(name: &str, secret: &[u8]) -> Client {
        Client {
            name: name.as_bytes().to_vec(),
            secret: secret.to_vec(),
            authenticated: false,
        }
    }

    /// Feed one CHAP packet.
    pub fn handle(&mut self, packet: &Packet) -> Vec<Output> {
        match Message::decode(packet) {
            Ok(Message::Challenge { value, .. }) => {
                let mut input = vec![packet.id];
                input.extend_from_slice(&self.secret);
                input.extend_from_slice(&value);
                let response = Message::Response {
                    value: md5::digest(&input).to_vec(),
                    name: self.name.clone(),
                }
                .encode(packet.id);
                let mut out = vec![Output::Send(response)];
                if self.authenticated {
                    out.push(Output::Rechallenged);
                }
                out
            }
            Ok(Message::Success(_)) => {
                self.authenticated = true;
                vec![Output::Ok]
            }
            Ok(Message::Failure(text)) => {
                self.authenticated = false;
                vec![Output::Failed(String::from_utf8_lossy(&text).into_owned())]
            }
            _ => Vec::new(),
        }
    }

    /// Whether the last word from the server was a Success.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Packet;

    const CHALLENGE: [u8; 16] = [
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20,
    ];
    /// `MD5(0x01 ‖ "example-secret" ‖ CHALLENGE)`, computed independently.
    const RESPONSE: &str = "f78cb6b6f0f928ad35a27378131dd268";

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

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
        let challenge = Message::Challenge {
            value: CHALLENGE.to_vec(),
            name: b"isp".to_vec(),
        };
        let packet = challenge.encode(1);
        assert_eq!(packet.code, CHALLENGE_CODE);
        assert_eq!(packet.data[0], 16);
        assert_eq!(&packet.data[17..], b"isp");
        assert_eq!(Message::decode(&packet), Ok(challenge));
        let success = Message::Success(b"Welcome".to_vec()).encode(1);
        assert_eq!(success.data, b"Welcome".to_vec());
        assert_eq!(
            Message::decode(&success),
            Ok(Message::Success(b"Welcome".to_vec()))
        );
        let failure = Message::Failure(Vec::new()).encode(1);
        assert_eq!(Message::decode(&failure), Ok(Message::Failure(Vec::new())));
        let short = Packet {
            code: CHALLENGE_CODE,
            id: 1,
            data: vec![20, 1, 2],
        };
        assert!(Message::decode(&short).is_err());
        let odd = Packet {
            code: 9,
            id: 1,
            data: vec![],
        };
        assert!(Message::decode(&odd).is_err());
    }

    #[test]
    fn a_failure_with_bytes_that_are_not_utf8_round_trips() {
        let data = vec![0xff, 0xfe, b'n', 0x80];
        let packet = Packet {
            code: FAILURE_CODE,
            id: 2,
            data: data.clone(),
        };
        let message = Message::decode(&packet).unwrap();
        assert_eq!(message, Message::Failure(data.clone()));
        assert_eq!(
            Message::decode(&message.encode(2)),
            Ok(Message::Failure(data))
        );
    }

    #[test]
    fn chap_md5_response_matches_the_vector_and_success_is_ok() {
        let mut client = new_client();
        let challenge = Message::Challenge {
            value: CHALLENGE.to_vec(),
            name: b"isp".to_vec(),
        }
        .encode(1);
        let out = client.handle(&challenge);
        let sends = sent(&out);
        assert_eq!(sends.len(), 1);
        assert_eq!(
            sends[0].id, 1,
            "a Response carries the Challenge's identifier"
        );
        let Ok(Message::Response { value, name }) = Message::decode(&sends[0]) else {
            panic!("a Response was sent: {:?}", sends[0]);
        };
        assert_eq!(hex(&value), RESPONSE);
        assert_eq!(name, b"openfeo@isp.example".to_vec());
        assert!(!client.authenticated());
        let out = client.handle(&Message::Success(b"Welcome".to_vec()).encode(1));
        assert_eq!(out, vec![Output::Ok]);
        assert!(client.authenticated());
    }

    #[test]
    fn chap_failure_fails_and_a_rechallenge_after_success_is_answered() {
        let mut client = new_client();
        let out = client.handle(&Message::Failure(b"Access denied".to_vec()).encode(3));
        assert_eq!(out, vec![Output::Failed("Access denied".to_owned())]);
        let mut client = new_client();
        client.handle(
            &Message::Challenge {
                value: CHALLENGE.to_vec(),
                name: b"isp".to_vec(),
            }
            .encode(1),
        );
        client.handle(&Message::Success(Vec::new()).encode(1));
        let out = client.handle(
            &Message::Challenge {
                value: vec![9; 16],
                name: b"isp".to_vec(),
            }
            .encode(2),
        );
        assert_eq!(sent(&out).len(), 1, "answered");
        assert!(out.contains(&Output::Rechallenged), "{out:?}");
        assert!(
            client.authenticated(),
            "still, until the server says otherwise"
        );
    }

    #[test]
    fn debug_output_never_shows_the_secret() {
        let client = new_client();
        let text = format!("{client:?}");
        assert!(text.contains("openfeo@isp.example"), "{text}");
        assert!(!text.contains("example-secret"), "{text}");
    }
}
