// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! PPP over PPPoE: a frame is a two-byte protocol and its payload (RFC 2516 §4: no address or
//! control field, no protocol-field compression), and the control protocols share one packet
//! header (RFC 1661 §5: code, identifier, length) and one option layout (type, length, data).

use thiserror::Error;

/// Link Control Protocol.
pub const LCP: u16 = 0xc021;
/// Password Authentication Protocol.
pub const PAP: u16 = 0xc023;
/// Challenge Handshake Authentication Protocol.
pub const CHAP: u16 = 0xc223;
/// IP Control Protocol.
pub const IPCP: u16 = 0x8021;
/// IPv6 Control Protocol.
pub const IPV6CP: u16 = 0x8057;
/// IPv4 data, which the kernel carries.
pub const IPV4: u16 = 0x0021;
/// IPv6 data, which the kernel carries.
pub const IPV6: u16 = 0x0057;

/// The packet codes shared by LCP and the network control protocols (RFC 1661 §5).
pub mod code {
    pub const CONFIGURE_REQUEST: u8 = 1;
    pub const CONFIGURE_ACK: u8 = 2;
    pub const CONFIGURE_NAK: u8 = 3;
    pub const CONFIGURE_REJECT: u8 = 4;
    pub const TERMINATE_REQUEST: u8 = 5;
    pub const TERMINATE_ACK: u8 = 6;
    pub const CODE_REJECT: u8 = 7;
    pub const PROTOCOL_REJECT: u8 = 8;
    pub const ECHO_REQUEST: u8 = 9;
    pub const ECHO_REPLY: u8 = 10;
    pub const DISCARD_REQUEST: u8 = 11;
}

/// The packet header: code, identifier, length.
const PACKET_HEADER_LEN: usize = 4;
/// An option's type and length.
const OPTION_HEADER_LEN: usize = 2;

/// Why bytes are not a frame, a packet or an option list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    #[error("truncated PPP data")]
    Truncated,
    #[error("a one-byte protocol field (protocol-field compression, never agreed to)")]
    Compressed,
    #[error("packet length {declared} against {actual} bytes")]
    Length { declared: u16, actual: usize },
    #[error("option {kind} is malformed")]
    Option { kind: u8 },
}

/// A PPP frame as PPPoE carries it: the protocol and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub protocol: u16,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Split a frame into its protocol and payload.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] below two bytes; [`Error::Compressed`] when the first byte is odd
    /// (a one-byte protocol field), which we never negotiate.
    pub fn decode(bytes: &'a [u8]) -> Result<Frame<'a>, Error> {
        match bytes {
            [first, ..] if first & 1 == 1 => Err(Error::Compressed),
            [high, low, payload @ ..] => Ok(Frame {
                protocol: u16::from_be_bytes([*high, *low]),
                payload,
            }),
            _ => Err(Error::Truncated),
        }
    }

    /// The frame's bytes for `protocol` and `payload`.
    #[must_use]
    pub fn encode(protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + payload.len());
        bytes.extend_from_slice(&protocol.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }
}

/// A control-protocol packet: code, identifier and data, the length on the wire covering the
/// four-byte header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub code: u8,
    pub id: u8,
    pub data: Vec<u8>,
}

impl Packet {
    /// Decode a packet; bytes past its length are ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] below the header, [`Error::Length`] when the length is below the
    /// header or runs past the bytes.
    pub fn decode(bytes: &[u8]) -> Result<Packet, Error> {
        let (header, rest) = bytes
            .split_at_checked(PACKET_HEADER_LEN)
            .ok_or(Error::Truncated)?;
        let declared = u16::from_be_bytes([header[2], header[3]]);
        let length = usize::from(declared);
        if length < PACKET_HEADER_LEN {
            return Err(Error::Length {
                declared,
                actual: bytes.len(),
            });
        }
        let data = rest
            .get(..length - PACKET_HEADER_LEN)
            .ok_or(Error::Length {
                declared,
                actual: bytes.len(),
            })?;
        Ok(Packet {
            code: header[0],
            id: header[1],
            data: data.to_vec(),
        })
    }

    /// The packet's bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let length = u16::try_from(PACKET_HEADER_LEN + self.data.len()).unwrap_or(u16::MAX);
        let mut bytes = Vec::with_capacity(usize::from(length));
        bytes.push(self.code);
        bytes.push(self.id);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

/// Split an option list into `(type, data)` pairs.
///
/// # Errors
///
/// [`Error::Option`] naming the type whose length is below two or runs past the list.
pub fn options(data: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut out = Vec::new();
    let mut rest = data;
    while let Some((header, after)) = rest.split_at_checked(OPTION_HEADER_LEN) {
        let kind = header[0];
        let length = usize::from(header[1]);
        let body = length
            .checked_sub(OPTION_HEADER_LEN)
            .and_then(|len| after.split_at_checked(len))
            .ok_or(Error::Option { kind })?;
        out.push((kind, body.0));
        rest = body.1;
    }
    if !rest.is_empty() {
        return Err(Error::Option { kind: rest[0] });
    }
    Ok(out)
}

/// Append one option (type, length, data) to `out`.
pub fn put_option(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    out.push(kind);
    out.push(u8::try_from(OPTION_HEADER_LEN + data.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_is_a_protocol_and_its_payload() {
        let bytes = Frame::encode(LCP, &[1, 2, 3]);
        assert_eq!(bytes, vec![0xc0, 0x21, 1, 2, 3]);
        let frame = Frame::decode(&bytes).unwrap();
        assert_eq!((frame.protocol, frame.payload), (LCP, &[1u8, 2, 3][..]));
        assert_eq!(Frame::decode(&[0xc0]), Err(Error::Truncated));
        assert_eq!(
            Frame::decode(&[0x21, 1, 2]),
            Err(Error::Compressed),
            "a one-byte protocol field is PFC, which we never agree to"
        );
    }

    #[test]
    fn a_packet_has_code_id_and_a_length_that_covers_its_header() {
        let packet = Packet {
            code: code::CONFIGURE_REQUEST,
            id: 7,
            data: vec![1, 4, 0x05, 0xdc],
        };
        let bytes = packet.encode();
        assert_eq!(bytes, vec![1, 7, 0, 8, 1, 4, 0x05, 0xdc]);
        assert_eq!(Packet::decode(&bytes), Ok(packet.clone()));
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            Packet::decode(&padded),
            Ok(packet),
            "padding past the length is ignored"
        );
        assert_eq!(Packet::decode(&bytes[..3]), Err(Error::Truncated));
        assert_eq!(
            Packet::decode(&[1, 7, 0, 9, 1]),
            Err(Error::Length {
                declared: 9,
                actual: 5
            })
        );
        assert_eq!(
            Packet::decode(&[1, 7, 0, 3]),
            Err(Error::Length {
                declared: 3,
                actual: 4
            }),
            "a length below the header is nonsense"
        );
    }

    #[test]
    fn options_split_into_type_and_data_and_a_short_one_is_an_error() {
        let data = [1, 4, 0x05, 0xdc, 5, 6, 1, 2, 3, 4];
        assert_eq!(
            options(&data).unwrap(),
            vec![(1, &[0x05u8, 0xdc][..]), (5, &[1u8, 2, 3, 4][..])]
        );
        assert_eq!(options(&[1, 1]), Err(Error::Option { kind: 1 }));
        assert_eq!(options(&[1, 5, 0]), Err(Error::Option { kind: 1 }));
        let mut out = Vec::new();
        put_option(&mut out, 3, &[0xc0, 0x23]);
        assert_eq!(out, vec![3, 4, 0xc0, 0x23]);
    }
}
