// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The PPPoE discovery codec (RFC 2516 §5, RFC 4638 §3): the five discovery packets and their
//! tags, bounded, decoding never panicking. Session frames (`ETH_P_PPP_SES`) are the kernel's.

use thiserror::Error;

/// Ethertype of discovery frames.
pub const ETH_P_PPP_DISC: u16 = 0x8863;
/// Ethertype of session frames, which the kernel handles.
pub const ETH_P_PPP_SES: u16 = 0x8864;
/// The discovery broadcast.
pub const BROADCAST: [u8; 6] = [0xff; 6];

/// Version 1, type 1: the only values RFC 2516 defines, packed into the first byte.
const VERSION_TYPE: u8 = 0x11;
/// The header: version/type, code, session id, length.
const HEADER_LEN: usize = 6;
/// A tag's kind and length.
const TAG_HEADER_LEN: usize = 4;
/// At most this many tags in one packet.
pub const MAX_TAGS: usize = 32;
/// At most this many bytes in one tag.
pub const MAX_TAG_LEN: usize = 1480;

const TAG_END_OF_LIST: u16 = 0x0000;
const TAG_SERVICE_NAME: u16 = 0x0101;
const TAG_AC_NAME: u16 = 0x0102;
const TAG_HOST_UNIQ: u16 = 0x0103;
const TAG_AC_COOKIE: u16 = 0x0104;
const TAG_RELAY_SESSION_ID: u16 = 0x0110;
const TAG_PPP_MAX_PAYLOAD: u16 = 0x0120;
const TAG_SERVICE_NAME_ERROR: u16 = 0x0201;
const TAG_AC_SYSTEM_ERROR: u16 = 0x0202;
const TAG_GENERIC_ERROR: u16 = 0x0203;

/// Why bytes are not a discovery packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    #[error("truncated discovery packet")]
    Truncated,
    #[error("PPPoE version {0} (only 1 is known)")]
    Version(u8),
    #[error("PPPoE type {0} (only 1 is known)")]
    Type(u8),
    #[error("unknown discovery code {0:#04x}")]
    Code(u8),
    #[error("tag {kind:#06x} runs past its packet or has the wrong length")]
    TagLength { kind: u16 },
    #[error("more than {MAX_TAGS} tags")]
    TooMany,
    #[error("declared length {declared} but {actual} bytes follow the header")]
    Length { declared: u16, actual: usize },
}

/// The five discovery packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Padi,
    Pado,
    Padr,
    Pads,
    Padt,
}

impl Code {
    /// The code byte on the wire.
    #[must_use]
    pub fn byte(self) -> u8 {
        match self {
            Code::Padi => 0x09,
            Code::Pado => 0x07,
            Code::Padr => 0x19,
            Code::Pads => 0x65,
            Code::Padt => 0xa7,
        }
    }

    fn from_byte(byte: u8) -> Result<Code, Error> {
        Ok(match byte {
            0x09 => Code::Padi,
            0x07 => Code::Pado,
            0x19 => Code::Padr,
            0x65 => Code::Pads,
            0xa7 => Code::Padt,
            other => return Err(Error::Code(other)),
        })
    }
}

/// The tags of RFC 2516 appendix A and RFC 4638 §3. A string tag whose bytes are not UTF-8
/// is kept as [`Tag::Unknown`] with its kind, so it round-trips and nothing is guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tag {
    EndOfList,
    ServiceName(String),
    AcName(String),
    HostUniq(Vec<u8>),
    AcCookie(Vec<u8>),
    RelaySessionId(Vec<u8>),
    /// RFC 4638: the PPP payload size the sender can carry, 1492 and above.
    PppMaxPayload(u16),
    ServiceNameError(String),
    AcSystemError(String),
    GenericError(String),
    Unknown {
        kind: u16,
        data: Vec<u8>,
    },
}

impl Tag {
    fn kind(&self) -> u16 {
        match self {
            Tag::EndOfList => TAG_END_OF_LIST,
            Tag::ServiceName(_) => TAG_SERVICE_NAME,
            Tag::AcName(_) => TAG_AC_NAME,
            Tag::HostUniq(_) => TAG_HOST_UNIQ,
            Tag::AcCookie(_) => TAG_AC_COOKIE,
            Tag::RelaySessionId(_) => TAG_RELAY_SESSION_ID,
            Tag::PppMaxPayload(_) => TAG_PPP_MAX_PAYLOAD,
            Tag::ServiceNameError(_) => TAG_SERVICE_NAME_ERROR,
            Tag::AcSystemError(_) => TAG_AC_SYSTEM_ERROR,
            Tag::GenericError(_) => TAG_GENERIC_ERROR,
            Tag::Unknown { kind, .. } => *kind,
        }
    }

    fn data(&self) -> Vec<u8> {
        match self {
            Tag::EndOfList => Vec::new(),
            Tag::ServiceName(text)
            | Tag::AcName(text)
            | Tag::ServiceNameError(text)
            | Tag::AcSystemError(text)
            | Tag::GenericError(text) => text.as_bytes().to_vec(),
            Tag::HostUniq(data)
            | Tag::AcCookie(data)
            | Tag::RelaySessionId(data)
            | Tag::Unknown { data, .. } => data.clone(),
            Tag::PppMaxPayload(size) => size.to_be_bytes().to_vec(),
        }
    }

    fn decode(kind: u16, data: &[u8]) -> Result<Tag, Error> {
        let text = |data: &[u8]| String::from_utf8(data.to_vec()).ok();
        let unknown = || Tag::Unknown {
            kind,
            data: data.to_vec(),
        };
        Ok(match kind {
            TAG_END_OF_LIST if data.is_empty() => Tag::EndOfList,
            TAG_END_OF_LIST => return Err(Error::TagLength { kind }),
            TAG_SERVICE_NAME => text(data).map_or_else(unknown, Tag::ServiceName),
            TAG_AC_NAME => text(data).map_or_else(unknown, Tag::AcName),
            TAG_HOST_UNIQ => Tag::HostUniq(data.to_vec()),
            TAG_AC_COOKIE => Tag::AcCookie(data.to_vec()),
            TAG_RELAY_SESSION_ID => Tag::RelaySessionId(data.to_vec()),
            TAG_PPP_MAX_PAYLOAD => match data {
                [high, low] => Tag::PppMaxPayload(u16::from_be_bytes([*high, *low])),
                _ => return Err(Error::TagLength { kind }),
            },
            TAG_SERVICE_NAME_ERROR => text(data).map_or_else(unknown, Tag::ServiceNameError),
            TAG_AC_SYSTEM_ERROR => text(data).map_or_else(unknown, Tag::AcSystemError),
            TAG_GENERIC_ERROR => text(data).map_or_else(unknown, Tag::GenericError),
            _ => unknown(),
        })
    }
}

/// One discovery packet: the payload of an `ETH_P_PPP_DISC` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    pub code: Code,
    /// 0 until a PADS grants one.
    pub session_id: u16,
    pub tags: Vec<Tag>,
}

impl Discovery {
    /// Decode a discovery payload; bytes past the declared length (Ethernet padding) are
    /// ignored.
    ///
    /// # Errors
    ///
    /// [`Error`] for anything that is not a well-formed discovery packet.
    pub fn decode(bytes: &[u8]) -> Result<Discovery, Error> {
        let (header, rest) = bytes.split_at_checked(HEADER_LEN).ok_or(Error::Truncated)?;
        if header[0] >> 4 != VERSION_TYPE >> 4 {
            return Err(Error::Version(header[0] >> 4));
        }
        if header[0] & 0x0f != VERSION_TYPE & 0x0f {
            return Err(Error::Type(header[0] & 0x0f));
        }
        let code = Code::from_byte(header[1])?;
        let session_id = u16::from_be_bytes([header[2], header[3]]);
        let declared = u16::from_be_bytes([header[4], header[5]]);
        let mut body = rest.get(..usize::from(declared)).ok_or(Error::Length {
            declared,
            actual: rest.len(),
        })?;
        let mut tags = Vec::new();
        while !body.is_empty() {
            let (tag_header, after) = body
                .split_at_checked(TAG_HEADER_LEN)
                .ok_or(Error::Truncated)?;
            let kind = u16::from_be_bytes([tag_header[0], tag_header[1]]);
            let len = usize::from(u16::from_be_bytes([tag_header[2], tag_header[3]]));
            let (data, next) = after
                .split_at_checked(len)
                .filter(|_| len <= MAX_TAG_LEN)
                .ok_or(Error::TagLength { kind })?;
            if tags.len() == MAX_TAGS {
                return Err(Error::TooMany);
            }
            tags.push(Tag::decode(kind, data)?);
            body = next;
        }
        Ok(Discovery {
            code,
            session_id,
            tags,
        })
    }

    /// The packet's bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for tag in &self.tags {
            let data = tag.data();
            body.extend_from_slice(&tag.kind().to_be_bytes());
            body.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
            body.extend_from_slice(&data);
        }
        let mut bytes = Vec::with_capacity(HEADER_LEN + body.len());
        bytes.push(VERSION_TYPE);
        bytes.push(self.code.byte());
        bytes.extend_from_slice(&self.session_id.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    /// The first tag `pick` accepts.
    pub fn tag<T>(&self, pick: impl Fn(&Tag) -> Option<T>) -> Option<T> {
        self.tags.iter().find_map(pick)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_UNIQ: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03];

    fn padi() -> Discovery {
        Discovery {
            code: Code::Padi,
            session_id: 0,
            tags: vec![
                Tag::ServiceName(String::new()),
                Tag::HostUniq(HOST_UNIQ.to_vec()),
                Tag::PppMaxPayload(1500),
            ],
        }
    }

    #[test]
    fn padi_round_trips_with_host_uniq_service_and_max_payload() {
        let bytes = padi().encode();
        let mut expected = vec![
            0x11, 0x09, 0x00, 0x00, 0x00, 0x16, 0x01, 0x01, 0x00, 0x00, 0x01, 0x03, 0x00, 0x08,
        ];
        expected.extend_from_slice(&HOST_UNIQ);
        expected.extend_from_slice(&[0x01, 0x20, 0x00, 0x02, 0x05, 0xdc]);
        assert_eq!(bytes, expected, "RFC 2516 §5.1 layout, RFC 4638 §3 tag");
        assert_eq!(Discovery::decode(&bytes), Ok(padi()));
    }

    #[test]
    fn pado_decodes_with_ac_name_cookie_and_padding_ignored() {
        let mut bytes = vec![0x11, 0x07, 0x00, 0x00, 0x00, 0x00];
        let mut tags = Vec::new();
        tags.extend_from_slice(&[0x01, 0x02, 0x00, 0x03, b'i', b's', b'p']);
        tags.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        tags.extend_from_slice(&[0x01, 0x03, 0x00, 0x08]);
        tags.extend_from_slice(&HOST_UNIQ);
        tags.extend_from_slice(&[0x01, 0x04, 0x00, 0x04, 1, 2, 3, 4]);
        let len = u16::try_from(tags.len()).unwrap().to_be_bytes();
        bytes[4..6].copy_from_slice(&len);
        bytes.extend_from_slice(&tags);
        bytes.extend_from_slice(&[0u8; 20]); // Ethernet padding up to 60 bytes
        let pado = Discovery::decode(&bytes).expect("a PADO");
        assert_eq!(pado.code, Code::Pado);
        assert_eq!(
            pado.tags,
            vec![
                Tag::AcName("isp".to_owned()),
                Tag::ServiceName(String::new()),
                Tag::HostUniq(HOST_UNIQ.to_vec()),
                Tag::AcCookie(vec![1, 2, 3, 4]),
            ]
        );
        assert_eq!(
            pado.tag(|tag| match tag {
                Tag::AcName(name) => Some(name.clone()),
                _ => None,
            }),
            Some("isp".to_owned())
        );
        assert_eq!(pado.encode(), bytes[..bytes.len() - 20].to_vec());
    }

    #[test]
    fn a_declared_length_longer_than_the_frame_is_an_error() {
        let bytes = [0x11, 0x09, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00];
        assert_eq!(
            Discovery::decode(&bytes),
            Err(Error::Length {
                declared: 16,
                actual: 4
            })
        );
        assert_eq!(Discovery::decode(&bytes[..5]), Err(Error::Truncated));
    }

    #[test]
    fn a_tag_longer_than_its_packet_is_an_error() {
        let bytes = [
            0x11, 0x09, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x08, 0xaa, 0xbb,
        ];
        assert_eq!(
            Discovery::decode(&bytes),
            Err(Error::TagLength { kind: 0x0103 })
        );
        let bad_payload = [
            0x11, 0x09, 0x00, 0x00, 0x00, 0x05, 0x01, 0x20, 0x00, 0x01, 0x05,
        ];
        assert_eq!(
            Discovery::decode(&bad_payload),
            Err(Error::TagLength { kind: 0x0120 })
        );
    }

    #[test]
    fn thirty_three_tags_are_too_many() {
        let mut too_many = Discovery {
            code: Code::Pado,
            session_id: 0,
            tags: Vec::new(),
        };
        for _ in 0..33 {
            too_many.tags.push(Tag::AcCookie(vec![1]));
        }
        assert_eq!(Discovery::decode(&too_many.encode()), Err(Error::TooMany));
        too_many.tags.pop();
        assert!(Discovery::decode(&too_many.encode()).is_ok());
    }

    #[test]
    fn an_unknown_tag_and_a_non_utf8_name_round_trip() {
        let packet = Discovery {
            code: Code::Pads,
            session_id: 0x1234,
            tags: vec![
                Tag::Unknown {
                    kind: 0x0105,
                    data: vec![0xde, 0xad],
                },
                Tag::Unknown {
                    kind: 0x0102,
                    data: vec![0xff, 0xfe],
                },
                Tag::RelaySessionId(vec![9]),
                Tag::GenericError("no".to_owned()),
                Tag::EndOfList,
            ],
        };
        assert_eq!(Discovery::decode(&packet.encode()), Ok(packet));
    }

    #[test]
    fn version_type_and_code_are_checked() {
        assert_eq!(
            Discovery::decode(&[0x21, 0x09, 0, 0, 0, 0]),
            Err(Error::Version(2))
        );
        assert_eq!(
            Discovery::decode(&[0x12, 0x09, 0, 0, 0, 0]),
            Err(Error::Type(2))
        );
        assert_eq!(
            Discovery::decode(&[0x11, 0x42, 0, 0, 0, 0]),
            Err(Error::Code(0x42))
        );
        assert_eq!(Code::Padt.byte(), 0xa7);
    }
}
