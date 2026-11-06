// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv6 wire format (RFC 8415 §8 and §21): the four-byte header and the options the
//! client, the responder and the lab need, with identity associations nested as the protocol
//! nests them. Everything else is kept as [`Dhcp6Option::Unknown`] and round-trips untouched.
//! Bounds are explicit (option counts, nesting depth, name lengths), so an adversarial message
//! costs a bounded amount of memory and never recurses deeper than the protocol allows.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use thiserror::Error;

/// The client's port (RFC 8415 §7.2).
pub const CLIENT_PORT: u16 = 546;
/// The server's and relay's port.
pub const SERVER_PORT: u16 = 547;
/// `ff02::1:2`, where clients send.
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// Top-level options a message may carry.
pub const MAX_OPTIONS: usize = 64;
/// Options inside an identity association, an address or a prefix.
pub const MAX_IA_OPTIONS: usize = 16;
/// Resolvers in a DNS servers option.
pub const MAX_ADDRS: usize = 16;
/// Names in a domain list.
pub const MAX_NAMES: usize = 16;
/// Codes in an option request.
pub const MAX_ORO: usize = 32;
/// IA → IAADDR/IAPREFIX → STATUS is as deep as the protocol goes.
const MAX_DEPTH: u8 = 2;
/// The DNS limits a name and a label (RFC 1035 §2.3.4).
const MAX_NAME: usize = 255;
const MAX_LABEL: u8 = 63;

const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IAADDR: u16 = 5;
const OPT_ORO: u16 = 6;
const OPT_ELAPSED_TIME: u16 = 8;
const OPT_STATUS_CODE: u16 = 13;
const OPT_RAPID_COMMIT: u16 = 14;
const OPT_DNS_SERVERS: u16 = 23;
const OPT_DOMAIN_LIST: u16 = 24;
const OPT_IA_PD: u16 = 25;
const OPT_IAPREFIX: u16 = 26;
const OPT_INFORMATION_REFRESH_TIME: u16 = 32;
const OPT_SOL_MAX_RT: u16 = 82;

/// RFC 8415 §7.3's message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Solicit,
    Advertise,
    Request,
    Confirm,
    Renew,
    Rebind,
    Reply,
    Release,
    Decline,
    Reconfigure,
    InformationRequest,
    /// A type this codec has no name for (relay messages among them).
    Other(u8),
}

impl From<u8> for MessageType {
    fn from(byte: u8) -> Self {
        match byte {
            1 => MessageType::Solicit,
            2 => MessageType::Advertise,
            3 => MessageType::Request,
            4 => MessageType::Confirm,
            5 => MessageType::Renew,
            6 => MessageType::Rebind,
            7 => MessageType::Reply,
            8 => MessageType::Release,
            9 => MessageType::Decline,
            10 => MessageType::Reconfigure,
            11 => MessageType::InformationRequest,
            other => MessageType::Other(other),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(kind: MessageType) -> Self {
        match kind {
            MessageType::Solicit => 1,
            MessageType::Advertise => 2,
            MessageType::Request => 3,
            MessageType::Confirm => 4,
            MessageType::Renew => 5,
            MessageType::Rebind => 6,
            MessageType::Reply => 7,
            MessageType::Release => 8,
            MessageType::Decline => 9,
            MessageType::Reconfigure => 10,
            MessageType::InformationRequest => 11,
            MessageType::Other(other) => other,
        }
    }
}

/// RFC 8415 §21.13's status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Success,
    UnspecFail,
    NoAddrsAvail,
    NoBinding,
    NotOnLink,
    UseMulticast,
    NoPrefixAvail,
    Other(u16),
}

impl From<u16> for StatusCode {
    fn from(code: u16) -> Self {
        match code {
            0 => StatusCode::Success,
            1 => StatusCode::UnspecFail,
            2 => StatusCode::NoAddrsAvail,
            3 => StatusCode::NoBinding,
            4 => StatusCode::NotOnLink,
            5 => StatusCode::UseMulticast,
            6 => StatusCode::NoPrefixAvail,
            other => StatusCode::Other(other),
        }
    }
}

impl From<StatusCode> for u16 {
    fn from(code: StatusCode) -> Self {
        match code {
            StatusCode::Success => 0,
            StatusCode::UnspecFail => 1,
            StatusCode::NoAddrsAvail => 2,
            StatusCode::NoBinding => 3,
            StatusCode::NotOnLink => 4,
            StatusCode::UseMulticast => 5,
            StatusCode::NoPrefixAvail => 6,
            StatusCode::Other(other) => other,
        }
    }
}

/// One option (RFC 8415 §21). Identity associations carry their addresses or prefixes as
/// nested options, which carry their status the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dhcp6Option {
    /// Type 1: the client's DUID.
    ClientId(Vec<u8>),
    /// Type 2: the server's DUID.
    ServerId(Vec<u8>),
    /// Type 3.
    IaNa {
        iaid: u32,
        t1: u32,
        t2: u32,
        options: Vec<Dhcp6Option>,
    },
    /// Type 5, inside an `IA_NA`.
    IaAddr {
        addr: Ipv6Addr,
        preferred: u32,
        valid: u32,
        options: Vec<Dhcp6Option>,
    },
    /// Type 6: the option codes the client asks for.
    Oro(Vec<u16>),
    /// Type 8: centiseconds since the exchange began.
    ElapsedTime(u16),
    /// Type 13.
    StatusCode { code: StatusCode, message: String },
    /// Type 14.
    RapidCommit,
    /// Type 23 (RFC 3646).
    DnsServers(Vec<Ipv6Addr>),
    /// Type 24 (RFC 3646), names as dotted text.
    DomainList(Vec<String>),
    /// Type 25.
    IaPd {
        iaid: u32,
        t1: u32,
        t2: u32,
        options: Vec<Dhcp6Option>,
    },
    /// Type 26, inside an `IA_PD`.
    IaPrefix {
        prefix: Ipv6Net,
        preferred: u32,
        valid: u32,
        options: Vec<Dhcp6Option>,
    },
    /// Type 32 (RFC 8415 §21.23).
    InformationRefreshTime(u32),
    /// Type 82 (RFC 8415 §21.24).
    SolMaxRt(u32),
    /// Anything else, body bytes after the four-byte option header.
    Unknown { code: u16, data: Vec<u8> },
}

impl Dhcp6Option {
    /// The option code on the wire.
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Dhcp6Option::ClientId(_) => OPT_CLIENTID,
            Dhcp6Option::ServerId(_) => OPT_SERVERID,
            Dhcp6Option::IaNa { .. } => OPT_IA_NA,
            Dhcp6Option::IaAddr { .. } => OPT_IAADDR,
            Dhcp6Option::Oro(_) => OPT_ORO,
            Dhcp6Option::ElapsedTime(_) => OPT_ELAPSED_TIME,
            Dhcp6Option::StatusCode { .. } => OPT_STATUS_CODE,
            Dhcp6Option::RapidCommit => OPT_RAPID_COMMIT,
            Dhcp6Option::DnsServers(_) => OPT_DNS_SERVERS,
            Dhcp6Option::DomainList(_) => OPT_DOMAIN_LIST,
            Dhcp6Option::IaPd { .. } => OPT_IA_PD,
            Dhcp6Option::IaPrefix { .. } => OPT_IAPREFIX,
            Dhcp6Option::InformationRefreshTime(_) => OPT_INFORMATION_REFRESH_TIME,
            Dhcp6Option::SolMaxRt(_) => OPT_SOL_MAX_RT,
            Dhcp6Option::Unknown { code, .. } => *code,
        }
    }

    /// The status carried directly inside this option, when it is an IA, an address or a
    /// prefix with a status option.
    #[must_use]
    pub fn status(&self) -> Option<(StatusCode, &str)> {
        match self {
            Dhcp6Option::IaNa { options, .. }
            | Dhcp6Option::IaAddr { options, .. }
            | Dhcp6Option::IaPd { options, .. }
            | Dhcp6Option::IaPrefix { options, .. } => status_in(options),
            _ => None,
        }
    }
}

/// The status option among `options`, if any.
#[must_use]
pub fn status_in(options: &[Dhcp6Option]) -> Option<(StatusCode, &str)> {
    options.iter().find_map(|option| match option {
        Dhcp6Option::StatusCode { code, message } => Some((*code, message.as_str())),
        _ => None,
    })
}

/// One message: type, 24-bit transaction id, options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: MessageType,
    /// The transaction id; only the low 24 bits go on the wire.
    pub xid: u32,
    pub options: Vec<Dhcp6Option>,
}

/// Why bytes are not a message this codec accepts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// Fewer bytes than the header or an option length announces.
    #[error("message truncated")]
    Truncated,
    /// An option whose body does not fit its type.
    #[error("option {code} is malformed")]
    BadOption { code: u16 },
    /// More options, nested options, addresses or names than [`MAX_OPTIONS`] and friends.
    #[error("too many options")]
    TooMany,
}

impl Message {
    /// A message with no options yet.
    #[must_use]
    pub fn new(kind: MessageType, xid: u32) -> Message {
        Message {
            kind,
            xid: xid & 0x00ff_ffff,
            options: Vec::new(),
        }
    }

    /// Parse a message.
    ///
    /// # Errors
    ///
    /// [`Error`] for a truncated or malformed message; an unknown option is not an error.
    pub fn decode(bytes: &[u8]) -> Result<Message, Error> {
        let (&kind, rest) = bytes.split_first().ok_or(Error::Truncated)?;
        let xid_bytes: &[u8; 3] = rest
            .get(..3)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Truncated)?;
        let xid = (u32::from(xid_bytes[0]) << 16)
            | (u32::from(xid_bytes[1]) << 8)
            | u32::from(xid_bytes[2]);
        let options = decode_options(&rest[3..], 0, MAX_OPTIONS)?;
        Ok(Message {
            kind: MessageType::from(kind),
            xid,
            options,
        })
    }

    /// The bytes of the message.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(u8::from(self.kind));
        out.extend_from_slice(&self.xid.to_be_bytes()[1..]);
        encode_options(&self.options, &mut out);
        out
    }

    /// The client identifier, when present.
    #[must_use]
    pub fn client_id(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|option| match option {
            Dhcp6Option::ClientId(duid) => Some(duid.as_slice()),
            _ => None,
        })
    }

    /// The server identifier, when present.
    #[must_use]
    pub fn server_id(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|option| match option {
            Dhcp6Option::ServerId(duid) => Some(duid.as_slice()),
            _ => None,
        })
    }

    /// The top-level status, when present.
    #[must_use]
    pub fn status(&self) -> Option<(StatusCode, &str)> {
        status_in(&self.options)
    }

    /// Whether a top-level option with `code` is present.
    #[must_use]
    pub fn has(&self, code: u16) -> bool {
        self.options.iter().any(|option| option.code() == code)
    }
}

fn decode_options(mut bytes: &[u8], depth: u8, limit: usize) -> Result<Vec<Dhcp6Option>, Error> {
    let mut options = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(Error::Truncated);
        }
        let code = u16::from_be_bytes([bytes[0], bytes[1]]);
        let len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let body = bytes.get(4..4 + len).ok_or(Error::Truncated)?;
        if options.len() >= limit {
            return Err(Error::TooMany);
        }
        options.push(decode_option(code, body, depth)?);
        bytes = &bytes[4 + len..];
    }
    Ok(options)
}

fn decode_option(code: u16, body: &[u8], depth: u8) -> Result<Dhcp6Option, Error> {
    let bad = || Error::BadOption { code };
    let u32_at = |at: usize| -> Result<u32, Error> {
        body.get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(bad)
    };
    let addr_at = |at: usize| -> Result<Ipv6Addr, Error> {
        body.get(at..at + 16)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .map(Ipv6Addr::from)
            .ok_or_else(bad)
    };
    Ok(match code {
        OPT_CLIENTID => Dhcp6Option::ClientId(body.to_vec()),
        OPT_SERVERID => Dhcp6Option::ServerId(body.to_vec()),
        OPT_IA_NA | OPT_IA_PD | OPT_IAADDR | OPT_IAPREFIX => return decode_ia(code, body, depth),
        OPT_ORO if body.len().is_multiple_of(2) => {
            if body.len() / 2 > MAX_ORO {
                return Err(Error::TooMany);
            }
            Dhcp6Option::Oro(
                body.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_be_bytes(*pair))
                    .collect(),
            )
        }
        OPT_ELAPSED_TIME if body.len() == 2 => {
            Dhcp6Option::ElapsedTime(u16::from_be_bytes([body[0], body[1]]))
        }
        OPT_STATUS_CODE if body.len() >= 2 => Dhcp6Option::StatusCode {
            code: StatusCode::from(u16::from_be_bytes([body[0], body[1]])),
            message: String::from_utf8_lossy(&body[2..]).into_owned(),
        },
        OPT_RAPID_COMMIT if body.is_empty() => Dhcp6Option::RapidCommit,
        OPT_DNS_SERVERS if body.len().is_multiple_of(16) => {
            if body.len() / 16 > MAX_ADDRS {
                return Err(Error::TooMany);
            }
            Dhcp6Option::DnsServers(
                (0..body.len() / 16)
                    .map(|i| addr_at(i * 16))
                    .collect::<Result<_, _>>()?,
            )
        }
        OPT_DOMAIN_LIST => Dhcp6Option::DomainList(decode_names(body).ok_or_else(bad)?),
        OPT_INFORMATION_REFRESH_TIME if body.len() == 4 => {
            Dhcp6Option::InformationRefreshTime(u32_at(0)?)
        }
        OPT_SOL_MAX_RT if body.len() == 4 => Dhcp6Option::SolMaxRt(u32_at(0)?),
        OPT_ORO
        | OPT_ELAPSED_TIME
        | OPT_STATUS_CODE
        | OPT_RAPID_COMMIT
        | OPT_DNS_SERVERS
        | OPT_INFORMATION_REFRESH_TIME
        | OPT_SOL_MAX_RT => return Err(bad()),
        _ => Dhcp6Option::Unknown {
            code,
            data: body.to_vec(),
        },
    })
}

/// An identity association (3, 25), an address (5) or a prefix (26): the fixed fields, then
/// the options nested inside, one level deeper.
fn decode_ia(code: u16, body: &[u8], depth: u8) -> Result<Dhcp6Option, Error> {
    let bad = || Error::BadOption { code };
    let u32_at = |at: usize| -> Result<u32, Error> {
        body.get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(bad)
    };
    let addr_at = |at: usize| -> Result<Ipv6Addr, Error> {
        body.get(at..at + 16)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .map(Ipv6Addr::from)
            .ok_or_else(bad)
    };
    let nested = |from: usize| -> Result<Vec<Dhcp6Option>, Error> {
        if depth >= MAX_DEPTH {
            return Err(bad());
        }
        decode_options(body.get(from..).ok_or_else(bad)?, depth + 1, MAX_IA_OPTIONS)
    };
    Ok(match code {
        OPT_IA_NA | OPT_IA_PD if body.len() >= 12 => {
            let (iaid, t1, t2) = (u32_at(0)?, u32_at(4)?, u32_at(8)?);
            let options = nested(12)?;
            if code == OPT_IA_NA {
                Dhcp6Option::IaNa {
                    iaid,
                    t1,
                    t2,
                    options,
                }
            } else {
                Dhcp6Option::IaPd {
                    iaid,
                    t1,
                    t2,
                    options,
                }
            }
        }
        OPT_IAADDR if body.len() >= 24 => Dhcp6Option::IaAddr {
            addr: addr_at(0)?,
            preferred: u32_at(16)?,
            valid: u32_at(20)?,
            options: nested(24)?,
        },
        OPT_IAPREFIX if body.len() >= 25 => {
            let prefix = Ipv6Net::new(addr_at(9)?, body[8]).map_err(|_| bad())?;
            Dhcp6Option::IaPrefix {
                prefix,
                preferred: u32_at(0)?,
                valid: u32_at(4)?,
                options: nested(25)?,
            }
        }
        _ => return Err(bad()),
    })
}

/// A sequence of DNS wire-format names (RFC 1035 §3.1, no compression) as dotted text; `None`
/// when a label runs past the end, a pointer appears, a name is too long, or there are too many.
fn decode_names(mut bytes: &[u8]) -> Option<Vec<String>> {
    let mut names = Vec::new();
    while !bytes.is_empty() {
        if names.len() >= MAX_NAMES {
            return None;
        }
        let mut name = String::new();
        let mut consumed = 0usize;
        loop {
            let (&len, rest) = bytes.split_first()?;
            bytes = rest;
            consumed += 1;
            if len == 0 {
                break;
            }
            let len = usize::from(len);
            if len > usize::from(MAX_LABEL) {
                return None;
            }
            let label = bytes.get(..len)?;
            bytes = &bytes[len..];
            consumed += len;
            if consumed > MAX_NAME {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(label));
        }
        names.push(name);
    }
    Some(names)
}

fn encode_names(names: &[String], out: &mut Vec<u8>) {
    for name in names {
        for label in name.split('.').filter(|label| !label.is_empty()) {
            let label = &label.as_bytes()[..label.len().min(usize::from(MAX_LABEL))];
            // A label is at most 63 bytes, so the length always fits.
            out.push(u8::try_from(label.len()).unwrap_or(MAX_LABEL));
            out.extend_from_slice(label);
        }
        out.push(0);
    }
}

fn encode_options(options: &[Dhcp6Option], out: &mut Vec<u8>) {
    for option in options {
        out.extend_from_slice(&option.code().to_be_bytes());
        let len_at = out.len();
        out.extend_from_slice(&[0, 0]);
        match option {
            Dhcp6Option::ClientId(duid) | Dhcp6Option::ServerId(duid) => {
                out.extend_from_slice(duid);
            }
            Dhcp6Option::IaNa {
                iaid,
                t1,
                t2,
                options,
            }
            | Dhcp6Option::IaPd {
                iaid,
                t1,
                t2,
                options,
            } => {
                out.extend_from_slice(&iaid.to_be_bytes());
                out.extend_from_slice(&t1.to_be_bytes());
                out.extend_from_slice(&t2.to_be_bytes());
                encode_options(options, out);
            }
            Dhcp6Option::IaAddr {
                addr,
                preferred,
                valid,
                options,
            } => {
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&preferred.to_be_bytes());
                out.extend_from_slice(&valid.to_be_bytes());
                encode_options(options, out);
            }
            Dhcp6Option::IaPrefix {
                prefix,
                preferred,
                valid,
                options,
            } => {
                out.extend_from_slice(&preferred.to_be_bytes());
                out.extend_from_slice(&valid.to_be_bytes());
                out.push(prefix.prefix_len());
                out.extend_from_slice(&prefix.addr().octets());
                encode_options(options, out);
            }
            Dhcp6Option::Oro(codes) => {
                for code in codes {
                    out.extend_from_slice(&code.to_be_bytes());
                }
            }
            Dhcp6Option::ElapsedTime(centis) => out.extend_from_slice(&centis.to_be_bytes()),
            Dhcp6Option::StatusCode { code, message } => {
                out.extend_from_slice(&u16::from(*code).to_be_bytes());
                out.extend_from_slice(message.as_bytes());
            }
            Dhcp6Option::RapidCommit => {}
            Dhcp6Option::DnsServers(addrs) => {
                for addr in addrs {
                    out.extend_from_slice(&addr.octets());
                }
            }
            Dhcp6Option::DomainList(names) => encode_names(names, out),
            Dhcp6Option::InformationRefreshTime(secs) | Dhcp6Option::SolMaxRt(secs) => {
                out.extend_from_slice(&secs.to_be_bytes());
            }
            Dhcp6Option::Unknown { data, .. } => out.extend_from_slice(data),
        }
        let len = u16::try_from(out.len() - len_at - 2).unwrap_or(u16::MAX);
        out[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solicit() -> Message {
        Message {
            kind: MessageType::Solicit,
            xid: 0x00ab_cdef,
            options: vec![
                Dhcp6Option::ClientId(vec![0, 3, 0, 1, 0x52, 0x54, 0, 0xfe, 0, 0]),
                Dhcp6Option::IaPd {
                    iaid: 0x1234_5678,
                    t1: 0,
                    t2: 0,
                    options: vec![Dhcp6Option::IaPrefix {
                        prefix: "::/56".parse().unwrap(),
                        preferred: 0,
                        valid: 0,
                        options: Vec::new(),
                    }],
                },
                Dhcp6Option::IaNa {
                    iaid: 0x8765_4321,
                    t1: 0,
                    t2: 0,
                    options: Vec::new(),
                },
                Dhcp6Option::Oro(vec![23, 24, 82]),
                Dhcp6Option::ElapsedTime(0),
                Dhcp6Option::RapidCommit,
            ],
        }
    }

    #[test]
    fn a_solicit_round_trips() {
        let message = solicit();
        let bytes = message.encode();
        assert_eq!(bytes[0], 1, "Solicit is type 1");
        assert_eq!(&bytes[1..4], &[0xab, 0xcd, 0xef], "the 24-bit xid");
        assert_eq!(Message::decode(&bytes), Ok(message));
    }

    #[test]
    fn a_reply_from_the_rfc_shapes_decodes() {
        let mut bytes = vec![7, 0x00, 0x00, 0x01];
        // Server ID (2), 10 bytes.
        bytes.extend_from_slice(&[0, 2, 0, 10, 0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // Client ID (1), 10 bytes.
        bytes.extend_from_slice(&[0, 1, 0, 10, 0, 3, 0, 1, 0x52, 0x54, 0, 0xfe, 0, 0]);
        // IA_PD (25): iaid, t1 10, t2 16, then IAPREFIX (26) preferred 40 valid 60 len 56
        // prefix 2001:db8:100::.
        let mut ia_pd = vec![0x12, 0x34, 0x56, 0x78, 0, 0, 0, 10, 0, 0, 0, 16];
        let mut ia_prefix = vec![0, 0, 0, 40, 0, 0, 0, 60, 56];
        ia_prefix.extend_from_slice(&"2001:db8:100::".parse::<Ipv6Addr>().unwrap().octets());
        ia_pd.extend_from_slice(&[0, 26, 0, 25]);
        ia_pd.extend_from_slice(&ia_prefix);
        bytes.extend_from_slice(&[0, 25, 0, 41]);
        bytes.extend_from_slice(&ia_pd);
        // IA_NA (3) with IAADDR (5).
        let mut ia_na = vec![0x87, 0x65, 0x43, 0x21, 0, 0, 0, 10, 0, 0, 0, 16];
        let mut ia_addr = "2001:db8:ffff::1a4"
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec();
        ia_addr.extend_from_slice(&[0, 0, 0, 40, 0, 0, 0, 60]);
        ia_na.extend_from_slice(&[0, 5, 0, 24]);
        ia_na.extend_from_slice(&ia_addr);
        bytes.extend_from_slice(&[0, 3, 0, 40]);
        bytes.extend_from_slice(&ia_na);
        // DNS servers (23).
        bytes.extend_from_slice(&[0, 23, 0, 16]);
        bytes.extend_from_slice(&"2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap().octets());
        // Domain list (24): isp.example as labels.
        bytes.extend_from_slice(&[0, 24, 0, 13, 3, b'i', b's', b'p', 7]);
        bytes.extend_from_slice(b"example");
        bytes.push(0);
        // SOL_MAX_RT (82) 3600.
        bytes.extend_from_slice(&[0, 82, 0, 4, 0, 0, 0x0e, 0x10]);

        let message = Message::decode(&bytes).unwrap();
        assert_eq!(message.kind, MessageType::Reply);
        assert_eq!(message.xid, 1);
        assert_eq!(
            message.server_id(),
            Some(&[0u8, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff][..])
        );
        assert_eq!(
            message.client_id(),
            Some(&[0u8, 3, 0, 1, 0x52, 0x54, 0, 0xfe, 0, 0][..])
        );
        assert_eq!(
            message.options[2],
            Dhcp6Option::IaPd {
                iaid: 0x1234_5678,
                t1: 10,
                t2: 16,
                options: vec![Dhcp6Option::IaPrefix {
                    prefix: "2001:db8:100::/56".parse().unwrap(),
                    preferred: 40,
                    valid: 60,
                    options: Vec::new(),
                }],
            }
        );
        assert_eq!(
            message.options[3],
            Dhcp6Option::IaNa {
                iaid: 0x8765_4321,
                t1: 10,
                t2: 16,
                options: vec![Dhcp6Option::IaAddr {
                    addr: "2001:db8:ffff::1a4".parse().unwrap(),
                    preferred: 40,
                    valid: 60,
                    options: Vec::new(),
                }],
            }
        );
        assert_eq!(
            message.options[4],
            Dhcp6Option::DnsServers(vec!["2001:db8:ffff::1".parse().unwrap()])
        );
        assert_eq!(
            message.options[5],
            Dhcp6Option::DomainList(vec!["isp.example".to_owned()])
        );
        assert_eq!(message.options[6], Dhcp6Option::SolMaxRt(3600));
        assert_eq!(
            message.encode(),
            bytes,
            "and encodes back to the same bytes"
        );
    }

    #[test]
    fn a_status_inside_an_ia_decodes() {
        let message = Message {
            kind: MessageType::Reply,
            xid: 7,
            options: vec![Dhcp6Option::IaPd {
                iaid: 1,
                t1: 0,
                t2: 0,
                options: vec![Dhcp6Option::StatusCode {
                    code: StatusCode::NoPrefixAvail,
                    message: "no prefix".to_owned(),
                }],
            }],
        };
        let decoded = Message::decode(&message.encode()).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(
            decoded.options[0].status(),
            Some((StatusCode::NoPrefixAvail, "no prefix"))
        );
        assert_eq!(decoded.status(), None, "no top-level status");
    }

    #[test]
    fn an_overrunning_option_is_truncated() {
        // Header, then option 1 claiming 10 bytes with 3 present.
        let bytes = [1, 0, 0, 1, 0, 1, 0, 10, 0xaa, 0xbb, 0xcc];
        assert_eq!(Message::decode(&bytes), Err(Error::Truncated));
        // An option header cut in half.
        assert_eq!(Message::decode(&[1, 0, 0, 1, 0, 1]), Err(Error::Truncated));
    }

    #[test]
    fn too_many_options_is_too_many() {
        let mut bytes = vec![1, 0, 0, 1];
        for _ in 0..=MAX_OPTIONS {
            bytes.extend_from_slice(&[0, 14, 0, 0]);
        }
        assert_eq!(Message::decode(&bytes), Err(Error::TooMany));
        let mut ok = vec![1, 0, 0, 1];
        for _ in 0..MAX_OPTIONS {
            ok.extend_from_slice(&[0, 14, 0, 0]);
        }
        assert_eq!(Message::decode(&ok).unwrap().options.len(), MAX_OPTIONS);
    }

    #[test]
    fn a_malformed_known_option_is_bad() {
        // Rapid Commit with a body; Elapsed Time with three bytes; an IAPREFIX of length 200.
        assert_eq!(
            Message::decode(&[1, 0, 0, 1, 0, 14, 0, 1, 0]),
            Err(Error::BadOption { code: 14 })
        );
        assert_eq!(
            Message::decode(&[1, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0]),
            Err(Error::BadOption { code: 8 })
        );
        let mut bytes = vec![7, 0, 0, 1, 0, 26, 0, 25, 0, 0, 0, 1, 0, 0, 0, 1, 200];
        bytes.extend_from_slice(&[0; 16]);
        assert_eq!(Message::decode(&bytes), Err(Error::BadOption { code: 26 }));
    }

    #[test]
    fn nesting_stops_at_the_protocols_depth() {
        // IA_PD → IAPREFIX → IA_PD: the innermost container is one level too deep.
        let inner = Message {
            kind: MessageType::Reply,
            xid: 1,
            options: vec![Dhcp6Option::IaPd {
                iaid: 1,
                t1: 0,
                t2: 0,
                options: vec![Dhcp6Option::IaPrefix {
                    prefix: "2001:db8::/48".parse().unwrap(),
                    preferred: 1,
                    valid: 1,
                    options: vec![Dhcp6Option::IaPd {
                        iaid: 2,
                        t1: 0,
                        t2: 0,
                        options: Vec::new(),
                    }],
                }],
            }],
        };
        assert_eq!(
            Message::decode(&inner.encode()),
            Err(Error::BadOption { code: 25 })
        );
    }

    #[test]
    fn an_unknown_option_round_trips() {
        let message = Message {
            kind: MessageType::Other(200),
            xid: 0xff_ffff,
            options: vec![Dhcp6Option::Unknown {
                code: 0x1234,
                data: vec![1, 2, 3],
            }],
        };
        assert_eq!(Message::decode(&message.encode()), Ok(message));
    }

    #[test]
    fn a_three_byte_message_is_truncated() {
        assert_eq!(Message::decode(&[1, 0, 0]), Err(Error::Truncated));
        assert_eq!(Message::decode(&[]), Err(Error::Truncated));
        assert_eq!(
            Message::decode(&[11, 1, 2, 3]),
            Ok(Message::new(MessageType::InformationRequest, 0x0001_0203))
        );
    }

    #[test]
    fn a_domain_list_refuses_pointers_and_long_labels() {
        assert_eq!(
            Message::decode(&[7, 0, 0, 1, 0, 24, 0, 2, 0xc0, 0x0c]),
            Err(Error::BadOption { code: 24 })
        );
        let mut bytes = vec![7, 0, 0, 1, 0, 24, 0, 65, 64];
        bytes.extend_from_slice(&[b'a'; 64]);
        assert_eq!(Message::decode(&bytes), Err(Error::BadOption { code: 24 }));
        // A label cut short by the option's end.
        assert_eq!(
            Message::decode(&[7, 0, 0, 1, 0, 24, 0, 2, 5, b'a']),
            Err(Error::BadOption { code: 24 })
        );
    }

    #[test]
    fn message_and_status_types_map_both_ways() {
        for byte in 0..=u8::MAX {
            assert_eq!(u8::from(MessageType::from(byte)), byte);
        }
        for code in [0u16, 1, 2, 3, 4, 5, 6, 7, 999] {
            assert_eq!(u16::from(StatusCode::from(code)), code);
        }
        assert_eq!(MessageType::from(11), MessageType::InformationRequest);
        assert_eq!(StatusCode::from(6), StatusCode::NoPrefixAvail);
    }
}
