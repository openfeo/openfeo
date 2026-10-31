// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DNS message format (RFC 1035 §4, RFC 6891 for EDNS0): header, questions and the four
//! sections of resource records, with name compression on the way out and compression pointers
//! followed on the way in. Record types a forwarder must look inside are typed; everything else
//! is carried as bytes (RFC 3597).

use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use crate::name::{Name, NameError};

/// The Internet class.
pub const CLASS_IN: u16 = 1;
/// Any class (QCLASS only).
pub const CLASS_ANY: u16 = 255;

/// Record types the forwarder knows by name.
pub mod rtype {
    pub const A: u16 = 1;
    pub const NS: u16 = 2;
    pub const CNAME: u16 = 5;
    pub const SOA: u16 = 6;
    pub const PTR: u16 = 12;
    pub const MX: u16 = 15;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const OPT: u16 = 41;
    pub const ANY: u16 = 255;
}

/// Response codes (RFC 1035 §4.1.1).
pub mod rcode {
    pub const NOERROR: u8 = 0;
    pub const FORMERR: u8 = 1;
    pub const SERVFAIL: u8 = 2;
    pub const NXDOMAIN: u8 = 3;
    pub const NOTIMP: u8 = 4;
    pub const REFUSED: u8 = 5;
}

/// A standard query.
pub const OPCODE_QUERY: u8 = 0;
/// What a client without EDNS can take over UDP.
pub const UDP_PAYLOAD_PLAIN: usize = 512;
/// The UDP payload size we advertise (SPEC §7.7).
pub const EDNS_UDP_PAYLOAD: u16 = 1232;
/// The longest message (a TCP length prefix is two bytes).
pub const MAX_MESSAGE: usize = 65_535;

const HEADER_LEN: usize = 12;
/// The largest offset a compression pointer can carry.
const MAX_POINTER: usize = 0x3fff;

/// The message header (RFC 1035 §4.1.1), counts aside: one field per flag bit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct Header {
    pub id: u16,
    /// QR.
    pub response: bool,
    pub opcode: u8,
    /// AA.
    pub authoritative: bool,
    /// TC.
    pub truncated: bool,
    /// RD.
    pub recursion_desired: bool,
    /// RA.
    pub recursion_available: bool,
    /// AD (RFC 4035).
    pub authentic_data: bool,
    /// CD (RFC 4035).
    pub checking_disabled: bool,
    pub rcode: u8,
}

/// One question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    pub qclass: u16,
}

/// The fields of an OPT record (RFC 6891 §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns {
    pub udp_payload: u16,
    pub extended_rcode: u8,
    pub version: u8,
    /// DO.
    pub dnssec_ok: bool,
    /// Option code and data, in order.
    pub options: Vec<(u16, Vec<u8>)>,
}

/// Record data: typed where the forwarder must look inside, bytes otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Name),
    Ns(Name),
    Ptr(Name),
    Mx {
        preference: u16,
        exchange: Name,
    },
    Soa {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// Character strings, each up to 255 bytes.
    Txt(Vec<Vec<u8>>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    Opt(Edns),
    /// Any other type: the RDATA as received, never compressed (RFC 3597).
    Other(Vec<u8>),
}

/// One resource record. For an OPT record, [`RData::Opt`] is authoritative: encoding writes the
/// class and TTL from it, decoding fills it from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: RData,
}

/// A whole message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

/// Why bytes are not a DNS message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("{0} bytes is too short for a header")]
    TooShort(usize),
    #[error("message ends inside {0}")]
    Truncated(&'static str),
    #[error("bad compression pointer")]
    Pointer,
    #[error("{0}")]
    Name(#[from] NameError),
}

impl Header {
    fn decode(bytes: &[u8]) -> Header {
        let flags_hi = bytes[2];
        let flags_lo = bytes[3];
        Header {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            response: flags_hi & 0x80 != 0,
            opcode: (flags_hi >> 3) & 0x0f,
            authoritative: flags_hi & 0x04 != 0,
            truncated: flags_hi & 0x02 != 0,
            recursion_desired: flags_hi & 0x01 != 0,
            recursion_available: flags_lo & 0x80 != 0,
            authentic_data: flags_lo & 0x20 != 0,
            checking_disabled: flags_lo & 0x10 != 0,
            rcode: flags_lo & 0x0f,
        }
    }

    fn flags(&self) -> [u8; 2] {
        let hi = (u8::from(self.response) << 7)
            | ((self.opcode & 0x0f) << 3)
            | (u8::from(self.authoritative) << 2)
            | (u8::from(self.truncated) << 1)
            | u8::from(self.recursion_desired);
        let lo = (u8::from(self.recursion_available) << 7)
            | (u8::from(self.authentic_data) << 5)
            | (u8::from(self.checking_disabled) << 4)
            | (self.rcode & 0x0f);
        [hi, lo]
    }
}

impl Message {
    /// Parse a message. Compression pointers must point backwards; bytes after the last
    /// section are ignored.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for a short or malformed message.
    pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        if bytes.len() < HEADER_LEN {
            return Err(DecodeError::TooShort(bytes.len()));
        }
        let header = Header::decode(bytes);
        let count = |at: usize| usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
        let mut cursor = Cursor {
            bytes,
            pos: HEADER_LEN,
        };
        let mut questions = Vec::with_capacity(count(4).min(16));
        for _ in 0..count(4) {
            let name = cursor.name("question")?;
            let qtype = cursor.u16("question")?;
            let qclass = cursor.u16("question")?;
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }
        let answers = cursor.records(count(6), "answer")?;
        let authorities = cursor.records(count(8), "authority")?;
        let additionals = cursor.records(count(10), "additional")?;
        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// The message on the wire, names compressed, with no size limit.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(&self.header, self);
        for question in &self.questions {
            encoder.name(&question.name);
            encoder.u16(question.qtype);
            encoder.u16(question.qclass);
        }
        for record in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
        {
            encoder.record(record);
        }
        encoder.out
    }

    /// The message in at most `max` bytes: additionals other than OPT go first, then
    /// authorities, then answers, from the end; TC is set once an answer or authority was
    /// dropped (RFC 2181 §9).
    #[must_use]
    pub fn encode_within(&self, max: usize) -> Vec<u8> {
        let mut trimmed = self.clone();
        loop {
            let bytes = trimmed.encode();
            if bytes.len() <= max {
                return bytes;
            }
            if trimmed
                .additionals
                .iter()
                .any(|record| record.rtype != rtype::OPT)
            {
                trimmed
                    .additionals
                    .retain(|record| record.rtype == rtype::OPT);
            } else if trimmed.authorities.pop().is_some() || trimmed.answers.pop().is_some() {
                trimmed.header.truncated = true;
            } else if !trimmed.additionals.is_empty() {
                trimmed.additionals.clear();
            } else {
                return bytes;
            }
        }
    }

    /// The first question.
    #[must_use]
    pub fn question(&self) -> Option<&Question> {
        self.questions.first()
    }

    /// The OPT record's fields, when the message carries one.
    #[must_use]
    pub fn edns(&self) -> Option<&Edns> {
        self.additionals
            .iter()
            .find_map(|record| match &record.rdata {
                RData::Opt(edns) if record.rtype == rtype::OPT => Some(edns),
                _ => None,
            })
    }

    /// The largest UDP reply the sender can take: its OPT's payload size (at least 512), else
    /// 512.
    #[must_use]
    pub fn max_udp_payload(&self) -> usize {
        self.edns().map_or(UDP_PAYLOAD_PLAIN, |edns| {
            usize::from(edns.udp_payload).max(UDP_PAYLOAD_PLAIN)
        })
    }

    /// A reply to `query` with `rcode`: id, opcode, RD and CD copied, QR set, the question
    /// copied, nothing else.
    #[must_use]
    pub fn reply_to(query: &Message, rcode: u8) -> Message {
        Message {
            header: Header {
                id: query.header.id,
                response: true,
                opcode: query.header.opcode,
                recursion_desired: query.header.recursion_desired,
                checking_disabled: query.header.checking_disabled,
                rcode,
                ..Header::default()
            },
            questions: query.questions.clone(),
            ..Message::default()
        }
    }
}

/// The TTL field of an OPT record: extended RCODE, version, the DO flag (RFC 6891 §6.1.3).
fn edns_ttl(edns: &Edns) -> u32 {
    u32::from_be_bytes([
        edns.extended_rcode,
        edns.version,
        if edns.dnssec_ok { 0x80 } else { 0 },
        0,
    ])
}

/// A read position in a message.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize, section: &'static str) -> Result<&[u8], DecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DecodeError::Truncated(section))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated(section))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self, section: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, section)?[0])
    }

    fn u16(&mut self, section: &'static str) -> Result<u16, DecodeError> {
        let b = self.take(2, section)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, section: &'static str) -> Result<u32, DecodeError> {
        let b = self.take(4, section)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A name at the cursor, following compression pointers; the cursor ends after the first
    /// pointer or the root label. Every pointer must land below the lowest offset the name has
    /// reached so far: "strictly backwards" alone still allows a cycle (a pointer to a label
    /// that leads back to the same pointer), which would collect labels without end.
    fn name(&mut self, section: &'static str) -> Result<Name, DecodeError> {
        let mut labels = Vec::new();
        let mut pos = self.pos;
        let mut lowest = self.pos;
        let mut wire_len = 0usize;
        let mut end = None;
        loop {
            let len = *self.bytes.get(pos).ok_or(DecodeError::Truncated(section))?;
            match len & 0xc0 {
                0xc0 => {
                    let low = *self
                        .bytes
                        .get(pos + 1)
                        .ok_or(DecodeError::Truncated(section))?;
                    let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                    if target >= lowest {
                        return Err(DecodeError::Pointer);
                    }
                    end.get_or_insert(pos + 2);
                    lowest = target;
                    pos = target;
                }
                0 => {
                    if len == 0 {
                        end.get_or_insert(pos + 1);
                        break;
                    }
                    let label = self
                        .bytes
                        .get(pos + 1..pos + 1 + usize::from(len))
                        .ok_or(DecodeError::Truncated(section))?;
                    wire_len += 1 + usize::from(len);
                    if wire_len >= crate::name::MAX_NAME {
                        return Err(NameError::NameTooLong.into());
                    }
                    labels.push(label.to_vec());
                    pos += 1 + usize::from(len);
                }
                _ => return Err(DecodeError::Pointer),
            }
        }
        self.pos = end.unwrap_or(pos);
        Ok(Name::from_labels(labels)?)
    }

    fn records(&mut self, n: usize, section: &'static str) -> Result<Vec<Record>, DecodeError> {
        let mut records = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            records.push(self.record(section)?);
        }
        Ok(records)
    }

    fn record(&mut self, section: &'static str) -> Result<Record, DecodeError> {
        let name = self.name(section)?;
        let rtype = self.u16(section)?;
        let class = self.u16(section)?;
        let ttl = self.u32(section)?;
        let rdlen = usize::from(self.u16(section)?);
        let start = self.pos;
        let end = start
            .checked_add(rdlen)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(DecodeError::Truncated(section))?;
        let rdata = self.rdata(rtype, start, end, class, ttl)?;
        self.pos = end;
        // An OPT record's class and TTL are its EDNS fields: keep them in the form encoding
        // writes, so a decoded message re-encodes to itself.
        let (class, ttl) = if let RData::Opt(edns) = &rdata {
            (edns.udp_payload, edns_ttl(edns))
        } else {
            (class, ttl)
        };
        Ok(Record {
            name,
            rtype,
            class,
            ttl,
            rdata,
        })
    }

    /// The RDATA between `start` and `end`, typed where we know the type. Names inside may be
    /// compressed against the whole message.
    fn rdata(
        &self,
        rtype: u16,
        start: usize,
        end: usize,
        class: u16,
        ttl: u32,
    ) -> Result<RData, DecodeError> {
        let raw = &self.bytes[start..end];
        // Zero-length RDATA of a typed record (RFC 2136 uses them in updates) is empty data,
        // not an error; an OPT with no options is the ordinary EDNS case and stays typed.
        if raw.is_empty() && rtype != rtype::OPT {
            return Ok(RData::Other(Vec::new()));
        }
        let mut inner = Cursor {
            bytes: self.bytes,
            pos: start,
        };
        let section = "rdata";
        let rdata = match rtype {
            rtype::A => {
                let b = inner.take(4, section)?;
                RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            rtype::AAAA => {
                let b = inner.take(16, section)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(b);
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            rtype::CNAME => RData::Cname(inner.name(section)?),
            rtype::NS => RData::Ns(inner.name(section)?),
            rtype::PTR => RData::Ptr(inner.name(section)?),
            rtype::MX => RData::Mx {
                preference: inner.u16(section)?,
                exchange: inner.name(section)?,
            },
            rtype::SOA => RData::Soa {
                mname: inner.name(section)?,
                rname: inner.name(section)?,
                serial: inner.u32(section)?,
                refresh: inner.u32(section)?,
                retry: inner.u32(section)?,
                expire: inner.u32(section)?,
                minimum: inner.u32(section)?,
            },
            rtype::TXT => {
                let mut strings = Vec::new();
                while inner.pos < end {
                    let len = usize::from(inner.u8(section)?);
                    strings.push(inner.take(len, section)?.to_vec());
                }
                RData::Txt(strings)
            }
            rtype::SRV => RData::Srv {
                priority: inner.u16(section)?,
                weight: inner.u16(section)?,
                port: inner.u16(section)?,
                target: inner.name(section)?,
            },
            rtype::OPT => {
                // Options live within the RDATA; an incomplete last option is dropped rather
                // than failing the message, as hickory does (found by the differential target).
                let mut options = Vec::new();
                while inner.pos + 4 <= end {
                    let code = inner.u16(section)?;
                    let len = usize::from(inner.u16(section)?);
                    if inner.pos + len > end {
                        break;
                    }
                    let data = inner.take(len, section)?;
                    options.push((code, data.to_vec()));
                }
                inner.pos = end;
                let [extended_rcode, version, flags_hi, _] = ttl.to_be_bytes();
                RData::Opt(Edns {
                    udp_payload: class,
                    extended_rcode,
                    version,
                    dnssec_ok: flags_hi & 0x80 != 0,
                    options,
                })
            }
            _ => RData::Other(raw.to_vec()),
        };
        if inner.pos > end {
            return Err(DecodeError::Truncated(section));
        }
        Ok(rdata)
    }
}

/// Writes a message, compressing names against every name written so far.
struct Encoder<'a> {
    out: Vec<u8>,
    /// Suffixes already written and where: the labels from some label to the end, and that
    /// label's offset.
    known: Vec<(&'a [Vec<u8>], usize)>,
}

impl<'a> Encoder<'a> {
    fn new(header: &Header, message: &Message) -> Encoder<'a> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&header.id.to_be_bytes());
        out.extend_from_slice(&header.flags());
        for count in [
            message.questions.len(),
            message.answers.len(),
            message.authorities.len(),
            message.additionals.len(),
        ] {
            out.extend_from_slice(&u16::try_from(count).unwrap_or(u16::MAX).to_be_bytes());
        }
        Encoder {
            out,
            known: Vec::new(),
        }
    }

    fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    /// A name, compressed: the longest suffix already written becomes a pointer.
    fn name(&mut self, name: &'a Name) {
        let labels = name.labels();
        for (i, label) in labels.iter().enumerate() {
            let suffix = &labels[i..];
            if let Some((_, offset)) = self.known.iter().find(|(known, _)| *known == suffix) {
                let pointer = 0xc000 | u16::try_from(*offset).unwrap_or(0);
                self.u16(pointer);
                return;
            }
            if self.out.len() <= MAX_POINTER {
                self.known.push((suffix, self.out.len()));
            }
            self.out.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
            self.out.extend_from_slice(label);
        }
        self.out.push(0);
    }

    /// A name written in full, for RDATA that must not be compressed (RFC 3597, RFC 2782).
    fn plain_name(&mut self, name: &Name) {
        for label in name.labels() {
            self.out.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
            self.out.extend_from_slice(label);
        }
        self.out.push(0);
    }

    fn record(&mut self, record: &'a Record) {
        self.name(&record.name);
        self.u16(record.rtype);
        if let RData::Opt(edns) = &record.rdata {
            self.u16(edns.udp_payload);
            self.u32(edns_ttl(edns));
        } else {
            self.u16(record.class);
            self.u32(record.ttl);
        }
        let rdlen_at = self.out.len();
        self.u16(0);
        let start = self.out.len();
        match &record.rdata {
            RData::A(addr) => self.out.extend_from_slice(&addr.octets()),
            RData::Aaaa(addr) => self.out.extend_from_slice(&addr.octets()),
            RData::Cname(name) | RData::Ns(name) | RData::Ptr(name) => self.name(name),
            RData::Mx {
                preference,
                exchange,
            } => {
                self.u16(*preference);
                self.name(exchange);
            }
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                self.name(mname);
                self.name(rname);
                for value in [serial, refresh, retry, expire, minimum] {
                    self.u32(*value);
                }
            }
            RData::Txt(strings) => {
                for string in strings {
                    let len = string.len().min(255);
                    self.out.push(u8::try_from(len).unwrap_or(u8::MAX));
                    self.out.extend_from_slice(&string[..len]);
                }
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                self.u16(*priority);
                self.u16(*weight);
                self.u16(*port);
                self.plain_name(target);
            }
            RData::Opt(edns) => {
                for (code, data) in &edns.options {
                    self.u16(*code);
                    self.u16(u16::try_from(data.len()).unwrap_or(u16::MAX));
                    self.out.extend_from_slice(data);
                }
            }
            RData::Other(bytes) => self.out.extend_from_slice(bytes),
        }
        let rdlen = u16::try_from(self.out.len() - start).unwrap_or(u16::MAX);
        self.out[rdlen_at..rdlen_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    fn query(qname: &str, qtype: u16) -> Message {
        Message {
            header: Header {
                id: 0x1234,
                recursion_desired: true,
                ..Header::default()
            },
            questions: vec![Question {
                name: name(qname),
                qtype,
                qclass: CLASS_IN,
            }],
            ..Message::default()
        }
    }

    fn rr(owner: &str, rtype: u16, ttl: u32, rdata: RData) -> Record {
        Record {
            name: name(owner),
            rtype,
            class: CLASS_IN,
            ttl,
            rdata,
        }
    }

    fn opt(udp_payload: u16, dnssec_ok: bool, options: Vec<(u16, Vec<u8>)>) -> Record {
        Record {
            name: Name::root(),
            rtype: rtype::OPT,
            class: udp_payload,
            ttl: if dnssec_ok { 0x8000 } else { 0 },
            rdata: RData::Opt(Edns {
                udp_payload,
                extended_rcode: 0,
                version: 0,
                dnssec_ok,
                options,
            }),
        }
    }

    fn all_types_message() -> Message {
        let mut m = Message::reply_to(&query("all.example", rtype::ANY), rcode::NOERROR);
        m.answers = vec![
            rr(
                "all.example",
                rtype::A,
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            ),
            rr(
                "all.example",
                rtype::AAAA,
                60,
                RData::Aaaa("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            ),
            rr(
                "alias.example",
                rtype::CNAME,
                60,
                RData::Cname(name("all.example")),
            ),
            rr("example", rtype::NS, 60, RData::Ns(name("ns.example"))),
            rr(
                "1.2.0.192.in-addr.arpa",
                rtype::PTR,
                60,
                RData::Ptr(name("all.example")),
            ),
            rr(
                "example",
                rtype::MX,
                60,
                RData::Mx {
                    preference: 10,
                    exchange: name("mail.example"),
                },
            ),
            rr(
                "example",
                rtype::SOA,
                60,
                RData::Soa {
                    mname: name("ns.example"),
                    rname: name("hostmaster.example"),
                    serial: 1,
                    refresh: 3600,
                    retry: 600,
                    expire: 86_400,
                    minimum: 60,
                },
            ),
            rr(
                "all.example",
                rtype::TXT,
                60,
                RData::Txt(vec![b"hello".to_vec(), Vec::new()]),
            ),
            rr(
                "_sip._tcp.example",
                rtype::SRV,
                60,
                RData::Srv {
                    priority: 1,
                    weight: 2,
                    port: 5060,
                    target: name("sip.example"),
                },
            ),
            rr("all.example", 99, 60, RData::Other(vec![1, 2, 3])),
        ];
        m.additionals
            .push(opt(1232, true, vec![(10, vec![0xde, 0xad])]));
        m
    }

    #[test]
    fn a_query_encodes_to_the_rfc_1035_layout_and_back() {
        let q = query("nas.home.arpa", rtype::A);
        let bytes = q.encode();
        assert_eq!(
            &bytes[..12],
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            &bytes[12..],
            &[
                3, b'n', b'a', b's', 4, b'h', b'o', b'm', b'e', 4, b'a', b'r', b'p', b'a', 0, 0, 1,
                0, 1
            ]
        );
        assert_eq!(Message::decode(&bytes), Ok(q));
    }

    #[test]
    fn answers_compress_names_and_decode_pointers() {
        let mut m = Message::reply_to(&query("www.isp.example", rtype::A), rcode::NOERROR);
        m.answers.push(rr(
            "www.isp.example",
            rtype::A,
            60,
            RData::A(Ipv4Addr::new(198, 51, 100, 10)),
        ));
        m.authorities.push(rr(
            "isp.example",
            rtype::NS,
            60,
            RData::Ns(name("ns.isp.example")),
        ));
        let bytes = m.encode();
        assert_eq!(
            &bytes[12 + 21..12 + 21 + 2],
            &[0xc0, 0x0c],
            "the answer's owner is a pointer to the question's name"
        );
        assert!(
            bytes.len() < 12 + 21 + 2 + 14 + 2 + 14 + 10,
            "the NS target reuses the suffix: {} bytes",
            bytes.len()
        );
        assert_eq!(Message::decode(&bytes), Ok(m));
    }

    #[test]
    fn every_typed_rdata_round_trips() {
        let m = all_types_message();
        assert_eq!(Message::decode(&m.encode()), Ok(m.clone()));
        assert_eq!(
            m.edns().map(|e| (e.udp_payload, e.dnssec_ok)),
            Some((1232, true))
        );
        assert_eq!(m.max_udp_payload(), 1232);
        assert_eq!(query("x.example", rtype::A).max_udp_payload(), 512);
    }

    #[test]
    fn decoding_refuses_forward_pointers_loops_and_short_messages() {
        assert_eq!(Message::decode(&[0; 11]), Err(DecodeError::TooShort(11)));
        let mut loop_name = query("a.example", rtype::A).encode();
        loop_name[12] = 0xc0;
        loop_name[13] = 12;
        assert_eq!(Message::decode(&loop_name), Err(DecodeError::Pointer));
        let mut forward = query("a.example", rtype::A).encode();
        forward[12] = 0xc0;
        forward[13] = 0x20;
        assert_eq!(Message::decode(&forward), Err(DecodeError::Pointer));
        let cut = query("a.example", rtype::A).encode();
        assert_eq!(
            Message::decode(&cut[..cut.len() - 1]),
            Err(DecodeError::Truncated("question"))
        );
        let mut trailing = query("a.example", rtype::A).encode();
        trailing.extend_from_slice(&[0, 0, 0]);
        assert!(
            Message::decode(&trailing).is_ok(),
            "trailing bytes are ignored"
        );
    }

    /// Found by the `dns_differential` fuzz target: an OPT whose last option is cut short by
    /// RDLENGTH keeps the options before it, as hickory reads it.
    #[test]
    fn an_incomplete_trailing_edns_option_is_dropped() {
        let mut m = query("www.isp.example", rtype::AAAA);
        m.additionals
            .push(opt(1232, true, vec![(0x3401, vec![]), (0, vec![0; 16])]));
        let mut bytes = m.encode();
        // The OPT's RDLENGTH is the last two bytes before its options: shrink it to 4 + 2,
        // keeping the first option whole and 2 of the second option's 20 bytes.
        let rdlen_at = bytes.len() - 4 - 20 - 2;
        bytes[rdlen_at..rdlen_at + 2].copy_from_slice(&6u16.to_be_bytes());
        bytes.truncate(rdlen_at + 2 + 6);
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(
            decoded.edns().map(|e| e.options.clone()),
            Some(vec![(0x3401, vec![])])
        );
    }

    /// Found by the `dns_differential` fuzz target: a typed record with RDLENGTH 0 (RFC 2136's
    /// update prerequisites use them) is empty data, as hickory reads it, not a short SOA.
    #[test]
    fn zero_length_rdata_of_a_typed_record_is_empty_data() {
        let mut m = Message::reply_to(&query("nx.isp.example", rtype::A), rcode::NXDOMAIN);
        m.authorities
            .push(rr("isp.example", rtype::SOA, 0, RData::Other(Vec::new())));
        let decoded = Message::decode(&m.encode()).unwrap();
        assert_eq!(decoded.authorities[0].rdata, RData::Other(Vec::new()));
        let mut edns_only = query("x.example", rtype::A);
        edns_only.additionals.push(opt(1232, false, vec![]));
        assert_eq!(
            Message::decode(&edns_only.encode())
                .unwrap()
                .edns()
                .map(|e| e.options.len()),
            Some(0),
            "an OPT with no options stays an OPT"
        );
    }

    /// Found by the `dns_message` fuzz target as an out-of-memory input: a label followed by a
    /// pointer back to that label points "backwards" and loops forever.
    #[test]
    fn decoding_refuses_pointer_cycles() {
        let mut cycle = query("a.example", rtype::A).encode();
        cycle.truncate(12);
        cycle.extend_from_slice(&[1, b'a', 0xc0, 0x0c, 0, 1, 0, 1]);
        assert_eq!(Message::decode(&cycle), Err(DecodeError::Pointer));
    }

    #[test]
    fn encode_within_drops_sections_and_sets_tc() {
        let mut m = Message::reply_to(&query("big.isp.example", rtype::TXT), rcode::NOERROR);
        for _ in 0..3 {
            m.answers.push(rr(
                "big.isp.example",
                rtype::TXT,
                60,
                RData::Txt(vec![vec![b'x'; 250]]),
            ));
        }
        m.additionals.push(opt(1232, false, vec![]));
        assert!(m.encode().len() > 700);
        let small = Message::decode(&m.encode_within(512)).unwrap();
        assert!(small.header.truncated && small.answers.len() < 3 && small.edns().is_some());
        assert!(m.encode_within(512).len() <= 512);
        let whole = Message::decode(&m.encode_within(1232)).unwrap();
        assert!(!whole.header.truncated && whole.answers.len() == 3);
    }

    #[test]
    fn reply_to_copies_only_what_rfc_1035_says() {
        let mut q = query("x.example", rtype::A);
        q.header.checking_disabled = true;
        let r = Message::reply_to(&q, rcode::NXDOMAIN);
        assert_eq!(
            (
                r.header.id,
                r.header.response,
                r.header.recursion_desired,
                r.header.checking_disabled,
                r.header.rcode
            ),
            (0x1234, true, true, true, rcode::NXDOMAIN)
        );
        assert_eq!(r.questions, q.questions);
        assert!(r.answers.is_empty() && r.additionals.is_empty());
    }

    /// Seeds for `fuzz/fuzz_targets/dns_message.rs` and `dns_differential.rs`; run with
    /// `--ignored` to refresh them.
    #[test]
    #[ignore = "writes the fuzz corpus seeds"]
    fn write_dns_fuzz_corpus() {
        let mut nx = Message::reply_to(&query("nx.isp.example", rtype::A), rcode::NXDOMAIN);
        nx.authorities.push(rr(
            "isp.example",
            rtype::SOA,
            60,
            RData::Soa {
                mname: name("ns.isp.example"),
                rname: name("hostmaster.isp.example"),
                serial: 1,
                refresh: 30,
                retry: 30,
                expire: 30,
                minimum: 60,
            },
        ));
        let mut edns = query("www.isp.example", rtype::AAAA);
        edns.additionals.push(opt(1232, true, vec![]));
        let seeds = [
            ("seed-query.bin", query("nas.home.arpa", rtype::A).encode()),
            ("seed-answer.bin", all_types_message().encode()),
            ("seed-nxdomain.bin", nx.encode()),
            ("seed-edns.bin", edns.encode()),
        ];
        for target in ["dns_message", "dns_differential"] {
            let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fuzz/corpus")
                .join(target);
            std::fs::create_dir_all(&dir).unwrap();
            for (file, bytes) in &seeds {
                std::fs::write(dir.join(file), bytes).unwrap();
            }
        }
    }
}
