// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv4 message (RFC 2131 §2, RFC 2132 options): a fixed 236-byte header, the magic
//! cookie, and TLV options. Decoding joins repeated option codes (RFC 3396), reads options
//! overloaded into `sname` and `file` (option 52), skips padding, accepts a missing END, and
//! turns a known option with a malformed payload into [`DhcpOption::Unknown`] rather than
//! failing the message. Encoding writes options in order, splits any longer than 255 bytes
//! (RFC 3396), ends with END and pads to [`MIN_MESSAGE_LEN`].

use std::net::Ipv4Addr;
use std::ops::Range;

use thiserror::Error;

/// Servers and relays listen here.
pub const SERVER_PORT: u16 = 67;
/// Clients listen here.
pub const CLIENT_PORT: u16 = 68;
/// Follows the fixed header; its absence means "not DHCP".
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// `flags` bit asking servers and relays to broadcast their replies (RFC 2131 §4.1).
pub const FLAG_BROADCAST: u16 = 0x8000;
/// Encoded messages are padded to this (RFC 2131 §2: a BOOTP-sized minimum for old relays).
pub const MIN_MESSAGE_LEN: usize = 300;
/// The fixed header before the cookie.
pub const HEADER_LEN: usize = 236;

const COOKIE_END: usize = HEADER_LEN + MAGIC_COOKIE.len();
const SNAME: Range<usize> = 44..108;
const FILE: Range<usize> = 108..236;
const OPT_PAD: u8 = 0;
const OPT_END: u8 = 255;
const OVERLOAD_FILE: u8 = 1;
const OVERLOAD_SNAME: u8 = 2;
const MAX_OPTION_LEN: usize = 255;

/// The `op` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// From a client.
    BootRequest = 1,
    /// From a server.
    BootReply = 2,
}

/// Option 53.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    /// A value this crate does not know.
    Other(u8),
}

impl MessageType {
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => MessageType::Discover,
            2 => MessageType::Offer,
            3 => MessageType::Request,
            4 => MessageType::Decline,
            5 => MessageType::Ack,
            6 => MessageType::Nak,
            7 => MessageType::Release,
            8 => MessageType::Inform,
            other => MessageType::Other(other),
        }
    }

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            MessageType::Discover => 1,
            MessageType::Offer => 2,
            MessageType::Request => 3,
            MessageType::Decline => 4,
            MessageType::Ack => 5,
            MessageType::Nak => 6,
            MessageType::Release => 7,
            MessageType::Inform => 8,
            MessageType::Other(other) => other,
        }
    }
}

/// One route of option 121 or 249 (RFC 3442): `dst/prefix via`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClasslessRoute {
    pub dst: Ipv4Addr,
    pub prefix: u8,
    pub via: Ipv4Addr,
}

/// The options this crate types; everything else is [`DhcpOption::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    /// 1
    SubnetMask(Ipv4Addr),
    /// 3
    Router(Vec<Ipv4Addr>),
    /// 6
    DomainNameServer(Vec<Ipv4Addr>),
    /// 12
    HostName(String),
    /// 15
    DomainName(String),
    /// 26
    InterfaceMtu(u16),
    /// 28
    BroadcastAddr(Ipv4Addr),
    /// 42
    NtpServers(Vec<Ipv4Addr>),
    /// 50
    RequestedIpAddress(Ipv4Addr),
    /// 51, seconds.
    AddressLeaseTime(u32),
    /// 52: bit 1 = `file` holds options, bit 2 = `sname` does.
    OptionOverload(u8),
    /// 53
    MessageType(MessageType),
    /// 54
    ServerIdentifier(Ipv4Addr),
    /// 55, option codes.
    ParameterRequestList(Vec<u8>),
    /// 56, a server's text (with NAKs).
    Message(String),
    /// 57
    MaxMessageSize(u16),
    /// 58, T1 seconds.
    Renewal(u32),
    /// 59, T2 seconds.
    Rebinding(u32),
    /// 60
    VendorClass(Vec<u8>),
    /// 61
    ClientIdentifier(Vec<u8>),
    /// 121
    ClasslessStaticRoute(Vec<ClasslessRoute>),
    /// 249, Microsoft's pre-standard copy of 121.
    MsClasslessStaticRoute(Vec<ClasslessRoute>),
    /// Any other code, or a known code whose payload did not have the option's shape.
    Unknown { code: u8, data: Vec<u8> },
}

impl DhcpOption {
    /// The option code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            DhcpOption::SubnetMask(_) => 1,
            DhcpOption::Router(_) => 3,
            DhcpOption::DomainNameServer(_) => 6,
            DhcpOption::HostName(_) => 12,
            DhcpOption::DomainName(_) => 15,
            DhcpOption::InterfaceMtu(_) => 26,
            DhcpOption::BroadcastAddr(_) => 28,
            DhcpOption::NtpServers(_) => 42,
            DhcpOption::RequestedIpAddress(_) => 50,
            DhcpOption::AddressLeaseTime(_) => 51,
            DhcpOption::OptionOverload(_) => 52,
            DhcpOption::MessageType(_) => 53,
            DhcpOption::ServerIdentifier(_) => 54,
            DhcpOption::ParameterRequestList(_) => 55,
            DhcpOption::Message(_) => 56,
            DhcpOption::MaxMessageSize(_) => 57,
            DhcpOption::Renewal(_) => 58,
            DhcpOption::Rebinding(_) => 59,
            DhcpOption::VendorClass(_) => 60,
            DhcpOption::ClientIdentifier(_) => 61,
            DhcpOption::ClasslessStaticRoute(_) => 121,
            DhcpOption::MsClasslessStaticRoute(_) => 249,
            DhcpOption::Unknown { code, .. } => *code,
        }
    }

    /// The payload as the wire carries it.
    fn data(&self) -> Vec<u8> {
        match self {
            DhcpOption::SubnetMask(a)
            | DhcpOption::BroadcastAddr(a)
            | DhcpOption::RequestedIpAddress(a)
            | DhcpOption::ServerIdentifier(a) => a.octets().to_vec(),
            DhcpOption::Router(v) | DhcpOption::DomainNameServer(v) | DhcpOption::NtpServers(v) => {
                v.iter().flat_map(Ipv4Addr::octets).collect()
            }
            DhcpOption::HostName(s) | DhcpOption::DomainName(s) | DhcpOption::Message(s) => {
                s.as_bytes().to_vec()
            }
            DhcpOption::InterfaceMtu(n) | DhcpOption::MaxMessageSize(n) => n.to_be_bytes().to_vec(),
            DhcpOption::AddressLeaseTime(n) | DhcpOption::Renewal(n) | DhcpOption::Rebinding(n) => {
                n.to_be_bytes().to_vec()
            }
            DhcpOption::OptionOverload(v) => vec![*v],
            DhcpOption::MessageType(t) => vec![t.to_u8()],
            DhcpOption::ParameterRequestList(v)
            | DhcpOption::VendorClass(v)
            | DhcpOption::ClientIdentifier(v) => v.clone(),
            DhcpOption::ClasslessStaticRoute(r) | DhcpOption::MsClasslessStaticRoute(r) => {
                route_bytes(r)
            }
            DhcpOption::Unknown { data, .. } => data.clone(),
        }
    }

    /// Type `data` as option `code`; the raw bytes when the payload does not fit.
    fn typed(code: u8, data: Vec<u8>) -> DhcpOption {
        let parsed = match code {
            1 => addr(&data).map(DhcpOption::SubnetMask),
            3 => addrs(&data).map(DhcpOption::Router),
            6 => addrs(&data).map(DhcpOption::DomainNameServer),
            12 => text(&data).map(DhcpOption::HostName),
            15 => text(&data).map(DhcpOption::DomainName),
            26 => u16_of(&data).map(DhcpOption::InterfaceMtu),
            28 => addr(&data).map(DhcpOption::BroadcastAddr),
            42 => addrs(&data).map(DhcpOption::NtpServers),
            50 => addr(&data).map(DhcpOption::RequestedIpAddress),
            51 => u32_of(&data).map(DhcpOption::AddressLeaseTime),
            52 => u8_of(&data).map(DhcpOption::OptionOverload),
            53 => u8_of(&data).map(|v| DhcpOption::MessageType(MessageType::from_u8(v))),
            54 => addr(&data).map(DhcpOption::ServerIdentifier),
            55 => Some(DhcpOption::ParameterRequestList(data.clone())),
            56 => text(&data).map(DhcpOption::Message),
            57 => u16_of(&data).map(DhcpOption::MaxMessageSize),
            58 => u32_of(&data).map(DhcpOption::Renewal),
            59 => u32_of(&data).map(DhcpOption::Rebinding),
            60 => non_empty(&data).map(DhcpOption::VendorClass),
            61 => non_empty(&data).map(DhcpOption::ClientIdentifier),
            121 => routes(&data).map(DhcpOption::ClasslessStaticRoute),
            249 => routes(&data).map(DhcpOption::MsClasslessStaticRoute),
            _ => None,
        };
        parsed.unwrap_or(DhcpOption::Unknown { code, data })
    }
}

fn addr(data: &[u8]) -> Option<Ipv4Addr> {
    <[u8; 4]>::try_from(data).ok().map(Ipv4Addr::from)
}

fn addrs(data: &[u8]) -> Option<Vec<Ipv4Addr>> {
    let (quads, rest) = data.as_chunks::<4>();
    if quads.is_empty() || !rest.is_empty() {
        return None;
    }
    Some(quads.iter().map(|quad| Ipv4Addr::from(*quad)).collect())
}

/// UTF-8, never empty; trailing NULs are tolerated (some servers terminate names) but a NUL
/// followed by anything else is garbage, not a name.
fn text(data: &[u8]) -> Option<String> {
    let end = data
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |last| last + 1);
    let body = data.get(..end)?;
    if body.contains(&0) {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    (!text.is_empty()).then(|| text.to_owned())
}

fn u8_of(data: &[u8]) -> Option<u8> {
    match data {
        [value] => Some(*value),
        _ => None,
    }
}

fn u16_of(data: &[u8]) -> Option<u16> {
    <[u8; 2]>::try_from(data).ok().map(u16::from_be_bytes)
}

fn u32_of(data: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(data).ok().map(u32::from_be_bytes)
}

fn non_empty(data: &[u8]) -> Option<Vec<u8>> {
    (!data.is_empty()).then(|| data.to_vec())
}

/// RFC 3442 §Encoding: prefix length, the significant destination octets, the router.
fn routes(data: &[u8]) -> Option<Vec<ClasslessRoute>> {
    if data.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    let mut rest = data;
    while let Some((&prefix, tail)) = rest.split_first() {
        if prefix > 32 {
            return None;
        }
        let significant = usize::from(prefix).div_ceil(8);
        let (dst_bytes, tail) = tail.split_at_checked(significant)?;
        let (via_bytes, tail) = tail.split_at_checked(4)?;
        let mut dst = [0u8; 4];
        dst.get_mut(..significant)?.copy_from_slice(dst_bytes);
        out.push(ClasslessRoute {
            dst: Ipv4Addr::from(dst),
            prefix,
            via: addr(via_bytes)?,
        });
        rest = tail;
    }
    Some(out)
}

fn route_bytes(routes: &[ClasslessRoute]) -> Vec<u8> {
    let mut out = Vec::new();
    for route in routes {
        let significant = usize::from(route.prefix.min(32)).div_ceil(8);
        out.push(route.prefix);
        out.extend_from_slice(&route.dst.octets()[..significant]);
        out.extend_from_slice(&route.via.octets());
    }
    out
}

/// One DHCPv4 message (RFC 2131 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub op: Op,
    /// Hardware type; 1 is Ethernet.
    pub htype: u8,
    /// Hardware address length; 6 for Ethernet.
    pub hlen: u8,
    pub hops: u8,
    /// Transaction id, chosen by the client.
    pub xid: u32,
    /// Seconds since the client began acquiring or renewing.
    pub secs: u16,
    /// [`FLAG_BROADCAST`] and reserved bits.
    pub flags: u16,
    /// The client's address, only when it has one it can use.
    pub ciaddr: Ipv4Addr,
    /// "Your" address: what the server offers or confirms.
    pub yiaddr: Ipv4Addr,
    /// Next server (bootstrap).
    pub siaddr: Ipv4Addr,
    /// Relay agent address.
    pub giaddr: Ipv4Addr,
    /// Client hardware address, `hlen` bytes used.
    pub chaddr: [u8; 16],
    /// Server host name, or options when overloaded.
    pub sname: [u8; 64],
    /// Boot file name, or options when overloaded.
    pub file: [u8; 128],
    /// Options in wire order, repeated codes joined.
    pub options: Vec<DhcpOption>,
}

/// Why bytes are not a DHCP message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("{0} bytes is too short for a DHCP message (240 needed)")]
    TooShort(usize),
    #[error("not a DHCP message: magic cookie missing")]
    Cookie,
    #[error("option {code} runs past the end of the message")]
    Truncated { code: u8 },
    #[error("unknown op {0}")]
    Op(u8),
}

impl Message {
    /// Parse `bytes` as a message.
    ///
    /// # Errors
    ///
    /// When the bytes are shorter than the header and cookie, the cookie is missing, `op` is
    /// neither request nor reply, or an option's declared length runs past the end.
    pub fn decode(bytes: &[u8]) -> Result<Message, DecodeError> {
        if bytes.len() < COOKIE_END {
            return Err(DecodeError::TooShort(bytes.len()));
        }
        if bytes[HEADER_LEN..COOKIE_END] != MAGIC_COOKIE {
            return Err(DecodeError::Cookie);
        }
        let op = match bytes[0] {
            1 => Op::BootRequest,
            2 => Op::BootReply,
            other => return Err(DecodeError::Op(other)),
        };
        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&bytes[28..44]);
        let mut sname = [0u8; 64];
        sname.copy_from_slice(&bytes[SNAME]);
        let mut file = [0u8; 128];
        file.copy_from_slice(&bytes[FILE]);

        let mut raw: Vec<(u8, Vec<u8>)> = Vec::new();
        parse_tlvs(&bytes[COOKIE_END..], &mut raw)?;
        let overload = raw
            .iter()
            .find(|(code, _)| *code == 52)
            .and_then(|(_, data)| u8_of(data));
        if let Some(areas) = overload {
            if areas & OVERLOAD_FILE != 0 {
                parse_tlvs(&file, &mut raw)?;
            }
            if areas & OVERLOAD_SNAME != 0 {
                parse_tlvs(&sname, &mut raw)?;
            }
        }
        let options = raw
            .into_iter()
            .map(|(code, data)| DhcpOption::typed(code, data))
            .collect();

        Ok(Message {
            op,
            htype: bytes[1],
            hlen: bytes[2],
            hops: bytes[3],
            xid: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            secs: u16::from_be_bytes([bytes[8], bytes[9]]),
            flags: u16::from_be_bytes([bytes[10], bytes[11]]),
            ciaddr: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            yiaddr: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
            siaddr: Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23]),
            giaddr: Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]),
            chaddr,
            sname,
            file,
            options,
        })
    }

    /// The wire form: header, cookie, options in order (long ones split per RFC 3396), END,
    /// zero-padded to [`MIN_MESSAGE_LEN`].
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MIN_MESSAGE_LEN);
        out.push(self.op as u8);
        out.push(self.htype);
        out.push(self.hlen);
        out.push(self.hops);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        for field in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            out.extend_from_slice(&field.octets());
        }
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&self.sname);
        out.extend_from_slice(&self.file);
        out.extend_from_slice(&MAGIC_COOKIE);
        for option in &self.options {
            let code = option.code();
            let data = option.data();
            if data.is_empty() {
                out.extend_from_slice(&[code, 0]);
            }
            for chunk in data.chunks(MAX_OPTION_LEN) {
                out.push(code);
                out.push(u8::try_from(chunk.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(chunk);
            }
        }
        out.push(OPT_END);
        if out.len() < MIN_MESSAGE_LEN {
            out.resize(MIN_MESSAGE_LEN, 0);
        }
        out
    }

    /// The first option with `code`.
    #[must_use]
    pub fn option(&self, code: u8) -> Option<&DhcpOption> {
        self.options.iter().find(|option| option.code() == code)
    }

    /// Option 53, when present and well-formed.
    #[must_use]
    pub fn message_type(&self) -> Option<MessageType> {
        match self.option(53) {
            Some(DhcpOption::MessageType(kind)) => Some(*kind),
            _ => None,
        }
    }
}

/// Append `area`'s TLVs to `raw`, joining repeated codes (RFC 3396); PAD skipped, END stops.
fn parse_tlvs(area: &[u8], raw: &mut Vec<(u8, Vec<u8>)>) -> Result<(), DecodeError> {
    let mut rest = area;
    while let Some((&code, tail)) = rest.split_first() {
        match code {
            OPT_PAD => rest = tail,
            OPT_END => break,
            _ => {
                let (&len, tail) = tail.split_first().ok_or(DecodeError::Truncated { code })?;
                let (data, tail) = tail
                    .split_at_checked(usize::from(len))
                    .ok_or(DecodeError::Truncated { code })?;
                match raw.iter_mut().find(|(existing, _)| *existing == code) {
                    Some((_, joined)) => joined.extend_from_slice(data),
                    None => raw.push((code, data.to_vec())),
                }
                rest = tail;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4 as oracle;
    use dhcproto::{Decodable, Decoder, Encodable};
    use std::net::Ipv4Addr;

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xfe, 0x00, 0x00];
    const UNSPEC: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn chaddr() -> [u8; 16] {
        let mut chaddr = [0; 16];
        chaddr[..6].copy_from_slice(&MAC);
        chaddr
    }

    fn discover() -> Message {
        Message {
            op: Op::BootRequest,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0x1234_5678,
            secs: 3,
            flags: FLAG_BROADCAST,
            ciaddr: UNSPEC,
            yiaddr: UNSPEC,
            siaddr: UNSPEC,
            giaddr: UNSPEC,
            chaddr: chaddr(),
            sname: [0; 64],
            file: [0; 128],
            options: vec![
                DhcpOption::MessageType(MessageType::Discover),
                DhcpOption::ClientIdentifier(vec![
                    0xff, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x52, 0x54, 0x00, 0xfe,
                    0x00, 0x00,
                ]),
                DhcpOption::ParameterRequestList(vec![1, 3, 6, 15, 28, 26, 121, 249, 42, 58, 59]),
                DhcpOption::MaxMessageSize(1500),
                DhcpOption::HostName("openfeo-lab".to_owned()),
            ],
        }
    }

    /// A BOOTREPLY header, the cookie, `raw` option bytes as given (no END appended).
    fn reply_with_raw_options(raw: &[u8]) -> Vec<u8> {
        reply_with_areas(raw, &[0; 64], &[0; 128])
    }

    fn reply_with_areas(raw: &[u8], sname: &[u8; 64], file: &[u8; 128]) -> Vec<u8> {
        let mut bytes = vec![0u8; 236];
        bytes[0] = 2;
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[4..8].copy_from_slice(&0xabcd_0001u32.to_be_bytes());
        bytes[28..34].copy_from_slice(&MAC);
        bytes[44..108].copy_from_slice(sname);
        bytes[108..236].copy_from_slice(file);
        bytes.extend_from_slice(&MAGIC_COOKIE);
        bytes.extend_from_slice(raw);
        bytes
    }

    /// `(code, data)` of every TLV in the options area of `bytes`, in order, no joining.
    fn tlvs(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 240;
        while i < bytes.len() {
            match bytes[i] {
                0 => i += 1,
                255 => break,
                code => {
                    let len = bytes[i + 1] as usize;
                    out.push((code, bytes[i + 2..i + 2 + len].to_vec()));
                    i += 2 + len;
                }
            }
        }
        out
    }

    #[test]
    fn discover_round_trips_and_pads_to_300() {
        let bytes = discover().encode();
        assert_eq!(bytes.len(), MIN_MESSAGE_LEN);
        assert_eq!(&bytes[236..240], &MAGIC_COOKIE);
        assert_eq!(bytes[0], 1, "BOOTREQUEST");
        assert_eq!(&bytes[4..8], &0x1234_5678u32.to_be_bytes());
        assert_eq!(&bytes[10..12], &FLAG_BROADCAST.to_be_bytes());
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back, discover());
        assert_eq!(back.message_type(), Some(MessageType::Discover));
    }

    #[test]
    fn oracle_decodes_what_we_encode() {
        let bytes = discover().encode();
        let o = oracle::Message::decode(&mut Decoder::new(&bytes)).unwrap();
        assert_eq!(o.opcode(), oracle::Opcode::BootRequest);
        assert_eq!(o.xid(), 0x1234_5678);
        assert_eq!(o.secs(), 3);
        assert!(o.flags().broadcast());
        assert_eq!(o.chaddr(), &MAC);
        assert_eq!(o.opts().msg_type(), Some(oracle::MessageType::Discover));
        assert_eq!(
            o.opts().get(oracle::OptionCode::Hostname),
            Some(&oracle::DhcpOption::Hostname("openfeo-lab".to_owned()))
        );
        assert_eq!(
            o.opts().get(oracle::OptionCode::MaxMessageSize),
            Some(&oracle::DhcpOption::MaxMessageSize(1500))
        );
        let mut codes: Vec<u8> = o
            .opts()
            .iter()
            .map(|(code, _)| -> u8 { (*code).into() })
            .collect();
        codes.sort_unstable();
        assert_eq!(codes, vec![12, 53, 55, 57, 61]);
    }

    #[test]
    fn we_decode_what_the_oracle_encodes() {
        let server = ip(203, 0, 113, 1);
        let mut o = oracle::Message::new_with_id(
            0xabcd_0001,
            UNSPEC,
            ip(203, 0, 113, 100),
            UNSPEC,
            UNSPEC,
            &MAC,
        );
        o.set_opcode(oracle::Opcode::BootReply);
        let opts = o.opts_mut();
        opts.insert(oracle::DhcpOption::MessageType(oracle::MessageType::Ack));
        opts.insert(oracle::DhcpOption::SubnetMask(ip(255, 255, 255, 0)));
        opts.insert(oracle::DhcpOption::Router(vec![server]));
        opts.insert(oracle::DhcpOption::DomainNameServer(vec![server]));
        opts.insert(oracle::DhcpOption::DomainName("isp.example".to_owned()));
        opts.insert(oracle::DhcpOption::InterfaceMtu(1400));
        opts.insert(oracle::DhcpOption::AddressLeaseTime(60));
        opts.insert(oracle::DhcpOption::Renewal(20));
        opts.insert(oracle::DhcpOption::Rebinding(40));
        opts.insert(oracle::DhcpOption::ServerIdentifier(server));
        opts.insert(oracle::DhcpOption::ClasslessStaticRoute(vec![
            ("0.0.0.0/0".parse().unwrap(), server),
            ("198.51.100.0/24".parse().unwrap(), server),
        ]));
        let bytes = o.to_vec().unwrap();

        let m = Message::decode(&bytes).unwrap();
        assert_eq!(m.op, Op::BootReply);
        assert_eq!((m.htype, m.hlen, m.xid), (1, 6, 0xabcd_0001));
        assert_eq!(m.yiaddr, ip(203, 0, 113, 100));
        assert_eq!(&m.chaddr[..6], &MAC);
        assert_eq!(m.message_type(), Some(MessageType::Ack));
        assert_eq!(
            m.option(1),
            Some(&DhcpOption::SubnetMask(ip(255, 255, 255, 0)))
        );
        assert_eq!(m.option(3), Some(&DhcpOption::Router(vec![server])));
        assert_eq!(
            m.option(6),
            Some(&DhcpOption::DomainNameServer(vec![server]))
        );
        assert_eq!(
            m.option(15),
            Some(&DhcpOption::DomainName("isp.example".to_owned()))
        );
        assert_eq!(m.option(26), Some(&DhcpOption::InterfaceMtu(1400)));
        assert_eq!(m.option(51), Some(&DhcpOption::AddressLeaseTime(60)));
        assert_eq!(m.option(58), Some(&DhcpOption::Renewal(20)));
        assert_eq!(m.option(59), Some(&DhcpOption::Rebinding(40)));
        assert_eq!(m.option(54), Some(&DhcpOption::ServerIdentifier(server)));
        assert_eq!(
            m.option(121),
            Some(&DhcpOption::ClasslessStaticRoute(vec![
                ClasslessRoute {
                    dst: UNSPEC,
                    prefix: 0,
                    via: server
                },
                ClasslessRoute {
                    dst: ip(198, 51, 100, 0),
                    prefix: 24,
                    via: server
                },
            ]))
        );
    }

    #[test]
    fn rfc3442_examples_decode_byte_exact() {
        let via = ip(10, 0, 0, 1);
        let data: Vec<u8> = vec![
            0x00, 10, 0, 0, 1, // 0.0.0.0/0
            0x08, 10, 10, 0, 0, 1, // 10.0.0.0/8
            0x10, 10, 17, 10, 0, 0, 1, // 10.17.0.0/16
            0x18, 10, 27, 129, 10, 0, 0, 1, // 10.27.129.0/24
            0x19, 10, 229, 0, 128, 10, 0, 0, 1, // 10.229.0.128/25
        ];
        let mut raw = vec![121, u8::try_from(data.len()).unwrap()];
        raw.extend_from_slice(&data);
        raw.push(255);
        let m = Message::decode(&reply_with_raw_options(&raw)).unwrap();
        let route = |dst: Ipv4Addr, prefix: u8| ClasslessRoute { dst, prefix, via };
        let expected = vec![
            route(UNSPEC, 0),
            route(ip(10, 0, 0, 0), 8),
            route(ip(10, 17, 0, 0), 16),
            route(ip(10, 27, 129, 0), 24),
            route(ip(10, 229, 0, 128), 25),
        ];
        assert_eq!(
            m.option(121),
            Some(&DhcpOption::ClasslessStaticRoute(expected.clone()))
        );

        let mut again = m.clone();
        again.options = vec![DhcpOption::ClasslessStaticRoute(expected)];
        assert_eq!(tlvs(&again.encode()), vec![(121, data)]);
    }

    #[test]
    fn long_option_split_on_encode_and_joined_on_decode() {
        let routes: Vec<ClasslessRoute> = (0..70u8)
            .map(|n| ClasslessRoute {
                dst: ip(10, n, 0, 0),
                prefix: 16,
                via: ip(10, 0, 0, 1),
            })
            .collect();
        let mut m = discover();
        m.options = vec![DhcpOption::ClasslessStaticRoute(routes.clone())];
        let bytes = m.encode();
        let pieces = tlvs(&bytes);
        assert_eq!(pieces.len(), 2, "490 bytes split into two TLVs");
        assert!(pieces.iter().all(|(code, _)| *code == 121));
        assert_eq!(pieces[0].1.len(), 255);
        assert_eq!(pieces[1].1.len(), 490 - 255);
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back.options, vec![DhcpOption::ClasslessStaticRoute(routes)]);
    }

    #[test]
    fn overloaded_sname_and_file_carry_options() {
        let mut sname = [0u8; 64];
        sname[..7].copy_from_slice(&[54, 4, 203, 0, 113, 1, 255]);
        let mut file = [0u8; 128];
        file[..4].copy_from_slice(&[53, 1, 5, 255]);
        let bytes = reply_with_areas(&[52, 1, 3, 255], &sname, &file);
        let m = Message::decode(&bytes).unwrap();
        assert_eq!(m.message_type(), Some(MessageType::Ack));
        assert_eq!(
            m.option(54),
            Some(&DhcpOption::ServerIdentifier(ip(203, 0, 113, 1)))
        );
        assert_eq!(m.option(52), Some(&DhcpOption::OptionOverload(3)));
        assert_eq!(m.sname, sname, "the raw area is kept");
    }

    #[test]
    fn missing_end_is_accepted_and_pad_is_skipped() {
        let m = Message::decode(&reply_with_raw_options(&[0, 0, 53, 1, 1, 0, 0])).unwrap();
        assert_eq!(
            m.options,
            vec![DhcpOption::MessageType(MessageType::Discover)]
        );
    }

    #[test]
    fn malformed_known_option_becomes_unknown() {
        let m =
            Message::decode(&reply_with_raw_options(&[3, 3, 1, 2, 3, 53, 2, 1, 1, 255])).unwrap();
        assert_eq!(
            m.options,
            vec![
                DhcpOption::Unknown {
                    code: 3,
                    data: vec![1, 2, 3]
                },
                DhcpOption::Unknown {
                    code: 53,
                    data: vec![1, 1]
                },
            ]
        );
        assert_eq!(m.message_type(), None);
    }

    #[test]
    fn string_options_accept_trailing_nul_only() {
        let m = Message::decode(&reply_with_raw_options(&[12, 3, b'a', b'b', 0, 255])).unwrap();
        assert_eq!(m.option(12), Some(&DhcpOption::HostName("ab".to_owned())));
        let garbage_after_nul = [12, 5, b'a', b'b', 0, 0xff, 0xfe, 255];
        let m = Message::decode(&reply_with_raw_options(&garbage_after_nul)).unwrap();
        assert_eq!(
            m.option(12),
            Some(&DhcpOption::Unknown {
                code: 12,
                data: vec![b'a', b'b', 0, 0xff, 0xfe]
            })
        );
        let only_nul = [15, 1, 0, 255];
        let m = Message::decode(&reply_with_raw_options(&only_nul)).unwrap();
        assert!(matches!(
            m.option(15),
            Some(DhcpOption::Unknown { code: 15, .. })
        ));
    }

    #[test]
    fn truncated_and_malformed_inputs_are_errors_not_panics() {
        assert_eq!(Message::decode(&[]), Err(DecodeError::TooShort(0)));
        assert_eq!(Message::decode(&[2; 239]), Err(DecodeError::TooShort(239)));
        let mut bad_cookie = reply_with_raw_options(&[255]);
        bad_cookie[236] = 0;
        assert_eq!(Message::decode(&bad_cookie), Err(DecodeError::Cookie));
        assert_eq!(
            Message::decode(&reply_with_raw_options(&[3, 4, 1, 2])),
            Err(DecodeError::Truncated { code: 3 })
        );
        assert_eq!(
            Message::decode(&reply_with_raw_options(&[3])),
            Err(DecodeError::Truncated { code: 3 })
        );
        let mut bad_op = reply_with_raw_options(&[255]);
        bad_op[0] = 7;
        assert_eq!(Message::decode(&bad_op), Err(DecodeError::Op(7)));
    }

    #[test]
    fn classless_route_with_impossible_length_is_rejected() {
        let too_long_prefix = [121, 10, 33, 1, 2, 3, 4, 5, 10, 0, 0, 1, 255];
        let m = Message::decode(&reply_with_raw_options(&too_long_prefix)).unwrap();
        assert_eq!(
            m.option(121),
            Some(&DhcpOption::Unknown {
                code: 121,
                data: vec![33, 1, 2, 3, 4, 5, 10, 0, 0, 1]
            })
        );
        let truncated_route = [121, 3, 24, 10, 27, 255];
        let m = Message::decode(&reply_with_raw_options(&truncated_route)).unwrap();
        assert!(matches!(
            m.option(121),
            Some(DhcpOption::Unknown { code: 121, .. })
        ));
        let empty = [121, 0, 255];
        let m = Message::decode(&reply_with_raw_options(&empty)).unwrap();
        assert!(matches!(
            m.option(121),
            Some(DhcpOption::Unknown { code: 121, .. })
        ));
    }

    /// The committed seeds of `fuzz/corpus/dhcp4_message` (SPEC §11); rerun with
    /// `-- --ignored write_fuzz_corpus` when the encoder changes.
    #[test]
    #[ignore = "writes fuzz/corpus/dhcp4_message; run on demand"]
    fn write_fuzz_corpus() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/corpus/dhcp4_message");
        std::fs::create_dir_all(&dir).unwrap();
        let mut offer = discover();
        offer.op = Op::BootReply;
        offer.yiaddr = ip(203, 0, 113, 100);
        offer.options = vec![
            DhcpOption::MessageType(MessageType::Offer),
            DhcpOption::ServerIdentifier(ip(203, 0, 113, 1)),
            DhcpOption::AddressLeaseTime(60),
            DhcpOption::SubnetMask(ip(255, 255, 255, 0)),
            DhcpOption::Router(vec![ip(203, 0, 113, 1)]),
        ];
        let mut ack = offer.clone();
        ack.options
            .push(DhcpOption::ClasslessStaticRoute(vec![ClasslessRoute {
                dst: ip(198, 51, 100, 0),
                prefix: 24,
                via: ip(203, 0, 113, 1),
            }]));
        ack.options[0] = DhcpOption::MessageType(MessageType::Ack);
        for (name, m) in [("discover", discover()), ("offer", offer), ("ack", ack)] {
            std::fs::write(dir.join(format!("seed-{name}.bin")), m.encode()).unwrap();
        }
    }
}
