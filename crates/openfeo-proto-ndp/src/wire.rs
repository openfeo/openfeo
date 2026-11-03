// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Router solicitations and advertisements on the wire (RFC 4861 §4.1, §4.2, §4.6; RFC 8106;
//! RFC 4191), decoded into values and encoded back with the ICMPv6 checksum left zero for the
//! kernel to fill (a raw ICMPv6 socket computes and verifies it). Every option length is checked
//! against the packet before a byte of it is read; unknown options are kept and re-encoded.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use thiserror::Error;

/// ICMPv6 type of a router solicitation.
pub const ROUTER_SOLICITATION: u8 = 133;
/// ICMPv6 type of a router advertisement.
pub const ROUTER_ADVERTISEMENT: u8 = 134;

const SOURCE_LINK_LAYER: u8 = 1;
const PREFIX_INFORMATION: u8 = 3;
const MTU: u8 = 5;
const ROUTE_INFORMATION: u8 = 24;
const RDNSS: u8 = 25;
const DNSSL: u8 = 31;

/// RFC 4191 router preference, two bits in the advertisement's flags and in a route
/// information option. The reserved value `10` reads as medium (RFC 4191 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Preference {
    Low,
    #[default]
    Medium,
    High,
}

impl Preference {
    fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b01 => Preference::High,
            0b11 => Preference::Low,
            _ => Preference::Medium,
        }
    }

    fn bits(self) -> u8 {
        match self {
            Preference::High => 0b01,
            Preference::Low => 0b11,
            Preference::Medium => 0b00,
        }
    }
}

/// One option of a solicitation or advertisement (RFC 4861 §4.6, RFC 8106, RFC 4191). An option
/// whose contents do not fit its kind is kept as [`NdOption::Unknown`], as is any kind this
/// codec does not know, so one bad option never discards a whole advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdOption {
    /// Type 1 with an Ethernet address.
    SourceLinkLayer([u8; 6]),
    /// Type 3.
    PrefixInformation {
        prefix: Ipv6Net,
        /// The L flag.
        on_link: bool,
        /// The A flag.
        autonomous: bool,
        /// Seconds; `u32::MAX` is infinity.
        valid: u32,
        preferred: u32,
    },
    /// Type 5.
    Mtu(u32),
    /// Type 24 (RFC 4191).
    RouteInformation {
        prefix: Ipv6Net,
        preference: Preference,
        /// Seconds; `u32::MAX` is infinity.
        lifetime: u32,
    },
    /// Type 25 (RFC 8106).
    Rdnss { lifetime: u32, addrs: Vec<Ipv6Addr> },
    /// Type 31 (RFC 8106), names as dotted text.
    Dnssl { lifetime: u32, names: Vec<String> },
    /// Anything else, body bytes after the two-byte option header.
    Unknown { kind: u8, data: Vec<u8> },
}

/// A router advertisement's header fields (RFC 4861 §4.2) and options.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouterAdvertisement {
    /// 0 means unspecified.
    pub cur_hop_limit: u8,
    /// The M flag.
    pub managed: bool,
    /// The O flag.
    pub other: bool,
    pub preference: Preference,
    /// Seconds; 0 means "not a default router".
    pub router_lifetime: u16,
    /// Milliseconds; 0 means unspecified.
    pub reachable_time: u32,
    /// Milliseconds; 0 means unspecified.
    pub retrans_timer: u32,
    pub options: Vec<NdOption>,
}

/// A router solicitation or advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    RouterSolicitation { options: Vec<NdOption> },
    RouterAdvertisement(RouterAdvertisement),
}

/// Why bytes are not a solicitation or advertisement.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("{0} bytes is too short for a {1}")]
    TooShort(usize, &'static str),
    #[error("ICMPv6 type {0} is not a router solicitation or advertisement")]
    NotNdp(u8),
    #[error("{0}")]
    Malformed(&'static str),
}

impl Message {
    /// Decode an ICMPv6 message, header included, checksum ignored.
    ///
    /// # Errors
    ///
    /// [`Error::NotNdp`] for any other ICMPv6 type, [`Error::TooShort`] below the fixed header,
    /// [`Error::Malformed`] for a non-zero code or an option whose length is zero or runs past
    /// the end of the message.
    pub fn decode(bytes: &[u8]) -> Result<Message, Error> {
        let kind = *bytes.first().ok_or(Error::TooShort(0, "message"))?;
        match kind {
            ROUTER_SOLICITATION => {
                if bytes.len() < 8 {
                    return Err(Error::TooShort(bytes.len(), "router solicitation"));
                }
                if bytes[1] != 0 {
                    return Err(Error::Malformed("code must be 0"));
                }
                Ok(Message::RouterSolicitation {
                    options: options(&bytes[8..])?,
                })
            }
            ROUTER_ADVERTISEMENT => {
                if bytes.len() < 16 {
                    return Err(Error::TooShort(bytes.len(), "router advertisement"));
                }
                if bytes[1] != 0 {
                    return Err(Error::Malformed("code must be 0"));
                }
                let flags = bytes[5];
                Ok(Message::RouterAdvertisement(RouterAdvertisement {
                    cur_hop_limit: bytes[4],
                    managed: flags & 0x80 != 0,
                    other: flags & 0x40 != 0,
                    preference: Preference::from_bits(flags >> 3),
                    router_lifetime: u16::from_be_bytes([bytes[6], bytes[7]]),
                    reachable_time: be32(&bytes[8..12]),
                    retrans_timer: be32(&bytes[12..16]),
                    options: options(&bytes[16..])?,
                }))
            }
            other => Err(Error::NotNdp(other)),
        }
    }

    /// The message as ICMPv6 bytes with a zero checksum, which a raw ICMPv6 socket fills in.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Message::RouterSolicitation { options } => {
                out.extend_from_slice(&[ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
                encode_options(options, &mut out);
            }
            Message::RouterAdvertisement(ra) => {
                let flags = (u8::from(ra.managed) << 7)
                    | (u8::from(ra.other) << 6)
                    | (ra.preference.bits() << 3);
                out.extend_from_slice(&[ROUTER_ADVERTISEMENT, 0, 0, 0, ra.cur_hop_limit, flags]);
                out.extend_from_slice(&ra.router_lifetime.to_be_bytes());
                out.extend_from_slice(&ra.reachable_time.to_be_bytes());
                out.extend_from_slice(&ra.retrans_timer.to_be_bytes());
                encode_options(&ra.options, &mut out);
            }
        }
        out
    }

    /// The options of either message.
    #[must_use]
    pub fn options(&self) -> &[NdOption] {
        match self {
            Message::RouterSolicitation { options } => options,
            Message::RouterAdvertisement(ra) => &ra.options,
        }
    }
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Every option after the fixed header: a two-byte header (type, length in 8-byte units) and
/// the body. A length of zero or one past the end of the message refuses the message (RFC 4861
/// §4.6); the body's fit for its kind is judged per option.
fn options(mut rest: &[u8]) -> Result<Vec<NdOption>, Error> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 2 {
            return Err(Error::Malformed("option header runs past the end"));
        }
        let (kind, units) = (rest[0], rest[1]);
        if units == 0 {
            return Err(Error::Malformed("option of length 0"));
        }
        let len = usize::from(units) * 8;
        if rest.len() < len {
            return Err(Error::Malformed("option runs past the end"));
        }
        out.push(option(kind, &rest[2..len]));
        rest = &rest[len..];
    }
    Ok(out)
}

/// One option from its kind and body, or [`NdOption::Unknown`] when the body does not fit.
fn option(kind: u8, body: &[u8]) -> NdOption {
    let unknown = || NdOption::Unknown {
        kind,
        data: body.to_vec(),
    };
    match kind {
        SOURCE_LINK_LAYER if body.len() == 6 => {
            NdOption::SourceLinkLayer([body[0], body[1], body[2], body[3], body[4], body[5]])
        }
        PREFIX_INFORMATION if body.len() == 30 => {
            let Ok(prefix) = Ipv6Net::new(ipv6(&body[14..30]), body[0]) else {
                return unknown();
            };
            NdOption::PrefixInformation {
                prefix: prefix.trunc(),
                on_link: body[1] & 0x80 != 0,
                autonomous: body[1] & 0x40 != 0,
                valid: be32(&body[2..6]),
                preferred: be32(&body[6..10]),
            }
        }
        MTU if body.len() == 6 => NdOption::Mtu(be32(&body[2..6])),
        ROUTE_INFORMATION if matches!(body.len(), 6 | 14 | 22) => {
            let prefix_len = body[0];
            let carried = &body[6..];
            if usize::from(prefix_len) > carried.len() * 8 {
                return unknown();
            }
            let mut octets = [0u8; 16];
            octets[..carried.len()].copy_from_slice(carried);
            let Ok(prefix) = Ipv6Net::new(Ipv6Addr::from(octets), prefix_len) else {
                return unknown();
            };
            NdOption::RouteInformation {
                prefix: prefix.trunc(),
                preference: Preference::from_bits(body[1] >> 3),
                lifetime: be32(&body[2..6]),
            }
        }
        RDNSS if body.len() >= 22 && (body.len() - 6).is_multiple_of(16) => NdOption::Rdnss {
            lifetime: be32(&body[2..6]),
            addrs: body[6..]
                .as_chunks::<16>()
                .0
                .iter()
                .map(|a| Ipv6Addr::from(*a))
                .collect(),
        },
        DNSSL if body.len() >= 6 => match dnssl_names(&body[6..]) {
            Some(names) => NdOption::Dnssl {
                lifetime: be32(&body[2..6]),
                names,
            },
            None => unknown(),
        },
        _ => unknown(),
    }
}

fn ipv6(bytes: &[u8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(bytes);
    Ipv6Addr::from(octets)
}

/// DNS wire-format names (RFC 1035 §3.1, no compression) up to the zero padding; `None` when a
/// label is over 63 bytes, is a compression pointer, runs past the option, or holds a byte
/// other than a letter, a digit or a hyphen.
fn dnssl_names(mut rest: &[u8]) -> Option<Vec<String>> {
    let mut names = Vec::new();
    while rest.iter().any(|&b| b != 0) {
        let mut labels: Vec<String> = Vec::new();
        loop {
            let len = *rest.first()?;
            rest = &rest[1..];
            if len == 0 {
                break;
            }
            if len > 63 {
                return None;
            }
            let len = usize::from(len);
            if rest.len() < len {
                return None;
            }
            // Letters, digits and hyphen only: anything else cannot be carried as text and
            // written back faithfully, and is no use to a resolver either.
            if !rest[..len]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            {
                return None;
            }
            labels.push(String::from_utf8_lossy(&rest[..len]).into_owned());
            rest = &rest[len..];
        }
        if !labels.is_empty() {
            names.push(labels.join("."));
        }
    }
    Some(names)
}

fn encode_options(options: &[NdOption], out: &mut Vec<u8>) {
    for option in options {
        let start = out.len();
        match option {
            NdOption::SourceLinkLayer(mac) => {
                out.extend_from_slice(&[SOURCE_LINK_LAYER, 1]);
                out.extend_from_slice(mac);
            }
            NdOption::PrefixInformation {
                prefix,
                on_link,
                autonomous,
                valid,
                preferred,
            } => {
                let flags = (u8::from(*on_link) << 7) | (u8::from(*autonomous) << 6);
                out.extend_from_slice(&[PREFIX_INFORMATION, 4, prefix.prefix_len(), flags]);
                out.extend_from_slice(&valid.to_be_bytes());
                out.extend_from_slice(&preferred.to_be_bytes());
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&prefix.network().octets());
            }
            NdOption::Mtu(mtu) => {
                out.extend_from_slice(&[MTU, 1, 0, 0]);
                out.extend_from_slice(&mtu.to_be_bytes());
            }
            NdOption::RouteInformation {
                prefix,
                preference,
                lifetime,
            } => {
                let carried = match prefix.prefix_len() {
                    0 => 0,
                    1..=64 => 8,
                    _ => 16,
                };
                out.extend_from_slice(&[
                    ROUTE_INFORMATION,
                    1 + carried / 8,
                    prefix.prefix_len(),
                    preference.bits() << 3,
                ]);
                out.extend_from_slice(&lifetime.to_be_bytes());
                out.extend_from_slice(&prefix.network().octets()[..usize::from(carried)]);
            }
            NdOption::Rdnss { lifetime, addrs } => {
                let units = u8::try_from(1 + 2 * addrs.len()).unwrap_or(u8::MAX);
                out.extend_from_slice(&[RDNSS, units, 0, 0]);
                out.extend_from_slice(&lifetime.to_be_bytes());
                for addr in addrs.iter().take(usize::from(units.saturating_sub(1)) / 2) {
                    out.extend_from_slice(&addr.octets());
                }
            }
            NdOption::Dnssl { lifetime, names } => {
                out.extend_from_slice(&[DNSSL, 0, 0, 0]);
                out.extend_from_slice(&lifetime.to_be_bytes());
                for name in names {
                    for label in name.split('.').filter(|label| !label.is_empty()) {
                        let bytes = label.as_bytes();
                        let len = bytes.len().min(63);
                        out.push(u8::try_from(len).unwrap_or(63));
                        out.extend_from_slice(&bytes[..len]);
                    }
                    out.push(0);
                }
            }
            NdOption::Unknown { kind, data } => {
                out.extend_from_slice(&[*kind, 0]);
                out.extend_from_slice(data);
            }
        }
        // Pad to 8-byte units and write the length.
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let units = u8::try_from((out.len() - start) / 8).unwrap_or(u8::MAX);
        out[start + 1] = units;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn net(text: &str) -> Ipv6Net {
        text.parse().unwrap()
    }

    fn full_advertisement() -> RouterAdvertisement {
        RouterAdvertisement {
            cur_hop_limit: 64,
            managed: false,
            other: false,
            preference: Preference::High,
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![
                NdOption::SourceLinkLayer([0x52, 0x54, 0, 0xfe, 0, 1]),
                NdOption::PrefixInformation {
                    prefix: net("2001:db8:ffff::/64"),
                    on_link: true,
                    autonomous: true,
                    valid: 2_592_000,
                    preferred: 604_800,
                },
                NdOption::Mtu(1500),
                NdOption::RouteInformation {
                    prefix: net("2001:db8:1::/48"),
                    preference: Preference::High,
                    lifetime: 3600,
                },
                NdOption::Rdnss {
                    lifetime: 1800,
                    addrs: vec!["2001:db8:ffff::1".parse().unwrap()],
                },
                NdOption::Dnssl {
                    lifetime: 1800,
                    names: vec!["isp.example".to_owned()],
                },
            ],
        }
    }

    #[test]
    fn an_advertisement_with_every_option_round_trips() {
        let original = Message::RouterAdvertisement(full_advertisement());
        let bytes = original.encode();
        assert_eq!(bytes[0], 134, "type");
        assert_eq!(bytes[1], 0, "code");
        assert_eq!(&bytes[2..4], &[0, 0], "checksum left for the kernel");
        assert_eq!(bytes[4], 64, "cur hop limit");
        assert_eq!(bytes[5], 0x08, "flags: M=0, O=0, prf=01 (high)");
        assert_eq!(&bytes[6..8], &1800u16.to_be_bytes());
        assert_eq!(&bytes[8..16], &[0; 8], "reachable time and retrans timer");
        assert_eq!(bytes.len() % 8, 0, "options are 8-byte units");
        assert_eq!(Message::decode(&bytes), Ok(original));
        // The PIO's layout (RFC 4861 §4.6.2): type 3, length 4, prefix length, L|A flags.
        let pio = bytes.windows(2).position(|w| w == [3, 4]).unwrap();
        assert_eq!(bytes[pio + 2], 64);
        assert_eq!(bytes[pio + 3], 0xc0);
        // RDNSS (RFC 8106 §5.1): type 25, length 3 for one address.
        assert!(bytes.windows(2).any(|w| w == [25, 3]));
        // DNSSL: type 31, length 3 (8 header bytes + "isp.example" as 13 label bytes, padded
        // to 24).
        assert!(bytes.windows(2).any(|w| w == [31, 3]));
    }

    /// smoltcp (ADR-0018) reads back the header and the RFC 4861 options we write.
    #[test]
    fn smoltcp_agrees_on_the_header_and_the_rfc_4861_options() {
        use smoltcp::wire::{Icmpv6Packet, NdiscRepr};
        let bytes = Message::RouterAdvertisement(full_advertisement()).encode();
        let packet = Icmpv6Packet::new_checked(&bytes[..]).unwrap();
        let NdiscRepr::RouterAdvert {
            hop_limit,
            router_lifetime,
            lladdr,
            mtu,
            prefix_info,
            ..
        } = NdiscRepr::parse(&packet).unwrap()
        else {
            panic!("smoltcp sees an advertisement");
        };
        assert_eq!(hop_limit, 64);
        assert_eq!(router_lifetime.secs(), 1800);
        assert_eq!(lladdr.unwrap().as_bytes(), &[0x52, 0x54, 0, 0xfe, 0, 1]);
        assert_eq!(mtu, Some(1500));
        let info = prefix_info.unwrap();
        assert_eq!(info.prefix_len, 64);
        assert_eq!(info.valid_lifetime.secs(), 2_592_000);
        assert_eq!(info.preferred_lifetime.secs(), 604_800);
        assert_eq!(info.prefix, "2001:db8:ffff::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn a_solicitation_round_trips_and_a_type_other_than_133_or_134_is_not_ndp() {
        let rs = Message::RouterSolicitation {
            options: vec![NdOption::SourceLinkLayer([1, 2, 3, 4, 5, 6])],
        };
        let bytes = rs.encode();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 133);
        assert_eq!(Message::decode(&bytes), Ok(rs));
        let mut na = bytes.clone();
        na[0] = 136;
        assert_eq!(Message::decode(&na), Err(Error::NotNdp(136)));
        assert_eq!(
            Message::decode(&[134, 0, 0, 0, 64, 0]),
            Err(Error::TooShort(6, "router advertisement"))
        );
        let mut coded = bytes;
        coded[1] = 1;
        assert!(
            matches!(Message::decode(&coded), Err(Error::Malformed(_))),
            "code must be 0"
        );
    }

    #[test]
    fn an_option_running_past_the_end_or_of_length_zero_is_refused() {
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[3, 4, 64, 0xc0, 0, 0, 0, 1]); // a PIO claiming 32 bytes
        assert!(
            matches!(Message::decode(&bytes), Err(Error::Malformed(_))),
            "{bytes:?}"
        );
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[1, 0, 1, 2, 3, 4, 5, 6]);
        assert!(
            matches!(Message::decode(&bytes), Err(Error::Malformed(_))),
            "length 0"
        );
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[5, 1, 0, 0, 0, 0, 5, 220]);
        assert_eq!(
            Message::decode(&bytes).unwrap().options(),
            &[NdOption::Mtu(1500)],
            "a whole option after the header is fine"
        );
    }

    #[test]
    fn an_unknown_option_is_kept_and_re_encoded_verbatim() {
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[200, 1, 9, 8, 7, 6, 5, 4]);
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(
            decoded.options(),
            &[NdOption::Unknown {
                kind: 200,
                data: vec![9, 8, 7, 6, 5, 4]
            }]
        );
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn invalid_option_contents_are_kept_as_unknown_not_refused() {
        let names = Message::RouterAdvertisement(RouterAdvertisement {
            options: vec![NdOption::Dnssl {
                lifetime: 60,
                names: vec!["home.arpa".to_owned(), "a.b.example".to_owned()],
            }],
            ..RouterAdvertisement::default()
        });
        assert_eq!(Message::decode(&names.encode()), Ok(names));
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[25, 2, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(
            matches!(
                Message::decode(&bytes).unwrap().options()[0],
                NdOption::Unknown { kind: 25, .. }
            ),
            "rdnss length 2"
        );
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        let mut dnssl = vec![31, 10, 0, 0, 0, 0, 0, 60, 64];
        dnssl.extend_from_slice(&[b'a'; 64]);
        dnssl.resize(80, 0);
        bytes.extend_from_slice(&dnssl);
        assert!(
            matches!(
                Message::decode(&bytes).unwrap().options()[0],
                NdOption::Unknown { kind: 31, .. }
            ),
            "a 64-byte label"
        );
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[3, 4, 129, 0xc0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0; 16]);
        assert!(
            matches!(
                Message::decode(&bytes).unwrap().options()[0],
                NdOption::Unknown { kind: 3, .. }
            ),
            "prefix length 129"
        );
    }

    /// RFC 4861 §4.6.2 and RFC 4191 §2.3: bits beyond the prefix length are reserved and
    /// ignored, so a prefix decodes truncated and re-encodes with them zero (found by `ndp_wire`).
    #[test]
    fn prefix_bits_beyond_the_prefix_length_are_ignored() {
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        // A PIO for 2001:db8:ffff::/64 with junk in the host bits.
        bytes.extend_from_slice(&[3, 4, 64, 0xc0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        ]);
        // A route information option for a /44 carrying eight bytes with bits set past 44.
        bytes.extend_from_slice(&[
            24, 2, 44, 0x18, 0, 0, 0, 1, 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
        ]);
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(
            decoded.options()[0],
            NdOption::PrefixInformation {
                prefix: net("2001:db8:ffff::/64"),
                on_link: true,
                autonomous: true,
                valid: 1,
                preferred: 1,
            }
        );
        assert_eq!(
            decoded.options()[1],
            NdOption::RouteInformation {
                prefix: net("2001:db8:1230::/44"),
                preference: Preference::Low,
                lifetime: 1,
            }
        );
        assert_eq!(Message::decode(&decoded.encode()), Ok(decoded));
    }

    /// A search list is DNS names: a label with a byte outside letters, digits and hyphen (a
    /// NUL, a dot) cannot be carried as text and re-encoded faithfully, so the option stays
    /// bytes (found by `ndp_wire`).
    #[test]
    fn a_dnssl_with_a_label_that_is_not_a_hostname_label_is_kept_as_unknown() {
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[31, 2, 0, 0, 0, 0, 0, 60, 3, 0, b'.', 0, 0, 0, 0, 0]);
        let decoded = Message::decode(&bytes).unwrap();
        assert!(
            matches!(decoded.options()[0], NdOption::Unknown { kind: 31, .. }),
            "{decoded:?}"
        );
        assert_eq!(decoded.encode(), bytes);
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[31, 2, 0, 0, 0, 0, 0, 60, 2, b'A', b'1', 0, 0, 0, 0, 0]);
        assert_eq!(
            Message::decode(&bytes).unwrap().options()[0],
            NdOption::Dnssl {
                lifetime: 60,
                names: vec!["A1".to_owned()]
            },
            "case is kept"
        );
    }

    #[test]
    fn preference_10_reads_as_medium() {
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes[5] = 0x10;
        let Ok(Message::RouterAdvertisement(ra)) = Message::decode(&bytes) else {
            panic!("decodes");
        };
        assert_eq!(ra.preference, Preference::Medium);
        bytes[5] = 0x18;
        let Ok(Message::RouterAdvertisement(ra)) = Message::decode(&bytes) else {
            panic!("decodes");
        };
        assert_eq!(ra.preference, Preference::Low);
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[24, 1, 0, 0x10, 0, 0, 0x0e, 0x10]);
        assert_eq!(
            Message::decode(&bytes).unwrap().options(),
            &[NdOption::RouteInformation {
                prefix: "::/0".parse().unwrap(),
                preference: Preference::Medium,
                lifetime: 3600
            }]
        );
    }

    #[test]
    fn route_information_carries_as_many_prefix_bytes_as_its_length_allows() {
        for (prefix, len) in [
            ("::/0", 1u8),
            ("2001:db8::/32", 2),
            ("2001:db8:1::/48", 2),
            ("2001:db8:1:2:3::/80", 3),
        ] {
            let message = Message::RouterAdvertisement(RouterAdvertisement {
                options: vec![NdOption::RouteInformation {
                    prefix: prefix.parse().unwrap(),
                    preference: Preference::Low,
                    lifetime: 1,
                }],
                ..RouterAdvertisement::default()
            });
            let bytes = message.encode();
            assert_eq!(bytes[17], len, "{prefix}");
            assert_eq!(Message::decode(&bytes), Ok(message), "{prefix}");
        }
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[24, 1, 65, 0, 0, 0, 0, 1]);
        assert!(
            matches!(
                Message::decode(&bytes).unwrap().options()[0],
                NdOption::Unknown { kind: 24, .. }
            ),
            "65 bits in 0 bytes"
        );
    }

    #[test]
    fn an_rdnss_address_and_an_sllao_of_another_size_survive() {
        let mut bytes = Message::RouterAdvertisement(RouterAdvertisement::default()).encode();
        bytes.extend_from_slice(&[1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
        let decoded = Message::decode(&bytes).unwrap();
        assert!(
            matches!(decoded.options()[0], NdOption::Unknown { kind: 1, .. }),
            "a 16-byte link-layer address is not ethernet's"
        );
        assert_eq!(decoded.encode(), bytes);
        let addr: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
        let rdnss = Message::RouterAdvertisement(RouterAdvertisement {
            options: vec![NdOption::Rdnss {
                lifetime: 0,
                addrs: vec![addr, addr],
            }],
            ..RouterAdvertisement::default()
        });
        assert_eq!(rdnss.encode()[17], 5, "length 1 + 2 per address");
        assert_eq!(Message::decode(&rdnss.encode()), Ok(rdnss));
    }
}
