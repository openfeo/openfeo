// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! IPv4 and UDP headers around a DHCP message, for the raw-socket path a client takes before it
//! has an address (SPEC §7.2): the kernel cannot build them for us there.

use std::net::Ipv4Addr;

use thiserror::Error;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const PROTO_UDP: u8 = 17;
const TTL: u8 = 64;
/// Don't fragment: a server honours our maximum message size, so nothing here needs it.
const FLAGS_DF: u16 = 0x4000;
/// More-fragments bit and the 13-bit fragment offset.
const FRAGMENT_MASK: u16 = 0x3fff;

/// A UDP datagram taken out of an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

/// Why a packet yields no datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecapError {
    #[error("shorter than an IPv4 header")]
    TooShort,
    #[error("not IPv4")]
    NotIpv4,
    #[error("not UDP")]
    NotUdp,
    #[error("a fragment")]
    Fragment,
    #[error("IPv4 header checksum mismatch")]
    HeaderChecksum,
    #[error("length fields disagree with the packet")]
    Length,
    #[error("UDP checksum mismatch")]
    UdpChecksum,
}

/// The Internet checksum (RFC 1071) of `bytes`: the one's-complement of the one's-complement
/// sum of its 16-bit big-endian words, an odd trailing byte padded with zero. Over a header
/// that carries its own checksum it is 0 when the header is intact.
#[must_use]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in bytes.chunks(2) {
        let word = match chunk {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from_be_bytes([*high, 0]),
            _ => 0,
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// `payload` as a UDP datagram from `src:sport` to `dst:dport` inside an IPv4 packet: IHL 5,
/// TTL 64, DF set, both checksums filled in.
#[must_use]
pub fn encapsulate(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + udp_len;
    let udp_len16 = u16::try_from(udp_len).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&[0x45, 0x00]);
    out.extend_from_slice(&u16::try_from(total_len).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&FLAGS_DF.to_be_bytes());
    out.extend_from_slice(&[TTL, PROTO_UDP, 0, 0]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    let header_sum = internet_checksum(&out).to_be_bytes();
    out[10..12].copy_from_slice(&header_sum);

    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&udp_len16.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    let mut udp_sum = internet_checksum(&pseudo_header(src, dst, &out[IPV4_HEADER_LEN..]));
    if udp_sum == 0 {
        udp_sum = 0xffff;
    }
    out[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].copy_from_slice(&udp_sum.to_be_bytes());
    out
}

/// The UDP datagram inside the IPv4 `packet`.
///
/// # Errors
///
/// When the packet is not a whole, unfragmented IPv4/UDP packet whose header checksum, length
/// fields and (non-zero) UDP checksum are consistent.
pub fn decapsulate(packet: &[u8]) -> Result<Datagram<'_>, DecapError> {
    let fixed = packet.get(..IPV4_HEADER_LEN).ok_or(DecapError::TooShort)?;
    let ihl = usize::from(fixed[0] & 0x0f) * 4;
    if fixed[0] >> 4 != 4 || ihl < IPV4_HEADER_LEN {
        return Err(DecapError::NotIpv4);
    }
    let header = packet.get(..ihl).ok_or(DecapError::TooShort)?;
    if internet_checksum(header) != 0 {
        return Err(DecapError::HeaderChecksum);
    }
    if fixed[9] != PROTO_UDP {
        return Err(DecapError::NotUdp);
    }
    if u16::from_be_bytes([fixed[6], fixed[7]]) & FRAGMENT_MASK != 0 {
        return Err(DecapError::Fragment);
    }
    let total_len = usize::from(u16::from_be_bytes([fixed[2], fixed[3]]));
    if total_len < ihl + UDP_HEADER_LEN || total_len > packet.len() {
        return Err(DecapError::Length);
    }
    let udp = &packet[ihl..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len != udp.len() {
        return Err(DecapError::Length);
    }
    let src = Ipv4Addr::new(fixed[12], fixed[13], fixed[14], fixed[15]);
    let dst = Ipv4Addr::new(fixed[16], fixed[17], fixed[18], fixed[19]);
    if u16::from_be_bytes([udp[6], udp[7]]) != 0
        && internet_checksum(&pseudo_header(src, dst, udp)) != 0
    {
        return Err(DecapError::UdpChecksum);
    }
    Ok(Datagram {
        src,
        dst,
        sport: u16::from_be_bytes([udp[0], udp[1]]),
        dport: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[UDP_HEADER_LEN..],
    })
}

/// The UDP pseudo-header (RFC 768) followed by the UDP segment, what the UDP checksum covers.
fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + udp.len());
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&[0, PROTO_UDP]);
    out.extend_from_slice(&u16::try_from(udp.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(udp);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const ANY: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    const ALL: Ipv4Addr = Ipv4Addr::BROADCAST;

    /// A packet with its IPv4 header checksum recomputed after `edit` changed the header.
    fn edited(mut packet: Vec<u8>, edit: impl FnOnce(&mut [u8])) -> Vec<u8> {
        edit(&mut packet);
        packet[10] = 0;
        packet[11] = 0;
        let sum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    #[test]
    fn encapsulate_then_decapsulate_round_trips() {
        let payload = vec![0xabu8; 300];
        let packet = encapsulate(ANY, ALL, 68, 67, &payload);
        assert_eq!(packet.len(), 20 + 8 + 300);
        assert_eq!(packet[0], 0x45, "IPv4, IHL 5");
        assert_eq!(&packet[2..4], &328u16.to_be_bytes(), "total length");
        assert_eq!(packet[8], 64, "TTL");
        assert_eq!(packet[9], 17, "UDP");
        assert_eq!(&packet[12..16], &[0, 0, 0, 0]);
        assert_eq!(&packet[16..20], &[255, 255, 255, 255]);
        assert_eq!(&packet[20..22], &68u16.to_be_bytes());
        assert_eq!(&packet[22..24], &67u16.to_be_bytes());
        assert_eq!(&packet[24..26], &308u16.to_be_bytes(), "UDP length");
        assert_eq!(internet_checksum(&packet[..20]), 0, "header verifies");

        let d = decapsulate(&packet).unwrap();
        assert_eq!((d.src, d.dst, d.sport, d.dport), (ANY, ALL, 68, 67));
        assert_eq!(d.payload, &payload[..]);
    }

    #[test]
    fn ipv4_header_checksum_matches_a_known_vector() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet_checksum(&header), 0xb861);
    }

    #[test]
    fn fragments_bad_checksums_and_short_packets_are_errors() {
        let packet = encapsulate(ANY, ALL, 68, 67, &[1, 2, 3]);
        assert_eq!(decapsulate(&packet[..19]).err(), Some(DecapError::TooShort));
        assert_eq!(
            decapsulate(&edited(packet.clone(), |p| p[0] = 0x65)).err(),
            Some(DecapError::NotIpv4)
        );
        let mut bad_sum = packet.clone();
        bad_sum[8] = 63;
        assert_eq!(
            decapsulate(&bad_sum).err(),
            Some(DecapError::HeaderChecksum)
        );
        assert_eq!(
            decapsulate(&edited(packet.clone(), |p| p[9] = 6)).err(),
            Some(DecapError::NotUdp)
        );
        assert_eq!(
            decapsulate(&edited(packet.clone(), |p| p[6] |= 0x20)).err(),
            Some(DecapError::Fragment),
            "more fragments"
        );
        assert_eq!(
            decapsulate(&edited(packet.clone(), |p| p[7] = 1)).err(),
            Some(DecapError::Fragment),
            "fragment offset"
        );
        assert_eq!(
            decapsulate(&edited(packet.clone(), |p| p[3] += 1)).err(),
            Some(DecapError::Length),
            "total length past the buffer"
        );
        let mut udp_len = packet.clone();
        udp_len[25] -= 1;
        assert_eq!(decapsulate(&udp_len).err(), Some(DecapError::Length));
        let mut udp_sum = packet;
        udp_sum[29] ^= 0xff;
        assert_eq!(decapsulate(&udp_sum).err(), Some(DecapError::UdpChecksum));
    }

    #[test]
    fn zero_udp_checksum_is_accepted() {
        let mut packet = encapsulate(ANY, ALL, 68, 67, &[9; 10]);
        packet[26] = 0;
        packet[27] = 0;
        let d = decapsulate(&packet).unwrap();
        assert_eq!(d.payload, &[9; 10]);
    }
}
