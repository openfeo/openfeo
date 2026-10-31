// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! ARP for Ethernet/IPv4 (RFC 826), as a `SOCK_DGRAM` packet socket carries it: the 28-byte
//! payload without the Ethernet header. The DHCPv4 server probes an address with a request
//! before offering it (SPEC §7.6) and reads the replies.

use std::net::Ipv4Addr;

use thiserror::Error;

/// The Ethernet protocol number of ARP, for a packet socket.
pub const ETH_P_ARP: u16 = 0x0806;
/// The length of an Ethernet/IPv4 ARP packet.
pub const ARP_LEN: usize = 28;

const HTYPE_ETHERNET: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;

/// Request or reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    Request,
    Reply,
}

/// One Ethernet/IPv4 ARP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: ArpOp,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

/// Why bytes are not an Ethernet/IPv4 ARP packet.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArpError {
    #[error("{0} bytes is too short for ARP")]
    TooShort(usize),
    #[error("not Ethernet/IPv4 ARP")]
    NotEthernetIpv4,
    #[error("unknown ARP operation {0}")]
    Op(u16),
}

/// "Who has `target_ip`? Tell `sender_ip`", from `sender_mac`.
#[must_use]
pub fn request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> ArpPacket {
    ArpPacket {
        op: ArpOp::Request,
        sender_mac,
        sender_ip,
        target_mac: [0; 6],
        target_ip,
    }
}

impl ArpPacket {
    /// The 28 bytes on the wire.
    #[must_use]
    pub fn encode(&self) -> [u8; ARP_LEN] {
        let mut out = [0u8; ARP_LEN];
        out[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
        out[4] = 6;
        out[5] = 4;
        let op = match self.op {
            ArpOp::Request => OP_REQUEST,
            ArpOp::Reply => OP_REPLY,
        };
        out[6..8].copy_from_slice(&op.to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac);
        out[14..18].copy_from_slice(&self.sender_ip.octets());
        out[18..24].copy_from_slice(&self.target_mac);
        out[24..28].copy_from_slice(&self.target_ip.octets());
        out
    }

    /// Parse a packet; trailing bytes (padding) are ignored.
    ///
    /// # Errors
    ///
    /// [`ArpError`] for a short packet, a non-Ethernet/IPv4 one, or an operation other than
    /// request or reply.
    pub fn decode(bytes: &[u8]) -> Result<ArpPacket, ArpError> {
        if bytes.len() < ARP_LEN {
            return Err(ArpError::TooShort(bytes.len()));
        }
        let be16 = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        if be16(0) != HTYPE_ETHERNET || be16(2) != PTYPE_IPV4 || bytes[4] != 6 || bytes[5] != 4 {
            return Err(ArpError::NotEthernetIpv4);
        }
        let op = match be16(6) {
            OP_REQUEST => ArpOp::Request,
            OP_REPLY => ArpOp::Reply,
            other => return Err(ArpError::Op(other)),
        };
        let mac = |at: usize| -> [u8; 6] {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&bytes[at..at + 6]);
            mac
        };
        let ip = |at: usize| Ipv4Addr::new(bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]);
        Ok(ArpPacket {
            op,
            sender_mac: mac(8),
            sender_ip: ip(14),
            target_mac: mac(18),
            target_ip: ip(24),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_and_matches_the_wire_layout() {
        let p = request(
            [0x52, 0x54, 0, 0xfe, 0, 2],
            "192.168.1.1".parse().unwrap(),
            "192.168.1.100".parse().unwrap(),
        );
        let bytes = p.encode();
        assert_eq!(
            &bytes[..8],
            &[0, 1, 8, 0, 6, 4, 0, 1],
            "htype 1, ptype 0x0800, hlen 6, plen 4, op 1"
        );
        assert_eq!(&bytes[8..14], &[0x52, 0x54, 0, 0xfe, 0, 2]);
        assert_eq!(&bytes[14..18], &[192, 168, 1, 1]);
        assert_eq!(&bytes[18..24], &[0; 6]);
        assert_eq!(&bytes[24..28], &[192, 168, 1, 100]);
        assert_eq!(ArpPacket::decode(&bytes), Ok(p));
    }

    #[test]
    fn decode_rejects_short_foreign_and_unknown_op() {
        assert_eq!(ArpPacket::decode(&[0; 27]), Err(ArpError::TooShort(27)));
        let mut ipx = request([1; 6], Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED).encode();
        ipx[2] = 0x81;
        ipx[3] = 0x37;
        assert_eq!(ArpPacket::decode(&ipx), Err(ArpError::NotEthernetIpv4));
        let mut op = request([1; 6], Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED).encode();
        op[7] = 9;
        assert_eq!(ArpPacket::decode(&op), Err(ArpError::Op(9)));
        let mut reply = op;
        reply[7] = 2;
        assert_eq!(ArpPacket::decode(&reply).map(|p| p.op), Ok(ArpOp::Reply));
        assert!(
            ArpPacket::decode(&[reply.as_slice(), &[0u8; 18]].concat()).is_ok(),
            "trailing padding is allowed"
        );
    }

    /// Seeds for `fuzz/fuzz_targets/dhcp4_arp.rs`; run with `--ignored` to refresh them.
    #[test]
    #[ignore = "writes the fuzz corpus seeds"]
    fn write_arp_fuzz_corpus() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/dhcp4_arp");
        std::fs::create_dir_all(&dir).unwrap();
        let req = request(
            [0x52, 0x54, 0, 0xfe, 0, 2],
            "192.168.1.1".parse().unwrap(),
            "192.168.1.100".parse().unwrap(),
        );
        std::fs::write(dir.join("seed-request.bin"), req.encode()).unwrap();
        let reply = ArpPacket {
            op: ArpOp::Reply,
            sender_mac: [2, 0, 0, 0, 0, 0x99],
            sender_ip: "192.168.1.100".parse().unwrap(),
            target_mac: [0x52, 0x54, 0, 0xfe, 0, 2],
            target_ip: "192.168.1.1".parse().unwrap(),
        };
        std::fs::write(dir.join("seed-reply.bin"), reply.encode()).unwrap();
    }
}
