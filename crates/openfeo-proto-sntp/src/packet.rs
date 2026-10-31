// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The 48-byte SNTP packet (RFC 4330 §4): leap indicator, version and mode in the first byte,
//! then stratum, poll, precision, root delay, root dispersion, reference id and the four
//! timestamps. Anything after the 48 bytes (an authenticator) is ignored.

use crate::timestamp::NtpTimestamp;

pub const PACKET_LEN: usize = 48;
pub const MODE_CLIENT: u8 = 3;
pub const MODE_SERVER: u8 = 4;
/// Leap indicator 3: the server's clock is not synchronised.
pub const LI_UNSYNCHRONISED: u8 = 3;
/// Stratum 16: unsynchronised (RFC 5905 §7.3).
pub const STRATUM_UNSYNCHRONISED: u8 = 16;
/// Stratum 0: a kiss-o'-death; the reference id is an ASCII code (RFC 5905 §7.4).
pub const STRATUM_KISS: u8 = 0;

/// One SNTP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Packet {
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    /// An NTP short: 16.16 seconds.
    pub root_delay: u32,
    /// An NTP short: 16.16 seconds.
    pub root_dispersion: u32,
    pub reference_id: [u8; 4],
    pub reference: NtpTimestamp,
    pub originate: NtpTimestamp,
    pub receive: NtpTimestamp,
    pub transmit: NtpTimestamp,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("{0} bytes, 48 needed")]
    TooShort(usize),
    #[error("version {0}")]
    Version(u8),
}

impl Packet {
    /// The first 48 bytes as a packet; extra bytes (an authenticator) are ignored.
    ///
    /// # Errors
    ///
    /// Fewer than 48 bytes, or a version outside 1 to 4.
    pub fn decode(bytes: &[u8]) -> Result<Packet, DecodeError> {
        let Some(bytes) = bytes.first_chunk::<PACKET_LEN>() else {
            return Err(DecodeError::TooShort(bytes.len()));
        };
        let version = (bytes[0] >> 3) & 0x7;
        if !(1..=4).contains(&version) {
            return Err(DecodeError::Version(version));
        }
        let word = |at: usize| {
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let stamp = |at: usize| NtpTimestamp((u64::from(word(at)) << 32) | u64::from(word(at + 4)));
        Ok(Packet {
            leap: bytes[0] >> 6,
            version,
            mode: bytes[0] & 0x7,
            stratum: bytes[1],
            poll: i8::from_ne_bytes([bytes[2]]),
            precision: i8::from_ne_bytes([bytes[3]]),
            root_delay: word(4),
            root_dispersion: word(8),
            reference_id: [bytes[12], bytes[13], bytes[14], bytes[15]],
            reference: stamp(16),
            originate: stamp(24),
            receive: stamp(32),
            transmit: stamp(40),
        })
    }

    #[must_use]
    pub fn encode(&self) -> [u8; PACKET_LEN] {
        let mut bytes = [0u8; PACKET_LEN];
        bytes[0] = (self.leap << 6) | ((self.version & 0x7) << 3) | (self.mode & 0x7);
        bytes[1] = self.stratum;
        bytes[2] = self.poll.to_ne_bytes()[0];
        bytes[3] = self.precision.to_ne_bytes()[0];
        bytes[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.reference_id);
        bytes[16..24].copy_from_slice(&self.reference.0.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.originate.0.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.receive.0.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.transmit.0.to_be_bytes());
        bytes
    }

    /// The kiss code when this is a kiss-o'-death (stratum 0).
    #[must_use]
    pub fn kiss_code(&self) -> Option<[u8; 4]> {
        (self.stratum == STRATUM_KISS).then_some(self.reference_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timestamp::NtpTimestamp;

    #[test]
    fn a_client_request_encodes_to_48_bytes_and_decodes_back() {
        let request = Packet {
            leap: 0,
            version: 4,
            mode: MODE_CLIENT,
            poll: 6,
            precision: -20,
            transmit: NtpTimestamp(0xe9d2_3c00_8000_0000),
            ..Packet::default()
        };
        let bytes = request.encode();
        assert_eq!(bytes.len(), PACKET_LEN);
        assert_eq!(bytes[0], 0b00_100_011, "LI 0, VN 4, mode 3");
        assert_eq!(&bytes[40..48], &0xe9d2_3c00_8000_0000u64.to_be_bytes());
        assert_eq!(Packet::decode(&bytes), Ok(request));
    }

    #[test]
    fn decoding_accepts_trailing_bytes_and_refuses_short_or_versionless_packets() {
        let mut with_mac = Packet {
            version: 4,
            mode: MODE_SERVER,
            stratum: 2,
            ..Packet::default()
        }
        .encode()
        .to_vec();
        with_mac.extend_from_slice(&[0; 20]);
        assert_eq!(Packet::decode(&with_mac).map(|p| p.stratum), Ok(2));
        assert_eq!(Packet::decode(&[0; 47]), Err(DecodeError::TooShort(47)));
        let mut v0 = [0u8; 48];
        v0[0] = 0b00_000_011;
        assert_eq!(Packet::decode(&v0), Err(DecodeError::Version(0)));
        let mut v3 = [0u8; 48];
        v3[0] = 0b11_011_100;
        assert_eq!(
            Packet::decode(&v3).map(|p| (p.leap, p.version, p.mode)),
            Ok((3, 3, 4))
        );
    }

    #[test]
    fn stratum_zero_carries_a_kiss_code() {
        let kiss = Packet {
            version: 4,
            mode: MODE_SERVER,
            stratum: 0,
            reference_id: *b"RATE",
            ..Packet::default()
        };
        assert_eq!(kiss.kiss_code(), Some(*b"RATE"));
        assert_eq!(Packet { stratum: 2, ..kiss }.kiss_code(), None);
    }

    /// `cargo test -p openfeo-proto-sntp -- --ignored write_sntp_fuzz_corpus` writes the seeds of
    /// the `sntp_packet` fuzz target: a client request, a server reply and a kiss-o'-death.
    #[test]
    #[ignore = "writes fuzz/corpus/sntp_packet/seed-*.bin"]
    fn write_sntp_fuzz_corpus() {
        let request = Packet {
            version: 4,
            mode: MODE_CLIENT,
            poll: 6,
            precision: -20,
            transmit: NtpTimestamp(0xe9d2_3c00_8000_0000),
            ..Packet::default()
        };
        let reply = Packet {
            version: 4,
            mode: MODE_SERVER,
            stratum: 2,
            poll: 6,
            precision: -23,
            root_delay: 0x0000_0800,
            root_dispersion: 0x0000_0400,
            reference_id: [203, 0, 113, 1],
            reference: NtpTimestamp(0xe9d2_3b00_0000_0000),
            originate: request.transmit,
            receive: NtpTimestamp(0xe9d2_3c00_8100_0000),
            transmit: NtpTimestamp(0xe9d2_3c00_8200_0000),
            ..Packet::default()
        };
        let kiss = Packet {
            stratum: STRATUM_KISS,
            reference_id: *b"RATE",
            ..reply
        };
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/sntp_packet");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, packet) in [
            ("seed-request.bin", request),
            ("seed-reply.bin", reply),
            ("seed-kiss.bin", kiss),
        ] {
            std::fs::write(dir.join(name), packet.encode()).unwrap();
        }
    }
}
