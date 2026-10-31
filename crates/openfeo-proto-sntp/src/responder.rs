// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The LAN-side server (RFC 4330 §5, the server side): a client's request is answered with our
//! clock, one stratum below our source while we are synced, and honestly unsynchronised
//! otherwise, so clients keep trying rather than take a wrong time.

use crate::client::SyncState;
use crate::packet::{
    LI_UNSYNCHRONISED, MODE_CLIENT, MODE_SERVER, PACKET_LEN, Packet, STRATUM_UNSYNCHRONISED,
};
use crate::timestamp::{NANOS_PER_SEC, NtpTimestamp, nanos_to_short};

/// Our precision: about a microsecond (2^-20 s).
pub const PRECISION: i8 = -20;
/// Dispersion we add to the upstream's at the moment of a sample.
pub const OWN_DISPERSION_NS: i64 = 1_000_000;
/// RFC 5905 §11.2 PHI: the dispersion grows by this many parts per million of the time since the
/// last sample, our clock's assumed drift.
pub const PHI_PPM: i64 = 15;

/// The reply to a client's `query`, or `None` for anything that is not a version 3 or 4 mode 3
/// request: version copied, mode 4; while synced LI 0, stratum one below the source's (16 stays
/// 16), the source's address as the reference id, root delay and dispersion the upstream's plus
/// ours; otherwise LI 3, stratum 16 and a zero reference id. Originate is the query's transmit,
/// receive and transmit are `now`, reference is the state's.
#[must_use]
pub fn respond(query: &[u8], now_unix_ns: i64, state: &SyncState) -> Option<[u8; PACKET_LEN]> {
    let query = Packet::decode(query).ok()?;
    if query.mode != MODE_CLIENT || !(3..=4).contains(&query.version) {
        return None;
    }
    let now = NtpTimestamp::from_unix_nanos(now_unix_ns);
    let synced = state.synced && state.source.is_some();
    // Seconds since the last sample, aged at PHI: a clock last set an hour ago is 54 ms looser.
    let age_secs = state
        .last_sync_unix_secs
        .map_or(0, |last| (now_unix_ns / NANOS_PER_SEC - last).max(0));
    let aged_dispersion = state
        .root_dispersion_ns
        .saturating_add(OWN_DISPERSION_NS)
        .saturating_add(age_secs.saturating_mul(PHI_PPM * 1_000));
    let reply = Packet {
        leap: if synced { 0 } else { LI_UNSYNCHRONISED },
        version: query.version,
        mode: MODE_SERVER,
        stratum: if synced {
            state.stratum.saturating_add(1).min(STRATUM_UNSYNCHRONISED)
        } else {
            STRATUM_UNSYNCHRONISED
        },
        poll: query.poll,
        precision: PRECISION,
        root_delay: nanos_to_short(state.root_delay_ns.saturating_add(state.delay_ns)),
        root_dispersion: nanos_to_short(aged_dispersion),
        reference_id: match state.source {
            Some(source) if synced => source.octets(),
            _ => [0; 4],
        },
        reference: state.reference,
        originate: query.transmit,
        receive: now,
        transmit: now,
    };
    Some(reply.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::SyncState;
    use crate::packet::{LI_UNSYNCHRONISED, MODE_CLIENT, MODE_SERVER, STRATUM_UNSYNCHRONISED};
    use crate::timestamp::{NANOS_PER_SEC, NtpTimestamp, short_to_nanos};
    use std::net::Ipv4Addr;

    const UNIX_2026: i64 = 1_793_448_000 * NANOS_PER_SEC;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    #[test]
    fn a_synced_router_answers_one_stratum_below_its_source() {
        let state = SyncState {
            synced: true,
            source: Some(ip("203.0.113.1")),
            stratum: 2,
            delay_ns: 12_000_000,
            root_delay_ns: 20_000_000,
            root_dispersion_ns: 5_000_000,
            reference: NtpTimestamp::from_unix_nanos(UNIX_2026),
            ..SyncState::default()
        };
        let query = Packet {
            version: 4,
            mode: MODE_CLIENT,
            transmit: NtpTimestamp(0x1234_5678_9abc_def0),
            ..Packet::default()
        };
        let reply =
            Packet::decode(&respond(&query.encode(), UNIX_2026 + 1_000_000, &state).unwrap())
                .unwrap();
        assert_eq!(
            (reply.leap, reply.version, reply.mode, reply.stratum),
            (0, 4, MODE_SERVER, 3)
        );
        assert_eq!(reply.reference_id, [203, 0, 113, 1]);
        assert_eq!(reply.originate, query.transmit);
        assert_eq!(
            reply.receive,
            NtpTimestamp::from_unix_nanos(UNIX_2026 + 1_000_000)
        );
        assert_eq!(reply.transmit, reply.receive);
        assert_eq!(reply.reference, state.reference);
        // An NTP short resolves to 1/65536 s (about 15 µs).
        assert!((short_to_nanos(reply.root_delay) - 32_000_000).abs() < 16_000);
        assert!((short_to_nanos(reply.root_dispersion) - 6_000_000).abs() < 16_000);
        assert_eq!(reply.precision, PRECISION);
        let v3 = Packet {
            version: 3,
            ..query
        };
        assert_eq!(
            Packet::decode(&respond(&v3.encode(), UNIX_2026, &state).unwrap())
                .unwrap()
                .version,
            3
        );
    }

    #[test]
    fn unsynchronised_replies_say_so() {
        let query = Packet {
            version: 4,
            mode: MODE_CLIENT,
            transmit: NtpTimestamp(1),
            ..Packet::default()
        };
        let reply =
            Packet::decode(&respond(&query.encode(), UNIX_2026, &SyncState::default()).unwrap())
                .unwrap();
        assert_eq!(
            (reply.leap, reply.stratum, reply.reference_id),
            (LI_UNSYNCHRONISED, STRATUM_UNSYNCHRONISED, [0; 4])
        );
        assert_eq!(reply.originate, query.transmit);
    }

    #[test]
    fn only_client_requests_are_answered() {
        let state = SyncState::default();
        assert!(
            respond(
                &Packet {
                    version: 4,
                    mode: MODE_SERVER,
                    ..Packet::default()
                }
                .encode(),
                UNIX_2026,
                &state
            )
            .is_none(),
            "a server packet"
        );
        assert!(
            respond(
                &Packet {
                    version: 4,
                    mode: 5,
                    ..Packet::default()
                }
                .encode(),
                UNIX_2026,
                &state
            )
            .is_none(),
            "broadcast"
        );
        assert!(respond(&[0; 47], UNIX_2026, &state).is_none(), "short");
        assert!(
            respond(
                &Packet {
                    version: 2,
                    mode: MODE_CLIENT,
                    ..Packet::default()
                }
                .encode(),
                UNIX_2026,
                &state
            )
            .is_none(),
            "version 2"
        );
    }

    #[test]
    fn root_dispersion_ages_at_phi_since_the_last_sample() {
        let state = SyncState {
            synced: true,
            source: Some(ip("203.0.113.1")),
            stratum: 2,
            root_dispersion_ns: 5_000_000,
            last_sync_unix_secs: Some(1_793_448_000),
            ..SyncState::default()
        };
        let query = Packet {
            version: 4,
            mode: MODE_CLIENT,
            transmit: NtpTimestamp(0x1234_5678_9abc_def0),
            ..Packet::default()
        };
        let fresh = Packet::decode(&respond(&query.encode(), UNIX_2026, &state).unwrap()).unwrap();
        assert!(
            (short_to_nanos(fresh.root_dispersion) - 6_000_000).abs() < 16_000,
            "5 ms upstream + 1 ms own, got {}",
            short_to_nanos(fresh.root_dispersion)
        );
        let later = Packet::decode(
            &respond(&query.encode(), UNIX_2026 + 1_000 * NANOS_PER_SEC, &state).unwrap(),
        )
        .unwrap();
        assert!(
            (short_to_nanos(later.root_dispersion) - 21_000_000).abs() < 16_000,
            "1000 s at 15 ppm is 15 ms more, got {}",
            short_to_nanos(later.root_dispersion)
        );
    }
}
