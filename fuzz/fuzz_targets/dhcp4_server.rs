// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the DHCPv4 server core (SPEC §11): arbitrary bytes as a received packet, then a probe
//! reply and a late timeout, must never panic, and no expired lease may survive the timeout.

#![no_main]

use std::net::Ipv4Addr;

use libfuzzer_sys::fuzz_target;
use openfeo_proto_dhcp4::server::Input;
use openfeo_proto_dhcp4::{LeaseRecord, Reservation, Server, ServerConfig};

const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const POOL_START: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);

fn config() -> ServerConfig {
    ServerConfig {
        server: SERVER,
        prefix: 24,
        pool: (POOL_START, Ipv4Addr::new(192, 168, 1, 200)),
        lease_secs: 43_200,
        dns: vec![],
        ntp: vec![],
        domain: Some("home.arpa".to_owned()),
        reservations: vec![Reservation {
            mac: [0x52, 0x54, 0, 0xfe, 0x10, 0x10],
            client_id: None,
            address: Ipv4Addr::new(192, 168, 1, 10),
            hostname: Some("nas".to_owned()),
        }],
    }
}

fn leases() -> Vec<LeaseRecord> {
    vec![
        LeaseRecord {
            address: Ipv4Addr::new(192, 168, 1, 100),
            mac: [2, 0, 0, 0, 0, 1],
            client_id: None,
            hostname: Some("pc".to_owned()),
            granted_at: 0,
            expires_at: 3_000,
        },
        LeaseRecord {
            address: Ipv4Addr::new(192, 168, 1, 101),
            mac: [2, 0, 0, 0, 0, 2],
            client_id: Some(vec![0xff, 1, 2, 3, 4]),
            hostname: None,
            granted_at: 0,
            expires_at: 50_000,
        },
    ]
}

fuzz_target!(|data: &[u8]| {
    let mut server = Server::new(config(), leases(), 0);
    let _ = server.handle(Input::Packet(data.to_vec()), 1);
    let _ = server.handle(
        Input::ProbeReply {
            address: POOL_START,
            mac: [9; 6],
        },
        2,
    );
    let _ = server.handle(Input::Packet(data.to_vec()), 3);
    let _ = server.handle(Input::Timeout, 5_000);
    assert!(
        server.leases().iter().all(|lease| lease.expires_at > 5_000),
        "an expired lease survived the timeout"
    );
    if let Some(next) = server.next_timeout() {
        assert!(next > 5_000, "a timer in the past: {next}");
    }
});
