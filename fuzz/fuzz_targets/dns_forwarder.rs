// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the DNS forwarder core (SPEC §11): arbitrary bytes as a client's query over UDP and
//! TCP, then as the upstream's reply under the forwarded id, then every timeout, must never
//! panic, never leave more than `MAX_PENDING` queries waiting, and leave none waiting once every
//! attempt has timed out.
//!
//! The input is a two-byte big-endian length, the client's query, and the upstream's reply.

#![no_main]

use std::net::Ipv4Addr;

use libfuzzer_sys::fuzz_target;
use openfeo_proto_dns::Message;
use openfeo_proto_dns::forwarder::{
    Config, Forwarder, Input, LocalRecord, MAX_ATTEMPTS, MAX_PENDING, Output, Transport,
    UPSTREAM_TIMEOUT,
};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

fn config() -> Config {
    Config {
        upstreams: vec![Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2)],
        domain: "home.arpa".parse().expect("a name"),
        router_name: Some("openfeo.home.arpa".parse().expect("a name")),
        router_addrs: vec![Ipv4Addr::new(192, 168, 1, 1)],
        wan_addrs: Vec::new(),
        lan_subnets: vec!["192.168.1.0/24".parse().expect("a subnet")],
        guard_subnets: vec!["192.168.1.0/24".parse().expect("a subnet")],
        local: vec![LocalRecord {
            name: "nas.home.arpa".parse().expect("a name"),
            addr: Ipv4Addr::new(192, 168, 1, 10),
        }],
        rebind_allow: vec!["allowed.isp.example".parse().expect("a name")],
        cache_capacity: 16,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((len, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let split = usize::from(u16::from_be_bytes(*len)).min(rest.len());
    let (query, reply) = rest.split_at(split);
    let mut forwarder = Forwarder::new(config(), 7);
    for (id, transport) in [(1, Transport::Udp), (2, Transport::Tcp)] {
        let outputs = forwarder.handle(
            Input::Query {
                id,
                client: CLIENT,
                transport,
                bytes: query.to_vec(),
            },
            1,
        );
        for output in outputs {
            let Output::Forward {
                upstream,
                transport,
                bytes,
            } = output
            else {
                continue;
            };
            let forwarded = Message::decode(&bytes).expect("our own upstream query decodes");
            let mut reply = reply.to_vec();
            if let Some(id) = reply.first_chunk_mut::<2>() {
                *id = forwarded.header.id.to_be_bytes();
            }
            let _ = forwarder.handle(
                Input::UpstreamReply {
                    upstream,
                    transport,
                    bytes: reply,
                },
                2,
            );
        }
    }
    assert!(forwarder.pending() <= MAX_PENDING);
    let mut now = 2;
    for _ in 0..=MAX_ATTEMPTS {
        now += UPSTREAM_TIMEOUT;
        let _ = forwarder.handle(Input::Timeout, now);
        if let Some(next) = forwarder.next_timeout() {
            assert!(next > now, "a timer in the past: {next}");
        }
    }
    assert_eq!(
        forwarder.pending(),
        0,
        "a query survived every attempt's timeout"
    );
});
