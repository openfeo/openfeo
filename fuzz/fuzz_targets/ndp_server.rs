// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Arbitrary bytes as a solicitation to the LAN server core (SPEC §11): start, the bytes from
//! a link-local host with hop limit 255, every timeout for two advertisement intervals, then
//! stop, must never panic, never ask for a timer in the past, and stop within four final
//! intervals.

#![no_main]

use std::net::Ipv6Addr;

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ndp::server::{
    Config, Input, Lifetime, MAX_RTR_ADV_INTERVAL, MIN_DELAY_BETWEEN_RAS, Output, PIO_PREFERRED,
    PIO_VALID, Pio, Server,
};

fuzz_target!(|data: &[u8]| {
    let mut server = Server::new(
        Config {
            prefixes: vec![Pio {
                prefix: "2001:db8:1:222::/64".parse().expect("a prefix"),
                valid: Lifetime::Fixed(PIO_VALID),
                preferred: Lifetime::Fixed(PIO_PREFERRED),
            }],
            mac: [0x52, 0x54, 0, 0xfe, 0, 2],
            rdnss: vec!["2001:db8:1:222::1".parse().expect("an address")],
            mtu: Some(1500),
            domain: "home.arpa".to_owned(),
            router_lifetime: 1800,
            other: true,
            routes: Vec::new(),
        },
        u64::from(data.first().copied().unwrap_or(1)),
    );
    let _ = server.handle(Input::Start, 0);
    let _ = server.handle(
        Input::Solicitation {
            from: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            hop_limit: 255,
            bytes: data.to_vec(),
        },
        1,
    );
    let mut now = 1;
    while let Some(next) = server.next_timeout() {
        assert!(next > now, "a timer in the past: {next} at {now}");
        if next > 2 * MAX_RTR_ADV_INTERVAL {
            break;
        }
        now = next;
        let _ = server.handle(Input::Timeout, now);
    }
    let stop_at = now + 1;
    let mut outputs = server.handle(Input::Stop, stop_at);
    while let Some(next) = server.next_timeout() {
        assert!(next > now, "a timer in the past: {next} at {now}");
        now = next;
        outputs.extend(server.handle(Input::Timeout, now));
    }
    assert!(outputs.contains(&Output::Stopped), "stops");
    assert!(now <= stop_at + 4 * MIN_DELAY_BETWEEN_RAS, "stopped late: {now}");
});
