// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Arbitrary bytes as an advertisement to the WAN client core (SPEC §11): link up, the bytes
//! from a link-local router with hop limit 255, then every timeout the core asks for, must
//! never panic and must never ask for a timer in the past.

#![no_main]

use std::net::Ipv6Addr;

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ndp::client::{Client, Config, Input, RS_BACKOFF_MAX};

fuzz_target!(|data: &[u8]| {
    let mut client = Client::new(Config {
        ifname: "p0".to_owned(),
        secret: [7; 16],
        mac: [0x52, 0x54, 0, 0xfe, 0, 0],
    });
    let _ = client.handle(Input::LinkUp, 0);
    let _ = client.handle(
        Input::Advertisement {
            from: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            hop_limit: 255,
            bytes: data.to_vec(),
        },
        1,
    );
    let mut now = 1;
    for _ in 0..64 {
        let Some(next) = client.next_timeout() else {
            break;
        };
        assert!(next > now, "a timer in the past: {next} at {now}");
        if next > 4 * RS_BACKOFF_MAX {
            break;
        }
        now = next;
        let _ = client.handle(Input::Timeout, now);
    }
});
