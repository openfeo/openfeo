// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The DHCPv6 client core on arbitrary input: packets and timeouts in any order never panic,
//! and the next timer never lies in the past (SPEC §11).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_dhcp6::client::{Client, Config, Input};

fuzz_target!(|data: &[u8]| {
    let config = Config {
        duid: vec![0, 3, 0, 1, 0x52, 0x54, 0, 0xfe, 0, 0],
        iaid_pd: 0x11,
        iaid_na: 0x22,
        pd_hint: 56,
    };
    let mut client = Client::new(config, 0x5eed);
    let mut now: u64 = 0;
    client.handle(Input::Start { binding: None }, now);
    let mut rest = data;
    while let Some((&selector, tail)) = rest.split_first() {
        rest = tail;
        let input = match selector % 4 {
            0 => {
                now = client.next_timeout().unwrap_or(now).max(now);
                Input::Timeout
            }
            1 => Input::LinkDown,
            2 => Input::LinkUp,
            _ => {
                let len = usize::from(rest.first().copied().unwrap_or(0)).min(rest.len());
                let packet = rest[..len].to_vec();
                rest = &rest[len..];
                Input::Packet(packet)
            }
        };
        client.handle(input, now);
        if let Some(due) = client.next_timeout() {
            assert!(due >= now, "a timer in the past");
        }
        now = now.saturating_add(1);
    }
});
