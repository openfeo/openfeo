// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The PPP session core under arbitrary frames, timeouts and commands: it never panics, never
//! sends after `Down` until the next `Start`, and never leaves a timer in the past (SPEC §11).

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_proto_ppp::frame::{CHAP, IPCP, IPV6CP, LCP, PAP};
use openfeo_proto_ppp::session::{Config, Input, Output, Session};

fuzz_target!(|data: &[u8]| {
    let config = Config {
        username: "openfeo@isp.example".to_owned(),
        password: b"example-secret".to_vec(),
        mru: 1492,
        secret: [7; 16],
        wan: "wan0".to_owned(),
    };
    let mut session = Session::new(config, 0x5eed);
    let mut now: u64 = 0;
    let mut alive = false;
    let mut rest = data;
    while let Some((&kind, after)) = rest.split_first() {
        rest = after;
        let input = match kind % 8 {
            0 => Input::Start,
            1 => Input::Stop,
            2 => Input::CarrierLost,
            3 => {
                now += u64::from(rest.first().copied().unwrap_or(1)) * 500;
                rest = rest.get(1..).unwrap_or(&[]);
                Input::Timeout
            }
            n => {
                let len = usize::from(rest.first().copied().unwrap_or(0));
                rest = rest.get(1..).unwrap_or(&[]);
                let take = len.min(rest.len());
                let payload = rest[..take].to_vec();
                rest = &rest[take..];
                let protocol = match n {
                    4 => LCP,
                    5 => PAP,
                    6 => CHAP,
                    _ => {
                        if payload.len() % 3 == 0 {
                            IPCP
                        } else if payload.len() % 3 == 1 {
                            IPV6CP
                        } else {
                            0x8099
                        }
                    }
                };
                Input::Frame { protocol, payload }
            }
        };
        let started = matches!(input, Input::Start);
        let out = session.handle(input, now);
        for output in &out {
            match output {
                Output::Send { .. } => assert!(alive || started, "a send while dead: {out:?}"),
                Output::Down { .. } => alive = false,
                _ => {}
            }
        }
        if started {
            alive = true;
        }
        if let Some(due) = session.next_timeout() {
            assert!(due >= now, "a timer in the past: {due} < {now}");
        }
    }
});
