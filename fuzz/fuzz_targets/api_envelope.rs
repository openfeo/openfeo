// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the WebSocket envelope (SPEC §8.3, §11): the input is a sequence of frames (a length
//! byte, then that many bytes) fed to one connection whose backend accepts any token. Whatever
//! arrives, the core never panics, closes at most once, says nothing after closing, and never
//! queues more than its limits allow.

#![no_main]

use libfuzzer_sys::fuzz_target;
use openfeo_api::envelope::{Backend, Conn, Out};
use openfeo_config::api::Response;
use openfeo_config::events::Event;
use openfeo_config::state::{Counters, State};

struct Open;

impl Backend for Open {
    fn authenticate(&mut self, _token: &str) -> bool {
        true
    }

    fn backlog(&mut self, n: u32) -> Vec<Event> {
        (0..n.min(300)).map(|_| Event::default()).collect()
    }
}

fuzz_target!(|data: &[u8]| {
    let mut conn = Conn::new();
    let mut closes = 0;
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len).min(tail.len());
        let (frame, tail) = tail.split_at(len);
        rest = tail;
        for out in conn.on_binary(frame, &mut Open) {
            match out {
                Out::Send(_) => assert_eq!(closes, 0, "nothing is sent after a close"),
                Out::Ask { id, .. } => conn.reply(id, Ok(Response { body: None })),
                Out::Close(_) => closes += 1,
            }
        }
        conn.push_state(&State::default());
        conn.push_counters(&Counters::default());
        conn.push_event(&Event::default());
        let mut queued = 0;
        while conn.next_out().is_some() {
            queued += 1;
            assert!(queued <= 1024, "the outbox is bounded");
        }
    }
    assert!(closes <= 1);
});
