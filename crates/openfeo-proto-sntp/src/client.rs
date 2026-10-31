// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The SNTP client (RFC 4330) as a state machine: `Client::handle(Input, Now)` takes a poll
//! timer, a server's reply or new settings and says what to send, how the clock should move and
//! what happened. The driver in `openfeo-net` owns the socket and the clock.

use std::net::Ipv4Addr;

use crate::discipline::{Decision, decide};
use crate::packet::{LI_UNSYNCHRONISED, MODE_CLIENT, MODE_SERVER, Packet, STRATUM_UNSYNCHRONISED};
use crate::timestamp::{NANOS_PER_SEC, Now, NtpTimestamp, short_to_nanos};

/// Between rounds while the clock is not synced.
pub const POLL_UNSYNCED_MS: u64 = 16_000;
/// Between rounds once it is.
pub const POLL_SYNCED_MS: u64 = 1_024_000;
/// How long a server has to answer.
pub const REPLY_TIMEOUT_MS: u64 = 2_000;
/// Consecutive failures that mark a server down, and how long it stays so.
pub const MAX_FAILURES: u8 = 3;
pub const SERVER_HOLD_MS: u64 = 1_024_000;
/// Rounds without a valid sample after which a synced clock is declared unsynced.
pub const LOST_SYNC_ROUNDS: u8 = 4;
/// RFC 5905 MAXDISP: a sample whose root distance reaches it is unusable.
pub const MAX_ROOT_DISTANCE_NS: i64 = 16_000_000_000;
/// Our poll exponent in requests: 2^6 = 64 s, the conventional minimum.
const REQUEST_POLL: i8 = 6;
/// Our precision in requests: about a microsecond.
const REQUEST_PRECISION: i8 = -20;

/// The servers to ask and the time before which nothing is believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub servers: Vec<Ipv4Addr>,
    /// The build timestamp: a server whose time is earlier is wrong.
    pub floor_unix_secs: u64,
}

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// The timer of [`Client::next_poll`] fired.
    Poll,
    Reply {
        server: Ipv4Addr,
        bytes: Vec<u8>,
    },
    Configure(Config),
}

/// What the client wants done or known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Send {
        server: Ipv4Addr,
        bytes: Vec<u8>,
    },
    /// Jump the clock by this many nanoseconds.
    Step(i64),
    /// Slew the clock by this many nanoseconds.
    Slew(i64),
    Event(Event),
}

/// Why a reply was set aside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// LI 3, stratum 16 or above, or no transmit time: the server has no time to give.
    Unsynchronised,
    /// Stratum 0 with this code.
    KissOfDeath([u8; 4]),
    /// Not from the server we asked, or not an answer to what we sent.
    Mismatch,
    /// Not a server packet.
    Format,
    /// Root delay and dispersion too large to trust.
    RootDistance,
}

/// What happened, for the console and the World.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Configured {
        servers: usize,
    },
    /// Once per configuration that leaves none.
    NoServers,
    Step {
        server: Ipv4Addr,
        offset_ns: i64,
        stratum: u8,
    },
    /// A valid sample was applied; also carries the first sync after a loss.
    Synced {
        server: Ipv4Addr,
        offset_ns: i64,
        delay_ns: i64,
        stratum: u8,
    },
    Slewed {
        server: Ipv4Addr,
        offset_ns: i64,
    },
    /// The server's time is before the build.
    Refused {
        server: Ipv4Addr,
        transmit_unix_secs: i64,
        floor_unix_secs: u64,
    },
    Rejected {
        server: Ipv4Addr,
        reason: Reject,
    },
    ServerDown(Ipv4Addr),
    /// `DENY` or `RSTR`: the server is never asked again.
    ServerUnusable {
        server: Ipv4Addr,
        code: [u8; 4],
    },
    LostSync {
        rounds: u8,
    },
}

/// What the clock knows about itself; the responder and `World.time` read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncState {
    pub synced: bool,
    pub source: Option<Ipv4Addr>,
    pub stratum: u8,
    /// The last measured offset, positive when the clock was behind.
    pub offset_ns: i64,
    pub delay_ns: i64,
    pub root_delay_ns: i64,
    pub root_dispersion_ns: i64,
    /// The source's transmit time of the last valid sample.
    pub reference: NtpTimestamp,
    pub last_sync_unix_secs: Option<i64>,
}

/// One server as the client sees it.
#[derive(Debug, Clone)]
struct ServerState {
    addr: Ipv4Addr,
    failures: u8,
    /// Marked down until then.
    hold_until: Option<u64>,
    /// Told us to go away for good.
    unusable: bool,
}

/// A request awaiting its reply.
#[derive(Debug, Clone, Copy)]
struct Pending {
    server: Ipv4Addr,
    /// As sent, noise included: the reply must echo it.
    transmit: NtpTimestamp,
    /// The real time of sending, T1.
    sent_unix_ns: i64,
    sent_at: u64,
}

/// The client.
#[derive(Debug)]
pub struct Client {
    config: Config,
    servers: Vec<ServerState>,
    pending: Option<Pending>,
    /// When the current (or last) round started; `None` before the first and after `Configure`.
    round_start: Option<u64>,
    /// The next server to try in this round.
    round_pos: usize,
    /// Whether the current round is still asking servers.
    round_active: bool,
    /// Rounds in a row without a valid sample.
    empty_rounds: u8,
    state: SyncState,
    rng: u64,
}

impl Client {
    #[must_use]
    pub fn new(config: Config, seed: u64) -> Client {
        Client {
            servers: server_states(&config.servers, &[]),
            config,
            pending: None,
            round_start: None,
            round_pos: 0,
            round_active: false,
            empty_rounds: 0,
            state: SyncState::default(),
            rng: seed | 1,
        }
    }

    /// Feed one input at `now` and collect what to do about it.
    pub fn handle(&mut self, input: Input, now: Now) -> Vec<Output> {
        match input {
            Input::Poll => self.poll(now),
            Input::Reply { server, bytes } => self.reply(server, &bytes, now),
            Input::Configure(config) => self.configure(config),
        }
    }

    /// When the driver should next feed [`Input::Poll`]: the pending reply's deadline, the end
    /// of the current interval, `Some(0)` right after `new` or `Configure`, `None` with no
    /// server left to ask.
    #[must_use]
    pub fn next_poll(&self) -> Option<u64> {
        if self.servers.iter().all(|server| server.unusable) {
            return None;
        }
        if let Some(pending) = &self.pending {
            return Some(pending.sent_at + REPLY_TIMEOUT_MS);
        }
        let Some(start) = self.round_start else {
            return Some(0);
        };
        if self.round_active {
            return Some(0);
        }
        Some(start + self.interval())
    }

    #[must_use]
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    fn interval(&self) -> u64 {
        if self.state.synced {
            POLL_SYNCED_MS
        } else {
            POLL_UNSYNCED_MS
        }
    }

    fn poll(&mut self, now: Now) -> Vec<Output> {
        let mut outputs = Vec::new();
        if let Some(pending) = self.pending {
            if now.mono_ms < pending.sent_at + REPLY_TIMEOUT_MS {
                return outputs;
            }
            self.pending = None;
            self.fail(pending.server, now, &mut outputs);
            self.ask_next(now, &mut outputs);
        }
        if self.pending.is_none()
            && !self.round_active
            && self
                .round_start
                .is_none_or(|start| now.mono_ms >= start + self.interval())
        {
            self.round_start = Some(now.mono_ms);
            self.round_pos = 0;
            self.round_active = true;
            self.ask_next(now, &mut outputs);
        }
        outputs
    }

    /// Send the round's next request, or end the round when no server is left to ask.
    fn ask_next(&mut self, now: Now, outputs: &mut Vec<Output>) {
        if !self.round_active {
            return;
        }
        let Some(index) = self.next_usable(now) else {
            self.end_round(false, outputs);
            return;
        };
        self.round_pos = index + 1;
        let server = self.servers[index].addr;
        let transmit = self.noisy_transmit(now.unix_ns);
        let request = Packet {
            leap: 0,
            version: 4,
            mode: MODE_CLIENT,
            poll: REQUEST_POLL,
            precision: REQUEST_PRECISION,
            transmit,
            ..Packet::default()
        };
        self.pending = Some(Pending {
            server,
            transmit,
            sent_unix_ns: now.unix_ns,
            sent_at: now.mono_ms,
        });
        outputs.push(Output::Send {
            server,
            bytes: request.encode().to_vec(),
        });
    }

    /// The next server of this round that is usable and not held; when every remaining one is
    /// held and the round has asked nobody yet, the one whose hold ends first, its hold cleared.
    fn next_usable(&mut self, now: Now) -> Option<usize> {
        let candidates = self.round_pos..self.servers.len();
        let free = candidates.clone().find(|&i| {
            let server = &self.servers[i];
            !server.unusable && server.hold_until.is_none_or(|until| until <= now.mono_ms)
        });
        if free.is_some() {
            return free;
        }
        if self.round_pos > 0 {
            return None;
        }
        let earliest = candidates
            .filter(|&i| !self.servers[i].unusable)
            .min_by_key(|&i| self.servers[i].hold_until.unwrap_or(0))?;
        self.servers[earliest].hold_until = None;
        Some(earliest)
    }

    /// The round is over: with a sample it counts for the sync, without one against it.
    fn end_round(&mut self, had_sample: bool, outputs: &mut Vec<Output>) {
        self.round_active = false;
        self.round_pos = self.servers.len();
        if had_sample {
            self.empty_rounds = 0;
            return;
        }
        self.empty_rounds = self.empty_rounds.saturating_add(1);
        if self.state.synced && self.empty_rounds >= LOST_SYNC_ROUNDS {
            self.state.synced = false;
            outputs.push(Output::Event(Event::LostSync {
                rounds: self.empty_rounds,
            }));
            self.empty_rounds = 0;
        }
    }

    /// One more failure for `addr`; the third in a row marks it down.
    fn fail(&mut self, addr: Ipv4Addr, now: Now, outputs: &mut Vec<Output>) {
        let Some(server) = self.servers.iter_mut().find(|s| s.addr == addr) else {
            return;
        };
        server.failures = server.failures.saturating_add(1);
        if server.failures >= MAX_FAILURES {
            server.failures = 0;
            server.hold_until = Some(now.mono_ms + SERVER_HOLD_MS);
            outputs.push(Output::Event(Event::ServerDown(addr)));
        }
    }

    fn reply(&mut self, server: Ipv4Addr, bytes: &[u8], now: Now) -> Vec<Output> {
        let mut outputs = Vec::new();
        let rejected = |reason: Reject| vec![Output::Event(Event::Rejected { server, reason })];
        let Ok(packet) = Packet::decode(bytes) else {
            return rejected(Reject::Format);
        };
        let Some(pending) = self.pending else {
            return rejected(Reject::Mismatch);
        };
        if pending.server != server || packet.originate != pending.transmit {
            return rejected(Reject::Mismatch);
        }
        if packet.mode != MODE_SERVER {
            return rejected(Reject::Format);
        }
        if let Some(code) = packet.kiss_code() {
            // The server answered, so this request is over, and the round moves on.
            self.pending = None;
            outputs.push(Output::Event(Event::Rejected {
                server,
                reason: Reject::KissOfDeath(code),
            }));
            self.kiss(server, code, now, &mut outputs);
            self.ask_next(now, &mut outputs);
            return outputs;
        }
        if packet.leap == LI_UNSYNCHRONISED
            || packet.stratum >= STRATUM_UNSYNCHRONISED
            || packet.transmit.is_zero()
        {
            return rejected(Reject::Unsynchronised);
        }
        let root_delay = short_to_nanos(packet.root_delay);
        let root_dispersion = short_to_nanos(packet.root_dispersion);
        if root_delay / 2 + root_dispersion >= MAX_ROOT_DISTANCE_NS {
            return rejected(Reject::RootDistance);
        }
        let floor = self.config.floor_unix_secs;
        let t1 = pending.sent_unix_ns;
        let t2 = packet.receive.to_unix_nanos(floor);
        let t3 = packet.transmit.to_unix_nanos(floor);
        let t4 = now.unix_ns;
        let transmit_unix_secs = t3.div_euclid(NANOS_PER_SEC);
        if transmit_unix_secs < i64::try_from(floor).unwrap_or(i64::MAX) {
            self.pending = None;
            outputs.push(Output::Event(Event::Refused {
                server,
                transmit_unix_secs,
                floor_unix_secs: floor,
            }));
            self.fail(server, now, &mut outputs);
            self.ask_next(now, &mut outputs);
            return outputs;
        }
        let offset_ns = (t2 - t1).midpoint(t3 - t4);
        let delay_ns = (t4 - t1) - (t3 - t2);
        self.pending = None;
        let synced_before = self.state.synced;
        match decide(offset_ns, synced_before) {
            Decision::Step(ns) => {
                outputs.push(Output::Step(ns));
                outputs.push(Output::Event(Event::Step {
                    server,
                    offset_ns: ns,
                    stratum: packet.stratum,
                }));
            }
            Decision::Slew(ns) => {
                outputs.push(Output::Slew(ns));
                outputs.push(Output::Event(Event::Slewed {
                    server,
                    offset_ns: ns,
                }));
            }
            Decision::Hold => {}
        }
        if !synced_before || matches!(decide(offset_ns, synced_before), Decision::Step(_)) {
            outputs.push(Output::Event(Event::Synced {
                server,
                offset_ns,
                delay_ns,
                stratum: packet.stratum,
            }));
        }
        self.state = SyncState {
            synced: true,
            source: Some(server),
            stratum: packet.stratum,
            offset_ns,
            delay_ns,
            root_delay_ns: root_delay,
            root_dispersion_ns: root_dispersion,
            reference: packet.transmit,
            last_sync_unix_secs: Some((t4 + offset_ns).div_euclid(NANOS_PER_SEC)),
        };
        if let Some(state) = self.servers.iter_mut().find(|s| s.addr == server) {
            state.failures = 0;
            state.hold_until = None;
        }
        self.end_round(true, &mut outputs);
        outputs
    }

    /// `DENY` and `RSTR` retire the server; `RATE` (or any other code) holds it twice as long
    /// as a timeout would.
    fn kiss(&mut self, addr: Ipv4Addr, code: [u8; 4], now: Now, outputs: &mut Vec<Output>) {
        let Some(server) = self.servers.iter_mut().find(|s| s.addr == addr) else {
            return;
        };
        if &code == b"DENY" || &code == b"RSTR" {
            server.unusable = true;
            outputs.push(Output::Event(Event::ServerUnusable { server: addr, code }));
        } else {
            server.hold_until = Some(now.mono_ms + 2 * SERVER_HOLD_MS);
        }
    }

    fn configure(&mut self, config: Config) -> Vec<Output> {
        let mut outputs = vec![Output::Event(Event::Configured {
            servers: config.servers.len(),
        })];
        if config.servers.is_empty() {
            outputs.push(Output::Event(Event::NoServers));
        }
        self.servers = server_states(&config.servers, &self.servers);
        if self
            .pending
            .is_some_and(|pending| !config.servers.contains(&pending.server))
        {
            self.pending = None;
        }
        self.config = config;
        self.round_start = None;
        self.round_active = false;
        self.round_pos = 0;
        outputs
    }

    /// `unix_ns` as a transmit timestamp with its low 16 fraction bits randomised (RFC 4330 §3),
    /// so a reply can be matched to its request and not guessed.
    fn noisy_transmit(&mut self, unix_ns: i64) -> NtpTimestamp {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let stamp = NtpTimestamp::from_unix_nanos(unix_ns);
        NtpTimestamp((stamp.0 & !0xffff) | (self.rng & 0xffff))
    }
}

/// States for `servers`, keeping what `previous` knew about the ones that stay.
fn server_states(servers: &[Ipv4Addr], previous: &[ServerState]) -> Vec<ServerState> {
    servers
        .iter()
        .map(|addr| {
            previous
                .iter()
                .find(|s| s.addr == *addr)
                .cloned()
                .unwrap_or(ServerState {
                    addr: *addr,
                    failures: 0,
                    hold_until: None,
                    unusable: false,
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        LI_UNSYNCHRONISED, MODE_CLIENT, MODE_SERVER, STRATUM_KISS, STRATUM_UNSYNCHRONISED,
    };

    /// 2026-10-31T12:00:00Z, the build floor of these tests, in nanoseconds.
    const UNIX_2026: i64 = 1_793_448_000 * NANOS_PER_SEC;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn now(mono_ms: u64, unix_ns: i64) -> Now {
        Now { mono_ms, unix_ns }
    }

    /// The wall clock `mono_ms` after the tests' start.
    fn unix_at(mono_ms: u64) -> i64 {
        UNIX_2026 + i64::try_from(mono_ms).unwrap() * 1_000_000
    }

    fn config(servers: &[&str]) -> Config {
        Config {
            servers: servers.iter().map(|s| ip(s)).collect(),
            floor_unix_secs: 1_793_448_000,
        }
    }

    fn sent(outputs: &[Output]) -> Vec<(Ipv4Addr, Packet)> {
        outputs
            .iter()
            .filter_map(|o| match o {
                Output::Send { server, bytes } => Some((*server, Packet::decode(bytes).unwrap())),
                _ => None,
            })
            .collect()
    }

    /// A server's answer to `request`: its clock reads `server_unix_ns` when it transmits (and a
    /// millisecond less when it received), stratum `stratum`, small root delay and dispersion.
    fn reply_to(request: &Packet, server_unix_ns: i64, stratum: u8) -> Vec<u8> {
        Packet {
            leap: 0,
            version: 4,
            mode: MODE_SERVER,
            stratum,
            poll: request.poll,
            precision: -23,
            root_delay: 0x0000_0800,
            root_dispersion: 0x0000_0400,
            reference_id: [10, 0, 0, 1],
            reference: NtpTimestamp::from_unix_nanos(server_unix_ns - 10 * NANOS_PER_SEC),
            originate: request.transmit,
            receive: NtpTimestamp::from_unix_nanos(server_unix_ns - 1_000_000),
            transmit: NtpTimestamp::from_unix_nanos(server_unix_ns),
        }
        .encode()
        .to_vec()
    }

    /// A poll at `mono_ms`; the one request it sent.
    fn poll(c: &mut Client, mono_ms: u64) -> (Ipv4Addr, Packet) {
        let out = c.handle(Input::Poll, now(mono_ms, unix_at(mono_ms)));
        sent(&out)
            .first()
            .copied()
            .unwrap_or_else(|| panic!("no request sent at {mono_ms}: {out:?}"))
    }

    /// One server, one reply at offset zero: synced, with the next poll at the synced interval.
    fn synced_client() -> Client {
        let mut c = Client::new(config(&["203.0.113.1"]), 1);
        let (server, request) = poll(&mut c, 0);
        let out = c.handle(
            Input::Reply {
                server,
                bytes: reply_to(&request, unix_at(5), 2),
            },
            now(10, unix_at(10)),
        );
        assert!(c.state().synced, "{out:?}");
        c
    }

    #[test]
    fn the_first_valid_reply_steps_the_clock_and_reports_the_sync() {
        let mut c = Client::new(config(&["203.0.113.1"]), 1);
        assert_eq!(c.next_poll(), Some(0));
        let out = c.handle(Input::Poll, now(0, UNIX_2026));
        let (server, request) = sent(&out).remove(0);
        assert_eq!(
            (server, request.mode, request.version),
            (ip("203.0.113.1"), MODE_CLIENT, 4)
        );
        assert_eq!(c.next_poll(), Some(REPLY_TIMEOUT_MS));
        let server_time = UNIX_2026 + 7_200 * NANOS_PER_SEC;
        let out = c.handle(
            Input::Reply {
                server,
                bytes: reply_to(&request, server_time, 2),
            },
            now(20, UNIX_2026 + 20_000_000),
        );
        let step = out
            .iter()
            .find_map(|o| match o {
                Output::Step(ns) => Some(*ns),
                _ => None,
            })
            .unwrap();
        assert!((step - 7_200 * NANOS_PER_SEC).abs() < 20_000_000, "{step}");
        assert!(
            out.iter().any(|o| matches!(o, Output::Event(Event::Step { server: s, offset_ns, stratum: 2 }) if *s == server && *offset_ns == step)),
            "{out:?}"
        );
        assert!(
            out.iter().any(|o| matches!(o, Output::Event(Event::Synced { server: s, offset_ns, delay_ns, stratum: 2 }) if *s == server && *offset_ns == step && (0..50_000_000).contains(delay_ns))),
            "{out:?}"
        );
        assert!(c.state().synced && c.state().source == Some(server) && c.state().stratum == 2);
        assert_eq!(
            c.next_poll(),
            Some(POLL_SYNCED_MS),
            "the synced interval starts at the round"
        );
    }

    #[test]
    fn after_the_first_sync_small_offsets_slew_and_large_ones_step() {
        let mut c = synced_client();
        let (server, request) = poll(&mut c, POLL_SYNCED_MS);
        let out = c.handle(
            Input::Reply {
                server,
                bytes: reply_to(&request, unix_at(POLL_SYNCED_MS) + 200_000_000, 2),
            },
            now(POLL_SYNCED_MS + 10, unix_at(POLL_SYNCED_MS + 10)),
        );
        assert!(
            matches!(out[0], Output::Slew(ns) if (ns - 200_000_000).abs() < 15_000_000),
            "{out:?}"
        );
        let (server, request) = poll(&mut c, 2 * POLL_SYNCED_MS);
        let out = c.handle(
            Input::Reply {
                server,
                bytes: reply_to(&request, unix_at(2 * POLL_SYNCED_MS) + 3 * NANOS_PER_SEC, 2),
            },
            now(2 * POLL_SYNCED_MS + 10, unix_at(2 * POLL_SYNCED_MS + 10)),
        );
        assert!(
            matches!(out[0], Output::Step(ns) if (ns - 3 * NANOS_PER_SEC).abs() < 15_000_000),
            "{out:?}"
        );
        assert!(
            out.iter()
                .any(|o| matches!(o, Output::Event(Event::Step { .. })))
        );
    }

    #[test]
    fn a_transmit_time_before_the_floor_is_refused() {
        let mut c = Client::new(config(&["203.0.113.1"]), 1);
        let (server, request) = poll(&mut c, 0);
        let in_2013 = 1_377_993_600 * NANOS_PER_SEC;
        let out = c.handle(
            Input::Reply {
                server,
                bytes: reply_to(&request, in_2013, 2),
            },
            now(10, UNIX_2026),
        );
        assert_eq!(
            out,
            vec![Output::Event(Event::Refused {
                server,
                transmit_unix_secs: 1_377_993_600,
                floor_unix_secs: 1_793_448_000,
            })]
        );
        assert!(!c.state().synced);
    }

    #[test]
    fn replies_that_do_not_match_what_we_sent_are_ignored() {
        let mut c = Client::new(config(&["203.0.113.1", "203.0.113.2"]), 1);
        let (server, request) = poll(&mut c, 0);
        let good = reply_to(&request, UNIX_2026, 2);
        assert_eq!(
            c.handle(
                Input::Reply {
                    server: ip("203.0.113.2"),
                    bytes: good.clone(),
                },
                now(5, UNIX_2026),
            ),
            vec![Output::Event(Event::Rejected {
                server: ip("203.0.113.2"),
                reason: Reject::Mismatch,
            })]
        );
        let mut forged = Packet::decode(&good).unwrap();
        forged.originate = NtpTimestamp(forged.originate.0 ^ 1);
        assert_eq!(
            c.handle(
                Input::Reply {
                    server,
                    bytes: forged.encode().to_vec(),
                },
                now(6, UNIX_2026),
            ),
            vec![Output::Event(Event::Rejected {
                server,
                reason: Reject::Mismatch,
            })]
        );
        assert_eq!(
            c.handle(
                Input::Reply {
                    server,
                    bytes: vec![1, 2, 3],
                },
                now(7, UNIX_2026),
            ),
            vec![Output::Event(Event::Rejected {
                server,
                reason: Reject::Format,
            })]
        );
        assert!(!c.state().synced, "nothing moved the clock");
        assert!(
            c.handle(
                Input::Reply {
                    server,
                    bytes: good
                },
                now(8, UNIX_2026)
            )
            .iter()
            .any(|o| matches!(o, Output::Event(Event::Synced { .. }))),
            "the real reply still counts"
        );
    }

    #[test]
    fn kiss_of_death_and_unsynchronised_answers_move_nothing() {
        let mut c = Client::new(config(&["203.0.113.1", "203.0.113.2"]), 1);
        let (server, request) = poll(&mut c, 0);
        let mut unsynced = Packet::decode(&reply_to(&request, UNIX_2026, 2)).unwrap();
        unsynced.leap = LI_UNSYNCHRONISED;
        unsynced.stratum = STRATUM_UNSYNCHRONISED;
        assert_eq!(
            c.handle(
                Input::Reply {
                    server,
                    bytes: unsynced.encode().to_vec(),
                },
                now(5, UNIX_2026),
            ),
            vec![Output::Event(Event::Rejected {
                server,
                reason: Reject::Unsynchronised,
            })]
        );
        // The round moves on to .2 once .1's request times out.
        let (server, request) = poll(&mut c, REPLY_TIMEOUT_MS);
        assert_eq!(server, ip("203.0.113.2"));
        let mut deny = Packet::decode(&reply_to(&request, UNIX_2026, 2)).unwrap();
        deny.stratum = STRATUM_KISS;
        deny.reference_id = *b"DENY";
        let out = c.handle(
            Input::Reply {
                server,
                bytes: deny.encode().to_vec(),
            },
            now(REPLY_TIMEOUT_MS + 5, UNIX_2026),
        );
        assert!(out.contains(&Output::Event(Event::ServerUnusable {
            server,
            code: *b"DENY",
        })));
        assert!(
            !out.iter()
                .any(|o| matches!(o, Output::Step(_) | Output::Slew(_)))
        );
        let mut asked = Vec::new();
        for _ in 0..6 {
            let at = c.next_poll().unwrap();
            let out = c.handle(Input::Poll, now(at, unix_at(at)));
            asked.extend(sent(&out).into_iter().map(|(s, _)| s));
        }
        assert!(
            asked.len() >= 2 && asked.iter().all(|s| *s == ip("203.0.113.1")),
            "a DENY server is never asked again: {asked:?}"
        );
    }

    #[test]
    fn a_silent_server_is_marked_down_after_three_timeouts_and_the_next_is_tried() {
        let mut c = Client::new(config(&["203.0.113.99", "203.0.113.1"]), 1);
        let (first, _) = poll(&mut c, 0);
        assert_eq!(first, ip("203.0.113.99"));
        let out = c.handle(
            Input::Poll,
            now(REPLY_TIMEOUT_MS, unix_at(REPLY_TIMEOUT_MS)),
        );
        let (server, request) = sent(&out).remove(0);
        assert_eq!(server, ip("203.0.113.1"), "the timeout moves the round on");
        c.handle(
            Input::Reply {
                server,
                bytes: reply_to(&request, unix_at(REPLY_TIMEOUT_MS), 2),
            },
            now(REPLY_TIMEOUT_MS + 10, unix_at(REPLY_TIMEOUT_MS + 10)),
        );
        // Two more rounds: the first server times out again (failures 2 and 3), the second
        // answers.
        let mut downs = 0;
        for round in 1..=2 {
            let at = round * POLL_SYNCED_MS;
            let (server, _) = poll(&mut c, at);
            assert_eq!(
                server,
                ip("203.0.113.99"),
                "round {round} starts at the first server"
            );
            let out = c.handle(
                Input::Poll,
                now(at + REPLY_TIMEOUT_MS, unix_at(at + REPLY_TIMEOUT_MS)),
            );
            downs +=
                usize::from(out.contains(&Output::Event(Event::ServerDown(ip("203.0.113.99")))));
            let (server, request) = sent(&out).remove(0);
            c.handle(
                Input::Reply {
                    server,
                    bytes: reply_to(&request, unix_at(at + REPLY_TIMEOUT_MS), 2),
                },
                now(
                    at + REPLY_TIMEOUT_MS + 10,
                    unix_at(at + REPLY_TIMEOUT_MS + 10),
                ),
            );
        }
        assert_eq!(downs, 1, "down once, at the third consecutive timeout");
        let (server, _) = poll(&mut c, 3 * POLL_SYNCED_MS);
        assert_eq!(
            server,
            ip("203.0.113.1"),
            "the down server is skipped during its hold"
        );
        let (server, _) = poll(&mut c, 3 * POLL_SYNCED_MS + SERVER_HOLD_MS + POLL_SYNCED_MS);
        assert_eq!(server, ip("203.0.113.99"), "and tried again after it");
    }

    #[test]
    fn four_empty_rounds_lose_the_sync_and_configure_keeps_what_it_can() {
        let mut c = synced_client();
        for round in 1..=LOST_SYNC_ROUNDS {
            let at = u64::from(round) * POLL_SYNCED_MS;
            poll(&mut c, at);
            let out = c.handle(
                Input::Poll,
                now(at + REPLY_TIMEOUT_MS, unix_at(at + REPLY_TIMEOUT_MS)),
            );
            assert_eq!(
                out.contains(&Output::Event(Event::LostSync {
                    rounds: LOST_SYNC_ROUNDS,
                })),
                round == LOST_SYNC_ROUNDS,
                "round {round}: {out:?}"
            );
        }
        assert!(!c.state().synced);
        let last_round = u64::from(LOST_SYNC_ROUNDS) * POLL_SYNCED_MS;
        assert!(
            c.next_poll().unwrap() <= last_round + POLL_UNSYNCED_MS,
            "back to the unsynced interval: {:?}",
            c.next_poll()
        );
        let out = c.handle(
            Input::Configure(Config {
                servers: vec![],
                floor_unix_secs: 1_793_448_000,
            }),
            now(0, UNIX_2026),
        );
        assert_eq!(
            out,
            vec![
                Output::Event(Event::Configured { servers: 0 }),
                Output::Event(Event::NoServers),
            ]
        );
        assert_eq!(
            c.handle(Input::Poll, now(1, UNIX_2026)),
            vec![],
            "nothing to ask"
        );
        assert_eq!(c.next_poll(), None);
    }
}
