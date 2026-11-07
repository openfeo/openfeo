// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The LAN router-advertisement server (SPEC §7.3): advertises one LAN's prefix with the router
//! as resolver, on the timing of RFC 4861 §6.2 (periodic, the first few quickly, answers to
//! solicitations within half a second, at most one every three seconds, a change at once), and
//! says goodbye with lifetime 0 when stopped. No sockets, no clock: the driver feeds packets
//! and timeouts and sends what comes out.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

use crate::Timestamp;
use crate::wire::{Message, NdOption, Preference, RouterAdvertisement};

/// RFC 4861 §6.2.1 defaults, in milliseconds: the periodic interval's bounds.
pub const MIN_RTR_ADV_INTERVAL: Timestamp = 200_000;
pub const MAX_RTR_ADV_INTERVAL: Timestamp = 600_000;
/// RFC 4861 §10: the first advertisements come no further apart than this.
pub const MAX_INITIAL_RTR_ADVERT_INTERVAL: Timestamp = 16_000;
/// RFC 4861 §10: how many advertisements are sent at that pace after a start.
pub const MAX_INITIAL_RTR_ADVERTISEMENTS: u32 = 3;
/// RFC 4861 §10: a solicitation is answered within this.
pub const MAX_RA_DELAY_TIME: Timestamp = 500;
/// RFC 4861 §10: never two multicast advertisements closer than this.
pub const MIN_DELAY_BETWEEN_RAS: Timestamp = 3_000;
/// RFC 4861 §10: goodbye advertisements with lifetime 0 on stop.
pub const MAX_FINAL_RTR_ADVERTISEMENTS: u32 = 3;
/// RFC 4861 §6.2.1 default valid lifetime of a prefix, 30 days in seconds.
pub const PIO_VALID: u32 = 2_592_000;
/// RFC 4861 §6.2.1 default preferred lifetime of a prefix, 7 days in seconds.
pub const PIO_PREFERRED: u32 = 604_800;
/// RFC 8106 §5.1: three times the maximum advertisement interval, in seconds.
pub const RDNSS_LIFETIME: u32 = 1_800;
/// The hop limit hosts are told to use.
const CUR_HOP_LIMIT: u8 = 64;

/// Route information options are advertised with this lifetime (RFC 4191), refreshed by every
/// advertisement.
pub const ROUTE_INFO_LIFETIME: u32 = 1_800;

/// A prefix lifetime: fixed, or the seconds left to a moment on the driver's clock, capped,
/// so a deprecated prefix counts down at every advertisement (RFC 7084 L-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    Fixed(u32),
    Until { at: Timestamp, cap: u32 },
}

impl Lifetime {
    /// The seconds to advertise at `now`: the fixed value, or what is left (rounded up to a
    /// whole second, never below 0, never above the cap).
    #[must_use]
    pub fn secs(self, now: Timestamp) -> u32 {
        match self {
            Lifetime::Fixed(secs) => secs,
            Lifetime::Until { at, cap } => {
                let left = at.saturating_sub(now).div_ceil(1000);
                u32::try_from(left).map_or(cap, |secs| secs.min(cap))
            }
        }
    }
}

/// One prefix information option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pio {
    /// The /64.
    pub prefix: Ipv6Net,
    pub valid: Lifetime,
    pub preferred: Lifetime,
}

/// One route information option (RFC 4191).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rio {
    pub prefix: Ipv6Net,
    pub lifetime: u32,
    pub preference: Preference,
}

/// What one LAN's server advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The LAN's prefixes, each with its lifetimes (SPEC §7.3).
    pub prefixes: Vec<Pio>,
    /// The bridge's hardware address, sent as the source link-layer address.
    pub mac: [u8; 6],
    /// The resolvers hosts are pointed at: the router's addresses in the LAN; empty sends no
    /// RDNSS.
    pub rdnss: Vec<Ipv6Addr>,
    /// The bridge's MTU, when known.
    pub mtu: Option<u32>,
    /// The search domain; empty sends no DNSSL.
    pub domain: String,
    /// 1800 while the WAN has an IPv6 route, 0 when it does not (SPEC §7.3).
    pub router_lifetime: u16,
    /// The O flag: a stateless DHCPv6 responder answers on this LAN.
    pub other: bool,
    /// Route information options via this router.
    pub routes: Vec<Rio>,
}

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Begin advertising.
    Start,
    /// New contents; a change is advertised at once.
    Configure(Config),
    /// An ICMPv6 message received on the bridge, with the IPv6 source and hop limit.
    Solicitation {
        from: Ipv6Addr,
        hop_limit: u8,
        bytes: Vec<u8>,
    },
    /// The timer of [`Server::next_timeout`] fired.
    Timeout,
    /// Say goodbye and stop.
    Stop,
}

/// What the server wants done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send these bytes to `ff02::1`.
    Advertise(Vec<u8>),
    /// The final advertisements went out; the socket may close.
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Running,
    /// Final advertisements still to send.
    Stopping(u32),
    Stopped,
}

/// The server core for one LAN.
#[derive(Debug)]
pub struct Server {
    config: Config,
    rng: u64,
    state: State,
    /// Fast initial advertisements still to send after the one `Start` sends.
    initial_left: u32,
    /// The next periodic advertisement.
    periodic_at: Option<Timestamp>,
    /// A triggered advertisement: an answer to a solicitation, a change, a goodbye.
    due_at: Option<Timestamp>,
    last_sent: Option<Timestamp>,
}

impl Server {
    /// A server that advertises nothing until [`Input::Start`]; `seed` feeds the jitter.
    #[must_use]
    pub fn new(config: Config, seed: u64) -> Server {
        Server {
            config,
            rng: seed | 1,
            state: State::Idle,
            initial_left: 0,
            periodic_at: None,
            due_at: None,
            last_sent: None,
        }
    }

    /// Feed one input at `now` and collect what to do.
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Start => {
                if self.state == State::Idle {
                    self.state = State::Running;
                    self.initial_left = MAX_INITIAL_RTR_ADVERTISEMENTS;
                    self.advertise(now, &mut out);
                }
            }
            Input::Configure(config) => {
                if self.state == State::Running && config != self.config {
                    self.config = config;
                    self.trigger(now, 0, &mut out);
                }
            }
            Input::Solicitation {
                from,
                hop_limit,
                bytes,
            } => {
                let valid = hop_limit == 255
                    && (from.is_unspecified() || is_link_local(from))
                    && matches!(
                        Message::decode(&bytes),
                        Ok(Message::RouterSolicitation { .. })
                    );
                if valid && self.state == State::Running {
                    let delay = self.random(0, MAX_RA_DELAY_TIME);
                    self.trigger(now, delay, &mut out);
                }
            }
            Input::Timeout => match self.state {
                State::Running => {
                    if self.due_at.is_some_and(|at| at <= now)
                        || self.periodic_at.is_some_and(|at| at <= now)
                    {
                        self.advertise(now, &mut out);
                    }
                }
                State::Stopping(_) => {
                    if self.due_at.is_some_and(|at| at <= now) {
                        self.farewell(now, &mut out);
                    }
                }
                State::Idle | State::Stopped => {}
            },
            Input::Stop => {
                if self.state == State::Running {
                    self.state = State::Stopping(MAX_FINAL_RTR_ADVERTISEMENTS);
                    self.config.router_lifetime = 0;
                    self.periodic_at = None;
                    self.due_at = Some(self.floor(now));
                    if self.due_at == Some(now) {
                        self.farewell(now, &mut out);
                    }
                }
            }
        }
        out
    }

    /// When [`Server::handle`] next wants [`Input::Timeout`].
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        match self.state {
            State::Running => self.due_at.into_iter().chain(self.periodic_at).min(),
            State::Stopping(_) => self.due_at,
            State::Idle | State::Stopped => None,
        }
    }

    /// Schedule a triggered advertisement `delay` from now, never within
    /// [`MIN_DELAY_BETWEEN_RAS`] of the last one, and send at once when that is now.
    fn trigger(&mut self, now: Timestamp, delay: Timestamp, out: &mut Vec<Output>) {
        let at = (now + delay).max(self.floor(now));
        let at = self.due_at.map_or(at, |due| due.min(at));
        if at <= now {
            self.advertise(now, out);
        } else {
            self.due_at = Some(at);
        }
    }

    /// The earliest the next multicast advertisement may go out.
    fn floor(&self, now: Timestamp) -> Timestamp {
        self.last_sent
            .map_or(now, |last| (last + MIN_DELAY_BETWEEN_RAS).max(now))
    }

    /// Send the advertisement now and schedule the next periodic one: within 16 s while the
    /// initial ones remain, else at random within the configured bounds.
    fn advertise(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        out.push(Output::Advertise(self.message(now).encode()));
        self.last_sent = Some(now);
        self.due_at = None;
        let mut interval = self.random(MIN_RTR_ADV_INTERVAL, MAX_RTR_ADV_INTERVAL);
        if self.initial_left > 0 {
            self.initial_left -= 1;
            interval = interval.min(MAX_INITIAL_RTR_ADVERT_INTERVAL);
        }
        self.periodic_at = Some(now + interval);
    }

    /// One final advertisement with lifetime 0, then the next three seconds on, until the
    /// last, after which the server is stopped.
    fn farewell(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let State::Stopping(left) = self.state else {
            return;
        };
        out.push(Output::Advertise(self.message(now).encode()));
        self.last_sent = Some(now);
        if left <= 1 {
            self.state = State::Stopped;
            self.due_at = None;
            out.push(Output::Stopped);
        } else {
            self.state = State::Stopping(left - 1);
            self.due_at = Some(now + MIN_DELAY_BETWEEN_RAS);
        }
    }

    fn message(&self, now: Timestamp) -> Message {
        let mut options = vec![NdOption::SourceLinkLayer(self.config.mac)];
        for pio in &self.config.prefixes {
            options.push(NdOption::PrefixInformation {
                prefix: pio.prefix.trunc(),
                on_link: true,
                autonomous: true,
                valid: pio.valid.secs(now),
                preferred: pio.preferred.secs(now),
            });
        }
        if let Some(mtu) = self.config.mtu {
            options.push(NdOption::Mtu(mtu));
        }
        if !self.config.rdnss.is_empty() {
            options.push(NdOption::Rdnss {
                lifetime: RDNSS_LIFETIME,
                addrs: self.config.rdnss.clone(),
            });
        }
        if !self.config.domain.is_empty() {
            options.push(NdOption::Dnssl {
                lifetime: RDNSS_LIFETIME,
                names: vec![self.config.domain.clone()],
            });
        }
        for route in &self.config.routes {
            options.push(NdOption::RouteInformation {
                prefix: route.prefix.trunc(),
                preference: route.preference,
                lifetime: route.lifetime,
            });
        }
        Message::RouterAdvertisement(RouterAdvertisement {
            cur_hop_limit: CUR_HOP_LIMIT,
            managed: false,
            other: self.config.other,
            preference: Preference::Medium,
            router_lifetime: self.config.router_lifetime,
            reachable_time: 0,
            retrans_timer: 0,
            options,
        })
    }

    /// xorshift64, as the other cores: good enough for jitter.
    fn random(&mut self, lo: Timestamp, hi: Timestamp) -> Timestamp {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        lo + self.rng % (hi - lo + 1)
    }
}

fn is_link_local(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Message, NdOption, Preference};
    use ipnet::Ipv6Net;
    use std::net::Ipv6Addr;

    fn config(lifetime: u16) -> Config {
        Config {
            prefixes: vec![Pio {
                prefix: "2001:db8:1:222::/64".parse().unwrap(),
                valid: Lifetime::Fixed(PIO_VALID),
                preferred: Lifetime::Fixed(PIO_PREFERRED),
            }],
            mac: [0x52, 0x54, 0, 0xfe, 0, 2],
            rdnss: vec!["2001:db8:1:222::1".parse().unwrap()],
            mtu: Some(1500),
            domain: "home.arpa".to_owned(),
            router_lifetime: lifetime,
            other: false,
            routes: Vec::new(),
        }
    }

    /// Two prefixes, one counting down, two resolvers, O set, two routes.
    fn multi_config() -> Config {
        let mut config = config(1800);
        config.prefixes.push(Pio {
            prefix: "2001:db8:100:1::/64".parse().unwrap(),
            valid: Lifetime::Until {
                at: 60_000,
                cap: PIO_VALID,
            },
            preferred: Lifetime::Until {
                at: 40_000,
                cap: PIO_PREFERRED,
            },
        });
        config.rdnss.push("fd12:3456:789a:1::1".parse().unwrap());
        config.other = true;
        config.routes = vec![
            Rio {
                prefix: "fd12:3456:789a::/48".parse().unwrap(),
                lifetime: ROUTE_INFO_LIFETIME,
                preference: Preference::Medium,
            },
            Rio {
                prefix: "2001:db8:100::/56".parse().unwrap(),
                lifetime: ROUTE_INFO_LIFETIME,
                preference: Preference::Medium,
            },
        ];
        config
    }

    #[test]
    fn an_advertisement_carries_every_prefix_rdnss_the_o_flag_and_the_routes() {
        let mut s = Server::new(multi_config(), 7);
        let ra = adverts(&s.handle(Input::Start, 10_000)).remove(0);
        assert!(ra.other && !ra.managed);
        let pios: Vec<(Ipv6Net, u32, u32)> = ra
            .options
            .iter()
            .filter_map(|o| match o {
                NdOption::PrefixInformation {
                    prefix,
                    valid,
                    preferred,
                    on_link,
                    autonomous,
                } => {
                    assert!(*on_link && *autonomous);
                    Some((*prefix, *valid, *preferred))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            pios,
            vec![
                (
                    "2001:db8:1:222::/64".parse().unwrap(),
                    PIO_VALID,
                    PIO_PREFERRED
                ),
                ("2001:db8:100:1::/64".parse().unwrap(), 50, 30),
            ],
            "the second prefix's lifetimes are what is left at 10 s"
        );
        assert!(ra.options.contains(&NdOption::Rdnss {
            lifetime: RDNSS_LIFETIME,
            addrs: vec![
                "2001:db8:1:222::1".parse().unwrap(),
                "fd12:3456:789a:1::1".parse().unwrap(),
            ],
        }));
        let rios: Vec<(Ipv6Net, u32)> = ra
            .options
            .iter()
            .filter_map(|o| match o {
                NdOption::RouteInformation {
                    prefix,
                    preference,
                    lifetime,
                } => {
                    assert_eq!(*preference, Preference::Medium);
                    Some((*prefix, *lifetime))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            rios,
            vec![
                ("fd12:3456:789a::/48".parse().unwrap(), 1800),
                ("2001:db8:100::/56".parse().unwrap(), 1800),
            ]
        );
    }

    #[test]
    fn a_delegated_prefix_counts_down_between_advertisements() {
        let mut s = Server::new(multi_config(), 7);
        let _ = s.handle(Input::Start, 10_000);
        let later = adverts(&s.handle(Input::Timeout, s.next_timeout().unwrap())).remove(0);
        let delegated = later
            .options
            .iter()
            .find_map(|o| match o {
                NdOption::PrefixInformation {
                    prefix,
                    valid,
                    preferred,
                    ..
                } if prefix.to_string() == "2001:db8:100:1::/64" => Some((*valid, *preferred)),
                _ => None,
            })
            .unwrap();
        assert!(delegated.0 < 50 && delegated.1 < 30, "{delegated:?}");
    }

    #[test]
    fn a_lifetime_counts_down_rounds_up_and_caps() {
        let until = Lifetime::Until {
            at: 5_000,
            cap: 7200,
        };
        assert_eq!(until.secs(0), 5);
        assert_eq!(until.secs(4_100), 1, "900 ms left rounds up to a second");
        assert_eq!(until.secs(5_000), 0);
        assert_eq!(until.secs(6_000), 0, "never negative");
        assert_eq!(
            Lifetime::Until {
                at: u64::MAX,
                cap: 100
            }
            .secs(0),
            100,
            "capped"
        );
        assert_eq!(Lifetime::Fixed(42).secs(1_000_000), 42);
    }

    fn server(lifetime: u16) -> Server {
        Server::new(config(lifetime), 42)
    }

    fn ll(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n)
    }

    fn solicitation(from: Ipv6Addr, hop_limit: u8) -> Input {
        Input::Solicitation {
            from,
            hop_limit,
            bytes: Message::RouterSolicitation {
                options: vec![NdOption::SourceLinkLayer([1, 2, 3, 4, 5, 6])],
            }
            .encode(),
        }
    }

    fn adverts(out: &[Output]) -> Vec<RouterAdvertisement> {
        out.iter()
            .filter_map(|o| match o {
                Output::Advertise(bytes) => match Message::decode(bytes) {
                    Ok(Message::RouterAdvertisement(ra)) => Some(ra),
                    other => panic!("not an advertisement: {other:?}"),
                },
                Output::Stopped => None,
            })
            .collect()
    }

    #[test]
    fn start_advertises_at_once_then_three_within_16_s_then_between_200_and_600_s() {
        let mut s = server(1800);
        let out = s.handle(Input::Start, 0);
        assert_eq!(adverts(&out).len(), 1);
        let mut now = 0;
        let mut deltas = Vec::new();
        for _ in 0..8 {
            let next = s.next_timeout().unwrap();
            deltas.push(next - now);
            now = next;
            let out = s.handle(Input::Timeout, now);
            assert_eq!(
                adverts(&out).len(),
                1,
                "one advertisement per timeout at {now}"
            );
        }
        for (i, delta) in deltas.iter().enumerate() {
            if i < 3 {
                assert!(*delta <= MAX_INITIAL_RTR_ADVERT_INTERVAL, "{deltas:?}");
            } else {
                assert!(
                    (MIN_RTR_ADV_INTERVAL..=MAX_RTR_ADV_INTERVAL).contains(delta),
                    "{deltas:?}"
                );
            }
        }
        assert!(
            deltas[3..].iter().any(|d| *d != deltas[3]),
            "random, not fixed: {deltas:?}"
        );
    }

    #[test]
    fn the_advertisement_carries_pio_mtu_sllao_rdnss_dnssl_and_clear_m_and_o() {
        let mut s = server(1800);
        let ra = adverts(&s.handle(Input::Start, 0)).remove(0);
        assert_eq!(ra.cur_hop_limit, 64);
        assert!(!ra.managed && !ra.other);
        assert_eq!(ra.preference, Preference::Medium);
        assert_eq!(ra.router_lifetime, 1800);
        assert_eq!((ra.reachable_time, ra.retrans_timer), (0, 0));
        assert_eq!(
            ra.options,
            vec![
                NdOption::SourceLinkLayer([0x52, 0x54, 0, 0xfe, 0, 2]),
                NdOption::PrefixInformation {
                    prefix: "2001:db8:1:222::/64".parse().unwrap(),
                    on_link: true,
                    autonomous: true,
                    valid: PIO_VALID,
                    preferred: PIO_PREFERRED,
                },
                NdOption::Mtu(1500),
                NdOption::Rdnss {
                    lifetime: RDNSS_LIFETIME,
                    addrs: vec!["2001:db8:1:222::1".parse().unwrap()],
                },
                NdOption::Dnssl {
                    lifetime: RDNSS_LIFETIME,
                    names: vec!["home.arpa".to_owned()],
                },
            ]
        );
        let mut bare = config(0);
        bare.mtu = None;
        bare.domain = String::new();
        let mut s = Server::new(bare, 1);
        let ra = adverts(&s.handle(Input::Start, 0)).remove(0);
        assert_eq!(ra.router_lifetime, 0);
        assert!(
            !ra.options
                .iter()
                .any(|o| matches!(o, NdOption::Mtu(_) | NdOption::Dnssl { .. }))
        );
    }

    #[test]
    fn a_solicitation_is_answered_within_half_a_second() {
        let mut s = server(1800);
        s.handle(Input::Start, 0);
        let periodic = s.next_timeout().unwrap();
        assert!(
            s.handle(solicitation(ll(7), 255), 10_000).is_empty(),
            "answered after a delay, not at once"
        );
        let due = s.next_timeout().unwrap();
        assert!(
            (10_000..=10_000 + MAX_RA_DELAY_TIME).contains(&due),
            "{due}"
        );
        assert!(due < periodic);
        let out = s.handle(Input::Timeout, due);
        assert_eq!(adverts(&out).len(), 1);
        assert_eq!(
            s.handle(solicitation(Ipv6Addr::UNSPECIFIED, 255), 20_000),
            vec![]
        );
        let due = s.next_timeout().unwrap();
        assert!(
            (20_000..=20_500).contains(&due),
            "the unspecified source is a host without an address yet"
        );
    }

    #[test]
    fn a_burst_of_solicitations_gets_one_answer_per_three_seconds() {
        let mut s = server(1800);
        s.handle(Input::Start, 0);
        let mut sent = 0;
        let mut now = 100;
        for _ in 0..20 {
            sent += adverts(&s.handle(solicitation(ll(7), 255), now)).len();
            let next = s.next_timeout().unwrap();
            if next <= now + 100 {
                sent += adverts(&s.handle(Input::Timeout, next)).len();
            }
            now += 100;
        }
        // Up to now = 2100: the floor after the start advertisement at 0 is 3000.
        assert_eq!(sent, 0);
        let due = s.next_timeout().unwrap();
        assert_eq!(due, MIN_DELAY_BETWEEN_RAS);
        sent += adverts(&s.handle(Input::Timeout, due)).len();
        assert_eq!(sent, 1);
        for _ in 0..20 {
            sent += adverts(&s.handle(solicitation(ll(8), 255), due + 100)).len();
        }
        assert_eq!(s.next_timeout(), Some(2 * MIN_DELAY_BETWEEN_RAS));
        sent += adverts(&s.handle(Input::Timeout, 2 * MIN_DELAY_BETWEEN_RAS)).len();
        assert_eq!(sent, 2, "forty solicitations in six seconds: two answers");
    }

    #[test]
    fn a_solicitation_below_hop_limit_255_or_from_a_global_source_is_ignored() {
        let mut s = server(1800);
        s.handle(Input::Start, 0);
        let periodic = s.next_timeout();
        s.handle(solicitation(ll(7), 64), 10_000);
        assert_eq!(s.next_timeout(), periodic);
        s.handle(
            solicitation("2001:db8:1:222::9".parse().unwrap(), 255),
            10_000,
        );
        assert_eq!(s.next_timeout(), periodic);
        s.handle(
            Input::Solicitation {
                from: ll(7),
                hop_limit: 255,
                bytes: vec![134, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            10_000,
        );
        assert_eq!(
            s.next_timeout(),
            periodic,
            "an advertisement from a host is not a solicitation"
        );
    }

    #[test]
    fn a_configure_that_changes_the_lifetime_advertises_at_once() {
        let mut s = server(1800);
        s.handle(Input::Start, 0);
        let periodic = s.next_timeout().unwrap();
        assert_eq!(s.handle(Input::Configure(config(1800)), 4_000), vec![]);
        assert_eq!(s.next_timeout(), Some(periodic), "nothing changed");
        let out = s.handle(Input::Configure(config(0)), 5_000);
        assert_eq!(adverts(&out).len(), 1, "past the floor: at once");
        assert_eq!(adverts(&out)[0].router_lifetime, 0);
        let out = s.handle(Input::Configure(config(1800)), 6_000);
        assert!(
            out.is_empty(),
            "within three seconds of the last one: scheduled"
        );
        assert_eq!(s.next_timeout(), Some(5_000 + MIN_DELAY_BETWEEN_RAS));
        let out = s.handle(Input::Timeout, 8_000);
        assert_eq!(adverts(&out)[0].router_lifetime, 1800);
    }

    #[test]
    fn stop_sends_three_final_advertisements_with_lifetime_0_then_stops() {
        let mut s = server(1800);
        s.handle(Input::Start, 0);
        let out = s.handle(Input::Stop, 10_000);
        let mut finals = adverts(&out);
        let mut now = 10_000;
        while !out.contains(&Output::Stopped) && finals.len() < 5 {
            now = s.next_timeout().expect("a final advertisement is due");
            let out = s.handle(Input::Timeout, now);
            finals.extend(adverts(&out));
            if out.contains(&Output::Stopped) {
                break;
            }
        }
        assert_eq!(
            finals.len(),
            usize::try_from(MAX_FINAL_RTR_ADVERTISEMENTS).unwrap()
        );
        assert!(finals.iter().all(|ra| ra.router_lifetime == 0));
        assert_eq!(now, 10_000 + 2 * MIN_DELAY_BETWEEN_RAS);
        assert_eq!(s.next_timeout(), None);
        assert_eq!(s.handle(solicitation(ll(7), 255), now + 1), vec![]);
        assert_eq!(s.next_timeout(), None, "stopped for good");
    }
}
