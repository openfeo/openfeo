// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The WAN router-advertisement client (SPEC §7.3): solicits the ISP's router, keeps what its
//! advertisements say (the default router, a link prefix and the address it yields, on-link
//! prefixes, routes, resolvers, search names, the MTU) with every lifetime as a timer, and
//! reports the learned set whenever it changes. No sockets, no clock: the driver feeds packets
//! and timeouts and sends what comes out.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

use crate::Timestamp;
use crate::iid;
use crate::wire::{Message, NdOption, Preference};

/// RFC 4861 §10: the gap between the first solicitations.
pub const RTR_SOLICITATION_INTERVAL: Timestamp = 4_000;
/// RFC 4861 §10: how many solicitations go out at that gap before backing off.
pub const MAX_RTR_SOLICITATIONS: u32 = 3;
/// RFC 7559: the longest gap between solicitations, an hour.
pub const RS_BACKOFF_MAX: Timestamp = 3_600_000;
/// RFC 4862 §5.5.3: the floor under which a valid lifetime cannot be cut, in seconds.
pub const TWO_HOURS: u32 = 7_200;
/// RFC 8200 §5: an MTU option below the IPv6 minimum is ignored.
const MIN_MTU: u32 = 1280;
/// How many default routers are kept (RFC 4861 §5.1 asks for at least two).
pub const MAX_ROUTERS: usize = 16;
/// How many route information entries are kept.
pub const MAX_ROUTES: usize = 64;
/// How many resolvers are kept (RFC 8106 §5.3.1 suggests a small number).
pub const MAX_RESOLVERS: usize = 8;
/// How many search domains are kept.
pub const MAX_SEARCH: usize = 8;

/// What one WAN's client is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The WAN interface's name, part of the RFC 7217 input.
    pub ifname: String,
    /// The persisted stable-privacy secret.
    pub secret: [u8; 16],
    /// The interface's hardware address, sent in solicitations as the Source Link-Layer
    /// Address option; `None` on a PPP netdev, which has none (the option is optional, RFC 4861
    /// §4.1).
    pub mac: Option<[u8; 6]>,
}

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Carrier came (back).
    LinkUp,
    /// Carrier went away.
    LinkDown,
    /// An ICMPv6 message received on the interface, with the IPv6 source and hop limit.
    Advertisement {
        from: Ipv6Addr,
        hop_limit: u8,
        bytes: Vec<u8>,
    },
    /// The timer of [`Client::next_timeout`] fired.
    Timeout,
}

/// What the client wants done or known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send these bytes to `ff02::2`.
    Solicit(Vec<u8>),
    /// The learned set changed.
    Learned(Learned),
    /// Something for the console.
    Note(Note),
}

/// A route information option (RFC 4191) as learned.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    pub prefix: Ipv6Net,
    /// The advertising router's link-local address.
    pub via: Ipv6Addr,
    pub preference: Preference,
}

/// Everything the WAN currently knows from advertisements. Emitted only when it changes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Learned {
    /// The best default router: highest preference, then most recent.
    pub router: Option<Ipv6Addr>,
    /// Addresses from prefixes with the A flag, with their prefix length.
    pub addresses: Vec<Ipv6Net>,
    /// Prefixes with the L flag.
    pub on_link: Vec<Ipv6Net>,
    pub routes: Vec<Route>,
    /// RDNSS resolvers in the order first seen.
    pub dns: Vec<Ipv6Addr>,
    /// DNSSL names in the order first seen.
    pub search: Vec<String>,
    pub mtu: Option<u32>,
}

/// Console-worthy events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// A message was dropped, and why.
    Ignored(&'static str),
    /// RFC 8106 allows link-local resolvers; the forwarder has no scope to bind one to.
    LinkLocalResolverDropped(Ipv6Addr),
    /// Solicitations reached their hourly cap without an answer.
    StillSoliciting,
}

/// A lifetime as an expiry on the driver's clock; `None` is infinite.
type Expiry = Option<Timestamp>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouterEntry {
    preference: Preference,
    expires: Timestamp,
    seen: Timestamp,
}

/// The client core for one WAN.
#[derive(Debug)]
pub struct Client {
    config: Config,
    up: bool,
    solicit_at: Option<Timestamp>,
    solicitations: u32,
    backoff: Timestamp,
    cap_noted: bool,
    routers: BTreeMap<Ipv6Addr, RouterEntry>,
    /// Keyed by the /64 the address was made from.
    addresses: BTreeMap<Ipv6Net, (Ipv6Addr, Expiry)>,
    on_link: BTreeMap<Ipv6Net, Expiry>,
    routes: BTreeMap<(Ipv6Net, Ipv6Addr), (Preference, Expiry)>,
    dns: Vec<(Ipv6Addr, Expiry)>,
    search: Vec<(String, Expiry)>,
    mtu: Option<u32>,
    last: Learned,
}

impl Client {
    /// A client with the link down and nothing learned.
    #[must_use]
    pub fn new(config: Config) -> Client {
        Client {
            config,
            up: false,
            solicit_at: None,
            solicitations: 0,
            backoff: RTR_SOLICITATION_INTERVAL,
            cap_noted: false,
            routers: BTreeMap::new(),
            addresses: BTreeMap::new(),
            on_link: BTreeMap::new(),
            routes: BTreeMap::new(),
            dns: Vec::new(),
            search: Vec::new(),
            mtu: None,
            last: Learned::default(),
        }
    }

    /// Feed one input at `now` and collect what to do.
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::LinkUp => {
                self.up = true;
                self.start_soliciting(now, &mut out);
            }
            Input::LinkDown => {
                self.up = false;
                self.solicit_at = None;
                self.routers.clear();
                self.addresses.clear();
                self.on_link.clear();
                self.routes.clear();
                self.dns.clear();
                self.search.clear();
                self.mtu = None;
            }
            Input::Advertisement {
                from,
                hop_limit,
                bytes,
            } => {
                if let Some(why) = self.validate(from, hop_limit) {
                    out.push(Output::Note(Note::Ignored(why)));
                    return out;
                }
                let ra = match Message::decode(&bytes) {
                    Ok(Message::RouterAdvertisement(ra)) => ra,
                    Ok(Message::RouterSolicitation { .. }) => {
                        out.push(Output::Note(Note::Ignored(
                            "a solicitation, not an advertisement",
                        )));
                        return out;
                    }
                    Err(_) => {
                        out.push(Output::Note(Note::Ignored("malformed advertisement")));
                        return out;
                    }
                };
                // An answer: solicitations stop (RFC 4861 §6.3.7).
                self.solicit_at = None;
                if ra.router_lifetime > 0 {
                    // Every list is bounded: a neighbour on the link may send any number of
                    // advertisements, and each list keeps what it first saw up to its cap.
                    if self.routers.contains_key(&from) || self.routers.len() < MAX_ROUTERS {
                        self.routers.insert(
                            from,
                            RouterEntry {
                                preference: ra.preference,
                                expires: now + Timestamp::from(ra.router_lifetime) * 1000,
                                seen: now,
                            },
                        );
                    }
                } else {
                    self.routers.remove(&from);
                }
                for option in ra.options {
                    self.learn(from, option, now, &mut out);
                }
            }
            Input::Timeout => {
                self.expire(now);
                if self.up && self.routers.is_empty() && self.solicit_at.is_none() {
                    self.start_soliciting(now, &mut out);
                } else if self.solicit_at.is_some_and(|at| at <= now) {
                    self.solicit(now, &mut out);
                }
            }
        }
        let learned = self.learned();
        if learned != self.last {
            self.last = learned.clone();
            out.push(Output::Learned(learned));
        }
        out
    }

    /// When [`Client::handle`] next wants [`Input::Timeout`]: the next solicitation or the
    /// soonest lifetime to run out.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        let lifetimes = self
            .routers
            .values()
            .map(|r| r.expires)
            .chain(self.addresses.values().filter_map(|(_, e)| *e))
            .chain(self.on_link.values().filter_map(|e| *e))
            .chain(self.routes.values().filter_map(|(_, e)| *e))
            .chain(self.dns.iter().filter_map(|(_, e)| *e))
            .chain(self.search.iter().filter_map(|(_, e)| *e));
        self.solicit_at.into_iter().chain(lifetimes).min()
    }

    fn validate(&self, from: Ipv6Addr, hop_limit: u8) -> Option<&'static str> {
        if !self.up {
            Some("link down")
        } else if hop_limit != 255 {
            Some("hop limit below 255")
        } else if !is_link_local(from) {
            Some("source not link-local")
        } else {
            None
        }
    }

    fn start_soliciting(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        self.solicitations = 0;
        self.backoff = RTR_SOLICITATION_INTERVAL;
        self.cap_noted = false;
        self.solicit(now, out);
    }

    /// Send one solicitation and schedule the next: three at the initial gap, then doubling
    /// to the cap (RFC 7559).
    fn solicit(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let rs = Message::RouterSolicitation {
            options: self
                .config
                .mac
                .map(NdOption::SourceLinkLayer)
                .into_iter()
                .collect(),
        };
        out.push(Output::Solicit(rs.encode()));
        self.solicitations += 1;
        if self.solicitations >= MAX_RTR_SOLICITATIONS {
            self.backoff = (self.backoff * 2).min(RS_BACKOFF_MAX);
            if self.backoff == RS_BACKOFF_MAX && !self.cap_noted {
                self.cap_noted = true;
                out.push(Output::Note(Note::StillSoliciting));
            }
        }
        self.solicit_at = Some(now + self.backoff);
    }

    fn learn(&mut self, from: Ipv6Addr, option: NdOption, now: Timestamp, out: &mut Vec<Output>) {
        match option {
            NdOption::PrefixInformation {
                prefix,
                on_link,
                autonomous,
                valid,
                preferred: _,
            } => {
                if on_link {
                    set_lifetime(&mut self.on_link, prefix, valid, now);
                }
                if autonomous && prefix.prefix_len() == 64 {
                    self.address_lifetime(prefix, valid, now);
                }
            }
            NdOption::Mtu(mtu) => {
                if mtu >= MIN_MTU {
                    self.mtu = Some(mtu);
                }
            }
            NdOption::RouteInformation {
                prefix,
                preference,
                lifetime,
            } => {
                if lifetime == 0 {
                    self.routes.remove(&(prefix, from));
                } else if self.routes.contains_key(&(prefix, from))
                    || self.routes.len() < MAX_ROUTES
                {
                    self.routes
                        .insert((prefix, from), (preference, expiry(now, lifetime)));
                }
            }
            NdOption::Rdnss { lifetime, addrs } => {
                for addr in addrs {
                    if is_link_local(addr) {
                        out.push(Output::Note(Note::LinkLocalResolverDropped(addr)));
                    } else {
                        set_listed(&mut self.dns, addr, lifetime, now, MAX_RESOLVERS);
                    }
                }
            }
            NdOption::Dnssl { lifetime, names } => {
                for name in names {
                    set_listed(&mut self.search, name, lifetime, now, MAX_SEARCH);
                }
            }
            NdOption::SourceLinkLayer(_) | NdOption::Unknown { .. } => {}
        }
    }

    /// RFC 4862 §5.5.3 (e): a received valid lifetime over two hours or over what remains is
    /// taken; otherwise what remains is cut to two hours, unless it is already below that, in
    /// which case the option is ignored.
    fn address_lifetime(&mut self, prefix: Ipv6Net, valid: u32, now: Timestamp) {
        let addr = iid::stable_address(prefix, &self.config.ifname, &self.config.secret, 0);
        let received = expiry(now, valid);
        let Some((_, remaining)) = self.addresses.get(&prefix) else {
            if valid > 0 {
                self.addresses.insert(prefix, (addr, received));
            }
            return;
        };
        let remaining = *remaining;
        let two_hours = now + Timestamp::from(TWO_HOURS) * 1000;
        let taken = match (received, remaining) {
            (None, _) => None,
            (Some(received), None) => {
                if valid > TWO_HOURS {
                    Some(received)
                } else {
                    Some(two_hours)
                }
            }
            (Some(received), Some(remaining)) => {
                if valid > TWO_HOURS || received > remaining {
                    Some(received)
                } else if remaining <= two_hours {
                    Some(remaining)
                } else {
                    Some(two_hours)
                }
            }
        };
        self.addresses.insert(prefix, (addr, taken));
    }

    fn expire(&mut self, now: Timestamp) {
        self.routers.retain(|_, r| r.expires > now);
        self.addresses.retain(|_, (_, e)| e.is_none_or(|e| e > now));
        self.on_link.retain(|_, e| e.is_none_or(|e| e > now));
        self.routes.retain(|_, (_, e)| e.is_none_or(|e| e > now));
        self.dns.retain(|(_, e)| e.is_none_or(|e| e > now));
        self.search.retain(|(_, e)| e.is_none_or(|e| e > now));
    }

    fn learned(&self) -> Learned {
        // The best preference wins; among equals the current router stays, so an equal
        // newcomer's every advertisement does not flip the default route (#26); with no current
        // one among them, the most recent.
        let best = self.routers.values().map(|r| r.preference).max();
        let current = self.last.router.filter(|addr| {
            self.routers
                .get(addr)
                .is_some_and(|r| Some(r.preference) == best)
        });
        let router = current.or_else(|| {
            self.routers
                .iter()
                .filter(|(_, r)| Some(r.preference) == best)
                .max_by_key(|(_, r)| r.seen)
                .map(|(addr, _)| *addr)
        });
        Learned {
            router,
            addresses: self
                .addresses
                .values()
                .map(|(addr, _)| Ipv6Net::new_assert(*addr, 64))
                .collect(),
            on_link: self.on_link.keys().copied().collect(),
            routes: self
                .routes
                .iter()
                .map(|((prefix, via), (preference, _))| Route {
                    prefix: *prefix,
                    via: *via,
                    preference: *preference,
                })
                .collect(),
            dns: self.dns.iter().map(|(addr, _)| *addr).collect(),
            search: self.search.iter().map(|(name, _)| name.clone()).collect(),
            mtu: self.mtu,
        }
    }
}

fn is_link_local(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

/// `now + seconds`, or infinity for RFC 4861's all-ones lifetime.
fn expiry(now: Timestamp, seconds: u32) -> Expiry {
    (seconds != u32::MAX).then(|| now + Timestamp::from(seconds) * 1000)
}

/// A keyed entry: a lifetime of 0 removes it (RFC 4861 §6.3.4), otherwise it is added or
/// refreshed.
fn set_lifetime<K: Ord>(map: &mut BTreeMap<K, Expiry>, key: K, lifetime: u32, now: Timestamp) {
    if lifetime == 0 {
        map.remove(&key);
    } else {
        map.insert(key, expiry(now, lifetime));
    }
}

/// An ordered list entry: a lifetime of 0 removes it, otherwise it is added or refreshed in
/// place, keeping the order it was first seen in.
fn set_listed<T: PartialEq>(
    list: &mut Vec<(T, Expiry)>,
    item: T,
    lifetime: u32,
    now: Timestamp,
    cap: usize,
) {
    if lifetime == 0 {
        list.retain(|(i, _)| *i != item);
    } else if let Some(entry) = list.iter_mut().find(|(i, _)| *i == item) {
        entry.1 = expiry(now, lifetime);
    } else if list.len() < cap {
        list.push((item, expiry(now, lifetime)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Message, NdOption, Preference, RouterAdvertisement};
    use ipnet::Ipv6Net;
    use std::net::Ipv6Addr;

    const SECRET: [u8; 16] = [9; 16];
    const MAC: [u8; 6] = [0x52, 0x54, 0, 0xfe, 0, 0];

    fn client() -> Client {
        Client::new(Config {
            ifname: "p0".to_owned(),
            secret: SECRET,
            mac: Some(MAC),
        })
    }

    fn ll(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n)
    }

    fn net(text: &str) -> Ipv6Net {
        text.parse().unwrap()
    }

    fn ra(lifetime: u16, options: Vec<NdOption>) -> RouterAdvertisement {
        RouterAdvertisement {
            cur_hop_limit: 64,
            router_lifetime: lifetime,
            options,
            ..RouterAdvertisement::default()
        }
    }

    fn pio(prefix: &str, on_link: bool, autonomous: bool, valid: u32, preferred: u32) -> NdOption {
        NdOption::PrefixInformation {
            prefix: net(prefix),
            on_link,
            autonomous,
            valid,
            preferred,
        }
    }

    fn advert(from: Ipv6Addr, ra: &RouterAdvertisement) -> Input {
        Input::Advertisement {
            from,
            hop_limit: 255,
            bytes: Message::RouterAdvertisement(ra.clone()).encode(),
        }
    }

    fn learned(out: &[Output]) -> Option<Learned> {
        out.iter().rev().find_map(|o| match o {
            Output::Learned(l) => Some(l.clone()),
            _ => None,
        })
    }

    fn solicits(out: &[Output]) -> usize {
        out.iter()
            .filter(|o| matches!(o, Output::Solicit(_)))
            .count()
    }

    fn up(c: &mut Client) -> Vec<Output> {
        c.handle(Input::LinkUp, 0)
    }

    /// A PPP netdev has no hardware address (ADR-0023): its solicitations carry no Source
    /// Link-Layer Address option, which RFC 4861 §4.1 allows; a port's carry it as before.
    #[test]
    fn a_solicitation_without_a_mac_carries_no_source_link_layer_option() {
        use crate::wire::Message;
        let mut over_ppp = Client::new(Config {
            ifname: "ppp-wan0".to_owned(),
            secret: SECRET,
            mac: None,
        });
        let out = up(&mut over_ppp);
        let Output::Solicit(bytes) = &out[0] else {
            panic!("no solicitation: {out:?}");
        };
        let Ok(Message::RouterSolicitation { options }) = Message::decode(bytes) else {
            panic!("not a solicitation: {bytes:?}");
        };
        assert!(options.is_empty(), "{options:?}");
        let mut over_port = client();
        let out = up(&mut over_port);
        let Output::Solicit(bytes) = &out[0] else {
            panic!("no solicitation: {out:?}");
        };
        let Ok(Message::RouterSolicitation { options }) = Message::decode(bytes) else {
            panic!("not a solicitation: {bytes:?}");
        };
        assert_eq!(options, vec![NdOption::SourceLinkLayer(MAC)]);
    }

    #[test]
    fn link_up_solicits_three_times_four_seconds_apart_then_backs_off_to_an_hour() {
        let mut c = client();
        let out = up(&mut c);
        assert_eq!(solicits(&out), 1);
        let Output::Solicit(bytes) = &out[0] else {
            panic!("a solicitation first");
        };
        assert_eq!(
            Message::decode(bytes),
            Ok(Message::RouterSolicitation {
                options: vec![NdOption::SourceLinkLayer(MAC)]
            })
        );
        let mut now = 0;
        let mut deltas = Vec::new();
        let mut notes = 0;
        for _ in 0..16 {
            let next = c.next_timeout().unwrap();
            deltas.push(next - now);
            now = next;
            let out = c.handle(Input::Timeout, now);
            assert_eq!(solicits(&out), 1, "one solicitation per timeout at {now}");
            notes += out
                .iter()
                .filter(|o| matches!(o, Output::Note(Note::StillSoliciting)))
                .count();
        }
        assert_eq!(
            deltas,
            [
                4_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000, 512_000, 1_024_000,
                2_048_000, 3_600_000, 3_600_000, 3_600_000, 3_600_000, 3_600_000
            ]
        );
        assert_eq!(notes, 1, "the cap is noted once");
    }

    #[test]
    fn an_advertisement_with_a_router_is_learned_and_expires_on_its_lifetime() {
        let mut c = client();
        up(&mut c);
        let out = c.handle(advert(ll(1), &ra(10, vec![])), 1_000);
        assert_eq!(
            learned(&out),
            Some(Learned {
                router: Some(ll(1)),
                ..Learned::default()
            })
        );
        assert_eq!(
            c.next_timeout(),
            Some(11_000),
            "the lifetime, not another solicitation"
        );
        let out = c.handle(Input::Timeout, 11_000);
        assert_eq!(learned(&out), Some(Learned::default()));
        assert_eq!(solicits(&out), 1, "no router left: soliciting resumes");
    }

    #[test]
    fn a_lifetime_zero_advertisement_withdraws_the_router_but_keeps_the_link_address() {
        let mut c = client();
        up(&mut c);
        let link = pio("2001:db8:ffff::/64", true, true, 2_592_000, 604_800);
        let out = c.handle(advert(ll(1), &ra(1800, vec![link.clone()])), 1_000);
        let first = learned(&out).unwrap();
        assert_eq!(first.router, Some(ll(1)));
        assert_eq!(first.addresses.len(), 1);
        let out = c.handle(advert(ll(1), &ra(0, vec![link])), 2_000);
        let second = learned(&out).unwrap();
        assert_eq!(second.router, None);
        assert_eq!(second.addresses, first.addresses);
        assert_eq!(second.on_link, vec![net("2001:db8:ffff::/64")]);
    }

    #[test]
    fn a_prefix_with_a_and_l_yields_an_address_and_an_on_link_route() {
        let mut c = client();
        up(&mut c);
        let out = c.handle(
            advert(
                ll(1),
                &ra(
                    1800,
                    vec![pio("2001:db8:ffff::/64", true, true, 3600, 1800)],
                ),
            ),
            0,
        );
        let l = learned(&out).unwrap();
        let expected = crate::iid::stable_address(net("2001:db8:ffff::/64"), "p0", &SECRET, 0);
        assert_eq!(l.addresses, vec![Ipv6Net::new_assert(expected, 64)]);
        assert_eq!(l.on_link, vec![net("2001:db8:ffff::/64")]);
        assert_eq!(
            c.next_timeout(),
            Some(1_800_000),
            "the router's lifetime comes first"
        );
        let out = c.handle(
            advert(
                ll(1),
                &ra(
                    1800,
                    vec![pio("2001:db8:fffe::/64", false, true, 3600, 1800)],
                ),
            ),
            0,
        );
        let l = learned(&out).unwrap();
        assert_eq!(l.addresses.len(), 2, "a second prefix, a second address");
        assert_eq!(
            l.on_link,
            vec![net("2001:db8:ffff::/64")],
            "no L flag, no on-link route"
        );
    }

    #[test]
    fn a_prefix_that_is_not_a_slash_64_yields_no_address() {
        let mut c = client();
        up(&mut c);
        let out = c.handle(
            advert(
                ll(1),
                &ra(
                    1800,
                    vec![pio("2001:db8:ff00::/56", true, true, 3600, 1800)],
                ),
            ),
            0,
        );
        let l = learned(&out).unwrap();
        assert_eq!(l.addresses, vec![]);
        assert_eq!(l.on_link, vec![net("2001:db8:ff00::/56")]);
    }

    /// RFC 4861 §6.3.4: a lifetime of zero removes the entry at once; it must not become a
    /// timer that is already due (found by `ndp_client`).
    #[test]
    fn a_lifetime_of_zero_removes_an_on_link_prefix_instead_of_timing_it_out_now() {
        let mut c = client();
        up(&mut c);
        c.handle(
            advert(
                ll(1),
                &ra(1800, vec![pio("2001:db8:ffff::/64", true, false, 3600, 0)]),
            ),
            1,
        );
        let out = c.handle(
            advert(
                ll(1),
                &ra(1800, vec![pio("2001:db8:ffff::/64", true, false, 0, 0)]),
            ),
            2,
        );
        assert_eq!(learned(&out).unwrap().on_link, vec![]);
        assert!(c.next_timeout().unwrap() > 2, "{:?}", c.next_timeout());
        let out = c.handle(
            advert(
                ll(1),
                &ra(1800, vec![pio("2001:db8:fffe::/64", true, false, 0, 0)]),
            ),
            3,
        );
        assert!(learned(&out).is_none(), "never added: {out:?}");
        assert!(c.next_timeout().unwrap() > 3);
    }

    #[test]
    fn the_two_hour_rule_bounds_a_cut_valid_lifetime() {
        let mut c = client();
        up(&mut c);
        let prefix = "2001:db8:ffff::/64";
        c.handle(
            advert(ll(1), &ra(0, vec![pio(prefix, false, true, 86_400, 3600)])),
            0,
        );
        assert_eq!(c.next_timeout(), Some(86_400_000));
        // A cut to 60 s while 86399 s remain: two hours remain instead.
        c.handle(
            advert(ll(1), &ra(0, vec![pio(prefix, false, true, 60, 60)])),
            1_000,
        );
        assert_eq!(c.next_timeout(), Some(1_000 + 7_200_000));
        // A longer lifetime is always taken.
        c.handle(
            advert(ll(1), &ra(0, vec![pio(prefix, false, true, 100_000, 60)])),
            2_000,
        );
        assert_eq!(c.next_timeout(), Some(2_000 + 100_000_000));
        // Under two hours remaining, a shorter received lifetime is ignored.
        c.handle(
            advert(ll(1), &ra(0, vec![pio(prefix, false, true, 3_000, 60)])),
            3_000,
        );
        assert_eq!(c.next_timeout(), Some(3_000 + 7_200_000));
        c.handle(
            advert(ll(1), &ra(0, vec![pio(prefix, false, true, 30, 30)])),
            4_000,
        );
        assert_eq!(c.next_timeout(), Some(3_000 + 7_200_000), "ignored");
        // The address goes when its lifetime does.
        let out = c.handle(Input::Timeout, 3_000 + 7_200_000);
        assert_eq!(learned(&out).unwrap().addresses, vec![]);
    }

    /// Every learned list is bounded: a neighbour on the WAN link may send any number of
    /// advertisements, and each list keeps what it first saw up to its cap.
    #[test]
    fn learned_lists_are_capped() {
        let mut c = client();
        up(&mut c);
        let addrs: Vec<Ipv6Addr> = (1..=MAX_RESOLVERS + 4)
            .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, u16::try_from(i).unwrap()))
            .collect();
        let names: Vec<String> = (1..=MAX_SEARCH + 4)
            .map(|i| format!("d{i}.example"))
            .collect();
        let mut options = vec![
            NdOption::Rdnss {
                lifetime: 600,
                addrs: addrs.clone(),
            },
            NdOption::Dnssl {
                lifetime: 600,
                names: names.clone(),
            },
        ];
        options.extend((1..=MAX_ROUTES + 10).map(|i| NdOption::RouteInformation {
            prefix: net(&format!("2001:db8:{i:x}::/48")),
            preference: Preference::Medium,
            lifetime: 600,
        }));
        let out = c.handle(advert(ll(1), &ra(1800, options)), 0);
        let l = learned(&out).unwrap();
        assert_eq!(l.dns, addrs[..MAX_RESOLVERS].to_vec());
        assert_eq!(l.search, names[..MAX_SEARCH].to_vec());
        assert_eq!(l.routes.len(), MAX_ROUTES);
        for i in 2..=MAX_ROUTERS + 4 {
            c.handle(advert(ll(u16::try_from(i).unwrap()), &ra(1800, vec![])), 0);
        }
        assert_eq!(c.routers.len(), MAX_ROUTERS);
    }

    #[test]
    fn rdnss_dnssl_and_route_information_are_learned_and_a_link_local_resolver_is_dropped() {
        let mut c = client();
        up(&mut c);
        let resolver: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
        let out = c.handle(
            advert(
                ll(1),
                &ra(
                    1800,
                    vec![
                        NdOption::Rdnss {
                            lifetime: 60,
                            addrs: vec![resolver, ll(53)],
                        },
                        NdOption::Dnssl {
                            lifetime: 60,
                            names: vec!["isp.example".to_owned()],
                        },
                        NdOption::RouteInformation {
                            prefix: net("2001:db8:1::/48"),
                            preference: Preference::High,
                            lifetime: 30,
                        },
                        NdOption::Mtu(1492),
                    ],
                ),
            ),
            0,
        );
        assert!(out.contains(&Output::Note(Note::LinkLocalResolverDropped(ll(53)))));
        let l = learned(&out).unwrap();
        assert_eq!(l.dns, vec![resolver]);
        assert_eq!(l.search, vec!["isp.example".to_owned()]);
        assert_eq!(
            l.routes,
            vec![Route {
                prefix: net("2001:db8:1::/48"),
                via: ll(1),
                preference: Preference::High
            }]
        );
        assert_eq!(l.mtu, Some(1492));
        assert_eq!(
            c.next_timeout(),
            Some(30_000),
            "the route's lifetime is the soonest"
        );
        let out = c.handle(Input::Timeout, 60_000);
        let l = learned(&out).unwrap();
        assert!(l.routes.is_empty() && l.dns.is_empty() && l.search.is_empty());
        assert_eq!(l.router, Some(ll(1)));
    }

    #[test]
    fn the_preferred_router_wins_and_recency_breaks_ties() {
        let mut c = client();
        up(&mut c);
        c.handle(advert(ll(1), &ra(1800, vec![])), 0);
        let high = RouterAdvertisement {
            preference: Preference::High,
            ..ra(1800, vec![])
        };
        let out = c.handle(advert(ll(2), &high), 1);
        assert_eq!(learned(&out).unwrap().router, Some(ll(2)));
        let out = c.handle(advert(ll(3), &high), 2);
        assert_eq!(
            learned(&out),
            None,
            "an equal-preference newcomer does not displace the current router (#26)"
        );
        let out = c.handle(advert(ll(2), &ra(0, vec![])), 3);
        assert_eq!(
            learned(&out).unwrap().router,
            Some(ll(3)),
            "withdrawn: the other high one"
        );
    }

    #[test]
    fn an_equal_preference_newcomer_does_not_displace_the_current_router() {
        let mut c = client();
        up(&mut c);
        c.handle(advert(ll(1), &ra(1800, vec![])), 0);
        for now in 1..5 {
            let out = c.handle(advert(ll(2), &ra(1800, vec![])), now);
            assert_eq!(learned(&out), None, "{now}: nothing changed");
        }
        let out = c.handle(advert(ll(1), &ra(1800, vec![])), 5);
        assert_eq!(
            learned(&out),
            None,
            "a refresh of the current one changes nothing"
        );
        let out = c.handle(advert(ll(1), &ra(0, vec![])), 6);
        assert_eq!(
            learned(&out).unwrap().router,
            Some(ll(2)),
            "gone: the other one"
        );
    }

    #[test]
    fn a_higher_preference_newcomer_does() {
        let mut c = client();
        up(&mut c);
        c.handle(advert(ll(1), &ra(1800, vec![])), 0);
        let high = RouterAdvertisement {
            preference: Preference::High,
            ..ra(1800, vec![])
        };
        let out = c.handle(advert(ll(2), &high), 1);
        assert_eq!(learned(&out).unwrap().router, Some(ll(2)));
        let low = RouterAdvertisement {
            preference: Preference::Low,
            ..ra(1800, vec![])
        };
        let out = c.handle(advert(ll(3), &low), 2);
        assert_eq!(learned(&out), None, "a lower one changes nothing");
    }

    #[test]
    fn advertisements_below_hop_limit_255_or_from_a_global_source_are_ignored() {
        let mut c = client();
        up(&mut c);
        let out = c.handle(
            Input::Advertisement {
                from: ll(1),
                hop_limit: 64,
                bytes: Message::RouterAdvertisement(ra(1800, vec![])).encode(),
            },
            0,
        );
        assert!(
            matches!(out[..], [Output::Note(Note::Ignored(_))]),
            "{out:?}"
        );
        let out = c.handle(
            advert("2001:db8:ffff::1".parse().unwrap(), &ra(1800, vec![])),
            0,
        );
        assert!(
            matches!(out[..], [Output::Note(Note::Ignored(_))]),
            "{out:?}"
        );
        assert_eq!(c.next_timeout(), Some(4_000), "still soliciting");
    }

    #[test]
    fn a_malformed_advertisement_is_ignored() {
        let mut c = client();
        up(&mut c);
        for bytes in [
            vec![134, 0, 0, 0, 64, 0, 7, 8],
            {
                let mut b = Message::RouterAdvertisement(ra(1800, vec![])).encode();
                b.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0]);
                b
            },
            Message::RouterSolicitation { options: vec![] }.encode(),
        ] {
            let out = c.handle(
                Input::Advertisement {
                    from: ll(1),
                    hop_limit: 255,
                    bytes,
                },
                0,
            );
            assert!(
                matches!(out[..], [Output::Note(Note::Ignored(_))]),
                "{out:?}"
            );
        }
    }

    #[test]
    fn a_refresh_with_the_same_content_emits_nothing() {
        let mut c = client();
        up(&mut c);
        let message = ra(
            1800,
            vec![pio("2001:db8:ffff::/64", true, true, 3600, 1800)],
        );
        let out = c.handle(advert(ll(1), &message), 0);
        assert!(learned(&out).is_some());
        let out = c.handle(advert(ll(1), &message), 100);
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn link_down_clears_everything_and_link_up_solicits_again() {
        let mut c = client();
        up(&mut c);
        c.handle(
            advert(
                ll(1),
                &ra(
                    1800,
                    vec![pio("2001:db8:ffff::/64", true, true, 3600, 1800)],
                ),
            ),
            0,
        );
        let out = c.handle(Input::LinkDown, 10);
        assert_eq!(learned(&out), Some(Learned::default()));
        assert_eq!(c.next_timeout(), None);
        let out = c.handle(advert(ll(1), &ra(1800, vec![])), 11);
        assert!(
            matches!(out[..], [Output::Note(Note::Ignored(_))]),
            "down: {out:?}"
        );
        let out = c.handle(Input::LinkUp, 20);
        assert_eq!(solicits(&out), 1);
        assert_eq!(c.next_timeout(), Some(20 + 4_000));
    }
}
