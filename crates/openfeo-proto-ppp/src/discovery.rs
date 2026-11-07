// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The PPPoE discovery client (RFC 2516 §5, RFC 4638 §4): PADI until an acceptable PADO,
//! PADR until a PADS, then a session until a PADT from the access concentrator or a stop from
//! the driver. A core: packets in, packets and events out, timers as a single next deadline.

use crate::pppoe::{BROADCAST, Code, Discovery, Tag};
use crate::{MS, Timestamp};

/// PADI retransmission: after these waits, then every last one (§5.1's doubling, capped).
pub const PADI_TIMEOUTS: [Timestamp; 6] = [MS, 2 * MS, 4 * MS, 8 * MS, 16 * MS, 32 * MS];
/// PADR retransmission: the PADR goes out, then again after each of these; the last timeout
/// gives up on the offer and solicits again.
pub const PADR_TIMEOUTS: [Timestamp; 3] = [MS, 2 * MS, 4 * MS];
/// RFC 4638: a payload below this is not worth a tag.
const BASE_PAYLOAD: u16 = 1492;

/// What the driver asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// A service name to insist on; `None` takes any (and offers the empty name).
    pub service: Option<String>,
    /// An access-concentrator name to insist on; `None` takes any.
    pub ac: Option<String>,
    /// The PPP payload to ask for with PPP-Max-Payload (RFC 4638), `None` or at most 1492
    /// asking nothing: the driver passes `min(1500, port MTU − 8)` when the port carries it.
    pub max_payload: Option<u16>,
}

/// What the driver feeds in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Begin (or begin again after `Closed`): a fresh Host-Uniq, a PADI.
    Start,
    /// A discovery frame from `from`.
    Packet { from: [u8; 6], bytes: Vec<u8> },
    /// The timer of [`Client::next_timeout`] fired.
    Timeout,
    /// End the session (a PADT goes out) or the attempt.
    Stop,
}

/// What the client wants done or known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send these discovery bytes to `to` in an `ETH_P_PPP_DISC` frame.
    Send { to: [u8; 6], bytes: Vec<u8> },
    /// A session is up: the kernel plumbing can start.
    Session {
        id: u16,
        ac_mac: [u8; 6],
        ac_name: String,
        /// The PPP payload the access concentrator granted, when above 1492.
        max_payload: Option<u16>,
    },
    /// The session or the attempt is over; `Start` begins another.
    Closed(Reason),
    /// Something for the console.
    Note(Note),
}

/// Why the client closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The access concentrator sent a PADT.
    Padt,
    /// The driver said stop.
    Stopped,
}

/// Console-worthy events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    Padi,
    /// An offer, and why it was refused if it was.
    Pado {
        ac: String,
        service: String,
        refused: Option<&'static str>,
    },
    Padr,
    /// The access concentrator answered the PADR with a refusal.
    Refused(&'static str),
    /// A frame was dropped, and why.
    Ignored(&'static str),
}

/// Where the client is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Padi,
    Padr,
    Session,
    Closed,
}

/// The offer being requested.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Offer {
    ac_mac: [u8; 6],
    ac_name: String,
    service: String,
    cookie: Option<Vec<u8>>,
    relay: Option<Vec<u8>>,
    /// The payload tag to echo in the PADR, when the PADO allowed it.
    max_payload: Option<u16>,
}

/// The discovery client for one port.
#[derive(Debug)]
pub struct Client {
    config: Config,
    rng: u64,
    state: State,
    host_uniq: [u8; 8],
    padi_tries: usize,
    padr_tries: usize,
    timeout: Option<Timestamp>,
    offer: Option<Offer>,
    session: Option<(u16, [u8; 6])>,
}

impl Client {
    /// A client that does nothing until [`Input::Start`]; `seed` feeds the Host-Uniq.
    #[must_use]
    pub fn new(config: Config, seed: u64) -> Client {
        Client {
            config,
            rng: seed | 1,
            state: State::Idle,
            host_uniq: [0; 8],
            padi_tries: 0,
            padr_tries: 0,
            timeout: None,
            offer: None,
            session: None,
        }
    }

    /// Feed one input at `now`; do what comes back.
    pub fn handle(&mut self, input: Input, now: Timestamp) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Start => {
                if matches!(self.state, State::Idle | State::Closed) {
                    self.host_uniq = self.random().to_be_bytes();
                    self.solicit(now, &mut out);
                }
            }
            Input::Packet { from, bytes } => self.packet(from, &bytes, now, &mut out),
            Input::Timeout => {
                if self.timeout.is_some_and(|due| due <= now) {
                    self.expire(now, &mut out);
                }
            }
            Input::Stop => {
                if let (State::Session, Some((id, ac_mac))) = (self.state, self.session) {
                    out.push(Output::Send {
                        to: ac_mac,
                        bytes: Discovery {
                            code: Code::Padt,
                            session_id: id,
                            tags: vec![Tag::HostUniq(self.host_uniq.to_vec())],
                        }
                        .encode(),
                    });
                }
                self.close(Reason::Stopped, &mut out);
            }
        }
        out
    }

    /// When to feed [`Input::Timeout`]; `None` while nothing is pending.
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        self.timeout
    }

    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// This attempt's Host-Uniq, which every answer must echo.
    #[must_use]
    pub fn host_uniq(&self) -> [u8; 8] {
        self.host_uniq
    }

    // --- exchanges --------------------------------------------------------------------------

    fn solicit(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        self.state = State::Padi;
        self.offer = None;
        self.session = None;
        self.padi_tries = 0;
        self.padr_tries = 0;
        out.push(Output::Note(Note::Padi));
        self.send_padi(now, out);
    }

    fn send_padi(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let mut tags = vec![
            Tag::ServiceName(self.config.service.clone().unwrap_or_default()),
            Tag::HostUniq(self.host_uniq.to_vec()),
        ];
        if let Some(payload) = self.config.max_payload.filter(|p| *p > BASE_PAYLOAD) {
            tags.push(Tag::PppMaxPayload(payload));
        }
        out.push(Output::Send {
            to: BROADCAST,
            bytes: Discovery {
                code: Code::Padi,
                session_id: 0,
                tags,
            }
            .encode(),
        });
        let wait = PADI_TIMEOUTS[self.padi_tries.min(PADI_TIMEOUTS.len() - 1)];
        self.timeout = Some(now.saturating_add(wait));
    }

    fn send_padr(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        let Some(offer) = &self.offer else {
            return;
        };
        let mut tags = vec![
            Tag::ServiceName(offer.service.clone()),
            Tag::HostUniq(self.host_uniq.to_vec()),
        ];
        if let Some(cookie) = &offer.cookie {
            tags.push(Tag::AcCookie(cookie.clone()));
        }
        if let Some(relay) = &offer.relay {
            tags.push(Tag::RelaySessionId(relay.clone()));
        }
        if let Some(payload) = offer.max_payload {
            tags.push(Tag::PppMaxPayload(payload));
        }
        out.push(Output::Send {
            to: offer.ac_mac,
            bytes: Discovery {
                code: Code::Padr,
                session_id: 0,
                tags,
            }
            .encode(),
        });
        let wait = PADR_TIMEOUTS[self.padr_tries.min(PADR_TIMEOUTS.len() - 1)];
        self.timeout = Some(now.saturating_add(wait));
    }

    fn expire(&mut self, now: Timestamp, out: &mut Vec<Output>) {
        match self.state {
            State::Padi => {
                self.padi_tries += 1;
                self.send_padi(now, out);
            }
            State::Padr => {
                self.padr_tries += 1;
                if self.padr_tries >= PADR_TIMEOUTS.len() {
                    // The offer went unanswered: ask the link again.
                    self.solicit(now, out);
                } else {
                    self.send_padr(now, out);
                }
            }
            State::Idle | State::Session | State::Closed => self.timeout = None,
        }
    }

    fn close(&mut self, reason: Reason, out: &mut Vec<Output>) {
        self.state = State::Closed;
        self.timeout = None;
        self.offer = None;
        self.session = None;
        out.push(Output::Closed(reason));
    }

    // --- packets ----------------------------------------------------------------------------

    fn packet(&mut self, from: [u8; 6], bytes: &[u8], now: Timestamp, out: &mut Vec<Output>) {
        let Ok(packet) = Discovery::decode(bytes) else {
            out.push(Output::Note(Note::Ignored("undecodable")));
            return;
        };
        match (self.state, packet.code) {
            (State::Padi, Code::Pado) => self.offered(from, &packet, now, out),
            (State::Padr, Code::Pads) => self.granted(from, &packet, now, out),
            (State::Session, Code::Padt) => {
                if self.session == Some((packet.session_id, from)) {
                    self.close(Reason::Padt, out);
                } else {
                    out.push(Output::Note(Note::Ignored("not our session")));
                }
            }
            (State::Padi | State::Padr, Code::Padt) => {
                out.push(Output::Note(Note::Ignored("not our session")));
            }
            (State::Padr | State::Session | State::Idle | State::Closed, Code::Pado) => {
                out.push(Output::Note(Note::Ignored("not soliciting")));
            }
            _ => out.push(Output::Note(Note::Ignored("unexpected code"))),
        }
    }

    fn is_ours(&self, packet: &Discovery) -> bool {
        packet.tag(|tag| match tag {
            Tag::HostUniq(uniq) => Some(uniq.as_slice() == self.host_uniq),
            _ => None,
        }) == Some(true)
    }

    fn offered(
        &mut self,
        from: [u8; 6],
        packet: &Discovery,
        now: Timestamp,
        out: &mut Vec<Output>,
    ) {
        if packet.session_id != 0 || !self.is_ours(packet) {
            out.push(Output::Note(Note::Ignored("not our Host-Uniq")));
            return;
        }
        let ac_name = packet
            .tag(|tag| match tag {
                Tag::AcName(name) => Some(name.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let services: Vec<String> = packet
            .tags
            .iter()
            .filter_map(|tag| match tag {
                Tag::ServiceName(name) => Some(name.clone()),
                _ => None,
            })
            .collect();
        let wanted = self.config.service.clone().unwrap_or_default();
        let service = services
            .iter()
            .find(|name| **name == wanted)
            .cloned()
            .or_else(|| {
                self.config
                    .service
                    .is_none()
                    .then(|| services.first().cloned().unwrap_or_default())
            });
        let refused = if self.config.ac.as_ref().is_some_and(|ac| *ac != ac_name) {
            Some("access concentrator name")
        } else if service.is_none() {
            Some("service name")
        } else {
            None
        };
        out.push(Output::Note(Note::Pado {
            ac: ac_name.clone(),
            service: service.clone().unwrap_or(wanted.clone()),
            refused,
        }));
        let (None, Some(service)) = (refused, service) else {
            return;
        };
        let offered_payload = packet.tag(|tag| match tag {
            Tag::PppMaxPayload(size) => Some(*size),
            _ => None,
        });
        // RFC 4638 §4: the tag goes in the PADR only when the PADO allows at least what we ask.
        let max_payload = self
            .config
            .max_payload
            .filter(|ours| *ours > BASE_PAYLOAD)
            .filter(|ours| offered_payload.is_some_and(|theirs| theirs >= *ours));
        self.offer = Some(Offer {
            ac_mac: from,
            ac_name,
            service,
            cookie: packet.tag(|tag| match tag {
                Tag::AcCookie(cookie) => Some(cookie.clone()),
                _ => None,
            }),
            relay: packet.tag(|tag| match tag {
                Tag::RelaySessionId(id) => Some(id.clone()),
                _ => None,
            }),
            max_payload,
        });
        self.state = State::Padr;
        self.padr_tries = 0;
        out.push(Output::Note(Note::Padr));
        self.send_padr(now, out);
    }

    fn granted(
        &mut self,
        from: [u8; 6],
        packet: &Discovery,
        now: Timestamp,
        out: &mut Vec<Output>,
    ) {
        let Some(offer) = self.offer.clone() else {
            return;
        };
        if from != offer.ac_mac || !self.is_ours(packet) {
            out.push(Output::Note(Note::Ignored("not our Host-Uniq")));
            return;
        }
        let error = packet.tag(|tag| match tag {
            Tag::ServiceNameError(_) => Some("service name error"),
            Tag::AcSystemError(_) => Some("access concentrator error"),
            Tag::GenericError(_) => Some("generic error"),
            _ => None,
        });
        let refused = error.or((packet.session_id == 0).then_some("session id 0"));
        if let Some(why) = refused {
            out.push(Output::Note(Note::Refused(why)));
            // Back to PADI, after the holdoff the schedule has reached.
            self.state = State::Padi;
            self.offer = None;
            self.padi_tries += 1;
            let wait = PADI_TIMEOUTS[self.padi_tries.min(PADI_TIMEOUTS.len() - 1)];
            self.timeout = Some(now.saturating_add(wait));
            return;
        }
        let max_payload = packet
            .tag(|tag| match tag {
                Tag::PppMaxPayload(size) => Some(*size),
                _ => None,
            })
            .filter(|size| *size > BASE_PAYLOAD);
        self.state = State::Session;
        self.timeout = None;
        self.session = Some((packet.session_id, from));
        out.push(Output::Session {
            id: packet.session_id,
            ac_mac: from,
            ac_name: offer.ac_name,
            max_payload,
        });
    }

    fn random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pppoe::{Code, Discovery, Tag};

    const AC: [u8; 6] = [0x52, 0x54, 0, 0xfe, 0, 1];
    const OTHER_AC: [u8; 6] = [0x52, 0x54, 0, 0xfe, 0, 2];

    fn config() -> Config {
        Config {
            service: None,
            ac: None,
            max_payload: Some(1500),
        }
    }

    fn started(config: Config) -> (Client, Vec<Output>) {
        let mut client = Client::new(config, 0x5eed);
        let out = client.handle(Input::Start, 0);
        (client, out)
    }

    fn sent(out: &[Output]) -> Vec<([u8; 6], Discovery)> {
        out.iter()
            .filter_map(|output| match output {
                Output::Send { to, bytes } => Some((*to, Discovery::decode(bytes).expect("ours"))),
                _ => None,
            })
            .collect()
    }

    fn notes(out: &[Output]) -> Vec<Note> {
        out.iter()
            .filter_map(|output| match output {
                Output::Note(note) => Some(note.clone()),
                _ => None,
            })
            .collect()
    }

    fn session(out: &[Output]) -> Option<(u16, [u8; 6], String, Option<u16>)> {
        out.iter().find_map(|output| match output {
            Output::Session {
                id,
                ac_mac,
                ac_name,
                max_payload,
            } => Some((*id, *ac_mac, ac_name.clone(), *max_payload)),
            _ => None,
        })
    }

    fn packet(code: Code, session_id: u16, tags: Vec<Tag>) -> Vec<u8> {
        Discovery {
            code,
            session_id,
            tags,
        }
        .encode()
    }

    fn pado(client: &Client, ac_name: &str, extra: Vec<Tag>) -> Vec<u8> {
        let mut tags = vec![
            Tag::AcName(ac_name.to_owned()),
            Tag::ServiceName(String::new()),
            Tag::HostUniq(client.host_uniq().to_vec()),
        ];
        tags.extend(extra);
        packet(Code::Pado, 0, tags)
    }

    fn pads(client: &Client, session_id: u16, extra: Vec<Tag>) -> Vec<u8> {
        let mut tags = vec![
            Tag::ServiceName(String::new()),
            Tag::HostUniq(client.host_uniq().to_vec()),
        ];
        tags.extend(extra);
        packet(Code::Pads, session_id, tags)
    }

    fn from(ac: [u8; 6], bytes: Vec<u8>) -> Input {
        Input::Packet { from: ac, bytes }
    }

    #[test]
    fn start_broadcasts_a_padi_with_host_uniq_and_max_payload() {
        let (client, out) = started(config());
        let sends = sent(&out);
        assert_eq!(sends.len(), 1);
        let (to, padi) = &sends[0];
        assert_eq!(*to, BROADCAST);
        assert_eq!(padi.code, Code::Padi);
        assert_eq!(padi.session_id, 0);
        assert_eq!(
            padi.tags,
            vec![
                Tag::ServiceName(String::new()),
                Tag::HostUniq(client.host_uniq().to_vec()),
                Tag::PppMaxPayload(1500),
            ]
        );
        assert_ne!(client.host_uniq(), [0; 8]);
        assert_eq!(client.state(), State::Padi);
        assert_eq!(client.next_timeout(), Some(PADI_TIMEOUTS[0]));
        assert_eq!(notes(&out), vec![Note::Padi]);
        let (_, out) = started(Config {
            service: Some("isp".to_owned()),
            max_payload: None,
            ..config()
        });
        let (_, padi) = &sent(&out)[0];
        assert_eq!(padi.tags[0], Tag::ServiceName("isp".to_owned()));
        assert!(
            !padi
                .tags
                .iter()
                .any(|tag| matches!(tag, Tag::PppMaxPayload(_))),
            "no payload tag when nothing above 1492 is asked for"
        );
    }

    #[test]
    fn padi_retransmits_on_the_schedule_then_every_32_s() {
        let (mut client, _) = started(config());
        let host_uniq = client.host_uniq();
        let mut now = 0;
        let mut expected = PADI_TIMEOUTS.to_vec();
        expected.extend([32_000, 32_000]);
        for wait in expected {
            assert_eq!(client.next_timeout(), Some(now + wait), "after {now}");
            now += wait;
            let out = client.handle(Input::Timeout, now);
            let sends = sent(&out);
            assert_eq!(sends.len(), 1);
            assert_eq!(sends[0].1.code, Code::Padi);
            assert!(sends[0].1.tags.contains(&Tag::HostUniq(host_uniq.to_vec())));
        }
        assert_eq!(client.host_uniq(), host_uniq, "one attempt, one Host-Uniq");
    }

    #[test]
    fn the_first_acceptable_pado_gets_a_padr_echoing_cookie_relay_id_and_max_payload() {
        let (mut client, _) = started(config());
        let offer = pado(
            &client,
            "isp",
            vec![
                Tag::AcCookie(vec![1, 2, 3, 4]),
                Tag::RelaySessionId(vec![9]),
                Tag::PppMaxPayload(1500),
            ],
        );
        let out = client.handle(from(AC, offer), 500);
        let sends = sent(&out);
        assert_eq!(sends.len(), 1);
        let (to, padr) = &sends[0];
        assert_eq!(*to, AC);
        assert_eq!(padr.code, Code::Padr);
        assert_eq!(
            padr.tags,
            vec![
                Tag::ServiceName(String::new()),
                Tag::HostUniq(client.host_uniq().to_vec()),
                Tag::AcCookie(vec![1, 2, 3, 4]),
                Tag::RelaySessionId(vec![9]),
                Tag::PppMaxPayload(1500),
            ]
        );
        assert_eq!(client.state(), State::Padr);
        assert_eq!(client.next_timeout(), Some(500 + PADR_TIMEOUTS[0]));
        assert_eq!(
            notes(&out),
            vec![
                Note::Pado {
                    ac: "isp".to_owned(),
                    service: String::new(),
                    refused: None
                },
                Note::Padr
            ]
        );
        let late = pado(&client, "other", Vec::new());
        let out = client.handle(from(OTHER_AC, late), 600);
        assert!(
            sent(&out).is_empty(),
            "a second offer changes nothing: {out:?}"
        );
        assert_eq!(notes(&out), vec![Note::Ignored("not soliciting")]);
    }

    #[test]
    fn a_pado_the_filters_refuse_is_ignored_and_a_pads_with_session_zero_restarts() {
        let (mut client, _) = started(Config {
            ac: Some("home".to_owned()),
            ..config()
        });
        let out = client.handle(from(AC, pado(&client, "isp", Vec::new())), 100);
        assert!(sent(&out).is_empty(), "nothing sent: {out:?}");
        assert_eq!(
            notes(&out),
            vec![Note::Pado {
                ac: "isp".to_owned(),
                service: String::new(),
                refused: Some("access concentrator name")
            }]
        );
        assert_eq!(client.state(), State::Padi);
        let out = client.handle(from(OTHER_AC, pado(&client, "home", Vec::new())), 200);
        assert_eq!(sent(&out)[0].1.code, Code::Padr);
        let out = client.handle(from(OTHER_AC, pads(&client, 0, Vec::new())), 300);
        assert!(session(&out).is_none());
        assert!(sent(&out).is_empty(), "nothing sent: {out:?}");
        assert_eq!(notes(&out), vec![Note::Refused("session id 0")]);
        assert_eq!(client.state(), State::Padi);
        let holdoff = client.next_timeout().expect("a PADI is due");
        assert!(holdoff > 300);
        let out = client.handle(Input::Timeout, holdoff);
        assert_eq!(sent(&out)[0].1.code, Code::Padi);
        // An error tag is a refusal too.
        let out = client.handle(
            from(OTHER_AC, pado(&client, "home", Vec::new())),
            holdoff + 1,
        );
        assert_eq!(sent(&out)[0].1.code, Code::Padr);
        let out = client.handle(
            from(
                OTHER_AC,
                pads(&client, 7, vec![Tag::AcSystemError("full".to_owned())]),
            ),
            holdoff + 2,
        );
        assert!(session(&out).is_none());
        assert_eq!(
            notes(&out),
            vec![Note::Refused("access concentrator error")]
        );
    }

    #[test]
    fn a_pado_without_our_host_uniq_is_ignored() {
        let (mut client, _) = started(config());
        let offer = packet(
            Code::Pado,
            0,
            vec![
                Tag::AcName("isp".to_owned()),
                Tag::ServiceName(String::new()),
                Tag::HostUniq(vec![1, 2, 3]),
            ],
        );
        let out = client.handle(from(AC, offer), 100);
        assert!(sent(&out).is_empty(), "nothing sent: {out:?}");
        assert_eq!(notes(&out), vec![Note::Ignored("not our Host-Uniq")]);
        let no_uniq = packet(Code::Pado, 0, vec![Tag::AcName("isp".to_owned())]);
        let out = client.handle(from(AC, no_uniq), 101);
        assert_eq!(notes(&out), vec![Note::Ignored("not our Host-Uniq")]);
        let out = client.handle(from(AC, vec![0x11, 0x07, 0]), 102);
        assert_eq!(notes(&out), vec![Note::Ignored("undecodable")]);
        assert_eq!(client.state(), State::Padi);
    }

    #[test]
    fn max_payload_is_echoed_only_when_the_pado_offers_at_least_ours() {
        for (offered, echoed) in [
            (Some(1492), None),
            (None, None),
            (Some(1508), Some(1500)),
            (Some(1500), Some(1500)),
        ] {
            let (mut client, _) = started(config());
            let extra = offered.map(Tag::PppMaxPayload).into_iter().collect();
            let out = client.handle(from(AC, pado(&client, "isp", extra)), 100);
            let (_, padr) = &sent(&out)[0];
            let tag = padr.tag(|tag| match tag {
                Tag::PppMaxPayload(size) => Some(*size),
                _ => None,
            });
            assert_eq!(tag, echoed, "offered {offered:?}");
        }
    }

    #[test]
    fn pads_without_the_tag_means_none() {
        for (tag, expected) in [(None, None), (Some(1500), Some(1500)), (Some(1400), None)] {
            let (mut client, _) = started(config());
            client.handle(
                from(AC, pado(&client, "isp", vec![Tag::PppMaxPayload(1500)])),
                100,
            );
            let extra = tag.map(Tag::PppMaxPayload).into_iter().collect();
            let out = client.handle(from(AC, pads(&client, 0x1234, extra)), 200);
            assert_eq!(
                session(&out),
                Some((0x1234, AC, "isp".to_owned(), expected)),
                "tag {tag:?}"
            );
            assert_eq!(client.state(), State::Session);
            assert_eq!(client.next_timeout(), None);
        }
    }

    #[test]
    fn padr_retransmits_three_times_then_padi_again() {
        let (mut client, _) = started(config());
        client.handle(from(AC, pado(&client, "isp", Vec::new())), 100);
        let mut now = 100;
        let mut codes = Vec::new();
        for wait in PADR_TIMEOUTS {
            assert_eq!(client.next_timeout(), Some(now + wait));
            now += wait;
            let out = client.handle(Input::Timeout, now);
            codes.push(sent(&out)[0].1.code);
        }
        assert_eq!(codes, vec![Code::Padr, Code::Padr, Code::Padi]);
        assert_eq!(client.state(), State::Padi);
    }

    #[test]
    fn padt_from_the_ac_closes_and_stop_sends_padt() {
        let (mut client, _) = started(config());
        client.handle(from(AC, pado(&client, "isp", Vec::new())), 100);
        client.handle(from(AC, pads(&client, 0x0042, Vec::new())), 200);
        let wrong = packet(Code::Padt, 0x0043, Vec::new());
        let out = client.handle(from(AC, wrong), 300);
        assert_eq!(notes(&out), vec![Note::Ignored("not our session")]);
        assert_eq!(client.state(), State::Session);
        let out = client.handle(from(AC, packet(Code::Padt, 0x0042, Vec::new())), 400);
        assert!(
            matches!(out.as_slice(), [Output::Closed(Reason::Padt)]),
            "{out:?}"
        );
        assert_eq!(client.state(), State::Closed);

        let (mut client, _) = started(config());
        client.handle(from(AC, pado(&client, "isp", Vec::new())), 100);
        client.handle(from(AC, pads(&client, 0x0042, Vec::new())), 200);
        let out = client.handle(Input::Stop, 500);
        let sends = sent(&out);
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, AC);
        assert_eq!(sends[0].1.code, Code::Padt);
        assert_eq!(sends[0].1.session_id, 0x0042);
        assert!(matches!(out.last(), Some(Output::Closed(Reason::Stopped))));
        assert_eq!(client.state(), State::Closed);
        assert_eq!(client.next_timeout(), None);
        let out = client.handle(Input::Start, 600);
        assert_eq!(sent(&out)[0].1.code, Code::Padi, "a client can start again");
    }
}
