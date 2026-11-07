// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The Link Control Protocol (RFC 1661 §6, RFC 1334 §2, RFC 1994 §2): the options we offer
//! (MRU, magic number) and accept (the peer's MRU and magic, PAP or CHAP-MD5 as the way we
//! prove ourselves), the ones we refuse, the echo keepalive and the echo reply.

use crate::frame::{Error, Packet, code, options, put_option};
use crate::fsm::{Judgement, Options};
use crate::{MS, Timestamp};

/// Echo-Requests go out this often once the link is open.
pub const ECHO_INTERVAL: Timestamp = 10 * MS;
/// This many unanswered Echo-Requests in a row lose the link.
pub const ECHO_MISSES: u32 = 3;
/// The smallest MRU we let the peer impose on us (RFC 1661 §6.1's floor for a sane link).
pub const MIN_MRU: u16 = 576;
/// The MRU RFC 1661 assumes when none is negotiated.
pub const DEFAULT_MRU: u16 = 1500;

const OPT_MRU: u8 = 1;
const OPT_AUTH: u8 = 3;
const OPT_QUALITY: u8 = 4;
const OPT_MAGIC: u8 = 5;
const OPT_PFC: u8 = 7;
const OPT_ACFC: u8 = 8;
const OPT_CALLBACK: u8 = 13;
const OPT_MRRU: u8 = 17;
const PROTO_PAP: u16 = 0xc023;
const PROTO_CHAP: u16 = 0xc223;
const CHAP_MD5: u8 = 5;

/// How the peer wants us to prove ourselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProto {
    Pap,
    ChapMd5,
    /// Anything else (MS-CHAP, EAP): not supported.
    Other {
        protocol: u16,
        algorithm: Option<u8>,
    },
}

/// LCP options (RFC 1661 §6, RFC 1570, RFC 1990 for the ones we refuse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opt {
    Mru(u16),
    Auth(AuthProto),
    Magic(u32),
    Pfc,
    Acfc,
    Quality(u16),
    Callback(u8),
    Mrru(u16),
    Unknown { kind: u8, data: Vec<u8> },
}

/// What the negotiation settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    /// What we may receive: the MRU we asked for, as naked down, or the default if rejected.
    pub mru_ours: u16,
    /// What the peer may receive.
    pub mru_theirs: u16,
    /// How the peer wants us authenticated; `None` for not at all.
    pub auth: Option<AuthProto>,
    /// Our magic number, 0 when the peer rejected the option.
    pub magic_ours: u32,
    pub magic_theirs: u32,
}

/// Our side of LCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lcp {
    /// The largest MRU we can ask for: the PPPoE payload the port carries.
    max_mru: u16,
    mru_ours: Option<u16>,
    mru_theirs: u16,
    auth: Option<AuthProto>,
    /// How many times the peer insisted on an authentication protocol we do not speak.
    auth_insisted: u8,
    magic_ours: Option<u32>,
    magic_theirs: u32,
    echo_rejected: bool,
    rng: u64,
}

impl Lcp {
    /// LCP asking for `mru` (the payload the port carries) and a magic number from `seed`.
    #[must_use]
    pub fn new(mru: u16, seed: u64) -> Lcp {
        let mut lcp = Lcp {
            max_mru: mru,
            mru_ours: Some(mru),
            mru_theirs: DEFAULT_MRU,
            auth: None,
            auth_insisted: 0,
            magic_ours: None,
            magic_theirs: 0,
            echo_rejected: false,
            rng: seed | 1,
        };
        lcp.magic_ours = Some(lcp.random_magic());
        lcp
    }

    /// What the negotiation settled so far.
    #[must_use]
    pub fn negotiated(&self) -> Negotiated {
        Negotiated {
            mru_ours: self.mru_ours.unwrap_or(DEFAULT_MRU),
            mru_theirs: self.mru_theirs,
            auth: self.auth,
            magic_ours: self.magic_ours.unwrap_or(0),
            magic_theirs: self.magic_theirs,
        }
    }

    /// The peer insisted on an authentication protocol we do not speak, three times.
    #[must_use]
    pub fn auth_unsupported(&self) -> bool {
        self.auth_insisted > 2
    }

    /// The peer Code-Rejected Echo-Request: the keepalive cannot run.
    #[must_use]
    pub fn echo_rejected(&self) -> bool {
        self.echo_rejected
    }

    /// Act on a packet the automaton left to us: answer an Echo-Request with our magic (and
    /// the data after the peer's), drop a Discard-Request, note a Code-Reject of Echo-Request.
    /// Echo-Replies are the keepalive's ([`Keepalive::reply`]).
    pub fn handle_unknown(&mut self, packet: &Packet) -> Vec<Packet> {
        match packet.code {
            code::ECHO_REQUEST => {
                let mut data = self.negotiated().magic_ours.to_be_bytes().to_vec();
                data.extend_from_slice(packet.data.get(4..).unwrap_or(&[]));
                vec![Packet {
                    code: code::ECHO_REPLY,
                    id: packet.id,
                    data,
                }]
            }
            code::CODE_REJECT => {
                if packet.data.first() == Some(&code::ECHO_REQUEST) {
                    self.echo_rejected = true;
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn random_magic(&mut self) -> u32 {
        loop {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            let magic = u32::try_from(self.rng & 0xffff_ffff).unwrap_or(1);
            if magic != 0 {
                return magic;
            }
        }
    }
}

impl Options for Lcp {
    type Opt = Opt;

    fn decode(data: &[u8]) -> Result<Vec<Opt>, Error> {
        options(data)?
            .into_iter()
            .map(|(kind, data)| {
                let bad = Err(Error::Option { kind });
                Ok(match (kind, data) {
                    (OPT_MRU, [hi, lo]) => Opt::Mru(u16::from_be_bytes([*hi, *lo])),
                    (OPT_AUTH, [hi, lo, rest @ ..]) => {
                        let protocol = u16::from_be_bytes([*hi, *lo]);
                        Opt::Auth(match (protocol, rest) {
                            (PROTO_PAP, []) => AuthProto::Pap,
                            (PROTO_CHAP, [CHAP_MD5]) => AuthProto::ChapMd5,
                            (_, []) => AuthProto::Other {
                                protocol,
                                algorithm: None,
                            },
                            (_, [algorithm]) => AuthProto::Other {
                                protocol,
                                algorithm: Some(*algorithm),
                            },
                            _ => return bad,
                        })
                    }
                    (OPT_QUALITY, [hi, lo]) => Opt::Quality(u16::from_be_bytes([*hi, *lo])),
                    (OPT_MAGIC, [a, b, c, d]) => Opt::Magic(u32::from_be_bytes([*a, *b, *c, *d])),
                    (OPT_PFC, []) => Opt::Pfc,
                    (OPT_ACFC, []) => Opt::Acfc,
                    (OPT_CALLBACK, [operation, ..]) => Opt::Callback(*operation),
                    (OPT_MRRU, [hi, lo]) => Opt::Mrru(u16::from_be_bytes([*hi, *lo])),
                    (OPT_MRU | OPT_AUTH | OPT_MAGIC, _) => return bad,
                    // An option we reject whatever it says (Quality, PFC, ACFC, Callback, MRRU)
                    // in a shape not drawn above is kept verbatim, so the Configure-Reject can
                    // echo it instead of the whole request being dropped.
                    (kind, data) => Opt::Unknown {
                        kind,
                        data: data.to_vec(),
                    },
                })
            })
            .collect()
    }

    fn encode(opts: &[Opt]) -> Vec<u8> {
        let mut out = Vec::new();
        for opt in opts {
            match opt {
                Opt::Mru(mru) => put_option(&mut out, OPT_MRU, &mru.to_be_bytes()),
                Opt::Auth(AuthProto::Pap) => {
                    put_option(&mut out, OPT_AUTH, &PROTO_PAP.to_be_bytes());
                }
                Opt::Auth(AuthProto::ChapMd5) => {
                    let mut data = PROTO_CHAP.to_be_bytes().to_vec();
                    data.push(CHAP_MD5);
                    put_option(&mut out, OPT_AUTH, &data);
                }
                Opt::Auth(AuthProto::Other {
                    protocol,
                    algorithm,
                }) => {
                    let mut data = protocol.to_be_bytes().to_vec();
                    data.extend(algorithm);
                    put_option(&mut out, OPT_AUTH, &data);
                }
                Opt::Magic(magic) => put_option(&mut out, OPT_MAGIC, &magic.to_be_bytes()),
                Opt::Pfc => put_option(&mut out, OPT_PFC, &[]),
                Opt::Acfc => put_option(&mut out, OPT_ACFC, &[]),
                Opt::Quality(protocol) => {
                    put_option(&mut out, OPT_QUALITY, &protocol.to_be_bytes());
                }
                Opt::Callback(operation) => put_option(&mut out, OPT_CALLBACK, &[*operation]),
                Opt::Mrru(mrru) => put_option(&mut out, OPT_MRRU, &mrru.to_be_bytes()),
                Opt::Unknown { kind, data } => put_option(&mut out, *kind, data),
            }
        }
        out
    }

    fn ours(&self) -> Vec<Opt> {
        let mut ours = Vec::new();
        if let Some(mru) = self.mru_ours {
            ours.push(Opt::Mru(mru));
        }
        if let Some(magic) = self.magic_ours {
            ours.push(Opt::Magic(magic));
        }
        ours
    }

    fn judge(&mut self, theirs: &[Opt]) -> Judgement<Opt> {
        let mut naks = Vec::new();
        let mut rejects = Vec::new();
        let mut accepted = self.clone();
        for opt in theirs {
            match opt {
                Opt::Mru(mru) if *mru < MIN_MRU => naks.push(Opt::Mru(MIN_MRU)),
                Opt::Mru(mru) if *mru > self.max_mru => naks.push(Opt::Mru(self.max_mru)),
                Opt::Mru(mru) => accepted.mru_theirs = *mru,
                Opt::Auth(auth @ (AuthProto::Pap | AuthProto::ChapMd5)) => {
                    accepted.auth = Some(*auth);
                }
                Opt::Auth(AuthProto::Other { .. }) => {
                    self.auth_insisted = self.auth_insisted.saturating_add(1);
                    accepted.auth_insisted = self.auth_insisted;
                    match self.auth_insisted {
                        1 => naks.push(Opt::Auth(AuthProto::ChapMd5)),
                        2 => naks.push(Opt::Auth(AuthProto::Pap)),
                        _ => rejects.push(opt.clone()),
                    }
                }
                Opt::Magic(magic) if Some(*magic) == self.magic_ours => {
                    // The same magic on both ends is a looped line, or a coincidence; either
                    // way both numbers change (RFC 1661 §6.4).
                    let fresh = self.random_magic();
                    self.magic_ours = Some(fresh);
                    accepted.magic_ours = Some(fresh);
                    accepted.rng = self.rng;
                    naks.push(Opt::Magic(self.random_magic()));
                    accepted.rng = self.rng;
                }
                Opt::Magic(magic) => accepted.magic_theirs = *magic,
                Opt::Pfc
                | Opt::Acfc
                | Opt::Quality(_)
                | Opt::Callback(_)
                | Opt::Mrru(_)
                | Opt::Unknown { .. } => rejects.push(opt.clone()),
            }
        }
        if !rejects.is_empty() {
            Judgement::Reject(rejects)
        } else if !naks.is_empty() {
            Judgement::Nak(naks)
        } else {
            *self = accepted;
            Judgement::Ack
        }
    }

    fn naked(&mut self, suggested: &[Opt]) -> bool {
        for opt in suggested {
            match opt {
                Opt::Mru(mru) if (MIN_MRU..=self.max_mru).contains(mru) => {
                    self.mru_ours = Some(*mru);
                }
                Opt::Magic(_) => self.magic_ours = Some(self.random_magic()),
                _ => {}
            }
        }
        true
    }

    fn rejected(&mut self, opts: &[Opt]) -> bool {
        for opt in opts {
            match opt {
                Opt::Mru(_) => self.mru_ours = None,
                Opt::Magic(_) => self.magic_ours = None,
                _ => {}
            }
        }
        true
    }
}

/// The LCP echo keepalive: an Echo-Request every [`ECHO_INTERVAL`] once the link is open,
/// [`ECHO_MISSES`] unanswered in a row meaning the link is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keepalive {
    next: Option<Timestamp>,
    id: u8,
    misses: u32,
    lost: bool,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self::new()
    }
}

impl Keepalive {
    /// A keepalive that does nothing until [`Keepalive::start`].
    #[must_use]
    pub fn new() -> Keepalive {
        Keepalive {
            next: None,
            id: 0,
            misses: 0,
            lost: false,
        }
    }

    /// The link opened at `now`: the first echo goes out one interval later.
    pub fn start(&mut self, now: Timestamp) {
        self.next = Some(now.saturating_add(ECHO_INTERVAL));
        self.misses = 0;
        self.lost = false;
    }

    /// The link closed.
    pub fn stop(&mut self) {
        self.next = None;
    }

    /// When to call [`Keepalive::tick`].
    #[must_use]
    pub fn next_timeout(&self) -> Option<Timestamp> {
        self.next
    }

    /// At the deadline: the next Echo-Request carrying `magic`, or `None` once three went
    /// unanswered (then [`Keepalive::lost`] is true) or when nothing is due.
    pub fn tick(&mut self, now: Timestamp, magic: u32) -> Option<Packet> {
        let due = self.next?;
        if now < due {
            return None;
        }
        if self.misses >= ECHO_MISSES {
            self.lost = true;
            self.next = None;
            return None;
        }
        self.misses += 1;
        self.id = self.id.wrapping_add(1);
        self.next = Some(now.saturating_add(ECHO_INTERVAL));
        Some(Packet {
            code: code::ECHO_REQUEST,
            id: self.id,
            data: magic.to_be_bytes().to_vec(),
        })
    }

    /// An Echo-Reply arrived: any reply counts as a sign of life.
    pub fn reply(&mut self, packet: &Packet) {
        if packet.code == code::ECHO_REPLY {
            self.misses = 0;
        }
    }

    /// Echo-Requests out and unanswered.
    #[must_use]
    pub fn misses(&self) -> u32 {
        self.misses
    }

    /// Three Echo-Requests went unanswered.
    #[must_use]
    pub fn lost(&self) -> bool {
        self.lost
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Packet, code};
    use crate::fsm::{Action, Event, Fsm, Judgement, MAX_FAILURE, Options};

    fn new_lcp() -> Lcp {
        Lcp::new(1492, 0x5eed)
    }

    #[test]
    fn our_request_carries_mru_and_magic_only() {
        let lcp = new_lcp();
        let ours = lcp.ours();
        assert_eq!(ours.len(), 2);
        assert_eq!(ours[0], Opt::Mru(1492));
        assert!(matches!(ours[1], Opt::Magic(magic) if magic != 0));
        let bytes = Lcp::encode(&ours);
        assert_eq!(&bytes[..4], &[1, 4, 0x05, 0xd4]);
        assert_eq!(bytes[4..6], [5, 6]);
        assert_eq!(Lcp::decode(&bytes).unwrap(), ours);
    }

    #[test]
    fn options_round_trip_and_bad_lengths_are_errors() {
        let all = vec![
            Opt::Mru(1500),
            Opt::Auth(AuthProto::Pap),
            Opt::Auth(AuthProto::ChapMd5),
            Opt::Auth(AuthProto::Other {
                protocol: 0xc227,
                algorithm: Some(0x81),
            }),
            Opt::Magic(0xdead_beef),
            Opt::Pfc,
            Opt::Acfc,
            Opt::Quality(0xc025),
            Opt::Callback(6),
            Opt::Mrru(1500),
            Opt::Unknown {
                kind: 99,
                data: vec![1, 2],
            },
        ];
        assert_eq!(Lcp::decode(&Lcp::encode(&all)).unwrap(), all);
        assert_eq!(
            Lcp::encode(&[Opt::Auth(AuthProto::ChapMd5)]),
            vec![3, 5, 0xc2, 0x23, 0x05]
        );
        assert!(Lcp::decode(&[1, 3, 5]).is_err(), "an MRU is two bytes");
        assert!(Lcp::decode(&[5, 4, 1, 2]).is_err(), "a magic is four");
        assert!(
            Lcp::decode(&[3, 3, 0xc0]).is_err(),
            "an auth protocol is two"
        );
    }

    #[test]
    fn pap_or_chap_md5_is_accepted_and_anything_else_naked_to_chap_then_pap_then_rejected() {
        let mut lcp = new_lcp();
        assert_eq!(lcp.judge(&[Opt::Auth(AuthProto::Pap)]), Judgement::Ack);
        assert_eq!(lcp.negotiated().auth, Some(AuthProto::Pap));
        let mut lcp = new_lcp();
        assert_eq!(lcp.judge(&[Opt::Auth(AuthProto::ChapMd5)]), Judgement::Ack);
        assert_eq!(lcp.negotiated().auth, Some(AuthProto::ChapMd5));
        let mut lcp = new_lcp();
        let mschap = Opt::Auth(AuthProto::Other {
            protocol: 0xc223,
            algorithm: Some(0x81),
        });
        assert_eq!(
            lcp.judge(std::slice::from_ref(&mschap)),
            Judgement::Nak(vec![Opt::Auth(AuthProto::ChapMd5)])
        );
        assert_eq!(
            lcp.judge(std::slice::from_ref(&mschap)),
            Judgement::Nak(vec![Opt::Auth(AuthProto::Pap)])
        );
        assert!(!lcp.auth_unsupported());
        assert_eq!(
            lcp.judge(std::slice::from_ref(&mschap)),
            Judgement::Reject(vec![mschap])
        );
        assert!(lcp.auth_unsupported());
        assert_eq!(lcp.negotiated().auth, None);
    }

    #[test]
    fn mru_naks_converge_within_max_failure() {
        let mut lcp = Lcp::new(1500, 1);
        assert!(lcp.naked(&[Opt::Mru(1480)]));
        assert_eq!(lcp.ours()[0], Opt::Mru(1480), "a lower MRU is taken");
        assert!(lcp.naked(&[Opt::Mru(9000)]));
        assert_eq!(lcp.ours()[0], Opt::Mru(1480), "a higher one is not");
        assert_eq!(
            lcp.judge(&[Opt::Mru(2000)]),
            Judgement::Nak(vec![Opt::Mru(1500)]),
            "the peer may not send us more than our port carries"
        );
        assert_eq!(
            lcp.judge(&[Opt::Mru(500)]),
            Judgement::Nak(vec![Opt::Mru(MIN_MRU)])
        );
        assert_eq!(lcp.judge(&[Opt::Mru(1400)]), Judgement::Ack);
        assert_eq!(lcp.negotiated().mru_theirs, 1400);
        // Through the automaton: a peer that insists gets five Naks, then a Reject.
        let mut fsm = Fsm::new(Lcp::new(1500, 1), 1);
        fsm.handle(Event::Open, 0);
        fsm.handle(Event::Up, 0);
        let mut codes = Vec::new();
        for id in 1..=MAX_FAILURE + 1 {
            let request = Packet {
                code: code::CONFIGURE_REQUEST,
                id: u8::try_from(id).unwrap(),
                data: Lcp::encode(&[Opt::Mru(2000)]),
            };
            let actions = fsm.handle(Event::Receive(request), u64::from(id) * 100);
            codes.extend(actions.iter().filter_map(|action| match action {
                Action::Send(packet) if packet.code != code::CONFIGURE_REQUEST => Some(packet.code),
                _ => None,
            }));
        }
        let mut expected = vec![code::CONFIGURE_NAK; MAX_FAILURE as usize];
        expected.push(code::CONFIGURE_REJECT);
        assert_eq!(codes, expected);
    }

    #[test]
    fn a_magic_equal_to_ours_is_naked_and_ours_changes() {
        let mut lcp = new_lcp();
        let ours = lcp.negotiated().magic_ours;
        let judgement = lcp.judge(&[Opt::Magic(ours)]);
        let Judgement::Nak(suggested) = judgement else {
            panic!("expected a Nak, got {judgement:?}");
        };
        assert!(matches!(suggested[..], [Opt::Magic(theirs)] if theirs != ours));
        assert_ne!(lcp.negotiated().magic_ours, ours, "ours is drawn again");
        assert_eq!(lcp.judge(&[Opt::Magic(0x1234_5678)]), Judgement::Ack);
        assert_eq!(lcp.negotiated().magic_theirs, 0x1234_5678);
    }

    #[test]
    fn pfc_acfc_callback_mrru_quality_and_unknown_options_are_rejected() {
        let mut lcp = new_lcp();
        let refused = vec![
            Opt::Pfc,
            Opt::Acfc,
            Opt::Callback(0),
            Opt::Mrru(1500),
            Opt::Quality(0xc025),
            Opt::Unknown {
                kind: 99,
                data: vec![1],
            },
        ];
        let mut request = vec![Opt::Mru(1500)];
        request.extend(refused.clone());
        assert_eq!(lcp.judge(&request), Judgement::Reject(refused));
        // A Reject of ours is survivable: the defaults stand.
        assert!(lcp.rejected(&[Opt::Mru(1492), Opt::Magic(1)]));
        assert_eq!(lcp.ours(), vec![], "nothing left to ask for");
        assert_eq!(lcp.negotiated().mru_ours, 1500, "the default MRU");
        assert_eq!(
            lcp.negotiated().magic_ours,
            0,
            "no magic: echoes carry zero"
        );
    }

    /// An option we reject whatever its value decodes whatever its shape (Quality-Protocol with
    /// LQR's reporting period, RFC 1989; a bare Callback; PFC with data), so the request is
    /// answered with a Configure-Reject echoing it rather than dropped, which would leave LCP
    /// never opening with that concentrator. MRU and Magic-Number keep their strict shapes.
    #[test]
    fn rejected_options_of_any_shape_decode_so_they_can_be_rejected() {
        let mut bytes = Vec::new();
        put_option(&mut bytes, OPT_QUALITY, &[0xc0, 0x25, 0, 0, 0, 100]);
        put_option(&mut bytes, OPT_CALLBACK, &[]);
        put_option(&mut bytes, OPT_PFC, &[1]);
        put_option(&mut bytes, OPT_MRU, &[0x05, 0xdc]);
        let opts = Lcp::decode(&bytes).expect("decodes");
        assert_eq!(opts.len(), 4);
        let mut lcp = new_lcp();
        let Judgement::Reject(rejected) = lcp.judge(&opts) else {
            panic!("expected a Reject");
        };
        assert_eq!(rejected.len(), 3);
        assert_eq!(
            Lcp::encode(&rejected),
            bytes[..bytes.len() - 4],
            "echoed as received"
        );
        let mut bad = Vec::new();
        put_option(&mut bad, OPT_MRU, &[1]);
        assert!(Lcp::decode(&bad).is_err());
        let mut bad = Vec::new();
        put_option(&mut bad, OPT_MAGIC, &[1, 2]);
        assert!(Lcp::decode(&bad).is_err());
    }

    #[test]
    fn echo_requests_carry_our_magic_and_three_misses_are_lost() {
        let mut keepalive = Keepalive::new();
        keepalive.start(0);
        assert_eq!(keepalive.next_timeout(), Some(ECHO_INTERVAL));
        let magic = 0xcafe_f00d;
        let first = keepalive.tick(ECHO_INTERVAL, magic).expect("an echo");
        assert_eq!(first.code, code::ECHO_REQUEST);
        assert_eq!(first.data, magic.to_be_bytes());
        assert!(!keepalive.lost());
        let second = keepalive.tick(2 * ECHO_INTERVAL, magic).expect("an echo");
        assert_ne!(second.id, first.id);
        let third = keepalive.tick(3 * ECHO_INTERVAL, magic).expect("an echo");
        assert!(!keepalive.lost(), "three are out, none answered yet");
        assert_eq!(keepalive.tick(4 * ECHO_INTERVAL, magic), None);
        assert!(keepalive.lost(), "the third went unanswered");
        // An answer resets the count.
        let mut keepalive = Keepalive::new();
        keepalive.start(0);
        let first = keepalive.tick(ECHO_INTERVAL, magic).unwrap();
        keepalive.tick(2 * ECHO_INTERVAL, magic);
        keepalive.reply(&Packet {
            code: code::ECHO_REPLY,
            id: first.id,
            data: vec![0, 0, 0, 0],
        });
        assert_eq!(keepalive.misses(), 0);
        let _ = third;
    }

    #[test]
    fn the_peers_echo_request_is_answered_with_our_magic_and_discards_are_dropped() {
        let mut lcp = new_lcp();
        let ours = lcp.negotiated().magic_ours;
        let request = Packet {
            code: code::ECHO_REQUEST,
            id: 7,
            data: vec![1, 2, 3, 4, 9, 9],
        };
        let replies = lcp.handle_unknown(&request);
        assert_eq!(replies.len(), 1);
        assert_eq!((replies[0].code, replies[0].id), (code::ECHO_REPLY, 7));
        assert_eq!(&replies[0].data[..4], &ours.to_be_bytes());
        assert_eq!(
            &replies[0].data[4..],
            &[9, 9],
            "the data after the magic is echoed"
        );
        let discard = Packet {
            code: code::DISCARD_REQUEST,
            id: 8,
            data: vec![],
        };
        assert!(lcp.handle_unknown(&discard).is_empty(), "discarded");
        assert!(!lcp.echo_rejected());
        let rejected_echo = Packet {
            code: code::CODE_REJECT,
            id: 1,
            data: Packet {
                code: code::ECHO_REQUEST,
                id: 1,
                data: vec![],
            }
            .encode(),
        };
        assert!(
            lcp.handle_unknown(&rejected_echo).is_empty(),
            "nothing to answer"
        );
        assert!(
            lcp.echo_rejected(),
            "the keepalive stops: the peer cannot echo"
        );
    }
}
