// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The IPv6 Control Protocol (RFC 5072): one option, the interface identifier each end uses
//! for its link-local address on the link. Ours is derived from the stable-privacy secret and
//! the WAN's name, so the router's link-local address on the PPP link is stable (RFC 7217
//! style); a conflict with the peer's, or a Nak, is answered by the next derivation.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use openfeo_proto_ndp::iid::stable_address;

use crate::frame::{Error, options, put_option};
use crate::fsm::{Judgement, Options};

const OPT_INTERFACE_ID: u8 = 1;
/// The link-local prefix the identifiers are derived under.
const LINK_LOCAL: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 64);

/// IPV6CP options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opt {
    InterfaceId(u64),
    Unknown { kind: u8, data: Vec<u8> },
}

/// What IPV6CP settled once both sides acked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Up {
    pub local_iid: u64,
    pub peer_iid: u64,
}

/// Our side of IPV6CP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6cp {
    secret: [u8; 16],
    wan: String,
    /// The derivation counter behind our identifier: bumped past a conflict.
    counter: u8,
    ours: Option<u64>,
    peer: Option<u64>,
    acked: bool,
}

impl Ipv6cp {
    /// IPV6CP with an identifier derived from `secret` and the WAN's name.
    #[must_use]
    pub fn new(secret: &[u8; 16], wan: &str) -> Ipv6cp {
        let mut ipv6cp = Ipv6cp {
            secret: *secret,
            wan: wan.to_owned(),
            counter: 0,
            ours: None,
            peer: None,
            acked: false,
        };
        ipv6cp.ours = Some(ipv6cp.derive("ipv6cp", ipv6cp.counter));
        ipv6cp
    }

    /// The automaton reached Opened: our request was acked.
    pub fn acked(&mut self) {
        self.acked = true;
    }

    /// Both identifiers, once the layer is up.
    #[must_use]
    pub fn result(&self) -> Option<Ipv6Up> {
        match (self.acked, self.ours, self.peer) {
            (true, Some(local_iid), Some(peer_iid)) => Some(Ipv6Up {
                local_iid,
                peer_iid,
            }),
            _ => None,
        }
    }

    /// What we offer a peer whose identifier is zero or ours.
    #[must_use]
    pub fn suggestion_for_peer(&self) -> u64 {
        self.derive("ipv6cp-peer", self.counter)
    }

    /// RFC 7217's function over the link-local prefix, `label:wan` and the secret, never zero.
    fn derive(&self, label: &str, counter: u8) -> u64 {
        let name = format!("{label}:{}", self.wan);
        let mut counter = counter;
        loop {
            let address = stable_address(LINK_LOCAL, &name, &self.secret, counter);
            let iid = u64::try_from(u128::from(address) & u128::from(u64::MAX)).unwrap_or(1);
            if iid != 0 {
                return iid;
            }
            counter = counter.wrapping_add(1);
        }
    }
}

impl Options for Ipv6cp {
    type Opt = Opt;

    fn decode(data: &[u8]) -> Result<Vec<Opt>, Error> {
        options(data)?
            .into_iter()
            .map(|(kind, data)| {
                Ok(match kind {
                    OPT_INTERFACE_ID => {
                        let bytes: [u8; 8] = data.try_into().map_err(|_| Error::Option { kind })?;
                        Opt::InterfaceId(u64::from_be_bytes(bytes))
                    }
                    kind => Opt::Unknown {
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
                Opt::InterfaceId(id) => put_option(&mut out, OPT_INTERFACE_ID, &id.to_be_bytes()),
                Opt::Unknown { kind, data } => put_option(&mut out, *kind, data),
            }
        }
        out
    }

    fn ours(&self) -> Vec<Opt> {
        self.ours.map(Opt::InterfaceId).into_iter().collect()
    }

    fn judge(&mut self, theirs: &[Opt]) -> Judgement<Opt> {
        let mut rejects = Vec::new();
        let mut naks = Vec::new();
        let mut peer = self.peer;
        for opt in theirs {
            match opt {
                Opt::InterfaceId(0) => naks.push(Opt::InterfaceId(self.suggestion_for_peer())),
                Opt::InterfaceId(id) if Some(*id) == self.ours => {
                    // The same identifier at both ends: ours moves on, the peer is offered
                    // another (RFC 5072 §4.1).
                    self.counter = self.counter.wrapping_add(1);
                    self.ours = Some(self.derive("ipv6cp", self.counter));
                    naks.push(Opt::InterfaceId(self.suggestion_for_peer()));
                }
                Opt::InterfaceId(id) => peer = Some(*id),
                Opt::Unknown { .. } => rejects.push(opt.clone()),
            }
        }
        if !rejects.is_empty() {
            Judgement::Reject(rejects)
        } else if !naks.is_empty() {
            Judgement::Nak(naks)
        } else {
            self.peer = peer;
            Judgement::Ack
        }
    }

    fn naked(&mut self, suggested: &[Opt]) -> bool {
        for opt in suggested {
            match opt {
                Opt::InterfaceId(0) => return false,
                Opt::InterfaceId(id) => self.ours = Some(*id),
                Opt::Unknown { .. } => {}
            }
        }
        true
    }

    fn rejected(&mut self, opts: &[Opt]) -> bool {
        !opts.iter().any(|opt| matches!(opt, Opt::InterfaceId(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::{Judgement, Options};

    const SECRET: [u8; 16] = [7; 16];

    #[test]
    fn options_round_trip_and_bad_lengths_are_errors() {
        let all = vec![
            Opt::InterfaceId(0x0200_5eff_fe00_5301),
            Opt::Unknown {
                kind: 2,
                data: vec![0, 0x4f],
            },
        ];
        assert_eq!(Ipv6cp::decode(&Ipv6cp::encode(&all)).unwrap(), all);
        assert_eq!(
            Ipv6cp::encode(&[Opt::InterfaceId(1)]),
            vec![1, 10, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert!(
            Ipv6cp::decode(&[1, 6, 0, 0, 0, 1]).is_err(),
            "an identifier is eight bytes"
        );
    }

    #[test]
    fn ipv6cp_identifier_is_stable_for_a_secret_and_wan_and_never_zero() {
        let a = Ipv6cp::new(&SECRET, "wan0");
        let b = Ipv6cp::new(&SECRET, "wan0");
        assert_eq!(a.ours(), b.ours());
        let Opt::InterfaceId(id) = a.ours()[0] else {
            panic!("an identifier");
        };
        assert_ne!(id, 0);
        assert_ne!(Ipv6cp::new(&SECRET, "wan1").ours(), a.ours(), "per WAN");
        assert_ne!(Ipv6cp::new(&[8; 16], "wan0").ours(), a.ours(), "per secret");
        assert_eq!(a.result(), None);
    }

    #[test]
    fn an_identifier_equal_to_the_peers_is_rederived_and_the_peers_zero_is_naked() {
        let mut ipv6cp = Ipv6cp::new(&SECRET, "wan0");
        let Opt::InterfaceId(ours) = ipv6cp.ours()[0] else {
            panic!("an identifier");
        };
        let judgement = ipv6cp.judge(&[Opt::InterfaceId(ours)]);
        assert_eq!(
            judgement,
            Judgement::Nak(vec![Opt::InterfaceId(ipv6cp.suggestion_for_peer())]),
            "the peer is offered another"
        );
        assert_ne!(
            ipv6cp.ours()[0],
            Opt::InterfaceId(ours),
            "and ours moved too"
        );
        assert!(matches!(
            ipv6cp.judge(&[Opt::InterfaceId(0)]),
            Judgement::Nak(_)
        ));
        assert_eq!(ipv6cp.judge(&[Opt::InterfaceId(0x1234)]), Judgement::Ack);
        assert_eq!(
            ipv6cp.judge(&[Opt::Unknown {
                kind: 2,
                data: vec![]
            }]),
            Judgement::Reject(vec![Opt::Unknown {
                kind: 2,
                data: vec![]
            }])
        );
    }

    #[test]
    fn a_naked_identifier_is_taken_and_both_acks_give_the_result() {
        let mut ipv6cp = Ipv6cp::new(&SECRET, "wan0");
        assert!(ipv6cp.naked(&[Opt::InterfaceId(0xfeed)]));
        assert_eq!(ipv6cp.ours(), vec![Opt::InterfaceId(0xfeed)]);
        assert!(
            !ipv6cp.naked(&[Opt::InterfaceId(0)]),
            "zero is no identifier"
        );
        assert_eq!(ipv6cp.judge(&[Opt::InterfaceId(0x1234)]), Judgement::Ack);
        ipv6cp.acked();
        assert_eq!(
            ipv6cp.result(),
            Some(Ipv6Up {
                local_iid: 0xfeed,
                peer_iid: 0x1234
            })
        );
        let mut ipv6cp = Ipv6cp::new(&SECRET, "wan0");
        assert!(
            !ipv6cp.rejected(&[Opt::InterfaceId(1)]),
            "without an identifier there is no IPv6 on the link"
        );
    }
}
