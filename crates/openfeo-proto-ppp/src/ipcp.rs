// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The IP Control Protocol (RFC 1332 §3, RFC 1877): we ask for an address and the two
//! resolvers with zeros and take what the peer's Nak fills in; the peer's own address comes
//! from its request; header compression is refused.

use std::net::Ipv4Addr;

use crate::frame::{Error, options, put_option};
use crate::fsm::{Judgement, Options};

const OPT_COMPRESSION: u8 = 2;
const OPT_ADDRESS: u8 = 3;
const OPT_PRIMARY_DNS: u8 = 129;
const OPT_SECONDARY_DNS: u8 = 131;
/// Naks that still leave us with 0.0.0.0 before we conclude the peer will never number us.
const MAX_ZERO_NAKS: u32 = 5;

/// IPCP options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opt {
    Address(Ipv4Addr),
    PrimaryDns(Ipv4Addr),
    SecondaryDns(Ipv4Addr),
    /// IP-Compression-Protocol, with its data: refused.
    Compression(Vec<u8>),
    Unknown {
        kind: u8,
        data: Vec<u8>,
    },
}

/// What IPCP settled once both sides acked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Up {
    pub local: Ipv4Addr,
    /// The peer's address from its own request; `None` for an unnumbered peer.
    pub peer: Option<Ipv4Addr>,
    /// Primary then secondary resolver, the ones the peer named.
    pub dns: Vec<Ipv4Addr>,
}

/// Our side of IPCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipcp {
    /// What we ask for: 0.0.0.0 until naked, `None` once rejected.
    address: Option<Ipv4Addr>,
    primary: Option<Ipv4Addr>,
    secondary: Option<Ipv4Addr>,
    peer: Option<Ipv4Addr>,
    zero_naks: u32,
    acked: bool,
}

impl Default for Ipcp {
    fn default() -> Self {
        Self::new()
    }
}

impl Ipcp {
    /// IPCP asking for an address and two resolvers.
    #[must_use]
    pub fn new() -> Ipcp {
        Ipcp {
            address: Some(Ipv4Addr::UNSPECIFIED),
            primary: Some(Ipv4Addr::UNSPECIFIED),
            secondary: Some(Ipv4Addr::UNSPECIFIED),
            peer: None,
            zero_naks: 0,
            acked: false,
        }
    }

    /// The automaton reached Opened: our request was acked.
    pub fn acked(&mut self) {
        self.acked = true;
    }

    /// The addresses, once the layer is up with an address for us.
    #[must_use]
    pub fn result(&self) -> Option<Ipv4Up> {
        let local = self.address.filter(|a| !a.is_unspecified())?;
        let mut dns: Vec<Ipv4Addr> = [self.primary, self.secondary]
            .into_iter()
            .flatten()
            .filter(|dns| !dns.is_unspecified())
            .collect();
        // One resolver named twice (pppd with one `ms-dns`, many concentrators) is one resolver.
        dns.dedup();
        self.acked.then_some(Ipv4Up {
            local,
            peer: self.peer,
            dns,
        })
    }
}

fn address(data: &[u8], kind: u8) -> Result<Ipv4Addr, Error> {
    match data {
        [a, b, c, d] => Ok(Ipv4Addr::new(*a, *b, *c, *d)),
        _ => Err(Error::Option { kind }),
    }
}

impl Options for Ipcp {
    type Opt = Opt;

    fn decode(data: &[u8]) -> Result<Vec<Opt>, Error> {
        options(data)?
            .into_iter()
            .map(|(kind, data)| {
                Ok(match kind {
                    OPT_ADDRESS => Opt::Address(address(data, kind)?),
                    OPT_PRIMARY_DNS => Opt::PrimaryDns(address(data, kind)?),
                    OPT_SECONDARY_DNS => Opt::SecondaryDns(address(data, kind)?),
                    OPT_COMPRESSION => Opt::Compression(data.to_vec()),
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
                Opt::Address(a) => put_option(&mut out, OPT_ADDRESS, &a.octets()),
                Opt::PrimaryDns(a) => put_option(&mut out, OPT_PRIMARY_DNS, &a.octets()),
                Opt::SecondaryDns(a) => put_option(&mut out, OPT_SECONDARY_DNS, &a.octets()),
                Opt::Compression(data) => put_option(&mut out, OPT_COMPRESSION, data),
                Opt::Unknown { kind, data } => put_option(&mut out, *kind, data),
            }
        }
        out
    }

    fn ours(&self) -> Vec<Opt> {
        let mut ours = Vec::new();
        ours.extend(self.address.map(Opt::Address));
        ours.extend(self.primary.map(Opt::PrimaryDns));
        ours.extend(self.secondary.map(Opt::SecondaryDns));
        ours
    }

    fn judge(&mut self, theirs: &[Opt]) -> Judgement<Opt> {
        let mut rejects = Vec::new();
        let mut peer = self.peer;
        for opt in theirs {
            match opt {
                // We have no address to give an unnumbered peer: it must come numbered.
                Opt::Address(a) if a.is_unspecified() => rejects.push(opt.clone()),
                Opt::Address(a) => peer = Some(*a),
                // Resolvers asked of us (we have none to give), compression, the unknown.
                Opt::PrimaryDns(_)
                | Opt::SecondaryDns(_)
                | Opt::Compression(_)
                | Opt::Unknown { .. } => rejects.push(opt.clone()),
            }
        }
        if rejects.is_empty() {
            self.peer = peer;
            Judgement::Ack
        } else {
            Judgement::Reject(rejects)
        }
    }

    fn naked(&mut self, suggested: &[Opt]) -> bool {
        for opt in suggested {
            match opt {
                Opt::Address(a) if a.is_unspecified() => {
                    self.zero_naks += 1;
                    if self.zero_naks >= MAX_ZERO_NAKS {
                        return false;
                    }
                }
                Opt::Address(a) => self.address = Some(*a),
                Opt::PrimaryDns(a) => self.primary = (!a.is_unspecified()).then_some(*a),
                Opt::SecondaryDns(a) => self.secondary = (!a.is_unspecified()).then_some(*a),
                Opt::Compression(_) | Opt::Unknown { .. } => {}
            }
        }
        true
    }

    fn rejected(&mut self, opts: &[Opt]) -> bool {
        for opt in opts {
            match opt {
                Opt::Address(_) => return false,
                Opt::PrimaryDns(_) => self.primary = None,
                Opt::SecondaryDns(_) => self.secondary = None,
                Opt::Compression(_) | Opt::Unknown { .. } => {}
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::{Judgement, Options};
    use std::net::Ipv4Addr;

    const ISP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const OURS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 100);

    #[test]
    fn options_round_trip_and_bad_lengths_are_errors() {
        let all = vec![
            Opt::Address(OURS),
            Opt::PrimaryDns(ISP),
            Opt::SecondaryDns(Ipv4Addr::new(203, 0, 113, 2)),
            Opt::Compression(vec![0, 0x2d, 15, 1]),
            Opt::Unknown {
                kind: 99,
                data: vec![1],
            },
        ];
        assert_eq!(Ipcp::decode(&Ipcp::encode(&all)).unwrap(), all);
        assert_eq!(
            Ipcp::encode(&[Opt::Address(OURS)]),
            vec![3, 6, 203, 0, 113, 100]
        );
        assert!(
            Ipcp::decode(&[3, 5, 1, 2, 3]).is_err(),
            "an address is four bytes"
        );
        assert!(Ipcp::decode(&[129, 3, 1]).is_err());
    }

    /// pppd with one `ms-dns` (and many concentrators) names the same resolver as primary and
    /// secondary: it is one resolver, reported once, or the forwarder asks it twice.
    #[test]
    fn the_same_resolver_twice_is_reported_once() {
        let mut ipcp = Ipcp::new();
        assert!(ipcp.naked(&[
            Opt::Address(OURS),
            Opt::PrimaryDns(ISP),
            Opt::SecondaryDns(ISP),
        ]));
        ipcp.acked();
        assert_eq!(ipcp.result().map(|up| up.dns), Some(vec![ISP]));
    }

    #[test]
    fn ipcp_requests_zero_address_and_dns_and_takes_the_nak() {
        let mut ipcp = Ipcp::new();
        assert_eq!(
            ipcp.ours(),
            vec![
                Opt::Address(Ipv4Addr::UNSPECIFIED),
                Opt::PrimaryDns(Ipv4Addr::UNSPECIFIED),
                Opt::SecondaryDns(Ipv4Addr::UNSPECIFIED),
            ]
        );
        assert!(ipcp.naked(&[
            Opt::Address(OURS),
            Opt::PrimaryDns(ISP),
            Opt::SecondaryDns(Ipv4Addr::new(203, 0, 113, 2)),
        ]));
        assert_eq!(ipcp.ours()[0], Opt::Address(OURS));
        assert_eq!(ipcp.result(), None, "not up until both sides acked");
        ipcp.acked();
        assert_eq!(
            ipcp.result(),
            Some(Ipv4Up {
                local: OURS,
                peer: None,
                dns: vec![ISP, Ipv4Addr::new(203, 0, 113, 2)],
            })
        );
    }

    #[test]
    fn ipcp_accepts_the_peers_address_and_rejects_compression() {
        let mut ipcp = Ipcp::new();
        assert_eq!(
            ipcp.judge(&[
                Opt::Address(ISP),
                Opt::Compression(vec![0, 0x2d, 15, 1]),
                Opt::Unknown {
                    kind: 99,
                    data: vec![]
                }
            ]),
            Judgement::Reject(vec![
                Opt::Compression(vec![0, 0x2d, 15, 1]),
                Opt::Unknown {
                    kind: 99,
                    data: vec![]
                }
            ])
        );
        assert_eq!(ipcp.judge(&[Opt::Address(ISP)]), Judgement::Ack);
        assert!(ipcp.naked(&[Opt::Address(OURS)]));
        ipcp.acked();
        assert_eq!(ipcp.result().map(|up| up.peer), Some(Some(ISP)));
        // A peer that asks for 0.0.0.0 is told we cannot number it.
        let mut ipcp = Ipcp::new();
        assert_eq!(
            ipcp.judge(&[Opt::Address(Ipv4Addr::UNSPECIFIED)]),
            Judgement::Reject(vec![Opt::Address(Ipv4Addr::UNSPECIFIED)])
        );
    }

    #[test]
    fn ipcp_without_a_peer_address_is_unnumbered_and_dns_rejects_are_survivable() {
        let mut ipcp = Ipcp::new();
        assert_eq!(ipcp.judge(&[]), Judgement::Ack, "an empty request is fine");
        assert!(ipcp.rejected(&[
            Opt::PrimaryDns(Ipv4Addr::UNSPECIFIED),
            Opt::SecondaryDns(Ipv4Addr::UNSPECIFIED)
        ]));
        assert_eq!(ipcp.ours(), vec![Opt::Address(Ipv4Addr::UNSPECIFIED)]);
        assert!(ipcp.naked(&[Opt::Address(OURS)]));
        ipcp.acked();
        assert_eq!(
            ipcp.result(),
            Some(Ipv4Up {
                local: OURS,
                peer: None,
                dns: vec![],
            })
        );
        let mut ipcp = Ipcp::new();
        assert!(
            !ipcp.rejected(&[Opt::Address(Ipv4Addr::UNSPECIFIED)]),
            "no address, no IPv4"
        );
    }

    #[test]
    fn five_zero_naks_give_up() {
        let mut ipcp = Ipcp::new();
        for _ in 0..4 {
            assert!(ipcp.naked(&[Opt::Address(Ipv4Addr::UNSPECIFIED)]));
        }
        assert!(
            !ipcp.naked(&[Opt::Address(Ipv4Addr::UNSPECIFIED)]),
            "a peer that never numbers us"
        );
        let mut ipcp = Ipcp::new();
        for _ in 0..4 {
            assert!(ipcp.naked(&[Opt::Address(Ipv4Addr::UNSPECIFIED)]));
        }
        assert!(ipcp.naked(&[Opt::Address(OURS)]), "an address at last");
    }
}
