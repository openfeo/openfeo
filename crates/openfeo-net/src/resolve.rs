// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A stub resolver for the box's own lookups (SPEC §7.10: time server names "resolved through
//! the forwarder"): one A query to our forwarder on loopback, one answer.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use openfeo_proto_dns::wire::{
    CLASS_IN, EDNS_UDP_PAYLOAD, Edns, Header, Question, RData, Record, rcode, rtype,
};
use openfeo_proto_dns::{Message, Name};
use tokio::net::UdpSocket;

use crate::dhcp4::RECEIVE_BUFFER;

/// Our own forwarder, on loopback.
pub const LOCAL_RESOLVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
/// How long one lookup may take.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

/// The A records of `name` from `resolver`, empty when the name has none (NXDOMAIN or no A
/// records); `id` is the query id, which the answer must echo.
///
/// # Errors
///
/// When the socket fails, the resolver does not answer within [`RESOLVE_TIMEOUT`], or it
/// answers with an rcode other than NOERROR or NXDOMAIN.
pub async fn lookup_a(name: &Name, resolver: SocketAddr, id: u16) -> io::Result<Vec<Ipv4Addr>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.send_to(&a_query(name, id), resolver).await?;
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    let (len, _) = tokio::time::timeout(RESOLVE_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no answer from the resolver"))??;
    a_answers(&buf[..len], id, name)
}

/// A recursive A query for `name` with EDNS at our usual payload size.
pub(crate) fn a_query(name: &Name, id: u16) -> Vec<u8> {
    Message {
        header: Header {
            id,
            recursion_desired: true,
            ..Header::default()
        },
        questions: vec![Question {
            name: name.clone(),
            qtype: rtype::A,
            qclass: CLASS_IN,
        }],
        additionals: vec![Record {
            name: Name::root(),
            rtype: rtype::OPT,
            class: EDNS_UDP_PAYLOAD,
            ttl: 0,
            rdata: RData::Opt(Edns {
                udp_payload: EDNS_UDP_PAYLOAD,
                extended_rcode: 0,
                version: 0,
                dnssec_ok: false,
                options: Vec::new(),
            }),
        }],
        ..Message::default()
    }
    .encode()
}

/// The A records in `reply`, when it answers query `id` about `name`: empty for NXDOMAIN.
pub(crate) fn a_answers(reply: &[u8], id: u16, name: &Name) -> io::Result<Vec<Ipv4Addr>> {
    let message = Message::decode(reply)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    if message.header.id != id || !message.header.response {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not the answer to our query",
        ));
    }
    if message
        .question()
        .is_none_or(|question| question.name != *name)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "an answer about another name",
        ));
    }
    match message.header.rcode {
        rcode::NOERROR => Ok(message
            .answers
            .iter()
            .filter_map(|record| match record.rdata {
                RData::A(addr) => Some(addr),
                _ => None,
            })
            .collect()),
        rcode::NXDOMAIN => Ok(Vec::new()),
        other => Err(io::Error::other(format!(
            "the resolver answered rcode {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    #[test]
    fn an_a_query_is_built_and_its_answers_read_back() {
        let name: Name = "0.pool.ntp.org".parse().unwrap();
        let query = Message::decode(&a_query(&name, 0x1234)).unwrap();
        assert_eq!(
            (
                query.header.id,
                query.header.recursion_desired,
                query.questions[0].qtype
            ),
            (0x1234, true, rtype::A)
        );
        assert_eq!(query.max_udp_payload(), usize::from(EDNS_UDP_PAYLOAD));
        let mut reply = Message::reply_to(&query, rcode::NOERROR);
        reply.answers.push(Record {
            name: name.clone(),
            rtype: rtype::A,
            class: CLASS_IN,
            ttl: 60,
            rdata: RData::A(ip("203.0.113.1")),
        });
        reply.answers.push(Record {
            name: name.clone(),
            rtype: rtype::A,
            class: CLASS_IN,
            ttl: 60,
            rdata: RData::A(ip("203.0.113.2")),
        });
        assert_eq!(
            a_answers(&reply.encode(), 0x1234, &name).unwrap(),
            vec![ip("203.0.113.1"), ip("203.0.113.2")]
        );
        assert!(
            a_answers(&reply.encode(), 0x4321, &name).is_err(),
            "another id"
        );
        let servfail = Message::reply_to(&query, rcode::SERVFAIL);
        assert!(a_answers(&servfail.encode(), 0x1234, &name).is_err());
        assert_eq!(
            a_answers(
                &Message::reply_to(&query, rcode::NXDOMAIN).encode(),
                0x1234,
                &name
            )
            .unwrap(),
            Vec::<Ipv4Addr>::new(),
            "no such name: nothing, not an error"
        );
    }
}
