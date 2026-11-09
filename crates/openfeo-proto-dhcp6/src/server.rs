// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The stateless DHCPv6 responder (RFC 8415 §18.3.6; SPEC §7.3): an Information-Request from
//! a host that ignores RDNSS is answered with the resolvers, the domain list and a refresh
//! time. Nothing is assigned and nothing is remembered, so every other message type is left
//! unanswered: the advertisement said M = 0, and RFC 8415 §18.3 lets a server with nothing to
//! give stay silent.

use std::net::Ipv6Addr;

use crate::wire::{Dhcp6Option, Message, MessageType};

/// The Information Refresh Time handed out (RFC 8415 §21.23's default).
pub const INFORMATION_REFRESH_TIME: u32 = 86_400;

/// What one LAN's responder says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The router's DUID, the Server Identifier.
    pub duid: Vec<u8>,
    /// The resolvers: the router's addresses in that LAN.
    pub dns: Vec<Ipv6Addr>,
    /// The domain list: the system domain.
    pub domains: Vec<String>,
    /// Seconds before the host asks again.
    pub refresh_secs: u32,
}

/// The Reply to `request` when it is an Information-Request for this server from a link-local
/// source, else `None`:
/// the Server Identifier, the Client Identifier echoed when the host sent one, the resolvers,
/// the domain list and the refresh time, under the request's transaction id.
#[must_use]
pub fn reply(config: &Config, from: Ipv6Addr, request: &[u8]) -> Option<Vec<u8>> {
    // SPEC §7.3: a link-local source only; a host on the LAN asks from nothing else (#42).
    if !from.is_unicast_link_local() {
        return None;
    }
    let request = Message::decode(request).ok()?;
    if request.kind != MessageType::InformationRequest {
        return None;
    }
    if request
        .server_id()
        .is_some_and(|server| server != config.duid.as_slice())
    {
        return None;
    }
    let mut answer = Message::new(MessageType::Reply, request.xid);
    answer
        .options
        .push(Dhcp6Option::ServerId(config.duid.clone()));
    if let Some(client) = request.client_id() {
        answer.options.push(Dhcp6Option::ClientId(client.to_vec()));
    }
    if !config.dns.is_empty() {
        answer
            .options
            .push(Dhcp6Option::DnsServers(config.dns.clone()));
    }
    if !config.domains.is_empty() {
        answer
            .options
            .push(Dhcp6Option::DomainList(config.domains.clone()));
    }
    answer
        .options
        .push(Dhcp6Option::InformationRefreshTime(config.refresh_secs));
    Some(answer.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUID: [u8; 10] = [0, 3, 0, 1, 0x52, 0x54, 0, 0xfe, 0, 2];
    const HOST: [u8; 10] = [0, 3, 0, 1, 0x52, 0x54, 0, 0xfe, 0, 0x10];
    /// The host's link-local source.
    const LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x10);

    fn config() -> Config {
        Config {
            duid: DUID.to_vec(),
            dns: vec!["fd12:3456:789a:1::1".parse().unwrap()],
            domains: vec!["home.arpa".to_owned()],
            refresh_secs: INFORMATION_REFRESH_TIME,
        }
    }

    fn information_request(xid: u32, client: Option<&[u8]>, server: Option<&[u8]>) -> Vec<u8> {
        let mut message = Message::new(MessageType::InformationRequest, xid);
        if let Some(client) = client {
            message.options.push(Dhcp6Option::ClientId(client.to_vec()));
        }
        if let Some(server) = server {
            message.options.push(Dhcp6Option::ServerId(server.to_vec()));
        }
        message.options.push(Dhcp6Option::Oro(vec![23, 24]));
        message.options.push(Dhcp6Option::ElapsedTime(0));
        message.encode()
    }

    #[test]
    fn an_information_request_gets_dns_domain_and_refresh_time() {
        let bytes = reply(
            &config(),
            LL,
            &information_request(0x00ab_cdef, Some(&HOST), None),
        )
        .unwrap();
        let answer = Message::decode(&bytes).unwrap();
        assert_eq!(answer.kind, MessageType::Reply);
        assert_eq!(
            answer.options,
            vec![
                Dhcp6Option::ServerId(DUID.to_vec()),
                Dhcp6Option::ClientId(HOST.to_vec()),
                Dhcp6Option::DnsServers(vec!["fd12:3456:789a:1::1".parse().unwrap()]),
                Dhcp6Option::DomainList(vec!["home.arpa".to_owned()]),
                Dhcp6Option::InformationRefreshTime(86_400),
            ]
        );
    }

    #[test]
    fn the_reply_keeps_the_xid() {
        let bytes = reply(&config(), LL, &information_request(0x0012_3456, None, None)).unwrap();
        let answer = Message::decode(&bytes).unwrap();
        assert_eq!(answer.xid, 0x0012_3456);
        assert_eq!(answer.client_id(), None, "nothing to echo");
    }

    #[test]
    fn a_request_naming_this_server_is_answered_and_another_server_is_not() {
        assert!(
            reply(
                &config(),
                LL,
                &information_request(1, Some(&HOST), Some(&DUID))
            )
            .is_some()
        );
        assert_eq!(
            reply(
                &config(),
                LL,
                &information_request(1, Some(&HOST), Some(&HOST))
            ),
            None
        );
    }

    /// SPEC §7.3: an Information-Request is answered from a link-local source only (#42).
    #[test]
    fn a_request_from_a_global_source_is_ignored() {
        let request = information_request(7, Some(&HOST), None);
        assert!(reply(&config(), "fe80::5".parse().unwrap(), &request).is_some());
        assert!(reply(&config(), "2001:db8::5".parse().unwrap(), &request).is_none());
        assert!(reply(&config(), "fd12:3456:789a:1::5".parse().unwrap(), &request).is_none());
    }

    #[test]
    fn a_solicit_is_ignored() {
        for kind in [
            MessageType::Solicit,
            MessageType::Request,
            MessageType::Renew,
            MessageType::Rebind,
            MessageType::Confirm,
            MessageType::Release,
            MessageType::Decline,
            MessageType::Reply,
        ] {
            let mut message = Message::new(kind, 7);
            message.options.push(Dhcp6Option::ClientId(HOST.to_vec()));
            assert_eq!(reply(&config(), LL, &message.encode()), None, "{kind:?}");
        }
    }

    #[test]
    fn garbage_is_ignored() {
        assert_eq!(reply(&config(), LL, &[]), None);
        assert_eq!(reply(&config(), LL, &[11, 0, 0]), None);
        assert_eq!(reply(&config(), LL, &[11, 0, 0, 1, 0, 1, 0, 9]), None);
    }

    #[test]
    fn empty_lists_send_no_option() {
        let config = Config {
            dns: Vec::new(),
            domains: Vec::new(),
            ..config()
        };
        let bytes = reply(&config, LL, &information_request(1, None, None)).unwrap();
        let answer = Message::decode(&bytes).unwrap();
        assert_eq!(
            answer.options,
            vec![
                Dhcp6Option::ServerId(DUID.to_vec()),
                Dhcp6Option::InformationRefreshTime(86_400),
            ]
        );
    }
}
