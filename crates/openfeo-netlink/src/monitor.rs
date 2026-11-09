// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The rtnetlink connection and the monitor that keeps the cache current: subscribed to the
//! link, address and route multicast groups before the initial dumps, so nothing that changes
//! during the dump is missed, then applying every notification to the cache and publishing a new
//! `Arc<Cache>` on a `watch` channel.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use futures::StreamExt as _;
use futures::TryStreamExt as _;
use futures::channel::mpsc::UnboundedReceiver;
use ipnet::IpNet;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{
    InfoData, InfoKind, InfoVlan, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteType};
use netlink_packet_route::rule::{RuleAction as NlRuleAction, RuleAttribute, RuleMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{Handle, IpVersion, MulticastGroup, RouteMessageBuilder};
use tokio::sync::watch;
use tracing::debug;

use crate::types::{Addr, Cache, Link, LinkKind, Route, RouteKind, Rule, RuleAction};

/// Errors from the connection and from requests.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Opening the netlink socket.
    #[error("netlink socket: {0}")]
    Socket(#[from] std::io::Error),
    /// A request the kernel refused or that could not be sent.
    #[error("{op}: {source}")]
    Request {
        /// What was attempted, e.g. `add bridge br-lan0`.
        op: String,
        /// The rtnetlink error (carries the errno for `EEXIST` and friends).
        #[source]
        source: rtnetlink::Error,
    },
    /// The notification stream ended: the connection task is gone.
    #[error("netlink connection closed")]
    Closed,
}

/// Wrap an rtnetlink failure with what was being done.
pub(crate) fn request_error(op: impl Into<String>, source: rtnetlink::Error) -> Error {
    Error::Request {
        op: op.into(),
        source,
    }
}

/// The request connection the apply primitives use. Cheap to clone. Deliberately not the
/// monitor's socket (ADR-0011).
#[derive(Debug, Clone)]
pub struct Netlink {
    pub(crate) handle: Handle,
}

/// Owns the notification stream and the cache; `run` it as a task.
#[derive(Debug)]
pub struct Monitor {
    notifications:
        UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, netlink_sys::SocketAddr)>,
    tx: watch::Sender<Arc<Cache>>,
    cache: Cache,
}

impl Netlink {
    /// Open two connections: one subscribed to link, address and route notifications, which
    /// fills the cache from the initial dumps and keeps it current, and one for requests. They
    /// must be different sockets: the kernel does not multicast address and route changes back
    /// to the socket that requested them (ADR-0011), so one socket would never see its own
    /// applies land in the cache. The returned [`Monitor`] must be driven with [`Monitor::run`].
    ///
    /// # Errors
    ///
    /// When a socket cannot be opened or a dump fails.
    pub async fn connect() -> Result<(Netlink, Monitor), Error> {
        let (monitor_connection, monitor_handle, notifications) =
            rtnetlink::new_multicast_connection(&[
                MulticastGroup::Link,
                MulticastGroup::Ipv4Ifaddr,
                MulticastGroup::Ipv6Ifaddr,
                MulticastGroup::Ipv4Route,
                MulticastGroup::Ipv6Route,
                MulticastGroup::Ipv4Rule,
                MulticastGroup::Ipv6Rule,
            ])?;
        tokio::spawn(monitor_connection);
        let (request_connection, request_handle, _unsolicited) = rtnetlink::new_connection()?;
        tokio::spawn(request_connection);

        let mut cache = Cache::default();
        let mut links = monitor_handle.link().get().execute();
        while let Some(msg) = links
            .try_next()
            .await
            .map_err(|e| request_error("dump links", e))?
        {
            apply_link(&mut cache, &msg, true);
        }
        let mut addrs = monitor_handle.address().get().execute();
        while let Some(msg) = addrs
            .try_next()
            .await
            .map_err(|e| request_error("dump addresses", e))?
        {
            apply_addr(&mut cache, &msg, true);
        }
        let mut routes4 = monitor_handle
            .route()
            .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
            .execute();
        while let Some(msg) = routes4
            .try_next()
            .await
            .map_err(|e| request_error("dump IPv4 routes", e))?
        {
            apply_route(&mut cache, &msg, true);
        }
        let mut routes6 = monitor_handle
            .route()
            .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
            .execute();
        while let Some(msg) = routes6
            .try_next()
            .await
            .map_err(|e| request_error("dump IPv6 routes", e))?
        {
            apply_route(&mut cache, &msg, true);
        }
        for version in [IpVersion::V4, IpVersion::V6] {
            let mut rules = monitor_handle.rule().get(version).execute();
            while let Some(msg) = rules
                .try_next()
                .await
                .map_err(|e| request_error("dump rules", e))?
            {
                apply_rule(&mut cache, &msg, true);
            }
        }
        debug!(
            "netlink: initial dump: {} links, {} addresses, {} routes, {} rules",
            cache.links.len(),
            cache.addrs.len(),
            cache.routes.len(),
            cache.rules.len()
        );

        let (tx, _rx) = watch::channel(Arc::new(cache.clone()));
        Ok((
            Netlink {
                handle: request_handle,
            },
            Monitor {
                notifications,
                tx,
                cache,
            },
        ))
    }
}

impl Monitor {
    /// A receiver of cache snapshots, starting at the current one.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Arc<Cache>> {
        self.tx.subscribe()
    }

    /// Apply notifications until the connection goes away.
    ///
    /// # Errors
    ///
    /// [`Error::Closed`] when the notification stream ends.
    pub async fn run(mut self) -> Result<(), Error> {
        while let Some((message, _from)) = self.notifications.next().await {
            if let NetlinkPayload::InnerMessage(inner) = message.payload
                && apply(&mut self.cache, &inner)
            {
                self.tx.send_replace(Arc::new(self.cache.clone()));
            }
        }
        Err(Error::Closed)
    }
}

/// Apply one notification; `true` when the cache changed.
fn apply(cache: &mut Cache, msg: &RouteNetlinkMessage) -> bool {
    match msg {
        RouteNetlinkMessage::NewLink(m) => apply_link(cache, m, true),
        RouteNetlinkMessage::DelLink(m) => apply_link(cache, m, false),
        RouteNetlinkMessage::NewAddress(m) => apply_addr(cache, m, true),
        RouteNetlinkMessage::DelAddress(m) => apply_addr(cache, m, false),
        RouteNetlinkMessage::NewRoute(m) => apply_route(cache, m, true),
        RouteNetlinkMessage::DelRoute(m) => apply_route(cache, m, false),
        RouteNetlinkMessage::NewRule(m) => apply_rule(cache, m, true),
        RouteNetlinkMessage::DelRule(m) => apply_rule(cache, m, false),
        _ => false,
    }
}

fn apply_link(cache: &mut Cache, msg: &LinkMessage, present: bool) -> bool {
    // AF_BRIDGE notifications describe bridge port state (STP, VLANs) and would clobber the
    // AF_UNSPEC view of the same link; master changes arrive as AF_UNSPEC messages anyway.
    if msg.header.interface_family == AddressFamily::Bridge {
        return false;
    }
    let link = link_from(msg);
    if present {
        cache.links.insert(link.index, link.clone()) != Some(link)
    } else {
        cache.links.remove(&link.index).is_some()
    }
}

/// An address is its interface, its net and its peer: a message that only refreshes the
/// lifetimes replaces the entry, and a deletion matches whatever numbers it carries (#27).
fn apply_addr(cache: &mut Cache, msg: &AddressMessage, present: bool) -> bool {
    let Some(addr) = addr_from(msg) else {
        return false;
    };
    let before = cache.addrs.len();
    cache
        .addrs
        .retain(|a| !(a.ifindex == addr.ifindex && a.net == addr.net && a.peer == addr.peer));
    let removed = cache.addrs.len() != before;
    if present {
        cache.addrs.insert(addr);
        true
    } else {
        removed
    }
}

fn apply_route(cache: &mut Cache, msg: &RouteMessage, present: bool) -> bool {
    let Some(route) = route_from(msg) else {
        return false;
    };
    if present {
        // A re-announcement of a route may carry fields its predecessor lacked (the preferred
        // source): one entry per route identity.
        cache.remove_route(&route);
        cache.routes.insert(route)
    } else {
        cache.remove_route(&route)
    }
}

fn apply_rule(cache: &mut Cache, msg: &RuleMessage, present: bool) -> bool {
    let Some(rule) = rule_from(msg) else {
        return false;
    };
    if present {
        cache.rules.insert(rule)
    } else {
        cache.rules.remove(&rule)
    }
}

/// A rule in the shape the applier compares; `None` for a family or an action this crate does
/// not model (the kernel's `blackhole` and `prohibit` rules, `goto`, `nop`).
fn rule_from(msg: &RuleMessage) -> Option<Rule> {
    let v6 = match msg.header.family {
        AddressFamily::Inet => false,
        AddressFamily::Inet6 => true,
        _ => return None,
    };
    let mut table = u32::from(msg.header.table);
    let mut src_addr = None;
    let mut priority = 0;
    let mut suppress_prefixlen = None;
    let mut protocol = 0;
    for attr in &msg.attributes {
        match attr {
            RuleAttribute::Table(t) => table = *t,
            RuleAttribute::Source(ip) => src_addr = Some(*ip),
            RuleAttribute::Priority(p) => priority = *p,
            RuleAttribute::SuppressPrefixLen(len) => {
                suppress_prefixlen = u8::try_from(*len).ok().filter(|len| *len <= 128);
            }
            RuleAttribute::Protocol(p) => protocol = u8::from(*p),
            _ => {}
        }
    }
    let action = match msg.header.action {
        NlRuleAction::ToTable => RuleAction::ToTable(table),
        NlRuleAction::Unreachable => RuleAction::Unreachable,
        _ => return None,
    };
    let src = src_addr.and_then(|ip| IpNet::new(ip, msg.header.src_len).ok());
    Some(Rule {
        v6,
        priority,
        src,
        action,
        suppress_prefixlen,
        protocol,
    })
}

fn link_from(msg: &LinkMessage) -> Link {
    let flags = msg.header.flags;
    let mut link = Link {
        index: msg.header.index,
        name: String::new(),
        kind: None,
        master: None,
        parent: None,
        vlan_id: None,
        up: flags.contains(LinkFlags::Up),
        carrier: flags.contains(LinkFlags::LowerUp),
        mac: None,
        mtu: 0,
    };
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::IfName(name) => link.name.clone_from(name),
            LinkAttribute::Address(bytes) => {
                if let Ok(mac) = <[u8; 6]>::try_from(bytes.as_slice()) {
                    link.mac = Some(mac);
                }
            }
            LinkAttribute::Mtu(mtu) => link.mtu = *mtu,
            LinkAttribute::Controller(master) => link.master = Some(*master),
            LinkAttribute::Link(parent) => link.parent = Some(*parent),
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    match info {
                        LinkInfo::Kind(kind) => {
                            link.kind = Some(match kind {
                                InfoKind::Bridge => LinkKind::Bridge,
                                InfoKind::Veth => LinkKind::Veth,
                                InfoKind::Vlan => LinkKind::Vlan,
                                InfoKind::Other(name) => LinkKind::Other(name.clone()),
                                other => LinkKind::Other(format!("{other:?}").to_lowercase()),
                            });
                        }
                        LinkInfo::Data(InfoData::Vlan(vlan)) => {
                            for data in vlan {
                                if let InfoVlan::Id(id) = data {
                                    link.vlan_id = Some(*id);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    link
}

fn addr_from(msg: &AddressMessage) -> Option<Addr> {
    let mut address = None;
    let mut local = None;
    let mut lifetimes = (None, None);
    for attr in &msg.attributes {
        match attr {
            AddressAttribute::Address(a) => address = Some(*a),
            AddressAttribute::Local(a) => local = Some(*a),
            AddressAttribute::CacheInfo(info) => {
                // The kernel reports what is left; a deadline on the process clock is what
                // the applier compares (#27). All ones is forever.
                let now = openfeo_runtime::clock::uptime_ms();
                let deadline = |secs: u32| {
                    (secs != u32::MAX).then(|| now.saturating_add(u64::from(secs) * 1000))
                };
                lifetimes = (deadline(info.ifa_preferred), deadline(info.ifa_valid));
            }
            _ => {}
        }
    }
    // On point-to-point links IFA_ADDRESS is the peer; IFA_LOCAL is always ours.
    let ip = local.or(address)?;
    let peer = match (local, address) {
        (Some(local), Some(address)) if address != local => Some(address),
        _ => None,
    };
    let net = IpNet::new(ip, msg.header.prefix_len).ok()?;
    Some(Addr {
        ifindex: msg.header.index,
        net,
        scope: u8::from(msg.header.scope),
        peer,
        preferred_until_ms: lifetimes.0,
        valid_until_ms: lifetimes.1,
    })
}

fn route_from(msg: &RouteMessage) -> Option<Route> {
    let v6 = match msg.header.address_family {
        AddressFamily::Inet => false,
        AddressFamily::Inet6 => true,
        _ => return None,
    };
    let mut route = Route {
        v6,
        table: u32::from(msg.header.table),
        dst: None,
        gateway: None,
        oif: None,
        protocol: u8::from(msg.header.protocol),
        priority: 0,
        kind: match msg.header.kind {
            RouteType::BlackHole => RouteKind::Blackhole,
            RouteType::Unreachable => RouteKind::Unreachable,
            _ => RouteKind::Unicast,
        },
        pref_src: None,
    };
    for attr in &msg.attributes {
        match attr {
            RouteAttribute::Destination(a) => {
                route.dst = ip_of(a)
                    .and_then(|ip| IpNet::new(ip, msg.header.destination_prefix_length).ok());
            }
            RouteAttribute::Gateway(a) => route.gateway = ip_of(a),
            RouteAttribute::Oif(index) => route.oif = Some(*index),
            RouteAttribute::Priority(metric) => route.priority = *metric,
            RouteAttribute::Table(table) => route.table = *table,
            RouteAttribute::PrefSource(a) => route.pref_src = ip_of(a),
            _ => {}
        }
    }
    // The kernel reports an IPv6 blackhole or unreachable route with `lo` as its device where
    // the IPv4 one has none (ADR-0020); neither has an interface either way.
    if route.kind != RouteKind::Unicast {
        route.oif = None;
    }
    Some(route)
}

fn ip_of(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::address::CacheInfo;

    /// #27: the kernel's remaining lifetimes become deadlines on the process clock, so the
    /// applier can compare them with what it wants; the all-ones lifetime is infinite.
    #[test]
    fn cacheinfo_becomes_deadlines_and_infinite_is_none() {
        let mut msg = AddressMessage::default();
        msg.header.family = AddressFamily::Inet6;
        msg.header.prefix_len = 64;
        msg.header.index = 7;
        msg.attributes.push(AddressAttribute::Address(
            "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap().into(),
        ));
        let mut info = CacheInfo::default();
        info.ifa_preferred = 600;
        info.ifa_valid = 0xffff_ffff;
        msg.attributes.push(AddressAttribute::CacheInfo(info));
        let now = openfeo_runtime::clock::uptime_ms();
        let addr = addr_from(&msg).expect("an address");
        let preferred = addr
            .preferred_until_ms
            .expect("a finite preferred lifetime");
        assert!(
            preferred.abs_diff(now + 600_000) < 100,
            "{preferred} vs {now} + 600 s"
        );
        assert_eq!(addr.valid_until_ms, None, "all ones is forever");
        let mut plain = msg.clone();
        plain
            .attributes
            .retain(|a| !matches!(a, AddressAttribute::CacheInfo(_)));
        let addr = addr_from(&plain).expect("an address");
        assert_eq!((addr.preferred_until_ms, addr.valid_until_ms), (None, None));
    }
}
