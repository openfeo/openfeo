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
use netlink_packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{Handle, MulticastGroup, RouteMessageBuilder};
use tokio::sync::watch;
use tracing::debug;

use crate::types::{Addr, Cache, Link, LinkKind, Route};

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
        debug!(
            "netlink: initial dump: {} links, {} addresses, {} routes",
            cache.links.len(),
            cache.addrs.len(),
            cache.routes.len()
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

fn apply_addr(cache: &mut Cache, msg: &AddressMessage, present: bool) -> bool {
    let Some(addr) = addr_from(msg) else {
        return false;
    };
    if present {
        cache.addrs.insert(addr)
    } else {
        cache.addrs.remove(&addr)
    }
}

fn apply_route(cache: &mut Cache, msg: &RouteMessage, present: bool) -> bool {
    let Some(route) = route_from(msg) else {
        return false;
    };
    if present {
        cache.routes.insert(route)
    } else {
        cache.routes.remove(&route)
    }
}

fn link_from(msg: &LinkMessage) -> Link {
    let flags = msg.header.flags;
    let mut link = Link {
        index: msg.header.index,
        name: String::new(),
        kind: None,
        master: None,
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
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    if let LinkInfo::Kind(kind) = info {
                        link.kind = Some(match kind {
                            InfoKind::Bridge => LinkKind::Bridge,
                            InfoKind::Veth => LinkKind::Veth,
                            InfoKind::Other(name) => LinkKind::Other(name.clone()),
                            other => LinkKind::Other(format!("{other:?}").to_lowercase()),
                        });
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
    for attr in &msg.attributes {
        match attr {
            AddressAttribute::Address(a) => address = Some(*a),
            AddressAttribute::Local(a) => local = Some(*a),
            _ => {}
        }
    }
    // On point-to-point IPv4 links IFA_ADDRESS is the peer; IFA_LOCAL is always ours.
    let ip = local.or(address)?;
    let net = IpNet::new(ip, msg.header.prefix_len).ok()?;
    Some(Addr {
        ifindex: msg.header.index,
        net,
        scope: u8::from(msg.header.scope),
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
            _ => {}
        }
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
