// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The few netlink operations the appliers need. Every error names the operation, so a log line
//! reads `add route default via 203.0.113.1 dev p0: EEXIST`, and [`Error::is_exist`] lets an
//! applier treat "already there" as done.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt as _;
use ipnet::IpNet;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::route::{RouteMessage, RouteProtocol};
use rtnetlink::{LinkBridge, LinkUnspec, RouteMessageBuilder};

use crate::monitor::{Error, Netlink, request_error};
use crate::types::Route;

/// Linux errno values the appliers reason about.
pub mod errno {
    /// No such file or directory.
    pub const ENOENT: i32 = 2;
    /// No such process (what `RTM_DELROUTE` answers for a route that is not there).
    pub const ESRCH: i32 = 3;
    /// File exists.
    pub const EEXIST: i32 = 17;
    /// No such device.
    pub const ENODEV: i32 = 19;
    /// Cannot assign requested address (deleting an address that is not there).
    pub const EADDRNOTAVAIL: i32 = 99;
}

impl Error {
    /// The errno the kernel answered with, positive, when the failure was a netlink error reply.
    #[must_use]
    pub fn errno(&self) -> Option<i32> {
        match self {
            Error::Request {
                source: rtnetlink::Error::NetlinkError(message),
                ..
            } => Some(message.raw_code().abs()),
            _ => None,
        }
    }

    /// The kernel said `EEXIST`: the thing being added is already there.
    #[must_use]
    pub fn is_exist(&self) -> bool {
        self.errno() == Some(errno::EEXIST)
    }

    /// The kernel said the thing being removed is not there (`ENOENT`, `ESRCH`, `ENODEV`,
    /// `EADDRNOTAVAIL`).
    #[must_use]
    pub fn is_absent(&self) -> bool {
        matches!(
            self.errno(),
            Some(errno::ENOENT | errno::ESRCH | errno::ENODEV | errno::EADDRNOTAVAIL)
        )
    }
}

impl Netlink {
    /// `ip link add <name> type bridge` with `vlan_filtering` as given (SPEC §7.1 wants it on).
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EEXIST` when the name is taken).
    pub async fn link_add_bridge(&self, name: &str, vlan_filtering: bool) -> Result<(), Error> {
        let message = LinkBridge::new(name).vlan_filtering(vlan_filtering).build();
        self.handle
            .link()
            .add(message)
            .execute()
            .await
            .map_err(|e| request_error(format!("add bridge {name}"), e))
    }

    /// Enslave link `index` to `master`, or release it with `None`.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses.
    pub async fn link_set_master(&self, index: u32, master: Option<u32>) -> Result<(), Error> {
        let builder = LinkUnspec::new_with_index(index);
        let message = match master {
            Some(master) => builder.controller(master),
            None => builder.nocontroller(),
        }
        .build();
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(|e| request_error(format!("set master of link {index} to {master:?}"), e))
    }

    /// `ip link set <index> up|down`.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses.
    pub async fn link_set_up(&self, index: u32, up: bool) -> Result<(), Error> {
        let builder = LinkUnspec::new_with_index(index);
        let message = if up { builder.up() } else { builder.down() }.build();
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(|e| {
                request_error(
                    format!("set link {index} {}", if up { "up" } else { "down" }),
                    e,
                )
            })
    }

    /// `ip link set <index> name <name>`; the link should be down.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EEXIST` when the name is taken, `EBUSY` when
    /// the link is up on a kernel that forbids live renames).
    pub async fn link_set_name(&self, index: u32, name: &str) -> Result<(), Error> {
        let message = LinkUnspec::new_with_index(index).name(name).build();
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(|e| request_error(format!("rename link {index} to {name}"), e))
    }

    /// `ip link set <index> address <mac>`.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses.
    pub async fn link_set_mac(&self, index: u32, mac: [u8; 6]) -> Result<(), Error> {
        let message = LinkUnspec::new_with_index(index)
            .address(mac.to_vec())
            .build();
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(|e| request_error(format!("set mac of link {index}"), e))
    }

    /// `ip link del <index>`.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses.
    pub async fn link_del(&self, index: u32) -> Result<(), Error> {
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(|e| request_error(format!("delete link {index}"), e))
    }

    /// `ip addr add <net> dev <index>`.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EEXIST` when already present).
    pub async fn addr_add(&self, index: u32, net: IpNet) -> Result<(), Error> {
        self.handle
            .address()
            .add(index, net.addr(), net.prefix_len())
            .execute()
            .await
            .map_err(|e| request_error(format!("add addr {net} dev {index}"), e))
    }

    /// `ip addr del <net> dev <index>`.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EADDRNOTAVAIL` when not present).
    pub async fn addr_del(&self, index: u32, net: IpNet) -> Result<(), Error> {
        let mut message = AddressMessage::default();
        message.header.index = index;
        message.header.prefix_len = net.prefix_len();
        message.header.family = match net {
            IpNet::V4(_) => AddressFamily::Inet,
            IpNet::V6(_) => AddressFamily::Inet6,
        };
        message
            .attributes
            .push(AddressAttribute::Address(net.addr()));
        if net.addr().is_ipv4() {
            message.attributes.push(AddressAttribute::Local(net.addr()));
        }
        self.handle
            .address()
            .del(message)
            .execute()
            .await
            .map_err(|e| request_error(format!("del addr {net} dev {index}"), e))
    }

    /// `ip route add`, with the route's own table, protocol and metric.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EEXIST` for a duplicate).
    pub async fn route_add(&self, route: &Route) -> Result<(), Error> {
        self.handle
            .route()
            .add(route_message(route))
            .execute()
            .await
            .map_err(|e| request_error(format!("add route {}", describe(route)), e))
    }

    /// `ip route del` of exactly this route.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`ESRCH` when it is not there).
    pub async fn route_del(&self, route: &Route) -> Result<(), Error> {
        self.handle
            .route()
            .del(route_message(route))
            .execute()
            .await
            .map_err(|e| request_error(format!("del route {}", describe(route)), e))
    }
}

/// `default via 10.0.0.1 dev 3 proto 200 metric 10`, for errors and logs.
#[must_use]
pub fn describe(route: &Route) -> String {
    let mut text = route
        .dst
        .map_or_else(|| "default".to_owned(), |dst| dst.to_string());
    if let Some(gateway) = route.gateway {
        let _ = write!(text, " via {gateway}");
    }
    if let Some(oif) = route.oif {
        let _ = write!(text, " dev {oif}");
    }
    let _ = write!(
        text,
        " proto {} metric {} table {}",
        route.protocol, route.priority, route.table
    );
    text
}

fn route_message(route: &Route) -> RouteMessage {
    let protocol = RouteProtocol::from(route.protocol);
    if route.v6 {
        let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
            .table_id(route.table)
            .protocol(protocol)
            .priority(route.priority);
        if let Some(IpNet::V6(dst)) = route.dst {
            builder = builder.destination_prefix(dst.addr(), dst.prefix_len());
        }
        if let Some(IpAddr::V6(gateway)) = route.gateway {
            builder = builder.gateway(gateway);
        }
        if let Some(oif) = route.oif {
            builder = builder.output_interface(oif);
        }
        builder.build()
    } else {
        let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(route.table)
            .protocol(protocol)
            .priority(route.priority);
        if let Some(IpNet::V4(dst)) = route.dst {
            builder = builder.destination_prefix(dst.addr(), dst.prefix_len());
        }
        if let Some(IpAddr::V4(gateway)) = route.gateway {
            builder = builder.gateway(gateway);
        }
        if let Some(oif) = route.oif {
            builder = builder.output_interface(oif);
        }
        builder.build()
    }
}

impl Netlink {
    /// The interface index of `name`, by asking the kernel (a dump filtered by name on the request
    /// socket), for an interface created so recently that the monitor's cache does not have it.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] for anything other than "no such interface", which is `Ok(None)`.
    pub async fn link_index(&self, name: &str) -> Result<Option<u32>, Error> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute();
        match links.try_next().await {
            Ok(Some(message)) => Ok(Some(message.header.index)),
            Ok(None) => Ok(None),
            Err(source) => {
                let err = request_error(format!("look up link {name}"), source);
                if err.is_absent() { Ok(None) } else { Err(err) }
            }
        }
    }
}
