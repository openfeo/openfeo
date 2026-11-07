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
use netlink_packet_route::route::{RouteMessage, RouteProtocol, RouteScope, RouteType};
use netlink_packet_route::rule::{RuleAction as NlRuleAction, RuleAttribute, RuleMessage};
use rtnetlink::{LinkBridge, LinkUnspec, LinkVlan, RouteMessageBuilder};

use crate::monitor::{Error, Netlink, request_error};
use crate::types::{Route, RouteKind, Rule, RuleAction, TABLE_MAIN};

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
    /// Invalid argument (an MTU the device cannot take).
    pub const EINVAL: i32 = 22;
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

    /// The kernel said `EINVAL`: the request asks for something the device cannot do (an MTU
    /// above what it carries).
    #[must_use]
    pub fn is_invalid(&self) -> bool {
        self.errno() == Some(errno::EINVAL)
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
    /// The bridge is born down: the applier sets its MAC before bringing it up, so the kernel
    /// derives the bridge's link-local from that MAC. A bridge born up takes an EUI-64 of the
    /// random MAC it was created with and keeps it when the MAC changes.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EEXIST` when the name is taken).
    pub async fn link_add_bridge(&self, name: &str, vlan_filtering: bool) -> Result<(), Error> {
        let message = LinkBridge::new(name)
            .vlan_filtering(vlan_filtering)
            .down()
            .build();
        self.handle
            .link()
            .add(message)
            .execute()
            .await
            .map_err(|e| request_error(format!("add bridge {name}"), e))
    }

    /// `ip link add link <parent> name <name> type vlan id <id>`: an 802.1Q sub-interface, a LAN
    /// member or a tagged WAN (SPEC §7.1, §7.2, ADR-0017).
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EEXIST` when the name is taken).
    pub async fn link_add_vlan(&self, parent: u32, id: u16, name: &str) -> Result<(), Error> {
        let message = LinkVlan::new(name, parent, id).build();
        self.handle
            .link()
            .add(message)
            .execute()
            .await
            .map_err(|e| request_error(format!("add vlan {name} id {id} on link {parent}"), e))
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

    /// `ip link set <index> mtu <mtu>`.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EINVAL` for an MTU the device cannot take).
    pub async fn link_set_mtu(&self, index: u32, mtu: u32) -> Result<(), Error> {
        let message = LinkUnspec::new_with_index(index).mtu(mtu).build();
        self.handle
            .link()
            .set(message)
            .execute()
            .await
            .map_err(|e| request_error(format!("set link {index} mtu {mtu}"), e))
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

    /// `ip addr add <local> peer <peer> dev <index>`: a point-to-point address (a PPP netdev's),
    /// ours as `IFA_LOCAL` and the far end as `IFA_ADDRESS`, with `local`'s prefix length.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EEXIST` when already present).
    pub async fn addr_add_peer(&self, index: u32, local: IpNet, peer: IpAddr) -> Result<(), Error> {
        let mut request = self
            .handle
            .address()
            .add(index, local.addr(), local.prefix_len());
        let message = request.message_mut();
        message.attributes.retain(|attr| {
            !matches!(
                attr,
                AddressAttribute::Address(_) | AddressAttribute::Local(_)
            )
        });
        message
            .attributes
            .push(AddressAttribute::Local(local.addr()));
        message.attributes.push(AddressAttribute::Address(peer));
        request
            .execute()
            .await
            .map_err(|e| request_error(format!("add addr {local} peer {peer} dev {index}"), e))
    }

    /// `ip addr del <local> peer <peer> dev <index>`: the kernel matches a point-to-point address
    /// by both ends, so one added with [`Netlink::addr_add_peer`] goes with its peer.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EADDRNOTAVAIL` when not present).
    pub async fn addr_del_peer(&self, index: u32, local: IpNet, peer: IpAddr) -> Result<(), Error> {
        let mut message = AddressMessage::default();
        message.header.index = index;
        message.header.prefix_len = local.prefix_len();
        message.header.family = match local {
            IpNet::V4(_) => AddressFamily::Inet,
            IpNet::V6(_) => AddressFamily::Inet6,
        };
        message
            .attributes
            .push(AddressAttribute::Local(local.addr()));
        message.attributes.push(AddressAttribute::Address(peer));
        self.handle
            .address()
            .del(message)
            .execute()
            .await
            .map_err(|e| request_error(format!("del addr {local} peer {peer} dev {index}"), e))
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

    /// `ip rule add`, with the rule's priority, source, action, suppression and protocol.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`EEXIST` for a duplicate).
    pub async fn rule_add(&self, rule: &Rule) -> Result<(), Error> {
        let mut request = self.handle.rule().add();
        *request.message_mut() = rule_message(rule);
        request
            .execute()
            .await
            .map_err(|e| request_error(format!("add {}", describe_rule(rule)), e))
    }

    /// `ip rule del` of exactly this rule.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] when the kernel refuses (`ENOENT` when it is not there).
    pub async fn rule_del(&self, rule: &Rule) -> Result<(), Error> {
        self.handle
            .rule()
            .del(rule_message(rule))
            .execute()
            .await
            .map_err(|e| request_error(format!("del {}", describe_rule(rule)), e))
    }
}

/// `rule 2000 from 2001:db8:100::/56 lookup 100 proto 200`, `rule 1500 from all lookup main
/// suppress_prefixlength 0 proto 200` or `rule 2000 from 2001:db8:200::/56 unreachable proto
/// 200`, for errors and logs.
#[must_use]
pub fn describe_rule(rule: &Rule) -> String {
    let mut text = format!("rule {} from ", rule.priority);
    match rule.src {
        Some(src) => {
            let _ = write!(text, "{src}");
        }
        None => text.push_str("all"),
    }
    match rule.action {
        RuleAction::ToTable(TABLE_MAIN) => text.push_str(" lookup main"),
        RuleAction::ToTable(table) => {
            let _ = write!(text, " lookup {table}");
        }
        RuleAction::Unreachable => text.push_str(" unreachable"),
    }
    if let Some(len) = rule.suppress_prefixlen {
        let _ = write!(text, " suppress_prefixlength {len}");
    }
    let _ = write!(text, " proto {}", rule.protocol);
    text
}

/// The message for `rule`: the family and action in the header, the table in the header when
/// it fits a byte and always as an attribute, the source with its length, the priority, the
/// suppression and the protocol.
fn rule_message(rule: &Rule) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header.family = if rule.v6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    match rule.action {
        RuleAction::ToTable(table) => {
            message.header.action = NlRuleAction::ToTable;
            message.header.table = u8::try_from(table).unwrap_or(RT_TABLE_COMPAT);
            message.attributes.push(RuleAttribute::Table(table));
        }
        RuleAction::Unreachable => message.header.action = NlRuleAction::Unreachable,
    }
    if let Some(src) = rule.src {
        message.header.src_len = src.prefix_len();
        message.attributes.push(RuleAttribute::Source(src.addr()));
    }
    message
        .attributes
        .push(RuleAttribute::Priority(rule.priority));
    if let Some(len) = rule.suppress_prefixlen {
        message
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(u32::from(len)));
    }
    message
        .attributes
        .push(RuleAttribute::Protocol(RouteProtocol::from(rule.protocol)));
    message
}

/// `RT_TABLE_COMPAT`: the header's table byte for a table id above 255, which the attribute
/// then carries in full.
const RT_TABLE_COMPAT: u8 = 252;

/// `default via 10.0.0.1 dev 3 proto 200 metric 10`, `blackhole 192.0.2.248/29 proto 200
/// metric 1000` or `unreachable default proto 200 metric 1000 table 100`, for errors and logs.
#[must_use]
pub fn describe(route: &Route) -> String {
    let mut text = match route.kind {
        RouteKind::Unicast => String::new(),
        RouteKind::Blackhole => "blackhole ".to_owned(),
        RouteKind::Unreachable => "unreachable ".to_owned(),
    };
    text.push_str(
        &route
            .dst
            .map_or_else(|| "default".to_owned(), |dst| dst.to_string()),
    );
    if let Some(gateway) = route.gateway {
        let _ = write!(text, " via {gateway}");
    }
    if let Some(oif) = route.oif {
        let _ = write!(text, " dev {oif}");
    }
    if let Some(src) = route.pref_src {
        let _ = write!(text, " src {src}");
    }
    let _ = write!(
        text,
        " proto {} metric {} table {}",
        route.protocol, route.priority, route.table
    );
    text
}

/// The message for `route`. A unicast route without a gateway is a host or network on the device
/// and gets link scope, as `ip route add <dst> dev <if>` does; a gateway route through such a
/// host is refused unless the host route has that scope. A blackhole keeps universe scope and
/// carries its type.
fn route_message(route: &Route) -> RouteMessage {
    let mut message = route_message_builder(route);
    if route.gateway.is_none() && route.kind == RouteKind::Unicast {
        message.header.scope = RouteScope::Link;
    }
    message
}

fn route_message_builder(route: &Route) -> RouteMessage {
    let protocol = RouteProtocol::from(route.protocol);
    let kind = match route.kind {
        RouteKind::Unicast => RouteType::Unicast,
        RouteKind::Blackhole => RouteType::BlackHole,
        RouteKind::Unreachable => RouteType::Unreachable,
    };
    if route.v6 {
        let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
            .table_id(route.table)
            .protocol(protocol)
            .priority(route.priority)
            .kind(kind);
        if let Some(IpNet::V6(dst)) = route.dst {
            builder = builder.destination_prefix(dst.addr(), dst.prefix_len());
        }
        if let Some(IpAddr::V6(gateway)) = route.gateway {
            builder = builder.gateway(gateway);
        }
        if let Some(oif) = route.oif {
            builder = builder.output_interface(oif);
        }
        if let Some(IpAddr::V6(src)) = route.pref_src {
            builder = builder.pref_source(src);
        }
        builder.build()
    } else {
        let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(route.table)
            .protocol(protocol)
            .priority(route.priority)
            .kind(kind);
        if let Some(IpNet::V4(dst)) = route.dst {
            builder = builder.destination_prefix(dst.addr(), dst.prefix_len());
        }
        if let Some(IpAddr::V4(gateway)) = route.gateway {
            builder = builder.gateway(gateway);
        }
        if let Some(oif) = route.oif {
            builder = builder.output_interface(oif);
        }
        if let Some(IpAddr::V4(src)) = route.pref_src {
            builder = builder.pref_source(src);
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
