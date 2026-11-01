// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The kernel's network state over rtnetlink (SPEC §6.2, §13 `openfeo-netlink`): a monitor that
//! keeps a cache of links, addresses and routes current from notifications, and the apply
//! primitives the appliers use to make the kernel match the World. Observed state always comes
//! from the cache, never from a one-off dump, so an applier never races its own events.

#![forbid(unsafe_code)]

pub mod apply;
pub mod monitor;
pub mod types;

pub use apply::describe;
pub use monitor::{Error, Monitor, Netlink};
pub use types::{
    Addr, Cache, Link, LinkKind, RTPROT_OPENFEO, Route, RouteKind, SCOPE_LINK, SCOPE_UNIVERSE,
    TABLE_MAIN,
};
