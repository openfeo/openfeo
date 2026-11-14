// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! What a change of World means (SPEC §6.2, §10): run by the publisher inside every publish,
//! with the previous World and the next. It brings each WAN's status fact up to date in the
//! next World and names the events of the change. Because it sees every generation, a change
//! and its reversal are both reported, which a watcher of the `watch` channel would miss.

use std::collections::BTreeSet;
use std::sync::Arc;

use openfeo_config::Wan;
use openfeo_world::{EventDraft, WanPhase, WanStatusFact, World};

use crate::wan::{learned_ipv4, phase, reason};

/// Bring `next.wan_status` up to date and return the events of the change from `prev`, WANs in
/// config order and then LANs. `boot_ms` is now, in milliseconds since the kernel booted.
pub fn derive(prev: &World, next: &mut World, boot_ms: u64) -> Vec<EventDraft> {
    stamp(next, boot_ms);
    let mut events = Vec::new();
    for wan in &next.config.wans {
        wan_events(prev, next, wan, &mut events);
    }
    for lan in &next.config.lans {
        lease_events(prev, next, &lan.name, &mut events);
    }
    events
}

/// One status entry per configured WAN: a changed phase restarts its clock, reaching `Up`
/// clears the cause, and a WAN no longer configured loses its entry.
fn stamp(next: &mut World, boot_ms: u64) {
    let wanted: Vec<(String, WanPhase)> = next
        .config
        .wans
        .iter()
        .map(|wan| (wan.name.clone(), phase(next, wan)))
        .collect();
    let settled = next.wan_status.len() == wanted.len()
        && wanted.iter().all(|(name, phase)| {
            next.wan_status.get(name).is_some_and(|status| {
                status.phase == *phase && (*phase != WanPhase::Up || status.cause.is_none())
            })
        });
    if settled {
        return;
    }
    let statuses = Arc::make_mut(&mut next.wan_status);
    statuses.retain(|name, _| wanted.iter().any(|(wanted, _)| wanted == name));
    for (name, phase) in wanted {
        let status = statuses.entry(name).or_insert(WanStatusFact {
            phase,
            since_boot_ms: boot_ms,
            cause: None,
        });
        if status.phase != phase {
            status.phase = phase;
            status.since_boot_ms = boot_ms;
        }
        if phase == WanPhase::Up {
            status.cause = None;
        }
    }
}

fn was_up(world: &World, name: &str) -> bool {
    world
        .wan_status
        .get(name)
        .is_some_and(|status| status.phase == WanPhase::Up)
}

fn prefixes(world: &World, name: &str) -> BTreeSet<String> {
    world.dhcp6.get(name).map_or_default(|fact| {
        fact.prefixes
            .iter()
            .map(|prefix| prefix.net.to_string())
            .collect()
    })
}

fn wan_events(prev: &World, next: &World, wan: &Wan, events: &mut Vec<EventDraft>) {
    let name = &wan.name;
    match (was_up(prev, name), was_up(next, name)) {
        (true, false) => events
            .push(EventDraft::new(format!("wan.{name}.down")).with("reason", reason(next, wan))),
        (false, true) => events.push(EventDraft::new(format!("wan.{name}.up"))),
        _ => {}
    }
    let before = prev
        .config
        .wans
        .iter()
        .find(|old| old.name == *name)
        .and_then(|old| learned_ipv4(prev, old));
    let after = learned_ipv4(next, wan);
    if before != after {
        for (address, change) in [(before, "withdrawn"), (after, "added")] {
            if let Some(address) = address {
                events.push(
                    EventDraft::new(format!("wan.{name}.addr"))
                        .with("address", address)
                        .with("change", change),
                );
            }
        }
    }
    let (before, after) = (prefixes(prev, name), prefixes(next, name));
    for (prefix, change) in before
        .difference(&after)
        .map(|prefix| (prefix, "withdrawn"))
        .chain(after.difference(&before).map(|prefix| (prefix, "added")))
    {
        events.push(
            EventDraft::new(format!("wan.{name}.prefix"))
                .with("prefix", prefix.clone())
                .with("change", change),
        );
    }
}

/// A lease is a MAC holding an address: `(mac, address, host)`.
fn leases(world: &World, lan: &str) -> BTreeSet<(String, String, String)> {
    world.leases.get(lan).map_or_default(|leases| {
        leases
            .iter()
            .map(|lease| {
                (
                    lease.mac.to_string(),
                    lease.address.to_string(),
                    lease.hostname.clone().unwrap_or_default(),
                )
            })
            .collect()
    })
}

fn lease_events(prev: &World, next: &World, lan: &str, events: &mut Vec<EventDraft>) {
    let (before, after) = (leases(prev, lan), leases(next, lan));
    for ((mac, address, host), what) in before
        .difference(&after)
        .map(|lease| (lease, "released"))
        .chain(after.difference(&before).map(|lease| (lease, "granted")))
    {
        events.push(
            EventDraft::new(format!("lan.{lan}.lease.{what}"))
                .with("address", address.clone())
                .with("mac", mac.clone())
                .with("host", host.clone()),
        );
    }
}

#[cfg(test)]
mod tests {
    use openfeo_config::{Config, PortMap};

    use super::*;
    use crate::fixtures;
    use crate::wan::tests::lit;

    fn nothing() -> World {
        World::new(Config::default(), PortMap::default())
    }

    /// `world` as the publisher would hold it: its statuses stamped at boot.
    fn stamped(mut world: World) -> World {
        derive(&nothing(), &mut world, 0);
        world
    }

    #[test]
    fn losing_the_lease_is_down_with_the_cause_and_a_withdrawn_address() {
        let prev = stamped(lit(fixtures::dhcp_world(), "p0"));
        let mut next = lit(fixtures::dhcp_world_without_lease(), "p0");
        next.wan_status = prev.wan_status.clone();
        next.set_wan_cause("wan0", "lease expired");
        let events = derive(&prev, &mut next, 9_000);
        let topics: Vec<&str> = events.iter().map(|e| e.topic.as_str()).collect();
        assert_eq!(topics, ["wan.wan0.down", "wan.wan0.addr"]);
        assert_eq!(events[0].fields["reason"], "lease expired");
        assert_eq!(events[1].fields["address"], "203.0.113.100/24");
        assert_eq!(events[1].fields["change"], "withdrawn");
        let status = &next.wan_status["wan0"];
        assert_eq!(
            (status.phase, status.since_boot_ms),
            (WanPhase::Connecting, 9_000)
        );
        assert_eq!(status.cause.as_deref(), Some("lease expired"));
    }

    #[test]
    fn coming_up_clears_the_cause_and_keeps_the_stamp_while_nothing_changes() {
        let mut first = lit(fixtures::dhcp_world(), "p0");
        first.set_wan_cause("wan0", "nak");
        let events = derive(&nothing(), &mut first, 4_000);
        let topics: Vec<&str> = events.iter().map(|e| e.topic.as_str()).collect();
        assert_eq!(topics, ["wan.wan0.up", "wan.wan0.addr"]);
        assert_eq!(events[1].fields["change"], "added");
        assert_eq!(first.wan_status["wan0"].cause, None);
        assert_eq!(first.wan_status["wan0"].since_boot_ms, 4_000);
        let mut again = first.clone();
        assert_eq!(derive(&first, &mut again, 8_000), Vec::new());
        assert_eq!(again.wan_status["wan0"].since_boot_ms, 4_000);
        assert!(
            Arc::ptr_eq(&first.wan_status, &again.wan_status),
            "nothing changed, so nothing was copied"
        );
    }

    #[test]
    fn losing_carrier_is_down_for_no_carrier() {
        let prev = stamped(lit(fixtures::dhcp_world(), "p0"));
        let mut next = fixtures::dhcp_world();
        next.wan_status = prev.wan_status.clone();
        let events = derive(&prev, &mut next, 5);
        assert_eq!(events.len(), 1, "the lease is still held: no address event");
        assert_eq!(events[0].topic, "wan.wan0.down");
        assert_eq!(events[0].fields["reason"], "no carrier");
        assert_eq!(next.wan_status["wan0"].phase, WanPhase::Down);
    }

    #[test]
    fn a_lease_granted_and_released_names_the_lan_the_address_and_the_host() {
        let prev = stamped(fixtures::static_world());
        let mut next = fixtures::static_world_with_leases();
        next.wan_status = prev.wan_status.clone();
        let granted = derive(&prev, &mut next, 1);
        assert_eq!(granted.len(), fixtures::lease_facts()["lan0"].len());
        assert!(granted.iter().all(|e| e.topic == "lan.lan0.lease.granted"));
        let nas = granted
            .iter()
            .find(|e| e.fields["host"] == "nas")
            .expect("the nas");
        assert_eq!(nas.fields["address"], "192.168.1.10");
        assert_eq!(nas.fields["mac"], "52:54:00:fe:10:10");
        let mut gone = fixtures::static_world();
        gone.wan_status = next.wan_status.clone();
        let released = derive(&next, &mut gone, 2);
        assert_eq!(released.len(), 2);
        assert!(
            released
                .iter()
                .all(|e| e.topic == "lan.lan0.lease.released")
        );
    }

    #[test]
    fn a_delegated_prefix_coming_and_going_is_a_prefix_event() {
        let with = stamped(fixtures::pd_world());
        let mut without = with.clone();
        Arc::make_mut(&mut without.dhcp6).clear();
        let withdrawn = derive(&with, &mut without, 1);
        let prefix: Vec<_> = withdrawn
            .iter()
            .filter(|e| e.topic == "wan.wan0.prefix")
            .collect();
        assert_ne!(prefix.len(), 0);
        assert!(prefix.iter().all(|e| e.fields["change"] == "withdrawn"));
        let mut back = with.clone();
        back.wan_status = without.wan_status.clone();
        let added = derive(&without, &mut back, 2);
        assert!(
            added
                .iter()
                .any(|e| e.topic == "wan.wan0.prefix" && e.fields["change"] == "added")
        );
    }

    #[test]
    fn a_wan_removed_from_the_config_loses_its_status() {
        let prev = stamped(lit(fixtures::dhcp_world(), "p0"));
        assert!(prev.wan_status.contains_key("wan0"));
        let mut next = prev.clone();
        Arc::make_mut(&mut next.config).wans.clear();
        let events = derive(&prev, &mut next, 3);
        assert!(next.wan_status.is_empty());
        assert!(events.is_empty(), "a WAN that is gone is not reported down");
    }
}
