// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Sticky port naming (SPEC §7.1): a port keeps the `pN` it was first given; a never-seen
//! identity takes the lowest free number in bus-path order; a known identity that is absent is
//! reported as missing and kept in the map, so it gets its name back when it returns.

use std::collections::{BTreeMap, BTreeSet};

use openfeo_config::{PortMap, PortMapEntry};

use crate::MacAddr;

/// A port found on this boot: its bus-path identity, current kernel name and MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentPort {
    /// `pci-DDDD:BB:DD.F`.
    pub id: String,
    /// The name the kernel gave it (`eth0`), or its `pN` after a restart.
    pub ifname: String,
    /// Tie-breaker only (SPEC §2 Interface identity).
    pub mac: MacAddr,
}

/// The result of naming this boot's ports against the known map.
#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    /// The map to persist: known entries in their order, new ones appended.
    pub map: PortMap,
    /// Identities seen for the first time, with the names they were given.
    pub added: Vec<PortMapEntry>,
    /// Known identities absent on this boot (kept in the map).
    pub missing: Vec<PortMapEntry>,
    /// Current kernel name to wanted `pN`, for every present port.
    pub names: BTreeMap<String, String>,
}

/// Name every present port: known identities keep their names, new ones take the lowest free
/// `pN` in bus-path order (MAC as tie-breaker).
#[must_use]
pub fn assign(known: &PortMap, present: &[PresentPort]) -> Assignment {
    let mut map = known.clone();
    let mut sorted: Vec<&PresentPort> = present.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id).then(a.mac.cmp(&b.mac)));
    let mut taken: BTreeSet<String> = map.ports.iter().map(|e| e.name.clone()).collect();
    let mut added = Vec::new();
    let mut names = BTreeMap::new();
    for port in sorted {
        let known_name = map.name_of(&port.id).map(str::to_owned);
        let name = if let Some(name) = known_name {
            name
        } else {
            let name = lowest_free(&taken);
            taken.insert(name.clone());
            let entry = PortMapEntry {
                id: port.id.clone(),
                name: name.clone(),
            };
            map.ports.push(entry.clone());
            added.push(entry);
            name
        };
        names.insert(port.ifname.clone(), name);
    }
    let present_ids: BTreeSet<&str> = present.iter().map(|p| p.id.as_str()).collect();
    let missing = known
        .ports
        .iter()
        .filter(|e| !present_ids.contains(e.id.as_str()))
        .cloned()
        .collect();
    Assignment {
        map,
        added,
        missing,
        names,
    }
}

/// The lowest `pN` not in `taken`; with `k` names taken it is at most `p<k>`.
fn lowest_free(taken: &BTreeSet<String>) -> String {
    (0..=taken.len())
        .map(|n| format!("p{n}"))
        .find(|name| !taken.contains(name))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_config::PortMapEntry;

    fn mac(last: u8) -> MacAddr {
        MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, last])
    }

    fn present(id: &str, ifname: &str, last: u8) -> PresentPort {
        PresentPort {
            id: id.into(),
            ifname: ifname.into(),
            mac: mac(last),
        }
    }

    fn entry(id: &str, name: &str) -> PortMapEntry {
        PortMapEntry {
            id: id.into(),
            name: name.into(),
        }
    }

    fn pairs(map: &PortMap) -> Vec<(&str, &str)> {
        map.ports
            .iter()
            .map(|e| (e.id.as_str(), e.name.as_str()))
            .collect()
    }

    #[test]
    fn first_boot_assigns_in_path_order() {
        let a = assign(
            &PortMap::default(),
            &[
                present("pci-0000:00:06.0", "eth2", 2),
                present("pci-0000:00:04.0", "eth0", 0),
                present("pci-0000:00:05.0", "eth1", 1),
            ],
        );
        assert_eq!(
            pairs(&a.map),
            vec![
                ("pci-0000:00:04.0", "p0"),
                ("pci-0000:00:05.0", "p1"),
                ("pci-0000:00:06.0", "p2"),
            ]
        );
        assert_eq!(a.added.len(), 3);
        assert_eq!(a.missing, vec![]);
        assert_eq!(a.names["eth0"], "p0");
        assert_eq!(a.names["eth2"], "p2");
    }

    #[test]
    fn known_ports_keep_their_names_new_ones_take_the_lowest_free() {
        let known = PortMap {
            ports: vec![
                entry("pci-0000:00:04.0", "p0"),
                entry("pci-0000:00:06.0", "p2"),
            ],
        };
        let a = assign(
            &known,
            &[
                present("pci-0000:00:04.0", "eth0", 0),
                present("pci-0000:00:05.0", "eth1", 1),
                present("pci-0000:00:06.0", "eth2", 2),
            ],
        );
        assert_eq!(
            pairs(&a.map),
            vec![
                ("pci-0000:00:04.0", "p0"),
                ("pci-0000:00:06.0", "p2"),
                ("pci-0000:00:05.0", "p1"),
            ]
        );
        assert_eq!(a.added, vec![entry("pci-0000:00:05.0", "p1")]);
        assert_eq!(a.missing, vec![]);
        assert_eq!(a.names["eth1"], "p1");
        assert_eq!(a.names["eth2"], "p2");
    }

    #[test]
    fn missing_ports_are_reported_and_kept() {
        let known = PortMap {
            ports: vec![
                entry("pci-0000:00:04.0", "p0"),
                entry("pci-0000:00:05.0", "p1"),
                entry("pci-0000:00:06.0", "p2"),
            ],
        };
        let a = assign(
            &known,
            &[
                present("pci-0000:00:04.0", "eth0", 0),
                present("pci-0000:00:06.0", "eth1", 2),
            ],
        );
        assert_eq!(a.map, known);
        assert_eq!(a.added, vec![]);
        assert_eq!(a.missing, vec![entry("pci-0000:00:05.0", "p1")]);
        assert_eq!(a.names.len(), 2);
        assert_eq!(a.names["eth1"], "p2");
    }
}
