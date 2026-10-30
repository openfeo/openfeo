// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Planning kernel interface renames to their `pN` names (SPEC §7.1). When a wanted name is
//! currently held by another interface, every rename goes through a temporary `rn<index>` name
//! first, so the kernel never sees two devices wanting one name.

use std::collections::{BTreeMap, BTreeSet};

/// One `ip link set <index> name <to>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rename {
    /// Kernel interface index.
    pub index: u32,
    /// The new name.
    pub to: String,
}

/// The renames to apply in order. `current` is `(index, name)` for every interface; `wanted`
/// maps a current name to the name it should have (interfaces absent from `wanted` are left
/// alone). If any wanted name is currently in use, every changing interface first moves to
/// `rn<index>`.
#[must_use]
pub fn plan(current: &[(u32, String)], wanted: &BTreeMap<String, String>) -> Vec<Rename> {
    let changes: Vec<(u32, &str)> = current
        .iter()
        .filter_map(|(index, name)| {
            let to = wanted.get(name)?;
            (to != name).then_some((*index, to.as_str()))
        })
        .collect();
    if changes.is_empty() {
        return Vec::new();
    }
    let in_use: BTreeSet<&str> = current.iter().map(|(_, name)| name.as_str()).collect();
    let conflict = changes.iter().any(|(_, to)| in_use.contains(to));
    let mut out = Vec::with_capacity(changes.len() * 2);
    if conflict {
        out.extend(changes.iter().map(|(index, _)| Rename {
            index: *index,
            to: format!("rn{index}"),
        }));
    }
    out.extend(changes.iter().map(|(index, to)| Rename {
        index: *index,
        to: (*to).to_owned(),
    }));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wanted(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(from, to)| ((*from).to_owned(), (*to).to_owned()))
            .collect()
    }

    fn current(pairs: &[(u32, &str)]) -> Vec<(u32, String)> {
        pairs
            .iter()
            .map(|(index, name)| (*index, (*name).to_owned()))
            .collect()
    }

    #[test]
    fn rename_plan_is_empty_when_names_match() {
        let cur = current(&[(2, "p0"), (3, "p1")]);
        assert_eq!(plan(&cur, &wanted(&[("p0", "p0"), ("p1", "p1")])), vec![]);
    }

    #[test]
    fn rename_plan_is_direct_without_conflicts() {
        let cur = current(&[(2, "eth0"), (3, "eth1"), (4, "lo")]);
        assert_eq!(
            plan(&cur, &wanted(&[("eth0", "p1"), ("eth1", "p0")])),
            vec![
                Rename {
                    index: 2,
                    to: "p1".into(),
                },
                Rename {
                    index: 3,
                    to: "p0".into(),
                },
            ]
        );
    }

    #[test]
    fn rename_plan_swaps_through_temporary_names() {
        let cur = current(&[(2, "p0"), (3, "p1")]);
        assert_eq!(
            plan(&cur, &wanted(&[("p0", "p1"), ("p1", "p0")])),
            vec![
                Rename {
                    index: 2,
                    to: "rn2".into(),
                },
                Rename {
                    index: 3,
                    to: "rn3".into(),
                },
                Rename {
                    index: 2,
                    to: "p1".into(),
                },
                Rename {
                    index: 3,
                    to: "p0".into(),
                },
            ]
        );
    }
}
