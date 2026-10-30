// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Lookups on the generated [`PortMap`] (SPEC §7.1): bus-path identity to sticky kernel name and
//! back. Assignment of names to newly seen ports lives in `openfeo-world`.

use crate::PortMap;

impl PortMap {
    /// The kernel name given to the port with identity `id`.
    #[must_use]
    pub fn name_of(&self, id: &str) -> Option<&str> {
        self.ports
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.name.as_str())
    }

    /// The identity behind kernel name `name`.
    #[must_use]
    pub fn id_of(&self, name: &str) -> Option<&str> {
        self.ports
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.id.as_str())
    }

    /// Every kernel name, in map order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.ports.iter().map(|e| e.name.as_str())
    }
}
