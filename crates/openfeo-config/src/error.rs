// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Everything that can go wrong loading a configuration (SPEC §8.1, §8.2).

use std::io;
use std::path::PathBuf;

use crate::validate::Violation;

/// Why a configuration could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Reading or writing the file (other than it being absent, which means first boot).
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The errno.
        #[source]
        source: io::Error,
    },
    /// TOML syntax.
    #[error("TOML syntax: {0}")]
    Toml(String),
    /// The document does not fit the schema: unknown key, wrong type, two WAN kinds at once.
    #[error("config shape: {0}")]
    Shape(String),
    /// No usable `config_version`.
    #[error("config_version is missing or not a positive integer")]
    MissingVersion,
    /// Written by a newer image; a downgraded image refuses it (SPEC §5.4).
    #[error("config_version {found} is newer than this image supports ({supported})")]
    TooNew {
        /// The file's version.
        found: u32,
        /// The newest version this image understands.
        supported: u32,
    },
    /// The document fits the schema but breaks the rules in [`crate::validate`].
    #[error("{} validation error(s)", .0.len())]
    Invalid(Vec<Violation>),
}
