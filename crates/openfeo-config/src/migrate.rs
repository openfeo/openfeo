// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `config_version` and forward migrations (SPEC §8.2): `migrate(n -> n+1)` functions run on the
//! TOML table at load, each bumping the version; a file newer than this image understands is
//! refused, so a downgraded image never misreads a config.

use crate::error::ConfigError;

/// The schema version this image writes and understands.
pub const CURRENT_VERSION: u32 = 1;
/// The top-level key.
pub const VERSION_KEY: &str = "config_version";
/// One forward step on the raw document; `MIGRATIONS[n - 1]` takes version `n` to `n + 1`.
pub type Migration = fn(&mut toml::Table);
/// Every migration so far, oldest first. [`CURRENT_VERSION`] is always `MIGRATIONS.len() + 1`.
pub const MIGRATIONS: &[Migration] = &[];

/// The document's `config_version`.
///
/// # Errors
///
/// [`ConfigError::MissingVersion`] when absent, not an integer, or below 1.
pub fn version_of(doc: &toml::Table) -> Result<u32, ConfigError> {
    match doc.get(VERSION_KEY) {
        Some(toml::Value::Integer(n)) if *n >= 1 => {
            u32::try_from(*n).map_err(|_| ConfigError::MissingVersion)
        }
        _ => Err(ConfigError::MissingVersion),
    }
}

/// Bring `doc` to [`CURRENT_VERSION`], returning it with the list of versions migrated from
/// (empty when it was already current).
///
/// # Errors
///
/// [`ConfigError::MissingVersion`], or [`ConfigError::TooNew`] for a document from a newer image.
pub fn run(doc: toml::Table) -> Result<(toml::Table, Vec<u32>), ConfigError> {
    run_with(doc, MIGRATIONS)
}

/// [`run`] with an explicit migration list, whose length defines the target version.
///
/// # Errors
///
/// As [`run`].
pub fn run_with(
    mut doc: toml::Table,
    migrations: &[Migration],
) -> Result<(toml::Table, Vec<u32>), ConfigError> {
    let supported = u32::try_from(migrations.len()).map_or(u32::MAX, |n| n.saturating_add(1));
    let found = version_of(&doc)?;
    if found > supported {
        return Err(ConfigError::TooNew { found, supported });
    }
    let mut steps = Vec::new();
    for version in found..supported {
        // `version >= 1` and `version < migrations.len() + 1`, so the step exists.
        if let Some(step) = migrations.get(version as usize - 1) {
            step(&mut doc);
        }
        doc.insert(
            VERSION_KEY.to_owned(),
            toml::Value::Integer(i64::from(version + 1)),
        );
        steps.push(version);
    }
    Ok((doc, steps))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(version: i64) -> toml::Table {
        format!("config_version = {version}\n[system]\nhostname = \"x\"\n")
            .parse()
            .unwrap()
    }

    fn add_migrated_flag(doc: &mut toml::Table) {
        doc.insert("migrated".into(), toml::Value::Boolean(true));
    }

    #[test]
    fn current_version_passes_through() {
        let before = doc(i64::from(CURRENT_VERSION));
        let (after, steps) = run(before.clone()).unwrap();
        assert_eq!(after, before);
        assert_eq!(steps, Vec::<u32>::new());
    }

    #[test]
    fn current_version_matches_migration_count() {
        assert_eq!(CURRENT_VERSION as usize, MIGRATIONS.len() + 1);
    }

    #[test]
    fn missing_version_is_an_error() {
        let no_version: toml::Table = "[system]\nhostname = \"x\"\n".parse().unwrap();
        assert!(matches!(run(no_version), Err(ConfigError::MissingVersion)));
        assert!(matches!(run(doc(0)), Err(ConfigError::MissingVersion)));
        let not_an_int: toml::Table = "config_version = \"1\"\n".parse().unwrap();
        assert!(matches!(run(not_an_int), Err(ConfigError::MissingVersion)));
    }

    #[test]
    fn newer_than_supported_is_too_new() {
        match run(doc(i64::from(CURRENT_VERSION) + 1)) {
            Err(ConfigError::TooNew { found, supported }) => {
                assert_eq!(found, CURRENT_VERSION + 1);
                assert_eq!(supported, CURRENT_VERSION);
            }
            other => panic!("expected TooNew, got {other:?}"),
        }
    }

    #[test]
    fn run_with_applies_each_step_and_bumps() {
        let migrations: &[Migration] = &[add_migrated_flag];
        let (after, steps) = run_with(doc(1), migrations).unwrap();
        assert_eq!(steps, vec![1]);
        assert_eq!(after["config_version"], toml::Value::Integer(2));
        assert_eq!(after["migrated"], toml::Value::Boolean(true));
        assert_eq!(after["system"]["hostname"], toml::Value::String("x".into()));
    }
}
