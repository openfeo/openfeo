// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The admin password's place in `config.toml` (SPEC §8.2, §9). The hash is set by rewriting
//! the one key `[admin] password_hash` in place, so a hand-written file keeps its comments and
//! order; and a file the router refuses still yields its hash, so a typo elsewhere in the
//! config does not leave the panel for whoever is on the LAN to claim.

use std::fs;
use std::io;
use std::path::Path;

use openfeo_platform::atomic;
use toml_edit::{DocumentMut, Item, Table, value};

use crate::error::ConfigError;
use crate::load::STATE_FILE_MODE;
use crate::state::ConfigProblem;
use crate::{Admin, Config, PortMap, file};

/// What a config file's text gives up about the admin password without being valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Salvage {
    /// The file is TOML and carries this non-empty hash.
    Hash(String),
    /// The file is TOML and sets no password.
    NoHash,
    /// The file is not TOML: nothing can be read from it.
    Unreadable,
}

/// How the running config came to be, as the API needs to know it.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigState {
    /// `config.toml` was present and valid.
    Loaded,
    /// There was no file: first-boot defaults.
    FirstBoot,
    /// The file was refused and the router runs on first-boot defaults.
    Refused {
        /// The reason and the violations.
        problem: ConfigProblem,
        /// Whether the file is at least TOML. When it is not, no password can be read from it
        /// and none may be set over it.
        readable: bool,
    },
}

/// Read `[admin] password_hash` out of a config file's text, whatever else is wrong with it.
#[must_use]
pub fn salvage_password_hash(text: &str) -> Salvage {
    let Ok(table) = text.parse::<toml::Table>() else {
        return Salvage::Unreadable;
    };
    match table
        .get("admin")
        .and_then(|admin| admin.get("password_hash"))
        .and_then(toml::Value::as_str)
    {
        Some(hash) if !hash.is_empty() => Salvage::Hash(hash.to_owned()),
        _ => Salvage::NoHash,
    }
}

/// Set the admin password hash in the config file at `path`.
///
/// A file that exists has its `[admin] password_hash` key set in place and every other byte
/// kept. With no file, the first-boot defaults for `ports` are written out with the hash. Both
/// are written atomically at mode 0600.
///
/// # Errors
///
/// When the file cannot be read or written, or exists and is not TOML (it is then left as it
/// was).
pub fn write_password_hash(path: &Path, hash: &str, ports: &PortMap) -> Result<(), ConfigError> {
    let io_error = |source: io::Error| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let rendered = match fs::read_to_string(path) {
        Ok(text) => {
            let mut doc: DocumentMut = text
                .parse()
                .map_err(|err: toml_edit::TomlError| ConfigError::Toml(err.to_string()))?;
            let admin = doc
                .entry("admin")
                .or_insert_with(|| Item::Table(Table::new()));
            let Some(admin) = admin.as_table_like_mut() else {
                return Err(ConfigError::Toml("`admin` is not a table".to_owned()));
            };
            // A value already there keeps what surrounds it (a comment on its line).
            let mut new = toml_edit::Value::from(hash);
            if let Some(old) = admin.get("password_hash").and_then(Item::as_value) {
                *new.decor_mut() = old.decor().clone();
            }
            admin.insert("password_hash", value(new));
            doc.to_string()
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut config = Config::first_boot(ports);
            config.admin = Some(Admin {
                password_hash: hash.to_owned(),
            });
            file::render(&config)?
        }
        Err(err) => return Err(io_error(err)),
    };
    atomic::write(path, rendered.as_bytes(), STATE_FILE_MODE).map_err(io_error)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::PortMapEntry;
    use crate::load::{FIRST_BOOT_IPV4, Source, load};

    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";

    fn ports() -> PortMap {
        PortMap {
            ports: vec![PortMapEntry {
                id: "pci-0000:00:03.0".to_owned(),
                name: "p0".to_owned(),
            }],
        }
    }

    #[test]
    fn the_hash_is_set_in_place_and_nothing_else_moves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let before =
            "# my router\nconfig_version = 1\n\n[system]\nhostname = \"openfeo\"   # keep me\n";
        fs::write(&path, before).unwrap();
        write_password_hash(&path, HASH, &PortMap::default()).unwrap();
        let after = fs::read_to_string(&path).unwrap();
        assert!(
            after.starts_with(before),
            "the original text is a prefix: {after}"
        );
        assert!(after.contains(&format!("[admin]\npassword_hash = \"{HASH}\"")));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_password_hash(&path, "$argon2id$other", &PortMap::default()).unwrap();
        let changed = fs::read_to_string(&path).unwrap();
        assert_eq!(changed.matches("password_hash").count(), 1);
        assert!(changed.contains("password_hash = \"$argon2id$other\""));
        assert!(changed.contains("# keep me"));
        assert!(changed.starts_with(before));
    }

    #[test]
    fn a_hash_already_in_the_file_is_replaced_where_it_stands() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let before = "config_version = 1\n[admin]\npassword_hash = \"$argon2id$old\" # mine\n\n[system]\nhostname = \"openfeo\"\n";
        fs::write(&path, before).unwrap();
        write_password_hash(&path, HASH, &PortMap::default()).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            before.replace("$argon2id$old", HASH)
        );
    }

    #[test]
    fn with_no_file_the_first_boot_defaults_are_written_with_the_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_password_hash(&path, HASH, &ports()).unwrap();
        let loaded = load(&path, &ports()).unwrap();
        assert_eq!(loaded.source, Source::File);
        assert_eq!(loaded.config.admin.unwrap().password_hash, HASH);
        assert_eq!(loaded.config.lans[0].ipv4, FIRST_BOOT_IPV4);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_file_that_is_not_toml_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "config_version = = 1\n").unwrap();
        assert!(write_password_hash(&path, HASH, &PortMap::default()).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "config_version = = 1\n");
    }

    #[test]
    fn a_hash_is_salvaged_from_a_file_that_parses() {
        let refused = format!("[admin]\npassword_hash = \"{HASH}\"\n[[lans]]\nbogus = 1\n");
        assert_eq!(
            salvage_password_hash(&refused),
            Salvage::Hash(HASH.to_owned())
        );
        assert_eq!(
            salvage_password_hash("config_version = 1\n"),
            Salvage::NoHash
        );
        assert_eq!(
            salvage_password_hash("[admin]\npassword_hash = \"\"\n"),
            Salvage::NoHash
        );
        assert_eq!(salvage_password_hash("= ="), Salvage::Unreadable);
    }
}
