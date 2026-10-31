// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Loading `/state/config.toml` (SPEC §8.2): read, migrate (backing the original up as
//! `config.toml.bak.<n>` and rewriting the file), parse, validate. An absent file is the first
//! boot (SPEC §5.6): every port in one LAN at 192.168.1.1/24, nothing forwarded.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use openfeo_platform::atomic;

use crate::error::ConfigError;
use crate::migrate::{self, Migration};
use crate::{Config, Lan, PortMap, System, file, validate};

/// Hostname until the wizard sets one.
pub const DEFAULT_HOSTNAME: &str = "openfeo";
/// LAN domain (SPEC §7.6).
pub const DEFAULT_DOMAIN: &str = "home.arpa";
/// The temporary LAN every port joins before the wizard completes (SPEC §5.6).
pub const FIRST_BOOT_LAN: &str = "lan0";
/// Its address and subnet.
pub const FIRST_BOOT_IPV4: &str = "192.168.1.1/24";
/// The DHCPv4 pool of that LAN (SPEC §5.6 "DHCP on").
pub const FIRST_BOOT_POOL: (&str, &str) = ("192.168.1.100", "192.168.1.250");
/// Permission bits for every file under `/state` (SPEC §5.2).
pub const STATE_FILE_MODE: u32 = 0o600;

/// Where a loaded configuration came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `config.toml` was present and valid.
    File,
    /// No file: first-boot defaults, never written to disk (the wizard writes the first file).
    FirstBootDefaults,
}

/// The outcome of a successful load.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    /// The configuration to run.
    pub config: Config,
    /// File or defaults.
    pub source: Source,
    /// The version the file had before migration, when it was migrated.
    pub migrated_from: Option<u32>,
}

impl Config {
    /// The configuration of a box without `config.toml`: all ports in one LAN at
    /// `192.168.1.1/24`, no WANs, so nothing is forwarded (SPEC §5.6).
    #[must_use]
    pub fn first_boot(ports: &PortMap) -> Config {
        Config {
            config_version: migrate::CURRENT_VERSION,
            system: Some(System {
                hostname: DEFAULT_HOSTNAME.to_owned(),
                domain: DEFAULT_DOMAIN.to_owned(),
                ..System::default()
            }),
            ports: Vec::new(),
            wans: Vec::new(),
            lans: vec![Lan {
                name: FIRST_BOOT_LAN.to_owned(),
                ports: ports.names().map(str::to_owned).collect(),
                ipv4: FIRST_BOOT_IPV4.to_owned(),
                dhcp: Some(crate::LanDhcp {
                    range: vec![FIRST_BOOT_POOL.0.to_owned(), FIRST_BOOT_POOL.1.to_owned()],
                    ..crate::LanDhcp::default()
                }),
            }],
            firewall: None,
        }
    }
}

/// Load `path` against the live port map `ports`, migrating the file in place if it is old.
///
/// # Errors
///
/// Any [`ConfigError`] except that an absent file is not an error: it yields first-boot defaults.
pub fn load(path: &Path, ports: &PortMap) -> Result<Loaded, ConfigError> {
    load_with(path, ports, migrate::MIGRATIONS)
}

/// [`load`] with an explicit migration list (tests inject one; production uses
/// [`migrate::MIGRATIONS`]). A migrated file is backed up as `<name>.bak.<old version>` and
/// rewritten, both mode 0600, before parsing continues.
///
/// # Errors
///
/// As [`load`].
pub fn load_with(
    path: &Path,
    ports: &PortMap,
    migrations: &[Migration],
) -> Result<Loaded, ConfigError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(Loaded {
                config: Config::first_boot(ports),
                source: Source::FirstBootDefaults,
                migrated_from: None,
            });
        }
        Err(err) => return Err(io_error(path, err)),
    };
    let doc = file::table(&text)?;
    let (doc, steps) = migrate::run_with(doc, migrations)?;
    let migrated_from = steps.first().copied();
    if let Some(from) = migrated_from {
        let backup = backup_path(path, from);
        atomic::write(&backup, text.as_bytes(), STATE_FILE_MODE)
            .map_err(|err| io_error(&backup, err))?;
        let rendered = toml::to_string(&doc).map_err(|err| ConfigError::Toml(err.to_string()))?;
        atomic::write(path, rendered.as_bytes(), STATE_FILE_MODE)
            .map_err(|err| io_error(path, err))?;
    }
    let config: Config = file::from_table(doc)?;
    let violations = validate::validate(&config, ports);
    if !violations.is_empty() {
        return Err(ConfigError::Invalid(violations));
    }
    Ok(Loaded {
        config,
        source: Source::File,
        migrated_from,
    })
}

fn backup_path(path: &Path, version: u32) -> PathBuf {
    let name = path.file_name().map_or_else(
        || "config.toml".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    path.with_file_name(format!("{name}.bak.{version}"))
}

fn io_error(path: &Path, source: io::Error) -> ConfigError {
    ConfigError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::CURRENT_VERSION;
    use crate::validate::Code;
    use crate::{ConfigError, PortMapEntry};
    use std::os::unix::fs::PermissionsExt;

    fn live() -> PortMap {
        PortMap {
            ports: ["pci-0000:00:03.0", "pci-0000:00:04.0", "pci-0000:00:05.0"]
                .iter()
                .enumerate()
                .map(|(i, id)| PortMapEntry {
                    id: (*id).to_owned(),
                    name: format!("p{i}"),
                })
                .collect(),
        }
    }

    const VALID: &str = "config_version = 1\n\n[[wans]]\nname = \"wan0\"\nport = \"p0\"\npriority = 10\n[wans.static]\naddress = \"203.0.113.10/24\"\ngateway = \"203.0.113.1\"\n\n[[lans]]\nname = \"lan0\"\nports = [\"p1\", \"p2\"]\nipv4 = \"192.168.1.1/24\"\n";

    fn set_timezone(doc: &mut toml::Table) {
        let mut system = toml::Table::new();
        system.insert(
            "timezone".into(),
            toml::Value::String("Europe/London".into()),
        );
        doc.insert("system".into(), toml::Value::Table(system));
    }

    #[test]
    fn first_boot_has_one_lan_with_every_port() {
        let cfg = Config::first_boot(&live());
        assert_eq!(cfg.config_version, CURRENT_VERSION);
        let system = cfg.system.unwrap();
        assert_eq!(system.hostname, DEFAULT_HOSTNAME);
        assert_eq!(system.domain, DEFAULT_DOMAIN);
        assert_eq!(cfg.wans, Vec::new());
        assert_eq!(cfg.lans.len(), 1);
        assert_eq!(cfg.lans[0].name, FIRST_BOOT_LAN);
        assert_eq!(cfg.lans[0].ports, vec!["p0", "p1", "p2"]);
        assert_eq!(cfg.lans[0].ipv4, FIRST_BOOT_IPV4);
        assert_eq!(
            crate::validate::validate(&Config::first_boot(&live()), &live()),
            vec![]
        );
    }

    #[test]
    fn absent_file_gives_first_boot_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load(&dir.path().join("config.toml"), &live()).unwrap();
        assert_eq!(loaded.source, Source::FirstBootDefaults);
        assert_eq!(loaded.migrated_from, None);
        assert_eq!(loaded.config, Config::first_boot(&live()));
    }

    #[test]
    fn valid_file_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, VALID).unwrap();
        let loaded = load(&path, &live()).unwrap();
        assert_eq!(loaded.source, Source::File);
        assert_eq!(loaded.migrated_from, None);
        assert_eq!(loaded.config.wans[0].name, "wan0");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), VALID, "untouched");
    }

    #[test]
    fn invalid_file_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, VALID.replace("\"p1\", \"p2\"", "\"p7\"")).unwrap();
        match load(&path, &live()) {
            Err(ConfigError::Invalid(v)) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].code, Code::UnknownPort);
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn unreadable_shape_is_a_shape_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "config_version = 1\nbogus = 1\n").unwrap();
        assert!(matches!(load(&path, &live()), Err(ConfigError::Shape(_))));
    }

    #[test]
    fn migrated_file_is_backed_up_and_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, VALID).unwrap();
        let loaded = load_with(&path, &live(), &[set_timezone]).unwrap();
        assert_eq!(loaded.migrated_from, Some(1));
        assert_eq!(loaded.config.config_version, 2);
        assert_eq!(loaded.config.system.unwrap().timezone, "Europe/London");
        let backup = dir.path().join("config.toml.bak.1");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), VALID);
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(rewritten.contains("config_version = 2"), "{rewritten}");
        assert!(
            rewritten.contains("timezone = \"Europe/London\""),
            "{rewritten}"
        );
        for f in [&path, &backup] {
            let mode = std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}: {mode:o}", f.display());
        }
        // Loading the rewritten file with the same migrations is now a no-op.
        let again = load_with(&path, &live(), &[set_timezone]).unwrap();
        assert_eq!(again.migrated_from, None);
    }
}

#[cfg(test)]
mod first_boot_dhcp_tests {
    use super::*;
    use crate::PortMapEntry;
    use crate::validate::validate;

    #[test]
    fn first_boot_serves_dhcp_on_the_temporary_lan() {
        let ports = PortMap {
            ports: vec![
                PortMapEntry {
                    id: "pci-0000:00:03.0".into(),
                    name: "p0".into(),
                },
                PortMapEntry {
                    id: "pci-0000:00:04.0".into(),
                    name: "p1".into(),
                },
            ],
        };
        let config = Config::first_boot(&ports);
        let dhcp = config.lans[0]
            .dhcp
            .as_ref()
            .expect("DHCP on at first boot (SPEC §5.6)");
        assert_eq!(dhcp.range, vec![FIRST_BOOT_POOL.0, FIRST_BOOT_POOL.1]);
        assert_eq!(dhcp.range, vec!["192.168.1.100", "192.168.1.250"]);
        assert_eq!(
            (dhcp.lease_secs, dhcp.r#static.len(), dhcp.dns.len()),
            (0, 0, 0)
        );
        assert_eq!(validate(&config, &ports), vec![]);
    }
}
