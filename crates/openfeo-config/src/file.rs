// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `/state/config.toml` and `/state/identity/portmap` as text (SPEC §8.2): TOML is parsed to a
//! table, converted to a JSON value and read through the pbjson types, so the file is the
//! canonical JSON mapping of the schema spelled in TOML; rendering is the reverse, with the proto
//! field names.

use std::path::{Path, PathBuf};

use openfeo_platform::atomic;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::ConfigError;
use crate::load::STATE_FILE_MODE;
use crate::{Config, Dhcp4Lease, Dhcp6Lease, PortMap};

/// Parse a `config.toml` text into a [`Config`]. Syntax, unknown keys and wrong types are
/// errors; `config_version` and semantics are checked by `load`, not here.
///
/// # Errors
///
/// [`ConfigError::Toml`] for TOML syntax, [`ConfigError::Shape`] when the document does not fit
/// the schema (the message names the offending key).
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    from_table(table(text)?)
}

/// Render a [`Config`] as TOML with the proto field names.
///
/// # Errors
///
/// [`ConfigError::Shape`] or [`ConfigError::Toml`] if the value cannot be represented (it always
/// can for values produced by this crate).
pub fn render(config: &Config) -> Result<String, ConfigError> {
    to_toml(config)
}

/// The name of the file a change of config is kept in until it is confirmed (SPEC §5.5).
pub const PENDING_FILE: &str = "config.pending.toml";

/// Where the pending config is kept: beside the config at `config_path`.
#[must_use]
pub fn pending_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name(PENDING_FILE)
}

/// Write `text` to `path` whole (SPEC §5.2, §5.5): a temporary file beside it, synced, renamed
/// over it, the directory synced, at the mode of everything under `/state`. A power cut leaves
/// the file as it was or as it is now.
///
/// # Errors
///
/// [`ConfigError::Io`]; the target is then untouched and no temporary file is left.
pub fn write_whole(path: &Path, text: &str) -> Result<(), ConfigError> {
    atomic::write(path, text.as_bytes(), STATE_FILE_MODE).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Parse `/state/identity/portmap`.
///
/// # Errors
///
/// As [`parse`].
pub fn parse_portmap(text: &str) -> Result<PortMap, ConfigError> {
    from_table(table(text)?)
}

/// Render `/state/identity/portmap`.
///
/// # Errors
///
/// As [`render`].
pub fn render_portmap(map: &PortMap) -> Result<String, ConfigError> {
    to_toml(map)
}

/// Parse `/state/leases/dhcp4-<wan>.toml`.
///
/// # Errors
///
/// As [`parse`].
pub fn parse_dhcp4_lease(text: &str) -> Result<Dhcp4Lease, ConfigError> {
    from_table(table(text)?)
}

/// Render `/state/leases/dhcp4-<wan>.toml`.
///
/// # Errors
///
/// As [`render`].
pub fn render_dhcp4_lease(lease: &Dhcp4Lease) -> Result<String, ConfigError> {
    to_toml(lease)
}

/// Parse `/state/leases/dhcp6-<wan>.toml`.
///
/// # Errors
///
/// As [`parse`].
pub fn parse_dhcp6_lease(text: &str) -> Result<Dhcp6Lease, ConfigError> {
    from_table(table(text)?)
}

/// Render `/state/leases/dhcp6-<wan>.toml`.
///
/// # Errors
///
/// As [`render`].
pub fn render_dhcp6_lease(lease: &Dhcp6Lease) -> Result<String, ConfigError> {
    to_toml(lease)
}

/// Parse `/state/leases/dhcp4-server-<lan>.toml`, a LAN's lease database (SPEC §7.6).
///
/// # Errors
///
/// As [`parse`].
pub fn parse_dhcp4_server_leases(text: &str) -> Result<crate::Dhcp4ServerLeases, ConfigError> {
    from_table(table(text)?)
}

/// Render `/state/leases/dhcp4-server-<lan>.toml`.
///
/// # Errors
///
/// As [`render`].
pub fn render_dhcp4_server_leases(
    leases: &crate::Dhcp4ServerLeases,
) -> Result<String, ConfigError> {
    to_toml(leases)
}

/// The TOML document as a table, the form migrations work on.
///
/// # Errors
///
/// [`ConfigError::Toml`] for syntax errors.
pub fn table(text: &str) -> Result<toml::Table, ConfigError> {
    text.parse::<toml::Table>()
        .map_err(|err| ConfigError::Toml(err.to_string()))
}

/// Read a (possibly migrated) table into a schema type through its JSON mapping.
///
/// # Errors
///
/// [`ConfigError::Shape`] when the document does not fit the schema.
pub fn from_table<T: DeserializeOwned>(table: toml::Table) -> Result<T, ConfigError> {
    let json = serde_json::to_value(table).map_err(|err| ConfigError::Shape(err.to_string()))?;
    serde_json::from_value(json).map_err(|err| ConfigError::Shape(err.to_string()))
}

fn to_toml<T: Serialize>(value: &T) -> Result<String, ConfigError> {
    let json = serde_json::to_value(value).map_err(|err| ConfigError::Shape(err.to_string()))?;
    let table: toml::Table =
        serde_json::from_value(json).map_err(|err| ConfigError::Shape(err.to_string()))?;
    toml::to_string(&table).map_err(|err| ConfigError::Toml(err.to_string()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_pending_file_sits_beside_the_config() {
        assert_eq!(
            pending_path(Path::new("/state/config.toml")),
            Path::new("/state/config.pending.toml")
        );
        assert_eq!(PENDING_FILE, "config.pending.toml");
    }

    /// A power cut at any instant leaves the old file or the new one, never a torn one
    /// (SPEC §5.5): the text goes to a temporary file beside the target and is renamed over it.
    #[test]
    fn a_write_is_whole_or_absent() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let names = || -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        write_whole(&path, "config_version = 1\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "config_version = 1\n"
        );
        assert_eq!(names(), ["config.toml"], "no temporary file is left");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
        // Over an existing file.
        write_whole(&path, "config_version = 2\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "config_version = 2\n"
        );
        assert_eq!(names(), ["config.toml"]);
        // Into a directory that is not there: an error, and nothing made.
        let nowhere = dir.path().join("missing").join("config.toml");
        let err = write_whole(&nowhere, "x = 1\n").unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }), "{err}");
        assert!(!dir.path().join("missing").exists());
        // Over a target the rename cannot replace (a directory with something in it): an
        // error, the target as it was, and no temporary file left beside it.
        let blocked = dir.path().join("blocked.toml");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("keep"), "kept").unwrap();
        assert!(write_whole(&blocked, "x = 1\n").is_err());
        assert_eq!(
            std::fs::read_to_string(blocked.join("keep")).unwrap(),
            "kept"
        );
        assert_eq!(names(), ["blocked.toml", "config.toml"]);
    }

    #[test]
    fn the_admin_table_round_trips() {
        let text = "config_version = 1\n[admin]\npassword_hash = \"$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA\"\n";
        let config = super::parse(text).expect("parse");
        assert_eq!(
            config.admin.as_ref().expect("admin").password_hash,
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"
        );
        assert_eq!(
            super::parse(&super::render(&config).expect("render")).expect("reparse"),
            config
        );
    }

    use super::*;
    use crate::{Dhcp4Lease, Dhcp4Route, DhcpWan, wan};

    const SPEC_SHAPED: &str = r#"
config_version = 1

[system]
hostname = "openfeo"
domain = "home.arpa"
ntp_servers = ["0.pool.ntp.org", "1.pool.ntp.org"]

[[ports]]
id = "pci-0000:02:00.0"
name = "p0"

[[wans]]
name = "wan0"
port = "p0"
vlan = 0
priority = 10
[wans.static]
address = "203.0.113.10/24"
gateway = "203.0.113.1"
dns = ["203.0.113.1"]

[[lans]]
name = "lan0"
ports = ["p1", "p2"]
ipv4 = "192.168.1.1/24"
"#;

    #[test]
    fn parses_the_spec_shaped_file() {
        let cfg = parse(SPEC_SHAPED).unwrap();
        assert_eq!(cfg.config_version, 1);
        assert_eq!(cfg.system.as_ref().unwrap().domain, "home.arpa");
        assert_eq!(cfg.ports[0].id, "pci-0000:02:00.0");
        let wan = &cfg.wans[0];
        assert_eq!(wan.priority, 10);
        match &wan.kind {
            Some(wan::Kind::Static(s)) => {
                assert_eq!(s.address, "203.0.113.10/24");
                assert_eq!(s.gateway, "203.0.113.1");
                assert_eq!(s.dns, vec!["203.0.113.1"]);
            }
            other => panic!("expected a static WAN, got {other:?}"),
        }
        assert_eq!(cfg.lans[0].ports, vec!["p1", "p2"]);
    }

    #[test]
    fn render_then_parse_round_trips() {
        let cfg = parse(SPEC_SHAPED).unwrap();
        let text = render(&cfg).unwrap();
        assert!(text.contains("[wans.static]"), "{text}");
        assert!(text.contains("config_version = 1"), "{text}");
        assert_eq!(parse(&text).unwrap(), cfg);
    }

    #[test]
    fn unknown_key_is_rejected_with_its_name() {
        let text = "config_version = 1\n[[lans]]\nname = \"lan0\"\nports = [\"p1\"]\nipv4_addr = \"192.168.1.1/24\"\n";
        match parse(text) {
            Err(ConfigError::Shape(msg)) => assert!(msg.contains("ipv4_addr"), "{msg}"),
            other => panic!("expected a shape error, got {other:?}"),
        }
    }

    #[test]
    fn toml_syntax_error_is_reported() {
        assert!(matches!(
            parse("config_version = \n"),
            Err(ConfigError::Toml(_))
        ));
    }

    #[test]
    fn parses_firewall_section() {
        let text = "config_version = 1\n\n[firewall]\nwan_ping = true\n\n[[firewall.port_forwards]]\nname = \"lan-http\"\nproto = \"tcp\"\nport = 2222\nto = \"192.168.1.2\"\nto_port = 8080\n";
        let cfg = parse(text).unwrap();
        let firewall = cfg.firewall.unwrap();
        assert!(firewall.wan_ping);
        assert_eq!(firewall.port_forwards[0].name, "lan-http");
        assert_eq!(firewall.port_forwards[0].to, "192.168.1.2");
        assert_eq!(firewall.port_forwards[0].to_port, 8080);
    }

    const VM_DHCP: &str = include_str!("../../../harness/fixtures/vm-dhcp.toml");

    #[test]
    fn parses_a_dhcp_wan_with_options() {
        let cfg = parse(VM_DHCP).unwrap();
        match &cfg.wans[0].kind {
            Some(wan::Kind::Dhcp(dhcp)) => {
                assert_eq!(dhcp.hostname, "openfeo-lab");
                assert_eq!(dhcp.vendor_class, "");
            }
            other => panic!("expected a DHCP WAN, got {other:?}"),
        }
        assert_eq!(cfg.lans[0].ipv4, "192.168.1.1/24");
        assert!(cfg.firewall.unwrap().wan_ping);
    }

    #[test]
    fn empty_dhcp_table_selects_the_kind() {
        let text = "config_version = 1\n\n[[wans]]\nname = \"wan0\"\nport = \"p0\"\n[wans.dhcp]\n";
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.wans[0].kind, Some(wan::Kind::Dhcp(DhcpWan::default())));
    }

    #[test]
    fn dhcp4_lease_file_round_trips() {
        let lease = Dhcp4Lease {
            wan: "wan0".into(),
            mac: "52:54:00:fe:00:00".into(),
            address: "203.0.113.100/24".into(),
            server: "203.0.113.1".into(),
            gateway: String::new(),
            dns: vec!["203.0.113.1".into()],
            domain: "isp.example".into(),
            mtu: 1400,
            routes: vec![
                Dhcp4Route {
                    dst: "0.0.0.0/0".into(),
                    via: "203.0.113.1".into(),
                },
                Dhcp4Route {
                    dst: "198.51.100.0/24".into(),
                    via: "203.0.113.1".into(),
                },
            ],
            lease_secs: 60,
            t1_secs: 20,
            t2_secs: 40,
            obtained_unix: 1_793_491_200,
            ntp: vec!["203.0.113.1".into()],
            broadcast: "203.0.113.255".into(),
        };
        let text = render_dhcp4_lease(&lease).unwrap();
        assert!(text.contains("address = \"203.0.113.100/24\""), "{text}");
        assert!(text.contains("[[routes]]"), "{text}");
        assert_eq!(parse_dhcp4_lease(&text).unwrap(), lease);
    }

    #[test]
    fn portmap_file_round_trips() {
        let text = "[[ports]]\nid = \"pci-0000:00:03.0\"\nname = \"p0\"\n\n[[ports]]\nid = \"pci-0000:00:04.0\"\nname = \"p1\"\n";
        let map = parse_portmap(text).unwrap();
        assert_eq!(map.ports.len(), 2);
        assert_eq!(map.ports[1].name, "p1");
        assert_eq!(parse_portmap(&render_portmap(&map).unwrap()).unwrap(), map);
    }
}

#[cfg(test)]
mod dhcp4_server_leases_tests {
    use super::*;
    use crate::{Dhcp4ServerLease, Dhcp4ServerLeases};

    #[test]
    fn dhcp4_server_leases_round_trip() {
        let leases = Dhcp4ServerLeases {
            lan: "lan0".into(),
            leases: vec![Dhcp4ServerLease {
                mac: "52:54:00:fe:10:10".into(),
                client_id: String::new(),
                address: "192.168.1.10".into(),
                hostname: "nas".into(),
                granted_unix: 1_800_000_000,
                expires_unix: 1_800_043_200,
            }],
        };
        let text = render_dhcp4_server_leases(&leases).unwrap();
        assert!(text.contains("[[leases]]"), "{text}");
        assert_eq!(parse_dhcp4_server_leases(&text).unwrap(), leases);
        assert!(
            parse_dhcp4_server_leases("lan = \"lan0\"\nbogus = 1\n").is_err(),
            "unknown keys are refused"
        );
    }
}
