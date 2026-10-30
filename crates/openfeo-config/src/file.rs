// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `/state/config.toml` and `/state/identity/portmap` as text (SPEC §8.2): TOML is parsed to a
//! table, converted to a JSON value and read through the pbjson types, so the file is the
//! canonical JSON mapping of the schema spelled in TOML; rendering is the reverse, with the proto
//! field names.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::ConfigError;
use crate::{Config, PortMap};

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
    use super::*;
    use crate::wan;

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
    fn portmap_file_round_trips() {
        let text = "[[ports]]\nid = \"pci-0000:00:03.0\"\nname = \"p0\"\n\n[[ports]]\nid = \"pci-0000:00:04.0\"\nname = \"p1\"\n";
        let map = parse_portmap(text).unwrap();
        assert_eq!(map.ports.len(), 2);
        assert_eq!(map.ports[1].name, "p1");
        assert_eq!(parse_portmap(&render_portmap(&map).unwrap()).unwrap(), map);
    }
}
