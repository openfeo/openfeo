// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Boot-time kernel-option check (SPEC §4.2): `kernel/required.config` is compiled into the
//! binary and compared with the running kernel's `/proc/config.gz`. A kernel missing a required
//! option must not get router services, and the log says exactly which options are wrong.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read as _};

/// The required-options fragment every OpenFeO kernel must satisfy (SPEC §4.2).
pub const REQUIRED_FRAGMENT: &str = include_str!("../../../kernel/required.config");
/// Where a kernel built with `CONFIG_IKCONFIG_PROC` publishes its configuration.
pub const PROC_CONFIG_GZ: &str = "/proc/config.gz";

/// What the fragment demands of one symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Want {
    /// `CONFIG_X=y`.
    Yes,
    /// `CONFIG_X=<value>` with a value other than `y`.
    Value(String),
    /// `# CONFIG_X is not set`.
    Unset,
}

impl fmt::Display for Want {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Want::Yes => f.write_str("y"),
            Want::Value(v) => f.write_str(v),
            Want::Unset => f.write_str("unset"),
        }
    }
}

/// One line of the fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// `CONFIG_…`.
    pub symbol: String,
    /// The demanded state.
    pub want: Want,
}

/// Options the running kernel lacks or sets differently, as `SYMBOL(want=…,have=…)`, in fragment
/// order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing(pub Vec<String>);

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join(" "))
    }
}

impl std::error::Error for Missing {}

/// The requirements in `fragment`, in order. Blank lines and comments other than
/// `# CONFIG_X is not set` are ignored.
#[must_use]
pub fn parse_fragment(fragment: &str) -> Vec<Requirement> {
    fragment
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("# ") {
                let symbol = rest.strip_suffix(" is not set")?;
                return symbol.starts_with("CONFIG_").then(|| Requirement {
                    symbol: symbol.to_owned(),
                    want: Want::Unset,
                });
            }
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (symbol, value) = line.split_once('=')?;
            let want = if value == "y" {
                Want::Yes
            } else {
                Want::Value(value.to_owned())
            };
            Some(Requirement {
                symbol: symbol.to_owned(),
                want,
            })
        })
        .collect()
}

/// `symbol -> value` for every set option in a kernel config text.
fn index(running: &str) -> BTreeMap<&str, &str> {
    running
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .collect()
}

/// Compare the running kernel's config text with `fragment`.
///
/// # Errors
///
/// [`Missing`] listing every requirement the running kernel does not meet. `Ok` carries the number
/// of requirements checked.
pub fn check(running: &str, fragment: &str) -> Result<usize, Missing> {
    let have = index(running);
    let requirements = parse_fragment(fragment);
    let wrong: Vec<String> = requirements
        .iter()
        .filter_map(|r| {
            let actual = have.get(r.symbol.as_str()).copied();
            let ok = match &r.want {
                Want::Yes => actual == Some("y"),
                Want::Value(v) => actual == Some(v.as_str()),
                Want::Unset => actual.is_none(),
            };
            (!ok).then(|| {
                format!(
                    "{}(want={},have={})",
                    r.symbol,
                    r.want,
                    actual.unwrap_or("unset")
                )
            })
        })
        .collect();
    if wrong.is_empty() {
        Ok(requirements.len())
    } else {
        Err(Missing(wrong))
    }
}

/// The running kernel's configuration, gunzipped from [`PROC_CONFIG_GZ`].
///
/// # Errors
///
/// When the file is absent (no `CONFIG_IKCONFIG_PROC`, or not on Linux) or not valid gzip.
pub fn read_running() -> io::Result<String> {
    let file = std::fs::File::open(PROC_CONFIG_GZ)?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(file).read_to_string(&mut text)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAGMENT: &str = "\
# comment line

CONFIG_A=y
CONFIG_PANIC_TIMEOUT=10
# CONFIG_MODULES is not set
";

    #[test]
    fn parses_yes_value_and_not_set() {
        assert_eq!(
            parse_fragment(FRAGMENT),
            vec![
                Requirement {
                    symbol: "CONFIG_A".into(),
                    want: Want::Yes,
                },
                Requirement {
                    symbol: "CONFIG_PANIC_TIMEOUT".into(),
                    want: Want::Value("10".into()),
                },
                Requirement {
                    symbol: "CONFIG_MODULES".into(),
                    want: Want::Unset,
                },
            ]
        );
    }

    #[test]
    fn check_passes_and_counts() {
        let running =
            "CONFIG_A=y\nCONFIG_PANIC_TIMEOUT=10\n# CONFIG_MODULES is not set\nCONFIG_OTHER=y\n";
        assert_eq!(check(running, FRAGMENT), Ok(3));
    }

    #[test]
    fn check_reports_missing_and_mismatched() {
        let running = "CONFIG_PANIC_TIMEOUT=5\nCONFIG_MODULES=y\n";
        let missing = check(running, FRAGMENT).unwrap_err();
        assert_eq!(
            missing.to_string(),
            "CONFIG_A(want=y,have=unset) CONFIG_PANIC_TIMEOUT(want=10,have=5) \
             CONFIG_MODULES(want=unset,have=y)"
        );
        assert_eq!(missing.0.len(), 3);
    }

    #[test]
    fn required_fragment_is_the_checked_in_file() {
        assert!(REQUIRED_FRAGMENT.contains("CONFIG_BRIDGE_VLAN_FILTERING=y"));
        assert!(REQUIRED_FRAGMENT.contains("# CONFIG_MODULES is not set"));
        assert!(parse_fragment(REQUIRED_FRAGMENT).len() > 100);
    }
}
