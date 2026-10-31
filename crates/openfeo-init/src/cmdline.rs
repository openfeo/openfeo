// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Kernel command line: `openfeo.mode=`, `openfeo.slot=` and arbitrary `key=value` lookups.

use std::fmt;
use std::str::FromStr;

/// Where the binary is running (SPEC §2, process model). Set by `openfeo.mode=` on the kernel
/// command line or `--mode`; the flag wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Real hardware: full PID 1 duties, hardware watchdog, persistent `/state`.
    #[default]
    Metal,
    /// Virtual machine: as metal, with virtio devices.
    Vm,
    /// Own network namespace on a host kernel; no PID 1 duties.
    Container,
    /// USB installer.
    Installer,
    /// Rescue mode of the installer.
    Rescue,
}

impl Mode {
    /// The name used on the kernel command line and in `--mode`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Mode::Metal => "metal",
            Mode::Vm => "vm",
            Mode::Container => "container",
            Mode::Installer => "installer",
            Mode::Rescue => "rescue",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Mode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s {
            "metal" => Mode::Metal,
            "vm" => Mode::Vm,
            "container" => Mode::Container,
            "installer" => Mode::Installer,
            "rescue" => Mode::Rescue,
            other => return Err(Error::UnknownMode(other.to_owned())),
        })
    }
}

/// A/B boot slot (SPEC §5.1), from `openfeo.slot=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Slot A.
    A,
    /// Slot B.
    B,
}

impl Slot {
    /// The name used on the kernel command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Slot::A => "a",
            Slot::B => "b",
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Slot {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "a" => Ok(Slot::A),
            "b" => Ok(Slot::B),
            other => Err(Error::UnknownSlot(other.to_owned())),
        }
    }
}

/// A value this build does not understand.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// `openfeo.mode=` named a mode that does not exist.
    #[error("unknown openfeo.mode `{0}` (expected metal, vm, container, installer or rescue)")]
    UnknownMode(String),
    /// `openfeo.slot=` named a slot that does not exist.
    #[error("unknown openfeo.slot `{0}` (expected a or b)")]
    UnknownSlot(String),
}

/// A parsed kernel command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cmdline {
    /// `openfeo.mode=`, if present and known.
    pub mode: Option<Mode>,
    /// `openfeo.slot=`, if present and known.
    pub slot: Option<Slot>,
    /// One line per `openfeo.*` value this build does not know, for the console: the field it
    /// would have filled stays `None` and the rest of the line still counts.
    pub warnings: Vec<String>,
    params: Vec<(String, Option<String>)>,
}

impl Cmdline {
    /// The value of the last occurrence of `key`; `None` when absent or a bare flag.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_deref())
    }
}

/// Parse a kernel command line.
///
/// Tokens are separated by ASCII whitespace; a double-quoted value may contain whitespace and the
/// quotes are dropped. The last occurrence of a key wins. An `openfeo.mode` or `openfeo.slot`
/// value this build does not know leaves that field `None` and adds a line to `warnings`, so a
/// typo in one does not take the other with it.
#[must_use]
pub fn parse(s: &str) -> Cmdline {
    let mut cmdline = Cmdline::default();
    for token in tokens(s) {
        let param = match token.split_once('=') {
            Some((key, value)) => (key.to_owned(), Some(value.to_owned())),
            None => (token, None),
        };
        cmdline.params.push(param);
    }
    match cmdline.get("openfeo.mode").map(str::parse::<Mode>) {
        Some(Ok(mode)) => cmdline.mode = Some(mode),
        Some(Err(err)) => cmdline.warnings.push(err.to_string()),
        None => {}
    }
    match cmdline.get("openfeo.slot").map(str::parse::<Slot>) {
        Some(Ok(slot)) => cmdline.slot = Some(slot),
        Some(Err(err)) => cmdline.warnings.push(err.to_string()),
        None => {}
    }
    cmdline
}

/// Split on ASCII whitespace outside double quotes, dropping the quotes.
fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in s.chars() {
        match ch {
            '"' => quoted = !quoted,
            c if c.is_ascii_whitespace() && !quoted => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mode_and_slot() {
        let c = parse("console=ttyS0,115200 openfeo.mode=vm openfeo.slot=a panic=10");
        assert_eq!(c.warnings, Vec::<String>::new());
        assert_eq!(c.mode, Some(Mode::Vm));
        assert_eq!(c.slot, Some(Slot::A));
        assert_eq!(c.get("panic"), Some("10"));
    }

    #[test]
    fn missing_mode_is_none_and_defaults_to_metal() {
        let c = parse("console=ttyS0");
        assert_eq!(c.mode, None);
        assert_eq!(c.mode.unwrap_or_default(), Mode::Metal);
    }

    #[test]
    fn an_unknown_mode_is_a_warning_and_the_slot_survives() {
        let c = parse("openfeo.mode=weird openfeo.slot=b");
        assert_eq!((c.mode, c.slot), (None, Some(Slot::B)));
        assert_eq!(
            c.warnings,
            vec![
                "unknown openfeo.mode `weird` (expected metal, vm, container, installer or rescue)"
                    .to_owned()
            ]
        );
    }

    #[test]
    fn an_unknown_slot_is_a_warning_and_the_mode_survives() {
        let c = parse("openfeo.mode=vm openfeo.slot=c");
        assert_eq!((c.mode, c.slot), (Some(Mode::Vm), None));
        assert_eq!(
            c.warnings,
            vec!["unknown openfeo.slot `c` (expected a or b)".to_owned()]
        );
    }

    #[test]
    fn last_occurrence_wins() {
        assert_eq!(
            parse("openfeo.mode=vm openfeo.mode=rescue").mode,
            Some(Mode::Rescue)
        );
    }

    #[test]
    fn quotes_tabs_and_bare_flags() {
        let c = parse("quiet\t openfeo.chaos=\"child-exit:3\"   ro");
        assert_eq!(c.get("openfeo.chaos"), Some("child-exit:3"));
        assert_eq!(c.get("quiet"), None);
        assert_eq!(c.get("ro"), None);
        assert_eq!(c.get("nope"), None);
    }

    #[test]
    fn mode_round_trips_through_display() {
        for m in [
            Mode::Metal,
            Mode::Vm,
            Mode::Container,
            Mode::Installer,
            Mode::Rescue,
        ] {
            assert_eq!(m.to_string().parse::<Mode>().unwrap(), m);
        }
    }
}
