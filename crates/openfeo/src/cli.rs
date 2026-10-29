// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Command-line flags of the binary when it is not PID 1: `--mode <m>`, `--version`.

use std::fmt;

use openfeo_init::cmdline::{self, Mode};

/// Parsed flags.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cli {
    /// `--mode`, which overrides `openfeo.mode=` on the kernel command line.
    pub mode: Option<Mode>,
    /// `--version`: print and exit.
    pub print_version: bool,
}

/// A flag we do not understand.
#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    /// Not a flag of ours.
    Unknown(String),
    /// A flag that needs a value came last.
    MissingValue(&'static str),
    /// `--mode` named a mode that does not exist.
    BadMode(cmdline::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(arg) => write!(
                f,
                "unknown argument `{arg}` (expected --mode <m> or --version)"
            ),
            Self::MissingValue(flag) => write!(f, "{flag} needs a value"),
            Self::BadMode(err) => write!(f, "--mode: {err}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Parse the arguments after the program name.
///
/// # Errors
///
/// [`CliError`] for anything that is not `--mode <m>` or `--version`.
pub fn parse(mut args: impl Iterator<Item = String>) -> Result<Cli, CliError> {
    let mut cli = Cli::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                let value = args.next().ok_or(CliError::MissingValue("--mode"))?;
                cli.mode = Some(value.parse().map_err(CliError::BadMode)?);
            }
            "--version" => cli.print_version = true,
            other => return Err(CliError::Unknown(other.to_owned())),
        }
    }
    Ok(cli)
}

/// The flag wins over the kernel command line; neither means `metal` (SPEC §2).
#[must_use]
pub fn resolve_mode(flag: Option<Mode>, cmdline: Option<Mode>) -> Mode {
    flag.or(cmdline).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> impl Iterator<Item = String> {
        list.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn flag_beats_cmdline() {
        assert_eq!(resolve_mode(Some(Mode::Vm), Some(Mode::Rescue)), Mode::Vm);
    }

    #[test]
    fn cmdline_used_without_flag_and_default_is_metal() {
        assert_eq!(resolve_mode(None, Some(Mode::Vm)), Mode::Vm);
        assert_eq!(resolve_mode(None, None), Mode::Metal);
    }

    #[test]
    fn parses_mode_flag_and_rejects_unknown() {
        assert_eq!(parse(args(&["--mode", "vm"])).unwrap().mode, Some(Mode::Vm));
        assert!(parse(args(&["--version"])).unwrap().print_version);
        assert!(parse(args(&["--frob"])).is_err());
        assert!(parse(args(&["--mode"])).is_err());
        assert!(parse(args(&["--mode", "bogus"])).is_err());
    }
}
