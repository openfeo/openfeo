// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Boot-time decisions as pure functions, so the branches the harness cannot easily reach (a
//! kernel missing options, an unreadable `/proc/config.gz`, an invalid config file) are unit
//! tested: what to do about the kernel check (SPEC §4.2) and about the config load (SPEC §8.2,
//! §5.6).

use std::io;

use openfeo_config::ConfigError;
use openfeo_config::load::Loaded;
use openfeo_config::validate::Violation;
use openfeo_init::cmdline::Mode;
use openfeo_platform::kconfig;

/// What the kernel-option check means for this boot.
#[derive(Debug, PartialEq, Eq)]
pub enum KernelDecision {
    /// Every required option is present; the number checked.
    Proceed(usize),
    /// Router services must not start; the reason, with the exact options.
    Refuse(String),
    /// Container mode without a readable `/proc/config.gz`: the host's kernel is not ours to judge.
    SkipContainer(String),
}

/// Decide from the result of reading `/proc/config.gz`.
#[must_use]
pub fn kernel_decision(read: io::Result<String>, mode: Mode) -> KernelDecision {
    match read {
        Ok(text) => match kconfig::check(&text, kconfig::REQUIRED_FRAGMENT) {
            Ok(n) => KernelDecision::Proceed(n),
            Err(missing) => KernelDecision::Refuse(format!("missing required options: {missing}")),
        },
        Err(err) => {
            let reason = format!("cannot read {}: {err}", kconfig::PROC_CONFIG_GZ);
            if mode == Mode::Container {
                KernelDecision::SkipContainer(reason)
            } else {
                KernelDecision::Refuse(reason)
            }
        }
    }
}

/// What to run with after loading `config.toml`.
#[derive(Debug)]
pub enum ConfigDecision {
    /// The file (or first-boot defaults when there was none).
    Use(Box<Loaded>),
    /// The file is unusable: run first-boot defaults so the box stays reachable, and say why.
    Defaults {
        /// One line for the console.
        reason: String,
        /// Each validation violation, when that was the problem.
        violations: Vec<Violation>,
    },
}

/// Decide from the loader's result. An invalid file is never half-applied (SPEC §2 Config).
#[must_use]
pub fn config_decision(result: Result<Loaded, ConfigError>) -> ConfigDecision {
    match result {
        Ok(loaded) => ConfigDecision::Use(Box::new(loaded)),
        Err(ConfigError::Invalid(violations)) => ConfigDecision::Defaults {
            reason: format!("invalid ({} errors)", violations.len()),
            violations,
        },
        Err(err) => ConfigDecision::Defaults {
            reason: err.to_string(),
            violations: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfeo_config::load::{Loaded, Source};
    use openfeo_config::validate::{Code, Violation};
    use openfeo_config::{Config, ConfigError};
    use openfeo_init::cmdline::Mode;
    use openfeo_platform::kconfig::{REQUIRED_FRAGMENT, parse_fragment};

    fn unreadable() -> std::io::Result<String> {
        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    }

    #[test]
    fn kernel_decision_proceeds_with_count() {
        match kernel_decision(Ok(REQUIRED_FRAGMENT.to_owned()), Mode::Vm) {
            KernelDecision::Proceed(n) => assert_eq!(n, parse_fragment(REQUIRED_FRAGMENT).len()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn kernel_decision_refuses_on_missing_options() {
        match kernel_decision(Ok("CONFIG_FOO=y\n".to_owned()), Mode::Metal) {
            KernelDecision::Refuse(reason) => {
                assert!(
                    reason.contains("CONFIG_BRIDGE(want=y,have=unset)"),
                    "{reason}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn kernel_decision_skips_in_container_when_unreadable() {
        match kernel_decision(unreadable(), Mode::Container) {
            KernelDecision::SkipContainer(reason) => {
                assert!(reason.contains("/proc/config.gz"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn kernel_decision_refuses_when_unreadable_on_metal() {
        assert!(matches!(
            kernel_decision(unreadable(), Mode::Metal),
            KernelDecision::Refuse(_)
        ));
        assert!(matches!(
            kernel_decision(unreadable(), Mode::Vm),
            KernelDecision::Refuse(_)
        ));
    }

    #[test]
    fn config_decision_uses_a_valid_file() {
        let loaded = Loaded {
            config: Config::default(),
            source: Source::File,
            migrated_from: None,
        };
        assert!(matches!(
            config_decision(Ok(loaded)),
            ConfigDecision::Use(l) if l.source == Source::File
        ));
    }

    #[test]
    fn config_decision_falls_back_on_invalid_with_violations() {
        let violation = Violation {
            path: "lans[0].ports[0]".into(),
            code: Code::UnknownPort,
            message: "no port named \"p7\"".into(),
        };
        match config_decision(Err(ConfigError::Invalid(vec![violation.clone()]))) {
            ConfigDecision::Defaults { reason, violations } => {
                assert_eq!(reason, "invalid (1 errors)");
                assert_eq!(violations, vec![violation]);
            }
            other @ ConfigDecision::Use(_) => panic!("{other:?}"),
        }
    }

    #[test]
    fn config_decision_falls_back_on_other_errors() {
        match config_decision(Err(ConfigError::MissingVersion)) {
            ConfigDecision::Defaults { reason, violations } => {
                assert_eq!(
                    reason,
                    "config_version is missing or not a positive integer"
                );
                assert_eq!(violations, vec![]);
            }
            other @ ConfigDecision::Use(_) => panic!("{other:?}"),
        }
    }
}
