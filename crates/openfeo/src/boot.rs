// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Boot-time decisions as pure functions, so the branches the harness cannot easily reach (a
//! kernel missing options, an unreadable `/proc/config.gz`, an invalid config file) are unit
//! tested: what to do about the kernel check (SPEC §4.2) and about the config load (SPEC §8.2,
//! §5.6).

use std::io;

use openfeo_config::admin::{ConfigState, Salvage, salvage_password_hash};
use openfeo_config::load::{Loaded, Source};
use openfeo_config::state::{ConfigProblem, ConfigViolation};
use openfeo_config::validate::Violation;
use openfeo_config::{Config, ConfigError, PortMap};
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
        /// What the refused file still says about the admin password (SPEC §8.2).
        salvage: Salvage,
    },
}

/// Decide from the loader's result. An invalid file is never half-applied (SPEC §2 Config),
/// but its admin password is kept: `file_text` is the refused file's text, when it could be
/// read at all.
#[must_use]
pub fn config_decision(
    result: Result<Loaded, ConfigError>,
    file_text: Option<&str>,
) -> ConfigDecision {
    let salvage = || file_text.map_or(Salvage::Unreadable, salvage_password_hash);
    match result {
        Ok(loaded) => ConfigDecision::Use(Box::new(loaded)),
        Err(ConfigError::Invalid(violations)) => ConfigDecision::Defaults {
            reason: format!("invalid ({} errors)", violations.len()),
            violations,
            salvage: salvage(),
        },
        Err(err) => ConfigDecision::Defaults {
            reason: err.to_string(),
            violations: Vec::new(),
            salvage: salvage(),
        },
    }
}

/// The configuration to run and how it came to be: the file's, or first-boot defaults for
/// `ports`, which carry the refused file's admin password when it had one.
#[must_use]
pub fn config_to_run(decision: ConfigDecision, ports: &PortMap) -> (Config, ConfigState) {
    match decision {
        ConfigDecision::Use(loaded) => {
            let state = match loaded.source {
                Source::File => ConfigState::Loaded,
                Source::FirstBootDefaults => ConfigState::FirstBoot,
            };
            (loaded.config, state)
        }
        ConfigDecision::Defaults {
            reason,
            violations,
            salvage,
        } => {
            let mut config = Config::first_boot(ports);
            if let Salvage::Hash(hash) = &salvage {
                config.admin = Some(openfeo_config::Admin {
                    password_hash: hash.clone(),
                });
            }
            let problem = ConfigProblem {
                reason,
                violations: violations
                    .into_iter()
                    .map(|violation| ConfigViolation {
                        path: violation.path,
                        code: violation.code.to_string(),
                        message: violation.message,
                    })
                    .collect(),
            };
            let readable = salvage != Salvage::Unreadable;
            (config, ConfigState::Refused { problem, readable })
        }
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
            config_decision(Ok(loaded), None),
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
        match config_decision(Err(ConfigError::Invalid(vec![violation.clone()])), None) {
            ConfigDecision::Defaults {
                reason, violations, ..
            } => {
                assert_eq!(reason, "invalid (1 errors)");
                assert_eq!(violations, vec![violation]);
            }
            other @ ConfigDecision::Use(_) => panic!("{other:?}"),
        }
    }

    #[test]
    fn config_decision_falls_back_on_other_errors() {
        match config_decision(Err(ConfigError::MissingVersion), None) {
            ConfigDecision::Defaults {
                reason, violations, ..
            } => {
                assert_eq!(
                    reason,
                    "config_version is missing or not a positive integer"
                );
                assert_eq!(violations, vec![]);
            }
            other @ ConfigDecision::Use(_) => panic!("{other:?}"),
        }
    }

    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";

    fn invalid() -> Result<Loaded, ConfigError> {
        Err(ConfigError::Invalid(vec![Violation {
            path: "lans[0].ports[0]".into(),
            code: Code::UnknownPort,
            message: "no port named \"p7\"".into(),
        }]))
    }

    #[test]
    fn a_refused_file_keeps_its_password() {
        let text = format!("config_version = 1\n[admin]\npassword_hash = \"{HASH}\"\n");
        let decision = config_decision(invalid(), Some(&text));
        assert!(matches!(
            &decision,
            ConfigDecision::Defaults { salvage: Salvage::Hash(hash), .. } if hash == HASH
        ));
        let (config, state) = config_to_run(decision, &PortMap::default());
        assert_eq!(config.admin.unwrap().password_hash, HASH);
        assert_eq!(config.lans[0].name, "lan0", "first-boot defaults otherwise");
        let ConfigState::Refused { problem, readable } = state else {
            panic!("refused");
        };
        assert!(readable);
        assert_eq!(problem.reason, "invalid (1 errors)");
        assert_eq!(problem.violations[0].path, "lans[0].ports[0]");
        assert_eq!(problem.violations[0].code, "unknown_port");
    }

    #[test]
    fn a_refused_file_with_no_password_has_none_and_one_that_is_not_toml_is_unreadable() {
        let (config, state) = config_to_run(
            config_decision(invalid(), Some("config_version = 1\n")),
            &PortMap::default(),
        );
        assert_eq!(config.admin, None);
        assert!(matches!(state, ConfigState::Refused { readable: true, .. }));
        let (config, state) = config_to_run(
            config_decision(
                Err(ConfigError::Toml("expected a value".into())),
                Some("= ="),
            ),
            &PortMap::default(),
        );
        assert_eq!(config.admin, None);
        assert!(matches!(
            state,
            ConfigState::Refused {
                readable: false,
                ..
            }
        ));
        let (_, state) = config_to_run(config_decision(invalid(), None), &PortMap::default());
        assert!(
            matches!(
                state,
                ConfigState::Refused {
                    readable: false,
                    ..
                }
            ),
            "a file whose text could not be read at all"
        );
    }

    #[test]
    fn a_missing_file_is_first_boot_and_a_valid_one_is_loaded() {
        let first = Loaded {
            config: Config::first_boot(&PortMap::default()),
            source: Source::FirstBootDefaults,
            migrated_from: None,
        };
        let (_, state) = config_to_run(config_decision(Ok(first), None), &PortMap::default());
        assert_eq!(state, ConfigState::FirstBoot);
        let file = Loaded {
            config: Config::default(),
            source: Source::File,
            migrated_from: None,
        };
        let (_, state) = config_to_run(config_decision(Ok(file), None), &PortMap::default());
        assert_eq!(state, ConfigState::Loaded);
    }
}
