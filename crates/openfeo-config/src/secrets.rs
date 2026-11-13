// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The config's secrets over the API (SPEC §8.3): the admin's password hash and a PPPoE
//! password are written and never read back. A config goes out without them ([`redact`]); one
//! that comes in takes the running ones where it names none ([`carry`]); and the tag that
//! tells one config from another ([`tag`]) is made from the config without them, so that it
//! says nothing about a secret.

use prost::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{Config, wan};

/// `config` without its secrets: the admin's password hash and every PPPoE password are empty.
/// This is the config as the API hands it out.
#[must_use]
pub fn redact(config: &Config) -> Config {
    let mut redacted = config.clone();
    if let Some(admin) = &mut redacted.admin {
        admin.password_hash.clear();
    }
    for wan in &mut redacted.wans {
        if let Some(wan::Kind::Pppoe(account)) = &mut wan.kind {
            account.password.clear();
        }
    }
    redacted
}

/// Give a config that came in over the API the secrets it does not carry, from the one that is
/// running. Its admin table becomes the running one whatever it held: the password is changed
/// by its own call and by nothing else. A PPPoE WAN with no password takes the password of the
/// running WAN of the same name, when that one is PPPoE; any other is left empty, for validation
/// to refuse.
pub fn carry(running: &Config, proposed: &mut Config) {
    proposed.admin.clone_from(&running.admin);
    for wan in &mut proposed.wans {
        let Some(wan::Kind::Pppoe(account)) = &mut wan.kind else {
            continue;
        };
        if !account.password.is_empty() {
            continue;
        }
        let kept = running
            .wans
            .iter()
            .find(|other| other.name == wan.name)
            .and_then(|other| match &other.kind {
                Some(wan::Kind::Pppoe(account)) => Some(account.password.clone()),
                _ => None,
            });
        if let Some(password) = kept {
            account.password = password;
        }
    }
}

/// What tells one config from another, for an apply to name the config it was edited from
/// (SPEC §5.5): 32 lowercase hex characters, the first 16 bytes of SHA-256 over the config
/// without its secrets, in its protobuf encoding (which has no maps, so it is the same bytes
/// every time). Two configs that differ only in a secret, or in having an admin table at all,
/// share a tag.
#[must_use]
pub fn tag(config: &Config) -> String {
    // The admin table is left out whole, present or not: the password is changed by its own
    // call, and setting the first one must not make every config read before it stale.
    let mut tagged = redact(config);
    tagged.admin = None;
    let digest = Sha256::digest(tagged.encode_to_vec());
    digest
        .iter()
        .take(16)
        .fold(String::with_capacity(32), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Admin, PppoeWan, file, wan};

    const VM_PPPOE: &str = include_str!("../../../harness/fixtures/vm-pppoe.toml");
    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";

    /// The lab's PPPoE config with a password set, and a second PPPoE WAN.
    fn running() -> Config {
        let mut config = file::parse(VM_PPPOE).unwrap();
        config.admin = Some(Admin {
            password_hash: HASH.to_owned(),
        });
        let mut second = config.wans[0].clone();
        second.name = "wan1".to_owned();
        second.port = "p1".to_owned();
        second.ipv6 = None;
        account(&mut second).password = "another-secret".to_owned();
        config.wans.push(second);
        config
    }

    fn account(wan: &mut crate::Wan) -> &mut PppoeWan {
        let Some(wan::Kind::Pppoe(account)) = &mut wan.kind else {
            panic!("{} is not PPPoE", wan.name);
        };
        account
    }

    fn password(config: &Config, index: usize) -> &str {
        let Some(wan::Kind::Pppoe(account)) = &config.wans[index].kind else {
            panic!("wan {index} is not PPPoE");
        };
        &account.password
    }

    fn hash(config: &Config) -> &str {
        config
            .admin
            .as_ref()
            .map_or("", |admin| admin.password_hash.as_str())
    }

    #[test]
    fn redact_blanks_every_secret_and_nothing_else() {
        let config = running();
        let redacted = redact(&config);
        assert_eq!(hash(&redacted), "");
        assert_eq!(password(&redacted, 0), "");
        assert_eq!(password(&redacted, 1), "");
        // Put the three strings back and it is the config again: nothing else was touched.
        let mut restored = redacted.clone();
        restored.admin.as_mut().unwrap().password_hash = HASH.to_owned();
        account(&mut restored.wans[0]).password = "example-secret".to_owned();
        account(&mut restored.wans[1]).password = "another-secret".to_owned();
        assert_eq!(restored, config);
        // No rendering of it holds a secret.
        let text = file::render(&redacted).unwrap();
        for secret in [HASH, "example-secret", "another-secret"] {
            assert!(!text.contains(secret), "{text}");
        }
        // A config with no admin table gains none.
        let mut bare = config.clone();
        bare.admin = None;
        assert_eq!(redact(&bare).admin, None);
    }

    #[test]
    fn an_empty_pppoe_password_keeps_the_running_one() {
        let mut proposed = redact(&running());
        carry(&running(), &mut proposed);
        assert_eq!(proposed, running());
    }

    #[test]
    fn a_typed_password_replaces_it() {
        let mut proposed = redact(&running());
        account(&mut proposed.wans[0]).password = "typed".to_owned();
        carry(&running(), &mut proposed);
        assert_eq!(password(&proposed, 0), "typed");
        assert_eq!(
            password(&proposed, 1),
            "another-secret",
            "the other keeps its own"
        );
    }

    #[test]
    fn an_empty_password_on_a_wan_that_was_not_pppoe_stays_empty() {
        // The running WAN is DHCP; the proposal makes it PPPoE and names no password.
        let mut was_dhcp = running();
        was_dhcp.wans[0].kind = Some(wan::Kind::Dhcp(crate::DhcpWan::default()));
        let mut proposed = redact(&running());
        carry(&was_dhcp, &mut proposed);
        assert_eq!(
            password(&proposed, 0),
            "",
            "validation refuses it, as it always did"
        );
        assert_eq!(password(&proposed, 1), "another-secret");
    }

    #[test]
    fn a_renamed_wan_does_not_inherit_a_password() {
        let mut proposed = redact(&running());
        proposed.wans[0].name = "fibre".to_owned();
        carry(&running(), &mut proposed);
        assert_eq!(password(&proposed, 0), "");
        // Nor does a WAN take another's by position: the two swapped keep their own by name.
        let mut proposed = redact(&running());
        proposed.wans.swap(0, 1);
        carry(&running(), &mut proposed);
        assert_eq!(password(&proposed, 0), "another-secret");
        assert_eq!(password(&proposed, 1), "example-secret");
    }

    #[test]
    fn the_hash_is_never_taken_from_a_proposal() {
        // Another hash proposed.
        let mut proposed = running();
        proposed.admin.as_mut().unwrap().password_hash = "$argon2id$not-the-owners".to_owned();
        carry(&running(), &mut proposed);
        assert_eq!(hash(&proposed), HASH);
        // None proposed, and no admin table at all.
        let mut proposed = redact(&running());
        carry(&running(), &mut proposed);
        assert_eq!(hash(&proposed), HASH);
        let mut proposed = running();
        proposed.admin = None;
        carry(&running(), &mut proposed);
        assert_eq!(hash(&proposed), HASH);
        // A router with no password yet cannot be given one this way.
        let mut unset = running();
        unset.admin = None;
        let mut proposed = running();
        carry(&unset, &mut proposed);
        assert_eq!(proposed.admin, None);
    }

    #[test]
    fn two_configs_that_differ_only_in_a_secret_share_a_tag() {
        let config = running();
        let mut other = config.clone();
        account(&mut other.wans[0]).password = "changed".to_owned();
        other.admin.as_mut().unwrap().password_hash = "$argon2id$another".to_owned();
        assert_eq!(tag(&config), tag(&other));
        assert_eq!(tag(&config), tag(&redact(&config)));
    }

    /// The admin's password is not something an apply changes, so the tag does not see the
    /// admin table at all: a first password set (no table, then one) leaves the tag as it was.
    #[test]
    fn the_admin_table_is_no_part_of_the_tag() {
        let config = running();
        let mut none = config.clone();
        none.admin = None;
        let mut empty = config.clone();
        empty.admin = Some(Admin {
            password_hash: String::new(),
        });
        assert_eq!(tag(&none), tag(&config));
        assert_eq!(tag(&empty), tag(&config));
    }

    #[test]
    fn any_other_difference_changes_the_tag() {
        let config = running();
        let mut seen = vec![tag(&config)];
        let mut changed = config.clone();
        changed.wans[0].priority += 1;
        seen.push(tag(&changed));
        let mut changed = config.clone();
        account(&mut changed.wans[0]).username = "other@isp.example".to_owned();
        seen.push(tag(&changed));
        let mut changed = config.clone();
        changed.lans[0].ipv4 = "192.168.2.1/24".to_owned();
        seen.push(tag(&changed));
        let mut changed = config.clone();
        changed.wans.pop();
        seen.push(tag(&changed));
        let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
        assert_eq!(unique.len(), seen.len(), "{seen:?}");
        // And the same config has the same tag every time.
        assert_eq!(tag(&config), tag(&config.clone()));
    }

    #[test]
    fn the_tag_is_32_hex_characters() {
        for config in [running(), Config::default()] {
            let tag = tag(&config);
            assert_eq!(tag.len(), 32, "{tag}");
            assert!(
                tag.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{tag}"
            );
        }
    }
}
