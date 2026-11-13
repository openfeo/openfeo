// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The keeper of the config (SPEC §5.5): which config is confirmed, which is running, and,
//! while a change is pending, when it reverts. This is the core, with no clock, file or channel
//! of its own: it is told the time and it decides. [`crate::server::Shared`] does the rest (the
//! two files, the World, the events, the window's timer).
//!
//! An apply is decided in two steps so that nothing is taken before the files are written:
//! [`Keeper::accept`] says whether and what, changing nothing; [`Keeper::commit`] takes it.

use std::ops::RangeInclusive;
use std::sync::Arc;

use openfeo_config::admin::ConfigState;
use openfeo_config::validate::{Violation, validate};
use openfeo_config::{Admin, Config, PortMap, secrets};
use openfeo_reconcile::effects::{effects, touched_lans};
use openfeo_world::{Effect, PendingFact};

/// The window an apply is given when it names none (SPEC §5.5, ADR-0026).
pub const DEFAULT_WINDOW_SECS: u32 = 120;
/// The windows a request may name.
pub const WINDOW_SECS: RangeInclusive<u32> = 10..=600;

/// Why the keeper will not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The config breaks these rules.
    Invalid(Vec<Violation>),
    /// The apply was edited from a config that is no longer the one running.
    StaleTag,
    /// A change is pending: it is confirmed or reverted before another is made.
    ChangePending,
    /// There is no pending change to confirm or revert.
    NothingPending,
    /// The router runs on defaults because it refused the file on disk; a confirm would
    /// replace the owner's file.
    FileRefused,
    /// The window named is outside [`WINDOW_SECS`].
    Window,
}

/// Why a pending change was reverted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Someone asked.
    Asked,
    /// Nobody confirmed it within its window.
    TimedOut,
    /// The API task that kept its window was restarted: nobody is counting any more.
    Restarted,
}

/// An apply the keeper will take: see [`Keeper::accept`].
#[derive(Clone, PartialEq)]
pub struct Accepted {
    config: Arc<Config>,
    pending: Option<PendingFact>,
    effects: Vec<Effect>,
}

/// By hand: the config holds the admin's hash and the PPPoE passwords, and is not printed.
impl std::fmt::Debug for Accepted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Accepted")
            .field("pending", &self.pending)
            .field("effects", &self.effects)
            .finish_non_exhaustive()
    }
}

impl Accepted {
    /// The config to run, with the running secrets carried in.
    #[must_use]
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// What is pending once it runs; `None` for an immediate apply.
    #[must_use]
    pub fn pending(&self) -> Option<&PendingFact> {
        self.pending.as_ref()
    }

    /// What applying it does.
    #[must_use]
    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }
}

/// Which config is confirmed, which is running, and what is pending.
pub struct Keeper {
    /// What `config.toml` says, or the defaults the router started on.
    confirmed: Arc<Config>,
    /// The config that is running while it awaits its confirmation, and its fact.
    pending: Option<(Arc<Config>, PendingFact)>,
    default_window_secs: u32,
    file_refused: bool,
}

/// By hand: neither config is printed, for the secrets they hold.
impl std::fmt::Debug for Keeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keeper")
            .field("pending", &self.pending.as_ref().map(|(_, fact)| fact))
            .field("default_window_secs", &self.default_window_secs)
            .field("file_refused", &self.file_refused)
            .finish_non_exhaustive()
    }
}

impl Keeper {
    /// A keeper of `confirmed`, the config the router started on, which came to be as `state`
    /// says. `default_window_secs` is the window an apply is given when it names none.
    #[must_use]
    pub fn new(confirmed: Arc<Config>, state: &ConfigState, default_window_secs: u32) -> Keeper {
        Keeper {
            confirmed,
            pending: None,
            default_window_secs,
            file_refused: matches!(state, ConfigState::Refused { .. }),
        }
    }

    /// The config that is running: the pending one while there is one.
    #[must_use]
    pub fn running(&self) -> &Arc<Config> {
        self.pending
            .as_ref()
            .map_or(&self.confirmed, |(config, _)| config)
    }

    /// The config a revert goes back to.
    #[must_use]
    pub fn confirmed(&self) -> &Arc<Config> {
        &self.confirmed
    }

    /// The change that is pending.
    #[must_use]
    pub fn pending(&self) -> Option<&PendingFact> {
        self.pending.as_ref().map(|(_, fact)| fact)
    }

    /// The window an apply is given when it names none.
    #[must_use]
    pub fn default_window_secs(&self) -> u32 {
        self.default_window_secs
    }

    /// Look at a proposal without applying it: the proposal with the running secrets carried
    /// in and what applying it would do.
    ///
    /// # Errors
    ///
    /// [`Refusal::Invalid`] with what is wrong with it.
    pub fn check(
        &self,
        mut proposed: Config,
        ports: &PortMap,
    ) -> Result<(Config, Vec<Effect>), Refusal> {
        secrets::carry(self.running(), &mut proposed);
        let violations = validate(&proposed, ports);
        if !violations.is_empty() {
            return Err(Refusal::Invalid(violations));
        }
        let effects = effects(self.running(), &proposed);
        Ok((proposed, effects))
    }

    /// Decide an apply at `now_boot_ms` (milliseconds since the kernel booted, the only clock
    /// the window is counted on). Changes nothing: [`commit`](Self::commit) takes what this
    /// returns, once the files are written.
    ///
    /// # Errors
    ///
    /// The first that holds of: [`Refusal::FileRefused`], [`Refusal::ChangePending`],
    /// [`Refusal::Window`], [`Refusal::StaleTag`], [`Refusal::Invalid`].
    pub fn accept(
        &self,
        proposed: Config,
        tag: &str,
        immediate: bool,
        timeout_secs: u32,
        ports: &PortMap,
        now_boot_ms: u64,
    ) -> Result<Accepted, Refusal> {
        if self.file_refused {
            return Err(Refusal::FileRefused);
        }
        if self.pending.is_some() {
            return Err(Refusal::ChangePending);
        }
        let window_secs = match timeout_secs {
            0 => self.default_window_secs,
            named if WINDOW_SECS.contains(&named) => named,
            _ => return Err(Refusal::Window),
        };
        if tag != secrets::tag(self.running()) {
            return Err(Refusal::StaleTag);
        }
        let lans = touched_lans(self.running(), &proposed);
        let (config, effects) = self.check(proposed, ports)?;
        let pending = (!immediate).then(|| PendingFact {
            confirmed: self.confirmed.clone(),
            applied_boot_ms: now_boot_ms,
            reverts_boot_ms: now_boot_ms.saturating_add(u64::from(window_secs) * 1000),
            window_secs,
            effects: effects.clone(),
            lans,
        });
        Ok(Accepted {
            config: Arc::new(config),
            pending,
            effects,
        })
    }

    /// Take an apply that [`accept`](Self::accept) decided: it is the running config now,
    /// pending or, for an immediate one, confirmed.
    pub fn commit(&mut self, accepted: Accepted) {
        if let Some(fact) = accepted.pending {
            self.pending = Some((accepted.config, fact));
        } else {
            self.confirmed = accepted.config;
            self.pending = None;
        }
    }

    /// The pending config becomes the confirmed one, which is returned.
    ///
    /// # Errors
    ///
    /// [`Refusal::NothingPending`].
    pub fn confirm(&mut self) -> Result<Arc<Config>, Refusal> {
        let (config, _) = self.pending.take().ok_or(Refusal::NothingPending)?;
        self.confirmed = config;
        Ok(self.confirmed.clone())
    }

    /// Back to the confirmed config, which is returned for publishing again.
    ///
    /// # Errors
    ///
    /// [`Refusal::NothingPending`].
    pub fn revert(&mut self) -> Result<Arc<Config>, Refusal> {
        self.pending.take().ok_or(Refusal::NothingPending)?;
        Ok(self.confirmed.clone())
    }

    /// Whether the pending change's window has run out at `now_boot_ms`.
    #[must_use]
    pub fn due(&self, now_boot_ms: u64) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|(_, fact)| now_boot_ms >= fact.reverts_boot_ms)
    }

    /// The admin's password changed: every config held takes the new hash, so that neither a
    /// confirm nor a revert brings an old one back.
    pub fn set_hash(&mut self, hash: &str) {
        let admin = Some(Admin {
            password_hash: hash.to_owned(),
        });
        Arc::make_mut(&mut self.confirmed).admin.clone_from(&admin);
        if let Some((config, fact)) = &mut self.pending {
            Arc::make_mut(config).admin = admin;
            fact.confirmed = self.confirmed.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use openfeo_config::state::ConfigProblem;
    use openfeo_config::{StaticLease, wan};
    use openfeo_reconcile::fixtures;
    use openfeo_world::EffectKind;

    use super::*;

    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";
    const NOW: u64 = 5_000_000;

    fn ports() -> PortMap {
        fixtures::portmap()
    }

    /// The lab's DHCP config, with a password set.
    fn dhcp() -> Config {
        let mut config = (*fixtures::dhcp_world().config).clone();
        config.admin = Some(Admin {
            password_hash: HASH.to_owned(),
        });
        config
    }

    /// The lab's PPPoE config, with a password set.
    fn pppoe() -> Config {
        let mut config = (*fixtures::pppoe_world().config).clone();
        config.admin = Some(Admin {
            password_hash: HASH.to_owned(),
        });
        config
    }

    fn keeper(config: Config) -> Keeper {
        Keeper::new(Arc::new(config), &ConfigState::Loaded, DEFAULT_WINDOW_SECS)
    }

    /// The keeper, what it accepts and the fact it publishes all hold whole configs, the
    /// admin's hash and a PPPoE password in them: none says any of it when printed for a log.
    #[test]
    fn nothing_the_keeper_holds_is_printed_with_its_config() {
        let mut keeper = keeper(pppoe());
        let tag = secrets::tag(keeper.running());
        let accepted = keeper
            .accept(with_reservation(pppoe()), &tag, false, 0, &ports(), NOW)
            .unwrap();
        let fact = accepted.pending().unwrap().clone();
        let mut printed = vec![format!("{accepted:?}"), format!("{fact:?}")];
        keeper.commit(accepted);
        printed.push(format!("{keeper:?}"));
        for text in printed {
            assert!(
                !text.contains(HASH)
                    && !text.contains("example-secret")
                    && !text.contains("password"),
                "{text}"
            );
            // It still says what is going on.
            assert!(text.contains("120"), "{text}");
        }
    }

    /// `config` with a reservation more on `lan0`.
    fn with_reservation(mut config: Config) -> Config {
        config.lans[0]
            .dhcp
            .as_mut()
            .unwrap()
            .r#static
            .push(StaticLease {
                mac: "02:00:00:00:00:77".to_owned(),
                ip: "192.168.1.77".to_owned(),
                hostname: "printer".to_owned(),
                client_id: String::new(),
            });
        config
    }

    /// `config` with `lan0` at `192.168.2.1/24`: its pool, its reservations and the port
    /// forward's target moved with it.
    fn moved(mut config: Config) -> Config {
        let lan = &mut config.lans[0];
        lan.ipv4 = "192.168.2.1/24".to_owned();
        let dhcp = lan.dhcp.as_mut().unwrap();
        dhcp.range = vec!["192.168.2.100".to_owned(), "192.168.2.200".to_owned()];
        for lease in &mut dhcp.r#static {
            lease.ip = lease.ip.replace("192.168.1.", "192.168.2.");
        }
        if let Some(firewall) = &mut config.firewall {
            for forward in &mut firewall.port_forwards {
                forward.to = forward.to.replace("192.168.1.", "192.168.2.");
            }
        }
        config
    }

    fn tag_of(keeper: &Keeper) -> String {
        secrets::tag(keeper.running())
    }

    /// Accept with the keeper's own tag and take it.
    fn apply(keeper: &mut Keeper, proposed: Config, immediate: bool, timeout_secs: u32) {
        let tag = tag_of(keeper);
        let accepted = keeper
            .accept(proposed, &tag, immediate, timeout_secs, &ports(), NOW)
            .unwrap_or_else(|refusal| panic!("refused: {refusal:?}"));
        keeper.commit(accepted);
    }

    #[test]
    fn the_fixtures_are_valid_as_they_stand_and_moved() {
        // What the other tests lean on.
        for config in [dhcp(), moved(dhcp()), with_reservation(dhcp()), pppoe()] {
            let keeper = keeper(dhcp());
            assert!(keeper.check(config, &ports()).is_ok());
        }
    }

    #[test]
    fn an_apply_is_pending_until_confirmed() {
        let mut keeper = keeper(dhcp());
        assert_eq!(keeper.pending(), None);
        assert_eq!(**keeper.running(), dhcp());
        apply(&mut keeper, moved(dhcp()), false, 0);
        assert_eq!(**keeper.running(), moved(dhcp()));
        assert_eq!(**keeper.confirmed(), dhcp(), "not yet");
        let pending = keeper.pending().expect("pending");
        assert_eq!(pending.window_secs, 120);
        assert_eq!(pending.applied_boot_ms, NOW);
        assert_eq!(pending.reverts_boot_ms, NOW + 120_000);
        let confirmed = keeper.confirm().unwrap();
        assert_eq!(*confirmed, moved(dhcp()));
        assert_eq!(**keeper.confirmed(), moved(dhcp()));
        assert_eq!(**keeper.running(), moved(dhcp()));
        assert_eq!(keeper.pending(), None);
    }

    #[test]
    fn a_revert_brings_back_the_confirmed_config_and_its_tag() {
        let mut keeper = keeper(dhcp());
        let before = tag_of(&keeper);
        apply(&mut keeper, moved(dhcp()), false, 0);
        assert_ne!(tag_of(&keeper), before);
        let back = keeper.revert().unwrap();
        assert_eq!(*back, dhcp());
        assert_eq!(**keeper.running(), dhcp());
        assert_eq!(**keeper.confirmed(), dhcp());
        assert_eq!(keeper.pending(), None);
        assert_eq!(
            tag_of(&keeper),
            before,
            "a draft made before the change still applies"
        );
    }

    #[test]
    fn an_immediate_apply_is_confirmed_at_once() {
        let mut keeper = keeper(dhcp());
        let tag = tag_of(&keeper);
        let accepted = keeper
            .accept(moved(dhcp()), &tag, true, 0, &ports(), NOW)
            .unwrap();
        assert_eq!(accepted.pending(), None);
        assert_eq!(**accepted.config(), moved(dhcp()));
        keeper.commit(accepted);
        assert_eq!(keeper.pending(), None);
        assert_eq!(**keeper.confirmed(), moved(dhcp()));
        assert_eq!(**keeper.running(), moved(dhcp()));
    }

    #[test]
    fn accepting_changes_nothing() {
        let keeper = keeper(dhcp());
        let tag = tag_of(&keeper);
        let _accepted = keeper
            .accept(moved(dhcp()), &tag, false, 0, &ports(), NOW)
            .unwrap();
        assert_eq!(**keeper.running(), dhcp());
        assert_eq!(keeper.pending(), None);
    }

    fn refusal(keeper: &Keeper, proposed: Config, tag: &str, timeout_secs: u32) -> Refusal {
        keeper
            .accept(proposed, tag, false, timeout_secs, &ports(), NOW)
            .expect_err("accepted")
    }

    #[test]
    fn the_refusals_come_in_order() {
        // Each by itself.
        let plain = keeper(dhcp());
        let tag = tag_of(&plain);
        assert_eq!(refusal(&plain, moved(dhcp()), &tag, 9), Refusal::Window);
        assert_eq!(
            refusal(&plain, moved(dhcp()), "not-the-tag", 0),
            Refusal::StaleTag
        );
        let mut invalid = dhcp();
        invalid.lans[0].ipv4 = "192.168.2.1/24".to_owned();
        let Refusal::Invalid(violations) = refusal(&plain, invalid.clone(), &tag, 0) else {
            panic!("a pool outside its subnet is invalid");
        };
        assert_ne!(violations, Vec::new());
        let refused_file = Keeper::new(
            Arc::new(dhcp()),
            &ConfigState::Refused {
                problem: ConfigProblem::default(),
                readable: true,
            },
            DEFAULT_WINDOW_SECS,
        );
        assert_eq!(
            refusal(&refused_file, moved(dhcp()), &tag, 0),
            Refusal::FileRefused
        );
        let mut busy = keeper(dhcp());
        apply(&mut busy, with_reservation(dhcp()), false, 0);
        let busy_tag = tag_of(&busy);
        assert_eq!(
            refusal(&busy, moved(dhcp()), &busy_tag, 0),
            Refusal::ChangePending
        );
        // Several faults at once: the earliest in the order is the one named.
        assert_eq!(
            refusal(&refused_file, invalid.clone(), "not-the-tag", 9),
            Refusal::FileRefused
        );
        assert_eq!(
            refusal(&busy, invalid.clone(), "not-the-tag", 9),
            Refusal::ChangePending
        );
        assert_eq!(
            refusal(&plain, invalid.clone(), "not-the-tag", 9),
            Refusal::Window
        );
        assert_eq!(
            refusal(&plain, invalid, "not-the-tag", 0),
            Refusal::StaleTag
        );
        // An immediate apply is refused the same while one is pending.
        assert_eq!(
            busy.accept(moved(dhcp()), &busy_tag, true, 0, &ports(), NOW)
                .unwrap_err(),
            Refusal::ChangePending
        );
    }

    #[test]
    fn a_window_of_nine_or_six_hundred_and_one_is_refused_and_ten_and_six_hundred_are_not() {
        let keeper = keeper(dhcp());
        let tag = tag_of(&keeper);
        for refused in [1, 9, 601, u32::MAX] {
            assert_eq!(
                refusal(&keeper, moved(dhcp()), &tag, refused),
                Refusal::Window,
                "{refused}"
            );
        }
        for (window, millis) in [(10, 10_000), (600, 600_000), (45, 45_000)] {
            let accepted = keeper
                .accept(moved(dhcp()), &tag, false, window, &ports(), NOW)
                .unwrap();
            let pending = accepted.pending().unwrap();
            assert_eq!(pending.window_secs, window);
            assert_eq!(pending.reverts_boot_ms, NOW + millis);
        }
        // An immediate apply has no window to be wrong about, but a bad one is still said.
        assert_eq!(
            keeper
                .accept(moved(dhcp()), &tag, true, 9, &ports(), NOW)
                .unwrap_err(),
            Refusal::Window
        );
    }

    #[test]
    fn zero_means_the_default() {
        let short = Keeper::new(Arc::new(dhcp()), &ConfigState::Loaded, 15);
        assert_eq!(short.default_window_secs(), 15);
        let tag = tag_of(&short);
        let accepted = short
            .accept(moved(dhcp()), &tag, false, 0, &ports(), NOW)
            .unwrap();
        assert_eq!(accepted.pending().unwrap().window_secs, 15);
        assert_eq!(accepted.pending().unwrap().reverts_boot_ms, NOW + 15_000);
        assert_eq!(keeper(dhcp()).default_window_secs(), 120);
        assert_eq!(DEFAULT_WINDOW_SECS, 120);
        assert_eq!(WINDOW_SECS, 10..=600);
    }

    /// The window is measured on the clock the keeper is handed, milliseconds since the kernel
    /// booted, and on nothing else: the wall clock may step by years when SNTP first answers.
    #[test]
    fn the_window_is_counted_on_the_boot_clock_alone() {
        let mut keeper = keeper(dhcp());
        assert!(!keeper.due(u64::MAX), "nothing pending is never due");
        apply(&mut keeper, moved(dhcp()), false, 30);
        let at = keeper.pending().unwrap().reverts_boot_ms;
        assert_eq!(at, NOW + 30_000);
        assert!(!keeper.due(NOW));
        assert!(!keeper.due(at - 1));
        assert!(keeper.due(at));
        assert!(keeper.due(at + 1));
        keeper.confirm().unwrap();
        assert!(!keeper.due(u64::MAX));
    }

    #[test]
    fn nothing_pending_means_nothing_to_confirm_or_revert() {
        let mut keeper = keeper(dhcp());
        assert_eq!(keeper.confirm().unwrap_err(), Refusal::NothingPending);
        assert_eq!(keeper.revert().unwrap_err(), Refusal::NothingPending);
        apply(&mut keeper, moved(dhcp()), true, 0);
        assert_eq!(keeper.confirm().unwrap_err(), Refusal::NothingPending);
        assert_eq!(keeper.revert().unwrap_err(), Refusal::NothingPending);
        assert_eq!(**keeper.running(), moved(dhcp()), "and nothing was undone");
    }

    #[test]
    fn a_proposal_takes_the_running_secrets() {
        let keeper = keeper(pppoe());
        let tag = tag_of(&keeper);
        // As the API hands it out, with a foreign hash put in and a reservation added.
        let mut proposed = with_reservation(secrets::redact(&pppoe()));
        proposed.admin = Some(Admin {
            password_hash: "$argon2id$not-the-owners".to_owned(),
        });
        let accepted = keeper
            .accept(proposed, &tag, false, 0, &ports(), NOW)
            .unwrap();
        assert_eq!(**accepted.config(), with_reservation(pppoe()));
        // A password typed is taken; `check` carries the same way.
        let mut typed = secrets::redact(&pppoe());
        let Some(wan::Kind::Pppoe(account)) = &mut typed.wans[0].kind else {
            panic!("the fixture's WAN is PPPoE");
        };
        account.password = "typed".to_owned();
        let (checked, _) = keeper.check(typed, &ports()).unwrap();
        let Some(wan::Kind::Pppoe(account)) = &checked.wans[0].kind else {
            panic!("still PPPoE");
        };
        assert_eq!(account.password, "typed");
        assert_eq!(checked.admin, pppoe().admin);
    }

    #[test]
    fn a_new_password_reaches_every_config_held() {
        let hash_of = |config: &Config| config.admin.as_ref().unwrap().password_hash.clone();
        // Reverted afterwards.
        let mut keeper = keeper(dhcp());
        apply(&mut keeper, moved(dhcp()), false, 0);
        keeper.set_hash("$argon2id$new");
        assert_eq!(hash_of(keeper.running()), "$argon2id$new");
        assert_eq!(hash_of(keeper.confirmed()), "$argon2id$new");
        assert_eq!(hash_of(&keeper.revert().unwrap()), "$argon2id$new");
        // Confirmed afterwards.
        apply(&mut keeper, moved(dhcp()), false, 0);
        keeper.set_hash("$argon2id$newer");
        assert_eq!(hash_of(&keeper.confirm().unwrap()), "$argon2id$newer");
        // With nothing pending, and on a router that had none.
        keeper.set_hash("$argon2id$newest");
        assert_eq!(hash_of(keeper.running()), "$argon2id$newest");
        let mut bare = dhcp();
        bare.admin = None;
        let mut keeper = super::Keeper::new(Arc::new(bare), &ConfigState::FirstBoot, 120);
        keeper.set_hash(HASH);
        assert_eq!(hash_of(keeper.running()), HASH);
        // The tag does not move with a secret.
        let before = tag_of(&keeper);
        keeper.set_hash("$argon2id$again");
        assert_eq!(tag_of(&keeper), before);
    }

    #[test]
    fn a_refused_file_refuses_every_apply_and_still_checks() {
        let keeper = Keeper::new(
            Arc::new(dhcp()),
            &ConfigState::Refused {
                problem: ConfigProblem::default(),
                readable: false,
            },
            DEFAULT_WINDOW_SECS,
        );
        let tag = tag_of(&keeper);
        for immediate in [false, true] {
            assert_eq!(
                keeper
                    .accept(with_reservation(dhcp()), &tag, immediate, 0, &ports(), NOW)
                    .unwrap_err(),
                Refusal::FileRefused
            );
        }
        let (_, effects) = keeper.check(moved(dhcp()), &ports()).unwrap();
        assert_eq!(effects.len(), 1);
        // A router with no file at all is not refused anything.
        let first_boot = Keeper::new(Arc::new(dhcp()), &ConfigState::FirstBoot, 120);
        assert!(
            first_boot
                .accept(with_reservation(dhcp()), &tag, false, 0, &ports(), NOW)
                .is_ok()
        );
    }

    #[test]
    fn the_effects_and_the_touched_lans_are_those_of_the_change() {
        let keeper = keeper(dhcp());
        let tag = tag_of(&keeper);
        let accepted = keeper
            .accept(moved(dhcp()), &tag, false, 0, &ports(), NOW)
            .unwrap();
        let kinds = |effects: &[Effect]| -> Vec<(String, EffectKind)> {
            effects
                .iter()
                .map(|effect| (effect.subject.clone(), effect.kind))
                .collect()
        };
        assert_eq!(
            kinds(accepted.effects()),
            [("lan0".to_owned(), EffectKind::LanAddressMoves)]
        );
        let pending = accepted.pending().unwrap();
        assert_eq!(kinds(&pending.effects), kinds(accepted.effects()));
        assert_eq!(
            pending.lans.iter().map(String::as_str).collect::<Vec<_>>(),
            ["lan0"]
        );
        // A change that interrupts nothing is accepted with no effects and touches no LAN;
        // so is the running config itself.
        let mut quiet = dhcp();
        quiet.wans[0].priority += 1;
        for proposed in [quiet, dhcp()] {
            let accepted = keeper
                .accept(proposed, &tag, false, 0, &ports(), NOW)
                .unwrap();
            assert_eq!(accepted.effects(), []);
            assert!(accepted.pending().unwrap().lans.is_empty());
        }
        // An immediate apply still says what it did.
        let accepted = keeper
            .accept(with_reservation(dhcp()), &tag, true, 0, &ports(), NOW)
            .unwrap();
        assert_eq!(
            kinds(accepted.effects()),
            [("lan0".to_owned(), EffectKind::LanDhcpRestarts)]
        );
    }
}
