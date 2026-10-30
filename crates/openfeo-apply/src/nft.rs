// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The nft applier: hands the desired ruleset to libnftables as one batch whenever it differs
//! from the last ruleset this process applied. The batch's add/delete/add prologue replaces
//! `table inet openfeo` atomically (SPEC §7.5), so a fresh process (a restarted child) applies
//! once and converges without disturbing traffic; an unchanged World costs nothing.

use openfeo_nft::Nft;
use openfeo_reconcile::nft::DesiredNft;
use serde_json::Value;

use crate::{ApplyError, Report};

/// Makes the kernel's `table inet openfeo` match [`DesiredNft`].
#[derive(Debug)]
pub struct NftApplier {
    nft: Nft,
    last_applied: Option<Vec<Value>>,
}

impl NftApplier {
    /// An applier over one libnftables context; nothing applied yet.
    #[must_use]
    pub fn new(nft: Nft) -> Self {
        NftApplier {
            nft,
            last_applied: None,
        }
    }

    /// One pass: apply the ruleset when it differs from the last one applied (one operation),
    /// otherwise nothing.
    ///
    /// # Errors
    ///
    /// [`ApplyError::Nft`] with libnftables' error text when the batch is refused; the kernel then
    /// still runs the previous ruleset, and the next pass retries.
    pub fn apply(&mut self, desired: &DesiredNft) -> Result<Report, ApplyError> {
        if self.last_applied.as_deref() == Some(desired.ruleset.as_slice()) {
            return Ok(Report { ops: 0 });
        }
        let (chains, rules) = count(&desired.ruleset);
        match self.nft.apply(&desired.ruleset) {
            Ok(()) => {
                tracing::info!("ruleset applied: {chains} chains, {rules} rules");
                self.last_applied = Some(desired.ruleset.clone());
                Ok(Report { ops: 1 })
            }
            Err(err) => {
                let message = err.to_string();
                tracing::warn!("ruleset rejected: {message}");
                Err(ApplyError::Nft(message))
            }
        }
    }
}

/// Chains and rules added by the batch.
fn count(ruleset: &[Value]) -> (usize, usize) {
    let added = |kind: &str| {
        ruleset
            .iter()
            .filter(|object| object.get("add").is_some_and(|add| add.get(kind).is_some()))
            .count()
    };
    (added("chain"), added("rule"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn counts_chains_and_rules() {
        let ruleset = vec![
            json!({"add": {"table": {}}}),
            json!({"delete": {"table": {}}}),
            json!({"add": {"chain": {"name": "input"}}}),
            json!({"add": {"rule": {"chain": "input"}}}),
            json!({"add": {"rule": {"chain": "input"}}}),
        ];
        assert_eq!(count(&ruleset), (1, 2));
    }
}
