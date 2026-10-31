// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! `<crate version>+<build id>[.harness]`; the build id is `git describe` from the Makefile, or
//! `dev`. Builds with the `harness` feature (test hooks compiled in, ADR-0007) carry a `.harness`
//! marker so a lab image is never mistaken for a release.

/// When the binary was built, as seconds since the Unix epoch: the clock floor (SPEC §7.10),
/// `OPENFEO_BUILD_EPOCH` from the Makefile (the commit's time, or `SOURCE_DATE_EPOCH`); 0 for a
/// bare `cargo build`, which has no floor.
#[must_use]
pub fn build_epoch() -> u64 {
    option_env!("OPENFEO_BUILD_EPOCH")
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// The version string logged at start and printed by `--version`.
#[must_use]
pub fn version() -> String {
    let marker = if cfg!(feature = "harness") {
        ".harness"
    } else {
        ""
    };
    format!(
        "{}+{}{marker}",
        env!("CARGO_PKG_VERSION"),
        option_env!("OPENFEO_BUILD_ID").unwrap_or("dev")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_has_crate_version_and_build_id() {
        let v = version();
        assert!(v.starts_with("0.1.0+"), "{v}");
        assert!(v.len() > "0.1.0+".len(), "{v}");
    }

    #[test]
    fn harness_builds_are_marked() {
        let v = version();
        assert_eq!(v.ends_with(".harness"), cfg!(feature = "harness"), "{v}");
    }

    #[test]
    fn the_build_epoch_is_a_recent_timestamp_or_zero() {
        let epoch = build_epoch();
        assert!(epoch == 0 || epoch > 1_760_000_000, "{epoch}");
    }
}
