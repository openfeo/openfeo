// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Identity association identifiers (RFC 8415 §12): derived from the WAN's name, never
//! stored, so the same WAN asks under the same IAID after a reboot or a reinstall (SPEC §7.3).

use openfeo_proto_ndp::sha256;

/// The label of the prefix delegation IA.
pub const PD: &str = "pd";
/// The label of the address IA.
pub const NA: &str = "na";

/// The IAID of `kind` (`PD` or `NA`) on the WAN called `wan`: the first four bytes of
/// SHA-256 over `<kind>:<wan>`, big-endian.
#[must_use]
pub fn iaid(kind: &str, wan: &str) -> u32 {
    let digest = sha256::digest(format!("{kind}:{wan}").as_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iaid_is_stable_and_differs_per_kind() {
        assert_eq!(iaid(PD, "wan0"), iaid(PD, "wan0"));
        assert_ne!(iaid(PD, "wan0"), iaid(NA, "wan0"));
        assert_ne!(iaid(PD, "wan0"), iaid(PD, "wan1"));
        // Pinned, so a change in the derivation is a change every deployed router notices.
        let digest = sha256::digest(b"pd:wan0");
        assert_eq!(
            iaid(PD, "wan0"),
            u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
        );
    }
}
