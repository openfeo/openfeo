// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Identifiers (RFC 4361, RFC 8415 §11): the DUID a box keeps for life, the IAID of one port,
//! and the DHCPv4 client identifier made of both.

/// DUID-LL (RFC 8415 §11.4): type 3, hardware type 1 (Ethernet), the link-layer address.
/// Generated once from the lowest port's MAC and persisted; a changed NIC does not change it.
#[must_use]
pub fn duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut duid = vec![0, 3, 0, 1];
    duid.extend_from_slice(&mac);
    duid
}

/// The IAID of a port (RFC 4361 §6.1): stable per interface, here the last four bytes of its MAC.
#[must_use]
pub fn iaid(mac: [u8; 6]) -> [u8; 4] {
    [mac[2], mac[3], mac[4], mac[5]]
}

/// The DHCPv4 client identifier of RFC 4361 §6.1: type 255, the IAID, the DUID.
#[must_use]
pub fn client_id(iaid: [u8; 4], duid: &[u8]) -> Vec<u8> {
    let mut id = Vec::with_capacity(5 + duid.len());
    id.push(0xff);
    id.extend_from_slice(&iaid);
    id.extend_from_slice(duid);
    id
}

/// Lowercase hex, two digits per byte, no separators: the form `identity/duid` is kept in.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The inverse of [`hex`], either case; `None` for an odd length or a non-hex character.
#[must_use]
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(*pair.get(1)?).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xfe, 0x00, 0x00];

    #[test]
    fn duid_ll_iaid_and_client_id_have_the_rfc_shapes() {
        let duid = duid_ll(MAC);
        assert_eq!(hex(&duid), "00030001525400fe0000");
        assert_eq!(iaid(MAC), [0x00, 0xfe, 0x00, 0x00]);
        assert_eq!(
            hex(&client_id(iaid(MAC), &duid)),
            "ff00fe000000030001525400fe0000"
        );
    }

    #[test]
    fn hex_round_trips_and_rejects_odd_or_non_hex() {
        let bytes = duid_ll(MAC);
        assert_eq!(from_hex(&hex(&bytes)), Some(bytes));
        assert_eq!(from_hex("AB0f"), Some(vec![0xab, 0x0f]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex(""), Some(Vec::new()));
    }
}
