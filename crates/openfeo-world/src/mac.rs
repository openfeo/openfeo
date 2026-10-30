// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! A MAC address as a value type: parsed from and printed in the `aa:bb:cc:dd:ee:ff` form sysfs
//! uses, ordered bytewise so "the lowest member MAC" (SPEC §7.1) is a plain `min`.

use std::fmt;
use std::str::FromStr;

/// Six bytes, ordered bytewise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);

/// The text was not six colon-separated hex bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a MAC address (want aa:bb:cc:dd:ee:ff)")]
pub struct ParseMacError(pub String);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = ParseMacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || ParseMacError(s.to_owned());
        let mut bytes = [0u8; 6];
        let mut parts = s.split(':');
        for byte in &mut bytes {
            let part = parts.next().ok_or_else(bad)?;
            if part.len() != 2 {
                return Err(bad());
            }
            *byte = u8::from_str_radix(part, 16).map_err(|_| bad())?;
        }
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(MacAddr(bytes))
    }
}

impl serde::Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parses_formats_and_orders() {
        let a: MacAddr = "52:54:00:FE:00:02".parse().unwrap();
        assert_eq!(a, MacAddr([0x52, 0x54, 0x00, 0xfe, 0x00, 0x02]));
        assert_eq!(a.to_string(), "52:54:00:fe:00:02");
        let b: MacAddr = "52:54:00:fe:00:01".parse().unwrap();
        assert!(b < a);
        assert_eq!([a, b].into_iter().min(), Some(b));
        for bad in ["52:54:00:fe:00", "52:54:00:fe:00:0g", "", "5254.00fe.0002"] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad:?} parsed");
        }
        assert_eq!(serde_json::to_string(&a).unwrap(), "\"52:54:00:fe:00:02\"");
    }
}
