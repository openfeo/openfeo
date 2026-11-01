// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Domain names (RFC 1035 §2.3): a list of labels, compared case-insensitively, at most 63
//! bytes a label and 255 bytes on the wire.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use thiserror::Error;

/// The longest name on the wire, in bytes.
pub const MAX_NAME: usize = 255;
/// The longest label, in bytes.
pub const MAX_LABEL: usize = 63;

/// A domain name: its labels, ASCII-lowercased, root last and implicit. The root itself has
/// no labels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

/// Why text or labels are not a name.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NameError {
    #[error("empty label")]
    EmptyLabel,
    #[error("label over 63 bytes")]
    LabelTooLong,
    #[error("name over 255 bytes")]
    NameTooLong,
}

impl Name {
    /// The root, `.`.
    #[must_use]
    pub fn root() -> Name {
        Name { labels: Vec::new() }
    }

    /// A name from its labels, most specific first.
    ///
    /// # Errors
    ///
    /// [`NameError`] for an empty label, a label over 63 bytes or a name over 255 wire bytes.
    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Name, NameError> {
        let mut lowered = Vec::with_capacity(labels.len());
        for label in labels {
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if label.len() > MAX_LABEL {
                return Err(NameError::LabelTooLong);
            }
            lowered.push(label.to_ascii_lowercase());
        }
        let name = Name { labels: lowered };
        if name.wire_len() > MAX_NAME {
            return Err(NameError::NameTooLong);
        }
        Ok(name)
    }

    #[must_use]
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// The bytes an uncompressed encoding takes: each label with its length byte, then the root.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.labels
            .iter()
            .map(|label| label.len() + 1)
            .sum::<usize>()
            + 1
    }

    /// `self` is `suffix` or a subdomain of it.
    #[must_use]
    pub fn ends_with(&self, suffix: &Name) -> bool {
        self.labels.len() >= suffix.labels.len()
            && self.labels[self.labels.len() - suffix.labels.len()..] == suffix.labels[..]
    }

    /// `self`'s labels under `parent`'s: `nas` joined to `home.arpa` is `nas.home.arpa`.
    ///
    /// # Errors
    ///
    /// [`NameError::NameTooLong`] when the result does not fit on the wire.
    pub fn join(&self, parent: &Name) -> Result<Name, NameError> {
        let mut labels = self.labels.clone();
        labels.extend(parent.labels.iter().cloned());
        Name::from_labels(labels)
    }

    /// The name without its first label; `None` for the root.
    #[must_use]
    pub fn parent(&self) -> Option<Name> {
        self.labels.split_first().map(|(_, rest)| Name {
            labels: rest.to_vec(),
        })
    }
}

impl FromStr for Name {
    type Err = NameError;

    /// `nas.home.arpa` or `nas.home.arpa.`; `.` and the empty string are the root.
    fn from_str(text: &str) -> Result<Name, NameError> {
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty() {
            return Ok(Name::root());
        }
        Name::from_labels(
            text.split('.')
                .map(|label| label.as_bytes().to_vec())
                .collect(),
        )
    }
}

impl fmt::Display for Name {
    /// Labels joined by dots with the trailing root dot; the root alone is `.`. Bytes other than
    /// letters, digits, `-` and `_` are escaped as RFC 1035 §5.1 has it (`\.`, `\\`, else
    /// `\DDD`), so a name from the wire cannot forge a console line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_str(".");
        }
        for label in &self.labels {
            for &byte in label {
                match byte {
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' => {
                        write!(f, "{}", char::from(byte))?;
                    }
                    b'.' | b'\\' => write!(f, "\\{}", char::from(byte))?,
                    _ => write!(f, "\\{byte:03}")?,
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}

/// `10.1.168.192.in-addr.arpa` for 192.168.1.10.
#[must_use]
pub fn reverse_name(addr: Ipv4Addr) -> Name {
    let [a, b, c, d] = addr.octets();
    Name {
        labels: vec![
            d.to_string().into_bytes(),
            c.to_string().into_bytes(),
            b.to_string().into_bytes(),
            a.to_string().into_bytes(),
            b"in-addr".to_vec(),
            b"arpa".to_vec(),
        ],
    }
}

/// The address a full `in-addr.arpa` name stands for; `None` for anything else.
#[must_use]
pub fn reverse_addr(name: &Name) -> Option<Ipv4Addr> {
    let [d, c, b, a, in_addr, arpa] = name.labels.as_slice() else {
        return None;
    };
    if in_addr != b"in-addr" || arpa != b"arpa" {
        return None;
    }
    Some(Ipv4Addr::new(octet(a)?, octet(b)?, octet(c)?, octet(d)?))
}

/// A label as a decimal octet: one to three digits, no sign, no leading zero (`010` and `+10`
/// are names, not addresses).
fn octet(label: &[u8]) -> Option<u8> {
    let plain = (1..=3).contains(&label.len())
        && label.iter().all(u8::is_ascii_digit)
        && (label.len() == 1 || label[0] != b'0');
    if !plain {
        return None;
    }
    std::str::from_utf8(label).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse_lowercase_and_display_with_a_trailing_dot() {
        let name: Name = "NAS.Home.arpa".parse().unwrap();
        assert_eq!(name.to_string(), "nas.home.arpa.");
        assert_eq!(name.labels().len(), 3);
        assert_eq!("nas.home.arpa.".parse::<Name>().unwrap(), name);
        assert_eq!(".".parse::<Name>().unwrap(), Name::root());
        assert_eq!("".parse::<Name>().unwrap(), Name::root());
        assert_eq!(Name::root().to_string(), ".");
        assert_eq!(name.wire_len(), 1 + 3 + 1 + 4 + 1 + 4 + 1);
    }

    #[test]
    fn names_refuse_empty_long_labels_and_long_names() {
        assert_eq!("a..b".parse::<Name>(), Err(NameError::EmptyLabel));
        assert_eq!(
            format!("{}.x", "a".repeat(64)).parse::<Name>(),
            Err(NameError::LabelTooLong)
        );
        let long = std::iter::repeat_n("a".repeat(63), 5)
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(long.parse::<Name>(), Err(NameError::NameTooLong));
    }

    #[test]
    fn suffixes_parents_and_joins() {
        let domain: Name = "home.arpa".parse().unwrap();
        let nas: Name = "nas.home.arpa".parse().unwrap();
        assert!(nas.ends_with(&domain) && domain.ends_with(&domain) && !domain.ends_with(&nas));
        assert!(
            !"nothome.arpa".parse::<Name>().unwrap().ends_with(&domain),
            "label boundaries matter"
        );
        assert_eq!(nas.parent(), Some(domain.clone()));
        assert_eq!(Name::root().parent(), None);
        assert_eq!("nas".parse::<Name>().unwrap().join(&domain).unwrap(), nas);
    }

    #[test]
    fn reverse_names_round_trip() {
        let addr = Ipv4Addr::new(192, 168, 1, 10);
        assert_eq!(reverse_name(addr).to_string(), "10.1.168.192.in-addr.arpa.");
        assert_eq!(reverse_addr(&reverse_name(addr)), Some(addr));
        assert_eq!(
            reverse_addr(&"1.168.192.in-addr.arpa".parse().unwrap()),
            None
        );
        assert_eq!(reverse_addr(&"nas.home.arpa".parse().unwrap()), None);
    }

    #[test]
    fn display_escapes_what_is_not_a_plain_label_byte() {
        let name = Name::from_labels(vec![
            b"a b".to_vec(),
            b"x\ny".to_vec(),
            b"c.d".to_vec(),
            b"ok-1".to_vec(),
        ])
        .unwrap();
        assert_eq!(name.to_string(), r"a\032b.x\010y.c\.d.ok-1.");
        assert_eq!(
            "nas.home.arpa".parse::<Name>().unwrap().to_string(),
            "nas.home.arpa."
        );
    }

    #[test]
    fn reverse_names_need_plain_decimal_octets() {
        assert_eq!(
            reverse_addr(&"10.1.168.192.in-addr.arpa".parse().unwrap()),
            Some(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(
            reverse_addr(&"0.1.168.192.in-addr.arpa".parse().unwrap()),
            Some(Ipv4Addr::new(192, 168, 1, 0))
        );
        for odd in [
            "010.1.168.192.in-addr.arpa",
            "+10.1.168.192.in-addr.arpa",
            "1.168.192.in-addr.arpa",
            "256.1.168.192.in-addr.arpa",
        ] {
            assert_eq!(reverse_addr(&odd.parse().unwrap()), None, "{odd}");
        }
    }
}
