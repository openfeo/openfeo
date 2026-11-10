// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The listener's certificate (SPEC §9, ADR-0024): ECDSA P-256, self-signed, naming the
//! hostname and `<hostname>.<domain>`, with `serverAuth`, valid for 825 days because macOS
//! refuses anything longer, and reissued with the same key. Deciding what to do is a pure
//! function of the clock and a small record kept beside the certificate, so no X.509 parser is
//! needed in the binary.

use std::fs;
use std::io;
use std::path::Path;

use openfeo_config::System;
use openfeo_config::load::{DEFAULT_DOMAIN, DEFAULT_HOSTNAME, STATE_FILE_MODE};
use openfeo_platform::atomic;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::limits::{CERT_DAYS, CERT_RENEW_DAYS};

const DAY: u64 = 86_400;
const CERT_FILE: &str = "cert.der";
const KEY_FILE: &str = "key.pem";
const META_FILE: &str = "cert.toml";
/// The certificate is world-readable; the key is not.
const CERT_FILE_MODE: u32 = 0o644;

/// What the certificate code needs to know about time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// The wall clock, in Unix seconds.
    pub now_unix: u64,
    /// Whether SNTP has set it (SPEC §7.10); until then it is a guess.
    pub synced: bool,
    /// The build's epoch, the clock's floor.
    pub build_epoch: u64,
}

/// What is recorded beside a certificate, so that deciding needs no parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertMeta {
    /// Its subject alternative names.
    pub names: Vec<String>,
    /// Start of validity, in Unix seconds.
    pub not_before_unix: u64,
    /// End of validity, in Unix seconds.
    pub not_after_unix: u64,
    /// Issued before the clock was synced: its dates rest on the build's epoch.
    pub on_a_guess: bool,
}

/// What to do about the certificate now.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Action {
    /// It stands.
    Keep,
    /// There is none: make a key and a certificate.
    Issue,
    /// Make a new certificate with the same key.
    Reissue(Why),
}

/// Why a certificate is reissued.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Why {
    /// The hostname or domain changed.
    Names,
    /// Fewer than 60 days remain.
    Expiring,
    /// It was issued on a guess, and the clock now says it is expired or not yet valid.
    ClockNowKnown,
}

impl Why {
    /// The words for the console.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Why::Names => "names changed",
            Why::Expiring => "expiring",
            Why::ClockNowKnown => "clock now known",
        }
    }
}

/// A certificate cannot be made, read or kept.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// The key or the certificate could not be generated.
    #[error("certificate: {0}")]
    Generate(String),
    /// A file under the TLS directory.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: std::path::PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The record beside the certificate does not parse.
    #[error("{0}")]
    Meta(String),
}

/// Decide from the record of the certificate held (if any), the names it should carry and the
/// clock. Without a synced clock no judgement about expiry is made.
#[must_use]
pub fn decide(meta: Option<&CertMeta>, names: &[String], clock: &Clock) -> Action {
    let Some(meta) = meta else {
        return Action::Issue;
    };
    if meta.names != names {
        return Action::Reissue(Why::Names);
    }
    if !clock.synced {
        return Action::Keep;
    }
    let now = clock.now_unix;
    if meta.on_a_guess && (now >= meta.not_after_unix || now < meta.not_before_unix) {
        return Action::Reissue(Why::ClockNowKnown);
    }
    if meta.not_after_unix.saturating_sub(now) < u64::from(CERT_RENEW_DAYS) * DAY {
        return Action::Reissue(Why::Expiring);
    }
    Action::Keep
}

/// A certificate just made.
pub struct Issued {
    /// The certificate, DER.
    pub cert_der: Vec<u8>,
    /// Its private key, PEM (PKCS#8).
    pub key_pem: String,
    /// The record to keep beside it.
    pub meta: CertMeta,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key.
        f.debug_struct("Issued")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

fn at(unix: u64) -> Result<OffsetDateTime, CertError> {
    i64::try_from(unix)
        .ok()
        .and_then(|unix| OffsetDateTime::from_unix_timestamp(unix).ok())
        .ok_or_else(|| CertError::Generate(format!("{unix} is not a date")))
}

/// Make a certificate for `names`, with `key_pem` when reissuing or a new P-256 key. Its
/// validity starts a day before now, or a day before the build's epoch while the clock is a
/// guess, and runs 825 days.
///
/// # Errors
///
/// When the key does not parse or the certificate cannot be generated.
pub fn issue(key_pem: Option<&str>, names: &[String], clock: &Clock) -> Result<Issued, CertError> {
    let generate = |err: rcgen::Error| CertError::Generate(err.to_string());
    let key = match key_pem {
        Some(pem) => KeyPair::from_pem(pem).map_err(generate)?,
        None => KeyPair::generate().map_err(generate)?,
    };
    let base = if clock.synced {
        clock.now_unix
    } else {
        clock.build_epoch
    };
    let not_before_unix = base.saturating_sub(DAY);
    let not_after_unix = not_before_unix + u64::from(CERT_DAYS) * DAY;
    let mut params = CertificateParams::new(names.to_vec()).map_err(generate)?;
    params.not_before = at(not_before_unix)?;
    params.not_after = at(not_after_unix)?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if let Some(hostname) = names.first() {
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname.clone());
    }
    let cert = params.self_signed(&key).map_err(generate)?;
    Ok(Issued {
        cert_der: cert.der().to_vec(),
        key_pem: key.serialize_pem(),
        meta: CertMeta {
            names: names.to_vec(),
            not_before_unix,
            not_after_unix,
            on_a_guess: !clock.synced,
        },
    })
}

/// SHA-256 of the certificate as the console and browsers print it: `3F:9A:...`.
#[must_use]
pub fn fingerprint(cert_der: &[u8]) -> String {
    Sha256::digest(cert_der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The names the certificate carries: the hostname and `<hostname>.<domain>`.
#[must_use]
pub fn names(system: Option<&System>) -> Vec<String> {
    let or_default = |value: Option<&str>, default: &str| {
        value
            .filter(|value| !value.is_empty())
            .unwrap_or(default)
            .to_ascii_lowercase()
    };
    let hostname = or_default(system.map(|s| s.hostname.as_str()), DEFAULT_HOSTNAME);
    let domain = or_default(system.map(|s| s.domain.as_str()), DEFAULT_DOMAIN);
    vec![hostname.clone(), format!("{hostname}.{domain}")]
}

fn io_error(path: &Path, source: io::Error) -> CertError {
    CertError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The certificate, key and record kept under `dir`, or `None` when any of the three is
/// missing (the certificate is then issued afresh).
///
/// # Errors
///
/// When a file is there and cannot be read, or the record does not parse.
pub fn load(dir: &Path) -> Result<Option<(Vec<u8>, String, CertMeta)>, CertError> {
    let read = |name: &str| -> Result<Option<Vec<u8>>, CertError> {
        let path = dir.join(name);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(io_error(&path, err)),
        }
    };
    let (Some(cert), Some(key), Some(meta)) = (read(CERT_FILE)?, read(KEY_FILE)?, read(META_FILE)?)
    else {
        return Ok(None);
    };
    let key = String::from_utf8(key).map_err(|_| CertError::Meta("key.pem is not text".into()))?;
    let meta = String::from_utf8(meta)
        .map_err(|_| CertError::Meta("cert.toml is not text".into()))
        .and_then(|text| {
            toml::from_str(&text).map_err(|err| CertError::Meta(format!("cert.toml: {err}")))
        })?;
    Ok(Some((cert, key, meta)))
}

/// Keep `issued` under `dir`: the key at mode 0600, each file written atomically, the record
/// last so that a certificate without its record is issued afresh.
///
/// # Errors
///
/// When the directory or a file cannot be written.
pub fn store(dir: &Path, issued: &Issued) -> Result<(), CertError> {
    fs::create_dir_all(dir).map_err(|err| io_error(dir, err))?;
    let meta = toml::to_string(&issued.meta).map_err(|err| CertError::Meta(err.to_string()))?;
    for (name, bytes, mode) in [
        (KEY_FILE, issued.key_pem.as_bytes(), STATE_FILE_MODE),
        (CERT_FILE, issued.cert_der.as_slice(), CERT_FILE_MODE),
        (META_FILE, meta.as_bytes(), CERT_FILE_MODE),
    ] {
        let path = dir.join(name);
        atomic::write(&path, bytes, mode).map_err(|err| io_error(&path, err))?;
    }
    Ok(())
}

fn ymd(unix: u64) -> String {
    at(unix).map_or_else(
        |_| "?".to_owned(),
        |when| {
            format!(
                "{:04}-{:02}-{:02}",
                when.year(),
                u8::from(when.month()),
                when.day()
            )
        },
    )
}

/// `tls: fingerprint sha256 3F:9A:...`.
#[must_use]
pub fn line_fingerprint(cert_der: &[u8]) -> String {
    format!("tls: fingerprint sha256 {}", fingerprint(cert_der))
}

/// `tls: certificate issued for openfeo, openfeo.home.arpa until 2029-02-12`.
#[must_use]
pub fn line_issued(meta: &CertMeta) -> String {
    format!(
        "tls: certificate issued for {} until {}",
        meta.names.join(", "),
        ymd(meta.not_after_unix)
    )
}

/// `tls: certificate reissued (expiring) until 2029-02-12`.
#[must_use]
pub fn line_reissued(why: Why, meta: &CertMeta) -> String {
    format!(
        "tls: certificate reissued ({}) until {}",
        why.as_str(),
        ymd(meta.not_after_unix)
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use x509_parser::extensions::GeneralName;

    use super::*;

    fn names() -> Vec<String> {
        vec!["openfeo".into(), "openfeo.home.arpa".into()]
    }

    fn spki(cert_der: &[u8]) -> Vec<u8> {
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der).unwrap();
        cert.public_key().raw.to_vec()
    }

    #[test]
    fn the_certificate_is_one_macos_accepts() {
        let clock = Clock {
            now_unix: 1_794_300_000,
            synced: true,
            build_epoch: 1_794_000_000,
        };
        let issued = issue(None, &names(), &clock).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&issued.cert_der).unwrap();
        let sans: Vec<String> = cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(dns) => Some((*dns).to_owned()),
                _ => None,
            })
            .collect();
        assert_eq!(sans, names());
        assert!(
            cert.extended_key_usage()
                .unwrap()
                .unwrap()
                .value
                .server_auth
        );
        let validity = cert.validity();
        assert_eq!(
            validity.not_after.timestamp() - validity.not_before.timestamp(),
            825 * 86_400
        );
        assert_eq!(
            u64::try_from(validity.not_before.timestamp()).unwrap(),
            clock.now_unix - DAY
        );
        assert_eq!(
            cert.public_key().algorithm.algorithm.to_id_string(),
            "1.2.840.10045.2.1",
            "an EC key"
        );
        assert_eq!(fingerprint(&issued.cert_der).len(), 32 * 3 - 1);
        assert!(!issued.meta.on_a_guess);
        assert!(!format!("{issued:?}").contains("PRIVATE KEY"));
    }

    #[test]
    fn a_certificate_issued_on_a_guess_is_reissued_once_the_clock_is_right() {
        let build = 1_700_000_000;
        let unsynced = Clock {
            now_unix: build,
            synced: false,
            build_epoch: build,
        };
        let first = issue(None, &names(), &unsynced).unwrap();
        assert!(first.meta.on_a_guess);
        assert_eq!(first.meta.not_before_unix, build - DAY);
        assert_eq!(decide(Some(&first.meta), &names(), &unsynced), Action::Keep);
        let three_years_on = Clock {
            now_unix: build + 1_095 * DAY,
            synced: true,
            build_epoch: build,
        };
        assert_eq!(
            decide(Some(&first.meta), &names(), &three_years_on),
            Action::Reissue(Why::ClockNowKnown)
        );
        let second = issue(Some(&first.key_pem), &names(), &three_years_on).unwrap();
        assert!(!second.meta.on_a_guess);
        assert_eq!(
            spki(&first.cert_der),
            spki(&second.cert_der),
            "the key is kept"
        );
        assert_ne!(fingerprint(&first.cert_der), fingerprint(&second.cert_der));
        assert_eq!(
            decide(Some(&second.meta), &names(), &three_years_on),
            Action::Keep
        );
    }

    #[test]
    fn the_decision_table() {
        let now = 1_794_300_000;
        let synced = Clock {
            now_unix: now,
            synced: true,
            build_epoch: now - DAY,
        };
        let meta = |after_days: u64, on_a_guess: bool| CertMeta {
            names: names(),
            not_before_unix: now - DAY,
            not_after_unix: now + after_days * DAY,
            on_a_guess,
        };
        assert_eq!(decide(None, &names(), &synced), Action::Issue);
        assert_eq!(
            decide(Some(&meta(400, false)), &["other".to_owned()], &synced),
            Action::Reissue(Why::Names)
        );
        assert_eq!(
            decide(Some(&meta(59, false)), &names(), &synced),
            Action::Reissue(Why::Expiring)
        );
        assert_eq!(
            decide(Some(&meta(61, false)), &names(), &synced),
            Action::Keep
        );
        // A guess that happens to be valid by the real clock is kept until it nears its end.
        assert_eq!(
            decide(Some(&meta(400, true)), &names(), &synced),
            Action::Keep
        );
        let unsynced = Clock {
            synced: false,
            ..synced
        };
        assert_eq!(
            decide(Some(&meta(1, false)), &names(), &unsynced),
            Action::Keep,
            "no clock, no judgement about expiry"
        );
        assert_eq!(
            decide(Some(&meta(1, false)), &["other".to_owned()], &unsynced),
            Action::Reissue(Why::Names),
            "names need no clock"
        );
    }

    #[test]
    fn store_then_load_round_trips_and_the_key_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let tls = dir.path().join("tls");
        assert!(load(&tls).unwrap().is_none());
        let clock = Clock {
            now_unix: 1_794_300_000,
            synced: true,
            build_epoch: 1_794_000_000,
        };
        let issued = issue(None, &names(), &clock).unwrap();
        store(&tls, &issued).unwrap();
        let (cert, key, meta) = load(&tls).unwrap().unwrap();
        assert_eq!(cert, issued.cert_der);
        assert_eq!(key, issued.key_pem);
        assert_eq!(meta, issued.meta);
        let mode = |name: &str| fs::metadata(tls.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("key.pem"), 0o600);
        fs::remove_file(tls.join("cert.toml")).unwrap();
        assert!(
            load(&tls).unwrap().is_none(),
            "a certificate without its record is issued afresh"
        );
    }

    #[test]
    fn the_names_are_the_hostname_and_its_full_name() {
        assert_eq!(names(), super::names(None));
        let system = System {
            hostname: "Gate".into(),
            domain: "Example.NET".into(),
            ..System::default()
        };
        assert_eq!(super::names(Some(&system)), ["gate", "gate.example.net"]);
    }

    #[test]
    fn the_console_lines_read_as_the_contract_says() {
        let meta = CertMeta {
            names: names(),
            not_before_unix: 1_794_213_600,
            not_after_unix: 1_794_213_600 + 825 * DAY,
            on_a_guess: false,
        };
        assert_eq!(
            line_issued(&meta),
            "tls: certificate issued for openfeo, openfeo.home.arpa until 2029-02-11"
        );
        assert_eq!(
            line_reissued(Why::Expiring, &meta),
            "tls: certificate reissued (expiring) until 2029-02-11"
        );
        assert_eq!(Why::Names.as_str(), "names changed");
        assert_eq!(Why::ClockNowKnown.as_str(), "clock now known");
        let line = line_fingerprint(b"anything");
        assert!(line.starts_with("tls: fingerprint sha256 "));
        assert_eq!(line.len(), "tls: fingerprint sha256 ".len() + 95);
    }
}
