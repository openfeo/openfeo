// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

// The panel's built files as a table to embed (SPEC §8.4, ADR-0025). This file is included by
// `build.rs`, which runs it over `OPENFEO_PANEL_DIST`, and by `src/assets.rs`'s tests, which
// is why it is not a module of either: it uses nothing but `std`, `flate2` and `sha2`.

use std::fmt::Write as _;
use std::io::Write as _;

/// One file of the panel as it will sit in the binary.
#[derive(Debug)]
pub struct Built {
    /// Its path as a client asks for it, from `/`.
    pub path: String,
    /// What the `Content-Type` header says.
    pub content_type: &'static str,
    /// Whether `body` is gzip-compressed.
    pub gzip: bool,
    /// The `ETag`, quotes included: the first 16 hex digits of the SHA-256 of the file.
    pub etag: String,
    /// The bytes to embed: compressed when `gzip`, the file itself otherwise.
    pub body: Vec<u8>,
}

/// More than this in a panel directory is the wrong directory.
const MAX_TOTAL: usize = 8 * 1024 * 1024;

/// The content type for a file by its extension, or `None` for one the panel is not expected
/// to hold: a new kind of file is added here on purpose, not served by guesswork.
#[must_use]
pub fn content_type(path: &str) -> Option<&'static str> {
    let (_, extension) = path.rsplit_once('.')?;
    Some(match extension {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript",
        "css" => "text/css",
        "svg" => "image/svg+xml",
        "txt" => "text/plain; charset=utf-8",
        "json" => "application/json",
        "woff2" => "font/woff2",
        "png" => "image/png",
        "ico" => "image/x-icon",
        _ => return None,
    })
}

/// Fonts and bitmaps are compressed already; everything else is text.
fn compresses(content_type: &str) -> bool {
    !matches!(content_type, "font/woff2" | "image/png" | "image/x-icon")
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    // The default header carries no time and no name, so the same file gives the same bytes.
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(bytes)
        .and_then(|()| encoder.finish())
        .map_err(|err| format!("gzip: {err}"))
}

fn etag(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(bytes);
    let mut tag = String::from("\"");
    for byte in &digest[..8] {
        let _ = write!(tag, "{byte:02x}");
    }
    tag.push('"');
    tag
}

fn walk(
    dir: &std::path::Path,
    prefix: &str,
    total: &mut usize,
    out: &mut Vec<Built>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("{}: {err}", dir.display()))?;
        let on_disk = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{}: a name that is not UTF-8", on_disk.display()))?;
        let path = format!("{prefix}/{name}");
        // The entry's own type: a symlink is not followed.
        let kind = entry
            .file_type()
            .map_err(|err| format!("{}: {err}", on_disk.display()))?;
        if kind.is_dir() {
            walk(&on_disk, &path, total, out)?;
        } else if kind.is_file() {
            let content_type = content_type(&name).ok_or_else(|| {
                format!("{path}: no content type is known for this kind of file")
            })?;
            let bytes =
                std::fs::read(&on_disk).map_err(|err| format!("{}: {err}", on_disk.display()))?;
            *total += bytes.len();
            if *total > MAX_TOTAL {
                return Err(format!(
                    "more than 8 MiB of files (at {path}): that is not a panel"
                ));
            }
            let gzip_it = compresses(content_type);
            out.push(Built {
                etag: etag(&bytes),
                body: if gzip_it { gzip(&bytes)? } else { bytes },
                gzip: gzip_it,
                content_type,
                path,
            });
        } else {
            return Err(format!("{path}: neither a file nor a directory"));
        }
    }
    Ok(())
}

/// Every file under `dist`, sorted by path. A directory with no `index.html`, with a file
/// whose type is not known, with a symlink in it, or too large to be a panel is an error
/// that names what is wrong.
///
/// # Errors
///
/// A line that says which file or directory is wrong and why.
pub fn build_table(dist: &std::path::Path) -> Result<Vec<Built>, String> {
    let mut out = Vec::new();
    walk(dist, "", &mut 0, &mut out)?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    if !out.iter().any(|file| file.path == "/index.html") {
        return Err(format!("{}: no index.html", dist.display()));
    }
    Ok(out)
}
