// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The panel's files, embedded at build time and served from memory (SPEC §8.4, ADR-0025).
//!
//! `build.rs` makes the table from the directory `OPENFEO_PANEL_DIST` names. Text is held
//! gzip-compressed and sent that way to a client that takes it; a file under `/assets/` has a
//! hash in its name and is cached for good, and everything else is revalidated by its `ETag`.
//! A binary built without a panel holds an empty table and serves a placeholder page.

use std::io::Read as _;

use axum::body::Body;
use axum::http::header::{
    ACCEPT_ENCODING, ALLOW, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG,
    IF_NONE_MATCH, VARY,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::PLACEHOLDER_PAGE;

/// One embedded file.
#[derive(Debug)]
pub struct Asset {
    /// Its path as a client asks for it, from `/`.
    pub path: &'static str,
    /// What the `Content-Type` header says.
    pub content_type: &'static str,
    /// Whether `body` is gzip-compressed.
    pub gzip: bool,
    /// The `ETag`, quotes included.
    pub etag: &'static str,
    /// The bytes held: compressed when `gzip`, the file itself otherwise.
    pub body: &'static [u8],
}

/// The panel built into this binary; empty when it was built without one.
pub static PANEL: &[Asset] = include!(concat!(env!("OUT_DIR"), "/panel_assets.rs"));

/// The page every route of the panel is.
const PAGE: &str = "/index.html";
/// Where the files with a hash in their name are: never the page, and cached for good.
const HASHED: &str = "/assets/";
const FOR_GOOD: &str = "public, max-age=31536000, immutable";
const REVALIDATE: &str = "no-cache";

fn find(table: &'static [Asset], path: &str) -> Option<&'static Asset> {
    let path = if path == "/" { PAGE } else { path };
    table
        .binary_search_by(|asset| asset.path.cmp(path))
        .ok()
        .and_then(|at| table.get(at))
}

/// Whether an `Accept-Encoding` header takes gzip: `gzip` (or `x-gzip`) named with a weight
/// that is not zero, or `*` when gzip is not named.
fn takes_gzip(headers: &HeaderMap) -> bool {
    let (mut named, mut any) = (None, None);
    for value in headers.get_all(ACCEPT_ENCODING) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for entry in value.split(',') {
            let mut parts = entry.split(';');
            let coding = parts.next().unwrap_or_default().trim();
            let wanted = parts
                .find_map(|param| {
                    let (key, weight) = param.split_once('=')?;
                    key.trim()
                        .eq_ignore_ascii_case("q")
                        .then_some(weight.trim())
                })
                .is_none_or(|weight| weight.parse::<f32>().is_ok_and(|q| q > 0.0));
            if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
                named = Some(wanted);
            } else if coding == "*" {
                any = Some(wanted);
            }
        }
    }
    named.or(any).unwrap_or(false)
}

/// Whether the client already holds the file: its `If-None-Match` lists the tag (a weak
/// form of it will do) or is `*`.
fn holds(headers: &HeaderMap, etag: &str) -> bool {
    headers.get_all(IF_NONE_MATCH).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|held| held == "*" || held == etag || held.strip_prefix("W/") == Some(etag))
        })
    })
}

fn respond(asset: &'static Asset, headers: &HeaderMap, head: bool) -> Response {
    let cache = if asset.path.starts_with(HASHED) {
        FOR_GOOD
    } else {
        REVALIDATE
    };
    let mut response = if holds(headers, asset.etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let zipped = asset.gzip && takes_gzip(headers);
        let body: std::borrow::Cow<'static, [u8]> = if asset.gzip && !zipped {
            let mut plain = Vec::new();
            if flate2::read::GzDecoder::new(asset.body)
                .read_to_end(&mut plain)
                .is_err()
            {
                // The build compressed it; this cannot happen to a table the build made.
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            plain.into()
        } else {
            asset.body.into()
        };
        let length = body.len();
        let mut response = if head {
            Response::new(Body::empty())
        } else {
            Response::new(Body::from(body))
        };
        let out = response.headers_mut();
        out.insert(CONTENT_TYPE, HeaderValue::from_static(asset.content_type));
        out.insert(CONTENT_LENGTH, HeaderValue::from(length));
        if zipped {
            out.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        }
        response
    };
    let out = response.headers_mut();
    out.insert(ETAG, HeaderValue::from_static(asset.etag));
    out.insert(CACHE_CONTROL, HeaderValue::from_static(cache));
    if asset.gzip {
        out.insert(VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    response
}

/// Answer a request for one of the panel's files out of `table` (sorted by path, as the
/// build leaves it). `/` and any path that is not a file are the page, so the panel's own
/// routes survive a reload; a path under `/assets/` that is not a file is `404`, so a page
/// left open across an update is not handed HTML where it asked for a script.
#[must_use]
pub fn serve(
    table: &'static [Asset],
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> Response {
    let head = method == Method::HEAD;
    if !head && method != Method::GET {
        return (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, "GET, HEAD")]).into_response();
    }
    if let Some(asset) = find(table, path) {
        return respond(asset, headers, head);
    }
    if path.starts_with(HASHED) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match find(table, PAGE) {
        Some(page) => respond(page, headers, head),
        // Built without a panel (ADR-0025): say so.
        None if head => ([(CONTENT_TYPE, "text/html; charset=utf-8")], "").into_response(),
        None => (
            [(CONTENT_TYPE, "text/html; charset=utf-8")],
            PLACEHOLDER_PAGE,
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use axum::http::header::{
        ACCEPT_ENCODING, ALLOW, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
        ETAG, IF_NONE_MATCH, VARY,
    };
    use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
    use axum::response::Response;

    use super::*;

    /// The table builder, as `build.rs` runs it.
    mod built {
        include!("../build/assets.rs");
    }

    const PAGE: &str = "<!doctype html><title>OpenFeO</title><div id=\"app\"></div>\n";
    const SCRIPT: &str = "console.log('the panel');\n";
    const FONT: &[u8] = b"wOF2\0\x01\x02\x03 not really a font";

    fn write(dir: &Path, name: &str, bytes: &[u8]) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn dist() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "index.html", PAGE.as_bytes());
        write(dir.path(), "assets/app-1a2b3c4d.js", SCRIPT.as_bytes());
        write(dir.path(), "assets/sans-5e6f7a8b.woff2", FONT);
        write(dir.path(), "licences.txt", b"MIT text\n");
        dir
    }

    /// The table the build would embed for `dist()`, kept for the life of the test process.
    fn table() -> &'static [Asset] {
        let built = built::build_table(dist().path()).unwrap();
        let assets: Vec<Asset> = built
            .into_iter()
            .map(|file| Asset {
                path: Box::leak(file.path.into_boxed_str()),
                content_type: file.content_type,
                gzip: file.gzip,
                etag: Box::leak(file.etag.into_boxed_str()),
                body: Box::leak(file.body.into_boxed_slice()),
            })
            .collect();
        Box::leak(assets.into_boxed_slice())
    }

    fn headers(pairs: &[(axum::http::HeaderName, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| (name.clone(), HeaderValue::from_str(value).unwrap()))
            .collect()
    }

    fn get(path: &str, with: &[(axum::http::HeaderName, &str)]) -> Response {
        serve(table(), &Method::GET, path, &headers(with))
    }

    fn header<'a>(response: &'a Response, name: &axum::http::HeaderName) -> Option<&'a str> {
        response.headers().get(name).and_then(|v| v.to_str().ok())
    }

    async fn body(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    fn inflate(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[tokio::test]
    async fn the_page_answers_root_and_any_route_of_the_panel() {
        for path in ["/", "/index.html", "/wan/wan0", "/login"] {
            let response = get(path, &[]);
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                header(&response, &CONTENT_TYPE),
                Some("text/html; charset=utf-8"),
                "{path}"
            );
            assert_eq!(body(response).await, PAGE.as_bytes(), "{path}");
        }
        let notices = get("/licences.txt", &[]);
        assert_eq!(
            header(&notices, &CONTENT_TYPE),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(body(notices).await, b"MIT text\n");
    }

    #[tokio::test]
    async fn a_missing_asset_is_404_not_the_page() {
        // A tab left open across an update asks for a file the new binary does not have; the
        // page's HTML served as JavaScript would be a blank screen with no reason given.
        for path in [
            "/assets/app-00000000.js",
            "/assets/",
            "/assets/../index.html",
        ] {
            let response = get(path, &[]);
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(body(response).await.is_empty(), "{path}");
        }
    }

    #[test]
    fn a_hashed_file_is_cached_for_good_and_the_page_is_revalidated() {
        let script = get("/assets/app-1a2b3c4d.js", &[]);
        assert_eq!(
            header(&script, &CACHE_CONTROL),
            Some("public, max-age=31536000, immutable")
        );
        for path in ["/", "/licences.txt", "/some/route"] {
            assert_eq!(
                header(&get(path, &[]), &CACHE_CONTROL),
                Some("no-cache"),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn gzip_goes_to_a_client_that_takes_it_and_is_inflated_for_one_that_does_not() {
        let path = "/assets/app-1a2b3c4d.js";
        for accepts in [
            "gzip",
            "gzip, br",
            "br;q=1.0, gzip;q=0.5",
            "*",
            "x-gzip",
            "GZIP",
        ] {
            let response = get(path, &[(ACCEPT_ENCODING, accepts)]);
            assert_eq!(
                header(&response, &CONTENT_ENCODING),
                Some("gzip"),
                "{accepts}"
            );
            assert_eq!(header(&response, &VARY), Some("Accept-Encoding"));
            assert_eq!(header(&response, &CONTENT_TYPE), Some("text/javascript"));
            assert_eq!(
                inflate(&body(response).await),
                SCRIPT.as_bytes(),
                "{accepts}"
            );
        }
        for refuses in [
            None,
            Some("identity"),
            Some("br"),
            Some("gzip;q=0"),
            Some("gzip; q=0.0, *"),
            Some("*;q=0"),
            Some(""),
        ] {
            let with: Vec<_> = refuses
                .map(|value| (ACCEPT_ENCODING, value))
                .into_iter()
                .collect();
            let response = get(path, &with);
            assert_eq!(header(&response, &CONTENT_ENCODING), None, "{refuses:?}");
            assert_eq!(header(&response, &VARY), Some("Accept-Encoding"));
            assert_eq!(body(response).await, SCRIPT.as_bytes(), "{refuses:?}");
        }
        // A font is compressed already and is stored as it is, whatever the client takes.
        let font = get("/assets/sans-5e6f7a8b.woff2", &[(ACCEPT_ENCODING, "gzip")]);
        assert_eq!(header(&font, &CONTENT_ENCODING), None);
        assert_eq!(header(&font, &CONTENT_TYPE), Some("font/woff2"));
        assert_eq!(body(font).await, FONT);
    }

    #[tokio::test]
    async fn an_etag_the_client_holds_gets_304() {
        let first = get("/", &[]);
        let tag = header(&first, &ETAG).unwrap().to_owned();
        assert!(
            tag.starts_with('"') && tag.ends_with('"') && tag.len() == 18,
            "{tag}"
        );
        for held in [
            tag.clone(),
            format!("\"something-else\", {tag}"),
            format!("W/{tag}"),
            "*".to_owned(),
        ] {
            let response = get("/", &[(IF_NONE_MATCH, &held)]);
            assert_eq!(response.status(), StatusCode::NOT_MODIFIED, "{held}");
            assert_eq!(header(&response, &ETAG), Some(tag.as_str()));
            assert_eq!(header(&response, &CACHE_CONTROL), Some("no-cache"));
            assert!(body(response).await.is_empty(), "{held}");
        }
        let other = get("/", &[(IF_NONE_MATCH, "\"0123456789abcdef\"")]);
        assert_eq!(other.status(), StatusCode::OK);
        // The same file has the same tag however it is asked for.
        assert_eq!(header(&get("/index.html", &[]), &ETAG), Some(tag.as_str()));
        assert_ne!(
            header(&get("/licences.txt", &[]), &ETAG),
            Some(tag.as_str())
        );
    }

    #[tokio::test]
    async fn head_carries_the_length_and_no_body() {
        let path = "/assets/app-1a2b3c4d.js";
        let plain = serve(table(), &Method::HEAD, path, &HeaderMap::new());
        assert_eq!(plain.status(), StatusCode::OK);
        assert_eq!(
            header(&plain, &CONTENT_LENGTH),
            Some(SCRIPT.len().to_string().as_str())
        );
        assert_eq!(body(plain).await.len(), 0);
        let wanted = headers(&[(ACCEPT_ENCODING, "gzip")]);
        let zipped_len = body(serve(table(), &Method::GET, path, &wanted))
            .await
            .len();
        let zipped = serve(table(), &Method::HEAD, path, &wanted);
        assert_eq!(
            header(&zipped, &CONTENT_LENGTH),
            Some(zipped_len.to_string().as_str())
        );
        assert_eq!(header(&zipped, &CONTENT_ENCODING), Some("gzip"));
        assert_eq!(body(zipped).await.len(), 0);
    }

    #[test]
    fn only_get_and_head() {
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
            let response = serve(table(), &method, "/", &HeaderMap::new());
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method}"
            );
            assert_eq!(header(&response, &ALLOW), Some("GET, HEAD"));
        }
    }

    #[tokio::test]
    async fn without_a_built_panel_the_placeholder_is_served() {
        for path in ["/", "/licences.txt", "/any/route"] {
            let response = serve(&[], &Method::GET, path, &HeaderMap::new());
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let text = String::from_utf8(body(response).await).unwrap();
            assert!(
                text.contains("The panel was not built into this binary"),
                "{path}"
            );
        }
        let asset = serve(&[], &Method::GET, "/assets/app.js", &HeaderMap::new());
        assert_eq!(asset.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn the_table_is_sorted_typed_and_tagged() {
        let built = built::build_table(dist().path()).unwrap();
        let paths: Vec<&str> = built.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/assets/app-1a2b3c4d.js",
                "/assets/sans-5e6f7a8b.woff2",
                "/index.html",
                "/licences.txt"
            ]
        );
        let script = &built[0];
        assert_eq!(script.content_type, "text/javascript");
        assert!(script.gzip);
        assert_eq!(inflate(&script.body), SCRIPT.as_bytes());
        assert_eq!(script.etag.len(), 18);
        let font = &built[1];
        assert!(!font.gzip);
        assert_eq!(font.body, FONT);
        // The same bytes give the same table: a build is reproducible.
        let again = built::build_table(dist().path()).unwrap();
        assert_eq!(again[0].body, script.body);
        assert_eq!(again[0].etag, script.etag);
        for (name, wanted) in [
            ("a.html", "text/html; charset=utf-8"),
            ("a.css", "text/css"),
            ("a.svg", "image/svg+xml"),
            ("a.json", "application/json"),
            ("a.png", "image/png"),
            ("a.ico", "image/x-icon"),
        ] {
            assert_eq!(built::content_type(name), Some(wanted), "{name}");
        }
        assert_eq!(built::content_type("a.map"), None);
        assert_eq!(built::content_type("Makefile"), None);
    }

    #[test]
    fn an_unknown_extension_names_its_file() {
        let dir = dist();
        write(dir.path(), "assets/notes.md", b"# notes\n");
        let err = built::build_table(dir.path()).unwrap_err();
        assert!(err.contains("notes.md"), "{err}");
    }

    #[test]
    fn a_directory_without_a_page_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "assets/app.js", b"x");
        let err = built::build_table(dir.path()).unwrap_err();
        assert!(err.contains("index.html"), "{err}");
        let missing = built::build_table(&dir.path().join("nowhere")).unwrap_err();
        assert!(missing.contains("nowhere"), "{missing}");
    }

    #[test]
    fn a_symlink_is_refused() {
        let dir = dist();
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("assets/host.txt")).unwrap();
        let err = built::build_table(dir.path()).unwrap_err();
        assert!(err.contains("host.txt"), "{err}");
    }

    #[test]
    fn more_than_a_panel_is_refused() {
        let dir = dist();
        write(
            dir.path(),
            "assets/huge.js",
            &vec![b'x'; 8 * 1024 * 1024 + 1],
        );
        let err = built::build_table(dir.path()).unwrap_err();
        assert!(err.contains("8 MiB"), "{err}");
    }
}
