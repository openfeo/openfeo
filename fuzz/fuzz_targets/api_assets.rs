// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Fuzz the serving of the panel's files (SPEC §8.4, §11): an arbitrary path, an arbitrary
//! `Accept-Encoding` and an arbitrary `If-None-Match` (the input's first three lines) never
//! panic, are answered 200, 304 or 404, and a 200 carries the right file whichever way it
//! is encoded. A compressed body goes only to a client that named gzip or `*`.

#![no_main]

use std::io::{Read as _, Write as _};
use std::sync::OnceLock;
use std::future::Future as _;
use std::task::{Context, Poll, Waker};

use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, IF_NONE_MATCH};
use http::{HeaderMap, HeaderValue, Method};
use libfuzzer_sys::fuzz_target;
use openfeo_api::assets::{Asset, serve};

const PAGE: &[u8] = b"<!doctype html><title>OpenFeO</title><div id=\"app\"></div>\n";
const SCRIPT: &[u8] = b"console.log('the panel');\n";
const FONT: &[u8] = b"wOF2 not really a font";

fn gzip(bytes: &[u8]) -> &'static [u8] {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(bytes).expect("gzip into memory");
    Box::leak(encoder.finish().expect("gzip into memory").into_boxed_slice())
}

/// Three files, sorted by path as the build leaves them, with the bytes each stands for.
fn table() -> &'static [(Asset, &'static [u8])] {
    static TABLE: OnceLock<Vec<(Asset, &'static [u8])>> = OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            (
                Asset {
                    path: "/assets/app-1a2b3c4d.js",
                    content_type: "text/javascript",
                    gzip: true,
                    etag: "\"1111111111111111\"",
                    body: gzip(SCRIPT),
                },
                SCRIPT,
            ),
            (
                Asset {
                    path: "/assets/sans-5e6f7a8b.woff2",
                    content_type: "font/woff2",
                    gzip: false,
                    etag: "\"2222222222222222\"",
                    body: FONT,
                },
                FONT,
            ),
            (
                Asset {
                    path: "/index.html",
                    content_type: "text/html; charset=utf-8",
                    gzip: true,
                    etag: "\"3333333333333333\"",
                    body: gzip(PAGE),
                },
                PAGE,
            ),
        ]
    })
}

fn assets() -> &'static [Asset] {
    static ASSETS: OnceLock<Vec<Asset>> = OnceLock::new();
    ASSETS.get_or_init(|| {
        table()
            .iter()
            .map(|(asset, _)| Asset {
                path: asset.path,
                content_type: asset.content_type,
                gzip: asset.gzip,
                etag: asset.etag,
                body: asset.body,
            })
            .collect()
    })
}

/// The whole body of a response made from memory: ready at the first poll.
fn body_of<B>(response: http::Response<B>) -> Vec<u8>
where
    B: http_body_util::BodyExt,
    B::Error: std::fmt::Debug,
{
    let mut collect = std::pin::pin!(response.into_body().collect());
    match collect
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(body)) => body.to_bytes().to_vec(),
        Poll::Ready(Err(err)) => panic!("the body failed: {err:?}"),
        Poll::Pending => panic!("a body held in memory was not ready"),
    }
}

fn inflate(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut out)
        .expect("what goes out as gzip is gzip");
    out
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut lines = text.splitn(3, '\n');
    let path = lines.next().unwrap_or_default();
    let accept = lines.next();
    let held = lines.next();
    let mut headers = HeaderMap::new();
    if let Some(Ok(value)) = accept.map(HeaderValue::from_str) {
        headers.insert(ACCEPT_ENCODING, value);
    }
    if let Some(Ok(value)) = held.map(HeaderValue::from_str) {
        headers.insert(IF_NONE_MATCH, value);
    }

    let response = serve(assets(), &Method::GET, path, &headers);
    let status = response.status().as_u16();
    let file = table()
        .iter()
        .find(|(asset, _)| asset.path == path || (path == "/" && asset.path == "/index.html"));
    match status {
        404 => {
            assert!(
                file.is_none() && path.starts_with("/assets/"),
                "{path:?} is not a missing asset"
            );
            assert!(body_of(response).is_empty(), "a 404 has no body");
        }
        304 => {
            assert!(
                headers.contains_key(IF_NONE_MATCH),
                "304 to a client that holds nothing"
            );
            assert!(body_of(response).is_empty(), "a 304 has no body");
        }
        200 => {
            let zipped = response.headers().get(CONTENT_ENCODING).is_some();
            if zipped {
                let named = accept.is_some_and(|accept| {
                    accept.to_ascii_lowercase().contains("gzip") || accept.contains('*')
                });
                assert!(named, "gzip to a client that did not ask: {accept:?}");
            }
            let body = body_of(response);
            let plain = if zipped { inflate(&body) } else { body };
            // A path that is not a file is the page, unless it is under /assets/ (a 404).
            let wanted = file.map_or(PAGE, |(_, plain)| plain);
            assert!(plain == wanted, "{path:?} was answered with another file");
        }
        other => panic!("{other} for {path:?}"),
    }

    let head = serve(assets(), &Method::HEAD, path, &headers);
    assert_eq!(head.status().as_u16(), status, "HEAD and GET disagree");
    assert!(body_of(head).is_empty(), "a HEAD has no body");
});
