// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! Compile `proto/openfeo/v1/*.proto` with protox (a pure-Rust compiler, so no `protoc` is
//! needed), then generate the prost types and their pbjson serde impls. pbjson keeps the proto
//! field names on serialisation so the TOML on disk reads as SPEC §8.2 shows it.

use std::fmt::Write as _;
use std::path::PathBuf;

use protox::prost_reflect::prost_types::{DescriptorProto, FileDescriptorSet};

/// The one package the proto files declare.
const PACKAGE: &str = "openfeo.v1";

/// What makes a field a secret by its name: any of these in it. `pass` is for a password and
/// a passphrase; `key` and `hash` also catch what is no secret (a public key, a checksum),
/// and such a field then wants a `Debug` written by hand all the same, or another name.
const SECRET_WORDS: [&str; 8] = [
    "pass",
    "token",
    "secret",
    "hash",
    "key",
    "psk",
    "credential",
    "cookie",
];

/// `FieldDescriptorProto.Type`: a string, bytes, and a message (which is what a map is).
const TYPE_STRING: i32 = 9;
const TYPE_BYTES: i32 = 12;
const TYPE_MESSAGE: i32 = 11;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    println!("cargo:rerun-if-changed={}", proto_root.display());
    let out = PathBuf::from(std::env::var("OUT_DIR")?);

    let fds = protox::compile(
        [
            "openfeo/v1/config.proto",
            "openfeo/v1/state.proto",
            "openfeo/v1/events.proto",
            "openfeo/v1/api.proto",
        ],
        [proto_root],
    )?;
    let bytes = prost::Message::encode_to_vec(&fds);
    std::fs::write(out.join("descriptors.bin"), &bytes)?;

    // A message with a field that is a secret by its name gets no derived `Debug`: it does
    // not compile inside another message until its `Debug` is written by hand, which
    // `src/secrets.rs` does, so that a password, a token or a hash is never printed, by the
    // message or by anything that holds it. A test there holds the list to what it expects.
    let secrets = secret_fields(&fds);
    std::fs::write(out.join("secret_fields.rs"), listing(&secrets)?)?;
    prost_build::Config::new()
        .out_dir(&out)
        .skip_debug(
            secrets
                .iter()
                .map(|(message, _)| format!(".{PACKAGE}.{message}")),
        )
        .compile_fds(fds)?;
    pbjson_build::Builder::new()
        .register_descriptors(&bytes)?
        .preserve_proto_field_names()
        .out_dir(&out)
        .build(&[".openfeo.v1"])?;
    Ok(())
}

/// Every field of the wire that is a secret by its name, as `(message, field)` with the
/// message's path under the package (`Admin`, `Outer.Inner`), in order: a string or bytes
/// field, or a map to strings or bytes, whose name has one of [`SECRET_WORDS`] in it.
fn secret_fields(fds: &FileDescriptorSet) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for file in &fds.file {
        if file.package() != PACKAGE {
            continue;
        }
        let mut pending: Vec<_> = file
            .message_type
            .iter()
            .map(|message| (message.name().to_owned(), message))
            .collect();
        while let Some((path, message)) = pending.pop() {
            // A map is a repeated nested message of a key and a value, marked as an entry.
            // The entry is not a message of ours (its `key` is no secret): the map's field
            // in the message that holds it answers for it.
            if is_map_entry(message) {
                continue;
            }
            let maps_to_text = |type_name: &str| {
                message.nested_type.iter().any(|entry| {
                    is_map_entry(entry)
                        && type_name == format!(".{PACKAGE}.{path}.{}", entry.name())
                        && entry.field.iter().any(|value| {
                            value.number() == 2
                                && matches!(value.r#type, Some(TYPE_STRING | TYPE_BYTES))
                        })
                })
            };
            for field in &message.field {
                let text = match field.r#type {
                    Some(TYPE_STRING | TYPE_BYTES) => true,
                    Some(TYPE_MESSAGE) => maps_to_text(field.type_name()),
                    _ => false,
                };
                if text && SECRET_WORDS.iter().any(|word| field.name().contains(word)) {
                    found.push((path.clone(), field.name().to_owned()));
                }
            }
            for nested in &message.nested_type {
                pending.push((format!("{path}.{}", nested.name()), nested));
            }
        }
    }
    found.sort();
    found
}

/// Whether a message is the entry the compiler makes for a `map<…>` field.
fn is_map_entry(message: &DescriptorProto) -> bool {
    message
        .options
        .as_ref()
        .and_then(|options| options.map_entry)
        == Some(true)
}

/// The list as Rust source, for the test in `src/secrets.rs` to read.
fn listing(secrets: &[(String, String)]) -> Result<String, std::fmt::Error> {
    let mut source = String::from(
        "/// Every field of the wire that is a secret by its name, as `build.rs` found them.\n\
         const SECRET_FIELDS: &[(&str, &str)] = &[\n",
    );
    for (message, field) in secrets {
        writeln!(source, "    ({message:?}, {field:?}),")?;
    }
    source.push_str("];\n");
    Ok(source)
}
