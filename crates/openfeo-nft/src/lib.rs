// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! libnftables linked in-process (SPEC §2, ADR-0003, ADR-0012): [`Nft`] owns one context
//! configured for JSON in and out, applies a whole ruleset as one buffer (so one batch: atomic),
//! and lists the kernel's ruleset as JSON. `unsafe` lives in [`sys`] only.

#![deny(unsafe_code)]

#[allow(unsafe_code)]
pub mod sys;

use std::ffi::CString;

use serde_json::{Value, json};

/// What libnftables can go wrong with.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    /// `nft_ctx_new` or buffer setup failed (allocation).
    #[error("libnftables context could not be created")]
    Init,
    /// libnftables refused the command; `message` is its error text.
    #[error("libnftables rejected the command: {message}")]
    Rejected {
        /// The error buffer, trimmed.
        message: String,
    },
    /// The output was not the JSON document expected.
    #[error("libnftables output is not the expected JSON: {0}")]
    Output(String),
}

/// One libnftables context: JSON in (no DNS), JSON out (numeric everything), buffered output and
/// error text. One task uses it at a time (it is `Send`, not `Sync`).
pub struct Nft {
    ctx: sys::Ctx,
}

impl std::fmt::Debug for Nft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Nft")
    }
}

impl Nft {
    /// A fresh context. Opens no socket: capabilities matter only when a command runs.
    ///
    /// # Errors
    ///
    /// [`NftError::Init`] when libnftables cannot allocate the context or its buffers.
    pub fn new() -> Result<Self, NftError> {
        let mut ctx = sys::Ctx::new(sys::NFT_CTX_DEFAULT).ok_or(NftError::Init)?;
        ctx.set_input_flags(sys::NFT_CTX_INPUT_JSON | sys::NFT_CTX_INPUT_NO_DNS);
        ctx.set_output_flags(sys::NFT_CTX_OUTPUT_JSON | sys::NFT_CTX_OUTPUT_NUMERIC_ALL);
        if ctx.buffer_output() != 0 || ctx.buffer_error() != 0 {
            return Err(NftError::Init);
        }
        Ok(Nft { ctx })
    }

    /// Runs one JSON document (`{"nftables": [...]}`) and returns the raw output buffer.
    ///
    /// # Errors
    ///
    /// [`NftError::Rejected`] with libnftables' error text when the command fails; nothing of a
    /// failed document is committed.
    pub fn run(&mut self, command: &str) -> Result<String, NftError> {
        let command = CString::new(command).map_err(|_| NftError::Rejected {
            message: "command contains a NUL byte".to_owned(),
        })?;
        let rc = self.ctx.run(&command);
        if rc != 0 {
            let mut message = self.ctx.error().trim().to_owned();
            if message.is_empty() {
                message = format!("libnftables returned {rc} without an error message");
            }
            return Err(NftError::Rejected { message });
        }
        Ok(self.ctx.output())
    }

    /// Applies `ruleset` (the objects of an `nftables` array) as one batch.
    ///
    /// # Errors
    ///
    /// [`NftError::Rejected`] when libnftables or the kernel refuses any object; then nothing of
    /// the batch is applied.
    pub fn apply(&mut self, ruleset: &[Value]) -> Result<(), NftError> {
        let document = json!({ "nftables": ruleset }).to_string();
        self.run(&document).map(drop)
    }

    /// `list ruleset`: the `nftables` array of the JSON output.
    ///
    /// # Errors
    ///
    /// [`NftError::Rejected`] when listing fails (no netlink access), [`NftError::Output`] when
    /// the output is not a JSON document with an `nftables` array.
    pub fn list_ruleset(&mut self) -> Result<Value, NftError> {
        let output = self.run(r#"{"nftables":[{"list":{"ruleset":null}}]}"#)?;
        let mut document: Value = serde_json::from_str(&output)
            .map_err(|err| NftError::Output(format!("{err}: {output}")))?;
        match document.get_mut("nftables").map(Value::take) {
            Some(array @ Value::Array(_)) => Ok(array),
            _ => Err(NftError::Output(output)),
        }
    }
}
