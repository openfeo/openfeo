// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Andrew Newton

//! The raw libnftables interface (`include/nftables/libnftables.h`) and [`Ctx`], an owned
//! context. This is the only module in the crate allowed `unsafe` (SPEC §9); every block says why
//! it is sound. The context owns its buffers: libnftables resets both at the start of each
//! `nft_run_cmd_from_buffer`, so a buffer read right after a run belongs to that run.

use std::ffi::{CStr, c_char, c_int, c_uint};
use std::marker::{PhantomData, PhantomPinned};
use std::ptr::NonNull;

/// Opaque `struct nft_ctx`.
#[repr(C)]
pub struct nft_ctx {
    _data: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// `nft_ctx_new(NFT_CTX_DEFAULT)`.
pub const NFT_CTX_DEFAULT: u32 = 0;
/// Input: never resolve names through DNS.
pub const NFT_CTX_INPUT_NO_DNS: c_uint = 1 << 0;
/// Input: the buffer is libnftables JSON, not nft syntax.
pub const NFT_CTX_INPUT_JSON: c_uint = 1 << 1;
/// Output: JSON.
pub const NFT_CTX_OUTPUT_JSON: c_uint = 1 << 4;
/// Output: numeric protocols, priorities, symbols and times.
pub const NFT_CTX_OUTPUT_NUMERIC_ALL: c_uint = (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10);

unsafe extern "C" {
    fn nft_ctx_new(flags: u32) -> *mut nft_ctx;
    fn nft_ctx_free(ctx: *mut nft_ctx);
    fn nft_ctx_input_set_flags(ctx: *mut nft_ctx, flags: c_uint) -> c_uint;
    fn nft_ctx_output_set_flags(ctx: *mut nft_ctx, flags: c_uint);
    fn nft_ctx_buffer_output(ctx: *mut nft_ctx) -> c_int;
    fn nft_ctx_buffer_error(ctx: *mut nft_ctx) -> c_int;
    fn nft_ctx_get_output_buffer(ctx: *mut nft_ctx) -> *const c_char;
    fn nft_ctx_get_error_buffer(ctx: *mut nft_ctx) -> *const c_char;
    fn nft_run_cmd_from_buffer(nft: *mut nft_ctx, buf: *const c_char) -> c_int;
}

/// An owned libnftables context. Not `Sync`: libnftables contexts are single-threaded; `Send`
/// because the pointer is uniquely owned and the library keeps no thread-local state for it.
pub struct Ctx {
    ptr: NonNull<nft_ctx>,
}

// SAFETY: `Ctx` is the only owner of its `nft_ctx`; libnftables ties nothing in a context to the
// thread that created it, so moving the owner to another thread is sound. `&Ctx` is still not
// shareable across threads (no `Sync`), which is what the library requires.
unsafe impl Send for Ctx {}

impl Ctx {
    /// `nft_ctx_new(flags)`; `None` when libnftables could not allocate.
    #[must_use]
    pub fn new(flags: u32) -> Option<Self> {
        // SAFETY: plain call; the library allocates and returns NULL on failure.
        let ptr = unsafe { nft_ctx_new(flags) };
        NonNull::new(ptr).map(|ptr| Ctx { ptr })
    }

    /// `nft_ctx_input_set_flags`; returns the previous flags.
    pub fn set_input_flags(&mut self, flags: c_uint) -> c_uint {
        // SAFETY: `self.ptr` is a live context owned by `self`.
        unsafe { nft_ctx_input_set_flags(self.ptr.as_ptr(), flags) }
    }

    /// `nft_ctx_output_set_flags`.
    pub fn set_output_flags(&mut self, flags: c_uint) {
        // SAFETY: `self.ptr` is a live context owned by `self`.
        unsafe { nft_ctx_output_set_flags(self.ptr.as_ptr(), flags) }
    }

    /// Route the output into a buffer this context owns; 0 on success.
    pub fn buffer_output(&mut self) -> c_int {
        // SAFETY: `self.ptr` is a live context owned by `self`.
        unsafe { nft_ctx_buffer_output(self.ptr.as_ptr()) }
    }

    /// Route the error text into a buffer this context owns; 0 on success.
    pub fn buffer_error(&mut self) -> c_int {
        // SAFETY: `self.ptr` is a live context owned by `self`.
        unsafe { nft_ctx_buffer_error(self.ptr.as_ptr()) }
    }

    /// `nft_run_cmd_from_buffer`: 0 on success, anything else means the error buffer explains.
    pub fn run(&mut self, command: &CStr) -> c_int {
        // SAFETY: `self.ptr` is a live context owned by `self`; `command` is NUL-terminated and
        // outlives the call, which does not retain it.
        unsafe { nft_run_cmd_from_buffer(self.ptr.as_ptr(), command.as_ptr()) }
    }

    /// The output buffer of the last run (empty when buffering is off or nothing was written).
    #[must_use]
    pub fn output(&self) -> String {
        // SAFETY: `self.ptr` is a live context owned by `self`.
        let ptr = unsafe { nft_ctx_get_output_buffer(self.ptr.as_ptr()) };
        c_string(ptr)
    }

    /// The error buffer of the last run.
    #[must_use]
    pub fn error(&self) -> String {
        // SAFETY: `self.ptr` is a live context owned by `self`.
        let ptr = unsafe { nft_ctx_get_error_buffer(self.ptr.as_ptr()) };
        c_string(ptr)
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` came from `nft_ctx_new` and is freed exactly once, here.
        unsafe { nft_ctx_free(self.ptr.as_ptr()) }
    }
}

/// Copies a C string the context owns; NULL (buffering off) reads as empty.
fn c_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: libnftables hands out a NUL-terminated buffer it owns, valid until the next run
    // on the same context, and we copy it out before returning.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}
