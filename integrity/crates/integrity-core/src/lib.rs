// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Single Source of Truth (SSOT) for Yasvara integrity, attestation, boot-digest,
//! PIF normalization, CBOR RKP provisioning parsing, strict DER/AAID codecs, and
//! Bionic property-hiding policy.
//!
//! Built strictly `#![no_std]` with zero external crates:
//! - Without `alloc` (`no_stdlibs: true` in Bionic `libc.so`): zero heap allocation,
//!   zero ELF TLS, zero locks, pure `.text`/`.rodata`.
//! - With `alloc` (default in `keystore2`, `libyasvara_integrity_jni`, and host tests):
//!   enables DER KeyDescription patching, PIF normalization, and per-app patch override parsing.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod cbor;
pub mod contract;
pub mod der;
pub mod digest;
pub mod prop_policy;
pub mod version;

#[cfg(feature = "alloc")]
pub mod base64;
#[cfg(feature = "alloc")]
pub mod patch_override;
#[cfg(feature = "alloc")]
pub mod pif;
#[cfg(feature = "alloc")]
pub mod x509;
