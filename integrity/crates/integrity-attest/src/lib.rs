// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Unified attestation cryptography, keybox store/parser, file cache, and X.509 leaf /
//! `PURPOSE_ATTEST_KEY` re-signer shared directly by `keystore2` and `libyasvara_integrity_jni`.

pub mod cache;
pub mod keybox;
pub mod patcher;

extern "C" {
    fn yasvara_verify_x509_signature(
        cert_buf: *const u8,
        cert_len: usize,
        issuer_buf: *const u8,
        issuer_len: usize,
    ) -> bool;
}

/// Uses BoringSSL `X509_verify` to verify that `cert_der` was signed by `issuer_der`'s public key.
/// Supports cross-curve/digest combinations (e.g. P-384 intermediate signing a P-256 batch cert).
pub fn verify_x509_signature(cert_der: &[u8], issuer_der: &[u8]) -> bool {
    if cert_der.is_empty() || issuer_der.is_empty() {
        return false;
    }
    // SAFETY: `yasvara_verify_x509_signature` reads only within the supplied slices and retains
    // no pointers after returning.
    unsafe {
        yasvara_verify_x509_signature(
            cert_der.as_ptr(),
            cert_der.len(),
            issuer_der.as_ptr(),
            issuer_der.len(),
        )
    }
}
