// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Canonical SHA-256 (64 hex / 32 B) or SHA-512 (128 hex / 64 B) verified-boot digest codec.
//! Strictly rejects all-zero digests across every layer (Rust, Bionic, Java, RKP).

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Returns true if `bytes` is empty or consists solely of `0x00`.
pub fn is_all_zero(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    bytes.iter().fold(0u8, |acc, &b| acc | b) == 0
}

#[inline]
fn lower_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Validates a canonical lowercase hex digest (64 or 128 chars, non-zero) with zero allocation.
pub fn is_canonical_hex(hex: &[u8]) -> bool {
    if hex.len() != 64 && hex.len() != 128 {
        return false;
    }
    let mut non_zero = false;
    for &b in hex {
        if lower_nibble(b).is_none() {
            return false;
        }
        if b != b'0' {
            non_zero = true;
        }
    }
    non_zero
}

/// Zero-alloc canonical lowercase hex decoder into a 64-byte stack buffer.
/// Returns the decoded byte length (32 or 64). Rejects missing, malformed, uppercase,
/// whitespace, or all-zero digests.
pub fn decode_canonical_into(hex: &[u8], out: &mut [u8; 64]) -> Result<usize, &'static str> {
    if hex.len() != 64 && hex.len() != 128 {
        return Err("canonical boot digest must be 64 or 128 lowercase hex characters");
    }
    let out_len = hex.len() / 2;
    let mut non_zero = 0u8;
    let mut i = 0;
    while i < out_len {
        let hi = lower_nibble(hex[2 * i]).ok_or("canonical boot digest is not lowercase hex")?;
        let lo = lower_nibble(hex[2 * i + 1]).ok_or("canonical boot digest is not lowercase hex")?;
        let byte = (hi << 4) | lo;
        non_zero |= byte;
        out[i] = byte;
        i += 1;
    }
    if non_zero == 0 {
        return Err("canonical boot digest must not be all-zero");
    }
    Ok(out_len)
}

/// Decodes a canonical lowercase hex digest (64 or 128 chars, non-zero) into a `Vec<u8>`.
#[cfg(feature = "alloc")]
pub fn parse_boot_digest(value: Option<&str>) -> Result<Vec<u8>, &'static str> {
    let value = value.ok_or("canonical boot digest is missing")?;
    let mut buf = [0u8; 64];
    let len = decode_canonical_into(value.as_bytes(), &mut buf)?;
    Ok(buf[..len].to_vec())
}

/// Normalizes external bootloader property input (tolerates uppercase, `:`, whitespace; caps
/// input length at 512 bytes; rejects all-zero or non-32/64-byte digests).
#[cfg(feature = "alloc")]
pub fn normalize_boot_digest(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() > 512 {
        return None;
    }
    if is_canonical_hex(bytes) {
        return Some(String::from(value));
    }
    let mut out = Vec::with_capacity(128);
    let mut non_zero = false;
    for &raw in bytes {
        if raw == b':' || raw.is_ascii_whitespace() {
            continue;
        }
        let c = if raw.is_ascii_uppercase() { raw + (b'a' - b'A') } else { raw };
        lower_nibble(c)?;
        if out.len() == 128 {
            return None;
        }
        if c != b'0' {
            non_zero = true;
        }
        out.push(c);
    }
    if (out.len() != 64 && out.len() != 128) || !non_zero {
        return None;
    }
    String::from_utf8(out).ok()
}

/// Encodes a 32- or 64-byte non-zero digest into canonical lowercase hex.
#[cfg(feature = "alloc")]
pub fn encode_boot_digest(value: &[u8]) -> Option<String> {
    if (value.len() != 32 && value.len() != 64) || is_all_zero(value) {
        return None;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(value.len() * 2);
    for &b in value {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    String::from_utf8(out).ok()
}

/// Selects the per-boot canonical digest from bootloader and/or TEE attestation.
/// Returns `None` if both are absent OR if bootloader and TEE measurements conflict!
#[cfg(feature = "alloc")]
pub fn select_boot_digest(
    bootloader_value: Option<&str>,
    attested_hash: Option<&[u8]>,
) -> Option<(String, &'static str)> {
    let bootloader = bootloader_value.and_then(normalize_boot_digest);
    let attested = attested_hash.and_then(encode_boot_digest);
    match (bootloader, attested) {
        (Some(b), Some(a)) if b != a => None,
        (Some(b), _) => Some((b, "bootloader")),
        (None, Some(a)) => Some((a, "tee")),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nostd_canonical_hex_and_zero_check() {
        assert!(!is_canonical_hex(&[b'0'; 64]));
        assert!(is_canonical_hex(&[b'a'; 64]));
        assert!(is_canonical_hex(&[b'f'; 128]));
        assert!(!is_canonical_hex(&[b'A'; 64]));
        assert!(is_all_zero(&[0u8; 32]));
        assert!(!is_all_zero(&[0u8, 1u8]));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn canonical_and_zero_rejection() {
        let zeros64 = "0".repeat(64);
        assert!(!is_canonical_hex(zeros64.as_bytes()));
        assert!(parse_boot_digest(Some(&zeros64)).is_err());
        assert!(normalize_boot_digest(&zeros64).is_none());

        let valid64 = "ab".repeat(32);
        assert!(is_canonical_hex(valid64.as_bytes()));
        let decoded = parse_boot_digest(Some(&valid64)).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(encode_boot_digest(&decoded).as_deref(), Some(valid64.as_str()));

        let valid128 = "cd".repeat(64);
        assert!(is_canonical_hex(valid128.as_bytes()));
        assert_eq!(parse_boot_digest(Some(&valid128)).unwrap().len(), 64);

        assert!(parse_boot_digest(Some(&"AB".repeat(32))).is_err());
        assert_eq!(normalize_boot_digest(&"AB:CD".repeat(16)).unwrap(), "abcd".repeat(16));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn selection_rejects_conflict() {
        let a = [0x11u8; 32];
        let b_hex = "22".repeat(32);
        assert!(select_boot_digest(Some(&b_hex), Some(&a)).is_none());
        let a_hex = "11".repeat(32);
        assert_eq!(select_boot_digest(Some(&a_hex), Some(&a)), Some((a_hex.clone(), "bootloader")));
        assert_eq!(select_boot_digest(None, Some(&a)), Some((a_hex, "tee")));
    }
}
