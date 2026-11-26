// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Tempel NFC engine.
//!
//! Zero external crates (`core`/`std` only), deterministic, zero-allocation hot paths for
//! NCI 2.0 Listen-A/B/F encoding, hardware `2F 45` 40-key MIFARE batching, Type-4A NDEF /
//! scripted APDU HCE responding, card classification, `.mct`/`.nfc`/`.bin` dump codecs,
//! Indonesian e-Money read-only decoding, multi-tech physical card writing (Gen2/CUID/FUID,
//! Gen3 APDU, Gen4 Ultimate Magic, NTAG/Ultralight, NFC-V, FeliCa Lite-S), and binary vault
//! persistence with auto-revert policy.

pub mod apdu;
pub mod nci;
pub mod tag;
pub mod vault;

/// IEEE 802.3 CRC-32 (polynomial 0xEDB88320, reflected). Pure const-friendly bit loop,
/// zero static tables to keep binary footprint tiny while remaining sub-microsecond.
#[inline]
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// ISO 14443-3A 4-byte UID Block Check Character (XOR of all 4 UID bytes).
#[inline]
pub const fn bcc_uid4(uid: [u8; 4]) -> u8 {
    uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
}

/// Decodes hex string (ignoring ASCII whitespace, `:`, and `-`) directly into `out`.
/// Returns number of bytes written, or `None` on invalid nibble, odd nibble count, or overflow.
pub fn hex_decode_into(input: &str, out: &mut [u8]) -> Option<usize> {
    let mut n = 0usize;
    let mut hi: Option<u8> = None;
    for b in input.bytes() {
        if b.is_ascii_whitespace() || b == b':' || b == b'-' {
            continue;
        }
        let nib = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        if let Some(h) = hi.take() {
            if n >= out.len() {
                return None;
            }
            out[n] = (h << 4) | nib;
            n += 1;
        } else {
            hi = Some(nib);
        }
    }
    if hi.is_some() {
        return None;
    }
    Some(n)
}

/// Allocates and decodes a hex string (tolerates spaces, colons, hyphens).
pub fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; input.len() / 2 + 1];
    let len = hex_decode_into(input, &mut buf)?;
    buf.truncate(len);
    Some(buf)
}

/// Encodes `bytes` as uppercase hex into `out` (needs `bytes.len() * 2` bytes).
pub fn hex_encode_into(bytes: &[u8], out: &mut [u8]) -> usize {
    const LUT: &[u8; 16] = b"0123456789ABCDEF";
    let count = bytes.len().min(out.len() / 2);
    for (i, &b) in bytes[..count].iter().enumerate() {
        out[i * 2] = LUT[(b >> 4) as usize];
        out[i * 2 + 1] = LUT[(b & 0x0F) as usize];
    }
    count * 2
}

/// Uppercase hex string helper.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut buf = vec![0u8; bytes.len() * 2];
    hex_encode_into(bytes, &mut buf);
    // Safety: LUT contains strictly ASCII bytes.
    unsafe { String::from_utf8_unchecked(buf) }
}

/// Uppercase colon-separated hex string (e.g. `DE:AD:BE:EF`) for UI display.
pub fn hex_encode_colon(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    const LUT: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(bytes.len() * 3 - 1);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(b':');
        }
        out.push(LUT[(b >> 4) as usize]);
        out.push(LUT[(b & 0x0F) as usize]);
    }
    unsafe { String::from_utf8_unchecked(out) }
}
