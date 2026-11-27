// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Minimal zero-dependency RFC 4648 standard Base64 encoder & decoder (`alloc`).

#![cfg(feature = "alloc")]

use alloc::string::String;
use alloc::vec::Vec;

const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard Base64 encoding (with `=` padding, no line breaks).
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

#[inline]
fn val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict standard Base64 decoder (ignores ASCII whitespace; accepts padded or unpadded tails).
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut clean: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input {
        if !b.is_ascii_whitespace() {
            clean.push(b);
        }
    }
    if clean.is_empty() {
        return Some(Vec::new());
    }
    // Trim up to 2 trailing '=' padding chars (if length is multiple of 4).
    let pad = clean.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 || (pad > 0 && clean.len() % 4 != 0) {
        return None;
    }
    let data = &clean[..clean.len() - pad];
    if data.len() % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity((data.len() * 3) / 4);
    let mut i = 0;
    while i + 4 <= data.len() {
        let a = val(data[i])? as u32;
        let b = val(data[i + 1])? as u32;
        let c = val(data[i + 2])? as u32;
        let d = val(data[i + 3])? as u32;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((n >> 16) & 0xff) as u8);
        out.push(((n >> 8) & 0xff) as u8);
        out.push((n & 0xff) as u8);
        i += 4;
    }
    match data.len() - i {
        0 => {}
        2 => {
            let a = val(data[i])? as u32;
            let b = val(data[i + 1])? as u32;
            out.push((((a << 18) | (b << 12)) >> 16) as u8);
        }
        3 => {
            let a = val(data[i])? as u32;
            let b = val(data[i + 1])? as u32;
            let c = val(data[i + 2])? as u32;
            let n = (a << 18) | (b << 12) | (c << 6);
            out.push(((n >> 16) & 0xff) as u8);
            out.push(((n >> 8) & 0xff) as u8);
        }
        _ => return None,
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_invalid_inputs() {
        for sample in [b"".as_slice(), b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let enc = encode(sample);
            assert_eq!(decode(enc.as_bytes()).as_deref(), Some(sample));
        }
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(decode(b"Zm9v\n YmFy").as_deref(), Some(b"foobar".as_slice()));
        assert!(decode(b"Zm9v===").is_none());
        assert!(decode(b"A").is_none());
        assert!(decode(b"Zm9!").is_none());
    }
}
