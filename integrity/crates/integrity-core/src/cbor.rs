// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-allocation `#![no_std]` CBOR parser for the RKP ProvisioningInfo certificate
//! extension (OID `1.3.6.1.4.1.11129.2.1.30`), extracting top-level map key `3` (manufacturer).

use crate::contract::{MAX_CBOR_DEPTH, MAX_PROP_VALUE_BYTES, MAX_PROVISIONING_BYTES};

/// Parses top-level CBOR map key `3` (UTF-8 text string) from a ProvisioningInfo payload.
/// Returns a trimmed slice bounded by `MAX_PROP_VALUE_BYTES` (91 UTF-8 bytes).
pub fn parse_provisioning_manufacturer(cbor: &[u8]) -> Option<&str> {
    if cbor.is_empty() || cbor.len() > MAX_PROVISIONING_BYTES {
        return None;
    }
    let mut pos = 0usize;
    let map_len = read_cbor_header(cbor, &mut pos, 5)?;
    for _ in 0..map_len {
        let key_initial = *cbor.get(pos)?;
        if (key_initial >> 5) == 0 {
            let key = read_cbor_header(cbor, &mut pos, 0)?;
            if key == 3 {
                let val_len = usize::try_from(read_cbor_header(cbor, &mut pos, 3)?).ok()?;
                let end = pos.checked_add(val_len)?;
                let raw = core::str::from_utf8(cbor.get(pos..end)?).ok()?;
                let trimmed = raw.trim();
                if trimmed.is_empty() || trimmed.len() > MAX_PROP_VALUE_BYTES {
                    return None;
                }
                return Some(trimmed);
            }
        } else if !skip_cbor_item(cbor, &mut pos, 0) {
            return None;
        }
        if !skip_cbor_item(cbor, &mut pos, 0) {
            return None;
        }
    }
    None
}

fn read_cbor_header(cbor: &[u8], pos: &mut usize, expected_major: u8) -> Option<u64> {
    let initial = *cbor.get(*pos)?;
    *pos += 1;
    if (initial >> 5) != expected_major {
        return None;
    }
    read_cbor_arg(cbor, pos, initial & 0x1f)
}

fn read_cbor_arg(cbor: &[u8], pos: &mut usize, ai: u8) -> Option<u64> {
    if ai < 24 {
        return Some(u64::from(ai));
    }
    let extra = match ai {
        24 => 1usize,
        25 => 2usize,
        26 => 4usize,
        27 => 8usize,
        _ => return None,
    };
    let end = pos.checked_add(extra)?;
    let slice = cbor.get(*pos..end)?;
    *pos = end;
    let mut val = 0u64;
    for &b in slice {
        val = (val << 8) | u64::from(b);
    }
    Some(val)
}

fn skip_cbor_item(cbor: &[u8], pos: &mut usize, depth: usize) -> bool {
    if depth > MAX_CBOR_DEPTH {
        return false;
    }
    let Some(&initial) = cbor.get(*pos) else {
        return false;
    };
    *pos += 1;
    let major = initial >> 5;
    let ai = initial & 0x1f;
    if major == 7 {
        let extra = match ai {
            0..=23 => 0usize,
            24 => 1usize,
            25 => 2usize,
            26 => 4usize,
            27 => 8usize,
            _ => return false,
        };
        let Some(end) = pos.checked_add(extra) else {
            return false;
        };
        if end > cbor.len() {
            return false;
        }
        *pos = end;
        return true;
    }
    let Some(arg) = read_cbor_arg(cbor, pos, ai) else {
        return false;
    };
    match major {
        0 | 1 => true,
        2 | 3 => {
            let Ok(len) = usize::try_from(arg) else {
                return false;
            };
            let Some(end) = pos.checked_add(len) else {
                return false;
            };
            if end > cbor.len() {
                return false;
            }
            *pos = end;
            true
        }
        4 => {
            for _ in 0..arg {
                if !skip_cbor_item(cbor, pos, depth + 1) {
                    return false;
                }
            }
            true
        }
        5 => {
            for _ in 0..arg {
                if !skip_cbor_item(cbor, pos, depth + 1) || !skip_cbor_item(cbor, pos, depth + 1) {
                    return false;
                }
            }
            true
        }
        6 => skip_cbor_item(cbor, pos, depth + 1),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key3_and_skips_nested_fields() {
        // {1: 42, 2: [1, {9: "skip"}], 3: "Google"}
        let cbor = [
            0xa3, // map(3)
            0x01, 0x18, 0x2a, // 1: 42
            0x02, 0x82, 0x01, 0xa1, 0x09, 0x64, b's', b'k', b'i', b'p', // 2: [1, {9: "skip"}]
            0x03, 0x66, b'G', b'o', b'o', b'g', b'l', b'e', // 3: "Google"
        ];
        assert_eq!(parse_provisioning_manufacturer(&cbor), Some("Google"));
    }

    #[test]
    fn rejects_empty_oversized_or_truncated() {
        assert_eq!(parse_provisioning_manufacturer(&[]), None);
        assert_eq!(parse_provisioning_manufacturer(&[0xa1, 0x03, 0x60]), None); // empty string
        assert_eq!(parse_provisioning_manufacturer(&[0xa1, 0x03, 0x66, b'G']), None); // truncated
    }
}
