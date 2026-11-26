// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-allocation Type-4A NDEF & scripted ISO-DEP HCE responder plus NDEF message builders.
//!
//! Hot-path `process_t4t_ndef_into` and `process_script_into` write straight into a caller
//! stack buffer (`[u8; 260]`) with zero heap allocations.

/// NFC Forum Type 4 Tag v2.0 NDEF Application AID (`D2 76 00 00 85 01 01`).
pub const NDEF_APP_AID: [u8; 7] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
pub const CC_FILE_ID: [u8; 2] = [0xE1, 0x03];
pub const NDEF_FILE_ID: [u8; 2] = [0xE1, 0x04];

pub const SW_OK: [u8; 2] = [0x90, 0x00];
pub const SW_FILE_NOT_FOUND: [u8; 2] = [0x6A, 0x82];
pub const SW_WRONG_P1P2: [u8; 2] = [0x6A, 0x86];
pub const SW_WRONG_LENGTH: [u8; 2] = [0x67, 0x00];
pub const SW_SECURITY_NOT_SATISFIED: [u8; 2] = [0x69, 0x82];
pub const SW_INS_NOT_SUPPORTED: [u8; 2] = [0x6D, 0x00];
pub const SW_CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];

/// Standard 15-byte Capability Container for a read-only Type 4A NDEF tag (max 4096 B).
const CC_FILE: [u8; 15] = [
    0x00, 0x0F, // CCLEN = 15
    0x20,       // Mapping version 2.0
    0x00, 0xFF, // MLe = 255 bytes max R-APDU
    0x00, 0xFF, // MLc = 255 bytes max C-APDU
    0x04, 0x06, // NDEF File Control TLV (T=04, L=06)
    0xE1, 0x04, // File ID = E104
    0x10, 0x00, // Max NDEF file size = 4096 B
    0x00,       // Read access: free
    0xFF,       // Write access: read-only
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum T4tSelection {
    #[default]
    None,
    NdefApp,
    CcFile,
    NdefFile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduRule {
    /// Command prefix (1..=255 bytes); exact match takes priority over shorter prefixes.
    pub match_prefix: Vec<u8>,
    /// Full response including SW1 SW2 (2..=258 bytes).
    pub response: Vec<u8>,
}

/// Zero-allocation NFC Forum Type 4A NDEF tag responder.
///
/// `ndef_payload` is the raw NDEF message bytes (without the 2-byte NLEN prefix; NLEN is
/// synthesized on the fly so callers store no redundant length framing).
/// Returns number of bytes written to `out` (minimum 2 for SW1/SW2).
pub fn process_t4t_ndef_into(
    sel: &mut T4tSelection,
    ndef_payload: &[u8],
    apdu: &[u8],
    out: &mut [u8; 260],
) -> usize {
    if apdu.len() < 4 {
        return write_sw(out, SW_WRONG_LENGTH);
    }
    let (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);
    if (cla & 0xFC) != 0x00 {
        return write_sw(out, SW_INS_NOT_SUPPORTED);
    }

    match ins {
        // SELECT
        0xA4 => {
            if apdu.len() < 5 {
                return write_sw(out, SW_WRONG_LENGTH);
            }
            let lc = apdu[4] as usize;
            if apdu.len() < 5 + lc {
                return write_sw(out, SW_WRONG_LENGTH);
            }
            let data = &apdu[5..5 + lc];
            match (p1, p2) {
                // Select by DF Name (AID)
                (0x04, 0x00) => {
                    if data == NDEF_APP_AID {
                        *sel = T4tSelection::NdefApp;
                        write_sw(out, SW_OK)
                    } else {
                        *sel = T4tSelection::None;
                        write_sw(out, SW_FILE_NOT_FOUND)
                    }
                }
                // Select EF by File ID
                (0x00, 0x0C) | (0x00, 0x00) => {
                    if *sel == T4tSelection::None {
                        return write_sw(out, SW_CONDITIONS_NOT_SATISFIED);
                    }
                    if data == CC_FILE_ID {
                        *sel = T4tSelection::CcFile;
                        write_sw(out, SW_OK)
                    } else if data == NDEF_FILE_ID {
                        *sel = T4tSelection::NdefFile;
                        write_sw(out, SW_OK)
                    } else {
                        write_sw(out, SW_FILE_NOT_FOUND)
                    }
                }
                _ => write_sw(out, SW_WRONG_P1P2),
            }
        }
        // READ BINARY
        0xB0 => {
            if apdu.len() < 5 {
                return write_sw(out, SW_WRONG_LENGTH);
            }
            let offset = (((p1 as usize) << 8) | (p2 as usize)) & 0x7FFF;
            let raw_le = apdu[4] as usize;
            let req_len = if raw_le == 0 { 255 } else { raw_le.min(255) };

            match *sel {
                T4tSelection::CcFile => {
                    if offset > CC_FILE.len() {
                        return write_sw(out, SW_WRONG_P1P2);
                    }
                    let end = (offset + req_len).min(CC_FILE.len());
                    let n = end - offset;
                    out[..n].copy_from_slice(&CC_FILE[offset..end]);
                    out[n..n + 2].copy_from_slice(&SW_OK);
                    n + 2
                }
                T4tSelection::NdefFile => {
                    let nlen = ndef_payload.len().min(4094);
                    let total = 2 + nlen;
                    if offset > total {
                        return write_sw(out, SW_WRONG_P1P2);
                    }
                    let end = (offset + req_len).min(total);
                    let n = end - offset;
                    let hdr = [(nlen >> 8) as u8, (nlen & 0xFF) as u8];
                    for i in 0..n {
                        let idx = offset + i;
                        out[i] = if idx < 2 {
                            hdr[idx]
                        } else {
                            ndef_payload[idx - 2]
                        };
                    }
                    out[n..n + 2].copy_from_slice(&SW_OK);
                    n + 2
                }
                _ => write_sw(out, SW_CONDITIONS_NOT_SATISFIED),
            }
        }
        // UPDATE BINARY — read-only tag
        0xD6 => write_sw(out, SW_SECURITY_NOT_SATISFIED),
        _ => write_sw(out, SW_INS_NOT_SUPPORTED),
    }
}

/// Zero-allocation scripted ISO-DEP APDU matcher (longest prefix wins).
pub fn process_script_into(rules: &[ApduRule], apdu: &[u8], out: &mut [u8; 260]) -> usize {
    let mut best: Option<&ApduRule> = None;
    for r in rules {
        if !r.match_prefix.is_empty() && apdu.starts_with(&r.match_prefix) {
            if best.map_or(true, |b| r.match_prefix.len() > b.match_prefix.len()) {
                best = Some(r);
            }
        }
    }
    if let Some(rule) = best {
        let len = rule.response.len().min(out.len());
        if len >= 2 {
            out[..len].copy_from_slice(&rule.response[..len]);
            return len;
        }
    }
    write_sw(out, SW_FILE_NOT_FOUND)
}

#[inline]
fn write_sw(out: &mut [u8; 260], sw: [u8; 2]) -> usize {
    out[0] = sw[0];
    out[1] = sw[1];
    2
}

// ---------------------------------------------------------------------------
// NDEF message encoders (used for both Type-4A HCE emulation and NTAG writing)
// ---------------------------------------------------------------------------

const URI_PREFIXES: &[(u8, &str)] = &[
    (0x04, "https://"),
    (0x03, "http://"),
    (0x02, "https://www."),
    (0x01, "http://www."),
    (0x05, "tel:"),
    (0x06, "mailto:"),
];

fn encode_ndef_record(tnf: u8, rtype: &[u8], payload: &[u8]) -> Vec<u8> {
    let short = payload.len() <= 255;
    let flags = 0xC0 | if short { 0x10 } else { 0x00 } | (tnf & 0x07); // MB | ME | [SR] | TNF
    let mut out = Vec::with_capacity(3 + rtype.len() + payload.len() + if short { 0 } else { 3 });
    out.push(flags);
    out.push(rtype.len() as u8);
    if short {
        out.push(payload.len() as u8);
    } else {
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    }
    out.extend_from_slice(rtype);
    out.extend_from_slice(payload);
    out
}

/// Encodes an NFC Forum Well-Known URI NDEF message (`https://...`, `tel:...`, etc.).
pub fn encode_ndef_uri(uri: &str) -> Vec<u8> {
    let mut code = 0x00u8;
    let mut rest = uri;
    for &(c, prefix) in URI_PREFIXES {
        if let Some(stripped) = uri.strip_prefix(prefix) {
            code = c;
            rest = stripped;
            break;
        }
    }
    let mut payload = Vec::with_capacity(1 + rest.len());
    payload.push(code);
    payload.extend_from_slice(rest.as_bytes());
    encode_ndef_record(0x01, b"U", &payload)
}

/// Encodes an NFC Forum Well-Known UTF-8 Text NDEF message.
pub fn encode_ndef_text(lang: &str, text: &str) -> Vec<u8> {
    let lang_b = &lang.as_bytes()[..lang.len().min(63)];
    let mut payload = Vec::with_capacity(1 + lang_b.len() + text.len());
    payload.push(lang_b.len() as u8);
    payload.extend_from_slice(lang_b);
    payload.extend_from_slice(text.as_bytes());
    encode_ndef_record(0x01, b"T", &payload)
}

/// Encodes an Android-standard Wi-Fi Simple Config NDEF record (`application/vnd.wfa.wsc`).
pub fn encode_ndef_wifi(ssid: &str, passphrase: &str, wpa2_personal: bool) -> Vec<u8> {
    let mut cred = Vec::with_capacity(32 + ssid.len() + passphrase.len());
    // Network Index = 1
    cred.extend_from_slice(&[0x10, 0x26, 0x00, 0x01, 0x01]);
    // SSID (0x1045)
    let sb = ssid.as_bytes();
    cred.extend_from_slice(&[0x10, 0x45]);
    cred.extend_from_slice(&(sb.len() as u16).to_be_bytes());
    cred.extend_from_slice(sb);
    // Auth Type (0x1003): 0x0020 WPA2-Personal, 0x0001 Open
    let auth: u16 = if wpa2_personal && !passphrase.is_empty() { 0x0020 } else { 0x0001 };
    cred.extend_from_slice(&[0x10, 0x03, 0x00, 0x02]);
    cred.extend_from_slice(&auth.to_be_bytes());
    // Encryption Type (0x100F): 0x0008 AES, 0x0001 None
    let enc: u16 = if auth == 0x0020 { 0x0008 } else { 0x0001 };
    cred.extend_from_slice(&[0x10, 0x0F, 0x00, 0x02]);
    cred.extend_from_slice(&enc.to_be_bytes());
    // Network Key (0x1027)
    let kb = passphrase.as_bytes();
    cred.extend_from_slice(&[0x10, 0x27]);
    cred.extend_from_slice(&(kb.len() as u16).to_be_bytes());
    cred.extend_from_slice(kb);
    // MAC Address wildcard (0x1020)
    cred.extend_from_slice(&[0x10, 0x20, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    let mut payload = Vec::with_capacity(4 + cred.len());
    // Credential TLV (0x100E)
    payload.extend_from_slice(&[0x10, 0x0E]);
    payload.extend_from_slice(&(cred.len() as u16).to_be_bytes());
    payload.extend_from_slice(&cred);
    encode_ndef_record(0x02, b"application/vnd.wfa.wsc", &payload)
}

/// Encodes a vCard 3.0 NDEF contact card (`text/vcard`).
pub fn encode_ndef_vcard(name: &str, phone: &str, email: &str) -> Vec<u8> {
    let mut s = String::with_capacity(64 + name.len() + phone.len() + email.len());
    s.push_str("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:");
    s.push_str(name);
    if !phone.is_empty() {
        s.push_str("\r\nTEL:");
        s.push_str(phone);
    }
    if !email.is_empty() {
        s.push_str("\r\nEMAIL:");
        s.push_str(email);
    }
    s.push_str("\r\nEND:VCARD");
    encode_ndef_record(0x02, b"text/vcard", s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t4t_ndef_full_read_sequence() {
        let ndef = encode_ndef_uri("https://yasvara.org");
        let mut sel = T4tSelection::None;
        let mut out = [0u8; 260];

        // 1. SELECT NDEF App
        let mut cmd = vec![0x00, 0xA4, 0x04, 0x00, 0x07];
        cmd.extend_from_slice(&NDEF_APP_AID);
        cmd.push(0x00);
        let n = process_t4t_ndef_into(&mut sel, &ndef, &cmd, &mut out);
        assert_eq!(&out[..n], &SW_OK);
        assert_eq!(sel, T4tSelection::NdefApp);

        // 2. SELECT CC (E103) + READ BINARY
        let n = process_t4t_ndef_into(&mut sel, &ndef, &[0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03], &mut out);
        assert_eq!(&out[..n], &SW_OK);
        let n = process_t4t_ndef_into(&mut sel, &ndef, &[0x00, 0xB0, 0x00, 0x00, 0x0F], &mut out);
        assert_eq!(n, 17);
        assert_eq!(&out[..15], &CC_FILE);
        assert_eq!(&out[15..17], &SW_OK);

        // 3. SELECT NDEF (E104) + READ NLEN + READ BODY
        let n = process_t4t_ndef_into(&mut sel, &ndef, &[0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04], &mut out);
        assert_eq!(&out[..n], &SW_OK);
        let n = process_t4t_ndef_into(&mut sel, &ndef, &[0x00, 0xB0, 0x00, 0x00, 0x02], &mut out);
        assert_eq!(n, 4);
        let nlen = u16::from_be_bytes([out[0], out[1]]) as usize;
        assert_eq!(nlen, ndef.len());

        let n = process_t4t_ndef_into(&mut sel, &ndef, &[0x00, 0xB0, 0x00, 0x02, nlen as u8], &mut out);
        assert_eq!(n, nlen + 2);
        assert_eq!(&out[..nlen], ndef.as_slice());
        assert_eq!(&out[nlen..nlen + 2], &SW_OK);

        // 4. UPDATE BINARY refused
        let n = process_t4t_ndef_into(&mut sel, &ndef, &[0x00, 0xD6, 0x00, 0x00, 0x01, 0x00], &mut out);
        assert_eq!(&out[..n], &SW_SECURITY_NOT_SATISFIED);
    }

    #[test]
    fn script_responder_longest_prefix_wins() {
        let rules = vec![
            ApduRule { match_prefix: vec![0x00, 0xA4], response: vec![0x6A, 0x82] },
            ApduRule {
                match_prefix: vec![0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x01, 0x02, 0x03, 0x04],
                response: vec![0xCA, 0xFE, 0x90, 0x00],
            },
        ];
        let mut out = [0u8; 260];
        let n = process_script_into(
            &rules,
            &[0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x01, 0x02, 0x03, 0x04, 0x00],
            &mut out,
        );
        assert_eq!(&out[..n], &[0xCA, 0xFE, 0x90, 0x00]);
        let n = process_script_into(&rules, &[0x80, 0xCA, 0x00, 0x00], &mut out);
        assert_eq!(&out[..n], &SW_FILE_NOT_FOUND);
    }

    #[test]
    fn ndef_wifi_and_vcard_build() {
        let w = encode_ndef_wifi("HomeNet", "secret123", true);
        assert!(w.windows(23).any(|x| x == b"application/vnd.wfa.wsc"));
        assert!(w.windows(7).any(|x| x == b"HomeNet"));
        let v = encode_ndef_vcard("Budi", "+628123", "budi@example.com");
        assert!(v.windows(10).any(|x| x == b"text/vcard"));
        assert!(v.windows(7).any(|x| x == b"FN:Budi"));
    }
}
