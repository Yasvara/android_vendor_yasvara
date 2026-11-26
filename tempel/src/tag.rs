// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Card classification, `.mct`/`.nfc`/`.bin` dump codecs, Indonesian e-Money read-only
//! decoding, and hardware-verified multi-tech physical card WRITER frame builders.
//!
//! Supported physical write targets (verified against onyx SN220U `NxpMfcReader.cc` + `NativeNfcTag.cpp`):
//! - MIFARE Classic Gen2 / CUID / FUID / UFUID (unrestricted `0xA0` Block 0 + sectors + value blocks)
//! - MIFARE Classic Gen3 APDU (`90 F0 CC CC 10`, `90 FB CC CC 07`, `90 FD 11 11 00`)
//! - MIFARE / NTAG Gen4 Ultimate Magic Card (`CF <pwd4> C6/CD/CE/F0/FE/CC`)
//! - NTAG213/215/216 / Ultralight / C / EV1 / Magic NTAG (`0xA2`, `0x3A`, `0x1B`, `0x60`)
//! - ISO 15693 / NFC-V (`0x2B`, `0x20`, `0x21`, `0x22`)
//! - FeliCa Lite-S Type 3 (`0x00`, `0x06`, `0x08`)
//!
//! Anti-brick guards:
//! - `validate_mfc_access_bits` rejects inverted-nibble mismatches before any sector trailer write.
//! - `is_ntag_lock_or_cfg_page` flags OTP/lock/CFG pages so accidental lock-bit writes are blocked.

use crate::{bcc_uid4, hex_decode, hex_decode_into, hex_encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagError {
    InvalidLength,
    InvalidHex,
    InvalidFormat,
    InvalidAccessBits,
    ProtectedPage,
    CapacityExceeded,
    InvalidSectorOrBlock,
}

/// Public well-known default/factory MIFARE Classic keys (for honest sector readability check
/// and hardware `2F 45` batch verification — no cryptographic attacks).
pub const DEFAULT_MFC_KEYS: [[u8; 6]; 20] = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Factory default
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], // MAD Key A
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7], // NFC Forum NDEF Key A
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // All-zero blank
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5], // Common B-key
    [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD], // Common hotel/access
    [0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A],
    [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    [0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97],
    [0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F],
    [0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91],
    [0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6],
    [0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9],
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06], // Xiaomi MITSM default #5
    [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
    [0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0],
    [0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1],
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
    [0x26, 0x97, 0x3E, 0xA7, 0x43, 0x21],
    [0xEE, 0x00, 0x42, 0xF8, 0x88, 0x40],
];

// ---------------------------------------------------------------------------
// Card classification & honest compatibility verdict
// ---------------------------------------------------------------------------

pub const TECH_NFC_A: u32 = 1 << 0;
pub const TECH_NFC_B: u32 = 1 << 1;
pub const TECH_NFC_F: u32 = 1 << 2;
pub const TECH_NFC_V: u32 = 1 << 3;
pub const TECH_ISO_DEP: u32 = 1 << 4;
pub const TECH_MIFARE_CLASSIC: u32 = 1 << 5;
pub const TECH_MIFARE_ULTRALIGHT: u32 = 1 << 6;
pub const TECH_NDEF: u32 = 1 << 7;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardPreset {
    Unknown = 0,
    MifareClassic1K = 1,
    MifareClassic4K = 2,
    UltralightNtag = 3,
    DesfireOrType4A = 4,
    Felica = 5,
    Iso14443B = 6,
    Iso15693V = 7,
    EmvOrEMoney = 8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmulationVerdict {
    /// Phone can emulate UID + ATQA + SAK directly (`emulateNfcTechnologyATag`).
    UidOnlyReady = 0,
    /// Phone can emulate static UID + Type-4A NDEF / ISO-DEP HCE.
    Type4HceReady = 1,
    /// Phone can emulate arbitrary FeliCa IDm + PMm + System Code (`LF_T3T_ID1`).
    FelicaReady = 2,
    /// Phone can emulate ISO 14443-B PUPI + AppData (`LB_NFCID0`).
    TypeBReady = 3,
    /// MIFARE Classic with encrypted sectors: UID-only may work on UID doors; use Gen2/3/4 Magic Card Writer for full sector clone.
    MifareEncryptedNeedsMagicCard = 4,
    /// EMV bank card or e-Money: purse cannot be cloned; UID-only door clone & read-only balance inspection supported.
    EmvOrEmoneyUidOnly = 5,
    /// NTAG/Ultralight memory tag: phone emulates 7B UID only (SN220U rejects T2T Listen); write physical NTAG for full memory clone.
    NtagUidOnlyOrWriteTag = 6,
    /// ISO 15693 / NFC-V: no NFCC Listen-V; full read & physical NFC-V block writer supported.
    NfcVWriteOnly = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardAnalysis {
    pub preset: CardPreset,
    pub verdict: EmulationVerdict,
    pub can_emulate_on_phone: bool,
    pub can_write_physical: bool,
    pub encrypted_sectors: u8,
    pub total_sectors: u8,
}

/// Classifies a scanned card accurately so the UI reports exact hardware capabilities.
pub fn classify_tag(
    tech_mask: u32,
    uid_len: usize,
    _atqa: [u8; 2],
    sak: u8,
    has_ndef: bool,
    is_emv_or_emoney: bool,
    total_sectors: u8,
    readable_sectors: u8,
) -> CardAnalysis {
    if (tech_mask & TECH_NFC_V) != 0 {
        return CardAnalysis {
            preset: CardPreset::Iso15693V,
            verdict: EmulationVerdict::NfcVWriteOnly,
            can_emulate_on_phone: false,
            can_write_physical: true,
            encrypted_sectors: 0,
            total_sectors: 0,
        };
    }
    if (tech_mask & TECH_NFC_F) != 0 {
        return CardAnalysis {
            preset: CardPreset::Felica,
            verdict: EmulationVerdict::FelicaReady,
            can_emulate_on_phone: true,
            can_write_physical: true,
            encrypted_sectors: 0,
            total_sectors: 0,
        };
    }
    if (tech_mask & TECH_NFC_B) != 0 {
        return CardAnalysis {
            preset: if is_emv_or_emoney {
                CardPreset::EmvOrEMoney
            } else {
                CardPreset::Iso14443B
            },
            verdict: if is_emv_or_emoney {
                EmulationVerdict::EmvOrEmoneyUidOnly
            } else {
                EmulationVerdict::TypeBReady
            },
            can_emulate_on_phone: uid_len == 4,
            can_write_physical: false,
            encrypted_sectors: 0,
            total_sectors: 0,
        };
    }
    if is_emv_or_emoney {
        return CardAnalysis {
            preset: CardPreset::EmvOrEMoney,
            verdict: EmulationVerdict::EmvOrEmoneyUidOnly,
            can_emulate_on_phone: matches!(uid_len, 4 | 7 | 10),
            can_write_physical: false,
            encrypted_sectors: 0,
            total_sectors: 0,
        };
    }
    if (tech_mask & TECH_MIFARE_CLASSIC) != 0 || matches!(sak, 0x08 | 0x09 | 0x18 | 0x28 | 0x38 | 0x88) {
        let preset = if sak == 0x18 || sak == 0x38 || total_sectors > 16 {
            CardPreset::MifareClassic4K
        } else {
            CardPreset::MifareClassic1K
        };
        let enc = total_sectors.saturating_sub(readable_sectors);
        let verdict = if enc > 0 {
            EmulationVerdict::MifareEncryptedNeedsMagicCard
        } else {
            EmulationVerdict::UidOnlyReady
        };
        return CardAnalysis {
            preset,
            verdict,
            can_emulate_on_phone: matches!(uid_len, 4 | 7 | 10),
            can_write_physical: true,
            encrypted_sectors: enc,
            total_sectors,
        };
    }
    if (tech_mask & TECH_ISO_DEP) != 0 || (sak & 0x20) != 0 {
        return CardAnalysis {
            preset: CardPreset::DesfireOrType4A,
            verdict: EmulationVerdict::Type4HceReady,
            can_emulate_on_phone: matches!(uid_len, 4 | 7 | 10),
            can_write_physical: true,
            encrypted_sectors: 0,
            total_sectors: 0,
        };
    }
    if (tech_mask & TECH_MIFARE_ULTRALIGHT) != 0 || sak == 0x00 {
        return CardAnalysis {
            preset: CardPreset::UltralightNtag,
            verdict: if has_ndef {
                EmulationVerdict::Type4HceReady
            } else {
                EmulationVerdict::NtagUidOnlyOrWriteTag
            },
            can_emulate_on_phone: matches!(uid_len, 4 | 7 | 10),
            can_write_physical: true,
            encrypted_sectors: 0,
            total_sectors: 0,
        };
    }
    CardAnalysis {
        preset: CardPreset::Unknown,
        verdict: EmulationVerdict::UidOnlyReady,
        can_emulate_on_phone: matches!(uid_len, 4 | 7 | 10),
        can_write_physical: false,
        encrypted_sectors: 0,
        total_sectors: 0,
    }
}

// ---------------------------------------------------------------------------
// MIFARE Classic Block 0, Access Bits anti-brick validator & Value Block codec
// ---------------------------------------------------------------------------

/// Builds a spec-compliant 16-byte MIFARE Classic Block 0 from UID, SAK, ATQA and optional
/// manufacturer bytes. Automatically computes the exact 4-byte UID BCC (`u0^u1^u2^u3`).
pub fn build_mfc_block0(
    uid: &[u8],
    sak: u8,
    atqa: [u8; 2],
    mfg_tail: Option<&[u8]>,
) -> Result<[u8; 16], TagError> {
    let mut blk = [0u8; 16];
    match uid.len() {
        4 => {
            let u = [uid[0], uid[1], uid[2], uid[3]];
            blk[0..4].copy_from_slice(&u);
            blk[4] = bcc_uid4(u);
            blk[5] = sak;
            blk[6] = atqa[0];
            blk[7] = atqa[1];
            if let Some(tail) = mfg_tail {
                let n = tail.len().min(8);
                blk[8..8 + n].copy_from_slice(&tail[..n]);
            } else {
                // NXP-like standard non-zero manufacturer tail
                blk[8..16].copy_from_slice(&[0x88, 0x04, 0x00, 0xC8, 0x00, 0x00, 0x20, 0x00]);
            }
            Ok(blk)
        }
        7 => {
            blk[0..7].copy_from_slice(uid);
            if let Some(tail) = mfg_tail {
                let n = tail.len().min(9);
                blk[7..7 + n].copy_from_slice(&tail[..n]);
            }
            Ok(blk)
        }
        _ => Err(TagError::InvalidLength),
    }
}

/// Validates MIFARE Classic 3-byte sector trailer access bits (bytes 6, 7, 8 of trailer).
///
/// ISO/NXP MIFARE Classic permanently bricks a sector if the inverted nibbles don't match:
/// - `byte6_lo == (~byte7_hi) & 0x0F` (~C1)
/// - `byte6_hi == (~byte8_lo) & 0x0F` (~C2)
/// - `byte7_lo == (~byte8_hi) & 0x0F` (~C3)
#[inline]
pub const fn validate_mfc_access_bits(access: [u8; 3]) -> bool {
    let b6 = access[0];
    let b7 = access[1];
    let b8 = access[2];
    let c1_inv = b6 & 0x0F;
    let c2_inv = (b6 >> 4) & 0x0F;
    let c3_inv = b7 & 0x0F;
    let c1 = (b7 >> 4) & 0x0F;
    let c2 = b8 & 0x0F;
    let c3 = (b8 >> 4) & 0x0F;
    ((c1 ^ c1_inv) == 0x0F) && ((c2 ^ c2_inv) == 0x0F) && ((c3 ^ c3_inv) == 0x0F)
}

/// Returns true if `block` is a MIFARE Classic sector trailer (1K: blocks 3,7..63; 4K: +128..255 every 16).
#[inline]
pub const fn is_mfc_trailer_block(block: u16) -> bool {
    if block < 128 {
        (block & 3) == 3
    } else {
        ((block - 128) & 15) == 15
    }
}

/// Encodes a MIFARE Classic signed 32-bit Value Block (`val, ~val, val, addr, ~addr, addr, ~addr`).
pub fn encode_mfc_value_block(value: i32, addr: u8) -> [u8; 16] {
    let v = value.to_le_bytes();
    let nv = (!value).to_le_bytes();
    let na = !addr;
    [
        v[0], v[1], v[2], v[3],
        nv[0], nv[1], nv[2], nv[3],
        v[0], v[1], v[2], v[3],
        addr, na, addr, na,
    ]
}

/// Decodes and verifies a MIFARE Classic Value Block.
pub fn decode_mfc_value_block(blk: &[u8; 16]) -> Option<(i32, u8)> {
    let v0 = i32::from_le_bytes([blk[0], blk[1], blk[2], blk[3]]);
    let nv = i32::from_le_bytes([blk[4], blk[5], blk[6], blk[7]]);
    let v1 = i32::from_le_bytes([blk[8], blk[9], blk[10], blk[11]]);
    if v0 != v1 || v0 != !nv {
        return None;
    }
    if blk[12] != blk[14] || blk[13] != blk[15] || blk[12] != !blk[13] {
        return None;
    }
    Some((v0, blk[12]))
}

// ---------------------------------------------------------------------------
// Gen3 APDU & Gen4 Ultimate Magic Card (UMC) hardware write frame builders
// ---------------------------------------------------------------------------

/// Gen3 Magic MIFARE APDU: write 16-byte Block 0 (`90 F0 CC CC 10 <block0>`).
pub fn build_gen3_write_block0(block0: &[u8; 16]) -> [u8; 21] {
    let mut out = [0u8; 21];
    out[0..5].copy_from_slice(&[0x90, 0xF0, 0xCC, 0xCC, 0x10]);
    out[5..21].copy_from_slice(block0);
    out
}

/// Gen3 Magic MIFARE APDU: write 7-byte UID directly (`90 FB CC CC 07 <uid7>`).
pub fn build_gen3_write_uid7(uid7: &[u8; 7]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..5].copy_from_slice(&[0x90, 0xFB, 0xCC, 0xCC, 0x07]);
    out[5..12].copy_from_slice(uid7);
    out
}

/// Gen3 / UFUID permanent lock APDU (`90 FD 11 11 00`).
pub const GEN3_LOCK_CMD: [u8; 5] = [0x90, 0xFD, 0x11, 0x11, 0x00];

/// Gen4 Ultimate Magic Card (UMC) target emulation mode byte (config byte 0).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gen4Mode {
    MifareClassic1K = 0x00,
    MifareClassic4K = 0x01,
    Ultralight = 0x02,
    Ntag213 = 0x03,
    Ntag215 = 0x04,
    Ntag216 = 0x05,
}

/// Gen4 UMC: Get 32-byte card configuration (`CF <pwd4> C6`).
pub fn build_gen4_get_config(pwd: [u8; 4]) -> [u8; 6] {
    [0xCF, pwd[0], pwd[1], pwd[2], pwd[3], 0xC6]
}

/// Gen4 UMC: Direct block/page read without Crypto1 auth (`CF <pwd4> CE <block>`).
pub fn build_gen4_read_block(pwd: [u8; 4], block: u8) -> [u8; 7] {
    [0xCF, pwd[0], pwd[1], pwd[2], pwd[3], 0xCE, block]
}

/// Gen4 UMC: Direct 16-byte block write (including Block 0) without Crypto1 auth (`CF <pwd4> CD <block> <16B>`).
/// Validates access bits automatically when writing a MIFARE sector trailer!
pub fn build_gen4_write_block(
    pwd: [u8; 4],
    block: u8,
    data: &[u8; 16],
    check_trailer: bool,
) -> Result<[u8; 23], TagError> {
    if check_trailer && is_mfc_trailer_block(block as u16) {
        if !validate_mfc_access_bits([data[6], data[7], data[8]]) {
            return Err(TagError::InvalidAccessBits);
        }
    }
    let mut out = [0u8; 23];
    out[0] = 0xCF;
    out[1..5].copy_from_slice(&pwd);
    out[5] = 0xCD;
    out[6] = block;
    out[7..23].copy_from_slice(data);
    Ok(out)
}

/// Gen4 UMC: Build full `CF <pwd4> F0 <cfg>` configuration frame to reconfigure card persona
/// (mode, UID length 4/7/10B, ATQA, SAK, Gen1a/Gen2 compat, shadow mode).
pub fn build_gen4_set_config(
    pwd: [u8; 4],
    mode: Gen4Mode,
    uid_len: u8,
    atqa: [u8; 2],
    sak: u8,
    enable_gen2_write: bool,
    shadow_mode: u8,
) -> Result<[u8; 34], TagError> {
    let uid_len_code = match uid_len {
        4 => 0x00,
        7 => 0x01,
        10 => 0x02,
        _ => return Err(TagError::InvalidLength),
    };
    // Standard 28-byte UMC configuration block (CF <pwd4> F0 <28B cfg>)
    let mut out = [0u8; 34];
    out[0] = 0xCF;
    out[1..5].copy_from_slice(&pwd);
    out[5] = 0xF0;
    let cfg = &mut out[6..34];
    cfg[0] = mode as u8;
    cfg[1] = 0x00; // Total sectors / auto
    cfg[2] = if enable_gen2_write { 0x02 } else { 0x01 }; // 0x02 = Gen2 direct write enabled
    cfg[3] = uid_len_code;
    cfg[4] = 0x00; // ATS len = 0
    cfg[5] = sak;
    cfg[6] = atqa[0];
    cfg[7] = atqa[1];
    cfg[8] = shadow_mode.min(2); // 0=pre-write, 1=restore, 2=high-speed
    Ok(out)
}

/// Gen4 UMC: Change 4-byte backdoor password (`CF <old_pwd4> FE <new_pwd4>`).
pub fn build_gen4_set_pwd(old_pwd: [u8; 4], new_pwd: [u8; 4]) -> [u8; 10] {
    [
        0xCF, old_pwd[0], old_pwd[1], old_pwd[2], old_pwd[3],
        0xFE, new_pwd[0], new_pwd[1], new_pwd[2], new_pwd[3],
    ]
}

// ---------------------------------------------------------------------------
// NTAG213/215/216 / Ultralight / Magic NTAG writer + anti-brick lock guard
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtagVariant {
    Ultralight = 0, // 16 pages (user 4..=15)
    UltralightC = 1, // 48 pages (user 4..=39)
    Ntag213 = 2,    // 45 pages (user 4..=39)
    Ntag215 = 3,    // 135 pages (user 4..=129)
    Ntag216 = 4,    // 231 pages (user 4..=225)
}

impl NtagVariant {
    pub const fn total_pages(self) -> u8 {
        match self {
            Self::Ultralight => 16,
            Self::UltralightC => 48,
            Self::Ntag213 => 45,
            Self::Ntag215 => 135,
            Self::Ntag216 => 231,
        }
    }

    pub const fn user_page_range(self) -> (u8, u8) {
        match self {
            Self::Ultralight => (4, 15),
            Self::UltralightC => (4, 39),
            Self::Ntag213 => (4, 39),
            Self::Ntag215 => (4, 129),
            Self::Ntag216 => (4, 225),
        }
    }

    /// Detects NTAG213/215/216 from 8-byte `GET_VERSION (0x60)` response (storage byte 6).
    pub const fn from_get_version(resp: &[u8]) -> Option<Self> {
        if resp.len() < 7 || resp[1] != 0x04 {
            return None;
        }
        match resp[6] {
            0x0F => Some(Self::Ntag213),
            0x11 => Some(Self::Ntag215),
            0x13 => Some(Self::Ntag216),
            _ => None,
        }
    }
}

/// True if writing `page` could permanently lock or alter password/config bytes on `variant`.
pub const fn is_ntag_lock_or_cfg_page(variant: NtagVariant, page: u8) -> bool {
    let (first_user, last_user) = variant.user_page_range();
    page < first_user || page > last_user
}

/// `NfcA.transceive` frame: NTAG/Ultralight 4-byte page write (`0xA2 <page> <d0..d3>`).
pub fn build_ntag_write_page(
    variant: NtagVariant,
    page: u8,
    data: [u8; 4],
    allow_protected: bool,
) -> Result<[u8; 6], TagError> {
    if page >= variant.total_pages() {
        return Err(TagError::InvalidSectorOrBlock);
    }
    if !allow_protected && is_ntag_lock_or_cfg_page(variant, page) {
        return Err(TagError::ProtectedPage);
    }
    Ok([0xA2, page, data[0], data[1], data[2], data[3]])
}

#[inline]
pub const fn build_ntag_fast_read(start_page: u8, end_page: u8) -> [u8; 3] {
    [0x3A, start_page, end_page]
}

#[inline]
pub const fn build_ntag_pwd_auth(pwd: [u8; 4]) -> [u8; 5] {
    [0x1B, pwd[0], pwd[1], pwd[2], pwd[3]]
}

/// Wraps an NDEF message in Type-2 Tag TLV (`03 <len> <ndef> FE`, zero-padded to 4-byte pages)
/// starting at Page 4. Returns `(page_num, [u8; 4])` list ready for `0xA2` writes.
pub fn build_ntag_ndef_pages(
    variant: NtagVariant,
    ndef_msg: &[u8],
) -> Result<Vec<(u8, [u8; 4])>, TagError> {
    let (start, end) = variant.user_page_range();
    let max_bytes = ((end - start + 1) as usize) * 4;
    let hdr_len = if ndef_msg.len() < 0xFF { 2 } else { 4 };
    let total = hdr_len + ndef_msg.len() + 1; // + 0xFE terminator
    if total > max_bytes {
        return Err(TagError::CapacityExceeded);
    }
    let padded = (total + 3) & !3;
    let mut stream = vec![0u8; padded];
    stream[0] = 0x03; // NDEF Message TLV
    if ndef_msg.len() < 0xFF {
        stream[1] = ndef_msg.len() as u8;
        stream[2..2 + ndef_msg.len()].copy_from_slice(ndef_msg);
        stream[2 + ndef_msg.len()] = 0xFE;
    } else {
        stream[1] = 0xFF;
        stream[2] = (ndef_msg.len() >> 8) as u8;
        stream[3] = (ndef_msg.len() & 0xFF) as u8;
        stream[4..4 + ndef_msg.len()].copy_from_slice(ndef_msg);
        stream[4 + ndef_msg.len()] = 0xFE;
    }
    let mut pages = Vec::with_capacity(padded / 4);
    for (i, chunk) in stream.chunks_exact(4).enumerate() {
        pages.push((start + i as u8, [chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Ok(pages)
}

// ---------------------------------------------------------------------------
// ISO 15693 (NFC-V) & FeliCa Lite-S (Type 3) physical tag write frame builders
// ---------------------------------------------------------------------------

/// ISO 15693 `NfcV.transceive` Get System Information (`flags=0x22` addressed + 8B UID + `0x2B`).
pub fn build_nfcv_get_sys_info(uid8: [u8; 8]) -> [u8; 10] {
    let mut f = [0u8; 10];
    f[0] = 0x22; // High data rate + Addressed
    f[1] = 0x2B;
    f[2..10].copy_from_slice(&uid8);
    f
}

/// ISO 15693 `NfcV.transceive` Read Single Block (`0x22 0x20 <uid8> <block>`).
pub fn build_nfcv_read_block(uid8: [u8; 8], block: u8) -> [u8; 11] {
    let mut f = [0u8; 11];
    f[0] = 0x22;
    f[1] = 0x20;
    f[2..10].copy_from_slice(&uid8);
    f[10] = block;
    f
}

/// ISO 15693 `NfcV.transceive` Write Single Block (`0x22 0x21 <uid8> <block> <data>`).
pub fn build_nfcv_write_block(uid8: [u8; 8], block: u8, data: &[u8]) -> Result<Vec<u8>, TagError> {
    if !matches!(data.len(), 4 | 8) {
        return Err(TagError::InvalidLength);
    }
    let mut f = Vec::with_capacity(11 + data.len());
    f.push(0x22);
    f.push(0x21);
    f.extend_from_slice(&uid8);
    f.push(block);
    f.extend_from_slice(data);
    Ok(f)
}

/// FeliCa Lite-S `NfcF.transceive` Read Without Encryption (`0x06`, service `0x000B` R/O).
pub fn build_felica_read_block(idm: [u8; 8], block_num: u8) -> [u8; 16] {
    let mut f = [0u8; 16];
    f[0] = 16;   // Length
    f[1] = 0x06; // Read Without Encryption
    f[2..10].copy_from_slice(&idm);
    f[10] = 1;   // 1 service
    f[11] = 0x0B; // Service code 0x000B (little-endian: 0B 00 = NDEF/Lite-S read)
    f[12] = 0x00;
    f[13] = 1;   // 1 block
    f[14] = 0x80; // 2-byte block list element, service 0
    f[15] = block_num;
    f
}

/// FeliCa Lite-S `NfcF.transceive` Write Without Encryption (`0x08`, service `0x0009` R/W, 16B block).
pub fn build_felica_write_block(idm: [u8; 8], block_num: u8, data: &[u8; 16]) -> [u8; 32] {
    let mut f = [0u8; 32];
    f[0] = 32;   // Length
    f[1] = 0x08; // Write Without Encryption
    f[2..10].copy_from_slice(&idm);
    f[10] = 1;
    f[11] = 0x09; // Service code 0x0009 (little-endian: 09 00 = Lite-S R/W)
    f[12] = 0x00;
    f[13] = 1;
    f[14] = 0x80;
    f[15] = block_num;
    f[16..32].copy_from_slice(data);
    f
}

// ---------------------------------------------------------------------------
// Multi-format Dump Codecs: MCT `.mct`, Flipper Zero `.nfc`, Raw `.bin`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCardDump {
    pub tech: u8, // 1=NFC-A, 2=NFC-B, 3=NFC-F, 4=NFC-V
    pub uid: Vec<u8>,
    pub atqa: [u8; 2],
    pub sak: u8,
    pub ats: Vec<u8>,
    pub system_code: [u8; 2],
    pub pmm: [u8; 8],
    /// MIFARE Classic blocks (64 for 1K, 256 for 4K) or NTAG pages (4 bytes each).
    pub mfc_blocks: Vec<[u8; 16]>,
    pub ntag_pages: Vec<[u8; 4]>,
}

/// Parses MIFARE Classic Tool `.mct` text dump (`+Sector: N` followed by 32-hex-char lines).
/// Supports unknown bytes marked as `-` (substituted with `0x00`).
pub fn parse_mct(text: &str) -> Result<ParsedCardDump, TagError> {
    let mut sectors: Vec<(usize, Vec<[u8; 16]>)> = Vec::new();
    let mut cur_sector: Option<usize> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("+Sector:") {
            let sec: usize = rest.trim().parse().map_err(|_| TagError::InvalidFormat)?;
            if sec >= 40 {
                return Err(TagError::InvalidSectorOrBlock);
            }
            cur_sector = Some(sec);
            sectors.push((sec, Vec::with_capacity(if sec < 32 { 4 } else { 16 })));
            continue;
        }
        if let Some((_, blocks)) = sectors.last_mut() {
            if cur_sector.is_none() || line.len() != 32 {
                return Err(TagError::InvalidFormat);
            }
            let sanitized: String = line
                .bytes()
                .map(|b| if b == b'-' { '0' } else { b as char })
                .collect();
            let mut blk = [0u8; 16];
            if hex_decode_into(&sanitized, &mut blk) != Some(16) {
                return Err(TagError::InvalidHex);
            }
            blocks.push(blk);
        }
    }
    if sectors.is_empty() {
        return Err(TagError::InvalidFormat);
    }

    let max_sec = sectors.iter().map(|(s, _)| *s).max().unwrap_or(0);
    let total_blocks = if max_sec >= 16 { 256 } else { 64 };
    let mut mfc_blocks = vec![[0u8; 16]; total_blocks];
    for (sec, blks) in sectors {
        let base = if sec < 32 { sec * 4 } else { 128 + (sec - 32) * 16 };
        for (i, b) in blks.into_iter().enumerate() {
            if base + i < total_blocks {
                mfc_blocks[base + i] = b;
            }
        }
    }
    let b0 = mfc_blocks[0];
    let (uid, sak, atqa) = if bcc_uid4([b0[0], b0[1], b0[2], b0[3]]) == b0[4] {
        (b0[0..4].to_vec(), b0[5], [b0[6], b0[7]])
    } else {
        (
            b0[0..7].to_vec(),
            if total_blocks == 256 { 0x18 } else { 0x08 },
            [0x44, 0x00],
        )
    };
    Ok(ParsedCardDump {
        tech: 1,
        uid,
        atqa,
        sak,
        ats: Vec::new(),
        system_code: [0; 2],
        pmm: [0; 8],
        mfc_blocks,
        ntag_pages: Vec::new(),
    })
}

/// Exports MIFARE Classic blocks to MIFARE Classic Tool `.mct` text format.
pub fn export_mct(blocks: &[[u8; 16]]) -> String {
    let sectors = if blocks.len() > 64 { 40 } else { blocks.len() / 4 };
    let mut out = String::with_capacity(blocks.len() * 34 + sectors * 14);
    let mut hex_line = [0u8; 32];
    for sec in 0..sectors {
        let (base, count) = if sec < 32 { (sec * 4, 4) } else { (128 + (sec - 32) * 16, 16) };
        if base >= blocks.len() {
            break;
        }
        out.push_str("+Sector: ");
        out.push_str(&sec.to_string());
        out.push('\n');
        for i in 0..count {
            if base + i >= blocks.len() {
                break;
            }
            crate::hex_encode_into(&blocks[base + i], &mut hex_line);
            out.push_str(unsafe { std::str::from_utf8_unchecked(&hex_line) });
            out.push('\n');
        }
    }
    out
}

/// Parses Flipper Zero `.nfc` file (v2/v3/v4: ISO 14443-3A/4A, MIFARE Classic, NTAG/UL, FeliCa, ISO 14443-3B).
pub fn parse_flipper_nfc(text: &str) -> Result<ParsedCardDump, TagError> {
    let mut tech = 1u8;
    let mut uid = Vec::new();
    let mut atqa = [0x04u8, 0x00u8];
    let mut sak = 0x08u8;
    let mut ats = Vec::new();
    let mut system_code = [0u8; 2];
    let mut pmm = [0u8; 8];
    let mut mfc_blocks: Vec<(usize, [u8; 16])> = Vec::new();
    let mut ntag_pages: Vec<(usize, [u8; 4])> = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        match key {
            "Device type" => {
                if val.contains("FeliCa") {
                    tech = 3;
                } else if val.contains("14443-3B") || val.contains("14443-4B") {
                    tech = 2;
                } else if val.contains("15693") {
                    tech = 4;
                }
            }
            "UID" | "IDm" | "PUPI" => {
                uid = hex_decode(val).ok_or(TagError::InvalidHex)?;
            }
            "ATQA" => {
                let bytes = hex_decode(val).ok_or(TagError::InvalidHex)?;
                if bytes.len() == 2 {
                    // Flipper stores ATQA as MSB LSB (e.g. `00 04` for MIFARE 1K -> wire `04 00`)
                    // Normalize: standard 14443-3A wire byte 0 has SDD bit in low 5 bits.
                    if bytes[0] == 0x00 && (bytes[1] & 0x1F) != 0 {
                        atqa = [bytes[1], bytes[0]];
                    } else {
                        atqa = [bytes[0], bytes[1]];
                    }
                }
            }
            "SAK" => {
                let bytes = hex_decode(val).ok_or(TagError::InvalidHex)?;
                if bytes.len() == 1 {
                    sak = bytes[0];
                }
            }
            "ATS" | "Historical bytes" => {
                ats = hex_decode(val).unwrap_or_default();
            }
            "PMm" => {
                let bytes = hex_decode(val).ok_or(TagError::InvalidHex)?;
                if bytes.len() == 8 {
                    pmm.copy_from_slice(&bytes);
                }
            }
            "System code" => {
                let bytes = hex_decode(val).ok_or(TagError::InvalidHex)?;
                if bytes.len() == 2 {
                    system_code.copy_from_slice(&bytes);
                }
            }
            k if k.starts_with("Block ") => {
                if let Ok(idx) = k[6..].trim().parse::<usize>() {
                    let clean: String = val
                        .bytes()
                        .map(|b| if b == b'?' { '0' } else { b as char })
                        .collect();
                    let mut blk = [0u8; 16];
                    if hex_decode_into(&clean, &mut blk) == Some(16) {
                        mfc_blocks.push((idx, blk));
                    }
                }
            }
            k if k.starts_with("Page ") => {
                if let Ok(idx) = k[5..].trim().parse::<usize>() {
                    let mut pg = [0u8; 4];
                    if hex_decode_into(val, &mut pg) == Some(4) {
                        ntag_pages.push((idx, pg));
                    }
                }
            }
            _ => {}
        }
    }

    if uid.is_empty() {
        return Err(TagError::InvalidFormat);
    }

    let mut dense_mfc = Vec::new();
    if let Some(max_b) = mfc_blocks.iter().map(|(i, _)| *i).max() {
        dense_mfc.resize(max_b + 1, [0u8; 16]);
        for (i, b) in mfc_blocks {
            dense_mfc[i] = b;
        }
    }
    let mut dense_ntag = Vec::new();
    if let Some(max_p) = ntag_pages.iter().map(|(i, _)| *i).max() {
        dense_ntag.resize(max_p + 1, [0u8; 4]);
        for (i, p) in ntag_pages {
            dense_ntag[i] = p;
        }
    }

    Ok(ParsedCardDump {
        tech,
        uid,
        atqa,
        sak,
        ats,
        system_code,
        pmm,
        mfc_blocks: dense_mfc,
        ntag_pages: dense_ntag,
    })
}

/// Exports a card to Flipper Zero `.nfc` v4 format.
pub fn export_flipper_nfc(dump: &ParsedCardDump) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("Filetype: Flipper NFC device\nVersion: 4\n");
    let dev = match dump.tech {
        2 => "ISO14443-3B",
        3 => "FeliCa",
        4 => "ISO15693",
        _ if !dump.mfc_blocks.is_empty() => "Mifare Classic",
        _ if !dump.ntag_pages.is_empty() => "NTAG/Ultralight",
        _ => "ISO14443-3A",
    };
    out.push_str("Device type: ");
    out.push_str(dev);
    out.push('\n');
    let id_label = match dump.tech {
        2 => "PUPI: ",
        3 => "IDm: ",
        _ => "UID: ",
    };
    out.push_str(id_label);
    push_spaced_hex(&mut out, &dump.uid);
    out.push('\n');
    if dump.tech == 1 {
        out.push_str("ATQA: ");
        push_spaced_hex(&mut out, &[dump.atqa[1], dump.atqa[0]]);
        out.push('\n');
        out.push_str("SAK: ");
        out.push_str(&hex_encode(&[dump.sak]));
        out.push('\n');
    } else if dump.tech == 3 {
        out.push_str("PMm: ");
        push_spaced_hex(&mut out, &dump.pmm);
        out.push('\n');
        out.push_str("System code: ");
        push_spaced_hex(&mut out, &dump.system_code);
        out.push('\n');
    }
    for (i, b) in dump.mfc_blocks.iter().enumerate() {
        out.push_str("Block ");
        out.push_str(&i.to_string());
        out.push_str(": ");
        push_spaced_hex(&mut out, b);
        out.push('\n');
    }
    for (i, p) in dump.ntag_pages.iter().enumerate() {
        out.push_str("Page ");
        out.push_str(&i.to_string());
        out.push_str(": ");
        push_spaced_hex(&mut out, p);
        out.push('\n');
    }
    out
}

fn push_spaced_hex(out: &mut String, bytes: &[u8]) {
    const LUT: &[u8; 16] = b"0123456789ABCDEF";
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0F) as usize] as char);
    }
}

/// Parses raw binary dump (MIFARE 1K 1024B / 4K 4096B / NTAG213 180B / NTAG215 540B / NTAG216 924B).
pub fn parse_raw_bin(data: &[u8]) -> Result<ParsedCardDump, TagError> {
    match data.len() {
        1024 | 4096 => {
            let mut blocks = Vec::with_capacity(data.len() / 16);
            for chunk in data.chunks_exact(16) {
                let mut b = [0u8; 16];
                b.copy_from_slice(chunk);
                blocks.push(b);
            }
            let b0 = blocks[0];
            let (uid, sak, atqa) = if bcc_uid4([b0[0], b0[1], b0[2], b0[3]]) == b0[4] {
                (b0[0..4].to_vec(), b0[5], [b0[6], b0[7]])
            } else {
                (
                    b0[0..7].to_vec(),
                    if data.len() == 4096 { 0x18 } else { 0x08 },
                    [0x44, 0x00],
                )
            };
            Ok(ParsedCardDump {
                tech: 1,
                uid,
                atqa,
                sak,
                ats: Vec::new(),
                system_code: [0; 2],
                pmm: [0; 8],
                mfc_blocks: blocks,
                ntag_pages: Vec::new(),
            })
        }
        64 | 180 | 192 | 540 | 924 => {
            let mut pages = Vec::with_capacity(data.len() / 4);
            for chunk in data.chunks_exact(4) {
                pages.push([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            // Type-2 7-byte UID sits in page 0 bytes 0..3 and page 1 bytes 0..4
            let mut uid = Vec::with_capacity(7);
            uid.extend_from_slice(&pages[0][0..3]);
            uid.extend_from_slice(&pages[1][0..4]);
            Ok(ParsedCardDump {
                tech: 1,
                uid,
                atqa: [0x44, 0x00],
                sak: 0x00,
                ats: Vec::new(),
                system_code: [0; 2],
                pmm: [0; 8],
                mfc_blocks: Vec::new(),
                ntag_pages: pages,
            })
        }
        _ => Err(TagError::InvalidLength),
    }
}

// ---------------------------------------------------------------------------
// Indonesian e-Money Read-Only Inspector (Mandiri, BCA Flazz, BNI TapCash, BRI Brizzi)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EMoneyIssuer {
    Unknown = 0,
    MandiriEMoney = 1,
    BcaFlazz = 2,
    BniTapCash = 3,
    BriBrizzi = 4,
    KmtFelica = 5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EMoneyInfo {
    pub issuer: EMoneyIssuer,
    pub card_number: String,
    pub balance_idr: u64,
}

/// Read-only ISO-DEP APDU probe constants for Indonesian prepaid cards.
pub const APDU_MANDIRI_SELECT: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
pub const APDU_MANDIRI_CARD_INFO: &[u8] = &[0x00, 0xB3, 0x00, 0x00, 0x3F];
pub const APDU_MANDIRI_BALANCE: &[u8] = &[0x00, 0xB5, 0x00, 0x00, 0x0A];

pub const APDU_FLAZZ_SELECT: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x0B, 0xA0, 0x00, 0x00, 0x00, 0x18, 0x0F, 0x00, 0x00, 0x01, 0x80, 0x01,
];
pub const APDU_FLAZZ_BALANCE: &[u8] = &[0x80, 0x32, 0x00, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];

pub const APDU_TAPCASH_SELECT: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x42, 0x4E, 0x49, 0x10, 0x00, 0x01,
];
pub const APDU_TAPCASH_BALANCE: &[u8] = &[0x90, 0x32, 0x03, 0x00, 0x00];

pub const APDU_BRIZZI_SELECT: &[u8] = &[
    0x90, 0x5A, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00,
];
pub const APDU_BRIZZI_CARD_INFO: &[u8] = &[0x90, 0xBD, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00];
pub const APDU_BRIZZI_BALANCE: &[u8] = &[0x90, 0x6C, 0x00, 0x00, 0x01, 0x03, 0x00];

fn is_sw_ok(resp: &[u8]) -> bool {
    resp.len() >= 2
        && ((resp[resp.len() - 2] == 0x90 && resp[resp.len() - 1] == 0x00)
            || (resp[resp.len() - 2] == 0x91 && resp[resp.len() - 1] == 0x00))
}

fn bcd_digits(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let hi = (b >> 4) & 0x0F;
        let lo = b & 0x0F;
        if hi <= 9 {
            s.push((b'0' + hi) as char);
        }
        if lo <= 9 {
            s.push((b'0' + lo) as char);
        }
    }
    s
}

/// Decodes raw read-only APDU responses for Indonesian prepaid transit/e-Money cards.
pub fn decode_emoney(
    issuer: EMoneyIssuer,
    info_resp: &[u8],
    balance_resp: &[u8],
) -> Option<EMoneyInfo> {
    if !is_sw_ok(balance_resp) {
        return None;
    }
    let bal_data = &balance_resp[..balance_resp.len() - 2];
    match issuer {
        EMoneyIssuer::MandiriEMoney => {
            if bal_data.len() < 4 {
                return None;
            }
            // Mandiri balance: 4-byte little-endian unsigned IDR
            let balance = u32::from_le_bytes([bal_data[0], bal_data[1], bal_data[2], bal_data[3]]) as u64;
            let card_number = if is_sw_ok(info_resp) && info_resp.len() >= 10 {
                bcd_digits(&info_resp[0..8])
            } else {
                String::new()
            };
            Some(EMoneyInfo { issuer, card_number, balance_idr: balance })
        }
        EMoneyIssuer::BcaFlazz => {
            if bal_data.len() < 4 {
                return None;
            }
            // BCA Flazz balance: 3-byte or 4-byte big-endian IDR
            let balance = u32::from_be_bytes([bal_data[0], bal_data[1], bal_data[2], bal_data[3]]) as u64;
            let card_number = if is_sw_ok(info_resp) && info_resp.len() >= 10 {
                bcd_digits(&info_resp[0..8])
            } else {
                String::new()
            };
            Some(EMoneyInfo { issuer, card_number, balance_idr: balance })
        }
        EMoneyIssuer::BniTapCash => {
            // BNI TapCash: 3-byte signed/unsigned big-endian balance in bytes 2..5 (or 0..4)
            if bal_data.len() < 4 {
                return None;
            }
            let balance = if bal_data.len() >= 6 {
                ((bal_data[2] as u64) << 16) | ((bal_data[3] as u64) << 8) | (bal_data[4] as u64)
            } else {
                u32::from_be_bytes([bal_data[0], bal_data[1], bal_data[2], bal_data[3]]) as u64
            };
            let card_number = if is_sw_ok(info_resp) && info_resp.len() >= 10 {
                bcd_digits(&info_resp[0..8])
            } else {
                String::new()
            };
            Some(EMoneyInfo { issuer, card_number, balance_idr: balance })
        }
        EMoneyIssuer::BriBrizzi => {
            // DESFire GetValue (0x6C): 4-byte little-endian signed value
            if bal_data.len() < 4 {
                return None;
            }
            let balance = i32::from_le_bytes([bal_data[0], bal_data[1], bal_data[2], bal_data[3]]).max(0) as u64;
            let card_number = if is_sw_ok(info_resp) && info_resp.len() >= 13 {
                bcd_digits(&info_resp[3..11])
            } else {
                String::new()
            };
            Some(EMoneyInfo { issuer, card_number, balance_idr: balance })
        }
        EMoneyIssuer::KmtFelica | EMoneyIssuer::Unknown => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfc_block0_and_access_bits_guard() {
        let b0 = build_mfc_block0(&[0xDE, 0xAD, 0xBE, 0xEF], 0x08, [0x04, 0x00], None).unwrap();
        assert_eq!(b0[4], 0xDE ^ 0xAD ^ 0xBE ^ 0xEF);
        assert_eq!(b0[5], 0x08);
        assert_eq!(&b0[6..8], &[0x04, 0x00]);

        // Factory default transport access bits FF 07 80 are valid; corrupted 00 00 00 is rejected!
        assert!(validate_mfc_access_bits([0xFF, 0x07, 0x80]));
        assert!(validate_mfc_access_bits([0x78, 0x77, 0x88]));
        assert!(!validate_mfc_access_bits([0x00, 0x00, 0x00]));
        assert!(!validate_mfc_access_bits([0xFF, 0x07, 0x81]));

        // Gen4 block write refuses to brick sector trailer 3 with bad access bits
        let mut bad_trailer = [0xFFu8; 16];
        bad_trailer[6] = 0x00;
        bad_trailer[7] = 0x00;
        bad_trailer[8] = 0x00;
        assert_eq!(
            build_gen4_write_block([0; 4], 3, &bad_trailer, true),
            Err(TagError::InvalidAccessBits)
        );
        bad_trailer[6] = 0xFF;
        bad_trailer[7] = 0x07;
        bad_trailer[8] = 0x80;
        let ok_cmd = build_gen4_write_block([0; 4], 3, &bad_trailer, true).unwrap();
        assert_eq!(&ok_cmd[0..7], &[0xCF, 0, 0, 0, 0, 0xCD, 3]);
    }

    #[test]
    fn value_block_round_trip() {
        let vb = encode_mfc_value_block(50_000, 4);
        assert_eq!(decode_mfc_value_block(&vb), Some((50_000, 4)));
        let mut corrupt = vb;
        corrupt[0] ^= 1;
        assert_eq!(decode_mfc_value_block(&corrupt), None);
    }

    #[test]
    fn ntag_anti_brick_and_ndef_pages() {
        // Page 2 (lock bytes) & Page 41 (CFG0 on NTAG213) blocked by default
        assert_eq!(
            build_ntag_write_page(NtagVariant::Ntag213, 2, [0; 4], false),
            Err(TagError::ProtectedPage)
        );
        assert_eq!(
            build_ntag_write_page(NtagVariant::Ntag213, 41, [0; 4], false),
            Err(TagError::ProtectedPage)
        );
        assert!(build_ntag_write_page(NtagVariant::Ntag213, 4, [1, 2, 3, 4], false).is_ok());

        let ndef = crate::apdu::encode_ndef_uri("https://yasvara.org");
        let pages = build_ntag_ndef_pages(NtagVariant::Ntag213, &ndef).unwrap();
        assert_eq!(pages[0].0, 4);
        assert_eq!(pages[0].1[0], 0x03);
        assert_eq!(pages[0].1[1] as usize, ndef.len());
    }

    #[test]
    fn mct_and_flipper_round_trip() {
        let mut blks = vec![[0u8; 16]; 64];
        blks[0] = build_mfc_block0(&[0xDE, 0xAD, 0xBE, 0xEF], 0x08, [0x04, 0x00], None).unwrap();
        blks[3] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mct = export_mct(&blks);
        let parsed = parse_mct(&mct).unwrap();
        assert_eq!(parsed.uid, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(parsed.sak, 0x08);
        assert_eq!(parsed.mfc_blocks[0], blks[0]);

        let flipper = export_flipper_nfc(&parsed);
        let reparsed = parse_flipper_nfc(&flipper).unwrap();
        assert_eq!(reparsed.uid, parsed.uid);
        assert_eq!(reparsed.sak, 0x08);
        assert_eq!(reparsed.atqa, [0x04, 0x00]);
        assert_eq!(reparsed.mfc_blocks[0], blks[0]);
    }

    #[test]
    fn emoney_decoders() {
        // Mandiri: 150,000 IDR = 0x000249F0 little-endian -> F0 49 02 00
        let info = [0x60, 0x32, 0x98, 0x10, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x90, 0x00];
        let bal = [0xF0, 0x49, 0x02, 0x00, 0x90, 0x00];
        let decoded = decode_emoney(EMoneyIssuer::MandiriEMoney, &info, &bal).unwrap();
        assert_eq!(decoded.balance_idr, 150_000);
        assert_eq!(decoded.card_number, "6032981012345678");

        // BRI Brizzi DESFire status 91 00, 75,000 IDR LE = F8 24 01 00
        let brizzi_bal = [0xF8, 0x24, 0x01, 0x00, 0x91, 0x00];
        let bd = decode_emoney(EMoneyIssuer::BriBrizzi, &[], &brizzi_bal).unwrap();
        assert_eq!(bd.balance_idr, 75_000);
    }
}
