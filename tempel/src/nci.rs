// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Hardware-verified NCI 2.0 & NXP SN220U encoders and validators.
//!
//! All parameter IDs and formats verified against live onyx (SN220U FW 01.01.3F):
//! - Type-A (`emulateNfcTechnologyATag`): `0x30` `LA_BIT_FRAME_SDD`, `0x31` `LA_PLATFORM_CONFIG`,
//!   `0x32` `LA_SEL_INFO`, `0x33` `LA_NFCID1` (4/7/10B), `0x58` `LI_A_RATS_TB1`, `0x59` `LI_A_HIST_BY`.
//! - Type-B (`20 02` `CORE_SET_CONFIG`): `0x38` `LB_SENSB_INFO`, `0x39` `LB_NFCID0` (4B PUPI),
//!   `0x3A` `LB_APPLICATION_DATA` (4B), `0x3E` `LB_H_INFO_RESP` (<=16B).
//! - Type-F (`20 02` `CORE_SET_CONFIG`): `0x40..=0x43` `LF_T3T_ID1..4` (18B = SC[2]+IDm[8]+PMm[8]),
//!   `0x53` `LF_T3T_FLAGS` (2B bitmask). Accepts arbitrary non-`02FE` IDm without AOSP Nfc fork.
//! - Hardware 40-key MIFARE verifier (`2F 45`): Op `0x01` KeyInfo, Op `0x02` KeyList (<=40x6B),
//!   NTF `6F 45` status decoder.

/// NCI 2.0 parameter IDs (volatile RAM RF listen registers — NEVER touches 0xA0xx EEPROM).
pub const PMID_LA_BIT_FRAME_SDD: u8 = 0x30;
pub const PMID_LA_PLATFORM_CONFIG: u8 = 0x31;
pub const PMID_LA_SEL_INFO: u8 = 0x32;
pub const PMID_LA_NFCID1: u8 = 0x33;
pub const PMID_LB_SENSB_INFO: u8 = 0x38;
pub const PMID_LB_NFCID0: u8 = 0x39;
pub const PMID_LB_APPLICATION_DATA: u8 = 0x3A;
pub const PMID_LB_H_INFO_RESP: u8 = 0x3E;
pub const PMID_LF_T3T_ID1: u8 = 0x40;
pub const PMID_LF_T3T_FLAGS: u8 = 0x53;
pub const PMID_LI_A_RATS_TB1: u8 = 0x58;
pub const PMID_LI_A_HIST_BY: u8 = 0x59;
pub const PMID_NFCC_CONFIG_CONTROL: u8 = 0x85;

/// NXP SN220U vendor NCI MIFARE 40-key verifier (`MT=1, GID=0x0F, OID=0x45`).
pub const NCI_MT_CMD: u8 = 1;
pub const NCI_GID_CORE: u8 = 0x00;
pub const NCI_GID_RF: u8 = 0x01;
pub const NCI_GID_PROP: u8 = 0x0F;
pub const NCI_OID_CORE_SET_CONFIG: u8 = 0x02;
pub const NCI_OID_CORE_GET_CONFIG: u8 = 0x03;
pub const NCI_OID_RF_DEACTIVATE: u8 = 0x06;
pub const NCI_OID_NXP_MFC_VERIFY: u8 = 0x45;

pub const MAX_ATS_HIST_LEN: usize = 15;
pub const MAX_LB_HINFO_LEN: usize = 16;
pub const MFC_VERIFY_MAX_KEYS_PER_BATCH: usize = 40;
pub const MFC_VERIFY_MAX_PAYLOAD: usize = 1 + MFC_VERIFY_MAX_KEYS_PER_BATCH * 6; // 241 B

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NciError {
    InvalidUidLength,
    InvalidAtqa,
    InvalidHistLength,
    InvalidSlot,
    InvalidKeyBatch,
    BufferTooSmall,
}

/// Validated parameters for Android 17 `NfcOemExtension.emulateNfcTechnologyATag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenAConfig {
    /// Masked 5-bit `LA_BIT_FRAME_SDD` (`atqa[0] & 0x1F`, Trap T3).
    pub bit_frame_sdd: u8,
    /// Masked 4-bit `LA_PLATFORM_CONFIG` (`atqa[1] & 0x0F`).
    pub platform_config: u8,
    /// `LA_SEL_INFO` (SAK). Never zero-length (Trap T5).
    pub sel_info: u8,
    /// 4, 7, or 10 bytes.
    pub uid: [u8; 10],
    pub uid_len: u8,
    /// `LI_A_RATS_TB1` (0x00 when non-ISO-DEP; e.g. 0x78 for ISO-DEP).
    pub rats_tb1: u8,
    /// `LI_A_HIST_BY` (ATS historical bytes, 0..=15 bytes).
    pub hist_bytes: [u8; MAX_ATS_HIST_LEN],
    pub hist_len: u8,
}

impl ListenAConfig {
    /// Builds and validates a Listen-A emulation config from raw scanned card parameters.
    ///
    /// Note on Trap T3: ISO 14443-3A ATQA byte 0 encodes UID size in bits 7..6 (`00`=4B, `01`=7B,
    /// `10`=10B) and bit-frame anticollision in bits 4..0 (usually `0x04`). NCI `LA_BIT_FRAME_SDD`
    /// only carries bits 4..0; the NFCC derives UID-size bits from `LA_NFCID1` length.
    pub fn from_card(
        uid: &[u8],
        atqa: [u8; 2],
        sak: u8,
        rats_tb1: u8,
        hist: &[u8],
    ) -> Result<Self, NciError> {
        if !matches!(uid.len(), 4 | 7 | 10) {
            return Err(NciError::InvalidUidLength);
        }
        if hist.len() > MAX_ATS_HIST_LEN {
            return Err(NciError::InvalidHistLength);
        }
        let sdd = atqa[0] & 0x1F;
        // Standard ISO 14443-3A requires exactly one of bits 4..0 set; default to 0x04 if 0.
        let bit_frame_sdd = if sdd == 0 { 0x04 } else { sdd };
        let platform_config = atqa[1] & 0x0F;

        let mut uid_buf = [0u8; 10];
        uid_buf[..uid.len()].copy_from_slice(uid);
        let mut hist_buf = [0u8; MAX_ATS_HIST_LEN];
        hist_buf[..hist.len()].copy_from_slice(hist);

        let is_isodep = (sak & 0x20) != 0;
        Ok(Self {
            bit_frame_sdd,
            platform_config,
            sel_info: sak,
            uid: uid_buf,
            uid_len: uid.len() as u8,
            rats_tb1: if is_isodep {
                if rats_tb1 == 0 { 0x78 } else { rats_tb1 }
            } else {
                0x00
            },
            hist_bytes: hist_buf,
            hist_len: if is_isodep { hist.len() as u8 } else { 0 },
        })
    }

    #[inline]
    pub fn uid_slice(&self) -> &[u8] {
        &self.uid[..self.uid_len as usize]
    }

    #[inline]
    pub fn hist_slice(&self) -> &[u8] {
        &self.hist_bytes[..self.hist_len as usize]
    }

    /// True if ISO-DEP bit (0x20) is cleared in SAK, which disables HCE/Payments (Trap T1).
    #[inline]
    pub const fn disables_payments(&self) -> bool {
        (self.sel_info & 0x20) == 0
    }

    /// True if ISO-DEP protocol routing should point to Host (`0x00`) instead of `eSE1` (Trap T4).
    #[inline]
    pub const fn supports_isodep(&self) -> bool {
        (self.sel_info & 0x20) != 0
    }
}

/// Validated Listen-B (ISO 14443-3B / 4B) config for `CORE_SET_CONFIG (20 02)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenBConfig {
    pub pupi: [u8; 4],
    pub app_data: [u8; 4],
    /// Bit 0 = ISO-DEP over Type-B (`0x01` for 4B HCE, `0x00` for 3B PUPI-only).
    pub sensb_info: u8,
    pub h_info_resp: [u8; MAX_LB_HINFO_LEN],
    pub h_info_len: u8,
}

impl ListenBConfig {
    pub fn new(
        pupi: [u8; 4],
        app_data: [u8; 4],
        isodep: bool,
        h_info: &[u8],
    ) -> Result<Self, NciError> {
        if h_info.len() > MAX_LB_HINFO_LEN {
            return Err(NciError::InvalidHistLength);
        }
        let mut h = [0u8; MAX_LB_HINFO_LEN];
        h[..h_info.len()].copy_from_slice(h_info);
        Ok(Self {
            pupi,
            app_data,
            sensb_info: if isodep { 0x01 } else { 0x00 },
            h_info_resp: h,
            h_info_len: h_info.len() as u8,
        })
    }

    /// Encodes `CORE_SET_CONFIG` payload (without 3-byte NCI header) directly into `out`.
    /// Sets `NFCC_CONFIG_CONTROL=0`, `LB_NFCID0`, `LB_APPLICATION_DATA`, `LB_SENSB_INFO`,
    /// and optional `LB_H_INFO_RESP`.
    pub fn encode_set_config_into(&self, out: &mut [u8]) -> Result<usize, NciError> {
        let has_hinfo = self.h_info_len > 0;
        let needed = 1 + 3 + 6 + 6 + 3 + if has_hinfo { 2 + self.h_info_len as usize } else { 0 };
        if out.len() < needed {
            return Err(NciError::BufferTooSmall);
        }
        let mut p = 0usize;
        out[p] = if has_hinfo { 5 } else { 4 };
        p += 1;

        // NFCC_CONFIG_CONTROL = 0x00
        out[p..p + 3].copy_from_slice(&[PMID_NFCC_CONFIG_CONTROL, 1, 0x00]);
        p += 3;

        // LB_NFCID0 (4B PUPI)
        out[p] = PMID_LB_NFCID0;
        out[p + 1] = 4;
        out[p + 2..p + 6].copy_from_slice(&self.pupi);
        p += 6;

        // LB_APPLICATION_DATA (4B)
        out[p] = PMID_LB_APPLICATION_DATA;
        out[p + 1] = 4;
        out[p + 2..p + 6].copy_from_slice(&self.app_data);
        p += 6;

        // LB_SENSB_INFO (1B)
        out[p..p + 3].copy_from_slice(&[PMID_LB_SENSB_INFO, 1, self.sensb_info]);
        p += 3;

        if has_hinfo {
            let hl = self.h_info_len as usize;
            out[p] = PMID_LB_H_INFO_RESP;
            out[p + 1] = self.h_info_len;
            out[p + 2..p + 2 + hl].copy_from_slice(&self.h_info_resp[..hl]);
            p += 2 + hl;
        }
        Ok(p)
    }

    /// Encodes volatile RAM restore payload for `CORE_SET_CONFIG` (clears custom PUPI/AppData).
    pub fn encode_reset_config_into(out: &mut [u8]) -> Result<usize, NciError> {
        const RESET: [u8; 15] = [
            4,
            PMID_LB_NFCID0, 0,
            PMID_LB_APPLICATION_DATA, 4, 0, 0, 0, 0,
            PMID_LB_SENSB_INFO, 1, 0x00,
            PMID_LB_H_INFO_RESP, 1, 0x00,
        ];
        if out.len() < RESET.len() {
            return Err(NciError::BufferTooSmall);
        }
        out[..RESET.len()].copy_from_slice(&RESET);
        Ok(RESET.len())
    }
}

/// Validated Listen-F (FeliCa / NFC-F) config for `CORE_SET_CONFIG (20 02)`.
/// Proven on SN220U FW 01.01.3F: accepts arbitrary 8-byte IDm (no `02FE` restriction!).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenFConfig {
    pub system_code: [u8; 2],
    pub idm: [u8; 8],
    pub pmm: [u8; 8],
    /// Hardware slot `0..4` (`LF_T3T_MAX=4` on SN220U).
    pub slot: u8,
}

impl ListenFConfig {
    pub const DEFAULT_PMM: [u8; 8] = [0x00, 0xF1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00];

    pub fn new(system_code: [u8; 2], idm: [u8; 8], pmm: [u8; 8], slot: u8) -> Result<Self, NciError> {
        if slot >= 4 {
            return Err(NciError::InvalidSlot);
        }
        Ok(Self { system_code, idm, pmm, slot })
    }

    /// Encodes `CORE_SET_CONFIG` payload (28 bytes): `NFCC_CONFIG_CONTROL=0`, 18-byte
    /// `LF_T3T_ID{slot+1}` (`SC[2] + IDm[8] + PMm[8]`), and 2-byte `LF_T3T_FLAGS` bitmask.
    pub fn encode_set_config_into(&self, out: &mut [u8]) -> Result<usize, NciError> {
        const LEN: usize = 1 + 3 + 20 + 4; // 28 bytes
        if out.len() < LEN {
            return Err(NciError::BufferTooSmall);
        }
        let mut p = 0usize;
        out[p] = 3;
        p += 1;

        out[p..p + 3].copy_from_slice(&[PMID_NFCC_CONFIG_CONTROL, 1, 0x00]);
        p += 3;

        out[p] = PMID_LF_T3T_ID1 + self.slot;
        out[p + 1] = 18;
        out[p + 2..p + 4].copy_from_slice(&self.system_code);
        out[p + 4..p + 12].copy_from_slice(&self.idm);
        out[p + 12..p + 20].copy_from_slice(&self.pmm);
        p += 20;

        let mask = 1u16 << self.slot;
        out[p] = PMID_LF_T3T_FLAGS;
        out[p + 1] = 2;
        out[p + 2] = (mask & 0xFF) as u8;
        out[p + 3] = (mask >> 8) as u8;
        p += 4;
        Ok(p)
    }

    /// Disables all custom Listen-F slots (`LF_T3T_FLAGS = 0x0000`).
    pub fn encode_reset_config_into(out: &mut [u8]) -> Result<usize, NciError> {
        const RESET: [u8; 5] = [1, PMID_LF_T3T_FLAGS, 2, 0x00, 0x00];
        if out.len() < RESET.len() {
            return Err(NciError::BufferTooSmall);
        }
        out[..RESET.len()].copy_from_slice(&RESET);
        Ok(RESET.len())
    }
}

/// Hardware 40-key MIFARE batch verifier (`2F 45` / `6F 45`) wire codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfcVerifyNtf {
    NoKeyFound,
    ReadyForNextBatch,
    KeyFound([u8; 6]),
    TagRemoved,
    RetryLastBatch,
    Unknown(u8),
}

/// Encodes `2F 45` Op `0x01` (KeyInfo: sector `0..=39`, Key A or Key B).
#[inline]
pub const fn encode_mfc_verify_info(sector: u8, is_key_b: bool) -> [u8; 2] {
    [0x01, (sector & 0x7F) | if is_key_b { 0x80 } else { 0x00 }]
}

/// Encodes `2F 45` Op `0x02` (KeyList: 1..=40 keys, 6 bytes each) directly into `out`.
pub fn encode_mfc_verify_keys_into(
    keys: &[[u8; 6]],
    out: &mut [u8],
) -> Result<usize, NciError> {
    if keys.is_empty() || keys.len() > MFC_VERIFY_MAX_KEYS_PER_BATCH {
        return Err(NciError::InvalidKeyBatch);
    }
    let needed = 1 + keys.len() * 6;
    if out.len() < needed {
        return Err(NciError::BufferTooSmall);
    }
    out[0] = 0x02;
    let mut p = 1usize;
    for k in keys {
        out[p..p + 6].copy_from_slice(k);
        p += 6;
    }
    Ok(p)
}

/// Decodes SN220U `6F 45` vendor notification payload.
pub fn parse_mfc_verify_ntf(payload: &[u8]) -> Option<MfcVerifyNtf> {
    let &code = payload.first()?;
    Some(match code {
        0x00 => MfcVerifyNtf::NoKeyFound,
        0x01 => MfcVerifyNtf::ReadyForNextBatch,
        0x02 => {
            if payload.len() < 7 {
                return None;
            }
            let mut key = [0u8; 6];
            key.copy_from_slice(&payload[1..7]);
            MfcVerifyNtf::KeyFound(key)
        }
        0x03 => MfcVerifyNtf::TagRemoved,
        0x04 => MfcVerifyNtf::RetryLastBatch,
        other => MfcVerifyNtf::Unknown(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_a_masks_sdd_and_handles_uid_sizes() {
        // 7-byte NTAG: ATQA 0x44 0x00 -> SDD must be masked to 0x04 (bits 4..0)
        let cfg = ListenAConfig::from_card(
            &[0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0x44, 0x00],
            0x00,
            0x00,
            &[],
        )
        .unwrap();
        assert_eq!(cfg.bit_frame_sdd, 0x04);
        assert_eq!(cfg.platform_config, 0x00);
        assert_eq!(cfg.sel_info, 0x00);
        assert_eq!(cfg.uid_slice().len(), 7);
        assert!(cfg.disables_payments());
        assert!(!cfg.supports_isodep());

        // ISO-DEP 4B card with ATS historical bytes
        let iso = ListenAConfig::from_card(
            &[0x01, 0x02, 0x03, 0x04],
            [0x04, 0x00],
            0x20,
            0x78,
            b"TEMPEL",
        )
        .unwrap();
        assert!(!iso.disables_payments());
        assert!(iso.supports_isodep());
        assert_eq!(iso.rats_tb1, 0x78);
        assert_eq!(iso.hist_slice(), b"TEMPEL");

        // Reject invalid UID lengths and oversized hist
        assert_eq!(
            ListenAConfig::from_card(&[1, 2, 3], [0x04, 0x00], 0x08, 0, &[]),
            Err(NciError::InvalidUidLength)
        );
        assert_eq!(
            ListenAConfig::from_card(&[1, 2, 3, 4], [0x04, 0x00], 0x20, 0x78, &[0u8; 16]),
            Err(NciError::InvalidHistLength)
        );
    }

    #[test]
    fn listen_b_encodes_verified_sn220u_sequence() {
        let b = ListenBConfig::new([0xCA, 0xFE, 0xBA, 0xBE], [0x11, 0x22, 0x33, 0x44], true, &[])
            .unwrap();
        let mut buf = [0u8; 64];
        let n = b.encode_set_config_into(&mut buf).unwrap();
        assert_eq!(
            &buf[..n],
            &[
                4,
                0x85, 1, 0x00,
                0x39, 4, 0xCA, 0xFE, 0xBA, 0xBE,
                0x3A, 4, 0x11, 0x22, 0x33, 0x44,
                0x38, 1, 0x01,
            ]
        );
        let rn = ListenBConfig::encode_reset_config_into(&mut buf).unwrap();
        assert_eq!(buf[0], 4);
        assert_eq!(rn, 15);
    }

    #[test]
    fn listen_f_encodes_18b_non_02fe_idm() {
        let f = ListenFConfig::new(
            [0x12, 0xFC],
            [0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78],
            ListenFConfig::DEFAULT_PMM,
            0,
        )
        .unwrap();
        let mut buf = [0u8; 32];
        let n = f.encode_set_config_into(&mut buf).unwrap();
        assert_eq!(n, 28);
        assert_eq!(buf[0], 3);
        assert_eq!(buf[4], 0x40);
        assert_eq!(buf[5], 18);
        assert_eq!(&buf[6..8], &[0x12, 0xFC]);
        assert_eq!(&buf[8..16], &[0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78]);
        assert_eq!(&buf[24..28], &[0x53, 2, 0x01, 0x00]);
        assert_eq!(
            ListenFConfig::new([0x12, 0xFC], [0; 8], [0; 8], 4),
            Err(NciError::InvalidSlot)
        );
    }

    #[test]
    fn mfc_2f45_batch_codec() {
        assert_eq!(encode_mfc_verify_info(5, false), [0x01, 0x05]);
        assert_eq!(encode_mfc_verify_info(5, true), [0x01, 0x85]);
        let keys = [[0xFFu8; 6]; 40];
        let mut buf = [0u8; MFC_VERIFY_MAX_PAYLOAD];
        let n = encode_mfc_verify_keys_into(&keys, &mut buf).unwrap();
        assert_eq!(n, 241);
        assert_eq!(buf[0], 0x02);
        assert_eq!(
            encode_mfc_verify_keys_into(&[[0u8; 6]; 41], &mut [0u8; 300]),
            Err(NciError::InvalidKeyBatch)
        );
        assert_eq!(
            parse_mfc_verify_ntf(&[0x02, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5]),
            Some(MfcVerifyNtf::KeyFound([0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5]))
        );
        assert_eq!(parse_mfc_verify_ntf(&[0x02, 0xAA]), None);
    }
}
