// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Compact binary vault (`TMPL` v1 + IEEE CRC-32) and zero-overhead active profile policy.
//!
//! Layout:
//! - Magic `b"TMPL"` (4B), Version `1u8`, Flags `0u8`, Active ID `u32 LE`, Default Payment ID `u32 LE`,
//!   Next ID `u32 LE`, Profile Count `u16 LE`
//! - Repeated `Profile` records with bounded lengths
//! - Trailing IEEE CRC-32 (`u32 LE`) over all preceding bytes.
//!
//! Bounded capacity (max 64 profiles, bounded per-field lengths) prevents OOM/DoS on malformed files.

use crate::apdu::{ApduRule, T4tSelection};
use crate::crc32_ieee;
use crate::nci::{ListenAConfig, ListenBConfig, ListenFConfig};

pub const VAULT_MAGIC: [u8; 4] = *b"TMPL";
pub const VAULT_VERSION: u8 = 1;
pub const MAX_PROFILES: usize = 64;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_PKG_LEN: usize = 128;
pub const MAX_PAYLOAD_LEN: usize = 4096;
pub const MAX_APDU_RULES: usize = 32;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKind {
    PaymentWallet = 0,
    UidTypeA = 1,
    IsoDepHce = 2,
    NdefT4t = 3,
    FelicaHcef = 4,
    UidTypeB = 5,
    Shield = 6,
}

impl ProfileKind {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::PaymentWallet),
            1 => Some(Self::UidTypeA),
            2 => Some(Self::IsoDepHce),
            3 => Some(Self::NdefT4t),
            4 => Some(Self::FelicaHcef),
            5 => Some(Self::UidTypeB),
            6 => Some(Self::Shield),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::PaymentWallet => "payment",
            Self::UidTypeA => "uid_a",
            Self::IsoDepHce => "isodep",
            Self::NdefT4t => "ndef",
            Self::FelicaHcef => "felica",
            Self::UidTypeB => "uid_b",
            Self::Shield => "shield",
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityGate {
    Always = 0,
    #[default]
    ScreenOn = 1,
    Unlocked = 2,
    Biometric = 3,
}

impl SecurityGate {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Always),
            1 => Some(Self::ScreenOn),
            2 => Some(Self::Unlocked),
            3 => Some(Self::Biometric),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevertPolicy {
    Sticky,
    AfterTap,
    TimeoutSec(u16),
}

impl Default for RevertPolicy {
    fn default() -> Self {
        Self::TimeoutSec(60)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub id: u32,
    pub kind: ProfileKind,
    pub name: String,
    pub color_argb: u32,
    pub icon_id: u8,
    pub gate: SecurityGate,
    pub revert: RevertPolicy,
    pub show_on_lockscreen: bool,

    // PaymentWallet target package (e.g. `com.gojek.gopay`, `com.google.android.apps.walletnfcrel`)
    pub wallet_pkg: String,

    // NFC-A / NFC-B / NFC-F identity fields
    pub uid: Vec<u8>,       // 4/7/10B (A), 4B PUPI (B), 8B IDm (F)
    pub atqa: [u8; 2],      // NFC-A ATQA
    pub sak: u8,            // NFC-A SAK
    pub rats_tb1: u8,       // NFC-A RATS TB1 (0x78 for ISO-DEP)
    pub hist_bytes: Vec<u8>,// NFC-A ATS hist or NFC-B H_INFO
    pub app_data: [u8; 4],  // NFC-B LB_APPLICATION_DATA
    pub system_code: [u8; 2], // NFC-F System Code
    pub pmm: [u8; 8],       // NFC-F PMm

    // Type-4A NDEF payload (raw NDEF message, without 2B NLEN) or MIFARE/NTAG dump bytes
    pub payload: Vec<u8>,
    // Optional scripted ISO-DEP APDU responses
    pub apdu_rules: Vec<ApduRule>,
}

impl Profile {
    pub fn payment(id: u32, name: &str, wallet_pkg: &str) -> Self {
        Self {
            id,
            kind: ProfileKind::PaymentWallet,
            name: name.chars().take(MAX_NAME_LEN).collect(),
            color_argb: 0xFF00AA5B,
            icon_id: 1,
            gate: SecurityGate::Unlocked,
            revert: RevertPolicy::Sticky,
            show_on_lockscreen: true,
            wallet_pkg: wallet_pkg.chars().take(MAX_PKG_LEN).collect(),
            uid: Vec::new(),
            atqa: [0x04, 0x00],
            sak: 0x20,
            rats_tb1: 0,
            hist_bytes: Vec::new(),
            app_data: [0; 4],
            system_code: [0; 2],
            pmm: [0; 8],
            payload: Vec::new(),
            apdu_rules: Vec::new(),
        }
    }

    pub fn uid_a(id: u32, name: &str, uid: &[u8], atqa: [u8; 2], sak: u8) -> Self {
        Self {
            id,
            kind: ProfileKind::UidTypeA,
            name: name.chars().take(MAX_NAME_LEN).collect(),
            color_argb: 0xFF3B82F6,
            icon_id: 2,
            gate: SecurityGate::ScreenOn,
            revert: RevertPolicy::TimeoutSec(60),
            show_on_lockscreen: true,
            wallet_pkg: String::new(),
            uid: uid.to_vec(),
            atqa,
            sak,
            rats_tb1: if (sak & 0x20) != 0 { 0x78 } else { 0x00 },
            hist_bytes: Vec::new(),
            app_data: [0; 4],
            system_code: [0; 2],
            pmm: [0; 8],
            payload: Vec::new(),
            apdu_rules: Vec::new(),
        }
    }

    pub fn listen_a_config(&self) -> Option<ListenAConfig> {
        ListenAConfig::from_card(&self.uid, self.atqa, self.sak, self.rats_tb1, &self.hist_bytes).ok()
    }

    pub fn listen_b_config(&self) -> Option<ListenBConfig> {
        if self.uid.len() != 4 {
            return None;
        }
        let mut pupi = [0u8; 4];
        pupi.copy_from_slice(&self.uid);
        ListenBConfig::new(pupi, self.app_data, (self.sak & 0x01) != 0, &self.hist_bytes).ok()
    }

    pub fn listen_f_config(&self) -> Option<ListenFConfig> {
        if self.uid.len() != 8 {
            return None;
        }
        let mut idm = [0u8; 8];
        idm.copy_from_slice(&self.uid);
        let pmm = if self.pmm == [0; 8] { ListenFConfig::DEFAULT_PMM } else { self.pmm };
        ListenFConfig::new(self.system_code, idm, pmm, 0).ok()
    }
}

/// Complete runtime state of Tempel inside `system_server`.
#[derive(Debug, Default)]
pub struct Vault {
    pub profiles: Vec<Profile>,
    pub active_id: u32,          // 0 = idle / stock default payment mode
    pub default_payment_id: u32, // profile ID to revert to after timeout/tap
    pub next_id: u32,
    pub armed_since_ms: u64,
    pub revert_deadline_ms: u64, // 0 = no timer armed
    pub t4t_sel: T4tSelection,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
            active_id: 0,
            default_payment_id: 0,
            next_id: 1,
            armed_since_ms: 0,
            revert_deadline_ms: 0,
            t4t_sel: T4tSelection::None,
        }
    }

    pub fn get(&self, id: u32) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn active(&self) -> Option<&Profile> {
        if self.active_id == 0 {
            return None;
        }
        self.get(self.active_id)
    }

    /// Inserts (when `profile.id == 0`) or updates an existing profile. Returns assigned ID or 0 if full.
    pub fn upsert(&mut self, mut profile: Profile) -> u32 {
        profile.name = profile.name.chars().take(MAX_NAME_LEN).collect();
        profile.wallet_pkg = profile.wallet_pkg.chars().take(MAX_PKG_LEN).collect();
        profile.payload.truncate(MAX_PAYLOAD_LEN);
        profile.apdu_rules.truncate(MAX_APDU_RULES);

        if profile.id != 0 {
            if let Some(slot) = self.profiles.iter_mut().find(|p| p.id == profile.id) {
                let id = profile.id;
                *slot = profile;
                return id;
            }
        }
        if self.profiles.len() >= MAX_PROFILES {
            return 0;
        }
        let id = self.next_id.max(1);
        self.next_id = id.wrapping_add(1).max(1);
        profile.id = id;
        if profile.kind == ProfileKind::PaymentWallet && self.default_payment_id == 0 {
            self.default_payment_id = id;
        }
        self.profiles.push(profile);
        id
    }

    pub fn remove(&mut self, id: u32) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        if self.profiles.len() == before {
            return false;
        }
        if self.active_id == id {
            self.active_id = self.default_payment_id;
            self.revert_deadline_ms = 0;
        }
        if self.default_payment_id == id {
            self.default_payment_id = self
                .profiles
                .iter()
                .find(|p| p.kind == ProfileKind::PaymentWallet)
                .map(|p| p.id)
                .unwrap_or(0);
        }
        true
    }

    /// Arms `id` (or `0` to disarm back to default payment wallet).
    /// Returns the revert delay in ms (0 if sticky/no timer needed).
    pub fn activate(&mut self, id: u32, now_ms: u64) -> Option<u64> {
        self.t4t_sel = T4tSelection::None;
        if id == 0 {
            self.active_id = self.default_payment_id;
            self.armed_since_ms = now_ms;
            self.revert_deadline_ms = 0;
            return Some(0);
        }
        let p = self.get(id)?;
        let delay_ms = match (p.kind, p.revert) {
            (ProfileKind::PaymentWallet, _) => 0,
            (_, RevertPolicy::Sticky) => 0,
            (_, RevertPolicy::AfterTap) => 60_000, // safety backstop if user never taps
            (_, RevertPolicy::TimeoutSec(s)) => (s as u64) * 1000,
        };
        self.active_id = id;
        self.armed_since_ms = now_ms;
        self.revert_deadline_ms = if delay_ms > 0 { now_ms.saturating_add(delay_ms) } else { 0 };
        Some(delay_ms)
    }

    /// Called on one-shot timer fire: reverts to `default_payment_id` if deadline elapsed.
    pub fn check_revert(&mut self, now_ms: u64) -> bool {
        if self.revert_deadline_ms != 0 && now_ms >= self.revert_deadline_ms {
            self.active_id = self.default_payment_id;
            self.revert_deadline_ms = 0;
            self.t4t_sel = T4tSelection::None;
            return true;
        }
        false
    }

    /// Called when RF field deactivates after a tap: reverts immediately if policy is `AfterTap`.
    pub fn on_tap_completed(&mut self) -> bool {
        if let Some(p) = self.active() {
            if p.revert == RevertPolicy::AfterTap && p.kind != ProfileKind::PaymentWallet {
                self.active_id = self.default_payment_id;
                self.revert_deadline_ms = 0;
                self.t4t_sel = T4tSelection::None;
                return true;
            }
        }
        false
    }

    /// Zero-allocation HCE APDU dispatch against the currently armed profile.
    pub fn process_apdu_into(&mut self, apdu: &[u8], out: &mut [u8; 260]) -> usize {
        let Some(idx) = self.profiles.iter().position(|p| p.id == self.active_id) else {
            out[0] = 0x6A;
            out[1] = 0x82;
            return 2;
        };
        match self.profiles[idx].kind {
            ProfileKind::NdefT4t => {
                let mut sel = self.t4t_sel;
                let n = crate::apdu::process_t4t_ndef_into(
                    &mut sel,
                    &self.profiles[idx].payload,
                    apdu,
                    out,
                );
                self.t4t_sel = sel;
                n
            }
            ProfileKind::IsoDepHce => {
                if !self.profiles[idx].apdu_rules.is_empty() {
                    crate::apdu::process_script_into(&self.profiles[idx].apdu_rules, apdu, out)
                } else if !self.profiles[idx].payload.is_empty() {
                    let mut sel = self.t4t_sel;
                    let n = crate::apdu::process_t4t_ndef_into(
                        &mut sel,
                        &self.profiles[idx].payload,
                        apdu,
                        out,
                    );
                    self.t4t_sel = sel;
                    n
                } else {
                    out[0] = 0x6A;
                    out[1] = 0x82;
                    2
                }
            }
            _ => {
                out[0] = 0x6A;
                out[1] = 0x82;
                2
            }
        }
    }

    /// Compact binary serialization with trailing IEEE CRC-32.
    pub fn encode_binary(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.profiles.len() * 96);
        buf.extend_from_slice(&VAULT_MAGIC);
        buf.push(VAULT_VERSION);
        buf.push(0); // flags
        buf.extend_from_slice(&self.active_id.to_le_bytes());
        buf.extend_from_slice(&self.default_payment_id.to_le_bytes());
        buf.extend_from_slice(&self.next_id.to_le_bytes());
        buf.extend_from_slice(&(self.profiles.len() as u16).to_le_bytes());

        for p in &self.profiles {
            buf.extend_from_slice(&p.id.to_le_bytes());
            buf.push(p.kind as u8);
            buf.extend_from_slice(&p.color_argb.to_le_bytes());
            buf.push(p.icon_id);
            buf.push(p.gate as u8);
            match p.revert {
                RevertPolicy::Sticky => {
                    buf.push(0);
                    buf.extend_from_slice(&0u16.to_le_bytes());
                }
                RevertPolicy::AfterTap => {
                    buf.push(1);
                    buf.extend_from_slice(&0u16.to_le_bytes());
                }
                RevertPolicy::TimeoutSec(s) => {
                    buf.push(2);
                    buf.extend_from_slice(&s.to_le_bytes());
                }
            }
            buf.push(if p.show_on_lockscreen { 1 } else { 0 });
            put_bytes_u8(&mut buf, p.name.as_bytes());
            put_bytes_u8(&mut buf, p.wallet_pkg.as_bytes());
            put_bytes_u8(&mut buf, &p.uid);
            buf.extend_from_slice(&p.atqa);
            buf.push(p.sak);
            buf.push(p.rats_tb1);
            put_bytes_u8(&mut buf, &p.hist_bytes);
            buf.extend_from_slice(&p.app_data);
            buf.extend_from_slice(&p.system_code);
            buf.extend_from_slice(&p.pmm);
            put_bytes_u16(&mut buf, &p.payload);
            buf.push(p.apdu_rules.len().min(MAX_APDU_RULES) as u8);
            for r in p.apdu_rules.iter().take(MAX_APDU_RULES) {
                put_bytes_u8(&mut buf, &r.match_prefix);
                put_bytes_u16(&mut buf, &r.response);
            }
        }
        let crc = crc32_ieee(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Validates magic, version, bounds, and CRC-32 before swapping state atomically.
    pub fn decode_binary(&mut self, data: &[u8]) -> bool {
        if data.len() < 24 {
            return false;
        }
        let (body, crc_tail) = data.split_at(data.len() - 4);
        let expected_crc = u32::from_le_bytes([crc_tail[0], crc_tail[1], crc_tail[2], crc_tail[3]]);
        if crc32_ieee(body) != expected_crc {
            return false;
        }
        if body[0..4] != VAULT_MAGIC || body[4] != VAULT_VERSION {
            return false;
        }
        let mut r = Reader::new(&body[6..]);
        let Some(active_id) = r.u32_le() else { return false };
        let Some(default_payment_id) = r.u32_le() else { return false };
        let Some(next_id) = r.u32_le() else { return false };
        let Some(count) = r.u16_le() else { return false };
        if count as usize > MAX_PROFILES {
            return false;
        }

        let mut profiles = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let Some(id) = r.u32_le() else { return false };
            let Some(kind) = r.u8().and_then(ProfileKind::from_u8) else { return false };
            let Some(color_argb) = r.u32_le() else { return false };
            let Some(icon_id) = r.u8() else { return false };
            let Some(gate) = r.u8().and_then(SecurityGate::from_u8) else { return false };
            let Some(rev_tag) = r.u8() else { return false };
            let Some(rev_sec) = r.u16_le() else { return false };
            let revert = match rev_tag {
                0 => RevertPolicy::Sticky,
                1 => RevertPolicy::AfterTap,
                2 => RevertPolicy::TimeoutSec(rev_sec),
                _ => return false,
            };
            let Some(lock_flag) = r.u8() else { return false };
            let Some(name_b) = r.bytes_u8(MAX_NAME_LEN * 4) else { return false };
            let Ok(name) = std::str::from_utf8(name_b) else { return false };
            let Some(pkg_b) = r.bytes_u8(MAX_PKG_LEN) else { return false };
            let Ok(wallet_pkg) = std::str::from_utf8(pkg_b) else { return false };
            let Some(uid) = r.bytes_u8(16) else { return false };
            let Some(atqa) = r.fixed::<2>() else { return false };
            let Some(sak) = r.u8() else { return false };
            let Some(rats_tb1) = r.u8() else { return false };
            let Some(hist_bytes) = r.bytes_u8(32) else { return false };
            let Some(app_data) = r.fixed::<4>() else { return false };
            let Some(system_code) = r.fixed::<2>() else { return false };
            let Some(pmm) = r.fixed::<8>() else { return false };
            let Some(payload) = r.bytes_u16(MAX_PAYLOAD_LEN) else { return false };
            let Some(rule_count) = r.u8() else { return false };
            if rule_count as usize > MAX_APDU_RULES {
                return false;
            }
            let mut apdu_rules = Vec::with_capacity(rule_count as usize);
            for _ in 0..rule_count {
                let Some(mp) = r.bytes_u8(255) else { return false };
                let Some(resp) = r.bytes_u16(260) else { return false };
                apdu_rules.push(ApduRule {
                    match_prefix: mp.to_vec(),
                    response: resp.to_vec(),
                });
            }
            profiles.push(Profile {
                id,
                kind,
                name: name.to_string(),
                color_argb,
                icon_id,
                gate,
                revert,
                show_on_lockscreen: lock_flag != 0,
                wallet_pkg: wallet_pkg.to_string(),
                uid: uid.to_vec(),
                atqa,
                sak,
                rats_tb1,
                hist_bytes: hist_bytes.to_vec(),
                app_data,
                system_code,
                pmm,
                payload: payload.to_vec(),
                apdu_rules,
            });
        }
        if !r.is_eof() {
            return false;
        }
        self.profiles = profiles;
        self.active_id = active_id;
        self.default_payment_id = default_payment_id;
        self.next_id = next_id.max(1);
        self.revert_deadline_ms = 0;
        self.t4t_sel = T4tSelection::None;
        true
    }

    pub fn dump_summary(&self) -> String {
        let mut s = format!(
            "Tempel Vault: {} profiles, active_id={}, default_payment_id={}\n",
            self.profiles.len(),
            self.active_id,
            self.default_payment_id
        );
        for p in &self.profiles {
            let mark = if p.id == self.active_id { "*" } else { " " };
            s.push_str(&format!(
                " {} [{}] {:<7} {:?} uid={} sak={:02X} pkg={}\n",
                mark,
                p.id,
                p.kind.label(),
                p.name,
                crate::hex_encode(&p.uid),
                p.sak,
                p.wallet_pkg
            ));
        }
        s
    }
}

fn put_bytes_u8(buf: &mut Vec<u8>, bytes: &[u8]) {
    let n = bytes.len().min(255);
    buf.push(n as u8);
    buf.extend_from_slice(&bytes[..n]);
}

fn put_bytes_u16(buf: &mut Vec<u8>, bytes: &[u8]) {
    let n = bytes.len().min(u16::MAX as usize);
    buf.extend_from_slice(&(n as u16).to_le_bytes());
    buf.extend_from_slice(&bytes[..n]);
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn is_eof(&self) -> bool {
        self.pos == self.data.len()
    }
    fn u8(&mut self) -> Option<u8> {
        let &b = self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn u16_le(&mut self) -> Option<u16> {
        let s = self.data.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32_le(&mut self) -> Option<u32> {
        let s = self.data.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.data.get(self.pos..self.pos + N)?;
        self.pos += N;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Some(out)
    }
    fn bytes_u8(&mut self, max: usize) -> Option<&'a [u8]> {
        let len = self.u8()? as usize;
        if len > max {
            return None;
        }
        let s = self.data.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(s)
    }
    fn bytes_u16(&mut self, max: usize) -> Option<&'a [u8]> {
        let len = self.u16_le()? as usize;
        if len > max {
            return None;
        }
        let s = self.data.get(self.pos..self.pos + len)?;
        self.pos += len;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_binary_roundtrip_and_corruption_rejection() {
        let mut v = Vault::new();
        let pay_id = v.upsert(Profile::payment(0, "GoPay QRIS", "com.gojek.gopay"));
        let door_id = v.upsert(Profile::uid_a(0, "Pintu Rumah", &[0xDE, 0xAD, 0xBE, 0xEF], [0x04, 0x00], 0x08));
        assert_eq!(v.default_payment_id, pay_id);
        assert_eq!(v.activate(door_id, 1_000), Some(60_000));

        let encoded = v.encode_binary();
        let mut v2 = Vault::new();
        assert!(v2.decode_binary(&encoded));
        assert_eq!(v2.profiles.len(), 2);
        assert_eq!(v2.active_id, door_id);
        assert_eq!(v2.default_payment_id, pay_id);

        // Bit-flip corruption must fail CRC check without mutating existing vault
        let mut bad = encoded.clone();
        bad[10] ^= 0x80;
        assert!(!v2.decode_binary(&bad));
        assert_eq!(v2.profiles.len(), 2);

        // Truncated inputs must fail cleanly
        for cut in [0, 1, 4, 15, encoded.len() - 1] {
            assert!(!v2.decode_binary(&encoded[..cut]));
        }
    }

    #[test]
    fn auto_revert_timeout_and_after_tap() {
        let mut v = Vault::new();
        let pay = v.upsert(Profile::payment(0, "GoPay", "com.gojek.gopay"));
        let mut door = Profile::uid_a(0, "Lobby", &[1, 2, 3, 4], [4, 0], 8);
        door.revert = RevertPolicy::TimeoutSec(30);
        let door_id = v.upsert(door);

        assert_eq!(v.activate(door_id, 10_000), Some(30_000));
        assert!(!v.check_revert(39_999));
        assert!(v.check_revert(40_000));
        assert_eq!(v.active_id, pay);

        // AfterTap mode
        let mut once = Profile::uid_a(0, "Lift", &[5, 6, 7, 8], [4, 0], 8);
        once.revert = RevertPolicy::AfterTap;
        let once_id = v.upsert(once);
        v.activate(once_id, 50_000);
        assert!(v.on_tap_completed());
        assert_eq!(v.active_id, pay);
    }
}
