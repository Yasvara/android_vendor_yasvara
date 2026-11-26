// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! On-device `/metadata/yasvara/` binary persistence formats (`SPEC-0051` §6):
//! - `RecoveryTheme` (32 B, `recovery_theme.bin`)
//! - `BootCanary` (32 B, `boot_canary.bin`)
//! - `PulihLock` (64 B, `pulih_lock.bin`, salted iterated SHA-256 PIN verifier)
//!
//! Every struct carries a 4-byte magic, format version, and IEEE CRC32 checksum
//! so power-cut or truncated writes are always rejected cleanly without panic.

use crate::crypto::sha256_bytes as sha256;

/// Standard IEEE 802.3 CRC32 (pure Rust, zero external crates).
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

/// 32-byte `/metadata/yasvara/recovery_theme.bin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryTheme {
    pub seed_argb: u32,
    pub variant: u8,
    pub oled_black: bool,
    pub locale: u8,
    pub refresh_hz: u8,
    pub brightness: u16,
}

impl Default for RecoveryTheme {
    fn default() -> Self {
        Self {
            seed_argb: 0xFF6750A4,
            variant: 0,
            oled_black: false,
            locale: 0,
            refresh_hz: 120,
            brightness: 200,
        }
    }
}

impl RecoveryTheme {
    pub const MAGIC: [u8; 4] = *b"YVTH";
    pub const VERSION: u16 = 1;
    pub const SIZE: usize = 32;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&Self::MAGIC);
        buf[4..6].copy_from_slice(&Self::VERSION.to_le_bytes());
        buf[6] = self.variant;
        buf[7] = u8::from(self.oled_black);
        buf[8..12].copy_from_slice(&self.seed_argb.to_le_bytes());
        buf[12] = self.locale;
        buf[13] = self.refresh_hz;
        buf[14..16].copy_from_slice(&self.brightness.to_le_bytes());
        let crc = crc32_ieee(&buf[0..28]);
        buf[28..32].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() != Self::SIZE {
            return Err("recovery_theme: invalid size");
        }
        if buf[0..4] != Self::MAGIC {
            return Err("recovery_theme: bad magic");
        }
        let ver = u16::from_le_bytes([buf[4], buf[5]]);
        if ver != Self::VERSION {
            return Err("recovery_theme: unsupported version");
        }
        let expected_crc = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        if crc32_ieee(&buf[0..28]) != expected_crc {
            return Err("recovery_theme: crc32 mismatch");
        }
        Ok(Self {
            variant: buf[6],
            oled_black: buf[7] != 0,
            seed_argb: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            locale: buf[12],
            refresh_hz: buf[13],
            brightness: u16::from_le_bytes([buf[14], buf[15]]),
        })
    }
}

/// 32-byte `/metadata/yasvara/boot_canary.bin`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootCanary {
    pub fail_count: u8,
    pub last_slot: u8,
    pub flags: u16,
    pub last_ts: u64,
}

impl BootCanary {
    pub const MAGIC: [u8; 4] = *b"YVBC";
    pub const VERSION: u16 = 1;
    pub const SIZE: usize = 32;
    pub const THRESHOLD: u8 = 3;

    pub fn is_bootlooping(&self) -> bool {
        self.fail_count >= Self::THRESHOLD
    }

    pub fn record_boot_attempt(&mut self, slot: u8, now_secs: u64) {
        self.fail_count = self.fail_count.saturating_add(1);
        self.last_slot = slot;
        self.last_ts = now_secs;
    }

    pub fn mark_boot_completed(&mut self) {
        self.fail_count = 0;
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&Self::MAGIC);
        buf[4..6].copy_from_slice(&Self::VERSION.to_le_bytes());
        buf[6] = self.fail_count;
        buf[7] = self.last_slot;
        buf[8..10].copy_from_slice(&self.flags.to_le_bytes());
        buf[12..20].copy_from_slice(&self.last_ts.to_le_bytes());
        let crc = crc32_ieee(&buf[0..28]);
        buf[28..32].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() != Self::SIZE {
            return Err("boot_canary: invalid size");
        }
        if buf[0..4] != Self::MAGIC {
            return Err("boot_canary: bad magic");
        }
        let ver = u16::from_le_bytes([buf[4], buf[5]]);
        if ver != Self::VERSION {
            return Err("boot_canary: unsupported version");
        }
        let expected_crc = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        if crc32_ieee(&buf[0..28]) != expected_crc {
            return Err("boot_canary: crc32 mismatch");
        }
        Ok(Self {
            fail_count: buf[6],
            last_slot: buf[7],
            flags: u16::from_le_bytes([buf[8], buf[9]]),
            last_ts: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
        })
    }
}

/// 64-byte `/metadata/yasvara/pulih_lock.bin` optional PIN security gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PulihLock {
    pub iters: u32,
    pub salt: [u8; 16],
    pub hash: [u8; 32],
}

impl PulihLock {
    pub const MAGIC: [u8; 4] = *b"YVLK";
    pub const VERSION: u16 = 1;
    pub const SIZE: usize = 64;
    pub const DEFAULT_ITERS: u32 = 10_000;

    pub fn create(pin: &str, salt: [u8; 16], iters: u32) -> Result<Self, &'static str> {
        if !(4..=8).contains(&pin.len()) || !pin.bytes().all(|b| b.is_ascii_digit()) {
            return Err("pulih_lock: PIN must be 4-8 ASCII digits");
        }
        let iters = iters.max(1000);
        let hash = stretch_pin(pin.as_bytes(), &salt, iters);
        Ok(Self { iters, salt, hash })
    }

    pub fn verify(&self, pin: &str) -> bool {
        let cand = stretch_pin(pin.as_bytes(), &self.salt, self.iters);
        // Constant-time compare
        let mut diff = 0u8;
        for (a, b) in cand.iter().zip(self.hash.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&Self::MAGIC);
        buf[4..6].copy_from_slice(&Self::VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&self.iters.to_le_bytes());
        buf[12..28].copy_from_slice(&self.salt);
        buf[28..60].copy_from_slice(&self.hash);
        let crc = crc32_ieee(&buf[0..60]);
        buf[60..64].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() != Self::SIZE {
            return Err("pulih_lock: invalid size");
        }
        if buf[0..4] != Self::MAGIC {
            return Err("pulih_lock: bad magic");
        }
        let ver = u16::from_le_bytes([buf[4], buf[5]]);
        if ver != Self::VERSION {
            return Err("pulih_lock: unsupported version");
        }
        let expected_crc = u32::from_le_bytes([buf[60], buf[61], buf[62], buf[63]]);
        if crc32_ieee(&buf[0..60]) != expected_crc {
            return Err("pulih_lock: crc32 mismatch");
        }
        Ok(Self {
            iters: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            salt: buf[12..28].try_into().unwrap(),
            hash: buf[28..60].try_into().unwrap(),
        })
    }
}

fn stretch_pin(pin: &[u8], salt: &[u8; 16], iters: u32) -> [u8; 32] {
    let mut seed = Vec::with_capacity(salt.len() + pin.len());
    seed.extend_from_slice(salt);
    seed.extend_from_slice(pin);
    let mut h = sha256(&seed);
    let mut scratch = [0u8; 48];
    for _ in 1..iters {
        scratch[0..32].copy_from_slice(&h);
        scratch[32..48].copy_from_slice(salt);
        h = sha256(&scratch);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_roundtrip_and_corruption_rejected() {
        let th = RecoveryTheme {
            seed_argb: 0xFF006A6A,
            variant: 2,
            oled_black: true,
            locale: 1,
            refresh_hz: 120,
            brightness: 255,
        };
        let mut raw = th.to_bytes();
        assert_eq!(RecoveryTheme::from_bytes(&raw).unwrap(), th);
        raw[10] ^= 0xFF;
        assert!(RecoveryTheme::from_bytes(&raw).is_err());
    }

    #[test]
    fn boot_canary_triggers_at_three_failures() {
        let mut c = BootCanary::default();
        c.record_boot_attempt(0, 100);
        c.record_boot_attempt(0, 120);
        assert!(!c.is_bootlooping());
        c.record_boot_attempt(0, 140);
        assert!(c.is_bootlooping());
        let raw = c.to_bytes();
        assert_eq!(BootCanary::from_bytes(&raw).unwrap(), c);
        c.mark_boot_completed();
        assert!(!c.is_bootlooping());
    }

    #[test]
    fn pulih_lock_verifies_pin_and_rejects_wrong_pin() {
        let salt = [0x42u8; 16];
        let lock = PulihLock::create("246810", salt, 1000).unwrap();
        let raw = lock.to_bytes();
        let decoded = PulihLock::from_bytes(&raw).unwrap();
        assert!(decoded.verify("246810"));
        assert!(!decoded.verify("246811"));
        assert!(PulihLock::create("12", salt, 1000).is_err());
        assert!(PulihLock::create("abcd", salt, 1000).is_err());
    }
}
