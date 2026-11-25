// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Fixed-layout `#[repr(C)]` PODs persisted under `/metadata/pasang` and `/metadata/yasvara`,
//! OTA runtime options (including dev-gated `clean_overlay`), and the `BootControlOps` trait.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::crypto::crc32;

// ====================================================== 32-byte RecoveryThemeSeed POD

pub const THEME_SEED_MAGIC: [u8; 4] = *b"YTHM";
pub const THEME_SEED_VERSION: u16 = 1;
pub const DEFAULT_RECOVERY_THEME_PATH: &str = "/metadata/yasvara/recovery_theme.bin";

/// Exact 32-byte POD written by Laras (`ColorViewModel` / `pasangd`) and read by `Pulih`
/// Recovery at boot to derive matching Material You M3 Expressive palettes offline.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryThemeSeed {
    pub magic: [u8; 4],       // "YTHM"
    pub version: u16,         // 1
    pub flags: u16,           // bit 0 = oled_black, bit 1 = high_contrast
    pub seed_argb: u32,       // e.g. 0xFF6750A4
    pub locale: [u8; 8],      // e.g. "en_US\0\0\0" or "in_ID\0\0\0"
    pub reserved: [u8; 8],    // zeroed
    pub crc32: u32,           // CRC32 over bytes 0..28
}

impl RecoveryThemeSeed {
    pub const FLAG_OLED_BLACK: u16 = 1 << 0;
    pub const FLAG_HIGH_CONTRAST: u16 = 1 << 1;

    pub fn new(seed_argb: u32, oled_black: bool, locale_str: &str) -> Self {
        let mut locale = [0u8; 8];
        let lb = locale_str.as_bytes();
        let take = lb.len().min(7);
        locale[..take].copy_from_slice(&lb[..take]);
        let mut s = Self {
            magic: THEME_SEED_MAGIC,
            version: THEME_SEED_VERSION,
            flags: if oled_black { Self::FLAG_OLED_BLACK } else { 0 },
            seed_argb,
            locale,
            reserved: [0u8; 8],
            crc32: 0,
        };
        let bytes = s.to_bytes_without_crc();
        s.crc32 = crc32(&bytes);
        s
    }

    fn to_bytes_without_crc(&self) -> [u8; 28] {
        let mut out = [0u8; 28];
        out[0..4].copy_from_slice(&self.magic);
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..12].copy_from_slice(&self.seed_argb.to_le_bytes());
        out[12..20].copy_from_slice(&self.locale);
        out[20..28].copy_from_slice(&self.reserved);
        out
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let body = self.to_bytes_without_crc();
        out[0..28].copy_from_slice(&body);
        let c = crc32(&body);
        out[28..32].copy_from_slice(&c.to_le_bytes());
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != 32 || raw[0..4] != THEME_SEED_MAGIC {
            return Err("Invalid RecoveryThemeSeed magic or size".into());
        }
        let version = u16::from_le_bytes(raw[4..6].try_into().unwrap());
        if version != THEME_SEED_VERSION {
            return Err(format!("Unsupported RecoveryThemeSeed version {version}"));
        }
        let stored_crc = u32::from_le_bytes(raw[28..32].try_into().unwrap());
        if crc32(&raw[0..28]) != stored_crc {
            return Err("RecoveryThemeSeed CRC32 mismatch".into());
        }
        let mut locale = [0u8; 8];
        locale.copy_from_slice(&raw[12..20]);
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&raw[20..28]);
        Ok(Self {
            magic: THEME_SEED_MAGIC,
            version,
            flags: u16::from_le_bytes(raw[6..8].try_into().unwrap()),
            seed_argb: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
            locale,
            reserved,
            crc32: stored_crc,
        })
    }

    pub fn oled_black(&self) -> bool {
        (self.flags & Self::FLAG_OLED_BLACK) != 0
    }

    pub fn locale_str(&self) -> String {
        let end = self.locale.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.locale[..end]).into_owned()
    }
}

pub fn write_recovery_theme_atomic(path: &Path, seed: &RecoveryThemeSeed) -> Result<(), String> {
    if let Some(par) = path.parent() {
        fs::create_dir_all(par).map_err(|e| format!("mkdir {}: {e}", par.display()))?;
    }
    let tmp = path.with_extension("bin.tmp");
    fs::write(&tmp, seed.to_bytes()).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))?;
    Ok(())
}

// ====================================================== 32-byte BootCanary POD

pub const BOOT_CANARY_MAGIC: [u8; 4] = *b"YCNY";
pub const DEFAULT_BOOT_CANARY_PATH: &str = "/metadata/yasvara/boot_canary.bin";

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootCanary {
    pub magic: [u8; 4],        // 0..4   "YCNY"
    pub version: u16,          // 4..6   1
    pub failed_boots: u16,     // 6..8   incremented on early init, cleared on sys.boot_completed=1
    pub active_slot: u32,      // 8..12  0=_a, 1=_b
    pub flags: u32,            // 12..16 bit 0 = safe_mode_triggered
    pub last_boot_epoch: u64,  // 16..24 naturally 8-byte aligned!
    pub reserved: u32,         // 24..28
    pub crc32: u32,            // 28..32 CRC32 over bytes 0..28
}

impl BootCanary {
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..4].copy_from_slice(&BOOT_CANARY_MAGIC);
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out[6..8].copy_from_slice(&self.failed_boots.to_le_bytes());
        out[8..12].copy_from_slice(&self.active_slot.to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..24].copy_from_slice(&self.last_boot_epoch.to_le_bytes());
        out[24..28].copy_from_slice(&self.reserved.to_le_bytes());
        let c = crc32(&out[0..28]);
        out[28..32].copy_from_slice(&c.to_le_bytes());
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != 32 || raw[0..4] != BOOT_CANARY_MAGIC {
            return Err("Invalid BootCanary magic or size".into());
        }
        let stored = u32::from_le_bytes(raw[28..32].try_into().unwrap());
        if crc32(&raw[0..28]) != stored {
            return Err("BootCanary CRC32 mismatch".into());
        }
        Ok(Self {
            magic: BOOT_CANARY_MAGIC,
            version: u16::from_le_bytes(raw[4..6].try_into().unwrap()),
            failed_boots: u16::from_le_bytes(raw[6..8].try_into().unwrap()),
            active_slot: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
            flags: u32::from_le_bytes(raw[12..16].try_into().unwrap()),
            last_boot_epoch: u64::from_le_bytes(raw[16..24].try_into().unwrap()),
            reserved: u32::from_le_bytes(raw[24..28].try_into().unwrap()),
            crc32: stored,
        })
    }
}

// ====================================================== SlotStateCache (/metadata/pasang/slot_state.bin)

pub const SLOT_STATE_MAGIC: [u8; 4] = *b"YSLT";
pub const SLOT_STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedPartitionHash {
    pub size: u64,
    pub sha256: [u8; 32],
}

/// Persistent hash cache for both A and B slots so Layer-1 Whole-Partition Skip
/// resolves in < 1 ms without re-hashing unchanged firmware or dynamic partitions.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SlotStateCache {
    pub slot_a: BTreeMap<String, CachedPartitionHash>,
    pub slot_b: BTreeMap<String, CachedPartitionHash>,
}

impl SlotStateCache {
    pub fn slot_map(&self, slot: u32) -> &BTreeMap<String, CachedPartitionHash> {
        if slot == 0 { &self.slot_a } else { &self.slot_b }
    }

    pub fn slot_map_mut(&mut self, slot: u32) -> &mut BTreeMap<String, CachedPartitionHash> {
        if slot == 0 { &mut self.slot_a } else { &mut self.slot_b }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for map in [&self.slot_a, &self.slot_b] {
            body.extend_from_slice(&(map.len() as u32).to_le_bytes());
            for (name, h) in map {
                let nb = name.as_bytes();
                body.extend_from_slice(&(nb.len() as u16).to_le_bytes());
                body.extend_from_slice(nb);
                body.extend_from_slice(&h.size.to_le_bytes());
                body.extend_from_slice(&h.sha256);
            }
        }
        let c = crc32(&body);
        let mut out = Vec::with_capacity(12 + body.len());
        out.extend_from_slice(SLOT_STATE_MAGIC.as_slice());
        out.extend_from_slice(&SLOT_STATE_VERSION.to_le_bytes());
        out.extend_from_slice(&c.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 20 || raw[0..4] != SLOT_STATE_MAGIC {
            return Err("Invalid SlotStateCache magic".into());
        }
        let ver = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        if ver != SLOT_STATE_VERSION {
            return Err(format!("Unsupported SlotStateCache version {ver}"));
        }
        let exp_crc = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let body = &raw[12..];
        if crc32(body) != exp_crc {
            return Err("SlotStateCache CRC32 mismatch".into());
        }
        let mut pos = 0usize;
        let mut maps = [BTreeMap::new(), BTreeMap::new()];
        for map in &mut maps {
            if pos + 4 > body.len() {
                return Err("Truncated SlotStateCache map header".into());
            }
            let count = u32::from_le_bytes(body[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            for _ in 0..count {
                if pos + 2 > body.len() {
                    return Err("Truncated SlotStateCache entry".into());
                }
                let nlen = u16::from_le_bytes(body[pos..pos + 2].try_into().unwrap()) as usize;
                pos += 2;
                if pos + nlen + 40 > body.len() {
                    return Err("Truncated SlotStateCache entry payload".into());
                }
                let name = String::from_utf8_lossy(&body[pos..pos + nlen]).into_owned();
                pos += nlen;
                let size = u64::from_le_bytes(body[pos..pos + 8].try_into().unwrap());
                let mut sha256 = [0u8; 32];
                sha256.copy_from_slice(&body[pos + 8..pos + 40]);
                pos += 40;
                map.insert(name, CachedPartitionHash { size, sha256 });
            }
        }
        Ok(Self {
            slot_a: std::mem::take(&mut maps[0]),
            slot_b: std::mem::take(&mut maps[1]),
        })
    }

    pub fn load_or_default(path: &Path) -> Self {
        fs::read(path)
            .ok()
            .and_then(|b| Self::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), String> {
        if let Some(par) = path.parent() {
            fs::create_dir_all(par).map_err(|e| format!("mkdir {}: {e}", par.display()))?;
        }
        let tmp = path.with_extension("bin.tmp");
        fs::write(&tmp, self.to_bytes()).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))?;
        Ok(())
    }
}

// ====================================================== ResumeState (/metadata/pasang/resume.bin)

pub const RESUME_MAGIC: [u8; 4] = *b"YRSM";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeState {
    pub manifest_sha256: [u8; 32],
    pub target_slot: u32,
    pub completed_partitions: Vec<String>,
}

impl ResumeState {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.manifest_sha256);
        body.extend_from_slice(&self.target_slot.to_le_bytes());
        body.extend_from_slice(&(self.completed_partitions.len() as u32).to_le_bytes());
        for p in &self.completed_partitions {
            let b = p.as_bytes();
            body.extend_from_slice(&(b.len() as u16).to_le_bytes());
            body.extend_from_slice(b);
        }
        let c = crc32(&body);
        let mut out = Vec::with_capacity(12 + body.len());
        out.extend_from_slice(&RESUME_MAGIC);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&c.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 52 || raw[0..4] != RESUME_MAGIC {
            return Err("Invalid ResumeState magic".into());
        }
        let exp = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let body = &raw[12..];
        if crc32(body) != exp {
            return Err("ResumeState CRC32 mismatch".into());
        }
        let mut manifest_sha256 = [0u8; 32];
        manifest_sha256.copy_from_slice(&body[0..32]);
        let target_slot = u32::from_le_bytes(body[32..36].try_into().unwrap());
        let count = u32::from_le_bytes(body[36..40].try_into().unwrap()) as usize;
        let mut pos = 40usize;
        let mut completed_partitions = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 2 > body.len() {
                return Err("Truncated ResumeState".into());
            }
            let n = u16::from_le_bytes(body[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + n > body.len() {
                return Err("Truncated ResumeState name".into());
            }
            completed_partitions.push(String::from_utf8_lossy(&body[pos..pos + n]).into_owned());
            pos += n;
        }
        Ok(Self {
            manifest_sha256,
            target_slot,
            completed_partitions,
        })
    }
}

// ====================================================== OtaOptions & BootControlOps

/// Options controlling an In-OS Live CoW OTA installation.
#[derive(Debug, Clone)]
pub struct OtaOptions {
    /// Developer-only option: clear `/mnt/scratch/overlay/*/upper` automatically after a
    /// successful OTA commit so dev overlay pushes never mask freshly installed partitions.
    /// Hidden from normal `user` builds in Laras UI.
    pub clean_overlay: bool,
    /// Enable Layer 2 Sub-Partition `dm-linear` Extent Aliasing (default: true).
    pub enable_extent_aliasing: bool,
    /// Minimum contiguous alias run in 4 KiB blocks (default: 64 = 256 KiB).
    pub min_alias_blocks: u64,
    /// Skip redundant full readback SHA-256 on userdebug when explicitly requested (default: false).
    pub fast_verify: bool,
    /// Allow unsigned / dev-key payloads (default: false on user, opt-in on userdebug/host).
    pub allow_dev_key: bool,
    /// Snapshot 1 MiB original `super` metadata to `<metadata_dir>/last_good/` before writing.
    pub backup_last_good: bool,
    /// Plan and verify without mutating any block devices or switching slots.
    pub dry_run: bool,
    /// Worker threads for parallel decode/write/verify (0 = auto, capped at 8).
    pub max_threads: usize,
}

impl Default for OtaOptions {
    fn default() -> Self {
        Self {
            clean_overlay: false,
            enable_extent_aliasing: true,
            min_alias_blocks: 64, // 256 KiB
            fast_verify: false,
            allow_dev_key: false,
            backup_last_good: true,
            dry_run: false,
            max_threads: 8,
        }
    }
}

impl OtaOptions {
    /// Parse a flat JSON object string (zero external crate!) produced by Laras / `IPasang.aidl`.
    pub fn from_json_str(json: &str) -> Self {
        let mut opts = Self::default();
        if let Some(v) = json_bool(json, "clean_overlay") {
            opts.clean_overlay = v;
        }
        if let Some(v) = json_bool(json, "enable_extent_aliasing") {
            opts.enable_extent_aliasing = v;
        }
        if let Some(v) = json_bool(json, "fast_verify") {
            opts.fast_verify = v;
        }
        if let Some(v) = json_bool(json, "allow_dev_key") {
            opts.allow_dev_key = v;
        }
        if let Some(v) = json_bool(json, "backup_last_good") {
            opts.backup_last_good = v;
        }
        if let Some(v) = json_bool(json, "dry_run") {
            opts.dry_run = v;
        }
        if let Some(v) = json_u64(json, "min_alias_blocks") {
            opts.min_alias_blocks = v.clamp(1, 4096);
        }
        if let Some(v) = json_u64(json, "max_threads") {
            opts.max_threads = (v as usize).min(16);
        }
        opts
    }
}

pub fn json_bool(json: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let rest = json[pos + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

pub fn json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let rest = json[pos + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Platform abstraction for A/B Boot Control HAL (`IBootControl` on Android, mock on host).
pub trait BootControlOps: Send + Sync {
    fn current_slot(&self) -> Result<u32, String>;
    fn active_boot_slot(&self) -> Result<u32, String>;
    fn is_slot_bootable(&self, slot: u32) -> Result<bool, String>;
    fn is_slot_successful(&self, slot: u32) -> Result<bool, String>;
    fn set_active_boot_slot(&self, slot: u32) -> Result<(), String>;
    fn mark_boot_successful(&self) -> Result<(), String>;
    /// Returns `"none"`, `"snapshotted"`, `"merging"`, `"cancelled"`, or `"unknown"`.
    fn snapshot_merge_status(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pod_layouts_and_roundtrips() {
        assert_eq!(std::mem::size_of::<RecoveryThemeSeed>(), 32);
        assert_eq!(std::mem::size_of::<BootCanary>(), 32);

        let seed = RecoveryThemeSeed::new(0xFF6750A4, true, "in_ID");
        let raw = seed.to_bytes();
        let parsed = RecoveryThemeSeed::from_bytes(&raw).unwrap();
        assert_eq!(parsed.seed_argb, 0xFF6750A4);
        assert!(parsed.oled_black());
        assert_eq!(parsed.locale_str(), "in_ID");

        let mut sc = SlotStateCache::default();
        sc.slot_b.insert(
            "vendor".into(),
            CachedPartitionHash {
                size: 1024,
                sha256: [0xABu8; 32],
            },
        );
        let sc2 = SlotStateCache::from_bytes(&sc.to_bytes()).unwrap();
        assert_eq!(sc, sc2);

        let opts = OtaOptions::from_json_str(
            r#"{"clean_overlay": true, "fast_verify": true, "allow_dev_key": true, "max_threads": 4}"#,
        );
        assert!(opts.clean_overlay);
        assert!(opts.fast_verify);
        assert!(opts.allow_dev_key);
        assert_eq!(opts.max_threads, 4);
    }
}
