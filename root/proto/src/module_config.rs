// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-module key-value configuration store (`persist.config` and volatile `tmp.config`).
//!
//! Compact binary format `AKMC` v1 (`[b'A', b'K', b'M', b'C']`) with strict size caps,
//! supporting KSU/BakaSU-compatible keys like `override.description` and `manage.<feature>`.

use std::collections::BTreeMap;

pub const CONFIG_MAGIC: [u8; 4] = *b"AKMC";
pub const CONFIG_VERSION: u32 = 1;
pub const MAX_CONFIG_ENTRIES: usize = 512;
pub const MAX_KEY_LEN: usize = 256;
pub const MAX_VAL_LEN: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModuleConfig {
    pub entries: BTreeMap<String, String>,
}

impl ModuleConfig {
    pub fn validate_key(key: &str) -> bool {
        !key.is_empty()
            && key.len() <= MAX_KEY_LEN
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
    }

    pub fn set(&mut self, key: impl Into<String>, val: impl Into<String>) -> Result<(), &'static str> {
        let k = key.into();
        let v = val.into();
        if !Self::validate_key(&k) {
            return Err("invalid config key");
        }
        if v.len() > MAX_VAL_LEN {
            return Err("config value too long");
        }
        if !self.entries.contains_key(&k) && self.entries.len() >= MAX_CONFIG_ENTRIES {
            return Err("too many config entries");
        }
        self.entries.insert(k, v);
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    pub fn delete(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    pub fn merge_overlay(&self, overlay: &ModuleConfig) -> ModuleConfig {
        let mut out = self.clone();
        for (k, v) in &overlay.entries {
            out.entries.insert(k.clone(), v.clone());
        }
        out
    }

    pub fn override_description(&self) -> Option<&str> {
        self.get("override.description").filter(|s| !s.is_empty())
    }

    /// Returns feature names declared via `manage.<feature>=true` (or `1`).
    pub fn managed_features(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (k, v) in &self.entries {
            if let Some(feat) = k.strip_prefix("manage.") {
                if !feat.is_empty() && matches!(v.as_str(), "1" | "true" | "TRUE" | "yes") {
                    out.push(feat.to_string());
                }
            }
        }
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.entries.len() * 32);
        out.extend_from_slice(&CONFIG_MAGIC);
        out.extend_from_slice(&CONFIG_VERSION.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for (k, v) in &self.entries {
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            out.extend_from_slice(v.as_bytes());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 12 {
            return Err("config buffer too short");
        }
        if buf[0..4] != CONFIG_MAGIC {
            // Plain text fallback (`key=value\n`) for human-edited configs.
            if let Ok(text) = std::str::from_utf8(buf) {
                let mut cfg = ModuleConfig::default();
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some((k, v)) = line.split_once('=') {
                        let _ = cfg.set(k.trim(), v.trim());
                    }
                }
                return Ok(cfg);
            }
            return Err("bad config magic");
        }
        let ver = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if ver != CONFIG_VERSION {
            return Err("unsupported config version");
        }
        let count = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;
        if count > MAX_CONFIG_ENTRIES {
            return Err("too many config entries");
        }
        let mut at = 12usize;
        let mut cfg = ModuleConfig::default();
        for _ in 0..count {
            if at + 4 > buf.len() {
                return Err("truncated key len");
            }
            let klen = u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize;
            at += 4;
            if klen > MAX_KEY_LEN || at + klen + 4 > buf.len() {
                return Err("bad key len");
            }
            let key = std::str::from_utf8(&buf[at..at + klen]).map_err(|_| "bad utf8 key")?;
            at += klen;
            let vlen = u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize;
            at += 4;
            if vlen > MAX_VAL_LEN || at + vlen > buf.len() {
                return Err("bad val len");
            }
            let val = std::str::from_utf8(&buf[at..at + vlen]).map_err(|_| "bad utf8 val")?;
            at += vlen;
            cfg.set(key, val)?;
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_roundtrip_and_merge() {
        let mut persist = ModuleConfig::default();
        persist.set("override.description", "Persistent desc").unwrap();
        persist.set("manage.play_integrity", "true").unwrap();

        let enc = persist.encode();
        let dec = ModuleConfig::decode(&enc).unwrap();
        assert_eq!(dec, persist);
        assert_eq!(dec.managed_features(), vec!["play_integrity".to_string()]);

        let mut tmp = ModuleConfig::default();
        tmp.set("override.description", "Runtime status: active").unwrap();
        let merged = persist.merge_overlay(&tmp);
        assert_eq!(merged.override_description(), Some("Runtime status: active"));
        assert_eq!(merged.managed_features(), vec!["play_integrity".to_string()]);
    }

    #[test]
    fn text_fallback_parses() {
        let cfg = ModuleConfig::decode(b"# comment\nmanage.play_integrity=1\noverride.description=Hi\n").unwrap();
        assert_eq!(cfg.override_description(), Some("Hi"));
        assert_eq!(cfg.managed_features(), vec!["play_integrity".to_string()]);
    }
}
