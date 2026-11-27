// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Atomic binary snapshot (`YVPI`) of normalized Yasvara integrity policy shared between
//! `YasvaraAttestationService` (writer via JNI -> `/data/misc/yasvara_attest/policy.bin`)
//! and `keystore2` (cached reader via `FileCache`, 1 `lstat` fast-path per attestation).
//!
//! Strictly `#![no_std]` + `alloc`, zero external crates, `#![forbid(unsafe_code)]`.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::contract::{
    BASE_ATTEST_TARGETS, MAX_POLICY_BYTES, MAX_PROP_VALUE_BYTES, RKP_EXEMPT_MAX_SLOTS,
};
use crate::der::{aaid_has_package, DeviceIdOverrides};
use crate::pif::{normalize_pif, parse_flat_json_string_map};
use crate::version::parse_patch_date;

pub const POLICY_MAGIC: [u8; 4] = *b"YVPI";
pub const POLICY_VERSION: u16 = 1;

pub const POLICY_FLAG_TRICKY_ENABLED: u16 = 1 << 0;
pub const POLICY_FLAG_PIF_ENABLED: u16 = 1 << 1;
pub const POLICY_FLAG_AKAR_YIELDED: u16 = 1 << 2;

const MAX_STR_LEN: usize = 1024;
const MAX_LIST_LEN: usize = 512;

/// Normalized, self-contained integrity policy snapshot compiled once in Rust.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub flags: u16,
    pub generation: u64,
    pub os_version: u32,
    pub rkp_manufacturer: String,
    pub pif_brand: String,
    pub pif_device: String,
    pub pif_product: String,
    pub pif_manufacturer: String,
    pub pif_model: String,
    pub pif_release: String,
    pub pif_build_id: String,
    pub pif_security_patch: String,
    pub global_patch_override: String,
    pub targets: Vec<String>,
    pub patch_overrides: Vec<(String, String)>,
    pub rkp_exempt_pkgs: Vec<String>,
}

/// Inputs supplied by `YasvaraAttestationService` when compiling a new `policy.bin`.
pub struct PolicyCompileInput<'a> {
    pub tricky_enabled: bool,
    pub pif_enabled: bool,
    pub akar_yielded: bool,
    pub generation: u64,
    pub raw_pif: &'a str,
    pub platform_release: &'a str,
    pub rkp_manufacturer: &'a str,
    pub targets: &'a [String],
    pub raw_patch_override_json: &'a str,
    pub raw_app_spoof_map_json: &'a str,
}

impl PolicySnapshot {
    /// Compiles and normalizes all integrity inputs into one canonical binary-ready snapshot.
    pub fn compile(input: &PolicyCompileInput<'_>) -> Self {
        let mut flags = 0u16;
        if input.tricky_enabled {
            flags |= POLICY_FLAG_TRICKY_ENABLED;
        }
        if input.akar_yielded {
            flags |= POLICY_FLAG_AKAR_YIELDED;
        }

        let mut snap = Self {
            flags,
            generation: input.generation,
            rkp_manufacturer: input.rkp_manufacturer.trim().to_string(),
            ..Self::default()
        };

        if input.pif_enabled && !input.akar_yielded {
            let plat = if input.platform_release.trim().is_empty() {
                "17"
            } else {
                input.platform_release.trim()
            };
            if let Some(norm) = normalize_pif(input.raw_pif, plat) {
                snap.flags |= POLICY_FLAG_PIF_ENABLED;
                snap.os_version = norm.os_version;
                let get = |k: &str| norm.fields.get(k).cloned().unwrap_or_default();
                snap.pif_brand = get("BRAND");
                snap.pif_device = get("DEVICE");
                snap.pif_product = get("PRODUCT");
                snap.pif_manufacturer = get("MANUFACTURER");
                snap.pif_model = get("MODEL");
                snap.pif_release = get("RELEASE");
                snap.pif_build_id = get("ID");
                snap.pif_security_patch = get("SECURITY_PATCH");
            }
        }

        let mut target_set = BTreeSet::new();
        for t in input.targets {
            let trimmed = t.trim();
            if !trimmed.is_empty() && trimmed.len() <= MAX_STR_LEN {
                target_set.insert(trimmed.to_string());
            }
        }
        snap.targets = target_set.into_iter().take(MAX_LIST_LEN).collect();

        let po_raw = input.raw_patch_override_json.trim();
        if !po_raw.is_empty() {
            if let Some(map) = parse_flat_json_string_map(po_raw) {
                if let Some(star) = map.get("*") {
                    let v = star.trim();
                    if parse_patch_date(v).is_some() {
                        snap.global_patch_override = v.to_string();
                    }
                }
                for (pkg, raw_date) in map {
                    if pkg == "*" {
                        continue;
                    }
                    let pkg_t = pkg.trim();
                    let date_t = raw_date.trim();
                    if !pkg_t.is_empty()
                        && pkg_t.len() <= MAX_STR_LEN
                        && parse_patch_date(date_t).is_some()
                    {
                        snap.patch_overrides.push((pkg_t.to_string(), date_t.to_string()));
                        if snap.patch_overrides.len() >= MAX_LIST_LEN {
                            break;
                        }
                    }
                }
            }
        }

        snap.rkp_exempt_pkgs = extract_app_spoof_packages(input.raw_app_spoof_map_json);
        snap
    }

    #[inline]
    pub fn is_tricky_enabled(&self) -> bool {
        (self.flags & POLICY_FLAG_TRICKY_ENABLED) != 0
    }

    #[inline]
    pub fn is_pif_enabled(&self) -> bool {
        (self.flags & POLICY_FLAG_PIF_ENABLED) != 0 && (self.flags & POLICY_FLAG_AKAR_YIELDED) == 0
    }

    #[inline]
    pub fn is_akar_yielded(&self) -> bool {
        (self.flags & POLICY_FLAG_AKAR_YIELDED) != 0
    }

    #[inline]
    pub fn has_pif_profile(&self) -> bool {
        self.os_version > 0
            || !self.pif_release.is_empty()
            || !self.pif_build_id.is_empty()
            || !self.pif_brand.is_empty()
            || !self.pif_model.is_empty()
    }

    pub fn is_target_aaid(&self, aaid: &[u8]) -> bool {
        if BASE_ATTEST_TARGETS.iter().any(|pkg| aaid_has_package(aaid, pkg.as_bytes())) {
            return true;
        }
        self.targets.iter().any(|pkg| aaid_has_package(aaid, pkg.as_bytes()))
    }

    pub fn resolve_patch_override(&self, caller_packages: &[&str]) -> Option<&str> {
        for &pkg in caller_packages {
            if let Ok(idx) = self.patch_overrides.binary_search_by(|(k, _)| k.as_str().cmp(pkg)) {
                return Some(self.patch_overrides[idx].1.as_str());
            }
        }
        if !self.global_patch_override.is_empty() {
            Some(self.global_patch_override.as_str())
        } else {
            None
        }
    }

    pub fn pif_id_overrides(&self) -> Option<DeviceIdOverrides> {
        if self.pif_brand.is_empty() && self.pif_model.is_empty() {
            return None;
        }
        Some(DeviceIdOverrides {
            brand: self.pif_brand.clone(),
            device: self.pif_device.clone(),
            product: self.pif_product.clone(),
            manufacturer: self.pif_manufacturer.clone(),
            model: self.pif_model.clone(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&POLICY_MAGIC);
        out.extend_from_slice(&POLICY_VERSION.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.os_version.to_le_bytes());

        write_str(&mut out, &self.rkp_manufacturer);
        write_str(&mut out, &self.pif_brand);
        write_str(&mut out, &self.pif_device);
        write_str(&mut out, &self.pif_product);
        write_str(&mut out, &self.pif_manufacturer);
        write_str(&mut out, &self.pif_model);
        write_str(&mut out, &self.pif_release);
        write_str(&mut out, &self.pif_build_id);
        write_str(&mut out, &self.pif_security_patch);
        write_str(&mut out, &self.global_patch_override);

        let targets_len = self.targets.len().min(MAX_LIST_LEN);
        out.extend_from_slice(&(targets_len as u16).to_le_bytes());
        for t in &self.targets[..targets_len] {
            write_str(&mut out, t);
        }

        let po_len = self.patch_overrides.len().min(MAX_LIST_LEN);
        out.extend_from_slice(&(po_len as u16).to_le_bytes());
        for (pkg, date) in &self.patch_overrides[..po_len] {
            write_str(&mut out, pkg);
            write_str(&mut out, date);
        }

        let exempt_len = self.rkp_exempt_pkgs.len().min(MAX_LIST_LEN);
        out.extend_from_slice(&(exempt_len as u16).to_le_bytes());
        for pkg in &self.rkp_exempt_pkgs[..exempt_len] {
            write_str(&mut out, pkg);
        }

        let checksum = fnv1a64(&out);
        out.extend_from_slice(&checksum.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 28 || bytes.len() > MAX_POLICY_BYTES {
            return None;
        }
        let body_len = bytes.len() - 8;
        let expected_sum = u64::from_le_bytes(bytes[body_len..].try_into().ok()?);
        if fnv1a64(&bytes[..body_len]) != expected_sum {
            return None;
        }
        let mut r = Reader { b: &bytes[..body_len], pos: 0 };
        if r.read_bytes(4)? != POLICY_MAGIC {
            return None;
        }
        if r.read_u16()? != POLICY_VERSION {
            return None;
        }
        let flags = r.read_u16()?;
        let generation = r.read_u64()?;
        let os_version = r.read_u32()?;

        let rkp_manufacturer = r.read_str()?;
        let pif_brand = r.read_str()?;
        let pif_device = r.read_str()?;
        let pif_product = r.read_str()?;
        let pif_manufacturer = r.read_str()?;
        let pif_model = r.read_str()?;
        let pif_release = r.read_str()?;
        let pif_build_id = r.read_str()?;
        let pif_security_patch = r.read_str()?;
        let global_patch_override = r.read_str()?;

        let targets_len = r.read_u16()? as usize;
        if targets_len > MAX_LIST_LEN {
            return None;
        }
        let mut targets = Vec::with_capacity(targets_len);
        for _ in 0..targets_len {
            targets.push(r.read_str()?);
        }

        let po_len = r.read_u16()? as usize;
        if po_len > MAX_LIST_LEN {
            return None;
        }
        let mut patch_overrides = Vec::with_capacity(po_len);
        for _ in 0..po_len {
            let pkg = r.read_str()?;
            let date = r.read_str()?;
            patch_overrides.push((pkg, date));
        }
        patch_overrides.sort_by(|a, b| a.0.cmp(&b.0));

        let exempt_len = r.read_u16()? as usize;
        if exempt_len > MAX_LIST_LEN {
            return None;
        }
        let mut rkp_exempt_pkgs = Vec::with_capacity(exempt_len);
        for _ in 0..exempt_len {
            rkp_exempt_pkgs.push(r.read_str()?);
        }

        if r.pos != r.b.len() {
            return None;
        }

        Some(Self {
            flags,
            generation,
            os_version,
            rkp_manufacturer,
            pif_brand,
            pif_device,
            pif_product,
            pif_manufacturer,
            pif_model,
            pif_release,
            pif_build_id,
            pif_security_patch,
            global_patch_override,
            targets,
            patch_overrides,
            rkp_exempt_pkgs,
        })
    }
}

/// Extracts sorted, unique package names assigned a non-empty profile in `yasvara_app_spoof_map`.
pub fn extract_app_spoof_packages(raw_json: &str) -> Vec<String> {
    let trimmed = raw_json.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Some(map) = parse_flat_json_string_map(trimmed) else {
        return Vec::new();
    };
    let mut set = BTreeSet::new();
    for (pkg, prof) in map {
        let p = pkg.trim();
        let v = prof.trim();
        if !p.is_empty()
            && !v.is_empty()
            && p.len() <= MAX_PROP_VALUE_BYTES
            && !p.bytes().any(|b| b == b',' || b == 0 || b.is_ascii_whitespace())
        {
            set.insert(p.to_string());
        }
    }
    set.into_iter().take(MAX_LIST_LEN).collect()
}

/// Greedily packs package names into `RKP_EXEMPT_MAX_SLOTS` comma-separated slots, each strictly
/// `<= MAX_PROP_VALUE_BYTES` (91 bytes) for safe `SystemProperties.set` publication and zero-alloc
/// Bionic scanning. Unused trailing slots are `""` so callers can clear stale values atomically.
pub fn pack_rkp_exempt_slots(packages: &[String]) -> Vec<String> {
    let mut slots: Vec<String> = Vec::with_capacity(RKP_EXEMPT_MAX_SLOTS);
    let mut current = String::new();

    for raw in packages {
        let pkg = raw.trim();
        if pkg.is_empty()
            || pkg.len() > MAX_PROP_VALUE_BYTES
            || pkg.bytes().any(|b| b == b',' || b == 0 || b.is_ascii_whitespace())
        {
            continue;
        }
        let sep = if current.is_empty() { 0 } else { 1 };
        if current.len() + sep + pkg.len() > MAX_PROP_VALUE_BYTES {
            slots.push(current);
            if slots.len() >= RKP_EXEMPT_MAX_SLOTS {
                return slots;
            }
            current = String::from(pkg);
        } else {
            if sep == 1 {
                current.push(',');
            }
            current.push_str(pkg);
        }
    }
    if !current.is_empty() && slots.len() < RKP_EXEMPT_MAX_SLOTS {
        slots.push(current);
    }
    while slots.len() < RKP_EXEMPT_MAX_SLOTS {
        slots.push(String::new());
    }
    slots
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(MAX_STR_LEN);
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.extend_from_slice(&bytes[..len]);
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn read_u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.read_bytes(2)?.try_into().ok()?))
    }

    fn read_u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.read_bytes(4)?.try_into().ok()?))
    }

    fn read_u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.read_bytes(8)?.try_into().ok()?))
    }

    fn read_str(&mut self) -> Option<String> {
        let len = self.read_u16()? as usize;
        if len > MAX_STR_LEN {
            return None;
        }
        let raw = self.read_bytes(len)?;
        let s = core::str::from_utf8(raw).ok()?;
        Some(s.to_string())
    }
}

fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prop_policy::csv_contains_token;
    use alloc::vec;

    #[test]
    fn compile_roundtrip_and_queries() {
        let targets = vec![
            "com.example.bank".to_string(),
            "com.example.wallet".to_string(),
            "com.example.bank".to_string(),
        ];
        let snap = PolicySnapshot::compile(&PolicyCompileInput {
            tricky_enabled: true,
            pif_enabled: true,
            akar_yielded: false,
            generation: 42,
            raw_pif: r#"{
                "MANUFACTURER": "Google",
                "MODEL": "Pixel 9 Pro",
                "FINGERPRINT": "google/caiman_beta/caiman:17/CP2A.260605.006/12345678:user/release-keys",
                "SECURITY_PATCH": "2026-09-05"
            }"#,
            platform_release: "17",
            rkp_manufacturer: "nubia",
            targets: &targets,
            raw_patch_override_json: r#"{"*":"2026-08-05","com.example.bank":"2026-10-05"}"#,
            raw_app_spoof_map_json: r#"{"com.mobile.legends":"vivo","com.netflix.mediaclient":"s25u"}"#,
        });

        assert!(snap.is_tricky_enabled());
        assert!(snap.is_pif_enabled());
        assert!(!snap.is_akar_yielded());
        assert_eq!(snap.generation, 42);
        assert_eq!(snap.os_version, 170_000);
        assert_eq!(snap.rkp_manufacturer, "nubia");
        assert_eq!(snap.pif_brand, "google");
        assert_eq!(snap.pif_model, "Pixel 9 Pro");
        assert_eq!(snap.targets, vec!["com.example.bank", "com.example.wallet"]);
        assert_eq!(snap.resolve_patch_override(&["com.example.bank"]), Some("2026-10-05"));
        assert_eq!(snap.resolve_patch_override(&["com.other.app"]), Some("2026-08-05"));
        assert_eq!(
            snap.rkp_exempt_pkgs,
            vec!["com.mobile.legends", "com.netflix.mediaclient"]
        );

        let encoded = snap.encode();
        let decoded = PolicySnapshot::decode(&encoded).expect("valid snapshot must decode");
        assert_eq!(decoded, snap);

        // Bitflip, truncation, trailing bytes, wrong magic/version must all fail cleanly.
        let mut flipped = encoded.clone();
        flipped[10] ^= 0x01;
        assert!(PolicySnapshot::decode(&flipped).is_none());
        assert!(PolicySnapshot::decode(&encoded[..encoded.len() - 1]).is_none());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(PolicySnapshot::decode(&trailing).is_none());
        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        assert!(PolicySnapshot::decode(&bad_magic).is_none());
    }

    #[test]
    fn akar_yield_disables_pif_flag_and_profile() {
        let snap = PolicySnapshot::compile(&PolicyCompileInput {
            tricky_enabled: true,
            pif_enabled: true,
            akar_yielded: true,
            generation: 7,
            raw_pif: r#"{"BRAND":"google","MODEL":"Pixel 9"}"#,
            platform_release: "17",
            rkp_manufacturer: "nubia",
            targets: &[],
            raw_patch_override_json: "",
            raw_app_spoof_map_json: "",
        });
        assert!(snap.is_akar_yielded());
        assert!(!snap.is_pif_enabled());
        assert!(snap.pif_id_overrides().is_none());
    }

    #[test]
    fn rkp_exempt_slot_packing_and_csv_scan() {
        let pkgs = vec![
            "com.mobile.legends".to_string(),
            "com.netflix.mediaclient".to_string(),
            "com.tencent.ig".to_string(),
            "com.miHoYo.GenshinImpact".to_string(),
            "com.activision.callofduty.shooter".to_string(),
            "com.dts.freefireth".to_string(),
        ];
        let slots = pack_rkp_exempt_slots(&pkgs);
        assert_eq!(slots.len(), RKP_EXEMPT_MAX_SLOTS);
        for slot in &slots {
            assert!(slot.len() <= MAX_PROP_VALUE_BYTES);
        }
        for pkg in &pkgs {
            assert!(
                slots.iter().any(|s| csv_contains_token(s.as_bytes(), pkg.as_bytes())),
                "missing packed package {pkg}"
            );
        }
        assert!(!csv_contains_token(slots[0].as_bytes(), b"com.mobile"));
        assert!(!csv_contains_token(slots[0].as_bytes(), b"mobile.legends"));
    }
}
