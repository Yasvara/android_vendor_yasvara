// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Per-app and global (`"*"`) security patch override JSON resolver (`{pkg|"*": "YYYY-MM-DD"}`).
//! Shared between `YasvaraAttestationService` (control plane) and `keystore2` (native Rust
//! attestation engine), making per-app patch overrides work end-to-end (fixes Audit F5).

use alloc::string::String;

use crate::pif::parse_flat_json_string_map;
use crate::version::parse_patch_date;

/// Extracts the validated global `"*"` override date from `patch_override` JSON, if any.
pub fn global_patch_override(json: &str) -> Option<String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return None;
    }
    let map = parse_flat_json_string_map(trimmed)?;
    let val = map.get("*")?.trim();
    parse_patch_date(val)?;
    Some(String::from(val))
}

/// Resolves the validated patch override date (`YYYY-MM-DD` or `YYYY-MM`) for any package in
/// `caller_packages`, falling back to `"*"` if present.
pub fn resolve_patch_override_for_packages(
    json: &str,
    caller_packages: &[&str],
) -> Option<String> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return None;
    }
    let map = parse_flat_json_string_map(trimmed)?;
    for &pkg in caller_packages {
        if let Some(raw) = map.get(pkg) {
            let v = raw.trim();
            if parse_patch_date(v).is_some() {
                return Some(String::from(v));
            }
        }
    }
    let star = map.get("*")?.trim();
    parse_patch_date(star)?;
    Some(String::from(star))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_per_app_before_wildcard_and_rejects_malformed() {
        let json = r#"{"*":"2026-08-05","com.bca":"2026-09-05","com.bad":"not-a-date"}"#;
        assert_eq!(global_patch_override(json).as_deref(), Some("2026-08-05"));
        assert_eq!(
            resolve_patch_override_for_packages(json, &["com.bca"]).as_deref(),
            Some("2026-09-05")
        );
        assert_eq!(
            resolve_patch_override_for_packages(json, &["com.other"]).as_deref(),
            Some("2026-08-05")
        );
        assert_eq!(
            resolve_patch_override_for_packages(json, &["com.bad"]).as_deref(),
            Some("2026-08-05")
        );
    }
}
