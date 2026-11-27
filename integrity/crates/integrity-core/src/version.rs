// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Checked OS version, security patch level (`YYYYMM` / `YYYYMMDD`), Trunk Stable / Canary
//! Build ID inference, and codename healing — shared across Keystore2, system_server, and Laras.

/// Strict checked ASCII unsigned integer parser.
pub fn parse_decimal(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }
    value.bytes().try_fold(0u32, |n, b| {
        if !b.is_ascii_digit() {
            return None;
        }
        n.checked_mul(10)?.checked_add(u32::from(b - b'0'))
    })
}

/// Parses `YYYY-MM-DD` or `YYYY-MM` (an omitted day defaults to `01`, never a malformed day).
pub fn parse_patch_date(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.trim().split('-');
    let year = parts.next()?;
    let month = parts.next()?;
    let day = parts.next().unwrap_or("01");
    if parts.next().is_some() || year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return None;
    }
    let year = parse_decimal(year)?;
    let month = parse_decimal(month)?;
    let day = parse_decimal(day)?;
    if !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    let days_in_month = match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days_in_month).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

/// `YYYY-MM-DD` (or `YYYY-MM`) -> `YYYYMMDD` (KeyMint tags 718 / 719).
pub fn parse_long_patch(value: &str) -> Option<u32> {
    let (year, month, day) = parse_patch_date(value)?;
    year.checked_mul(10000)?.checked_add(month.checked_mul(100)?)?.checked_add(day)
}

/// `YYYY-MM-DD` (or `YYYY-MM`) -> `YYYYMM` (KeyMint tag 706).
pub fn parse_os_patchlevel(value: &str) -> Option<u32> {
    let (year, month, _) = parse_patch_date(value)?;
    year.checked_mul(100)?.checked_add(month)
}

/// Parses `"17"`, `"16.1"`, `"14.0.1"` -> `major * 10000 + minor * 100 + sub` (KeyMint tag 705).
pub fn parse_version_number(value: &str) -> Option<u32> {
    let mut parts = value.trim().split('.');
    let component = |s: &str| {
        let n = parse_decimal(s)?;
        (s.len() <= 2 && n <= 99).then_some(n)
    };
    let major = component(parts.next()?)?;
    let minor = parts.next().map(component).unwrap_or(Some(0))?;
    let sub = parts.next().map(component).unwrap_or(Some(0))?;
    if parts.next().is_some() {
        return None;
    }
    major.checked_mul(10000)?.checked_add(minor.checked_mul(100)?)?.checked_add(sub)
}

/// Infers KeyMint OS version (`major * 10000`) from Build ID when `RELEASE` is a codename.
pub fn infer_version_from_build_id(build_id: &str) -> Option<u32> {
    let id = build_id.trim();
    if id.is_empty() {
        return None;
    }
    // Android 17: Trunk Stable CP2 / CP3 / CP4 / DP1
    if id.starts_with("CP2")
        || id.starts_with("CP3")
        || id.starts_with("CP4")
        || id.starts_with("DP1")
    {
        return Some(170_000);
    }
    // Rolling Android Canary: ZP11.25* = Android 16 (2025), ZP11.26* = Android 17 (2026)+
    if let Some(rest) = id.strip_prefix("ZP11.") {
        if rest.len() >= 2 {
            if let Some(yy) = parse_decimal(&rest[..2]) {
                if yy >= 26 {
                    return (yy - 9).checked_mul(10_000);
                }
            }
        }
        return Some(160_000);
    }
    // Android 16 (Baklava): BP2 / BP3 / BP4 / BD / CP1
    if id.starts_with("BP2")
        || id.starts_with("BP3")
        || id.starts_with("BP4")
        || id.starts_with("BD")
        || id.starts_with("CP1")
    {
        return Some(160_000);
    }
    // Android 15 (Vanilla Ice Cream): AP3 / AP4 / AD / BP1
    if id.starts_with("AP3")
        || id.starts_with("AP4")
        || id.starts_with("AD")
        || id.starts_with("BP1")
    {
        return Some(150_000);
    }
    // Android 14 (Upside Down Cake): AP1 / AP2
    if id.starts_with("AP1") || id.starts_with("AP2") {
        return Some(140_000);
    }
    // Standard OEM build ID prefixes
    match id.as_bytes()[0] {
        b'U' => Some(140_000),
        b'T' => Some(130_000),
        b'S' => Some(120_000),
        b'R' => Some(110_000),
        b'Q' => Some(100_000),
        _ => None,
    }
}

/// Named Android dessert codename -> fixed major release number.
pub fn release_for_codename(codename: &str) -> Option<u32> {
    let t = codename.trim();
    if t.eq_ignore_ascii_case("cinnamonbun") {
        Some(17)
    } else if t.eq_ignore_ascii_case("baklava") {
        Some(16)
    } else if t.eq_ignore_ascii_case("vanillaicecream") {
        Some(15)
    } else if t.eq_ignore_ascii_case("upsidedowncake") {
        Some(14)
    } else if t.eq_ignore_ascii_case("tiramisu") {
        Some(13)
    } else {
        None
    }
}

/// Extracts the release segment from `brand/product/device:RELEASE/id/...`.
pub fn fingerprint_release(fp: &str) -> Option<&str> {
    let (_, after_colon) = fp.split_once(':')?;
    let (rel, _) = after_colon.split_once('/')?;
    let rel = rel.trim();
    (!rel.is_empty()).then_some(rel)
}

/// Extracts the build ID segment from `brand/product/device:release/ID/inc:type/tags`.
pub fn fingerprint_build_id(fp: &str) -> Option<&str> {
    let (_, after_colon) = fp.split_once(':')?;
    let mut parts = after_colon.split('/');
    let _rel = parts.next()?;
    let id = parts.next()?.trim();
    (!id.is_empty()).then_some(id)
}

/// Major Android release for a codename fingerprint segment (e.g. `"CANARY"`, `"Baklava"`).
/// `"CANARY"` (and unknown rolling codenames) resolves to `max(id_major, platform_major)`.
pub fn infer_release_from_fingerprint_or_platform(
    fp_release: &str,
    build_id: Option<&str>,
    platform_release: Option<&str>,
) -> Option<u32> {
    if let Some(named) = release_for_codename(fp_release) {
        return Some(named);
    }
    let id_major = build_id.and_then(infer_version_from_build_id).map(|v| v / 10_000).unwrap_or(0);
    let plat_major =
        platform_release.and_then(parse_version_number).map(|v| v / 10_000).unwrap_or(0);
    let best = if id_major >= plat_major { id_major } else { plat_major };
    (best > 0).then_some(best)
}

/// Returns the healed major release when `fp` has a non-numeric release segment (`":CANARY/"`)
/// and `current_release` is missing, non-numeric, or a different major than the inferred one.
pub fn healed_codename_release(
    fp: Option<&str>,
    current_release: Option<&str>,
    build_id: Option<&str>,
    platform_release: Option<&str>,
) -> Option<u32> {
    let fp = fp?;
    let fp_rel = fingerprint_release(fp)?;
    if parse_version_number(fp_rel).is_some() {
        return None;
    }
    let eff_id = build_id.filter(|s| !s.trim().is_empty()).or_else(|| fingerprint_build_id(fp));
    let inferred = infer_release_from_fingerprint_or_platform(fp_rel, eff_id, platform_release)?;
    if let Some(cur) = current_release.and_then(parse_version_number) {
        if cur / 10_000 == inferred {
            return None;
        }
    }
    Some(inferred)
}

/// Resolves KeyMint `TAG_OS_VERSION` (705) from a PIF profile.
pub fn resolve_pif_os_version(
    fp: Option<&str>,
    release: Option<&str>,
    build_id: Option<&str>,
    platform_release: Option<&str>,
) -> u32 {
    if let Some(healed_major) = healed_codename_release(fp, release, build_id, platform_release) {
        if let Some(v) = healed_major.checked_mul(10_000) {
            return v;
        }
    }
    if let Some(rel_ver) = release.and_then(parse_version_number) {
        return rel_ver;
    }
    if let Some(id_ver) = build_id.and_then(infer_version_from_build_id) {
        return id_ver;
    }
    // Pure codenames without numeric info default to 0 (AOSP Keymaster).
    0
}

/// Resolves KeyMint `TAG_OS_VERSION` when staged `os_version` property may already be present.
pub fn resolve_os_version_with_staged(
    staged_os_version: Option<&str>,
    pif_release: Option<&str>,
    pif_build_id: Option<&str>,
    is_pif_active: bool,
    host_release: Option<&str>,
) -> Option<u32> {
    if let Some(staged) = staged_os_version.and_then(|s| parse_decimal(s.trim())) {
        return Some(staged);
    }
    if is_pif_active {
        pif_release
            .and_then(parse_version_number)
            .or_else(|| pif_build_id.and_then(infer_version_from_build_id))
            .or(Some(0))
    } else {
        host_release.and_then(parse_version_number)
    }
}

/// Returns `YYYYMM` board/vendor/llndk `api_level` if explicitly present (never an SDK int!).
pub fn resolve_board_api_level<'a>(
    board_api_level: Option<&'a str>,
    api_level: Option<&'a str>,
) -> Option<&'a str> {
    if let Some(b) = board_api_level.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(b);
    }
    let a = api_level.map(str::trim)?;
    if a.len() == 6 {
        if let Some(v) = parse_decimal(a) {
            if v >= 200_000 {
                return Some(a);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_date_validation() {
        assert_eq!(parse_os_patchlevel("2026-09-05"), Some(202609));
        assert_eq!(parse_long_patch("2026-09-05"), Some(20260905));
        assert_eq!(parse_long_patch("2026-09"), Some(20260901));
        assert_eq!(parse_long_patch("2024-02-29"), Some(20240229));
        assert_eq!(parse_long_patch("2025-02-29"), None);
        assert_eq!(parse_long_patch("2026-13-01"), None);
        assert_eq!(parse_long_patch("2026-09-05-extra"), None);
    }

    #[test]
    fn canary_and_trunk_stable_inference() {
        assert_eq!(infer_version_from_build_id("CP2A.260605.006"), Some(170_000));
        assert_eq!(infer_version_from_build_id("ZP11.260410.001"), Some(170_000));
        assert_eq!(infer_version_from_build_id("ZP11.251201.001"), Some(160_000));
        assert_eq!(infer_version_from_build_id("BP2A.250605.031"), Some(160_000));
        assert_eq!(infer_version_from_build_id("AP3A.241005.015"), Some(150_000));
        assert_eq!(infer_version_from_build_id("UKQ1.230804.001"), Some(140_000));

        let fp = "google/caiman_beta/caiman:CANARY/ZP11.251201.001/12345:user/release-keys";
        assert_eq!(
            healed_codename_release(Some(fp), Some("16"), Some("ZP11.251201.001"), Some("17")),
            Some(17)
        );
        assert_eq!(
            resolve_pif_os_version(Some(fp), Some("16"), Some("ZP11.251201.001"), Some("17")),
            170_000
        );
    }
}
