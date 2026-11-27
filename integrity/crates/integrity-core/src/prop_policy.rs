// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure `#![no_std]`, zero-allocation property classification and override policy engine.
//! Shared directly by `integrity-bionic` (linked into `libc.so`), `integrity-codegen`,
//! and host tests — eliminating all C++ policy duplication in Bionic.

use crate::contract::{
    BOOT_STORY, CAMERA_EXEMPT_PREFIXES, COLLECTOR_STORY, HIDDEN_EXACT, HIDDEN_PREFIXES,
    PROP_BOOT_VBMETA_DIGEST, PROP_PIF_PREFIX, PROP_RKP_EXEMPT_PREFIX, PROP_RKP_MANUFACTURER,
    PUBLIC_YASVARA_PROPS, RKP_MFG_EXEMPT_EXACT, ROM_FLAVOR_PREFIXES,
};

/// Process role bitmask cached once per PID in Bionic.
pub const ROLE_NONE: i32 = 0;
pub const ROLE_APP: i32 = 1 << 0;
pub const ROLE_COLLECTOR: i32 = 1 << 1;
pub const ROLE_RKP_MFG_EXEMPT: i32 = 1 << 2;

/// One-pass resolution verdict for `__system_property_read_callback` / `__system_property_serial`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropVerdict {
    Real = 0,
    RealAppRo = 1,
    Hidden = 2,
    Overridden = 3,
}

#[inline]
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a == b
}

#[inline]
fn starts_with(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && &s[..prefix.len()] == prefix
}

#[inline]
fn ends_with(s: &[u8], suffix: &[u8]) -> bool {
    s.len() >= suffix.len() && &s[s.len() - suffix.len()..] == suffix
}

#[inline]
fn ends_with_strict(s: &[u8], suffix: &[u8]) -> bool {
    s.len() > suffix.len() && &s[s.len() - suffix.len()..] == suffix
}

#[inline]
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    let mut i = 0;
    let limit = haystack.len() - needle.len();
    while i <= limit {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

/// Fast 3-byte prefix filter covering 100% of properties Yasvara ever hides, overrides,
/// or normalizes (`ro.`, `per`, `ini`, `sys`, `ser`, `ven`, `dev`).
#[inline]
pub fn may_intercept(name: &[u8]) -> bool {
    if name.len() < 3 {
        return false;
    }
    match name[0] {
        b'r' => name[1] == b'o' && name[2] == b'.',
        b'p' => name[1] == b'e' && name[2] == b'r',
        b'i' => name[1] == b'n' && name[2] == b'i',
        b's' => (name[1] == b'y' && name[2] == b's') || (name[1] == b'e' && name[2] == b'r'),
        b'v' => name[1] == b'e' && name[2] == b'n',
        b'd' => name[1] == b'e' && name[2] == b'v',
        _ => false,
    }
}

pub fn cmdline_is_zygote(n: &[u8]) -> bool {
    bytes_eq(n, b"zygote")
        || bytes_eq(n, b"zygote64")
        || bytes_eq(n, b"usap32")
        || bytes_eq(n, b"usap64")
        || bytes_eq(n, b"<pre-initialized>")
        || ends_with(n, b"_zygote")
}

pub fn cmdline_is_placeholder(n: &[u8]) -> bool {
    contains_subslice(n, b"app_process")
}

pub fn cmdline_is_collector(n: &[u8]) -> bool {
    bytes_eq(n, b"com.google.android.gms")
        || starts_with(n, b"com.google.android.gms.")
        || bytes_eq(n, b"com.google.android.gsf")
        || starts_with(n, b"com.google.process.g")
        || bytes_eq(n, b"com.android.vending")
        || starts_with(n, b"com.android.vending.")
}

pub fn cmdline_is_rkp_mfg_exempt(n: &[u8]) -> bool {
    for &exact in RKP_MFG_EXEMPT_EXACT {
        if bytes_eq(n, exact.as_bytes()) {
            return true;
        }
    }
    for &prefix in CAMERA_EXEMPT_PREFIXES {
        if starts_with(n, prefix.as_bytes()) {
            return true;
        }
    }
    false
}

/// Classifies an app-UID process cmdline (already truncated at `':'`) into `ROLE_*` bits.
pub fn classify_app_cmdline(name: &[u8]) -> i32 {
    if name.is_empty() || cmdline_is_zygote(name) || cmdline_is_placeholder(name) {
        return ROLE_NONE;
    }
    let mut role = ROLE_APP;
    if cmdline_is_collector(name) {
        role |= ROLE_COLLECTOR;
    }
    if cmdline_is_rkp_mfg_exempt(name) {
        role |= ROLE_RKP_MFG_EXEMPT;
    }
    role
}

#[inline]
pub fn is_boot_digest_prop(name: &[u8]) -> bool {
    bytes_eq(name, PROP_BOOT_VBMETA_DIGEST.as_bytes())
}

#[inline]
pub fn is_pif_staging(name: &[u8]) -> bool {
    starts_with(name, PROP_PIF_PREFIX.as_bytes())
}

#[inline]
pub fn is_rkp_mfg_staging(name: &[u8]) -> bool {
    bytes_eq(name, PROP_RKP_MANUFACTURER.as_bytes())
        || starts_with(name, PROP_RKP_EXEMPT_PREFIX.as_bytes())
}

/// Zero-allocation exact token match in a comma-separated ASCII package list.
pub fn csv_contains_token(csv: &[u8], token: &[u8]) -> bool {
    if token.is_empty() || csv.is_empty() {
        return false;
    }
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= csv.len() {
        if i == csv.len() || csv[i] == b',' {
            if i > start && bytes_eq(&csv[start..i], token) {
                return true;
            }
            start = i + 1;
        }
        i += 1;
    }
    false
}

pub fn is_hidden_marker(name: &[u8]) -> bool {
    for &pub_prop in PUBLIC_YASVARA_PROPS {
        if bytes_eq(name, pub_prop.as_bytes()) {
            return false;
        }
    }
    for &prefix in HIDDEN_PREFIXES {
        if starts_with(name, prefix.as_bytes()) {
            return true;
        }
    }
    for &exact in HIDDEN_EXACT {
        if bytes_eq(name, exact.as_bytes()) {
            return true;
        }
    }
    false
}

pub fn is_product_manufacturer_prop(name: &[u8]) -> bool {
    if bytes_eq(name, b"ro.product.manufacturer_for_attestation") {
        return true;
    }
    if !starts_with(name, b"ro.product.") {
        return false;
    }
    // Match `ro.product.<partition>.manufacturer` or `ro.product.manufacturer`.
    let mut dot = name.len();
    while dot > 0 {
        dot -= 1;
        if name[dot] == b'.' {
            return bytes_eq(&name[dot + 1..], b"manufacturer");
        }
    }
    false
}

pub fn find_boot_story(name: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < BOOT_STORY.len() {
        if bytes_eq(name, BOOT_STORY[i].0.as_bytes()) {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn boot_story_value_cstr(index: usize) -> Option<&'static [u8]> {
    match index {
        0 | 1 | 2 => Some(b"green\0"),
        3 | 4 | 5 | 8 => Some(b"locked\0"),
        6 => Some(b"1\0"),
        7 => Some(b"enforcing\0"),
        9 => Some(b"encrypted\0"),
        10 => Some(b"stopped\0"),
        11 | 12 | 13 | 14 | 15 => Some(b"mtp\0"),
        _ => None,
    }
}

pub fn find_collector_story_cstr(name: &[u8]) -> Option<&'static [u8]> {
    for &(k, _) in COLLECTOR_STORY {
        if bytes_eq(name, k.as_bytes()) {
            return Some(b"android-build\0");
        }
    }
    None
}

/// Global secure/debug/user-build overrides for `ro.*` properties (caller guarantees `ro.` prefix).
pub fn build_identity_story_cstr(name: &[u8]) -> Option<&'static [u8]> {
    if bytes_eq(name, b"ro.secure") || bytes_eq(name, b"ro.adb.secure") {
        return Some(b"1\0");
    }
    if bytes_eq(name, b"ro.debuggable") {
        return Some(b"0\0");
    }
    if ends_with_strict(name, b".build.type") {
        return Some(b"user\0");
    }
    if ends_with_strict(name, b".build.tags") {
        return Some(b"release-keys\0");
    }
    None
}

/// Maps a `ro.*` identity property to the NUL-terminated PIF staging property name (collector only).
pub fn staging_for_identity_cstr(name: &[u8]) -> Option<&'static [u8]> {
    if bytes_eq(name, b"ro.build.product") {
        return Some(b"persist.sys.yasvara.pif.device\0");
    }
    if bytes_eq(name, b"ro.build.display.id") {
        return Some(b"persist.sys.yasvara.pif.build_id\0");
    }
    // Partition build/version suffixes MUST run before `ro.product.*` so `ro.product.build.*`
    // is spoofed rather than dropped as an unknown `ro.product.*` field.
    if ends_with_strict(name, b".build.fingerprint") {
        return Some(b"persist.sys.yasvara.pif.fingerprint\0");
    }
    if ends_with_strict(name, b".build.id") {
        return Some(b"persist.sys.yasvara.pif.build_id\0");
    }
    if ends_with_strict(name, b".security_patch") {
        return Some(b"persist.sys.yasvara.pif.security_patch\0");
    }
    if ends_with_strict(name, b".build.version.incremental") {
        return Some(b"persist.sys.yasvara.pif.incremental\0");
    }
    if ends_with_strict(name, b".build.version.release") {
        return Some(b"persist.sys.yasvara.pif.release\0");
    }
    if ends_with_strict(name, b".build.description") {
        return Some(b"persist.sys.yasvara.pif.description\0");
    }
    if ends_with_strict(name, b".build.flavor") {
        return Some(b"persist.sys.yasvara.pif.flavor\0");
    }
    if ends_with_strict(name, b".first_api_level") {
        return Some(b"persist.sys.yasvara.pif.first_api_level\0");
    }
    if ends_with_strict(name, b".api_level") {
        return Some(b"persist.sys.yasvara.pif.api_level\0");
    }
    if starts_with(name, b"ro.product.") {
        let mut dot = name.len();
        while dot > 0 {
            dot -= 1;
            if name[dot] == b'.' {
                let field = &name[dot + 1..];
                if bytes_eq(field, b"manufacturer") {
                    return Some(b"persist.sys.yasvara.pif.manufacturer\0");
                }
                if bytes_eq(field, b"brand") {
                    return Some(b"persist.sys.yasvara.pif.brand\0");
                }
                if bytes_eq(field, b"model") {
                    return Some(b"persist.sys.yasvara.pif.model\0");
                }
                if bytes_eq(field, b"device") {
                    return Some(b"persist.sys.yasvara.pif.device\0");
                }
                if bytes_eq(field, b"name") {
                    return Some(b"persist.sys.yasvara.pif.name\0");
                }
                return None;
            }
        }
    }
    None
}

/// Strips custom-ROM prefixes (`yasvara_`, `lineage_`, `evolution_`) and rewrites
/// `-userdebug`/`-eng` to `-user` into `out` (NUL-terminated). Returns byte length excluding NUL
/// when a rewrite occurred, else `None`.
pub fn normalize_build_flavor(raw: &[u8], out: &mut [u8]) -> Option<usize> {
    if raw.is_empty() {
        return None;
    }
    let mut start = raw;
    let mut stripped = false;
    for &p in ROM_FLAVOR_PREFIXES {
        let pb = p.as_bytes();
        if starts_with(start, pb) {
            start = &start[pb.len()..];
            stripped = true;
            break;
        }
    }
    let (stem, rewrite_user) = if ends_with_strict(start, b"-userdebug") {
        (&start[..start.len() - 10], true)
    } else if ends_with_strict(start, b"-eng") {
        (&start[..start.len() - 4], true)
    } else {
        (start, false)
    };
    if !stripped && !rewrite_user {
        return None;
    }
    let needed = stem.len() + if rewrite_user { 5 } else { 0 };
    if needed + 1 > out.len() {
        return None;
    }
    out[..stem.len()].copy_from_slice(stem);
    if rewrite_user {
        out[stem.len()..stem.len() + 5].copy_from_slice(b"-user");
    }
    out[needed] = 0;
    Some(needed)
}

/// Assembles `brand/product/device:release/id/incremental:type/tags` into `out` (NUL-terminated).
/// Used when a PIF fingerprint exceeds the 91-byte non-ro property limit.
pub fn assemble_fingerprint(parts: [&[u8]; 8], out: &mut [u8]) -> Option<usize> {
    const SEPS: [&[u8]; 8] = [b"/", b"/", b":", b"/", b"/", b":", b"/", b""];
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < 8 {
        let p = parts[i];
        if p.is_empty() {
            return None;
        }
        let sep = SEPS[i];
        if pos + p.len() + sep.len() + 1 > out.len() {
            return None;
        }
        out[pos..pos + p.len()].copy_from_slice(p);
        pos += p.len();
        if !sep.is_empty() {
            out[pos..pos + sep.len()].copy_from_slice(sep);
            pos += sep.len();
        }
        i += 1;
    }
    out[pos] = 0;
    Some(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_story_table_alignment() {
        assert_eq!(BOOT_STORY.len(), 16);
        for (i, &(k, v)) in BOOT_STORY.iter().enumerate() {
            assert!(may_intercept(k.as_bytes()), "may_intercept missed BOOT_STORY key: {k}");
            assert_eq!(find_boot_story(k.as_bytes()), Some(i));
            let cstr = boot_story_value_cstr(i).unwrap();
            assert_eq!(&cstr[..cstr.len() - 1], v.as_bytes());
            assert_eq!(*cstr.last().unwrap(), 0);
        }
        for &(k, _) in COLLECTOR_STORY {
            assert!(may_intercept(k.as_bytes()), "may_intercept missed COLLECTOR_STORY key: {k}");
        }
        for &p in HIDDEN_PREFIXES {
            assert!(may_intercept(p.as_bytes()), "may_intercept missed HIDDEN_PREFIXES entry: {p}");
        }
        for &k in HIDDEN_EXACT {
            assert!(may_intercept(k.as_bytes()), "may_intercept missed HIDDEN_EXACT key: {k}");
        }
    }

    #[test]
    fn flavor_normalization_and_hidden_markers() {
        let mut buf = [0u8; 92];
        let n = normalize_build_flavor(b"yasvara_onyx-userdebug", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"onyx-user");
        assert!(normalize_build_flavor(b"onyx-user", &mut buf).is_none());

        assert!(!is_hidden_marker(b"ro.yasvara.boot.digest"));
        assert!(!is_hidden_marker(b"ro.yasvara.boot.source"));
        assert!(is_hidden_marker(b"ro.yasvara.version"));
        assert!(is_hidden_marker(b"persist.sys.yasvara.trickystore"));
        assert!(is_hidden_marker(b"ro.lineage.build.version"));
        assert!(is_hidden_marker(b"ro.boottime.adb_root"));
        assert!(is_hidden_marker(b"ro.boottime.adbd"));
        assert!(is_hidden_marker(b"init.svc_debug_pid.adbd"));
        assert!(is_hidden_marker(b"persist.adb.tls_server.enable"));
        assert!(is_hidden_marker(b"persist.adb.wifi.guid"));
        assert!(is_hidden_marker(b"dev.mnt.blk.mnt.scratch"));
        assert!(is_hidden_marker(b"dev.mnt.dev.mnt.scratch"));
        assert!(is_hidden_marker(b"dev.mnt.rootdisk.mnt.scratch"));
        assert!(is_hidden_marker(b"ro.boottime.yasvara_sessiond"));
        assert!(!is_hidden_marker(b"ro.boottime.init"));
        assert!(!is_hidden_marker(b"dev.mnt.blk.data"));
    }

    #[test]
    fn product_build_precedence_and_rkp_mfg() {
        assert_eq!(
            staging_for_identity_cstr(b"ro.product.build.fingerprint"),
            Some(b"persist.sys.yasvara.pif.fingerprint\0".as_slice())
        );
        assert_eq!(
            staging_for_identity_cstr(b"ro.product.vendor.manufacturer"),
            Some(b"persist.sys.yasvara.pif.manufacturer\0".as_slice())
        );
        assert!(is_product_manufacturer_prop(b"ro.product.manufacturer"));
        assert!(is_product_manufacturer_prop(b"ro.product.vendor.manufacturer"));
        assert!(is_product_manufacturer_prop(b"ro.product.manufacturer_for_attestation"));
        assert!(!is_product_manufacturer_prop(b"ro.product.build.id"));
    }

    #[test]
    fn cmdline_roles() {
        assert_eq!(classify_app_cmdline(b"zygote64"), ROLE_NONE);
        assert_eq!(classify_app_cmdline(b"app_process64"), ROLE_NONE);
        assert_eq!(
            classify_app_cmdline(b"com.google.android.gms.unstable"),
            ROLE_APP | ROLE_COLLECTOR
        );
        assert_eq!(
            classify_app_cmdline(b"com.google.android.GoogleCamera"),
            ROLE_APP | ROLE_RKP_MFG_EXEMPT
        );
        assert_eq!(classify_app_cmdline(b"org.yasvara.laras"), ROLE_APP | ROLE_RKP_MFG_EXEMPT);
        assert_eq!(classify_app_cmdline(b"com.example.bank"), ROLE_APP);
    }
}
