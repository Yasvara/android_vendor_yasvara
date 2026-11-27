// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Strict DER codecs, AttestationApplicationId (AAID) structural parser, and KeyMint
//! `KeyDescription` validator/patcher.

#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::contract::{
    AID_APP_START, AID_USER_OFFSET, MAX_AUTHORIZATION_FIELDS, MAX_KEY_DESCRIPTION_LEN,
    TAG_ROOT_OF_TRUST,
};
#[cfg(feature = "alloc")]
use crate::contract::{
    PROP_BOOT_DIGEST, TAG_ATTESTATION_ID_BRAND, TAG_ATTESTATION_ID_DEVICE,
    TAG_ATTESTATION_ID_IMEI, TAG_ATTESTATION_ID_MANUFACTURER, TAG_ATTESTATION_ID_MEID,
    TAG_ATTESTATION_ID_MODEL, TAG_ATTESTATION_ID_PRODUCT, TAG_ATTESTATION_ID_SECOND_IMEI,
    TAG_ATTESTATION_ID_SERIAL, TAG_BOOT_PATCHLEVEL, TAG_OS_PATCHLEVEL, TAG_OS_VERSION,
    TAG_VENDOR_PATCHLEVEL,
};
#[cfg(feature = "alloc")]
use crate::digest::is_all_zero;

/// Android UIDs carry a user/profile component; system appIds bypass patching in every user.
#[inline]
pub const fn is_app_uid(caller_uid: u32) -> bool {
    caller_uid % AID_USER_OFFSET >= AID_APP_START
}

/// Top-level attestation modification gate shared across request preparation & response patching.
pub fn should_modify_attestation(
    caller_uid: u32,
    master: Option<&str>,
    has_unmanaged_attestation_key: bool,
) -> bool {
    is_app_uid(caller_uid) && master == Some("1") && !has_unmanaged_attestation_key
}

/// Parsed single DER TLV element borrowing the input slice.
#[derive(Clone, Copy, Debug)]
pub struct Elem<'a> {
    pub tag: &'a [u8],
    pub value: &'a [u8],
    pub total: usize,
}

/// Reads exactly one DER element consuming all of `input`.
pub fn read_single(input: &[u8]) -> Result<Elem<'_>, &'static str> {
    let elem = read_elem(input)?;
    if elem.total != input.len() {
        return Err("trailing data after DER element");
    }
    Ok(elem)
}

/// Strict canonical DER TLV reader (rejects EOC, indefinite length, nonminimal tags/lengths).
pub fn read_elem(input: &[u8]) -> Result<Elem<'_>, &'static str> {
    let first = *input.first().ok_or("truncated DER (no tag)")?;
    if first == 0 {
        return Err("DER end-of-contents tag is not allowed");
    }
    let mut i = 1usize;
    if first & 0x1f == 0x1f {
        let mut number = 0u32;
        loop {
            if i > 5 {
                return Err("DER tag exceeds u32 bound");
            }
            let b = *input.get(i).ok_or("truncated multi-byte tag")?;
            if i == 1 && b & 0x7f == 0 {
                return Err("nonminimal DER tag");
            }
            number = number
                .checked_mul(128)
                .and_then(|n| n.checked_add(u32::from(b & 0x7f)))
                .ok_or("DER tag overflow")?;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        if number < 31 {
            return Err("nonminimal DER high tag");
        }
    }
    let tag = &input[..i];
    let l0 = *input.get(i).ok_or("truncated length")?;
    i += 1;
    let len = if l0 & 0x80 == 0 {
        l0 as usize
    } else {
        let nbytes = (l0 & 0x7f) as usize;
        if nbytes == 0 || nbytes > 4 {
            return Err("unsupported or indefinite DER length");
        }
        if input.get(i) == Some(&0) {
            return Err("nonminimal DER length");
        }
        let mut v = 0usize;
        for _ in 0..nbytes {
            v = v
                .checked_mul(256)
                .and_then(|v| input.get(i).and_then(|b| v.checked_add(*b as usize)))
                .ok_or("truncated or overflowing DER length")?;
            i += 1;
        }
        if v < 128 {
            return Err("nonminimal DER long length");
        }
        v
    };
    let end = i.checked_add(len).ok_or("length overflow")?;
    if end > input.len() {
        return Err("value runs past end of input");
    }
    Ok(Elem { tag, value: &input[i..end], total: end })
}

/// Extracts the tag number from an explicit constructed context tag (`[N]`).
pub fn context_tag_number(tag: &[u8]) -> Option<u32> {
    let first = *tag.first()?;
    if first & 0xE0 != 0xA0 {
        return None;
    }
    if first & 0x1f != 0x1f {
        return Some(u32::from(first & 0x1f));
    }
    let mut n: u32 = 0;
    for &b in &tag[1..] {
        n = n.checked_mul(128)?.checked_add(u32::from(b & 0x7f))?;
    }
    Some(n)
}

pub fn read_uint(field: &[u8], tag: u8) -> Result<u32, &'static str> {
    let elem = read_single(field)?;
    if elem.tag != [tag] || elem.value.is_empty() || elem.value[0] & 0x80 != 0 {
        return Err("expected a nonnegative DER INTEGER/ENUMERATED");
    }
    if elem.value.len() > 1 && elem.value[0] == 0 && elem.value[1] & 0x80 == 0 {
        return Err("nonminimal DER INTEGER/ENUMERATED");
    }
    elem.value.iter().try_fold(0u32, |v, b| {
        v.checked_mul(256)
            .and_then(|v| v.checked_add(u32::from(*b)))
            .ok_or("DER INTEGER/ENUMERATED exceeds u32")
    })
}

/// Structurally parses an Android `AttestationApplicationId` DER blob and visits every
/// `AttestationPackageInfo.package_name` (ignoring `signature_digests` so digest bytes can
/// never masquerade as a package name).
///
/// Schema:
/// ```asn1
/// AttestationApplicationId ::= SEQUENCE {
///     package_infos     SET OF AttestationPackageInfo,
///     signature_digests SET OF OCTET STRING
/// }
/// AttestationPackageInfo ::= SEQUENCE {
///     package_name OCTET STRING,
///     version      INTEGER
/// }
/// ```
pub fn for_each_aaid_package<'a>(aaid: &'a [u8], mut f: impl FnMut(&'a [u8]) -> bool) -> bool {
    let Ok(seq) = read_single(aaid) else {
        return false;
    };
    if seq.tag != [0x30] {
        return false;
    }
    let Ok(pkg_infos_set) = read_elem(seq.value) else {
        return false;
    };
    if pkg_infos_set.tag != [0x31] {
        return false;
    }
    let mut rest = pkg_infos_set.value;
    let mut count = 0usize;
    while !rest.is_empty() && count < 64 {
        let Ok(pkg_info) = read_elem(rest) else {
            return false;
        };
        if pkg_info.tag != [0x30] {
            return false;
        }
        let Ok(pkg_name) = read_elem(pkg_info.value) else {
            return false;
        };
        if pkg_name.tag != [0x04] {
            return false;
        }
        if f(pkg_name.value) {
            return true;
        }
        rest = &rest[pkg_info.total..];
        count += 1;
    }
    false
}

/// Strict DER check: returns true iff `target_pkg` is an exact package name in `aaid`.
pub fn aaid_has_package(aaid: &[u8], target_pkg: &[u8]) -> bool {
    for_each_aaid_package(aaid, |pkg| pkg == target_pkg)
}

/// Zero-alloc view of a hardware attestation `KeyDescription` extension value.
#[derive(Clone, Copy, Debug)]
pub struct HardwareAttestationInfo<'a> {
    pub attestation_version: u32,
    pub attestation_security_level: u32,
    pub keymaster_security_level: u32,
    pub challenge: &'a [u8],
    pub verified_boot_key: &'a [u8],
    pub device_locked: bool,
    pub verified_boot_state: u32,
    pub verified_boot_hash: &'a [u8],
}

/// Parses a hardware `KeyDescription` (strictly requiring hardware-enforced `RootOfTrust`
/// with no software/duplicate `RootOfTrust`). Used by boot-digest probing and self-checks.
pub fn parse_hardware_attestation<'a>(
    raw: &'a [u8],
) -> Result<HardwareAttestationInfo<'a>, &'static str> {
    if raw.len() > MAX_KEY_DESCRIPTION_LEN {
        return Err("KeyDescription exceeds 64 KiB bound");
    }
    let top = read_single(raw)?;
    if top.tag != [0x30] {
        return Err("KeyDescription is not a SEQUENCE");
    }
    let mut fields: [&'a [u8]; 8] = [&[]; 8];
    let mut content = top.value;
    for slot in &mut fields {
        if content.is_empty() {
            return Err("KeyDescription expected 8 fields");
        }
        let e = read_elem(content)?;
        *slot = &content[..e.total];
        content = &content[e.total..];
    }
    if !content.is_empty() {
        return Err("KeyDescription expected 8 fields");
    }
    let attestation_version = read_uint(fields[0], 0x02)?;
    let attestation_security_level = read_security_level(fields[1])?;
    read_uint(fields[2], 0x02)?;
    let keymaster_security_level = read_security_level(fields[3])?;
    let challenge_elem = read_single(fields[4])?;
    if challenge_elem.tag != [0x04] || challenge_elem.value.len() > 128 {
        return Err("KeyDescription challenge is not a valid <=128B OCTET STRING");
    }
    if read_single(fields[5])?.tag != [0x04] {
        return Err("KeyDescription unique ID is not an OCTET STRING");
    }
    let sw = read_list(fields[6])?;
    let hw = read_list(fields[7])?;

    let rot_raw = find_hardware_root_of_trust(sw, hw)?;
    let (boot_key, device_locked, verified_boot_state, boot_hash) = parse_root_of_trust(rot_raw)?;
    Ok(HardwareAttestationInfo {
        attestation_version,
        attestation_security_level,
        keymaster_security_level,
        challenge: challenge_elem.value,
        verified_boot_key: boot_key,
        device_locked,
        verified_boot_state,
        verified_boot_hash: boot_hash,
    })
}

fn find_hardware_root_of_trust<'a>(sw: &'a [u8], hw: &'a [u8]) -> Result<&'a [u8], &'static str> {
    let mut root: Option<&'a [u8]> = None;
    for (hardware, mut rest) in [(false, sw), (true, hw)] {
        let mut count = 0usize;
        while !rest.is_empty() {
            if count == MAX_AUTHORIZATION_FIELDS {
                return Err("DER field count exceeds bound");
            }
            let e = read_elem(rest)?;
            let tag = context_tag_number(e.tag)
                .ok_or("AuthorizationList field is not an explicit context tag")?;
            if tag == TAG_ROOT_OF_TRUST {
                if !hardware {
                    return Err("original RootOfTrust is software-enforced, not hardware-enforced");
                }
                if root.replace(e.value).is_some() {
                    return Err("duplicate original hardware RootOfTrust");
                }
            }
            rest = &rest[e.total..];
            count += 1;
        }
    }
    root.ok_or("original hardware RootOfTrust is missing")
}

fn parse_root_of_trust<'a>(raw: &'a [u8]) -> Result<(&'a [u8], bool, u32, &'a [u8]), &'static str> {
    let sequence = read_single(raw)?;
    if sequence.tag != [0x30] {
        return Err("expected a SEQUENCE");
    }
    let mut fields: [&'a [u8]; 4] = [&[]; 4];
    let mut content = sequence.value;
    for slot in &mut fields {
        if content.is_empty() {
            return Err("expected key, deviceLocked, verifiedBootState and verifiedBootHash");
        }
        let e = read_elem(content)?;
        *slot = &content[..e.total];
        content = &content[e.total..];
    }
    if !content.is_empty() {
        return Err("expected key, deviceLocked, verifiedBootState and verifiedBootHash");
    }
    let key_elem = read_single(fields[0])?;
    if key_elem.tag != [0x04] {
        return Err("verifiedBootKey is not an OCTET STRING");
    }
    let locked = read_single(fields[1])?;
    if locked.tag != [0x01] || !matches!(locked.value, [0x00] | [0xff]) {
        return Err("deviceLocked is not a DER BOOLEAN");
    }
    let state = read_uint(fields[2], 0x0a)?;
    if state > 3 {
        return Err("invalid verifiedBootState");
    }
    let hash = read_single(fields[3])?;
    if hash.tag != [0x04] || !matches!(hash.value.len(), 32 | 64) {
        return Err("verifiedBootHash must be a SHA-256 or SHA-512 OCTET STRING");
    }
    Ok((key_elem.value, locked.value == [0xff], state, hash.value))
}

fn read_security_level(field: &[u8]) -> Result<u32, &'static str> {
    let level = read_uint(field, 0x0a)?;
    if level > 2 {
        return Err("invalid attestation/keymaster security level");
    }
    Ok(level)
}

fn read_list(field: &[u8]) -> Result<&[u8], &'static str> {
    let e = read_single(field)?;
    if e.tag != [0x30] {
        return Err("AuthorizationList is not a SEQUENCE");
    }
    Ok(e.value)
}

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceIdOverrides {
    pub brand: String,
    pub device: String,
    pub product: String,
    pub manufacturer: String,
    pub model: String,
}

#[cfg(feature = "alloc")]
pub struct PatchConfig<'a> {
    pub canonical_boot_digest: &'a [u8],
    pub boot_key: Option<&'a [u8]>,
    pub id_overrides: Option<&'a DeviceIdOverrides>,
    pub os_version: Option<u32>,
    pub os_patchlevel: Option<u32>,
    pub vendor_patchlevel: Option<u32>,
    pub boot_patchlevel: Option<u32>,
}

#[cfg(feature = "alloc")]
pub struct PatchedKeyDescription {
    pub der: Vec<u8>,
    pub attestation_version: u32,
    pub attestation_security_level: u32,
    pub keymaster_security_level: u32,
}

/// Validates and patches an Android KeyMint `KeyDescription` extension value.
#[cfg(feature = "alloc")]
pub fn patch_key_description(
    raw: &[u8],
    config: &PatchConfig,
) -> Result<PatchedKeyDescription, String> {
    if raw.len() > MAX_KEY_DESCRIPTION_LEN {
        return Err("KeyDescription exceeds 64 KiB bound".into());
    }
    if !matches!(config.canonical_boot_digest.len(), 32 | 64)
        || is_all_zero(config.canonical_boot_digest)
    {
        return Err("canonical boot digest must be non-zero SHA-256 or SHA-512".into());
    }
    let top = read_single(raw)?;
    if top.tag != [0x30] {
        return Err("KeyDescription is not a SEQUENCE".into());
    }
    let fields = split_elems(top.value, 8)?;
    if fields.len() != 8 {
        return Err(format!("KeyDescription expected 8 fields, got {}", fields.len()));
    }
    let attestation_version = read_uint(fields[0], 0x02)?;
    let attestation_security_level = read_security_level(fields[1])?;
    read_uint(fields[2], 0x02)?;
    let keymaster_security_level = read_security_level(fields[3])?;
    let challenge_elem = read_single(fields[4])?;
    if challenge_elem.tag != [0x04] || challenge_elem.value.len() > 128 {
        return Err("KeyDescription challenge is not a valid <=128B OCTET STRING".into());
    }
    if read_single(fields[5])?.tag != [0x04] {
        return Err("KeyDescription unique ID is not an OCTET STRING".into());
    }
    let sw = read_list(fields[6])?;
    let hw = read_list(fields[7])?;

    let rot_raw = find_hardware_root_of_trust(sw, hw)?;
    let (orig_boot_key, _, _, orig_boot_hash) =
        parse_root_of_trust(rot_raw).map_err(|e| format!("original hardware RootOfTrust: {}", e))?;

    let hash_all_zero = is_all_zero(orig_boot_hash);
    if !hash_all_zero && orig_boot_hash != config.canonical_boot_digest {
        return Err(format!(
            "original hardware RootOfTrust: verifiedBootHash disagrees with {}; check per-boot digest publisher",
            PROP_BOOT_DIGEST
        ));
    }
    let effective_hash: Vec<u8> = if hash_all_zero {
        config.canonical_boot_digest.to_vec()
    } else {
        orig_boot_hash.to_vec()
    };

    let mut boot_key = orig_boot_key.to_vec();
    if is_all_zero(&boot_key) {
        if let Some(key) = config.boot_key.filter(|k| k.len() == 32 && !is_all_zero(k)) {
            boot_key = key.to_vec();
        }
    }

    let mut overrides = Vec::new();
    let spoofed_rot_seq = {
        let mut body = Vec::new();
        body.extend_from_slice(&tlv(&[0x04], &boot_key));
        body.extend_from_slice(&[0x01, 0x01, 0xff]); // deviceLocked = TRUE
        body.extend_from_slice(&[0x0a, 0x01, 0x00]); // verifiedBootState = Verified(0)
        body.extend_from_slice(&tlv(&[0x04], &effective_hash));
        tlv(&[0x30], &body)
    };
    overrides.push((TAG_ROOT_OF_TRUST, tlv(&context_tag(TAG_ROOT_OF_TRUST), &spoofed_rot_seq)));
    if let Some(os_ver) = config.os_version {
        overrides.push((TAG_OS_VERSION, explicit_integer(TAG_OS_VERSION, os_ver)));
    }
    if let Some(os_patch) = config.os_patchlevel {
        overrides.push((TAG_OS_PATCHLEVEL, explicit_integer(TAG_OS_PATCHLEVEL, os_patch)));
    }
    if let Some(ids) = config.id_overrides {
        let id_list: &[(u32, &str)] = &[
            (TAG_ATTESTATION_ID_BRAND, &ids.brand),
            (TAG_ATTESTATION_ID_DEVICE, &ids.device),
            (TAG_ATTESTATION_ID_PRODUCT, &ids.product),
            (TAG_ATTESTATION_ID_MANUFACTURER, &ids.manufacturer),
            (TAG_ATTESTATION_ID_MODEL, &ids.model),
        ];
        for (tag, val) in id_list {
            if !val.is_empty() {
                overrides.push((*tag, explicit_octet_string(*tag, val.as_bytes())));
            }
        }
    }
    if let Some(v) = config.vendor_patchlevel {
        overrides.push((TAG_VENDOR_PATCHLEVEL, explicit_integer(TAG_VENDOR_PATCHLEVEL, v)));
    }
    if let Some(b) = config.boot_patchlevel {
        overrides.push((TAG_BOOT_PATCHLEVEL, explicit_integer(TAG_BOOT_PATCHLEVEL, b)));
    }

    let strip_hw_unique_ids = config.id_overrides.is_some_and(|ids| {
        !ids.brand.is_empty()
            || !ids.device.is_empty()
            || !ids.product.is_empty()
            || !ids.model.is_empty()
    });
    let mut seen = Vec::new();
    let sw = replace_in_list(sw, &overrides, strip_hw_unique_ids, &mut seen)?;
    let mut hw = replace_in_list(hw, &overrides, strip_hw_unique_ids, &mut seen)?;
    for tag in [TAG_VENDOR_PATCHLEVEL, TAG_BOOT_PATCHLEVEL] {
        if !seen.contains(&tag) {
            if let Some((_, elem)) = overrides.iter().find(|(t, _)| *t == tag) {
                hw = insert_in_order(hw, tag, elem)?;
            }
        }
    }

    let mut body = Vec::with_capacity(raw.len() + 64);
    for field in &fields[..6] {
        body.extend_from_slice(field);
    }
    body.extend_from_slice(&tlv(&[0x30], &sw));
    body.extend_from_slice(&tlv(&[0x30], &hw));
    let der = tlv(&[0x30], &body);
    if der.len() > MAX_KEY_DESCRIPTION_LEN {
        return Err("patched KeyDescription exceeds 64 KiB bound".into());
    }
    Ok(PatchedKeyDescription {
        der,
        attestation_version,
        attestation_security_level,
        keymaster_security_level,
    })
}

#[cfg(feature = "alloc")]
fn replace_in_list(
    body: &[u8],
    overrides: &[(u32, Vec<u8>)],
    strip_hw_unique_ids: bool,
    seen: &mut Vec<u32>,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    while !rest.is_empty() {
        let e = read_elem(rest)?;
        let mut hit = None;
        let mut drop_elem = false;
        if let Some(n) = context_tag_number(e.tag) {
            if strip_hw_unique_ids
                && matches!(
                    n,
                    TAG_ATTESTATION_ID_SERIAL
                        | TAG_ATTESTATION_ID_IMEI
                        | TAG_ATTESTATION_ID_MEID
                        | TAG_ATTESTATION_ID_SECOND_IMEI
                )
            {
                drop_elem = true;
            } else if let Some((_, repl)) = overrides.iter().find(|(t, _)| *t == n) {
                hit = Some((n, repl));
            }
        }
        if !drop_elem {
            match hit {
                Some((n, repl)) => {
                    out.extend_from_slice(repl);
                    if !seen.contains(&n) {
                        seen.push(n);
                    }
                }
                None => out.extend_from_slice(&rest[..e.total]),
            }
        }
        rest = &rest[e.total..];
    }
    Ok(out)
}

#[cfg(feature = "alloc")]
fn insert_in_order(body: Vec<u8>, num: u32, element: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(body.len() + element.len());
    let mut rest: &[u8] = &body;
    let mut inserted = false;
    while !rest.is_empty() {
        let e = read_elem(rest)?;
        if !inserted {
            if let Some(n) = context_tag_number(e.tag) {
                if n > num {
                    out.extend_from_slice(element);
                    inserted = true;
                }
            }
        }
        out.extend_from_slice(&rest[..e.total]);
        rest = &rest[e.total..];
    }
    if !inserted {
        out.extend_from_slice(element);
    }
    Ok(out)
}

#[cfg(feature = "alloc")]
fn split_elems(mut content: &[u8], limit: usize) -> Result<Vec<&[u8]>, String> {
    let mut out = Vec::new();
    while !content.is_empty() {
        if out.len() == limit {
            return Err("DER field count exceeds bound".into());
        }
        let e = read_elem(content)?;
        out.push(&content[..e.total]);
        content = &content[e.total..];
    }
    Ok(out)
}

#[cfg(feature = "alloc")]
fn explicit_integer(tag_num: u32, value: u32) -> Vec<u8> {
    tlv(&context_tag(tag_num), &tlv(&[0x02], &der_uint(value)))
}

#[cfg(feature = "alloc")]
fn explicit_octet_string(tag_num: u32, value: &[u8]) -> Vec<u8> {
    tlv(&context_tag(tag_num), &tlv(&[0x04], value))
}

#[cfg(feature = "alloc")]
pub fn context_tag(n: u32) -> Vec<u8> {
    if n < 0x1f {
        return vec![0xA0 | (n & 0x1f) as u8];
    }
    let mut digits = Vec::new();
    let mut v = n;
    while v > 0 {
        digits.push((v & 0x7f) as u8);
        v >>= 7;
    }
    digits.reverse();
    let mut out = Vec::with_capacity(1 + digits.len());
    out.push(0xBF);
    let last = digits.len() - 1;
    for (i, d) in digits.iter().enumerate() {
        out.push(if i == last { *d } else { d | 0x80 });
    }
    out
}

#[cfg(feature = "alloc")]
pub fn der_uint(mut value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut be = Vec::new();
    while value > 0 {
        be.push((value & 0xff) as u8);
        value >>= 8;
    }
    be.reverse();
    if be[0] & 0x80 != 0 {
        be.insert(0, 0x00);
    }
    be
}

#[cfg(feature = "alloc")]
pub fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut be = Vec::new();
    let mut v = n;
    while v > 0 {
        be.push((v & 0xff) as u8);
        v >>= 8;
    }
    be.reverse();
    let mut out = Vec::with_capacity(1 + be.len());
    out.push(0x80 | be.len() as u8);
    out.extend_from_slice(&be);
    out
}

#[cfg(feature = "alloc")]
pub fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 5 + value.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&der_len(value.len()));
    out.extend_from_slice(value);
    out
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::digest::parse_boot_digest;
    use crate::version::{parse_decimal, parse_long_patch, parse_os_patchlevel, parse_version_number};

    fn config(digest: &[u8]) -> PatchConfig<'_> {
        PatchConfig {
            canonical_boot_digest: digest,
            boot_key: None,
            id_overrides: None,
            os_version: None,
            os_patchlevel: None,
            vendor_patchlevel: None,
            boot_patchlevel: None,
        }
    }

    fn root_fields(key: &[u8], digest: &[u8]) -> Vec<Vec<u8>> {
        vec![
            tlv(&[0x04], key),
            vec![0x01, 0x01, 0x00], // Original unlocked device.
            vec![0x0a, 0x01, 0x02], // Original Unverified state.
            tlv(&[0x04], digest),
        ]
    }

    fn root(fields: &[Vec<u8>]) -> Vec<u8> {
        tlv(&context_tag(TAG_ROOT_OF_TRUST), &tlv(&[0x30], &fields.concat()))
    }

    fn description(sw: &[u8], hw: &[u8], attest_level: u8, keymaster_level: u8) -> Vec<u8> {
        tlv(
            &[0x30],
            &[
                tlv(&[0x02], &der_uint(400)),
                vec![0x0a, 0x01, attest_level],
                tlv(&[0x02], &der_uint(300)),
                vec![0x0a, 0x01, keymaster_level],
                tlv(&[0x04], b"test challenge"),
                tlv(&[0x04], b"test unique ID"),
                tlv(&[0x30], sw),
                tlv(&[0x30], hw),
            ]
            .concat(),
        )
    }

    fn description_fields(raw: &[u8]) -> Vec<&[u8]> {
        split_elems(read_single(raw).unwrap().value, 8).unwrap()
    }

    fn authorization(list: &[u8], tag: u32) -> Option<&[u8]> {
        split_elems(read_list(list).unwrap(), MAX_AUTHORIZATION_FIELDS)
            .unwrap()
            .into_iter()
            .find(|field| context_tag_number(read_single(field).unwrap().tag) == Some(tag))
    }

    fn build_aaid(pkgs: &[&[u8]], sigs: &[&[u8]]) -> Vec<u8> {
        let mut pkg_set = Vec::new();
        for p in pkgs {
            let mut info = tlv(&[0x04], p);
            info.extend_from_slice(&tlv(&[0x02], &[0x01]));
            pkg_set.extend_from_slice(&tlv(&[0x30], &info));
        }
        let mut sig_set = Vec::new();
        for s in sigs {
            sig_set.extend_from_slice(&tlv(&[0x04], s));
        }
        let mut body = tlv(&[0x31], &pkg_set);
        body.extend_from_slice(&tlv(&[0x31], &sig_set));
        tlv(&[0x30], &body)
    }

    #[test]
    fn strict_aaid_ignores_signature_digest_spoofing() {
        let fake_in_sig = b"com.google.android.gms";
        let aaid = build_aaid(&[b"com.example.untrusted"], &[fake_in_sig]);
        assert!(aaid_has_package(&aaid, b"com.example.untrusted"));
        assert!(!aaid_has_package(&aaid, b"com.google.android.gms"));
    }

    #[test]
    fn strict_aaid_matches_multi_package_uid() {
        let aaid = build_aaid(&[b"com.google.android.gsf", b"com.google.android.gms"], &[&[0xaa; 32]]);
        assert!(aaid_has_package(&aaid, b"com.google.android.gms"));
        assert!(aaid_has_package(&aaid, b"com.google.android.gsf"));
        assert!(!aaid_has_package(&aaid, b"com.google.android.gmsx"));
    }

    #[test]
    fn modification_policy_requires_enabled_master_and_preserves_explicit_signers() {
        for uid in [10_000, 110_000] {
            assert!(should_modify_attestation(uid, Some("1"), false));
            for master in [None, Some("0"), Some(""), Some("false"), Some("garbage"), Some("2")] {
                assert!(!should_modify_attestation(uid, master, false));
                assert!(!should_modify_attestation(uid, master, true));
            }
            assert!(!should_modify_attestation(uid, Some("1"), true));
        }
        for uid in [0, 1000, 9999, 101_000] {
            assert!(!should_modify_attestation(uid, Some("1"), false));
        }
    }

    #[test]
    fn patch_parsers_and_version_parsers_edge_cases() {
        for (input, long, short) in [
            ("2026-09-05", 20260905, 202609),
            (" 2024-04-01 ", 20240401, 202404),
            ("2024-04", 20240401, 202404),
            ("2024-02-29", 20240229, 202402),
            ("2000-02-29", 20000229, 200002),
            ("0001-01-01", 10101, 101),
            ("9999-12-31", 99991231, 999912),
        ] {
            assert_eq!(parse_long_patch(input), Some(long), "{input}");
            assert_eq!(parse_os_patchlevel(input), Some(short), "{input}");
        }
        for bad in [
            "", "2024", "2024-", "2024-04-", "2024-04-bad", "2024-04-01-extra", "2024-00-01",
            "2024-13-01", "2024-01-00", "2024-01-32", "2024-04-31", "2023-02-29", "1900-02-29",
            "2024-02-30", "0000-01-01", "2024-4-01", "2024-04-1", "24-04-01", "+024-04-01",
            "4294967296-12-31", "18446744073709551616-01-01",
        ] {
            assert_eq!(parse_long_patch(bad), None, "{bad:?}");
            assert_eq!(parse_os_patchlevel(bad), None, "{bad:?}");
        }
        for (input, expected) in [
            ("0", 0), ("14", 140000), ("14.0", 140000), ("15.1.2", 150102),
            (" 17.0.0 ", 170000), ("99.99.99", 999999), ("01.02.03", 10203),
        ] {
            assert_eq!(parse_version_number(input), Some(expected), "{input}");
        }
        for bad in [
            "", "CANARY", "14.", "14..1", "14.0.", "14.bad", "14.0.0.1", "+14", "-14",
            "100", "14.100", "14.0.100", "000", "4294967296", "18446744073709551616.0.0",
        ] {
            assert_eq!(parse_version_number(bad), None, "{bad:?}");
        }
        assert_eq!(parse_decimal("4294967295"), Some(u32::MAX));
        assert_eq!(parse_decimal("4294967296"), None);
    }

    #[test]
    fn canonical_digest_rejects_all_zero_and_malformed() {
        let sha256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert_eq!(parse_boot_digest(Some(sha256)).unwrap(), (0u8..32).collect::<Vec<_>>());
        assert_eq!(parse_boot_digest(Some(&"ab".repeat(64))).unwrap(), vec![0xab; 64]);
        // Security invariant: all-zero digests MUST be rejected across every layer!
        assert!(parse_boot_digest(Some(&"00".repeat(32))).is_err());
        assert!(parse_boot_digest(Some(&"00".repeat(64))).is_err());
        assert!(parse_boot_digest(None).is_err());
        for bad in [
            String::new(), "a".repeat(63), "a".repeat(65), "a".repeat(127), "a".repeat(129),
            "AB".repeat(32), "ag".repeat(32), format!(" {}", "ab".repeat(32)),
            format!("{}\n", "ab".repeat(32)), format!("0x{}", "ab".repeat(32)),
        ] {
            assert!(parse_boot_digest(Some(&bad)).is_err());
        }
    }

    #[test]
    fn original_uid_guard_and_rot_spoofing() {
        for uid in [0, 1000, 1017, 9999, 100_000, 101_000, 109_999, 201_000] {
            assert!(!is_app_uid(uid));
        }
        for uid in [10_000, 19_999, 99_000, 110_000, 199_999, 210_000] {
            assert!(is_app_uid(uid));
        }
        let digest = [0x56; 32];
        let original = description(&[], &root(&root_fields(&[0; 32], &digest)), 0, 2);
        let patched = patch_key_description(&original, &config(&digest)).unwrap();
        let hw = description_fields(&patched.der)[7];
        let rot_seq = read_single(read_single(authorization(hw, TAG_ROOT_OF_TRUST).unwrap()).unwrap().value).unwrap();
        let rot_fields = split_elems(rot_seq.value, 4).unwrap();
        assert_eq!(read_single(rot_fields[0]).unwrap().value, [0u8; 32]);
        assert_eq!(rot_fields[1], [0x01, 0x01, 0xff]);
        assert_eq!(rot_fields[2], [0x0a, 0x01, 0x00]);
        assert_eq!(read_single(rot_fields[3]).unwrap().value, digest);
    }

    #[test]
    fn zero_boot_key_fallback_and_zero_hw_hash_replacement() {
        let canonical = [0x31; 32];
        let fallback = [0x5a; 32];
        let original = description(&[], &root(&root_fields(&[0; 32], &[0u8; 32])), 1, 1);
        let mut cfg = config(&canonical);
        cfg.boot_key = Some(&fallback);
        let patched = patch_key_description(&original, &cfg).unwrap();
        let hw = description_fields(&patched.der)[7];
        let rot_seq = read_single(read_single(authorization(hw, TAG_ROOT_OF_TRUST).unwrap()).unwrap().value).unwrap();
        let rot_fields = split_elems(rot_seq.value, 4).unwrap();
        assert_eq!(read_single(rot_fields[0]).unwrap().value, fallback);
        assert_eq!(read_single(rot_fields[3]).unwrap().value, canonical);
    }

    #[test]
    fn mismatching_and_malformed_rot_refuse_patch() {
        for size in [32, 64] {
            let digest = vec![0x12; size];
            let original = description(&[], &root(&root_fields(&[0; 32], &digest)), 1, 1);
            let mut mismatch = digest.clone();
            mismatch[size - 1] ^= 1;
            let err = patch_key_description(&original, &config(&mismatch)).err().unwrap();
            assert!(err.contains("verifiedBootHash disagrees with ro.yasvara.boot.digest"));
            let other = vec![0x12; if size == 32 { 64 } else { 32 }];
            assert!(patch_key_description(&original, &config(&other)).is_err());
        }
        let digest = [0x12; 32];
        let original_root = root(&root_fields(&[0; 32], &digest));
        for (sw, hw, expected) in [
            (vec![], vec![], "missing"),
            (original_root.clone(), vec![], "software-enforced"),
            (original_root.clone(), original_root.clone(), "software-enforced"),
            (vec![], [original_root.clone(), original_root.clone()].concat(), "duplicate"),
        ] {
            let err = patch_key_description(&description(&sw, &hw, 1, 1), &config(&digest)).err().unwrap();
            assert!(err.contains(expected), "{err}");
        }
        assert!(patch_key_description(&vec![0; MAX_KEY_DESCRIPTION_LEN + 1], &config(&digest)).is_err());
    }

    #[test]
    fn nonboot_overrides_strip_hw_ids_when_pif_active_and_preserve_when_inactive() {
        let digest = [0x12; 32];
        let sw = [explicit_integer(TAG_OS_VERSION, 130000), explicit_integer(TAG_OS_PATCHLEVEL, 202601)].concat();
        let id_values = [
            (TAG_ATTESTATION_ID_BRAND, "brand"),
            (TAG_ATTESTATION_ID_DEVICE, "device"),
            (TAG_ATTESTATION_ID_PRODUCT, "product"),
            (TAG_ATTESTATION_ID_MANUFACTURER, "manufacturer"),
            (TAG_ATTESTATION_ID_MODEL, "model"),
        ];
        let mut hw = root(&root_fields(&[0; 32], &digest));
        for (tag, _) in id_values {
            hw.extend_from_slice(&explicit_octet_string(tag, b"old"));
        }
        let orig_serial = explicit_octet_string(TAG_ATTESTATION_ID_SERIAL, b"unchanged serial");
        let orig_imei = explicit_octet_string(TAG_ATTESTATION_ID_IMEI, b"862948071104480");
        let orig_imei2 = explicit_octet_string(TAG_ATTESTATION_ID_SECOND_IMEI, b"862948071104498");
        hw.extend_from_slice(&orig_serial);
        hw.extend_from_slice(&orig_imei);
        hw.extend_from_slice(&explicit_integer(TAG_BOOT_PATCHLEVEL, 20260105));
        hw.extend_from_slice(&orig_imei2);
        let original = description(&sw, &hw, 0, 2);

        let ids = DeviceIdOverrides {
            brand: "brand".into(), device: "device".into(), product: "product".into(),
            manufacturer: "manufacturer".into(), model: "model".into(),
        };
        let mut cfg = config(&digest);
        cfg.id_overrides = Some(&ids);
        cfg.os_version = Some(170000);
        cfg.os_patchlevel = Some(202610);
        cfg.vendor_patchlevel = Some(20261005);
        cfg.boot_patchlevel = Some(20261005);
        let patched = patch_key_description(&original, &cfg).unwrap();
        let after = description_fields(&patched.der);
        assert_eq!(authorization(after[6], TAG_OS_VERSION), Some(explicit_integer(TAG_OS_VERSION, 170000).as_slice()));
        assert_eq!(authorization(after[6], TAG_OS_PATCHLEVEL), Some(explicit_integer(TAG_OS_PATCHLEVEL, 202610).as_slice()));
        for (tag, val) in id_values {
            assert_eq!(authorization(after[7], tag), Some(explicit_octet_string(tag, val.as_bytes()).as_slice()));
        }
        assert_eq!(authorization(after[7], TAG_ATTESTATION_ID_SERIAL), None);
        assert_eq!(authorization(after[7], TAG_ATTESTATION_ID_IMEI), None);
        assert_eq!(authorization(after[7], TAG_ATTESTATION_ID_SECOND_IMEI), None);
        assert_eq!(authorization(after[7], TAG_VENDOR_PATCHLEVEL), Some(explicit_integer(TAG_VENDOR_PATCHLEVEL, 20261005).as_slice()));
        assert_eq!(authorization(after[7], TAG_BOOT_PATCHLEVEL), Some(explicit_integer(TAG_BOOT_PATCHLEVEL, 20261005).as_slice()));

        let patched_no_pif = patch_key_description(&original, &config(&digest)).unwrap();
        let after_no_pif = description_fields(&patched_no_pif.der);
        assert_eq!(authorization(after_no_pif[7], TAG_ATTESTATION_ID_SERIAL), Some(orig_serial.as_slice()));
        assert_eq!(authorization(after_no_pif[7], TAG_ATTESTATION_ID_IMEI), Some(orig_imei.as_slice()));
        assert_eq!(authorization(after_no_pif[7], TAG_ATTESTATION_ID_SECOND_IMEI), Some(orig_imei2.as_slice()));
    }

    #[test]
    fn truncations_oversized_challenge_and_mutations_never_panic() {
        let digest = [0x12; 64];
        let original = description(&[], &root(&root_fields(&[0; 32], &digest)), 1, 2);
        for end in 0..original.len() {
            assert!(patch_key_description(&original[..end], &config(&digest)).is_err());
        }
        for idx in 0..original.len() {
            for b in [0x00, 0x7f, 0x80, 0xff] {
                let mut mutated = original.clone();
                mutated[idx] = b;
                let _ = patch_key_description(&mutated, &config(&digest));
            }
        }
        let oversized = tlv(&[0x30], &[
            tlv(&[0x02], &der_uint(300)), vec![0x0a, 0x01, 1],
            tlv(&[0x02], &der_uint(300)), vec![0x0a, 0x01, 1],
            tlv(&[0x04], &vec![0x41; 129]), tlv(&[0x04], b"uid"),
            tlv(&[0x30], &[]), tlv(&[0x30], &root(&root_fields(&[0; 32], &[0x12; 32]))),
        ].concat());
        assert!(patch_key_description(&oversized, &config(&[0x12; 32])).is_err());
    }
}
