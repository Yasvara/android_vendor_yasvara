// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Thin, panic-safe JNI bridge for `com.android.server.yasvara.YasvaraIntegrityNative`
//! loaded once inside `system_server`. Zero background threads, zero duplicate logic —
//! every parser and validator delegates directly to `yasvara_integrity_core` and
//! `yasvara_integrity_attest`.

use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jbyteArray, jint, jobjectArray, jstring, JNI_FALSE};
use jni::JNIEnv;

use yasvara_integrity_attest::keybox::{inspect_keybox, json_escape};
use yasvara_integrity_attest::patcher::extract_hardware_boot_hash;
use yasvara_integrity_core::contract::KEYBOX_ERR_NONE;
use yasvara_integrity_core::digest::{encode_boot_digest, normalize_boot_digest, select_boot_digest};
use yasvara_integrity_core::patch_override::global_patch_override;
use yasvara_integrity_core::pif::normalize_pif;
use yasvara_integrity_core::version::{
    infer_release_from_fingerprint_or_platform, infer_version_from_build_id,
};

fn jstr(env: &mut JNIEnv, s: &JString) -> String {
    if s.is_null() {
        return String::new();
    }
    env.get_string(s).map(Into::into).unwrap_or_default()
}

fn jbytes(env: &JNIEnv, arr: &JByteArray) -> Vec<u8> {
    if arr.is_null() {
        return Vec::new();
    }
    env.convert_byte_array(arr).unwrap_or_default()
}

fn to_jstr(env: &JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|j| j.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn to_jbytes(env: &JNIEnv, data: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(data)
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn to_string_array(env: &mut JNIEnv, items: &[String]) -> jobjectArray {
    let Ok(arr) = env.new_object_array(items.len() as i32, "java/lang/String", JObject::null())
    else {
        return std::ptr::null_mut();
    };
    for (i, item) in items.iter().enumerate() {
        let Ok(s) = env.new_string(item) else {
            return std::ptr::null_mut();
        };
        if env.set_object_array_element(&arr, i as i32, s).is_err() {
            return std::ptr::null_mut();
        }
    }
    arr.into_raw()
}

/// Validates and parses a raw XML or Base64(XML) keybox using the EXACT same BoringSSL +
/// x509_cert + CBOR parser that `keystore2` uses at runtime.
///
/// Returns a JSON object:
/// `{"valid":bool,"error":int,"normalizedXml":str,"publicChainXml":str,"rkpManufacturer":str,"stamp":str,"infoJson":str}`
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_YasvaraIntegrityNative_nativeInspectKeybox<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    raw_xml: JString<'l>,
    require_private_key: jboolean,
) -> jstring {
    let raw = jstr(&mut env, &raw_xml);
    let insp = inspect_keybox(&raw, require_private_key != JNI_FALSE);
    let valid = insp.error == KEYBOX_ERR_NONE;
    let out = format!(
        "{{\"valid\":{},\"error\":{},\"normalizedXml\":\"{}\",\"publicChainXml\":\"{}\",\"rkpManufacturer\":\"{}\",\"stamp\":\"{}\",\"infoJson\":\"{}\"}}",
        valid,
        insp.error,
        json_escape(&insp.normalized_xml),
        json_escape(&insp.public_chain_xml),
        json_escape(&insp.rkp_manufacturer),
        json_escape(&insp.stamp),
        json_escape(&insp.info_json),
    );
    to_jstr(&env, &out)
}

/// Normalizes a PIF JSON/prop string against `platform_release`, returning flat
/// `[key0, val0, key1, val1, ...]` pairs (all UTF-8 bounded `<= 91` bytes) or null on error.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_YasvaraIntegrityNative_nativeNormalizePif<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    raw_pif: JString<'l>,
    platform_release: JString<'l>,
) -> jobjectArray {
    let raw = jstr(&mut env, &raw_pif);
    let plat = jstr(&mut env, &platform_release);
    let Some(norm) = normalize_pif(&raw, if plat.is_empty() { "17" } else { &plat }) else {
        return std::ptr::null_mut();
    };
    let mut flat = Vec::with_capacity(norm.staging.len() * 2);
    for (k, v) in norm.staging {
        flat.push(k.to_string());
        flat.push(v);
    }
    to_string_array(&mut env, &flat)
}

/// Extracts the validated global `"*"` patch override date (`YYYY-MM-DD` / `YYYY-MM`), or `""`.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_YasvaraIntegrityNative_nativeGlobalPatchOverride<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    raw_json: JString<'l>,
) -> jstring {
    let raw = jstr(&mut env, &raw_json);
    let date = global_patch_override(&raw).unwrap_or_default();
    to_jstr(&env, &date)
}

/// Validates a hardware attestation certificate chain DER array + challenge and returns the
/// verified 32/64-byte `verifiedBootHash`, or null if invalid.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_YasvaraIntegrityNative_nativeExtractHardwareBootHash<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    chain_der: JObjectArray<'l>,
    expected_challenge: JByteArray<'l>,
) -> jbyteArray {
    if chain_der.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(len) = env.get_array_length(&chain_der) else {
        return std::ptr::null_mut();
    };
    if !(2..=16).contains(&len) {
        return std::ptr::null_mut();
    }
    let mut certs = Vec::with_capacity(len as usize);
    for i in 0..len {
        let Ok(obj) = env.get_object_array_element(&chain_der, i) else {
            return std::ptr::null_mut();
        };
        let arr = JByteArray::from(obj);
        let bytes = jbytes(&env, &arr);
        if bytes.is_empty() {
            return std::ptr::null_mut();
        }
        certs.push(bytes);
    }
    let challenge = jbytes(&env, &expected_challenge);
    match extract_hardware_boot_hash(&certs, &challenge) {
        Some(hash) => to_jbytes(&env, &hash),
        None => std::ptr::null_mut(),
    }
}

/// Selects canonical per-boot digest from bootloader property and/or hardware-attested hash.
/// Returns:
/// - `[digest, source]` when valid and consistent
/// - `["CONFLICT"]` when both are valid and disagree (caller must abort publishing)
/// - `null` when neither is available yet
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_YasvaraIntegrityNative_nativeSelectBootDigest<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    bootloader_raw: JString<'l>,
    attested_hash: JByteArray<'l>,
) -> jobjectArray {
    let bl = jstr(&mut env, &bootloader_raw);
    let att = jbytes(&env, &attested_hash);
    let bl_opt = (!bl.is_empty()).then_some(bl.as_str());
    let att_opt = (!att.is_empty()).then_some(att.as_slice());

    if let Some((digest, source)) = select_boot_digest(bl_opt, att_opt) {
        return to_string_array(&mut env, &[digest, source.to_string()]);
    }
    if bl_opt.and_then(normalize_boot_digest).is_some()
        && att_opt.and_then(encode_boot_digest).is_some()
    {
        return to_string_array(&mut env, &["CONFLICT".to_string()]);
    }
    std::ptr::null_mut()
}

/// Exposes Rust's single-source Build-ID -> KeyMint OS version inference (or -1 if unknown).
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_YasvaraIntegrityNative_nativeInferVersionFromBuildId<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    build_id: JString<'l>,
) -> jint {
    let id = jstr(&mut env, &build_id);
    infer_version_from_build_id(&id).map(|v| v as jint).unwrap_or(-1)
}

/// Exposes Rust's single-source codename/Canary major release inference (or `""` if unknown).
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_YasvaraIntegrityNative_nativeInferRelease<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    fp_release: JString<'l>,
    build_id: JString<'l>,
    platform_release: JString<'l>,
) -> jstring {
    let fp_rel = jstr(&mut env, &fp_release);
    let id = jstr(&mut env, &build_id);
    let plat = jstr(&mut env, &platform_release);
    let out = infer_release_from_fingerprint_or_platform(
        &fp_rel,
        (!id.is_empty()).then_some(id.as_str()),
        (!plat.is_empty()).then_some(plat.as_str()),
    )
    .map(|m| m.to_string())
    .unwrap_or_default();
    to_jstr(&env, &out)
}
