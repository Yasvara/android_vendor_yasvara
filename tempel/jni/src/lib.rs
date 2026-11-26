// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Thin, panic-safe JNI bridge for `com.android.server.yasvara.tempel.TempelNative`.
//! Loaded once inside `system_server`; zero threads, zero background allocations.

use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobjectArray, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempel::apdu::{encode_ndef_text, encode_ndef_uri, encode_ndef_vcard, encode_ndef_wifi, ApduRule};
use tempel::nci::{
    encode_mfc_verify_info, encode_mfc_verify_keys_into, ListenBConfig, ListenFConfig,
    MFC_VERIFY_MAX_PAYLOAD,
};
use tempel::tag::{
    build_felica_read_block, build_felica_write_block, build_gen3_write_block0,
    build_gen3_write_uid7, build_gen4_get_config, build_gen4_read_block, build_gen4_set_config,
    build_gen4_write_block, build_mfc_block0, build_nfcv_read_block, build_nfcv_write_block,
    build_ntag_ndef_pages, build_ntag_write_page, classify_tag, decode_emoney, export_flipper_nfc,
    export_mct, parse_flipper_nfc, parse_mct, parse_raw_bin, validate_mfc_access_bits, EMoneyIssuer,
    Gen4Mode, NtagVariant, ParsedCardDump, DEFAULT_MFC_KEYS,
};
use tempel::vault::{Profile, ProfileKind, RevertPolicy, SecurityGate, Vault};
use tempel::{hex_decode, hex_encode};

static VAULT: OnceLock<Mutex<Vault>> = OnceLock::new();

fn vault() -> MutexGuard<'static, Vault> {
    VAULT
        .get_or_init(|| Mutex::new(Vault::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

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

fn to_jbytes(env: &JNIEnv, data: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(data)
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn to_jstr(env: &JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|j| j.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn to_jbool(b: bool) -> jboolean {
    if b { JNI_TRUE } else { JNI_FALSE }
}

fn to_string_array(env: &mut JNIEnv, items: &[String]) -> jobjectArray {
    let Ok(arr) = env.new_object_array(items.len() as i32, "java/lang/String", JObject::null()) else {
        return std::ptr::null_mut();
    };
    for (i, item) in items.iter().enumerate() {
        let Ok(s) = env.new_string(item) else { return std::ptr::null_mut() };
        if env.set_object_array_element(&arr, i as i32, s).is_err() {
            return std::ptr::null_mut();
        }
    }
    arr.into_raw()
}

// ---------------------------------------------------------------------------
// Vault persistence & profile CRUD
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeLoadVault<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    blob: JByteArray<'l>,
) -> jboolean {
    let data = jbytes(&env, &blob);
    to_jbool(vault().decode_binary(&data))
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeSaveVault<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jbyteArray {
    let blob = vault().encode_binary();
    to_jbytes(&env, &blob)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeDump<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jstring {
    let s = vault().dump_summary();
    to_jstr(&env, &s)
}

/// Tab-delimited profile rows for lean Binder IPC:
/// `id\tkind\tname\tcolor\ticon\tgate\trevertType\trevertSec\tlock\twalletPkg\tuidHex\tatqaHex\tsakHex\tscHex\tpmmHex\tpayloadLen`
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeListProfiles<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jobjectArray {
    let rows: Vec<String> = {
        let v = vault();
        v.profiles
            .iter()
            .map(|p| {
                let (rt, rs) = match p.revert {
                    RevertPolicy::Sticky => (0u8, 0u16),
                    RevertPolicy::AfterTap => (1, 0),
                    RevertPolicy::TimeoutSec(s) => (2, s),
                };
                format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:02X}\t{}\t{}\t{}",
                    p.id,
                    p.kind as u8,
                    p.name.replace('\t', " ").replace('\n', " "),
                    p.color_argb,
                    p.icon_id,
                    p.gate as u8,
                    rt,
                    rs,
                    if p.show_on_lockscreen { 1 } else { 0 },
                    p.wallet_pkg.replace('\t', ""),
                    hex_encode(&p.uid),
                    hex_encode(&p.atqa),
                    p.sak,
                    hex_encode(&p.system_code),
                    hex_encode(&p.pmm),
                    p.payload.len(),
                )
            })
            .collect()
    };
    to_string_array(&mut env, &rows)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeUpsertProfile<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    id: jint,
    kind: jint,
    name: JString<'l>,
    color_argb: jint,
    icon_id: jint,
    gate: jint,
    revert_type: jint,
    revert_sec: jint,
    show_lock: jboolean,
    wallet_pkg: JString<'l>,
    uid: JByteArray<'l>,
    atqa: JByteArray<'l>,
    sak: jint,
    rats_tb1: jint,
    hist: JByteArray<'l>,
    app_data: JByteArray<'l>,
    sys_code: JByteArray<'l>,
    pmm: JByteArray<'l>,
    payload: JByteArray<'l>,
) -> jint {
    let Some(k) = ProfileKind::from_u8(kind as u8) else { return 0 };
    let g = SecurityGate::from_u8(gate as u8).unwrap_or_default();
    let revert = match revert_type {
        0 => RevertPolicy::Sticky,
        1 => RevertPolicy::AfterTap,
        _ => RevertPolicy::TimeoutSec((revert_sec.clamp(5, 3600)) as u16),
    };
    let atqa_v = jbytes(&env, &atqa);
    let mut atqa_arr = [0x04u8, 0x00u8];
    if atqa_v.len() >= 2 {
        atqa_arr = [atqa_v[0], atqa_v[1]];
    }
    let app_v = jbytes(&env, &app_data);
    let mut app_arr = [0u8; 4];
    if app_v.len() >= 4 {
        app_arr.copy_from_slice(&app_v[..4]);
    }
    let sc_v = jbytes(&env, &sys_code);
    let mut sc_arr = [0u8; 2];
    if sc_v.len() >= 2 {
        sc_arr.copy_from_slice(&sc_v[..2]);
    }
    let pmm_v = jbytes(&env, &pmm);
    let mut pmm_arr = [0u8; 8];
    if pmm_v.len() >= 8 {
        pmm_arr.copy_from_slice(&pmm_v[..8]);
    }
    let p = Profile {
        id: id.max(0) as u32,
        kind: k,
        name: jstr(&mut env, &name),
        color_argb: color_argb as u32,
        icon_id: icon_id as u8,
        gate: g,
        revert,
        show_on_lockscreen: show_lock != JNI_FALSE,
        wallet_pkg: jstr(&mut env, &wallet_pkg),
        uid: jbytes(&env, &uid),
        atqa: atqa_arr,
        sak: sak as u8,
        rats_tb1: rats_tb1 as u8,
        hist_bytes: jbytes(&env, &hist),
        app_data: app_arr,
        system_code: sc_arr,
        pmm: pmm_arr,
        payload: jbytes(&env, &payload),
        apdu_rules: Vec::new(),
    };
    vault().upsert(p) as jint
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeSetApduRules<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    profile_id: jint,
    rules_text: JString<'l>,
) -> jboolean {
    let text = jstr(&mut env, &rules_text);
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((req_h, rsp_h)) = line.split_once("->") else { continue };
        if let (Some(req), Some(rsp)) = (hex_decode(req_h), hex_decode(rsp_h)) {
            if !req.is_empty() && rsp.len() >= 2 {
                rules.push(ApduRule { match_prefix: req, response: rsp });
            }
        }
    }
    let mut v = vault();
    if let Some(p) = v.profiles.iter_mut().find(|p| p.id == profile_id as u32) {
        p.apdu_rules = rules;
        return JNI_TRUE;
    }
    JNI_FALSE
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeRemoveProfile(
    _: JNIEnv,
    _: JClass,
    id: jint,
) -> jboolean {
    to_jbool(vault().remove(id.max(0) as u32))
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeSetDefaultPayment(
    _: JNIEnv,
    _: JClass,
    id: jint,
) {
    vault().default_payment_id = id.max(0) as u32;
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeGetActiveId(
    _: JNIEnv,
    _: JClass,
) -> jint {
    vault().active_id as jint
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeGetDefaultPaymentId(
    _: JNIEnv,
    _: JClass,
) -> jint {
    vault().default_payment_id as jint
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeGetPayload<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    id: jint,
) -> jbyteArray {
    let v = vault();
    match v.get(id.max(0) as u32) {
        Some(p) => to_jbytes(&env, &p.payload),
        None => std::ptr::null_mut(),
    }
}

/// Arms `id` (or 0 to disarm to default payment). Returns revert delay ms, or -1 if unknown id.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeActivate(
    _: JNIEnv,
    _: JClass,
    id: jint,
    now_ms: jlong,
) -> jlong {
    match vault().activate(id.max(0) as u32, now_ms.max(0) as u64) {
        Some(delay) => delay as jlong,
        None => -1,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeCheckRevert(
    _: JNIEnv,
    _: JClass,
    now_ms: jlong,
) -> jboolean {
    to_jbool(vault().check_revert(now_ms.max(0) as u64))
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeOnTapCompleted(
    _: JNIEnv,
    _: JClass,
) -> jboolean {
    to_jbool(vault().on_tap_completed())
}

// ---------------------------------------------------------------------------
// NCI command builders for active profile (Listen-A / Listen-B / Listen-F / 2F 45)
// ---------------------------------------------------------------------------

/// Returns packed Listen-A params for active profile:
/// `[sdd, plat, sak, rats, uidLen, uid..., histLen, hist...]` or null if invalid.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildActiveListenA<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jbyteArray {
    let v = vault();
    let Some(cfg) = v.active().and_then(|p| p.listen_a_config()) else {
        return std::ptr::null_mut();
    };
    let mut out = Vec::with_capacity(6 + cfg.uid_len as usize + cfg.hist_len as usize);
    out.push(cfg.bit_frame_sdd);
    out.push(cfg.platform_config);
    out.push(cfg.sel_info);
    out.push(cfg.rats_tb1);
    out.push(cfg.uid_len);
    out.extend_from_slice(cfg.uid_slice());
    out.push(cfg.hist_len);
    out.extend_from_slice(cfg.hist_slice());
    to_jbytes(&env, &out)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildActiveListenB<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jbyteArray {
    let v = vault();
    let Some(cfg) = v.active().and_then(|p| p.listen_b_config()) else {
        return std::ptr::null_mut();
    };
    let mut buf = [0u8; 64];
    match cfg.encode_set_config_into(&mut buf) {
        Ok(n) => to_jbytes(&env, &buf[..n]),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildResetListenB<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jbyteArray {
    let mut buf = [0u8; 32];
    match ListenBConfig::encode_reset_config_into(&mut buf) {
        Ok(n) => to_jbytes(&env, &buf[..n]),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildActiveListenF<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jbyteArray {
    let v = vault();
    let Some(cfg) = v.active().and_then(|p| p.listen_f_config()) else {
        return std::ptr::null_mut();
    };
    let mut buf = [0u8; 32];
    match cfg.encode_set_config_into(&mut buf) {
        Ok(n) => to_jbytes(&env, &buf[..n]),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildResetListenF<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jbyteArray {
    let mut buf = [0u8; 16];
    match ListenFConfig::encode_reset_config_into(&mut buf) {
        Ok(n) => to_jbytes(&env, &buf[..n]),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildMfc2f45Info<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    sector: jint,
    is_key_b: jboolean,
) -> jbyteArray {
    let b = encode_mfc_verify_info(sector as u8, is_key_b != JNI_FALSE);
    to_jbytes(&env, &b)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildMfc2f45DefaultKeys<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jbyteArray {
    let mut buf = [0u8; MFC_VERIFY_MAX_PAYLOAD];
    match encode_mfc_verify_keys_into(&DEFAULT_MFC_KEYS, &mut buf) {
        Ok(n) => to_jbytes(&env, &buf[..n]),
        Err(_) => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Zero-alloc HCE APDU hot path & NDEF builders
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeProcessApdu<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    apdu: JByteArray<'l>,
) -> jbyteArray {
    let req = jbytes(&env, &apdu);
    let mut out = [0u8; 260];
    let n = vault().process_apdu_into(&req, &mut out);
    to_jbytes(&env, &out[..n])
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildNdef<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    kind: jint,
    a: JString<'l>,
    b: JString<'l>,
    c: JString<'l>,
) -> jbyteArray {
    let sa = jstr(&mut env, &a);
    let sb = jstr(&mut env, &b);
    let sc = jstr(&mut env, &c);
    let bytes = match kind {
        0 => encode_ndef_uri(&sa),
        1 => encode_ndef_text(if sa.is_empty() { "en" } else { &sa }, &sb),
        2 => encode_ndef_wifi(&sa, &sb, sc != "open"),
        3 => encode_ndef_vcard(&sa, &sb, &sc),
        _ => Vec::new(),
    };
    to_jbytes(&env, &bytes)
}

// ---------------------------------------------------------------------------
// Classifier, dump import/export, e-Money decoder & physical card writer frames
// ---------------------------------------------------------------------------

/// Returns `preset\tverdict\tcanEmulate\tcanWrite\tencSectors\ttotalSectors`.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeClassifyTag<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    tech_mask: jint,
    uid_len: jint,
    atqa0: jint,
    atqa1: jint,
    sak: jint,
    has_ndef: jboolean,
    is_emoney: jboolean,
    total_sectors: jint,
    readable_sectors: jint,
) -> jstring {
    let a = classify_tag(
        tech_mask as u32,
        uid_len.max(0) as usize,
        [atqa0 as u8, atqa1 as u8],
        sak as u8,
        has_ndef != JNI_FALSE,
        is_emoney != JNI_FALSE,
        total_sectors.max(0) as u8,
        readable_sectors.max(0) as u8,
    );
    let s = format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        a.preset as u8,
        a.verdict as u8,
        if a.can_emulate_on_phone { 1 } else { 0 },
        if a.can_write_physical { 1 } else { 0 },
        a.encrypted_sectors,
        a.total_sectors,
    );
    to_jstr(&env, &s)
}

/// Parses `.mct` (format=0), Flipper `.nfc` (format=1), or raw `.bin` (format=2).
/// Returns `tech\tuidHex\tatqaHex\tsakHex\tscHex\tpmmHex\tmfcBlocksHex\tntagPagesHex` or null.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeImportDump<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    format: jint,
    text: JString<'l>,
    bin: JByteArray<'l>,
) -> jstring {
    let parsed: Result<ParsedCardDump, _> = match format {
        0 => parse_mct(&jstr(&mut env, &text)),
        1 => parse_flipper_nfc(&jstr(&mut env, &text)),
        2 => parse_raw_bin(&jbytes(&env, &bin)),
        _ => return std::ptr::null_mut(),
    };
    let Ok(d) = parsed else { return std::ptr::null_mut() };
    let mut mfc_raw = Vec::with_capacity(d.mfc_blocks.len() * 16);
    for b in &d.mfc_blocks {
        mfc_raw.extend_from_slice(b);
    }
    let mut ntag_raw = Vec::with_capacity(d.ntag_pages.len() * 4);
    for p in &d.ntag_pages {
        ntag_raw.extend_from_slice(p);
    }
    let s = format!(
        "{}\t{}\t{}\t{:02X}\t{}\t{}\t{}\t{}",
        d.tech,
        hex_encode(&d.uid),
        hex_encode(&d.atqa),
        d.sak,
        hex_encode(&d.system_code),
        hex_encode(&d.pmm),
        hex_encode(&mfc_raw),
        hex_encode(&ntag_raw),
    );
    to_jstr(&env, &s)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeExportProfile<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    profile_id: jint,
    format: jint, // 0=MCT, 1=Flipper .nfc
) -> jstring {
    let v = vault();
    let Some(p) = v.get(profile_id.max(0) as u32) else {
        return std::ptr::null_mut();
    };
    let mut mfc_blocks = Vec::new();
    let mut ntag_pages = Vec::new();
    if matches!(p.payload.len(), 1024 | 4096) {
        for c in p.payload.chunks_exact(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(c);
            mfc_blocks.push(b);
        }
    } else if matches!(p.payload.len(), 64 | 180 | 192 | 540 | 924) {
        for c in p.payload.chunks_exact(4) {
            ntag_pages.push([c[0], c[1], c[2], c[3]]);
        }
    }
    let out = if format == 0 && !mfc_blocks.is_empty() {
        export_mct(&mfc_blocks)
    } else {
        let tech = match p.kind {
            ProfileKind::UidTypeB => 2,
            ProfileKind::FelicaHcef => 3,
            _ => 1,
        };
        export_flipper_nfc(&ParsedCardDump {
            tech,
            uid: p.uid.clone(),
            atqa: p.atqa,
            sak: p.sak,
            ats: p.hist_bytes.clone(),
            system_code: p.system_code,
            pmm: p.pmm,
            mfc_blocks,
            ntag_pages,
        })
    };
    to_jstr(&env, &out)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeDecodeEMoney<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    issuer_code: jint,
    info_resp: JByteArray<'l>,
    bal_resp: JByteArray<'l>,
) -> jstring {
    let issuer = match issuer_code {
        1 => EMoneyIssuer::MandiriEMoney,
        2 => EMoneyIssuer::BcaFlazz,
        3 => EMoneyIssuer::BniTapCash,
        4 => EMoneyIssuer::BriBrizzi,
        _ => return std::ptr::null_mut(),
    };
    let info = jbytes(&env, &info_resp);
    let bal = jbytes(&env, &bal_resp);
    let Some(decoded) = decode_emoney(issuer, &info, &bal) else {
        return std::ptr::null_mut();
    };
    to_jstr(&env, &format!("{}\t{}\t{}", decoded.issuer as u8, decoded.balance_idr, decoded.card_number))
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildMfcBlock0<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    uid: JByteArray<'l>,
    sak: jint,
    atqa0: jint,
    atqa1: jint,
) -> jbyteArray {
    let u = jbytes(&env, &uid);
    match build_mfc_block0(&u, sak as u8, [atqa0 as u8, atqa1 as u8], None) {
        Ok(b0) => to_jbytes(&env, &b0),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeValidateMfcAccessBits(
    _: JNIEnv,
    _: JClass,
    b6: jint,
    b7: jint,
    b8: jint,
) -> jboolean {
    to_jbool(validate_mfc_access_bits([b6 as u8, b7 as u8, b8 as u8]))
}

/// Multi-tech physical tag writer frame builder:
/// - op 0: Gen3 write Block 0 (`data` = 16B Block 0)
/// - op 1: Gen3 write 7B UID (`data` = 7B UID)
/// - op 2: Gen4 Get Config (`arg1` = 4B pwd packed BE)
/// - op 3: Gen4 Read Block (`arg1` = pwd, `arg2` = block)
/// - op 4: Gen4 Write Block (`arg1` = pwd, `arg2` = block, `data` = 16B; trailer access-bits validated!)
/// - op 5: Gen4 Set Config (`arg1` = pwd, `arg2` = mode | (uidLen<<8) | (sak<<16), `data` = [atqa0, atqa1, gen2, shadow])
/// - op 6: NTAG Write Page (`arg1` = variant, `arg2` = page | (allowProtected<<16), `data` = 4B)
/// - op 7: NFC-V Read Block (`arg2` = block, `data` = 8B UID)
/// - op 8: NFC-V Write Block (`arg2` = block, `data` = 8B UID + 4/8B block data)
/// - op 9: FeliCa Lite-S Read Block (`arg2` = block, `data` = 8B IDm)
/// - op 10: FeliCa Lite-S Write Block (`arg2` = block, `data` = 8B IDm + 16B block data)
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildWriteFrame<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    op: jint,
    arg1: jint,
    arg2: jint,
    data: JByteArray<'l>,
) -> jbyteArray {
    let d = jbytes(&env, &data);
    let pwd = (arg1 as u32).to_be_bytes();
    let res: Option<Vec<u8>> = match op {
        0 if d.len() == 16 => {
            let mut b0 = [0u8; 16];
            b0.copy_from_slice(&d);
            Some(build_gen3_write_block0(&b0).to_vec())
        }
        1 if d.len() == 7 => {
            let mut u7 = [0u8; 7];
            u7.copy_from_slice(&d);
            Some(build_gen3_write_uid7(&u7).to_vec())
        }
        2 => Some(build_gen4_get_config(pwd).to_vec()),
        3 => Some(build_gen4_read_block(pwd, arg2 as u8).to_vec()),
        4 if d.len() == 16 => {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&d);
            build_gen4_write_block(pwd, arg2 as u8, &blk, true).ok().map(|f| f.to_vec())
        }
        5 if d.len() >= 4 => {
            let mode = match (arg2 & 0xFF) as u8 {
                0 => Gen4Mode::MifareClassic1K,
                1 => Gen4Mode::MifareClassic4K,
                2 => Gen4Mode::Ultralight,
                3 => Gen4Mode::Ntag213,
                4 => Gen4Mode::Ntag215,
                5 => Gen4Mode::Ntag216,
                _ => return std::ptr::null_mut(),
            };
            let uid_len = ((arg2 >> 8) & 0xFF) as u8;
            let sak = ((arg2 >> 16) & 0xFF) as u8;
            build_gen4_set_config(pwd, mode, uid_len, [d[0], d[1]], sak, d[2] != 0, d[3])
                .ok()
                .map(|f| f.to_vec())
        }
        6 if d.len() == 4 => {
            let var = match arg1 {
                0 => NtagVariant::Ultralight,
                1 => NtagVariant::UltralightC,
                2 => NtagVariant::Ntag213,
                3 => NtagVariant::Ntag215,
                4 => NtagVariant::Ntag216,
                _ => return std::ptr::null_mut(),
            };
            let page = (arg2 & 0xFF) as u8;
            let allow_prot = ((arg2 >> 16) & 1) != 0;
            build_ntag_write_page(var, page, [d[0], d[1], d[2], d[3]], allow_prot)
                .ok()
                .map(|f| f.to_vec())
        }
        7 if d.len() == 8 => {
            let mut u8a = [0u8; 8];
            u8a.copy_from_slice(&d);
            Some(build_nfcv_read_block(u8a, arg2 as u8).to_vec())
        }
        8 if d.len() >= 12 => {
            let mut u8a = [0u8; 8];
            u8a.copy_from_slice(&d[0..8]);
            build_nfcv_write_block(u8a, arg2 as u8, &d[8..]).ok()
        }
        9 if d.len() == 8 => {
            let mut idm = [0u8; 8];
            idm.copy_from_slice(&d);
            Some(build_felica_read_block(idm, arg2 as u8).to_vec())
        }
        10 if d.len() == 24 => {
            let mut idm = [0u8; 8];
            let mut blk = [0u8; 16];
            idm.copy_from_slice(&d[0..8]);
            blk.copy_from_slice(&d[8..24]);
            Some(build_felica_write_block(idm, arg2 as u8, &blk).to_vec())
        }
        _ => None,
    };
    match res {
        Some(f) => to_jbytes(&env, &f),
        None => std::ptr::null_mut(),
    }
}

/// Packs NDEF TLV into NTAG 4-byte page write frames (`[page, d0, d1, d2, d3] * N`).
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_tempel_TempelNative_nativeBuildNtagNdefPages<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    variant: jint,
    ndef_msg: JByteArray<'l>,
) -> jbyteArray {
    let var = match variant {
        0 => NtagVariant::Ultralight,
        1 => NtagVariant::UltralightC,
        2 => NtagVariant::Ntag213,
        3 => NtagVariant::Ntag215,
        4 => NtagVariant::Ntag216,
        _ => return std::ptr::null_mut(),
    };
    let msg = jbytes(&env, &ndef_msg);
    let Ok(pages) = build_ntag_ndef_pages(var, &msg) else {
        return std::ptr::null_mut();
    };
    let mut flat = Vec::with_capacity(pages.len() * 5);
    for (pg, d) in pages {
        flat.push(pg);
        flat.extend_from_slice(&d);
    }
    to_jbytes(&env, &flat)
}
