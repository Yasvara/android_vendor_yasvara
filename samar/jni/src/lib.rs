// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! JNI surface of the Samar policy for `com.android.server.yasvara.samar.SamarNative`.
//! One policy per process; every call takes its lock briefly and never panics across the FFI.

use jni::objects::{JClass, JDoubleArray, JFloatArray, JIntArray, JObject, JString};
use jni::sys::{jboolean, jdouble, jdoubleArray, jfloat, jint, jlong, jobjectArray, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use samar::geo;
use samar::motion::{Source, Speed};
use samar::policy::{Mode, Policy, Target};
use std::sync::{Mutex, MutexGuard, OnceLock};

static POLICY: OnceLock<Mutex<Policy>> = OnceLock::new();

fn policy() -> MutexGuard<'static, Policy> {
    POLICY
        .get_or_init(|| Mutex::new(Policy::new(0x5A_4D_41_52)))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn string(env: &mut JNIEnv, s: &JString) -> String {
    if s.is_null() {
        return String::new();
    }
    env.get_string(s).map(Into::into).unwrap_or_default()
}

fn jbool(b: bool) -> jboolean {
    if b {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

fn new_string(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
}

fn string_array(env: &mut JNIEnv, items: &[String]) -> jobjectArray {
    let Ok(array) = env.new_object_array(items.len() as i32, "java/lang/String", JObject::null()) else {
        return std::ptr::null_mut();
    };
    for (i, item) in items.iter().enumerate() {
        let Ok(s) = env.new_string(item) else { return std::ptr::null_mut() };
        if env.set_object_array_element(&array, i as i32, s).is_err() {
            return std::ptr::null_mut();
        }
    }
    array.into_raw()
}

fn double_array(env: &mut JNIEnv, values: &[f64]) -> jdoubleArray {
    match env.new_double_array(values.len() as i32) {
        Ok(a) if env.set_double_array_region(&a, 0, values).is_ok() => a.into_raw(),
        _ => std::ptr::null_mut(),
    }
}

fn app_id(id: jint) -> u32 {
    id.max(0) as u32
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeDecode<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    text: JString<'l>,
) -> jboolean {
    let text = string(&mut env, &text);
    jbool(policy().decode(&text))
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeEncode<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jstring {
    let text = policy().encode();
    new_string(&mut env, &text)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeDump<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jstring {
    let text = policy().dump();
    new_string(&mut env, &text)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeBind<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    pkg: JString<'l>,
    id: jint,
) {
    let pkg = string(&mut env, &pkg);
    if !pkg.is_empty() {
        policy().bind(&pkg, app_id(id));
    }
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeUnbind<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    pkg: JString<'l>,
) {
    let pkg = string(&mut env, &pkg);
    policy().unbind(&pkg);
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeSetExempt(
    _: JNIEnv,
    _: JClass,
    id: jint,
    exempt: jboolean,
) {
    policy().set_exempt(app_id(id), exempt != JNI_FALSE);
}

/// 0 real, 1 global, 2 the app's own profile.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeResolve(
    _: JNIEnv,
    _: JClass,
    id: jint,
    emergency: jboolean,
) -> jint {
    match policy().resolve(app_id(id), emergency != JNI_FALSE) {
        Target::Real => 0,
        Target::Global => 1,
        Target::App(_) => 2,
    }
}

/// Fills `out` with lat, lng, altitude, accuracy, vertical accuracy, speed, speed accuracy,
/// bearing, bearing accuracy; absent fields are NaN. False when the app sees the real location.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeFix<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    id: jint,
    emergency: jboolean,
    source: jint,
    out: JDoubleArray<'l>,
) -> jboolean {
    let Some(f) = policy().fix(app_id(id), emergency != JNI_FALSE, Source::from_u8(source as u8)) else {
        return JNI_FALSE;
    };
    let o = |v: Option<f32>| v.map(f64::from).unwrap_or(f64::NAN);
    let values = [
        f.lat,
        f.lng,
        f.altitude.unwrap_or(f64::NAN),
        f.accuracy as f64,
        o(f.vertical_accuracy),
        o(f.speed),
        o(f.speed_accuracy),
        o(f.bearing),
        o(f.bearing_accuracy),
    ];
    jbool(env.set_double_array_region(&out, 0, &values).is_ok())
}

/// Writes up to ids.length satellites: ids[i] = constellation << 24 | used << 16 | svid and four
/// floats each in `values` (cn0, elevation, azimuth, carrier Hz). Returns the count, or -1 when
/// the app sees the real sky.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeSky<'l>(
    env: JNIEnv<'l>,
    _: JClass<'l>,
    id: jint,
    emergency: jboolean,
    now_ns: jlong,
    ids: JIntArray<'l>,
    values: JFloatArray<'l>,
) -> jint {
    let Some(sats) = policy().sky(app_id(id), emergency != JNI_FALSE, now_ns) else {
        return -1;
    };
    let cap = env.get_array_length(&ids).unwrap_or(0).max(0) as usize;
    let cap = cap.min(env.get_array_length(&values).unwrap_or(0).max(0) as usize / 4);
    let n = sats.len().min(cap);
    let mut id_buf = Vec::with_capacity(n);
    let mut value_buf = Vec::with_capacity(n * 4);
    for s in &sats[..n] {
        id_buf.push(((s.constellation as i32) << 24) | ((s.used_in_fix as i32) << 16) | s.svid as i32);
        value_buf.extend_from_slice(&[s.cn0, s.elevation, s.azimuth, s.carrier_hz]);
    }
    if env.set_int_array_region(&ids, 0, &id_buf).is_err() || env.set_float_array_region(&values, 0, &value_buf).is_err() {
        return -1;
    }
    n as jint
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeLayers(
    _: JNIEnv,
    _: JClass,
    id: jint,
) -> jint {
    policy().layers(app_id(id)) as jint
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeStep(
    _: JNIEnv,
    _: JClass,
    now_ns: jlong,
) {
    policy().step(now_ns);
}

/// Bit 0 any override active, 1 something moving, 2 any layer active, 3 global switch on.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeState(
    _: JNIEnv,
    _: JClass,
) -> jint {
    let p = policy();
    (p.active() as jint) | (p.moving() as jint) << 1 | (p.layers_active() as jint) << 2 | (p.global_on() as jint) << 3
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeSetGlobalOn(
    _: JNIEnv,
    _: JClass,
    on: jboolean,
) {
    policy().set_global_on(on != JNI_FALSE);
}

/// Returns the implied jump speed in m/s, or NaN for an invalid point.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativePlace<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    target: JString<'l>,
    lat: jdouble,
    lng: jdouble,
    now_ns: jlong,
) -> jdouble {
    let target = string(&mut env, &target);
    policy().place(&target, lat, lng, now_ns).unwrap_or(f64::NAN)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeSetAltitude<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    target: JString<'l>,
    altitude: jdouble,
) {
    let target = string(&mut env, &target);
    policy().set_altitude(&target, altitude);
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeSetJoystick<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    target: JString<'l>,
    x: jfloat,
    y: jfloat,
) {
    let target = string(&mut env, &target);
    if x.is_finite() && y.is_finite() {
        policy().set_joystick(&target, x as f64, y as f64);
    }
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeSetSpeed<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    target: JString<'l>,
    preset: jint,
) {
    let target = string(&mut env, &target);
    policy().set_speed(&target, Speed::from_u8(preset as u8));
}

/// lat, lng, altitude, speed, heading, speed preset, has place (1/0); null for an unknown app.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativePosition<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    target: JString<'l>,
) -> jdoubleArray {
    let target = string(&mut env, &target);
    let Some(p) = policy().position(&target) else { return std::ptr::null_mut() };
    let values = [p.lat, p.lng, p.altitude, p.speed, p.heading, p.speed_preset as u8 as f64, p.has_place as u8 as f64];
    double_array(&mut env, &values)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeMode<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    pkg: JString<'l>,
) -> jint {
    let pkg = string(&mut env, &pkg);
    policy().mode(&pkg) as jint
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeSetMode<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    pkg: JString<'l>,
    mode: jint,
) {
    let pkg = string(&mut env, &pkg);
    policy().set_mode(&pkg, Mode::from_u8(mode as u8));
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeSetLayers<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    target: JString<'l>,
    mask: jint,
    value: jint,
) {
    let target = string(&mut env, &target);
    policy().set_layers(&target, mask as u32, value as u32);
}

/// mask << 32 | value of a target's layer override; global reports all bits as set in the mask.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeLayerOverride<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    target: JString<'l>,
) -> jlong {
    let target = string(&mut env, &target);
    let (mask, value) = policy().layer_override(&target);
    ((mask as jlong) << 32) | value as jlong
}

/// One entry per configured app: "package\tmode\tmask\tvalue".
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeConfiguredApps<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jobjectArray {
    let apps: Vec<String> = policy()
        .configured_apps()
        .into_iter()
        .map(|(pkg, mode, mask, value)| format!("{pkg}\t{}\t{mask}\t{value}", mode as u8))
        .collect();
    string_array(&mut env, &apps)
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeAddPlace<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    name: JString<'l>,
    lat: jdouble,
    lng: jdouble,
) -> jboolean {
    let name = string(&mut env, &name);
    jbool(policy().add_place(&name, lat, lng))
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeRemovePlace(
    _: JNIEnv,
    _: JClass,
    index: jint,
) -> jboolean {
    jbool(index >= 0 && policy().remove_place(index as usize))
}

#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativePlaceNames<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jobjectArray {
    let names: Vec<String> = policy().places().iter().map(|p| p.name.clone()).collect();
    string_array(&mut env, &names)
}

/// Saved place coordinates, lat/lng interleaved.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativePlaceCoords<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
) -> jdoubleArray {
    let coords: Vec<f64> = policy().places().iter().flat_map(|p| [p.lat, p.lng]).collect();
    double_array(&mut env, &coords)
}

/// [lat, lng] or null.
#[no_mangle]
pub extern "system" fn Java_com_android_server_yasvara_samar_SamarNative_nativeParse<'l>(
    mut env: JNIEnv<'l>,
    _: JClass<'l>,
    text: JString<'l>,
    ref_lat: jdouble,
    ref_lng: jdouble,
) -> jdoubleArray {
    let text = string(&mut env, &text);
    match geo::parse(&text, ref_lat, ref_lng) {
        Some((lat, lng)) => double_array(&mut env, &[lat, lng]),
        None => std::ptr::null_mut(),
    }
}
