// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Padat core crate (`std`-only, zero external crates —).

pub mod engine;
pub mod ioctl;
pub mod policy;
pub mod probe;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use engine::{JobProgress, RootPaths, RunControl};
use policy::{CompAlgo, CompProfile, Policy, Scopes, DEFAULT_POLICY_PATH};

static CANCEL_FLAG: AtomicBool = AtomicBool::new(false);
static PAUSED_FLAG: AtomicBool = AtomicBool::new(false);
static PROGRESS: JobProgress = JobProgress::new();

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new("{}").unwrap())
        .into_raw()
}

unsafe fn from_c_str(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

/// Frees a C string previously returned by any `padat_*` FFI function.
#[no_mangle]
pub unsafe extern "C" fn padat_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub extern "C" fn padat_status_json() -> *mut c_char {
    to_c_string(engine::status_json(
        PAUSED_FLAG.load(Ordering::Relaxed),
        &PROGRESS,
    ))
}

#[no_mangle]
pub extern "C" fn padat_get_policy_json() -> *mut c_char {
    let pol = Policy::load(Path::new(DEFAULT_POLICY_PATH));
    to_c_string(pol.to_json())
}

#[no_mangle]
pub unsafe extern "C" fn padat_set_policy_json(json: *const c_char) -> i32 {
    let s = from_c_str(json);
    match Policy::from_json(&s) {
        Ok(pol) => match pol.save_atomic(Path::new(DEFAULT_POLICY_PATH)) {
            Ok(()) => 0,
            Err(_) => -5, // EIO
        },
        Err(_) => -22, // EINVAL
    }
}

#[no_mangle]
pub extern "C" fn padat_set_paused(paused: bool) {
    PAUSED_FLAG.store(paused, Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn padat_cancel_job() {
    CANCEL_FLAG.store(true, Ordering::SeqCst);
}

fn scopes_from_mask(mask: u32) -> Scopes {
    Scopes {
        apk_lib: (mask & 0x01) != 0,
        art_oat: (mask & 0x02) != 0,
        external_data: (mask & 0x04) != 0,
        obb: (mask & 0x08) != 0,
        internal_files: (mask & 0x10) != 0,
    }
}

fn profile_from_ffi(algo: u8, level: u8, cluster_kb: u16) -> CompProfile {
    let a = match algo {
        1 => CompAlgo::Lz4Hc,
        2 => CompAlgo::Zstd,
        _ => CompAlgo::Lz4,
    };
    CompProfile {
        algo: a,
        level,
        cluster_kb,
    }
    .normalized()
}

#[no_mangle]
pub unsafe extern "C" fn padat_scan_package_json(
    pkg: *const c_char,
    algo: u8,
    level: u8,
    cluster_kb: u16,
    scope_mask: u32,
) -> *mut c_char {
    let pkg = from_c_str(pkg);
    let pol = Policy::load(Path::new(DEFAULT_POLICY_PATH));
    let prof = profile_from_ffi(algo, level, cluster_kb);
    let scopes = if scope_mask == 0 {
        Scopes::FULL_APP
    } else {
        scopes_from_mask(scope_mask)
    };
    let stats = engine::scan_package(&RootPaths::default(), &pkg, prof, scopes, &pol);
    to_c_string(stats.to_json())
}

#[no_mangle]
pub unsafe extern "C" fn padat_compress_package_json(
    pkg: *const c_char,
    algo: u8,
    level: u8,
    cluster_kb: u16,
    scope_mask: u32,
    allow_running: bool,
) -> *mut c_char {
    let pkg = from_c_str(pkg);
    if PROGRESS.busy.swap(true, Ordering::SeqCst) {
        return to_c_string("{\"error\":\"busy\"}".into());
    }
    CANCEL_FLAG.store(false, Ordering::SeqCst);
    PROGRESS.begin(&pkg, "compress");

    let pol = Policy::load(Path::new(DEFAULT_POLICY_PATH));
    let prof = profile_from_ffi(algo, level, cluster_kb);
    let scopes = if scope_mask == 0 {
        Scopes::TIER1_ONLY
    } else {
        scopes_from_mask(scope_mask)
    };
    let ctl = RunControl {
        cancel: &CANCEL_FLAG,
        paused: &PAUSED_FLAG,
        allow_running,
        thermal_pause_mc: pol.thermal_pause_mc,
        progress: Some(&PROGRESS),
    };
    let rep = engine::compress_package(&RootPaths::default(), &pkg, prof, scopes, &pol, &ctl);

    PROGRESS.end();
    to_c_string(rep.to_json())
}

#[no_mangle]
pub unsafe extern "C" fn padat_sync_package_json(
    pkg: *const c_char,
    algo: u8,
    level: u8,
    cluster_kb: u16,
    scope_mask: u32,
) -> *mut c_char {
    let pkg = from_c_str(pkg);
    if PROGRESS.busy.swap(true, Ordering::SeqCst) {
        return to_c_string("{\"error\":\"busy\"}".into());
    }
    CANCEL_FLAG.store(false, Ordering::SeqCst);
    PROGRESS.begin(&pkg, "sync");

    let pol = Policy::load(Path::new(DEFAULT_POLICY_PATH));
    let prof = profile_from_ffi(algo, level, cluster_kb);
    let scopes = if scope_mask == 0 {
        Scopes::FULL_APP
    } else {
        scopes_from_mask(scope_mask)
    };
    let ctl = RunControl {
        cancel: &CANCEL_FLAG,
        paused: &PAUSED_FLAG,
        allow_running: true,
        thermal_pause_mc: pol.thermal_pause_mc,
        progress: Some(&PROGRESS),
    };
    let rep = engine::sync_package_incremental(&RootPaths::default(), &pkg, prof, scopes, &pol, &ctl);

    PROGRESS.end();
    to_c_string(rep.to_json())
}

#[no_mangle]
pub unsafe extern "C" fn padat_decompress_package_json(
    pkg: *const c_char,
    scope_mask: u32,
    allow_running: bool,
) -> *mut c_char {
    let pkg = from_c_str(pkg);
    if PROGRESS.busy.swap(true, Ordering::SeqCst) {
        return to_c_string("{\"error\":\"busy\"}".into());
    }
    CANCEL_FLAG.store(false, Ordering::SeqCst);
    PROGRESS.begin(&pkg, "decompress");

    let pol = Policy::load(Path::new(DEFAULT_POLICY_PATH));
    let scopes = if scope_mask == 0 {
        Scopes::FULL_APP
    } else {
        scopes_from_mask(scope_mask)
    };
    let ctl = RunControl {
        cancel: &CANCEL_FLAG,
        paused: &PAUSED_FLAG,
        allow_running,
        thermal_pause_mc: pol.thermal_pause_mc,
        progress: Some(&PROGRESS),
    };
    let rep = engine::decompress_package(&RootPaths::default(), &pkg, scopes, &ctl);

    PROGRESS.end();
    to_c_string(rep.to_json())
}

#[no_mangle]
pub unsafe extern "C" fn padat_release_path_json(path: *const c_char) -> *mut c_char {
    let p = from_c_str(path);
    let rep = engine::release_path(Path::new(&p));
    to_c_string(rep.to_json())
}

#[no_mangle]
pub extern "C" fn padat_cleanup_stale_temps() -> u64 {
    let r = RootPaths::default();
    let pol = Policy::load(Path::new(DEFAULT_POLICY_PATH));
    engine::cleanup_stale_temps_for_policy(&r, &pol)
}

#[no_mangle]
pub unsafe extern "C" fn padat_apply_dir_profile(
    path: *const c_char,
    algo: u8,
    level: u8,
    cluster_kb: u16,
) -> i32 {
    let p = from_c_str(path);
    let prof = profile_from_ffi(algo, level, cluster_kb);
    match engine::apply_dir_profile(Path::new(&p), prof) {
        Ok(()) => 0,
        Err(e) => -(e.raw_os_error().unwrap_or(5)),
    }
}

#[no_mangle]
pub extern "C" fn padat_all_stats_json() -> *mut c_char {
    let stats = engine::stat_all_packages_parallel(&RootPaths::default());
    let mut out = String::with_capacity(stats.len() * 384 + 2);
    out.push('[');
    for (idx, st) in stats.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&st.to_json());
    }
    out.push(']');
    to_c_string(out)
}
