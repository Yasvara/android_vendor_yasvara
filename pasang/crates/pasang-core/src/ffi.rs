// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Thin `#[no_mangle] pub unsafe extern "C"` FFI boundary for `pasangd` (C++ lazy AIDL daemon).
//!
//! Strictly follows `SPEC-0000`: explicit null/length checks, JSON / `#[repr(C)]` PODs,
//! zero panics across FFI boundaries, and complete `/// # Safety` documentation.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crate::codec::{register_bz2_decoder, register_xz_decoder, register_zstd_decoder, DecompressFn};
use crate::cow_ota::{run_ota, OtaEnvironment, OtaPhase, OtaProgress};
use crate::crypto::{
    register_platform_rsa_verifier, register_platform_sha256, PlatformRsaVerifyFn,
    PlatformSha256FinalFn, PlatformSha256InitFn, PlatformSha256OneshotFn, PlatformSha256UpdateFn,
};
use crate::lp::{parse_geometry, parse_slot_metadata, LP_SECTOR_SIZE, LP_TARGET_TYPE_LINEAR};
use crate::overlay::{clean_overlays, inspect_overlays, DEFAULT_OVERLAY_ROOT, DEFAULT_PROC_MOUNTS};
use crate::slot::{
    json_escape, write_recovery_theme_atomic, BootControlOps, OtaOptions, RecoveryThemeSeed,
    DEFAULT_RECOVERY_THEME_PATH,
};

// ====================================================== Platform C BootControl Hook Table

/// C vtable registered once by `pasangd` (`boot_control_shim.cpp`) at daemon startup.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PasangPlatformHooks {
    pub current_slot: Option<unsafe extern "C" fn() -> i32>,
    pub active_boot_slot: Option<unsafe extern "C" fn() -> i32>,
    pub is_slot_bootable: Option<unsafe extern "C" fn(slot: u32) -> i32>,
    pub is_slot_successful: Option<unsafe extern "C" fn(slot: u32) -> i32>,
    pub set_active_boot_slot: Option<unsafe extern "C" fn(slot: u32) -> i32>,
    pub mark_boot_successful: Option<unsafe extern "C" fn() -> i32>,
    pub snapshot_merge_status: Option<unsafe extern "C" fn() -> i32>,
    pub rsa_verify: Option<PlatformRsaVerifyFn>,
    pub zstd_decompress: Option<DecompressFn>,
    pub xz_decompress: Option<DecompressFn>,
    pub bz2_decompress: Option<DecompressFn>,
    pub sha256_oneshot: Option<PlatformSha256OneshotFn>,
    pub sha256_init: Option<PlatformSha256InitFn>,
    pub sha256_update: Option<PlatformSha256UpdateFn>,
    pub sha256_final: Option<PlatformSha256FinalFn>,
}

static HOOKS: OnceLock<Mutex<Option<PasangPlatformHooks>>> = OnceLock::new();
static PROGRESS: OnceLock<Mutex<OtaProgress>> = OnceLock::new();
static CANCEL_FLAG: AtomicBool = AtomicBool::new(false);
static JOB_RUNNING: AtomicBool = AtomicBool::new(false);
static _RESERVED_PTR: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

fn progress_state() -> &'static Mutex<OtaProgress> {
    PROGRESS.get_or_init(|| Mutex::new(OtaProgress::default()))
}

struct FfiBootControl;

impl BootControlOps for FfiBootControl {
    fn current_slot(&self) -> Result<u32, String> {
        let guard = HOOKS.get().and_then(|m| m.lock().ok());
        if let Some(Some(h)) = guard.as_deref() {
            if let Some(f) = h.current_slot {
                // SAFETY: `f` is a valid C function pointer registered by `pasangd`.
                let rc = unsafe { f() };
                if rc >= 0 {
                    return Ok(rc as u32);
                }
                return Err(format!("IBootControl::getCurrentSlot failed ({rc})"));
            }
        }
        // Fallback: parse `/proc/cmdline` `androidboot.slot_suffix=`
        if let Ok(cmd) = std::fs::read_to_string("/proc/cmdline") {
            if cmd.contains("slot_suffix=_b") {
                return Ok(1);
            }
            if cmd.contains("slot_suffix=_a") {
                return Ok(0);
            }
        }
        Err("No BootControl hook registered and slot_suffix not found".into())
    }

    fn active_boot_slot(&self) -> Result<u32, String> {
        let guard = HOOKS.get().and_then(|m| m.lock().ok());
        if let Some(Some(h)) = guard.as_deref() {
            if let Some(f) = h.active_boot_slot {
                // SAFETY: `f` is a valid C function pointer registered by `pasangd`.
                let rc = unsafe { f() };
                if rc >= 0 {
                    return Ok(rc as u32);
                }
            }
        }
        self.current_slot()
    }

    fn is_slot_bootable(&self, slot: u32) -> Result<bool, String> {
        let guard = HOOKS.get().and_then(|m| m.lock().ok());
        if let Some(Some(h)) = guard.as_deref() {
            if let Some(f) = h.is_slot_bootable {
                // SAFETY: `f` is a valid C function pointer registered by `pasangd`.
                return Ok(unsafe { f(slot) } > 0);
            }
        }
        Ok(false)
    }

    fn is_slot_successful(&self, slot: u32) -> Result<bool, String> {
        let guard = HOOKS.get().and_then(|m| m.lock().ok());
        if let Some(Some(h)) = guard.as_deref() {
            if let Some(f) = h.is_slot_successful {
                // SAFETY: `f` is a valid C function pointer registered by `pasangd`.
                return Ok(unsafe { f(slot) } > 0);
            }
        }
        Ok(false)
    }

    fn set_active_boot_slot(&self, slot: u32) -> Result<(), String> {
        let guard = HOOKS.get().and_then(|m| m.lock().ok());
        if let Some(Some(h)) = guard.as_deref() {
            if let Some(f) = h.set_active_boot_slot {
                // SAFETY: `f` is a valid C function pointer registered by `pasangd`.
                let rc = unsafe { f(slot) };
                if rc == 0 {
                    return Ok(());
                }
                return Err(format!("IBootControl::setActiveBootSlot({slot}) failed ({rc})"));
            }
        }
        Err("BootControl set_active_boot_slot hook not registered".into())
    }

    fn mark_boot_successful(&self) -> Result<(), String> {
        let guard = HOOKS.get().and_then(|m| m.lock().ok());
        if let Some(Some(h)) = guard.as_deref() {
            if let Some(f) = h.mark_boot_successful {
                // SAFETY: `f` is a valid C function pointer registered by `pasangd`.
                let rc = unsafe { f() };
                if rc == 0 {
                    return Ok(());
                }
                return Err(format!("IBootControl::markBootSuccessful failed ({rc})"));
            }
        }
        Err("BootControl mark_boot_successful hook not registered".into())
    }

    fn snapshot_merge_status(&self) -> String {
        let guard = HOOKS.get().and_then(|m| m.lock().ok());
        if let Some(Some(h)) = guard.as_deref() {
            if let Some(f) = h.snapshot_merge_status {
                // SAFETY: `f` is a valid C function pointer registered by `pasangd`.
                return match unsafe { f() } {
                    0 => "none".into(),
                    1 => "unknown".into(),
                    2 => "snapshotted".into(),
                    3 => "merging".into(),
                    4 => "cancelled".into(),
                    _ => "unknown".into(),
                };
            }
        }
        "none".into()
    }
}

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new("{\"error\":\"interior nul\"}").unwrap())
        .into_raw()
}

/// # Safety
/// `ptr` must be null or a valid NUL-terminated UTF-8 string.
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees `ptr` is a valid NUL-terminated C string.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// # Safety
/// `hooks` must be a valid pointer to a `PasangPlatformHooks` struct (may be null to clear).
#[no_mangle]
pub unsafe extern "C" fn pasang_register_hooks(hooks: *const PasangPlatformHooks) {
    let lock = HOOKS.get_or_init(|| Mutex::new(None));
    if hooks.is_null() {
        if let Ok(mut g) = lock.lock() {
            *g = None;
        }
        return;
    }
    // SAFETY: Caller guarantees `hooks` is non-null and properly aligned.
    let h = unsafe { *hooks };
    if let Some(f) = h.rsa_verify {
        register_platform_rsa_verifier(f);
    }
    if let Some(f) = h.zstd_decompress {
        register_zstd_decoder(f);
    }
    if let Some(f) = h.xz_decompress {
        register_xz_decoder(f);
    }
    if let Some(f) = h.bz2_decompress {
        register_bz2_decoder(f);
    }
    if let (Some(oneshot), Some(init), Some(upd), Some(fin)) =
        (h.sha256_oneshot, h.sha256_init, h.sha256_update, h.sha256_final)
    {
        register_platform_sha256(oneshot, init, upd, fin);
    }
    if let Ok(mut g) = lock.lock() {
        *g = Some(h);
    }
}

/// # Safety
/// `ptr` must be null or a pointer previously returned by a `pasang_*_json` function.
#[no_mangle]
pub unsafe extern "C" fn pasang_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // SAFETY: `ptr` was allocated by `CString::into_raw()` in `to_c_string`.
        let _ = unsafe { CString::from_raw(ptr) };
    }
}

#[no_mangle]
pub extern "C" fn pasang_is_busy() -> bool {
    JOB_RUNNING.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn pasang_status_json() -> *mut c_char {
    let json = progress_state()
        .lock()
        .map(|g| g.to_json())
        .unwrap_or_else(|_| "{\"phase\":\"error\",\"error\":\"lock poisoned\"}".into());
    to_c_string(json)
}

/// Build JSON telemetry describing A/B slots, `super` total/used/free bytes, and VAB merge state.
pub fn build_slot_info_json(env: &OtaEnvironment, bootctl: &dyn BootControlOps) -> String {
    let cur = bootctl.current_slot().unwrap_or(0);
    let active_next = bootctl.active_boot_slot().unwrap_or(cur);
    let a_bootable = bootctl.is_slot_bootable(0).unwrap_or(false);
    let b_bootable = bootctl.is_slot_bootable(1).unwrap_or(false);
    let a_ok = bootctl.is_slot_successful(0).unwrap_or(false);
    let b_ok = bootctl.is_slot_successful(1).unwrap_or(false);
    let merge = bootctl.snapshot_merge_status();

    let mut super_total = 0u64;
    let mut super_active_used = 0u64;
    let mut super_free = 0u64;
    let mut active_parts = 0usize;

    if let Ok(mut f) = File::open(&env.super_device) {
        let mut hdr = vec![0u8; 1024 * 1024];
        if f.read_exact(&mut hdr).is_ok() {
            if let Ok(geom) = parse_geometry(&hdr) {
                if let Ok(meta) = parse_slot_metadata(&hdr, &geom, cur) {
                    super_total = meta.super_size_bytes();
                    active_parts = meta.partitions.len();
                    let cur_suf = if cur == 0 { "_a" } else { "_b" };
                    for p in &meta.partitions {
                        if p.name.ends_with(cur_suf) || p.name == "scratch" {
                            for e in meta.partition_extents(p) {
                                if e.target_type == LP_TARGET_TYPE_LINEAR {
                                    super_active_used += e.num_sectors * LP_SECTOR_SIZE;
                                }
                            }
                        }
                    }
                    super_free = super_total.saturating_sub(super_active_used);
                }
            }
        }
    }

    let ovl = inspect_overlays(&env.proc_mounts_path, &env.scratch_overlay_root);
    format!(
        "{{\"version\":\"{}\",\"current_slot\":{},\"current_suffix\":\"{}\",\
         \"active_boot_slot\":{},\"slot_a_bootable\":{},\"slot_a_successful\":{},\
         \"slot_b_bootable\":{},\"slot_b_successful\":{},\"merge_status\":\"{}\",\
         \"super_total_bytes\":{},\"super_used_bytes\":{},\"super_free_bytes\":{},\
         \"active_partition_count\":{},\"overlay_active\":{},\"overlay_files\":{},\
         \"overlay_bytes\":{}}}",
        crate::PASANG_VERSION,
        cur,
        if cur == 0 { "_a" } else { "_b" },
        active_next,
        a_bootable,
        a_ok,
        b_bootable,
        b_ok,
        json_escape(&merge),
        super_total,
        super_active_used,
        super_free,
        active_parts,
        ovl.overlay_active,
        ovl.total_files,
        ovl.total_bytes,
    )
}

#[no_mangle]
pub extern "C" fn pasang_slot_info_json() -> *mut c_char {
    let env = OtaEnvironment::android_default();
    to_c_string(build_slot_info_json(&env, &FfiBootControl))
}

#[no_mangle]
pub extern "C" fn pasang_overlay_status_json() -> *mut c_char {
    let st = inspect_overlays(Path::new(DEFAULT_PROC_MOUNTS), Path::new(DEFAULT_OVERLAY_ROOT));
    to_c_string(st.to_json())
}

#[no_mangle]
pub extern "C" fn pasang_clean_overlays_json() -> *mut c_char {
    let rep = clean_overlays(Path::new(DEFAULT_OVERLAY_ROOT), None);
    to_c_string(rep.to_json())
}

/// # Safety
/// `path_ptr` and `opts_json_ptr` must be null or valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn pasang_plan_ota_json(
    path_ptr: *const c_char,
    opts_json_ptr: *const c_char,
) -> *mut c_char {
    // SAFETY: Caller guarantees valid NUL-terminated C strings.
    let Some(path) = (unsafe { cstr_to_str(path_ptr) }) else {
        return to_c_string("{\"error\":\"null path\"}".into());
    };
    // SAFETY: Caller guarantees valid NUL-terminated C string or null.
    let mut opts = unsafe { cstr_to_str(opts_json_ptr) }
        .map(OtaOptions::from_json_str)
        .unwrap_or_default();
    opts.dry_run = true;

    let env = OtaEnvironment::android_default();
    match run_ota(&env, &FfiBootControl, Path::new(path), &opts, None, None) {
        Ok(res) => to_c_string(res.plan.to_json()),
        Err(e) => to_c_string(format!("{{\"error\":\"{}\"}}", json_escape(&e))),
    }
}

/// Starts an asynchronous In-OS CoW OTA job on a dedicated background worker thread.
/// Returns `0` if started, `-16` (`-EBUSY`) if an OTA is already running, `-22` on bad args.
///
/// # Safety
/// `path_ptr` and `opts_json_ptr` must be null or valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn pasang_start_ota(
    path_ptr: *const c_char,
    opts_json_ptr: *const c_char,
) -> i32 {
    // SAFETY: Caller guarantees valid NUL-terminated C string.
    let Some(path) = (unsafe { cstr_to_str(path_ptr) }) else {
        return -22;
    };
    // SAFETY: Caller guarantees valid NUL-terminated C string or null.
    let mut opts = unsafe { cstr_to_str(opts_json_ptr) }
        .map(OtaOptions::from_json_str)
        .unwrap_or_default();
    opts.dry_run = false;

    if JOB_RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return -16; // EBUSY
    }
    CANCEL_FLAG.store(false, Ordering::Release);
    let path_owned = PathBuf::from(path);

    let spawn_res = thread::Builder::new()
        .name("pasang-ota".into())
        .spawn(move || {
            let env = OtaEnvironment::android_default();
            let res = run_ota(
                &env,
                &FfiBootControl,
                &path_owned,
                &opts,
                Some(progress_state()),
                Some(&CANCEL_FLAG),
            );
            if let Err(err) = res {
                if let Ok(mut g) = progress_state().lock() {
                    if g.phase != OtaPhase::Cancelled {
                        g.phase = OtaPhase::Error;
                        g.error_message = err;
                    }
                }
            }
            JOB_RUNNING.store(false, Ordering::Release);
        });

    if spawn_res.is_err() {
        JOB_RUNNING.store(false, Ordering::Release);
        return -12; // ENOMEM
    }
    0
}

#[no_mangle]
pub extern "C" fn pasang_cancel_ota() {
    CANCEL_FLAG.store(true, Ordering::Release);
}

/// Write the 32-byte Material You seed POD to `/metadata/yasvara/recovery_theme.bin`.
/// Returns `0` on success, negative errno on error.
///
/// # Safety
/// `locale_ptr` must be null or a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn pasang_write_recovery_theme(
    seed_argb: u32,
    oled_black: bool,
    locale_ptr: *const c_char,
) -> i32 {
    // SAFETY: Caller guarantees valid NUL-terminated C string or null.
    let locale = unsafe { cstr_to_str(locale_ptr) }.unwrap_or("en_US");
    let seed = RecoveryThemeSeed::new(seed_argb, oled_black, locale);
    match write_recovery_theme_atomic(Path::new(DEFAULT_RECOVERY_THEME_PATH), &seed) {
        Ok(()) => 0,
        Err(_) => -5,
    }
}

/// CLI entrypoint called by `pasangd` when invoked as `/system_ext/bin/pasang <args...>`
/// (inherits `libzstd`/`liblzma`/`libbz`/BoringSSL/`BootControlClient` hooks with 0 binary duplication!).
///
/// # Safety
/// `argv` must be an array of `argc` valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn pasang_run_cli(argc: i32, argv: *const *const c_char) -> i32 {
    if argc <= 1 || argv.is_null() {
        eprintln!(
            "usage: pasang <slot|status|inspect|plan|apply|overlay|theme> [args...]"
        );
        return 0;
    }
    let mut args = Vec::with_capacity((argc - 1) as usize);
    for i in 1..(argc as usize) {
        // SAFETY: Caller guarantees `argv` has at least `argc` elements.
        let p = unsafe { *argv.add(i) };
        if let Some(s) = unsafe { cstr_to_str(p) } {
            args.push(s.to_string());
        }
    }
    run_cli_args(&args)
}

fn run_cli_args(args: &[String]) -> i32 {
    let Some(cmd) = args.first().map(|s| s.as_str()) else {
        return 2;
    };
    let env = OtaEnvironment::android_default();
    match cmd {
        "slot" | "status" => {
            println!("{}", build_slot_info_json(&env, &FfiBootControl));
            0
        }
        "overlay" => match args.get(1).map(|s| s.as_str()) {
            Some("clean") => {
                let rep = clean_overlays(Path::new(DEFAULT_OVERLAY_ROOT), None);
                println!("{}", rep.to_json());
                if rep.errors.is_empty() { 0 } else { 1 }
            }
            _ => {
                let st = inspect_overlays(Path::new(DEFAULT_PROC_MOUNTS), Path::new(DEFAULT_OVERLAY_ROOT));
                println!("{}", st.to_json());
                0
            }
        },
        "plan" | "apply" => {
            let mut opts = OtaOptions {
                dry_run: cmd == "plan",
                ..Default::default()
            };
            let mut path: Option<PathBuf> = None;
            for a in &args[1..] {
                match a.as_str() {
                    "--clean-overlay" => opts.clean_overlay = true,
                    "--keep-overlay" => opts.clean_overlay = false,
                    "--fast-verify" => opts.fast_verify = true,
                    "--allow-dev-key" => opts.allow_dev_key = true,
                    "--no-alias" => opts.enable_extent_aliasing = false,
                    "--dry-run" => opts.dry_run = true,
                    s if !s.starts_with('-') => path = Some(PathBuf::from(s)),
                    other => {
                        eprintln!("error: unknown flag {other}");
                        return 2;
                    }
                }
            }
            let Some(ota_path) = path else {
                eprintln!("usage: pasang {cmd} [flags] <ota.zip|payload.bin>");
                return 2;
            };
            let prog = Arc::new(Mutex::new(OtaProgress::default()));
            let done_flag = Arc::new(AtomicBool::new(false));
            let prog_w = Arc::clone(&prog);
            let done_w = Arc::clone(&done_flag);
            let watcher = thread::spawn(move || {
                let mut last_line = String::new();
                while !done_w.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(200));
                    let snap = match prog_w.lock() {
                        Ok(g) => g.clone(),
                        Err(_) => break,
                    };
                    if matches!(snap.phase, OtaPhase::Idle | OtaPhase::Done) {
                        continue;
                    }
                    let line = match snap.phase {
                        OtaPhase::Flashing => {
                            let w_mib = snap.bytes_written as f64 / (1024.0 * 1024.0);
                            let t_mib = snap.bytes_to_write as f64 / (1024.0 * 1024.0);
                            let pct = if snap.bytes_to_write > 0 {
                                (snap.bytes_written as f64 * 100.0 / snap.bytes_to_write as f64)
                                    .clamp(0.0, 100.0)
                            } else {
                                0.0
                            };
                            let spd = snap.speed_bps as f64 / (1024.0 * 1024.0);
                            format!(
                                "  [flashing]  {:<18} {:>6.1}/{:.1} MiB ({:>5.1}%) · {:>5.1} MiB/s · ETA {}s",
                                snap.current_partition,
                                w_mib,
                                t_mib,
                                pct,
                                spd,
                                snap.eta_seconds.max(0)
                            )
                        }
                        other => {
                            format!(
                                "  [{:<9}] {} ({:.1}s)",
                                other.as_str(),
                                snap.current_partition,
                                snap.elapsed_ms as f64 / 1000.0
                            )
                        }
                    };
                    if line != last_line {
                        let mut err = std::io::stderr().lock();
                        let _ = writeln!(err, "{line}");
                        let _ = err.flush();
                        last_line = line;
                    }
                }
            });

            let res = run_ota(&env, &FfiBootControl, &ota_path, &opts, Some(prog.as_ref()), None);
            done_flag.store(true, Ordering::Release);
            let _ = watcher.join();

            match res {
                Ok(res) => {
                    println!(
                        "{{\"ok\":true,\"dry_run\":{},\"committed_slot\":{},\"elapsed_ms\":{},\"bytes_written\":{},\"plan\":{}}}",
                        opts.dry_run,
                        res.committed_slot,
                        res.elapsed_ms,
                        res.bytes_written,
                        res.plan.to_json()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        "inspect" => {
            let Some(p) = args.get(1) else {
                eprintln!("usage: pasang inspect <ota.zip|payload.bin>");
                return 2;
            };
            let Ok(mut f) = File::open(p) else {
                eprintln!("error: cannot open {p}");
                return 1;
            };
            match crate::payload::parse_payload(&mut f) {
                Ok(m) => {
                    println!(
                        "CrAU v{} block={} partitions={} sigs={}",
                        m.version,
                        m.block_size,
                        m.partitions.len(),
                        m.metadata_signatures.len()
                    );
                    for pt in &m.partitions {
                        println!(
                            "  {:<20} {:>8.1} MiB ({} ops)",
                            pt.name,
                            pt.new_info.size as f64 / (1024.0 * 1024.0),
                            pt.operations.len()
                        );
                    }
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            }
        }
        "theme" => {
            if args.get(1).map(|s| s.as_str()) == Some("write") && args.len() >= 4 {
                let hex = args[2].trim_start_matches("0x").trim_start_matches('#');
                let argb = u32::from_str_radix(hex, 16).unwrap_or(0xFF6750A4);
                let oled = args[3] == "1" || args[3] == "true";
                let loc = args.get(4).map(|s| s.as_str()).unwrap_or("en_US");
                let seed = RecoveryThemeSeed::new(argb, oled, loc);
                match write_recovery_theme_atomic(Path::new(DEFAULT_RECOVERY_THEME_PATH), &seed) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("error: {e}");
                        1
                    }
                }
            } else {
                eprintln!("usage: pasang theme write <argb_hex> <0|1> [locale]");
                2
            }
        }
        other => {
            eprintln!("error: unknown command {other}");
            2
        }
    }
}
