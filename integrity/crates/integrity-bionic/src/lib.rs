// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `#![no_std]` zero-alloc, zero-TLS, lock-free Rust implementation of Bionic's Yasvara
//! property-hiding & spoofing hooks (`libc.so` only).
//!
//! Linked directly into `libc_common_shared` (`no_stdlibs: true`, identical to AOSP's
//! `libicu4x_bionic`). All policy, tables, prefix/suffix matchers, canonical digest validation,
//! and flavor normalization come straight from `yasvara_integrity_core` (Single Source of Truth).

#![no_std]

#[cfg(feature = "panic_abort")]
#[panic_handler]
fn panic_abort(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "panic_abort")]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

use core::ffi::{c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicUsize, Ordering};

use yasvara_integrity_core::contract::{
    AID_APP_START, AID_USER_OFFSET, AID_WEBVIEW_ZYGOTE, PROP_OVERRIDE_MAX, PROP_VALUE_MAX,
};
use yasvara_integrity_core::digest::is_canonical_hex;
use yasvara_integrity_core::prop_policy::{
    assemble_fingerprint, boot_story_value_cstr, build_identity_story_cstr, classify_app_cmdline,
    cmdline_is_collector, cmdline_is_placeholder, cmdline_is_rkp_mfg_exempt, cmdline_is_zygote,
    find_boot_story, find_collector_story_cstr, is_boot_digest_prop, is_hidden_marker,
    is_pif_staging, is_product_manufacturer_prop, is_rkp_mfg_staging, may_intercept,
    normalize_build_flavor, staging_for_identity_cstr, PropVerdict, ROLE_APP, ROLE_COLLECTOR,
    ROLE_NONE, ROLE_RKP_MFG_EXEMPT,
};

// Thin platform primitives provided by `bionic/libc/bionic/system_property_api.cpp` &
// `yasvara_prop_hide.cpp` (or by the host test harness).
extern "C" {
    fn yasvara_prop_raw_get(name: *const c_char, value: *mut c_char) -> c_int;
    fn yasvara_prop_raw_get_ro(name: *const c_char) -> *const c_char;
    fn yasvara_bionic_getpid() -> c_int;
    fn yasvara_bionic_getuid() -> u32;
    fn yasvara_bionic_read_cmdline(out: *mut u8, out_size: usize) -> bool;
}

const K_BOOT_DIGEST_PROP: &[u8] = b"ro.yasvara.boot.digest\0";
const K_STEALTH_PROP: &[u8] = b"persist.sys.yasvara.stealth\0";
const K_PIF_ENABLED_PROP: &[u8] = b"persist.sys.yasvara.pif.enabled\0";
const K_LEGACY_PIF_PROP: &[u8] = b"persist.sys.yasvara.pif\0";
const K_TRICKY_PROP: &[u8] = b"persist.sys.yasvara.trickystore\0";
const K_RKP_MFG_PROP: &[u8] = b"persist.sys.yasvara.rkp_manufacturer\0";
const K_PIF_FINGERPRINT_PROP: &[u8] = b"persist.sys.yasvara.pif.fingerprint\0";
const K_EMPTY_CSTR: &[u8] = b"\0";

const K_FP_COMPONENTS: [&[u8]; 8] = [
    b"persist.sys.yasvara.pif.brand\0",
    b"persist.sys.yasvara.pif.name\0",
    b"persist.sys.yasvara.pif.device\0",
    b"persist.sys.yasvara.pif.release\0",
    b"persist.sys.yasvara.pif.build_id\0",
    b"persist.sys.yasvara.pif.incremental\0",
    b"persist.sys.yasvara.pif.build_type\0",
    b"persist.sys.yasvara.pif.build_tags\0",
];

// ---------------------------------------------------------------------------
// Lock-free PID-cached ProcessRole & append-only .bss string intern pool
// ---------------------------------------------------------------------------

static CACHED_PID: AtomicI32 = AtomicI32::new(-1);
static CACHED_ROLE: AtomicI32 = AtomicI32::new(ROLE_NONE);

const INTERN_POOL_BYTES: usize = 8192;
const MAX_INTERN_STRINGS: usize = 128;

// SAFETY: Every byte range `[off..off+len]` is exclusively reserved via CAS on `INTERN_OFFSET`,
// fully initialized before its pointer is published with `Ordering::Release` in `INTERN_PTRS`,
// and immutable forever after. Zero mutexes, zero ELF TLS, zero heap allocation.
#[repr(transparent)]
struct SyncPool(core::cell::UnsafeCell<[u8; INTERN_POOL_BYTES]>);
unsafe impl Sync for SyncPool {}

static INTERN_POOL: SyncPool = SyncPool(core::cell::UnsafeCell::new([0u8; INTERN_POOL_BYTES]));
static INTERN_OFFSET: AtomicUsize = AtomicUsize::new(0);
static INTERN_PTRS: [AtomicPtr<u8>; MAX_INTERN_STRINGS] = {
    const NULL: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
    [NULL; MAX_INTERN_STRINGS]
};

#[inline]
unsafe fn cstr_bytes<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() || (p as usize) < 0x1000 {
        return None;
    }
    let mut len = 0usize;
    // Bounded scan to prevent runaway reads on malformed pointers.
    while len < 512 {
        // SAFETY: Caller guarantees valid C string pointer above low guard page.
        if unsafe { *p.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `p` is valid for `len` bytes.
    Some(unsafe { core::slice::from_raw_parts(p as *const u8, len) })
}

#[inline]
unsafe fn copy_cstr(dst: *mut c_char, dst_size: usize, src_bytes: &[u8]) {
    if dst.is_null() || dst_size == 0 {
        return;
    }
    let max_copy = dst_size - 1;
    let n = if src_bytes.len() < max_copy { src_bytes.len() } else { max_copy };
    // SAFETY: Caller guarantees `dst` has capacity `dst_size`.
    unsafe {
        ptr::copy_nonoverlapping(src_bytes.as_ptr(), dst as *mut u8, n);
        *dst.add(n) = 0;
    }
}

#[inline]
fn raw_get_prop<'a>(name_cstr: &[u8], buf: &'a mut [u8; PROP_VALUE_MAX]) -> Option<&'a [u8]> {
    // SAFETY: `name_cstr` is NUL-terminated; `buf` has PROP_VALUE_MAX capacity.
    let len = unsafe {
        yasvara_prop_raw_get(name_cstr.as_ptr() as *const c_char, buf.as_mut_ptr() as *mut c_char)
    };
    if len <= 0 {
        return None;
    }
    let n = (len as usize).min(PROP_VALUE_MAX - 1);
    Some(&buf[..n])
}

fn intern_override_bytes(s: &[u8]) -> *const c_char {
    // Fast scan for an already-interned identical string.
    let mut i = 0;
    while i < MAX_INTERN_STRINGS {
        let cur = INTERN_PTRS[i].load(Ordering::Acquire);
        if cur.is_null() {
            break;
        }
        // SAFETY: Every non-null entry points to an immutable NUL-terminated slice in INTERN_POOL.
        if let Some(existing) = unsafe { cstr_bytes(cur as *const c_char) } {
            if existing == s {
                return cur as *const c_char;
            }
        }
        i += 1;
    }

    let needed = s.len() + 1;
    let mut off = INTERN_OFFSET.load(Ordering::Acquire);
    loop {
        if off > INTERN_POOL_BYTES || needed > INTERN_POOL_BYTES - off {
            return K_EMPTY_CSTR.as_ptr() as *const c_char;
        }
        match INTERN_OFFSET.compare_exchange_weak(
            off,
            off + needed,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => off = actual,
        }
    }

    // SAFETY: Exclusive reservation `[off..off+needed]` inside `INTERN_POOL`.
    let dst = unsafe {
        let base = (*INTERN_POOL.0.get()).as_mut_ptr().add(off);
        ptr::copy_nonoverlapping(s.as_ptr(), base, s.len());
        *base.add(s.len()) = 0;
        base
    };

    let mut slot = 0;
    while slot < MAX_INTERN_STRINGS {
        match INTERN_PTRS[slot].compare_exchange(
            ptr::null_mut(),
            dst,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            Ok(_) => return dst as *const c_char,
            Err(existing_ptr) => {
                if !existing_ptr.is_null() {
                    // SAFETY: Published immutable C string in `INTERN_POOL`.
                    if let Some(existing) = unsafe { cstr_bytes(existing_ptr as *const c_char) } {
                        if existing == s {
                            let _ = INTERN_OFFSET.compare_exchange(
                                off + needed,
                                off,
                                Ordering::AcqRel,
                                Ordering::Relaxed,
                            );
                            return existing_ptr as *const c_char;
                        }
                    }
                }
            }
        }
        slot += 1;
    }
    K_EMPTY_CSTR.as_ptr() as *const c_char
}

fn resolve_process_role() -> i32 {
    // SAFETY: External libc/host syscall trampoline.
    let cur = unsafe { yasvara_bionic_getpid() };
    if CACHED_PID.load(Ordering::Acquire) == cur {
        return CACHED_ROLE.load(Ordering::Relaxed);
    }

    // SAFETY: External libc/host syscall trampoline.
    let app_id = unsafe { yasvara_bionic_getuid() } % AID_USER_OFFSET;
    let mut cmdline = [0u8; 256];
    if app_id < AID_APP_START {
        if cur == 1 || (app_id != 0 && app_id != AID_WEBVIEW_ZYGOTE) {
            CACHED_ROLE.store(ROLE_NONE, Ordering::Relaxed);
            CACHED_PID.store(cur, Ordering::Release);
            return ROLE_NONE;
        }
        // SAFETY: `cmdline` is a valid writable stack buffer.
        if unsafe { yasvara_bionic_read_cmdline(cmdline.as_mut_ptr(), cmdline.len()) } {
            let name = slice_until_nul(&cmdline);
            if !cmdline_is_zygote(name) && !cmdline_is_placeholder(name) {
                CACHED_ROLE.store(ROLE_NONE, Ordering::Relaxed);
                CACHED_PID.store(cur, Ordering::Release);
            }
        }
        return ROLE_NONE;
    }

    // SAFETY: `cmdline` is a valid writable stack buffer.
    if !unsafe { yasvara_bionic_read_cmdline(cmdline.as_mut_ptr(), cmdline.len()) } {
        return ROLE_NONE;
    }
    let name = slice_until_nul(&cmdline);
    let role = classify_app_cmdline(name);
    if role == ROLE_NONE {
        return ROLE_NONE;
    }
    CACHED_ROLE.store(role, Ordering::Relaxed);
    CACHED_PID.store(cur, Ordering::Release);
    role
}

#[inline]
fn slice_until_nul(buf: &[u8]) -> &[u8] {
    let mut n = 0;
    while n < buf.len() && buf[n] != 0 {
        n += 1;
    }
    &buf[..n]
}

/// Independent ROM/boot/adb/marker stealth gate.
/// Checks `persist.sys.yasvara.stealth` first, falling back to legacy `persist.sys.yasvara.pif`
/// (default ON when unset). Never caches unset/transient values so live changes apply cleanly.
fn stealth_enabled() -> bool {
    let mut buf = [0u8; PROP_VALUE_MAX];
    if let Some(v) = raw_get_prop(K_STEALTH_PROP, &mut buf) {
        return v[0] != b'0';
    }
    if let Some(v) = raw_get_prop(K_LEGACY_PIF_PROP, &mut buf) {
        return v[0] != b'0';
    }
    true
}

/// Independent built-in PIF profile spoofing gate for Play Integrity collectors.
/// Checks authoritative `persist.sys.yasvara.pif.enabled` (written by `YasvaraAttestationService`
/// and cleared when user disables PIF or an Akar module claims `play_integrity`), falling back
/// to `stealth_enabled()` only when `.enabled` has not yet been staged.
fn pif_profile_enabled() -> bool {
    let mut buf = [0u8; PROP_VALUE_MAX];
    if let Some(v) = raw_get_prop(K_PIF_ENABLED_PROP, &mut buf) {
        return v[0] != b'0';
    }
    stealth_enabled()
}

fn trickystore_enabled() -> bool {
    let mut buf = [0u8; PROP_VALUE_MAX];
    match raw_get_prop(K_TRICKY_PROP, &mut buf) {
        Some(v) => v[0] != b'0',
        None => true,
    }
}

/// Returns the immutable mapped RO pointer to `ro.yasvara.boot.digest` iff it is a valid
/// canonical 64/128 lowercase non-zero hex digest. Never caches a missing value.
fn canonical_boot_digest_ptr() -> *const c_char {
    // SAFETY: NUL-terminated static property name.
    let ptr = unsafe { yasvara_prop_raw_get_ro(K_BOOT_DIGEST_PROP.as_ptr() as *const c_char) };
    let Some(bytes) = (unsafe { cstr_bytes(ptr) }) else {
        return ptr::null();
    };
    if is_canonical_hex(bytes) {
        ptr
    } else {
        ptr::null()
    }
}

unsafe fn emit_dynamic(
    val: &[u8],
    buffer: *mut c_char,
    size: usize,
    intern: bool,
) -> *const c_char {
    if !buffer.is_null() {
        // SAFETY: Caller guarantees `buffer` holds `size` bytes.
        unsafe { copy_cstr(buffer, size, val) };
    }
    if intern {
        intern_override_bytes(val)
    } else {
        buffer as *const c_char
    }
}

unsafe fn rkp_manufacturer_override(
    role: i32,
    name: &[u8],
    buffer: *mut c_char,
    size: usize,
    intern: bool,
) -> *const c_char {
    if (role & (ROLE_COLLECTOR | ROLE_RKP_MFG_EXEMPT)) != 0 {
        return ptr::null();
    }
    if !trickystore_enabled() || !is_product_manufacturer_prop(name) {
        return ptr::null();
    }
    let mut raw = [0u8; PROP_VALUE_MAX];
    let Some(mfg) = raw_get_prop(K_RKP_MFG_PROP, &mut raw) else {
        return ptr::null();
    };
    // SAFETY: Caller upholds `buffer`/`size` contract.
    unsafe { emit_dynamic(mfg, buffer, size, intern) }
}

unsafe fn assemble_pif_fingerprint_into(out: &mut [u8; PROP_OVERRIDE_MAX]) -> Option<usize> {
    let mut b0 = [0u8; PROP_VALUE_MAX];
    let mut b1 = [0u8; PROP_VALUE_MAX];
    let mut b2 = [0u8; PROP_VALUE_MAX];
    let mut b3 = [0u8; PROP_VALUE_MAX];
    let mut b4 = [0u8; PROP_VALUE_MAX];
    let mut b5 = [0u8; PROP_VALUE_MAX];
    let mut b6 = [0u8; PROP_VALUE_MAX];
    let mut b7 = [0u8; PROP_VALUE_MAX];
    let parts = [
        raw_get_prop(K_FP_COMPONENTS[0], &mut b0)?,
        raw_get_prop(K_FP_COMPONENTS[1], &mut b1)?,
        raw_get_prop(K_FP_COMPONENTS[2], &mut b2)?,
        raw_get_prop(K_FP_COMPONENTS[3], &mut b3)?,
        raw_get_prop(K_FP_COMPONENTS[4], &mut b4)?,
        raw_get_prop(K_FP_COMPONENTS[5], &mut b5)?,
        raw_get_prop(K_FP_COMPONENTS[6], &mut b6)?,
        raw_get_prop(K_FP_COMPONENTS[7], &mut b7)?,
    ];
    assemble_fingerprint(parts, out)
}

unsafe fn story_override(
    role: i32,
    name: &[u8],
    name_ptr: *const c_char,
    buffer: *mut c_char,
    size: usize,
    intern: bool,
) -> *const c_char {
    if let Some(idx) = find_boot_story(name) {
        if let Some(cstr) = boot_story_value_cstr(idx) {
            return cstr.as_ptr() as *const c_char;
        }
    }
    if name.len() < 3 || &name[..3] != b"ro." {
        return ptr::null();
    }
    if let Some(cstr) = build_identity_story_cstr(name) {
        return cstr.as_ptr() as *const c_char;
    }

    if (role & ROLE_COLLECTOR) != 0 {
        if pif_profile_enabled() {
            if let Some(cstr) = find_collector_story_cstr(name) {
                return cstr.as_ptr() as *const c_char;
            }
            if name.len() > 18 && &name[name.len() - 18..] == b".build.fingerprint" {
                let mut raw = [0u8; PROP_VALUE_MAX];
                if let Some(fp) = raw_get_prop(K_PIF_FINGERPRINT_PROP, &mut raw) {
                    // SAFETY: Caller upholds `buffer`/`size` contract.
                    return unsafe { emit_dynamic(fp, buffer, size, intern) };
                }
                let mut assembled = [0u8; PROP_OVERRIDE_MAX];
                let limit = size.min(PROP_OVERRIDE_MAX);
                if let Some(n) = unsafe { assemble_pif_fingerprint_into(&mut assembled) } {
                    if n < limit {
                        // SAFETY: Caller upholds `buffer`/`size` contract.
                        return unsafe { emit_dynamic(&assembled[..n], buffer, size, intern) };
                    }
                }
            }
            if let Some(staging_cstr) = staging_for_identity_cstr(name) {
                let mut raw = [0u8; PROP_VALUE_MAX];
                if let Some(val) = raw_get_prop(staging_cstr, &mut raw) {
                    // SAFETY: Caller upholds `buffer`/`size` contract.
                    return unsafe { emit_dynamic(val, buffer, size, intern) };
                }
            }
        }
    } else {
        // SAFETY: Caller upholds `buffer`/`size` contract.
        let mfg = unsafe { rkp_manufacturer_override(role, name, buffer, size, intern) };
        if !mfg.is_null() {
            return mfg;
        }
    }

    if name.len() > 13 && &name[name.len() - 13..] == b".build.flavor" {
        // SAFETY: `name_ptr` is a valid NUL-terminated `ro.*` property name.
        let raw_ptr = unsafe { yasvara_prop_raw_get_ro(name_ptr) };
        if let Some(raw_bytes) = unsafe { cstr_bytes(raw_ptr) } {
            let mut scratch = [0u8; PROP_VALUE_MAX];
            let cap = size.min(PROP_VALUE_MAX);
            if let Some(n) = normalize_build_flavor(raw_bytes, &mut scratch[..cap]) {
                // SAFETY: Caller upholds `buffer`/`size` contract.
                return unsafe { emit_dynamic(&scratch[..n], buffer, size, intern) };
            }
        }
    }
    ptr::null()
}

// ---------------------------------------------------------------------------
// Exported C ABI (exact symbols consumed by Bionic libc.so & host tests)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn yasvara_prop_is_app_process() -> bool {
    (resolve_process_role() & ROLE_APP) != 0
}

#[no_mangle]
pub extern "C" fn yasvara_prop_is_non_collector_app_process() -> bool {
    (resolve_process_role() & (ROLE_APP | ROLE_COLLECTOR)) == ROLE_APP
}

/// # Safety
/// `name` may be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn yasvara_prop_should_hide(name: *const c_char) -> bool {
    // SAFETY: Checked inside `cstr_bytes`.
    let Some(bytes) = (unsafe { cstr_bytes(name) }) else {
        return false;
    };
    if !may_intercept(bytes) {
        return false;
    }
    let role = resolve_process_role();
    if (role & ROLE_APP) == 0 {
        return false;
    }
    if is_pif_staging(bytes) {
        return (role & ROLE_COLLECTOR) == 0;
    }
    if is_rkp_mfg_staging(bytes) {
        return true;
    }
    if !stealth_enabled() {
        return false;
    }
    is_hidden_marker(bytes)
}

/// # Safety
/// `name` may be null or a valid C string; `buffer` may be null or have `PROP_OVERRIDE_MAX` bytes;
/// `value` must be a valid non-null writable pointer.
#[no_mangle]
pub unsafe extern "C" fn yasvara_prop_resolve(
    name: *const c_char,
    buffer: *mut c_char,
    value: *mut *const c_char,
) -> PropVerdict {
    if value.is_null() {
        return PropVerdict::Real;
    }
    // SAFETY: Checked inside `cstr_bytes`.
    let Some(bytes) = (unsafe { cstr_bytes(name) }) else {
        return PropVerdict::Real;
    };
    if !may_intercept(bytes) {
        return PropVerdict::Real;
    }
    if is_boot_digest_prop(bytes) {
        let digest_ptr = canonical_boot_digest_ptr();
        // SAFETY: `value` checked non-null above.
        unsafe { *value = digest_ptr };
        return if digest_ptr.is_null() { PropVerdict::Real } else { PropVerdict::Overridden };
    }
    let role = resolve_process_role();
    if (role & ROLE_APP) == 0 {
        return PropVerdict::Real;
    }
    if is_pif_staging(bytes) {
        return if (role & ROLE_COLLECTOR) != 0 { PropVerdict::Real } else { PropVerdict::Hidden };
    }
    if is_rkp_mfg_staging(bytes) {
        return PropVerdict::Hidden;
    }
    let is_ro = bytes.len() >= 3 && &bytes[..3] == b"ro.";
    if stealth_enabled() {
        if is_hidden_marker(bytes) {
            return PropVerdict::Hidden;
        }
        // SAFETY: Caller guarantees `buffer` (if non-null) has `PROP_OVERRIDE_MAX` bytes.
        let v = unsafe { story_override(role, bytes, name, buffer, PROP_OVERRIDE_MAX, true) };
        if !v.is_null() {
            // SAFETY: `value` is non-null.
            unsafe { *value = v };
            return PropVerdict::Overridden;
        }
    } else {
        // SAFETY: Caller guarantees `buffer` (if non-null) has `PROP_OVERRIDE_MAX` bytes.
        let v = unsafe { rkp_manufacturer_override(role, bytes, buffer, PROP_OVERRIDE_MAX, true) };
        if !v.is_null() {
            // SAFETY: `value` is non-null.
            unsafe { *value = v };
            return PropVerdict::Overridden;
        }
    }
    if is_ro { PropVerdict::RealAppRo } else { PropVerdict::Real }
}

/// # Safety
/// `name` may be null or a valid C string; `value` must have `PROP_VALUE_MAX` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn yasvara_prop_should_spoof(
    name: *const c_char,
    value: *mut c_char,
) -> bool {
    if value.is_null() {
        return false;
    }
    // SAFETY: Checked inside `cstr_bytes`.
    let Some(bytes) = (unsafe { cstr_bytes(name) }) else {
        return false;
    };
    if !may_intercept(bytes) {
        return false;
    }
    if is_boot_digest_prop(bytes) {
        let digest_ptr = canonical_boot_digest_ptr();
        let Some(digest_bytes) = (unsafe { cstr_bytes(digest_ptr) }) else {
            return false;
        };
        if digest_bytes.len() >= PROP_VALUE_MAX {
            // Never silently truncate SHA-512 (128 chars) into legacy 92-byte buffers.
            // SAFETY: `value` is non-null with `PROP_VALUE_MAX` capacity.
            unsafe { *value = 0 };
        } else {
            // SAFETY: `value` has `PROP_VALUE_MAX` capacity.
            unsafe { copy_cstr(value, PROP_VALUE_MAX, digest_bytes) };
        }
        return true;
    }
    let role = resolve_process_role();
    if (role & ROLE_APP) == 0 {
        return false;
    }
    if is_pif_staging(bytes) {
        if (role & ROLE_COLLECTOR) != 0 {
            return false;
        }
        // SAFETY: `value` is non-null.
        unsafe { *value = 0 };
        return true;
    }
    if is_rkp_mfg_staging(bytes) {
        // SAFETY: `value` is non-null.
        unsafe { *value = 0 };
        return true;
    }
    if !stealth_enabled() {
        // SAFETY: `value` has `PROP_VALUE_MAX` bytes.
        let v = unsafe { rkp_manufacturer_override(role, bytes, value, PROP_VALUE_MAX, false) };
        if v.is_null() {
            return false;
        }
        if v != value as *const c_char {
            if let Some(vb) = unsafe { cstr_bytes(v) } {
                unsafe { copy_cstr(value, PROP_VALUE_MAX, vb) };
            }
        }
        return true;
    }
    if is_hidden_marker(bytes) {
        // SAFETY: `value` is non-null.
        unsafe { *value = 0 };
        return true;
    }
    // SAFETY: `value` has `PROP_VALUE_MAX` bytes.
    let v = unsafe { story_override(role, bytes, name, value, PROP_VALUE_MAX, false) };
    if v.is_null() {
        return false;
    }
    if v != value as *const c_char {
        if let Some(vb) = unsafe { cstr_bytes(v) } {
            unsafe { copy_cstr(value, PROP_VALUE_MAX, vb) };
        }
    }
    true
}

/// # Safety
/// `name` may be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn yasvara_prop_synth_absent_index(name: *const c_char) -> c_int {
    // SAFETY: Checked inside `cstr_bytes`.
    let Some(bytes) = (unsafe { cstr_bytes(name) }) else {
        return -1;
    };
    if !may_intercept(bytes) || !yasvara_prop_is_app_process() || !stealth_enabled() {
        return -1;
    }
    match find_boot_story(bytes) {
        Some(idx) => idx as c_int,
        None => -1,
    }
}

/// # Safety
/// `name` may be null or a valid C string.
#[no_mangle]
pub unsafe extern "C" fn yasvara_prop_synth_digest_value(name: *const c_char) -> *const c_char {
    // SAFETY: Checked inside `cstr_bytes`.
    let Some(bytes) = (unsafe { cstr_bytes(name) }) else {
        return ptr::null();
    };
    if !is_boot_digest_prop(bytes) {
        return ptr::null();
    }
    canonical_boot_digest_ptr()
}

/// # Safety
/// `name` must be a valid C string or null.
#[no_mangle]
pub unsafe extern "C" fn yasvara_cmdline_is_zygote_ffi(name: *const c_char) -> bool {
    unsafe { cstr_bytes(name) }.is_some_and(cmdline_is_zygote)
}

/// # Safety
/// `name` must be a valid C string or null.
#[no_mangle]
pub unsafe extern "C" fn yasvara_cmdline_is_placeholder_ffi(name: *const c_char) -> bool {
    unsafe { cstr_bytes(name) }.is_some_and(cmdline_is_placeholder)
}

/// # Safety
/// `name` must be a valid C string or null.
#[no_mangle]
pub unsafe extern "C" fn yasvara_cmdline_is_collector_ffi(name: *const c_char) -> bool {
    unsafe { cstr_bytes(name) }.is_some_and(cmdline_is_collector)
}

/// # Safety
/// `name` must be a valid C string or null.
#[no_mangle]
pub unsafe extern "C" fn yasvara_cmdline_is_rkp_mfg_exempt_ffi(name: *const c_char) -> bool {
    unsafe { cstr_bytes(name) }.is_some_and(cmdline_is_rkp_mfg_exempt)
}
