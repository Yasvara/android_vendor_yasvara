// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! C ABI for `netd`, `libnetd_resolv` and JNI.
//!
//! Every struct crossing the boundary is `#[repr(C)]`. Pointers come from C/C++ and are valid for
//! the call; `saring_dns_ops()` hands a static table across the `com.android.tethering` APEX seam
//! once at resolver startup.

use crate::clean::clean_url;
use crate::state::Controller;
use crate::Names;
use core::slice;
use std::ffi::{c_char, CStr};

/// Magic value passed in `android_net_context.{app_netid, uid}` during `resolv_init` to claim
/// `SaringDnsOps` without changing `ResolverNetdCallbacks` or `libnetd_resolv.map.txt`.
pub const SARING_OPS_MAGIC: u32 = 0x5352_4E47; // "SRNG"

/// Function-pointer table handed from `netd` into `libnetd_resolv.so` once at startup.
#[repr(C)]
pub struct SaringDnsOps {
    pub version: u32,
    pub resolve: unsafe extern "C" fn(
        netid: u32,
        mark: u32,
        uid: u32,
        flags: u32,
        query: *const u8,
        query_len: usize,
        answer: *mut u8,
        answer_cap: usize,
        rcode: *mut i32,
    ) -> isize,
    pub inspect_answer: unsafe extern "C" fn(
        netid: u32,
        mark: u32,
        query: *const u8,
        query_len: usize,
        answer: *mut u8,
        answer_len: usize,
        answer_cap: usize,
        rcode: *mut i32,
    ) -> isize,
    pub flush_net: extern "C" fn(netid: u32),
}

static DNS_OPS: SaringDnsOps = SaringDnsOps {
    version: 1,
    resolve: saring_dns_resolve,
    inspect_answer: saring_dns_inspect_answer,
    flush_net: saring_dns_flush_net,
};

#[no_mangle]
pub extern "C" fn saring_dns_ops() -> *const SaringDnsOps {
    &DNS_OPS
}

#[no_mangle]
pub extern "C" fn saring_init() {
    Controller::global().init();
}

/// Evaluates whether a lookup from `uid` for NUL-terminated `name` is allowed (`true` = allowed,
/// `false` = refused, matching `evaluate_domain_name_callback`).
///
/// # Safety
/// `name` is null or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn saring_evaluate_domain(uid: u32, name: *const c_char) -> bool {
    if name.is_null() {
        return true;
    }
    // SAFETY: per this function's contract.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    !Controller::global().is_blocked(uid, bytes)
}

/// Attempts to answer a DNS wire query via Saring's filter, SafeSearch synthesizer, 16-shard
/// Serve-Stale cache, or coalesced DoT upstream. Returns `>= 0` bytes written into `answer`, or
/// `-1` to fall through to AOSP's resolver.
///
/// # Safety
/// `query` holds `query_len` bytes; `answer` is writable for `answer_cap` bytes; `rcode` is
/// non-null and writable.
#[no_mangle]
pub unsafe extern "C" fn saring_dns_resolve(
    netid: u32,
    mark: u32,
    uid: u32,
    flags: u32,
    query: *const u8,
    query_len: usize,
    answer: *mut u8,
    answer_cap: usize,
    rcode: *mut i32,
) -> isize {
    if query.is_null() || answer.is_null() || rcode.is_null() || query_len < 12 || answer_cap < 12
    {
        return -1;
    }
    // SAFETY: per this function's contract.
    let q = unsafe { slice::from_raw_parts(query, query_len) };
    // SAFETY: per this function's contract.
    let ans = unsafe { slice::from_raw_parts_mut(answer, answer_cap) };
    match Controller::global().resolve_dns(netid, mark, uid, flags, q, ans) {
        Some((len, rc)) => {
            // SAFETY: per this function's contract.
            unsafe { *rcode = rc };
            len as isize
        }
        None => -1,
    }
}

/// Inspects a plaintext UDP/53 answer for ISP sinkhole / `TTL=0` / unrequested SafeSearch VIP
/// poisoning, retrying over encrypted DoT if poisoned. Returns final byte length in `answer`.
///
/// # Safety
/// `query` holds `query_len` bytes; `answer` holds `answer_len <= answer_cap` bytes and is
/// writable up to `answer_cap`; `rcode` is non-null and writable.
#[no_mangle]
pub unsafe extern "C" fn saring_dns_inspect_answer(
    netid: u32,
    mark: u32,
    query: *const u8,
    query_len: usize,
    answer: *mut u8,
    answer_len: usize,
    answer_cap: usize,
    rcode: *mut i32,
) -> isize {
    if query.is_null()
        || answer.is_null()
        || rcode.is_null()
        || query_len < 12
        || answer_len < 12
        || answer_len > answer_cap
    {
        return answer_len as isize;
    }
    // SAFETY: per this function's contract.
    let q = unsafe { slice::from_raw_parts(query, query_len) };
    // SAFETY: per this function's contract.
    let ans = unsafe { slice::from_raw_parts_mut(answer, answer_cap) };
    // SAFETY: per this function's contract.
    let rc = unsafe { &mut *rcode };
    Controller::global().inspect_plaintext_answer(netid, mark, q, ans, answer_len, rc)
}

#[no_mangle]
pub extern "C" fn saring_dns_flush_net(netid: u32) {
    Controller::global().flush_net(netid);
}

#[no_mangle]
pub extern "C" fn saring_on_network_change(netid: u32, force: bool) {
    Controller::global().on_default_network_change(netid, force);
}

#[no_mangle]
pub extern "C" fn saring_begin() -> bool {
    Controller::global().begin()
}

/// # Safety
/// `chunk` holds `len` readable bytes (or `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn saring_append(chunk: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    if chunk.is_null() {
        return false;
    }
    // SAFETY: per this function's contract.
    Controller::global().append(unsafe { slice::from_raw_parts(chunk, len) })
}

#[no_mangle]
pub extern "C" fn saring_commit() -> i64 {
    Controller::global().commit()
}

/// # Safety
/// `exempt_ids` holds `exempt_len` readable `i32`s (or `exempt_len == 0`).
#[no_mangle]
pub unsafe extern "C" fn saring_configure(
    enabled: bool,
    exempt_ids: *const i32,
    exempt_len: usize,
    pause_seconds: i32,
) {
    let ids = if exempt_ids.is_null() || exempt_len == 0 {
        &[]
    } else {
        // SAFETY: per this function's contract.
        unsafe { slice::from_raw_parts(exempt_ids, exempt_len) }
    };
    Controller::global().configure(enabled, ids, pause_seconds);
}

/// # Safety
/// `blocked_ids` holds `blocked_len` readable `i32`s (or `blocked_len == 0`).
#[no_mangle]
pub unsafe extern "C" fn saring_set_options(
    dns_mode: u8,
    safesearch: u8,
    blocked_ids: *const i32,
    blocked_len: usize,
) {
    let ids = if blocked_ids.is_null() || blocked_len == 0 {
        &[]
    } else {
        // SAFETY: per this function's contract.
        unsafe { slice::from_raw_parts(blocked_ids, blocked_len) }
    };
    Controller::global().set_options(dns_mode, safesearch, ids);
}

/// Writes up to `cap` counters (`[checked, refused, entries, created, cache_hits, poison_blocked]`)
/// into `out` and returns how many were written.
///
/// # Safety
/// `out` is writable for `cap` `i64` elements.
#[no_mangle]
pub unsafe extern "C" fn saring_stats(out: *mut i64, cap: usize) -> usize {
    if out.is_null() || cap == 0 {
        return 0;
    }
    let stats = Controller::global().stats();
    let n = cap.min(stats.len());
    // SAFETY: per this function's contract.
    unsafe { slice::from_raw_parts_mut(out, n) }.copy_from_slice(&stats[..n]);
    n
}

/// Writes newline-separated refusal log entries into `out` (NUL-terminated when `cap > 0`).
/// Returns the byte length written (excluding NUL).
///
/// # Safety
/// `out` is writable for `cap` bytes (or `cap == 0`).
#[no_mangle]
pub unsafe extern "C" fn saring_log(clear: bool, out: *mut u8, cap: usize) -> usize {
    let lines = Controller::global().log(clear);
    if out.is_null() || cap == 0 {
        return 0;
    }
    // SAFETY: per this function's contract.
    let buf = unsafe { slice::from_raw_parts_mut(out, cap) };
    let mut w = 0usize;
    let max_write = cap - 1;
    for (i, line) in lines.iter().enumerate() {
        let need = line.len() + usize::from(i > 0);
        if w + need > max_write {
            break;
        }
        if i > 0 {
            buf[w] = b'\n';
            w += 1;
        }
        buf[w..w + line.len()].copy_from_slice(line.as_bytes());
        w += line.len();
    }
    buf[w] = 0;
    w
}

/// Unwraps Google click-tracker redirects and strips tracking query parameters into `out`.
/// Returns written bytes when changed, or 0 when `url` is unchanged or invalid.
///
/// # Safety
/// `url` holds `url_len` bytes; `out` is writable for `out_cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn saring_clean_url(
    url: *const u8,
    url_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> usize {
    if url.is_null() || out.is_null() || url_len == 0 || out_cap == 0 {
        return 0;
    }
    // SAFETY: per this function's contract.
    let src = unsafe { slice::from_raw_parts(url, url_len) };
    // SAFETY: per this function's contract.
    let dst = unsafe { slice::from_raw_parts_mut(out, out_cap) };
    clean_url(src, dst).unwrap_or(0)
}

/// Entry count of a blob that passes the full check, or -1.
///
/// # Safety
/// `blob` must point at `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn saring_check(blob: *const u8, len: usize) -> i64 {
    if blob.is_null() {
        return -1;
    }
    // SAFETY: per this function's contract.
    Names::open(unsafe { slice::from_raw_parts(blob, len) }).map_or(-1, |n| n.len() as i64)
}

/// Whether the resolver must refuse `name`. The blob must have passed `saring_check`.
///
/// # Safety
/// Both pointers must be readable for their lengths.
#[no_mangle]
pub unsafe extern "C" fn saring_name_blocked(
    blob: *const u8,
    len: usize,
    name: *const u8,
    name_len: usize,
) -> bool {
    if blob.is_null() || name.is_null() {
        return false;
    }
    // SAFETY: per this function's contract.
    Names::view(unsafe { slice::from_raw_parts(blob, len) })
        .is_some_and(|n| n.blocked(unsafe { slice::from_raw_parts(name, name_len) }))
}

/// Whether a web layer must refuse a request for `url` made by a page on `page`.
///
/// # Safety
/// All pointers must be readable for their lengths.
#[no_mangle]
pub unsafe extern "C" fn saring_request_blocked(
    blob: *const u8,
    len: usize,
    url: *const u8,
    url_len: usize,
    page: *const u8,
    page_len: usize,
    navigation: bool,
) -> bool {
    if blob.is_null() || url.is_null() || page.is_null() {
        return false;
    }
    // SAFETY: per this function's contract.
    Names::view(unsafe { slice::from_raw_parts(blob, len) }).is_some_and(|n| {
        n.request_blocked(
            // SAFETY: per this function's contract.
            unsafe { slice::from_raw_parts(url, url_len) },
            // SAFETY: per this function's contract.
            unsafe { slice::from_raw_parts(page, page_len) },
            navigation,
        )
    })
}
