// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Thin C ABI for `daemon/main.cpp`.
//!
//! Every `pub unsafe extern "C" fn` validates null pointers and lengths before creating slices.

use core::slice;

use crate::hud::layout::HudWidgetPlan;
use crate::life::LifeActions;
use crate::Engine;

/// Creates and initializes a new Pantau [`Engine`], pinning the thread to the efficiency cluster
/// when `tune_thread` is true. Returns null on failure.
#[no_mangle]
pub extern "C" fn pantau_engine_new(tune_thread: bool) -> *mut Engine {
    match Engine::new(tune_thread) {
        Some(eng) => Box::into_raw(Box::new(eng)),
        None => core::ptr::null_mut(),
    }
}

/// # Safety
/// `eng` must be a pointer returned by [`pantau_engine_new`] (or null).
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_free(eng: *mut Engine) {
    if !eng.is_null() {
        // SAFETY: per this function's contract.
        unsafe { drop(Box::from_raw(eng)) };
    }
}

/// # Safety
/// `eng` must be a valid [`Engine`] pointer.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_snapshot_fd(eng: *const Engine) -> i32 {
    if eng.is_null() {
        return -1;
    }
    // SAFETY: per this function's contract.
    unsafe { &*eng }.snapshot_fd()
}

/// # Safety
/// `eng` must be valid; `profile` must hold `len` bytes (or be null when `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_configure(
    eng: *mut Engine,
    profile: *const u8,
    len: usize,
) -> LifeActions {
    if eng.is_null() {
        return LifeActions::default();
    }
    let bytes = if profile.is_null() || len == 0 {
        &[][..]
    } else {
        // SAFETY: per this function's contract.
        unsafe { slice::from_raw_parts(profile, len) }
    };
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.configure(bytes)
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_session(
    eng: *mut Engine,
    task_id: i32,
    uid: i32,
    is_game: bool,
) -> LifeActions {
    if eng.is_null() {
        return LifeActions::default();
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.on_session(task_id, uid, is_game)
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_set_consumers(
    eng: *mut Engine,
    consumers: u64,
) -> LifeActions {
    if eng.is_null() {
        return LifeActions::default();
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.set_panel_consumers(consumers)
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_on_fps(eng: *mut Engine, fps_x100: u16) {
    if eng.is_null() {
        return;
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.on_fps(fps_x100);
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_on_event(
    eng: *mut Engine,
    kind: u32,
    a: i64,
    b: i64,
) -> LifeActions {
    if eng.is_null() {
        return LifeActions::default();
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.on_event(kind, a, b)
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_tick(eng: *mut Engine) -> LifeActions {
    if eng.is_null() {
        return LifeActions::default();
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.tick()
}

/// Copies a JSON query result into `out_buf` (`out_cap` bytes). Returns bytes written.
///
/// # Safety
/// `eng` must be valid; `cmd` holds `cmd_len` bytes; `out_buf` is writable for `out_cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_query(
    eng: *mut Engine,
    cmd: *const u8,
    cmd_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
) -> usize {
    if eng.is_null() || cmd.is_null() || out_buf.is_null() || out_cap == 0 {
        return 0;
    }
    // SAFETY: per this function's contract.
    let cmd_bytes = unsafe { slice::from_raw_parts(cmd, cmd_len) };
    // SAFETY: per this function's contract.
    let out = unsafe { slice::from_raw_parts_mut(out_buf, out_cap) };
    // SAFETY: per this function's contract.
    let res = unsafe { &mut *eng }.query_json(cmd_bytes);
    let n = res.len().min(out_cap);
    out[..n].copy_from_slice(&res[..n]);
    n
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_display_changed(
    eng: *mut Engine,
    rotation: u8,
    width_px: u32,
    height_px: u32,
    refresh_hz: u16,
) {
    if eng.is_null() {
        return;
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.display_changed(rotation, width_px, height_px, refresh_hz);
}

/// # Safety
/// `eng` must be valid; `argb4` must point to 4 `u32` ARGB values.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_set_monet(eng: *mut Engine, argb4: *const u32) {
    if eng.is_null() || argb4.is_null() {
        return;
    }
    // SAFETY: per this function's contract.
    let s = unsafe { slice::from_raw_parts(argb4, 4) };
    let vals = [s[0], s[1], s[2], s[3]];
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.set_monet(&vals);
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_move_widget(
    eng: *mut Engine,
    widget_idx: u32,
    x: i32,
    y: i32,
) {
    if eng.is_null() {
        return;
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.move_widget(widget_idx as usize, x, y);
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_hud_plan(eng: *mut Engine, widget_idx: u32) -> HudWidgetPlan {
    if eng.is_null() {
        return HudWidgetPlan::default();
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.hud_plan(widget_idx as usize)
}

/// # Safety
/// `eng` must be valid; `dst` must be writable for `dst_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_hud_render(
    eng: *mut Engine,
    widget_idx: u32,
    dst: *mut u8,
    dst_len: usize,
    stride_px: u32,
    slot_idx: u32,
) -> u32 {
    if eng.is_null() || dst.is_null() || dst_len == 0 {
        return 0;
    }
    // SAFETY: per this function's contract.
    let buf = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.hud_render(widget_idx as usize, buf, stride_px as usize, slot_idx as usize)
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_ensure_snapshot(eng: *mut Engine) {
    if eng.is_null() {
        return;
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.ensure_fresh_snapshot();
}

/// # Safety
/// `eng` must be valid; `label`/`rgba` must be valid for `label_len`/`rgba_len` bytes (or null when 0).
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_put_uid_meta(
    eng: *mut Engine,
    uid: u32,
    label: *const u8,
    label_len: usize,
    rgba: *const u8,
    rgba_len: usize,
) -> bool {
    if eng.is_null() {
        return false;
    }
    let lbl = if label.is_null() || label_len == 0 {
        &[][..]
    } else {
        // SAFETY: per this function's contract.
        unsafe { slice::from_raw_parts(label, label_len) }
    };
    let px = if rgba.is_null() || rgba_len == 0 {
        &[][..]
    } else {
        // SAFETY: per this function's contract.
        unsafe { slice::from_raw_parts(rgba, rgba_len) }
    };
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.put_uid_meta(uid, lbl, px)
}

/// # Safety
/// `eng` must be valid.
#[no_mangle]
pub unsafe extern "C" fn pantau_engine_push_net_meta(
    eng: *mut Engine,
    link_mask: u8,
    wifi_standard: u8,
    wifi_freq_mhz: u16,
    wifi_link_mbps: u16,
    wifi_rssi_dbm: i16,
    cell_gen: u8,
    cell_level: u8,
    cell_rsrp_dbm: i16,
) -> bool {
    if eng.is_null() {
        return false;
    }
    // SAFETY: per this function's contract.
    unsafe { &mut *eng }.push_net_meta(
        link_mask,
        wifi_standard,
        wifi_freq_mhz,
        wifi_link_mbps,
        wifi_rssi_dbm,
        cell_gen,
        cell_level,
        cell_rsrp_dbm,
    )
}
