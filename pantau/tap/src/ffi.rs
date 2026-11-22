// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! C ABI symbols exported by `libpantau_tap` (`#![no_std]`) for framework shims.
//!
//! Each subsystem owns a static [`TapChannel`] whose `mode` atomic is directly readable from
//! `pantau_tap.h` so the disarmed path compiles to a single `ldr` + `cbz` with zero call overhead.

use core::slice;

use crate::wire::{
    BlurRec, FrameRec, InputRec, LayerDeltaRec, PresentRec, RingKind, TraceSliceRec, UiFrameRec,
};
use crate::TapChannel;

// Exported channel globals. The first field of `TapChannel<T>` is `pub mode: AtomicU32` at offset 0,
// so C/C++ headers can read `*(const _Atomic uint32_t*)&pantau_tap_<name>` directly inline.
#[no_mangle]
pub static pantau_tap_frame_ch: TapChannel<FrameRec> = TapChannel::new();
#[no_mangle]
pub static pantau_tap_ui_ch: TapChannel<UiFrameRec> = TapChannel::new();
#[no_mangle]
pub static pantau_tap_input_ch: TapChannel<InputRec> = TapChannel::new();
#[no_mangle]
pub static pantau_tap_present_ch: TapChannel<PresentRec> = TapChannel::new();
#[no_mangle]
pub static pantau_tap_scene_ch: TapChannel<LayerDeltaRec> = TapChannel::new();
#[no_mangle]
pub static pantau_tap_blur_ch: TapChannel<BlurRec> = TapChannel::new();
#[no_mangle]
pub static pantau_tap_slice_ch: TapChannel<TraceSliceRec> = TapChannel::new();

macro_rules! export_tap_fns {
    ($arm:ident, $disarm:ident, $push:ident, $ch:ident, $rec:ty, $kind:expr) => {
        /// # Safety
        /// `ring_base` must point to a valid 64-byte-aligned ring of `byte_len` bytes, and
        /// `extra_uids` (if non-null) must hold `extra_len` elements.
        #[no_mangle]
        pub unsafe extern "C" fn $arm(
            ring_base: *mut u8,
            byte_len: usize,
            mode: u32,
            extra_uids: *const u32,
            extra_len: usize,
        ) -> bool {
            let uids = if extra_uids.is_null() || extra_len == 0 {
                &[][..]
            } else {
                // SAFETY: per this function's contract.
                unsafe { slice::from_raw_parts(extra_uids, extra_len) }
            };
            // SAFETY: per this function's contract.
            unsafe { $ch.arm(ring_base, byte_len, $kind, mode, uids) }
        }

        /// Disarms the tap and returns the previously mapped pointer (safe to `munmap`).
        #[no_mangle]
        pub extern "C" fn $disarm() -> *mut u8 {
            $ch.disarm()
        }

        /// # Safety
        /// `rec` must point to a valid, readable record.
        #[no_mangle]
        #[cold]
        pub unsafe extern "C" fn $push(uid: u32, rec: *const $rec) -> bool {
            if rec.is_null() {
                return false;
            }
            // SAFETY: per this function's contract.
            $ch.push(uid, unsafe { &*rec })
        }
    };
}

export_tap_fns!(
    pantau_tap_frame_arm,
    pantau_tap_frame_disarm,
    pantau_tap_frame_push,
    pantau_tap_frame_ch,
    FrameRec,
    RingKind::Frame
);
export_tap_fns!(
    pantau_tap_ui_arm,
    pantau_tap_ui_disarm,
    pantau_tap_ui_push,
    pantau_tap_ui_ch,
    UiFrameRec,
    RingKind::UiFrame
);
export_tap_fns!(
    pantau_tap_input_arm,
    pantau_tap_input_disarm,
    pantau_tap_input_push,
    pantau_tap_input_ch,
    InputRec,
    RingKind::Input
);
export_tap_fns!(
    pantau_tap_present_arm,
    pantau_tap_present_disarm,
    pantau_tap_present_push,
    pantau_tap_present_ch,
    PresentRec,
    RingKind::Present
);
export_tap_fns!(
    pantau_tap_scene_arm,
    pantau_tap_scene_disarm,
    pantau_tap_scene_push,
    pantau_tap_scene_ch,
    LayerDeltaRec,
    RingKind::LayerDelta
);
export_tap_fns!(
    pantau_tap_blur_arm,
    pantau_tap_blur_disarm,
    pantau_tap_blur_push,
    pantau_tap_blur_ch,
    BlurRec,
    RingKind::Blur
);
export_tap_fns!(
    pantau_tap_slice_arm,
    pantau_tap_slice_disarm,
    pantau_tap_slice_push,
    pantau_tap_slice_ch,
    TraceSliceRec,
    RingKind::TraceSlice
);

/// FNV-1a 64-bit hash exposed for C++ shims hashing layer / trace names with zero alloc.
///
/// # Safety
/// `data` must hold `len` bytes (or be null when `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn pantau_tap_fnv1a64(data: *const u8, len: usize) -> u64 {
    if data.is_null() || len == 0 {
        return crate::wire::fnv1a_64(&[]);
    }
    // SAFETY: per this function's contract.
    crate::wire::fnv1a_64(unsafe { slice::from_raw_parts(data, len) })
}
