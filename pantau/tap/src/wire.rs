// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Cache-line-aligned `#[repr(C)]` PODs shared across framework taps and `pantaud`.
//!
//! Every record size is locked at compile time so C++, Rust and Jejak share one binary layout.

use core::mem::{align_of, size_of};
use core::sync::atomic::AtomicU32;

/// Magic header for all Pantau SPSC tap rings ("PNTR" little-endian).
pub const RING_MAGIC: u32 = 0x5254_4E50;
pub const RING_VERSION: u16 = 1;

/// Ring payload discriminant stored in [`RingHeader::kind`].
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingKind {
    Frame = 1,
    UiFrame = 2,
    Input = 3,
    Present = 4,
    LayerDelta = 5,
    Blur = 6,
    TraceSlice = 7,
}

/// Lock-free SPSC ring header (128 bytes = 2 cache lines).
///
/// Producer writes `tail` & `drops` on cache line 0; consumer updates `head` on cache line 1.
/// Keeping them on separate 64-byte lines eliminates cache-line bouncing between producer cores
/// (SurfaceFlinger / InputFlinger / HWUI) and `pantaud` pinned to the efficiency cluster.
#[repr(C, align(64))]
pub struct RingHeader {
    // ── Cache line 0: read-mostly metadata + producer-owned cursors ──
    pub magic: u32,
    pub version: u16,
    pub kind: u16,
    pub cap: u32,  // power-of-two slot count
    pub mask: u32, // cap - 1
    pub tail: AtomicU32,
    pub drops: AtomicU32,
    pub elem_size: u32,
    pub _pad0: [u8; 36],

    // ── Cache line 1: consumer-owned cursor ──
    pub head: AtomicU32,
    pub flags: AtomicU32,
    pub _pad1: [u8; 56],
}

/// SurfaceFlinger per-frame record (64 B = 1 cache line).
///
/// Captures both Choreographer-predicted frames (`PredictionState::Valid`) and native Vulkan/GLES
/// game frames (`PredictionState::None` A1) plus `DisplayFrame` timestamps.
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameRec {
    pub present_ns: i64,
    pub vsync_token: i64,
    pub uid: u32,
    pub layer_id: i32,
    // Microsecond deltas relative to `present_ns` (negative = earlier than present).
    pub act_start_us: i32,
    pub act_queue_us: i32,
    pub act_end_us: i32, // acquire fence signal
    pub sf_start_us: i32,
    pub sf_end_us: i32,
    pub sf_gpu_us: i32, // DisplayFrame GPU fence
    pub jank_legacy: u16,
    pub jank_exp: u16,
    pub display_jank: u16,
    pub refresh_hz: u16,
    pub render_hz: u16,
    pub jank_score_x100: u16,
    pub prediction_state: u8, // 0=None, 1=Valid, 2=Expired
    pub present_state: u8,    // 0=Unknown, 1=Presented, 2=Dropped, 3=Early
    pub flags: u8,            // bit0=gpu_composition, bit1=dropped, bit2=not_composited
    pub _pad: u8,
}

pub const FRAME_FLAG_GPU_COMP: u8 = 1 << 0;
pub const FRAME_FLAG_DROPPED: u8 = 1 << 1;
pub const FRAME_FLAG_NOT_COMPOSITED: u8 = 1 << 2;

/// HWUI 25-stage UI frame record (64 B = 1 cache line).
///
/// Joins 1:1 with [`FrameRec`] via `vsync_id == vsync_token`.
/// Individual stage durations are encoded in 10 µs units (`0..655.35 ms`, saturating) while
/// `total_us` keeps exact microsecond resolution up to 4294 s (for Daveys).
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UiFrameRec {
    pub vsync_id: i64,
    pub intended_vsync_ns: i64,
    pub uid: u32,
    pub pid: u32,
    pub total_us: u32,
    pub hwui_jank_bits: u16,
    pub skipped_frames: u16,
    // Stage durations in 10 µs units (0.01 ms resolution, saturating at u16::MAX).
    pub vsync_delay_10us: u16,
    pub input_10us: u16,
    pub anim_10us: u16,
    pub layout_10us: u16,
    pub draw_10us: u16,
    pub sync_wait_10us: u16,
    pub sync_upload_10us: u16,
    pub rt_issue_10us: u16,
    pub dequeue_10us: u16,
    pub queue_10us: u16,
    pub gpu_10us: u16,
    pub present_delta_10us: u16,
    pub flags: u8, // bit0=davey, bit1=rt_anim, bit2=surface_canvas
    pub _pad: [u8; 7],
}

pub const UI_FLAG_DAVEY: u8 = 1 << 0;
pub const UI_FLAG_RT_ANIM: u8 = 1 << 1;
pub const UI_FLAG_SURFACE_CANVAS: u8 = 1 << 2;

/// Immediate InputDispatcher completion record (32 B = half cache line A2).
#[repr(C, align(32))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct InputRec {
    pub event_ns: i64,
    pub event_id: i32,
    pub uid: u32,
    pub read_us: u32,    // readTime - eventTime
    pub deliver_us: u32, // deliveryTime - eventTime
    pub consume_us: u32, // consumeTime - deliveryTime
    pub finish_10us: u16, // (finishTime - consumeTime) / 10 µs
    pub event_type: u8,  // 0=other, 1=touch_down, 2=touch_move, 3=touch_up, 4=key
    pub flags: u8,       // bit0=slow_event, bit1=has_gfx_present
}

/// Optional `framefx` present-hook record (64 B = 1 cache line, armed games only).
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PresentRec {
    pub present_ns: i64,
    pub frame_idx: u64,
    pub uid: u32,
    pub cpu_frame_us: u32,
    pub acquire_wait_us: u32,
    pub present_block_us: u32,
    pub gpu_frame_us: u32,
    pub pipelines_compiled: u16,
    pub submits: u16,
    pub render_scale_permille: u16,
    pub flags: u16, // bit0=luwes_generated, bit1=vulkan, bit2=gles
    pub _pad: [u8; 20],
}

/// Per-frame SurfaceFlinger layer/scene diff record (64 B = 1 cache line, `--scene`).
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LayerDeltaRec {
    pub display_frame_ns: i64,
    pub name_hash: u64, // FNV-1a 64-bit of layer name
    pub layer_id: i32,
    pub uid: u32,
    pub z: i32,
    pub buffer_id_lo: u32,
    pub frame_num: u32,
    pub solid_argb: u32,
    pub left: i16,
    pub top: i16,
    pub right: i16,
    pub bottom: i16,
    pub alpha_u16: u16, // 0..65535
    pub corner_px: u16,
    pub bg_blur_radius: u16,
    pub flags: u16,
    pub blur_regions: u8,
    pub buffer_state: u8, // 0=None, 1=SolidColor, 2=Buffer
    pub comp_type: u8,    // 0=Device, 1=Client, 2=Solid
    pub delta_kind: u8,   // 0=Added, 1=Changed, 2=Removed
    pub _pad: [u8; 4],
}

/// RenderEngine realtime blur & composition profiler record (64 B = 1 cache line, `--blur`).
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BlurRec {
    pub present_ns: i64,
    pub re_cpu_us: u32,
    pub re_gpu_us: u32,
    pub blur_pass_gpu_us: u32,
    pub invalidator_layer_id: i32,
    pub blur_area_permille: u16,
    pub max_radius: u16,
    pub downscale_x100: u16,
    pub blur_layers: u8,
    pub passes: u8,
    pub filter_kind: u8, // 0=none, 1=kawase_dual_v2, 2=gaussian, 3=custom_vibrancy
    pub cache_hit: u8,
    pub flattener_hit: u8,
    pub hwc_device_layers: u8,
    pub client_layers: u8,
    pub sf_gpu_missed: u8,
    pub _pad: [u8; 26],
}

/// Executed-code trace slice record (32 B, `--trace-code`).
#[repr(C, align(32))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TraceSliceRec {
    pub ts_ns: i64,
    pub name_hash: u64,
    pub dur_us: u32,
    pub tid: u32,
    pub uid: u32,
    pub kind: u16,
    pub depth: u8,
    pub flags: u8,
}

/// FNV-1a 64-bit hash for layer/section names (no allocation, deterministic across host/device).
#[inline(always)]
pub const fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
        i += 1;
    }
    h
}

/// Total mapped byte size required for a ring of `cap` slots of `T`.
/// Returns `None` if `cap` is not a power of two or overflows.
#[inline]
pub const fn ring_byte_size<T>(cap: u32) -> Option<usize> {
    if cap == 0 || (cap & (cap - 1)) != 0 {
        return None;
    }
    let slots = match (cap as usize).checked_mul(size_of::<T>()) {
        Some(v) => v,
        None => return None,
    };
    size_of::<RingHeader>().checked_add(slots)
}

// Compile-time layout locks.
const _: () = assert!(size_of::<RingHeader>() == 128);
const _: () = assert!(align_of::<RingHeader>() == 64);
const _: () = assert!(size_of::<FrameRec>() == 64);
const _: () = assert!(size_of::<UiFrameRec>() == 64);
const _: () = assert!(size_of::<InputRec>() == 32);
const _: () = assert!(size_of::<PresentRec>() == 64);
const _: () = assert!(size_of::<LayerDeltaRec>() == 64);
const _: () = assert!(size_of::<BlurRec>() == 64);
const _: () = assert!(size_of::<TraceSliceRec>() == 32);
