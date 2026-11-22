/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PANTAU_TAP_MODE_OFF   0u
#define PANTAU_TAP_MODE_ALL   0xFFFFFFFFu
#define PANTAU_TAP_MODE_MULTI 0xFFFFFFFEu

#define PANTAU_FRAME_FLAG_GPU_COMP       (1u << 0)
#define PANTAU_FRAME_FLAG_DROPPED        (1u << 1)
#define PANTAU_FRAME_FLAG_NOT_COMPOSITED (1u << 2)

#define PANTAU_UI_FLAG_DAVEY          (1u << 0)
#define PANTAU_UI_FLAG_RT_ANIM        (1u << 1)
#define PANTAU_UI_FLAG_SURFACE_CANVAS (1u << 2)

typedef struct __attribute__((aligned(64))) PantauFrameRec {
    int64_t  present_ns;
    int64_t  vsync_token;
    uint32_t uid;
    int32_t  layer_id;
    int32_t  act_start_us;
    int32_t  act_queue_us;
    int32_t  act_end_us;
    int32_t  sf_start_us;
    int32_t  sf_end_us;
    int32_t  sf_gpu_us;
    uint16_t jank_legacy;
    uint16_t jank_exp;
    uint16_t display_jank;
    uint16_t refresh_hz;
    uint16_t render_hz;
    uint16_t jank_score_x100;
    uint8_t  prediction_state;
    uint8_t  present_state;
    uint8_t  flags;
    uint8_t  _pad;
} PantauFrameRec;

typedef struct __attribute__((aligned(64))) PantauUiFrameRec {
    int64_t  vsync_id;
    int64_t  intended_vsync_ns;
    uint32_t uid;
    uint32_t pid;
    uint32_t total_us;
    uint16_t hwui_jank_bits;
    uint16_t skipped_frames;
    uint16_t vsync_delay_10us;
    uint16_t input_10us;
    uint16_t anim_10us;
    uint16_t layout_10us;
    uint16_t draw_10us;
    uint16_t sync_wait_10us;
    uint16_t sync_upload_10us;
    uint16_t rt_issue_10us;
    uint16_t dequeue_10us;
    uint16_t queue_10us;
    uint16_t gpu_10us;
    uint16_t present_delta_10us;
    uint8_t  flags;
    uint8_t  _pad[7];
} PantauUiFrameRec;

typedef struct __attribute__((aligned(32))) PantauInputRec {
    int64_t  event_ns;
    int32_t  event_id;
    uint32_t uid;
    uint32_t read_us;
    uint32_t deliver_us;
    uint32_t consume_us;
    uint16_t finish_10us;
    uint8_t  event_type;
    uint8_t  flags;
} PantauInputRec;

typedef struct __attribute__((aligned(64))) PantauPresentRec {
    int64_t  present_ns;
    uint64_t frame_idx;
    uint32_t uid;
    uint32_t cpu_frame_us;
    uint32_t acquire_wait_us;
    uint32_t present_block_us;
    uint32_t gpu_frame_us;
    uint16_t pipelines_compiled;
    uint16_t submits;
    uint16_t render_scale_permille;
    uint16_t flags;
    uint8_t  _pad[20];
} PantauPresentRec;

typedef struct __attribute__((aligned(64))) PantauLayerDeltaRec {
    int64_t  display_frame_ns;
    uint64_t name_hash;
    int32_t  layer_id;
    uint32_t uid;
    int32_t  z;
    uint32_t buffer_id_lo;
    uint32_t frame_num;
    uint32_t solid_argb;
    int16_t  left;
    int16_t  top;
    int16_t  right;
    int16_t  bottom;
    uint16_t alpha_u16;
    uint16_t corner_px;
    uint16_t bg_blur_radius;
    uint16_t flags;
    uint8_t  blur_regions;
    uint8_t  buffer_state;
    uint8_t  comp_type;
    uint8_t  delta_kind;
    uint8_t  _pad[4];
} PantauLayerDeltaRec;

typedef struct __attribute__((aligned(64))) PantauBlurRec {
    int64_t  present_ns;
    uint32_t re_cpu_us;
    uint32_t re_gpu_us;
    uint32_t blur_pass_gpu_us;
    int32_t  invalidator_layer_id;
    uint16_t blur_area_permille;
    uint16_t max_radius;
    uint16_t downscale_x100;
    uint8_t  blur_layers;
    uint8_t  passes;
    uint8_t  filter_kind;
    uint8_t  cache_hit;
    uint8_t  flattener_hit;
    uint8_t  hwc_device_layers;
    uint8_t  client_layers;
    uint8_t  sf_gpu_missed;
    uint8_t  _pad[26];
} PantauBlurRec;

typedef struct __attribute__((aligned(32))) PantauTraceSliceRec {
    int64_t  ts_ns;
    uint64_t name_hash;
    uint32_t dur_us;
    uint32_t tid;
    uint32_t uid;
    uint16_t kind;
    uint8_t  depth;
    uint8_t  flags;
} PantauTraceSliceRec;

#ifdef __cplusplus
static_assert(sizeof(PantauFrameRec) == 64, "PantauFrameRec size drift");
static_assert(sizeof(PantauUiFrameRec) == 64, "PantauUiFrameRec size drift");
static_assert(sizeof(PantauInputRec) == 32, "PantauInputRec size drift");
static_assert(sizeof(PantauPresentRec) == 64, "PantauPresentRec size drift");
static_assert(sizeof(PantauLayerDeltaRec) == 64, "PantauLayerDeltaRec size drift");
static_assert(sizeof(PantauBlurRec) == 64, "PantauBlurRec size drift");
static_assert(sizeof(PantauTraceSliceRec) == 32, "PantauTraceSliceRec size drift");
#endif

/* First 4 bytes of every TapChannel<T> is `mode: AtomicU32`. */
extern uint32_t pantau_tap_frame_ch;
extern uint32_t pantau_tap_ui_ch;
extern uint32_t pantau_tap_input_ch;
extern uint32_t pantau_tap_present_ch;
extern uint32_t pantau_tap_scene_ch;
extern uint32_t pantau_tap_blur_ch;
extern uint32_t pantau_tap_slice_ch;

static inline bool pantau_tap_fast_armed(const uint32_t* mode_word, uint32_t uid) {
    uint32_t m = __atomic_load_n(mode_word, __ATOMIC_RELAXED);
    return __builtin_expect(
            m != PANTAU_TAP_MODE_OFF &&
            (m == uid || m >= PANTAU_TAP_MODE_MULTI), 0);
}

#define pantau_tap_frame_armed(uid)   pantau_tap_fast_armed(&pantau_tap_frame_ch, (uid))
#define pantau_tap_ui_armed(uid)      pantau_tap_fast_armed(&pantau_tap_ui_ch, (uid))
#define pantau_tap_input_armed(uid)   pantau_tap_fast_armed(&pantau_tap_input_ch, (uid))
#define pantau_tap_present_armed(uid) pantau_tap_fast_armed(&pantau_tap_present_ch, (uid))
#define pantau_tap_scene_armed()      (__builtin_expect(__atomic_load_n(&pantau_tap_scene_ch, __ATOMIC_RELAXED) != 0u, 0))
#define pantau_tap_blur_armed()       (__builtin_expect(__atomic_load_n(&pantau_tap_blur_ch, __ATOMIC_RELAXED) != 0u, 0))
#define pantau_tap_slice_armed(uid)   pantau_tap_fast_armed(&pantau_tap_slice_ch, (uid))

bool  pantau_tap_frame_arm(uint8_t* ring, size_t len, uint32_t mode, const uint32_t* extra, size_t extra_len);
void* pantau_tap_frame_disarm(void);
bool  pantau_tap_frame_push(uint32_t uid, const PantauFrameRec* rec);

bool  pantau_tap_ui_arm(uint8_t* ring, size_t len, uint32_t mode, const uint32_t* extra, size_t extra_len);
void* pantau_tap_ui_disarm(void);
bool  pantau_tap_ui_push(uint32_t uid, const PantauUiFrameRec* rec);

bool  pantau_tap_input_arm(uint8_t* ring, size_t len, uint32_t mode, const uint32_t* extra, size_t extra_len);
void* pantau_tap_input_disarm(void);
bool  pantau_tap_input_push(uint32_t uid, const PantauInputRec* rec);

bool  pantau_tap_present_arm(uint8_t* ring, size_t len, uint32_t mode, const uint32_t* extra, size_t extra_len);
void* pantau_tap_present_disarm(void);
bool  pantau_tap_present_push(uint32_t uid, const PantauPresentRec* rec);

bool  pantau_tap_scene_arm(uint8_t* ring, size_t len, uint32_t mode, const uint32_t* extra, size_t extra_len);
void* pantau_tap_scene_disarm(void);
bool  pantau_tap_scene_push(uint32_t uid, const PantauLayerDeltaRec* rec);

bool  pantau_tap_blur_arm(uint8_t* ring, size_t len, uint32_t mode, const uint32_t* extra, size_t extra_len);
void* pantau_tap_blur_disarm(void);
bool  pantau_tap_blur_push(uint32_t uid, const PantauBlurRec* rec);

bool  pantau_tap_slice_arm(uint8_t* ring, size_t len, uint32_t mode, const uint32_t* extra, size_t extra_len);
void* pantau_tap_slice_disarm(void);
bool  pantau_tap_slice_push(uint32_t uid, const PantauTraceSliceRec* rec);

uint64_t pantau_tap_fnv1a64(const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif
