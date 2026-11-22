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

typedef struct PantauEngine PantauEngine;

typedef struct PantauLifeActions {
    uint8_t  state;
    uint32_t timer_ms;
    bool     hud_visible;
    bool     allow_exit;
    bool     disarm_taps;
    uint64_t active_consumers;
    int32_t  focused_task_id;
    uint32_t focused_uid;
} PantauLifeActions;

typedef struct PantauHudWidgetPlan {
    bool     enabled;
    bool     needs_resize;
    bool     needs_redraw;
    bool     skip_screenshot;
    uint32_t w;
    uint32_t h;
    int32_t  x;
    int32_t  y;
} PantauHudWidgetPlan;

PantauEngine*       pantau_engine_new(bool tune_thread);
void                pantau_engine_free(PantauEngine* eng);
int32_t             pantau_engine_snapshot_fd(const PantauEngine* eng);
PantauLifeActions   pantau_engine_configure(PantauEngine* eng, const uint8_t* profile, size_t len);
PantauLifeActions   pantau_engine_session(PantauEngine* eng, int32_t task_id, int32_t uid, bool is_game);
PantauLifeActions   pantau_engine_set_consumers(PantauEngine* eng, uint64_t consumers);
void                pantau_engine_on_fps(PantauEngine* eng, uint16_t fps_x100);
PantauLifeActions   pantau_engine_on_event(PantauEngine* eng, uint32_t kind, int64_t a, int64_t b);
PantauLifeActions   pantau_engine_tick(PantauEngine* eng);
size_t              pantau_engine_query(PantauEngine* eng, const uint8_t* cmd, size_t cmd_len,
                                        uint8_t* out_buf, size_t out_cap);
void                pantau_engine_display_changed(PantauEngine* eng, uint8_t rotation,
                                                  uint32_t width_px, uint32_t height_px,
                                                  uint16_t refresh_hz);
void                pantau_engine_set_monet(PantauEngine* eng, const uint32_t* argb4);
void                pantau_engine_move_widget(PantauEngine* eng, uint32_t widget_idx, int32_t x, int32_t y);
PantauHudWidgetPlan pantau_engine_hud_plan(PantauEngine* eng, uint32_t widget_idx);
uint32_t            pantau_engine_hud_render(PantauEngine* eng, uint32_t widget_idx, uint8_t* dst,
                                             size_t dst_len, uint32_t stride_px, uint32_t slot_idx);
void                pantau_engine_ensure_snapshot(PantauEngine* eng);
bool                pantau_engine_put_uid_meta(PantauEngine* eng, uint32_t uid,
                                               const uint8_t* label, size_t label_len,
                                               const uint8_t* rgba, size_t rgba_len);
bool                pantau_engine_push_net_meta(PantauEngine* eng, uint8_t link_mask,
                                                uint8_t wifi_std, uint16_t wifi_freq_mhz,
                                                uint16_t wifi_link_mbps, int16_t wifi_rssi_dbm,
                                                uint8_t cell_gen, uint8_t cell_level,
                                                int16_t cell_rsrp_dbm);

#ifdef __cplusplus
}
#endif
