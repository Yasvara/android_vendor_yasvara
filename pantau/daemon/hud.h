/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <array>
#include <cstdint>

#include <binder/IBinder.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/SurfaceControl.h>
#include <ui/GraphicBuffer.h>
#include <utils/StrongPointer.h>

#include "pantau_core.h"

namespace pantau {

constexpr uint32_t kWidgetCount = 5;

/**
 * Thin C++ SurfaceFlinger HUD surface owner.
 *
 * Rust (`pantau_engine_hud_plan` / `pantau_engine_hud_render`) owns all layout, dirty checks,
 * and ARMv9 NEON blitting. This class only manages `SurfaceComposerClient`, 5 child buffer-state
 * layers, and 2 ping-pong `GraphicBuffer`s per active widget (no BLASTBufferQueue, NoVote).
 */
class HudSurfaces {
public:
    HudSurfaces() = default;
    ~HudSurfaces();

    /** Sets Display 0 Accessibility Overlays handle so scrcpy & screenshots mirror HUD layers. */
    void setParentHandle(const android::sp<android::IBinder>& parentHandle);

    /** Reconciles all 5 widgets with Rust plans and commits one coalesced SF Transaction. */
    void sync(PantauEngine* eng, bool hudVisible);

    /** Destroys root & all widget layers + frees all GraphicBuffers (0 VRAM when hidden/off). */
    void destroyAll();

private:
    struct Slot {
        android::sp<android::SurfaceControl> sc;
        std::array<android::sp<android::GraphicBuffer>, 2> bufs;
        uint32_t w = 0;
        uint32_t h = 0;
        int32_t x = -1;
        int32_t y = -1;
        bool skipScreenshot = false;
        uint32_t nextSlot = 0;
        bool bufFresh[2] = {true, true};

        void reset() {
            bufs[0].clear();
            bufs[1].clear();
            sc.clear();
            w = h = 0;
            x = y = -1;
            nextSlot = 0;
            bufFresh[0] = bufFresh[1] = true;
        }
    };

    bool ensureRoot();
    bool ensureWidget(uint32_t idx, const PantauHudWidgetPlan& plan,
                      android::SurfaceComposerClient::Transaction& t);

    android::sp<android::IBinder> mParentHandle;
    android::sp<android::SurfaceComposerClient> mClient;
    android::sp<android::SurfaceControl> mRoot;
    std::array<Slot, kWidgetCount> mWidgets;
};

} // namespace pantau
