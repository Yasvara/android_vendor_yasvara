/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#define LOG_TAG "pantaud"

#include "hud.h"

#include <android-base/logging.h>
#include <android/gui/ISurfaceComposerClient.h>
#include <binder/IPCThreadState.h>
#include <gui/LayerState.h>
#include <hardware/gralloc.h>
#include <system/window.h>
#include <ui/GraphicTypes.h>
#include <ui/LayerStack.h>
#include <ui/PixelFormat.h>
#include <utils/String8.h>

#include <vector>

namespace pantau {

namespace {

using android::GraphicBuffer;
using android::OK;
using android::PIXEL_FORMAT_RGBA_8888;
using android::sp;
using android::String8;
using android::SurfaceComposerClient;
using android::SurfaceControl;
using android::gui::ISurfaceComposerClient;

// Just below WindowManagerPolicyConstants.STRICT_MODE_LAYER (1010000): above games & bars.
constexpr int32_t kHudRootLayer = 1009999;

constexpr const char* kWidgetNames[kWidgetCount] = {
        "PantauHudClassic",
        "PantauHudMini",
        "PantauHudProcs",
        "PantauHudTemp",
        "PantauHudNet",
};

constexpr uint64_t kBufferUsage = static_cast<uint64_t>(
        GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
        GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_TEXTURE);
constexpr uint32_t kLockUsage = GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN;

} // namespace

HudSurfaces::~HudSurfaces() {
    destroyAll();
}

void HudSurfaces::setParentHandle(const android::sp<android::IBinder>& parentHandle) {
    if (mParentHandle == parentHandle) return;
    mParentHandle = parentHandle;
    if (mRoot != nullptr) {
        // Recreate root cleanly under the new Display 0 Accessibility Overlays parent on next sync.
        destroyAll();
    }
}

void HudSurfaces::destroyAll() {
    bool any = (mRoot != nullptr);
    SurfaceComposerClient::Transaction t;
    std::vector<sp<SurfaceControl>> dead;
    dead.reserve(kWidgetCount + 1);
    for (auto& w : mWidgets) {
        if (w.sc != nullptr) {
            t.unsetBuffer(w.sc).hide(w.sc).reparent(w.sc, nullptr);
            dead.push_back(w.sc);
            any = true;
        }
        w.reset();
    }
    if (mRoot != nullptr) {
        t.hide(mRoot).reparent(mRoot, nullptr);
        dead.push_back(mRoot);
        mRoot.clear();
    }
    if (any) {
        t.apply();
    }
    dead.clear();
    mClient.clear();
    if (any) {
        android::IPCThreadState::self()->flushCommands();
    }
}

bool HudSurfaces::ensureRoot() {
    if (mRoot != nullptr) return true;

    mClient = sp<SurfaceComposerClient>::make();
    if (mClient->initCheck() != OK) {
        LOG(ERROR) << "SurfaceComposerClient initCheck failed";
        mClient.clear();
        return false;
    }

    bool parented = false;
    if (mParentHandle != nullptr) {
        if (mClient->createSurfaceChecked(String8("PantauHudRoot"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                          &mRoot, ISurfaceComposerClient::eFXSurfaceContainer,
                                          mParentHandle) == OK &&
            mRoot != nullptr && mRoot->isValid()) {
            parented = true;
        } else {
            LOG(WARNING) << "createSurfaceChecked under Display 0 a11y parent failed; falling back";
            mRoot.clear();
            mParentHandle.clear();
        }
    }

    if (!parented) {
        mRoot = mClient->createSurface(String8("PantauHudRoot"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                       ISurfaceComposerClient::eFXSurfaceContainer);
        if (mRoot == nullptr || !mRoot->isValid()) {
            LOG(ERROR) << "Failed to create PantauHudRoot container layer";
            mRoot.clear();
            mClient.clear();
            return false;
        }
    }

    SurfaceComposerClient::Transaction t;
    if (!parented) {
        t.setLayerStack(mRoot, android::ui::LayerStack::fromValue(0));
    }
    // Never vote in SF LayerHistory/RefreshRateSelector so 1-2 Hz HUD ticks cannot force 60 Hz!
    t.setLayer(mRoot, kHudRootLayer)
            .setTrustedOverlay(mRoot, true)
            .setFrameRateSelectionStrategy(
                    mRoot, ANATIVEWINDOW_FRAME_RATE_SELECTION_STRATEGY_OVERRIDE_CHILDREN)
            .setFrameRate(mRoot, 0.0f, ANATIVEWINDOW_FRAME_RATE_NO_VOTE,
                          ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS)
            .setFrameRateCategory(mRoot, ANATIVEWINDOW_FRAME_RATE_CATEGORY_NO_PREFERENCE, false)
            .show(mRoot)
            .apply();
    return true;
}

bool HudSurfaces::ensureWidget(uint32_t idx, const PantauHudWidgetPlan& plan,
                               SurfaceComposerClient::Transaction& t) {
    Slot& s = mWidgets[idx];
    if (s.sc == nullptr) {
        int32_t flags = ISurfaceComposerClient::eFXSurfaceBufferState |
                        ISurfaceComposerClient::eNonPremultiplied;
        if (plan.skip_screenshot) {
            flags |= ISurfaceComposerClient::eSkipScreenshot;
        }
        if (mClient->createSurfaceChecked(String8(kWidgetNames[idx]), plan.w, plan.h,
                                          PIXEL_FORMAT_RGBA_8888, &s.sc, flags,
                                          mRoot->getHandle()) != OK ||
            s.sc == nullptr) {
            LOG(ERROR) << "createSurfaceChecked failed for " << kWidgetNames[idx];
            return false;
        }
        s.skipScreenshot = plan.skip_screenshot;
        s.x = -1;
        s.y = -1;
        t.setLayer(s.sc, static_cast<int32_t>(idx + 1))
                .setTrustedOverlay(s.sc, true)
                .setFrameRate(s.sc, 0.0f, ANATIVEWINDOW_FRAME_RATE_NO_VOTE,
                              ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS)
                .setFrameRateCategory(s.sc, ANATIVEWINDOW_FRAME_RATE_CATEGORY_NO_PREFERENCE, false)
                .show(s.sc);
    }

    if (s.w != plan.w || s.h != plan.h || s.bufs[0] == nullptr || s.bufs[1] == nullptr) {
        for (uint32_t b = 0; b < 2; ++b) {
            auto gb = sp<GraphicBuffer>::make(plan.w, plan.h, HAL_PIXEL_FORMAT_RGBA_8888, 1u,
                                              kBufferUsage, kWidgetNames[idx]);
            if (gb->initCheck() != OK) {
                LOG(ERROR) << "GraphicBuffer alloc failed (" << plan.w << "x" << plan.h << ")";
                s.bufs[0].clear();
                s.bufs[1].clear();
                return false;
            }
            s.bufs[b] = std::move(gb);
        }
        s.w = plan.w;
        s.h = plan.h;
        s.nextSlot = 0;
        s.bufFresh[0] = true;
        s.bufFresh[1] = true;
    }

    if (s.skipScreenshot != plan.skip_screenshot) {
        s.skipScreenshot = plan.skip_screenshot;
        const uint32_t flag = android::layer_state_t::eLayerSkipScreenshot;
        t.setFlags(s.sc, plan.skip_screenshot ? flag : 0, flag);
    }
    return true;
}

void HudSurfaces::sync(PantauEngine* eng, bool hudVisible) {
    if (!hudVisible) {
        destroyAll();
        return;
    }

    SurfaceComposerClient::Transaction t;
    std::vector<sp<SurfaceControl>> dead;
    bool dirtyTxn = false;
    bool anyEnabled = false;

    for (uint32_t i = 0; i < kWidgetCount; ++i) {
        const PantauHudWidgetPlan plan = pantau_engine_hud_plan(eng, i);
        Slot& s = mWidgets[i];

        if (!plan.enabled || plan.w == 0 || plan.h == 0) {
            if (s.sc != nullptr) {
                t.unsetBuffer(s.sc).hide(s.sc).reparent(s.sc, nullptr);
                dead.push_back(s.sc);
                s.reset();
                dirtyTxn = true;
            }
            continue;
        }

        anyEnabled = true;
        if (!ensureRoot()) return;
        if (!ensureWidget(i, plan, t)) continue;

        if (s.x != plan.x || s.y != plan.y) {
            s.x = plan.x;
            s.y = plan.y;
            t.setPosition(s.sc, static_cast<float>(plan.x), static_cast<float>(plan.y))
                    .setFrameRate(s.sc, 0.0f, ANATIVEWINDOW_FRAME_RATE_NO_VOTE,
                                  ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS)
                    .setFrameRateCategory(
                            s.sc, ANATIVEWINDOW_FRAME_RATE_CATEGORY_NO_PREFERENCE, false);
            dirtyTxn = true;
        }

        if (plan.needs_redraw || s.bufFresh[s.nextSlot & 1u]) {
            const uint32_t slotIdx = s.nextSlot & 1u;
            const uint32_t renderFlags = slotIdx | (s.bufFresh[slotIdx] ? 0x100u : 0u);
            const sp<GraphicBuffer>& gb = s.bufs[slotIdx];
            void* vaddr = nullptr;
            if (gb->getWidth() >= plan.w && gb->getHeight() >= plan.h &&
                gb->lock(kLockUsage, &vaddr) == OK && vaddr != nullptr) {
                const uint32_t stridePx = gb->getStride();
                if (stridePx >= plan.w) {
                    const size_t byteLen =
                            static_cast<size_t>(stridePx) * static_cast<size_t>(plan.h) * 4u;
                    pantau_engine_hud_render(eng, i, static_cast<uint8_t*>(vaddr), byteLen, stridePx,
                                             renderFlags);
                }
                gb->unlock();
                s.bufFresh[slotIdx] = false;
                // Per-transaction NoVote matches SF's own RefreshRateOverlay so 1-2 Hz HUD posts
                // never trigger LayerHistory::Min (60 Hz) or QueuedTransactionState::isFrameActive!
                t.setBuffer(s.sc, gb)
                        .setDataspace(s.sc, android::ui::Dataspace::V0_SRGB)
                        .setFrameRate(s.sc, 0.0f, ANATIVEWINDOW_FRAME_RATE_NO_VOTE,
                                      ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS)
                        .setFrameRateCategory(
                                s.sc, ANATIVEWINDOW_FRAME_RATE_CATEGORY_NO_PREFERENCE, false);
                s.nextSlot = slotIdx ^ 1u;
                dirtyTxn = true;
            }
        }
    }

    if (dirtyTxn) {
        t.apply();
    }
    if (!dead.empty()) {
        dead.clear();
        android::IPCThreadState::self()->flushCommands();
    }
    if (!anyEnabled) {
        destroyAll();
    }
}

} // namespace pantau
