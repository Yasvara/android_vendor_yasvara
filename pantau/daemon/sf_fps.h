/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <cstdint>
#include <functional>

#include <android/gui/BnFpsListener.h>
#include <utils/StrongPointer.h>

namespace pantau {

/**
 * Native SurfaceFlinger FPS listener (`addFpsListener` / `removeFpsListener`) owned by `pantaud`.
 *
 * Works independently of `org.yasvara.pentas:ui` so pinned HUDs keep tracking the focused task's
 * FPS after leaving a game.
 */
class SfFpsTracker {
public:
    using Callback = std::function<void(uint16_t fpsX100)>;

    explicit SfFpsTracker(Callback cb);
    ~SfFpsTracker();

    /** Registers for `taskId` when `active && taskId >= 0`; unregisters otherwise. */
    void sync(int32_t taskId, bool active);

private:
    class Listener final : public android::gui::BnFpsListener {
    public:
        explicit Listener(Callback cb) : mCb(std::move(cb)) {}
        android::binder::Status onFpsReported(float fps) override;

    private:
        Callback mCb;
    };

    android::sp<Listener> mListener;
    int32_t mTaskId = -1;
};

} // namespace pantau
