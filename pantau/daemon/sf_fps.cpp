/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#define LOG_TAG "pantaud"

#include "sf_fps.h"

#include <cmath>

#include <android-base/logging.h>
#include <gui/SurfaceComposerClient.h>

namespace pantau {

using android::OK;
using android::sp;
using android::SurfaceComposerClient;
using android::binder::Status;

SfFpsTracker::SfFpsTracker(Callback cb) : mListener(sp<Listener>::make(std::move(cb))) {}

SfFpsTracker::~SfFpsTracker() {
    sync(-1, false);
}

void SfFpsTracker::sync(int32_t taskId, bool active) {
    const int32_t want = (active && taskId >= 0) ? taskId : -1;
    if (want == mTaskId) return;

    if (mTaskId >= 0) {
        SurfaceComposerClient::removeFpsListener(mListener);
        mTaskId = -1;
    }
    if (want >= 0) {
        if (SurfaceComposerClient::addFpsListener(want, mListener) == OK) {
            mTaskId = want;
        } else {
            LOG(WARNING) << "addFpsListener failed for task " << want;
        }
    }
}

Status SfFpsTracker::Listener::onFpsReported(float fps) {
    if (std::isfinite(fps) && fps >= 0.0f) {
        const float scaled = std::round(fps * 100.0f);
        const uint16_t clamped =
                scaled >= 65535.0f ? 65535u : static_cast<uint16_t>(scaled);
        mCb(clamped);
    }
    return Status::ok();
}

} // namespace pantau
