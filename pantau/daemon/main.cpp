/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#define LOG_TAG "pantaud"

#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <binder/IPCThreadState.h>
#include <binder/LazyServiceRegistrar.h>
#include <binder/ParcelFileDescriptor.h>
#include <binder/ProcessState.h>
#include <yasvara/pantau/BnPantau.h>

#include "hud.h"
#include "pantau_core.h"
#include "sf_fps.h"

namespace {

using android::IPCThreadState;
using android::OK;
using android::ProcessState;
using android::sp;
using android::binder::LazyServiceRegistrar;
using android::binder::Status;
using android::binder::unique_fd;
using android::os::ParcelFileDescriptor;

constexpr uint64_t kTokenBinder = 1;
constexpr uint64_t kTokenTimer = 2;
constexpr uint64_t kMaskFps = 1ull << 7;

void setTimerMs(int tfd, uint32_t periodMs, bool fastWarmup) {
    itimerspec spec{};
    if (periodMs > 0) {
        spec.it_interval.tv_sec = periodMs / 1000;
        spec.it_interval.tv_nsec = (periodMs % 1000) * 1000000L;
        if (fastWarmup && periodMs >= 500) {
            // 150 ms warm-up first tick so delta metrics (CPU%, Net KB/s) populate almost instantly!
            spec.it_value.tv_sec = 0;
            spec.it_value.tv_nsec = 150 * 1000000L;
        } else {
            spec.it_value = spec.it_interval;
        }
    }
    timerfd_settime(tfd, 0, &spec, nullptr);
}

// Thread-safe Binder service: libgui/SurfaceComposerClient may spawn a Binder PoolThread even
// when polling on the reactor thread, so every engine & HUD access is serialized under `mMu`.
class PantauService final : public yasvara::pantau::BnPantau {
public:
    PantauService(PantauEngine* eng, int timerFd)
          : mEngine(eng),
            mTimerFd(timerFd),
            mFps([this](uint16_t fpsX100) {
                std::lock_guard<std::mutex> lock(mMu);
                pantau_engine_on_fps(mEngine, fpsX100);
                if (mHudVisible) {
                    mHud.sync(mEngine, true);
                }
            }) {}

    ~PantauService() override {
        std::lock_guard<std::mutex> lock(mMu);
        mFps.sync(-1, false);
        mHud.destroyAll();
    }

    Status configure(const std::string& hudProfile) override {
        std::lock_guard<std::mutex> lock(mMu);
        applyLocked(pantau_engine_configure(
                mEngine, reinterpret_cast<const uint8_t*>(hudProfile.data()), hudProfile.size()));
        return Status::ok();
    }

    Status session(int32_t taskId, int32_t uid, bool isGame) override {
        std::lock_guard<std::mutex> lock(mMu);
        applyLocked(pantau_engine_session(mEngine, taskId, uid, isGame));
        return Status::ok();
    }

    Status setConsumers(int64_t consumerMask) override {
        std::lock_guard<std::mutex> lock(mMu);
        applyLocked(pantau_engine_set_consumers(mEngine, static_cast<uint64_t>(consumerMask)));
        return Status::ok();
    }

    Status event(int32_t kind, int64_t a, int64_t b) override {
        std::lock_guard<std::mutex> lock(mMu);
        applyLocked(pantau_engine_on_event(mEngine, static_cast<uint32_t>(kind), a, b));
        return Status::ok();
    }

    Status pushFps(int32_t fpsX100) override {
        std::lock_guard<std::mutex> lock(mMu);
        if (fpsX100 >= 0 && fpsX100 <= 65535) {
            pantau_engine_on_fps(mEngine, static_cast<uint16_t>(fpsX100));
            if (mHudVisible) mHud.sync(mEngine, true);
        }
        return Status::ok();
    }

    Status displayChanged(int32_t rotation, int32_t widthPx, int32_t heightPx,
                          int32_t refreshHz) override {
        std::lock_guard<std::mutex> lock(mMu);
        pantau_engine_display_changed(mEngine, static_cast<uint8_t>(rotation & 3),
                                      widthPx > 0 ? static_cast<uint32_t>(widthPx) : 0u,
                                      heightPx > 0 ? static_cast<uint32_t>(heightPx) : 0u,
                                      refreshHz > 0 ? static_cast<uint16_t>(refreshHz) : 0u);
        if (mHudVisible) mHud.sync(mEngine, true);
        return Status::ok();
    }

    Status setMonet(const std::vector<int32_t>& argb4) override {
        std::lock_guard<std::mutex> lock(mMu);
        if (argb4.size() >= 4) {
            const uint32_t c[4] = {
                    static_cast<uint32_t>(argb4[0]),
                    static_cast<uint32_t>(argb4[1]),
                    static_cast<uint32_t>(argb4[2]),
                    static_cast<uint32_t>(argb4[3]),
            };
            pantau_engine_set_monet(mEngine, c);
            if (mHudVisible) mHud.sync(mEngine, true);
        }
        return Status::ok();
    }

    Status moveWidget(int32_t widgetId, int32_t x, int32_t y) override {
        std::lock_guard<std::mutex> lock(mMu);
        if (widgetId >= 0) {
            pantau_engine_move_widget(mEngine, static_cast<uint32_t>(widgetId), x, y);
            if (mHudVisible) mHud.sync(mEngine, true);
        }
        return Status::ok();
    }

    Status pushUidMeta(int32_t uid, const std::string& label,
                       const std::vector<uint8_t>& rgba28x28) override {
        std::lock_guard<std::mutex> lock(mMu);
        if (uid > 0) {
            const bool visibleHit = pantau_engine_put_uid_meta(
                    mEngine, static_cast<uint32_t>(uid),
                    reinterpret_cast<const uint8_t*>(label.data()), label.size(), rgba28x28.data(),
                    rgba28x28.size());
            if (visibleHit && mHudVisible) mHud.sync(mEngine, true);
        }
        return Status::ok();
    }

    Status pushNetMeta(int32_t linkMask, int32_t wifiStd, int32_t wifiFreqMhz,
                       int32_t wifiLinkMbps, int32_t wifiRssiDbm, int32_t cellGen,
                       int32_t cellLevel, int32_t cellRsrpDbm) override {
        std::lock_guard<std::mutex> lock(mMu);
        const bool changed = pantau_engine_push_net_meta(
                mEngine, static_cast<uint8_t>(linkMask & 0xff),
                static_cast<uint8_t>(wifiStd & 0xff),
                static_cast<uint16_t>(wifiFreqMhz > 0 ? wifiFreqMhz : 0),
                static_cast<uint16_t>(wifiLinkMbps > 0 ? wifiLinkMbps : 0),
                static_cast<int16_t>(wifiRssiDbm),
                static_cast<uint8_t>(cellGen & 0xff),
                static_cast<uint8_t>(cellLevel & 0xff),
                static_cast<int16_t>(cellRsrpDbm));
        if (changed && mHudVisible) mHud.sync(mEngine, true);
        return Status::ok();
    }

    Status setHudParent(const sp<android::IBinder>& parentHandle) override {
        std::lock_guard<std::mutex> lock(mMu);
        mHud.setParentHandle(parentHandle);
        if (mHudVisible) mHud.sync(mEngine, true);
        return Status::ok();
    }

    Status snapshotFd(ParcelFileDescriptor* out) override {
        std::lock_guard<std::mutex> lock(mMu);
        // Ensure zero-delay first frame: populate Snapshot synchronously before handing out fd!
        pantau_engine_ensure_snapshot(mEngine);
        int raw = pantau_engine_snapshot_fd(mEngine);
        if (raw < 0) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE, "snapshot unavailable");
        }
        // Re-open memfd truly O_RDONLY via /proc/self/fd so Binder transfers a read-only file
        // description (least-privilege; clients only need SELinux `read`/`map`, never `write`).
        char path[48];
        std::snprintf(path, sizeof(path), "/proc/self/fd/%d", raw);
        int roFd = open(path, O_RDONLY | O_CLOEXEC);
        if (roFd < 0) {
            LOG(ERROR) << "open(" << path << ", O_RDONLY) failed: " << errno;
            return Status::fromServiceSpecificError(errno, "open ro snapshot fd failed");
        }
        *out = ParcelFileDescriptor(unique_fd(roFd));
        return Status::ok();
    }

    Status query(const std::string& cmd, std::string* out) override {
        std::lock_guard<std::mutex> lock(mMu);
        char buf[8192];
        size_t n = pantau_engine_query(
                mEngine, reinterpret_cast<const uint8_t*>(cmd.data()), cmd.size(),
                reinterpret_cast<uint8_t*>(buf), sizeof(buf));
        out->assign(buf, n);
        return Status::ok();
    }

    void onTimerTick() {
        uint64_t expirations = 0;
        (void)read(mTimerFd, &expirations, sizeof(expirations));
        std::lock_guard<std::mutex> lock(mMu);
        applyLocked(pantau_engine_tick(mEngine));
    }

    bool allowExit() {
        std::lock_guard<std::mutex> lock(mMu);
        return mAllowExit;
    }

private:
    void applyLocked(const PantauLifeActions& a) {
        if (a.timer_ms != mTimerMs) {
            const bool waking = (mTimerMs == 0 && a.timer_ms > 0);
            mTimerMs = a.timer_ms;
            setTimerMs(mTimerFd, mTimerMs, waking);
        }
        mHudVisible = a.hud_visible;
        mAllowExit = a.allow_exit;
        mFps.sync(a.focused_task_id, (a.active_consumers & kMaskFps) != 0);
        mHud.sync(mEngine, mHudVisible);
        LazyServiceRegistrar::getInstance().forcePersist(!a.allow_exit);
    }

    std::mutex mMu;
    PantauEngine* mEngine;
    int mTimerFd;
    uint32_t mTimerMs = 0;
    bool mHudVisible = false;
    bool mAllowExit = true;
    pantau::HudSurfaces mHud;
    pantau::SfFpsTracker mFps;
};

} // namespace

int main() {
    android::base::InitLogging(nullptr, android::base::LogdLogger(android::base::SYSTEM));

    PantauEngine* eng = pantau_engine_new(/*tune_thread=*/true);
    if (!eng) {
        LOG(ERROR) << "pantau_engine_new failed";
        return 1;
    }

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (tfd < 0 || epfd < 0) {
        LOG(ERROR) << "timerfd/epoll create failed";
        pantau_engine_free(eng);
        return 1;
    }

    // Zero extra Binder threads: poll Binder fd directly inside our single epoll loop.
    ProcessState::self()->setThreadPoolMaxThreadCount(0);
    int binderFd = -1;
    if (IPCThreadState::self()->setupPolling(&binderFd) != OK || binderFd < 0) {
        LOG(ERROR) << "IPCThreadState::setupPolling failed";
        close(tfd);
        close(epfd);
        pantau_engine_free(eng);
        return 1;
    }

    auto service = sp<PantauService>::make(eng, tfd);
    auto& registrar = LazyServiceRegistrar::getInstance();
    if (registrar.registerService(service, "yasvara.pantau") != OK) {
        LOG(ERROR) << "registerService(yasvara.pantau) failed";
        close(tfd);
        close(epfd);
        pantau_engine_free(eng);
        return 1;
    }
    IPCThreadState::self()->flushCommands();

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.u64 = kTokenBinder;
    epoll_ctl(epfd, EPOLL_CTL_ADD, binderFd, &ev);

    ev.events = EPOLLIN;
    ev.data.u64 = kTokenTimer;
    epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev);

    LOG(INFO) << "pantaud ready (M2 native NEON HUD + SF FPS + single-thread epoll)";

    constexpr int kIdleExitTimeoutMs = 15000;
    epoll_event events[8];
    for (;;) {
        const int timeoutMs = service->allowExit() ? kIdleExitTimeoutMs : -1;
        int n = epoll_wait(epfd, events, 8, timeoutMs);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) {
            if (service->allowExit()) {
                (void)registrar.tryUnregister();
                LOG(INFO) << "pantaud idle exit (0 KB idle)";
                break;
            }
            continue;
        }
        for (int i = 0; i < n; ++i) {
            if (events[i].data.u64 == kTokenBinder) {
                IPCThreadState::self()->handlePolledCommands();
                IPCThreadState::self()->flushCommands();
            } else if (events[i].data.u64 == kTokenTimer) {
                service->onTimerTick();
            }
        }
    }

    close(tfd);
    close(epfd);
    pantau_engine_free(eng);
    return 0;
}
