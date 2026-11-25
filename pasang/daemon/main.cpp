/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#define LOG_TAG "pasangd"

#include <malloc.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/LazyServiceRegistrar.h>
#include <binder/ProcessState.h>
#include <private/android_filesystem_config.h>
#include <utils/String16.h>
#include <yasvara/pasang/BnPasang.h>

#include "pasang_ffi.h"

namespace {

using android::IPCThreadState;
using android::OK;
using android::ProcessState;
using android::String16;
using android::sp;
using android::binder::LazyServiceRegistrar;
using android::binder::Status;

constexpr int64_t kIdleExitSeconds = 30;

int64_t monoNowSec() {
    using namespace std::chrono;
    return duration_cast<seconds>(steady_clock::now().time_since_epoch()).count();
}

std::string takeRustString(char* ptr) {
    if (!ptr) {
        return "{}";
    }
    std::string out(ptr);
    pasang_free_string(ptr);
    return out;
}

bool callerAuthorized() {
    const uid_t uid = IPCThreadState::self()->getCallingUid();
    if (uid == AID_ROOT || uid == AID_SYSTEM) {
        return true;
    }
    return android::checkCallingPermission(String16("yasvara.permission.MANAGE_PASANG"));
}

struct PersistGuard {
    PersistGuard(std::atomic<int>& active, std::atomic<int64_t>& lastActivity)
          : mActive(active), mLastActivity(lastActivity) {
        mLastActivity.store(monoNowSec(), std::memory_order_relaxed);
        if (mActive.fetch_add(1) == 0) {
            LazyServiceRegistrar::getInstance().forcePersist(true);
        }
    }
    ~PersistGuard() {
        mLastActivity.store(monoNowSec(), std::memory_order_relaxed);
        if (mActive.fetch_sub(1) == 1) {
            mallopt(M_PURGE, 0);
            LazyServiceRegistrar::getInstance().forcePersist(false);
        }
    }
    std::atomic<int>& mActive;
    std::atomic<int64_t>& mLastActivity;
};

class PasangBinderService final : public yasvara::pasang::BnPasang {
public:
    PasangBinderService() : mLastActivitySec(monoNowSec()) {}

    bool isIdleForExit() const {
        if (mActiveCalls.load(std::memory_order_acquire) > 0) return false;
        if (pasang_is_busy()) return false;
        return (monoNowSec() - mLastActivitySec.load(std::memory_order_relaxed)) >= kIdleExitSeconds;
    }

    Status statusJson(std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "pasangd: unauthorized caller");
        }
        touch();
        *out = takeRustString(pasang_status_json());
        return Status::ok();
    }

    Status slotInfoJson(std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "pasangd: unauthorized caller");
        }
        touch();
        *out = takeRustString(pasang_slot_info_json());
        return Status::ok();
    }

    Status overlayStatusJson(std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "pasangd: unauthorized caller");
        }
        touch();
        *out = takeRustString(pasang_overlay_status_json());
        return Status::ok();
    }

    Status cleanOverlaysNowJson(std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "pasangd: unauthorized caller");
        }
        PersistGuard guard(mActiveCalls, mLastActivitySec);
        *out = takeRustString(pasang_clean_overlays_json());
        return Status::ok();
    }

    Status planOtaJson(const std::string& path, const std::string& optionsJson,
                       std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "pasangd: unauthorized caller");
        }
        PersistGuard guard(mActiveCalls, mLastActivitySec);
        *out = takeRustString(pasang_plan_ota_json(path.c_str(), optionsJson.c_str()));
        return Status::ok();
    }

    Status startOta(const std::string& path, const std::string& optionsJson,
                    int32_t* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "pasangd: unauthorized caller");
        }
        touch();
        LazyServiceRegistrar::getInstance().forcePersist(true);
        const int32_t rc = pasang_start_ota(path.c_str(), optionsJson.c_str());
        if (rc != 0) {
            LazyServiceRegistrar::getInstance().forcePersist(false);
        }
        *out = rc;
        return Status::ok();
    }

    Status cancelOta() override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "pasangd: unauthorized caller");
        }
        touch();
        pasang_cancel_ota();
        return Status::ok();
    }

    Status writeRecoveryTheme(int32_t seedArgb, bool oledBlack, const std::string& locale,
                              int32_t* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "pasangd: unauthorized caller");
        }
        touch();
        *out = pasang_write_recovery_theme(
            static_cast<uint32_t>(seedArgb), oledBlack, locale.c_str());
        return Status::ok();
    }

    Status rebootToNewSlot(int32_t* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "pasangd: unauthorized caller");
        }
        touch();
        if (pasang_is_busy()) {
            *out = -16; // EBUSY
            return Status::ok();
        }
        const bool ok = android::base::SetProperty("sys.powerctl", "reboot");
        *out = ok ? 0 : -1;
        return Status::ok();
    }

private:
    void touch() { mLastActivitySec.store(monoNowSec(), std::memory_order_relaxed); }

    std::atomic<int> mActiveCalls{0};
    std::atomic<int64_t> mLastActivitySec{0};
};

} // namespace

int main(int argc, char* argv[]) {
    android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));

    pasang_init_platform_hooks();

    // Multi-call binary: when invoked via `/system_ext/bin/pasang` symlink (or with CLI args),
    // execute CLI mode directly with full native libzstd/liblzma/libbz/BoringSSL/BootControl hooks!
    const char* argv0 = (argc > 0 && argv[0]) ? argv[0] : "pasangd";
    const char* slash = std::strrchr(argv0, '/');
    const char* base = slash ? (slash + 1) : argv0;
    if (std::strcmp(base, "pasang") == 0 || argc > 1) {
        return pasang_run_cli(argc, const_cast<const char* const*>(argv));
    }

    sp<ProcessState> ps(ProcessState::self());
    ps->setThreadPoolMaxThreadCount(4);
    ps->startThreadPool();

    auto service = sp<PasangBinderService>::make();
    auto& registrar = LazyServiceRegistrar::getInstance();
    if (registrar.registerService(service, "yasvara.pasang") != OK) {
        LOG(ERROR) << "registerService(yasvara.pasang) failed";
        return 1;
    }

    // Idle reaper: release buffers and exit to 0 KB idle RAM when no OTA or RPC is active.
    std::thread([service]() {
        bool was_busy = false;
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            const bool busy = pasang_is_busy();
            if (was_busy && !busy) {
                mallopt(M_PURGE, 0);
                LazyServiceRegistrar::getInstance().forcePersist(false);
            }
            was_busy = busy;
            if (service->isIdleForExit()) {
                mallopt(M_PURGE, 0);
                (void)LazyServiceRegistrar::getInstance().tryUnregister();
                LOG(INFO) << "pasangd idle exit (0 KB idle)";
                _exit(0);
            }
        }
    }).detach();

    LOG(INFO) << "pasangd ready (lazy Rust In-OS Live CoW OTA daemon)";
    IPCThreadState::self()->joinThreadPool();
    return 0;
}
