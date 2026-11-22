/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#define LOG_TAG "padatd"

#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <string>

#include <android-base/logging.h>
#include <binder/IPCThreadState.h>
#include <binder/LazyServiceRegistrar.h>
#include <binder/ProcessState.h>
#include <private/android_filesystem_config.h>
#include <yasvara/padat/BnPadat.h>

#include "padat_ffi.h"

namespace {

using android::IPCThreadState;
using android::OK;
using android::ProcessState;
using android::sp;
using android::binder::LazyServiceRegistrar;
using android::binder::Status;

std::string takeRustString(char* ptr) {
    if (!ptr) {
        return "{}";
    }
    std::string out(ptr);
    padat_free_string(ptr);
    return out;
}

bool callerAuthorized() {
    const uid_t uid = IPCThreadState::self()->getCallingUid();
    return uid == AID_ROOT || uid == AID_SYSTEM;
}

struct PersistGuard {
    explicit PersistGuard(std::atomic<int>& active) : mActive(active) {
        if (mActive.fetch_add(1) == 0) {
            LazyServiceRegistrar::getInstance().forcePersist(true);
        }
    }
    ~PersistGuard() {
        if (mActive.fetch_sub(1) == 1) {
            LazyServiceRegistrar::getInstance().forcePersist(false);
        }
    }
    std::atomic<int>& mActive;
};

class PadatBinderService final : public yasvara::padat::BnPadat {
public:
    Status statusJson(std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        *out = takeRustString(padat_status_json());
        return Status::ok();
    }

    Status getPolicyJson(std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        *out = takeRustString(padat_get_policy_json());
        return Status::ok();
    }

    Status setPolicyJson(const std::string& json, int32_t* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        *out = padat_set_policy_json(json.c_str());
        return Status::ok();
    }

    Status scanPackageJson(const std::string& pkg, int32_t algo, int32_t level,
                           int32_t clusterKb, int32_t scopeMask, std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        PersistGuard guard(mActiveJobs);
        *out = takeRustString(padat_scan_package_json(
                pkg.c_str(), static_cast<uint8_t>(algo & 0xff), static_cast<uint8_t>(level & 0xff),
                static_cast<uint16_t>(clusterKb > 0 ? clusterKb : 16),
                static_cast<uint32_t>(scopeMask)));
        return Status::ok();
    }

    Status compressPackageJson(const std::string& pkg, int32_t algo, int32_t level,
                               int32_t clusterKb, int32_t scopeMask, bool allowRunning,
                               std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        PersistGuard guard(mActiveJobs);
        *out = takeRustString(padat_compress_package_json(
                pkg.c_str(), static_cast<uint8_t>(algo & 0xff), static_cast<uint8_t>(level & 0xff),
                static_cast<uint16_t>(clusterKb > 0 ? clusterKb : 16),
                static_cast<uint32_t>(scopeMask), allowRunning));
        return Status::ok();
    }

    Status syncPackageJson(const std::string& pkg, int32_t algo, int32_t level,
                           int32_t clusterKb, int32_t scopeMask, std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        PersistGuard guard(mActiveJobs);
        *out = takeRustString(padat_sync_package_json(
                pkg.c_str(), static_cast<uint8_t>(algo & 0xff), static_cast<uint8_t>(level & 0xff),
                static_cast<uint16_t>(clusterKb > 0 ? clusterKb : 16),
                static_cast<uint32_t>(scopeMask)));
        return Status::ok();
    }

    Status decompressPackageJson(const std::string& pkg, int32_t scopeMask, bool allowRunning,
                                 std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        PersistGuard guard(mActiveJobs);
        *out = takeRustString(padat_decompress_package_json(
                pkg.c_str(), static_cast<uint32_t>(scopeMask), allowRunning));
        return Status::ok();
    }

    Status releasePathJson(const std::string& path, std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        PersistGuard guard(mActiveJobs);
        *out = takeRustString(padat_release_path_json(path.c_str()));
        return Status::ok();
    }

    Status allStatsJson(std::string* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        PersistGuard guard(mActiveJobs);
        *out = takeRustString(padat_all_stats_json());
        return Status::ok();
    }

    Status cleanupStaleTemps(int64_t* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        PersistGuard guard(mActiveJobs);
        *out = static_cast<int64_t>(padat_cleanup_stale_temps());
        return Status::ok();
    }

    Status applyDirProfile(const std::string& path, int32_t algo, int32_t level,
                           int32_t clusterKb, int32_t* out) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        *out = padat_apply_dir_profile(
                path.c_str(), static_cast<uint8_t>(algo & 0xff), static_cast<uint8_t>(level & 0xff),
                static_cast<uint16_t>(clusterKb > 0 ? clusterKb : 16));
        return Status::ok();
    }

    Status setPaused(bool paused) override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        padat_set_paused(paused);
        return Status::ok();
    }

    Status cancelJob() override {
        if (!callerAuthorized()) {
            return Status::fromExceptionCode(Status::EX_SECURITY, "padatd: unauthorized caller");
        }
        padat_cancel_job();
        return Status::ok();
    }

private:
    std::atomic<int> mActiveJobs{0};
};

} // namespace

int main() {
    android::base::InitLogging(nullptr, android::base::LogdLogger(android::base::SYSTEM));

    // Allow 4 concurrent Binder threads so `statusJson`, `setPaused`, `cancelJob`,
    // `applyDirProfile`, and `getPolicyJson` never queue behind long compression/sync jobs.
    sp<ProcessState> ps(ProcessState::self());
    ps->setThreadPoolMaxThreadCount(4);
    ps->startThreadPool();

    auto service = sp<PadatBinderService>::make();
    auto& registrar = LazyServiceRegistrar::getInstance();
    if (registrar.registerService(service, "yasvara.padat") != OK) {
        LOG(ERROR) << "registerService(yasvara.padat) failed";
        return 1;
    }

    LOG(INFO) << "padatd ready (lazy Rust F2FS realtime compression daemon)";
    IPCThreadState::self()->joinThreadPool();
    return 0;
}
