/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "hentak-tagger"

#include "Tagger.h"

#include <dlfcn.h>
#include <log/log.h>
#include <onnxruntime_c_api.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cmath>
#include <string>
#include <vector>

// hentak::ffi (Rust).
extern "C" {
void* hentak_tagger_open(uint8_t* base, size_t len, size_t window48);
void hentak_tagger_close(void* runner);
size_t hentak_tagger_next(void* runner, float* mel, float* bands, size_t frames, uint64_t* end);
void hentak_tagger_publish(void* runner, uint64_t end, const float* labels, const float* levels);
}

namespace aidl::vendor::yasvara::hentak {

namespace {

constexpr size_t kShmBytes = 4096 + (size_t{1} << 17) * 4;  // hentak::tagger::shm::BYTES
constexpr size_t kMels = 128;
constexpr size_t kBands = 16;
constexpr size_t kLabels = 12;
constexpr char kRuntime[] = "/vendor/lib64/hentak/libonnxruntime.so";
constexpr char kBackend[] = "/vendor/lib64/hentak/libQnnHtp.so";
// The u8 network's HTP graph, compiled for V73 on onyx (EP context). No CPU fallback: on one core
// the network takes ~30 ms per 40 ms window, so without HTP the detector's rules play alone.
constexpr char kContext[] = "/vendor/etc/hentak/tagger_ctx.onnx";
// Our QNN's DSP skeleton first: onyx's own QNN (an older one) keeps its in rfsa/adsp.
constexpr char kDspPath[] = "/vendor/etc/hentak/dsp;/vendor/lib/rfsa/adsp;/vendor/dsp/cdsp;/vendor/dsp";
constexpr int kNice = -10;

bool check(const OrtApi* ort, OrtStatus* s, const char* what) {
    if (!s) return true;
    ALOGE("%s: %s", what, ort->GetErrorMessage(s));
    ort->ReleaseStatus(s);
    return false;
}

}  // namespace

std::shared_ptr<Tagger> Tagger::create() {
    if (access(kContext, R_OK) != 0 || access(kRuntime, R_OK) != 0) return nullptr;
    // The network loads on the first attach: at boot this HAL starts before the CDSP is up.
    return ndk::SharedRefBase::make<Tagger>();
}

Tagger::~Tagger() {
    stop();
    if (mSession) mOrt->ReleaseSession(mSession);
    if (mEnv) mOrt->ReleaseEnv(mEnv);
}

// Burst: each call votes the DSP up and lets it sleep after (0.66 ms p50 every 40 ms on onyx).
OrtSession* Tagger::open() {
    OrtSessionOptions* so = nullptr;
    if (!check(mOrt, mOrt->CreateSessionOptions(&so), "options")) return nullptr;
    mOrt->SetIntraOpNumThreads(so, 1);
    const char* keys[] = {"backend_path", "htp_performance_mode", "htp_arch"};
    const char* vals[] = {kBackend, "burst", "73"};
    OrtSession* session = nullptr;
    if (check(mOrt, mOrt->SessionOptionsAppendExecutionProvider(so, "QNN", keys, vals, 3), "qnn")) {
        mOrt->AddSessionConfigEntry(so, "session.disable_cpu_ep_fallback", "1");
        check(mOrt, mOrt->CreateSession(mEnv, kContext, so, &session), "htp");
    }
    mOrt->ReleaseSessionOptions(so);
    if (session) ALOGI("%s on HTP", kContext);
    return session;
}

bool Tagger::load() {
    if (!mOrt) {
        setenv("ADSP_LIBRARY_PATH", kDspPath, 1);
        void* lib = dlopen(kRuntime, RTLD_NOW | RTLD_LOCAL);
        auto base = lib ? reinterpret_cast<const OrtApiBase* (*)()>(dlsym(lib, "OrtGetApiBase")) : nullptr;
        if (!base) {
            ALOGE("%s: %s", kRuntime, dlerror());
            return false;
        }
        mOrt = base()->GetApi(ORT_API_VERSION);
        if (!mOrt) return false;
    }
    if (!mEnv) {
        if (!check(mOrt, mOrt->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "hentak", &mEnv), "env")) return false;
        mOrt->DisableTelemetryEvents(mEnv);
    }
    mSession = open();
    if (!mSession) return false;

    OrtTypeInfo* ti = nullptr;
    const OrtTensorTypeAndShapeInfo* tsi = nullptr;
    int64_t dims[4] = {};
    if (!check(mOrt, mOrt->SessionGetInputTypeInfo(mSession, 0, &ti), "input") ||
        !check(mOrt, mOrt->CastTypeInfoToTensorInfo(ti, &tsi), "input") ||
        !check(mOrt, mOrt->GetDimensions(tsi, dims, 4), "input")) {
        return false;
    }
    mOrt->ReleaseTypeInfo(ti);
    mFrames = static_cast<size_t>(dims[3]);  // mel: 1 × 1 × 128 × frames
    return mFrames > 0;
}

ndk::ScopedAStatus Tagger::attach(ndk::ScopedFileDescriptor* out) {
    std::lock_guard<std::mutex> l(mLock);
    stop();
    if (!mSession && !load()) return ndk::ScopedAStatus::fromExceptionCode(EX_SERVICE_SPECIFIC);
    mFd = memfd_create("hentak-tagger", MFD_CLOEXEC);
    if (mFd < 0 || ftruncate(mFd, kShmBytes) != 0) {
        stop();
        return ndk::ScopedAStatus::fromExceptionCode(EX_SERVICE_SPECIFIC);
    }
    mBase = mmap(nullptr, kShmBytes, PROT_READ | PROT_WRITE, MAP_SHARED, mFd, 0);
    if (mBase == MAP_FAILED) mBase = nullptr;
    mRunner = mBase ? hentak_tagger_open(static_cast<uint8_t*>(mBase), kShmBytes, mFrames * 480)
                    : nullptr;
    if (!mRunner) {
        stop();
        return ndk::ScopedAStatus::fromExceptionCode(EX_SERVICE_SPECIFIC);
    }
    mRun = true;
    mThread = std::thread(&Tagger::loop, this);
    *out = ndk::ScopedFileDescriptor(dup(mFd));
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Tagger::detach() {
    std::lock_guard<std::mutex> l(mLock);
    stop();
    return ndk::ScopedAStatus::ok();
}

void Tagger::stop() {
    mRun = false;
    if (mThread.joinable()) mThread.join();
    if (mRunner) hentak_tagger_close(mRunner);
    mRunner = nullptr;
    if (mBase) munmap(mBase, kShmBytes);
    mBase = nullptr;
    if (mFd >= 0) close(mFd);
    mFd = -1;
}

void Tagger::loop() {
    setpriority(PRIO_PROCESS, 0, kNice);
    std::vector<float> mel(kMels * mFrames), bands(kBands * mFrames);
    OrtMemoryInfo* mem = nullptr;
    mOrt->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &mem);
    const int64_t melDims[] = {1, 1, kMels, static_cast<int64_t>(mFrames)};
    const int64_t bandDims[] = {1, kBands, static_cast<int64_t>(mFrames)};
    OrtValue* in[2] = {};
    mOrt->CreateTensorWithDataAsOrtValue(mem, mel.data(), mel.size() * sizeof(float), melDims, 4,
                                         ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &in[0]);
    mOrt->CreateTensorWithDataAsOrtValue(mem, bands.data(), bands.size() * sizeof(float), bandDims,
                                         3, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &in[1]);
    const char* inNames[] = {"mel", "hi"};
    const char* outNames[] = {"labels", "level"};
    while (mRun) {
        uint64_t end = 0;
        if (hentak_tagger_next(mRunner, mel.data(), bands.data(), mFrames, &end) == 0) continue;
        OrtValue* out[2] = {};
        if (!check(mOrt, mOrt->Run(mSession, nullptr, inNames, in, 2, outNames, 2, out), "run")) {
            continue;
        }
        float* labels = nullptr;
        float* levels = nullptr;
        mOrt->GetTensorMutableData(out[0], reinterpret_cast<void**>(&labels));
        mOrt->GetTensorMutableData(out[1], reinterpret_cast<void**>(&levels));
        // Outputs are the window's last two 40 ms frames; the newest is the second.
        float lv[kLabels];
        for (size_t k = 0; k < kLabels; k++) lv[k] = levels[kLabels + k] * 20.0f;  // LEVEL_SCALE dB
        hentak_tagger_publish(mRunner, end, labels + kLabels, lv);
        mOrt->ReleaseValue(out[0]);
        mOrt->ReleaseValue(out[1]);
    }
    mOrt->ReleaseValue(in[0]);
    mOrt->ReleaseValue(in[1]);
    mOrt->ReleaseMemoryInfo(mem);
}

}  // namespace aidl::vendor::yasvara::hentak
