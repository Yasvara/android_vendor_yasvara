/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <aidl/vendor/yasvara/hentak/BnTagger.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

struct OrtApi;
struct OrtEnv;
struct OrtSession;

namespace aidl::vendor::yasvara::hentak {

// the learned game-sound tagger on HTP, inside the vibrator HAL (the one process here
// that may open the NPU). audioserver's haptics worker writes the game track into the session
// memory; a thread here labels the newest window every 40 ms, or at once on a request, and
// publishes the labels back. Front end and session layout: hentak::tagger (Rust).
class Tagger : public BnTagger {
  public:
    // Null without the HTP graph or ONNX Runtime: the service then isn't registered.
    static std::shared_ptr<Tagger> create();
    Tagger() = default;  // public for ndk::SharedRefBase::make; use create()
    ~Tagger();

    ndk::ScopedAStatus attach(ndk::ScopedFileDescriptor* out) override;
    ndk::ScopedAStatus detach() override;

  private:
    bool load();
    OrtSession* open();
    void stop();
    void loop();

    const OrtApi* mOrt = nullptr;
    OrtEnv* mEnv = nullptr;
    OrtSession* mSession = nullptr;
    size_t mFrames = 0;  // the network's input frames (10 ms each)

    std::mutex mLock;  // attach / detach
    std::thread mThread;
    std::atomic<bool> mRun{false};
    int mFd = -1;
    void* mBase = nullptr;
    void* mRunner = nullptr;
};

}  // namespace aidl::vendor::yasvara::hentak
