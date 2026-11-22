/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#include <cstdio>

#include "RingWatch.h"

using aidl::android::hardware::vibrator::RingWatch;

static int sFailed;

static void check(const char* name, bool ok) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) sFailed++;
}

constexpr int64_t kMs = 1000000;

// The follow loop against a kernel that takes a 5 ms chunk on time until `diesAt`, then stops
// (it read the chip in standby). Returns when the watch first fires, -1 if never.
static int64_t firesAt(int64_t diesAt, int64_t until) {
    RingWatch watch(50 * kMs);
    watch.reset(0);
    int pending = 0;
    int64_t nextTake = 5 * kMs;
    for (int64_t t = 0; t <= until; t += kMs) {
        if (t < diesAt && pending > 0 && t >= nextTake) {
            pending--;
            nextTake = t + 5 * kMs;
        }
        if (watch.stalled(pending, t)) return t;
        if (pending < 2) {
            pending++;
            watch.queued();
        }
    }
    return -1;
}

int main() {
    check("a stream that keeps taking never stalls", firesAt(1'000'000 * kMs, 2000 * kMs) == -1);
    const int64_t t = firesAt(300 * kMs, 2000 * kMs);
    check("a stream the kernel ended is caught within 60 ms", t > 300 * kMs && t <= 360 * kMs);
    check("a stream that never started is caught", firesAt(0, 2000 * kMs) == 51 * kMs);

    RingWatch watch(50 * kMs);
    watch.reset(0);
    watch.queued();
    check("queued but untaken: not yet", !watch.stalled(1, 40 * kMs));
    check("queued but untaken: stalled", watch.stalled(1, 51 * kMs));
    watch.reset(51 * kMs);
    check("restart clears it", !watch.stalled(0, 120 * kMs));
    watch.queued();
    check("an empty ring is never stalled", !watch.stalled(0, 500 * kMs));

    printf(sFailed ? "%d failed\n" : "all passed\n", sFailed);
    return sFailed ? 1 : 0;
}
