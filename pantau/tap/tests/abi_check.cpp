/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */
#include <cstdio>
#include <cstring>

#include "pantau_tap.h"

int main() {
    // Disarmed fast-path must return false on 1 relaxed load.
    if (pantau_tap_frame_armed(10042)) return 1;
    if (pantau_tap_ui_armed(10042)) return 2;
    if (pantau_tap_input_armed(10042)) return 3;
    if (pantau_tap_scene_armed()) return 4;
    if (pantau_tap_blur_armed()) return 5;

    // FNV-1a 64-bit sanity check.
    const char* s = "SurfaceView[org.yasvara.laras]";
    uint64_t h = pantau_tap_fnv1a64(reinterpret_cast<const uint8_t*>(s), std::strlen(s));
    if (h == 0) return 6;

    std::printf("pantau_tap_abi_check: PASS (fnv1a=0x%llx)\n",
                static_cast<unsigned long long>(h));
    return 0;
}
