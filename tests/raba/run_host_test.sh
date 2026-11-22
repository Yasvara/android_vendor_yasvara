#!/bin/bash
# Raba's profile table (system_server), the HAL's bank parser and its stream stall watch, on the host.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
jdk=$root/prebuilts/jdk/jdk21/linux-x86/bin
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

"$jdk/javac" -nowarn -d "$out" \
    "$here"/stubs/android/annotation/*.java "$here"/stubs/android/compat/annotation/*.java \
    "$here"/stubs/libcore/util/*.java "$root"/libcore/json/src/main/java/org/json/*.java \
    "$root/frameworks/base/services/core/java/com/android/server/vibrator/RabaProfile.java" \
    "$here/RabaProfileTest.java"
"$jdk/java" -cp "$out" com.android.server.vibrator.RabaProfileTest

hal=$root/vendor/qcom/opensource/vibrator/aidl/VibratorOL
c++ -std=c++20 -Wall -Werror -I"$here/stubs" -I"$hal" -o "$out/bank" \
    "$hal/TextureBank.cpp" "$here/texture_bank_test.cpp"
"$out/bank" "$root/vendor/xiaomi/onyx/proprietary/odm/firmware/aw8697_haptic.bin" \
    "$(cd "$root/.." && pwd)/lab/haptics/raba/waves"

c++ -std=c++20 -Wall -Werror -I"$hal" -o "$out/watch" "$here/ring_watch_test.cpp"
"$out/watch"
