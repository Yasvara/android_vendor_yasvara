#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Builds libyasvara_xposed.so for every ABI the ROM ships and drops it into ../prebuilt/<abi>/.
# Needs an NDK (r29+, C++ modules), CMake >= 3.28 and ninja >= 1.11 (set NINJA=...).
#
#   ./build.sh [arm64-v8a] [armeabi-v7a]     default: both
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${YASVARA_XPOSED_OUT:-/tmp/yasvara-xposed-build}
NDK=${ANDROID_NDK_ROOT:-$(ls -d /opt/android-sdk/ndk/30.* /opt/android-sdk/ndk/29.* 2>/dev/null | sort -V | tail -1)}
NINJA=${NINJA:-$(command -v ninja)}   # must be >= 1.11 (C++ modules need dyndep); AOSP ships 1.9
[ -d "$NDK" ] || { echo "no NDK found, set ANDROID_NDK_ROOT"; exit 1; }
ABIS=("$@"); [ ${#ABIS[@]} -gt 0 ] || ABIS=(arm64-v8a armeabi-v7a)
for abi in "${ABIS[@]}"; do
    B=$OUT/$abi
    cmake -S "$HERE" -B "$B" -G Ninja -DCMAKE_MAKE_PROGRAM="$NINJA" \
        -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI="$abi" -DANDROID_PLATFORM=android-31 -DANDROID_STL=c++_static \
        -DCMAKE_BUILD_TYPE=Release \
        -DYASVARA_XPOSED_VERSION_CODE=1 -DYASVARA_XPOSED_VERSION_NAME=yasvara-1 \
        -DCMAKE_CXX_FLAGS="-DPHMAP_HAVE_SSE2=0 -DPHMAP_HAVE_SSSE3=0" \
        -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-z,max-page-size=16384"
    "$NINJA" -C "$B" yasvara_xposed
    mkdir -p "$HERE/../prebuilt/$abi"
    "$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" --strip-unneeded -o \
        "$HERE/../prebuilt/$abi/libyasvara_xposed.so" "$B/libyasvara_xposed.so"
    ls -l "$HERE/../prebuilt/$abi/libyasvara_xposed.so"
done
