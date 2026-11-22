#!/usr/bin/env bash
# Kernel VFS/procfs hiding & normalization smoke test on a rooted adb device.
# Requires yasvara_app_exec and yasvara_vfs_probe:
#   ./build.sh -q onyx yasvara_app_exec yasvara_vfs_probe
# Exercises both libc wrappers and raw svc #0 syscall() paths under an app UID (u0_a*)
# and a system daemon UID (1000).

set -euo pipefail

OUT=${OUT:-src/out/target/product/onyx}
EXEC_SRC=$OUT/data/nativetest64/yasvara_app_exec/yasvara_app_exec
PROBE_SRC=$OUT/data/nativetest64/yasvara_vfs_probe/yasvara_vfs_probe
EXEC_DEV=/data/local/tmp/yasvara_app_exec
PROBE_DEV=/data/local/tmp/yasvara_vfs_probe
FAKE_SO_DIR=/data/local/tmp/xposed_smoke_dir
FAKE_SO=$FAKE_SO_DIR/libdummy_smoke.so

sh_() { adb shell "$*"; }

[ -f "$EXEC_SRC" ] || { echo "build yasvara_app_exec first: $EXEC_SRC"; exit 2; }
[ -f "$PROBE_SRC" ] || { echo "build yasvara_vfs_probe first: $PROBE_SRC"; exit 2; }

adb push "$EXEC_SRC" "$EXEC_DEV" >/dev/null && sh_ chmod 755 "$EXEC_DEV"
adb push "$PROBE_SRC" "$PROBE_DEV" >/dev/null && sh_ chmod 755 "$PROBE_DEV"
sh_ "mkdir -p $FAKE_SO_DIR && cp /system/lib64/libz.so $FAKE_SO && chmod 755 $FAKE_SO_DIR && chmod 644 $FAKE_SO"
trap 'sh_ "rm -rf $EXEC_DEV $PROBE_DEV $FAKE_SO_DIR" >/dev/null 2>&1 || true' EXIT

pass=0 fail=0

APP_UID=$(sh_ "dumpsys package com.google.android.gms 2>/dev/null | sed -n 's/.*userId=\([0-9]*\).*/\1/p' | head -n1" | tr -d '\r')
APP_UID=${APP_UID:-10150}

echo "Testing kernel VFS/procfs hiding as daemon uid=1000 vs app uid=$APP_UID"

if daemon_out=$(sh_ "$EXEC_DEV --uid 1000 --context u:r:su:s0 -- $PROBE_DEV --expect-daemon --map-file $FAKE_SO --marker xposed_smoke_dir" 2>&1); then
  printf '%s\n' "$daemon_out"
  pass=$((pass + 1))
else
  printf '%s\n' "$daemon_out"
  fail=$((fail + 1))
fi

if app_out=$(sh_ "$EXEC_DEV --uid $APP_UID --context u:r:su:s0 -- $PROBE_DEV --expect-app --map-file $FAKE_SO --marker xposed_smoke_dir" 2>&1); then
  printf '%s\n' "$app_out"
  pass=$((pass + 1))
else
  printf '%s\n' "$app_out"
  fail=$((fail + 1))
fi

if sh_out=$(sh_ "$EXEC_DEV --uid $APP_UID -- /system/bin/sh -c 'grep -E \" (overlay|overlayfs|/mnt/scratch) \" /proc/self/mountinfo && exit 1; stat -f -c \"%t\" /system'" 2>&1); then
  echo "PASS: untrusted_app /system/bin/sh mountinfo clean, statfs(/system) magic=$sh_out"
  pass=$((pass + 1))
else
  echo "FAIL: untrusted_app /system/bin/sh check: $sh_out"
  fail=$((fail + 1))
fi

echo "---"
printf '%d passed, %d failed\n' "$pass" "$fail"
exit $fail

