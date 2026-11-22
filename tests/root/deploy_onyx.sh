#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# puts the native root of the current build on a POCO F7 (onyx) through the overlay
# (like install.sh), reboots once, labels the new files, starts the daemon and runs
# run_device_tests.sh. Nothing is flashed; `./install.sh --reset` takes everything back out.
#
#   vendor/yasvara/tests/root/deploy_onyx.sh [--wait] [--no-tests] [-n]
#     --wait       block until the phone is connected (adb wait-for-device)
#     --no-tests   deploy and start the daemon, skip run_device_tests.sh
#     -n           show what would be pushed and stop
#
# What it pushes (only files whose sha1 differs): the two native binaries and the init rc,
# the SELinux files of every partition (one consistent set), services.jar + its oat files
# (system_server, not the boot classpath) and Laras with its oat files.
#
# A reboot relocks the phone: unlock it afterwards for phase B of the tests (the service
# refuses changes on a locked device). The daemon tests run either way.
set -u -o pipefail
WAIT=0; TESTS=1; DRY=0
for a in "$@"; do case $a in --wait) WAIT=1;; --no-tests) TESTS=0;; -n) DRY=1;; *) echo "unknown option $a"; exit 2;; esac; done
HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(cd "$HERE/../../../.." && pwd)"
export YASVARA_DEVICE=onyx
OUT="$TREE/out/target/product/onyx"
say() { echo "[$(date +%H:%M:%S)] $*"; }
ash() { adb shell "$@" | tr -d '\r'; }
wait_boot() { adb wait-for-device; until [ "$(ash getprop sys.boot_completed)" = 1 ]; do sleep 3; done; }

[ -d "$OUT" ] || { echo "no build output at $OUT"; exit 2; }
for f in system/xbin/yasvara_rootd system/xbin/yasvara_su system/etc/init/yasvara_sessiond.rc system/lib64/libandroid_runtime.so system/framework/services.jar \
         system_ext/priv-app/Laras/Laras.apk odm/etc/selinux/precompiled_sepolicy; do
  [ -e "$OUT/$f" ] || { echo "missing build output: $f (run ./build.sh onyx first)"; exit 2; }
done

if [ $WAIT = 1 ]; then say "waiting for the phone…"; adb wait-for-device; fi
adb get-state >/dev/null 2>&1 || { echo "no device (use --wait)"; exit 2; }
[ "$(ash getprop ro.product.device)" = onyx ] || { echo "the connected device is not onyx"; exit 2; }
say "device build $(ash getprop ro.build.id) / host build $(grep -m1 '^ro.build.id=' "$OUT/system/build.prop" | cut -d= -f2)"
adb root >/dev/null 2>&1; adb wait-for-device
[ "$(ash id -u)" = 0 ] || { echo "adb root is not available: enable Rooted debugging in Developer options"; exit 2; }

# ---- what differs ------------------------------------------------------------------
FILES=(
  system/xbin/yasvara_rootd
  system/xbin/yasvara_su
  system/etc/init/yasvara_sessiond.rc
  system/lib64/libandroid_runtime.so
  system/framework/services.jar
  system/framework/services.jar.prof
  system/framework/oat/arm64/services.art
  system/framework/oat/arm64/services.odex
  system/framework/oat/arm64/services.vdex
  system_ext/etc/permissions/Laras.xml
  system_ext/priv-app/Laras/Laras.apk
  system_ext/priv-app/Laras/oat/arm64/Laras.odex
  system_ext/priv-app/Laras/oat/arm64/Laras.vdex
)
for p in system system_ext product vendor odm; do
  for f in "$OUT/$p/etc/selinux/"*; do [ -f "$f" ] && FILES+=("$p/etc/selinux/$(basename "$f")"); done
done
declare -A DEV
while read -r sum path; do DEV["$path"]="$sum"; done < <(ash "sha1sum $(printf '/%s ' "${FILES[@]}") 2>/dev/null")
PUSH=()
for f in "${FILES[@]}"; do
  [ -f "$OUT/$f" ] || continue
  [ "${DEV[/$f]-}" = "$(sha1sum "$OUT/$f" | cut -d' ' -f1)" ] || PUSH+=("$f")
done
# moved everything out of world-searchable directories; leftovers of the old layout
# would define yasvara_rootd twice (init rc) and keep a public su.
OLD=(/system/bin/su /system_ext/bin/su /system_ext/bin/yasvara_rootd /system_ext/etc/init/yasvara_rootd.rc
     /system/etc/init/yasvara_rootd.rc)
LEFT=$(ash "ls ${OLD[*]} 2>/dev/null" | wc -l)
say "${#PUSH[@]} files differ; $LEFT files of the old layout to remove"
printf '    %s\n' "${PUSH[@]-}"
[ $DRY = 1 ] && exit 0

# ---- push -----------------------------------------------------------------------------
adb remount >/dev/null 2>&1
if [ "$(ash mount | grep -c ' /system_ext type overlay (rw')" = 0 ]; then
  say "overlay is read-only: rebooting once to enable it"
  adb reboot; wait_boot; adb root >/dev/null 2>&1; adb wait-for-device; adb remount >/dev/null 2>&1
fi
for f in "${PUSH[@]}"; do
  ash "mkdir -p /$(dirname "$f")" >/dev/null
  adb push "$OUT/$f" "/$f" >/dev/null || { echo "push failed: $f"; exit 1; }
done
ash "rm -f ${OLD[*]}" >/dev/null
# `adb shell su` keeps working: a symlink next to the real client, inside the 0750 directory.
ash "ln -sf yasvara_su /system/xbin/su" >/dev/null
ash "chmod 755 /system/xbin/yasvara_rootd /system/xbin/yasvara_su; chmod 644 /system/etc/init/yasvara_sessiond.rc" >/dev/null
ash sync >/dev/null
say "pushed; rebooting to load the new policy, init rc and system_server"
adb reboot
sleep 15; wait_boot
say "booted ($(ash getprop ro.build.id)), enforcing: $(ash getenforce)"
adb root >/dev/null 2>&1; adb wait-for-device

# ---- the new files could not be labelled before the policy that names their types ------------
# (the overlay comes back read-only after a boot: labelling needs it writable again)
adb remount >/dev/null 2>&1
ash "restorecon -F -R /system/xbin/su /system/xbin/yasvara_su /system/xbin/yasvara_rootd /system/etc/init/yasvara_sessiond.rc /data/misc/yasvara_root" >/dev/null
say "labels: $(ash ls -LZ /system/xbin/yasvara_rootd | cut -d' ' -f1) / $(ash ls -LZ /system/xbin/yasvara_su | cut -d' ' -f1)"
ash "setprop ctl.stop yasvara_sessiond; sleep 1; setprop ctl.start yasvara_sessiond" >/dev/null
for _ in $(seq 1 20); do [ "$(ash getprop init.svc.yasvara_sessiond)" = running ] && break; sleep 0.5; done
say "daemon: $(ash getprop init.svc.yasvara_sessiond) ($(ash ps -AZ | grep yasvara_rootd | head -1 | cut -d' ' -f1))"
say "system_server: $(ash pidof system_server) service: $(ash service check yasvara_session)"

if [ $TESTS = 1 ]; then say "running the device tests"; OUT="$OUT" "$HERE/run_device_tests.sh"; fi
say "done"
