#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Pushes the SELinux files of the current build into the overlay of a running device (dev
# iteration, like install.sh does for modules): every changed file under */etc/selinux of
# system, system_ext, product, vendor and odm, as one consistent set. Policy is compiled from
# these at boot (or loaded precompiled from /odm when the sha256 files match), so a partial
# push is never made: either every changed file goes, or none.
#
#   YASVARA_DEVICE=onyx vendor/yasvara/tests/root/push_selinux.sh [-n]    # -n: list only
set -u -o pipefail
DRY=0; [ "${1:-}" = -n ] && DRY=1
HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(cd "$HERE/../../../.." && pwd)"
DEV=${YASVARA_DEVICE:-onyx}
OUT="$TREE/out/target/product/$DEV"
[ -d "$OUT" ] || { echo "no $OUT"; exit 2; }
[ "$(adb shell getprop ro.product.device | tr -d '\r')" = "$DEV" ] || { echo "connected device is not $DEV"; exit 2; }
[ "$(adb shell id -u | tr -d '\r')" = 0 ] || { adb root >/dev/null 2>&1; adb wait-for-device; }

declare -A DEVSUM
while read -r sum path; do DEVSUM["$path"]="$sum"; done < <(
  adb shell 'for p in system system_ext product vendor odm; do sha1sum /$p/etc/selinux/* 2>/dev/null; done' | tr -d '\r')

CHANGED=()
for p in system system_ext product vendor odm; do
  for f in "$OUT/$p/etc/selinux/"*; do
    [ -f "$f" ] || continue
    remote="/$p/etc/selinux/$(basename "$f")"
    local_sum=$(sha1sum "$f" | cut -d' ' -f1)
    if [ "${DEVSUM[$remote]-}" != "$local_sum" ]; then CHANGED+=("$f|$remote"); fi
  done
done
if [ ${#CHANGED[@]} -eq 0 ]; then echo "SELinux files already match the build"; exit 0; fi
printf '  %s\n' "${CHANGED[@]##*|}"
[ $DRY = 1 ] && exit 0

adb remount >/dev/null 2>&1
for e in "${CHANGED[@]}"; do
  adb push "${e%%|*}" "${e##*|}" >/dev/null || { echo "push failed: ${e##*|}"; exit 1; }
done
adb shell "restorecon -F $(printf '%s ' "${CHANGED[@]##*|}")" >/dev/null 2>&1
adb shell sync
echo "pushed ${#CHANGED[@]} files; a reboot loads the new policy"
