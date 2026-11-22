#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Device checks for on a freshly flashed userdebug build.
# Prints one line per check; details go to $OUT. Leaves the user's colour and theme settings as
# it found them (each sub-script restores what it changes).
set -u
here=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/yas_verify_$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
adb root >/dev/null 2>&1; adb wait-for-device
until [[ "$(adb shell getprop sys.boot_completed | tr -d '\r')" == 1 ]]; do sleep 2; done

line() { printf '%-44s %s\n' "$1" "$2"; }
avc() { adb shell dmesg | grep -c 'avc: *denied' ; }
avc_start=$(avc)

line "build" "$(adb shell getprop ro.yasvara.version | tr -d '\r')"
flag=$(adb shell aflags list 2>/dev/null | grep enable_theme_service | awk '{print $2, $4}')
line "enable_theme_service (want: disabled read-only)" "${flag:-not listed}"
adb shell dumpsys activity service com.android.systemui YasThemeState > "$OUT/theme_state.txt"
line "SystemUI YasThemeState dump" "$(grep -c 'yasvara_\|colorFingerprint' "$OUT/theme_state.txt") lines"

# M0: apply transition (reveal) and its frame stats.
"$here/themes/transition.sh" > "$OUT/transition.txt" 2>&1
line "transition: begin" "$(grep -o 'token=[0-9]*, cover=[a-z]*' "$OUT/transition.txt" | head -1)"
line "transition: SystemUI janky frames" "$(grep -m1 'Janky frames' "$OUT/transition.txt" | sed 's/.*: //')"

# M0: no relaunch of our apps on an overlay flip (Laras in front, then the launcher).
adb shell am start -a org.yasvara.laras.action.OPEN >/dev/null 2>&1; sleep 3
"$here/themes/relaunch_count.sh" 2 > "$OUT/relaunch_laras.txt" 2>&1
line "relaunch (Laras in front)" "$(head -1 "$OUT/relaunch_laras.txt")"
adb shell input keyevent HOME; sleep 2
"$here/themes/relaunch_count.sh" 2 > "$OUT/relaunch_home.txt" 2>&1
line "relaunch (launcher in front)" "$(head -1 "$OUT/relaunch_home.txt")"

# M0: preview colour seam spike.
OUT="$OUT/seam" "$here/color/seam_spike.sh" > "$OUT/seam.txt" 2>&1
while read -r l; do line "seam spike" "$l"; done < <(grep -E 'coverage|palette-dependent' "$OUT/seam.txt")

# M1: fingerprint parity on 20 specs.
"$here/color/fingerprint_parity.sh" > "$OUT/parity.txt" 2>&1
line "fingerprint parity" "$(tail -1 "$OUT/parity.txt")"

line "new AVC denials" "$(( $(avc) - avc_start ))"
adb shell dmesg | grep 'avc: *denied' | tail -20 > "$OUT/avc.txt"
echo "details: $OUT"
