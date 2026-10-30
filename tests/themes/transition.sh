#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Runs a no-op theme apply transition (SPEC-0002 §7.1, M0 exit): SystemUI covers the display
# with a snapshot, and the reveal runs as soon as the caller reports ready. Prints SystemUI's
# frame stats for the reveal. Needs `adb root` (the provider requires CUSTOMIZE_SYSTEM_UI).
#
# Usage: transition.sh [x] [y]   (reveal centre in display px; default the display centre)
set -eu
adb root >/dev/null
size=$(adb shell wm size | tr -d '\r' | awk '{print $NF}' | tail -1)
x=${1:-$(( ${size%x*} / 2 ))}
y=${2:-$(( ${size#*x} / 2 ))}
uri=content://com.android.systemui.customization

adb shell dumpsys gfxinfo com.android.systemui reset >/dev/null
begin=$(adb shell content call --uri "$uri" --method yas_transition_begin \
    --extra x:f:"$x" --extra y:f:"$y" --extra expect_theme_change:b:false | tr -d '\r')
echo "begin: $begin"
token=$(sed -n 's/.*token=\([0-9]*\).*/\1/p' <<<"$begin")
[[ -n "$token" && "$token" != 0 ]] || { echo "refused"; exit 1; }
sleep 0.3
adb shell content call --uri "$uri" --method yas_transition_ready --extra token:i:"$token" >/dev/null
sleep 2
adb shell dumpsys gfxinfo com.android.systemui | grep -E "Total frames rendered|Janky frames|50th|90th|99th" | head -6
adb shell dumpsys activity service com.android.systemui YasThemeTransition 2>/dev/null \
    | grep -A2 "YasThemeTransition:" || true
