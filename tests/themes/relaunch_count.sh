#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Flips the system colour overlays and counts activity relaunches and recreations.
# Laras, SystemUI and the launcher must never relaunch on an overlay change; third-party apps
# may. Needs a device on adb; open Laras and go home first so both have a resumed activity.
#
# Usage: relaunch_count.sh [flips]   (default 2: change the palette, then put it back)
set -u
flips=${1:-2}
ours='org.yasvara.laras|com.android.launcher3|com.android.systemui'

orig=$(adb shell settings get secure theme_customization_overlay_packages | tr -d '\r')
adb logcat -b events -c
for i in $(seq 1 "$flips"); do
    if (( i % 2 )); then
        # A preset seed forces SystemUI to build new fabricated overlays.
        adb shell settings put secure theme_customization_overlay_packages \
            "'{\"android.theme.customization.system_palette\":\"$(printf '%06X' $((RANDOM * 512 % 0xFFFFFF)))\",\"android.theme.customization.color_source\":\"preset\",\"android.theme.customization.theme_style\":\"TONAL_SPOT\"}'"
    else
        if [[ "$orig" == "null" ]]; then
            adb shell settings delete secure theme_customization_overlay_packages >/dev/null
        else
            adb shell settings put secure theme_customization_overlay_packages "'$orig'"
        fi
    fi
    sleep 4
done
# A17 logs relaunches as wm_relaunch_(resume_)activity (older builds: am_relaunch_activity). An
# activity that recreates itself never reaches the server, so count fresh onCreate calls too.
events=$(adb logcat -b events -d | grep -E "(wm|am)_relaunch(_resume)?_activity|wm_on_create_called")
all=$(printf '%s\n' "$events" | grep -E -c "_relaunch" || true)
mine=$(printf '%s\n' "$events" | grep -E "$ours" | grep -c . || true)
echo "flips=$flips relaunches_total=$all relaunches_or_recreates_ours=$mine"
[[ -n "$events" ]] && printf '%s\n' "$events" | grep -E "$ours"
exit $(( mine > 0 ))
