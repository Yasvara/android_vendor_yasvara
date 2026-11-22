#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# review screenshots of the Settings home: light and dark, font scale 1.0 and
# 2.0, top of the page and scrolled, into golden/ next to this script (not pixel-gated).
# The screen must be on and unlocked. Restores the night mode and font scale it found.
set -u
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:-$here/golden}
pkg=com.android.settings
mkdir -p "$dir"

sh() { adb shell "$@" | tr -d '\r'; }

night=$(sh cmd uimode night | awk '{print $NF}')
font=$(sh settings get system font_scale)
restore() {
    sh cmd uimode night "$night" >/dev/null
    if [[ "$font" == null ]]; then sh settings delete system font_scale >/dev/null
    else sh settings put system font_scale "$font"; fi
    sh am force-stop $pkg
}
trap restore EXIT

size=$(sh wm size | awk '{print $NF}' | tail -1)
x=$(( ${size%x*} / 2 )) h=${size#*x}

shoot() {  # name
    sh am force-stop $pkg
    sh am start -W -n $pkg/.Settings >/dev/null
    sleep 2.5
    adb exec-out screencap -p > "$dir/home_$1.png"
    sh input swipe $x $(( h * 3 / 4 )) $x $(( h / 4 )) 400
    sleep 1.5
    adb exec-out screencap -p > "$dir/home_$1_scrolled.png"
    echo "home_$1.png home_$1_scrolled.png"
}

for mode in no yes; do
    sh cmd uimode night $mode >/dev/null
    sleep 1
    theme=$([[ $mode == yes ]] && echo dark || echo light)
    sh settings put system font_scale 1.0
    shoot "${theme}_font1.0"
    sh settings put system font_scale 2.0
    sleep 1
    shoot "${theme}_font2.0"
done
