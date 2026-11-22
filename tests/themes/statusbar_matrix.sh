#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# screenshot matrix: the real status bar in every battery style and icon set, in
# fixed states (SystemUI demo mode), on dark and light backgrounds. Writes the crops and an
# index.html to $OUT. Puts back every setting it changes, also when interrupted.
#
#   statusbar_matrix.sh            # all
#   statusbar_matrix.sh battery    # battery styles only
#   statusbar_matrix.sh icons      # icon sets only
set -u
here=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/yas_statusbar_$(date +%Y%m%d-%H%M%S)}
what=${1:-all}
mkdir -p "$OUT"
ash() { adb shell "$@" | tr -d '\r'; }

adb root >/dev/null 2>&1; adb wait-for-device

# What we change, to put back.
old_style=$(ash content query --uri content://lineagesettings/system \
    --where "name=\'status_bar_battery_style\'" | sed -n 's/.*value=\([^,]*\).*/\1/p')
old_percent=$(ash content query --uri content://lineagesettings/system \
    --where "name=\'status_bar_show_battery_percent\'" | sed -n 's/.*value=\([^,]*\).*/\1/p')
old_theme=$(ash settings get secure yasvara_theme)
old_demo=$(ash settings get global sysui_demo_allowed)
old_night=$(ash cmd uimode night | sed 's/Night mode: //')

lineage_put() { ash content insert --uri content://lineagesettings/system \
    --bind name:s:"$1" --bind value:s:"$2" >/dev/null; }
demo() { ash am broadcast -a com.android.systemui.demo -e command "$@" >/dev/null; }

restore() {
    demo exit
    [[ "$old_demo" == null ]] && ash settings delete global sysui_demo_allowed >/dev/null \
        || ash settings put global sysui_demo_allowed "$old_demo"
    if [[ -n "$old_style" ]]; then lineage_put status_bar_battery_style "$old_style"
    else ash content delete --uri content://lineagesettings/system \
        --where "name=\'status_bar_battery_style\'" >/dev/null; fi
    if [[ -n "$old_percent" ]]; then lineage_put status_bar_show_battery_percent "$old_percent"
    else ash content delete --uri content://lineagesettings/system \
        --where "name=\'status_bar_show_battery_percent\'" >/dev/null; fi
    if [[ "$old_theme" == null ]]; then ash settings delete secure yasvara_theme >/dev/null
    else ash settings put secure yasvara_theme "'$old_theme'"; fi
    ash cmd uimode night "$old_night" >/dev/null
    echo "restored settings; results in $OUT/index.html"
}
trap restore EXIT

# The status bar's frame, from the window manager; the right part holds icons and battery.
frame=$(ash dumpsys window windows | grep -A40 'Window{.* StatusBar}' \
    | grep -m1 -o 'mFrame=\[0,0\]\[[0-9]*,[0-9]*\]' | grep -o '[0-9]*' | tail -2)
width=$(echo "$frame" | head -1); height=$(echo "$frame" | tail -1)
width=${width:-1080}; height=${height:-90}
crop_x=$((width * 45 / 100)); crop_w=$((width - crop_x))

ash settings put global sysui_demo_allowed 1
demo enter
demo clock -e hhmm 1245
demo notifications -e visible false
demo status -e bluetooth connected -e volume vibrate -e alarm hide -e location hide
ash cmd statusbar collapse >/dev/null

# Fixed states: [name]=demo arguments for battery and network.
declare -A battery_state=(
    [57]="-e level 57 -e plugged false -e powersave false"
    [5charging]="-e level 5 -e plugged true -e powersave false"
    [30saver]="-e level 30 -e plugged false -e powersave true"
)
battery_order=(57 5charging 30saver)
declare -A icon_state=(
    [full]="mobile:-e mobile show -e level 4 -e datatype 5g -e fully true|wifi:-e wifi show -e level 4 -e fully true"
    [weak]="mobile:-e mobile show -e level 1 -e datatype lte -e fully true|wifi:-e wifi show -e level 1 -e fully true"
    [nonet]="mobile:-e mobile show -e level 3 -e datatype 4g -e fully false|wifi:-e wifi show -e level 2 -e fully false"
)
icon_order=(full weak nonet)
battery_styles=(0 100 101 102 1 3 103 2)
battery_names=(Icon Capsule Segments Ring Circle Dotted Glyph Text)
icon_sets=(aosp yas-wedge yas-blocks yas-dots yas-outline yas-mono-thin)

shoot() {  # $1 = file name; crops the right of the status bar
    ash screencap -p /data/local/tmp/yas_sb.png
    adb pull /data/local/tmp/yas_sb.png "$OUT/full.png" >/dev/null
    python3 "$here/pngcrop.py" "$OUT/full.png" "$OUT/$1" "$crop_x" 0 "$crop_w" "$height"
}

apply_icons() {  # $1 = icon state
    local part parts args
    IFS='|' read -r -a parts <<< "${icon_state[$1]}"
    for part in "${parts[@]}"; do
        read -r -a args <<< "${part#*:}"
        demo network "${args[@]}"
    done
}

html="$OUT/index.html"
echo '<!doctype html><meta charset=utf-8><title>Status bar matrix</title><style>
body{font:14px sans-serif;background:#888;margin:16px}td{padding:4px}img{display:block;height:44px}
th{text-align:left;padding:4px 8px}</style>' > "$html"

for theme in dark light; do
    [[ "$theme" == dark ]] && ash cmd uimode night yes >/dev/null || ash cmd uimode night no >/dev/null
    # Settings draws its own background, so the status bar tint is fixed per theme.
    ash am start -W -a android.settings.SETTINGS >/dev/null; sleep 2

    if [[ "$what" == all || "$what" == battery ]]; then
        apply_icons full
        lineage_put status_bar_show_battery_percent 1
        echo "<h2>Battery styles, $theme</h2><table><tr><th></th>" >> "$html"
        for s in "${battery_order[@]}"; do echo "<th>$s</th>" >> "$html"; done
        echo '</tr>' >> "$html"
        for i in "${!battery_styles[@]}"; do
            style=${battery_styles[$i]}
            lineage_put status_bar_battery_style "$style"
            echo "<tr><th>${battery_names[$i]} ($style)</th>" >> "$html"
            for s in "${battery_order[@]}"; do
                read -r -a args <<< "${battery_state[$s]}"
                demo battery "${args[@]}"; sleep 1
                f="battery_${theme}_${style}_$s.png"; shoot "$f"
                echo "<td><img src=\"$f\"></td>" >> "$html"
            done
            echo '</tr>' >> "$html"
        done
        echo '</table>' >> "$html"
        lineage_put status_bar_battery_style 0
    fi

    if [[ "$what" == all || "$what" == icons ]]; then
        demo battery -e level 57 -e plugged false -e powersave false
        echo "<h2>Icon sets, $theme</h2><table><tr><th></th>" >> "$html"
        for s in "${icon_order[@]}"; do echo "<th>$s</th>" >> "$html"; done
        echo '</tr>' >> "$html"
        for set in "${icon_sets[@]}"; do
            ash settings put secure yasvara_theme "'{\"v\":1,\"statusIcons\":\"$set\"}'"
            echo "<tr><th>$set</th>" >> "$html"
            for s in "${icon_order[@]}"; do
                apply_icons "$s"; sleep 1
                f="icons_${theme}_${set}_$s.png"; shoot "$f"
                echo "<td><img src=\"$f\"></td>" >> "$html"
            done
            echo '</tr>' >> "$html"
        done
        echo '</table>' >> "$html"
    fi
done
rm -f "$OUT/full.png"
ash rm -f /data/local/tmp/yas_sb.png
