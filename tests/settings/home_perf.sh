#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# SPEC-0004 §8 metrics of the Settings home on the connected device, one line each:
#   cold start     `am start -W` TotalTime, median of N cold launches
#   first frame    "Displayed" and "Fully drawn" from ActivityTaskManager, medians
#   entrance UI    UI-thread ms per frame while the home enters (median / p90 / max)
#   scroll         10 flings: janky frames (gfxinfo) and frames over 32 ms (framestats)
#   idle           frames drawn in 5 s, starting 6 s after the last change (must be 0)
#   PSS            dumpsys meminfo TOTAL PSS after the flings
#
# Usage: home_perf.sh [runs]            (default 10 cold launches)
#   HOME_UI=0 home_perf.sh              stock home for this run (the §8 baseline)
#   HOME_UI=1 home_perf.sh              Yasvara home for this run
# The screen must be on and unlocked. Restores yasvara_settings_home and leaves Settings closed.
set -u
runs=${1:-10}
pkg=com.android.settings
act=$pkg/.Settings

sh() { adb shell "$@" | tr -d '\r'; }

old_home=$(sh settings get global yasvara_settings_home)
restore() {
    if [[ -n "${HOME_UI:-}" ]]; then
        if [[ "$old_home" == null ]]; then
            sh settings delete global yasvara_settings_home >/dev/null
        else
            sh settings put global yasvara_settings_home "$old_home"
        fi
    fi
    sh am force-stop $pkg
}
trap restore EXIT
[[ -n "${HOME_UI:-}" ]] && sh settings put global yasvara_settings_home "$HOME_UI"

size=$(sh wm size | awk '{print $NF}' | tail -1)
w=${size%x*} h=${size#*x}
x=$(( w / 2 ))

median() { sort -n | awk '{a[NR]=$1} END {if (NR) print a[int((NR+1)/2)]; else print "n/a"}'; }

# "+1s234ms" / "+845ms" -> milliseconds
to_ms() { sed -E 's/^\+//; s/^([0-9]+)s([0-9]+)ms$/\1 \2/; s/^([0-9]+)ms$/0 \1/' |
    awk '{print $1 * 1000 + $2}'; }

# Frame rows of `dumpsys gfxinfo framestats`, as "flags uiMs totalMs" (ms, one frame per line).
frames() {
    sh dumpsys gfxinfo $pkg framestats | awk -F, '
        /^---PROFILEDATA---/ { inside = !inside; header = 1; next }
        inside && header { for (i = 1; i <= NF; i++) col[$i] = i; header = 0; next }
        inside && NF > 10 && $1 ~ /^[0-9]+$/ {
            ui = ($(col["SyncQueued"]) - $(col["HandleInputStart"])) / 1e6
            total = ($(col["FrameCompleted"]) - $(col["IntendedVsync"])) / 1e6
            if (total > 0 && total < 10000) printf "%s %.2f %.2f\n", $1, ui, total
        }'
}

# "Displayed" and "Fully drawn" are streamed while the launches run: on a phone with verbose
# window manager logs the 256 KiB ring buffer can roll over before a later `logcat -d` reads it.
atm_log=$(mktemp)
adb logcat -T 1 -v brief ActivityTaskManager:I '*:S' >"$atm_log" 2>/dev/null &
atm_pid=$!

starts=() entrance=()
for ((i = 0; i < runs; i++)); do
    sh am force-stop $pkg
    sleep 1.5
    # A fresh task: an activity of another app left on top of the Settings task (Laras, opened
    # from the home) would otherwise take the launch.
    out=$(sh am start -W -f 0x10008000 -n $act)
    starts+=("$(awk '/TotalTime/ {print $2}' <<<"$out")")
    sh dumpsys gfxinfo $pkg reset >/dev/null
    sleep 2.5
    entrance+=("$(frames | awk '$1 == 0 {print $2}')")
done
kill $atm_pid 2>/dev/null
wait $atm_pid 2>/dev/null
log=$(tr -d '\r' <"$atm_log"); rm -f "$atm_log"
mapfile -t displayed < <(grep -o "Displayed $pkg/[^:]*: +[0-9sm]*" <<<"$log" | awk '{print $NF}' | to_ms)
mapfile -t drawn < <(grep -o "Fully drawn $pkg/[^:]*: +[0-9sm]*" <<<"$log" | awk '{print $NF}' | to_ms)

printf '%-26s %s ms (runs: %s)\n' "cold start TotalTime" \
    "$(printf '%s\n' "${starts[@]}" | median)" "${starts[*]}"
printf '%-26s %s ms\n' "Displayed (median)" "$(printf '%s\n' "${displayed[@]:-}" | median)"
printf '%-26s %s ms\n' "Fully drawn (median)" "$(printf '%s\n' "${drawn[@]:-}" | median)"
printf '%s\n' "${entrance[@]}" | awk 'NF' | sort -n | awk '
    {a[NR] = $1} END {
        if (!NR) { printf "%-26s n/a\n", "entrance UI ms/frame"; exit }
        p90 = int(NR * 0.9); if (p90 < 1) p90 = 1
        printf "%-26s median %.2f  p90 %.2f  max %.2f  (%d frames)\n", "entrance UI ms/frame",
            a[int((NR + 1) / 2)], a[p90], a[NR], NR }'

# Scroll: the last cold start is on screen; let it settle, then five flings down, five up.
sleep 3
sh dumpsys gfxinfo $pkg reset >/dev/null
for ((i = 0; i < 5; i++)); do sh input swipe $x $(( h * 3 / 4 )) $x $(( h / 4 )) 90; sleep 0.9; done
for ((i = 0; i < 5; i++)); do sh input swipe $x $(( h / 4 )) $x $(( h * 3 / 4 )) 90; sleep 0.9; done
sleep 1
gfx=$(sh dumpsys gfxinfo $pkg)
printf '%-26s %s\n' "scroll janky frames" "$(grep -m1 'Janky frames:' <<<"$gfx" | sed 's/.*: //')"
printf '%-26s %s\n' "scroll frames rendered" "$(grep -m1 'Total frames rendered' <<<"$gfx" | sed 's/.*: //')"
printf '%-26s %s\n' "scroll 99th percentile" "$(grep -m1 '99th percentile' <<<"$gfx" | sed 's/.*: //')"
printf '%-26s %s\n' "scroll frames > 32 ms" "$(frames | awk '$1 == 0 && $3 > 32 {n++} END {print n + 0}')"
printf '%-26s %s\n' "PSS" "$(sh dumpsys meminfo $pkg | awk '/TOTAL PSS:/ {print $3 " KB"; exit}')"

# Idle: nothing may draw once the home has settled (§4.1: within 6 s of the last change).
sleep 6
sh dumpsys gfxinfo $pkg reset >/dev/null
sleep 5
printf '%-26s %s\n' "idle frames (5 s)" \
    "$(sh dumpsys gfxinfo $pkg | grep -m1 'Total frames rendered' | sed 's/.*: //')"
