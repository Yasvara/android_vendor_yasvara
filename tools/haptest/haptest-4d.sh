#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# 4D game haptics, part by part: numbered segments straight into /dev/si_haptic, each one
# isolating a piece of the game path, so the ones that crackle say where the crackle is.
# Hold the phone as in a game, don't touch the screen, and note the numbers that feel like
# grit or crackle instead of a clean buzz.
#
#   haptest-4d.sh [out.csv]          every segment
#   ONLY="4 11 12" haptest-4d.sh     just these
#   GAP=4 haptest-4d.sh              seconds of rest between segments (default 2.5)
#
#   A  plain f0 carrier at the HAL's levels: does a weak drive crackle by itself (8-bit steps)?
#   B  the same carrier in the HAL's 120-sample buffers, 2 queued: the kernel stream, not the wave
#   C  gunfire, kick + decay, up to 1300 rpm and the strong knee
#   D  the HAL's follow loop (StreamPlayer::runFollow) on game-like hits: smooth or wobbling
#      levels (a noisy sound's body), with or without its envelope tracker, long or cut tails
#   E  rumble and a blast
#
# The coil cools between segments (resistance back within COOL_PCT of cold), and the run stops
# on any driver fault.
set -euo pipefail

OUT=${1:-haptest-4d-$(date +%Y%m%d-%H%M%S).csv}
GAP=${GAP:-2.5}
COOL_PCT=${COOL_PCT:-4}
ONLY=${ONLY:-}
BIN=/data/local/tmp/haptest
NODE=/sys/bus/i2c/devices/5-006b
BIN_SRC=${BIN_SRC:-$(dirname "$0")/../../../../out/target/product/onyx/system/bin/haptest}

ash() { adb shell "$@"; }

adb root >/dev/null
adb wait-for-device
adb push "$BIN_SRC" "$BIN" >/dev/null
ash chmod 755 "$BIN"

R0=$(ash cat $NODE/lra_resistance | tr -dc 0-9)
F0=$(ash cat $NODE/f0 | tr -dc 0-9)
echo "cold coil ${R0} mohm, f0 ${F0:0:3}.${F0:3} Hz, out=$OUT" >&2

cool() {
    local r
    while :; do
        r=$(ash cat $NODE/lra_resistance | tr -dc 0-9)
        (( r * 100 <= R0 * (100 + COOL_PCT) )) && return
        echo "     coil +$(( (r - R0) * 1000 / R0 ))‰, cooling" >&2
        sleep 5
    done
}

SEGMENTS=(
    # label | haptest arguments | what it isolates
    "A1 carrier 0.28|--wave sine --ms 2000 --level 0.28|the HAL's sustain at level 1"
    "A2 carrier 0.14|--wave sine --ms 2000 --level 0.14|level 0.5"
    "A3 carrier 0.056|--wave sine --ms 2000 --level 0.056|level 0.2, a hit's body"
    "A4 carrier 0.011|--wave sine --ms 2000 --level 0.011|level 0.04, a hit's tail: ±1-2 steps of 127"
    "B5 carrier 0.14, HAL buffers|--wave sine --ms 2000 --level 0.14 --chunk 120 --ahead 2|same as A2 through the HAL's stream pacing"
    "C6 gun 600 rpm|--wave gun --rpm 600 --ms 2500 --level 0.28 --tau 30|assault rifle"
    "C7 gun 900 rpm|--wave gun --rpm 900 --ms 2500 --level 0.28 --tau 25|SMG"
    "C8 gun 1300 rpm|--wave gun --rpm 1300 --ms 2500 --level 0.28 --tau 15|fastest the detector keeps up with"
    "C9 gun 1300 rpm strong|--wave gun --rpm 1300 --ms 1500 --level 0.55 --kick 3 --tau 20|strong knee, 3 kick cycles: the hardest the bench plays"
    "D10 follow smooth|--wave follow --ms 3000 --every 300 --tau 60 --level 1 --jitter 0 --track 3|clean hits through the HAL's loop"
    "D11 follow wobble|--wave follow --ms 3000 --every 300 --tau 60 --level 1 --jitter 0.35 --track 3|levels wobbling ±35 % every 5 ms (skills, explosions)"
    "D12 follow wobble, no tracker|--wave follow --ms 3000 --every 300 --tau 60 --level 1 --jitter 0.35 --track 0|D11 without the overdrive/brake tracker"
    "D13 follow smooth, no tracker|--wave follow --ms 3000 --every 300 --tau 60 --level 1 --jitter 0 --track 0|D10 without the tracker"
    "D14 follow long tail|--wave follow --ms 3000 --every 600 --tau 200 --level 1 --end 0.03 --hit-ms 600|tails left down to 3 %"
    "D15 follow tail cut|--wave follow --ms 3000 --every 600 --tau 200 --level 1 --end 0.15 --hit-ms 600|D14 with tails cut at 15 %"
    "D16 follow wobble, HAL buffers|--wave follow --ms 3000 --every 300 --tau 60 --level 1 --jitter 0.35 --track 3 --chunk 120 --ahead 2|D11 through the HAL's stream pacing"
    "D17 follow rapid|--wave follow --ms 3000 --every 100 --tau 40 --level 1 --jitter 0.2 --track 3|600 rpm hits with wobble: skill spam, full auto"
    "E18 rumble|--wave follow --ms 3000 --every 3000 --tau 900 --level 0.6 --jitter 0.1 --hit-ms 3000 --track 3|engine / long rumble"
    "E19 blast|--wave follow --ms 2000 --every 2000 --tau 400 --level 1 --hit-ms 1200 --track 3|explosion, one hit ringing out"
)

header=--header
: > "$OUT"
total=${#SEGMENTS[@]}
echo "hold the phone, hands still; starting in 3 s" >&2
sleep 3
for i in "${!SEGMENTS[@]}"; do
    n=$((i + 1))
    if [[ -n "$ONLY" && " $ONLY " != *" $n "* ]]; then continue; fi
    IFS='|' read -r label args what <<< "${SEGMENTS[$i]}"
    cool
    printf '\n[%2d/%d] %s\n        %s\n' "$n" "$total" "$label" "$what" >&2
    # shellcheck disable=SC2086
    line=$(ash "$BIN $header --gap 0 $args --label '$label'") || { echo "haptest failed: $label" >&2; exit 1; }
    header=
    echo "$line" >> "$OUT"
    # Columns 16..18: ocp, uvp, otp.
    if echo "$line" | awk -F, '$1!="wave" && ($16>0 || $17>0 || $18>0) {f=1} END {exit !f}'; then
        echo "FAULT reported, stopping at $label" >&2
        ash cat $NODE/fault >&2
        exit 3
    fi
    echo "$line" | awk -F, '$1!="wave" {printf "        peak %.2f g, rms %.2f g, coil %d mohm\n", $9, $10, $20}' >&2
    sleep "$GAP"
done
cat >&2 <<EOF

done: $OUT
Which numbers crackled?
  only A4 (or A3/A4)        weak drive itself: 8-bit steps at low levels
  B5 but not A2             the stream transport (120-sample buffers)
  D11 but not D10           wobbling levels from the sound
  D11 but not D12           the HAL's envelope tracker amplifies the wobble
  D14 but not D15           long weak tails
  everything                chip or driver output itself
EOF
