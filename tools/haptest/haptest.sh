#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Boost / brake / level sweep for the sih688x LRA, measured by the phone's accelerometer.
# Lay the phone flat on a soft, stable surface and don't touch it while it runs.
#
#   haptest.sh [out.csv]            full sweep
#   SWEEP="92 110" haptest.sh       custom boost list (1/10 V)
#
# Stops when the driver reports a fault, and waits for the coil to cool when its
# resistance rises more than COOL_PCT over the cold value.
set -euo pipefail

OUT=${1:-haptest-$(date +%Y%m%d-%H%M%S).csv}
SWEEP=${SWEEP:-"92 96 100 105 110"}
REPEAT=${REPEAT:-5}
COOL_PCT=${COOL_PCT:-4}
BIN=/data/local/tmp/haptest
NODE=/sys/bus/i2c/devices/5-006b
BIN_SRC=${BIN_SRC:-$(dirname "$0")/../../../../out/target/product/onyx/system/bin/haptest}

ash() { adb shell "$@"; }

adb root >/dev/null
adb wait-for-device
adb push "$BIN_SRC" "$BIN" >/dev/null
ash chmod 755 "$BIN"
ash "[ -e $NODE/fault ]" || { echo "driver has no fault node: load the patched si_haptic.ko first" >&2; exit 1; }

VB0=$(ash cat $NODE/drv_vboost | tr -dc 0-9)
restore() { ash "echo $VB0 > $NODE/drv_vboost; echo 2 0 > $NODE/brake_ctrl" || true; }
trap restore EXIT

ash "echo 0 > $NODE/fault"
R0=$(ash cat $NODE/lra_resistance | tr -dc 0-9)
echo "cold lra=${R0} mohm, vboost=${VB0}, out=$OUT" >&2

cool() {
    local r
    while :; do
        r=$(ash cat $NODE/lra_resistance | tr -dc 0-9)
        (( r * 100 <= R0 * (100 + COOL_PCT) )) && return
        echo "  coil ${r} mohm (+$(( (r - R0) * 1000 / R0 ))‰): cooling" >&2
        sleep 10
    done
}

header=--header
trial() {
    local line
    line=$(ash "$BIN $header --repeat $REPEAT $*") || { echo "haptest failed: $*" >&2; exit 1; }
    header=
    echo "$line" | tee -a "$OUT"
    # Columns 16..18: ocp, uvp, otp.
    if echo "$line" | awk -F, 'NR>0 && $1!="wave" && ($16>0 || $17>0 || $18>0) {f=1} END {exit !f}'; then
        echo "FAULT reported, stopping: $*" >&2
        ash cat $NODE/fault >&2
        exit 3
    fi
    cool
}

: > "$OUT"
for vb in $SWEEP; do
    for brake in 0 1; do
        trial --vboost "$vb" --brake "$brake" --wave kick --ms 40
        trial --vboost "$vb" --brake "$brake" --wave burst --ms 60 --tau 15
    done
    trial --vboost "$vb" --brake 0 --wave sine --ms 150 --level 1
    trial --vboost "$vb" --brake 0 --wave rumble --freq 80 --ms 200 --level 1
done

# Linearity at the top boost: a flattening rms/level curve means the mass hits its stops.
top=${SWEEP##* }
for lvl in 0.25 0.5 0.75 1.0; do
    trial --vboost "$top" --brake 0 --wave sine --ms 150 --level "$lvl"
done
echo "done: $OUT" >&2
