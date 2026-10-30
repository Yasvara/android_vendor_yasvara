#!/usr/bin/env bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# GPU stability per clock level, for checking an undervolt. Needs adb root.
#
# Each GPU power level is pinned in turn and gpustab runs its four workloads there against a
# reference made at the lowest level. A level fails on any wrong checksum (the GPU computed
# something wrong: the voltage is too low for that clock), on a GPU hang or reset, or by
# rebooting the phone: the level under test is written to the phone first, and the next run
# reports it.
#
#   gpustab.sh [--seconds 60] [--levels "8 7 6"] [--gap-ms 0] [--max-temp 90] [--cool 50]
#              [--out FILE]
#
# Levels are kgsl power levels, 0 the fastest; the default is every level, slowest first. The
# thermal and performance daemons' clock caps are overridden while a level runs, so a level stops
# early, as HOT, once the GPU passes --max-temp degrees. Each level waits for the GPU to cool to
# --cool degrees first, so the kernel's own thermal limit doesn't hold the clock down.

set -u

SECONDS_PER_LEVEL=60
LEVELS=""
GAP_MS=0
MAX_TEMP=90
COOL=50
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --seconds) SECONDS_PER_LEVEL=$2; shift 2 ;;
        --levels) LEVELS=$2; shift 2 ;;
        --gap-ms) GAP_MS=$2; shift 2 ;;
        --max-temp) MAX_TEMP=$2; shift 2 ;;
        --cool) COOL=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) sed -n '2,/^$/p' "$0" | sed -n 's/^# \{0,1\}//p'; exit 2 ;;
    esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../../../.." && pwd)
BIN=$(ls "$TOP"/out/target/product/*/system/bin/gpustab 2>/dev/null | head -1)
[ -n "$BIN" ] || { echo "gpustab not built: ./build.sh <device> gpustab"; exit 2; }
D=/data/local/tmp/gpustab
K=/sys/class/kgsl/kgsl-3d0
[ -n "$OUT" ] || OUT="gpustab-$(date +%Y%m%d-%H%M%S).txt"

sh() { adb shell "$@" | tr -d '\r'; }
log() { echo "$*" | tee -a "$OUT"; }

adb root >/dev/null 2>&1
adb wait-for-device
sh "mkdir -p $D"
adb push "$BIN" "$D/gpustab" >/dev/null && sh "chmod 755 $D/gpustab"

BOOT=$(sh cat /proc/sys/kernel/random/boot_id)
PREV=$(sh "cat $D/testing 2>/dev/null")
if [ -n "$PREV" ]; then
    set -- $PREV
    if [ "$1" != "$BOOT" ]; then
        log "previous run: the phone REBOOTED at level $2 ($3 MHz): unstable there"
    else
        log "previous run stopped at level $2 ($3 MHz) without a reboot"
    fi
    sh "rm -f $D/testing"
fi

COUNT=$(sh cat $K/num_pwrlevels)
read -r -a FREQS <<< "$(sh cat $K/gpu_available_frequencies)"
ORIG_MIN=$(sh cat $K/min_pwrlevel)
ORIG_MAX=$(sh cat $K/max_pwrlevel)
ORIG_MINCLK=$(sh cat $K/min_clock_mhz)
ORIG_MAXCLK=$(sh cat $K/max_clock_mhz)
[ -n "$LEVELS" ] || LEVELS=$(seq $((COUNT - 1)) -1 0 | tr '\n' ' ')

# The clock caps first, which daemons rewrite (the run below asserts them every second); then the
# levels, where kgsl keeps max_pwrlevel <= min_pwrlevel (0 is the fastest), so whichever side
# keeps that moves first.
clocks() { echo "echo $1 > $K/max_clock_mhz; echo $1 > $K/min_clock_mhz; echo $1 > $K/max_clock_mhz"; }
pin() {
    local cur
    sh "$(clocks "$(mhz "$1")")"
    cur=$(sh cat $K/max_pwrlevel)
    if [ "$1" -lt "$cur" ]; then
        sh "echo $1 > $K/max_pwrlevel; echo $1 > $K/min_pwrlevel"
    else
        sh "echo $1 > $K/min_pwrlevel; echo $1 > $K/max_pwrlevel"
    fi
}
restore() {
    sh "echo $ORIG_MAX > $K/max_pwrlevel; echo $ORIG_MIN > $K/min_pwrlevel; echo $ORIG_MAX > $K/max_pwrlevel"
    sh "echo $ORIG_MAXCLK > $K/max_clock_mhz; echo $ORIG_MINCLK > $K/min_clock_mhz; echo $ORIG_MAXCLK > $K/max_clock_mhz"
}
trap 'restore; sh "rm -f $D/testing"; exit 130' INT TERM

mhz() { echo $(( ${FREQS[$1]:-0} / 1000000 )); }
# GPU faults kgsl counted, and its fault, hang and recovery lines.
faults() {
    echo "$(sh cat $K/gpufaults | tr ' ' '+' | sed 's/+*$//' | bc) $(sh "dmesg | grep -c -i -E 'kgsl.*(fault|hang|snapshot|recover)|gmu.*(fault|timeout)'")"
}

log "gpustab $(date '+%F %T') $(sh getprop ro.product.device) kernel $(sh uname -r)"
log "levels: $COUNT, $(for i in $(seq 0 $((COUNT - 1))); do printf '%s:%s ' "$i" "$(mhz "$i")"; done)MHz"
log "thermal cap now at level $(sh cat $K/thermal_pwrlevel); GPU $(( $(sh cat $K/temp) / 1000 )) C"

# The reference, at the slowest level: the clock least likely to compute wrong.
SLOWEST=$((COUNT - 1))
pin $SLOWEST
sh "echo $BOOT $SLOWEST $(mhz $SLOWEST) > $D/testing"
if ! sh "$D/gpustab --make-ref $D/ref.bin" | tee -a "$OUT" | grep -q "RESULT REF"; then
    log "could not make the reference at $(mhz $SLOWEST) MHz"
    restore
    exit 1
fi
sh "rm -f $D/testing"

printf '%-6s %-9s %-10s %-8s %s\n' level asked_MHz ran_MHz max_C result | tee -a "$OUT"
for L in $LEVELS; do
    pin "$SLOWEST"
    waited=0
    while [ "$(( $(sh cat $K/temp) / 1000 ))" -gt "$COOL" ] && [ $waited -lt 300 ]; do
        sleep 5
        waited=$((waited + 5))
    done
    pin "$L"
    sh "echo $BOOT $L $(mhz "$L") > $D/testing"
    before=$(faults)
    # Every second: the caps again, the clock and temperature, and a stop when too hot.
    result=$(sh "( while :; do $(clocks "$(mhz "$L")"); t=\$(cat $K/temp); echo S \$(cat $K/gpuclk) \$t;
                   [ \$t -gt ${MAX_TEMP}000 ] && echo HOT && pkill -x gpustab; sleep 1; done ) & s=\$!;
                 $D/gpustab --seconds $SECONDS_PER_LEVEL --gap-ms $GAP_MS --ref $D/ref.bin; echo EXIT \$?;
                 kill \$s")
    ran=$(echo "$result" | awk '/^S /{ if ($2 > m) m = $2 } END { printf "%d", m / 1000000 }')
    hot=$(echo "$result" | awk '/^S /{ if ($3 > m) m = $3 } END { printf "%d", m / 1000 }')
    line=$(echo "$result" | grep '^RESULT' | sed 's/^RESULT //')
    [ -n "$line" ] || line="no result (gpustab died)"
    extra=""
    echo "$result" | grep -q '^HOT' && extra="$extra HOT: stopped above $MAX_TEMP C"
    [ "$(faults)" != "$before" ] && extra="$extra GPU fault (kgsl)"
    [ "$ran" -lt "$(( $(mhz "$L") - 5 ))" ] && extra="$extra (throttled: ran below the asked clock)"
    printf '%-6s %-9s %-10s %-8s %s\n' "$L" "$(mhz "$L")" "$ran" "$hot" "$line$extra" | tee -a "$OUT"
    sh "rm -f $D/testing"
    echo "$result" | grep -v '^S ' >> "$OUT"
done
restore
log "done; levels restored ($ORIG_MAX..$ORIG_MIN). Results in $OUT"
