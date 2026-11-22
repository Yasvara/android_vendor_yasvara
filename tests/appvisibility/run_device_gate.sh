#!/bin/bash
# Checks the rules from the point of view of a caller's uid. Needs adb root.
# usage: run_device_gate.sh <target pkg> <observer pkg>
set -euo pipefail
target=$1 observer=$2
adb root >/dev/null; adb wait-for-device
uid_of() { adb shell "pm list packages -U $1" | tr -d '\r' | sed -n "s/^package:$1 uid:\([0-9,]*\).*/\1/p" | cut -d, -f1; }
sees() { adb shell "su $1 -c 'pm path $2'" 2>/dev/null | tr -d '\r' | grep -c base.apk || true; }
for caller in com.android.launcher3 com.android.systemui "$observer"; do
    echo "$caller sees $target: $(sees "$(uid_of "$caller")" "$target")"
done
adb shell dumpsys yasvara_app_visibility
