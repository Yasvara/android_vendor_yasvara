#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# SPEC-0007 T0/T3: what an app that is not enrolled for root can observe about Akar.
#
#   exposure.sh [-o report.txt]     install the scanner, run it, print the leaks ("!" lines)
#   exposure.sh --diff A.txt B.txt  the gate: exit 1 if the reports differ
#
# The scanner (YasvaraRootTestScan) is a targetSdk-28 app, the weakest sandbox. It only reads.
set -u
OUT=${ANDROID_PRODUCT_OUT:-${OUT:-}}
PKG=org.yasvara.roottest.scan

if [ "${1:-}" = --diff ]; then
  if diff -u "$2" "$3"; then echo "reports are identical"; else echo "EXPOSURE DIFF"; exit 1; fi
  exit 0
fi
DEST=""; [ "${1:-}" = -o ] && DEST=$2
[ -n "$OUT" ] || { echo "set ANDROID_PRODUCT_OUT or OUT"; exit 2; }
APK=$OUT/testcases/YasvaraRootTestScan/arm64/YasvaraRootTestScan.apk
adb install -r -t "$APK" >/dev/null 2>&1 || { echo "cannot install the scanner"; exit 2; }
adb shell am force-stop $PKG
adb logcat -c
adb shell am broadcast -n $PKG/.Scan -a org.yasvara.roottest.scan.RUN >/dev/null
for _ in $(seq 1 60); do
  adb logcat -d -s RootScan:I | grep -q "done lines=" && break
  sleep 0.5
done
adb logcat -d -s RootScan:I | grep "done lines=" || { echo "scanner did not finish"; exit 1; }
REPORT=$(adb shell "run-as $PKG cat files/report.txt" | tr -d '\r')
[ -n "$DEST" ] && printf '%s\n' "$REPORT" > "$DEST"
echo "---- leaks (what an unenrolled app can see of Akar) ----"
printf '%s\n' "$REPORT" | grep '^!' | sed 's/^!//'
echo "---- information (stock userdebug / build posture) ----"
printf '%s\n' "$REPORT" | grep -E '^ (prop|build|selinux)\|' | sed 's/^ //'
