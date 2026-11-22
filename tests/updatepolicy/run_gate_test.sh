#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# on-device check (adb root). YasvaraTestStore updates itself the way a store does, so
# the update policy gate sees a non-exempt installer. Statuses are PackageInstaller's:
#   0 success · -1 PENDING_USER_ACTION · 7 INCOMPATIBLE (from INSTALL_FAILED_USER_RESTRICTED)
#
# M0  gate, 1 -> 2 updates: AUTO, NEVER, NEVER + allow once (consumed by the update), DELAY,
#     ASK; a same-version session (splits, repair) is never gated
# v2  a paused app is handed to Laras as update owner and back when shown in the store;
#     Skip refuses exactly the skipped version
# M2  vault: an allowed 1 -> 2 update saves version 1; rollback reinstalls it, pins Never and
#     keeps the installer of record
# M3  review: an Ask update 1 -> 2 leaves a review with version, size and signer facts
# M5  a crash right after the rollback raises the clear-data notice; an Auto app opted into
#     the vault still gets its outgoing version saved
set -u
OUT=${ANDROID_PRODUCT_OUT:?run from a lunched shell or set ANDROID_PRODUCT_OUT}
V1=$OUT/testcases/YasvaraTestStore/arm64/YasvaraTestStore.apk
V2=$OUT/testcases/YasvaraTestStoreV2/arm64/YasvaraTestStoreV2.apk
PKG=org.yasvara.teststore
svc() { adb shell service call yasvara_update_policy "$@"; }
# A service-call parcel dump as one string: the ASCII column joined, UTF-16 padding dots dropped
# (so "1.0" reads "10").
text() { sed -n "s/.*'\(.*\)').*/\1/p; s/.*'\(.*\)'\s*$/\1/p" | tr -d '\n.'; }
policy() { svc 3 s16 $PKG i32 "$1" i32 "${2:-0}" i32 0 >/dev/null; }
vc() { adb shell dumpsys package $PKG | sed -n 's/.*versionCode=\([0-9]*\).*/\1/p' | head -1; }
owner() { adb shell dumpsys package $PKG | sed -n 's/.*updateOwnerPackageName=\(.*\)/\1/p' | head -1 | tr -d '\r'; }
num() { tr -d '\t' | sed -n 's/.*Parcel( *00000000 \([0-9a-f]\{8\}\) \([0-9a-f]\{8\}\).*/\2\1/p' | head -1; }
v1() { adb install -r -d -g "$V1" >/dev/null 2>&1; }  # adb is exempt from the gate
fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 ($3)"; else echo "FAIL $1 want=$2 got=$3"; fail=1; fi; }

adb shell pm uninstall $PKG >/dev/null 2>&1
adb install -g "$V1" >/dev/null 2>&1 || { echo "install failed"; exit 1; }
adb push -q "$V2" /data/local/tmp/ts2.apk && adb shell chmod 644 /data/local/tmp/ts2.apk
# "Install unknown apps" must be allowed, or stock asks first; silent updates are throttled.
adb shell appops set $PKG REQUEST_INSTALL_PACKAGES allow
adb shell cmd package set-silent-updates-policy --allow-unlimited-silent-updates $PKG >/dev/null
sleep 2  # let the fresh install settle, or the first silent update can still ask

run() {  # run <name> <want-status> [apk]
    adb logcat -c
    if [ -n "${3:-}" ]; then
        adb shell am broadcast -n $PKG/.SelfUpdate --es apk "$3" >/dev/null
    else
        adb shell am broadcast -n $PKG/.SelfUpdate >/dev/null
    fi
    local got=""
    for _ in $(seq 1 40); do
        got=$(adb logcat -d -s TestStore:I | sed -n 's/.*result status=\(-\{0,1\}[0-9]*\).*/\1/p' | tail -1)
        [ -n "$got" ] && break
        sleep 0.5
    done
    check "$1" "$2" "${got:-none}"
}

echo "== M0 gate"
policy 0; run AUTO 0 /data/local/tmp/ts2.apk; v1
policy 3; run SAME_VERSION_NEVER 0
run NEVER 7 /data/local/tmp/ts2.apk
svc 5 s16 $PKG i64 1 i32 0 >/dev/null; run NEVER_ALLOW_ONCE 0 /data/local/tmp/ts2.apk
sleep 2
check ALLOW_ONCE_CONSUMED 0000000000000000 "$(svc 20 s16 $PKG i32 0 | num)"
v1; run NEVER_AFTER_ALLOW_ONCE 7 /data/local/tmp/ts2.apk
policy 1 7; run DELAY_7D 7 /data/local/tmp/ts2.apk
policy 2; run ASK -1 /data/local/tmp/ts2.apk

echo "== v2 owner + skip"
policy 3; sleep 1
check HIDDEN_OWNER_LARAS org.yasvara.laras "$(owner)"
svc 18 s16 $PKG i32 1 i32 0 >/dev/null; sleep 1
check SHOWN_OWNER_RESTORED "" "$(owner | grep -v null)"
svc 18 s16 $PKG i32 0 i32 0 >/dev/null; sleep 1
check HIDDEN_AGAIN org.yasvara.laras "$(owner)"
svc 21 s16 $PKG i64 2 i32 0 >/dev/null; sleep 1
check SKIP_POLICY 4 "$(svc 1 s16 $PKG i32 0 | sed -n 's/.*00000000 0000000\([0-9]\).*/\1/p')"
check SKIP_OWNER_RESTORED "" "$(owner | grep -v null)"
run SKIP_V2 7 /data/local/tmp/ts2.apk

echo "== M3 review"
policy 2; run ASK_V2 -1 /data/local/tmp/ts2.apk
review=$(svc 13 s16 $PKG i32 0 | text)
echo "$review" | grep -q "version|10|20|1|2" && check REVIEW_VERSION yes yes || check REVIEW_VERSION yes "no: $review"
echo "$review" | grep -q "signer|same" && check REVIEW_SIGNER_SAME yes yes || check REVIEW_SIGNER_SAME yes no

echo "== M2 vault + rollback"
policy 3; svc 5 s16 $PKG i64 2 i32 0 >/dev/null
run NEVER_ALLOW_V2 0 /data/local/tmp/ts2.apk
check UPDATED_TO_V2 2 "$(vc)"
svc 9 s16 $PKG i32 0 | text | grep -q "1|10|" && check VAULT_HAS_V1 yes yes || check VAULT_HAS_V1 yes no
before=$(adb shell pm list packages -i $PKG | sed -n 's/.*installer=//p' | tr -d '\r')
# rollback(pkg, 1, clearData=false, pin=true, user 0, statusReceiver=null)
svc 12 s16 $PKG i64 1 i32 0 i32 1 i32 0 i32 0 >/dev/null
for _ in $(seq 1 20); do [ "$(vc)" = 1 ] && break; sleep 0.5; done
check ROLLED_BACK_TO_V1 1 "$(vc)"
check PINNED_NEVER 3 "$(svc 1 s16 $PKG i32 0 | sed -n 's/.*00000000 0000000\([0-9]\).*/\1/p')"
check INSTALLER_KEPT "$before" "$(adb shell pm list packages -i $PKG | sed -n 's/.*installer=//p' | tr -d '\r')"

echo "== M5 rollback crash + vault opt-in"
adb logcat -c
# Start the process (a self-update of a missing file fails at once), then crash it.
adb shell am broadcast -n $PKG/.SelfUpdate --es apk /data/local/tmp/missing.apk >/dev/null
sleep 1; adb shell am crash $PKG; sleep 3
adb logcat -d -s YasvaraUpdatePolicy:W | grep -q "crashed right after a rollback" \
    && check ROLLBACK_CRASH_NOTICE yes yes || check ROLLBACK_CRASH_NOTICE yes no
policy 0
svc 10 s16 $PKG i64 0 i32 0 >/dev/null
check AUTO_VAULT_OFF 0 "$(svc 15 s16 $PKG i32 0 | sed -n 's/.*00000000 0000000\([0-9]\).*/\1/p')"
svc 14 s16 $PKG i32 1 i32 0 >/dev/null
check AUTO_VAULT_ON 1 "$(svc 15 s16 $PKG i32 0 | sed -n 's/.*00000000 0000000\([0-9]\).*/\1/p')"
run AUTO_UPDATE_V2 0 /data/local/tmp/ts2.apk
svc 9 s16 $PKG i32 0 | text | grep -q "1|10|" && check AUTO_VAULT_HAS_V1 yes yes || check AUTO_VAULT_HAS_V1 yes no
svc 14 s16 $PKG i32 0 i32 0 >/dev/null

policy 0
svc 10 s16 $PKG i64 0 i32 0 >/dev/null
adb shell cmd package set-silent-updates-policy --reset >/dev/null
adb shell rm -f /data/local/tmp/ts2.apk
adb uninstall $PKG >/dev/null
exit $fail
