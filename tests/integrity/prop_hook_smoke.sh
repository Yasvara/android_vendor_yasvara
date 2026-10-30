#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# On-device check of the libc.so property hooks, and of the static Akar client, as an app sees
# them. Run after every bionic change, before trusting an integrity verdict. Needs adb root and
# yasvara_app_exec (./build.sh -q onyx yasvara_app_exec). Read-only, apart from one `su -c id`
# from an enrolled app that is already running (it shows in that app's Akar audit log).
#
#   OUT=…/out/target/product/onyx vendor/yasvara/tests/integrity/prop_hook_smoke.sh
set -u
OUT=${ANDROID_PRODUCT_OUT:-${OUT:?set ANDROID_PRODUCT_OUT or OUT}}
HELPER_SRC=$OUT/data/nativetest64/yasvara_app_exec/yasvara_app_exec
HELPER=/data/local/tmp/yasvara_app_exec
APP_UID=10999                                  # any uid in the app range
APP_NAME=org.yasvara.smoke
COLLECTOR=com.google.android.gms.unstable      # the only process handed the PIF identity
PIF=persist.sys.yasvara.pif
PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
skip() { SKIP=$((SKIP+1)); echo "  skip $1"; }
sh_()  { adb shell "$@" | tr -d '\r'; }
eq()   { if [ "$3" = "$2" ]; then ok "$1"; else bad "$1 (wanted '$2', got '$3')"; fi; }

adb root >/dev/null 2>&1; adb wait-for-device
[ "$(sh_ id -u)" = 0 ] || { echo "adb root is not available (enable Rooted debugging)"; exit 2; }
[ -f "$HELPER_SRC" ] || { echo "build yasvara_app_exec first: $HELPER_SRC"; exit 2; }
adb push "$HELPER_SRC" $HELPER >/dev/null && sh_ chmod 755 $HELPER

# reads <who> <prop>...  → "<prop>\t<get|find>\t<value>" lines, as uid/name <who>
declare -A GOT
reads() {
  local who=$1; shift
  local args out rc
  case $who in
    app)       args="--uid $APP_UID --name $APP_NAME" ;;
    collector) args="--uid $APP_UID --name $COLLECTOR" ;;
    system)    args="--uid 1000 --context u:r:system_app:s0 --name com.android.settings" ;;
  esac
  out=$(sh_ "$HELPER $args --props $*; echo rc=\$?")
  rc=${out##*rc=}
  [ "$rc" = 0 ] || bad "$who reader exited $rc (libc crash?)"
  while IFS=$'\t' read -r name how value; do
    [ -n "$how" ] && GOT["$who|$name|$how"]=$value
  done <<< "${out%rc=*}"
}
# both <who> <prop> <expected>: get() and find()+read_callback() must agree
both() { eq "$1 get  $2" "$3" "${GOT[$1|$2|get]-}"; eq "$1 find $2" "$3" "${GOT[$1|$2|find]-}"; }
hidden() { eq "$1 get  $2" "" "${GOT[$1|$2|get]-}"; eq "$1 find $2" "<absent>" "${GOT[$1|$2|find]-}"; }
real() { sh_ getprop "$1"; }

STORY=(ro.boot.verifiedbootstate ro.boot.flash.locked ro.boot.vbmeta.device_state ro.build.type
       ro.build.tags ro.debuggable)
WANT=(green 1 locked user release-keys 0)
MARKERS=$(sh_ "getprop | sed -n 's/^\[\(ro\.\(yasvara\|lineage\)[^]]*\)\].*/\1/p' | head -3")
SPOOF=$(real $PIF)
echo "== $(real ro.build.id), $PIF=${SPOOF:-unset}"

echo "== app process ($APP_NAME, uid $APP_UID)"
reads app "${STORY[@]}" $MARKERS $PIF.fingerprint ro.build.fingerprint
if [ "$SPOOF" = 1 ]; then
  for i in "${!STORY[@]}"; do both app "${STORY[$i]}" "${WANT[$i]}"; done
  for m in $MARKERS; do hidden app "$m"; done
else
  skip "boot story and marker hiding ($PIF is not 1)"
fi
hidden app $PIF.fingerprint
both app ro.build.fingerprint "$(real ro.build.fingerprint)"

echo "== collector ($COLLECTOR)"
reads collector ro.build.fingerprint ro.product.model ro.build.version.security_patch \
  init.svc.adbd sys.usb.state ro.boot.verifiedbootstate
if [ "$SPOOF" = 1 ]; then
  for f in fingerprint:ro.build.fingerprint model:ro.product.model \
           security_patch:ro.build.version.security_patch; do
    staged=$(real $PIF.${f%%:*})
    if [ -n "$staged" ]; then both collector "${f#*:}" "$staged"; else skip "collector ${f#*:} (not staged)"; fi
  done
  both collector init.svc.adbd stopped
  both collector sys.usb.state mtp
  both collector ro.boot.verifiedbootstate green
else
  skip "collector identity ($PIF is not 1)"
fi

echo "== system uid keeps the real values"
reads system ro.boot.verifiedbootstate ro.build.type
both system ro.boot.verifiedbootstate "$(real ro.boot.verifiedbootstate)"
both system ro.build.type "$(real ro.build.type)"

echo "== exec from an app"
out=$(sh_ "$HELPER --uid $APP_UID -- /system/bin/getprop ro.boot.verifiedbootstate; echo rc=\$?")
eq "dynamic getprop exits cleanly" "rc=0" "${out##*$'\n'}"
[ "$SPOOF" = 1 ] && eq "dynamic getprop sees the boot story" green "${out%%$'\n'*}"

echo "== Akar client from an enrolled app"
if [ "$(real persist.yasvara.root.enabled)" != 1 ]; then
  skip "Akar is off"
else
  pid=""
  for pkg in $(sh_ "grep -v '^#' /data/misc/yasvara_root/grants.v1 | awk '{print \$8}'"); do
    pid=$(sh_ pidof "$pkg" | awk '{print $1}'); [ -n "$pid" ] && break
  done
  if [ -z "$pid" ]; then
    skip "no enrolled app is running (open one, e.g. Scene)"
  else
    out=$(sh_ "$HELPER --pid $pid -- /system/bin/sh -c 'su -c id </dev/null; echo rc=\$?'")
    eq "su from $pkg exits cleanly" "rc=0" "${out##*$'\n'}"
    case "$out" in *"uid=0(root)"*) ok "su from $pkg is root" ;; *) bad "su from $pkg: $out" ;; esac
  fi
fi

sh_ rm -f $HELPER
echo "== $PASS passed, $FAIL failed, $SKIP skipped"
[ $FAIL = 0 ]
