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
COLLECTOR=com.google.android.gms.unstable      # collector process handed the PIF identity (GMS/GSF/Play Store)
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
trap 'sh_ rm -f "$HELPER" >/dev/null 2>&1 || true' EXIT

# reads <who> <prop>...  → "<prop>\t<get|find>\t<value>" lines, as uid/name <who>
declare -A GOT
reads() {
  local who=$1; shift
  local args out rc
  case $who in
    app)       args="--uid $APP_UID --name $APP_NAME" ;;
    app_priv)  args="--uid $APP_UID --context u:r:su:s0 --name $APP_NAME" ;;
    collector) args="--uid $APP_UID --context u:r:gmscore_app:s0:c512,c768 --name $COLLECTOR" ;;
    vending)   args="--uid $APP_UID --context u:r:priv_app:s0:c512,c768 --name com.android.vending" ;;
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
# userdebug_or_eng_prop (ro.debuggable, ro.secure) is denied to untrusted_app by SELinux:
# find() returns <absent> while get() returns the spoofed value (when spoof is on).
get_only_absent_find() { eq "$1 get  $2" "$3" "${GOT[$1|$2|get]-}"; eq "$1 find $2" "<absent>" "${GOT[$1|$2|find]-}"; }
real() { sh_ getprop "$1"; }
norm_flavor() {
  local v=$1
  v=${v#yasvara_}; v=${v#lineage_}; v=${v#evolution_}
  case $v in
    *-userdebug) v=${v%-userdebug}-user ;;
    *-eng)       v=${v%-eng}-user ;;
  esac
  printf '%s' "$v"
}

BOOT_STORY=(
  "ro.boot.verifiedbootstate:green"
  "ro.vendor.boot.verifiedbootstate:green"
  "ro.boot.flash.locked:1"
  "ro.boot.vbmeta.device_state:locked"
  "ro.boot.veritymode:enforcing"
  "ro.secureboot.lockstate:locked"
  "init.svc.adbd:stopped"
  "sys.usb.state:mtp"
  "sys.usb.config:mtp"
)
IDENTITY_STORY=(
  "ro.build.type:user"
  "ro.vendor.build.type:user"
  "ro.build.tags:release-keys"
  "ro.adb.secure:1"
)
MARKERS=$(sh_ "getprop | sed -n 's/^\[\(ro\.lineage\.[^]]*\)\].*/\1/p' | head -2; getprop | sed -n 's/^\[\(ro\.yasvara\.[^]]*\)\].*/\1/p' | grep -vE '^ro\.yasvara\.boot\.(digest|source)$' | head -2")
SPOOF=$(real $PIF)
SPOOF_ACTIVE=1
[ "$SPOOF" = 0 ] && SPOOF_ACTIVE=0
echo "== $(real ro.build.id), $PIF=${SPOOF:-unset} (active=$SPOOF_ACTIVE)"

echo "== app process ($APP_NAME, uid $APP_UID)"
APP_STORY_PROPS=()
for entry in "${BOOT_STORY[@]}" "${IDENTITY_STORY[@]}"; do APP_STORY_PROPS+=("${entry%%:*}"); done
FLAVOR_REAL=$(real ro.build.flavor)
HOST_REAL=$(real ro.build.host)
reads app "${APP_STORY_PROPS[@]}" ro.build.flavor ro.debuggable ro.secure \
  $MARKERS $PIF.fingerprint ro.build.fingerprint ro.build.host
reads app_priv ro.debuggable ro.secure

if [ "$SPOOF_ACTIVE" = 1 ]; then
  for entry in "${BOOT_STORY[@]}" "${IDENTITY_STORY[@]}"; do
    both app "${entry%%:*}" "${entry#*:}"
  done
  [ -n "$FLAVOR_REAL" ] && both app ro.build.flavor "$(norm_flavor "$FLAVOR_REAL")"
  get_only_absent_find app ro.debuggable 0
  get_only_absent_find app ro.secure 1
  both app_priv ro.debuggable 0
  both app_priv ro.secure 1
  for m in $MARKERS; do
    hidden app "$m"
  done
else
  for p in ro.boot.verifiedbootstate ro.build.type ro.build.tags ro.build.flavor; do
    v=$(real "$p")
    [ -n "$v" ] && both app "$p" "$v" || hidden app "$p"
  done
  skip "marker hiding ($PIF is 0)"
fi
hidden app $PIF.fingerprint
both app ro.build.fingerprint "$(real ro.build.fingerprint)"
[ -n "$HOST_REAL" ] && both app ro.build.host "$HOST_REAL"

echo "== collector ($COLLECTOR + com.android.vending)"
reads collector ro.build.fingerprint ro.product.model ro.build.version.security_patch \
  ro.build.host ro.build.user init.svc.adbd sys.usb.state ro.boot.verifiedbootstate ro.build.type \
  $PIF.fingerprint
reads vending ro.build.host init.svc.adbd ro.boot.verifiedbootstate
if [ "$SPOOF_ACTIVE" = 1 ]; then
  for f in fingerprint:ro.build.fingerprint model:ro.product.model \
           security_patch:ro.build.version.security_patch; do
    staged=$(real $PIF.${f%%:*})
    if [ -n "$staged" ]; then both collector "${f#*:}" "$staged"; else skip "collector ${f#*:} (not staged)"; fi
  done
  staged_fp=$(real $PIF.fingerprint)
  [ -n "$staged_fp" ] && both collector $PIF.fingerprint "$staged_fp"
  both collector ro.build.host android-build
  both collector ro.build.user android-build
  both collector init.svc.adbd stopped
  both collector sys.usb.state mtp
  both collector ro.boot.verifiedbootstate green
  both collector ro.build.type user
  both vending ro.build.host android-build
  both vending init.svc.adbd stopped
  both vending ro.boot.verifiedbootstate green
else
  skip "collector identity ($PIF is 0)"
fi

echo "== system uid keeps the real values"
reads system ro.boot.verifiedbootstate ro.build.type ro.build.host ro.build.flavor
both system ro.boot.verifiedbootstate "$(real ro.boot.verifiedbootstate)"
both system ro.build.type "$(real ro.build.type)"
[ -n "$HOST_REAL" ] && both system ro.build.host "$HOST_REAL"
[ -n "$FLAVOR_REAL" ] && both system ro.build.flavor "$FLAVOR_REAL"

echo "== canonical boot digest across identities"
CANONICAL=$(real ro.yasvara.boot.digest)
SOURCE=$(real ro.yasvara.boot.source)
if [ ${#CANONICAL} = 64 ] || [ ${#CANONICAL} = 128 ]; then
  for who in app collector system; do
    reads "$who" ro.boot.vbmeta.digest ro.yasvara.boot.digest ro.yasvara.boot.source
    eq "$who canonical callback" "$CANONICAL" "${GOT[$who|ro.yasvara.boot.digest|find]-}"
    eq "$who digest alias callback" "$CANONICAL" "${GOT[$who|ro.boot.vbmeta.digest|find]-}"
    both "$who" ro.yasvara.boot.source "$SOURCE"
    if [ ${#CANONICAL} = 64 ]; then
      both "$who" ro.boot.vbmeta.digest "$CANONICAL"
      both "$who" ro.yasvara.boot.digest "$CANONICAL"
    else
      eq "$who SHA-512 alias is not truncated by legacy get" "" "${GOT[$who|ro.boot.vbmeta.digest|get]-}"
    fi
  done
else
  skip "canonical boot measurement unavailable; original hardware path must be retained"
fi

echo "== exec from an app"
out=$(sh_ "$HELPER --uid $APP_UID -- /system/bin/getprop ro.boot.verifiedbootstate; echo rc=\$?")
eq "dynamic getprop exits cleanly" "rc=0" "${out##*$'\n'}"
want_exec_boot=$(real ro.boot.verifiedbootstate)
[ "$SPOOF_ACTIVE" = 1 ] && want_exec_boot=green
eq "dynamic getprop sees app verified boot state" "$want_exec_boot" "${out%%$'\n'*}"

echo "== Akar client from an enrolled app"
if [ "$(real init.svc.yasvara_sessiond)" != running ]; then
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
