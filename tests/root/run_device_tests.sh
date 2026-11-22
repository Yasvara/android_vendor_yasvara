#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# on-device checks of yasvara_rootd + su. Needs `adb root` (Rooted debugging) and a
# build with the daemon. Two phases:
#
#   A. daemon only — no unlock needed. The test plays system_server: it writes grants.v1 itself
#      (as root) and drives the real untrusted_app_27 "Termux" (YasvaraRootTestPeer).
#   B. control plane — needs the device unlocked (the service refuses changes otherwise):
#      YasvaraRootTestAdmin enrols/revokes through YasvaraRootService. Skipped when locked.
#
# Both apps are direct-boot aware and the test grants carry the "allow before unlock" flag, so
# phase A also runs on a freshly rebooted, still locked device.
#
#   OUT=…/out/target/product/onyx vendor/yasvara/tests/root/run_device_tests.sh
set -u
OUT=${ANDROID_PRODUCT_OUT:-${OUT:?set ANDROID_PRODUCT_OUT or OUT}}
PEER_APK=$OUT/testcases/YasvaraRootTestPeer/arm64/YasvaraRootTestPeer.apk
ADMIN_APK=$OUT/testcases/YasvaraRootTestAdmin/arm64/YasvaraRootTestAdmin.apk
PEER=org.yasvara.roottest.peer
ADMIN=org.yasvara.roottest.admin
DIR=/data/misc/yasvara_root
# apps see the client as /system/xbin/su only inside their own mount namespace, and only
# when enrolled at the time they start; the real file is /system/xbin/yasvara_su.
SU=/system/xbin/su
REAL_SU=/system/xbin/yasvara_su
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ok   $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
expect() { if [[ "$3" == *"$2"* ]]; then ok "$1"; else bad "$1 (wanted '$2', got '$(echo "$3" | head -c 300)')"; fi; }
refute() { if [[ "$3" != *"$2"* ]]; then ok "$1"; else bad "$1 (found '$2' in '$(echo "$3" | head -c 300)')"; fi; }
sh_() { adb shell "$@" | tr -d '\r'; }

adb root >/dev/null 2>&1; adb wait-for-device
[ "$(sh_ id -u)" = 0 ] || { echo "adb root is not available (enable Rooted debugging)"; exit 2; }

# The owner's real grants are not the test's to destroy: phase A writes grants.v1 itself, so
# keep a copy and put it back however the run ends.
OWNER_GRANTS=/data/local/tmp/grants.v1.owner
sh_ "cp $DIR/grants.v1 $OWNER_GRANTS 2>/dev/null; true" >/dev/null
restore_grants() {
  adb root >/dev/null 2>&1; adb wait-for-device
  # The test apps must not outlive the run: the admin app holds MANAGE_ROOT and the peer runs
  # whatever it is sent, so a leftover copy is a way for another app to root the phone.
  adb shell "setprop debug.yasvara.root.test_admin 0; pm uninstall $ADMIN; pm uninstall $PEER" >/dev/null 2>&1
  adb shell "[ -f $OWNER_GRANTS ] && cp $OWNER_GRANTS $DIR/grants.v1.new && chown system:system $DIR/grants.v1.new && chmod 660 $DIR/grants.v1.new && mv $DIR/grants.v1.new $DIR/grants.v1; rm -f $OWNER_GRANTS" >/dev/null 2>&1
}
trap restore_grants EXIT
# …and while the test runs, the owner's own grants stay in the file (their apps keep working).
OWNER_LINES=$(sh_ "grep -v '^#' $OWNER_GRANTS 2>/dev/null | grep -v '^\$' || true")

echo "== setup"
adb install -r -t "$PEER_APK" >/dev/null 2>&1 || { echo "cannot install the peer"; exit 2; }
adb install -r -t -g "$ADMIN_APK" >/dev/null 2>&1 || echo "  (admin app not installed: phase B skipped)"
sh_ setprop debug.yasvara.root.test_admin 1
UID_PEER=$(sh_ pm list packages -U $PEER | sed -n 's/.*uid:\([0-9]*\).*/\1/p' | head -1)
echo "  peer uid $UID_PEER; ROM: $(sh_ getprop ro.build.id)"
sh_ setprop ctl.start yasvara_sessiond
for _ in $(seq 1 20); do [ "$(sh_ getprop init.svc.yasvara_sessiond)" = running ] && break; sleep 0.5; done
expect "daemon is running" "running" "$(sh_ getprop init.svc.yasvara_sessiond)"
# A stale persisted switch from older builds shows up here too: persisted properties cannot be
# deleted by init, only edited out of /data/property/persistent_properties.
named=$(sh_ "getprop | grep -E 'yasvara\\.root\\.|yasvara_rootd'")
[ -z "$named" ] && ok "no property names the daemon" || bad "properties name the daemon: $named"
expect "socket exists with the right label" "yasvara_su_socket" "$(sh_ ls -lZ $DIR/run/ctl.sock)"
expect "daemon domain" "u:r:yasvara_rootd:s0" "$(sh_ ps -AZ | grep yasvara_rootd)"
expect "client is installed and labelled" "yasvara_su_client_exec" "$(sh_ ls -LZ $REAL_SU)"
expect "data dir label and owner" "yasvara_root_data_file" "$(sh_ ls -ldZ $DIR)"

grants() { # frozen [lines…]  — what system_server would write
  local f=$1; shift
  local body="# yasvara-root grants v1 frozen=$f version=$RANDOM"
  for l in "$@"; do body="$body\n$l"; done
  [ -n "$OWNER_LINES" ] && body="$body\n$OWNER_LINES"
  adb shell "printf '$body\n' > $DIR/grants.v1.new; chown system:system $DIR/grants.v1.new; chmod 660 $DIR/grants.v1.new; mv $DIR/grants.v1.new $DIR/grants.v1" >/dev/null
  sleep 0.5   # inotify → rootd rewrites enrolled.set
}
peer() { # tag cmd  → output of the command run by the peer app (untrusted_app_27)
  local tag=$1 cmd=$2
  adb logcat -c
  # A new process, so that Zygote decides about the projection from the current enrolled.set
  # (FRESH=0 keeps a running peer: revocation must work on it without a restart).
  if [ "${FRESH:-1}" = 1 ]; then
    adb shell am force-stop $PEER
    # force-stop is asynchronous: wait for the old process to be gone, or the broadcast can land
    # in it and the app keeps the mounts of its previous start.
    for _ in $(seq 1 20); do [ -z "$(adb shell pidof $PEER | tr -d '\r')" ] && break; sleep 0.2; done
    sleep 0.3
  fi
  # the command goes through the device shell: single quotes inside it must survive
  local q=${cmd//\'/\'\\\'\'}
  adb shell am broadcast -n $PEER/.Run --es tag "$tag" --es cmd "'$q'" >/dev/null
  local out=""
  for _ in $(seq 1 60); do
    out=$(adb logcat -d -s RootPeer:I | tr -d '\r' | grep "\[$tag\]" | sed "s/.*\[$tag\] //")
    [[ "$out" == *"exit="* ]] && break
    sleep 0.5
  done
  echo "$out"
}
now_ms() { date +%s%3N; }

echo "== phase A: the daemon"
grants 0
out=$(peer denied "$SU -c id")
expect "an unenrolled app has no su to run: EACCES, the same as for any name" "inaccessible or not found" "$out"
out=$(peer uniform "ls /system/xbin 2>&1; ls /system/xbin/su 2>&1; ls /system/xbin/yasvara_su 2>&1; ls /system/xbin/nothing_here 2>&1")
refute "…no ENOENT anywhere (existence is not observable)" "No such file" "$out"
expect "…every name below xbin gives the same answer" "Permission denied" "$out"
refute "…and the real ctl.sock is not reachable" "ctl.sock" "$(peer sock "ls /data/misc/yasvara_root 2>&1")"

grants 0 "$UID_PEER root global 1 0 - sig $PEER"
out=$(peer root "$SU -c id")
expect "enrolled ROOT tier runs as uid 0" "uid=0(root)" "$out"
expect "…in AOSP's su domain" "context=u:r:su:s0" "$out"

grants 0 "$UID_PEER shell global 1 0 - sig $PEER"
out=$(peer shell "$SU -c id")
expect "enrolled SHELL tier runs as uid 2000" "uid=2000(shell)" "$out"
expect "…in the enforcing shell domain" "context=u:r:shell:s0" "$out"
out=$(peer shellnoroot "$SU -t root -c id")
expect "SHELL grant cannot ask for root" "does not allow" "$out"

grants 0 "$UID_PEER root global 1 0 - sig $PEER"
out=$(peer env "$SU -c 'echo PATH=\$PATH; echo HOME=\$HOME; echo USER=\$USER'")
expect "PATH is the system one" "/system/bin" "$out"
expect "USER is root" "USER=root" "$out"
out=$(peer dac "$SU -c 'ls /data/data | grep -m3 com; id -Z'")
expect "root can list /data/data" "com." "$out"
out=$(peer net "$SU -c 'ping -c1 -W2 127.0.0.1 | grep loss'")
expect "root has network access (inet group)" "0% packet loss" "$out"
out=$(peer mnt "$SU -c 'mount | head -1; grep -c . /proc/self/mounts'")
expect "root runs in the caller's mount namespace" "exit=0" "$out"
out=$(peer exitcode "$SU -c 'exit 42'")
expect "exit code is passed through" "exit=42" "$out"
out=$(peer ver "$SU -v")
expect "su -v" ":YASVARA" "$out"
out=$(peer tsu "$SU 0 --preserve-environment -c 'PATH=/system/bin:/system/xbin:\$PATH id -u'")
expect "tsu-style invocation (user, --preserve-environment, -c)" "0" "$out"

# A restart of the daemon makes a new socket inode; the app was given the directory, so a
# process that is already running keeps working (no restart of the app needed).
grants 0 "$UID_PEER root global 1 0 - sig $PEER"
out=$(peer prerestart "$SU -c id"); expect "before a daemon restart" "uid=0(root)" "$out"
sh_ "setprop ctl.stop yasvara_sessiond; sleep 1; setprop ctl.start yasvara_sessiond; sleep 2" >/dev/null
out=$(FRESH=0 peer postrestart "$SU -c id"); expect "a running app still reaches the daemon after it restarted" "uid=0(root)" "$out"

grants 1 "$UID_PEER root global 1 0 - sig $PEER"
out=$(peer frozen "$SU -c id")
expect "frozen policy projects nothing" "inaccessible or not found" "$out"
grants 0 "$UID_PEER root global 1 1 - sig $PEER"
out=$(peer expired "$SU -c id")
expect "an expired grant refuses" "expired" "$out"
grants 0
out=$(FRESH=0 peer revoked "$SU -c id")
expect "revocation is effective at the next request (running app, no restart)" "not enrolled" "$out"
out=$(peer revoked2 "$SU -c id")
expect "…and a restarted app is no longer given su at all" "inaccessible or not found" "$out"

echo "== phase A: audit and events"
audit=$(sh_ cat $DIR/audit.0 2>/dev/null)
expect "audit has DENY lines" "|DENY|" "$audit"
expect "audit has EXEC lines" "|EXEC|" "$audit"
expect "audit has EXIT lines" "|EXIT|" "$audit"
expect "audit file is group-readable by system" "system" "$(sh_ ls -l $DIR/audit.0)"

echo "== phase A: interactive pty (adb -tt, caller is root so no grant is needed)"
out=$(timeout 20 adb shell -tt 'su -c "echo PTY=\$((40+2)); [ -t 0 ] && echo TTY=yes"' 2>&1 | tr -d '\r')
expect "pty: command output" "PTY=42" "$out"
expect "pty: shell sees a terminal" "TTY=yes" "$out"

echo "== phase A: latency (uid 0 caller, interleaved, p50 <= +3 ms, p99 <= +8 ms)"
BENCH=$OUT/system_ext/bin/yasvara_su_bench
if [ -f "$BENCH" ]; then
  adb push -q "$BENCH" /data/local/tmp/yasvara_su_bench && adb shell chmod 755 /data/local/tmp/yasvara_su_bench
  sh_ /data/local/tmp/yasvara_su_bench 300 -- /system/bin/sh -c : -- $REAL_SU -c : | sed 's/^/  /'
else
  echo "  (build it: ./build.sh onyx -k yasvara_su_bench)"
fi

echo "== phase A: policy for adb shell and other uids"
out=$(sh_ "su 2000 -c id")
expect "root can switch to another uid" "uid=2000" "$out"

echo "== collected denials of the (permissive, still being tightened) daemon domain"
sh_ "logcat -d -b all | grep 'avc:' | grep 'scontext=u:r:yasvara_rootd:s0'" | sed -E 's/.*avc: *//' | sort | uniq -c | sort -rn | head -30

echo "== phase B: control plane (needs the device unlocked)"
if [ "$(sh_ dumpsys window | grep -c 'mDreamingLockscreen=true\|isKeyguardShowing=true')" != 0 ] || [ "$(sh_ getprop sys.user.0.ce_available)" != true ]; then
  echo "  device is locked: skipped"
else
  admin() { # tag op [extras…]
    local tag=$1; shift
    adb logcat -c
    adb shell am broadcast -n $ADMIN/.Cmd --es tag "$tag" "$@" >/dev/null
    local out=""
    for _ in $(seq 1 30); do
      out=$(adb logcat -d -s RootAdmin:I | tr -d '\r' | grep "\[$tag\]" | sed "s/.*\[$tag\] //")
      [[ "$out" == *done* || "$out" == *error* || "$out" == *"no service"* ]] && break
      sleep 0.5
    done
    echo "$out"
  }
  out=$(admin s1 --es op state); expect "service: state" "enabled=true" "$out"
  out=$(admin s2 --es op selftest); expect "service: self test reaches the daemon" "ok v1" "$out"
  out=$(admin e1 --es op enroll --es pkg $PEER --ei tier 2 --ei scope 0); expect "service: enrol the peer as root" "ok=true" "$out"
  out=$(peer svc "$SU -c id"); expect "peer is root after enrolment" "uid=0(root)" "$out"
  out=$(admin g1 --es op grants); expect "service: grant listed with its package" "$PEER" "$out"
  out=$(admin f1 --es op freeze); expect "service: freeze" "ok=true" "$out"
  out=$(peer svcf "$SU -c id"); expect "frozen via the service projects nothing" "inaccessible or not found" "$out"
  admin f2 --es op unfreeze >/dev/null
  out=$(admin e2 --es op enroll --es pkg $PEER --ei tier 2 --ei scope 2 --el ms 3000); expect "service: timed grant" "ok=true" "$out"
  sleep 4
  out=$(peer svct "$SU -c id"); expect "timed grant expires without any timer" "expired" "$out"
  out=$(admin e3 --es op enroll --es pkg $PEER --ei tier 1 --ei scope 1); expect "service: until-reboot grant" "ok=true" "$out"
  out=$(peer svcr "$SU -c id"); expect "until-reboot grant works this boot" "uid=2000" "$out"
  out=$(admin v1 --es op revoke --ei uid "$UID_PEER"); expect "service: revoke" "ok=true" "$out"
  # The running app still holds its projection, so the daemon is what refuses it (and reports
  # the denial); a restarted app is then not given su at all and never reaches the daemon.
  out=$(FRESH=0 peer svcv "$SU -c id"); expect "revoked via the service: refused at the next request" "not enrolled" "$out"
  out=$(peer svcv2 "$SU -c id"); expect "…and a restarted app gets no su" "inaccessible or not found" "$out"
  out=$(admin d1 --es op denied); expect "service: denied attempts are listed" "$PEER" "$out"
  out=$(admin a1 --es op audit --ei limit 10); expect "service: audit merged" "|GRANT|" "$out"
  out=$(admin x1 --es op enroll --es pkg com.android.settings --ei tier 2 --ei scope 0); expect "service: system uids cannot be enrolled" "ok=false" "$out"
fi

echo "== phase C: adb shell su (D5), the caller is the real shell uid, not root"
write_grants() { # the test plays system_server again (needs adb root)
  grants "$@"
}
adb_as_shell() { adb unroot >/dev/null 2>&1; adb wait-for-device; sleep 1; [ "$(adb shell id -u | tr -d '\r')" = 2000 ]; }
adb_as_root() { adb root >/dev/null 2>&1; adb wait-for-device; sleep 1; }
sht() { timeout 20 adb shell "$@" 2>&1 | tr -d '\r'; }
write_grants 0 "$UID_PEER root global 1 0 - sig $PEER"
if ! adb_as_shell; then
  adb_as_root
  echo "  (adb unroot is not available: skipped)"
else
  out=$(sht 'su -c id'); expect "adb shell su is off until the owner enrols it" "not enrolled" "$out"
  adb_as_root
  write_grants 0 "2000 root global 1 0 - adb shell"
  adb_as_shell
  out=$(sht 'su -c id'); expect "enrolled adb shell gets root" "uid=0(root)" "$out"
  expect "…in the su domain" "context=u:r:su:s0" "$out"
  out=$(sht 'su -t shell -c id'); expect "adb shell can ask for the shell tier" "uid=2000(shell)" "$out"
  expect "…in the enforcing shell domain" "context=u:r:shell:s0" "$out"
  out=$(timeout 20 adb shell -tt 'su -c "id -u; [ -t 0 ] && echo TTY=yes"' 2>&1 | tr -d '\r')
  expect "adb shell -tt su: terminal" "TTY=yes" "$out"
  out=$(echo piped-in | timeout 20 adb shell 'su -c cat' 2>&1 | tr -d '\r'); expect "stdin through adb shell" "piped-in" "$out"
  out=$(sht 'su -c "id" > /data/local/tmp/yasvara_c6.txt; cat /data/local/tmp/yasvara_c6.txt; rm -f /data/local/tmp/yasvara_c6.txt')
  expect "stdout redirected to a file" "uid=0(root)" "$out"
  out=$(sht 'su -t shell -c "id" > /data/local/tmp/yasvara_c7.txt; cat /data/local/tmp/yasvara_c7.txt; rm -f /data/local/tmp/yasvara_c7.txt')
  expect "shell tier with stdout redirected to a file" "uid=2000(shell)" "$out"
  adb_as_root
  write_grants 0 "2000 shell global 1 0 - adb shell"
  adb_as_shell
  out=$(sht 'su -t root -c id'); expect "a shell-tier adb grant cannot ask for root" "does not allow" "$out"
  adb_as_root
fi

echo
echo "passed: $PASS  failed: $FAIL"
[ $FAIL = 0 ]
