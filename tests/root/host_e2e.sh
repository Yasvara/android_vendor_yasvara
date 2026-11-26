#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Host end-to-end test of yasvara_rootd + su (no Android, no privileges): the daemon is built
# with the `unprivileged-test` feature, which skips setns/setuid/setcon, so what is tested is
# the protocol, policy reload, fd passing, the pty pump, exit codes, SIGHUP, audit and limits.
#
#   vendor/yasvara/tests/root/host_e2e.sh      # builds with cargo (offline) and runs
set -u -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"                  # …/src
# Always /tmp: the sockets live in here and sun_path holds 108 bytes, which a long $TMPDIR exceeds.
W="$(mktemp -d /tmp/yre.XXXXXX)"
mkdir -p "$W/ws" "$W/data"
DAEMON=""
trap '[ -n "$DAEMON" ] && kill $DAEMON 2>/dev/null; rm -rf "$W"' EXIT

R="$ROOT/vendor/yasvara/root"
cat > "$W/ws/Cargo.toml" <<TOML
[workspace]
members = ["rootd", "su", "proto"]
resolver = "2"
TOML
mkdir -p "$W/ws"/{rootd,su,proto}
cat > "$W/ws/proto/Cargo.toml" <<TOML
[package]
name = "yasvara_root_proto"
version = "0.1.0"
edition = "2021"
[lib]
path = "$R/proto/src/lib.rs"
TOML
for c in rootd su; do
  feat=$([ $c = rootd ] && echo 'unprivileged-test = []' || echo 'host-test = []')
  cat > "$W/ws/$c/Cargo.toml" <<TOML
[package]
name = "$c"
version = "0.1.0"
edition = "2021"
[[bin]]
name = "$c"
path = "$R/$c/src/main.rs"
[features]
$feat
[dependencies]
libc = { path = "$ROOT/external/rust/android-crates-io/crates/libc" }
yasvara_root_proto = { path = "../proto" }
TOML
done
FEATURES=rootd/unprivileged-test,su/host-test
echo "== unit tests"
UT=$( cd "$W/ws" && CARGO_TARGET_DIR="$W/target" cargo test --offline --workspace --features $FEATURES 2>&1 | grep -E "^test result|FAILED|panicked|^error" )
echo "$UT"
UNIT_FAIL=0; [[ "$UT" == *FAILED* || "$UT" == *panicked* || "$UT" == *"error"* ]] && UNIT_FAIL=1
( cd "$W/ws" && CARGO_TARGET_DIR="$W/target" cargo build --offline --features $FEATURES 2>&1 | grep -E "^error" )
SU="$W/target/debug/su"; D="$W/target/debug/rootd"
export YASVARA_SU_SOCKET="$W/sock"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ok   $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
expect() { # name expected-substring actual
  if [[ "$3" == *"$2"* ]]; then ok "$1"; else bad "$1 (wanted '$2', got '$3')"; fi
}
grants() { # frozen version [lines…]
  local f=$1 v=$2; shift 2
  { echo "# yasvara-root grants v1 frozen=$f version=$v"; for l in "$@"; do echo "$l"; done; } > "$W/data/grants.v1.new"
  mv "$W/data/grants.v1.new" "$W/data/grants.v1"
}
ME=$(id -u)

"$D" --socket "$W/sock" --data-dir "$W/data" --test-unprivileged & DAEMON=$!
sleep 0.3

echo "== policy"
out=$("$SU" -c id 2>&1 </dev/null); rc=$?
expect "no policy file → denied" "not enrolled" "$out"
[ $rc = 1 ] && ok "denied exit code 1" || bad "denied exit code $rc"
# The request is queued before the verdict is read; one larger than the socket buffer blocks
# until the daemon closes, and the verdict must still come out ahead of the reset.
BIG=$(head -c 120000 /dev/zero | tr '\0' x)   # one argument is capped at 128 KiB
out=$(timeout 5 "$SU" -c "$BIG" 0 "$BIG" "$BIG" 2>&1 </dev/null); rc=$?
expect "denied with a large queued request → still the reason" "not enrolled" "$out"
[ $rc = 1 ] && ok "large queued request: exit code 1, no hang" || bad "large queued request: exit code $rc"

grants 0 1 "$ME root req 0 0 - sig com.test"
out=$("$SU" -s /bin/sh -c 'echo hello; echo err >&2; exit 7' 2>&1 </dev/null); rc=$?
expect "enrolled runs the command (stdout)" "hello" "$out"
expect "enrolled runs the command (stderr)" "err" "$out"
[ $rc = 7 ] && ok "exit code is the command's" || bad "exit code $rc, wanted 7"
out=$("$SU" -s /bin/sh 0 printf '%s|' a 'b c' 2>&1 </dev/null); rc=$?
expect "AOSP form: su 0 CMD ARGS runs CMD directly" "a|b c|" "$out"
[ $rc = 0 ] && ok "AOSP form exit code" || bad "AOSP form exit code $rc"
out=$("$SU" -s /bin/sh -c'printf "x\n"' 2>/dev/null </dev/null | od -An -tx1 | tr -d ' \n')
[ "$out" = "780a" ] && ok "attached -cCMD, byte-exact output (no CRLF)" || bad "attached -cCMD output bytes '$out'"
out=$(timeout 5 "$SU" -c "$BIG" 0 "$BIG" "$BIG" 2>&1 </dev/null)
expect "oversized request: the session's reason, not a broken pipe" "bad request" "$out"

grants 0 2
out=$("$SU" -s /bin/sh -c true 2>&1 </dev/null); expect "revocation is effective on the next request" "not enrolled" "$out"

grants 1 3 "$ME root req 0 0 - sig com.test"
out=$("$SU" -s /bin/sh -c true 2>&1 </dev/null); expect "frozen refuses" "frozen" "$out"

grants 0 4 "$ME root req 0 1 - sig com.test"      # expires 1 ms after the epoch
out=$("$SU" -s /bin/sh -c true 2>&1 </dev/null); expect "expired grant refuses" "expired" "$out"

grants 0 5 "$ME root req 0 0 not-this-boot sig com.test"
out=$("$SU" -s /bin/sh -c true 2>&1 </dev/null); expect "'until reboot' grant of another boot refuses" "expired" "$out"

echo "== enrolled.set (what Zygote reads)"
grants 0 5 "10195 root req 0 0 - sig com.a" "10100 shell req 0 0 - sig com.b"
sleep 0.3                                              # inotify → daemon rewrites the set
[ "$(od -An -tu4 -v "$W/data/enrolled.set" | tr -s ' ' | sed 's/^ //')" = "10100 10195" ] \
  && ok "set follows grants.v1 (sorted uids) without any request" || bad "enrolled.set: $(od -An -tu4 "$W/data/enrolled.set" 2>&1)"
[ "$(stat -c %a "$W/data/enrolled.set")" = 644 ] && ok "set is world-readable (zygote), not writable" || bad "enrolled.set mode"
grants 1 5 "10195 root req 0 0 - sig com.a"
sleep 0.3
[ ! -s "$W/data/enrolled.set" ] && ok "frozen policy projects nothing" || bad "frozen set not empty"

echo "== request handling"
grants 0 6 "$ME shell req 0 0 - sig com.test"
out=$("$SU" -t root -s /bin/sh -c true 2>&1 </dev/null); expect "asking for more than the grant allows" "does not allow" "$out"
out=$("$SU" -M -s /bin/sh -c true 2>&1 </dev/null); expect "global namespace needs the grant" "does not allow" "$out"
out=$("$SU" -t shell -s /bin/sh -c 'echo fine' 2>&1 </dev/null); expect "asking for less is fine" "fine" "$out"

echo "== SHELL tier (stdio relayed through daemon-owned pipes)"
out=$(echo relayed-in | "$SU" -s /bin/sh -c '/bin/cat; echo relayed-err >&2' 2>&1); expect "stdin reaches the shell, stderr comes back" "relayed-in" "$out"
expect "…stderr too" "relayed-err" "$out"
out=$("$SU" -s /bin/sh -c '/usr/bin/head -c 3000000 /dev/zero | /usr/bin/wc -c' 2>/dev/null </dev/null); expect "3 MB through the relay arrives whole" "3000000" "$out"
"$SU" -s /bin/sh -c 'exit 5' >/dev/null 2>&1 </dev/null; [ $? = 5 ] && ok "SHELL tier exit code" || bad "SHELL tier exit code"
out=$(echo ok | "$SU" -s /bin/sh -c 'read x; echo got-$x' 2>&1); expect "SHELL tier reads one line of stdin" "got-ok" "$out"

echo "== fallback: shells that cannot be an exec-time entrypoint (fork + setcon)"
out=$("$SU" -s /bin/bash -c 'echo fb-$((1+1)); exit 4' 2>&1 </dev/null); rc=$?
expect "SHELL tier, custom shell runs" "fb-2" "$out"; [ $rc = 4 ] && ok "…exit code" || bad "…exit code $rc"
grants 0 61 "$ME root req 0 0 - sig com.test"
out=$(echo in-fb | "$SU" -s /bin/bash -c '/bin/cat; exit 6' 2>&1); rc=$?
expect "ROOT tier, custom shell runs" "in-fb" "$out"; [ $rc = 6 ] && ok "…exit code" || bad "…exit code $rc"

echo "== environment and arguments"
grants 0 7 "$ME root req 0 0 - sig com.test"
out=$(LD_PRELOAD=/x.so FOO=bar PATH=/tmp "$SU" -s /bin/sh -c 'echo "LD=[$LD_PRELOAD] FOO=$FOO PATH=$PATH USER=$USER"' 2>&1 </dev/null)
expect "LD_* stripped by default" "LD=[]" "$out"; expect "env passed" "FOO=bar" "$out"
expect "PATH reset to the system one" "/system/bin" "$out"; expect "USER set" "USER=root" "$out"
out=$(LD_PRELOAD=/x.so PATH=/tmp "$SU" -p -s /bin/sh -c 'echo "LD=[$LD_PRELOAD] PATH=$PATH"' 2>&1 </dev/null)
expect "-p keeps LD_*" "LD=[/x.so]" "$out"; expect "-p keeps PATH" "PATH=/tmp" "$out"
out=$(cd /usr && "$SU" -s /bin/sh -c 'pwd' 2>&1 </dev/null); expect "cwd is the caller's" "/usr" "$out"
out=$("$SU" -s /bin/sh "$ME" -c 'echo $0 $1' x a1 2>&1 </dev/null); expect "arguments after the command" "x a1" "$out"
out=$(echo hello-from-stdin | "$SU" -s /bin/sh -c '/bin/cat' 2>&1); expect "stdin is passed through" "hello-from-stdin" "$out"
out=$("$SU" -s /nonexistent/sh -c true 2>&1 </dev/null); rc=$?
expect "missing shell is reported" "nonexistent" "$out"
[ $rc = 127 ] && ok "missing shell exit code 127" || bad "missing shell exit $rc"
out=$("$SU" -v); expect "su -v" ":YASVARA" "$out"

echo "== interactive (pty)"
PTY=$(python3 - "$SU" <<'PYEOF'
import fcntl, os, pty, select, struct, sys, termios, time
su = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.execv(su, [su, "-s", "/bin/sh"])
buf = b""
def read_until(token, timeout=5):
    global buf
    end = time.time() + timeout
    while token not in buf and time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                d = os.read(fd, 4096)
            except OSError:
                break
            if not d:
                break
            buf += d
    return token in buf
os.write(fd, b"echo $((6*7))\n")
a = read_until(b"42")
os.write(fd, b"[ -t 0 ] && echo TTY=$((40+2))\n")
b = read_until(b"TTY=42")
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 31, 97, 0, 0))
time.sleep(0.4)
os.write(fd, b"/usr/bin/stty size\n")
c = read_until(b"31 97")
os.write(fd, b"exit 3\n")
_, st = os.waitpid(pid, 0)
print(a, b, c, os.WEXITSTATUS(st))
PYEOF
)
set -- $PTY
[ "${1:-}" = True ] && ok "pty: command runs" || bad "pty: command ($PTY)"
[ "${2:-}" = True ] && ok "pty: shell sees a tty" || bad "pty: tty ($PTY)"
[ "${3:-}" = True ] && ok "pty: window size forwarded" || bad "pty: winsize ($PTY)"
[ "${4:-}" = 3 ] && ok "pty: exit code" || bad "pty: exit code ($PTY)"

echo "== lifetime"
grants 0 8 "$ME root req 0 0 - sig com.test"
"$SU" -s /bin/sh -c '/bin/sleep 30 & echo $! > '"$W"'/childpid; wait' >/dev/null 2>&1 </dev/null & SUPID=$!
sleep 0.5
kill -9 $SUPID 2>/dev/null; wait $SUPID 2>/dev/null
sleep 0.6
CP=$(cat "$W/childpid" 2>/dev/null)
if [ -n "$CP" ] && ! kill -0 "$CP" 2>/dev/null; then ok "caller killed → shell hung up"; else bad "caller killed but the shell survived (pid $CP)"; kill -9 "$CP" 2>/dev/null; fi

echo "== audit"
sleep 0.2
a="$(cat "$W/data/audit.0" 2>/dev/null)"
expect "audit has START" "|START|" "$a"; expect "audit has DENY" "|DENY|" "$a"
expect "audit has EXEC" "|EXEC|" "$a"; expect "audit has EXIT" "|EXIT|" "$a"

echo "== limits"
# global: under a confined grant each su briefly holds a second slot for its namespace retry
grants 0 9 "$ME root global 0 0 - sig com.test"
PIDS=""
for i in $(seq 1 20); do "$SU" -s /bin/sh -c '/bin/sleep 4' >/dev/null 2>&1 </dev/null & PIDS="$PIDS $!"; done
sleep 0.8
out=$("$SU" -s /bin/sh -c true 2>&1 </dev/null); expect "more than 16 sessions per uid → busy" "too many" "$out"
kill $PIDS 2>/dev/null; wait $PIDS 2>/dev/null

echo "== mount namespace handshake"
# The first frame says whether the grant needs the caller's mount namespace (an app cannot open
# /proc/self/ns/mnt under SELinux, so a global grant must not ask for it), and a confined grant
# cannot be escaped by leaving the descriptor out of the request.
probe() { # socket → "<wants|global> <ack status>" for a request that carries no namespace fd
python3 - "$1" <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
v = s.recv(16)
wants = struct.unpack("<I", v[12:16])[0] & (1 << 31)
cmd = b"true"
hdr = struct.pack("<IHHIBBHHHI6I", 0x55534159, 1, 1 << 4, 0, 0, 0, 24, 80, 0, 0o22, 0, len(cmd), 0, 0, 0, 0)
s.sendall(hdr + cmd)
a = s.recv(16)
print("wants" if wants else "global", a[5] if len(a) == 16 else "none")
PY
}
grants 0 30 "$ME root req 0 0 - sig com.test"
out=$(probe "$W/sock"); expect "confined grant asks for the namespace" "wants" "$out"
if [[ "$out" == *" 0" ]]; then bad "confined grant runs without a namespace fd"; else ok "confined grant refuses a request without a namespace fd"; fi
grants 0 31 "$ME root global 0 0 - sig com.test"
out=$(probe "$W/sock"); expect "global grant does not ask for the namespace" "global 0" "$out"
echo "== master switch and stop"
{ echo "# yasvara-root grants v1 enabled=0 frozen=0 version=40"; echo "$ME root global 0 0 - sig com.test"; } > "$W/data/grants.v1.new"
mv "$W/data/grants.v1.new" "$W/data/grants.v1"; sleep 0.2
out=$("$SU" -s /bin/sh -c true 2>&1 </dev/null); expect "enabled=0 refuses a granted uid" "root is off" "$out"
[ -s "$W/data/enrolled.set" ] && bad "enabled=0 still projects someone" || ok "enabled=0 projects nobody"
grants 0 41 "$ME root global 0 0 - sig com.test"; sleep 0.2
[ -s "$W/data/enrolled.set" ] && ok "back on: projected again" || bad "back on: nobody projected"
# init stops it with SIGTERM first (gentle_kill): nothing may be left that reads as running.
kill -TERM "$DAEMON"; for _ in $(seq 1 20); do kill -0 "$DAEMON" 2>/dev/null || break; sleep 0.05; done
kill -0 "$DAEMON" 2>/dev/null && bad "SIGTERM: daemon still running" || ok "SIGTERM: daemon exits"
[ -e "$W/sock" ] && bad "SIGTERM: socket left behind" || ok "SIGTERM: socket removed"
[ -e "$W/data/enrolled.set" ] && bad "SIGTERM: projection set left behind" || ok "SIGTERM: projection set removed"
DAEMON=""
echo "== socket handed over by init (bound, not listening)"
# init creates the socket and binds it but never calls listen(); the daemon has to. Without it
# clients get ECONNREFUSED and epoll reports EPOLLHUP forever (a busy loop). Found on the
# device, where --socket is not used.
mkdir -p "$W/data2"
IPID=$(python3 - "$W/sock2" "$D" "$W/data2" <<'PY'
import os, socket, sys
path, daemon, data = sys.argv[1:4]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path); os.chmod(path, 0o666)
os.set_inheritable(s.fileno(), True)
env = dict(os.environ, ANDROID_SOCKET_yasvara_su=str(s.fileno()))
pid = os.fork()
if pid == 0:
    # Do not hold the pipe of the $(...) this runs in open, or the substitution never ends.
    null = os.open("/dev/null", os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)
    os.execve(daemon, [daemon, "--data-dir", data, "--test-unprivileged"], env)
print(pid)
PY
)
sleep 0.4
out=$(YASVARA_SU_SOCKET="$W/sock2" "$SU" -s /bin/sh -c true 2>&1 </dev/null)
expect "inherited socket accepts clients" "not enrolled" "$out"
t0=$(awk '{print $14+$15}' /proc/$IPID/stat 2>/dev/null); sleep 2
t1=$(awk '{print $14+$15}' /proc/$IPID/stat 2>/dev/null)
if [ -n "$t0" ] && [ $((t1 - t0)) -le 1 ]; then ok "idle daemon uses no CPU (${t0}→${t1} ticks in 2 s)"; else bad "idle daemon is spinning (${t0}→${t1} ticks in 2 s)"; fi
kill "$IPID" 2>/dev/null

echo
[ "$UNIT_FAIL" = 0 ] || bad "unit tests"
echo "passed: $PASS  failed: $FAIL"
[ $FAIL = 0 ]
