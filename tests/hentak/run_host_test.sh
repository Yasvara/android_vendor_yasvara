#!/bin/bash
# Hentak on the host: the Rust crate's unit tests, the v2 detector on real game audio (rounds felt,
# no cutout in long fire, knife hits felt, speech left alone), MLBB skills under the game's own
# battle music with a catalog from the phone's scan, flame, knife and hit captures through the HAL
# render, and the Wwise Vorbis decoder against ffmpeg on real MLBB banks.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
lab=$(cd "$root/.." && pwd)/lab/haptics
export PATH=$root/prebuilts/rust-toolchain/linux-x86/1.93.1/bin:$PATH
export CARGO_TARGET_DIR=$lab/v3/target
(cd "$root/frameworks/av/services/hentak/rust" && cargo test --offline --release --quiet)
(cd "$lab/v3" && cargo build --offline --release --quiet)
bin=$CARGO_TARGET_DIR/release/hentak-lab
# 73.5-82.5 s: knife, ~19 swings (a whoosh, then a thump when it lands); one hit each, not two.
"$bin" tap2 "$lab/v3/captures/df-20261104-a.wav" "$here/df-20261104-a.bursts.txt" --native \
    --hits 73.5 82.5 16 26 "$@"
# Two lines of dialogue with shots inside and after them: the shots are blasts, the speech nothing.
"$bin" tap2 "$lab/captures/hentak-voice.wav" - --native --max-impacts 0
# The hero's skill sounds felt with and without the battle music under them; the music, once
# locked, and the voice lines felt not at all.
"$bin" skills "$lab/v3/heap/mlbb" | grep -E "PASS|FAIL"
# Captures from the phone, through the detector and the HAL's follow render: X.Borg's flamethrower
# is one sustained level, not a kick per crackle; a knife at the air swishes every swing without a
# kick; a knife into the dummy, then its fall, kicks once a blow instead of rattling.
cap=$lab/v3/captures
"$bin" replay "$cap/mlbb-xborg-20261104.wav" "$cap/mlbb-20261104.htc" --gate 0.3 4.0 6 0.08 --quiet | tail -1
"$bin" replay "$cap/df-20261104-knife.wav" --gate 0.5 11.5 4 0.08 --min-driven 10 --quiet | tail -1
"$bin" replay "$cap/df-20261104-hit.wav" --gate 1.5 2.7 4 1 --quiet | tail -1
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"$bin" wem-check "$out" "$lab"/v3/heap/mlbb/*.bnk "$lab"/v3/heap/pck/*.pck | tail -1
