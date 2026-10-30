#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# M0 preview colour seam spike (SPEC-0002 §11 Q6). Applies a reference palette, screenshots the
# Laras lock screen canvas, restores the user's palette, then previews the reference palette as
# a draft through each seam and screenshots again. A seam passes when its canvas matches the
# reference wherever the palette changes anything. Needs a debuggable build with Laras M0.
#
# Usage: seam_spike.sh [seed-hex]   (default E91E63)
set -eu
seed=${1:-E91E63}
out=${OUT:-/tmp/yas_seam_spike}
mkdir -p "$out"
key=theme_customization_overlay_packages
laras() {
    adb shell am force-stop org.yasvara.laras
    adb logcat -c
    adb shell am start -W -a org.yasvara.laras.action.OPEN ${1:+--es yas_seam "$1"} >/dev/null
    sleep 6
}
shot() { adb exec-out screencap > "$out/$1.raw"; }

orig=$(adb shell settings get secure $key | tr -d '\r')
restore() {
    if [[ "$orig" == "null" ]]; then adb shell settings delete secure $key >/dev/null
    else adb shell settings put secure $key "'$orig'"; fi
}
trap restore EXIT

adb shell settings put secure $key \
    "'{\"android.theme.customization.system_palette\":\"$seed\",\"android.theme.customization.color_source\":\"preset\",\"android.theme.customization.theme_style\":\"TONAL_SPOT\"}'"
sleep 4
laras capture
laras off
shot reference
canvas=$(adb logcat -d -s LarasSeamSpike | sed -n 's/.*canvas=//p' | tail -1 | tr -d '\r')
restore
sleep 4
laras off
shot applied
for seam in colorres frro; do
    laras "$seam"
    shot "$seam"
    adb logcat -d | grep -E "PreviewColorSeam|Cannot load draft" | tail -3 || true
done
laras off

echo "canvas=$canvas"
python3 - "$out" "$canvas" <<'PY'
import struct, sys
import numpy as np

def screen(path):
    """Reads raw screencap output: a little-endian header (width, height, format, …) then RGBA."""
    data = open(path, "rb").read()
    w, h = struct.unpack("<II", data[:8])
    pixels = np.frombuffer(data[len(data) - w * h * 4:], np.uint8).reshape(h, w, 4)
    return pixels[:, :, :3].astype(np.int32)

out, canvas = sys.argv[1], sys.argv[2]
l, t, r, b = map(int, canvas.split())
crop = lambda n: screen(f"{out}/{n}.raw")[t:b, l:r]
ref, applied = crop("reference"), crop("applied")
far = lambda a, c: np.abs(a - c).max(axis=2) > 12
changed = far(ref, applied)
print(f"palette-dependent pixels: {changed.sum()} of {changed.size}")
for seam in ("colorres", "frro"):
    miss = far(ref, crop(seam))
    wrong, extra = (changed & miss).sum(), (~changed & miss).sum()
    cov = 100.0 * (changed.sum() - wrong) / max(changed.sum(), 1)
    print(f"{seam}: coverage {cov:.2f}% ({wrong} palette pixels wrong, {extra} other pixels differ)")
PY
