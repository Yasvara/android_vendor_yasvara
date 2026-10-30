#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Fingerprint parity (SPEC-0002 §3.3, M1 exit): for 20 specs, the colours Laras resolves on this
# device must be the colours SystemUI applies, bit for bit. Each spec is resolved by Laras (debug
# intent) and applied through Settings; the two fingerprints must match. Restores the user's
# colour spec at the end. Needs a debuggable build with SPEC-0002 M1.
set -u
key=yasvara_color
orig=$(adb shell settings get secure $key | tr -d '\r')
restore() {
    if [[ "$orig" == "null" ]]; then adb shell settings delete secure $key >/dev/null
    else adb shell settings put secure $key "'$orig'"; fi
}
trap restore EXIT

seeds=(FF1E6FA8 FF2E7D32 FFE0663D FF6F4E37 FFF4EBD0 FF3F51B5 FFE3A018 FF5B7083 FFC2A878 FF5C8DAE
       FFF2A7C3 FF9C4DCC FF36454F FFD81B60 FF00897B FF3D6BE0 FF808080 FFFF0000 FF0000FF FF0A0A0A)
styles=(TONAL_SPOT NEUTRAL VIBRANT EXPRESSIVE CONTENT MONOCHROMATIC RAINBOW FRUIT_SALAD FIDELITY CMF)
pass=0; fail=0
for i in "${!seeds[@]}"; do
    style=${styles[$((i % ${#styles[@]}))]}
    chroma=$(awk "BEGIN{print 0.6 + ($i % 5) * 0.3}")
    surface=$(( (i % 3) * 3 - 3 ))
    tint=$([[ $((i % 2)) == 0 ]] && echo true || echo false)
    contrast=$(awk "BEGIN{print ($i % 4) * 0.25}")
    spec="{\"v\":1,\"source\":{\"type\":\"custom\"},\"seeds\":{\"primary\":\"#${seeds[$i]}\"},\"style\":\"$style\",\"chroma\":{\"a1\":$chroma,\"n1\":$chroma},\"tint\":{\"enabled\":$tint,\"strength\":10},\"tone\":{\"surface\":$surface,\"accent\":0},\"contrast\":$contrast}"
    adb logcat -c
    adb shell am start -W -a org.yasvara.laras.action.OPEN --es yas_resolve "'$spec'" >/dev/null
    sleep 1
    laras=$(adb logcat -d -s LarasColorDebug | sed -n 's/.*fp=//p' | tail -1 | tr -d '\r')
    adb shell settings put secure $key "'$spec'"
    sleep 2
    sysui=$(adb shell dumpsys activity service com.android.systemui YasThemeState \
        | sed -n 's/.*colorFingerprint=//p' | head -1 | tr -d '\r')
    if [[ -n "$laras" && "$laras" == "$sysui" ]]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1)); echo "MISMATCH #$i $style laras=$laras sysui=$sysui"
    fi
done
echo "fingerprint parity: $pass/20 match, $fail mismatch"
exit $(( fail > 0 ))
