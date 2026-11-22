#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# every entry of the stock homepage (stock keys and injected tiles) is on the
# Yasvara home. Collects the entry titles of the stock homepage (yasvara_settings_home=0) and
# every text of the Yasvara home, scrolling through each, and lists stock titles the Yasvara
# home lacks. The screen must be on and unlocked. Restores yasvara_settings_home.
set -u
pkg=com.android.settings
tmp=$(mktemp -d)

sh() { adb shell "$@" | tr -d '\r'; }

old=$(sh settings get global yasvara_settings_home)
restore() {
    if [[ "$old" == null ]]; then sh settings delete global yasvara_settings_home >/dev/null
    else sh settings put global yasvara_settings_home "$old"; fi
    sh am force-stop $pkg
    rm -rf "$tmp"
}
trap restore EXIT

size=$(sh wm size | awk '{print $NF}' | tail -1)
x=$(( ${size%x*} / 2 )) h=${size#*x}

# Texts on screen; with $1 = titles, only the stock list's entry titles (android:id/title).
# On the Yasvara home it also lists the first part of each content description: the hero's
# rings are the entries for Battery and Storage and speak "Battery, 87 percent, ...".
texts() {
    local nodes
    sh uiautomator dump /sdcard/yas_entries.xml >/dev/null 2>&1
    nodes=$(sh cat /sdcard/yas_entries.xml | tr '>' '\n')
    {
        if [[ "${1:-}" == titles ]]; then
            grep 'resource-id="android:id/title"' <<<"$nodes" | sed -n 's/.* text="\([^"]*\)".*/\1/p'
        else
            sed -n 's/.* text="\([^"]*\)".*/\1/p' <<<"$nodes"
            sed -n 's/.* content-desc="\([^",]*\)[",].*/\1/p' <<<"$nodes"
        fi
    } | sed 's/&amp;/\&/g' | grep -v '^$'
}

collect() {  # mode (0 stock, 1 Yasvara), filter
    sh settings put global yasvara_settings_home "$1"
    sh am force-stop $pkg
    sh am start -W -n $pkg/.Settings >/dev/null
    sleep 3
    for i in 1 2 3 4 5 6; do
        texts "${2:-}"
        sh input swipe $x $(( h * 3 / 4 )) $x $(( h / 4 )) 500
        sleep 1.2
    done | sort -u
}

collect 0 titles > "$tmp/stock"
collect 1 > "$tmp/yasvara"
missing=$(comm -23 "$tmp/stock" "$tmp/yasvara")
echo "stock homepage entries: $(wc -l < "$tmp/stock")"
sed 's/^/  /' "$tmp/stock"
if [[ -n "$missing" ]]; then
    echo "missing on the Yasvara home:"
    sed 's/^/  /' <<<"$missing"
    echo "home_entries: FAIL"
    exit 1
fi
echo "home_entries: PASS (every stock entry is on the Yasvara home)"
