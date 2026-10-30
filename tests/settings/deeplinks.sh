#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# SPEC-0004 §10 deep links on the connected device, one line per check:
#   home   a deep link to the homepage with :settings:fragment_args_key scrolls the Yasvara home
#          to that tile and pulses it ("YasvaraHome: Highlighted <key>" in logcat), and the tile
#          is on screen afterwards (uiautomator).
#   pages  search-result style deep links into sub-pages (About phone included) open the page
#          with the target preference on screen (the stock highlight).
# The screen must be on and unlocked. Leaves Settings closed.
set -u
pkg=com.android.settings
fails=0

sh() { adb shell "$@" | tr -d '\r'; }
line() { printf '%-52s %s\n' "$1" "$2"; [[ "$2" == PASS* ]] || fails=$((fails + 1)); }

h=$(sh wm size | awk '{print $NF}' | tail -1); h=${h#*x}

# Whether a node whose text matches $1 (or whose content description starts with "$1,": the
# hero's rings) is fully on screen in a fresh uiautomator dump.
on_screen() {
    local text=${1//&/&amp;}
    sh uiautomator dump /sdcard/yas_deeplinks.xml >/dev/null 2>&1
    sh cat /sdcard/yas_deeplinks.xml | tr '>' '\n' |
        grep -m1 -F -e "text=\"$text\"" -e "content-desc=\"$text," | sed -n 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\2 \4/p' |
        awk -v h="$h" '{ exit !($1 >= 0 && $2 <= h && $2 > $1) }'
}

home_link() {  # key, title shown on its tile
    local key=$1 title=$2 since
    sh am force-stop $pkg
    since=$(sh "date '+%m-%d %H:%M:%S.000'")
    sh am start -W -n $pkg/.Settings -f 0x10008000 --es :settings:fragment_args_key "$key" >/dev/null
    sleep 3
    if adb logcat -d -v brief -T "$since" YasvaraHome:I '*:S' | grep -q "Highlighted $key"; then
        if on_screen "$title"; then line "home: $key" PASS; else line "home: $key" "FAIL (not on screen)"; fi
    else
        line "home: $key" "FAIL (no highlight in logcat)"
    fi
}

page_link() {  # label, intent action, key, title of the target preference
    local label=$1 action=$2 key=$3 title=$4
    sh am force-stop $pkg
    sh am start -W -a "$action" -f 0x10008000 --es :settings:fragment_args_key "$key" >/dev/null
    sleep 3
    if on_screen "$title"; then line "page: $label ($key)" PASS; else line "page: $label ($key)" "FAIL"; fi
}

if [[ "$(sh settings get global yasvara_settings_home)" == 0 ]]; then
    echo "yasvara_settings_home is 0: the home checks need the Yasvara home"
else
    home_link top_level_about_device "About phone"
    home_link top_level_location "Location"
    home_link top_level_network "Network & internet"
    # Battery and Storage have no tile: the link pulses the hero's ring.
    home_link top_level_battery "Battery"
    home_link top_level_storage "Storage"
fi
page_link "About phone" android.settings.DEVICE_INFO_SETTINGS build_number "Build number"
page_link "About phone" android.settings.DEVICE_INFO_SETTINGS legal_container "Legal & credits"
page_link "Display" android.settings.DISPLAY_SETTINGS dark_ui_mode "Dark theme"
page_link "Battery" android.intent.action.POWER_USAGE_SUMMARY battery_saver "Battery Saver"

sh rm -f /sdcard/yas_deeplinks.xml
sh am force-stop $pkg
echo "deeplinks: $([[ $fails -eq 0 ]] && echo PASS || echo "FAIL ($fails)")"
exit $(( fails > 0 ))
