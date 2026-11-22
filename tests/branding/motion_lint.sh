#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# motion-token lint: new Yasvara Compose code takes springs and durations only
# from MaterialTheme.motionScheme. Fails on a tween(), spring(), keyframes or repeatable spec
# written with literal numbers in the Yasvara sources below.
#
# Usage: motion_lint.sh [source dir...]   (default: YasvaraBrand and Settings' org/yasvara)
set -u
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../../../.." && pwd)
dirs=("$@")
if [[ ${#dirs[@]} -eq 0 ]]; then
    dirs=(
        "$top/vendor/yasvara/libs/YasvaraBrand/src"
        "$top/packages/apps/Settings/src/org/yasvara"
    )
fi

pattern='\b(tween|spring|keyframes|repeatable|infiniteRepeatable)\s*(<[^>]*>)?\s*\([^)]*[0-9]'
hits=$(command grep -rnE --include='*.kt' "$pattern" "${dirs[@]}" || true)
# durationMillis = 300, dampingRatio = 0.8f, stiffness = 200f written out anywhere.
hits+=$(command grep -rnE --include='*.kt' \
    '\b(durationMillis|delayMillis|dampingRatio|stiffness)\s*=\s*[0-9]' "${dirs[@]}" || true)
# Comments may name the specs.
hits=$(command grep -vE '^[^:]+:[0-9]+:\s*(\*|//)' <<<"$hits" || true)
if [[ -n "$hits" ]]; then
    echo "$hits"
    echo "motion_lint: FAIL (use MaterialTheme.motionScheme specs)"
    exit 1
fi
echo "motion_lint: PASS (${dirs[*]})"
