#!/bin/bash
# Compiles YasvaraTabirPolicy + AppVisibilityPolicy with their unit & benchmark suite on host JDK.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
jdk=$root/prebuilts/jdk/jdk21/linux-x86/bin
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"$jdk/javac" -d "$out" \
    "$root/frameworks/base/core/java/android/security/yasvara/YasvaraTabirPolicy.java" \
    "$root/frameworks/base/core/java/android/security/yasvara/YasvaraRiskCacheReset.java" \
    "$root/frameworks/base/services/core/java/com/android/server/yasvara/visibility/AppVisibilityPolicy.java" \
    "$here/AppVisibilityPolicyTest.java"
"$jdk/java" -cp "$out" AppVisibilityPolicyTest
python3 "$here/tabir_contract_test.py"
