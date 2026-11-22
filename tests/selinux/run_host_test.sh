#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

chmod +x "${SCRIPT_DIR}/selinux_leak_test.py"
echo "[selinux-test] Running SELinux Zero-Leak Unit Test Suite (SRC_ROOT=${SRC_ROOT})..."
ANDROID_BUILD_TOP="${SRC_ROOT}" python3 "${SCRIPT_DIR}/selinux_leak_test.py" "$@"

