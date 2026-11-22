#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# Host tests of the Nada engine: bit-exact idle path, zero-delay convolver against direct
# convolution, filter responses, stage swap, upload checks, schema consistency.
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/out/host/nada-cargo}"
cd "$root/frameworks/av/services/nada/dsp"
cargo test --offline --quiet
