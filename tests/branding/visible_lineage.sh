#!/bin/bash
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
#
# no user-visible "Lineage" outside Legal & credits, licence texts and
# copyright headers. Dumps the string tables (aapt2 dump strings) of every APK the build
# installs, plus recovery's binary strings, and fails on a "Lineage" that
# visible_lineage.allow does not explain. Also fails if LineageOS statistics, whose strings are
# allowed only because nothing shows them, gets an entry point back.
#
# Usage: visible_lineage.sh [product out dir]
#   (default: $ANDROID_PRODUCT_OUT, else out/target/product/grus of this tree)
# Needs a build: it reads installed-files*.txt and the built APKs, not the device.
set -u
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../../../.." && pwd)
out=${1:-${ANDROID_PRODUCT_OUT:-$top/out/target/product/grus}}
aapt2=$top/out/host/linux-x86/bin/aapt2
[[ -x "$aapt2" ]] || aapt2=$top/prebuilts/sdk/tools/linux/bin/aapt2
[[ -d "$out" ]] || { echo "no product out dir: $out"; exit 2; }

exec python3 - "$out" "$aapt2" "$here/visible_lineage.allow" <<'PY'
import fnmatch
import glob
import os
import re
import subprocess
import sys

out, aapt2, allow_file = sys.argv[1:4]
NEEDLE = "Lineage"


def load_allow():
    entries = []
    with open(allow_file, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            target, rule, why = (line.split("\t") + ["", ""])[:3]
            kind, _, pattern = rule.partition(":")
            entries.append((target, kind, pattern, why))
    return entries


ALLOW = load_allow()


def rules_for(name, kind):
    return [(p, w) for t, k, p, w in ALLOW if k == kind and (t == "*" or t == name)]


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, errors="replace").stdout


def resource_blocks(apk):
    """resource name -> text of its values (all configs), from aapt2 dump resources."""
    blocks, name, lines = {}, None, []
    for line in run(aapt2, "dump", "resources", apk).splitlines():
        m = re.match(r"\s*resource 0x[0-9a-f]+ (\S+)", line)
        if m:
            if name:
                blocks[name] = "\n".join(lines)
            name, lines = m.group(1), []
        elif name:
            lines.append(line)
    if name:
        blocks[name] = "\n".join(lines)
    return blocks


def pool_strings(apk):
    hits = []
    for line in run(aapt2, "dump", "strings", apk).splitlines():
        m = re.match(r"String #\d+ : (.*)", line)
        if m and NEEDLE in m.group(1):
            hits.append(m.group(1))
    return hits


def installed_apks():
    apks = set()
    for listing in glob.glob(os.path.join(out, "installed-files*.txt")):
        if re.search(r"ramdisk|recovery|root", os.path.basename(listing)):
            continue
        with open(listing, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if parts and parts[-1].endswith(".apk"):
                    path = os.path.join(out, parts[-1].lstrip("/"))
                    if os.path.isfile(path):
                        apks.add(path)
    return sorted(apks)


failures, allowed, scanned = [], 0, 0

for apk in installed_apks():
    scanned += 1
    name = os.path.basename(apk)
    hits = pool_strings(apk)
    if not hits:
        continue
    blocks = None
    for hit in hits:
        if any(re.search(p, hit) for p, _ in rules_for(name, "re")):
            allowed += 1
            continue
        if blocks is None:
            blocks = resource_blocks(apk)
        # A value line of `aapt2 dump resources` reads `(config) "value`.
        first = '"' + hit.split("\n")[0][:120]
        owners = [r for r, text in blocks.items() if first in text]
        globs = [p for p, _ in rules_for(name, "res")]
        if owners and all(any(fnmatch.fnmatch(o, g) for g in globs) for o in owners):
            allowed += 1
            continue
        failures.append(f"{name}: {', '.join(owners) or '(not a resource value)'}: {hit[:160]!r}")

# Recovery: the strings of its binaries (the logo is an image: replaces it).
recovery_bins = glob.glob(os.path.join(out, "recovery", "root", "system", "bin", "recovery"))
for path in recovery_bins:
    scanned += 1
    with open(path, "rb") as f:
        data = f.read()
    for raw in re.findall(rb"[\x20-\x7e]{4,}", data):
        text = raw.decode()
        if NEEDLE.lower() not in text.lower():
            continue
        if any(re.search(p, text) for p, _ in rules_for("recovery", "re")):
            allowed += 1
            continue
        if NEEDLE in text:
            failures.append(f"recovery: {text[:160]!r}")

# LineageOS statistics must stay without an entry point (its strings are allowed only so).
for apk in installed_apks():
    if os.path.basename(apk) != "LineageParts.apk":
        continue
    for xml in ("res/xml/trust_preferences.xml", "res/xml/parts_catalog.xml"):
        tree = run(aapt2, "dump", "xmltree", "--file", xml, apk)
        if '"lineagestats"' in tree:
            failures.append(f"LineageParts.apk: {xml} offers LineageOS statistics again")

for f in failures:
    print("FAIL " + f)
print(f"visible_lineage: {'FAIL' if failures else 'PASS'} "
      f"({scanned} files, {allowed} allowed, {len(failures)} unexplained)")
sys.exit(1 if failures else 0)
PY
