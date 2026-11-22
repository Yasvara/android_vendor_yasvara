#!/usr/bin/env python3
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
"""Build-time contract for the verified-boot-state and release-keys build props.

Reads source and, when present, the built system/build.prop. It is not a device test: it
proves the property is generated, not that a given process reads it.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
OVERRIDE = "ro.appcompat_override.ro.boot.verifiedbootstate=green"
GEN = "build/soong/scripts/gen_build_prop.py"
CONFIG_MK = "build/make/core/config.mk"
PROCESS_LIST = "frameworks/base/services/core/java/com/android/server/am/ProcessList.java"
HOOK = "bionic/libc/bionic/yasvara_prop_hide.cpp"
HOOK_H = "bionic/libc/bionic/yasvara_prop_hide.h"
BUILD_PROP = ROOT / "out/target/product/onyx/system/build.prop"


def read(rel):
    return (ROOT / rel).read_text()


def secure_branch(src):
    """The `user`/`userdebug` block of append_additional_system_props."""
    m = re.search(r'if config\["BuildVariant"\] == "user" or config\["BuildVariant"\] == "userdebug":'
                  r'(.*?)\n  else:', src, re.S)
    assert m, "secure build-variant branch not found"
    return m.group(1)


class GeneratedProps(unittest.TestCase):
    def test_override_emitted_for_user_and_userdebug_only(self):
        src = read(GEN)
        self.assertIn(f'props.append("{OVERRIDE}")', secure_branch(src))
        self.assertEqual(src.count("verifiedbootstate"), 2)  # comment-free: one prop, one name

    def test_release_keys_for_non_eng(self):
        src = read(GEN)
        keys = re.search(r"def get_build_keys\(.*?\n\n", src, re.S).group(0)
        self.assertRegex(keys, r'get_build_variant\(product_config\) != "eng"[\s\S]*?"release-keys"')
        self.assertRegex(read(CONFIG_MK),
                         r"ifneq \(\$\(filter user userdebug,\$\(TARGET_BUILD_VARIANT\)\),\)\nBUILD_KEYS := release-keys")

    @unittest.skipUnless(BUILD_PROP.exists(), "no built system/build.prop")
    def test_built_build_prop(self):
        props = dict(l.split("=", 1) for l in BUILD_PROP.read_text().splitlines()
                     if "=" in l and not l.startswith("#"))
        self.assertEqual(props.get("ro.appcompat_override.ro.boot.verifiedbootstate"), "green")
        self.assertEqual(props.get("ro.build.tags"), "release-keys")
        self.assertTrue(props["ro.build.fingerprint"].endswith("/release-keys"))


class AppsActuallySeeIt(unittest.TestCase):
    """The override only matters if an app process resolves it before the real value."""

    def test_override_reaches_app_processes(self):
        # AOSP reads ro.appcompat_override.* only in processes zygote marked via
        # EnableOverrides(), and ProcessList marks only packages named in DeviceConfig.
        gated = "appcompat_sysprop_override_pkgs" in read(PROCESS_LIST)
        # Otherwise the libc hook must return the green state itself.
        hooked = "verifiedbootstate" in (read(HOOK) + read(HOOK_H))
        self.assertTrue(hooked or not gated,
                        "apps still read the real ro.boot.verifiedbootstate: the override is "
                        "gated to appcompat_sysprop_override_pkgs and the libc hook does not "
                        "serve it")


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
