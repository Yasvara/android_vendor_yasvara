#!/usr/bin/env python3
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
"""Static contract: Java publisher, init, SELinux and keystore2 agree on one keybox location.

Reads source only. It catches path/label/publication drift; it is not an Android build,
a policy compile, or a device lifecycle test.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
DIR = "/data/misc/yasvara_attest"


def read(rel):
    return (ROOT / rel).read_text()


SERVICE = "frameworks/base/services/core/java/com/android/server/yasvara/YasvaraAttestationService.java"
STORE = "frameworks/base/services/core/java/com/android/server/yasvara/YasvaraKeyboxStore.java"
MOD_RS = "system/security/keystore2/src/yasvara/mod.rs"
KEYBOX_RS = "system/security/keystore2/src/yasvara/keybox.rs"
INIT = "system/core/rootdir/init.rc"
SEPOLICY = "vendor/yasvara/sepolicy/private"


class KeyboxSsot(unittest.TestCase):
    def test_paths_agree(self):
        self.assertIn(f'Paths.get("{DIR}")', read(STORE))
        self.assertIn(f'ATTEST_DIR: &str = "{DIR}"', read(MOD_RS))
        self.assertIn('{}/keybox.xml', read(KEYBOX_RS))
        self.assertIn('{}/targets', read(MOD_RS))
        self.assertIn('"targets"', read(SERVICE))

    def test_no_keystore_tree_mirror(self):
        for rel in (SERVICE, STORE):
            code = re.sub(r"//.*|/\*.*?\*/", "", read(rel), flags=re.S)
            self.assertNotIn("/data/misc/keystore", code)
            self.assertNotRegex(code, r"(?i)chown|Os\.chmod|setOwner")

    def test_init_creates_setgid_dir(self):
        self.assertRegex(read(INIT), rf"mkdir {DIR} 02750 system keystore")
        self.assertIn(f"restorecon {DIR}", read(INIT))

    def test_selinux_label_and_access(self):
        contexts = read(f"{SEPOLICY}/file_contexts")
        self.assertRegex(contexts, r"/data/misc/yasvara_attest\(/\.\*\)\?\s+u:object_r:yasvara_attest_data_file:s0")
        te = read(f"{SEPOLICY}/yasvara_attest.te")
        self.assertRegex(te, r"type yasvara_attest_data_file,.*core_data_file_type")
        self.assertRegex(te, r"allow system_server yasvara_attest_data_file:file create_file_perms")
        self.assertRegex(te, r"allow keystore yasvara_attest_data_file:file r_file_perms")
        self.assertNotRegex(te, r"allow keystore yasvara_attest_data_file:\w+ [^;]*(write|create|unlink|rename)")
        # The keystore tree's own neverallows must stay untouched.
        self.assertNotIn("yasvara", read("system/sepolicy/private/keystore.te"))

    def test_control_plane_single_source(self):
        service = read(SERVICE)
        self.assertIn("YasvaraTrickyStore.effectiveTargets", service)
        self.assertIn("persist.sys.yasvara.trickystore", service)
        self.assertIn("persist.sys.yasvara.trickystore", read(MOD_RS))
        self.assertRegex(service, r"protectChain[\s\S]*?isEnabled\(mContext\)")
        self.assertIn("KEY_TARGETS", service)

    def test_laras_never_falls_back_to_secure_private_key(self):
        repo = read("packages/apps/Laras/src/org/yasvara/laras/data/integrity/KeyboxRepository.kt")
        imp = repo[repo.index("fun import("):repo.index("fun delete(")]
        self.assertNotIn("store.putString(IntegrityKeys.TS_KEYBOX, clean)", imp)
        self.assertIn("stripPrivateKeys(xml)", imp)
        self.assertIn("SERVICE_UNAVAILABLE", imp)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
