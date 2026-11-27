#!/usr/bin/env python3
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
"""Static contract: Rust SSOT, Java publisher, init, SELinux, Laras and keystore2 agree on one
keybox location and never leak private keys into Settings.Secure."""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
DIR = "/data/misc/yasvara_attest"


def read(rel):
    return (ROOT / rel).read_text()


CONTRACT_RS = "vendor/yasvara/integrity/crates/integrity-core/src/contract.rs"
KEYBOX_RS = "vendor/yasvara/integrity/crates/integrity-attest/src/keybox.rs"
MOD_RS = "system/security/keystore2/src/yasvara/mod.rs"
SERVICE = "frameworks/base/services/core/java/com/android/server/yasvara/YasvaraAttestationService.java"
STORE = "frameworks/base/services/core/java/com/android/server/yasvara/YasvaraKeyboxStore.java"
INIT = "system/core/rootdir/init.rc"
SEPOLICY = "vendor/yasvara/sepolicy/private"


class KeyboxSsot(unittest.TestCase):
    def test_paths_agree(self):
        self.assertIn(f'ATTEST_DIR: &str = "{DIR}"', read(CONTRACT_RS))
        self.assertIn(f'Paths.get("{DIR}")', read(STORE))
        self.assertIn("{ATTEST_DIR}/{KEYBOX_FILENAME}", read(KEYBOX_RS))
        self.assertIn("{ATTEST_DIR}/{TARGETS_FILENAME}", read(MOD_RS))
        self.assertIn("{ATTEST_DIR}/{PATCH_OVERRIDE_FILENAME}", read(MOD_RS))
        self.assertIn("YasvaraIntegrityContract.TARGETS_FILENAME", read(SERVICE))
        self.assertIn("YasvaraIntegrityContract.PATCH_OVERRIDE_FILENAME", read(SERVICE))

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
        self.assertNotIn("yasvara", read("system/sepolicy/private/keystore.te"))

    def test_control_plane_single_source(self):
        service = read(SERVICE)
        self.assertIn("YasvaraTrickyStore.effectiveTargets", service)
        self.assertIn("YasvaraIntegrityContract.PROP_TRICKY_ENABLED", service)
        self.assertIn("PROP_TRICKY_ENABLED", read(MOD_RS))
        self.assertIn("YasvaraIntegrityContract.SECURE_TRICKY_TARGETS", service)
        self.assertIn("YasvaraIntegrityContract.SECURE_INTEGRITY_PURGE_GEN", service)
        self.assertIn("YasvaraIntegrityNative.nativeInspectKeybox", service)
        self.assertIn("purgeIntegrityCache", service)
        self.assertIn("getStatus", service)
        self.assertIn("onBootDigestPublished", service)
        self.assertNotIn("getRung", service)
        self.assertNotIn("SECURE_TRICKY_RUNG", read(CONTRACT_RS))
        # Dead Java fallback classes and obsolete RungStore must remain purged.
        core = ROOT / "frameworks/base/core/java/android/security/yasvara"
        for purged in (
            "YasvaraKeySynthesizer.java",
            "YasvaraLeafPatcher.java",
            "YasvaraLadder.java",
            "YasvaraKeyboxProvider.java",
            "YasvaraAttestation.java",
            "YasvaraServiceClient.java",
        ):
            self.assertFalse((core / purged).exists(), f"dead fallback class resurfaced: {purged}")
        self.assertFalse(
            (ROOT / "packages/apps/Laras/src/org/yasvara/laras/data/integrity/RungStore.kt").exists(),
            "dead RungStore.kt resurfaced",
        )

    def test_laras_never_falls_back_to_secure_private_key(self):
        repo = read("packages/apps/Laras/src/org/yasvara/laras/data/integrity/KeyboxRepository.kt")
        imp = repo[repo.index("fun import("):repo.index("fun delete(")]
        self.assertIn("AttestationService.inspectKeybox", imp)
        self.assertIn("inspected.publicChainXml", imp)
        self.assertIn("SERVICE_UNAVAILABLE", imp)
        self.assertNotIn("YasvaraKeyboxProvider", repo)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
