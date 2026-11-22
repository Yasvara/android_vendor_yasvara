#!/usr/bin/env python3
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
"""Compile/run the production Java policy, then check its cross-language wire contract."""
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[4]
HERE = pathlib.Path(__file__).resolve().parent
CORE = ROOT / "frameworks/base/core/java/android/security/yasvara"
SERVICE = ROOT / "frameworks/base/services/core/java/com/android/server/yasvara"
RUST = ROOT / "system/security/keystore2/src/yasvara"
BIONIC = ROOT / "bionic/libc/bionic"


def main():
    with tempfile.TemporaryDirectory(prefix="yasvara-boot-digest-") as output:
        subprocess.run([
            "javac", "-Xlint:all", "-Werror", "-d", output,
            str(CORE / "YasvaraBootDigest.java"), str(HERE / "BootDigestHostTest.java"),
        ], check=True, timeout=30)
        subprocess.run(["java", "-cp", output, "BootDigestHostTest"], check=True, timeout=15)

    # Guard the contract across build systems; the runtime tests above exercise the policy.
    canonical = '"ro.yasvara.boot.digest"'
    for source in (CORE / "YasvaraBootDigest.java", RUST / "attestation.rs",
                   BIONIC / "yasvara_prop_hide.cpp"):
        assert canonical in source.read_text(), f"canonical property drift: {source}"
    old_symbols = ("DEFAULT_VBMETA_DIGEST", "DEFAULT_BOOT_KEY", "sBootDigestHex", "publishBootDigest")
    for folder in (CORE, RUST, BIONIC):
        for source in folder.iterdir():
            if source.suffix not in (".java", ".rs", ".cpp", ".h"):
                continue
            text = source.read_text()
            assert not any(symbol in text for symbol in old_symbols), f"old fallback/cache in {source}"
    publisher = (SERVICE / "YasvaraBootDigestPublisher.java").read_text()
    assert "SystemProperties.set(YasvaraBootDigest.PROPERTY, selection.digest)" in publisher
    assert "sys.user.0.ce_available" not in publisher, "CE readiness is not user-unlocked readiness"
    assert "UserManager" in publisher and "Intent.ACTION_USER_UNLOCKED" in publisher
    assert "mThread.quitSafely()" in publisher
    service = (SERVICE / "YasvaraAttestationService.java").read_text()
    assert service.index("YasvaraBootDigestPublisher.start") < service.index("new JSONObject(raw)")
    assert 'setNative("vbmeta_digest", "")' in service, "retire persistent old digest"
    contexts = (ROOT / "vendor/yasvara/sepolicy/private/property_contexts").read_text()
    assert "ro.yasvara.boot.digest" in contexts and "ro.yasvara.boot.source" in contexts
    print("Cross-language source/initialization contract: passed")


if __name__ == "__main__":
    main()
