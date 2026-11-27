#!/usr/bin/env python3
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
"""Compile/run the production Java boot-digest shim against Rust-generated YasvaraIntegrityContract,
then verify the Full Rust SSOT wire contract across Rust, Bionic, Java, and SELinux."""
import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[4]
HERE = pathlib.Path(__file__).resolve().parent
CORE = ROOT / "frameworks/base/core/java/android/security/yasvara"
SERVICE = ROOT / "frameworks/base/services/core/java/com/android/server/yasvara"
KEYSTORE = ROOT / "system/security/keystore2/src/yasvara"
BIONIC = ROOT / "bionic/libc/bionic"
INTEGRITY = ROOT / "vendor/yasvara/integrity"


def main():
    with tempfile.TemporaryDirectory(prefix="yasvara-boot-digest-") as output:
        out_dir = pathlib.Path(output)
        contract_java = out_dir / "android/security/yasvara/YasvaraIntegrityContract.java"
        contract_java.parent.mkdir(parents=True, exist_ok=True)
        generated = subprocess.check_output(
            ["cargo", "run", "--quiet", "--bin", "yasvara_integrity_codegen", "--", "--java"],
            cwd=INTEGRITY,
            text=True,
            timeout=60,
        )
        contract_java.write_text(generated, encoding="utf-8")
        subprocess.run([
            "javac", "-Xlint:all", "-Werror", "-d", output,
            str(contract_java),
            str(CORE / "YasvaraBootDigest.java"),
            str(HERE / "BootDigestHostTest.java"),
        ], check=True, timeout=30)
        subprocess.run(["java", "-cp", output, "BootDigestHostTest"], check=True, timeout=15)

    # Guard the Full Rust SSOT contract across layers.
    contract_rs = (INTEGRITY / "crates/integrity-core/src/contract.rs").read_text()
    assert 'PROP_BOOT_DIGEST: &str = "ro.yasvara.boot.digest"' in contract_rs
    assert "YasvaraIntegrityContract.PROP_BOOT_DIGEST" in (CORE / "YasvaraBootDigest.java").read_text()
    assert "PROP_BOOT_DIGEST" in (KEYSTORE / "mod.rs").read_text()
    assert 'b"ro.yasvara.boot.digest\\0"' in (INTEGRITY / "crates/integrity-bionic/src/lib.rs").read_text()

    old_symbols = ("DEFAULT_VBMETA_DIGEST", "DEFAULT_BOOT_KEY", "sBootDigestHex", "publishBootDigest")
    for folder in (CORE, KEYSTORE, BIONIC):
        for source in folder.iterdir():
            if source.suffix not in (".java", ".rs", ".cpp", ".h"):
                continue
            text = source.read_text()
            assert not any(symbol in text for symbol in old_symbols), f"old fallback/cache in {source}"

    publisher = (SERVICE / "YasvaraBootDigestPublisher.java").read_text()
    assert "YasvaraIntegrityContract.PROP_BOOT_DIGEST" in publisher
    assert "YasvaraIntegrityNative.nativeExtractHardwareBootHash" in publisher
    assert "YasvaraIntegrityNative.nativeSelectBootDigest" in publisher
    assert "bouncycastle" not in publisher, "publisher must delegate ASN.1/X.509 to Rust JNI"
    assert "checkValidity" not in publisher, "publisher must not fail on pre-NTP RTC skew"
    assert "sys.user.0.ce_available" not in publisher, "CE readiness is not user-unlocked readiness"
    assert "UserManager" in publisher and "Intent.ACTION_USER_UNLOCKED" in publisher
    assert "mThread.quitSafely()" in publisher

    service = (SERVICE / "YasvaraAttestationService.java").read_text()
    assert "YasvaraBootDigestPublisher.start" in service
    assert "YasvaraIntegrityNative.nativeNormalizePif" in service
    assert "YasvaraIntegrityNative.nativeInspectKeybox" in service

    contexts = (ROOT / "vendor/yasvara/sepolicy/private/property_contexts").read_text()
    assert "ro.yasvara.boot.digest" in contexts and "ro.yasvara.boot.source" in contexts
    print("Cross-language Full Rust SSOT contract: passed")


if __name__ == "__main__":
    main()
