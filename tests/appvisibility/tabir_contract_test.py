#!/usr/bin/env python3
# SPDX-FileCopyrightText: The Yasvara Project
# SPDX-License-Identifier: Apache-2.0
"""Anti-false-report regression & cross-layer contract tests for Tabir, Kait, Zygisk, and Akar.

Ensures policy unit tests can never report false-green while framework call sites, shared-Bundle
defensive cloning, system Xposed module discovery, Kait uninstall wiring, or conceal invariants
regress.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[4]


def read(rel: str) -> str:
    return (SRC / rel).read_text(encoding="utf-8")


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def extract_brace_block(text: str, signature_re: str) -> str:
    m = re.search(signature_re, text, re.S)
    if not m:
        raise AssertionError(f"Method/block not found: {signature_re}")
    start = text.find("{", m.start())
    if start < 0:
        raise AssertionError(f"Opening brace not found for: {signature_re}")
    depth = 0
    for i in range(start, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise AssertionError(f"Unbalanced braces for: {signature_re}")


class TestComputerEngineXposedStripCoverage(unittest.TestCase):
    """Prevents the Duck Detector 'Xposed meta-data: 4 module(s)' false-green regression."""

    def setUp(self) -> None:
        self.ce = read("frameworks/base/services/core/java/com/android/server/pm/ComputerEngine.java")

    def test_strip_clones_shared_bundle_before_mutating(self) -> None:
        body = extract_brace_block(
            self.ce, r"private static Bundle stripXposedMetaDataBundle\(Bundle metaData\)"
        )
        self.assertIn("new Bundle(metaData)", body, "Must defensively clone AndroidPackage shared Bundle")
        self.assertNotIn("metaData.remove(", body, "Must never mutate caller/shared Bundle in-place")
        self.assertRegex(body, r"return\s+\w+\.isEmpty\(\)\s*\?\s*null\s*:\s*\w+;")

    def test_every_app_facing_application_info_path_strips_xposed_metadata(self) -> None:
        # 1. getApplicationInfoInternalBody
        body = extract_brace_block(self.ce, r"protected ApplicationInfo getApplicationInfoInternalBody\(")
        self.assertIn("stripXposedMetaData(", body)

        # 2. generateApplicationInfoFromSettings
        settings_body = extract_brace_block(
            self.ce, r"public final ApplicationInfo generateApplicationInfoFromSettings\("
        )
        self.assertIn("stripXposedMetaData(ai,", settings_body)

        # 3. getInstalledApplications MUST strip in BOTH the MATCH_UNINSTALLED_PACKAGES loop
        #    AND the normal installed packages loop (exact API Duck Detector calls!).
        inst_body = extract_brace_block(
            self.ce, r"public List<ApplicationInfo> getInstalledApplications\("
        )
        self.assertGreaterEqual(
            inst_body.count("stripXposedMetaData(ai,"),
            2,
            "getInstalledApplications must strip Xposed meta-data in BOTH installed and uninstalled loops",
        )

        # 4. generatePackageInfo
        pkg_body = extract_brace_block(self.ce, r"public final PackageInfo generatePackageInfo\(")
        self.assertIn("stripXposedMetaData(packageInfo,", pkg_body)


class TestTabirServiceAndRootSyncContracts(unittest.TestCase):
    """Prevents system Xposed module blind spots, missing MTG hiding, and Tabir<->Akar drift."""

    def test_visibility_service_discovers_system_xposed_modules_and_syncs_akar(self) -> None:
        svc = read(
            "frameworks/base/services/core/java/com/android/server/yasvara/visibility/"
            "YasvaraAppVisibilityService.java"
        )
        self.assertIn('pkg.startsWith("com.mtg.")', svc)
        for tool in (
            "com.eltavine.duckdetector",
            "io.github.vvb2060.keyattestation",
            "gr.nikolasspyr.integritycheck",
            "io.github.a13e300.ksuwebui",
        ):
            self.assertIn(tool, svc, f"Missing known root/detection tool: {tool}")
        # System branch in rebuildLocked MUST inspect META_XPOSED so system Kait modules are covered.
        sys_block = extract_brace_block(svc, r"if \(sys\) \{")
        self.assertIn("META_XPOSED", sys_block)
        self.assertIn("modulesSet.add(pkg)", sys_block)
        self.assertIn("xposedModuleAppIds.add(appId)", sys_block)
        self.assertIn("YasvaraRootService.syncTabirProtectedUids", svc)
        self.assertIn("YasvaraRiskCacheReset.mergePackageEpoch", svc)

    def test_root_service_syncs_tabir_uids_into_zygisk_and_unmount_confs(self) -> None:
        root_svc = read(
            "frameworks/base/services/core/java/com/android/server/yasvara/root/YasvaraRootService.java"
        )
        self.assertIn("public static void syncTabirProtectedUids(int[] appIds)", root_svc)
        self.assertIn("zygisk.conf", root_svc)
        self.assertIn("unmount.conf", root_svc)
        self.assertIn("# tabir=", root_svc)

    def test_spoof_engine_uses_ssot_risk_reset_and_neutral_temp_stamp(self) -> None:
        spoof = read("frameworks/base/core/java/android/security/yasvara/YasvaraSpoofEngine.java")
        self.assertIn("YasvaraRiskCacheReset.applyIfNeeded(", spoof)
        self.assertIn("purgeStaleAttestationKeys(packageName)", spoof)
        self.assertIn("YasvaraRiskCacheReset.isProtectedKeyAlias(alias)", spoof)
        self.assertIn("YasvaraRiskCacheReset.isStaleAttestationAlias(alias)", spoof)
        self.assertIn("KeyProperties.PURPOSE_ATTEST_KEY", spoof)
        self.assertIn('stampFile.getName() + ".tmp." + Process.myPid()', spoof)
        self.assertNotIn('DG_STAMP_FILE + ".tmp."', spoof)

    def test_kernel_overlay_mount_visibility_wired_across_all_surfaces(self) -> None:
        fd_c = read("kernel/xiaomi/sm8735/fs/proc/fd.c")
        stat_c = read("kernel/xiaomi/sm8735/fs/stat.c")
        proc_ns_c = read("kernel/xiaomi/sm8735/fs/proc_namespace.c")
        ns_c = read("kernel/xiaomi/sm8735/fs/namespace.c")
        mmu_c = read("kernel/xiaomi/sm8735/fs/proc/task_mmu.c")
        self.assertIn("yasvara_resolve_visible_mount(", fd_c)
        self.assertIn("yasvara_resolve_visible_mount(", stat_c)
        self.assertIn("yasvara_visible_dev(", stat_c)
        self.assertIn("yasvara_resolve_visible_parent(", proc_ns_c)
        self.assertIn("yasvara_resolve_visible_parent(", ns_c)
        self.assertIn("yasvara_visible_dev(", mmu_c)


class TestKaitUninstallEndToEndContract(unittest.TestCase):
    """Prevents the 3-part Kait module uninstall bug from regressing."""

    def test_laras_permissions_intent_and_resume_refresh(self) -> None:
        manifest = read("packages/apps/Laras/AndroidManifest.xml")
        self.assertIn("android.permission.REQUEST_DELETE_PACKAGES", manifest)
        self.assertIn("android.permission.DELETE_PACKAGES", manifest)
        privapp = read("packages/apps/Laras/org.yasvara.laras.xml")
        self.assertIn("android.permission.DELETE_PACKAGES", privapp)
        repo = read("packages/apps/Laras/src/org/yasvara/laras/data/kait/KaitRepository.kt")
        self.assertIn("Intent.ACTION_DELETE", repo)
        ui = read("packages/apps/Laras/src/org/yasvara/laras/ui/kait/ModulesSection.kt")
        self.assertIn("Lifecycle.Event.ON_RESUME", ui)
        self.assertIn("viewModel.refresh(loadRepo = false)", ui)

    def test_kait_service_prunes_on_package_removal_and_boot(self) -> None:
        svc = read(
            "frameworks/base/services/core/java/com/android/server/yasvara/kait/KaitManagerService.java"
        )
        loader = read(
            "frameworks/base/services/core/java/com/android/server/yasvara/kait/ModuleLoader.java"
        )
        self.assertIn("ACTION_PACKAGE_REMOVED", svc)
        self.assertIn("ACTION_PACKAGE_FULLY_REMOVED", svc)
        self.assertIn("ACTION_LOCKED_BOOT_COMPLETED", svc)
        self.assertIn("mConfig.forget(", svc)
        self.assertIn("mLoader.pruneMissing(", svc)
        self.assertIn("void pruneMissing(", loader)


class TestHardeningAndConcealInvariants(unittest.TestCase):
    """Verifies L1-L9, OH-1..OH-5, BUG-Z1/Z2/M1 stay closed."""

    def test_l1_l2_l4_l9_conceal_contracts(self) -> None:
        # L1: Zygisk claims ART hook via hidden GetEnv magic, zero dlsym.
        z_lib = strip_c_comments(read("vendor/yasvara/zygisk/src/lib.rs"))
        self.assertIn("0x595A_4A48", z_lib)
        self.assertNotIn("yasvara_zygisk_hook_jni", z_lib)
        vm_ext = strip_c_comments(read("art/runtime/jni/java_vm_ext.cc"))
        self.assertIn("0x595A4A48", vm_ext)
        self.assertIn("getuid() == 0", vm_ext)

        # L2: Kait receives private ResXmlOps vtable, zero dlsym yasvara_kait_xml_*.
        k_lib = strip_c_comments(read("vendor/yasvara/kait/rust/jni/src/lib.rs"))
        self.assertIn("KaitResXmlOps", k_lib)
        self.assertNotIn("yasvara_kait_xml_", k_lib)

        # L4: Companion installs in xbin, not system_ext/bin.
        z_bp = read("vendor/yasvara/zygisk/Android.bp")
        self.assertIn("install_in_xbin: true", z_bp)
        comp_rs = read("vendor/yasvara/root/rootd/src/zygisk_companion.rs")
        self.assertIn("/system/xbin/yasvara_zygisk_companion", comp_rs)

        # L9: Framework overlays mapped into every app carry neutral APK names.
        ov_bp = read("vendor/yasvara-gms/overlay/Android.bp")
        gms_mk = read("vendor/yasvara-gms/products/gms.mk")
        self.assertNotIn("YasvaraGoogleWebViewOverlay", ov_bp.split("resource_dirs")[0])
        self.assertIn('name: "GoogleWebViewOverlay"', ov_bp)
        self.assertIn('name: "GmsConfigOverlay"', ov_bp)
        self.assertNotIn("YasvaraGoogleWebViewOverlay", gms_mk)
        self.assertNotIn("YasvaraGmsConfigOverlay", gms_mk)

        # OH-4: KaitChain zero-copy getArgs.
        chain = read("vendor/yasvara/kait/runtime/kotlin/org/yasvara/kait/impl/hooks/KaitChain.kt")
        self.assertNotIn("toMutableList()", chain)
        self.assertIn("args.asList()", chain)

        # BUG-Z1: Companion uses eventfd wake.
        comp_bin = read("vendor/yasvara/zygisk/src/companion_bin.rs")
        self.assertIn("libc::eventfd", comp_bin)
        self.assertIn("Recv::Wake", comp_bin)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
