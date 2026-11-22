#!/usr/bin/env python3
"""
Automated SELinux Zero-Leak Unit Test Suite.

Verifies three layers:
  1. Synthetic CIL fixture tests (secilc + sepolicy-analyze) proving the oracle catches
     dirty transitions, capability leaks, forbidden root/adbroot contexts, and Yasvara/ROM
     service/data leaks while failing closed if positive controls break.
  2. Source tree policy audit across system/sepolicy, device/lineage/sepolicy,
     vendor/yasvara/sepolicy, and ServiceManager::listServices.
  3. Compiled ROM binary policy audit (precompiled_sepolicy) across concrete domains.
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Iterable, Iterator


def find_src_root() -> Path:
    env_root = os.environ.get("ANDROID_BUILD_TOP")
    if env_root:
        return Path(env_root).resolve()
    # vendor/yasvara/tests/selinux/selinux_leak_test.py -> src/
    return Path(__file__).resolve().parents[4]


SRC_ROOT = find_src_root()
HOST_BIN = SRC_ROOT / "out/host/linux-x86/bin"
SEPOLICY_ANALYZE = HOST_BIN / "sepolicy-analyze"
SECILC = HOST_BIN / "secilc"
CHECKFC = HOST_BIN / "checkfc"

FORBIDDEN_RAW_CONTEXT_TYPES = (
    "ksu",
    "ksu_file",
    "magisk",
    "magisk_file",
    "lsposed_file",
    "droidspacesd",
    "msd_app",
    "msd_daemon",
    "xposed_data",
    "adbroot",
    "adbroot_exec",
    "adbroot_data_file",
    "adbroot_service",
    "xposed_file",
)

PROTECTED_SERVICES_DENIED_TO_UNTRUSTED = (
    "lineage_hardware_service",
    "lineage_health_interface_service",
    "lineage_globalactions_service",
    "lineage_livedisplay_service",
    "lineage_profile_service",
    "lineage_sensitive_phone_numbers_service",
    "lineage_trust_service",
    "hal_lineage_health_service",
    "hal_lineage_livedisplay_service",
    "hal_lineage_powershare_service",
    "hal_lineage_touch_service",
    "yasvara_root_service",
    "yasvara_update_policy_service",
    "yasvara_adbd_ctl_service",
    "yasvara_layang_service",
    "yasvara_swara_service",
    "yasvara_pentas_service",
    "yasvara_ketik_service",
    "yasvara_hentak_service",
)

PROTECTED_DATA_FILES_DENIED_TO_UNTRUSTED = (
    "yasvara_root_data_file",
    "yasvara_zygote_set_file",
    "yasvara_attest_data_file",
    "yasvara_adbd_ctl_data_file",
)

# Concrete dirty access rules probed by Duck Detector (dirty_policy_probe.cpp).
DIRTY_ACCESS_RULES = (
    ("system_server execmem", "system_server", "system_server", "process", "execmem"),
    ("fsck_untrusted sys_admin", "fsck_untrusted", "fsck_untrusted", "capability", "sys_admin"),
    ("shell -> su transition", "shell", "su", "process", "transition"),
    ("shell -> su dyntransition", "shell", "su", "process", "dyntransition"),
    ("zygote -> adb_data_file search", "zygote", "adb_data_file", "dir", "search"),
    ("rootfs -> tmpfs associate", "rootfs", "tmpfs", "filesystem", "associate"),
    ("kernel -> tmpfs fifo open", "kernel", "tmpfs", "fifo_file", "open"),
    ("kernel -> adb_data_file read", "kernel", "adb_data_file", "file", "read"),
    ("system_server -> apk_data_file execute", "system_server", "apk_data_file", "file", "execute"),
    ("dex2oat -> dex2oat_exec execute_no_trans", "dex2oat", "dex2oat_exec", "file", "execute_no_trans"),
)


def strip_te_comments(text: str) -> str:
    lines = []
    for line in text.splitlines():
        idx = line.find("#")
        if idx >= 0:
            line = line[:idx]
        lines.append(line)
    return "\n".join(lines)


class BinaryPolicyAnalyzer:
    """Wraps host sepolicy-analyze against a compiled SELinux binary policy."""

    def __init__(self, policy_path: Path) -> None:
        self.policy_path = policy_path
        self._attr_cache: dict[str, set[str]] = {}
        self._defined_cache: dict[str, bool] = {}

    def attribute_members(self, attr_name: str) -> set[str]:
        if attr_name in self._attr_cache:
            return self._attr_cache[attr_name]
        proc = subprocess.run(
            [str(SEPOLICY_ANALYZE), str(self.policy_path), "attribute", attr_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            self._attr_cache[attr_name] = set()
            return set()
        members = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
        self._attr_cache[attr_name] = members
        return members

    def all_known_types(self) -> set[str]:
        known: set[str] = set()
        for attr in ("domain", "file_type", "fs_type", "service_manager_type", "property_type"):
            known.update(self.attribute_members(attr))
        return known

    def is_type_defined(self, name: str) -> bool:
        """Probes libsepol's policydb->p_types symbol table directly via checkfc."""
        if name in self._defined_cache:
            return self._defined_cache[name]
        if not CHECKFC.is_file():
            defined = name in self.all_known_types()
            self._defined_cache[name] = defined
            return defined
        with tempfile.NamedTemporaryFile("w", suffix=".fc", encoding="utf-8") as tmp:
            tmp.write(f"/probe_{name} u:object_r:{name}:s0\n")
            tmp.flush()
            proc = subprocess.run(
                [str(CHECKFC), str(self.policy_path), tmp.name],
                capture_output=True,
                text=True,
                check=False,
            )
        combined = proc.stdout + "\n" + proc.stderr
        if "could not find attribute" in combined or "invalid binary policy" in combined:
            raise RuntimeError(f"checkfc failed to inspect binary policy: {combined.strip()}")
        defined = f"type {name} is not defined" not in combined
        self._defined_cache[name] = defined
        return defined

    def types_defined_in_policydb(self, candidates: Iterable[str]) -> set[str]:
        return {name for name in set(candidates) if self.is_type_defined(name)}

    def check_neverallow(self, rule: str) -> tuple[bool, str]:
        """Returns (passes_neverallow, raw_output). True means access is DENIED."""
        proc = subprocess.run(
            [str(SEPOLICY_ANALYZE), str(self.policy_path), "neverallow", "-n", rule],
            capture_output=True,
            text=True,
            check=False,
        )
        combined = (proc.stdout + "\n" + proc.stderr).strip()
        if "Unknown" in combined or "ERROR" in combined or "Failed" in combined:
            raise RuntimeError(f"Invalid neverallow query {rule!r}: {combined}")
        return proc.returncode == 0, combined

    def audit(self, require_yasvara_controls: bool = False) -> list[str]:
        errors: list[str] = []
        known_types = self.all_known_types()

        # 1. Positive controls MUST hold (otherwise neverallow checks could be vacuous).
        pos_zygote_ok, _ = self.check_neverallow(
            "neverallow app_zygote isolated_app:process dyntransition;"
        )
        if pos_zygote_ok:
            errors.append("Positive control failed: app_zygote -> isolated_app dyntransition is NOT allowed")

        pos_sm_ok, _ = self.check_neverallow(
            "neverallow untrusted_app servicemanager:service_manager list;"
        )
        if pos_sm_ok:
            errors.append("Positive control failed: untrusted_app -> servicemanager list is NOT allowed")

        if require_yasvara_controls:
            defined_ctl = self.types_defined_in_policydb(["yasvara_adbd_ctl"])
            if "yasvara_adbd_ctl" not in defined_ctl:
                errors.append("Expected type yasvara_adbd_ctl missing from compiled policy")
            else:
                adbd_ctl_denied, _ = self.check_neverallow(
                    "neverallow adbd yasvara_adbd_ctl:binder call;"
                )
                if adbd_ctl_denied:
                    errors.append("Positive control failed: adbd -> yasvara_adbd_ctl binder call NOT allowed")

        # 2. Forbidden context / type names (kernel security_context_to_sid / policydb->p_types oracle).
        defined_forbidden = self.types_defined_in_policydb(FORBIDDEN_RAW_CONTEXT_TYPES)
        for forbidden in sorted(defined_forbidden):
            errors.append(f"Forbidden SELinux type present in SID/type table: {forbidden}")

        # 3. All Duck Detector dirty access rules.
        rule_types = {t for _, s, tg, _, _ in DIRTY_ACCESS_RULES for t in (s, tg)}
        defined_rule_types = self.types_defined_in_policydb(rule_types)
        for label, src, tgt, tclass, perm in DIRTY_ACCESS_RULES:
            if src not in defined_rule_types or tgt not in defined_rule_types:
                continue
            denied, detail = self.check_neverallow(f"neverallow {src} {tgt}:{tclass} {perm};")
            if not denied:
                errors.append(f"Dirty SELinux rule allowed ({label}): {detail}")

        # 4. Concrete untrusted app domains isolation.
        app_domains = self.attribute_members("appdomain") or self.types_defined_in_policydb(
            ["untrusted_app", "untrusted_app_34", "untrusted_app_32", "isolated_app"]
        )
        untrusted_domains = sorted(
            d for d in app_domains
            if d == "untrusted_app" or d.startswith("untrusted_app_") or d in ("ephemeral_app", "isolated_app")
        )
        if not untrusted_domains:
            errors.append("No concrete untrusted_app* domains discovered in binary policy")
            return errors

        src_set = "{ " + " ".join(untrusted_domains) + " }"

        present_services = sorted(self.types_defined_in_policydb(PROTECTED_SERVICES_DENIED_TO_UNTRUSTED))
        if present_services:
            tgt_set = "{ " + " ".join(present_services) + " }"
            denied, detail = self.check_neverallow(
                f"neverallow {src_set} {tgt_set}:service_manager {{ find add }};"
            )
            if not denied:
                errors.append(f"Untrusted app service_manager leak: {detail}")

        present_data = sorted(self.types_defined_in_policydb(PROTECTED_DATA_FILES_DENIED_TO_UNTRUSTED))
        if present_data:
            tgt_set = "{ " + " ".join(present_data) + " }"
            for cls, perms in (
                ("dir", "{ read write open search getattr }"),
                ("file", "{ read write open getattr execute }"),
                ("sock_file", "{ read write open getattr }"),
            ):
                denied, detail = self.check_neverallow(
                    f"neverallow {src_set} {tgt_set}:{cls} {perms};"
                )
                if not denied:
                    errors.append(f"Untrusted app data leak ({cls}): {detail}")

        if "sepolicy_file" in self.types_defined_in_policydb(["sepolicy_file"]):
            denied, detail = self.check_neverallow(
                f"neverallow {src_set} sepolicy_file:file {{ read write open }};"
            )
            if not denied:
                errors.append(f"Untrusted app can read/open sepolicy_file: {detail}")

        return errors


SYNTHETIC_BASE_CIL = """
(class security (compute_av))
(class process (fork transition dyntransition execmem))
(class capability (sys_admin))
(class binder (call))
(class service_manager (add find list))
(class filesystem (associate))
(class dir (read write open search getattr))
(class file (read write open getattr execute execute_no_trans))
(class fifo_file (open))
(class sock_file (read write open getattr))
(classorder (security process capability binder service_manager filesystem dir file fifo_file sock_file))

(sid kernel)
(sidorder (kernel))

(user u)
(role r)
(role object_r)
(userrole u r)
(userrole u object_r)
(sensitivity s0)
(sensitivityorder (s0))
(level s0 (s0))
(userlevel u s0)
(userrange u (s0 s0))

(typeattribute domain)
(typeattribute appdomain)
(typeattribute file_type)
(typeattribute dev_type)
(typeattribute fs_type)
(typeattribute service_manager_type)
(typeattribute property_type)
(expandtypeattribute (domain appdomain file_type dev_type fs_type service_manager_type property_type) false)

(type kernel)
(type system_server)
(type fsck_untrusted)
(type shell)
(type su)
(type adbd)
(type zygote)
(type app_zygote)
(type isolated_app)
(type untrusted_app)
(type untrusted_app_34)
(type dex2oat)
(type servicemanager)
(type yasvara_adbd_ctl)
(roletype r kernel)
(roletype r system_server)
(roletype r fsck_untrusted)
(roletype r shell)
(roletype r su)
(roletype r adbd)
(roletype r zygote)
(roletype r app_zygote)
(roletype r isolated_app)
(roletype r untrusted_app)
(roletype r untrusted_app_34)
(roletype r dex2oat)
(roletype r servicemanager)
(roletype r yasvara_adbd_ctl)
(typeattributeset domain (kernel system_server fsck_untrusted shell su adbd zygote app_zygote isolated_app untrusted_app untrusted_app_34 dex2oat servicemanager yasvara_adbd_ctl))
(typeattributeset appdomain (isolated_app untrusted_app untrusted_app_34))

(type rootfs)
(type tmpfs)
(type adb_data_file)
(type apk_data_file)
(type dex2oat_exec)
(type sepolicy_file)
(type yasvara_root_data_file)
(type yasvara_zygote_set_file)
(type yasvara_attest_data_file)
(type yasvara_adbd_ctl_data_file)
(typeattributeset fs_type (rootfs tmpfs))
(typeattributeset file_type (adb_data_file apk_data_file dex2oat_exec sepolicy_file yasvara_root_data_file yasvara_zygote_set_file yasvara_attest_data_file yasvara_adbd_ctl_data_file))

(type lineage_profile_service)
(type yasvara_root_service)
(type yasvara_update_policy_service)
(type yasvara_adbd_ctl_service)
(typeattributeset service_manager_type (lineage_profile_service yasvara_root_service yasvara_update_policy_service yasvara_adbd_ctl_service))

(sidcontext kernel (u r kernel (s0 s0)))

; Clean baseline positive rules:
(allow adbd yasvara_adbd_ctl (binder (call)))
{positive_controls}
{extra_rules}
"""

DEFAULT_POSITIVE_CONTROLS = """
(allow app_zygote isolated_app (process (dyntransition)))
(allow untrusted_app servicemanager (service_manager (list)))
"""


@contextlib.contextmanager
def compile_synthetic_cil(
    extra_rules: str = "", positive_controls: str = DEFAULT_POSITIVE_CONTROLS
) -> Iterator[BinaryPolicyAnalyzer]:
    with tempfile.TemporaryDirectory() as tmp:
        cil_path = Path(tmp) / "policy.cil"
        bin_path = Path(tmp) / "policy.bin"
        cil_path.write_text(
            SYNTHETIC_BASE_CIL.format(positive_controls=positive_controls, extra_rules=extra_rules),
            encoding="utf-8",
        )
        proc = subprocess.run(
            [str(SECILC), "-M", "true", "-G", "-N", "-c", "30", "-o", str(bin_path), "-f", "/dev/null", str(cil_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"secilc failed: {proc.stdout}\n{proc.stderr}")
        yield BinaryPolicyAnalyzer(bin_path)


@unittest.skipUnless(SECILC.is_file() and SEPOLICY_ANALYZE.is_file(), "Host secilc/sepolicy-analyze required")
class TestSyntheticCilPolicyOracle(unittest.TestCase):
    """Unit tests proving the binary SELinux leak analyzer catches every class of leak."""

    def test_clean_synthetic_policy_passes(self) -> None:
        with compile_synthetic_cil() as analyzer:
            self.assertEqual(analyzer.audit(require_yasvara_controls=True), [])

    def test_detects_shell_to_su_transition_leak(self) -> None:
        with compile_synthetic_cil("(allow shell su (process (transition)))") as analyzer:
            errors = analyzer.audit()
            self.assertTrue(any("shell -> su transition" in e for e in errors), errors)

    def test_detects_fsck_untrusted_sys_admin_leak(self) -> None:
        with compile_synthetic_cil("(allow fsck_untrusted fsck_untrusted (capability (sys_admin)))") as analyzer:
            errors = analyzer.audit()
            self.assertTrue(any("fsck_untrusted sys_admin" in e for e in errors), errors)

    def test_detects_forbidden_adbroot_and_root_contexts(self) -> None:
        for bad_type in ("adbroot", "magisk", "ksu", "lsposed_file"):
            with self.subTest(bad_type=bad_type):
                with compile_synthetic_cil(
                    f"(type {bad_type})\n(roletype r {bad_type})\n(typeattributeset domain ({bad_type}))"
                ) as analyzer:
                    errors = analyzer.audit()
                    self.assertTrue(any(bad_type in e for e in errors), errors)

    def test_detects_untrusted_app_service_and_data_leaks(self) -> None:
        with compile_synthetic_cil("(allow untrusted_app_34 lineage_profile_service (service_manager (find)))") as svc_leak:
            self.assertTrue(any("service_manager leak" in e for e in svc_leak.audit()))

        with compile_synthetic_cil("(allow untrusted_app yasvara_root_data_file (file (read)))") as data_leak:
            self.assertTrue(any("data leak" in e for e in data_leak.audit()))

        with compile_synthetic_cil("(allow untrusted_app sepolicy_file (file (open)))") as sepol_leak:
            self.assertTrue(any("sepolicy_file" in e for e in sepol_leak.audit()))

    def test_fails_closed_when_positive_control_missing(self) -> None:
        with compile_synthetic_cil(
            positive_controls="(allow untrusted_app servicemanager (service_manager (list)))"
        ) as analyzer:
            errors = analyzer.audit()
            self.assertTrue(any("Positive control failed" in e for e in errors), errors)


class TestSourceSepolicyNoLeaks(unittest.TestCase):
    """Audits source .te, *_contexts, and ServiceManager.cpp directly."""

    def test_su_te_has_no_shell_auto_trans(self) -> None:
        su_te = strip_te_comments((SRC_ROOT / "system/sepolicy/private/su.te").read_text(encoding="utf-8"))
        self.assertNotRegex(
            su_te,
            r"domain_auto_trans\s*\(\s*shell\s*,\s*su_exec\s*,\s*su\s*\)",
            "shell -> su auto-transition must be removed from su.te",
        )
        self.assertNotRegex(su_te, r"allow\s+shell\s+su\s*:\s*process\s+.*transition")

    def test_fsck_untrusted_has_no_sys_admin(self) -> None:
        fsck_te = strip_te_comments(
            (SRC_ROOT / "device/lineage/sepolicy/common/private/fsck_untrusted.te").read_text(encoding="utf-8")
        )
        self.assertNotIn("sys_admin", fsck_te)

    def test_no_forbidden_types_declared_in_source_trees(self) -> None:
        trees = [
            SRC_ROOT / "system/sepolicy",
            SRC_ROOT / "device/lineage/sepolicy",
            SRC_ROOT / "vendor/yasvara/sepolicy",
        ]
        type_decl_re = re.compile(
            r"^\s*type\s+(" + "|".join(re.escape(t) for t in FORBIDDEN_RAW_CONTEXT_TYPES) + r")\b",
            re.MULTILINE,
        )
        for tree in trees:
            for te_file in tree.rglob("*.te"):
                cleaned = strip_te_comments(te_file.read_text(encoding="utf-8", errors="ignore"))
                m = type_decl_re.search(cleaned)
                self.assertIsNone(m, f"Forbidden type declared in {te_file}: {m.group(0) if m else ''}")

        for ctx_file in (
            SRC_ROOT / "device/lineage/sepolicy/common/private/file_contexts",
            SRC_ROOT / "device/lineage/sepolicy/common/private/service_contexts",
            SRC_ROOT / "vendor/yasvara/sepolicy/private/file_contexts",
            SRC_ROOT / "vendor/yasvara/sepolicy/private/service_contexts",
        ):
            cleaned = strip_te_comments(ctx_file.read_text(encoding="utf-8"))
            for forbidden in FORBIDDEN_RAW_CONTEXT_TYPES:
                self.assertNotRegex(
                    cleaned,
                    rf"\bu:(?:r|object_r):{re.escape(forbidden)}:s0\b",
                    f"Forbidden context {forbidden} referenced in {ctx_file}",
                )

    def test_lineage_and_yasvara_services_not_findable_by_untrusted_apps(self) -> None:
        trees = [
            SRC_ROOT / "device/lineage/sepolicy",
            SRC_ROOT / "vendor/yasvara/sepolicy",
        ]
        svc_pattern = "|".join(re.escape(s) for s in PROTECTED_SERVICES_DENIED_TO_UNTRUSTED)
        bad_allow = re.compile(
            rf"allow\s+[^\n;]*\buntrusted_app\w*\b[^\n;]*\b(?:{svc_pattern})\s*:\s*service_manager\s+[^\n;]*\bfind\b"
        )
        for tree in trees:
            for te_file in tree.rglob("*.te"):
                cleaned = strip_te_comments(te_file.read_text(encoding="utf-8", errors="ignore"))
                self.assertIsNone(bad_allow.search(cleaned), f"Service leak in {te_file}")

    def test_sepolicy_cil_and_root_rc_files_labeled_sepolicy_file(self) -> None:
        yasvara_fc = strip_te_comments(
            (SRC_ROOT / "vendor/yasvara/sepolicy/private/file_contexts").read_text(encoding="utf-8")
        )
        lineage_fc = strip_te_comments(
            (SRC_ROOT / "device/lineage/sepolicy/common/private/file_contexts").read_text(encoding="utf-8")
        )
        for expected in ("system_ext_sepolicy", "product_sepolicy", "yasvara_sessiond"):
            self.assertRegex(yasvara_fc, rf"{expected}.*u:object_r:sepolicy_file:s0")
        self.assertRegex(lineage_fc, r"adb_root\\\.rc\s+u:object_r:sepolicy_file:s0")

    def test_yasvara_property_contexts_hides_sessiond_status(self) -> None:
        prop_ctx = (SRC_ROOT / "vendor/yasvara/sepolicy/private/property_contexts").read_text(encoding="utf-8")
        self.assertRegex(
            strip_te_comments(prop_ctx),
            r"init\.svc\.yasvara_sessiond\s+u:object_r:init_svc_debug_prop:s0",
        )

    def test_servicemanager_listservices_enforces_can_find_quiet(self) -> None:
        sm_cpp = (SRC_ROOT / "frameworks/native/cmds/servicemanager/ServiceManager.cpp").read_text(encoding="utf-8")
        access_cpp = (SRC_ROOT / "frameworks/native/cmds/servicemanager/Access.cpp").read_text(encoding="utf-8")
        self.assertIn("canFindQuiet", sm_cpp)
        self.assertIn("multiuser_get_app_id(ctx.uid) >= AID_APP", sm_cpp)
        self.assertIn("avc_has_perm_noaudit", access_cpp)


class TestCompiledRomBinarySepolicy(unittest.TestCase):
    """Audits the full compiled precompiled_sepolicy for onyx when up to date."""

    @classmethod
    def setUpClass(cls) -> None:
        env_pol = os.environ.get("SELINUX_BINARY_POLICY")
        cls.policy_path = (
            Path(env_pol).resolve()
            if env_pol
            else SRC_ROOT / "out/target/product/onyx/odm/etc/selinux/precompiled_sepolicy"
        )
        if not SEPOLICY_ANALYZE.is_file() or not cls.policy_path.is_file():
            raise unittest.SkipTest(f"Binary policy or sepolicy-analyze unavailable ({cls.policy_path})")

        edited_sources: Iterable[Path] = (
            SRC_ROOT / "system/sepolicy/private/su.te",
            SRC_ROOT / "device/lineage/sepolicy/common/private/fsck_untrusted.te",
            SRC_ROOT / "device/lineage/sepolicy/common/private/adbroot.te",
            SRC_ROOT / "device/lineage/sepolicy/common/private/untrusted_app.te",
        )
        pol_mtime = cls.policy_path.stat().st_mtime
        stale = [p for p in edited_sources if p.exists() and p.stat().st_mtime > pol_mtime]
        if stale and not env_pol:
            raise unittest.SkipTest(
                f"precompiled_sepolicy is older than edited .te files ({[p.name for p in stale]}); rebuild first"
            )

    def test_compiled_rom_precompiled_sepolicy_zero_leaks(self) -> None:
        analyzer = BinaryPolicyAnalyzer(self.policy_path)
        errors = analyzer.audit(require_yasvara_controls=True)
        self.assertEqual(errors, [], "\n".join(errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
