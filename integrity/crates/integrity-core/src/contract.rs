// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Canonical constants, property names, target/exempt sets, boot story, and OIDs shared
//! across `keystore2`, `libc.so`, `system_server`, `framework.jar`, `Laras`, and `rkpdapp`.
//!
//! Change a package, property, or table HERE once; Soong recompiles Bionic + Keystore2 + JNI
//! and regenerates `YasvaraIntegrityContract.java` + `yasvara_integrity_bionic.h` automatically.

/// Canonical directory owned by init (`02750 system:keystore`, `yasvara_attest_data_file`).
pub const ATTEST_DIR: &str = "/data/misc/yasvara_attest";
pub const KEYBOX_FILENAME: &str = "keybox.xml";
pub const POLICY_FILENAME: &str = "policy.bin";
pub const TARGETS_FILENAME: &str = "targets";
pub const PATCH_OVERRIDE_FILENAME: &str = "patch_override";
pub const LEGACY_KEYBOX_PATH: &str = "/data/system/yasvara/keybox.xml";

/// Active external Akar/Zygisk module feature claims (`play_integrity`, ...).
pub const AKAR_MANAGED_FEATURES_PATH: &str = "/data/misc/yasvara_root/managed_features";
pub const AKAR_FEATURE_PLAY_INTEGRITY: &str = "play_integrity";

/// Offline fallback PIF profile path on `/product`.
pub const PIF_FALLBACK_PATH: &str = "/product/etc/yasvara/pif_fallback.json";

/// Binder service name and write permission.
pub const SERVICE_NAME: &str = "yasvara_attestation";
pub const PERMISSION_WRITE: &str = "yasvara.permission.WRITE_ATTESTATION";

/// Boot digest SSOT properties and probe alias.
pub const PROP_BOOT_DIGEST: &str = "ro.yasvara.boot.digest";
pub const PROP_BOOT_SOURCE: &str = "ro.yasvara.boot.source";
pub const PROP_BOOT_VBMETA_DIGEST: &str = "ro.boot.vbmeta.digest";
pub const PROP_BOOT_VBMETA_PUBKEY_DIGEST: &str = "ro.boot.vbmeta.public_key_digest";
pub const BOOT_DIGEST_PROBE_ALIAS: &str = "YasvaraBootDigest";

/// Native control-plane and staging property names.
pub const PROP_PIF_PREFIX: &str = "persist.sys.yasvara.pif.";
/// Legacy master property (product default `1` in `yasvara_spoof.mk`; also consulted when
/// `PROP_STEALTH_ENABLED` / `PROP_PIF_ENABLED` are unset).
pub const PROP_PIF_LEGACY_MASTER: &str = "persist.sys.yasvara.pif";
/// Explicit built-in PIF profile spoofing toggle (`"1"` or `"0"`), written by
/// `YasvaraAttestationService` (set to `"0"` when user disables PIF or an Akar module claims
/// `play_integrity`).
pub const PROP_PIF_ENABLED: &str = "persist.sys.yasvara.pif.enabled";
/// Independent ROM/boot/adb/marker stealth toggle (`"1"` or `"0"`). Remains active even when
/// PIF profile spoofing is disabled or yielded to an external Akar module.
pub const PROP_STEALTH_ENABLED: &str = "persist.sys.yasvara.stealth";
pub const PROP_TRICKY_ENABLED: &str = "persist.sys.yasvara.trickystore";
pub const PROP_PATCH_OVERRIDE: &str = "persist.sys.yasvara.trickystore.patch_override";
pub const PROP_RKP_MANUFACTURER: &str = "persist.sys.yasvara.rkp_manufacturer";
pub const PROP_RKP_EXEMPT_PREFIX: &str = "persist.sys.yasvara.rkp_exempt.";
pub const RKP_EXEMPT_MAX_SLOTS: usize = 8;
pub const PROP_RKP_SPOOF: &str = "persist.sys.yasvara.rkp_spoof";
pub const PROP_PHOTOS_SPOOF: &str = "persist.sys.yasvara.photos_spoof";
pub const PROP_SNAP_SPOOF: &str = "persist.sys.yasvara.snap_spoof";

/// Settings.Secure keys shared between `YasvaraAttestationService`, `YasvaraSpoofEngine`,
/// `YasvaraTrickyStore`, and `Laras`.
pub const SECURE_PIF_ENABLED: &str = "yasvara_pif_enabled";
pub const SECURE_PIF_CONFIG: &str = "yasvara_pif_config";
pub const SECURE_SPOOF_MODE: &str = "yasvara_spoof_mode";
pub const SECURE_APP_SPOOF_MAP: &str = "yasvara_app_spoof_map";
pub const SECURE_PHOTOS_SPOOF: &str = "yasvara_photos_spoof";
pub const SECURE_SNAP_SPOOF: &str = "yasvara_snap_spoof";
pub const SECURE_KEYBOX_STAMP: &str = "yasvara_keybox_stamp";
pub const SECURE_RKP_MANUFACTURER: &str = "yasvara_rkp_manufacturer";
pub const SECURE_TRICKY_ENABLED: &str = "yasvara_trickystore_enabled";
pub const SECURE_TRICKY_TARGETS: &str = "yasvara_trickystore_targets";
pub const SECURE_TRICKY_PATCH_OVERRIDE: &str = "yasvara_trickystore_patch_override";
pub const SECURE_INTEGRITY_PURGE_GEN: &str = "yasvara_integrity_purge_gen";

/// Obsolete Settings.Secure keys from the removed ladder/rung architecture, deleted once on boot.
pub const LEGACY_SECURE_KEYS: &[&str] = &[
    "yasvara_trickystore_rung",
    "yasvara_trickystore_force",
    "yasvara_trickystore_tee_reprobe",
];

/// Core Android / Google / Yasvara package names.
pub const PKG_GMS: &str = "com.google.android.gms";
pub const PKG_GSF: &str = "com.google.android.gsf";
pub const PROC_GMS_UNSTABLE: &str = "com.google.android.gms.unstable";
pub const PKG_VENDING: &str = "com.android.vending";
pub const PKG_WALLET: &str = "com.google.android.apps.walletnfcrel";
pub const PKG_LARAS: &str = "org.yasvara.laras";
pub const PKG_PHOTOS: &str = "com.google.android.apps.photos";
pub const PKG_SNAPCHAT: &str = "com.snapchat.android";
pub const PKG_SI: &str = "com.google.android.settings.intelligence";
pub const PKG_RKPD: &str = "com.android.rkpdapp";

/// Always-covered attestation target packages (fast-path in RAM inside `keystore2`).
pub const BASE_ATTEST_TARGETS: &[&str] = &[PKG_GMS, PKG_GSF, PKG_VENDING, PKG_LARAS];

/// Default seed target list shown in Laras and used when `yasvara_trickystore_targets` is empty.
pub const DEFAULT_TRICKY_TARGETS: &[&str] = &[PKG_GMS, PKG_VENDING, PKG_WALLET];

/// PIF collector packages (receive full PIF profile in Java + Bionic + Keystore2).
pub const PIF_COLLECTOR_PACKAGES: &[&str] = &[PKG_GMS, PKG_GSF, PKG_VENDING];

/// Camera packages always exempt from Build/manufacturer spoofing (Java + Bionic).
pub const CAMERA_EXEMPT_PREFIXES: &[&str] = &[
    "com.android.camera",
    "com.google.android.GoogleCamera",
    "com.google.android.cameralite",
    "com.google.android.apps.cameralite",
];

/// Exact packages exempt from RKP keybox manufacturer override (in addition to collectors & cameras).
pub const RKP_MFG_EXEMPT_EXACT: &[&str] = &[PKG_RKPD, PKG_LARAS, PKG_PHOTOS, PKG_SNAPCHAT];

/// Staged subkeys under `persist.sys.yasvara.pif.<key>`.
pub const NATIVE_PIF_STAGING_KEYS: &[&str] = &[
    "manufacturer",
    "brand",
    "model",
    "device",
    "name",
    "fingerprint",
    "release",
    "build_id",
    "security_patch",
    "first_api_level",
    "build_type",
    "build_tags",
    "api_level",
    "os_version",
    "incremental",
    "flavor",
    "description",
];

/// Verified-boot + stopped-adbd + USB story served to app processes by Bionic while stealth is on.
/// Absent properties in this table are synthesized by `__system_property_find()`.
pub const BOOT_STORY: &[(&str, &str)] = &[
    ("ro.boot.verifiedbootstate", "green"),
    ("ro.vendor.boot.verifiedbootstate", "green"),
    ("vendor.boot.verifiedbootstate", "green"),
    ("ro.boot.vbmeta.device_state", "locked"),
    ("ro.vendor.boot.vbmeta.device_state", "locked"),
    ("vendor.boot.vbmeta.device_state", "locked"),
    ("ro.boot.flash.locked", "1"),
    ("ro.boot.veritymode", "enforcing"),
    ("ro.secureboot.lockstate", "locked"),
    ("ro.crypto.state", "encrypted"),
    ("init.svc.adbd", "stopped"),
    ("sys.usb.state", "mtp"),
    ("sys.usb.config", "mtp"),
    ("persist.sys.usb.config", "mtp"),
    ("vendor.usb.config", "mtp"),
    ("persist.vendor.usb.config", "mtp"),
];

/// Additional fixed properties served to Play Integrity collectors.
pub const COLLECTOR_STORY: &[(&str, &str)] = &[
    ("ro.build.host", "android-build"),
    ("ro.build.user", "android-build"),
];

/// Custom-ROM property prefixes hidden from app processes (except public boot SSOT properties).
pub const HIDDEN_PREFIXES: &[&str] = &[
    "ro.yasvara",
    "ro.lineage",
    "ro.cm",
    "ro.evolution",
    "persist.yasvara",
    "persist.sys.yasvara",
    "persist.lineage",
    "sys.yasvara",
    "init.svc.yasvara",
    "init.svc_debug_pid.yasvara",
    "ro.boottime.yasvara",
];

/// Exact properties hidden from app processes.
pub const HIDDEN_EXACT: &[&str] = &[
    "ro.modversion",
    "ro.build.selinux",
    "init.svc.adb_root",
    "init.svc_debug_pid.adb_root",
    "init.svc_debug_pid.adbd",
    "ro.boottime.adb_root",
    "ro.boottime.adbd",
    "service.adb.root",
    "persist.adb.tls_server.enable",
    "persist.adb.wifi.guid",
    "dev.mnt.blk.mnt.scratch",
    "dev.mnt.dev.mnt.scratch",
    "dev.mnt.rootdisk.mnt.scratch",
];

/// Custom-ROM prefixes stripped when normalizing `*.build.flavor`.
pub const ROM_FLAVOR_PREFIXES: &[&str] = &["yasvara_", "lineage_", "evolution_"];

/// Public, nonsecret properties under `ro.yasvara.*` that remain readable across processes.
pub const PUBLIC_YASVARA_PROPS: &[&str] = &[PROP_BOOT_DIGEST, PROP_BOOT_SOURCE];

/// X.509 Extension OIDs.
pub const ATTESTATION_EXT_OID: &str = "1.3.6.1.4.1.11129.2.1.17";
pub const PROVISIONING_INFO_OID: &str = "1.3.6.1.4.1.11129.2.1.30";
pub const SUBJECT_KEY_ID_OID: &str = "2.5.29.14";
pub const AUTHORITY_KEY_ID_OID: &str = "2.5.29.35";

/// KeyMint AuthorizationList explicit tag numbers.
pub const TAG_ROOT_OF_TRUST: u32 = 704;
pub const TAG_OS_VERSION: u32 = 705;
pub const TAG_OS_PATCHLEVEL: u32 = 706;
pub const TAG_ATTESTATION_ID_BRAND: u32 = 710;
pub const TAG_ATTESTATION_ID_DEVICE: u32 = 711;
pub const TAG_ATTESTATION_ID_PRODUCT: u32 = 712;
pub const TAG_ATTESTATION_ID_SERIAL: u32 = 713;
pub const TAG_ATTESTATION_ID_IMEI: u32 = 714;
pub const TAG_ATTESTATION_ID_MEID: u32 = 715;
pub const TAG_ATTESTATION_ID_MANUFACTURER: u32 = 716;
pub const TAG_ATTESTATION_ID_MODEL: u32 = 717;
pub const TAG_VENDOR_PATCHLEVEL: u32 = 718;
pub const TAG_BOOT_PATCHLEVEL: u32 = 719;
pub const TAG_ATTESTATION_ID_SECOND_IMEI: u32 = 723;

/// Hard bounds shared across all parsers and Bionic buffers.
pub const PROP_VALUE_MAX: usize = 92;
pub const MAX_PROP_VALUE_BYTES: usize = 91;
pub const PROP_OVERRIDE_MAX: usize = 129; // 128 hex chars + NUL
pub const MAX_KEY_DESCRIPTION_LEN: usize = 64 * 1024;
pub const MAX_AUTHORIZATION_FIELDS: usize = 256;
pub const MAX_PROVISIONING_BYTES: usize = 64 * 1024;
pub const MAX_CBOR_DEPTH: usize = 32;
pub const MAX_KEYBOX_BYTES: usize = 800_000;
pub const MAX_KEYBOX_CHARS: usize = 200_000;
pub const MAX_POLICY_BYTES: usize = 256 * 1024;

/// Domain-separation prefix for derived verifiedBootKey when hardware reports an all-zero key.
pub const BOOT_KEY_DERIVE_PREFIX: &[u8] = b"yasvara.verified-boot-key";

/// Android UID constants (matches `private/android_filesystem_config.h`).
pub const AID_USER_OFFSET: u32 = 100_000;
pub const AID_APP_START: u32 = 10_000;
pub const AID_WEBVIEW_ZYGOTE: u32 = 1053;

/// Keybox error codes shared with Laras UI (`KeyboxProblem`).
pub const KEYBOX_ERR_NONE: i32 = 0;
pub const KEYBOX_ERR_EMPTY: i32 = 1;
pub const KEYBOX_ERR_NOT_XML: i32 = 2;
pub const KEYBOX_ERR_NO_CERTIFICATE: i32 = 3;
pub const KEYBOX_ERR_BAD_CERTIFICATE: i32 = 4;
pub const KEYBOX_ERR_CHAIN_TOO_SHORT: i32 = 5;
pub const KEYBOX_ERR_INVALID_KEYBOX: i32 = 6;
pub const KEYBOX_ERR_NO_PRIVATE_KEY: i32 = 7;
pub const KEYBOX_ERR_TOO_LARGE: i32 = 8;
