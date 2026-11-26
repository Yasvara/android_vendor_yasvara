// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Anti-Brick Safety Guard for `Pulih` Recovery & `Pasang`.
//!
//! Enforces compile-time & runtime invariants so neither a UI bug, bad user tap,
//! nor malformed image can hard-brick the device:
//! 1. Hard blocklist of critical bootloader / EFS / modem-calibration / GPT
//!    partitions that must NEVER be wiped, formatted, or blindly overwritten.
//! 2. Image magic validation for `boot`, `init_boot`, `vendor_boot`, `recovery`,
//!    `dtbo`, and `vbmeta` raw flashes.
//! 3. Active-slot / mounted-vendor conflict guard before raw/dynamic writes.
//! 4. Thermal runaway ceiling evaluator for fast-charging safety.

use std::fmt;

/// Critical partitions that can permanently hard-brick the device or destroy
/// IMEI / calibration / bootloader chain if wiped or formatted in recovery.
pub const CRITICAL_PROTECTED_PARTITIONS: &[&str] = &[
    "xbl",
    "xbl_config",
    "xbl_ramdump",
    "xbl_sc_logs",
    "abl",
    "tz",
    "hyp",
    "devcfg",
    "keymaster",
    "km4",
    "aop",
    "aop_config",
    "qupfw",
    "uefi",
    "uefisecapp",
    "shrm",
    "cpucp",
    "featenabler",
    "imagefv",
    "persist",
    "modemst1",
    "modemst2",
    "fsg",
    "fsc",
    "ddr",
    "cdt",
    "ssd",
    "secdata",
    "limits",
    "limits-cdsp",
    "spunvm",
    "multiimgoem",
    "multiimgqti",
    "pdp",
    "pdp_cdb",
    "super",
    "gpt",
    "sda",
    "sdb",
    "sdc",
    "sdd",
    "sde",
    "sdf",
];

/// Partitions explicitly allowed for wipe / format in Recovery.
pub const FORMATTABLE_PARTITIONS: &[&str] = &[
    "userdata",
    "data",
    "metadata",
    "cache",
    "usbotg",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafetyError {
    ProtectedCriticalPartition(String),
    NotFormattable(String),
    EmptyImage,
    ImageExceedsPartition { image_bytes: u64, part_bytes: u64 },
    InvalidImageMagic { partition: String, expected: &'static str },
    ActiveSlotConflict(String),
    UnalignedSize { size: u64, align: u64 },
}

impl fmt::Display for SafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtectedCriticalPartition(p) => {
                write!(f, "BLOCKED: '{p}' is a critical anti-brick protected partition")
            }
            Self::NotFormattable(p) => {
                write!(f, "BLOCKED: '{p}' is not in the safe formattable partition allowlist")
            }
            Self::EmptyImage => write!(f, "BLOCKED: image is empty (0 bytes)"),
            Self::ImageExceedsPartition { image_bytes, part_bytes } => write!(
                f,
                "BLOCKED: image ({image_bytes} B) exceeds target partition ({part_bytes} B)"
            ),
            Self::InvalidImageMagic { partition, expected } => {
                write!(f, "BLOCKED: '{partition}' image missing valid {expected} magic header")
            }
            Self::ActiveSlotConflict(p) => {
                write!(f, "BLOCKED: '{p}' targets active slot while read-only vendor/Wi-Fi is mounted")
            }
            Self::UnalignedSize { size, align } => {
                write!(f, "BLOCKED: size {size} is not aligned to {align} bytes")
            }
        }
    }
}

/// Strip `_a` / `_b` A/B slot suffix for base partition name matching.
pub fn strip_slot_suffix(name: &str) -> &str {
    name.strip_suffix("_a")
        .or_else(|| name.strip_suffix("_b"))
        .unwrap_or(name)
}

/// Returns `true` if `partition` is on the hard anti-brick blocklist.
pub fn is_critical_protected(partition: &str) -> bool {
    let base = strip_slot_suffix(partition.trim()).to_ascii_lowercase();
    CRITICAL_PROTECTED_PARTITIONS.iter().any(|&p| p == base)
}

/// Guard any Wipe or Format operation.
pub fn validate_wipe_or_format(partition: &str) -> Result<(), SafetyError> {
    let base = strip_slot_suffix(partition.trim()).to_ascii_lowercase();
    if is_critical_protected(&base) {
        return Err(SafetyError::ProtectedCriticalPartition(partition.to_string()));
    }
    if !FORMATTABLE_PARTITIONS.iter().any(|&p| p == base) {
        return Err(SafetyError::NotFormattable(partition.to_string()));
    }
    Ok(())
}

/// Guard any raw `.img` flash operation before writing a single byte to block storage.
pub fn validate_raw_flash(
    partition: &str,
    image_header: &[u8],
    image_bytes: u64,
    partition_bytes: u64,
    active_slot_suffix: &str,
    ro_vendor_mounted: bool,
) -> Result<(), SafetyError> {
    if is_critical_protected(partition) {
        return Err(SafetyError::ProtectedCriticalPartition(partition.to_string()));
    }
    if image_bytes == 0 {
        return Err(SafetyError::EmptyImage);
    }
    if partition_bytes > 0 && image_bytes > partition_bytes {
        return Err(SafetyError::ImageExceedsPartition {
            image_bytes,
            part_bytes: partition_bytes,
        });
    }
    if ro_vendor_mounted && !active_slot_suffix.is_empty() && partition.ends_with(active_slot_suffix) {
        return Err(SafetyError::ActiveSlotConflict(partition.to_string()));
    }

    let base = strip_slot_suffix(partition).to_ascii_lowercase();
    match base.as_str() {
        "boot" | "init_boot" | "recovery" => {
            if image_header.len() < 8 || &image_header[0..8] != b"ANDROID!" {
                return Err(SafetyError::InvalidImageMagic {
                    partition: partition.to_string(),
                    expected: "ANDROID!",
                });
            }
        }
        "vendor_boot" => {
            if image_header.len() < 8 || &image_header[0..8] != b"VNDRBOOT" {
                return Err(SafetyError::InvalidImageMagic {
                    partition: partition.to_string(),
                    expected: "VNDRBOOT",
                });
            }
        }
        "vbmeta" | "vbmeta_system" | "vbmeta_vendor" => {
            if image_header.len() < 4 || &image_header[0..4] != b"AVB0" {
                return Err(SafetyError::InvalidImageMagic {
                    partition: partition.to_string(),
                    expected: "AVB0",
                });
            }
        }
        "dtbo" => {
            // DTBO header magic is big-endian 0xD7B7AB1E
            if image_header.len() < 4 || image_header[0..4] != [0xD7, 0xB7, 0xAB, 0x1E] {
                return Err(SafetyError::InvalidImageMagic {
                    partition: partition.to_string(),
                    expected: "DTBO (0xD7B7AB1E)",
                });
            }
        }
        _ => {}
    }

    Ok(())
}

/// Rust Thermal Safety Governor action for fast charging (`SPEC-0051` §5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThermalAction {
    /// `< 39.0 C`: allow requested profile (PD/PPS or HyperCharge).
    FullProfile,
    /// `39.0..42.0 C`: smoothly step down `mca_charger_thermal` level.
    StepDown,
    /// `42.0..46.0 C`: cap to conservative 18W buck charging + amber badge.
    Cap18W,
    /// `>= 46.0 C`: hard pause charging (`input_suspend=1`) until `< 42.0 C`.
    SuspendCharging,
}

/// Stateless + hysteresis thermal governor evaluator (`temp_tenths_c`, e.g., `415` = `41.5 C`).
pub fn evaluate_thermal_governor(temp_tenths_c: i32, currently_suspended: bool) -> ThermalAction {
    if temp_tenths_c >= 460 || (currently_suspended && temp_tenths_c >= 420) {
        ThermalAction::SuspendCharging
    } else if temp_tenths_c >= 420 {
        ThermalAction::Cap18W
    } else if temp_tenths_c >= 390 {
        ThermalAction::StepDown
    } else {
        ThermalAction::FullProfile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_partitions_blocked_for_wipe_and_raw_flash() {
        for p in [
            "xbl_a", "xbl_b", "abl_a", "tz_b", "persist", "modemst1", "modemst2", "fsg", "super",
            "sda",
        ] {
            assert!(is_critical_protected(p), "{p} must be protected");
            assert!(matches!(
                validate_wipe_or_format(p),
                Err(SafetyError::ProtectedCriticalPartition(_))
            ));
            assert!(matches!(
                validate_raw_flash(p, b"ANDROID!", 4096, 8192, "_a", false),
                Err(SafetyError::ProtectedCriticalPartition(_))
            ));
        }
    }

    #[test]
    fn safe_format_allowlist_works() {
        assert!(validate_wipe_or_format("userdata").is_ok());
        assert!(validate_wipe_or_format("metadata").is_ok());
        assert!(validate_wipe_or_format("usbotg").is_ok());
        assert!(matches!(
            validate_wipe_or_format("boot_a"),
            Err(SafetyError::NotFormattable(_))
        ));
    }

    #[test]
    fn raw_flash_validates_magic_size_and_active_slot() {
        // Valid boot image
        assert!(validate_raw_flash("boot_b", b"ANDROID!\x00\x00", 16 * 1024 * 1024, 64 * 1024 * 1024, "_a", true).is_ok());
        // Corrupt/random file flashed to boot_b MUST fail
        assert!(matches!(
            validate_raw_flash("boot_b", b"PK\x03\x04notaboot", 1024, 64 * 1024 * 1024, "_a", false),
            Err(SafetyError::InvalidImageMagic { .. })
        ));
        // Oversized image MUST fail
        assert!(matches!(
            validate_raw_flash("boot_b", b"ANDROID!", 128 * 1024 * 1024, 64 * 1024 * 1024, "_a", false),
            Err(SafetyError::ImageExceedsPartition { .. })
        ));
        // Active slot flash while ro vendor mounted MUST fail
        assert!(matches!(
            validate_raw_flash("boot_a", b"ANDROID!", 1024, 64 * 1024 * 1024, "_a", true),
            Err(SafetyError::ActiveSlotConflict(_))
        ));
        // Valid vendor_boot, vbmeta, dtbo
        assert!(validate_raw_flash("vendor_boot_b", b"VNDRBOOT", 4096, 96 * 1024 * 1024, "_a", false).is_ok());
        assert!(validate_raw_flash("vbmeta_b", b"AVB0\x00\x00", 4096, 65536, "_a", false).is_ok());
        assert!(validate_raw_flash("dtbo_b", &[0xD7, 0xB7, 0xAB, 0x1E, 0, 0], 4096, 8 * 1024 * 1024, "_a", false).is_ok());
    }

    #[test]
    fn thermal_governor_hysteresis_protects_battery() {
        assert_eq!(evaluate_thermal_governor(350, false), ThermalAction::FullProfile);
        assert_eq!(evaluate_thermal_governor(405, false), ThermalAction::StepDown);
        assert_eq!(evaluate_thermal_governor(435, false), ThermalAction::Cap18W);
        assert_eq!(evaluate_thermal_governor(460, false), ThermalAction::SuspendCharging);
        // Hysteresis keeps charging suspended at 43.0 C until temp drops < 42.0 C
        assert_eq!(evaluate_thermal_governor(430, true), ThermalAction::SuspendCharging);
        assert_eq!(evaluate_thermal_governor(419, true), ThermalAction::StepDown);
    }
}
