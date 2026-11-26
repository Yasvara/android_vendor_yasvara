// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Power-User Recovery Suite (`SPEC-0051` §5.9):
//! - Root Modules Manager (Magisk / Akar / KernelSU / Zygisk) + Safe Mode Disable-All
//! - Multi-ZIP Flash Queue with pre-flight validation
//! - Device Passport (`sysinfo`) with default-masked privacy identifiers
//! - Anti-brick Partition Guard wrapper

use pasang_core::safety::{validate_raw_flash, validate_wipe_or_format, SafetyError};
use std::fs;
use std::path::{Path, PathBuf};

/// Parsed Magisk / Akar / KernelSU module metadata from `module.prop`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootModule {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub path: PathBuf,
    pub disabled: bool,
    pub pending_remove: bool,
}

/// Scan a module root (e.g., `/data/adb/modules`) and parse every module safely.
pub fn scan_root_modules(modules_root: &Path) -> Vec<RootModule> {
    let mut list = Vec::new();
    let Ok(rd) = fs::read_dir(modules_root) else {
        return list;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().to_string();
        let prop_raw = fs::read_to_string(path.join("module.prop")).unwrap_or_default();
        let mut name = id.clone();
        let mut version = String::new();
        let mut author = String::new();
        for line in prop_raw.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "name" => name = v.trim().to_string(),
                    "version" => version = v.trim().to_string(),
                    "author" => author = v.trim().to_string(),
                    _ => {}
                }
            }
        }
        list.push(RootModule {
            id,
            name,
            version,
            author,
            disabled: path.join("disable").exists(),
            pending_remove: path.join("remove").exists(),
            path,
        });
    }
    list.sort_by(|a, b| a.id.cmp(&b.id));
    list
}

/// Toggle a single root module's `disable` marker file.
pub fn set_module_disabled(module_dir: &Path, disabled: bool) -> std::io::Result<()> {
    let flag = module_dir.join("disable");
    if disabled {
        fs::write(flag, b"")
    } else if flag.exists() {
        fs::remove_file(flag)
    } else {
        Ok(())
    }
}

/// 1-tap Bootloop Rescue Safe Mode: creates `disable` in every module directory.
pub fn disable_all_modules(modules_root: &Path) -> std::io::Result<usize> {
    let mods = scan_root_modules(modules_root);
    let mut count = 0;
    for m in mods {
        set_module_disabled(&m.path, true)?;
        count += 1;
    }
    Ok(count)
}

/// Multi-ZIP / Image Flash Queue item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlashItem {
    OtaZip(PathBuf),
    RawImage { path: PathBuf, target_partition: String },
}

/// Ordered Flash Queue with strict pre-flight anti-brick validation.
#[derive(Clone, Debug, Default)]
pub struct FlashQueue {
    pub items: Vec<FlashItem>,
}

impl FlashQueue {
    pub const MAX_ITEMS: usize = 16;

    pub fn push(&mut self, item: FlashItem) -> Result<(), &'static str> {
        if self.items.len() >= Self::MAX_ITEMS {
            return Err("flash queue full (max 16 items)");
        }
        self.items.push(item);
        Ok(())
    }

    /// Verify every raw image in the queue passes `pasang_core::safety::validate_raw_flash`
    /// before touching storage!
    pub fn preflight_validate(
        &self,
        active_slot_suffix: &str,
        ro_vendor_mounted: bool,
    ) -> Result<(), SafetyError> {
        for item in &self.items {
            if let FlashItem::RawImage {
                path,
                target_partition,
            } = item
            {
                let data = fs::read(path).unwrap_or_default();
                let header = &data[..data.len().min(64)];
                validate_raw_flash(
                    target_partition,
                    header,
                    data.len() as u64,
                    0,
                    active_slot_suffix,
                    ro_vendor_mounted,
                )?;
            }
        }
        Ok(())
    }
}

/// Safe wrapper for any Recovery Wipe/Format request.
pub fn guard_partition_wipe(partition: &str) -> Result<(), SafetyError> {
    validate_wipe_or_format(partition)
}

/// Device Passport snapshot (`SPEC-0051` §5.9.5) with privacy masking by default.
#[derive(Clone, Debug)]
pub struct DevicePassport {
    pub model: String,
    pub codename: String,
    pub serial: String,
    pub wifi_mac: String,
    pub kernel: String,
    pub verified_boot: String,
    pub active_slot: String,
}

impl DevicePassport {
    pub fn format_export(&self, reveal_identifiers: bool) -> String {
        let serial = if reveal_identifiers {
            self.serial.as_str()
        } else {
            "[REDACTED]"
        };
        let mac = if reveal_identifiers {
            self.wifi_mac.as_str()
        } else {
            "[REDACTED]"
        };
        format!(
            "Yasvara Pulih Device Passport\n\
             Model:         {}\n\
             Codename:      {}\n\
             Serial:        {}\n\
             Wi-Fi MAC:     {}\n\
             Kernel:        {}\n\
             Verified Boot: {}\n\
             Active Slot:   {}\n",
            self.model, self.codename, serial, mac, self.kernel, self.verified_boot, self.active_slot
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_manager_scans_and_disables_all_in_safe_mode() {
        let tmp = std::env::temp_dir().join(format!("pulih_mods_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let m1 = tmp.join("akar_core");
        let m2 = tmp.join("zygisk_next");
        fs::create_dir_all(&m1).unwrap();
        fs::create_dir_all(&m2).unwrap();
        fs::write(m1.join("module.prop"), "name=Akar Core\nversion=1.0\nauthor=Yasvara\n").unwrap();
        fs::write(m2.join("module.prop"), "name=Zygisk Next\nversion=1.2\nauthor=Dr-TSNG\n").unwrap();

        let scanned = scan_root_modules(&tmp);
        assert_eq!(scanned.len(), 2);
        assert_eq!(scanned[0].name, "Akar Core");
        assert!(!scanned[0].disabled);

        let disabled_cnt = disable_all_modules(&tmp).unwrap();
        assert_eq!(disabled_cnt, 2);
        assert!(scan_root_modules(&tmp).iter().all(|m| m.disabled));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn flash_queue_blocks_bad_boot_image_and_protected_partition() {
        let tmp = std::env::temp_dir().join(format!("pulih_fq_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let bad_img = tmp.join("bad.img");
        fs::write(&bad_img, b"NOT_A_BOOT_IMAGE").unwrap();

        let mut q = FlashQueue::default();
        q.push(FlashItem::RawImage {
            path: bad_img.clone(),
            target_partition: "boot_b".to_string(),
        })
        .unwrap();
        assert!(q.preflight_validate("_a", false).is_err());

        // Protected partition blocked
        assert!(guard_partition_wipe("persist").is_err());
        assert!(guard_partition_wipe("xbl_a").is_err());
        assert!(guard_partition_wipe("userdata").is_ok());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn device_passport_masks_identifiers_by_default() {
        let dp = DevicePassport {
            model: "POCO F7".into(),
            codename: "onyx".into(),
            serial: "cf49eff5".into(),
            wifi_mac: "aa:bb:cc:dd:ee:ff".into(),
            kernel: "6.12.119-Drago".into(),
            verified_boot: "orange".into(),
            active_slot: "_a".into(),
        };
        let masked = dp.format_export(false);
        assert!(!masked.contains("cf49eff5"));
        assert!(!masked.contains("aa:bb:cc:dd:ee:ff"));
        let revealed = dp.format_export(true);
        assert!(revealed.contains("cf49eff5"));
    }
}
