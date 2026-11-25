// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! 4-Layer Bootguard & Safe Mode persistence and stage handlers.
//!
//! Layers evaluated at `post-fs-data`:
//!   1. Hardware shortcut (`keywatch` volatile file OR `/proc/yasvara_bootkey` kernel early latch).
//!   2. Android platform Safe Mode (`persist.sys.safemode=1` / `ro.sys.safemode=1`).
//!   3. Manual escape flag (`<data_dir>/safemode`).
//!   4. Persistent `/metadata/vold/yasvara_akar/bootcount` strike counter:
//!      - Strike 1 -> Smart Rollback (auto-disables newly installed/enabled/updated modules vs `last_good.set`).
//!      - Strike 2 -> Full Safe Mode (mounts nothing, runs no scripts, bypasses Zygisk, parks counter).

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use yasvara_root_proto::bootguard::{
    decide_bootcount, BootcountDecision, BootguardStatus, LastGoodSnapshot, ModuleStamp,
    SafeModeReason,
};

use crate::{keywatch, sys};

pub const DEFAULT_META_DIR: &str = "/metadata/vold/yasvara_akar";

pub struct BootguardPaths {
    pub data_dir: PathBuf,
    pub meta_dir: PathBuf,
}

impl BootguardPaths {
    pub fn resolve(data_dir: &Path, meta_override: Option<&Path>) -> Self {
        let meta_dir = match meta_override {
            Some(p) => p.to_path_buf(),
            None => {
                let primary = PathBuf::from(DEFAULT_META_DIR);
                if Path::new("/metadata").is_dir() && fs::create_dir_all(&primary).is_ok() {
                    primary
                } else {
                    let fb = data_dir.join("bootguard");
                    let _ = fs::create_dir_all(&fb);
                    fb
                }
            }
        };
        let _ = fs::create_dir_all(&meta_dir);
        let _ = fs::set_permissions(&meta_dir, fs::Permissions::from_mode(0o700));
        Self { data_dir: data_dir.to_path_buf(), meta_dir }
    }

    pub fn bootcount_path(&self) -> PathBuf {
        self.meta_dir.join("bootcount")
    }

    pub fn last_good_path(&self) -> PathBuf {
        self.meta_dir.join("last_good.set")
    }

    pub fn status_path(&self) -> PathBuf {
        self.data_dir.join("bootguard.status")
    }

    pub fn manual_flag_path(&self) -> PathBuf {
        self.data_dir.join("safemode")
    }

    pub fn modules_dir(&self) -> PathBuf {
        self.data_dir.join("modules")
    }
}

fn write_synced_0600(path: &Path, content: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(content)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir_fd) = fs::File::open(parent) {
            let _ = dir_fd.sync_all();
        }
    }
    Ok(())
}

/// Scans `<data_dir>/modules` for active/disabled stamps used by Smart Rollback diffing.
pub fn scan_module_stamps(modules_dir: &Path) -> Vec<ModuleStamp> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(modules_dir) else {
        return out;
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        let Some(id) = path.file_name().and_then(|s| s.to_str()) else { continue };
        if id.starts_with('.') {
            continue;
        }
        if !path.join("module.prop").is_file() {
            continue;
        }
        let enabled = !path.join("disable").exists() && !path.join("remove").exists();
        let mtime_secs = fs::metadata(path.join("module.prop"))
            .or_else(|_| fs::metadata(&path))
            .map(|m| m.mtime().max(0) as u64)
            .unwrap_or(0);
        out.push(ModuleStamp { id: id.to_string(), mtime_secs, enabled });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn read_bootcount(paths: &BootguardPaths) -> u32 {
    fs::read_to_string(paths.bootcount_path())
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn write_bootcount(paths: &BootguardPaths, count: u32) {
    let _ = write_synced_0600(&paths.bootcount_path(), format!("{count}\n").as_bytes());
}

fn write_status(paths: &BootguardPaths, status: &BootguardStatus) {
    let _ = sys::replace_file(&paths.status_path(), status.encode().as_bytes());
}

pub fn read_status(data_dir: &Path) -> BootguardStatus {
    fs::read_to_string(data_dir.join("bootguard.status"))
        .map(|s| BootguardStatus::parse(&s))
        .unwrap_or_default()
}

/// Evaluates all 4 Bootguard layers at `post-fs-data`.
/// Returns the resolved `BootguardStatus` (if `status.safe_mode` is true, caller MUST skip
/// mounting, scripts, sepolicy patching, and Native Zygisk).
pub fn evaluate_post_fs_data(paths: &BootguardPaths, unprivileged_test: bool) -> BootguardStatus {
    // 1. Stop early keywatch and read/disarm kernel early latch.
    if !unprivileged_test {
        keywatch::signal_keywatch_done(&paths.data_dir);
    }
    let kernel_key = if unprivileged_test { None } else { keywatch::consume_kernel_bootkey() };
    let volatile_key = if unprivileged_test {
        None
    } else {
        keywatch::consume_volatile_safemode(&paths.data_dir)
    };
    let key_trigger = volatile_key.or(kernel_key);

    let android_safemode = !unprivileged_test
        && (sys::get_prop("persist.sys.safemode").as_deref() == Some("1")
            || sys::get_prop("ro.sys.safemode").as_deref() == Some("1"));
    let manual_flag = paths.manual_flag_path().exists();

    let prev_count = read_bootcount(paths);
    let now = sys::now_wall_ms();

    // Explicit safe mode triggers (Layers 1–3) take immediate precedence without incrementing bootcount.
    if let Some(kt) = key_trigger {
        let status = BootguardStatus {
            bootcount: prev_count,
            safe_mode: true,
            reason: SafeModeReason::KeyShortcut,
            key_trigger: kt,
            disabled_suspects: Vec::new(),
            zygisk_bypassed: true,
            timestamp_ms: now,
        };
        write_status(paths, &status);
        sys::audit(&paths.data_dir, &format!("{now}|BOOTGUARD|0|0|safemode|key|{}", status.key_trigger));
        return status;
    }
    if android_safemode {
        let status = BootguardStatus {
            bootcount: prev_count,
            safe_mode: true,
            reason: SafeModeReason::AndroidSafemode,
            key_trigger: String::new(),
            disabled_suspects: Vec::new(),
            zygisk_bypassed: true,
            timestamp_ms: now,
        };
        write_status(paths, &status);
        return status;
    }
    if manual_flag {
        let status = BootguardStatus {
            bootcount: prev_count,
            safe_mode: true,
            reason: SafeModeReason::ManualFlag,
            key_trigger: String::new(),
            disabled_suspects: Vec::new(),
            zygisk_bypassed: true,
            timestamp_ms: now,
        };
        write_status(paths, &status);
        return status;
    }

    // Layer 4: Bootcount strike evaluation.
    let last_good = fs::read_to_string(paths.last_good_path())
        .map(|s| LastGoodSnapshot::parse(&s))
        .unwrap_or_default();
    let current = scan_module_stamps(&paths.modules_dir());
    let (next_count, decision) = decide_bootcount(prev_count, &last_good, &current);
    write_bootcount(paths, next_count);

    let status = match decision {
        BootcountDecision::Normal => BootguardStatus {
            bootcount: next_count,
            safe_mode: false,
            reason: SafeModeReason::None,
            key_trigger: String::new(),
            disabled_suspects: Vec::new(),
            zygisk_bypassed: false,
            timestamp_ms: now,
        },
        BootcountDecision::SmartRollback { suspects } => {
            for id in &suspects {
                let disable_flag = paths.modules_dir().join(id).join("disable");
                let _ = fs::write(&disable_flag, b"");
            }
            sys::audit(
                &paths.data_dir,
                &format!("{now}|BOOTGUARD|0|0|smart_rollback|{}|-", suspects.join(",")),
            );
            BootguardStatus {
                bootcount: next_count,
                safe_mode: false,
                reason: SafeModeReason::BootloopSmartRollback,
                key_trigger: String::new(),
                disabled_suspects: suspects,
                zygisk_bypassed: false,
                timestamp_ms: now,
            }
        }
        BootcountDecision::FullSafeMode => {
            sys::audit(&paths.data_dir, &format!("{now}|BOOTGUARD|0|0|safemode|bootloop|-"));
            BootguardStatus {
                bootcount: next_count,
                safe_mode: true,
                reason: SafeModeReason::BootloopFull,
                key_trigger: String::new(),
                disabled_suspects: Vec::new(),
                zygisk_bypassed: true,
                timestamp_ms: now,
            }
        }
    };
    write_status(paths, &status);
    status
}

/// Called after `sys.boot_completed=1` (+ stability window on real device).
/// Resets bootcount to 0 and records a fresh `last_good.set` snapshot when not in Full Safe Mode.
pub fn mark_boot_stable(paths: &BootguardPaths) {
    write_bootcount(paths, 0);
    let mut status = read_status(&paths.data_dir);
    status.bootcount = 0;
    if !status.safe_mode {
        let stamps = scan_module_stamps(&paths.modules_dir());
        let snap = LastGoodSnapshot { modules: stamps };
        let _ = write_synced_0600(&paths.last_good_path(), snap.encode().as_bytes());
    }
    write_status(paths, &status);
}

/// Clears manual safe mode flag, resets bootcount to 0, and clears safe mode status for next boot.
pub fn clear_safemode(paths: &BootguardPaths) -> io::Result<()> {
    let _ = fs::remove_file(paths.manual_flag_path());
    let _ = fs::remove_file(paths.data_dir.join(keywatch::VOLATILE_SAFEMODE_NAME));
    write_bootcount(paths, 0);
    let status = BootguardStatus {
        bootcount: 0,
        safe_mode: false,
        reason: SafeModeReason::None,
        key_trigger: String::new(),
        disabled_suspects: Vec::new(),
        zygisk_bypassed: false,
        timestamp_ms: sys::now_wall_ms(),
    };
    write_status(paths, &status);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smart_rollback_disables_only_new_module_and_recovers() {
        let tmp = std::env::temp_dir().join(format!("yasvara-bg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let data = tmp.join("data");
        let meta = tmp.join("meta");
        fs::create_dir_all(data.join("modules/good_mod")).unwrap();
        fs::write(data.join("modules/good_mod/module.prop"), "id=good_mod\nname=Good\n").unwrap();

        let paths = BootguardPaths::resolve(&data, Some(&meta));
        // Boot 1: normal boot -> bootcount=1 -> mark stable -> saves last_good.set, bootcount=0.
        let s1 = evaluate_post_fs_data(&paths, true);
        assert!(!s1.safe_mode);
        assert_eq!(s1.bootcount, 1);
        mark_boot_stable(&paths);
        assert_eq!(read_bootcount(&paths), 0);

        // Install a bad module and simulate bootloop (Boot 2 starts -> crashes before boot_completed).
        fs::create_dir_all(data.join("modules/bad_mod")).unwrap();
        fs::write(data.join("modules/bad_mod/module.prop"), "id=bad_mod\nname=Bad\n").unwrap();
        let s2 = evaluate_post_fs_data(&paths, true);
        assert!(!s2.safe_mode);
        assert_eq!(s2.bootcount, 1);

        // Boot 3 after crash: Strike 1 triggers Smart Rollback of `bad_mod` only!
        let s3 = evaluate_post_fs_data(&paths, true);
        assert!(!s3.safe_mode);
        assert_eq!(s3.reason, SafeModeReason::BootloopSmartRollback);
        assert_eq!(s3.disabled_suspects, vec!["bad_mod".to_string()]);
        assert!(data.join("modules/bad_mod/disable").exists());
        assert!(!data.join("modules/good_mod/disable").exists());

        // If Boot 3 ALSO crashes -> Strike 2 triggers Full Safe Mode!
        let s4 = evaluate_post_fs_data(&paths, true);
        assert!(s4.safe_mode);
        assert_eq!(s4.reason, SafeModeReason::BootloopFull);

        // Clearing safe mode resets cleanly.
        clear_safemode(&paths).unwrap();
        assert_eq!(read_bootcount(&paths), 0);
        assert!(!read_status(&data).safe_mode);

        let _ = fs::remove_dir_all(&tmp);
    }
}
