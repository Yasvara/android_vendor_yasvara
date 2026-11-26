// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `pulih` — Full-Rust 120 Hz Material You Recovery + Kernel/Power Tuner for Yasvara (`SPEC-0051`).

pub mod cli;
pub mod doctor;
pub mod drm;
pub mod evdev_linux;
pub mod files;
pub mod gpu;
pub mod hardware;
pub mod input;
pub mod ipc;
pub mod kernel;
pub mod super_mount;
pub mod ui;
pub mod wifi;

use pasang_core::meta::{BootCanary, PulihLock, RecoveryTheme};
use pasang_core::slot::RecoveryThemeSeed;
use std::fs;
use std::path::Path;

pub const THEME_PATH: &str = "/metadata/yasvara/recovery_theme.bin";
pub const CANARY_PATH: &str = "/metadata/yasvara/boot_canary.bin";
pub const LOCK_PATH: &str = "/metadata/yasvara/pulih_lock.bin";
pub const FASTBOOTD_BIN: &str = "/system/bin/fastbootd";

/// Boot configuration loaded at recovery startup in < 5 ms (zero `/data` mount!).
#[derive(Clone, Debug)]
pub struct BootContext {
    pub theme: RecoveryTheme,
    pub canary: BootCanary,
    pub lock: Option<PulihLock>,
    pub enter_fastbootd: bool,
}

/// Check Android BCB (`/dev/block/by-name/misc` first 32 bytes) for `"boot-fastboot"`.
pub fn bcb_requests_fastboot(misc_path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(misc_path) else {
        return false;
    };
    use std::io::Read;
    let mut cmd = [0u8; 32];
    if f.read_exact(&mut cmd).is_err() {
        return false;
    }
    cmd.starts_with(b"boot-fastboot")
}

/// Clear Android BCB `command` field (`boot-recovery` / `bootonce-*`) in
/// `/dev/block/by-name/misc` so the next normal reboot returns to Android OS
/// instead of looping back into Recovery!
pub fn clear_bcb_command(misc_path: &Path) -> std::io::Result<bool> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut f = fs::OpenOptions::new().read(true).write(true).open(misc_path)?;
    let mut cmd = [0u8; 32];
    f.read_exact(&mut cmd)?;
    if cmd.iter().all(|&b| b == 0) {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&[0u8; 32])?;
    f.sync_all()?;
    Ok(true)
}

impl BootContext {
    /// Load `/metadata/yasvara/*` safely with corrupt-file fallback defaults.
    /// Reads BOTH Laras's `"YTHM"` `RecoveryThemeSeed` and `"YVTH"` `RecoveryTheme`!
    pub fn load_from(dir: &Path, args: &[String]) -> Self {
        let theme = fs::read(dir.join("recovery_theme.bin"))
            .ok()
            .and_then(|b| {
                if let Ok(seed) = RecoveryThemeSeed::from_bytes(&b) {
                    let loc = if seed.locale_str().starts_with("in") || seed.locale_str().starts_with("id") {
                        1
                    } else {
                        0
                    };
                    Some(RecoveryTheme {
                        seed_argb: seed.seed_argb,
                        variant: 0,
                        oled_black: seed.oled_black(),
                        locale: loc,
                        refresh_hz: 120,
                        brightness: 200,
                    })
                } else {
                    RecoveryTheme::from_bytes(&b).ok()
                }
            })
            .unwrap_or_default();
        let canary = fs::read(dir.join("boot_canary.bin"))
            .ok()
            .and_then(|b| BootCanary::from_bytes(&b).ok())
            .unwrap_or_default();
        let lock = fs::read(dir.join("pulih_lock.bin"))
            .ok()
            .and_then(|b| PulihLock::from_bytes(&b).ok());
        let enter_fastbootd = args.iter().any(|a| a == "--fastboot")
            || bcb_requests_fastboot(Path::new("/dev/block/by-name/misc"));
        Self {
            theme,
            canary,
            lock,
            enter_fastbootd,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_context_survives_missing_or_corrupt_metadata_files() {
        let tmp = std::env::temp_dir().join(format!("pulih_bootctx_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // Corrupt theme + corrupt canary must NEVER panic — must fall back cleanly!
        fs::write(tmp.join("recovery_theme.bin"), b"corrupt_bytes").unwrap();
        fs::write(tmp.join("boot_canary.bin"), b"bad").unwrap();

        let ctx = BootContext::load_from(&tmp, &["pulih".into(), "--fastboot".into()]);
        assert_eq!(ctx.theme, RecoveryTheme::default());
        assert_eq!(ctx.canary, BootCanary::default());
        assert!(ctx.lock.is_none());
        assert!(ctx.enter_fastbootd);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn clear_bcb_command_clears_boot_recovery_and_preserves_rest() {
        let tmp = std::env::temp_dir().join(format!("pulih_bcb_{}.bin", std::process::id()));
        let mut misc = vec![0xAAu8; 2048];
        misc[0..13].copy_from_slice(b"boot-recovery");
        misc[13..32].fill(0);
        fs::write(&tmp, &misc).unwrap();

        assert!(!bcb_requests_fastboot(&tmp));
        assert!(clear_bcb_command(&tmp).unwrap());
        let after = fs::read(&tmp).unwrap();
        assert!(after[0..32].iter().all(|&b| b == 0));
        assert!(after[32..].iter().all(|&b| b == 0xAA));
        // Second clear is a no-op
        assert!(!clear_bcb_command(&tmp).unwrap());

        let _ = fs::remove_file(&tmp);
    }
}
