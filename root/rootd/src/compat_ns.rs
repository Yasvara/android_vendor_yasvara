// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Private `/data/adb` compatibility mount namespace.
//!
//! Real module storage lives exclusively under `/data/misc/yasvara_root/` so `/data/adb`
//! stays completely clean in the global/app namespace (preserving SELinux zero-leak and
//! eliminating `/data/adb/{modules,ksu,magisk}` forensic signals).
//!
//! Whenever `yasvara_rootd` runs a module installer (`customize.sh`), boot script
//! (`post-fs-data.sh`, `service.sh`, `post-mount.sh`, `boot-completed.sh`), `action.sh`,
//! or metamodule hook, it unshares a private mount namespace where `/` remains `MS_SHARED`
//! (so system mounts propagate globally) while `/data/adb` is `MS_PRIVATE` and bind-mounted
//! from `/data/misc/yasvara_root/adb_compat`.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::sys;

pub const COMPAT_ADB_MOUNTPOINT: &str = "/data/adb";
pub const REAL_ROOTD_BIN: &str = "/system/xbin/yasvara_rootd";

fn cpath(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))
}

fn bind_mount(src: &Path, dst: &Path) -> io::Result<()> {
    let csrc = cpath(src)?;
    let cdst = cpath(dst)?;
    sys::cvt(unsafe {
        libc::mount(
            csrc.as_ptr(),
            cdst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    })?;
    Ok(())
}

/// Ensures `<data_dir>/adb_compat` has all standard Magisk/KSU layout directories and
/// tool shims (`ksud`, `resetprop`, `magisk`, `akarctl`) pointing to `yasvara_rootd`.
pub fn prepare_compat_tree(data_dir: &Path, rootd_bin: &Path) -> io::Result<PathBuf> {
    let compat = data_dir.join("adb_compat");
    for sub in [
        "modules",
        "modules_update",
        "post-fs-data.d",
        "service.d",
        "post-mount.d",
        "boot-completed.d",
        "ksu/bin",
        "ksu/modules",
    ] {
        let d = compat.join(sub);
        fs::create_dir_all(&d)?;
        let _ = fs::set_permissions(&d, fs::Permissions::from_mode(0o755));
    }
    let bin_dir = compat.join("ksu/bin");
    for tool in ["ksud", "resetprop", "magisk", "akarctl"] {
        let link = bin_dir.join(tool);
        let _ = fs::remove_file(&link);
        let _ = symlink(rootd_bin, &link);
    }
    Ok(compat)
}

/// Enters a private mount namespace where `/data/adb` projects `<data_dir>/adb_compat`
/// and `<data_dir>/modules` + `<data_dir>/modules_update`, while `/` stays `MS_SHARED`
/// so module mounts propagate to the global mount namespace.
pub fn enter_compat_adb_namespace(data_dir: &Path, unprivileged_test: bool) -> io::Result<()> {
    if unprivileged_test {
        return Ok(());
    }
    let compat = prepare_compat_tree(data_dir, Path::new(REAL_ROOTD_BIN))?;
    sys::cvt(unsafe { libc::unshare(libc::CLONE_NEWNS) })?;

    // Keep `/` shared so system/vendor/product mounts propagate to PID 1 / Zygote.
    let root_c = CString::new("/").unwrap();
    let _ = unsafe {
        libc::mount(
            std::ptr::null(),
            root_c.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_SHARED,
            std::ptr::null(),
        )
    };

    let adb_dir = Path::new(COMPAT_ADB_MOUNTPOINT);
    if !adb_dir.exists() {
        let _ = fs::create_dir_all(adb_dir);
    }
    let adb_c = cpath(adb_dir)?;
    // Bind /data/adb onto itself first so we can mark it MS_PRIVATE cleanly even if it wasn't a mountpoint.
    let _ = unsafe {
        libc::mount(
            adb_c.as_ptr(),
            adb_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    let _ = unsafe {
        libc::mount(
            std::ptr::null(),
            adb_c.as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };

    // Preserve real /data/adb/adb_keys if present on the device.
    let real_keys = adb_dir.join("adb_keys");
    let compat_keys = compat.join("adb_keys");
    if real_keys.is_file() {
        let _ = fs::copy(&real_keys, &compat_keys);
    }

    bind_mount(&compat, adb_dir)?;
    let _ = bind_mount(&data_dir.join("modules"), &adb_dir.join("modules"));
    let _ = bind_mount(&data_dir.join("modules_update"), &adb_dir.join("modules_update"));
    Ok(())
}

/// Standard environment variables exposed to Magisk/KSU/BakaSU compatible scripts.
pub fn compat_env(data_dir: &Path, unprivileged_test: bool) -> Vec<(String, String)> {
    let adb_root = if unprivileged_test {
        data_dir.join("adb_compat")
    } else {
        PathBuf::from(COMPAT_ADB_MOUNTPOINT)
    };
    let ksu_bin = adb_root.join("ksu/bin");
    let path = if unprivileged_test {
        format!("{}:/usr/bin:/bin:/system/bin", ksu_bin.display())
    } else {
        format!(
            "{}:/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/vendor/bin",
            ksu_bin.display()
        )
    };
    vec![
        ("PATH".into(), path),
        ("YASVARA_AKAR".into(), "true".into()),
        ("YASVARA_AKAR_VER".into(), yasvara_root_proto::VERSION_NAME.into()),
        ("YASVARA_AKAR_VER_CODE".into(), "30100".into()),
        // Compatibility exports expected by standard Magisk/KSU modules:
        ("KSU".into(), "true".into()),
        ("KSU_VER".into(), "v3.1.0-akar".into()),
        ("KSU_VER_CODE".into(), "30100".into()),
        ("KSU_KERNEL_VER_CODE".into(), "30100".into()),
        ("MAGISK_VER".into(), "28.1-akar".into()),
        ("MAGISK_VER_CODE".into(), "28100".into()),
        ("ASH_STANDALONE".into(), "1".into()),
        ("AKAR_DATA_DIR".into(), data_dir.display().to_string()),
    ]
}
