// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! The Magisk/KSU `/data/adb` layout, without a mount.
//!
//! Module storage lives under `/data/misc/yasvara_root/`. The real `/data/adb` (stock,
//! `0700 root:root`, `adb_data_file`, no app may search it) gets symlinks into it, so scripts
//! that hardcode `/data/adb/...` work in every mount namespace, including init's
//! (`nsenter -t1 -m`), and the mount table never changes. Entries that already exist as real
//! files or directories belong to someone else and are left alone.

use std::fs;
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

pub const ADB_DIR: &str = "/data/adb";
pub const REAL_ROOTD_BIN: &str = "/system/xbin/yasvara_rootd";

/// Directories of the compat tree, relative to `<data_dir>/adb_compat`.
const COMPAT_DIRS: [&str; 8] = [
    "post-fs-data.d",
    "service.d",
    "post-mount.d",
    "boot-completed.d",
    "ksu/bin",
    "ksu/module_configs",
    "magisk",
    "initrc.d",
];

/// Tools reachable as `/data/adb/ksu/bin/<tool>`; the daemon dispatches on argv0.
const TOOLS: [&str; 4] = ["ksud", "resetprop", "magisk", "akarctl"];

/// One `/data/adb/<name>` link and where it points.
#[derive(Debug, PartialEq, Eq)]
pub struct Link {
    pub name: &'static str,
    pub target: PathBuf,
}

/// What `/data/adb` should hold.
pub fn plan_links(data_dir: &Path, rootd_bin: &Path, metamodule: Option<&Path>) -> Vec<Link> {
    let compat = data_dir.join("adb_compat");
    let mut v = vec![
        Link { name: "modules", target: data_dir.join("modules") },
        Link { name: "modules_update", target: data_dir.join("modules_update") },
        Link { name: "ksu", target: compat.join("ksu") },
        Link { name: "magisk", target: compat.join("magisk") },
        Link { name: "ksud", target: rootd_bin.to_path_buf() },
    ];
    for d in ["post-fs-data.d", "service.d", "post-mount.d", "boot-completed.d", "initrc.d"] {
        v.push(Link { name: d, target: compat.join(d) });
    }
    if let Some(m) = metamodule {
        v.push(Link { name: "metamodule", target: m.to_path_buf() });
    }
    v
}

/// Ensures the compat tree and the tool links inside it.
pub fn prepare_compat_tree(data_dir: &Path, rootd_bin: &Path) -> io::Result<PathBuf> {
    let compat = data_dir.join("adb_compat");
    for sub in COMPAT_DIRS {
        let d = compat.join(sub);
        fs::create_dir_all(&d)?;
        let _ = fs::set_permissions(&d, fs::Permissions::from_mode(0o755));
    }
    for tool in TOOLS {
        replace_link(&compat.join("ksu/bin").join(tool), rootd_bin)?;
    }
    replace_link(&compat.join("magisk/magisk"), rootd_bin)?;
    Ok(compat)
}

fn replace_link(link: &Path, target: &Path) -> io::Result<()> {
    if fs::read_link(link).ok().as_deref() == Some(target) {
        return Ok(());
    }
    let _ = fs::remove_file(link);
    symlink(target, link)
}

/// Creates or repoints `/data/adb/<name>` links. Returns the names skipped because a real
/// file or directory is there. A stale `metamodule` link is removed when none is active.
pub fn sync_adb_links(adb_dir: &Path, links: &[Link]) -> io::Result<Vec<&'static str>> {
    fs::create_dir_all(adb_dir)?;
    let mut skipped = Vec::new();
    for l in links {
        let path = adb_dir.join(l.name);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => replace_link(&path, &l.target)?,
            Ok(_) => skipped.push(l.name),
            Err(_) => symlink(&l.target, &path)?,
        }
    }
    let meta = adb_dir.join("metamodule");
    if !links.iter().any(|l| l.name == "metamodule")
        && fs::symlink_metadata(&meta).is_ok_and(|m| m.file_type().is_symlink())
    {
        let _ = fs::remove_file(meta);
    }
    Ok(skipped)
}

/// Environment for every module script (installer, stages, `action.sh`, WebUI exec).
pub fn compat_env(data_dir: &Path, unprivileged_test: bool) -> Vec<(String, String)> {
    let adb_root = if unprivileged_test { data_dir.join("adb_compat") } else { PathBuf::from(ADB_DIR) };
    let ksu_bin = adb_root.join("ksu/bin");
    let path = if unprivileged_test {
        format!("{}:/usr/bin:/bin:/system/bin", ksu_bin.display())
    } else {
        format!(
            "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/vendor/bin:{}",
            ksu_bin.display()
        )
    };
    let zygisk = crate::modules::is_zygisk_enabled(data_dir);
    let mut v: Vec<(String, String)> = vec![
        ("PATH".into(), path),
        ("YASVARA_AKAR".into(), "true".into()),
        ("YASVARA_AKAR_VER".into(), yasvara_root_proto::VERSION_NAME.into()),
        ("YASVARA_AKAR_VER_CODE".into(), AKAR_VER_CODE.into()),
        ("KSU".into(), "true".into()),
        ("KSU_VER".into(), "v3.1.0-akar".into()),
        ("KSU_VER_CODE".into(), AKAR_VER_CODE.into()),
        ("KSU_KERNEL_VER_CODE".into(), AKAR_VER_CODE.into()),
        ("KSU_HAS_HOT_INSTALL".into(), "true".into()),
        ("MAGISK_VER".into(), "28.1-akar".into()),
        ("MAGISK_VER_CODE".into(), "28100".into()),
        ("ASH_STANDALONE".into(), "1".into()),
        ("AKAR_DATA_DIR".into(), data_dir.display().to_string()),
    ];
    if zygisk {
        v.push(("ZYGISK_ENABLED".into(), "1".into()));
    }
    v
}

pub const AKAR_VER_CODE: &str = "30100";

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("akar-adb-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn links_are_created_repointed_and_foreign_entries_kept() {
        let t = tmp("links");
        let data = t.join("data");
        let adb = t.join("adb");
        fs::create_dir_all(adb.join("magisk")).unwrap(); // someone else's real dir
        fs::write(adb.join("adb_keys"), b"k").unwrap();
        symlink("/nowhere", adb.join("modules")).unwrap(); // stale link of ours
        let links = plan_links(&data, Path::new("/system/xbin/yasvara_rootd"), None);
        let skipped = sync_adb_links(&adb, &links).unwrap();
        assert_eq!(skipped, vec!["magisk"]);
        assert_eq!(fs::read_link(adb.join("modules")).unwrap(), data.join("modules"));
        assert_eq!(fs::read_link(adb.join("ksud")).unwrap(), PathBuf::from("/system/xbin/yasvara_rootd"));
        assert_eq!(fs::read(adb.join("adb_keys")).unwrap(), b"k", "unrelated files untouched");
        // Idempotent.
        assert!(sync_adb_links(&adb, &links).unwrap() == vec!["magisk"]);
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn metamodule_link_follows_the_active_one() {
        let t = tmp("meta");
        let data = t.join("data");
        let adb = t.join("adb");
        let m = data.join("modules/meta_overlay");
        let with = plan_links(&data, Path::new("/r"), Some(&m));
        sync_adb_links(&adb, &with).unwrap();
        assert_eq!(fs::read_link(adb.join("metamodule")).unwrap(), m);
        let without = plan_links(&data, Path::new("/r"), None);
        sync_adb_links(&adb, &without).unwrap();
        assert!(fs::symlink_metadata(adb.join("metamodule")).is_err());
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn compat_tree_has_tool_links() {
        let t = tmp("tree");
        let compat = prepare_compat_tree(&t, Path::new("/r")).unwrap();
        for tool in TOOLS {
            assert_eq!(fs::read_link(compat.join("ksu/bin").join(tool)).unwrap(), PathBuf::from("/r"));
        }
        assert_eq!(fs::read_link(compat.join("magisk/magisk")).unwrap(), PathBuf::from("/r"));
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn env_exports_the_module_contract() {
        let t = tmp("env");
        let env = compat_env(&t, true);
        let get = |k: &str| env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.clone());
        assert_eq!(get("KSU").as_deref(), Some("true"));
        assert_eq!(get("KSU_HAS_HOT_INSTALL").as_deref(), Some("true"));
        assert_eq!(get("ZYGISK_ENABLED"), None, "Zygisk off");
        fs::write(t.join("modules.conf"), "enabled=1\n").unwrap();
        fs::write(t.join("zygisk.conf"), "enabled=1\n").unwrap();
        let env = compat_env(&t, true);
        assert!(env.iter().any(|(k, v)| k == "ZYGISK_ENABLED" && v == "1"));
        let _ = fs::remove_dir_all(&t);
    }
}
