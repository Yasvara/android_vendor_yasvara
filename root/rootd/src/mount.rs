// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Built-in Hybrid OverlayFS + Magic Mount engine with optional `metamodule=1` override.
//!
//! - Handles standard Android partitions: `system`, `vendor`, `product`, `system_ext`, `odm`,
//!   including Magisk-style `system/{vendor,product,system_ext,odm}` aliasing.
//! - Uses kernel OverlayFS per touched sub-directory (1 mount per directory, zero tmpfs copy
//!   overhead), preserving `.replace` and `c 0 0` whiteouts.
//! - Automatically falls back to recursive Magic Mount (`tmpfs` + bind-mount with SELinux
//!   context cloning via `lgetxattr`/`lsetxattr`) if OverlayFS cannot attach to a target.
//! - If an enabled module declares `metamodule=1` and ships `metamount.sh`, delegates mounting
//!   to it inside the private `/data/adb` compat namespace and captures resulting mountpoints.
//! - Publishes `<data_dir>/mounts.set` for Zygote's `TabirUnmount`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use yasvara_root_proto::mounts::MountsSet;

use crate::sys;

pub const PARTITIONS: [&str; 5] = ["system", "vendor", "product", "system_ext", "odm"];
pub const SYSTEM_SUB_PARTITIONS: [&str; 4] = ["vendor", "product", "system_ext", "odm"];

/// A single mount plan target (e.g. target = `/system/etc`, layers = `[mod_a/system/etc, mod_b/system/etc]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayTarget {
    pub target_dir: PathBuf,
    pub layers: Vec<PathBuf>,
    pub has_replace: bool,
}

/// Scans enabled module directories (sorted deterministically by module ID) and groups
/// every touched partition sub-directory into consolidated OverlayFS / Magic Mount targets.
pub fn build_mount_plan(module_dirs: &[PathBuf]) -> Vec<OverlayTarget> {
    let mut by_target: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    let mut replace_targets: BTreeSet<PathBuf> = BTreeSet::new();

    for mod_dir in module_dirs {
        if mod_dir.join("disable").exists()
            || mod_dir.join("remove").exists()
            || mod_dir.join("skip_mount").exists()
        {
            continue;
        }
        for part in PARTITIONS {
            let part_root = mod_dir.join(part);
            if !part_root.is_dir() {
                continue;
            }
            let Ok(entries) = fs::read_dir(&part_root) else { continue };
            for ent in entries.flatten() {
                let name = ent.file_name();
                let Some(name_str) = name.to_str() else { continue };
                let src_path = ent.path();

                // Map Magisk-style `system/vendor/...` to `/vendor/...` (and product/system_ext/odm).
                if part == "system" && SYSTEM_SUB_PARTITIONS.contains(&name_str) && src_path.is_dir() {
                    if let Ok(sub_entries) = fs::read_dir(&src_path) {
                        for sub in sub_entries.flatten() {
                            let sub_name = sub.file_name();
                            let target = PathBuf::from("/").join(name_str).join(&sub_name);
                            let sub_src = sub.path();
                            if sub_src.is_dir() {
                                if sub_src.join(".replace").exists() {
                                    replace_targets.insert(target.clone());
                                }
                                by_target.entry(target).or_default().push(sub_src);
                            } else {
                                let parent_target = PathBuf::from("/").join(name_str);
                                by_target.entry(parent_target).or_default().push(src_path.clone());
                                break;
                            }
                        }
                    }
                    continue;
                }

                let target = PathBuf::from("/").join(part).join(&name);
                if src_path.is_dir() {
                    if src_path.join(".replace").exists() {
                        replace_targets.insert(target.clone());
                    }
                    by_target.entry(target).or_default().push(src_path);
                } else {
                    // Direct file under partition root (rare) -> mount partition root itself.
                    let root_target = PathBuf::from("/").join(part);
                    by_target.entry(root_target).or_default().push(part_root.clone());
                }
            }
        }
    }

    by_target
        .into_iter()
        .map(|(target_dir, mut layers)| {
            // Deduplicate identical layer paths while preserving order.
            let mut seen = BTreeSet::new();
            layers.retain(|p| seen.insert(p.clone()));
            let has_replace = replace_targets.contains(&target_dir);
            OverlayTarget { target_dir, layers, has_replace }
        })
        .collect()
}

fn cstr_path(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nul in path"))
}

fn clone_selinux_context(src: &Path, dst: &Path) {
    let (Ok(cs), Ok(cd)) = (cstr_path(src), cstr_path(dst)) else { return };
    let attr = CString::new("security.selinux").unwrap();
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::lgetxattr(
            cs.as_ptr(),
            attr.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n > 0 {
        unsafe {
            libc::lsetxattr(
                cd.as_ptr(),
                attr.as_ptr(),
                buf.as_ptr() as *const libc::c_void,
                n as usize,
                0,
            );
        }
    }
}

/// Checks whether `path` is a Magic/OverlayFS whiteout (`c 0 0` char device).
pub fn is_whiteout(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else { return false };
    meta.file_type().is_char_device() && meta.rdev() == 0
}

/// Escapes colons and commas in overlayfs `lowerdir=` option paths.
pub fn escape_overlay_dir(p: &Path) -> String {
    let raw = p.to_string_lossy();
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if matches!(ch, ':' | ',' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Attempts a read-only stacked OverlayFS mount onto `target.target_dir`.
fn try_mount_overlay(target: &OverlayTarget) -> io::Result<()> {
    if !target.target_dir.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "target dir missing"));
    }
    let mut lowers: Vec<String> = target.layers.iter().map(|p| escape_overlay_dir(p)).collect();
    // Unless `.replace` is requested, append the stock partition directory as the lowest layer.
    if !target.has_replace {
        lowers.push(escape_overlay_dir(&target.target_dir));
    }
    let opts = format!("lowerdir={}", lowers.join(":"));
    let src = CString::new("overlay").unwrap();
    let fstype = CString::new("overlay").unwrap();
    let cdst = cstr_path(&target.target_dir)?;
    let copts = CString::new(opts).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad opts"))?;

    sys::cvt(unsafe {
        libc::mount(
            src.as_ptr(),
            cdst.as_ptr(),
            fstype.as_ptr(),
            libc::MS_RDONLY | libc::MS_NOATIME,
            copts.as_ptr() as *const libc::c_void,
        )
    })?;
    Ok(())
}

/// Fallback Magic Mount: mounts a `tmpfs` over `target_dir`, clones original directory entries
/// (unless `.replace` or whiteout), and bind-mounts module files on top with matching SELinux labels.
fn mount_magic_fallback(target: &OverlayTarget) -> io::Result<()> {
    if !target.target_dir.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "target dir missing"));
    }
    // Collect original entries before masking target_dir with tmpfs.
    let mut orig_entries: BTreeMap<String, PathBuf> = BTreeMap::new();
    if !target.has_replace {
        if let Ok(rd) = fs::read_dir(&target.target_dir) {
            for ent in rd.flatten() {
                if let Some(name) = ent.file_name().to_str() {
                    orig_entries.insert(name.to_string(), ent.path());
                }
            }
        }
    }
    // Collect module overrides (earlier layer in `layers` wins, matching overlayfs precedence).
    let mut mod_entries: BTreeMap<String, Option<PathBuf>> = BTreeMap::new();
    for layer in &target.layers {
        let Ok(rd) = fs::read_dir(layer) else { continue };
        for ent in rd.flatten() {
            let fname = ent.file_name();
            let Some(name) = fname.to_str() else { continue };
            if name == ".replace" {
                continue;
            }
            let p = ent.path();
            if mod_entries.contains_key(name) {
                continue;
            }
            if is_whiteout(&p) {
                mod_entries.insert(name.to_string(), None);
            } else {
                mod_entries.insert(name.to_string(), Some(p));
            }
        }
    }

    // Hold a directory fd to original target_dir so we can bind-mount original files back if needed.
    let cdst = cstr_path(&target.target_dir)?;
    let orig_dir_fd = sys::cvt(unsafe {
        libc::open(cdst.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
    })?;
    let orig_meta = fs::metadata(&target.target_dir).ok();
    let mode = orig_meta.as_ref().map(|m| m.mode() & 0o777).unwrap_or(0o755);

    let tmpfs = CString::new("tmpfs").unwrap();
    let opts = CString::new(format!("mode={mode:o},uid=0,gid=0")).unwrap();
    let mres = sys::cvt(unsafe {
        libc::mount(
            tmpfs.as_ptr(),
            cdst.as_ptr(),
            tmpfs.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            opts.as_ptr() as *const libc::c_void,
        )
    });
    if let Err(e) = mres {
        sys::close(orig_dir_fd);
        return Err(e);
    }

    // Restore non-overridden original entries from orig_dir_fd.
    for name in orig_entries.keys() {
        if mod_entries.contains_key(name) {
            continue;
        }
        let proc_src = PathBuf::from(format!("/proc/self/fd/{orig_dir_fd}/{name}"));
        let dst = target.target_dir.join(name);
        let Ok(meta) = fs::symlink_metadata(&proc_src) else { continue };
        if meta.file_type().is_symlink() {
            if let Ok(link_tgt) = fs::read_link(&proc_src) {
                let _ = std::os::unix::fs::symlink(link_tgt, &dst);
            }
        } else if meta.is_dir() {
            if fs::create_dir(&dst).is_ok() {
                if let (Ok(cs), Ok(cd)) = (cstr_path(&proc_src), cstr_path(&dst)) {
                    unsafe { libc::mount(cs.as_ptr(), cd.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REC, std::ptr::null()) };
                }
            }
        } else if fs::File::create(&dst).is_ok() {
            if let (Ok(cs), Ok(cd)) = (cstr_path(&proc_src), cstr_path(&dst)) {
                unsafe { libc::mount(cs.as_ptr(), cd.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) };
            }
        }
    }

    // Apply module overrides.
    for (name, maybe_src) in &mod_entries {
        let Some(src) = maybe_src else { continue };
        let dst = target.target_dir.join(name);
        let Ok(meta) = fs::symlink_metadata(src) else { continue };
        if meta.file_type().is_symlink() {
            if let Ok(link_tgt) = fs::read_link(src) {
                let _ = std::os::unix::fs::symlink(link_tgt, &dst);
            }
        } else if meta.is_dir() {
            if fs::create_dir(&dst).is_ok() {
                let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(meta.mode() & 0o777));
                clone_selinux_context(src, &dst);
                if let (Ok(cs), Ok(cd)) = (cstr_path(src), cstr_path(&dst)) {
                    unsafe { libc::mount(cs.as_ptr(), cd.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REC, std::ptr::null()) };
                }
            }
        } else if fs::File::create(&dst).is_ok() {
            let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(meta.mode() & 0o777));
            clone_selinux_context(src, &dst);
            if let (Ok(cs), Ok(cd)) = (cstr_path(src), cstr_path(&dst)) {
                unsafe { libc::mount(cs.as_ptr(), cd.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) };
            }
        }
    }

    // Lock the tmpfs read-only.
    unsafe {
        libc::mount(
            std::ptr::null(),
            cdst.as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            std::ptr::null(),
        );
    }
    sys::close(orig_dir_fd);
    Ok(())
}

/// Parses `/proc/self/mountinfo` to collect active mountpoints (used for metamodule diffing).
pub fn snapshot_mountpoints() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else { return set };
    for line in text.lines() {
        let mut cols = line.split_whitespace();
        let _id = cols.next();
        let _parent = cols.next();
        let _major_minor = cols.next();
        let _root = cols.next();
        if let Some(mnt_point) = cols.next() {
            set.insert(mnt_point.to_string());
        }
    }
    set
}

/// Executes the built-in Hybrid Mount plan and returns the list of actually mounted paths
/// (suitable for writing to `mounts.set`).
pub fn execute_hybrid_mount(
    module_dirs: &[PathBuf],
    unprivileged_test: bool,
) -> (MountsSet, Vec<(String, &'static str)>) {
    let plan = build_mount_plan(module_dirs);
    let mut mounted = Vec::new();
    let mut report = Vec::new();
    for target in &plan {
        let path_str = target.target_dir.to_string_lossy().into_owned();
        if unprivileged_test {
            mounted.push(path_str.clone());
            report.push((path_str, "overlay-dryrun"));
            continue;
        }
        match try_mount_overlay(target) {
            Ok(()) => {
                mounted.push(path_str.clone());
                report.push((path_str, "overlay"));
            }
            Err(_) => {
                if mount_magic_fallback(target).is_ok() {
                    mounted.push(path_str.clone());
                    report.push((path_str, "magic"));
                }
            }
        }
    }
    (MountsSet { paths: mounted }, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_plan_groups_partitions_and_aliases_system_vendor() {
        let tmp = std::env::temp_dir().join(format!("yasvara-mnt-plan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let m1 = tmp.join("mod_a");
        let m2 = tmp.join("mod_b");
        let m3 = tmp.join("mod_disabled");
        fs::create_dir_all(m1.join("system/etc")).unwrap();
        fs::create_dir_all(m1.join("system/vendor/etc")).unwrap();
        fs::create_dir_all(m2.join("system/etc")).unwrap();
        fs::write(m2.join("system/etc/.replace"), b"").unwrap();
        fs::create_dir_all(m3.join("system/bin")).unwrap();
        fs::write(m3.join("disable"), b"").unwrap();

        let plan = build_mount_plan(&[m1.clone(), m2.clone(), m3]);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].target_dir, PathBuf::from("/system/etc"));
        assert_eq!(plan[0].layers.len(), 2);
        assert!(plan[0].has_replace);
        assert_eq!(plan[1].target_dir, PathBuf::from("/vendor/etc"));
        assert_eq!(plan[1].layers, vec![m1.join("system/vendor/etc")]);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn overlay_escape_handles_colons_and_commas() {
        assert_eq!(escape_overlay_dir(Path::new("/a/b:c,d")), "/a/b\\:c\\,d");
    }
}
