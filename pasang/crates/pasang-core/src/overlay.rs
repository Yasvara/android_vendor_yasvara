// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Developer OverlayFS inspector and safe upperdir cleaner (`/mnt/scratch/overlay`).
//!
//! Used by:
//! - Optional post-OTA auto-clean (`OtaOptions::clean_overlay`, gated to dev/debug settings in Laras)
//! - On-demand "Clean OverlayFS Now" button in Laras Debug Options & `pasang overlay clean`

use std::fs;
use std::path::{Path, PathBuf};

use crate::slot::json_escape;

pub const DEFAULT_OVERLAY_ROOT: &str = "/mnt/scratch/overlay";
pub const DEFAULT_PROC_MOUNTS: &str = "/proc/mounts";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionOverlayInfo {
    pub partition: String,
    pub mounted: bool,
    pub file_count: u64,
    pub total_bytes: u64,
    pub upper_path: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct OverlayStatus {
    pub overlay_active: bool,
    pub scratch_mounted: bool,
    pub total_files: u64,
    pub total_bytes: u64,
    pub partitions: Vec<PartitionOverlayInfo>,
}

impl OverlayStatus {
    pub fn to_json(&self) -> String {
        let mut s = String::from("{");
        s.push_str(&format!("\"overlay_active\":{},", self.overlay_active));
        s.push_str(&format!("\"scratch_mounted\":{},", self.scratch_mounted));
        s.push_str(&format!("\"total_files\":{},", self.total_files));
        s.push_str(&format!("\"total_bytes\":{},", self.total_bytes));
        s.push_str("\"partitions\":[");
        for (i, p) in self.partitions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!(
                "{{\"partition\":\"{}\",\"mounted\":{},\"file_count\":{},\"total_bytes\":{}}}",
                json_escape(&p.partition),
                p.mounted,
                p.file_count,
                p.total_bytes
            ));
        }
        s.push_str("]}");
        s
    }
}

#[derive(Debug, Clone, Default)]
pub struct OverlayCleanReport {
    pub cleaned_partitions: Vec<String>,
    pub removed_entries: u64,
    pub freed_bytes: u64,
    pub errors: Vec<String>,
}

impl OverlayCleanReport {
    pub fn to_json(&self) -> String {
        let mut s = String::from("{");
        s.push_str(&format!("\"removed_entries\":{},", self.removed_entries));
        s.push_str(&format!("\"freed_bytes\":{},", self.freed_bytes));
        s.push_str("\"cleaned_partitions\":[");
        for (i, p) in self.cleaned_partitions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("\"{}\"", json_escape(p)));
        }
        s.push_str("],\"errors\":[");
        for (i, e) in self.errors.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("\"{}\"", json_escape(e)));
        }
        s.push_str("]}");
        s
    }
}

fn count_dir_recursive(dir: &Path) -> (u64, u64) {
    let Ok(rd) = fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut files = 0u64;
    let mut bytes = 0u64;
    for entry in rd.flatten() {
        let p = entry.path();
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_dir() {
            let (cf, cb) = count_dir_recursive(&p);
            files += cf;
            bytes += cb;
        } else {
            files += 1;
            bytes += meta.len();
        }
    }
    (files, bytes)
}

/// Inspect active overlayfs mounts from `proc_mounts_path` and count overlaid files under
/// `overlay_root/<part>/upper`.
pub fn inspect_overlays(proc_mounts_path: &Path, overlay_root: &Path) -> OverlayStatus {
    let mounts_txt = fs::read_to_string(proc_mounts_path).unwrap_or_default();
    let mut mounted_parts = Vec::new();
    let mut scratch_mounted = false;

    for line in mounts_txt.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        let target = cols[1];
        let fstype = cols[2];
        if target == "/mnt/scratch" {
            scratch_mounted = true;
        }
        if fstype == "overlay" {
            let name = target.trim_start_matches('/');
            if !name.is_empty() && !name.contains('/') {
                mounted_parts.push(name.to_string());
            }
        }
    }

    let mut seen = Vec::new();
    let mut partitions = Vec::new();

    if let Ok(rd) = fs::read_dir(overlay_root) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let part = entry.file_name().to_string_lossy().into_owned();
            let upper = p.join("upper");
            let (fc, tb) = if upper.is_dir() {
                count_dir_recursive(&upper)
            } else {
                (0, 0)
            };
            let mounted = mounted_parts.iter().any(|m| m == &part);
            seen.push(part.clone());
            partitions.push(PartitionOverlayInfo {
                partition: part,
                mounted,
                file_count: fc,
                total_bytes: tb,
                upper_path: upper,
            });
        }
    }

    for mp in mounted_parts {
        if !seen.iter().any(|s| s == &mp) {
            let upper = overlay_root.join(&mp).join("upper");
            partitions.push(PartitionOverlayInfo {
                partition: mp,
                mounted: true,
                file_count: 0,
                total_bytes: 0,
                upper_path: upper,
            });
        }
    }

    partitions.sort_by(|a, b| a.partition.cmp(&b.partition));
    let total_files = partitions.iter().map(|p| p.file_count).sum();
    let total_bytes = partitions.iter().map(|p| p.total_bytes).sum();
    let overlay_active = partitions.iter().any(|p| p.mounted || p.file_count > 0);

    OverlayStatus {
        overlay_active,
        scratch_mounted,
        total_files,
        total_bytes,
        partitions,
    }
}

fn clear_dir_contents(dir: &Path) -> Result<(u64, u64), String> {
    if !dir.is_dir() {
        return Ok((0, 0));
    }
    let mut removed = 0u64;
    let mut freed = 0u64;
    let rd = fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let p = entry.path();
        let meta = fs::symlink_metadata(&p)
            .map_err(|e| format!("lstat {}: {e}", p.display()))?;
        if meta.file_type().is_dir() {
            let (cf, cb) = count_dir_recursive(&p);
            fs::remove_dir_all(&p).map_err(|e| format!("rmdir {}: {e}", p.display()))?;
            removed += cf.max(1);
            freed += cb;
        } else {
            let sz = meta.len();
            fs::remove_file(&p).map_err(|e| format!("unlink {}: {e}", p.display()))?;
            removed += 1;
            freed += sz;
        }
    }
    Ok((removed, freed))
}

/// Safely wipe all overlaid upperdir + workdir entries under `overlay_root` (either for
/// specific partition names or every partition directory present). Never removes the
/// `overlay_root` or `<part>/upper` directories themselves so active mounts stay consistent
/// until reboot into the new slot.
pub fn clean_overlays(
    overlay_root: &Path,
    only_partitions: Option<&[String]>,
) -> OverlayCleanReport {
    let mut report = OverlayCleanReport::default();
    let Ok(rd) = fs::read_dir(overlay_root) else {
        return report;
    };

    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let part = entry.file_name().to_string_lossy().into_owned();
        if let Some(filter) = only_partitions {
            if !filter.iter().any(|x| x == &part) {
                continue;
            }
        }
        let upper = p.join("upper");
        let work = p.join("work");
        let mut touched = false;
        match clear_dir_contents(&upper) {
            Ok((r, b)) => {
                if r > 0 {
                    touched = true;
                }
                report.removed_entries += r;
                report.freed_bytes += b;
            }
            Err(e) => report.errors.push(format!("{part}/upper: {e}")),
        }
        if work.is_dir() {
            if let Err(e) = clear_dir_contents(&work) {
                report.errors.push(format!("{part}/work: {e}"));
            }
        }
        if touched {
            report.cleaned_partitions.push(part);
        }
    }
    report.cleaned_partitions.sort();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlay_inspect_and_clean() {
        let root = std::env::temp_dir().join(format!("pasang-ovl-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mounts = root.join("mounts");
        let ovl = root.join("overlay");
        fs::create_dir_all(ovl.join("system_ext/upper/priv-app/Laras")).unwrap();
        fs::create_dir_all(ovl.join("vendor/upper/etc")).unwrap();
        fs::create_dir_all(ovl.join("vendor/work/work")).unwrap();
        fs::write(ovl.join("system_ext/upper/priv-app/Laras/Laras.apk"), vec![1u8; 4096]).unwrap();
        fs::write(ovl.join("vendor/upper/etc/test.conf"), b"abc").unwrap();
        fs::write(
            &mounts,
            "/dev/block/dm-9 /mnt/scratch f2fs rw 0 0\noverlay /system_ext overlay rw,lowerdir=/system_ext 0 0\n",
        )
        .unwrap();

        let st = inspect_overlays(&mounts, &ovl);
        assert!(st.overlay_active);
        assert!(st.scratch_mounted);
        assert_eq!(st.total_files, 2);
        assert_eq!(st.total_bytes, 4099);

        let rep = clean_overlays(&ovl, None);
        assert_eq!(rep.removed_entries, 2);
        assert_eq!(rep.freed_bytes, 4099);
        assert_eq!(rep.cleaned_partitions, vec!["system_ext", "vendor"]);
        assert!(rep.errors.is_empty());

        let st2 = inspect_overlays(&mounts, &ovl);
        assert_eq!(st2.total_files, 0);
        assert_eq!(st2.total_bytes, 0);
        let _ = fs::remove_dir_all(&root);
    }
}
