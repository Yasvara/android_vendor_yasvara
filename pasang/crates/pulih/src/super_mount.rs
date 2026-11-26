// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust Dynamic `super` Read-Only `dm-linear` Mapper & `modules.dep` Kernel
//! Module Dependency Loader for `Pulih` Recovery.
//!
//! Uses `pasang_core::lp` (SHA-256 verified AOSP `liblp` v10.0/v10.2 parser) +
//! Linux `/dev/device-mapper` (`DM_READONLY_FLAG`) to mount `vendor_dlkm_<slot>`,
//! `vendor_<slot>`, and `system_dlkm_<slot>` read-only on demand with **0 bytes
//! added to `recovery.img`**, enabling real Adreno GPU (`msm_kgsl.ko`), Vulkan/DOOM,
//! and Wi-Fi 7 (`qca_cld3_wcn7750.ko`) straight from the installed Android ROM!

use pasang_core::lp::{
    parse_geometry, parse_slot_metadata, LpMetadata, LP_SECTOR_SIZE, LP_TARGET_TYPE_LINEAR,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PulihDmExtent {
    pub logical_sector: u64,
    pub num_sectors: u64,
    pub physical_sector: u64,
    pub target_type: u32,
}

#[cfg(target_os = "android")]
extern "C" {
    fn pulih_dm_map_ro(
        dm_name: *const std::ffi::c_char,
        super_path: *const std::ffi::c_char,
        extents: *const PulihDmExtent,
        num_extents: u32,
    ) -> i32;
    fn pulih_dm_remove(dm_name: *const std::ffi::c_char) -> i32;
}

const SUPER_CANDIDATES: &[&str] = &[
    "/dev/block/by-name/super",
    "/dev/block/bootdevice/by-name/super",
];

/// Detect active A/B slot suffix (`"_a"` or `"_b"`) from `/proc/cmdline`.
pub fn detect_active_slot_suffix() -> String {
    if let Ok(cmd) = fs::read_to_string("/proc/cmdline") {
        if let Some(tok) = cmd
            .split_whitespace()
            .find(|t| t.starts_with("androidboot.slot_suffix="))
        {
            let s = tok.trim_start_matches("androidboot.slot_suffix=");
            if s == "_a" || s == "_b" {
                return s.to_string();
            }
        }
    }
    "_a".to_string()
}

/// Read and parse verified `LpMetadata` from `/dev/block/by-name/super`.
pub fn load_super_metadata(active_slot_suffix: &str) -> Result<(String, LpMetadata), String> {
    let super_path = SUPER_CANDIDATES
        .iter()
        .find(|p| Path::new(p).exists())
        .copied()
        .ok_or_else(|| "super block device not found".to_string())?;

    let mut f = fs::File::open(super_path)
        .map_err(|e| format!("open {super_path} failed: {e}"))?;
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MiB covers geometry + primary & backup slots
    let mut total = 0usize;
    while total < buf.len() {
        match f.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => return Err(format!("read {super_path} failed: {e}")),
        }
    }
    buf.truncate(total);

    let geom = parse_geometry(&buf)?;
    let slot_idx: u32 = if active_slot_suffix.ends_with('b') { 1 } else { 0 };
    let meta = parse_slot_metadata(&buf, &geom, slot_idx)
        .or_else(|_| parse_slot_metadata(&buf, &geom, 0))?;
    Ok((super_path.to_string(), meta))
}

/// Compute real unallocated space on `super` in GiB from verified LP metadata.
pub fn read_super_free_gib(active_slot_suffix: &str) -> Option<f32> {
    let (_, meta) = load_super_metadata(active_slot_suffix).ok()?;
    let total_bytes = meta.super_size_bytes();
    if total_bytes == 0 {
        return None;
    }
    let used_sectors: u64 = meta
        .extents
        .iter()
        .filter(|e| e.target_type == LP_TARGET_TYPE_LINEAR)
        .map(|e| e.num_sectors)
        .sum();
    let used_bytes = used_sectors.saturating_mul(LP_SECTOR_SIZE);
    let free_bytes = total_bytes.saturating_sub(used_bytes);
    Some(free_bytes as f32 / (1024.0 * 1024.0 * 1024.0))
}

/// Map a dynamic partition (e.g. `"vendor_dlkm_a"`, `"vendor_a"`, `"system_dlkm_a"`)
/// read-only via Linux `dm-linear` -> `/dev/block/mapper/<part_name>`.
pub fn map_super_partition_ro(part_name: &str, active_slot_suffix: &str) -> Result<PathBuf, String> {
    let mapper_node = PathBuf::from(format!("/dev/block/mapper/{part_name}"));
    if mapper_node.exists() {
        return Ok(mapper_node);
    }

    let (super_path, meta) = load_super_metadata(active_slot_suffix)?;
    let part = meta
        .partitions
        .iter()
        .find(|p| p.name == part_name)
        .ok_or_else(|| format!("partition '{part_name}' not found in super LP metadata"))?;
    let lp_extents = meta.partition_extents(part);
    if lp_extents.is_empty() {
        return Err(format!("partition '{part_name}' has 0 extents in super"));
    }

    let mut dm_extents = Vec::with_capacity(lp_extents.len());
    let mut logical = 0u64;
    for e in lp_extents {
        dm_extents.push(PulihDmExtent {
            logical_sector: logical,
            num_sectors: e.num_sectors,
            physical_sector: e.target_data,
            target_type: if e.target_type == LP_TARGET_TYPE_LINEAR { 0 } else { 1 },
        });
        logical += e.num_sectors;
    }

    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;
        let cname = CString::new(part_name).map_err(|_| "invalid dm name")?;
        let csuper = CString::new(super_path.as_str()).map_err(|_| "invalid super path")?;
        let rc = unsafe {
            pulih_dm_map_ro(
                cname.as_ptr(),
                csuper.as_ptr(),
                dm_extents.as_ptr(),
                dm_extents.len() as u32,
            )
        };
        if rc != 0 {
            return Err(format!("dm-linear map '{part_name}' failed (errno={rc})"));
        }
        Ok(mapper_node)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (super_path, dm_extents);
        Err("dm-linear requires Android kernel".into())
    }
}

/// Remove a read-only `dm-linear` device cleanly after unmounting.
pub fn remove_dm_device(part_name: &str) {
    #[cfg(target_os = "android")]
    if let Ok(cname) = std::ffi::CString::new(part_name) {
        unsafe {
            let _ = pulih_dm_remove(cname.as_ptr());
        }
    }
    #[cfg(not(target_os = "android"))]
    let _ = part_name;
}

/// Check if `mountpoint` is already mounted according to `/proc/mounts`.
pub fn is_mounted(mountpoint: &str) -> bool {
    fs::read_to_string("/proc/mounts")
        .map(|s| {
            s.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|mp| mp == mountpoint)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Map and mount a dynamic partition (e.g. `part_base = "vendor_dlkm"`, `slot = "_a"`)
/// read-only at `mountpoint`. Returns `Ok(true)` if freshly mounted by this call,
/// or `Ok(false)` if already mounted.
pub fn mount_super_ro(
    part_base: &str,
    active_slot_suffix: &str,
    mountpoint: &str,
) -> Result<bool, String> {
    if is_mounted(mountpoint) {
        return Ok(false);
    }
    let full_name = format!("{part_base}{active_slot_suffix}");
    let dev = map_super_partition_ro(&full_name, active_slot_suffix)
        .or_else(|_| map_super_partition_ro(part_base, active_slot_suffix))?;
    let _ = fs::create_dir_all(mountpoint);
    let dev_s = dev.to_string_lossy().to_string();
    for fst in ["erofs", "ext4"] {
        if Command::new("/system/bin/mount")
            .args(["-t", fst, "-o", "ro", &dev_s, mountpoint])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Err(format!("mount -o ro {dev_s} -> {mountpoint} failed (erofs/ext4)"))
}

/// Normalize a Linux kernel module name (`foo-bar.ko` / `/path/foo-bar.ko` -> `"foo_bar"`).
pub fn normalize_mod_name(raw: &str) -> String {
    let base = Path::new(raw)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| raw.to_string());
    base.strip_suffix(".ko")
        .unwrap_or(&base)
        .replace('-', "_")
}

/// Read currently loaded kernel module names from `/proc/modules`.
pub fn read_loaded_modules() -> HashSet<String> {
    fs::read_to_string("/proc/modules")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(normalize_mod_name)
        .collect()
}

/// Parse `modules.dep` into a map: `normalized_mod_name -> (module_path, Vec<dep_paths>)`.
pub fn parse_modules_dep(content: &str) -> HashMap<String, (String, Vec<String>)> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = trimmed.split_once(':') else {
            continue;
        };
        let target = lhs.trim().to_string();
        let deps: Vec<String> = rhs.split_whitespace().map(|s| s.to_string()).collect();
        map.insert(normalize_mod_name(&target), (target, deps));
    }
    map
}

/// Compute exact topological load order (dependencies FIRST, target LAST) for `target_mod`,
/// skipping any module already present in `already_loaded`.
pub fn resolve_load_order(
    dep_map: &HashMap<String, (String, Vec<String>)>,
    already_loaded: &HashSet<String>,
    target_mod: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    fn dfs(
        key: &str,
        dep_map: &HashMap<String, (String, Vec<String>)>,
        already_loaded: &HashSet<String>,
        visited: &mut HashSet<String>,
        out: &mut Vec<String>,
    ) {
        if already_loaded.contains(key) || !visited.insert(key.to_string()) {
            return;
        }
        if let Some((path, deps)) = dep_map.get(key) {
            // In modules.dep, dependencies are listed left-to-right (direct -> deeper);
            // visiting deeper deps first ensures bottom-up insmod order!
            for d in deps.iter().rev() {
                let dk = normalize_mod_name(d);
                if dep_map.contains_key(&dk) {
                    dfs(&dk, dep_map, already_loaded, visited, out);
                } else if !already_loaded.contains(&dk) && visited.insert(dk) {
                    out.push(d.clone());
                }
            }
            out.push(path.clone());
        }
    }
    dfs(&normalize_mod_name(target_mod), dep_map, already_loaded, &mut visited, &mut out);
    out
}

/// Resolve all missing dependencies from `modules.dep` across `mod_dirs` and `insmod`
/// them in dependency order, finally loading `target_ko`.
pub fn load_module_with_deps(target_ko: &str, mod_dirs: &[&Path]) -> Result<(), String> {
    let loaded = read_loaded_modules();
    let target_key = normalize_mod_name(target_ko);
    if loaded.contains(&target_key) {
        return Ok(());
    }

    // Merge all available modules.dep tables
    let mut dep_map = HashMap::new();
    for dir in mod_dirs {
        if let Ok(txt) = fs::read_to_string(dir.join("modules.dep")) {
            for (k, v) in parse_modules_dep(&txt) {
                dep_map.entry(k).or_insert(v);
            }
        }
    }

    let order = if dep_map.contains_key(&target_key) {
        resolve_load_order(&dep_map, &loaded, target_ko)
    } else {
        // Direct fallback when modules.dep lacks entry
        let mut v = Vec::new();
        for dir in mod_dirs {
            let p = dir.join(target_ko);
            if p.exists() {
                v.push(p.to_string_lossy().to_string());
                break;
            }
        }
        v
    };

    if order.is_empty() {
        return Err(format!("{target_ko} not found in mounted module directories"));
    }

    let mut current_loaded = loaded;
    for raw_path in order {
        let key = normalize_mod_name(&raw_path);
        if current_loaded.contains(&key) {
            continue;
        }
        // Resolve path: absolute path first, else look up basename across mod_dirs
        let mut resolved = PathBuf::from(&raw_path);
        if !resolved.exists() {
            if let Some(fname) = Path::new(&raw_path).file_name() {
                for dir in mod_dirs {
                    let cand = dir.join(fname);
                    if cand.exists() {
                        resolved = cand;
                        break;
                    }
                }
            }
        }
        if !resolved.exists() {
            if key == target_key {
                return Err(format!("target module missing: {}", resolved.display()));
            }
            continue;
        }

        let output = Command::new("/system/bin/insmod")
            .arg(&resolved)
            .output()
            .map_err(|e| format!("insmod {} exec failed: {e}", resolved.display()))?;
        if output.status.success() {
            current_loaded.insert(key);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            // Ignore EEXIST ("File exists") if built-in or already loaded under alias
            if !stderr.contains("File exists") && key == target_key {
                return Err(format!(
                    "insmod {} failed: {}",
                    resolved.display(),
                    if stderr.is_empty() {
                        format!("exit {:?}", output.status.code())
                    } else {
                        stderr
                    }
                ));
            }
        }
    }
    Ok(())
}

/// Symlink matching firmware files/directories from `src_dir` into `/lib/firmware`
/// so kernel Direct Firmware Loader finds Adreno GMU/SQE/AQE & WCN7750 firmware.
pub fn expose_firmware_by_prefix(src_dir: &Path, prefixes: &[&str]) -> usize {
    let mut linked = 0usize;
    let Ok(rd) = fs::read_dir(src_dir) else {
        return 0;
    };
    let _ = fs::create_dir_all("/lib/firmware");
    for ent in rd.flatten() {
        let p = ent.path();
        let Some(name) = p.file_name() else {
            continue;
        };
        let ns = name.to_string_lossy().to_ascii_lowercase();
        if prefixes.iter().any(|pref| ns.contains(pref)) {
            let dst = Path::new("/lib/firmware").join(name);
            if !dst.exists() && std::os::unix::fs::symlink(&p, &dst).is_ok() {
                linked += 1;
            }
        }
    }
    linked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_onyx_msm_kgsl_and_wcn7750_modules_dep_order() {
        let dep_txt = "\
/vendor_dlkm/lib/modules/msm_kgsl.ko: /vendor_dlkm/lib/modules/msm_performance.ko /vendor_dlkm/lib/modules/sched-walt.ko /vendor_dlkm/lib/modules/ipclite.ko /vendor_dlkm/lib/modules/msm_hw_fence.ko
/vendor_dlkm/lib/modules/msm_performance.ko: /vendor_dlkm/lib/modules/sched-walt.ko
/vendor_dlkm/lib/modules/ipclite.ko:
/vendor_dlkm/lib/modules/qca_cld3_wcn7750.ko: /vendor_dlkm/lib/modules/icnss2.ko /system_dlkm/lib/modules/rfkill.ko
/vendor_dlkm/lib/modules/icnss2.ko: /vendor_dlkm/lib/modules/cnss_prealloc.ko
/vendor_dlkm/lib/modules/cnss_prealloc.ko:
";
        let map = parse_modules_dep(dep_txt);
        let mut already = HashSet::new();
        already.insert("sched_walt".into());
        already.insert("msm_hw_fence".into());

        let kgsl_order = resolve_load_order(&map, &already, "msm_kgsl.ko");
        // sched-walt & msm_hw_fence already loaded -> skipped; ipclite & msm_performance BEFORE msm_kgsl!
        assert!(!kgsl_order.iter().any(|p| p.contains("sched-walt")));
        assert!(!kgsl_order.iter().any(|p| p.contains("msm_hw_fence")));
        let idx_perf = kgsl_order.iter().position(|p| p.contains("msm_performance")).unwrap();
        let idx_ipc = kgsl_order.iter().position(|p| p.contains("ipclite")).unwrap();
        let idx_kgsl = kgsl_order.iter().position(|p| p.contains("msm_kgsl")).unwrap();
        assert!(idx_perf < idx_kgsl);
        assert!(idx_ipc < idx_kgsl);

        let wifi_order = resolve_load_order(&map, &already, "qca_cld3_wcn7750.ko");
        let idx_pre = wifi_order.iter().position(|p| p.contains("cnss_prealloc")).unwrap();
        let idx_icnss = wifi_order.iter().position(|p| p.contains("icnss2")).unwrap();
        let idx_rfkill = wifi_order.iter().position(|p| p.contains("rfkill")).unwrap();
        let idx_wlan = wifi_order.iter().position(|p| p.contains("qca_cld3_wcn7750")).unwrap();
        assert!(idx_pre < idx_icnss);
        assert!(idx_icnss < idx_wlan);
        assert!(idx_rfkill < idx_wlan);
    }
}
