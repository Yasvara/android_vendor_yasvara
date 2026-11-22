// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Padat compression, decompression, release, scanner, 6-bucket accounting, and parallel engine.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::ioctl::{
    self, F2fsCompOptionV2, FS_COMPR_FL, FS_IMMUTABLE_FL, FS_NOCOMP_FL, FS_VERITY_FL,
};
use crate::policy::{escape_json, CompAlgo, CompProfile, Policy, Scopes};
use crate::probe::{self, ProbeVerdict, BLOCKED_DIR_SEGMENTS};

const COPY_BUF_SIZE: usize = 1024 * 1024; // 1 MB sequential I/O chunks
const SMALL_FILE_FAST_MAX: u64 = 256 * 1024; // <= 256 KB: single read -> in-memory probe -> write
const ASYNC_FLUSH_THRESHOLD: u64 = 8 * 1024 * 1024; // >= 8 MB: overlap writeback every 4 MB
const ASYNC_FLUSH_WINDOW: u64 = 4 * 1024 * 1024;
// Linux arch-specific open(2) flags (arch/arm64/include/uapi/asm/fcntl.h vs asm-generic/fcntl.h).
// NOTE: On ARM/AArch64, 0o00200000 is O_DIRECT and 0o00400000 is O_LARGEFILE! Passing x86_64
// constants on AArch64 caused every directory open(O_DIRECTORY) to fail with EINVAL.
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
const O_DIRECTORY: i32 = 0o00040000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
const O_DIRECTORY: i32 = 0o00200000;

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
const O_NOFOLLOW: i32 = 0o00100000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
const O_NOFOLLOW: i32 = 0o00400000;
const TEMP_CHECK_INTERVAL_MS: u64 = 2000;

static MONO_EPOCH: OnceLock<Instant> = OnceLock::new();
static THERMAL_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
static LAST_TEMP_CHECK_MS: AtomicU64 = AtomicU64::new(0);
static CACHED_TEMP_MC: AtomicI32 = AtomicI32::new(0);
static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn mono_ms() -> u64 {
    let start = MONO_EPOCH.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

#[derive(Debug, Clone)]
pub struct RootPaths {
    pub data_app: PathBuf,
    pub ext_data: PathBuf,
    pub ext_obb: PathBuf,
    pub user_data: PathBuf,
    pub user_de_data: PathBuf,
    pub packages_list: PathBuf,
}

impl Default for RootPaths {
    fn default() -> Self {
        Self {
            data_app: PathBuf::from("/data/app"),
            ext_data: PathBuf::from("/data/media/0/Android/data"),
            ext_obb: PathBuf::from("/data/media/0/Android/obb"),
            user_data: PathBuf::from("/data/user/0"),
            user_de_data: PathBuf::from("/data/user_de/0"),
            packages_list: PathBuf::from("/data/system/packages.list"),
        }
    }
}

/// Real-time lock-free progress telemetry for an active job, exposed via `status_json()`.
pub struct JobProgress {
    pub busy: AtomicBool,
    pub start_ms: AtomicU64,
    pub total_files: AtomicU64,
    pub done_files: AtomicU64,
    pub compressed_files: AtomicU64,
    pub skipped_files: AtomicU64,
    pub error_files: AtomicU64,
    pub total_bytes: AtomicU64,
    pub done_bytes: AtomicU64,
    pub saved_bytes: AtomicI64,
    pub active_package: Mutex<String>,
    pub active_action: Mutex<String>,
    pub current_file: Mutex<String>,
    pub pause_reason: Mutex<String>,
}

impl JobProgress {
    pub const fn new() -> Self {
        Self {
            busy: AtomicBool::new(false),
            start_ms: AtomicU64::new(0),
            total_files: AtomicU64::new(0),
            done_files: AtomicU64::new(0),
            compressed_files: AtomicU64::new(0),
            skipped_files: AtomicU64::new(0),
            error_files: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            done_bytes: AtomicU64::new(0),
            saved_bytes: AtomicI64::new(0),
            active_package: Mutex::new(String::new()),
            active_action: Mutex::new(String::new()),
            current_file: Mutex::new(String::new()),
            pause_reason: Mutex::new(String::new()),
        }
    }

    pub fn begin(&self, pkg: &str, action: &str) {
        self.start_ms.store(mono_ms(), Ordering::SeqCst);
        self.total_files.store(0, Ordering::SeqCst);
        self.done_files.store(0, Ordering::SeqCst);
        self.compressed_files.store(0, Ordering::SeqCst);
        self.skipped_files.store(0, Ordering::SeqCst);
        self.error_files.store(0, Ordering::SeqCst);
        self.total_bytes.store(0, Ordering::SeqCst);
        self.done_bytes.store(0, Ordering::SeqCst);
        self.saved_bytes.store(0, Ordering::SeqCst);
        if let Ok(mut g) = self.active_package.lock() {
            *g = pkg.to_string();
        }
        if let Ok(mut g) = self.active_action.lock() {
            *g = action.to_string();
        }
        if let Ok(mut g) = self.current_file.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.pause_reason.lock() {
            g.clear();
        }
        self.busy.store(true, Ordering::SeqCst);
    }

    pub fn end(&self) {
        self.busy.store(false, Ordering::SeqCst);
        if let Ok(mut g) = self.active_package.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.active_action.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.current_file.lock() {
            g.clear();
        }
        if let Ok(mut g) = self.pause_reason.lock() {
            g.clear();
        }
    }

    pub fn set_current_file(&self, path: &Path) {
        if let Ok(mut g) = self.current_file.try_lock() {
            *g = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
        }
    }

    pub fn set_pause_reason(&self, reason: &str) {
        if let Ok(mut g) = self.pause_reason.try_lock() {
            if g.as_str() != reason {
                *g = reason.to_string();
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ScopeBucket {
    pub logical_bytes: u64,
    pub physical_bytes: u64,
    pub compressed_files: u64,
    pub total_files: u64,
}

impl ScopeBucket {
    pub fn saved_bytes(&self) -> u64 {
        self.logical_bytes.saturating_sub(self.physical_bytes)
    }

    #[inline]
    fn add_uncompressed(&mut self, logical_raw: u64, physical: u64) {
        self.total_files += 1;
        // Count actual allocated disk space (falling back to logical_raw for F2FS inline files
        // with st_blocks == 0), guaranteeing physical <= logical and zero false sparse-file savings.
        let disk = if physical > 0 { physical } else { logical_raw };
        self.logical_bytes += disk;
        self.physical_bytes += disk;
    }

    #[inline]
    fn add_compressed(&mut self, uncomp_disk: u64, physical: u64) {
        self.total_files += 1;
        self.logical_bytes += uncomp_disk.max(physical);
        self.physical_bytes += physical;
        self.compressed_files += 1;
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"logical_bytes\":{},\"physical_bytes\":{},\"saved_bytes\":{},\"compressed_files\":{},\"total_files\":{}}}",
            self.logical_bytes,
            self.physical_bytes,
            self.saved_bytes(),
            self.compressed_files,
            self.total_files,
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PackageBreakdown {
    pub apk_lib: ScopeBucket,
    pub art_oat: ScopeBucket,
    pub external_data: ScopeBucket,
    pub obb: ScopeBucket,
    pub internal_files: ScopeBucket,
    pub cache_other: ScopeBucket,
}

impl PackageBreakdown {
    pub fn total_logical(&self) -> u64 {
        self.apk_lib.logical_bytes
            + self.art_oat.logical_bytes
            + self.external_data.logical_bytes
            + self.obb.logical_bytes
            + self.internal_files.logical_bytes
            + self.cache_other.logical_bytes
    }

    pub fn total_physical(&self) -> u64 {
        self.apk_lib.physical_bytes
            + self.art_oat.physical_bytes
            + self.external_data.physical_bytes
            + self.obb.physical_bytes
            + self.internal_files.physical_bytes
            + self.cache_other.physical_bytes
    }

    pub fn total_saved(&self) -> u64 {
        self.apk_lib.saved_bytes()
            + self.art_oat.saved_bytes()
            + self.external_data.saved_bytes()
            + self.obb.saved_bytes()
            + self.internal_files.saved_bytes()
            + self.cache_other.saved_bytes()
    }

    pub fn total_compressed_files(&self) -> u64 {
        self.apk_lib.compressed_files
            + self.art_oat.compressed_files
            + self.external_data.compressed_files
            + self.obb.compressed_files
            + self.internal_files.compressed_files
            + self.cache_other.compressed_files
    }

    pub fn total_files(&self) -> u64 {
        self.apk_lib.total_files
            + self.art_oat.total_files
            + self.external_data.total_files
            + self.obb.total_files
            + self.internal_files.total_files
            + self.cache_other.total_files
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"apk_lib\":{},\"art_oat\":{},\"external_data\":{},\"obb\":{},\"internal_files\":{},\"cache_other\":{}}}",
            self.apk_lib.to_json(),
            self.art_oat.to_json(),
            self.external_data.to_json(),
            self.obb.to_json(),
            self.internal_files.to_json(),
            self.cache_other.to_json(),
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct PackageStats {
    pub package: String,
    pub is_running: bool,
    pub logical_bytes: u64,
    pub physical_bytes: u64,
    pub saved_bytes: u64,
    pub compressed_files: u64,
    pub total_files: u64,
    pub skipped_incompressible: u64,
    pub skipped_verity: u64,
    pub skipped_excluded: u64,
    pub candidate_files: u64,
    pub est_extra_savings_bytes: u64,
    pub detected_profile: Option<CompProfile>,
    pub breakdown: PackageBreakdown,
}

impl PackageStats {
    pub fn to_json(&self) -> String {
        let prof_json = match self.detected_profile {
            Some(p) => format!(
                "{{\"algo\":\"{}\",\"level\":{},\"cluster_kb\":{}}}",
                p.algo.as_str(),
                p.level,
                p.cluster_kb
            ),
            None => "null".to_string(),
        };
        format!(
            "{{\"package\":\"{}\",\"is_running\":{},\"logical_bytes\":{},\"physical_bytes\":{},\"saved_bytes\":{},\"compressed_files\":{},\"total_files\":{},\"candidate_files\":{},\"est_extra_savings_bytes\":{},\"skipped_incompressible\":{},\"skipped_verity\":{},\"skipped_excluded\":{},\"detected_profile\":{},\"buckets\":{}}}",
            escape_json(&self.package),
            self.is_running,
            self.logical_bytes,
            self.physical_bytes,
            self.saved_bytes,
            self.compressed_files,
            self.total_files,
            self.candidate_files,
            self.est_extra_savings_bytes,
            self.skipped_incompressible,
            self.skipped_verity,
            self.skipped_excluded,
            prof_json,
            self.breakdown.to_json(),
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct RunReport {
    pub package: String,
    pub action: String,
    pub processed_files: u64,
    pub compressed_files: u64,
    pub decompressed_files: u64,
    pub released_files: u64,
    pub skipped_already_done: u64,
    pub skipped_probe: u64,
    pub skipped_policy: u64,
    pub skipped_verity: u64,
    pub skipped_busy_or_toctou: u64,
    pub errors: u64,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub cancelled: bool,
    pub refused_running: bool,
}

impl RunReport {
    pub fn saved_delta(&self) -> i64 {
        (self.bytes_before as i64) - (self.bytes_after as i64)
    }

    pub fn merge_from(&mut self, other: &RunReport) {
        self.processed_files += other.processed_files;
        self.compressed_files += other.compressed_files;
        self.decompressed_files += other.decompressed_files;
        self.released_files += other.released_files;
        self.skipped_already_done += other.skipped_already_done;
        self.skipped_probe += other.skipped_probe;
        self.skipped_policy += other.skipped_policy;
        self.skipped_verity += other.skipped_verity;
        self.skipped_busy_or_toctou += other.skipped_busy_or_toctou;
        self.errors += other.errors;
        self.bytes_before += other.bytes_before;
        self.bytes_after += other.bytes_after;
        self.cancelled |= other.cancelled;
        self.refused_running |= other.refused_running;
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"package\":\"{}\",\"action\":\"{}\",\"processed_files\":{},\"compressed_files\":{},\"decompressed_files\":{},\"released_files\":{},\"skipped_already_done\":{},\"skipped_probe\":{},\"skipped_policy\":{},\"skipped_verity\":{},\"skipped_busy_or_toctou\":{},\"errors\":{},\"bytes_before\":{},\"bytes_after\":{},\"saved_delta_bytes\":{},\"cancelled\":{},\"refused_running\":{}}}",
            escape_json(&self.package),
            escape_json(&self.action),
            self.processed_files,
            self.compressed_files,
            self.decompressed_files,
            self.released_files,
            self.skipped_already_done,
            self.skipped_probe,
            self.skipped_policy,
            self.skipped_verity,
            self.skipped_busy_or_toctou,
            self.errors,
            self.bytes_before,
            self.bytes_after,
            self.saved_delta(),
            self.cancelled,
            self.refused_running,
        )
    }
}

pub struct RunControl<'a> {
    pub cancel: &'a AtomicBool,
    pub paused: &'a AtomicBool,
    pub allow_running: bool,
    pub thermal_pause_mc: i32,
    pub progress: Option<&'a JobProgress>,
}

/// Reads system/kernel F2FS compression status and live job progress as JSON.
pub fn status_json(paused: bool, progress: &JobProgress) -> String {
    let kernel_support = Path::new("/sys/fs/f2fs/features/compression").exists();
    let features = fs::read_to_string("/dev/sys/fs/by-name/userdata/features")
        .unwrap_or_default()
        .trim()
        .to_string();
    let userdata_support = features.split(',').any(|f| f.trim() == "compression");
    let read_u64 = |name: &str| -> u64 {
        fs::read_to_string(format!("/dev/sys/fs/by-name/userdata/{name}"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    let written = read_u64("compr_written_block");
    let saved = read_u64("compr_saved_block");
    let auto_res = read_u64("compr_auto_reserved");
    let auto_res_en = read_u64("compress_auto_reserve");
    let new_inodes = read_u64("compr_new_inode");
    let cache_pct = read_u64("compress_percent");
    let temp_mc = read_battery_temp_mc().unwrap_or(0);

    let busy = progress.busy.load(Ordering::Relaxed);
    let active_pkg = progress
        .active_package
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let active_action = progress
        .active_action
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let current_file = progress
        .current_file
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    let pause_reason = progress
        .pause_reason
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();

    let total_files = progress.total_files.load(Ordering::Relaxed);
    let done_files = progress.done_files.load(Ordering::Relaxed);
    let compressed_files = progress.compressed_files.load(Ordering::Relaxed);
    let skipped_files = progress.skipped_files.load(Ordering::Relaxed);
    let error_files = progress.error_files.load(Ordering::Relaxed);
    let total_bytes = progress.total_bytes.load(Ordering::Relaxed);
    let done_bytes = progress.done_bytes.load(Ordering::Relaxed);
    let saved_bytes = progress.saved_bytes.load(Ordering::Relaxed);
    let elapsed_ms = if busy {
        mono_ms().saturating_sub(progress.start_ms.load(Ordering::Relaxed))
    } else {
        0
    };
    let speed_bps = if elapsed_ms >= 200 {
        done_bytes.saturating_mul(1000) / elapsed_ms
    } else {
        0
    };

    format!(
        "{{\"kernel_compression\":{},\"userdata_compression\":{},\"compress_auto_reserve\":{},\"compr_written_blocks\":{},\"compr_saved_blocks\":{},\"compr_auto_reserved\":{},\"compr_new_inodes\":{},\"compress_percent\":{},\"battery_temp_mc\":{},\"busy\":{},\"paused\":{},\"pause_reason\":\"{}\",\"active_package\":\"{}\",\"active_action\":\"{}\",\"total_files\":{},\"done_files\":{},\"compressed_files\":{},\"skipped_files\":{},\"error_files\":{},\"total_bytes\":{},\"done_bytes\":{},\"saved_bytes\":{},\"elapsed_ms\":{},\"speed_bps\":{},\"current_file\":\"{}\"}}",
        kernel_support,
        userdata_support,
        auto_res_en != 0,
        written,
        saved,
        auto_res,
        new_inodes,
        cache_pct,
        temp_mc,
        busy,
        paused,
        escape_json(&pause_reason),
        escape_json(&active_pkg),
        escape_json(&active_action),
        total_files,
        done_files,
        compressed_files,
        skipped_files,
        error_files,
        total_bytes,
        done_bytes,
        saved_bytes,
        elapsed_ms,
        speed_bps,
        escape_json(&current_file),
    )
}

fn discover_battery_thermal_path() -> Option<PathBuf> {
    if let Ok(rd) = fs::read_dir("/sys/class/thermal") {
        let mut fallback: Option<PathBuf> = None;
        for ent in rd.flatten() {
            let name = ent.file_name();
            let Some(ns) = name.to_str() else { continue };
            if !ns.starts_with("thermal_zone") {
                continue;
            }
            let z = ent.path();
            let Ok(ty) = fs::read_to_string(z.join("type")) else {
                continue;
            };
            let ty = ty.trim();
            if ty == "battery" {
                return Some(z.join("temp"));
            }
            if ty == "batt_therm" {
                fallback = Some(z.join("temp"));
            }
        }
        if fallback.is_some() {
            return fallback;
        }
    }
    let ps = PathBuf::from("/sys/class/power_supply/battery/temp");
    if ps.exists() {
        return Some(ps);
    }
    None
}

/// Cached battery temperature in millicelsius (discovered once, refreshed at most once every 2s).
pub fn read_battery_temp_mc() -> Option<i32> {
    let now = mono_ms();
    let last = LAST_TEMP_CHECK_MS.load(Ordering::Relaxed);
    if last > 0 && now.saturating_sub(last) < TEMP_CHECK_INTERVAL_MS {
        let v = CACHED_TEMP_MC.load(Ordering::Relaxed);
        return if v > 0 { Some(v) } else { None };
    }
    LAST_TEMP_CHECK_MS.store(now, Ordering::Relaxed);
    let path = THERMAL_PATH.get_or_init(discover_battery_thermal_path).as_ref()?;
    let raw = fs::read_to_string(path).ok()?;
    let v = raw.trim().parse::<i32>().ok()?;
    let mc = if v > 0 && v < 1000 { v * 100 } else { v };
    CACHED_TEMP_MC.store(mc, Ordering::Relaxed);
    Some(mc)
}

/// Looks up a package's UID from `/data/system/packages.list`.
pub fn find_package_uid(roots: &RootPaths, pkg: &str) -> Option<u32> {
    let content = fs::read_to_string(&roots.packages_list).ok()?;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(name), Some(uid_s)) = (parts.next(), parts.next()) {
            if name == pkg {
                return uid_s.parse().ok();
            }
        }
    }
    None
}

/// Checks whether a `/proc/<pid>` process is actively running (foreground, visible, perceptible,
/// or active service — `oom_score_adj <= 500`), ignoring frozen/cached background apps (`>= 900`).
fn is_pid_active_not_cached(pid_str: &str) -> bool {
    match fs::read_to_string(format!("/proc/{pid_str}/oom_score_adj")) {
        Ok(s) => s.trim().parse::<i32>().map(|adj| adj <= 500).unwrap_or(true),
        Err(_) => true,
    }
}

/// Returns true if any active (non-cached) process belonging to `pkg` is alive in `/proc`.
pub fn is_package_running(roots: &RootPaths, pkg: &str) -> bool {
    let target_uid = find_package_uid(roots, pkg);
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return false,
    };
    for ent in entries.flatten() {
        let fname = ent.file_name();
        let pid_str = match fname.to_str() {
            Some(s) if s.bytes().all(|b| b.is_ascii_digit()) => s,
            _ => continue,
        };
        if pid_str.parse::<u32>().unwrap_or(0) < 300 {
            continue;
        }
        if let Some(uid) = target_uid {
            if let Ok(st) = fs::metadata(ent.path()) {
                if st.uid() != uid {
                    continue;
                }
            }
        }
        let cmdline_path = format!("/proc/{pid_str}/cmdline");
        if let Ok(raw) = fs::read(cmdline_path) {
            let proc_name = raw.split(|&b| b == 0).next().unwrap_or(&[]);
            if let Ok(s) = std::str::from_utf8(proc_name) {
                if (s == pkg || s.starts_with(&format!("{pkg}:")))
                    && is_pid_active_not_cached(pid_str)
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Collects all actively running (non-cached, `oom_score_adj <= 500`) app process names in one scan.
pub fn snapshot_running_processes() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for ent in entries.flatten() {
        let fname = ent.file_name();
        let Some(pid_str) = fname.to_str() else { continue };
        if !pid_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if pid_str.parse::<u32>().unwrap_or(0) < 300 {
            continue;
        }
        if let Ok(raw) = fs::read(format!("/proc/{pid_str}/cmdline")) {
            let proc_name = raw.split(|&b| b == 0).next().unwrap_or(&[]);
            if let Ok(s) = std::str::from_utf8(proc_name) {
                if !s.is_empty() && s.contains('.') && is_pid_active_not_cached(pid_str) {
                    out.push(s.to_string());
                }
            }
        }
    }
    out
}

/// Finds `/data/app/~~<rand>/<pkg>-<rand>` code directory for `pkg`.
pub fn find_app_code_dir(roots: &RootPaths, pkg: &str) -> Option<PathBuf> {
    let prefix = format!("{pkg}-");
    let top = fs::read_dir(&roots.data_app).ok()?;
    for ent in top.flatten() {
        let p = ent.path();
        if !p.is_dir() {
            continue;
        }
        let name = ent.file_name();
        if let Some(s) = name.to_str() {
            if s.starts_with(&prefix) || s == pkg {
                return Some(p);
            }
        }
        if let Ok(sub) = fs::read_dir(&p) {
            for sent in sub.flatten() {
                if let Some(s) = sent.file_name().to_str() {
                    if (s.starts_with(&prefix) || s == pkg) && sent.path().is_dir() {
                        return Some(sent.path());
                    }
                }
            }
        }
    }
    None
}

/// Lists all installed third-party / updated packages found under `/data/app`.
pub fn list_installed_packages(roots: &RootPaths) -> Vec<String> {
    let mut pkgs = Vec::new();
    let Ok(top) = fs::read_dir(&roots.data_app) else {
        return pkgs;
    };
    for ent in top.flatten() {
        let p = ent.path();
        if !p.is_dir() {
            continue;
        }
        let Ok(sub) = fs::read_dir(&p) else {
            continue;
        };
        for sent in sub.flatten() {
            if !sent.path().is_dir() {
                continue;
            }
            if let Some(name) = sent.file_name().to_str() {
                if let Some((pkg, _)) = name.split_once('-') {
                    if pkg.contains('.') {
                        pkgs.push(pkg.to_string());
                    }
                }
            }
        }
    }
    pkgs.sort();
    pkgs.dedup();
    pkgs
}

fn is_blocked_dir_name(name: &str) -> bool {
    BLOCKED_DIR_SEGMENTS
        .iter()
        .any(|&b| b.eq_ignore_ascii_case(name))
}

#[derive(Default)]
struct ProfileProbe {
    found: Option<CompProfile>,
}

fn dir_has_compr_flag(dir: &Path) -> bool {
    OpenOptions::new()
        .read(true)
        .open(dir)
        .ok()
        .and_then(|f| ioctl::get_fs_flags(f.as_raw_fd()).ok())
        .map(|fl| (fl & FS_COMPR_FL) != 0)
        .unwrap_or(false)
}

#[inline]
fn record_stat_file(
    bucket: &mut ScopeBucket,
    path: &Path,
    logical_raw: u64,
    physical: u64,
    dir_has_compr: bool,
    probe: Option<&mut ProfileProbe>,
) {
    let Some(pr) = probe else {
        // Excluded bucket (cache/DB/user_de): never open files, zero false savings.
        bucket.add_uncompressed(logical_raw, physical);
        return;
    };
    let uncomp_disk = (logical_raw.saturating_add(4095) / 4096) * 4096;
    // Fast path (~99.5% of files, zero extra syscalls): cannot be F2FS-compressed with saved blocks.
    if logical_raw < 16 * 1024 || physical == 0 || physical + 4096 > uncomp_disk {
        bucket.add_uncompressed(logical_raw, physical);
        return;
    }
    // Directory already tagged FS_COMPR_FL and package profile already known: skip per-file ioctl
    // so 70k-file compressed games stay ~1s total.
    if dir_has_compr && pr.found.is_some() {
        bucket.add_compressed(uncomp_disk, physical);
        return;
    }
    // Verify genuine F2FS compression (filters out sparse uncompressed files like Spotify/AyuGram)
    // and capture real on-disk algorithm/level/cluster size.
    if let Ok(f) = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(path) {
        if let Ok(opt) = ioctl::get_compress_option_v2(f.as_raw_fd()) {
            if pr.found.is_none() {
                pr.found = CompProfile::from_v2_ioctl(opt);
            }
            bucket.add_compressed(uncomp_disk, physical);
            return;
        }
    }
    bucket.add_uncompressed(logical_raw, physical);
}

fn stat_tree_into(dir: &Path, bucket: &mut ScopeBucket, mut probe: Option<&mut ProfileProbe>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let dir_compr = if probe.is_some() {
        dir_has_compr_flag(dir)
    } else {
        false
    };
    for ent in rd.flatten() {
        // Check d_type first (zero extra syscall!) to skip symlinks, FIFOs, and sockets
        // without triggering lstat() or SELinux getattr denials on app_data_file sockets/pipes.
        if let Ok(ft) = ent.file_type() {
            if ft.is_symlink() || (!ft.is_dir() && !ft.is_file()) {
                continue;
            }
            let p = ent.path();
            if ft.is_dir() {
                stat_tree_into(&p, bucket, probe.as_deref_mut());
                continue;
            }
            if let Ok(meta) = fs::symlink_metadata(&p) {
                if meta.is_file() {
                    record_stat_file(
                        bucket,
                        &p,
                        meta.len(),
                        meta.blocks() * 512,
                        dir_compr,
                        probe.as_deref_mut(),
                    );
                }
            }
            continue;
        }
        let p = ent.path();
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            stat_tree_into(&p, bucket, probe.as_deref_mut());
        } else if meta.is_file() {
            record_stat_file(
                bucket,
                &p,
                meta.len(),
                meta.blocks() * 512,
                dir_compr,
                probe.as_deref_mut(),
            );
        }
    }
}

/// Computes complete 6-bucket storage breakdown matching Android Settings App Info,
/// verifying real F2FS compression (zero fake sparse-file savings) and real on-disk profile.
pub fn compute_package_breakdown_with_profile(
    roots: &RootPaths,
    pkg: &str,
) -> (PackageBreakdown, Option<CompProfile>) {
    let mut bd = PackageBreakdown::default();
    let mut probe = ProfileProbe::default();

    // 1. /data/app/... -> apk_lib + art_oat
    if let Some(code_dir) = find_app_code_dir(roots, pkg) {
        let code_compr = dir_has_compr_flag(&code_dir);
        if let Ok(rd) = fs::read_dir(&code_dir) {
            for ent in rd.flatten() {
                let p = ent.path();
                let Ok(meta) = fs::symlink_metadata(&p) else {
                    continue;
                };
                if meta.file_type().is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    if ent.file_name().to_str() == Some("oat") {
                        stat_tree_into(&p, &mut bd.art_oat, Some(&mut probe));
                    } else {
                        stat_tree_into(&p, &mut bd.apk_lib, Some(&mut probe));
                    }
                } else if meta.is_file() {
                    record_stat_file(
                        &mut bd.apk_lib,
                        &p,
                        meta.len(),
                        meta.blocks() * 512,
                        code_compr,
                        Some(&mut probe),
                    );
                }
            }
        }
    }

    // 2. /data/media/0/Android/data/<pkg> -> external_data (non-cache) + cache_other (cache)
    let ext_root = roots.ext_data.join(pkg);
    if let Ok(rd) = fs::read_dir(&ext_root) {
        let ext_compr = dir_has_compr_flag(&ext_root);
        for ent in rd.flatten() {
            let p = ent.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let name = ent.file_name();
            let is_cache = name.to_str().map(is_blocked_dir_name).unwrap_or(false);
            if meta.is_dir() {
                if is_cache {
                    stat_tree_into(&p, &mut bd.cache_other, None);
                } else {
                    stat_tree_into(&p, &mut bd.external_data, Some(&mut probe));
                }
            } else if meta.is_file() {
                record_stat_file(
                    &mut bd.external_data,
                    &p,
                    meta.len(),
                    meta.blocks() * 512,
                    ext_compr,
                    Some(&mut probe),
                );
            }
        }
    }

    // 3. /data/media/0/Android/obb/<pkg> -> obb
    let obb_root = roots.ext_obb.join(pkg);
    if obb_root.is_dir() {
        stat_tree_into(&obb_root, &mut bd.obb, Some(&mut probe));
    }

    // 4. /data/user/0/<pkg> -> internal_files (files & non-blocked subdirs) + cache_other (cache/DB/prefs)
    let user_root = roots.user_data.join(pkg);
    if let Ok(rd) = fs::read_dir(&user_root) {
        for ent in rd.flatten() {
            let p = ent.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let name = ent.file_name();
            let name_str = name.to_str().unwrap_or("");
            if meta.is_dir() {
                if is_blocked_dir_name(name_str) || name_str == "oat" {
                    stat_tree_into(&p, &mut bd.cache_other, None);
                } else {
                    stat_tree_into(&p, &mut bd.internal_files, Some(&mut probe));
                }
            } else if meta.is_file() {
                bd.cache_other.add_uncompressed(meta.len(), meta.blocks() * 512);
            }
        }
    }

    // 5. /data/user_de/0/<pkg> -> cache_other (device-encrypted metadata, excluded for safety)
    let user_de_root = roots.user_de_data.join(pkg);
    if user_de_root.is_dir() {
        stat_tree_into(&user_de_root, &mut bd.cache_other, None);
    }

    (bd, probe.found)
}

pub fn compute_package_breakdown(roots: &RootPaths, pkg: &str) -> PackageBreakdown {
    compute_package_breakdown_with_profile(roots, pkg).0
}

/// Collects target `(files, inherit_dirs)` for the user-selected compressible scopes.
fn collect_scope_files(roots: &RootPaths, pkg: &str, scopes: Scopes) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut files = Vec::new();
    let mut inherit_dirs = Vec::new();

    if let Some(code_dir) = find_app_code_dir(roots, pkg) {
        // Never attempt F2FS ioctls on Incremental FS (incfs) app mounts.
        if !ioctl::is_incfs_path(&code_dir) {
            if scopes.apk_lib {
                collect_apk_lib_files(&code_dir, &mut files, &mut inherit_dirs);
            }
            if scopes.art_oat {
                let oat_dir = code_dir.join("oat");
                if oat_dir.is_dir() {
                    walk_files_and_dirs(&oat_dir, &mut files, &mut inherit_dirs);
                }
            }
        }
    }
    if scopes.external_data {
        let ext_root = roots.ext_data.join(pkg);
        if let Ok(rd) = fs::read_dir(&ext_root) {
            for ent in rd.flatten() {
                let p = ent.path();
                let name = ent.file_name();
                if name.to_str().map(is_blocked_dir_name).unwrap_or(false) {
                    continue;
                }
                if p.is_dir() {
                    walk_files_and_dirs(&p, &mut files, &mut inherit_dirs);
                } else if p.is_file() {
                    files.push(p);
                }
            }
        }
    }
    if scopes.obb {
        let d = roots.ext_obb.join(pkg);
        if d.is_dir() {
            walk_files_and_dirs(&d, &mut files, &mut inherit_dirs);
        }
    }
    if scopes.internal_files {
        let user_root = roots.user_data.join(pkg);
        if let Ok(rd) = fs::read_dir(&user_root) {
            for ent in rd.flatten() {
                let p = ent.path();
                let name = ent.file_name();
                let ns = name.to_str().unwrap_or("");
                if is_blocked_dir_name(ns) || ns == "oat" {
                    continue;
                }
                if p.is_dir() {
                    walk_files_and_dirs(&p, &mut files, &mut inherit_dirs);
                }
            }
        }
    }

    (files, inherit_dirs)
}

fn collect_apk_lib_files(code_dir: &Path, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) {
    if let Ok(rd) = fs::read_dir(code_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if ent.file_name().to_str() == Some("lib") {
                    walk_files_and_dirs(&p, files, dirs);
                }
            } else if meta.is_file() {
                files.push(p);
            }
        }
    }
}

fn walk_files_and_dirs(dir: &Path, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) {
    if let Some(name) = dir.file_name().and_then(|s| s.to_str()) {
        if is_blocked_dir_name(name) {
            return;
        }
    }
    dirs.push(dir.to_path_buf());
    let Ok(rd) = fs::read_dir(dir) else { return };
    for ent in rd.flatten() {
        if let Ok(ft) = ent.file_type() {
            if ft.is_symlink() || (!ft.is_dir() && !ft.is_file()) {
                continue;
            }
            let p = ent.path();
            if ft.is_dir() {
                walk_files_and_dirs(&p, files, dirs);
            } else {
                files.push(p);
            }
            continue;
        }
        let p = ent.path();
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk_files_and_dirs(&p, files, dirs);
        } else if meta.is_file() {
            files.push(p);
        }
    }
}

/// Returns true if `dir` directly contains a SQLite database (by extension, and when
/// `sniff_extensionless_magic` is true, by 16-byte magic on extensionless / `.dat` / `.bin` files).
/// Prevents stamping `FS_COMPR_FL` onto root dirs like `/data/user/0/<pkg>/files` when they hold
/// extensionless SQLite catalogs (e.g. `meta`), without opening 100k+ game asset files under
/// `/data/media/0/Android/data` on every incremental sync.
fn dir_directly_contains_sqlite(dir: &Path, sniff_extensionless_magic: bool) -> bool {
    let Ok(rd) = fs::read_dir(dir) else {
        return false;
    };
    let mut magic = [0u8; 16];
    for ent in rd.flatten() {
        if let Ok(ft) = ent.file_type() {
            if !ft.is_file() {
                continue;
            }
        }
        let fname = ent.file_name();
        let Some(name) = fname.to_str() else {
            continue;
        };
        let low = name.to_ascii_lowercase();
        if low.ends_with(".db")
            || low.ends_with(".db-wal")
            || low.ends_with(".db-journal")
            || low.ends_with("-journal")
            || low.ends_with(".sqlite")
            || low.ends_with(".sqlite3")
            || low.ends_with(".mdb")
        {
            return true;
        }
        if !sniff_extensionless_magic {
            continue;
        }
        // Only open files that could plausibly be an extensionless or generic-extension SQLite DB.
        let maybe_sqlite = match name.rsplit_once('.') {
            None => true,
            Some((stem, _)) if stem.is_empty() => false,
            Some((_, ext)) => matches!(
                ext.to_ascii_lowercase().as_str(),
                "dat" | "bin" | "store" | "catalog" | "idx" | "cache"
            ),
        };
        if !maybe_sqlite {
            continue;
        }
        let p = ent.path();
        if let Ok(mut f) = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&p)
        {
            if f.read(&mut magic).unwrap_or(0) == 16 && probe::is_sqlite_header(&magic) {
                return true;
            }
        }
    }
    false
}

/// Applies `FS_COMPR_FL` + `F2FS_IOC_SET_COMPRESS_OPTION_V2` onto a directory so future files
/// inherit the per-app preset in realtime. Skips dirtying the inode when the
/// directory already carries the exact target profile.
pub fn apply_dir_profile(dir: &Path, profile: CompProfile) -> io::Result<()> {
    let profile = profile.normalized();
    let target = profile.to_v2_ioctl();
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(dir)?;
    let fd = f.as_raw_fd();
    if let Ok(flags) = ioctl::get_fs_flags(fd) {
        if (flags & FS_COMPR_FL) != 0 && (flags & FS_NOCOMP_FL) == 0 {
            if let Ok(cur) = ioctl::get_compress_option_v2(fd) {
                if CompProfile::from_v2_ioctl(cur) == Some(profile) {
                    return Ok(());
                }
            }
        }
    }
    ioctl::set_compr_flag(fd)?;
    ioctl::set_compress_option_v2(fd, target)
}

/// Safe dir profile helper that avoids enabling inheritance on dirs directly holding SQLite DBs.
pub fn apply_dir_profile_safe(dir: &Path, profile: CompProfile) -> io::Result<()> {
    apply_dir_profile_safe_inner(dir, profile, true)
}

fn apply_dir_profile_safe_inner(
    dir: &Path,
    profile: CompProfile,
    sniff_extensionless_magic: bool,
) -> io::Result<()> {
    if dir_directly_contains_sqlite(dir, sniff_extensionless_magic) {
        let _ = clear_dir_profile(dir);
        return Ok(());
    }
    apply_dir_profile(dir, profile)
}

pub fn clear_dir_profile(dir: &Path) -> io::Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(dir)?;
    ioctl::clear_compr_and_nocomp_flags(f.as_raw_fd())
}

/// Fast stat-only summary across a package with complete 6-bucket breakdown (zero file opens/reads).
pub fn stat_package_fast(
    roots: &RootPaths,
    pkg: &str,
    running_procs: Option<&[String]>,
) -> PackageStats {
    let is_running = match running_procs {
        Some(procs) => procs
            .iter()
            .any(|s| s == pkg || s.starts_with(&format!("{pkg}:"))),
        None => is_package_running(roots, pkg),
    };
    let (bd, detected_profile) = compute_package_breakdown_with_profile(roots, pkg);
    PackageStats {
        package: pkg.to_string(),
        is_running,
        logical_bytes: bd.total_logical(),
        physical_bytes: bd.total_physical(),
        saved_bytes: bd.total_saved(),
        compressed_files: bd.total_compressed_files(),
        total_files: bd.total_files(),
        detected_profile,
        breakdown: bd,
        ..Default::default()
    }
}

/// Parallel 4-thread stat-only overview across all installed packages.
pub fn stat_all_packages_parallel(roots: &RootPaths) -> Vec<PackageStats> {
    let pkgs = list_installed_packages(roots);
    if pkgs.is_empty() {
        return Vec::new();
    }
    let running = snapshot_running_processes();
    let n = pkgs.len();
    let results: Vec<Mutex<Option<PackageStats>>> = (0..n).map(|_| Mutex::new(None)).collect();
    let next_idx = AtomicUsize::new(0);
    let (max_workers, _) = ioctl::compute_worker_plan();
    let threads = max_workers.min(n);

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next_idx.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                let st = stat_package_fast(roots, &pkgs[i], Some(&running));
                if let Ok(mut g) = results[i].lock() {
                    *g = Some(st);
                }
            });
        }
    });

    results
        .into_iter()
        .filter_map(|m| m.into_inner().ok().flatten())
        .collect()
}

/// Dry-run Smart Probe scan: computes complete 6-bucket sizes + projected savings on selected scopes.
pub fn scan_package(
    roots: &RootPaths,
    pkg: &str,
    profile: CompProfile,
    scopes: Scopes,
    policy: &Policy,
) -> PackageStats {
    let (bd, detected_profile) = compute_package_breakdown_with_profile(roots, pkg);
    let mut stats = PackageStats {
        package: pkg.to_string(),
        is_running: is_package_running(roots, pkg),
        logical_bytes: bd.total_logical(),
        physical_bytes: bd.total_physical(),
        saved_bytes: bd.total_saved(),
        compressed_files: bd.total_compressed_files(),
        total_files: bd.total_files(),
        detected_profile,
        breakdown: bd,
        ..Default::default()
    };

    let (files, _) = collect_scope_files(roots, pkg, scopes);
    let target_norm = profile.normalized();

    // Parallelize probing across 4 threads so 70k-file games scan rapidly!
    let next_idx = AtomicUsize::new(0);
    let cand = AtomicU64::new(0);
    let est_extra = AtomicU64::new(0);
    let skip_incomp = AtomicU64::new(0);
    let skip_verity = AtomicU64::new(0);
    let skip_excl = AtomicU64::new(0);
    let total = files.len();
    let (max_workers, _) = ioctl::compute_worker_plan();
    let threads = max_workers.min(total.max(1));

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next_idx.fetch_add(1, Ordering::Relaxed);
                if i >= total {
                    break;
                }
                let path = &files[i];
                if probe::is_path_excluded(path) {
                    skip_excl.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Ok(meta) = fs::symlink_metadata(path) else {
                    continue;
                };
                if !meta.is_file() || meta.len() < policy.min_file_bytes || meta.nlink() > 1 {
                    continue;
                }
                let logical = meta.len();
                let physical = meta.blocks() * 512;

                let Ok(f) = File::open(path) else {
                    continue;
                };
                let fd = f.as_raw_fd();
                let flags = ioctl::get_fs_flags(fd).unwrap_or(0);
                if (flags & FS_VERITY_FL) != 0 {
                    skip_verity.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if (flags & FS_COMPR_FL) != 0
                    && physical < logical
                    && ioctl::get_compress_option_v2(fd)
                        .ok()
                        .and_then(CompProfile::from_v2_ioctl)
                        == Some(target_norm)
                {
                    continue;
                }

                match probe::probe_file(path, logical, profile, policy.min_saving_pct) {
                    Ok(ProbeVerdict::Compress(est_pct)) => {
                        cand.fetch_add(1, Ordering::Relaxed);
                        let proj_phys =
                            logical.saturating_mul(100u64.saturating_sub(est_pct as u64)) / 100;
                        est_extra.fetch_add(physical.saturating_sub(proj_phys), Ordering::Relaxed);
                    }
                    Ok(ProbeVerdict::ExcludedPolicy) => {
                        skip_excl.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(ProbeVerdict::Incompressible { .. }) => {
                        skip_incomp.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {}
                }
            });
        }
    });

    stats.candidate_files = cand.load(Ordering::Relaxed);
    stats.est_extra_savings_bytes = est_extra.load(Ordering::Relaxed);
    stats.skipped_incompressible = skip_incomp.load(Ordering::Relaxed);
    stats.skipped_verity = skip_verity.load(Ordering::Relaxed);
    stats.skipped_excluded = skip_excl.load(Ordering::Relaxed);
    stats
}

/// Compresses all eligible files in `pkg` in parallel (dynamic big-core workers, zero per-file
/// fsync checkpoint storms, single-read small-file fast path, kernel `copy_file_range` + async
/// writeback overlap on large files, single `syncfs` at end) with real-time `JobProgress` updates.
pub fn compress_package(
    roots: &RootPaths,
    pkg: &str,
    profile: CompProfile,
    scopes: Scopes,
    policy: &Policy,
    ctl: &RunControl<'_>,
) -> RunReport {
    run_compress_or_sync(roots, pkg, profile, scopes, policy, ctl, false)
}

/// Fast incremental post-update / post-game-session sync:
/// 1. Stamps safe directory inheritance onto any new subdirectories.
/// 2. Reclaims unreleased blocks on newly created or WOF-auto-reserved compressed files.
/// 3. Compresses newly `rename()`d uncompressed files (e.g. game patches moved from `cache/`).
/// 4. Skips already-released & `FS_NOCOMP_FL` files in microseconds, and auto-heals any
///    extensionless SQLite DB that accidentally inherited `FS_COMPR_FL`.
pub fn sync_package_incremental(
    roots: &RootPaths,
    pkg: &str,
    profile: CompProfile,
    scopes: Scopes,
    policy: &Policy,
    ctl: &RunControl<'_>,
) -> RunReport {
    run_compress_or_sync(roots, pkg, profile, scopes, policy, ctl, true)
}

fn run_compress_or_sync(
    roots: &RootPaths,
    pkg: &str,
    profile: CompProfile,
    scopes: Scopes,
    policy: &Policy,
    ctl: &RunControl<'_>,
    incremental_idle: bool,
) -> RunReport {
    let mut rep = RunReport {
        package: pkg.to_string(),
        action: if incremental_idle {
            "sync".into()
        } else {
            "compress".into()
        },
        ..Default::default()
    };

    if !ctl.allow_running && is_package_running(roots, pkg) {
        rep.refused_running = true;
        return rep;
    }

    let profile = profile.normalized();
    let target_opt = profile.to_v2_ioctl();
    let (all_files, inherit_dirs) = collect_scope_files(roots, pkg, scopes);

    // Apply SQLite-safe per-directory inheritance so future realtime downloads/updates inherit it.
    // Only sniff extensionless SQLite magic under `/data/user/` (internal_files); external game
    // asset trees (e.g. 110k files in Android/data) still block `.db`/`.sqlite` by filename with
    // zero extra open()/read() syscalls.
    for (didx, dir) in inherit_dirs.iter().enumerate() {
        if (didx & 31) == 0 && check_cancel_or_pause(ctl) {
            rep.cancelled = true;
            return rep;
        }
        let sniff_magic = dir.starts_with(&roots.user_data);
        let _ = apply_dir_profile_safe_inner(dir, profile, sniff_magic);
    }

    // Fast pre-pass: filter out excluded paths & tiny files (< min_file_bytes) via `lstat` alone,
    // and compute exact `total_files` + `total_bytes` for determinate UI progress!
    let mut work_items: Vec<(PathBuf, u64)> = Vec::with_capacity(all_files.len());
    let mut pre_skipped_policy = 0u64;
    let mut total_bytes = 0u64;
    for (idx, path) in all_files.into_iter().enumerate() {
        if (idx & 511) == 0 && check_cancel_or_pause(ctl) {
            rep.cancelled = true;
            return rep;
        }
        if probe::is_path_excluded(&path) {
            pre_skipped_policy += 1;
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.nlink() > 1 || meta.len() < policy.min_file_bytes {
            pre_skipped_policy += 1;
            continue;
        }
        // In incremental sync mode, files whose physical size is already clearly smaller than
        // logical size are almost certainly already compressed & released; still check them
        // quickly only if physical >= logical (unreleased or newly moved from cache!).
        if incremental_idle && meta.blocks() * 512 + 4096 <= meta.len() {
            rep.skipped_already_done += 1;
            rep.processed_files += 1;
            continue;
        }
        total_bytes += meta.len();
        work_items.push((path, meta.len()));
    }

    // Process largest files first so parallel threads balance cleanly without tail-stragglers!
    work_items.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    rep.processed_files += pre_skipped_policy;
    rep.skipped_policy = pre_skipped_policy;

    if let Some(prog) = ctl.progress {
        prog.total_files
            .store(work_items.len() as u64, Ordering::SeqCst);
        prog.total_bytes.store(total_bytes, Ordering::SeqCst);
    }

    let total_work = work_items.len();
    if total_work == 0 {
        return rep;
    }

    let (max_workers, cpu_mask) = ioctl::compute_worker_plan();
    let worker_cap = if incremental_idle {
        max_workers.min(3)
    } else {
        max_workers
    };
    let next_idx = AtomicUsize::new(0);
    let threads = worker_cap.min(total_work);
    let partial_reports: Vec<Mutex<RunReport>> = (0..threads)
        .map(|_| Mutex::new(RunReport::default()))
        .collect();

    std::thread::scope(|s| {
        for tid in 0..threads {
            let items_ref = &work_items;
            let idx_ref = &next_idx;
            let out_ref = &partial_reports[tid];
            s.spawn(move || {
                ioctl::set_worker_priority(cpu_mask, incremental_idle);
                let mut local = RunReport::default();
                let mut copy_buf = vec![0u8; COPY_BUF_SIZE];

                loop {
                    if check_cancel_or_pause(ctl) {
                        local.cancelled = true;
                        break;
                    }
                    let i = idx_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= items_ref.len() {
                        break;
                    }
                    let (ref path, logical_est) = items_ref[i];
                    if let Some(prog) = ctl.progress {
                        prog.set_current_file(path);
                    }
                    local.processed_files += 1;
                    let before_comp = local.compressed_files + local.released_files;
                    let before_delta = local.saved_delta();
                    let before_err = local.errors;

                    let mut bytes_accounted = 0u64;
                    if compress_single_file(
                        path,
                        profile,
                        target_opt,
                        policy,
                        ctl,
                        &mut local,
                        &mut copy_buf,
                        &mut bytes_accounted,
                        incremental_idle,
                    )
                    .is_err()
                    {
                        local.errors += 1;
                    }

                    if let Some(prog) = ctl.progress {
                        let rem = logical_est.saturating_sub(bytes_accounted);
                        if rem > 0 {
                            prog.done_bytes.fetch_add(rem, Ordering::Relaxed);
                        }
                        prog.done_files.fetch_add(1, Ordering::Relaxed);
                        if local.compressed_files + local.released_files > before_comp {
                            prog.compressed_files.fetch_add(1, Ordering::Relaxed);
                            let d = local.saved_delta() - before_delta;
                            if d != 0 {
                                prog.saved_bytes.fetch_add(d, Ordering::Relaxed);
                            }
                        } else if local.errors > before_err {
                            prog.error_files.fetch_add(1, Ordering::Relaxed);
                        } else {
                            prog.skipped_files.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                if let Ok(mut g) = out_ref.lock() {
                    *g = local;
                }
            });
        }
    });

    for m in partial_reports {
        if let Ok(part) = m.into_inner() {
            rep.merge_from(&part);
        }
    }

    // Single filesystem sync ONCE at job completion (1 F2FS checkpoint instead of 2 per file!).
    if rep.compressed_files > 0 || rep.released_files > 0 || rep.decompressed_files > 0 {
        if let Ok(f) = File::open(&roots.data_app) {
            ioctl::sync_filesystem(f.as_raw_fd());
        }
    }
    rep
}

/// Decompresses all compressed files in `pkg` in parallel and clears directory inheritance flags.
pub fn decompress_package(
    roots: &RootPaths,
    pkg: &str,
    scopes: Scopes,
    ctl: &RunControl<'_>,
) -> RunReport {
    let mut rep = RunReport {
        package: pkg.to_string(),
        action: "decompress".into(),
        ..Default::default()
    };

    if !ctl.allow_running && is_package_running(roots, pkg) {
        rep.refused_running = true;
        return rep;
    }

    let (all_files, inherit_dirs) = collect_scope_files(roots, pkg, scopes);

    for dir in &inherit_dirs {
        let _ = clear_dir_profile(dir);
    }

    let mut work_items: Vec<(PathBuf, u64)> = Vec::new();
    let mut total_bytes = 0u64;
    for path in all_files {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.nlink() > 1 {
            continue;
        }
        // Only enqueue files that actually look compressed or have FS_COMPR_FL
        if meta.len() >= 16384 && (meta.blocks() * 512 < meta.len()) {
            total_bytes += meta.len();
            work_items.push((path, meta.len()));
        } else if meta.len() >= 16384 {
            if let Ok(f) = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(&path) {
                if (ioctl::get_fs_flags(f.as_raw_fd()).unwrap_or(0) & FS_COMPR_FL) != 0 {
                    total_bytes += meta.len();
                    work_items.push((path, meta.len()));
                }
            }
        }
    }

    if let Some(prog) = ctl.progress {
        prog.total_files
            .store(work_items.len() as u64, Ordering::SeqCst);
        prog.total_bytes.store(total_bytes, Ordering::SeqCst);
    }

    let total_work = work_items.len();
    if total_work == 0 {
        return rep;
    }

    let (max_workers, cpu_mask) = ioctl::compute_worker_plan();
    let next_idx = AtomicUsize::new(0);
    let threads = max_workers.min(total_work);
    let partial_reports: Vec<Mutex<RunReport>> = (0..threads)
        .map(|_| Mutex::new(RunReport::default()))
        .collect();

    std::thread::scope(|s| {
        for tid in 0..threads {
            let items_ref = &work_items;
            let idx_ref = &next_idx;
            let out_ref = &partial_reports[tid];
            s.spawn(move || {
                ioctl::set_worker_priority(cpu_mask, false);
                let mut local = RunReport::default();
                let mut copy_buf = vec![0u8; COPY_BUF_SIZE];

                loop {
                    if check_cancel_or_pause(ctl) {
                        local.cancelled = true;
                        break;
                    }
                    let i = idx_ref.fetch_add(1, Ordering::Relaxed);
                    if i >= items_ref.len() {
                        break;
                    }
                    let (ref path, logical_est) = items_ref[i];
                    if let Some(prog) = ctl.progress {
                        prog.set_current_file(path);
                    }
                    local.processed_files += 1;
                    let mut bytes_accounted = 0u64;
                    if decompress_single_file(path, ctl, &mut local, &mut copy_buf, &mut bytes_accounted, false)
                        .is_err()
                    {
                        local.errors += 1;
                    }
                    if let Some(prog) = ctl.progress {
                        let rem = logical_est.saturating_sub(bytes_accounted);
                        if rem > 0 {
                            prog.done_bytes.fetch_add(rem, Ordering::Relaxed);
                        }
                        prog.done_files.fetch_add(1, Ordering::Relaxed);
                    }
                }

                if let Ok(mut g) = out_ref.lock() {
                    *g = local;
                }
            });
        }
    });

    for m in partial_reports {
        if let Ok(part) = m.into_inner() {
            rep.merge_from(&part);
        }
    }

    if rep.decompressed_files > 0 {
        if let Ok(f) = File::open(&roots.data_app) {
            ioctl::sync_filesystem(f.as_raw_fd());
        }
    }
    rep
}

/// Calls `F2FS_IOC_RELEASE_COMPRESS_BLOCKS` on all compressed files under `path` (directory or file).
/// Safe to run after `dexopt`, APK install, or idle maintenance to reclaim WOF auto-reserved blocks.
pub fn release_path(path: &Path) -> RunReport {
    let mut rep = RunReport {
        package: path.to_string_lossy().into_owned(),
        action: "release".into(),
        ..Default::default()
    };
    if ioctl::is_incfs_path(path) {
        return rep;
    }
    let mut files = Vec::new();
    let mut dummy_dirs = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        walk_files_and_dirs(path, &mut files, &mut dummy_dirs);
    }

    for fpath in files {
        rep.processed_files += 1;
        if probe::is_path_excluded(&fpath) {
            rep.skipped_policy += 1;
            continue;
        }
        let Ok(meta_before) = fs::symlink_metadata(&fpath) else {
            continue;
        };
        let Ok(f) = File::open(&fpath) else {
            continue;
        };
        let fd = f.as_raw_fd();
        let flags = ioctl::get_fs_flags(fd).unwrap_or(0);
        if (flags & FS_COMPR_FL) == 0 {
            continue;
        }
        let before = meta_before.blocks() * 512;
        match ioctl::release_compress_blocks(fd) {
            Ok(released_blks) if released_blks > 0 => {
                rep.released_files += 1;
                rep.bytes_before += before;
                let after = fs::symlink_metadata(&fpath)
                    .map(|m| m.blocks() * 512)
                    .unwrap_or(before.saturating_sub(released_blks * 4096));
                rep.bytes_after += after;
            }
            Ok(_) => rep.skipped_already_done += 1,
            Err(e) if e.raw_os_error() == Some(16) /* EBUSY */ => rep.skipped_busy_or_toctou += 1,
            Err(_) => rep.skipped_already_done += 1,
        }
    }
    rep
}

/// Removes any leftover `.padat.<pid>.*.tmp` files from interrupted runs under `dir`.
pub fn cleanup_stale_temps(dir: &Path) -> u64 {
    let mut removed = 0u64;
    let Ok(rd) = fs::read_dir(dir) else {
        return 0;
    };
    for ent in rd.flatten() {
        // Use d_type first (zero lstat() syscalls on 100k+ normal files).
        if let Ok(ft) = ent.file_type() {
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                removed += cleanup_stale_temps(&ent.path());
            } else if ft.is_file() {
                if let Some(name) = ent.file_name().to_str() {
                    if name.starts_with('.') && name.contains(".padat.") && name.ends_with(".tmp") {
                        if fs::remove_file(ent.path()).is_ok() {
                            removed += 1;
                        }
                    }
                }
            }
            continue;
        }
        let p = ent.path();
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            removed += cleanup_stale_temps(&p);
        } else if let Some(name) = ent.file_name().to_str() {
            if name.starts_with('.') && name.contains(".padat.") && name.ends_with(".tmp") {
                if fs::remove_file(&p).is_ok() {
                    removed += 1;
                }
            }
        }
    }
    removed
}

/// Scoped boot-time stale temp cleanup: inspects only opted-in package trees (and `/data/app`
/// when `auto_tier1` is enabled), joining `/data/user/0/<pkg>` directly so `padatd` never needs
/// `read` permission on `/data/user/0` (`system_data_file`) and never walks unrelated apps.
pub fn cleanup_stale_temps_for_policy(roots: &RootPaths, policy: &Policy) -> u64 {
    let mut removed = 0u64;
    if policy.auto_tier1 {
        removed += cleanup_stale_temps(&roots.data_app);
    }
    for (pkg, pp) in &policy.packages {
        if !policy.auto_tier1 {
            if let Some(code_dir) = find_app_code_dir(roots, pkg) {
                removed += cleanup_stale_temps(&code_dir);
            }
        }
        if pp.scopes.external_data {
            removed += cleanup_stale_temps(&roots.ext_data.join(pkg));
        }
        if pp.scopes.obb {
            removed += cleanup_stale_temps(&roots.ext_obb.join(pkg));
        }
        if pp.scopes.internal_files {
            removed += cleanup_stale_temps(&roots.user_data.join(pkg));
        }
    }
    removed
}

fn check_cancel_or_pause(ctl: &RunControl<'_>) -> bool {
    loop {
        if ctl.cancel.load(Ordering::Relaxed) {
            return true;
        }
        let user_or_game_paused = ctl.paused.load(Ordering::Relaxed);
        let hot = read_battery_temp_mc()
            .map(|t| t >= ctl.thermal_pause_mc)
            .unwrap_or(false);
        if !user_or_game_paused && !hot {
            if let Some(prog) = ctl.progress {
                prog.set_pause_reason("");
            }
            return false;
        }
        if let Some(prog) = ctl.progress {
            prog.set_pause_reason(if hot { "thermal" } else { "paused" });
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn build_temp_path(orig: &Path) -> io::Result<PathBuf> {
    let parent = orig
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent"))?;
    let fname = orig
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-utf8 filename"))?;
    let pid = std::process::id();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(".{fname}.padat.{pid}.{seq}.tmp")))
}

#[allow(clippy::too_many_arguments)]
fn compress_single_file(
    path: &Path,
    profile: CompProfile,
    target_opt: F2fsCompOptionV2,
    policy: &Policy,
    ctl: &RunControl<'_>,
    rep: &mut RunReport,
    buf: &mut [u8],
    bytes_accounted: &mut u64,
    incremental: bool,
) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.nlink() > 1 || meta.len() < policy.min_file_bytes {
        rep.skipped_policy += 1;
        return Ok(());
    }

    let logical = meta.len();
    let phys_before = meta.blocks() * 512;

    let mut src = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let src_fd = src.as_raw_fd();

    let flags = ioctl::get_fs_flags(src_fd).unwrap_or(0);
    if (flags & (FS_VERITY_FL | FS_IMMUTABLE_FL)) != 0 {
        rep.skipped_verity += 1;
        return Ok(());
    }

    // Safety guard: if an excluded file (DB, writable mmap ringbuffer, KV store, etc.)
    // was previously compressed, auto-heal it by decompressing & marking FS_NOCOMP_FL!
    if probe::is_path_excluded(path) {
        if (flags & FS_COMPR_FL) != 0 {
            drop(src);
            let _ = decompress_single_file(path, ctl, rep, buf, bytes_accounted, true);
        } else {
            rep.skipped_policy += 1;
        }
        return Ok(());
    }

    // Already tagged FS_NOCOMP_FL: skip in O(1) during incremental sync (post-update/post-session).
    // Explicit manual compress runs still re-evaluate so switching algorithms/re-enabling works cleanly.
    if (flags & FS_NOCOMP_FL) != 0 && incremental {
        rep.skipped_probe += 1;
        return Ok(());
    }

    // Already compressed with the exact requested algorithm/level/cluster?
    if (flags & FS_COMPR_FL) != 0
        && ioctl::get_compress_option_v2(src_fd)
            .ok()
            .and_then(CompProfile::from_v2_ioctl)
            == Some(profile.normalized())
    {
        // Safety guard: if an extensionless SQLite DB accidentally inherited FS_COMPR_FL,
        // auto-heal by decompressing & marking FS_NOCOMP_FL!
        let mut hdr = [0u8; 16];
        if src.read(&mut hdr).unwrap_or(0) == 16 && probe::is_sqlite_header(&hdr) {
            drop(src);
            let _ = decompress_single_file(path, ctl, rep, buf, bytes_accounted, true);
            return Ok(());
        }
        if let Ok(rel) = ioctl::release_compress_blocks(src_fd) {
            if rel > 0 {
                rep.released_files += 1;
                rep.bytes_before += phys_before;
                let phys_after = fs::symlink_metadata(path)
                    .map(|m| m.blocks() * 512)
                    .unwrap_or(phys_before.saturating_sub(rel * 4096));
                rep.bytes_after += phys_after;
                return Ok(());
            }
        }
        rep.skipped_already_done += 1;
        return Ok(());
    }

    // Small-file single-read fast path (<= 256 KB): read the entire file ONCE into `buf`,
    // probe purely in memory, and write that exact same buffer to `tmp` with zero extra syscalls!
    let mut small_buf_len: Option<usize> = None;
    if logical <= SMALL_FILE_FAST_MAX && (logical as usize) <= buf.len() {
        let want = logical as usize;
        let mut got = 0usize;
        while got < want {
            let n = src.read(&mut buf[got..want])?;
            if n == 0 {
                break;
            }
            got += n;
        }
        match probe::probe_slice(path, &buf[..got], profile, policy.min_saving_pct) {
            ProbeVerdict::ExcludedPolicy => {
                if (flags & FS_COMPR_FL) != 0 && probe::is_sqlite_header(&buf[..got]) {
                    drop(src);
                    let _ = decompress_single_file(path, ctl, rep, buf, bytes_accounted, true);
                } else {
                    rep.skipped_policy += 1;
                }
                return Ok(());
            }
            ProbeVerdict::Incompressible {
                entropy_x100,
                est_saving_pct,
            } => {
                if (entropy_x100 >= 795
                    || est_saving_pct == 0
                    || profile.algo == CompAlgo::Zstd)
                    && (flags & FS_COMPR_FL) == 0
                {
                    let _ = ioctl::set_nocomp_flag(src_fd);
                }
                rep.skipped_probe += 1;
                return Ok(());
            }
            ProbeVerdict::Compress(_) => {
                small_buf_len = Some(got);
            }
        }
    } else {
        // Large-file path (> 256 KB): reuse already-open `src_fd` (zero double-open!)
        match probe::probe_fd(&mut src, path, logical, profile, policy.min_saving_pct)? {
            ProbeVerdict::ExcludedPolicy => {
                rep.skipped_policy += 1;
                return Ok(());
            }
            ProbeVerdict::Incompressible {
                entropy_x100,
                est_saving_pct,
            } => {
                if (entropy_x100 >= 795
                    || est_saving_pct == 0
                    || profile.algo == CompAlgo::Zstd)
                    && (flags & FS_COMPR_FL) == 0
                {
                    let _ = ioctl::set_nocomp_flag(src_fd);
                }
                rep.skipped_probe += 1;
                return Ok(());
            }
            ProbeVerdict::Compress(_) => {}
        }
        ioctl::fadvise_sequential(src_fd);
    }

    let tmp_path = build_temp_path(path)?;
    let _ = fs::remove_file(&tmp_path);

    let mut tmp = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&tmp_path)?;
    let tmp_fd = tmp.as_raw_fd();

    struct TempGuard(Option<PathBuf>);
    impl Drop for TempGuard {
        fn drop(&mut self) {
            if let Some(p) = self.0.take() {
                let _ = fs::remove_file(p);
            }
        }
    }
    let mut guard = TempGuard(Some(tmp_path.clone()));

    ioctl::set_compr_flag(tmp_fd)?;
    ioctl::set_compress_option_v2(tmp_fd, target_opt)?;

    if let Some(got) = small_buf_len {
        tmp.write_all(&buf[..got])?;
        *bytes_accounted += got as u64;
        if let Some(prog) = ctl.progress {
            prog.done_bytes.fetch_add(got as u64, Ordering::Relaxed);
        }
    } else {
        // Large-file streaming: use kernel zero-copy `copy_file_range` (with fallback to read/write)
        // and kick non-blocking `sync_file_range(WRITE)` every 4 MB for files >= 8 MB so kernel
        // F2FS compression overlaps asynchronously with reading!
        let mut use_cfr = true;
        let mut written = 0u64;
        let mut flushed_to = 0u64;
        let overlap_flush = logical >= ASYNC_FLUSH_THRESHOLD;

        loop {
            if check_cancel_or_pause(ctl) {
                rep.cancelled = true;
                return Ok(());
            }
            let copied = if use_cfr {
                match ioctl::copy_file_range_chunk(src_fd, tmp_fd, COPY_BUF_SIZE) {
                    Ok(n) => n,
                    Err(_) => {
                        use_cfr = false;
                        let n = src.read(buf)?;
                        if n > 0 {
                            tmp.write_all(&buf[..n])?;
                        }
                        n
                    }
                }
            } else {
                let n = src.read(buf)?;
                if n > 0 {
                    tmp.write_all(&buf[..n])?;
                }
                n
            };
            if copied == 0 {
                break;
            }
            written += copied as u64;
            *bytes_accounted += copied as u64;
            if let Some(prog) = ctl.progress {
                prog.done_bytes.fetch_add(copied as u64, Ordering::Relaxed);
            }
            if overlap_flush && written.saturating_sub(flushed_to) >= ASYNC_FLUSH_WINDOW {
                ioctl::sync_file_range_write(tmp_fd, flushed_to, written - flushed_to);
                flushed_to = written;
            }
        }
    }

    // Flush dirty pages through F2FS compression & reclaim freed blocks WITHOUT triggering
    // a per-file `CP_COMPRESSED` full filesystem checkpoint (f2fs_release_compress_blocks
    // internally runs filemap_write_and_wait_range!).
    let _ = ioctl::release_compress_blocks(tmp_fd);

    let tmp_meta = tmp.metadata()?;
    let phys_after = tmp_meta.blocks() * 512;

    let saving_vs_logical_pct = if logical > 0 && phys_after < logical {
        ((logical - phys_after) * 100) / logical
    } else {
        0
    };
    let already_compr = (flags & FS_COMPR_FL) != 0;
    if saving_vs_logical_pct < policy.min_saving_pct as u64
        || phys_after >= logical
        || (!already_compr && phys_after >= phys_before)
    {
        if profile.algo == CompAlgo::Zstd && !already_compr {
            let _ = ioctl::set_nocomp_flag(src_fd);
        }
        rep.skipped_probe += 1;
        return Ok(());
    }

    // Preserve uid, gid, mode, timestamps, and SELinux/xattrs.
    ioctl::preserve_metadata(
        src_fd,
        tmp_fd,
        &tmp_path,
        meta.uid(),
        meta.gid(),
        meta.mode(),
        meta.atime(),
        meta.atime_nsec(),
        meta.mtime(),
        meta.mtime_nsec(),
    )?;

    // TOCTOU check: ensure original file wasn't modified or replaced during copy!
    let cur = fs::symlink_metadata(path)?;
    if cur.ino() != meta.ino()
        || cur.len() != meta.len()
        || cur.mtime() != meta.mtime()
        || cur.mtime_nsec() != meta.mtime_nsec()
    {
        rep.skipped_busy_or_toctou += 1;
        return Ok(());
    }

    drop(tmp);
    drop(src);

    fs::rename(&tmp_path, path)?;
    guard.0 = None;

    rep.compressed_files += 1;
    rep.bytes_before += phys_before;
    rep.bytes_after += phys_after;
    Ok(())
}

fn decompress_single_file(
    path: &Path,
    ctl: &RunControl<'_>,
    rep: &mut RunReport,
    buf: &mut [u8],
    bytes_accounted: &mut u64,
    mark_nocomp: bool,
) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.nlink() > 1 {
        return Ok(());
    }
    let mut src = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let src_fd = src.as_raw_fd();
    let flags = ioctl::get_fs_flags(src_fd).unwrap_or(0);
    if (flags & FS_COMPR_FL) == 0 {
        rep.skipped_already_done += 1;
        return Ok(());
    }
    if (flags & (FS_VERITY_FL | FS_IMMUTABLE_FL)) != 0 {
        rep.skipped_verity += 1;
        return Ok(());
    }

    let phys_before = meta.blocks() * 512;
    let tmp_path = build_temp_path(path)?;
    let _ = fs::remove_file(&tmp_path);

    let mut tmp = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&tmp_path)?;
    let tmp_fd = tmp.as_raw_fd();

    if mark_nocomp {
        let _ = ioctl::set_nocomp_flag(tmp_fd);
    } else {
        let _ = ioctl::clear_compr_and_nocomp_flags(tmp_fd);
    }

    loop {
        if check_cancel_or_pause(ctl) {
            let _ = fs::remove_file(&tmp_path);
            rep.cancelled = true;
            return Ok(());
        }
        let n = src.read(buf)?;
        if n == 0 {
            break;
        }
        tmp.write_all(&buf[..n])?;
        *bytes_accounted += n as u64;
        if let Some(prog) = ctl.progress {
            prog.done_bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    ioctl::preserve_metadata(
        src_fd,
        tmp_fd,
        &tmp_path,
        meta.uid(),
        meta.gid(),
        meta.mode(),
        meta.atime(),
        meta.atime_nsec(),
        meta.mtime(),
        meta.mtime_nsec(),
    )?;

    let phys_after = tmp.metadata()?.blocks() * 512;
    let cur = fs::symlink_metadata(path)?;
    if cur.ino() != meta.ino()
        || cur.len() != meta.len()
        || cur.mtime() != meta.mtime()
        || cur.mtime_nsec() != meta.mtime_nsec()
    {
        let _ = fs::remove_file(&tmp_path);
        rep.skipped_busy_or_toctou += 1;
        return Ok(());
    }

    drop(tmp);
    drop(src);
    fs::rename(&tmp_path, path)?;

    rep.decompressed_files += 1;
    rep.bytes_before += phys_before;
    rep.bytes_after += phys_after;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_package_distinguishes_compressible_vs_encrypted_and_excluded() {
        let base = std::env::temp_dir().join(format!("padat_eng_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);

        let code_dir = base.join("app/~~rnd/com.example.game-123");
        let oat_dir = code_dir.join("oat/arm64");
        let ext_dir = base.join("ext/com.example.game/files");
        let usr_dir = base.join("usr/com.example.game/files");
        let usr_cache = base.join("usr/com.example.game/cache");
        fs::create_dir_all(&oat_dir).unwrap();
        fs::create_dir_all(&ext_dir).unwrap();
        fs::create_dir_all(&usr_dir).unwrap();
        fs::create_dir_all(&usr_cache).unwrap();

        // Compressible .vdex
        let vdex = vec![0x42u8; 256 * 1024];
        fs::write(oat_dir.join("base.vdex"), &vdex).unwrap();

        // Excluded .art
        fs::write(oat_dir.join("base.art"), &vdex).unwrap();

        // Extensionless SQLite DB in internal files (must be excluded by magic!)
        let mut sql = vec![0u8; 128 * 1024];
        sql[..16].copy_from_slice(b"SQLite format 3\0");
        fs::write(usr_dir.join("meta"), &sql).unwrap();

        // Compressible Unity asset in internal files
        fs::write(usr_dir.join("asset.unity3d"), &vdex).unwrap();

        // Cache file (must show up in cache_other!)
        fs::write(usr_cache.join("tmp.dat"), &vdex).unwrap();

        // High-entropy encrypted game blob in ext_dir
        let mut s = 0x1234_5678_9abc_def0u64;
        let mut enc = vec![0u8; 256 * 1024];
        for b in &mut enc {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = (s & 0xff) as u8;
        }
        fs::write(ext_dir.join("encrypted.blk"), &enc).unwrap();

        let roots = RootPaths {
            data_app: base.join("app"),
            ext_data: base.join("ext"),
            ext_obb: base.join("obb"),
            user_data: base.join("usr"),
            user_de_data: base.join("usr_de"),
            packages_list: base.join("packages.list"),
        };
        let pol = Policy::default();
        let all_scopes = Scopes {
            apk_lib: true,
            art_oat: true,
            external_data: true,
            obb: true,
            internal_files: true,
        };
        let stats = scan_package(&roots, "com.example.game", CompProfile::BALANCED, all_scopes, &pol);
        assert_eq!(stats.candidate_files, 2); // base.vdex + asset.unity3d
        assert_eq!(stats.skipped_excluded, 2); // base.art + SQLite `meta`
        assert_eq!(stats.skipped_incompressible, 1); // encrypted.blk
        assert!(stats.breakdown.internal_files.logical_bytes >= 384 * 1024);
        assert!(stats.breakdown.cache_other.logical_bytes >= 256 * 1024);
        assert!(stats.est_extra_savings_bytes > 200 * 1024);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn open_dir_with_o_directory_and_o_nofollow_succeeds() {
        let dir = std::env::temp_dir().join(format!("padat_odir_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let res = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(&dir);
        assert!(res.is_ok(), "O_DIRECTORY|O_NOFOLLOW open failed: {:?}", res.err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sqlite_dir_check_and_policy_temp_cleanup() {
        use crate::policy::{PackagePolicy, Preset};
        let base = std::env::temp_dir().join(format!("padat_sql_clean_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);

        let ext_dir = base.join("ext/com.test.app/files");
        let usr_dir = base.join("usr/com.test.app/files");
        fs::create_dir_all(&ext_dir).unwrap();
        fs::create_dir_all(&usr_dir).unwrap();

        // Extensionless SQLite file in internal dir must be caught when sniffing is enabled.
        let mut sql = vec![0u8; 4096];
        sql[..16].copy_from_slice(b"SQLite format 3\0");
        fs::write(usr_dir.join("meta"), &sql).unwrap();
        assert!(dir_directly_contains_sqlite(&usr_dir, true));
        assert!(!dir_directly_contains_sqlite(&usr_dir, false));

        // Explicit `.db` in ext_dir must be caught even without magic sniffing.
        fs::write(ext_dir.join("catalog.db"), b"x").unwrap();
        assert!(dir_directly_contains_sqlite(&ext_dir, false));

        // Scoped temp cleanup must remove `.padat.*.tmp` under opted-in package dirs only.
        fs::write(usr_dir.join(".asset.padat.123.1.tmp"), b"stale").unwrap();
        fs::write(ext_dir.join(".bundle.padat.123.2.tmp"), b"stale").unwrap();
        let mut pol = Policy::default();
        pol.packages.insert(
            "com.test.app".into(),
            PackagePolicy {
                preset: Preset::Balanced,
                profile: CompProfile::BALANCED,
                scopes: Scopes {
                    apk_lib: true,
                    art_oat: true,
                    external_data: true,
                    obb: false,
                    internal_files: true,
                },
            },
        );
        let roots = RootPaths {
            data_app: base.join("app"),
            ext_data: base.join("ext"),
            ext_obb: base.join("obb"),
            user_data: base.join("usr"),
            user_de_data: base.join("usr_de"),
            packages_list: base.join("packages.list"),
        };
        assert_eq!(cleanup_stale_temps_for_policy(&roots, &pol), 2);
        assert!(!usr_dir.join(".asset.padat.123.1.tmp").exists());
        assert!(!ext_dir.join(".bundle.padat.123.2.tmp").exists());

        let _ = fs::remove_dir_all(&base);
    }
}
