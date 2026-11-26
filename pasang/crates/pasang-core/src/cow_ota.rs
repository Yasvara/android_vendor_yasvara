// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! 9-Step Atomic In-OS Live CoW OTA Engine (`Pasang`).
//!
//! Runs directly inside live Android (zero reboot to recovery, zero post-boot VAB merge!)
//! and identically inside host loopback unit tests via `OtaEnvironment`.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Instant;

use crate::avb;
use crate::codec::decode_op_into;
use crate::crypto::{hex_encode, sha256_bytes, sha256_prefix16, verify_metadata_signatures, Sha256};
use crate::dedup::{build_extent_alias_runs, ActiveBlockIndex, BlockKey};
use crate::lp::{
    align_up, parse_geometry, parse_slot_metadata, plan_ota_inactive_slot, slot_suffix,
    ExtentLimits, LogicalRun, LpExtent, LpMetadata, OtaPartitionExtentSpec, OtaSuperPlan,
    LP_BLOCK_SIZE, LP_SECTOR_SIZE, LP_SECTORS_PER_BLOCK, LP_TARGET_TYPE_LINEAR,
    LP_TARGET_TYPE_ZERO,
};
use crate::overlay::{clean_overlays, inspect_overlays, OverlayCleanReport};
use crate::payload::{parse_payload, OpType, PartitionUpdate, PayloadManifest};
use crate::slot::{
    json_escape, BootControlOps, CachedPartitionHash, OtaOptions, ResumeState, SlotStateCache,
};

/// Filesystem/device seam enabling the exact same OTA engine on Android & host tests.
#[derive(Debug, Clone)]
pub struct OtaEnvironment {
    pub super_device: PathBuf,
    pub by_name_dir: PathBuf,
    pub metadata_dir: PathBuf,
    pub scratch_overlay_root: PathBuf,
    pub proc_mounts_path: PathBuf,
    pub otacerts_path: PathBuf,
    /// Optional externally-supplied live dm-linear occupied sector intervals.
    pub live_dm_occupied: Vec<(u64, u64)>,
    /// A/B partitions of this device (`ro.product.ab_ota_partitions`), used to carry raw
    /// partitions a partial payload does not include over from the active slot.
    pub ab_partitions: Vec<String>,
}

impl OtaEnvironment {
    pub fn android_default() -> Self {
        Self {
            super_device: PathBuf::from("/dev/block/by-name/super"),
            by_name_dir: PathBuf::from("/dev/block/by-name"),
            metadata_dir: PathBuf::from("/metadata/pasang"),
            scratch_overlay_root: PathBuf::from("/mnt/scratch/overlay"),
            proc_mounts_path: PathBuf::from("/proc/mounts"),
            otacerts_path: PathBuf::from("/system/etc/security/otacerts.zip"),
            live_dm_occupied: Vec::new(),
            ab_partitions: read_ab_ota_partitions(),
        }
    }
}

fn read_ab_ota_partitions() -> Vec<String> {
    const KEY: &str = "ro.product.ab_ota_partitions=";
    for f in [
        "/product/etc/build.prop",
        "/system/build.prop",
        "/system_ext/etc/build.prop",
        "/vendor/build.prop",
    ] {
        if let Ok(txt) = fs::read_to_string(f) {
            if let Some(v) = txt.lines().find_map(|l| l.strip_prefix(KEY)) {
                return v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
        }
    }
    Vec::new()
}

/// Copy planned write segments of a carried-over dynamic partition from the active slot's
/// sectors (`src`, logical order) into freshly allocated super sectors, with readback.
fn copy_carried_segments(
    super_rw: &mut File,
    src: &[LpExtent],
    segs: &[crate::lp::PhysicalWriteSegment],
    total_written: &mut u64,
) -> Result<(), String> {
    let mut buf = vec![0u8; 1024 * 1024];
    let mut back = vec![0u8; 1024 * 1024];
    for seg in segs {
        let mut done = 0u64;
        while done < seg.length_bytes {
            let logical = seg.logical_byte_offset + done;
            let mut ext_base = 0u64;
            let mut phys = None;
            for e in src {
                let len = e.num_sectors * LP_SECTOR_SIZE;
                if logical < ext_base + len {
                    phys = Some((e.target_data * LP_SECTOR_SIZE + (logical - ext_base), ext_base + len - logical));
                    break;
                }
                ext_base += len;
            }
            let (src_off, avail) = phys.ok_or("carried segment beyond source extents")?;
            let n = (seg.length_bytes - done).min(avail).min(buf.len() as u64) as usize;
            let dst_off = seg.super_byte_offset + done;
            super_rw
                .seek(SeekFrom::Start(src_off))
                .and_then(|_| super_rw.read_exact(&mut buf[..n]))
                .map_err(|e| format!("read carried src@{src_off}: {e}"))?;
            super_rw
                .seek(SeekFrom::Start(dst_off))
                .and_then(|_| super_rw.write_all(&buf[..n]))
                .map_err(|e| format!("write carried dst@{dst_off}: {e}"))?;
            super_rw
                .seek(SeekFrom::Start(dst_off))
                .and_then(|_| super_rw.read_exact(&mut back[..n]))
                .map_err(|e| format!("readback carried dst@{dst_off}: {e}"))?;
            if buf[..n] != back[..n] {
                return Err(format!("ABORT BEFORE COMMIT: carried copy mismatch at super byte {dst_off}"));
            }
            *total_written += n as u64;
            done += n as u64;
        }
    }
    Ok(())
}

fn block_dev_size(path: &Path) -> Result<u64, String> {
    let mut f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    f.seek(SeekFrom::End(0)).map_err(|e| format!("size {}: {e}", path.display()))
}

fn copy_raw_partition(src: &Path, dst: &Path, size: u64, total_written: &mut u64) -> Result<(), String> {
    let mut s = File::open(src).map_err(|e| format!("open {}: {e}", src.display()))?;
    let mut d = OpenOptions::new()
        .write(true)
        .open(dst)
        .map_err(|e| format!("open rw {}: {e}", dst.display()))?;
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut rem = size;
    while rem > 0 {
        let n = (rem as usize).min(buf.len());
        s.read_exact(&mut buf[..n]).map_err(|e| format!("read {}: {e}", src.display()))?;
        d.write_all(&buf[..n]).map_err(|e| format!("write {}: {e}", dst.display()))?;
        rem -= n as u64;
        *total_written += n as u64;
    }
    d.sync_data().map_err(|e| format!("fsync {}: {e}", dst.display()))
}

/// AVB vbmeta header flags (`AVB0` magic, flags at byte 120), or `None` if unreadable.
fn read_vbmeta_flags(path: &Path) -> Option<u32> {
    let mut hdr = [0u8; 128];
    File::open(path).ok()?.read_exact(&mut hdr).ok()?;
    (&hdr[..4] == b"AVB0").then(|| u32::from_be_bytes(hdr[120..124].try_into().unwrap()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtaPhase {
    Idle,
    Preflight,
    Indexing,
    Planning,
    Flashing,
    Verifying,
    Committing,
    CleaningOverlay,
    Done,
    Cancelled,
    Error,
}

impl OtaPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Preflight => "preflight",
            Self::Indexing => "indexing",
            Self::Planning => "planning",
            Self::Flashing => "flashing",
            Self::Verifying => "verifying",
            Self::Committing => "committing",
            Self::CleaningOverlay => "cleaning_overlay",
            Self::Done => "done",
            Self::Cancelled => "cancelled",
            Self::Error => "error",
        }
    }
}

/// Thread-safe live OTA progress & Hyper-Flash telemetry snapshot (rendered by Laras at 120 Hz).
#[derive(Debug, Clone)]
pub struct OtaProgress {
    pub phase: OtaPhase,
    pub active_slot: u32,
    pub target_slot: u32,
    pub current_partition: String,
    pub partitions_done: usize,
    pub partitions_total: usize,
    pub bytes_total_logical: u64,
    pub bytes_aliased: u64,
    pub bytes_zeroed: u64,
    pub bytes_skipped_whole: u64,
    pub bytes_to_write: u64,
    pub bytes_written: u64,
    pub speed_bps: u64,
    pub eta_seconds: i64,
    pub elapsed_ms: u64,
    pub total_extents: usize,
    pub overlay_cleaned_files: u64,
    pub overlay_freed_bytes: u64,
    pub reboot_required: bool,
    pub error_message: String,
}

impl Default for OtaProgress {
    fn default() -> Self {
        Self {
            phase: OtaPhase::Idle,
            active_slot: 0,
            target_slot: 1,
            current_partition: String::new(),
            partitions_done: 0,
            partitions_total: 0,
            bytes_total_logical: 0,
            bytes_aliased: 0,
            bytes_zeroed: 0,
            bytes_skipped_whole: 0,
            bytes_to_write: 0,
            bytes_written: 0,
            speed_bps: 0,
            eta_seconds: -1,
            elapsed_ms: 0,
            total_extents: 0,
            overlay_cleaned_files: 0,
            overlay_freed_bytes: 0,
            reboot_required: false,
            error_message: String::new(),
        }
    }
}

impl OtaProgress {
    pub fn to_json(&self) -> String {
        let saved = self.bytes_aliased + self.bytes_zeroed + self.bytes_skipped_whole;
        let alias_pct = if self.bytes_total_logical > 0 {
            ((saved as f64) * 100.0) / (self.bytes_total_logical as f64)
        } else {
            0.0
        };
        let progress_pct = match self.phase {
            OtaPhase::Done => 100.0,
            OtaPhase::Idle => 0.0,
            _ if self.bytes_to_write > 0 => {
                ((self.bytes_written as f64) * 100.0 / (self.bytes_to_write as f64)).clamp(0.0, 99.5)
            }
            _ if self.partitions_total > 0 => {
                ((self.partitions_done as f64) * 100.0 / (self.partitions_total as f64))
                    .clamp(0.0, 99.5)
            }
            _ => 0.0,
        };
        format!(
            "{{\"phase\":\"{}\",\"busy\":{},\"active_slot\":{},\"target_slot\":{},\
             \"current_partition\":\"{}\",\"partitions_done\":{},\"partitions_total\":{},\
             \"progress_pct\":{:.2},\"alias_pct\":{:.1},\
             \"bytes_total_logical\":{},\"bytes_aliased\":{},\"bytes_zeroed\":{},\
             \"bytes_skipped_whole\":{},\"bytes_to_write\":{},\"bytes_written\":{},\
             \"speed_bps\":{},\"eta_seconds\":{},\"elapsed_ms\":{},\"total_extents\":{},\
             \"overlay_cleaned_files\":{},\"overlay_freed_bytes\":{},\
             \"reboot_required\":{},\"error\":\"{}\"}}",
            self.phase.as_str(),
            matches!(
                self.phase,
                OtaPhase::Preflight
                    | OtaPhase::Indexing
                    | OtaPhase::Planning
                    | OtaPhase::Flashing
                    | OtaPhase::Verifying
                    | OtaPhase::Committing
                    | OtaPhase::CleaningOverlay
            ),
            self.active_slot,
            self.target_slot,
            json_escape(&self.current_partition),
            self.partitions_done,
            self.partitions_total,
            progress_pct,
            alias_pct,
            self.bytes_total_logical,
            self.bytes_aliased,
            self.bytes_zeroed,
            self.bytes_skipped_whole,
            self.bytes_to_write,
            self.bytes_written,
            self.speed_bps,
            self.eta_seconds,
            self.elapsed_ms,
            self.total_extents,
            self.overlay_cleaned_files,
            self.overlay_freed_bytes,
            self.reboot_required,
            json_escape(&self.error_message),
        )
    }
}

/// Summary returned by a dry-run `plan_ota` call (shown in Laras preview & `yv ota plan`).
#[derive(Debug, Clone)]
pub struct OtaPlanSummary {
    pub active_slot: u32,
    pub target_slot: u32,
    pub signature_verified: bool,
    pub dynamic_partitions: usize,
    pub raw_partitions: usize,
    pub whole_skipped_partitions: usize,
    pub bytes_total_logical: u64,
    pub bytes_aliased: u64,
    pub bytes_zeroed: u64,
    pub bytes_skipped_whole: u64,
    pub bytes_to_write: u64,
    pub total_extents: usize,
    pub free_super_before: u64,
    pub free_super_after: u64,
    pub overlay_files_present: u64,
    pub partial_update: bool,
    pub carried_partitions: usize,
    pub carried_bytes_copied: u64,
}

impl OtaPlanSummary {
    pub fn to_json(&self) -> String {
        let saved = self.bytes_aliased + self.bytes_zeroed + self.bytes_skipped_whole;
        let saved_pct = if self.bytes_total_logical > 0 {
            (saved as f64) * 100.0 / (self.bytes_total_logical as f64)
        } else {
            0.0
        };
        format!(
            "{{\"active_slot\":{},\"target_slot\":{},\"signature_verified\":{},\
             \"dynamic_partitions\":{},\"raw_partitions\":{},\"whole_skipped_partitions\":{},\
             \"bytes_total_logical\":{},\"bytes_aliased\":{},\"bytes_zeroed\":{},\
             \"bytes_skipped_whole\":{},\"bytes_to_write\":{},\"saved_pct\":{:.1},\
             \"total_extents\":{},\"free_super_before\":{},\"free_super_after\":{},\
             \"overlay_files_present\":{},\"partial_update\":{},\"carried_partitions\":{},\
             \"carried_bytes_copied\":{}}}",
            self.active_slot,
            self.target_slot,
            self.signature_verified,
            self.dynamic_partitions,
            self.raw_partitions,
            self.whole_skipped_partitions,
            self.bytes_total_logical,
            self.bytes_aliased,
            self.bytes_zeroed,
            self.bytes_skipped_whole,
            self.bytes_to_write,
            saved_pct,
            self.total_extents,
            self.free_super_before,
            self.free_super_after,
            self.overlay_files_present,
            self.partial_update,
            self.carried_partitions,
            self.carried_bytes_copied,
        )
    }
}

/// Result returned when an OTA completes successfully.
#[derive(Debug, Clone)]
pub struct OtaApplyResult {
    pub plan: OtaPlanSummary,
    pub elapsed_ms: u64,
    pub bytes_written: u64,
    pub overlay_clean: Option<OverlayCleanReport>,
    pub committed_slot: u32,
}

/// Stream-decode a partition's operations across up to 8 worker threads (~32 MiB peak RAM!)
/// using lock-free `pread` (`FileExt::read_at`) to verify blob SHA-256, decompress ZSTD/XZ/BZ2,
/// and compute all 4 KiB block keys in parallel without buffering the full partition image!
fn stream_index_partition_blocks(
    payload_file: &mut File,
    manifest: &PayloadManifest,
    pu: &PartitionUpdate,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<BlockKey>, String> {
    let bs = manifest.block_size as usize;
    let total_blocks = (align_up(pu.new_info.size, manifest.block_size) / manifest.block_size) as usize;
    let zkey = crate::dedup::zero_block_key();
    let keys = vec![zkey; total_blocks];

    #[cfg(unix)]
    {
        let workers = thread::available_parallelism()
            .map(|n| n.get().clamp(1, 8))
            .unwrap_or(4)
            .min(pu.operations.len().max(1));
        if workers > 1 && pu.operations.len() > 1 {
            let next_op = AtomicUsize::new(0);
            let first_err: Mutex<Option<String>> = Mutex::new(None);
            let keys_mu: Mutex<Vec<BlockKey>> = Mutex::new(keys);
            let file_ref: &File = &*payload_file;

            let read_exact_at = |offset: u64, dst: &mut [u8]| -> std::io::Result<()> {
                let mut pos = 0usize;
                while pos < dst.len() {
                    let n = file_ref.read_at(&mut dst[pos..], offset + pos as u64)?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "unexpected EOF in payload",
                        ));
                    }
                    pos += n;
                }
                Ok(())
            };

            thread::scope(|s| {
                for _ in 0..workers {
                    s.spawn(|| {
                        let mut blob_buf: Vec<u8> = Vec::new();
                        let mut op_buf: Vec<u8> = Vec::new();
                        let mut local_pairs: Vec<(usize, BlockKey)> = Vec::new();
                        loop {
                            if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
                                let mut g = first_err.lock().unwrap();
                                if g.is_none() {
                                    *g = Some("OTA cancelled by user".into());
                                }
                                break;
                            }
                            if first_err.lock().unwrap().is_some() {
                                break;
                            }
                            let oi = next_op.fetch_add(1, Ordering::Relaxed);
                            if oi >= pu.operations.len() {
                                break;
                            }
                            let op = &pu.operations[oi];
                            if op.op_type == OpType::Zero || op.op_type == OpType::Discard {
                                continue;
                            }
                            if op.op_type == OpType::SourceCopy {
                                let mut g = first_err.lock().unwrap();
                                if g.is_none() {
                                    *g = Some(format!(
                                        "{}: op#{oi} SOURCE_COPY requires delta base (use full payload or .pidx Range)",
                                        pu.name
                                    ));
                                }
                                break;
                            }

                            let dst_bytes = (op.total_dst_blocks() as usize) * bs;
                            blob_buf.resize(op.data_length as usize, 0);
                            if let Err(e) =
                                read_exact_at(manifest.data_blob_offset + op.data_offset, &mut blob_buf)
                            {
                                let mut g = first_err.lock().unwrap();
                                if g.is_none() {
                                    *g = Some(format!("read blob {} op#{oi}: {e}", pu.name));
                                }
                                break;
                            }
                            if let Some(exp_hash) = op.data_sha256 {
                                if sha256_bytes(&blob_buf) != exp_hash {
                                    let mut g = first_err.lock().unwrap();
                                    if g.is_none() {
                                        *g = Some(format!(
                                            "{}: op#{oi} blob SHA-256 mismatch (corrupt OTA file)",
                                            pu.name
                                        ));
                                    }
                                    break;
                                }
                            }
                            op_buf.resize(dst_bytes, 0);
                            if let Err(e) = decode_op_into(op.op_type, &blob_buf, &mut op_buf) {
                                let mut g = first_err.lock().unwrap();
                                if g.is_none() {
                                    *g = Some(format!("{} op#{oi}: {e}", pu.name));
                                }
                                break;
                            }

                            local_pairs.clear();
                            let mut pos = 0usize;
                            for ext in &op.dst_extents {
                                for b in 0..ext.num_blocks as usize {
                                    let blk_idx = ext.start_block as usize + b;
                                    if blk_idx < total_blocks && pos + bs <= op_buf.len() {
                                        local_pairs.push((blk_idx, sha256_prefix16(&op_buf[pos..pos + bs])));
                                    }
                                    pos += bs;
                                }
                            }
                            if !local_pairs.is_empty() {
                                let mut kg = keys_mu.lock().unwrap();
                                for &(idx, key) in &local_pairs {
                                    kg[idx] = key;
                                }
                            }
                        }
                    });
                }
            });

            if let Some(err) = first_err.into_inner().unwrap() {
                return Err(err);
            }
            return Ok(keys_mu.into_inner().unwrap());
        }
    }

    // Single-threaded fallback
    let mut keys = keys;
    let mut op_buf: Vec<u8> = Vec::new();
    let mut blob_buf: Vec<u8> = Vec::new();

    for (oi, op) in pu.operations.iter().enumerate() {
        if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
            return Err("OTA cancelled by user".into());
        }
        if op.op_type == OpType::Zero || op.op_type == OpType::Discard {
            continue;
        }
        if op.op_type == OpType::SourceCopy {
            return Err(format!(
                "{}: op#{oi} SOURCE_COPY requires delta base (use full payload or .pidx Range)",
                pu.name
            ));
        }

        let dst_bytes = (op.total_dst_blocks() as usize) * bs;
        blob_buf.resize(op.data_length as usize, 0);
        payload_file
            .seek(SeekFrom::Start(manifest.data_blob_offset + op.data_offset))
            .map_err(|e| format!("seek blob {} op#{oi}: {e}", pu.name))?;
        payload_file
            .read_exact(&mut blob_buf)
            .map_err(|e| format!("read blob {} op#{oi}: {e}", pu.name))?;

        if let Some(exp_hash) = op.data_sha256 {
            if sha256_bytes(&blob_buf) != exp_hash {
                return Err(format!(
                    "{}: op#{oi} blob SHA-256 mismatch (corrupt OTA file)",
                    pu.name
                ));
            }
        }

        op_buf.resize(dst_bytes, 0);
        decode_op_into(op.op_type, &blob_buf, &mut op_buf)
            .map_err(|e| format!("{} op#{oi}: {e}", pu.name))?;

        let mut pos = 0usize;
        for ext in &op.dst_extents {
            for b in 0..ext.num_blocks as usize {
                let blk_idx = ext.start_block as usize + b;
                if blk_idx < keys.len() && pos + bs <= op_buf.len() {
                    keys[blk_idx] = sha256_prefix16(&op_buf[pos..pos + bs]);
                }
                pos += bs;
            }
        }
    }
    Ok(keys)
}

/// Stream-write ONLY the non-aliased `write_segments` of a dynamic partition directly from
/// `payload_file` into `super_rw` using ~2 MiB peak RAM (skipping decode completely for any
/// operation whose blocks are 100% aliased or zeroed!).
fn stream_write_dynamic_partition(
    payload_file: &mut File,
    super_rw: &mut File,
    manifest: &PayloadManifest,
    pu: &PartitionUpdate,
    write_segments: &[crate::lp::PhysicalWriteSegment],
    total_written: &mut u64,
    total_bytes_to_write: u64,
    write_start: Instant,
    update_prog: &dyn Fn(&dyn Fn(&mut OtaProgress)),
    cancel: Option<&AtomicBool>,
) -> Result<(), String> {
    if write_segments.is_empty() {
        return Ok(());
    }
    let bs = manifest.block_size;
    let bs_u = bs as usize;

    // Build compact block -> super_byte_offset map ONLY for blocks that actually need writing.
    let total_blocks = (align_up(pu.new_info.size, bs) / bs) as usize;
    let mut blk_to_super: Vec<u64> = vec![u64::MAX; total_blocks];
    for seg in write_segments {
        let start_blk = (seg.logical_byte_offset / bs) as usize;
        let nblks = (seg.length_bytes / bs) as usize;
        for i in 0..nblks {
            if start_blk + i < blk_to_super.len() {
                blk_to_super[start_blk + i] = seg.super_byte_offset + (i as u64) * bs;
            }
        }
    }

    let mut blob_buf: Vec<u8> = Vec::new();
    let mut op_buf: Vec<u8> = Vec::new();
    let zero_blk = vec![0u8; bs_u];

    for (oi, op) in pu.operations.iter().enumerate() {
        if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
            return Err("OTA cancelled by user".into());
        }
        // Check if ANY block in this op maps to a physical write segment; if none, skip decoding!
        let needs_any = op.dst_extents.iter().any(|ext| {
            let s = ext.start_block as usize;
            let e = (s + ext.num_blocks as usize).min(blk_to_super.len());
            blk_to_super[s..e].iter().any(|&p| p != u64::MAX)
        });
        if !needs_any {
            continue;
        }

        if op.op_type == OpType::Zero || op.op_type == OpType::Discard {
            for ext in &op.dst_extents {
                for b in 0..ext.num_blocks as usize {
                    let blk_idx = ext.start_block as usize + b;
                    if blk_idx < blk_to_super.len() && blk_to_super[blk_idx] != u64::MAX {
                        super_rw
                            .seek(SeekFrom::Start(blk_to_super[blk_idx]))
                            .map_err(|e| format!("seek super zero: {e}"))?;
                        super_rw
                            .write_all(&zero_blk)
                            .map_err(|e| format!("write super zero: {e}"))?;
                        blk_to_super[blk_idx] = u64::MAX;
                        *total_written += bs;
                    }
                }
            }
            continue;
        }

        let dst_bytes = (op.total_dst_blocks() as usize) * bs_u;
        blob_buf.resize(op.data_length as usize, 0);
        payload_file
            .seek(SeekFrom::Start(manifest.data_blob_offset + op.data_offset))
            .map_err(|e| format!("seek blob {} op#{oi}: {e}", pu.name))?;
        payload_file
            .read_exact(&mut blob_buf)
            .map_err(|e| format!("read blob {} op#{oi}: {e}", pu.name))?;
        if let Some(exp_hash) = op.data_sha256 {
            if sha256_bytes(&blob_buf) != exp_hash {
                return Err(format!("{}: op#{oi} blob SHA-256 mismatch", pu.name));
            }
        }

        op_buf.resize(dst_bytes, 0);
        decode_op_into(op.op_type, &blob_buf, &mut op_buf)
            .map_err(|e| format!("{} op#{oi}: {e}", pu.name))?;

        // Coalesce contiguous runs of blocks inside this op to issue big sequential writes!
        let mut src_off = 0usize;
        for ext in &op.dst_extents {
            let mut b = 0usize;
            let n = ext.num_blocks as usize;
            while b < n {
                let blk_idx = ext.start_block as usize + b;
                let super_off = if blk_idx < blk_to_super.len() {
                    blk_to_super[blk_idx]
                } else {
                    u64::MAX
                };
                if super_off == u64::MAX {
                    b += 1;
                    src_off += bs_u;
                    continue;
                }
                // Extend contiguous run in both logical op_buf and physical super_off
                let run_start_src = src_off;
                let mut run_blks = 1usize;
                while b + run_blks < n {
                    let next_idx = ext.start_block as usize + b + run_blks;
                    if next_idx < blk_to_super.len()
                        && blk_to_super[next_idx] == super_off + (run_blks as u64) * bs
                    {
                        run_blks += 1;
                    } else {
                        break;
                    }
                }
                let run_bytes = run_blks * bs_u;
                super_rw
                    .seek(SeekFrom::Start(super_off))
                    .map_err(|e| format!("seek super@{super_off}: {e}"))?;
                super_rw
                    .write_all(&op_buf[run_start_src..run_start_src + run_bytes])
                    .map_err(|e| format!("write super {}: {e}", pu.name))?;
                for r in 0..run_blks {
                    blk_to_super[ext.start_block as usize + b + r] = u64::MAX;
                }
                *total_written += run_bytes as u64;
                b += run_blks;
                src_off += run_bytes;
            }
        }

        let elapsed_s = write_start.elapsed().as_secs_f64().max(0.001);
        let written_now = *total_written;
        let bps = (written_now as f64 / elapsed_s) as u64;
        let eta = if bps > 0 && total_bytes_to_write > written_now {
            ((total_bytes_to_write - written_now) / bps) as i64
        } else {
            0
        };
        update_prog(&|g| {
            g.bytes_written = written_now;
            g.speed_bps = bps;
            g.eta_seconds = eta;
        });
    }

    // Zero-fill any allocated blocks not explicitly covered by a payload op (e.g. sparse tail holes).
    let mut b = 0usize;
    while b < blk_to_super.len() {
        let super_off = blk_to_super[b];
        if super_off == u64::MAX {
            b += 1;
            continue;
        }
        let mut run_blks = 1usize;
        while b + run_blks < blk_to_super.len()
            && blk_to_super[b + run_blks] == super_off + (run_blks as u64) * bs
        {
            run_blks += 1;
        }
        super_rw
            .seek(SeekFrom::Start(super_off))
            .map_err(|e| format!("seek super tail zero@{super_off}: {e}"))?;
        let mut rem_blks = run_blks;
        while rem_blks > 0 {
            super_rw
                .write_all(&zero_blk)
                .map_err(|e| format!("write super tail zero {}: {e}", pu.name))?;
            rem_blks -= 1;
            *total_written += bs;
        }
        b += run_blks;
    }
    Ok(())
}

/// Stream-write a raw inactive A/B partition (`boot`, `dtbo`, `vendor_boot`, `modem`, etc.)
/// op-by-op using ~2 MiB peak RAM + `fsync`.
fn stream_write_raw_partition(
    payload_file: &mut File,
    dev_path: &Path,
    manifest: &PayloadManifest,
    pu: &PartitionUpdate,
    total_written: &mut u64,
    write_start: Instant,
    update_prog: &dyn Fn(&dyn Fn(&mut OtaProgress)),
    cancel: Option<&AtomicBool>,
) -> Result<(), String> {
    let bs = manifest.block_size;
    let bs_u = bs as usize;
    let mut dev = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| format!("open rw {}: {e}", dev_path.display()))?;

    let mut blob_buf: Vec<u8> = Vec::new();
    let mut op_buf: Vec<u8> = Vec::new();
    let zero_chunk = vec![0u8; 256 * 1024];

    for (oi, op) in pu.operations.iter().enumerate() {
        if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
            return Err("OTA cancelled by user".into());
        }
        if op.op_type == OpType::Zero || op.op_type == OpType::Discard {
            for ext in &op.dst_extents {
                let start_off = ext.start_block * bs;
                if start_off >= pu.new_info.size {
                    continue;
                }
                let mut rem = (ext.num_blocks * bs).min(pu.new_info.size - start_off);
                dev.seek(SeekFrom::Start(start_off))
                    .map_err(|e| format!("seek raw zero {}: {e}", dev_path.display()))?;
                while rem > 0 {
                    let take = (rem as usize).min(zero_chunk.len());
                    dev.write_all(&zero_chunk[..take])
                        .map_err(|e| format!("write raw zero {}: {e}", dev_path.display()))?;
                    rem -= take as u64;
                    *total_written += take as u64;
                }
            }
            continue;
        }

        let dst_bytes = (op.total_dst_blocks() as usize) * bs_u;
        blob_buf.resize(op.data_length as usize, 0);
        payload_file
            .seek(SeekFrom::Start(manifest.data_blob_offset + op.data_offset))
            .map_err(|e| format!("seek raw blob {} op#{oi}: {e}", pu.name))?;
        payload_file
            .read_exact(&mut blob_buf)
            .map_err(|e| format!("read raw blob {} op#{oi}: {e}", pu.name))?;
        if let Some(exp_hash) = op.data_sha256 {
            if sha256_bytes(&blob_buf) != exp_hash {
                return Err(format!("{}: raw op#{oi} blob SHA-256 mismatch", pu.name));
            }
        }
        op_buf.resize(dst_bytes, 0);
        decode_op_into(op.op_type, &blob_buf, &mut op_buf)
            .map_err(|e| format!("{} raw op#{oi}: {e}", pu.name))?;

        let mut src_off = 0usize;
        for ext in &op.dst_extents {
            let start_off = ext.start_block * bs;
            let len_full = (ext.num_blocks as usize) * bs_u;
            if start_off < pu.new_info.size {
                let write_len = (len_full as u64).min(pu.new_info.size - start_off) as usize;
                dev.seek(SeekFrom::Start(start_off))
                    .map_err(|e| format!("seek raw {}: {e}", dev_path.display()))?;
                dev.write_all(&op_buf[src_off..src_off + write_len])
                    .map_err(|e| format!("write raw {}: {e}", dev_path.display()))?;
                *total_written += write_len as u64;
            }
            src_off += len_full;
        }
        let elapsed_s = write_start.elapsed().as_secs_f64().max(0.001);
        let written_now = *total_written;
        let bps = (written_now as f64 / elapsed_s) as u64;
        update_prog(&|g| {
            g.bytes_written = written_now;
            g.speed_bps = bps;
        });
    }
    dev.sync_data()
        .map_err(|e| format!("fsync {}: {e}", dev_path.display()))?;
    Ok(())
}

/// Verify a dynamic partition by reading its virtual image through its exact planned `LpExtent` list
/// (combining active-slot `Alias` sectors + `ZERO` extents + newly written `super` sectors)!
fn verify_dynamic_extents_sha256(
    super_file: &mut File,
    extents: &[LpExtent],
    exact_size: u64,
) -> Result<[u8; 32], String> {
    let mut h = Sha256::new();
    let mut rem = exact_size;
    let mut buf = vec![0u8; 4 * 1024 * 1024];

    for ext in extents {
        if rem == 0 {
            break;
        }
        let ext_bytes = (ext.num_sectors * LP_SECTOR_SIZE).min(rem);
        match ext.target_type {
            LP_TARGET_TYPE_ZERO => {
                h.update_zeros(ext_bytes);
                rem -= ext_bytes;
            }
            LP_TARGET_TYPE_LINEAR => {
                super_file
                    .seek(SeekFrom::Start(ext.target_data * LP_SECTOR_SIZE))
                    .map_err(|e| format!("verify seek super: {e}"))?;
                let mut left = ext_bytes;
                while left > 0 {
                    let take = (left as usize).min(buf.len());
                    super_file
                        .read_exact(&mut buf[..take])
                        .map_err(|e| format!("verify read super: {e}"))?;
                    h.update(&buf[..take]);
                    left -= take as u64;
                }
                rem -= ext_bytes;
            }
            other => return Err(format!("Unknown LpExtent target_type {other}")),
        }
    }
    if rem != 0 {
        return Err(format!("Extents shorter than partition size by {rem} bytes"));
    }
    Ok(h.finalize())
}

fn read_raw_partition_hash(dev_path: &Path, exact_size: u64) -> Result<[u8; 32], String> {
    let mut f = File::open(dev_path).map_err(|e| format!("open {}: {e}", dev_path.display()))?;
    let mut h = Sha256::new();
    let mut rem = exact_size;
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    while rem > 0 {
        let take = (rem as usize).min(buf.len());
        f.read_exact(&mut buf[..take])
            .map_err(|e| format!("read {}: {e}", dev_path.display()))?;
        h.update(&buf[..take]);
        rem -= take as u64;
    }
    Ok(h.finalize())
}

/// Active-slot extents, new size and new SHA-256 of a whole-partition alias candidate.
type Layer1Job = (Vec<LpExtent>, u64, [u8; 32]);

/// Runs `f` over `items` on up to `workers` threads, preserving order.
fn parallel_map<T: Sync, R: Send>(items: &[T], workers: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    thread::scope(|s| {
        for _ in 0..workers.clamp(1, items.len().max(1)) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= items.len() {
                    break;
                }
                let r = f(&items[i]);
                out.lock().unwrap()[i] = Some(r);
            });
        }
    });
    out.into_inner().unwrap().into_iter().map(|r| r.expect("parallel_map slot")).collect()
}

fn io_workers(opts: &OtaOptions) -> usize {
    let auto = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let cap = if opts.max_threads == 0 { 8 } else { opts.max_threads };
    auto.min(cap).max(1)
}

const PLAN_CACHE_MAGIC: &[u8; 4] = b"YSPC";
const PLAN_CACHE_VERSION: u32 = 1;

type CachedDynamicPlan = (Vec<OtaPartitionExtentSpec>, usize, u64);

fn plan_cache_key(
    manifest_sha: &[u8; 32],
    active_slot: u32,
    super_hdr: &[u8],
    live_occupied: &[(u64, u64)],
    preserve_scratch: bool,
    opts: &OtaOptions,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(crate::PASANG_VERSION.as_bytes());
    h.update(manifest_sha);
    h.update(&active_slot.to_le_bytes());
    h.update(super_hdr);
    for (a, b) in live_occupied {
        h.update(&a.to_le_bytes());
        h.update(&b.to_le_bytes());
    }
    h.update(&[preserve_scratch as u8, opts.enable_extent_aliasing as u8]);
    h.update(&opts.min_alias_blocks.to_le_bytes());
    h.finalize()
}

fn save_plan_cache(
    path: &Path,
    key: &[u8; 32],
    specs: &[OtaPartitionExtentSpec],
    whole_skipped: usize,
    dyn_bytes_skipped: u64,
) -> std::io::Result<()> {
    let mut b = Vec::with_capacity(4096);
    b.extend_from_slice(PLAN_CACHE_MAGIC);
    b.extend_from_slice(&PLAN_CACHE_VERSION.to_le_bytes());
    b.extend_from_slice(key);
    b.extend_from_slice(&(whole_skipped as u64).to_le_bytes());
    b.extend_from_slice(&dyn_bytes_skipped.to_le_bytes());
    b.extend_from_slice(&(specs.len() as u32).to_le_bytes());
    for sp in specs {
        b.extend_from_slice(&(sp.base_name.len() as u16).to_le_bytes());
        b.extend_from_slice(sp.base_name.as_bytes());
        b.extend_from_slice(&sp.total_bytes.to_le_bytes());
        b.extend_from_slice(&(sp.runs.len() as u32).to_le_bytes());
        for run in &sp.runs {
            match *run {
                LogicalRun::Alias { phys_start_sector, num_sectors } => {
                    b.push(0);
                    b.extend_from_slice(&phys_start_sector.to_le_bytes());
                    b.extend_from_slice(&num_sectors.to_le_bytes());
                }
                LogicalRun::Zero { num_sectors } => {
                    b.push(1);
                    b.extend_from_slice(&num_sectors.to_le_bytes());
                }
                LogicalRun::Allocate { num_sectors } => {
                    b.push(2);
                    b.extend_from_slice(&num_sectors.to_le_bytes());
                }
            }
        }
    }
    let digest = sha256_bytes(&b);
    b.extend_from_slice(&digest);
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &b)?;
    fs::rename(&tmp, path)
}

fn load_plan_cache(path: &Path, key: &[u8; 32]) -> Option<CachedDynamicPlan> {
    let raw = fs::read(path).ok()?;
    if raw.len() < 32 {
        return None;
    }
    let (body, digest) = raw.split_at(raw.len() - 32);
    if sha256_bytes(body) != digest {
        return None;
    }
    let mut pos = 0usize;
    let mut take = |n: usize| -> Option<&[u8]> {
        let s = body.get(pos..pos + n)?;
        pos += n;
        Some(s)
    };
    if take(4)? != PLAN_CACHE_MAGIC {
        return None;
    }
    let u32_of = |s: &[u8]| u32::from_le_bytes(s.try_into().unwrap());
    let u64_of = |s: &[u8]| u64::from_le_bytes(s.try_into().unwrap());
    if u32_of(take(4)?) != PLAN_CACHE_VERSION || take(32)? != key {
        return None;
    }
    let whole_skipped = u64_of(take(8)?) as usize;
    let dyn_bytes = u64_of(take(8)?);
    let n = u32_of(take(4)?) as usize;
    let mut specs = Vec::with_capacity(n);
    for _ in 0..n {
        let nl = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let base_name = String::from_utf8(take(nl)?.to_vec()).ok()?;
        let total_bytes = u64_of(take(8)?);
        let nr = u32_of(take(4)?) as usize;
        let mut runs = Vec::with_capacity(nr);
        for _ in 0..nr {
            runs.push(match take(1)?[0] {
                0 => LogicalRun::Alias {
                    phys_start_sector: u64_of(take(8)?),
                    num_sectors: u64_of(take(8)?),
                },
                1 => LogicalRun::Zero { num_sectors: u64_of(take(8)?) },
                2 => LogicalRun::Allocate { num_sectors: u64_of(take(8)?) },
                _ => return None,
            });
        }
        specs.push(OtaPartitionExtentSpec { base_name, total_bytes, runs });
    }
    Some((specs, whole_skipped, dyn_bytes))
}

/// Core 9-step Atomic In-OS CoW OTA execution (both dry-run plan and real apply!).
pub fn run_ota(
    env: &OtaEnvironment,
    bootctl: &dyn BootControlOps,
    ota_path: &Path,
    opts: &OtaOptions,
    progress: Option<&Mutex<OtaProgress>>,
    cancel: Option<&AtomicBool>,
) -> Result<OtaApplyResult, String> {
    let t0 = Instant::now();
    let check_cancel = || -> Result<(), String> {
        if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
            if let Some(p) = progress {
                if let Ok(mut g) = p.lock() {
                    g.phase = OtaPhase::Cancelled;
                }
            }
            return Err("OTA cancelled by user".into());
        }
        Ok(())
    };
    let update_prog = |f: &dyn Fn(&mut OtaProgress)| {
        if let Some(p) = progress {
            if let Ok(mut g) = p.lock() {
                g.elapsed_ms = t0.elapsed().as_millis() as u64;
                f(&mut g);
            }
        }
    };

    // ====================================================================
    // STEP 1: Pre-flight Gate + Super Metadata Read & Pre-Flash Backup
    // ====================================================================
    update_prog(&|g| {
        *g = OtaProgress::default();
        g.phase = OtaPhase::Preflight;
    });

    let active_slot = bootctl.current_slot()?;
    if active_slot > 1 {
        return Err(format!("Invalid current_slot={active_slot}"));
    }
    let target_slot = 1 - active_slot;
    let active_suffix = slot_suffix(active_slot);
    let target_suffix = slot_suffix(target_slot);

    let merge_status = bootctl.snapshot_merge_status();
    if merge_status != "none" && merge_status != "unknown" {
        return Err(format!(
            "Virtual A/B snapshot merge is active (`{merge_status}`); wait for merge to finish"
        ));
    }

    update_prog(&|g| {
        g.active_slot = active_slot;
        g.target_slot = target_slot;
    });

    // Read 1 MiB super header
    let mut super_ro = File::open(&env.super_device)
        .map_err(|e| format!("open super {}: {e}", env.super_device.display()))?;
    let mut super_hdr = vec![0u8; 1024 * 1024];
    super_ro
        .read_exact(&mut super_hdr)
        .map_err(|e| format!("read 1 MiB super header: {e}"))?;
    let geom = parse_geometry(&super_hdr)?;
    let active_meta: LpMetadata = parse_slot_metadata(&super_hdr, &geom, active_slot)?;

    // Snapshot original 1 MiB super metadata before mutating anything
    if opts.backup_last_good && !opts.dry_run {
        let last_good = env.metadata_dir.join("last_good");
        fs::create_dir_all(&last_good)
            .map_err(|e| format!("mkdir {}: {e}", last_good.display()))?;
        fs::write(last_good.join("super_meta.bin"), &super_hdr)
            .map_err(|e| format!("backup super_meta.bin: {e}"))?;
    }

    // ====================================================================
    // STEP 2: Zero-Unpack Payload Open + Manifest Parse + RSA Signature Gate
    // ====================================================================
    let mut payload_file = File::open(ota_path)
        .map_err(|e| format!("open OTA {}: {e}", ota_path.display()))?;
    let manifest = parse_payload(&mut payload_file)?;
    let sig_ok = verify_metadata_signatures(
        &manifest.metadata_sha256,
        &manifest.metadata_signatures,
        &env.otacerts_path,
        opts.allow_dev_key,
    )?;

    check_cancel()?;

    // Mounted scratch stays protected so the running slot keeps working until reboot. fs_mgr maps
    // scratch from the booting slot's metadata, so the target slot lists it only where the old
    // upperdirs still fit the new lowers: on `keep_overlay`, or for a partial payload, which
    // carries every partition it does not rewrite byte for byte (the upperdirs of the ones it
    // rewrites are cleared after the commit). A full OTA boots without old-build upperdirs.
    let ovl_status = inspect_overlays(&env.proc_mounts_path, &env.scratch_overlay_root);
    let mut effective_live_occupied = env.live_dm_occupied.clone();
    if ovl_status.scratch_mounted {
        if let Some(sp) = active_meta.partitions.iter().find(|p| p.name == "scratch") {
            for e in active_meta.partition_extents(sp) {
                if e.target_type == LP_TARGET_TYPE_LINEAR && e.target_source == 0 {
                    effective_live_occupied.push((e.target_data, e.target_data + e.num_sectors));
                }
            }
        }
    }
    let preserve_scratch =
        ovl_status.scratch_mounted && (opts.keep_overlay || manifest.partial_update);

    // Load cached slot hashes & resume state
    let slot_cache_path = env.metadata_dir.join("slot_state.bin");
    let resume_path = env.metadata_dir.join("resume.bin");
    let mut slot_cache = SlotStateCache::load_or_default(&slot_cache_path);
    let resume_done: HashSet<String> = fs::read(&resume_path)
        .ok()
        .and_then(|b| ResumeState::from_bytes(&b).ok())
        .filter(|r| r.manifest_sha256 == manifest.metadata_sha256 && r.target_slot == target_slot)
        .map(|r| r.completed_partitions.into_iter().collect())
        .unwrap_or_default();

    let mut dynamic_updates: Vec<&PartitionUpdate> = Vec::new();
    let mut raw_updates: Vec<&PartitionUpdate> = Vec::new();
    let active_has = |base: &str| {
        let n = format!("{base}{active_suffix}");
        active_meta.partitions.iter().any(|p| p.name == n)
    };
    for pu in &manifest.partitions {
        if manifest.dynamic_metadata.is_dynamic(&pu.name) || active_has(&pu.name) {
            dynamic_updates.push(pu);
        } else {
            raw_updates.push(pu);
        }
    }

    let total_logical: u64 = manifest.partitions.iter().map(|p| p.new_info.size).sum();
    update_prog(&|g| {
        g.phase = OtaPhase::Indexing;
        g.partitions_total = manifest.partitions.len();
        g.bytes_total_logical = total_logical;
    });

    // ====================================================================
    // STEP 3 & 4: Low-RAM Per-Partition Indexing + Layer 1/2 Extent Alias Planning (~25 MB peak RAM!)
    // ====================================================================
    update_prog(&|g| g.phase = OtaPhase::Planning);

    // Indexing is the slow part and depends only on the payload, the active slot and the
    // allocation inputs, so a dry run leaves its result for the apply that follows it.
    let plan_key = plan_cache_key(
        &manifest.metadata_sha256,
        active_slot,
        &super_hdr,
        &effective_live_occupied,
        preserve_scratch,
        opts,
    );
    let plan_cache_path = env.metadata_dir.join("plan_cache.bin");
    let cached_specs = load_plan_cache(&plan_cache_path, &plan_key)
        .filter(|c| c.0.len() == dynamic_updates.len());
    let reused_plan = cached_specs.is_some();
    let (dynamic_specs, whole_skipped_count, dyn_bytes_skipped_whole) = if let Some(c) = cached_specs {
        c
    } else {
        // Layer-1 candidates are read and hashed in parallel. A cache entry that disagrees with the
        // new hash proves a change without reading; a cache entry that agrees is still verified,
        // since super can be rewritten behind pasang (kernel CoW install, recovery flash).
        let layer1_jobs: Vec<Option<Layer1Job>> = dynamic_updates
            .iter()
            .map(|pu| {
                let new_hash = pu.new_info.hash?;
                let ap = active_meta
                    .partitions
                    .iter()
                    .find(|p| p.name == format!("{}{active_suffix}", pu.name))?;
                let exts = active_meta.partition_extents(ap);
                let all_linear = exts.iter().all(|e| e.target_type == LP_TARGET_TYPE_LINEAR);
                let active_sz: u64 = exts.iter().map(|e| e.num_sectors * LP_SECTOR_SIZE).sum();
                if !all_linear || active_sz != align_up(pu.new_info.size, LP_BLOCK_SIZE) {
                    return None;
                }
                let known_changed = slot_cache
                    .slot_map(active_slot)
                    .get(&pu.name)
                    .is_some_and(|c| c.size != pu.new_info.size || c.sha256 != new_hash);
                if known_changed {
                    return None;
                }
                Some((exts.to_vec(), pu.new_info.size, new_hash))
            })
            .collect();
        update_prog(&|g| g.current_partition = "layer1-verify".into());
        let layer1_match: Vec<bool> = parallel_map(&layer1_jobs, io_workers(opts), |job| {
            let Some((exts, size, hash)) = job else {
                return false;
            };
            File::open(&env.super_device)
                .ok()
                .and_then(|mut f| verify_dynamic_extents_sha256(&mut f, exts, *size).ok())
                .is_some_and(|h| h == *hash)
        });
        check_cancel()?;

        let mut dynamic_specs: Vec<OtaPartitionExtentSpec> = Vec::with_capacity(dynamic_updates.len());
        let mut whole_skipped_count = 0usize;
        let mut dyn_bytes_skipped_whole = 0u64;

        for (di, pu) in dynamic_updates.iter().enumerate() {
            check_cancel()?;
            update_prog(&|g| {
                g.phase = OtaPhase::Indexing;
                g.current_partition = format!("{} ({}/{})", pu.name, di + 1, dynamic_updates.len());
                g.partitions_done = di;
            });
            let active_name = format!("{}{active_suffix}", pu.name);
            let active_part = active_meta
                .partitions
                .iter()
                .find(|p| p.name == active_name);

            // Layer 1: Whole-Partition Exact SHA-256 Match -> 100% Alias, 0 bytes decoded/written!
            let mut whole_aliased = false;
            if let (Some(ap), true) = (active_part, layer1_match[di]) {
                let active_exts = active_meta.partition_extents(ap);
                {
                    let runs: Vec<LogicalRun> = active_exts
                        .iter()
                        .map(|e| LogicalRun::Alias {
                            phys_start_sector: e.target_data,
                            num_sectors: e.num_sectors,
                        })
                        .collect();
                    dynamic_specs.push(OtaPartitionExtentSpec {
                        base_name: pu.name.clone(),
                        total_bytes: pu.new_info.size,
                        runs,
                    });
                    whole_skipped_count += 1;
                    dyn_bytes_skipped_whole += pu.new_info.size;
                    whole_aliased = true;
                }
            }

            if whole_aliased {
                continue;
            }

            let padded_blocks = align_up(pu.new_info.size, LP_BLOCK_SIZE) / LP_BLOCK_SIZE;
            let runs = if opts.enable_extent_aliasing {
                if let Some(ap) = active_part {
                    update_prog(&|g| g.phase = OtaPhase::Indexing);
                    let exts = active_meta.partition_extents(ap);
                    let est_blocks = (exts.iter().map(|e| e.num_sectors).sum::<u64>() / LP_SECTORS_PER_BLOCK) as usize;
                    let mut part_index = ActiveBlockIndex::with_capacity(est_blocks);
                    part_index.index_super_extents_parallel(&mut super_ro, exts)?;
                    check_cancel()?;

                    update_prog(&|g| g.phase = OtaPhase::Planning);
                    let new_keys = stream_index_partition_blocks(&mut payload_file, &manifest, pu, cancel)?;
                    let (runs, _stats) =
                        build_extent_alias_runs(&new_keys, &part_index, opts.min_alias_blocks);
                    runs
                } else {
                    vec![LogicalRun::Allocate {
                        num_sectors: padded_blocks * LP_SECTORS_PER_BLOCK,
                    }]
                }
            } else {
                vec![LogicalRun::Allocate {
                    num_sectors: padded_blocks * LP_SECTORS_PER_BLOCK,
                }]
            };

            dynamic_specs.push(OtaPartitionExtentSpec {
                base_name: pu.name.clone(),
                total_bytes: pu.new_info.size,
                runs,
            });
        }
        (dynamic_specs, whole_skipped_count, dyn_bytes_skipped_whole)
    };
    let mut whole_skipped_count = whole_skipped_count;
    let mut bytes_skipped_whole = dyn_bytes_skipped_whole;
    if opts.dry_run && !reused_plan {
        let _ = fs::create_dir_all(&env.metadata_dir);
        let _ = save_plan_cache(
            &plan_cache_path,
            &plan_key,
            &dynamic_specs,
            whole_skipped_count,
            dyn_bytes_skipped_whole,
        );
    }

    // Partial payload: every active-slot dynamic partition it does not touch is aliased
    // as-is into the target slot.
    let mut dynamic_specs = dynamic_specs;
    let mut carried_dynamic: Vec<(String, Vec<LpExtent>)> = Vec::new();
    if manifest.partial_update {
        if env.ab_partitions.is_empty() {
            return Err("Partial payload needs ro.product.ab_ota_partitions to carry raw partitions".into());
        }
        let in_payload = |n: &str| manifest.partitions.iter().any(|p| p.name == n);
        if !in_payload("vbmeta") {
            let flags = read_vbmeta_flags(&env.by_name_dir.join(format!("vbmeta{active_suffix}")));
            if flags.is_some_and(|f| f & 3 != 3) {
                return Err(
                    "Partial payload without vbmeta needs AVB verification and hashtree disabled \
                     (vbmeta --flags 3) on the active slot"
                        .into(),
                );
            }
        }
        for p in &active_meta.partitions {
            let Some(base) = p.name.strip_suffix(active_suffix) else {
                continue;
            };
            if dynamic_updates.iter().any(|u| u.name == base) {
                continue;
            }
            let exts = active_meta.partition_extents(p).to_vec();
            if exts.iter().any(|e| e.target_type != LP_TARGET_TYPE_LINEAR || e.target_source != 0) {
                return Err(format!("Cannot carry over {}: non-linear extents", p.name));
            }
            let bytes: u64 = exts.iter().map(|e| e.num_sectors * LP_SECTOR_SIZE).sum();
            if bytes % LP_BLOCK_SIZE != 0 {
                return Err(format!("Cannot carry over {}: size {bytes} not 4 KiB aligned", p.name));
            }
            dynamic_specs.push(OtaPartitionExtentSpec {
                base_name: base.to_string(),
                total_bytes: bytes,
                runs: exts
                    .iter()
                    .map(|e| LogicalRun::Alias {
                        phys_start_sector: e.target_data,
                        num_sectors: e.num_sectors,
                    })
                    .collect(),
            });
            carried_dynamic.push((base.to_string(), exts));
        }
    }
    let carried_dynamic_bytes: u64 = carried_dynamic
        .iter()
        .map(|(_, e)| e.iter().map(|x| x.num_sectors * LP_SECTOR_SIZE).sum::<u64>())
        .sum();

    // Plan super extents for all dynamic partitions!
    let super_plan: OtaSuperPlan = plan_ota_inactive_slot(
        &super_hdr,
        active_slot,
        &dynamic_specs,
        &effective_live_occupied,
        preserve_scratch,
        ExtentLimits {
            min_alias_sectors: opts.min_alias_blocks * LP_SECTORS_PER_BLOCK,
            ..ExtentLimits::default()
        },
    )?;

    // Check raw A/B partitions (Layer 1 whole-partition skip against existing target slot!)
    let mut raw_to_write: Vec<(&PartitionUpdate, PathBuf)> = Vec::new();
    let mut raw_bytes_to_write = 0u64;
    let mut raw_candidates: Vec<(&PartitionUpdate, PathBuf)> = Vec::new();
    for pu in &raw_updates {
        let target_dev = env.by_name_dir.join(format!("{}{target_suffix}", pu.name));
        let active_dev = env.by_name_dir.join(format!("{}{active_suffix}", pu.name));
        let dev = if target_dev.exists() {
            target_dev
        } else if active_dev.exists() {
            // Non-A/B partition fallback if needed (never touch mounted active partitions)
            return Err(format!(
                "Target inactive raw partition missing: {}",
                target_dev.display()
            ));
        } else {
            // Skip optional firmware partition absent on this device variant
            continue;
        };

        raw_candidates.push((pu, dev));
    }

    // The target slot is never trusted from cache: recovery and fastboot write it behind pasang.
    update_prog(&|g| g.current_partition = "raw-compare".into());
    let raw_matches: Vec<bool> = parallel_map(&raw_candidates, io_workers(opts), |(pu, dev)| {
        if resume_done.contains(&pu.name) {
            return true;
        }
        pu.new_info
            .hash
            .is_some_and(|exp| read_raw_partition_hash(dev, pu.new_info.size).is_ok_and(|h| h == exp))
    });
    check_cancel()?;

    for ((pu, dev), already_matches) in raw_candidates.into_iter().zip(raw_matches) {
        if already_matches {
            whole_skipped_count += 1;
            bytes_skipped_whole += pu.new_info.size;
        } else {
            raw_bytes_to_write += pu.new_info.size;
            raw_to_write.push((pu, dev));
        }
    }

    // Partial payload: raw A/B partitions it does not include must match the active slot.
    let mut raw_carry: Vec<(String, PathBuf, PathBuf, u64)> = Vec::new();
    let mut raw_carried_hashes: Vec<(String, u64, [u8; 32])> = Vec::new();
    if manifest.partial_update {
        let mut pairs: Vec<(String, PathBuf, PathBuf, u64)> = Vec::new();
        for name in &env.ab_partitions {
            if manifest.partitions.iter().any(|p| &p.name == name) || active_has(name) {
                continue;
            }
            let src = env.by_name_dir.join(format!("{name}{active_suffix}"));
            let dst = env.by_name_dir.join(format!("{name}{target_suffix}"));
            if !src.exists() || !dst.exists() {
                continue;
            }
            let size = block_dev_size(&src)?;
            if block_dev_size(&dst)? < size {
                return Err(format!("{} smaller than {}", dst.display(), src.display()));
            }
            pairs.push((name.clone(), src, dst, size));
        }
        update_prog(&|g| g.current_partition = "carry-compare".into());
        let hashes: Vec<Result<([u8; 32], [u8; 32]), String>> =
            parallel_map(&pairs, io_workers(opts), |(_, src, dst, size)| {
                Ok((read_raw_partition_hash(src, *size)?, read_raw_partition_hash(dst, *size)?))
            });
        check_cancel()?;
        for (pair, h) in pairs.into_iter().zip(hashes) {
            let (hs, hd) = h?;
            raw_carried_hashes.push((pair.0.clone(), pair.3, hs));
            if hs != hd {
                raw_carry.push(pair);
            }
        }
    }
    let raw_carry_bytes: u64 = raw_carry.iter().map(|c| c.3).sum();

    let total_bytes_to_write = super_plan.total_bytes_to_write + raw_bytes_to_write + raw_carry_bytes;
    let plan_summary = OtaPlanSummary {
        active_slot,
        target_slot,
        signature_verified: sig_ok,
        dynamic_partitions: dynamic_updates.len(),
        raw_partitions: raw_updates.len(),
        whole_skipped_partitions: whole_skipped_count,
        bytes_total_logical: total_logical,
        bytes_aliased: super_plan
            .total_bytes_aliased
            .saturating_sub(dyn_bytes_skipped_whole + carried_dynamic_bytes),
        bytes_zeroed: super_plan.total_bytes_zeroed,
        bytes_skipped_whole,
        bytes_to_write: total_bytes_to_write,
        total_extents: super_plan.total_extents,
        free_super_before: super_plan.free_bytes_before,
        free_super_after: super_plan.free_bytes_after,
        overlay_files_present: ovl_status.total_files,
        partial_update: manifest.partial_update,
        carried_partitions: carried_dynamic.len() + raw_carried_hashes.len(),
        carried_bytes_copied: raw_carry_bytes,
    };

    update_prog(&|g| {
        g.bytes_aliased = plan_summary.bytes_aliased;
        g.bytes_zeroed = plan_summary.bytes_zeroed;
        g.bytes_skipped_whole = plan_summary.bytes_skipped_whole;
        g.bytes_to_write = plan_summary.bytes_to_write;
        g.total_extents = plan_summary.total_extents;
    });

    if opts.dry_run {
        update_prog(&|g| g.phase = OtaPhase::Done);
        return Ok(OtaApplyResult {
            plan: plan_summary,
            elapsed_ms: t0.elapsed().as_millis() as u64,
            bytes_written: 0,
            overlay_clean: None,
            committed_slot: target_slot,
        });
    }

    // ====================================================================
    // STEP 5: Stream-Write Delta Segments to Free `super` Sectors & Raw Inactive Partitions
    // ====================================================================
    update_prog(&|g| g.phase = OtaPhase::Flashing);
    let write_start = Instant::now();
    let mut total_written = 0u64;
    let mut parts_done = whole_skipped_count;
    let mut completed_for_resume: Vec<String> = resume_done.into_iter().collect();

    let mut super_rw = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&env.super_device)
        .map_err(|e| format!("open rw super {}: {e}", env.super_device.display()))?;

    for pp in &super_plan.partitions {
        check_cancel()?;
        if pp.write_segments.is_empty() {
            continue;
        }
        update_prog(&|g| {
            g.current_partition = pp.target_name.clone();
            g.partitions_done = parts_done;
        });

        if let Some((_, src)) = carried_dynamic.iter().find(|(b, _)| *b == pp.base_name) {
            copy_carried_segments(&mut super_rw, src, &pp.write_segments, &mut total_written)?;
            continue;
        }

        let pu = dynamic_updates
            .iter()
            .copied()
            .find(|u| u.name == pp.base_name)
            .ok_or_else(|| format!("Internal error: missing PartitionUpdate for {}", pp.base_name))?;

        stream_write_dynamic_partition(
            &mut payload_file,
            &mut super_rw,
            &manifest,
            pu,
            &pp.write_segments,
            &mut total_written,
            total_bytes_to_write,
            write_start,
            &update_prog,
            cancel,
        )?;

        parts_done += 1;
        completed_for_resume.push(pp.base_name.clone());
        let rs = ResumeState {
            manifest_sha256: manifest.metadata_sha256,
            target_slot,
            completed_partitions: completed_for_resume.clone(),
        };
        let _ = fs::create_dir_all(&env.metadata_dir);
        let _ = fs::write(&resume_path, rs.to_bytes());
    }
    super_rw
        .sync_data()
        .map_err(|e| format!("fsync super data: {e}"))?;

    for (pu, dev_path) in &raw_to_write {
        check_cancel()?;
        update_prog(&|g| {
            g.current_partition = format!("{}{target_suffix}", pu.name);
            g.partitions_done = parts_done;
        });
        stream_write_raw_partition(
            &mut payload_file,
            dev_path,
            &manifest,
            pu,
            &mut total_written,
            write_start,
            &update_prog,
            cancel,
        )?;
        parts_done += 1;
        update_prog(&|g| g.partitions_done = parts_done);
        completed_for_resume.push(pu.name.clone());
        let rs = ResumeState {
            manifest_sha256: manifest.metadata_sha256,
            target_slot,
            completed_partitions: completed_for_resume.clone(),
        };
        let _ = fs::write(&resume_path, rs.to_bytes());
    }

    for (name, src, dst, size) in &raw_carry {
        check_cancel()?;
        update_prog(&|g| g.current_partition = format!("carry {name}{target_suffix}"));
        copy_raw_partition(src, dst, *size, &mut total_written)?;
    }

    // ====================================================================
    // STEP 6 & 7: Full Readback SHA-256 Verification + AVB Sanity Check
    // ====================================================================
    update_prog(&|g| {
        g.phase = OtaPhase::Verifying;
        g.current_partition = "readback-sha256".into();
    });

    if !opts.fast_verify {
        // Verify all dynamic partitions in parallel (each opens its own RO super fd, hardware sha256-ce)
        let dyn_jobs: Vec<(&crate::lp::PlannedDynamicPartition, u64, [u8; 32])> = super_plan
            .partitions
            .iter()
            .filter_map(|pp| {
                let pu = dynamic_updates.iter().find(|u| u.name == pp.base_name)?;
                let exp = pu.new_info.hash?;
                Some((pp, pu.new_info.size, exp))
            })
            .collect();
        let next_v = AtomicUsize::new(0);
        let v_err: Mutex<Option<String>> = Mutex::new(None);
        let v_workers = thread::available_parallelism()
            .map(|n| n.get().clamp(1, 4))
            .unwrap_or(4)
            .min(dyn_jobs.len().max(1));
        thread::scope(|s| {
            for _ in 0..v_workers {
                s.spawn(|| loop {
                    if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
                        let mut g = v_err.lock().unwrap();
                        if g.is_none() {
                            *g = Some("OTA cancelled by user".into());
                        }
                        break;
                    }
                    if v_err.lock().unwrap().is_some() {
                        break;
                    }
                    let idx = next_v.fetch_add(1, Ordering::Relaxed);
                    if idx >= dyn_jobs.len() {
                        break;
                    }
                    let (pp, sz, exp_hash) = dyn_jobs[idx];
                    update_prog(&|g| g.current_partition = format!("verify {}", pp.target_name));
                    let mut sf = match File::open(&env.super_device) {
                        Ok(f) => f,
                        Err(e) => {
                            let mut g = v_err.lock().unwrap();
                            if g.is_none() {
                                *g = Some(format!("open super verify {}: {e}", pp.target_name));
                            }
                            break;
                        }
                    };
                    match verify_dynamic_extents_sha256(&mut sf, &pp.extents, sz) {
                        Ok(got) if got == exp_hash => {}
                        Ok(got) => {
                            let mut g = v_err.lock().unwrap();
                            if g.is_none() {
                                *g = Some(format!(
                                    "ABORT BEFORE COMMIT: readback SHA-256 mismatch on {} (exp={} got={})",
                                    pp.target_name,
                                    hex_encode(&exp_hash),
                                    hex_encode(&got)
                                ));
                            }
                            break;
                        }
                        Err(e) => {
                            let mut g = v_err.lock().unwrap();
                            if g.is_none() {
                                *g = Some(e);
                            }
                            break;
                        }
                    }
                });
            }
        });
        if let Some(err) = v_err.into_inner().unwrap() {
            return Err(err);
        }
        for (pu, dev_path) in &raw_to_write {
            check_cancel()?;
            update_prog(&|g| g.current_partition = format!("verify {}{target_suffix}", pu.name));
            if let Some(exp_hash) = pu.new_info.hash {
                let got = read_raw_partition_hash(dev_path, pu.new_info.size)?;
                if got != exp_hash {
                    return Err(format!(
                        "ABORT BEFORE COMMIT: raw readback SHA-256 mismatch on {} (exp={} got={})",
                        dev_path.display(),
                        hex_encode(&exp_hash),
                        hex_encode(&got)
                    ));
                }
            }
            // AVB footer/vbmeta structural sanity check on raw boot/vbmeta images
            let mut rf = File::open(dev_path)
                .map_err(|e| format!("open avb check {}: {e}", dev_path.display()))?;
            let _ = avb::inspect_partition_avb(&mut rf, pu.new_info.size)?;
        }
    }

    if !opts.fast_verify {
        for (name, _, dst, size) in &raw_carry {
            let exp = raw_carried_hashes.iter().find(|h| &h.0 == name).map(|h| h.2);
            if exp != Some(read_raw_partition_hash(dst, *size)?) {
                return Err(format!("ABORT BEFORE COMMIT: carried {} readback mismatch", dst.display()));
            }
        }
    }

    // ====================================================================
    // STEP 8: Atomic Commit (Primary + Backup LpMetadata -> Readback -> SetActiveSlot)
    // ====================================================================
    update_prog(&|g| {
        g.phase = OtaPhase::Committing;
        g.current_partition = "super-metadata".into();
    });

    let max_sz = super_plan.geometry.metadata_max_size as usize;
    let mut padded_slot = vec![0u8; max_sz];
    padded_slot[..super_plan.target_slot_blob.len()]
        .copy_from_slice(&super_plan.target_slot_blob);
    let expected_slot_hash = sha256_bytes(&padded_slot);

    let pri_off = super_plan.geometry.primary_offset(target_slot) as u64;
    let bak_off = super_plan.geometry.backup_offset(target_slot) as u64;

    super_rw
        .seek(SeekFrom::Start(pri_off))
        .map_err(|e| format!("seek primary lpmeta: {e}"))?;
    super_rw
        .write_all(&padded_slot)
        .map_err(|e| format!("write primary lpmeta: {e}"))?;
    super_rw
        .sync_data()
        .map_err(|e| format!("fsync primary lpmeta: {e}"))?;

    super_rw
        .seek(SeekFrom::Start(bak_off))
        .map_err(|e| format!("seek backup lpmeta: {e}"))?;
    super_rw
        .write_all(&padded_slot)
        .map_err(|e| format!("write backup lpmeta: {e}"))?;
    super_rw
        .sync_data()
        .map_err(|e| format!("fsync backup lpmeta: {e}"))?;

    // Verify both Primary and Backup slots read back bit-identical
    for (label, off) in [("primary", pri_off), ("backup", bak_off)] {
        let mut check_buf = vec![0u8; max_sz];
        super_rw
            .seek(SeekFrom::Start(off))
            .map_err(|e| format!("seek verify {label}: {e}"))?;
        super_rw
            .read_exact(&mut check_buf)
            .map_err(|e| format!("read verify {label}: {e}"))?;
        if sha256_bytes(&check_buf) != expected_slot_hash {
            return Err(format!("CRITICAL: {label} LpMetadata readback mismatch!"));
        }
    }

    // Flip active boot slot ONLY after every byte and metadata slot is verified!
    bootctl.set_active_boot_slot(target_slot)?;

    // Update SlotStateCache for target_slot & remove resume marker
    let carried_cache: Vec<(String, CachedPartitionHash)> = carried_dynamic
        .iter()
        .filter_map(|(b, _)| Some((b.clone(), slot_cache.slot_map(active_slot).get(b)?.clone())))
        .collect();
    let target_map = slot_cache.slot_map_mut(target_slot);
    target_map.clear();
    for (b, c) in carried_cache {
        target_map.insert(b, c);
    }
    for (name, size, sha256) in &raw_carried_hashes {
        target_map.insert(name.clone(), CachedPartitionHash { size: *size, sha256: *sha256 });
    }
    for pu in &manifest.partitions {
        if let Some(h) = pu.new_info.hash {
            target_map.insert(
                pu.name.clone(),
                CachedPartitionHash {
                    size: pu.new_info.size,
                    sha256: h,
                },
            );
        }
    }
    let _ = slot_cache.save_atomic(&slot_cache_path);
    let _ = fs::remove_file(&resume_path);
    let _ = fs::remove_file(&plan_cache_path);

    // ====================================================================
    // STEP 9: Optional Dev Auto-Clean OverlayFS
    // ====================================================================
    let rewritten: Vec<String> = dynamic_updates.iter().map(|p| p.name.clone()).collect();
    let clean_scope: Option<Option<&[String]>> = if opts.clean_overlay {
        Some(None)
    } else if preserve_scratch && manifest.partial_update && !opts.keep_overlay {
        // The scratch kept for a partial payload still overlays the partitions it rewrote.
        Some(Some(&rewritten))
    } else {
        None
    };
    let overlay_clean = clean_scope.map(|only| {
        update_prog(&|g| {
            g.phase = OtaPhase::CleaningOverlay;
            g.current_partition = "overlayfs".into();
        });
        let rep = clean_overlays(&env.scratch_overlay_root, only);
        update_prog(&|g| {
            g.overlay_cleaned_files = rep.removed_entries;
            g.overlay_freed_bytes = rep.freed_bytes;
        });
        rep
    });

    let elapsed_ms = t0.elapsed().as_millis() as u64;
    update_prog(&|g| {
        g.phase = OtaPhase::Done;
        g.partitions_done = manifest.partitions.len();
        g.current_partition.clear();
        g.reboot_required = true;
        g.elapsed_ms = elapsed_ms;
    });

    Ok(OtaApplyResult {
        plan: plan_summary,
        elapsed_ms,
        bytes_written: total_written,
        overlay_clean,
        committed_slot: target_slot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lp::{
        build_synthetic_super_header, LpBlockDevice, LpGroup, LpPartition, LP_HEADER_SIZE_V1_2,
    };
    use crate::payload::{build_synthetic_payload, build_synthetic_payload_ex};
    use std::sync::atomic::AtomicU32;

    struct MockBootControl {
        cur: u32,
        next: AtomicU32,
    }
    impl BootControlOps for MockBootControl {
        fn current_slot(&self) -> Result<u32, String> {
            Ok(self.cur)
        }
        fn active_boot_slot(&self) -> Result<u32, String> {
            Ok(self.next.load(Ordering::Acquire))
        }
        fn is_slot_bootable(&self, _slot: u32) -> Result<bool, String> {
            Ok(true)
        }
        fn is_slot_successful(&self, _slot: u32) -> Result<bool, String> {
            Ok(true)
        }
        fn set_active_boot_slot(&self, slot: u32) -> Result<(), String> {
            self.next.store(slot, Ordering::Release);
            Ok(())
        }
        fn mark_boot_successful(&self) -> Result<(), String> {
            Ok(())
        }
        fn snapshot_merge_status(&self) -> String {
            "none".into()
        }
    }

    /// Synthetic live OTA from slot _b with a mounted scratch overlay; returns the apply result
    /// and the partition names committed to the target slot's metadata.
    fn run_synthetic_ota(
        tag: &str,
        keep_overlay: bool,
        clean_overlay: bool,
        dry_run_first: bool,
    ) -> (OtaApplyResult, Vec<String>) {
        let dir = std::env::temp_dir().join(format!("pasang-e2e-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let by_name = dir.join("by-name");
        let meta_dir = dir.join("metadata");
        let ovl_dir = dir.join("overlay");
        let mounts_file = dir.join("mounts");
        fs::create_dir_all(&by_name).unwrap();
        fs::create_dir_all(&meta_dir).unwrap();
        fs::create_dir_all(ovl_dir.join("system_ext/upper/app")).unwrap();
        fs::write(ovl_dir.join("system_ext/upper/app/test.apk"), vec![7u8; 8192]).unwrap();
        fs::write(
            &mounts_file,
            "/dev/block/dm-9 /mnt/scratch f2fs rw 0 0\noverlay /system_ext overlay rw 0 0\n",
        )
        .unwrap();

        // Build synthetic 16 MiB super block file
        let super_size = 16 * 1024 * 1024u64;
        let super_path = by_name.join("super");

        // Active slot _b: vendor_b (2 MiB @ sector 2048), odm_b (1 MiB @ sector 6144)
        let mut old_vendor = vec![0u8; 2 * 1024 * 1024];
        for b in 0..512usize {
            let pat = (b as u32 + 1).wrapping_mul(0x27D4_EB2D).to_le_bytes();
            for c in old_vendor[b * 4096..(b + 1) * 4096].chunks_exact_mut(4) {
                c.copy_from_slice(&pat);
            }
        }
        let old_odm = vec![0x3Cu8; 1024 * 1024];

        let bd = LpBlockDevice {
            first_logical_sector: 2048,
            alignment: 1024 * 1024,
            alignment_offset: 0,
            size: super_size,
            partition_name: "super".into(),
            flags: 0,
        };
        let groups = vec![
            LpGroup { name: "default".into(), flags: 0, maximum_size: 0 },
            LpGroup { name: "qti_dynamic_partitions_a".into(), flags: 1, maximum_size: 14 * 1024 * 1024 },
            LpGroup { name: "qti_dynamic_partitions_b".into(), flags: 1, maximum_size: 14 * 1024 * 1024 },
        ];
        let slot1 = LpMetadata {
            major_version: 10,
            minor_version: 2,
            header_size: LP_HEADER_SIZE_V1_2 as u32,
            flags: 0,
            reserved: vec![0u8; 124],
            partitions: vec![
                LpPartition { name: "vendor_b".into(), attributes: 3, first_extent_index: 0, num_extents: 1, group_index: 2 },
                LpPartition { name: "odm_b".into(), attributes: 3, first_extent_index: 1, num_extents: 1, group_index: 2 },
                LpPartition { name: "scratch".into(), attributes: 0, first_extent_index: 2, num_extents: 1, group_index: 0 },
            ],
            extents: vec![
                LpExtent { num_sectors: 4096, target_type: LP_TARGET_TYPE_LINEAR, target_data: 2048, target_source: 0 },
                LpExtent { num_sectors: 2048, target_type: LP_TARGET_TYPE_LINEAR, target_data: 6144, target_source: 0 },
                LpExtent { num_sectors: 2048, target_type: LP_TARGET_TYPE_LINEAR, target_data: 8192, target_source: 0 },
            ],
            groups: groups.clone(),
            block_devices: vec![bd.clone()],
        };
        let slot0 = LpMetadata {
            major_version: 10,
            minor_version: 2,
            header_size: LP_HEADER_SIZE_V1_2 as u32,
            flags: 0,
            reserved: vec![0u8; 124],
            partitions: vec![],
            extents: vec![],
            groups,
            block_devices: vec![bd],
        };
        let hdr = build_synthetic_super_header(super_size, &slot0, &slot1).unwrap();
        let mut super_raw = vec![0u8; super_size as usize];
        super_raw[..hdr.len()].copy_from_slice(&hdr);
        super_raw[2048 * 512..2048 * 512 + old_vendor.len()].copy_from_slice(&old_vendor);
        super_raw[6144 * 512..6144 * 512 + old_odm.len()].copy_from_slice(&old_odm);
        fs::write(&super_path, &super_raw).unwrap();

        // Raw inactive boot_a partition file (256 KiB)
        fs::write(by_name.join("boot_a"), vec![0u8; 256 * 1024]).unwrap();

        // New OTA:
        // - `vendor`: shifted by +4 KiB (1 changed header block + 511 identical blocks!) -> 99.8% aliased!
        // - `odm`: 100% identical to odm_b -> Layer 1 whole-partition skip!
        // - `boot`: new 256 KiB raw image -> written to boot_a
        let mut new_vendor = vec![0u8; 2 * 1024 * 1024];
        new_vendor[0..4096].fill(0xFE);
        new_vendor[4096..].copy_from_slice(&old_vendor[..old_vendor.len() - 4096]);
        let new_boot = vec![0x99u8; 256 * 1024];

        let ota_bytes = build_synthetic_payload(
            4096,
            &["vendor", "odm"],
            &[("vendor", &new_vendor), ("odm", &old_odm), ("boot", &new_boot)],
        );
        let ota_path = dir.join("update.bin");
        fs::write(&ota_path, &ota_bytes).unwrap();

        let env = OtaEnvironment {
            super_device: super_path.clone(),
            by_name_dir: by_name.clone(),
            metadata_dir: meta_dir.clone(),
            scratch_overlay_root: ovl_dir.clone(),
            proc_mounts_path: mounts_file,
            otacerts_path: dir.join("missing_certs.zip"),
            live_dm_occupied: vec![(2048, 6144), (6144, 8192)],
            ab_partitions: Vec::new(),
        };
        let bootctl = MockBootControl {
            cur: 1,
            next: AtomicU32::new(1),
        };
        let opts = OtaOptions {
            clean_overlay,
            keep_overlay,
            allow_dev_key: true,
            enable_extent_aliasing: true,
            min_alias_blocks: 64,
            ..Default::default()
        };
        let prog = Mutex::new(OtaProgress::default());
        let plan_cache = meta_dir.join("plan_cache.bin");
        let dry = if dry_run_first {
            let dry_opts = OtaOptions { dry_run: true, ..opts.clone() };
            let d = run_ota(&env, &bootctl, &ota_path, &dry_opts, None, None).unwrap();
            assert!(plan_cache.is_file(), "dry run left no plan cache");
            Some(d)
        } else {
            None
        };
        let res = run_ota(&env, &bootctl, &ota_path, &opts, Some(&prog), None).unwrap();
        assert!(!plan_cache.exists(), "plan cache survived commit");
        if let Some(d) = dry {
            assert_eq!(d.plan.bytes_to_write, res.plan.bytes_to_write);
            assert_eq!(d.plan.bytes_aliased, res.plan.bytes_aliased);
            assert_eq!(d.plan.whole_skipped_partitions, res.plan.whole_skipped_partitions);
        }

        let super_now = fs::read(&super_path).unwrap();
        let geom = parse_geometry(&super_now).unwrap();
        let target_names: Vec<String> = parse_slot_metadata(&super_now, &geom, 0)
            .unwrap()
            .partitions
            .iter()
            .map(|p| p.name.clone())
            .collect();
        // Mounted scratch sectors must never be reused while the old slot is live.
        for pp in &res_partitions_extents(&super_now, &geom) {
            assert!(pp.1 <= 8192 || pp.0 >= 10240, "target extent {pp:?} overlaps live scratch");
        }

        assert_eq!(res.committed_slot, 0);
        assert_eq!(bootctl.active_boot_slot().unwrap(), 0);
        // odm was whole-partition skipped (1 MiB) and vendor aliased 511*4KiB (2044 KiB),
        // so only 4 KiB of vendor + 256 KiB of boot were physically written!
        assert_eq!(res.plan.whole_skipped_partitions, 1);
        assert_eq!(res.plan.bytes_aliased, 511 * 4096);
        assert_eq!(res.bytes_written, 4096 + 256 * 1024);

        if clean_overlay {
            let ovl = res.overlay_clean.as_ref().unwrap();
            assert_eq!(ovl.removed_entries, 1);
            assert_eq!(ovl.freed_bytes, 8192);
            assert_eq!(ovl.cleaned_partitions, vec!["system_ext"]);
        } else {
            assert!(res.overlay_clean.is_none());
            assert!(ovl_dir.join("system_ext/upper/app/test.apk").is_file());
        }

        // Verify boot_a bytes match new_boot
        assert_eq!(fs::read(by_name.join("boot_a")).unwrap(), new_boot);

        // Verify last_good backup exists
        assert!(meta_dir.join("last_good/super_meta.bin").is_file());

        let _ = fs::remove_dir_all(&dir);
        (res, target_names)
    }

    fn res_partitions_extents(super_buf: &[u8], geom: &crate::lp::LpGeometry) -> Vec<(u64, u64)> {
        let m = parse_slot_metadata(super_buf, geom, 0).unwrap();
        m.partitions
            .iter()
            .filter(|p| p.name != "scratch")
            .flat_map(|p| m.partition_extents(p).to_vec())
            .filter(|e| e.target_type == LP_TARGET_TYPE_LINEAR)
            .map(|e| (e.target_data, e.target_data + e.num_sectors))
            .collect()
    }

    #[test]
    fn test_end_to_end_live_cow_ota_drops_scratch_from_target_by_default() {
        let (_, names) = run_synthetic_ota("drop", false, false, false);
        assert!(names.iter().any(|n| n == "vendor_a"));
        assert!(!names.iter().any(|n| n == "scratch"), "target slot kept scratch: {names:?}");
    }

    #[test]
    fn test_end_to_end_live_cow_ota_keep_overlay_carries_scratch() {
        let (_, names) = run_synthetic_ota("keep", true, false, false);
        assert!(names.iter().any(|n| n == "scratch"), "scratch missing: {names:?}");
    }

    /// Kernel-style partial payload: only `vendor_dlkm` (dynamic) and `boot` (raw).
    /// With `scratch`, a mounted scratch holds `system` and `vendor_dlkm` upperdirs.
    fn run_partial_ota(tag: &str, vbmeta_flags: u32, scratch: bool) -> Result<(OtaApplyResult, PathBuf), String> {
        let dir = std::env::temp_dir().join(format!("pasang-partial-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let by_name = dir.join("by-name");
        fs::create_dir_all(&by_name).unwrap();
        let ovl = dir.join("overlay");
        if scratch {
            fs::write(
                dir.join("mounts"),
                "/dev/block/mapper/scratch /mnt/scratch ext4 rw 0 0\noverlay /system overlay ro 0 0\n",
            )
            .unwrap();
            for (part, file) in [("system", "lib64/libpushed.so"), ("vendor_dlkm", "lib/modules/old.ko")] {
                let f = ovl.join(part).join("upper").join(file);
                fs::create_dir_all(f.parent().unwrap()).unwrap();
                fs::write(f, b"x").unwrap();
            }
        } else {
            fs::write(dir.join("mounts"), "").unwrap();
        }

        let super_size = 16 * 1024 * 1024u64;
        let bd = LpBlockDevice {
            first_logical_sector: 2048,
            alignment: 1024 * 1024,
            alignment_offset: 0,
            size: super_size,
            partition_name: "super".into(),
            flags: 0,
        };
        let groups = vec![
            LpGroup { name: "default".into(), flags: 0, maximum_size: 0 },
            LpGroup { name: "qti_dynamic_partitions_a".into(), flags: 1, maximum_size: 14 * 1024 * 1024 },
            LpGroup { name: "qti_dynamic_partitions_b".into(), flags: 1, maximum_size: 14 * 1024 * 1024 },
        ];
        let lin = |n, at| LpExtent { num_sectors: n, target_type: LP_TARGET_TYPE_LINEAR, target_data: at, target_source: 0 };
        let part = |name: &str, i| LpPartition { name: name.into(), attributes: 1, first_extent_index: i, num_extents: 1, group_index: 2 };
        // system_b 2 MiB, vendor_dlkm_b 1 MiB, tiny_b 4 KiB (below the alias minimum -> copied)
        let mut slot1 = LpMetadata {
            major_version: 10,
            minor_version: 2,
            header_size: LP_HEADER_SIZE_V1_2 as u32,
            flags: 0,
            reserved: vec![0u8; 124],
            partitions: vec![part("system_b", 0), part("vendor_dlkm_b", 1), part("tiny_b", 2)],
            extents: vec![lin(4096, 2048), lin(2048, 6144), lin(8, 8192)],
            groups: groups.clone(),
            block_devices: vec![bd.clone()],
        };
        if scratch {
            slot1.partitions.push(LpPartition { name: "scratch".into(), attributes: 0, first_extent_index: 3, num_extents: 1, group_index: 0 });
            slot1.extents.push(lin(2048, 10240));
        }
        let slot0 = LpMetadata { partitions: vec![], extents: vec![], ..slot1.clone() };
        let hdr = build_synthetic_super_header(super_size, &slot0, &slot1).unwrap();
        let mut raw = vec![0u8; super_size as usize];
        raw[..hdr.len()].copy_from_slice(&hdr);
        let system: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        raw[2048 * 512..2048 * 512 + system.len()].copy_from_slice(&system);
        raw[6144 * 512..6144 * 512 + 1024 * 1024].fill(0x11);
        raw[8192 * 512..8192 * 512 + 4096].fill(0x77);
        let super_path = by_name.join("super");
        fs::write(&super_path, &raw).unwrap();

        fs::write(by_name.join("boot_a"), vec![0u8; 64 * 1024]).unwrap();
        fs::write(by_name.join("boot_b"), vec![0x01u8; 64 * 1024]).unwrap();
        fs::write(by_name.join("dtbo_a"), vec![0xAAu8; 32 * 1024]).unwrap();
        fs::write(by_name.join("dtbo_b"), vec![0xBBu8; 32 * 1024]).unwrap();
        fs::write(by_name.join("modem_a"), vec![0x5Cu8; 16 * 1024]).unwrap();
        fs::write(by_name.join("modem_b"), vec![0x5Cu8; 16 * 1024]).unwrap();
        let mut vbmeta = vec![0u8; 4096];
        vbmeta[..4].copy_from_slice(b"AVB0");
        vbmeta[120..124].copy_from_slice(&vbmeta_flags.to_be_bytes());
        fs::write(by_name.join("vbmeta_a"), &vbmeta).unwrap();
        fs::write(by_name.join("vbmeta_b"), &vbmeta).unwrap();

        let new_dlkm = vec![0x22u8; 1024 * 1024];
        let new_boot = vec![0x99u8; 64 * 1024];
        let ota = build_synthetic_payload_ex(
            4096,
            &["vendor_dlkm"],
            &[("vendor_dlkm", &new_dlkm), ("boot", &new_boot)],
            true,
        );
        let ota_path = dir.join("kernel.bin");
        fs::write(&ota_path, &ota).unwrap();

        let env = OtaEnvironment {
            super_device: super_path,
            by_name_dir: by_name.clone(),
            metadata_dir: dir.join("metadata"),
            scratch_overlay_root: dir.join("overlay"),
            proc_mounts_path: dir.join("mounts"),
            otacerts_path: dir.join("missing_certs.zip"),
            live_dm_occupied: vec![(2048, 8200)],
            ab_partitions: ["boot", "dtbo", "modem", "vbmeta", "system", "vendor_dlkm", "tiny"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        let bootctl = MockBootControl { cur: 1, next: AtomicU32::new(1) };
        let opts = OtaOptions { allow_dev_key: true, ..Default::default() };
        let res = run_ota(&env, &bootctl, &ota_path, &opts, None, None)?;
        Ok((res, dir))
    }

    #[test]
    fn test_partial_payload_carries_untouched_partitions() {
        let (res, dir) = run_partial_ota("carry", 3, false).unwrap();
        let by_name = dir.join("by-name");
        assert!(res.plan.partial_update);
        assert_eq!(res.committed_slot, 0);
        assert_eq!(fs::read(by_name.join("boot_a")).unwrap(), vec![0x99u8; 64 * 1024]);
        // dtbo differed -> copied from the active slot; modem/vbmeta already matched.
        assert_eq!(fs::read(by_name.join("dtbo_a")).unwrap(), vec![0xBBu8; 32 * 1024]);
        assert_eq!(res.plan.carried_bytes_copied, 32 * 1024);
        // system + tiny (dynamic) and dtbo, modem, vbmeta (raw) carried
        assert_eq!(res.plan.carried_partitions, 5);

        let sup = fs::read(by_name.join("super")).unwrap();
        let geom = parse_geometry(&sup).unwrap();
        let m = parse_slot_metadata(&sup, &geom, 0).unwrap();
        let read_part = |name: &str| -> Vec<u8> {
            let p = m.partitions.iter().find(|p| p.name == name).unwrap_or_else(|| panic!("{name} missing"));
            let mut v = Vec::new();
            for e in m.partition_extents(p) {
                let o = (e.target_data * 512) as usize;
                v.extend_from_slice(&sup[o..o + (e.num_sectors * 512) as usize]);
            }
            v
        };
        let system: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        assert_eq!(read_part("system_a"), system);
        assert_eq!(read_part("vendor_dlkm_a"), vec![0x22u8; 1024 * 1024]);
        assert_eq!(read_part("tiny_a"), vec![0x77u8; 4096]);
        // system_a aliases the active sectors; nothing of it was rewritten.
        let sys_a = m.partitions.iter().find(|p| p.name == "system_a").unwrap();
        assert_eq!(m.partition_extents(sys_a)[0].target_data, 2048);
        let tiny_a = m.partitions.iter().find(|p| p.name == "tiny_a").unwrap();
        assert_ne!(m.partition_extents(tiny_a)[0].target_data, 8192, "tiny run should be copied");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_partial_payload_keeps_scratch_and_clears_rewritten_upperdirs() {
        let (res, dir) = run_partial_ota("scratch", 3, true).unwrap();
        let sup = fs::read(dir.join("by-name/super")).unwrap();
        let geom = parse_geometry(&sup).unwrap();
        let m = parse_slot_metadata(&sup, &geom, 0).unwrap();
        let scratch = m.partitions.iter().find(|p| p.name == "scratch").expect("target slot dropped scratch");
        assert_eq!(m.partition_extents(scratch)[0].target_data, 10240, "scratch must keep its sectors");
        let ovl = dir.join("overlay");
        assert!(ovl.join("system/upper/lib64/libpushed.so").is_file(), "carried system lost its upperdir");
        assert!(!ovl.join("vendor_dlkm/upper/lib").exists(), "rewritten vendor_dlkm kept old modules");
        assert_eq!(res.overlay_clean.as_ref().unwrap().cleaned_partitions, ["vendor_dlkm"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_partial_payload_refuses_when_avb_enforced() {
        let err = run_partial_ota("avb", 0, false).unwrap_err();
        assert!(err.contains("vbmeta"), "{err}");
    }

    #[test]
    fn test_end_to_end_apply_reuses_dry_run_plan() {
        let (res, names) = run_synthetic_ota("reuse", false, false, true);
        assert_eq!(res.bytes_written, 4096 + 256 * 1024);
        assert!(names.iter().any(|n| n == "vendor_a"));
    }

    #[test]
    fn test_plan_cache_rejects_other_key_and_corruption() {
        let dir = std::env::temp_dir().join(format!("pasang-plancache-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("plan_cache.bin");
        let specs = vec![OtaPartitionExtentSpec {
            base_name: "vendor".into(),
            total_bytes: 8192,
            runs: vec![
                LogicalRun::Alias { phys_start_sector: 2048, num_sectors: 8 },
                LogicalRun::Allocate { num_sectors: 8 },
            ],
        }];
        save_plan_cache(&p, &[1u8; 32], &specs, 0, 0).unwrap();
        let got = load_plan_cache(&p, &[1u8; 32]).unwrap();
        assert_eq!(got.0[0].runs, specs[0].runs);
        assert!(load_plan_cache(&p, &[2u8; 32]).is_none());
        let mut raw = fs::read(&p).unwrap();
        raw[50] ^= 0xFF;
        fs::write(&p, raw).unwrap();
        assert!(load_plan_cache(&p, &[1u8; 32]).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_end_to_end_live_cow_ota_clean_overlay_wipes_live_upperdirs() {
        let (_, names) = run_synthetic_ota("clean", false, true, false);
        assert!(!names.iter().any(|n| n == "scratch"));
    }
}
