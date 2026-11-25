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
        }
    }
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
             \"overlay_files_present\":{}}}",
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

    // Inspect overlays upfront so we know whether `scratch` is mounted & how many dev files exist.
    // Safety: always keep mounted `scratch` sectors in `live_occupied` so live OS never faults
    // before reboot; when `opts.clean_overlay == true`, omit `scratch` from the target slot's
    // `LpMetadata` (`preserve_scratch = false`) so the new slot boots 100% clean with zero stale overlays!
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
    let preserve_scratch = ovl_status.scratch_mounted && !opts.clean_overlay;

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
    for pu in &manifest.partitions {
        if manifest.dynamic_metadata.is_dynamic(&pu.name) {
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

    let mut dynamic_specs: Vec<OtaPartitionExtentSpec> = Vec::with_capacity(dynamic_updates.len());
    let mut whole_skipped_count = 0usize;
    let mut dyn_bytes_skipped_whole = 0u64;
    let mut bytes_skipped_whole = 0u64;

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
        if let (Some(ap), Some(new_hash)) = (active_part, pu.new_info.hash) {
            let active_exts = active_meta.partition_extents(ap);
            let all_linear = active_exts
                .iter()
                .all(|e| e.target_type == LP_TARGET_TYPE_LINEAR);
            let active_sz: u64 = active_exts.iter().map(|e| e.num_sectors * LP_SECTOR_SIZE).sum();
            let cached_match = slot_cache
                .slot_map(active_slot)
                .get(&pu.name)
                .is_some_and(|c| c.size == pu.new_info.size && c.sha256 == new_hash);
            let verified_match = if cached_match {
                true
            } else if all_linear && active_sz >= pu.new_info.size {
                verify_dynamic_extents_sha256(&mut super_ro, active_exts, pu.new_info.size)
                    .map(|h| h == new_hash)
                    .unwrap_or(false)
            } else {
                false
            };
            if all_linear && verified_match && active_sz == align_up(pu.new_info.size, LP_BLOCK_SIZE)
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
                bytes_skipped_whole += pu.new_info.size;
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

        let already_matches = if resume_done.contains(&pu.name) {
            true
        } else if let Some(exp) = pu.new_info.hash {
            if slot_cache
                .slot_map(target_slot)
                .get(&pu.name)
                .is_some_and(|c| c.size == pu.new_info.size && c.sha256 == exp)
            {
                true
            } else {
                read_raw_partition_hash(&dev, pu.new_info.size)
                    .map(|h| h == exp)
                    .unwrap_or(false)
            }
        } else {
            false
        };

        if already_matches {
            whole_skipped_count += 1;
            bytes_skipped_whole += pu.new_info.size;
        } else {
            raw_bytes_to_write += pu.new_info.size;
            raw_to_write.push((pu, dev));
        }
    }

    let total_bytes_to_write = super_plan.total_bytes_to_write + raw_bytes_to_write;
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
            .saturating_sub(dyn_bytes_skipped_whole),
        bytes_zeroed: super_plan.total_bytes_zeroed,
        bytes_skipped_whole,
        bytes_to_write: total_bytes_to_write,
        total_extents: super_plan.total_extents,
        free_super_before: super_plan.free_bytes_before,
        free_super_after: super_plan.free_bytes_after,
        overlay_files_present: ovl_status.total_files,
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
    let target_map = slot_cache.slot_map_mut(target_slot);
    target_map.clear();
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

    // ====================================================================
    // STEP 9: Optional Dev Auto-Clean OverlayFS
    // ====================================================================
    let overlay_clean = if opts.clean_overlay {
        update_prog(&|g| {
            g.phase = OtaPhase::CleaningOverlay;
            g.current_partition = "overlayfs".into();
        });
        let rep = clean_overlays(&env.scratch_overlay_root, None);
        update_prog(&|g| {
            g.overlay_cleaned_files = rep.removed_entries;
            g.overlay_freed_bytes = rep.freed_bytes;
        });
        Some(rep)
    } else {
        None
    };

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
    use crate::payload::build_synthetic_payload;
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

    #[test]
    fn test_end_to_end_live_cow_ota_with_extent_aliasing_and_dev_overlay_clean() {
        let dir = std::env::temp_dir().join(format!("pasang-e2e-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let by_name = dir.join("by-name");
        let meta_dir = dir.join("metadata");
        let ovl_dir = dir.join("overlay");
        let mounts_file = dir.join("mounts");
        fs::create_dir_all(&by_name).unwrap();
        fs::create_dir_all(&meta_dir).unwrap();
        fs::create_dir_all(ovl_dir.join("system_ext/upper/app")).unwrap();
        fs::write(ovl_dir.join("system_ext/upper/app/test.apk"), vec![7u8; 8192]).unwrap();
        fs::write(&mounts_file, "overlay /system_ext overlay rw 0 0\n").unwrap();

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
            ],
            extents: vec![
                LpExtent { num_sectors: 4096, target_type: LP_TARGET_TYPE_LINEAR, target_data: 2048, target_source: 0 },
                LpExtent { num_sectors: 2048, target_type: LP_TARGET_TYPE_LINEAR, target_data: 6144, target_source: 0 },
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
        };
        let bootctl = MockBootControl {
            cur: 1,
            next: AtomicU32::new(1),
        };
        let opts = OtaOptions {
            clean_overlay: true,
            allow_dev_key: true,
            enable_extent_aliasing: true,
            min_alias_blocks: 64,
            ..Default::default()
        };
        let prog = Mutex::new(OtaProgress::default());
        let res = run_ota(&env, &bootctl, &ota_path, &opts, Some(&prog), None).unwrap();

        assert_eq!(res.committed_slot, 0);
        assert_eq!(bootctl.active_boot_slot().unwrap(), 0);
        // odm was whole-partition skipped (1 MiB) and vendor aliased 511*4KiB (2044 KiB),
        // so only 4 KiB of vendor + 256 KiB of boot were physically written!
        assert_eq!(res.plan.whole_skipped_partitions, 1);
        assert_eq!(res.plan.bytes_aliased, 511 * 4096);
        assert_eq!(res.bytes_written, 4096 + 256 * 1024);

        // Verify dev auto-clean overlay ran and wiped test.apk!
        let ovl = res.overlay_clean.unwrap();
        assert_eq!(ovl.removed_entries, 1);
        assert_eq!(ovl.freed_bytes, 8192);
        assert_eq!(ovl.cleaned_partitions, vec!["system_ext"]);

        // Verify boot_a bytes match new_boot
        assert_eq!(fs::read(by_name.join("boot_a")).unwrap(), new_boot);

        // Verify last_good backup exists
        assert!(meta_dir.join("last_good/super_meta.bin").is_file());

        let _ = fs::remove_dir_all(&dir);
    }
}
