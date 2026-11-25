// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Layer 2 Hyper-Flash: 4 KiB Content-Addressed Block Indexer, Sub-Partition
//! `dm-linear` Extent Aliasing Planner, and `.pidx` Sidecar Format.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::thread;

use crate::crypto::{crc32, sha256_prefix16};
use crate::lp::{
    coalesce_runs, LogicalRun, LpExtent, LP_BLOCK_SIZE, LP_SECTOR_SIZE, LP_SECTORS_PER_BLOCK,
    LP_TARGET_TYPE_LINEAR,
};

pub const PIDX_MAGIC: &[u8; 4] = b"PIDX";
pub const PIDX_VERSION: u32 = 1;

/// Compact 128-bit SHA-256 prefix for 4 KiB blocks (collision probability < 2^-128,
/// cuts index memory in half vs full 256-bit keys).
pub type BlockKey = [u8; 16];

/// Precomputed 128-bit SHA-256 prefix of an all-zero 4 KiB block.
pub fn zero_block_key() -> BlockKey {
    const ZERO_4K: [u8; 4096] = [0u8; 4096];
    sha256_prefix16(&ZERO_4K)
}

/// Content-addressed index of an active slot's physical 4 KiB blocks inside `super`.
/// Maps `BlockKey` -> physical starting sector (`u64`, 8-sector / 4 KiB aligned).
#[derive(Debug, Default, Clone)]
pub struct ActiveBlockIndex {
    pub map: HashMap<BlockKey, u64>,
    pub total_blocks_indexed: u64,
}

impl ActiveBlockIndex {
    pub fn with_capacity(blocks: usize) -> Self {
        Self {
            map: HashMap::with_capacity(blocks),
            total_blocks_indexed: 0,
        }
    }

    /// Index all `LP_TARGET_TYPE_LINEAR` extents of an active-slot partition by reading directly
    /// from `super_reader` (streaming 4 MiB chunks for minimal syscalls).
    pub fn index_super_extents<R: Read + Seek>(
        &mut self,
        super_reader: &mut R,
        extents: &[LpExtent],
    ) -> Result<u64, String> {
        let zkey = zero_block_key();
        let mut buf = vec![0u8; 4 * 1024 * 1024]; // 4 MiB aligned read chunk (1024 blocks)
        let mut added = 0u64;

        for ext in extents {
            if ext.target_type != LP_TARGET_TYPE_LINEAR || ext.target_source != 0 {
                continue;
            }
            if ext.target_data % LP_SECTORS_PER_BLOCK != 0
                || ext.num_sectors % LP_SECTORS_PER_BLOCK != 0
            {
                // Skip non-4KiB-aligned extents (safety: EROFS/AVB blocks are always 4KiB)
                continue;
            }
            let total_bytes = ext.num_sectors * LP_SECTOR_SIZE;
            let base_byte = ext.target_data * LP_SECTOR_SIZE;
            super_reader
                .seek(SeekFrom::Start(base_byte))
                .map_err(|e| format!("seek super@{base_byte}: {e}"))?;

            let mut done = 0u64;
            while done < total_bytes {
                let take = ((total_bytes - done) as usize).min(buf.len());
                super_reader
                    .read_exact(&mut buf[..take])
                    .map_err(|e| format!("read super@{}: {e}", base_byte + done))?;
                for (bi, blk) in buf[..take].chunks_exact(LP_BLOCK_SIZE as usize).enumerate() {
                    let key = sha256_prefix16(blk);
                    if key != zkey {
                        let phys_sector =
                            ext.target_data + (done / LP_SECTOR_SIZE) + (bi as u64) * LP_SECTORS_PER_BLOCK;
                        self.map.entry(key).or_insert(phys_sector);
                    }
                    added += 1;
                }
                done += take as u64;
            }
        }
        self.total_blocks_indexed += added;
        Ok(added)
    }

    /// Multi-threaded 4 KiB active-slot indexer reading `super` in 8 MiB sequential bursts
    /// and hashing 4 KiB blocks in parallel across CPU cores (`std::thread::scope`, 0 external crates).
    /// Produces the exact same deterministic lowest-physical-sector mapping as `index_super_extents`.
    pub fn index_super_extents_parallel(
        &mut self,
        super_file: &mut File,
        extents: &[LpExtent],
    ) -> Result<u64, String> {
        let zkey = zero_block_key();
        let workers = thread::available_parallelism()
            .map(|n| n.get().clamp(1, 8))
            .unwrap_or(4);
        if workers <= 1 {
            return self.index_super_extents(super_file, extents);
        }

        // 8 MiB chunk = 2048 × 4 KiB blocks -> evenly split across up to 8 threads
        let mut buf = vec![0u8; 8 * 1024 * 1024];
        let mut added = 0u64;

        for ext in extents {
            if ext.target_type != LP_TARGET_TYPE_LINEAR || ext.target_source != 0 {
                continue;
            }
            if ext.target_data % LP_SECTORS_PER_BLOCK != 0
                || ext.num_sectors % LP_SECTORS_PER_BLOCK != 0
            {
                continue;
            }
            let total_bytes = ext.num_sectors * LP_SECTOR_SIZE;
            let base_byte = ext.target_data * LP_SECTOR_SIZE;
            super_file
                .seek(SeekFrom::Start(base_byte))
                .map_err(|e| format!("seek super@{base_byte}: {e}"))?;

            let mut done = 0u64;
            while done < total_bytes {
                let take = ((total_bytes - done) as usize).min(buf.len());
                super_file
                    .read_exact(&mut buf[..take])
                    .map_err(|e| format!("read super@{}: {e}", base_byte + done))?;
                let chunk_start_sec = ext.target_data + (done / LP_SECTOR_SIZE);
                let nblks = take / (LP_BLOCK_SIZE as usize);
                let per_worker = nblks.div_ceil(workers).max(1);
                let slice = &buf[..nblks * (LP_BLOCK_SIZE as usize)];

                let parts: Vec<Vec<(BlockKey, u64)>> = thread::scope(|s| {
                    let mut handles = Vec::with_capacity(workers);
                    for wi in 0..workers {
                        let b_start = wi * per_worker;
                        if b_start >= nblks {
                            break;
                        }
                        let b_end = (b_start + per_worker).min(nblks);
                        let sub = &slice[b_start * (LP_BLOCK_SIZE as usize)
                            ..b_end * (LP_BLOCK_SIZE as usize)];
                        let sec0 = chunk_start_sec + (b_start as u64) * LP_SECTORS_PER_BLOCK;
                        handles.push(s.spawn(move || {
                            let mut out = Vec::with_capacity(b_end - b_start);
                            for (bi, blk) in
                                sub.chunks_exact(LP_BLOCK_SIZE as usize).enumerate()
                            {
                                let key = sha256_prefix16(blk);
                                if key != zkey {
                                    out.push((key, sec0 + (bi as u64) * LP_SECTORS_PER_BLOCK));
                                }
                            }
                            out
                        }));
                    }
                    handles
                        .into_iter()
                        .map(|h| h.join().unwrap_or_default())
                        .collect()
                });

                for part in parts {
                    for (key, phys_sector) in part {
                        self.map.entry(key).or_insert(phys_sector);
                    }
                }
                added += nblks as u64;
                done += take as u64;
            }
        }
        self.total_blocks_indexed += added;
        Ok(added)
    }

    /// Index an in-memory buffer placed at `phys_start_sector` (helper for tests & tools).
    pub fn index_slice(&mut self, data: &[u8], phys_start_sector: u64) {
        let zkey = zero_block_key();
        for (bi, blk) in data.chunks_exact(LP_BLOCK_SIZE as usize).enumerate() {
            let key = sha256_prefix16(blk);
            if key != zkey {
                self.map
                    .entry(key)
                    .or_insert(phys_start_sector + (bi as u64) * LP_SECTORS_PER_BLOCK);
            }
            self.total_blocks_indexed += 1;
        }
    }

    /// Serialize the active block index into compact binary format (`PIDX` v1 + CRC32).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(self.map.len() * 24);
        for (k, &sec) in &self.map {
            body.extend_from_slice(k);
            body.extend_from_slice(&sec.to_le_bytes());
        }
        let checksum = crc32(&body);
        let mut out = Vec::with_capacity(20 + body.len());
        out.extend_from_slice(PIDX_MAGIC);
        out.extend_from_slice(&PIDX_VERSION.to_le_bytes());
        out.extend_from_slice(&(self.map.len() as u64).to_le_bytes());
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Deserialize from binary `PIDX` cache file, verifying magic + CRC32.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 20 || &raw[0..4] != PIDX_MAGIC {
            return Err("Invalid PIDX cache magic".into());
        }
        let ver = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        if ver != PIDX_VERSION {
            return Err(format!("Unsupported PIDX version {ver}"));
        }
        let count = u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize;
        let expected_crc = u32::from_le_bytes(raw[16..20].try_into().unwrap());
        let body = &raw[20..];
        if body.len() != count * 24 {
            return Err("Truncated PIDX index body".into());
        }
        if crc32(body) != expected_crc {
            return Err("PIDX index CRC32 mismatch".into());
        }
        let mut map = HashMap::with_capacity(count);
        for rec in body.chunks_exact(24) {
            let mut key = [0u8; 16];
            key.copy_from_slice(&rec[0..16]);
            let sec = u64::from_le_bytes(rec[16..24].try_into().unwrap());
            map.insert(key, sec);
        }
        Ok(Self {
            map,
            total_blocks_indexed: count as u64,
        })
    }
}

/// Statistics produced by Sub-Partition Extent Aliasing for one partition.
#[derive(Debug, Default, Clone)]
pub struct AliasPlanStats {
    pub total_blocks: u64,
    pub aliased_blocks: u64,
    pub zero_blocks: u64,
    pub delta_blocks: u64,
    pub raw_run_count: usize,
}

impl AliasPlanStats {
    pub fn alias_ratio_pct(&self) -> f64 {
        if self.total_blocks == 0 {
            0.0
        } else {
            ((self.aliased_blocks + self.zero_blocks) as f64 * 100.0) / (self.total_blocks as f64)
        }
    }
}

/// Match a new partition's 4 KiB block keys against `active_index` to emit optimal
/// `LogicalRun` entries (`Alias` for shifted/identical active-slot EROFS runs,
/// `Allocate` for true delta & zero-padded blocks).
///
/// NOTE: Never emits `LogicalRun::Zero` (`LP_TARGET_TYPE_ZERO` / `dm-zero`) because Android
/// GKI kernels ship with `# CONFIG_DM_ZERO is not set`, causing `DM_TABLE_LOAD` `EINVAL` in
/// `first_stage_mount`! All-zero blocks coalesce into `Allocate` and are written as real zeros.
pub fn build_extent_alias_runs(
    new_block_keys: &[BlockKey],
    active_index: &ActiveBlockIndex,
    min_alias_blocks: u64,
) -> (Vec<LogicalRun>, AliasPlanStats) {
    let zkey = zero_block_key();
    let mut raw_runs: Vec<LogicalRun> = Vec::with_capacity(new_block_keys.len());

    for key in new_block_keys {
        if *key == zkey {
            raw_runs.push(LogicalRun::Allocate {
                num_sectors: LP_SECTORS_PER_BLOCK,
            });
        } else if let Some(&phys_sec) = active_index.map.get(key) {
            raw_runs.push(LogicalRun::Alias {
                phys_start_sector: phys_sec,
                num_sectors: LP_SECTORS_PER_BLOCK,
            });
        } else {
            raw_runs.push(LogicalRun::Allocate {
                num_sectors: LP_SECTORS_PER_BLOCK,
            });
        }
    }

    // Coalesce contiguous runs first, then promote sub-threshold Alias runs to Allocate
    // (avoiding tiny 4 KiB dm-linear fragmentation) and re-coalesce!
    let min_alias_sectors = min_alias_blocks * LP_SECTORS_PER_BLOCK;
    let mut coalesced = coalesce_runs(raw_runs);
    for r in &mut coalesced {
        if let LogicalRun::Alias { num_sectors, .. } = *r {
            if num_sectors < min_alias_sectors {
                *r = LogicalRun::Allocate { num_sectors };
            }
        }
    }
    let final_runs = coalesce_runs(coalesced);

    let mut stats = AliasPlanStats {
        total_blocks: new_block_keys.len() as u64,
        raw_run_count: final_runs.len(),
        ..Default::default()
    };
    for r in &final_runs {
        match *r {
            LogicalRun::Alias { num_sectors, .. } => {
                stats.aliased_blocks += num_sectors / LP_SECTORS_PER_BLOCK
            }
            LogicalRun::Zero { num_sectors } => {
                stats.zero_blocks += num_sectors / LP_SECTORS_PER_BLOCK
            }
            LogicalRun::Allocate { num_sectors } => {
                stats.delta_blocks += num_sectors / LP_SECTORS_PER_BLOCK
            }
        }
    }
    (final_runs, stats)
}

/// Optional `.pidx` OTA Sidecar Index (generated by `yv ota index <ota.zip>`).
/// Stores per-partition 4 KiB block keys so HTTP Range / `yv ota push --dedup` can skip
/// transferring already-present blocks before streaming!
#[derive(Debug, Clone)]
pub struct PidxPartition {
    pub name: String,
    pub total_bytes: u64,
    pub block_keys: Vec<BlockKey>,
}

#[derive(Debug, Clone)]
pub struct PidxSidecar {
    pub block_size: u32,
    pub partitions: Vec<PidxPartition>,
}

impl PidxSidecar {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.block_size.to_le_bytes());
        body.extend_from_slice(&(self.partitions.len() as u32).to_le_bytes());
        for p in &self.partitions {
            let nb = p.name.as_bytes();
            body.extend_from_slice(&(nb.len() as u16).to_le_bytes());
            body.extend_from_slice(nb);
            body.extend_from_slice(&p.total_bytes.to_le_bytes());
            body.extend_from_slice(&(p.block_keys.len() as u64).to_le_bytes());
            for k in &p.block_keys {
                body.extend_from_slice(k);
            }
        }
        let csum = crc32(&body);
        let mut out = Vec::with_capacity(12 + body.len());
        out.extend_from_slice(b"YPDX");
        out.extend_from_slice(&PIDX_VERSION.to_le_bytes());
        out.extend_from_slice(&csum.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 20 || &raw[0..4] != b"YPDX" {
            return Err("Invalid .pidx sidecar magic".into());
        }
        let ver = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        if ver != PIDX_VERSION {
            return Err(format!("Unsupported .pidx sidecar version {ver}"));
        }
        let exp_crc = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let body = &raw[12..];
        if crc32(body) != exp_crc {
            return Err(".pidx sidecar CRC32 mismatch".into());
        }
        let block_size = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let nparts = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
        let mut pos = 8usize;
        let mut partitions = Vec::with_capacity(nparts);
        for _ in 0..nparts {
            if pos + 2 > body.len() {
                return Err("Truncated .pidx partition header".into());
            }
            let nlen = u16::from_le_bytes(body[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + nlen + 16 > body.len() {
                return Err("Truncated .pidx partition metadata".into());
            }
            let name = String::from_utf8_lossy(&body[pos..pos + nlen]).into_owned();
            pos += nlen;
            let total_bytes = u64::from_le_bytes(body[pos..pos + 8].try_into().unwrap());
            let nblks = u64::from_le_bytes(body[pos + 8..pos + 16].try_into().unwrap()) as usize;
            pos += 16;
            if pos + nblks * 16 > body.len() {
                return Err("Truncated .pidx block keys".into());
            }
            let mut block_keys = Vec::with_capacity(nblks);
            for c in body[pos..pos + nblks * 16].chunks_exact(16) {
                let mut k = [0u8; 16];
                k.copy_from_slice(c);
                block_keys.push(k);
            }
            pos += nblks * 16;
            partitions.push(PidxPartition {
                name,
                total_bytes,
                block_keys,
            });
        }
        Ok(Self {
            block_size,
            partitions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shifted_erofs_extent_aliasing() {
        // Simulate real onyx vendor.img EROFS shift:
        // Active slot has 256 unique 4 KiB blocks (1 MiB) at sector 4096.
        // New OTA prepends 1 modified 4 KiB header block, shifting all 255 blocks forward by +4 KiB!
        let mut old_img = vec![0u8; 256 * 4096];
        for b in 0..256usize {
            let pat = ((b as u32) + 1).wrapping_mul(0x9E37_79B9).to_le_bytes();
            for chunk in old_img[b * 4096..(b + 1) * 4096].chunks_exact_mut(4) {
                chunk.copy_from_slice(&pat);
            }
        }
        let mut idx = ActiveBlockIndex::with_capacity(256);
        idx.index_slice(&old_img, 4096);

        // Roundtrip binary cache serialization
        let ser = idx.to_bytes();
        let idx2 = ActiveBlockIndex::from_bytes(&ser).unwrap();
        assert_eq!(idx2.map.len(), idx.map.len());

        // Construct shifted new image: [new_hdr_block] + old_img[0..255] + [zero_block]
        let mut new_keys = Vec::with_capacity(257);
        new_keys.push(sha256_prefix16(&[0xEEu8; 4096]));
        for b in 0..255usize {
            new_keys.push(sha256_prefix16(&old_img[b * 4096..(b + 1) * 4096]));
        }
        new_keys.push(zero_block_key());

        let (runs, stats) = build_extent_alias_runs(&new_keys, &idx2, 64);
        assert_eq!(stats.aliased_blocks, 255);
        assert_eq!(stats.zero_blocks, 0);
        assert_eq!(stats.delta_blocks, 2); // new header block + trailing zero block (no dm-zero!)
        assert_eq!(runs.len(), 3);
        assert!(runs.iter().all(|r| !matches!(r, LogicalRun::Zero { .. })));
        assert_eq!(
            runs[1],
            LogicalRun::Alias {
                phys_start_sector: 4096,
                num_sectors: 255 * 8,
            }
        );
    }

    #[test]
    fn test_pidx_sidecar_roundtrip() {
        let sc = PidxSidecar {
            block_size: 4096,
            partitions: vec![PidxPartition {
                name: "vendor".into(),
                total_bytes: 8192,
                block_keys: vec![[1u8; 16], [2u8; 16]],
            }],
        };
        let raw = sc.to_bytes();
        let dec = PidxSidecar::from_bytes(&raw).unwrap();
        assert_eq!(dec.block_size, 4096);
        assert_eq!(dec.partitions.len(), 1);
        assert_eq!(dec.partitions[0].name, "vendor");
        assert_eq!(dec.partitions[0].block_keys, vec![[1u8; 16], [2u8; 16]]);
    }
}
