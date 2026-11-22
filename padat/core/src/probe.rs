// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Smart Compressibility Probe.
//!
//! Prevents UFS write amplification on encrypted / already-compressed blobs (e.g. Genshin `.blk`,
//! WuWa Oodle `.pak`, Endfield `.chk`, media) by sampling <= 256 KB in memory (< 1 ms) before
//! touching disk.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::policy::{CompAlgo, CompProfile};

const PAGE_SIZE: usize = 4096;
const F2FS_COMPRESS_HEADER: usize = 24;

/// Path segments that must NEVER be compressed (sync-heavy DBs, volatile caches, SQLite atomic).
pub const BLOCKED_DIR_SEGMENTS: &[&str] = &[
    "databases",
    "shared_prefs",
    "no_backup",
    "code_cache",
    "cache",
    "app_webview",
    "app_textures",
    "app_crashSight",
    "app_telemetry",
    "datastore",
    "phenotype",
    "phenotype_storage_info",
    ".crashlytics.v3",
    "IndexedDB",
    "LevelDB",
    "Local Storage",
    "Session Storage",
    "mmkv",
    "xlog",
    "sp_xlogs-cache",
    "tracelog_xlog-cache",
    "BrowserMetrics",
    "blob_storage",
    "Service Worker",
    "GPUCache",
    "GrShaderCache",
    "ShaderCache",
    "DawnCache",
];

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// File extensions that must NEVER be compressed.
const BLOCKED_EXTENSIONS: &[&str] = &[
    // SQLite / DBs (CP_COMPRESSED fsync checkpoint trap + atomic write conflict)
    "db", "db-wal", "db-shm", "db-journal", "sqlite", "sqlite3", "wal", "shm", "journal",
    // Writable mmap ringbuffers, KV stores, LevelDB/RocksDB/LMDB/Realm
    "mmap", "mmap2", "mmap3", "xlog", "pma", "ldb", "sst", "realm", "mdb", "lock", "crc",
    // ART already-LZ4 images, profiles & dex2oat temp swap
    "art", "swap", "prof", "dm", "idsig", "digests",
    // Already-compressed media
    "mp4", "mkv", "webm", "avi", "mov", "m4v", "3gp",
    "jpg", "jpeg", "png", "webp", "heic", "heif", "avif", "gif",
    "ogg", "opus", "mp3", "aac", "m4a", "flac", "wma",
    // Already-compressed archives (NOTE: .apk and .obb are evaluated selectively, not here)
    "zip", "gz", "tgz", "bz2", "xz", "zst", "lz4", "7z", "rar",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// Worth compressing; carries projected savings percentage (0..100).
    Compress(u8),
    /// Excluded by hard path/extension policy (never touch, never flag).
    ExcludedPolicy,
    /// Sampled and confirmed high-entropy / incompressible (safe to tag FS_NOCOMP_FL).
    Incompressible { entropy_x100: u16, est_saving_pct: u8 },
}

/// Returns true if the path falls under an excluded directory or extension.
pub fn is_path_excluded(path: &Path) -> bool {
    for comp in path.components() {
        if let Some(s) = comp.as_os_str().to_str() {
            if BLOCKED_DIR_SEGMENTS.iter().any(|&b| b.eq_ignore_ascii_case(s)) {
                return true;
            }
        }
    }
    let fname = match path.file_name().and_then(|s| s.to_str()) {
        Some(n) => n,
        None => return true,
    };
    // Skip hidden Padat temp files.
    if fname.contains(".padat.") && fname.ends_with(".tmp") {
        return true;
    }
    // Check dot-separated segments to catch `foo.db-wal`, `base.art.tmp`, `base.odex.swap.tmp`.
    let lower = fname.to_ascii_lowercase();
    for seg in lower.split('.').skip(1) {
        if BLOCKED_EXTENSIONS.iter().any(|&e| e == seg) {
            return true;
        }
    }
    false
}

/// Computes Shannon byte entropy in bits/byte scaled by 100 (range 0..800).
pub fn shannon_entropy_x100(data: &[u8]) -> u16 {
    if data.is_empty() {
        return 0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            h -= p * p.log2();
        }
    }
    (h * 100.0).round().clamp(0.0, 800.0) as u16
}

/// Fast pure-Rust LZ4 block size estimator (4096-entry hash table, O(N), ~0.15 ms per 64 KB).
/// Returns estimated compressed payload size in bytes.
pub fn estimate_lz4_block_size(src: &[u8]) -> usize {
    let n = src.len();
    if n < 16 {
        return n;
    }
    const HASH_BITS: usize = 12;
    const HASH_SIZE: usize = 1 << HASH_BITS;
    let mut table = [u32::MAX; HASH_SIZE];

    let mut pos = 0usize;
    let mut anchor = 0usize;
    let mut out_len = 0usize;
    let limit = n.saturating_sub(12);

    while pos < limit {
        let v = u32::from_le_bytes([src[pos], src[pos + 1], src[pos + 2], src[pos + 3]]);
        let h = ((v.wrapping_mul(2654435761u32)) >> (32 - HASH_BITS)) as usize;
        let prev = table[h];
        table[h] = pos as u32;

        if prev != u32::MAX {
            let prev = prev as usize;
            let dist = pos - prev;
            if dist > 0 && dist <= 65535
                && src[prev] == src[pos]
                && src[prev + 1] == src[pos + 1]
                && src[prev + 2] == src[pos + 2]
                && src[prev + 3] == src[pos + 3]
            {
                let mut mlen = 4usize;
                while pos + mlen < limit && src[prev + mlen] == src[pos + mlen] {
                    mlen += 1;
                }
                let lit_len = pos - anchor;
                // Token (1) + extra literal len bytes + literals + offset (2) + extra match len bytes
                out_len += 1 + lit_len + 2;
                if lit_len >= 15 {
                    out_len += (lit_len - 15) / 255 + 1;
                }
                if mlen - 4 >= 15 {
                    out_len += (mlen - 4 - 15) / 255 + 1;
                }
                pos += mlen;
                anchor = pos;
                continue;
            }
        }
        pos += 1;
    }
    // Trailing literals
    let rem = n - anchor;
    out_len += 1 + rem;
    if rem >= 15 {
        out_len += (rem - 15) / 255 + 1;
    }
    out_len
}

/// Simulates exact F2FS cluster block savings on a sample slice (returns saved % 0..100).
pub fn estimate_cluster_saving_pct(data: &[u8], cluster_bytes: usize, algo: CompAlgo) -> u8 {
    let csize = cluster_bytes.max(16384);
    let pages_per_cluster = csize / PAGE_SIZE;
    let max_clen = csize - PAGE_SIZE - F2FS_COMPRESS_HEADER;

    let mut total_blocks = 0usize;
    let mut used_blocks = 0usize;

    for chunk in data.chunks(csize) {
        if chunk.len() < PAGE_SIZE * 4 {
            continue;
        }
        let chunk_pages = (chunk.len() + PAGE_SIZE - 1) / PAGE_SIZE;
        total_blocks += chunk_pages;
        // Fast entropy screen BEFORE running LZ4 hash matching: encrypted / pre-compressed
        // chunks (>= 7.95 bits/byte) cannot be shrunk by LZ4, LZ4HC, or ZSTD.
        let ent = shannon_entropy_x100(chunk);
        if ent >= 795 {
            used_blocks += chunk_pages;
            continue;
        }
        let lz4_len = estimate_lz4_block_size(chunk);
        // ZSTD/LZ4HC achieve tighter ratios than fast LZ4 on structured data (non-random),
        // modeled conservatively as ~0.82x (ZSTD) / ~0.90x (LZ4HC) when LZ4 finds real matches
        // or entropy < 7.80.
        let est_len = match algo {
            CompAlgo::Lz4 => lz4_len,
            CompAlgo::Lz4Hc => {
                if lz4_len < chunk.len() {
                    (lz4_len * 90) / 100
                } else {
                    lz4_len
                }
            }
            CompAlgo::Zstd => {
                // Entropy bound + LZ4 match boost
                let ent_bound = ((chunk.len() as u64 * ent as u64) / 800) as usize;
                let lz4_scaled = (lz4_len * 78) / 100;
                lz4_scaled.min(ent_bound.max(chunk.len() / 8))
            }
        };
        let eff_max = if chunk_pages == pages_per_cluster {
            max_clen
        } else {
            (chunk_pages.saturating_sub(1)) * PAGE_SIZE - F2FS_COMPRESS_HEADER
        };
        if est_len <= eff_max {
            used_blocks += (est_len + F2FS_COMPRESS_HEADER + PAGE_SIZE - 1) / PAGE_SIZE;
        } else {
            used_blocks += chunk_pages;
        }
    }

    if total_blocks == 0 || used_blocks >= total_blocks {
        return 0;
    }
    (((total_blocks - used_blocks) * 100) / total_blocks) as u8
}

/// Returns true if `data` starts with the 16-byte SQLite 3 database header (`"SQLite format 3\0"`).
pub fn is_sqlite_header(data: &[u8]) -> bool {
    data.len() >= SQLITE_MAGIC.len() && &data[..SQLITE_MAGIC.len()] == SQLITE_MAGIC
}

/// Pure in-memory Smart Probe on an already-read file buffer (zero extra syscalls/seeks!).
pub fn probe_slice(
    path: &Path,
    data: &[u8],
    profile: CompProfile,
    min_saving_pct: u8,
) -> ProbeVerdict {
    if is_path_excluded(path) || is_sqlite_header(data) {
        return ProbeVerdict::ExcludedPolicy;
    }
    let csize = profile.cluster_bytes();
    if data.len() < 16384 {
        return ProbeVerdict::Incompressible {
            entropy_x100: 0,
            est_saving_pct: 0,
        };
    }
    let entropy = shannon_entropy_x100(data);
    if entropy >= 795 {
        return ProbeVerdict::Incompressible {
            entropy_x100: entropy,
            est_saving_pct: 0,
        };
    }
    let est = estimate_cluster_saving_pct(data, csize, profile.algo);
    let admit_threshold = (min_saving_pct / 2).max(4);
    if est >= admit_threshold {
        ProbeVerdict::Compress(est)
    } else {
        ProbeVerdict::Incompressible {
            entropy_x100: entropy,
            est_saving_pct: est,
        }
    }
}

/// Probes up to 4 aligned clusters (<= 256 KB total) using an already-open `File` (reusing the fd
/// without double-opening, and rewinding to offset 0 when returning `ProbeVerdict::Compress`).
pub fn probe_fd(
    f: &mut File,
    path: &Path,
    file_size: u64,
    profile: CompProfile,
    min_saving_pct: u8,
) -> io::Result<ProbeVerdict> {
    if is_path_excluded(path) {
        return Ok(ProbeVerdict::ExcludedPolicy);
    }

    let csize = profile.cluster_bytes();
    if file_size < (csize as u64).min(16384) {
        return Ok(ProbeVerdict::Incompressible {
            entropy_x100: 0,
            est_saving_pct: 0,
        });
    }

    let _ = f.seek(SeekFrom::Start(0));

    // Check magic header (16 bytes) to exclude extensionless SQLite databases (e.g. game `meta`
    // or `.mdb` catalogs) that must NEVER hit F2FS CP_COMPRESSED fsync checkpoints or atomic writes.
    let mut magic = [0u8; 16];
    if f.read(&mut magic)? == 16 && is_sqlite_header(&magic) {
        return Ok(ProbeVerdict::ExcludedPolicy);
    }
    let _ = f.seek(SeekFrom::Start(0));

    // Fast 16 KB mid-file entropy screen for non-archive large files: encrypted game blobs
    // (`.blk`, `.pak`, `.chk`, `.pck`) fail in a single 16 KB read (~15 us) instead of 4x64 KB seeks.
    let ext_lower = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase());
    let is_mixed_container = matches!(ext_lower.as_deref(), Some("apk") | Some("obb"));
    if !is_mixed_container && file_size >= 65536 {
        let mut quick = [0u8; 16384];
        let probe_off = ((file_size / 3) / 4096) * 4096;
        if f.seek(SeekFrom::Start(probe_off)).is_ok() {
            let mut got = 0usize;
            while got < quick.len() {
                let n = f.read(&mut quick[got..])?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            if got == quick.len() {
                let h1 = shannon_entropy_x100(&quick);
                if h1 >= 795 {
                    if file_size < 4 * 1024 * 1024 {
                        return Ok(ProbeVerdict::Incompressible {
                            entropy_x100: h1,
                            est_saving_pct: 0,
                        });
                    }
                    let off2 = (((file_size * 2) / 3) / 4096) * 4096;
                    if f.seek(SeekFrom::Start(off2)).is_ok() {
                        let mut got2 = 0usize;
                        while got2 < quick.len() {
                            let n = f.read(&mut quick[got2..])?;
                            if n == 0 {
                                break;
                            }
                            got2 += n;
                        }
                        if got2 == quick.len() && shannon_entropy_x100(&quick) >= 795 {
                            return Ok(ProbeVerdict::Incompressible {
                                entropy_x100: h1,
                                est_saving_pct: 0,
                            });
                        }
                    }
                }
            }
        }
    }

    // Choose up to 4 cluster-aligned offsets (max 256 KB read total).
    let max_samples = (262_144 / csize).clamp(2, 4);
    let mut sample_buf = Vec::with_capacity(csize * max_samples);
    let mut tmp = vec![0u8; csize];

    let offsets: Vec<u64> = if file_size <= (csize * max_samples) as u64 {
        vec![0]
    } else {
        let mut offs = Vec::with_capacity(max_samples);
        let max_off = ((file_size - csize as u64) / csize as u64) * csize as u64;
        for i in 0..max_samples {
            let off = (max_off * i as u64) / ((max_samples - 1) as u64);
            let aligned = (off / csize as u64) * csize as u64;
            if !offs.contains(&aligned) {
                offs.push(aligned);
            }
        }
        offs
    };

    if offsets.len() == 1 && file_size <= (csize * max_samples) as u64 {
        let _ = f.seek(SeekFrom::Start(0));
        let mut total = vec![0u8; file_size as usize];
        let mut got = 0usize;
        while got < total.len() {
            let n = f.read(&mut total[got..])?;
            if n == 0 {
                break;
            }
            got += n;
        }
        sample_buf.extend_from_slice(&total[..got]);
    } else {
        for off in offsets {
            if f.seek(SeekFrom::Start(off)).is_ok() {
                let mut got = 0usize;
                while got < csize {
                    let n = f.read(&mut tmp[got..])?;
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
                if got >= 16384 {
                    sample_buf.extend_from_slice(&tmp[..got]);
                }
            }
        }
    }

    if sample_buf.len() < 16384 {
        return Ok(ProbeVerdict::Incompressible {
            entropy_x100: 0,
            est_saving_pct: 0,
        });
    }

    let entropy = shannon_entropy_x100(&sample_buf);
    let est = estimate_cluster_saving_pct(&sample_buf, csize, profile.algo);

    if entropy >= 795 && est == 0 {
        return Ok(ProbeVerdict::Incompressible {
            entropy_x100: entropy,
            est_saving_pct: 0,
        });
    }

    let admit_threshold = (min_saving_pct / 2).max(4);
    if est >= admit_threshold {
        let _ = f.seek(SeekFrom::Start(0));
        Ok(ProbeVerdict::Compress(est))
    } else {
        Ok(ProbeVerdict::Incompressible {
            entropy_x100: entropy,
            est_saving_pct: est,
        })
    }
}

/// Convenience wrapper opening `path` and running `probe_fd`.
pub fn probe_file(
    path: &Path,
    file_size: u64,
    profile: CompProfile,
    min_saving_pct: u8,
) -> io::Result<ProbeVerdict> {
    if is_path_excluded(path) {
        return Ok(ProbeVerdict::ExcludedPolicy);
    }
    let mut f = File::open(path)?;
    probe_fd(&mut f, path, file_size, profile, min_saving_pct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_exclusions_block_dbs_art_swap_media() {
        assert!(is_path_excluded(Path::new("/data/user/0/foo/databases/main.db")));
        assert!(is_path_excluded(Path::new("/data/user/0/foo/files/x.db-wal")));
        assert!(is_path_excluded(Path::new("/data/app/x/oat/arm64/base.art")));
        assert!(is_path_excluded(Path::new("/data/app/x/oat/arm64/base.odex.swap.1234.tmp")));
        assert!(is_path_excluded(Path::new("/data/media/0/Android/data/g/files/v.mp4")));
        assert!(!is_path_excluded(Path::new("/data/app/x/base.apk")));
        assert!(!is_path_excluded(Path::new("/data/app/x/oat/arm64/base.odex")));
        assert!(!is_path_excluded(Path::new("/data/app/x/oat/arm64/base.vdex")));
        assert!(!is_path_excluded(Path::new("/data/media/0/Android/data/g/files/Asb/foo.bytes")));
    }

    #[test]
    fn incompressible_random_blob_is_rejected() {
        // xorshift64 pseudo-random data mimics encrypted game blobs (entropy ~7.99 bits/byte).
        let mut s: u64 = 0xdead_beef_cafe_babe;
        let mut rnd = vec![0u8; 65536];
        for b in &mut rnd {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = s as u8;
        }
        assert!(shannon_entropy_x100(&rnd) >= 795);
        assert_eq!(estimate_cluster_saving_pct(&rnd, 16384, CompAlgo::Lz4), 0);
        assert_eq!(estimate_cluster_saving_pct(&rnd, 65536, CompAlgo::Zstd), 0);
    }

    #[test]
    fn structured_code_blob_compresses_well() {
        let mut buf = Vec::with_capacity(65536);
        for i in 0..1024u32 {
            buf.extend_from_slice(b"com/android/server/yasvara/padat/EngineMethod");
            buf.extend_from_slice(&i.to_le_bytes());
            buf.extend_from_slice(&[0u8; 15]);
        }
        let lz4 = estimate_cluster_saving_pct(&buf, 16384, CompAlgo::Lz4);
        let zstd = estimate_cluster_saving_pct(&buf, 65536, CompAlgo::Zstd);
        assert!(lz4 >= 40, "expected >=40% lz4, got {lz4}%");
        assert!(zstd >= lz4, "expected zstd ({zstd}%) >= lz4 ({lz4}%)");
    }
}
