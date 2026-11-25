// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust AOSP `liblp` v10.0 / v10.2 parser, serializer, same-slot CoW planner
//! (`yv install kernel`), and multi-extent inactive-slot CoW planner with
//! Sub-Partition `dm-linear` Extent Aliasing (`LP_TARGET_TYPE_LINEAR` + `LP_TARGET_TYPE_ZERO`).

use std::collections::{BTreeMap, HashMap};

use crate::crypto::sha256_bytes;

pub const LP_SECTOR_SIZE: u64 = 512;
pub const LP_BLOCK_SIZE: u64 = 4096;
pub const LP_SECTORS_PER_BLOCK: u64 = LP_BLOCK_SIZE / LP_SECTOR_SIZE; // 8
pub const LP_PARTITION_RESERVED_BYTES: usize = 4096;
pub const LP_METADATA_GEOMETRY_SIZE: usize = 4096;
pub const LP_METADATA_GEOMETRY_MAGIC: u32 = 0x616C4467;
pub const LP_METADATA_HEADER_MAGIC: u32 = 0x414C5030;
pub const LP_TARGET_TYPE_LINEAR: u32 = 0;
pub const LP_TARGET_TYPE_ZERO: u32 = 1;
pub const LP_HEADER_SIZE_V1_0: usize = 128;
pub const LP_HEADER_SIZE_V1_2: usize = 256;

pub const LP_PARTITION_ATTR_READONLY: u32 = 1 << 0;
pub const LP_PARTITION_ATTR_SLOT_SUFFIXED: u32 = 1 << 1;
pub const LP_PARTITION_ATTR_UPDATED: u32 = 1 << 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LpGeometry {
    pub metadata_max_size: u32,
    pub metadata_slot_count: u32,
    pub logical_block_size: u32,
}

impl LpGeometry {
    pub fn primary_offset(&self, slot: u32) -> usize {
        LP_PARTITION_RESERVED_BYTES
            + (LP_METADATA_GEOMETRY_SIZE * 2)
            + (self.metadata_max_size as usize) * (slot as usize)
    }

    pub fn backup_offset(&self, slot: u32) -> usize {
        let start = LP_PARTITION_RESERVED_BYTES
            + (LP_METADATA_GEOMETRY_SIZE * 2)
            + (self.metadata_max_size as usize) * (self.metadata_slot_count as usize);
        start + (self.metadata_max_size as usize) * (slot as usize)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LpPartition {
    pub name: String,
    pub attributes: u32,
    pub first_extent_index: u32,
    pub num_extents: u32,
    pub group_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LpExtent {
    pub num_sectors: u64,
    pub target_type: u32,
    pub target_data: u64,
    pub target_source: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LpGroup {
    pub name: String,
    pub flags: u32,
    pub maximum_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LpBlockDevice {
    pub first_logical_sector: u64,
    pub alignment: u32,
    pub alignment_offset: u32,
    pub size: u64,
    pub partition_name: String,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LpMetadata {
    pub major_version: u16,
    pub minor_version: u16,
    pub header_size: u32,
    pub flags: u32,
    pub reserved: Vec<u8>,
    pub partitions: Vec<LpPartition>,
    pub extents: Vec<LpExtent>,
    pub groups: Vec<LpGroup>,
    pub block_devices: Vec<LpBlockDevice>,
}

impl LpMetadata {
    pub fn partition_extents(&self, part: &LpPartition) -> &[LpExtent] {
        let s = part.first_extent_index as usize;
        let e = (s + part.num_extents as usize).min(self.extents.len());
        if s >= self.extents.len() {
            &[]
        } else {
            &self.extents[s..e]
        }
    }

    pub fn partition_size_bytes(&self, name: &str) -> Option<u64> {
        let p = self.partitions.iter().find(|p| p.name == name)?;
        let sectors: u64 = self.partition_extents(p).iter().map(|e| e.num_sectors).sum();
        Some(sectors * LP_SECTOR_SIZE)
    }

    pub fn super_size_bytes(&self) -> u64 {
        self.block_devices.first().map(|b| b.size).unwrap_or(0)
    }
}

#[inline]
fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
#[inline]
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
#[inline]
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn decode_cstr(raw: &[u8]) -> String {
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn encode_cstr(s: &str, width: usize) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() > width {
        return Err(format!("ASCII name too long ({} > {width}): {s}", b.len()));
    }
    let mut out = vec![0u8; width];
    out[..b.len()].copy_from_slice(b);
    Ok(out)
}

pub fn align_up(val: u64, align: u64) -> u64 {
    if align <= 1 {
        return val;
    }
    val.div_ceil(align) * align
}

pub fn merge_intervals(mut ivs: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ivs.retain(|&(s, e)| s < e);
    if ivs.is_empty() {
        return ivs;
    }
    ivs.sort_unstable();
    let mut out = vec![ivs[0]];
    for (s, e) in ivs.into_iter().skip(1) {
        let last = out.last_mut().unwrap();
        if s <= last.1 {
            last.1 = last.1.max(e);
        } else {
            out.push((s, e));
        }
    }
    out
}

pub fn parse_geometry(buf: &[u8]) -> Result<LpGeometry, String> {
    for off in [
        LP_PARTITION_RESERVED_BYTES,
        LP_PARTITION_RESERVED_BYTES + LP_METADATA_GEOMETRY_SIZE,
    ] {
        if off + 52 > buf.len() {
            continue;
        }
        let raw = &buf[off..off + 52];
        let magic = u32le(raw, 0);
        let struct_size = u32le(raw, 4);
        if magic != LP_METADATA_GEOMETRY_MAGIC || struct_size != 52 {
            continue;
        }
        let mut zeroed = [0u8; 52];
        zeroed[..8].copy_from_slice(&raw[..8]);
        zeroed[40..52].copy_from_slice(&raw[40..52]);
        if sha256_bytes(&zeroed) == raw[8..40] {
            return Ok(LpGeometry {
                metadata_max_size: u32le(raw, 40),
                metadata_slot_count: u32le(raw, 44),
                logical_block_size: u32le(raw, 48),
            });
        }
    }
    Err("Invalid LpMetadataGeometry (both primary and backup failed magic/SHA-256)".into())
}

pub fn parse_slot_metadata(buf: &[u8], geom: &LpGeometry, slot: u32) -> Result<LpMetadata, String> {
    let max_sz = geom.metadata_max_size as usize;
    for off in [geom.primary_offset(slot), geom.backup_offset(slot)] {
        if off + LP_HEADER_SIZE_V1_0 > buf.len() {
            continue;
        }
        let end = (off + max_sz).min(buf.len());
        let blob = &buf[off..end];
        let magic = u32le(blob, 0);
        let major = u16le(blob, 4);
        let minor = u16le(blob, 6);
        let hdr_size = u32le(blob, 8) as usize;
        let tables_size = u32le(blob, 44) as usize;
        if magic != LP_METADATA_HEADER_MAGIC {
            continue;
        }
        if hdr_size != LP_HEADER_SIZE_V1_0 && hdr_size != LP_HEADER_SIZE_V1_2 {
            continue;
        }
        if hdr_size + tables_size > blob.len() {
            continue;
        }
        let mut hdr_zeroed = blob[..hdr_size].to_vec();
        for b in &mut hdr_zeroed[12..44] {
            *b = 0;
        }
        if sha256_bytes(&hdr_zeroed) != blob[12..44] {
            continue;
        }
        let tables = &blob[hdr_size..hdr_size + tables_size];
        if sha256_bytes(tables) != blob[48..80] {
            continue;
        }
        let p_off = u32le(blob, 80) as usize;
        let p_num = u32le(blob, 84) as usize;
        let p_es = u32le(blob, 88) as usize;
        let e_off = u32le(blob, 92) as usize;
        let e_num = u32le(blob, 96) as usize;
        let e_es = u32le(blob, 100) as usize;
        let g_off = u32le(blob, 104) as usize;
        let g_num = u32le(blob, 108) as usize;
        let g_es = u32le(blob, 112) as usize;
        let b_off = u32le(blob, 116) as usize;
        let b_num = u32le(blob, 120) as usize;
        let b_es = u32le(blob, 124) as usize;
        if p_es != 52 || e_es != 24 || g_es != 48 || b_es != 64 {
            return Err(format!(
                "Unsupported LpMetadata entry sizes: p={p_es} e={e_es} g={g_es} b={b_es}"
            ));
        }
        if p_off + p_num * 52 > tables.len()
            || e_off + e_num * 24 > tables.len()
            || g_off + g_num * 48 > tables.len()
            || b_off + b_num * 64 > tables.len()
        {
            continue;
        }
        let (flags, reserved) = if hdr_size == LP_HEADER_SIZE_V1_2 {
            (u32le(blob, 128), blob[132..256].to_vec())
        } else {
            (0, Vec::new())
        };

        let mut partitions = Vec::with_capacity(p_num);
        for i in 0..p_num {
            let s = p_off + i * 52;
            partitions.push(LpPartition {
                name: decode_cstr(&tables[s..s + 36]),
                attributes: u32le(tables, s + 36),
                first_extent_index: u32le(tables, s + 40),
                num_extents: u32le(tables, s + 44),
                group_index: u32le(tables, s + 48),
            });
        }
        let mut extents = Vec::with_capacity(e_num);
        for i in 0..e_num {
            let s = e_off + i * 24;
            extents.push(LpExtent {
                num_sectors: u64le(tables, s),
                target_type: u32le(tables, s + 8),
                target_data: u64le(tables, s + 12),
                target_source: u32le(tables, s + 20),
            });
        }
        let mut groups = Vec::with_capacity(g_num);
        for i in 0..g_num {
            let s = g_off + i * 48;
            groups.push(LpGroup {
                name: decode_cstr(&tables[s..s + 36]),
                flags: u32le(tables, s + 36),
                maximum_size: u64le(tables, s + 40),
            });
        }
        let mut block_devices = Vec::with_capacity(b_num);
        for i in 0..b_num {
            let s = b_off + i * 64;
            block_devices.push(LpBlockDevice {
                first_logical_sector: u64le(tables, s),
                alignment: u32le(tables, s + 8),
                alignment_offset: u32le(tables, s + 12),
                size: u64le(tables, s + 16),
                partition_name: decode_cstr(&tables[s + 24..s + 60]),
                flags: u32le(tables, s + 60),
            });
        }
        return Ok(LpMetadata {
            major_version: major,
            minor_version: minor,
            header_size: hdr_size as u32,
            flags,
            reserved,
            partitions,
            extents,
            groups,
            block_devices,
        });
    }
    Err(format!("Failed to parse valid LpMetadata for slot {slot}"))
}

pub fn serialize_metadata(meta: &LpMetadata, geom: &LpGeometry) -> Result<Vec<u8>, String> {
    let mut p_blob = Vec::with_capacity(meta.partitions.len() * 52);
    for p in &meta.partitions {
        p_blob.extend_from_slice(&encode_cstr(&p.name, 36)?);
        p_blob.extend_from_slice(&p.attributes.to_le_bytes());
        p_blob.extend_from_slice(&p.first_extent_index.to_le_bytes());
        p_blob.extend_from_slice(&p.num_extents.to_le_bytes());
        p_blob.extend_from_slice(&p.group_index.to_le_bytes());
    }
    let mut e_blob = Vec::with_capacity(meta.extents.len() * 24);
    for e in &meta.extents {
        e_blob.extend_from_slice(&e.num_sectors.to_le_bytes());
        e_blob.extend_from_slice(&e.target_type.to_le_bytes());
        e_blob.extend_from_slice(&e.target_data.to_le_bytes());
        e_blob.extend_from_slice(&e.target_source.to_le_bytes());
    }
    let mut g_blob = Vec::with_capacity(meta.groups.len() * 48);
    for g in &meta.groups {
        g_blob.extend_from_slice(&encode_cstr(&g.name, 36)?);
        g_blob.extend_from_slice(&g.flags.to_le_bytes());
        g_blob.extend_from_slice(&g.maximum_size.to_le_bytes());
    }
    let mut b_blob = Vec::with_capacity(meta.block_devices.len() * 64);
    for b in &meta.block_devices {
        b_blob.extend_from_slice(&b.first_logical_sector.to_le_bytes());
        b_blob.extend_from_slice(&b.alignment.to_le_bytes());
        b_blob.extend_from_slice(&b.alignment_offset.to_le_bytes());
        b_blob.extend_from_slice(&b.size.to_le_bytes());
        b_blob.extend_from_slice(&encode_cstr(&b.partition_name, 36)?);
        b_blob.extend_from_slice(&b.flags.to_le_bytes());
    }

    let p_off = 0u32;
    let e_off = p_blob.len() as u32;
    let g_off = e_off + e_blob.len() as u32;
    let b_off = g_off + g_blob.len() as u32;
    let mut tables = Vec::with_capacity((b_off as usize) + b_blob.len());
    tables.extend_from_slice(&p_blob);
    tables.extend_from_slice(&e_blob);
    tables.extend_from_slice(&g_blob);
    tables.extend_from_slice(&b_blob);
    let tables_csum = sha256_bytes(&tables);

    let mut hdr = Vec::with_capacity(meta.header_size as usize);
    hdr.extend_from_slice(&LP_METADATA_HEADER_MAGIC.to_le_bytes());
    hdr.extend_from_slice(&meta.major_version.to_le_bytes());
    hdr.extend_from_slice(&meta.minor_version.to_le_bytes());
    hdr.extend_from_slice(&meta.header_size.to_le_bytes());
    hdr.extend_from_slice(&[0u8; 32]); // placeholder header_checksum
    hdr.extend_from_slice(&(tables.len() as u32).to_le_bytes());
    hdr.extend_from_slice(&tables_csum);
    for (off, num, es) in [
        (p_off, meta.partitions.len() as u32, 52u32),
        (e_off, meta.extents.len() as u32, 24u32),
        (g_off, meta.groups.len() as u32, 48u32),
        (b_off, meta.block_devices.len() as u32, 64u32),
    ] {
        hdr.extend_from_slice(&off.to_le_bytes());
        hdr.extend_from_slice(&num.to_le_bytes());
        hdr.extend_from_slice(&es.to_le_bytes());
    }
    if meta.header_size as usize == LP_HEADER_SIZE_V1_2 {
        hdr.extend_from_slice(&meta.flags.to_le_bytes());
        let mut res = vec![0u8; 124];
        let take = meta.reserved.len().min(124);
        res[..take].copy_from_slice(&meta.reserved[..take]);
        hdr.extend_from_slice(&res);
    }
    let hdr_csum = sha256_bytes(&hdr);
    hdr[12..44].copy_from_slice(&hdr_csum);

    let mut blob = hdr;
    blob.extend_from_slice(&tables);
    if blob.len() > geom.metadata_max_size as usize {
        return Err(format!(
            "Serialized LpMetadata ({} B) exceeds max ({} B)",
            blob.len(),
            geom.metadata_max_size
        ));
    }
    Ok(blob)
}

/// Build a fresh 1 MiB `super` metadata image (geometry + slots) for synthetic host testing.
pub fn build_synthetic_super_header(
    super_size_bytes: u64,
    slot0: &LpMetadata,
    slot1: &LpMetadata,
) -> Result<Vec<u8>, String> {
    let geom = LpGeometry {
        metadata_max_size: 65536,
        metadata_slot_count: 2,
        logical_block_size: 4096,
    };
    let mut geom_raw = [0u8; 52];
    geom_raw[0..4].copy_from_slice(&LP_METADATA_GEOMETRY_MAGIC.to_le_bytes());
    geom_raw[4..8].copy_from_slice(&52u32.to_le_bytes());
    geom_raw[40..44].copy_from_slice(&geom.metadata_max_size.to_le_bytes());
    geom_raw[44..48].copy_from_slice(&geom.metadata_slot_count.to_le_bytes());
    geom_raw[48..52].copy_from_slice(&geom.logical_block_size.to_le_bytes());
    let gsum = sha256_bytes(&geom_raw);
    geom_raw[8..40].copy_from_slice(&gsum);

    let mut buf = vec![0u8; 1024 * 1024];
    buf[LP_PARTITION_RESERVED_BYTES..LP_PARTITION_RESERVED_BYTES + 52].copy_from_slice(&geom_raw);
    let g2 = LP_PARTITION_RESERVED_BYTES + LP_METADATA_GEOMETRY_SIZE;
    buf[g2..g2 + 52].copy_from_slice(&geom_raw);

    for (slot, meta) in [(0u32, slot0), (1u32, slot1)] {
        let mut m = meta.clone();
        if let Some(bd) = m.block_devices.first_mut() {
            bd.size = super_size_bytes;
        }
        let blob = serialize_metadata(&m, &geom)?;
        let pri = geom.primary_offset(slot);
        let bak = geom.backup_offset(slot);
        buf[pri..pri + blob.len()].copy_from_slice(&blob);
        buf[bak..bak + blob.len()].copy_from_slice(&blob);
    }
    Ok(buf)
}

/// Same-slot CoW metadata planner (used by `yv install kernel` — replaces single-extent partitions
/// on `slot_num` without overlapping ANY slot's existing extents or live `dm-linear` extents).
pub fn plan_cow_metadata(
    meta_buf: &[u8],
    slot_num: u32,
    updates: &BTreeMap<String, u64>,
    extra_occupied: &[(u64, u64)],
) -> Result<(Vec<u8>, Vec<u8>, BTreeMap<String, (u64, u64)>), String> {
    let geom = parse_geometry(meta_buf)?;
    let active = parse_slot_metadata(meta_buf, &geom, slot_num)?;
    let super_dev = active
        .block_devices
        .first()
        .ok_or_else(|| "LpMetadata has no block_devices".to_string())?;
    let super_sectors = super_dev.size / LP_SECTOR_SIZE;

    let mut occupied: Vec<(u64, u64)> = extra_occupied.to_vec();
    for s in 0..geom.metadata_slot_count {
        if let Ok(sm) = parse_slot_metadata(meta_buf, &geom, s) {
            for ext in &sm.extents {
                if ext.target_type == LP_TARGET_TYPE_LINEAR && ext.target_source == 0 {
                    occupied.push((ext.target_data, ext.target_data + ext.num_sectors));
                }
            }
        }
    }
    let occupied = merge_intervals(occupied);
    let free_gaps = compute_free_gaps(super_dev.first_logical_sector, super_sectors, &occupied);

    let align_bytes = (1024u64 * 1024)
        .max(super_dev.alignment as u64)
        .max(geom.logical_block_size as u64);
    let align_sectors = align_bytes / LP_SECTOR_SIZE;
    let blk_sectors = (geom.logical_block_size as u64).max(LP_BLOCK_SIZE) / LP_SECTOR_SIZE;

    for pname in updates.keys() {
        if !active.partitions.iter().any(|p| &p.name == pname) {
            return Err(format!(
                "Partition `{pname}` not found in LpMetadata slot {slot_num}"
            ));
        }
    }

    let mut allocs: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut working_gaps = free_gaps.clone();
    for (pname, &img_bytes) in updates {
        if img_bytes == 0 {
            return Err(format!("Invalid 0-byte image for {pname}"));
        }
        let raw_sectors = align_up(img_bytes, LP_SECTOR_SIZE) / LP_SECTOR_SIZE;
        let need_sectors = align_up(raw_sectors, blk_sectors);
        let placed = take_contiguous_gap(&mut working_gaps, need_sectors, align_sectors, blk_sectors)
            .ok_or_else(|| {
                let free_mib: f64 = free_gaps
                    .iter()
                    .map(|(gs, ge)| (ge - gs) * LP_SECTOR_SIZE)
                    .sum::<u64>() as f64
                    / (1024.0 * 1024.0);
                format!(
                    "Insufficient contiguous free space in super for {pname} ({:.1} MiB needed; {:.1} MiB free)",
                    (need_sectors * LP_SECTOR_SIZE) as f64 / (1024.0 * 1024.0),
                    free_mib
                )
            })?;
        allocs.insert(pname.clone(), placed);
    }

    // Strict non-overlap assertion
    for (pname, &(ns, nl)) in &allocs {
        let ne = ns + nl;
        if ns < super_dev.first_logical_sector || ne > super_sectors {
            return Err(format!("CoW extent out of bounds for {pname}: {ns}..{ne}"));
        }
        for &(os, oe) in &occupied {
            if !(ne <= os || ns >= oe) {
                return Err(format!(
                    "CoW overlap detected for {pname}: [{ns},{ne}) vs [{os},{oe})"
                ));
            }
        }
    }

    let mut new_parts = Vec::with_capacity(active.partitions.len());
    let mut new_exts = Vec::with_capacity(active.extents.len());
    let mut grp_totals: HashMap<u32, u64> = HashMap::new();

    for p in &active.partitions {
        let first_idx = new_exts.len() as u32;
        let (num_ext, p_bytes) = if let Some(&(st, n)) = allocs.get(&p.name) {
            new_exts.push(LpExtent {
                num_sectors: n,
                target_type: LP_TARGET_TYPE_LINEAR,
                target_data: st,
                target_source: 0,
            });
            (1u32, n * LP_SECTOR_SIZE)
        } else {
            let slice = active.partition_extents(p);
            new_exts.extend_from_slice(slice);
            let bytes: u64 = slice.iter().map(|x| x.num_sectors * LP_SECTOR_SIZE).sum();
            (p.num_extents, bytes)
        };
        new_parts.push(LpPartition {
            name: p.name.clone(),
            attributes: p.attributes,
            first_extent_index: first_idx,
            num_extents: num_ext,
            group_index: p.group_index,
        });
        *grp_totals.entry(p.group_index).or_insert(0) += p_bytes;
    }

    for (gi, total_b) in grp_totals {
        let g = &active.groups[gi as usize];
        if g.maximum_size > 0 && total_b > g.maximum_size {
            return Err(format!(
                "Group `{}` size {total_b} exceeds maximum_size {}",
                g.name, g.maximum_size
            ));
        }
    }

    let new_meta = LpMetadata {
        major_version: active.major_version,
        minor_version: active.minor_version,
        header_size: active.header_size,
        flags: active.flags,
        reserved: active.reserved.clone(),
        partitions: new_parts,
        extents: new_exts,
        groups: active.groups.clone(),
        block_devices: active.block_devices.clone(),
    };
    let (out_buf, slot_blob) = commit_slot_into_buffer(meta_buf, &geom, slot_num, &new_meta)?;

    // Self-verify roundtrip parse
    let reparsed = parse_slot_metadata(&out_buf, &geom, slot_num)?;
    for (pname, &(exp_s, exp_n)) in &allocs {
        let rp = reparsed
            .partitions
            .iter()
            .find(|p| &p.name == pname)
            .ok_or_else(|| format!("Reparsed metadata missing {pname}"))?;
        let rext = &reparsed.extents[rp.first_extent_index as usize];
        if rp.num_extents != 1 || rext.target_data != exp_s || rext.num_sectors != exp_n {
            return Err(format!("Reparsed extent mismatch for {pname}"));
        }
    }

    Ok((out_buf, slot_blob, allocs))
}

// ====================================================== Inactive-Slot CoW + Extent Aliasing Planner

/// Logical run describing how a slice of a new inactive-slot partition is backed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalRun {
    /// Zero-copy alias pointing directly at an active-slot physical sector range (0 B UFS write!).
    Alias {
        phys_start_sector: u64,
        num_sectors: u64,
    },
    /// Sparse all-zero run emitted as `LP_TARGET_TYPE_ZERO` (0 B UFS write, 0 super space!).
    Zero { num_sectors: u64 },
    /// Delta run needing freshly allocated free sectors in `super`.
    Allocate { num_sectors: u64 },
}

impl LogicalRun {
    pub fn num_sectors(&self) -> u64 {
        match *self {
            LogicalRun::Alias { num_sectors, .. }
            | LogicalRun::Zero { num_sectors }
            | LogicalRun::Allocate { num_sectors } => num_sectors,
        }
    }
}

/// Input specification for one dynamic partition in the target inactive slot.
#[derive(Debug, Clone)]
pub struct OtaPartitionExtentSpec {
    /// Base partition name without slot suffix (e.g. `"system"`, `"vendor"`).
    pub base_name: String,
    /// Exact virtual size in bytes (rounded up to 4 KiB block boundary).
    pub total_bytes: u64,
    /// Ordered runs covering `align_up(total_bytes, 4096) / 512` sectors.
    pub runs: Vec<LogicalRun>,
}

/// Anti-fragmentation & extent budget limits for `dm-linear` Extent Aliasing.
#[derive(Debug, Clone, Copy)]
pub struct ExtentLimits {
    /// Maximum `dm-linear` extents allowed per dynamic partition (default: 64).
    pub max_extents_per_part: usize,
    /// Maximum total extents across all partitions in target slot (default: 256).
    pub max_total_extents: usize,
    /// Minimum contiguous Alias run length in 512B sectors (default: 512 = 256 KiB).
    pub min_alias_sectors: u64,
    /// Whether `LP_TARGET_TYPE_ZERO` (`dm-zero`) extents are allowed.
    /// Defaults to `false` because Android GKI kernels disable `CONFIG_DM_ZERO`!
    pub allow_dm_zero: bool,
}

impl Default for ExtentLimits {
    fn default() -> Self {
        Self {
            max_extents_per_part: 64,
            max_total_extents: 256,
            min_alias_sectors: 512, // 256 KiB
            allow_dm_zero: false,
        }
    }
}

/// Physical write instruction for an `Allocate` segment inside a dynamic partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalWriteSegment {
    /// Byte offset inside the new partition's virtual image.
    pub logical_byte_offset: u64,
    /// Physical byte offset inside `/dev/block/by-name/super`.
    pub super_byte_offset: u64,
    /// Exact number of bytes to write (4 KiB-aligned).
    pub length_bytes: u64,
}

/// Full plan for one dynamic partition in `target_slot`.
#[derive(Debug, Clone)]
pub struct PlannedDynamicPartition {
    pub base_name: String,
    pub target_name: String,
    pub total_bytes: u64,
    pub extents: Vec<LpExtent>,
    pub write_segments: Vec<PhysicalWriteSegment>,
    pub bytes_aliased: u64,
    pub bytes_zeroed: u64,
    pub bytes_to_write: u64,
}

/// Complete verified inactive-slot `super` plan ready for streaming write + atomic commit.
#[derive(Debug, Clone)]
pub struct OtaSuperPlan {
    pub active_slot: u32,
    pub target_slot: u32,
    pub geometry: LpGeometry,
    pub new_meta_buf: Vec<u8>,
    pub target_slot_blob: Vec<u8>,
    pub partitions: Vec<PlannedDynamicPartition>,
    pub total_bytes_aliased: u64,
    pub total_bytes_zeroed: u64,
    pub total_bytes_to_write: u64,
    pub total_extents: usize,
    pub free_bytes_before: u64,
    pub free_bytes_after: u64,
    pub compaction_demoted_runs: usize,
}

pub fn slot_suffix(slot: u32) -> &'static str {
    if slot == 0 { "_a" } else { "_b" }
}

fn compute_free_gaps(first_sector: u64, super_sectors: u64, occupied: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut free_gaps = Vec::new();
    let mut cursor = first_sector;
    for &(s, e) in occupied {
        if s > cursor && cursor < super_sectors {
            free_gaps.push((cursor, s.min(super_sectors)));
        }
        cursor = cursor.max(e);
    }
    if cursor < super_sectors {
        free_gaps.push((cursor, super_sectors));
    }
    free_gaps
}

fn take_contiguous_gap(
    working_gaps: &mut Vec<(u64, u64)>,
    need_sectors: u64,
    align_sectors: u64,
    blk_sectors: u64,
) -> Option<(u64, u64)> {
    for idx in 0..working_gaps.len() {
        let (gs, ge) = working_gaps[idx];
        let aligned_s = align_up(gs, align_sectors);
        if aligned_s + need_sectors <= ge {
            let next_s = align_up(aligned_s + need_sectors, blk_sectors);
            let mut rep = Vec::new();
            if aligned_s > gs {
                rep.push((gs, aligned_s));
            }
            if next_s < ge {
                rep.push((next_s, ge));
            }
            working_gaps.splice(idx..=idx, rep);
            return Some((aligned_s, need_sectors));
        }
    }
    None
}

/// Allocate `need_sectors` from `working_gaps` — prefers 1 MiB-aligned contiguous placement,
/// then 4 KiB-aligned contiguous placement, and finally scatter-gather multi-extent allocation!
fn take_scatter_gather(
    working_gaps: &mut Vec<(u64, u64)>,
    need_sectors: u64,
    align_sectors: u64,
    blk_sectors: u64,
) -> Result<Vec<(u64, u64)>, String> {
    if let Some(one) = take_contiguous_gap(working_gaps, need_sectors, align_sectors, blk_sectors) {
        return Ok(vec![one]);
    }
    if align_sectors != blk_sectors {
        if let Some(one) = take_contiguous_gap(working_gaps, need_sectors, blk_sectors, blk_sectors) {
            return Ok(vec![one]);
        }
    }
    // Scatter-gather across multiple 4 KiB-aligned free gaps (largest-first to minimize extent count)
    let mut rem = need_sectors;
    let mut pieces = Vec::new();
    let mut order: Vec<usize> = (0..working_gaps.len()).collect();
    order.sort_by(|&a, &b| {
        let la = working_gaps[a].1.saturating_sub(working_gaps[a].0);
        let lb = working_gaps[b].1.saturating_sub(working_gaps[b].0);
        lb.cmp(&la)
    });

    // Consume largest gaps first by rebuilding working_gaps cleanly
    let mut gaps = std::mem::take(working_gaps);
    gaps.sort_by(|a, b| (b.1 - b.0).cmp(&(a.1 - a.0)));
    let mut remaining_gaps = Vec::with_capacity(gaps.len());

    for (gs, ge) in gaps {
        if rem == 0 {
            remaining_gaps.push((gs, ge));
            continue;
        }
        let aligned_s = align_up(gs, blk_sectors);
        if aligned_s >= ge {
            remaining_gaps.push((gs, ge));
            continue;
        }
        let avail = ((ge - aligned_s) / blk_sectors) * blk_sectors;
        if avail == 0 {
            remaining_gaps.push((gs, ge));
            continue;
        }
        let take = rem.min(avail);
        pieces.push((aligned_s, take));
        rem -= take;
        if aligned_s > gs {
            remaining_gaps.push((gs, aligned_s));
        }
        let end = aligned_s + take;
        if end < ge {
            remaining_gaps.push((end, ge));
        }
    }
    remaining_gaps.sort_unstable();
    *working_gaps = remaining_gaps;

    if rem > 0 {
        return Err(format!(
            "Insufficient free space in super: still need {:.1} MiB",
            (rem * LP_SECTOR_SIZE) as f64 / (1024.0 * 1024.0)
        ));
    }
    Ok(pieces)
}

/// Coalesce adjacent compatible `LogicalRun` entries.
pub fn coalesce_runs(runs: Vec<LogicalRun>) -> Vec<LogicalRun> {
    let mut out: Vec<LogicalRun> = Vec::with_capacity(runs.len());
    for r in runs {
        if r.num_sectors() == 0 {
            continue;
        }
        match (out.last_mut(), &r) {
            (
                Some(LogicalRun::Alias {
                    phys_start_sector: ps,
                    num_sectors: pn,
                }),
                LogicalRun::Alias {
                    phys_start_sector: ns,
                    num_sectors: nn,
                },
            ) if *ps + *pn == *ns => {
                *pn += *nn;
            }
            (
                Some(LogicalRun::Zero { num_sectors: pn }),
                LogicalRun::Zero { num_sectors: nn },
            ) => {
                *pn += *nn;
            }
            (
                Some(LogicalRun::Allocate { num_sectors: pn }),
                LogicalRun::Allocate { num_sectors: nn },
            ) => {
                *pn += *nn;
            }
            _ => out.push(r),
        }
    }
    out
}

/// Enforce `min_alias_sectors` and `max_runs` by demoting the smallest `Alias` runs to `Allocate`.
fn enforce_run_budget(
    mut runs: Vec<LogicalRun>,
    min_alias_sectors: u64,
    max_runs: usize,
) -> (Vec<LogicalRun>, usize) {
    let mut demoted = 0usize;
    for r in &mut runs {
        if let LogicalRun::Alias { num_sectors, .. } = *r {
            if num_sectors < min_alias_sectors {
                *r = LogicalRun::Allocate { num_sectors };
                demoted += 1;
            }
        }
    }
    runs = coalesce_runs(runs);

    while runs.len() > max_runs {
        // Pick the smallest Alias run to demote so we keep the largest zero-copy aliases.
        let smallest_alias = runs
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match *r {
                LogicalRun::Alias { num_sectors, .. } => Some((i, num_sectors)),
                _ => None,
            })
            .min_by_key(|&(_, sz)| sz);
        if let Some((idx, sz)) = smallest_alias {
            runs[idx] = LogicalRun::Allocate { num_sectors: sz };
            demoted += 1;
            runs = coalesce_runs(runs);
        } else {
            break;
        }
    }
    (runs, demoted)
}

fn commit_slot_into_buffer(
    meta_buf: &[u8],
    geom: &LpGeometry,
    slot_num: u32,
    new_meta: &LpMetadata,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let super_dev = new_meta
        .block_devices
        .first()
        .ok_or_else(|| "LpMetadata has no block_devices".to_string())?;
    let slot_blob = serialize_metadata(new_meta, geom)?;
    let max_sz = geom.metadata_max_size as usize;
    let mut padded = vec![0u8; max_sz];
    padded[..slot_blob.len()].copy_from_slice(&slot_blob);

    let pri = geom.primary_offset(slot_num);
    let bak = geom.backup_offset(slot_num);
    if bak + max_sz > (super_dev.first_logical_sector * LP_SECTOR_SIZE) as usize {
        return Err("Metadata backup slot exceeds first_logical_sector".into());
    }
    if bak + max_sz > meta_buf.len() {
        return Err(format!(
            "meta_buf too small ({} B) for backup slot end ({} B)",
            meta_buf.len(),
            bak + max_sz
        ));
    }
    let mut out_buf = meta_buf.to_vec();
    out_buf[pri..pri + max_sz].copy_from_slice(&padded);
    out_buf[bak..bak + max_sz].copy_from_slice(&padded);
    Ok((out_buf, slot_blob))
}

/// Plan an atomic Inactive-Slot CoW OTA with Sub-Partition `dm-linear` Extent Aliasing,
/// `LP_TARGET_TYPE_ZERO` sparse extents, and scatter-gather allocation!
///
/// Guarantees:
/// 1. NEVER writes into any sector occupied by `active_slot`, `live_occupied`, or (if `preserve_scratch`) `scratch`.
/// 2. Reclaims all sectors exclusively owned by the old `target_slot`.
/// 3. Validates every `Alias` run lies inside `active_slot` read-only sectors.
/// 4. Enforces `ExtentLimits` (`max_extents_per_part`, `max_total_extents`) automatically.
/// 5. Produces byte-exact serialized `LpMetadata` for `target_slot` and self-verifies roundtrip parse.
pub fn plan_ota_inactive_slot(
    meta_buf: &[u8],
    active_slot: u32,
    specs: &[OtaPartitionExtentSpec],
    live_occupied: &[(u64, u64)],
    preserve_scratch: bool,
    limits: ExtentLimits,
) -> Result<OtaSuperPlan, String> {
    if active_slot > 1 {
        return Err(format!("Unsupported active_slot={active_slot} (expected 0 or 1)"));
    }
    let target_slot = 1 - active_slot;
    let active_suffix = slot_suffix(active_slot);
    let target_suffix = slot_suffix(target_slot);

    let geom = parse_geometry(meta_buf)?;
    let active_meta = parse_slot_metadata(meta_buf, &geom, active_slot)?;
    let super_dev = active_meta
        .block_devices
        .first()
        .ok_or_else(|| "Active LpMetadata has no block_devices".to_string())?;
    let super_sectors = super_dev.size / LP_SECTOR_SIZE;
    let blk_sectors = (geom.logical_block_size as u64).max(LP_BLOCK_SIZE) / LP_SECTOR_SIZE;
    let align_bytes = (1024u64 * 1024)
        .max(super_dev.alignment as u64)
        .max(geom.logical_block_size as u64);
    let align_sectors = align_bytes / LP_SECTOR_SIZE;

    // 1. Collect strictly protected intervals:
    //    - Active slot's suffixed partitions (ALL extents)
    //    - Live dm-linear extents (e.g., active mounted partitions + mounted scratch)
    //    - `scratch` partition extents if `preserve_scratch == true`
    let mut protected: Vec<(u64, u64)> = live_occupied.to_vec();
    let mut active_slot_readonly: Vec<(u64, u64)> = Vec::new();
    let mut preserved_unslotted: Vec<(LpPartition, Vec<LpExtent>)> = Vec::new();

    for p in &active_meta.partitions {
        let exts = active_meta.partition_extents(p);
        let is_scratch = p.name == "scratch";
        let is_active_part = p.name.ends_with(active_suffix);
        let is_target_part = p.name.ends_with(target_suffix);

        if is_active_part {
            for e in exts {
                if e.target_type == LP_TARGET_TYPE_LINEAR && e.target_source == 0 {
                    let iv = (e.target_data, e.target_data + e.num_sectors);
                    protected.push(iv);
                    active_slot_readonly.push(iv);
                }
            }
        } else if is_scratch {
            if preserve_scratch {
                for e in exts {
                    if e.target_type == LP_TARGET_TYPE_LINEAR && e.target_source == 0 {
                        protected.push((e.target_data, e.target_data + e.num_sectors));
                    }
                }
                preserved_unslotted.push((p.clone(), exts.to_vec()));
            }
        } else if !is_target_part {
            // Other non-slot-suffixed partitions (preserve safely)
            for e in exts {
                if e.target_type == LP_TARGET_TYPE_LINEAR && e.target_source == 0 {
                    protected.push((e.target_data, e.target_data + e.num_sectors));
                }
            }
            preserved_unslotted.push((p.clone(), exts.to_vec()));
        }
    }

    let protected = merge_intervals(protected);
    let active_ro_merged = merge_intervals(active_slot_readonly);
    let mut working_gaps = compute_free_gaps(super_dev.first_logical_sector, super_sectors, &protected);
    let free_bytes_before: u64 = working_gaps
        .iter()
        .map(|(s, e)| (e - s) * LP_SECTOR_SIZE)
        .sum();

    // 2. Normalize & enforce per-partition + global extent budgets (anti-fragmentation)
    let mut total_demoted = 0usize;
    let mut normalized_specs: Vec<(String, u64, Vec<LogicalRun>)> = Vec::with_capacity(specs.len());
    for spec in specs {
        let expected_sectors = align_up(spec.total_bytes, LP_BLOCK_SIZE) / LP_SECTOR_SIZE;
        let actual_sectors: u64 = spec.runs.iter().map(LogicalRun::num_sectors).sum();
        if actual_sectors != expected_sectors {
            return Err(format!(
                "Partition `{}` run sector sum ({actual_sectors}) != expected ({expected_sectors})",
                spec.base_name
            ));
        }
        let raw_runs: Vec<LogicalRun> = if limits.allow_dm_zero {
            spec.runs.clone()
        } else {
            spec.runs
                .iter()
                .map(|r| match r {
                    LogicalRun::Zero { num_sectors } => LogicalRun::Allocate {
                        num_sectors: *num_sectors,
                    },
                    other => other.clone(),
                })
                .collect()
        };
        let (runs, dem) = enforce_run_budget(
            raw_runs,
            limits.min_alias_sectors,
            limits.max_extents_per_part,
        );
        total_demoted += dem;
        normalized_specs.push((spec.base_name.clone(), spec.total_bytes, runs));
    }

    // Enforce global total extent budget across all partitions
    loop {
        let total_runs: usize = normalized_specs.iter().map(|(_, _, r)| r.len()).sum();
        if total_runs <= limits.max_total_extents {
            break;
        }
        // Demote the smallest Alias run across all partitions
        let mut best: Option<(usize, usize, u64)> = None;
        for (pi, (_, _, runs)) in normalized_specs.iter().enumerate() {
            for (ri, r) in runs.iter().enumerate() {
                if let LogicalRun::Alias { num_sectors, .. } = *r {
                    if best.map_or(true, |(_, _, bsz)| num_sectors < bsz) {
                        best = Some((pi, ri, num_sectors));
                    }
                }
            }
        }
        if let Some((pi, ri, sz)) = best {
            normalized_specs[pi].2[ri] = LogicalRun::Allocate { num_sectors: sz };
            normalized_specs[pi].2 = coalesce_runs(std::mem::take(&mut normalized_specs[pi].2));
            total_demoted += 1;
        } else {
            break;
        }
    }

    // 3. Validate every Alias run and allocate every Allocate run from free gaps
    let mut planned_parts = Vec::with_capacity(normalized_specs.len());
    let mut all_new_allocs: Vec<(String, u64, u64)> = Vec::new();
    let mut total_bytes_aliased = 0u64;
    let mut total_bytes_zeroed = 0u64;
    let mut total_bytes_to_write = 0u64;

    for (base_name, total_bytes, runs) in normalized_specs {
        let target_name = format!("{base_name}{target_suffix}");
        let mut extents = Vec::new();
        let mut write_segments = Vec::new();
        let mut logical_sector = 0u64;
        let mut p_aliased = 0u64;
        let mut p_zeroed = 0u64;
        let mut p_written = 0u64;

        for run in runs {
            match run {
                LogicalRun::Alias {
                    phys_start_sector,
                    num_sectors,
                } => {
                    let phys_end = phys_start_sector + num_sectors;
                    if phys_start_sector < super_dev.first_logical_sector
                        || phys_end > super_sectors
                    {
                        return Err(format!(
                            "Alias extent out of super bounds for {target_name}: {phys_start_sector}..{phys_end}"
                        ));
                    }
                    // Verify the aliased range lies strictly within active-slot read-only sectors!
                    let inside_active = active_ro_merged
                        .iter()
                        .any(|&(as_, ae)| phys_start_sector >= as_ && phys_end <= ae);
                    if !inside_active {
                        return Err(format!(
                            "Alias extent [{phys_start_sector},{phys_end}) for {target_name} is not inside active slot read-only extents"
                        ));
                    }
                    extents.push(LpExtent {
                        num_sectors,
                        target_type: LP_TARGET_TYPE_LINEAR,
                        target_data: phys_start_sector,
                        target_source: 0,
                    });
                    p_aliased += num_sectors * LP_SECTOR_SIZE;
                    logical_sector += num_sectors;
                }
                LogicalRun::Zero { num_sectors } => {
                    extents.push(LpExtent {
                        num_sectors,
                        target_type: LP_TARGET_TYPE_ZERO,
                        target_data: 0,
                        target_source: 0,
                    });
                    p_zeroed += num_sectors * LP_SECTOR_SIZE;
                    logical_sector += num_sectors;
                }
                LogicalRun::Allocate { num_sectors } => {
                    let pieces = take_scatter_gather(
                        &mut working_gaps,
                        num_sectors,
                        align_sectors,
                        blk_sectors,
                    )
                    .map_err(|e| format!("{target_name}: {e}"))?;
                    for (ps, pn) in pieces {
                        extents.push(LpExtent {
                            num_sectors: pn,
                            target_type: LP_TARGET_TYPE_LINEAR,
                            target_data: ps,
                            target_source: 0,
                        });
                        write_segments.push(PhysicalWriteSegment {
                            logical_byte_offset: logical_sector * LP_SECTOR_SIZE,
                            super_byte_offset: ps * LP_SECTOR_SIZE,
                            length_bytes: pn * LP_SECTOR_SIZE,
                        });
                        all_new_allocs.push((target_name.clone(), ps, ps + pn));
                        p_written += pn * LP_SECTOR_SIZE;
                        logical_sector += pn;
                    }
                }
            }
        }

        total_bytes_aliased += p_aliased;
        total_bytes_zeroed += p_zeroed;
        total_bytes_to_write += p_written;
        planned_parts.push(PlannedDynamicPartition {
            base_name,
            target_name,
            total_bytes,
            extents,
            write_segments,
            bytes_aliased: p_aliased,
            bytes_zeroed: p_zeroed,
            bytes_to_write: p_written,
        });
    }

    // 4. Exhaustive non-overlap invariant check:
    //    (a) No new allocation overlaps ANY protected interval (active slot / live dm / preserved scratch)
    //    (b) No two new allocations overlap each other
    for (pname, ns, ne) in &all_new_allocs {
        if *ns < super_dev.first_logical_sector || *ne > super_sectors {
            return Err(format!("New allocation out of bounds for {pname}: {ns}..{ne}"));
        }
        for &(ps, pe) in &protected {
            if !(*ne <= ps || *ns >= pe) {
                return Err(format!(
                    "CRITICAL: allocation overlap with active/live sector for {pname}: [{ns},{ne}) vs [{ps},{pe})"
                ));
            }
        }
    }
    let mut sorted_allocs: Vec<(u64, u64)> = all_new_allocs.iter().map(|&(_, s, e)| (s, e)).collect();
    sorted_allocs.sort_unstable();
    for pair in sorted_allocs.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(format!(
                "CRITICAL: internal overlap between new allocations: {:?} vs {:?}",
                pair[0], pair[1]
            ));
        }
    }

    // 5. Assemble target_slot LpMetadata (mirror groups cleanly from active_meta or existing target slot)
    let base_target_meta = parse_slot_metadata(meta_buf, &geom, target_slot).unwrap_or_else(|_| {
        // Construct clean groups mirroring active slot
        active_meta.clone()
    });
    let mut groups = base_target_meta.groups.clone();
    // Ensure target slot's dynamic group exists (e.g., `qti_dynamic_partitions_a` / `_b`)
    let target_group_idx = find_or_build_target_group(&mut groups, active_suffix, target_suffix);

    let mut new_parts: Vec<LpPartition> = Vec::new();
    let mut new_exts: Vec<LpExtent> = Vec::new();
    let mut grp_totals: HashMap<u32, u64> = HashMap::new();

    // Emit all planned target_slot dynamic partitions
    for pp in &planned_parts {
        let first_idx = new_exts.len() as u32;
        let num_ext = pp.extents.len() as u32;
        let bytes: u64 = pp.extents.iter().map(|e| e.num_sectors * LP_SECTOR_SIZE).sum();
        new_exts.extend_from_slice(&pp.extents);

        // Preserve original attributes (typically LP_PARTITION_ATTR_READONLY) without setting
        // LP_PARTITION_ATTR_UPDATED (which is reserved for Virtual A/B snapshot updates).
        let orig_attr = active_meta
            .partitions
            .iter()
            .find(|p| p.name == format!("{}{active_suffix}", pp.base_name))
            .map(|p| p.attributes)
            .unwrap_or(LP_PARTITION_ATTR_READONLY);

        new_parts.push(LpPartition {
            name: pp.target_name.clone(),
            attributes: orig_attr & !LP_PARTITION_ATTR_UPDATED,
            first_extent_index: first_idx,
            num_extents: num_ext,
            group_index: target_group_idx,
        });
        *grp_totals.entry(target_group_idx).or_insert(0) += bytes;
    }

    // Preserve unslotted partitions (e.g. `scratch` if `preserve_scratch` was requested)
    for (p, exts) in preserved_unslotted {
        let first_idx = new_exts.len() as u32;
        let bytes: u64 = exts.iter().map(|e| e.num_sectors * LP_SECTOR_SIZE).sum();
        let gi = if (p.group_index as usize) < groups.len() {
            p.group_index
        } else {
            0
        };
        new_exts.extend_from_slice(&exts);
        new_parts.push(LpPartition {
            name: p.name,
            attributes: p.attributes,
            first_extent_index: first_idx,
            num_extents: exts.len() as u32,
            group_index: gi,
        });
        *grp_totals.entry(gi).or_insert(0) += bytes;
    }

    for (gi, total_b) in grp_totals {
        if let Some(g) = groups.get(gi as usize) {
            if g.maximum_size > 0 && total_b > g.maximum_size {
                return Err(format!(
                    "Target group `{}` total size ({:.1} MiB) exceeds maximum_size ({:.1} MiB)",
                    g.name,
                    total_b as f64 / (1024.0 * 1024.0),
                    g.maximum_size as f64 / (1024.0 * 1024.0)
                ));
            }
        }
    }

    let total_extents = new_exts.len();
    let new_meta = LpMetadata {
        major_version: active_meta.major_version,
        minor_version: active_meta.minor_version,
        header_size: active_meta.header_size,
        flags: active_meta.flags,
        reserved: active_meta.reserved.clone(),
        partitions: new_parts,
        extents: new_exts,
        groups,
        block_devices: active_meta.block_devices.clone(),
    };

    let (new_meta_buf, target_slot_blob) =
        commit_slot_into_buffer(meta_buf, &geom, target_slot, &new_meta)?;

    // Self-verify roundtrip parse of BOTH target_slot AND active_slot (active must be untouched!)
    let reparsed_target = parse_slot_metadata(&new_meta_buf, &geom, target_slot)?;
    if reparsed_target.extents != new_meta.extents || reparsed_target.partitions != new_meta.partitions {
        return Err("Target slot LpMetadata roundtrip verification failed".into());
    }
    let reparsed_active = parse_slot_metadata(&new_meta_buf, &geom, active_slot)?;
    if reparsed_active != active_meta {
        return Err("CRITICAL: Active slot LpMetadata was unexpectedly mutated!".into());
    }

    let free_bytes_after: u64 = working_gaps
        .iter()
        .map(|(s, e)| (e - s) * LP_SECTOR_SIZE)
        .sum();

    Ok(OtaSuperPlan {
        active_slot,
        target_slot,
        geometry: geom,
        new_meta_buf,
        target_slot_blob,
        partitions: planned_parts,
        total_bytes_aliased,
        total_bytes_zeroed,
        total_bytes_to_write,
        total_extents,
        free_bytes_before,
        free_bytes_after,
        compaction_demoted_runs: total_demoted,
    })
}

fn find_or_build_target_group(
    groups: &mut Vec<LpGroup>,
    active_suffix: &str,
    target_suffix: &str,
) -> u32 {
    if let Some((idx, _)) = groups
        .iter()
        .enumerate()
        .find(|(_, g)| g.name.ends_with(target_suffix))
    {
        return idx as u32;
    }
    // Derive from active slot's suffixed group
    if let Some(ag) = groups
        .iter()
        .find(|g| g.name.ends_with(active_suffix))
        .cloned()
    {
        let prefix = ag.name.strip_suffix(active_suffix).unwrap_or(&ag.name);
        groups.push(LpGroup {
            name: format!("{prefix}{target_suffix}"),
            flags: ag.flags,
            maximum_size: ag.maximum_size,
        });
        return (groups.len() - 1) as u32;
    }
    if groups.is_empty() {
        groups.push(LpGroup {
            name: "default".into(),
            flags: 0,
            maximum_size: 0,
        });
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_super() -> Vec<u8> {
        // 128 MiB super (262,144 sectors), first_logical_sector = 2048
        let super_bytes = 128 * 1024 * 1024u64;
        let bd = LpBlockDevice {
            first_logical_sector: 2048,
            alignment: 1024 * 1024,
            alignment_offset: 0,
            size: super_bytes,
            partition_name: "super".into(),
            flags: 0,
        };
        let groups = vec![
            LpGroup { name: "default".into(), flags: 0, maximum_size: 0 },
            LpGroup { name: "qti_dynamic_partitions_a".into(), flags: 1, maximum_size: super_bytes - 4 * 1024 * 1024 },
            LpGroup { name: "qti_dynamic_partitions_b".into(), flags: 1, maximum_size: super_bytes - 4 * 1024 * 1024 },
        ];
        // Slot 1 (_b) active: system_b (16 MiB @ 2048), vendor_b (32 MiB @ 34816)
        let slot1 = LpMetadata {
            major_version: 10,
            minor_version: 2,
            header_size: LP_HEADER_SIZE_V1_2 as u32,
            flags: 0,
            reserved: vec![0u8; 124],
            partitions: vec![
                LpPartition { name: "system_b".into(), attributes: 3, first_extent_index: 0, num_extents: 1, group_index: 2 },
                LpPartition { name: "vendor_b".into(), attributes: 3, first_extent_index: 1, num_extents: 1, group_index: 2 },
            ],
            extents: vec![
                LpExtent { num_sectors: 32768, target_type: LP_TARGET_TYPE_LINEAR, target_data: 2048, target_source: 0 },
                LpExtent { num_sectors: 65536, target_type: LP_TARGET_TYPE_LINEAR, target_data: 34816, target_source: 0 },
            ],
            groups: groups.clone(),
            block_devices: vec![bd.clone()],
        };
        // Slot 0 (_a) stale inactive: occupying sectors 100352..165888 (should be reclaimed!)
        let slot0 = LpMetadata {
            major_version: 10,
            minor_version: 2,
            header_size: LP_HEADER_SIZE_V1_2 as u32,
            flags: 0,
            reserved: vec![0u8; 124],
            partitions: vec![
                LpPartition { name: "system_a".into(), attributes: 3, first_extent_index: 0, num_extents: 1, group_index: 1 },
            ],
            extents: vec![
                LpExtent { num_sectors: 65536, target_type: LP_TARGET_TYPE_LINEAR, target_data: 100352, target_source: 0 },
            ],
            groups,
            block_devices: vec![bd],
        };
        build_synthetic_super_header(super_bytes, &slot0, &slot1).unwrap()
    }

    #[test]
    fn test_merge_intervals_and_align() {
        assert_eq!(
            merge_intervals(vec![(100, 200), (150, 300), (400, 500), (300, 350)]),
            vec![(100, 350), (400, 500)]
        );
        assert_eq!(align_up(2049, 2048), 4096);
        assert_eq!(align_up(4096, 2048), 4096);
    }

    #[test]
    fn test_inactive_slot_extent_aliasing_and_zero_extents() {
        let super_hdr = make_test_super();
        // Update slot 0 (_a) while slot 1 (_b) is active:
        // - system_a: 2 MiB delta + 12 MiB aliased from system_b (shifted by 4 KiB = 8 sectors!) + 2 MiB ZERO
        // - vendor_a: 30 MiB aliased from vendor_b + 2 MiB delta
        let specs = vec![
            OtaPartitionExtentSpec {
                base_name: "system".into(),
                total_bytes: 16 * 1024 * 1024,
                runs: vec![
                    LogicalRun::Allocate { num_sectors: 4096 }, // 2 MiB
                    LogicalRun::Alias { phys_start_sector: 2048 + 8, num_sectors: 24576 }, // 12 MiB shifted!
                    LogicalRun::Zero { num_sectors: 4096 }, // 2 MiB zero!
                ],
            },
            OtaPartitionExtentSpec {
                base_name: "vendor".into(),
                total_bytes: 32 * 1024 * 1024,
                runs: vec![
                    LogicalRun::Alias { phys_start_sector: 34816, num_sectors: 61440 }, // 30 MiB
                    LogicalRun::Allocate { num_sectors: 4096 }, // 2 MiB
                ],
            },
        ];

        // Default ExtentLimits disables dm-zero for Android GKI compatibility (# CONFIG_DM_ZERO is not set)
        let plan_gki = plan_ota_inactive_slot(
            &super_hdr,
            1, // active = _b
            &specs,
            &[(2048, 34816), (34816, 100352)],
            false,
            ExtentLimits::default(),
        )
        .unwrap();

        assert_eq!(plan_gki.target_slot, 0);
        assert_eq!(plan_gki.total_bytes_aliased, 42 * 1024 * 1024);
        assert_eq!(plan_gki.total_bytes_zeroed, 0);
        assert_eq!(plan_gki.total_bytes_to_write, 6 * 1024 * 1024);
        assert!(plan_gki
            .partitions
            .iter()
            .all(|p| p.extents.iter().all(|e| e.target_type == LP_TARGET_TYPE_LINEAR)));

        // Explicit allow_dm_zero opt-in still emits LP_TARGET_TYPE_ZERO when requested
        let plan = plan_ota_inactive_slot(
            &super_hdr,
            1, // active = _b
            &specs,
            &[(2048, 34816), (34816, 100352)],
            false,
            ExtentLimits {
                allow_dm_zero: true,
                ..ExtentLimits::default()
            },
        )
        .unwrap();

        assert_eq!(plan.target_slot, 0);
        assert_eq!(plan.total_bytes_aliased, 42 * 1024 * 1024);
        assert_eq!(plan.total_bytes_zeroed, 2 * 1024 * 1024);
        assert_eq!(plan.total_bytes_to_write, 4 * 1024 * 1024);
        assert_eq!(plan.partitions[0].extents[2].target_type, LP_TARGET_TYPE_ZERO);
        // Verify active slot _b was completely untouched
        let geom = parse_geometry(&plan.new_meta_buf).unwrap();
        let active_after = parse_slot_metadata(&plan.new_meta_buf, &geom, 1).unwrap();
        let active_before = parse_slot_metadata(&super_hdr, &geom, 1).unwrap();
        assert_eq!(active_after, active_before);
    }

    #[test]
    fn test_extent_budget_anti_fragmentation() {
        let super_hdr = make_test_super();
        // Construct 100 alternating Alias/Allocate runs inside 16 MiB (exceeds max_extents=64!)
        let mut runs = Vec::new();
        for i in 0..50u64 {
            runs.push(LogicalRun::Alias {
                phys_start_sector: 2048 + i * 640,
                num_sectors: 512, // 256 KiB
            });
            runs.push(LogicalRun::Allocate { num_sectors: 128 }); // 64 KiB
        }
        let total_sectors: u64 = runs.iter().map(LogicalRun::num_sectors).sum();
        let specs = vec![OtaPartitionExtentSpec {
            base_name: "system".into(),
            total_bytes: total_sectors * LP_SECTOR_SIZE,
            runs,
        }];
        let plan = plan_ota_inactive_slot(
            &super_hdr,
            1,
            &specs,
            &[],
            false,
            ExtentLimits {
                max_extents_per_part: 16,
                max_total_extents: 64,
                min_alias_sectors: 512,
                allow_dm_zero: false,
            },
        )
        .unwrap();
        assert!(plan.compaction_demoted_runs > 0);
        assert!(plan.partitions[0].extents.len() <= 16);
    }

    #[test]
    fn test_alias_outside_active_slot_rejected() {
        let super_hdr = make_test_super();
        let specs = vec![OtaPartitionExtentSpec {
            base_name: "system".into(),
            total_bytes: 1024 * 1024,
            runs: vec![LogicalRun::Alias {
                phys_start_sector: 120000, // in old inactive slot, NOT active slot!
                num_sectors: 2048,
            }],
        }];
        let err = plan_ota_inactive_slot(&super_hdr, 1, &specs, &[], false, ExtentLimits::default())
            .unwrap_err();
        assert!(err.contains("not inside active slot"));
    }
}
