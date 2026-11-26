// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-dependency `CrAU` v2 Android OTA payload parser, protobuf wire decoder,
//! and ZIP / ZIP64 Central Directory locator (0-unpack `payload.bin` access).

use std::io::{Read, Seek, SeekFrom};

use crate::crypto::sha256_bytes;

pub const CRAU_MAGIC: &[u8; 4] = b"CrAU";
pub const CRAU_VERSION_2: u64 = 2;

const ZIP_EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP_CD_SIG: u32 = 0x0201_4b50;
const ZIP_LFH_SIG: u32 = 0x0403_4b50;

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub compression_method: u16,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_header_offset: u64,
    pub data_offset: u64,
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

/// Locate a named entry inside a `.zip` or ZIP64 archive without unpacking it.
pub fn find_zip_entry<R: Read + Seek>(r: &mut R, target_name: &str) -> Result<ZipEntry, String> {
    let entries = list_zip_entries(r)?;
    entries
        .into_iter()
        .find(|e| e.name == target_name)
        .ok_or_else(|| format!("ZIP entry `{target_name}` not found"))
}

/// List Central Directory entries of a `.zip` or ZIP64 archive.
pub fn list_zip_entries<R: Read + Seek>(r: &mut R) -> Result<Vec<ZipEntry>, String> {
    let file_len = r
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("seek end: {e}"))?;
    if file_len < 22 {
        return Err("File too small to be a ZIP archive".into());
    }
    let tail_len = (file_len.min(65536 + 22)) as usize;
    let tail_start = file_len - tail_len as u64;
    r.seek(SeekFrom::Start(tail_start))
        .map_err(|e| format!("seek tail: {e}"))?;
    let mut tail = vec![0u8; tail_len];
    r.read_exact(&mut tail)
        .map_err(|e| format!("read tail: {e}"))?;

    let mut eocd_rel = None;
    for i in (0..=tail.len() - 22).rev() {
        if u32le(&tail, i) == ZIP_EOCD_SIG {
            let comment_len = u16le(&tail, i + 20) as usize;
            if i + 22 + comment_len == tail.len() {
                eocd_rel = Some(i);
                break;
            }
        }
    }
    let eocd_rel = eocd_rel.ok_or_else(|| "ZIP End-of-Central-Directory not found".to_string())?;
    let eocd = &tail[eocd_rel..];

    let mut cd_entries = u16le(eocd, 10) as u64;
    let mut cd_size = u32le(eocd, 12) as u64;
    let mut cd_offset = u32le(eocd, 16) as u64;

    // Handle ZIP64 EOCD Locator if present (needed for OTA ZIPs > 4 GiB)
    if (cd_entries == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF)
        && eocd_rel >= 20
        && u32le(&tail, eocd_rel - 20) == ZIP64_LOCATOR_SIG
    {
        let zip64_eocd_off = u64le(&tail, eocd_rel - 12);
        r.seek(SeekFrom::Start(zip64_eocd_off))
            .map_err(|e| format!("seek zip64 eocd: {e}"))?;
        let mut z64 = [0u8; 56];
        r.read_exact(&mut z64)
            .map_err(|e| format!("read zip64 eocd: {e}"))?;
        if u32le(&z64, 0) != ZIP64_EOCD_SIG {
            return Err("Invalid ZIP64 EOCD signature".into());
        }
        cd_entries = u64le(&z64, 32);
        cd_size = u64le(&z64, 40);
        cd_offset = u64le(&z64, 48);
    }

    if cd_offset + cd_size > file_len {
        return Err("ZIP Central Directory out of file bounds".into());
    }
    r.seek(SeekFrom::Start(cd_offset))
        .map_err(|e| format!("seek cd: {e}"))?;
    let mut cd = vec![0u8; cd_size as usize];
    r.read_exact(&mut cd).map_err(|e| format!("read cd: {e}"))?;

    let mut out = Vec::with_capacity(cd_entries.min(4096) as usize);
    let mut pos = 0usize;
    while pos + 46 <= cd.len() {
        if u32le(&cd, pos) != ZIP_CD_SIG {
            return Err(format!("Bad ZIP CD signature at {pos}"));
        }
        let method = u16le(&cd, pos + 10);
        let mut csize = u32le(&cd, pos + 20) as u64;
        let mut usize_ = u32le(&cd, pos + 24) as u64;
        let name_len = u16le(&cd, pos + 28) as usize;
        let extra_len = u16le(&cd, pos + 30) as usize;
        let comment_len = u16le(&cd, pos + 32) as usize;
        let mut lfh_off = u32le(&cd, pos + 42) as u64;

        let name_start = pos + 46;
        let extra_start = name_start + name_len;
        let next = extra_start + extra_len + comment_len;
        if next > cd.len() {
            return Err("Truncated ZIP CD entry".into());
        }
        let name = String::from_utf8_lossy(&cd[name_start..extra_start]).into_owned();

        // Parse ZIP64 extra field (header id 0x0001) if any 32-bit field overflowed
        if usize_ == 0xFFFF_FFFF || csize == 0xFFFF_FFFF || lfh_off == 0xFFFF_FFFF {
            let extra = &cd[extra_start..extra_start + extra_len];
            let mut ep = 0usize;
            while ep + 4 <= extra.len() {
                let tag = u16le(extra, ep);
                let sz = u16le(extra, ep + 2) as usize;
                ep += 4;
                if ep + sz > extra.len() {
                    break;
                }
                if tag == 0x0001 {
                    let mut z = ep;
                    if usize_ == 0xFFFF_FFFF && z + 8 <= ep + sz {
                        usize_ = u64le(extra, z);
                        z += 8;
                    }
                    if csize == 0xFFFF_FFFF && z + 8 <= ep + sz {
                        csize = u64le(extra, z);
                        z += 8;
                    }
                    if lfh_off == 0xFFFF_FFFF && z + 8 <= ep + sz {
                        lfh_off = u64le(extra, z);
                    }
                }
                ep += sz;
            }
        }

        // Resolve exact data offset from Local File Header
        r.seek(SeekFrom::Start(lfh_off))
            .map_err(|e| format!("seek lfh for {name}: {e}"))?;
        let mut lfh = [0u8; 30];
        r.read_exact(&mut lfh)
            .map_err(|e| format!("read lfh for {name}: {e}"))?;
        if u32le(&lfh, 0) != ZIP_LFH_SIG {
            return Err(format!("Bad LFH signature for {name}"));
        }
        let lfh_nlen = u16le(&lfh, 26) as u64;
        let lfh_elen = u16le(&lfh, 28) as u64;
        let data_offset = lfh_off + 30 + lfh_nlen + lfh_elen;

        out.push(ZipEntry {
            name,
            compression_method: method,
            compressed_size: csize,
            uncompressed_size: usize_,
            local_header_offset: lfh_off,
            data_offset,
        });
        pos = next;
    }
    Ok(out)
}

/// Detect whether a file is an uncompressed `payload.bin` inside a `.zip` or a raw `CrAU` file,
/// returning `(payload_base_offset, payload_byte_length_opt)`.
pub fn locate_payload<R: Read + Seek>(r: &mut R) -> Result<(u64, Option<u64>), String> {
    r.seek(SeekFrom::Start(0))
        .map_err(|e| format!("seek 0: {e}"))?;
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)
        .map_err(|e| format!("read magic: {e}"))?;
    if &magic == CRAU_MAGIC {
        let len = r.seek(SeekFrom::End(0)).ok();
        return Ok((0, len));
    }
    if magic[0] == b'P' && magic[1] == b'K' {
        let entry = find_zip_entry(r, "payload.bin")?;
        if entry.compression_method != 0 {
            return Err(format!(
                "payload.bin in ZIP must be STORE (method 0), got method {}",
                entry.compression_method
            ));
        }
        return Ok((entry.data_offset, Some(entry.uncompressed_size)));
    }
    Err("File is neither a raw CrAU payload nor an Android OTA ZIP archive".into())
}

// ====================================================== Minimal Protobuf Wire Decoder

fn read_varint(buf: &[u8], i: &mut usize) -> Result<u64, String> {
    let mut res = 0u64;
    let mut shift = 0u32;
    loop {
        if *i >= buf.len() {
            return Err("Truncated protobuf varint".into());
        }
        let b = buf[*i];
        *i += 1;
        res |= ((b & 0x7F) as u64) << shift;
        if b < 0x80 {
            return Ok(res);
        }
        shift += 7;
        if shift >= 64 {
            return Err("Protobuf varint overflow".into());
        }
    }
}

enum PbVal<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed64,
    Fixed32,
}

fn next_field<'a>(buf: &'a [u8], i: &mut usize) -> Result<Option<(u32, PbVal<'a>)>, String> {
    if *i >= buf.len() {
        return Ok(None);
    }
    let key = read_varint(buf, i)?;
    let field_num = (key >> 3) as u32;
    let wire = (key & 7) as u8;
    let val = match wire {
        0 => PbVal::Varint(read_varint(buf, i)?),
        1 => {
            if *i + 8 > buf.len() {
                return Err("Truncated protobuf fixed64".into());
            }
            *i += 8;
            PbVal::Fixed64
        }
        2 => {
            let len = read_varint(buf, i)? as usize;
            if *i + len > buf.len() {
                return Err("Truncated protobuf length-delimited field".into());
            }
            let s = &buf[*i..*i + len];
            *i += len;
            PbVal::Bytes(s)
        }
        5 => {
            if *i + 4 > buf.len() {
                return Err("Truncated protobuf fixed32".into());
            }
            *i += 4;
            PbVal::Fixed32
        }
        other => return Err(format!("Unsupported protobuf wire type {other}")),
    };
    Ok(Some((field_num, val)))
}

// ====================================================== CrAU v2 Data Structures

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpType {
    Replace = 0,
    ReplaceBz = 1,
    SourceCopy = 4,
    SourceBsdiff = 5,
    Zero = 6,
    Discard = 7,
    ReplaceXz = 8,
    Puffdiff = 9,
    BrotliBsdiff = 10,
    Zucchini = 11,
    Lz4diffBsdiff = 12,
    Lz4diffPuffdiff = 13,
    ReplaceZstd = 14,
    Unknown = 255,
}

impl OpType {
    pub fn from_u64(v: u64) -> Self {
        match v {
            0 => Self::Replace,
            1 => Self::ReplaceBz,
            4 => Self::SourceCopy,
            5 => Self::SourceBsdiff,
            6 => Self::Zero,
            7 => Self::Discard,
            8 => Self::ReplaceXz,
            9 => Self::Puffdiff,
            10 => Self::BrotliBsdiff,
            11 => Self::Zucchini,
            12 => Self::Lz4diffBsdiff,
            13 => Self::Lz4diffPuffdiff,
            14 => Self::ReplaceZstd,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Replace => "REPLACE",
            Self::ReplaceBz => "REPLACE_BZ",
            Self::SourceCopy => "SOURCE_COPY",
            Self::SourceBsdiff => "SOURCE_BSDIFF",
            Self::Zero => "ZERO",
            Self::Discard => "DISCARD",
            Self::ReplaceXz => "REPLACE_XZ",
            Self::Puffdiff => "PUFFDIFF",
            Self::BrotliBsdiff => "BROTLI_BSDIFF",
            Self::Zucchini => "ZUCCHINI",
            Self::Lz4diffBsdiff => "LZ4DIFF_BSDIFF",
            Self::Lz4diffPuffdiff => "LZ4DIFF_PUFFDIFF",
            Self::ReplaceZstd => "REPLACE_ZSTD",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockExtent {
    pub start_block: u64,
    pub num_blocks: u64,
}

#[derive(Debug, Clone)]
pub struct InstallOperation {
    pub op_type: OpType,
    pub data_offset: u64,
    pub data_length: u64,
    pub src_extents: Vec<BlockExtent>,
    pub src_length: u64,
    pub dst_extents: Vec<BlockExtent>,
    pub dst_length: u64,
    pub data_sha256: Option<[u8; 32]>,
}

impl InstallOperation {
    pub fn total_dst_blocks(&self) -> u64 {
        self.dst_extents.iter().map(|e| e.num_blocks).sum()
    }
}

#[derive(Debug, Clone, Default)]
pub struct PartitionInfo {
    pub size: u64,
    pub hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct PartitionUpdate {
    pub name: String,
    pub old_info: PartitionInfo,
    pub new_info: PartitionInfo,
    pub operations: Vec<InstallOperation>,
    pub hash_tree_data_extent: Option<BlockExtent>,
    pub hash_tree_extent: Option<BlockExtent>,
    pub fec_extent: Option<BlockExtent>,
}

impl PartitionUpdate {
    pub fn payload_bytes(&self) -> u64 {
        self.operations.iter().map(|o| o.data_length).sum()
    }
}

#[derive(Debug, Clone, Default)]
pub struct DynamicPartitionGroup {
    pub name: String,
    pub size: u64,
    pub partition_names: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicPartitionMetadata {
    pub groups: Vec<DynamicPartitionGroup>,
    pub snapshot_enabled: bool,
    pub vabc_enabled: bool,
    pub vabc_compression: String,
    pub cow_version: u32,
}

impl DynamicPartitionMetadata {
    pub fn is_dynamic(&self, part_name: &str) -> bool {
        self.groups
            .iter()
            .any(|g| g.partition_names.iter().any(|n| n == part_name))
    }
}

#[derive(Debug, Clone)]
pub struct PayloadManifest {
    pub payload_base_offset: u64,
    pub version: u64,
    pub block_size: u64,
    pub minor_version: u32,
    pub manifest_size: u64,
    pub metadata_signature_size: u32,
    pub data_blob_offset: u64,
    /// SHA-256 over the header + manifest (the exact digest signed by `metadata_signatures`).
    pub metadata_sha256: [u8; 32],
    pub metadata_signatures: Vec<Vec<u8>>,
    pub signatures_offset: u64,
    pub signatures_size: u64,
    pub dynamic_metadata: DynamicPartitionMetadata,
    pub partitions: Vec<PartitionUpdate>,
    /// Payload covers a subset of partitions; the rest are carried over from the source slot.
    pub partial_update: bool,
}

fn parse_extent(b: &[u8]) -> Result<BlockExtent, String> {
    let mut i = 0;
    let mut start_block = 0u64;
    let mut num_blocks = 0u64;
    while let Some((f, v)) = next_field(b, &mut i)? {
        match (f, v) {
            (1, PbVal::Varint(x)) => start_block = x,
            (2, PbVal::Varint(x)) => num_blocks = x,
            _ => {}
        }
    }
    Ok(BlockExtent {
        start_block,
        num_blocks,
    })
}

fn parse_partition_info(b: &[u8]) -> Result<PartitionInfo, String> {
    let mut i = 0;
    let mut info = PartitionInfo::default();
    while let Some((f, v)) = next_field(b, &mut i)? {
        match (f, v) {
            (1, PbVal::Varint(sz)) => info.size = sz,
            (2, PbVal::Bytes(h)) if h.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(h);
                info.hash = Some(arr);
            }
            _ => {}
        }
    }
    Ok(info)
}

fn parse_operation(b: &[u8]) -> Result<InstallOperation, String> {
    let mut i = 0;
    let mut op = InstallOperation {
        op_type: OpType::Replace,
        data_offset: 0,
        data_length: 0,
        src_extents: Vec::new(),
        src_length: 0,
        dst_extents: Vec::new(),
        dst_length: 0,
        data_sha256: None,
    };
    while let Some((f, v)) = next_field(b, &mut i)? {
        match (f, v) {
            (1, PbVal::Varint(t)) => op.op_type = OpType::from_u64(t),
            (2, PbVal::Varint(o)) => op.data_offset = o,
            (3, PbVal::Varint(l)) => op.data_length = l,
            (4, PbVal::Bytes(e)) => op.src_extents.push(parse_extent(e)?),
            (5, PbVal::Varint(l)) => op.src_length = l,
            (6, PbVal::Bytes(e)) => op.dst_extents.push(parse_extent(e)?),
            (7, PbVal::Varint(l)) => op.dst_length = l,
            (8, PbVal::Bytes(h)) if h.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(h);
                op.data_sha256 = Some(arr);
            }
            _ => {}
        }
    }
    Ok(op)
}

fn parse_partition_update(b: &[u8]) -> Result<PartitionUpdate, String> {
    let mut i = 0;
    let mut name = String::new();
    let mut old_info = PartitionInfo::default();
    let mut new_info = PartitionInfo::default();
    let mut operations = Vec::new();
    let mut hash_tree_data_extent = None;
    let mut hash_tree_extent = None;
    let mut fec_extent = None;

    while let Some((f, v)) = next_field(b, &mut i)? {
        match (f, v) {
            (1, PbVal::Bytes(s)) => name = String::from_utf8_lossy(s).into_owned(),
            (6, PbVal::Bytes(p)) => old_info = parse_partition_info(p)?,
            (7, PbVal::Bytes(p)) => new_info = parse_partition_info(p)?,
            (8, PbVal::Bytes(o)) => operations.push(parse_operation(o)?),
            (10, PbVal::Bytes(e)) => hash_tree_data_extent = Some(parse_extent(e)?),
            (11, PbVal::Bytes(e)) => hash_tree_extent = Some(parse_extent(e)?),
            (15, PbVal::Bytes(e)) => fec_extent = Some(parse_extent(e)?),
            _ => {}
        }
    }
    Ok(PartitionUpdate {
        name,
        old_info,
        new_info,
        operations,
        hash_tree_data_extent,
        hash_tree_extent,
        fec_extent,
    })
}

fn parse_dynamic_metadata(b: &[u8]) -> Result<DynamicPartitionMetadata, String> {
    let mut i = 0;
    let mut dm = DynamicPartitionMetadata::default();
    while let Some((f, v)) = next_field(b, &mut i)? {
        match (f, v) {
            (1, PbVal::Bytes(gb)) => {
                let mut gi = 0;
                let mut g = DynamicPartitionGroup::default();
                while let Some((gf, gv)) = next_field(gb, &mut gi)? {
                    match (gf, gv) {
                        (1, PbVal::Bytes(s)) => g.name = String::from_utf8_lossy(s).into_owned(),
                        (2, PbVal::Varint(sz)) => g.size = sz,
                        (3, PbVal::Bytes(pn)) => {
                            g.partition_names.push(String::from_utf8_lossy(pn).into_owned())
                        }
                        _ => {}
                    }
                }
                dm.groups.push(g);
            }
            (2, PbVal::Varint(x)) => dm.snapshot_enabled = x != 0,
            (3, PbVal::Varint(x)) => dm.vabc_enabled = x != 0,
            (4, PbVal::Bytes(s)) => dm.vabc_compression = String::from_utf8_lossy(s).into_owned(),
            (5, PbVal::Varint(x)) => dm.cow_version = x as u32,
            _ => {}
        }
    }
    Ok(dm)
}

fn parse_signatures(b: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut i = 0;
    let mut out = Vec::new();
    while let Some((f, v)) = next_field(b, &mut i)? {
        if f == 1 {
            if let PbVal::Bytes(sig_msg) = v {
                let mut si = 0;
                while let Some((sf, sv)) = next_field(sig_msg, &mut si)? {
                    if sf == 2 {
                        if let PbVal::Bytes(raw_sig) = sv {
                            out.push(raw_sig.to_vec());
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Parse a `CrAU` v2 payload header & protobuf manifest from either an OTA `.zip` or raw `payload.bin`.
pub fn parse_payload<R: Read + Seek>(r: &mut R) -> Result<PayloadManifest, String> {
    let (base, _) = locate_payload(r)?;
    parse_payload_at(r, base)
}

pub fn parse_payload_at<R: Read + Seek>(r: &mut R, base: u64) -> Result<PayloadManifest, String> {
    r.seek(SeekFrom::Start(base))
        .map_err(|e| format!("seek payload base {base}: {e}"))?;
    let mut hdr20 = [0u8; 20];
    r.read_exact(&mut hdr20)
        .map_err(|e| format!("read CrAU header: {e}"))?;
    if &hdr20[0..4] != CRAU_MAGIC {
        return Err("Invalid CrAU magic".into());
    }
    let version = u64::from_be_bytes(hdr20[4..12].try_into().unwrap());
    let manifest_size = u64::from_be_bytes(hdr20[12..20].try_into().unwrap());
    if version != CRAU_VERSION_2 {
        return Err(format!("Unsupported CrAU version {version} (expected 2)"));
    }
    if manifest_size == 0 || manifest_size > 128 * 1024 * 1024 {
        return Err(format!("Implausible manifest_size={manifest_size}"));
    }

    let mut sigsz_raw = [0u8; 4];
    r.read_exact(&mut sigsz_raw)
        .map_err(|e| format!("read metadata_signature_size: {e}"))?;
    let metadata_signature_size = u32::from_be_bytes(sigsz_raw);

    let mut manifest_bytes = vec![0u8; manifest_size as usize];
    r.read_exact(&mut manifest_bytes)
        .map_err(|e| format!("read manifest ({manifest_size} B): {e}"))?;

    // Signed metadata region is the 24-byte header + manifest bytes
    let mut signed_region = Vec::with_capacity(24 + manifest_bytes.len());
    signed_region.extend_from_slice(&hdr20);
    signed_region.extend_from_slice(&sigsz_raw);
    signed_region.extend_from_slice(&manifest_bytes);
    let metadata_sha256 = sha256_bytes(&signed_region);

    let metadata_signatures = if metadata_signature_size > 0 {
        let mut sig_buf = vec![0u8; metadata_signature_size as usize];
        r.read_exact(&mut sig_buf)
            .map_err(|e| format!("read metadata signatures: {e}"))?;
        parse_signatures(&sig_buf)?
    } else {
        Vec::new()
    };

    let data_blob_offset = base + 24 + manifest_size + metadata_signature_size as u64;

    let mut block_size = 4096u64;
    let mut minor_version = 0u32;
    let mut signatures_offset = 0u64;
    let mut signatures_size = 0u64;
    let mut dynamic_metadata = DynamicPartitionMetadata::default();
    let mut partitions = Vec::new();
    let mut partial_update = false;

    let mut i = 0;
    while let Some((f, v)) = next_field(&manifest_bytes, &mut i)? {
        match (f, v) {
            (3, PbVal::Varint(bs)) => block_size = bs,
            (4, PbVal::Varint(o)) => signatures_offset = o,
            (5, PbVal::Varint(s)) => signatures_size = s,
            (12, PbVal::Varint(mv)) => minor_version = mv as u32,
            (13, PbVal::Bytes(pb)) => partitions.push(parse_partition_update(pb)?),
            (15, PbVal::Bytes(dm)) => dynamic_metadata = parse_dynamic_metadata(dm)?,
            (16, PbVal::Varint(x)) => partial_update = x != 0,
            _ => {}
        }
    }

    Ok(PayloadManifest {
        payload_base_offset: base,
        version,
        block_size,
        minor_version,
        manifest_size,
        metadata_signature_size,
        data_blob_offset,
        metadata_sha256,
        metadata_signatures,
        signatures_offset,
        signatures_size,
        dynamic_metadata,
        partitions,
        partial_update,
    })
}

// ====================================================== Minimal Protobuf Encoder (for tests & tools)

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn put_field_varint(out: &mut Vec<u8>, f: u32, v: u64) {
    put_varint(out, ((f as u64) << 3) | 0);
    put_varint(out, v);
}

fn put_field_bytes(out: &mut Vec<u8>, f: u32, data: &[u8]) {
    put_varint(out, ((f as u64) << 3) | 2);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// Build a valid synthetic `CrAU` v2 payload buffer containing `REPLACE` / `ZERO` operations
/// for host testing and verification!
pub fn build_synthetic_payload(
    block_size: u64,
    dynamic_names: &[&str],
    partitions: &[(&str, &[u8])],
) -> Vec<u8> {
    build_synthetic_payload_ex(block_size, dynamic_names, partitions, false)
}

pub fn build_synthetic_payload_ex(
    block_size: u64,
    dynamic_names: &[&str],
    partitions: &[(&str, &[u8])],
    partial_update: bool,
) -> Vec<u8> {
    let mut data_blobs = Vec::new();
    let mut manifest = Vec::new();
    put_field_varint(&mut manifest, 3, block_size);
    put_field_varint(&mut manifest, 12, if partial_update { 7 } else { 0 });
    if partial_update {
        put_field_varint(&mut manifest, 16, 1);
    }

    for &(name, img) in partitions {
        let mut pu = Vec::new();
        put_field_bytes(&mut pu, 1, name.as_bytes());
        let mut new_info = Vec::new();
        put_field_varint(&mut new_info, 1, img.len() as u64);
        let digest = sha256_bytes(img);
        put_field_bytes(&mut new_info, 2, &digest);
        put_field_bytes(&mut pu, 7, &new_info);

        // Emit 1 MiB chunks (or smaller tail), automatically using ZERO for all-zero chunks
        let chunk_blocks = (1024 * 1024 / block_size).max(1);
        let chunk_bytes = (chunk_blocks * block_size) as usize;
        let mut block_idx = 0u64;
        for chunk in img.chunks(chunk_bytes) {
            let nblocks = (chunk.len() as u64).div_ceil(block_size);
            let mut op = Vec::new();
            let mut ext = Vec::new();
            put_field_varint(&mut ext, 1, block_idx);
            put_field_varint(&mut ext, 2, nblocks);

            if chunk.iter().all(|&b| b == 0) {
                put_field_varint(&mut op, 1, OpType::Zero as u64);
                put_field_bytes(&mut op, 6, &ext);
            } else {
                let mut padded = chunk.to_vec();
                let target_len = (nblocks * block_size) as usize;
                if padded.len() < target_len {
                    padded.resize(target_len, 0);
                }
                let doff = data_blobs.len() as u64;
                let dhash = sha256_bytes(&padded);
                data_blobs.extend_from_slice(&padded);
                put_field_varint(&mut op, 1, OpType::Replace as u64);
                put_field_varint(&mut op, 2, doff);
                put_field_varint(&mut op, 3, padded.len() as u64);
                put_field_bytes(&mut op, 6, &ext);
                put_field_bytes(&mut op, 8, &dhash);
            }
            put_field_bytes(&mut pu, 8, &op);
            block_idx += nblocks;
        }
        put_field_bytes(&mut manifest, 13, &pu);
    }

    if !dynamic_names.is_empty() {
        let mut dm = Vec::new();
        let mut grp = Vec::new();
        put_field_bytes(&mut grp, 1, b"qti_dynamic_partitions");
        put_field_varint(&mut grp, 2, 11_000_000_000);
        for dn in dynamic_names {
            put_field_bytes(&mut grp, 3, dn.as_bytes());
        }
        put_field_bytes(&mut dm, 1, &grp);
        put_field_varint(&mut dm, 2, 1);
        put_field_bytes(&mut manifest, 15, &dm);
    }

    let mut out = Vec::with_capacity(24 + manifest.len() + data_blobs.len());
    out.extend_from_slice(CRAU_MAGIC);
    out.extend_from_slice(&CRAU_VERSION_2.to_be_bytes());
    out.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes()); // metadata_signature_size = 0
    out.extend_from_slice(&manifest);
    out.extend_from_slice(&data_blobs);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_synthetic_crau_roundtrip() {
        let mut sys = vec![0xABu8; 4096 * 4];
        sys[4096 * 2..4096 * 3].fill(0x00);
        let boot = vec![0x5Au8; 4096 * 2];
        let raw = build_synthetic_payload(4096, &["system"], &[("system", &sys), ("boot", &boot)]);
        let mut cur = Cursor::new(&raw);
        let manifest = parse_payload(&mut cur).unwrap();
        assert_eq!(manifest.version, 2);
        assert_eq!(manifest.block_size, 4096);
        assert_eq!(manifest.partitions.len(), 2);
        assert!(manifest.dynamic_metadata.is_dynamic("system"));
        assert!(!manifest.dynamic_metadata.is_dynamic("boot"));
        assert_eq!(manifest.partitions[0].new_info.size, sys.len() as u64);
        assert_eq!(manifest.partitions[0].new_info.hash, Some(sha256_bytes(&sys)));
    }
}
