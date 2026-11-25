// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust Android Verified Boot 2.0 (`AVBf` footer + `AVB0` VBMeta header +
//! Hash & Hashtree descriptor) parser for pre-commit partition sanity verification.

use std::io::{Read, Seek, SeekFrom};

pub const AVB_FOOTER_MAGIC: &[u8; 4] = b"AVBf";
pub const AVB_FOOTER_SIZE: usize = 64;
pub const AVB_VBMETA_MAGIC: &[u8; 4] = b"AVB0";
pub const AVB_VBMETA_HEADER_SIZE: usize = 256;

const AVB_DESCRIPTOR_TAG_HASHTREE: u64 = 1;
const AVB_DESCRIPTOR_TAG_HASH: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvbFooter {
    pub version_major: u32,
    pub version_minor: u32,
    pub original_image_size: u64,
    pub vbmeta_offset: u64,
    pub vbmeta_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvbDescriptorSummary {
    pub kind: &'static str,
    pub partition_name: String,
    pub image_size: u64,
    pub hash_algorithm: String,
    pub root_digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvbVBMetaInfo {
    pub required_version_major: u32,
    pub required_version_minor: u32,
    pub algorithm_type: u32,
    pub flags: u32,
    pub rollback_index: u64,
    pub release_string: String,
    pub descriptors: Vec<AvbDescriptorSummary>,
}

#[inline]
fn u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
#[inline]
fn u64be(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

pub fn parse_avb_footer(raw: &[u8]) -> Result<AvbFooter, String> {
    if raw.len() < AVB_FOOTER_SIZE {
        return Err("Buffer smaller than 64-byte AVB footer".into());
    }
    let f = &raw[raw.len() - AVB_FOOTER_SIZE..];
    if &f[0..4] != AVB_FOOTER_MAGIC {
        return Err("Missing AVBf footer magic".into());
    }
    Ok(AvbFooter {
        version_major: u32be(f, 4),
        version_minor: u32be(f, 8),
        original_image_size: u64be(f, 12),
        vbmeta_offset: u64be(f, 20),
        vbmeta_size: u64be(f, 28),
    })
}

pub fn parse_vbmeta_blob(blob: &[u8]) -> Result<AvbVBMetaInfo, String> {
    if blob.len() < AVB_VBMETA_HEADER_SIZE {
        return Err("Buffer smaller than 256-byte AVB0 VBMeta header".into());
    }
    if &blob[0..4] != AVB_VBMETA_MAGIC {
        return Err("Missing AVB0 VBMeta magic".into());
    }
    let required_version_major = u32be(blob, 4);
    let required_version_minor = u32be(blob, 8);
    let auth_block_size = u64be(blob, 12) as usize;
    let aux_block_size = u64be(blob, 20) as usize;
    let algorithm_type = u32be(blob, 28);
    let descriptors_offset = u64be(blob, 64) as usize;
    let descriptors_size = u64be(blob, 72) as usize;
    let rollback_index = u64be(blob, 112);
    let flags = u32be(blob, 120);
    let release_string = cstr(&blob[128..176]);

    let aux_start = AVB_VBMETA_HEADER_SIZE + auth_block_size;
    if aux_start + aux_block_size > blob.len() {
        return Err("VBMeta auxiliary data block exceeds blob size".into());
    }
    let desc_start = aux_start + descriptors_offset;
    let desc_end = desc_start + descriptors_size;
    if desc_end > aux_start + aux_block_size {
        return Err("VBMeta descriptors exceed auxiliary data block".into());
    }

    let mut descriptors = Vec::new();
    let mut pos = desc_start;
    while pos + 16 <= desc_end {
        let tag = u64be(blob, pos);
        let num_bytes_following = u64be(blob, pos + 8) as usize;
        let body_start = pos + 16;
        let next = body_start + num_bytes_following;
        if next > desc_end {
            break;
        }
        let body = &blob[body_start..next];
        match tag {
            AVB_DESCRIPTOR_TAG_HASH if body.len() >= 56 => {
                // AvbHashDescriptor (after 16-byte header):
                // 0..8 image_size, 8..40 hash_algorithm[32], 40..44 pname_len, 44..48 salt_len, 48..52 digest_len, 52..56 flags, 56..116 reserved
                let image_size = u64be(body, 0);
                let hash_algorithm = cstr(&body[8..40]);
                let pname_len = u32be(body, 40) as usize;
                let salt_len = u32be(body, 44) as usize;
                let digest_len = u32be(body, 48) as usize;
                let data_off = 116; // sizeof(AvbHashDescriptor) - 16 = 132 - 16 = 116
                if data_off + pname_len + salt_len + digest_len <= body.len() {
                    let pname =
                        String::from_utf8_lossy(&body[data_off..data_off + pname_len]).into_owned();
                    let d_off = data_off + pname_len + salt_len;
                    let digest = body[d_off..d_off + digest_len].to_vec();
                    descriptors.push(AvbDescriptorSummary {
                        kind: "hash",
                        partition_name: pname,
                        image_size,
                        hash_algorithm,
                        root_digest: digest,
                    });
                }
            }
            AVB_DESCRIPTOR_TAG_HASHTREE if body.len() >= 164 => {
                // AvbHashtreeDescriptor (after 16-byte header):
                // 0..4 dm_verity_version, 4..12 image_size, 12..20 tree_offset, 20..28 tree_size,
                // 28..32 data_block_size, 32..36 hash_block_size, 36..40 fec_num_roots, 40..48 fec_offset, 48..56 fec_size,
                // 56..88 hash_algorithm[32], 88..92 pname_len, 92..96 salt_len, 96..100 root_digest_len, 100..104 flags, 104..164 reserved
                let image_size = u64be(body, 4);
                let hash_algorithm = cstr(&body[56..88]);
                let pname_len = u32be(body, 88) as usize;
                let salt_len = u32be(body, 92) as usize;
                let digest_len = u32be(body, 96) as usize;
                let data_off = 164; // sizeof(AvbHashtreeDescriptor) - 16 = 180 - 16 = 164
                if data_off + pname_len + salt_len + digest_len <= body.len() {
                    let pname =
                        String::from_utf8_lossy(&body[data_off..data_off + pname_len]).into_owned();
                    let d_off = data_off + pname_len + salt_len;
                    let digest = body[d_off..d_off + digest_len].to_vec();
                    descriptors.push(AvbDescriptorSummary {
                        kind: "hashtree",
                        partition_name: pname,
                        image_size,
                        hash_algorithm,
                        root_digest: digest,
                    });
                }
            }
            _ => {}
        }
        pos = next;
    }

    Ok(AvbVBMetaInfo {
        required_version_major,
        required_version_minor,
        algorithm_type,
        flags,
        rollback_index,
        release_string,
        descriptors,
    })
}

/// Inspect AVB footer/VBMeta on a partition stream (`reader` of length `part_size`).
/// Returns `Ok(None)` if the partition is unsigned/has no AVB footer (e.g. raw firmware blobs),
/// or `Ok(Some(AvbVBMetaInfo))` if valid AVB metadata is present, or `Err` if corrupted.
pub fn inspect_partition_avb<R: Read + Seek>(
    r: &mut R,
    part_size: u64,
) -> Result<Option<AvbVBMetaInfo>, String> {
    if part_size < AVB_FOOTER_SIZE as u64 {
        return Ok(None);
    }
    // Direct VBMeta partition (e.g. vbmeta, vbmeta_system)?
    r.seek(SeekFrom::Start(0))
        .map_err(|e| format!("seek 0: {e}"))?;
    let mut head = [0u8; 4];
    if r.read_exact(&mut head).is_ok() && &head == AVB_VBMETA_MAGIC {
        let take = part_size.min(64 * 1024) as usize;
        r.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek 0: {e}"))?;
        let mut blob = vec![0u8; take];
        r.read_exact(&mut blob)
            .map_err(|e| format!("read vbmeta: {e}"))?;
        return Ok(Some(parse_vbmeta_blob(&blob)?));
    }

    // Standard AVB footer at the end of the partition
    r.seek(SeekFrom::Start(part_size - AVB_FOOTER_SIZE as u64))
        .map_err(|e| format!("seek footer: {e}"))?;
    let mut footer_raw = [0u8; AVB_FOOTER_SIZE];
    r.read_exact(&mut footer_raw)
        .map_err(|e| format!("read footer: {e}"))?;
    if &footer_raw[0..4] != AVB_FOOTER_MAGIC {
        return Ok(None);
    }
    let footer = parse_avb_footer(&footer_raw)?;
    if footer.vbmeta_offset + footer.vbmeta_size > part_size || footer.vbmeta_size > 2 * 1024 * 1024 {
        return Err(format!(
            "Corrupt AVB footer: vbmeta {}+{} out of partition bounds ({part_size})",
            footer.vbmeta_offset, footer.vbmeta_size
        ));
    }
    r.seek(SeekFrom::Start(footer.vbmeta_offset))
        .map_err(|e| format!("seek vbmeta: {e}"))?;
    let mut blob = vec![0u8; footer.vbmeta_size as usize];
    r.read_exact(&mut blob)
        .map_err(|e| format!("read footer vbmeta: {e}"))?;
    Ok(Some(parse_vbmeta_blob(&blob)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_avb_footer_and_vbmeta_parse() {
        let mut vbmeta = vec![0u8; 512];
        vbmeta[0..4].copy_from_slice(AVB_VBMETA_MAGIC);
        vbmeta[4..8].copy_from_slice(&1u32.to_be_bytes());
        vbmeta[8..12].copy_from_slice(&2u32.to_be_bytes());
        vbmeta[12..20].copy_from_slice(&0u64.to_be_bytes()); // auth_block_size
        vbmeta[20..28].copy_from_slice(&256u64.to_be_bytes()); // aux_block_size
        vbmeta[128..139].copy_from_slice(b"avbtool 1.3");

        let mut img = vec![0u8; 4096];
        img[2048..2560].copy_from_slice(&vbmeta);
        let foff = 4096 - 64;
        img[foff..foff + 4].copy_from_slice(AVB_FOOTER_MAGIC);
        img[foff + 4..foff + 8].copy_from_slice(&1u32.to_be_bytes());
        img[foff + 12..foff + 20].copy_from_slice(&2048u64.to_be_bytes());
        img[foff + 20..foff + 28].copy_from_slice(&2048u64.to_be_bytes());
        img[foff + 28..foff + 36].copy_from_slice(&512u64.to_be_bytes());

        let mut cur = Cursor::new(&img);
        let info = inspect_partition_avb(&mut cur, img.len() as u64)
            .unwrap()
            .unwrap();
        assert_eq!(info.required_version_major, 1);
        assert_eq!(info.required_version_minor, 2);
        assert_eq!(info.release_string, "avbtool 1.3");
    }
}
