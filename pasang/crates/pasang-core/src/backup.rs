// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Streaming `.yvbak` USTAR `tar` archive writer/reader + SHA-256 manifest
//! verification (`SPEC-0051` §5.10). Zero external crates.

use crate::crypto::{hex_encode, sha256_bytes as sha256};
use std::io::{self, Read, Write};

/// A single archived file entry in a `.yvbak` backup stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupEntry {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub size: u64,
    pub sha256_hex: String,
}

/// Write a POSIX USTAR tar archive entry and return its verified `BackupEntry`.
pub fn write_tar_entry<W: Write>(
    writer: &mut W,
    path: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
    data: &[u8],
) -> io::Result<BackupEntry> {
    let clean_path = path.trim_start_matches('/');
    if clean_path.len() > 100 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tar path exceeds 100-byte USTAR name field",
        ));
    }

    let mut hdr = [0u8; 512];
    hdr[0..clean_path.len()].copy_from_slice(clean_path.as_bytes());
    write_octal(&mut hdr[100..108], mode as u64);
    write_octal(&mut hdr[108..116], uid as u64);
    write_octal(&mut hdr[116..124], gid as u64);
    write_octal(&mut hdr[124..136], data.len() as u64);
    write_octal(&mut hdr[136..148], mtime);
    hdr[148..156].fill(b' ');
    hdr[156] = b'0'; // regular file
    hdr[257..263].copy_from_slice(b"ustar\0");
    hdr[263..265].copy_from_slice(b"00");

    let csum: u32 = hdr.iter().map(|&b| b as u32).sum();
    let csum_str = format!("{:06o}\0 ", csum);
    hdr[148..156].copy_from_slice(csum_str.as_bytes());

    writer.write_all(&hdr)?;
    writer.write_all(data)?;
    let pad = (512 - (data.len() % 512)) % 512;
    if pad > 0 {
        writer.write_all(&vec![0u8; pad])?;
    }

    Ok(BackupEntry {
        path: clean_path.to_string(),
        mode,
        uid,
        gid,
        mtime,
        size: data.len() as u64,
        sha256_hex: hex_encode(&sha256(data)),
    })
}

/// Write standard 1024-byte EOF trailer for a USTAR tar stream.
pub fn finish_tar<W: Write>(writer: &mut W) -> io::Result<()> {
    writer.write_all(&[0u8; 1024])
}

/// Read and checksum-verify every entry in a USTAR tar stream.
pub fn read_tar_entries<R: Read>(mut reader: R) -> io::Result<Vec<(BackupEntry, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut hdr = [0u8; 512];
    loop {
        match reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        if hdr.iter().all(|&b| b == 0) {
            break;
        }
        let stored_csum = parse_octal(&hdr[148..156])?;
        let mut calc = 0u64;
        for (i, &b) in hdr.iter().enumerate() {
            calc += if (148..156).contains(&i) { b' ' as u64 } else { b as u64 };
        }
        if calc != stored_csum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tar header checksum mismatch",
            ));
        }
        let name_end = hdr[0..100].iter().position(|&b| b == 0).unwrap_or(100);
        let path = String::from_utf8_lossy(&hdr[0..name_end]).to_string();
        // Reject path traversal attacks on restore!
        if path.contains("..") || path.starts_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsafe tar entry path: {path}"),
            ));
        }
        let mode = parse_octal(&hdr[100..108])? as u32;
        let uid = parse_octal(&hdr[108..116])? as u32;
        let gid = parse_octal(&hdr[116..124])? as u32;
        let size = parse_octal(&hdr[124..136])?;
        let mtime = parse_octal(&hdr[136..148])?;

        let mut data = vec![0u8; size as usize];
        reader.read_exact(&mut data)?;
        let pad = (512 - (size as usize % 512)) % 512;
        if pad > 0 {
            let mut sink = [0u8; 512];
            reader.read_exact(&mut sink[..pad])?;
        }
        let sha256_hex = hex_encode(&sha256(&data));
        out.push((
            BackupEntry {
                path,
                mode,
                uid,
                gid,
                mtime,
                size,
                sha256_hex,
            },
            data,
        ));
    }
    Ok(out)
}

fn write_octal(dst: &mut [u8], val: u64) {
    let width = dst.len() - 1;
    let s = format!("{:0width$o}\0", val, width = width);
    let bytes = s.as_bytes();
    let copy_len = bytes.len().min(dst.len());
    dst[..copy_len].copy_from_slice(&bytes[..copy_len]);
}

fn parse_octal(src: &[u8]) -> io::Result<u64> {
    let s = std::str::from_utf8(src)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 tar octal"))?
        .trim_matches(|c: char| c == '\0' || c == ' ');
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tar octal"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_backup_roundtrip_and_sha256_parity() {
        let mut buf = Vec::new();
        let e1 = write_tar_entry(&mut buf, "boot.img", 0o600, 0, 0, 1795567800, b"ANDROID!bootdata").unwrap();
        let e2 = write_tar_entry(&mut buf, "vbmeta.img", 0o600, 0, 0, 1795567801, b"AVB0meta").unwrap();
        finish_tar(&mut buf).unwrap();

        let entries = read_tar_entries(&buf[..]).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, e1);
        assert_eq!(entries[0].1, b"ANDROID!bootdata");
        assert_eq!(entries[1].0, e2);
        assert_eq!(entries[1].1, b"AVB0meta");
    }

    #[test]
    fn tar_rejects_path_traversal_on_restore() {
        let mut buf = Vec::new();
        write_tar_entry(&mut buf, "../etc/passwd", 0o644, 0, 0, 0, b"evil").unwrap();
        finish_tar(&mut buf).unwrap();
        assert!(read_tar_entries(&buf[..]).is_err());
    }
}
