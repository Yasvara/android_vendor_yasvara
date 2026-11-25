// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Operation decoder supporting `REPLACE`, `ZERO`, `DISCARD`, and pluggable C FFI
//! decompression callbacks (`libzstd`, `liblzma`, `libbz`) on Android/Recovery with
//! zero-dependency CLI fallback (`zstd`/`xz`/`bzip2`) on Linux host.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::payload::OpType;

/// C decompress callback signature:
/// Returns decompressed byte count (`>= 0`) on success, or negative error code on failure.
pub type DecompressFn = unsafe extern "C" fn(
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_cap: usize,
) -> isize;

static ZSTD_DECOMPRESS: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static XZ_DECOMPRESS: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static BZ2_DECOMPRESS: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

pub fn register_zstd_decoder(f: DecompressFn) {
    ZSTD_DECOMPRESS.store(f as *mut (), Ordering::Release);
}
pub fn register_xz_decoder(f: DecompressFn) {
    XZ_DECOMPRESS.store(f as *mut (), Ordering::Release);
}
pub fn register_bz2_decoder(f: DecompressFn) {
    BZ2_DECOMPRESS.store(f as *mut (), Ordering::Release);
}

fn call_c_decoder(slot: &AtomicPtr<()>, src: &[u8], dst: &mut [u8]) -> Option<Result<usize, String>> {
    let ptr = slot.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr` was stored from a valid `DecompressFn` via register_*_decoder.
    let f: DecompressFn = unsafe { std::mem::transmute(ptr) };
    // SAFETY: `src` and `dst` pointers and lengths are valid for the duration of this call.
    let rc = unsafe { f(src.as_ptr(), src.len(), dst.as_mut_ptr(), dst.len()) };
    if rc < 0 {
        Some(Err(format!("native decompressor failed with code {rc}")))
    } else {
        Some(Ok(rc as usize))
    }
}

fn host_pipe_decompress(bin: &str, args: &[&str], src: &[u8], dst: &mut [u8]) -> Result<usize, String> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {bin}: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(src)
            .map_err(|e| format!("write to {bin} stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait {bin}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{bin} failed ({:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if out.stdout.len() > dst.len() {
        return Err(format!(
            "{bin} output ({} B) exceeds dst capacity ({} B)",
            out.stdout.len(),
            dst.len()
        ));
    }
    dst[..out.stdout.len()].copy_from_slice(&out.stdout);
    Ok(out.stdout.len())
}

/// Decode one `InstallOperation`'s payload bytes into `dst` (which must be sized to the
/// operation's destination extent byte size). Trailing bytes past decoded output are zeroed.
pub fn decode_op_into(op_type: OpType, raw_blob: &[u8], dst: &mut [u8]) -> Result<usize, String> {
    match op_type {
        OpType::Replace => {
            if raw_blob.len() > dst.len() {
                return Err(format!(
                    "REPLACE blob ({} B) > dst ({} B)",
                    raw_blob.len(),
                    dst.len()
                ));
            }
            dst[..raw_blob.len()].copy_from_slice(raw_blob);
            if raw_blob.len() < dst.len() {
                dst[raw_blob.len()..].fill(0);
            }
            Ok(raw_blob.len())
        }
        OpType::Zero | OpType::Discard => {
            dst.fill(0);
            Ok(dst.len())
        }
        OpType::ReplaceZstd => {
            let n = match call_c_decoder(&ZSTD_DECOMPRESS, raw_blob, dst) {
                Some(r) => r?,
                None => host_pipe_decompress("zstd", &["-dc"], raw_blob, dst)?,
            };
            if n < dst.len() {
                dst[n..].fill(0);
            }
            Ok(n)
        }
        OpType::ReplaceXz => {
            let n = match call_c_decoder(&XZ_DECOMPRESS, raw_blob, dst) {
                Some(r) => r?,
                None => host_pipe_decompress("xz", &["-dc"], raw_blob, dst)?,
            };
            if n < dst.len() {
                dst[n..].fill(0);
            }
            Ok(n)
        }
        OpType::ReplaceBz => {
            let n = match call_c_decoder(&BZ2_DECOMPRESS, raw_blob, dst) {
                Some(r) => r?,
                None => host_pipe_decompress("bzip2", &["-dc"], raw_blob, dst)?,
            };
            if n < dst.len() {
                dst[n..].fill(0);
            }
            Ok(n)
        }
        other => Err(format!(
            "Unsupported install operation type {} (in-OS CoW OTA supports full/ZSTD/XZ/BZ/REPLACE/ZERO/SOURCE_COPY)",
            other.as_str()
        )),
    }
}
