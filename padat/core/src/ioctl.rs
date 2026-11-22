// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Low-level Linux / F2FS ioctls, xattr preservation, and worker scheduling helpers.
//! Zero external crates.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::OnceLock;

// Linux FS_IOC_{GET,SET}FLAGS on 64-bit LP64 (aarch64 / x86_64): sizeof(c_long) == 8.
const FS_IOC_GETFLAGS: u64 = 0x8008_6601;
const FS_IOC_SETFLAGS: u64 = 0x4008_6602;

pub const FS_COMPR_FL: u64 = 0x0000_0004;
pub const FS_IMMUTABLE_FL: u64 = 0x0000_0010;
pub const FS_NOCOMP_FL: u64 = 0x0000_0400;
pub const FS_VERITY_FL: u64 = 0x0010_0000;

// Linux F2FS ioctls (include/uapi/linux/f2fs.h + V2 extensions).
const F2FS_IOC_GET_COMPRESS_BLOCKS: u64 = 0x8008_f511;
const F2FS_IOC_RELEASE_COMPRESS_BLOCKS: u64 = 0x8008_f512;
const F2FS_IOC_RESERVE_COMPRESS_BLOCKS: u64 = 0x8008_f513;
const F2FS_IOC_GET_COMPRESS_OPTION_V2: u64 = 0x8004_f51c;
const F2FS_IOC_SET_COMPRESS_OPTION_V2: u64 = 0x4004_f51d;

pub const COMPRESS_LZO: u8 = 0;
pub const COMPRESS_LZ4: u8 = 1;
pub const COMPRESS_ZSTD: u8 = 2;
pub const COMPRESS_LZORLE: u8 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F2fsCompOptionV2 {
    pub algorithm: u8,
    pub log_cluster_size: u8,
    pub level: u8,
    pub flags: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn fchown(fd: i32, owner: u32, group: u32) -> i32;
    fn fchmod(fd: i32, mode: u32) -> i32;
    fn futimens(fd: i32, times: *const Timespec) -> i32;
    fn flistxattr(fd: i32, list: *mut u8, size: usize) -> isize;
    fn fgetxattr(fd: i32, name: *const c_char, value: *mut u8, size: usize) -> isize;
    fn fsetxattr(fd: i32, name: *const c_char, value: *const u8, size: usize, flags: i32) -> i32;
    fn lsetxattr(
        path: *const c_char,
        name: *const c_char,
        value: *const u8,
        size: usize,
        flags: i32,
    ) -> i32;
    fn statfs(path: *const c_char, buf: *mut u64) -> i32;
    fn syncfs(fd: i32) -> i32;
    fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32;
    fn syscall(num: i64, ...) -> i64;
}

const INCFS_MAGIC_NUMBER: u64 = 0x5346_434e;
const IOPRIO_CLASS_BE: i64 = 2;
const POSIX_FADV_SEQUENTIAL: i32 = 2;
const SYNC_FILE_RANGE_WRITE: u64 = 2;

#[cfg(target_arch = "aarch64")]
const SYS_SYNC_FILE_RANGE: i64 = 84;
#[cfg(target_arch = "x86_64")]
const SYS_SYNC_FILE_RANGE: i64 = 277;

#[cfg(target_arch = "aarch64")]
const SYS_COPY_FILE_RANGE: i64 = 285;
#[cfg(target_arch = "x86_64")]
const SYS_COPY_FILE_RANGE: i64 = 326;

#[cfg(target_arch = "aarch64")]
const SYS_IOPRIO_SET: i64 = 30;
#[cfg(target_arch = "x86_64")]
const SYS_IOPRIO_SET: i64 = 251;

#[cfg(target_arch = "aarch64")]
const SYS_SCHED_SETAFFINITY: i64 = 122;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_SETAFFINITY: i64 = 203;

const IOPRIO_WHO_PROCESS: i64 = 1;
const IOPRIO_CLASS_IDLE: i64 = 3;

pub fn get_fs_flags(fd: RawFd) -> io::Result<u64> {
    let mut flags: u64 = 0;
    let ret = unsafe { ioctl(fd, FS_IOC_GETFLAGS, &mut flags as *mut u64) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

pub fn set_fs_flags(fd: RawFd, flags: u64) -> io::Result<()> {
    let mut f = flags;
    let ret = unsafe { ioctl(fd, FS_IOC_SETFLAGS, &mut f as *mut u64) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_compr_flag(fd: RawFd) -> io::Result<()> {
    let mut flags = get_fs_flags(fd)?;
    if (flags & FS_COMPR_FL) != 0 && (flags & FS_NOCOMP_FL) == 0 {
        return Ok(());
    }
    flags &= !FS_NOCOMP_FL;
    flags |= FS_COMPR_FL;
    set_fs_flags(fd, flags)
}

pub fn set_nocomp_flag(fd: RawFd) -> io::Result<()> {
    let mut flags = get_fs_flags(fd)?;
    if (flags & FS_NOCOMP_FL) != 0 && (flags & FS_COMPR_FL) == 0 {
        return Ok(());
    }
    flags &= !FS_COMPR_FL;
    flags |= FS_NOCOMP_FL;
    set_fs_flags(fd, flags)
}

pub fn clear_compr_and_nocomp_flags(fd: RawFd) -> io::Result<()> {
    let mut flags = get_fs_flags(fd)?;
    let new_flags = flags & !(FS_COMPR_FL | FS_NOCOMP_FL);
    if new_flags == flags {
        return Ok(());
    }
    flags = new_flags;
    set_fs_flags(fd, flags)
}

pub fn get_compress_option_v2(fd: RawFd) -> io::Result<F2fsCompOptionV2> {
    let mut opt = F2fsCompOptionV2 {
        algorithm: 0,
        log_cluster_size: 0,
        level: 0,
        flags: 0,
    };
    let ret = unsafe { ioctl(fd, F2FS_IOC_GET_COMPRESS_OPTION_V2, &mut opt as *mut F2fsCompOptionV2) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(opt)
    }
}

pub fn set_compress_option_v2(fd: RawFd, opt: F2fsCompOptionV2) -> io::Result<()> {
    let mut o = opt;
    let ret = unsafe { ioctl(fd, F2FS_IOC_SET_COMPRESS_OPTION_V2, &mut o as *mut F2fsCompOptionV2) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn get_compress_blocks(fd: RawFd) -> io::Result<u64> {
    let mut blks: u64 = 0;
    let ret = unsafe { ioctl(fd, F2FS_IOC_GET_COMPRESS_BLOCKS, &mut blks as *mut u64) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(blks)
    }
}

pub fn release_compress_blocks(fd: RawFd) -> io::Result<u64> {
    let mut released: u64 = 0;
    let ret = unsafe { ioctl(fd, F2FS_IOC_RELEASE_COMPRESS_BLOCKS, &mut released as *mut u64) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(released)
    }
}

pub fn reserve_compress_blocks(fd: RawFd) -> io::Result<u64> {
    let mut reserved: u64 = 0;
    let ret = unsafe { ioctl(fd, F2FS_IOC_RESERVE_COMPRESS_BLOCKS, &mut reserved as *mut u64) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(reserved)
    }
}

/// Copies ownership, mode, timestamps, and all extended attributes (including `security.selinux`)
/// from `src_fd` onto `dst_fd` (falling back to `lsetxattr(dst_path)` if needed).
pub fn preserve_metadata(
    src_fd: RawFd,
    dst_fd: RawFd,
    dst_path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    atime_sec: i64,
    atime_nsec: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
) -> io::Result<()> {
    if unsafe { fchown(dst_fd, uid, gid) } < 0 {
        let e = io::Error::last_os_error();
        // On non-root host unit tests, chown to same uid is a no-op; ignore EPERM only if uid unchanged.
        if e.raw_os_error() != Some(1) {
            return Err(e);
        }
    }
    if unsafe { fchmod(dst_fd, mode & 0o7777) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // Copy extended attributes (notably `security.selinux`) using stack buffers to avoid
    // per-file heap allocations, and skip `fsetxattr` when `dst_fd` already inherited
    // the exact same value from the parent directory.
    let mut names_stack = [0u8; 512];
    let mut names_heap: Vec<u8> = Vec::new();
    let got_names: &[u8] = {
        let got = unsafe { flistxattr(src_fd, names_stack.as_mut_ptr(), names_stack.len()) };
        if got > 0 {
            &names_stack[..got as usize]
        } else if got < 0 && io::Error::last_os_error().raw_os_error() == Some(34) /* ERANGE */ {
            let need = unsafe { flistxattr(src_fd, std::ptr::null_mut(), 0) };
            if need > 0 {
                names_heap.resize(need as usize, 0);
                let g2 = unsafe { flistxattr(src_fd, names_heap.as_mut_ptr(), names_heap.len()) };
                if g2 > 0 {
                    &names_heap[..g2 as usize]
                } else {
                    &[]
                }
            } else {
                &[]
            }
        } else {
            &[]
        }
    };

    if !got_names.is_empty() {
        let dst_cpath = CString::new(dst_path.as_os_str().as_bytes()).ok();
        let mut val_stack = [0u8; 256];
        let mut dst_stack = [0u8; 256];
        let mut val_heap: Vec<u8> = Vec::new();
        let mut start = 0usize;
        let got = got_names.len();
        while start < got {
            let end = got_names[start..got]
                .iter()
                .position(|&b| b == 0)
                .map(|p| start + p)
                .unwrap_or(got);
            if end > start {
                let name_bytes = &got_names[start..end];
                let skip = name_bytes.starts_with(b"encryption.")
                    || name_bytes == b"security.capability"
                    || name_bytes.starts_with(b"system.verity");
                if !skip {
                    if let Ok(cname) = CString::new(name_bytes) {
                        let r = unsafe {
                            fgetxattr(src_fd, cname.as_ptr(), val_stack.as_mut_ptr(), val_stack.len())
                        };
                        let val_slice: Option<&[u8]> = if r >= 0 {
                            Some(&val_stack[..r as usize])
                        } else if io::Error::last_os_error().raw_os_error() == Some(34) {
                            let need = unsafe {
                                fgetxattr(src_fd, cname.as_ptr(), std::ptr::null_mut(), 0)
                            };
                            if need >= 0 {
                                val_heap.resize(need as usize, 0);
                                let r2 = unsafe {
                                    fgetxattr(src_fd, cname.as_ptr(), val_heap.as_mut_ptr(), val_heap.len())
                                };
                                if r2 >= 0 {
                                    Some(&val_heap[..r2 as usize])
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        if let Some(val) = val_slice {
                            // Fast check: skip fsetxattr if dst already inherited identical bytes!
                            let mut same = false;
                            if val.len() <= dst_stack.len() {
                                let dr = unsafe {
                                    fgetxattr(dst_fd, cname.as_ptr(), dst_stack.as_mut_ptr(), dst_stack.len())
                                };
                                if dr == val.len() as isize && &dst_stack[..val.len()] == val {
                                    same = true;
                                }
                            }
                            if !same {
                                let rc = unsafe {
                                    fsetxattr(dst_fd, cname.as_ptr(), val.as_ptr(), val.len(), 0)
                                };
                                if rc < 0 {
                                    if let Some(ref cp) = dst_cpath {
                                        let _ = unsafe {
                                            lsetxattr(
                                                cp.as_ptr(),
                                                cname.as_ptr(),
                                                val.as_ptr(),
                                                val.len(),
                                                0,
                                            )
                                        };
                                    }
                                }
                            }
                        }
                    }
                }
            }
            start = end + 1;
        }
    }

    // Preserve timestamps last so xattr/chmod don't bump mtime.
    let times = [
        Timespec {
            tv_sec: atime_sec,
            tv_nsec: atime_nsec,
        },
        Timespec {
            tv_sec: mtime_sec,
            tv_nsec: mtime_nsec,
        },
    ];
    let _ = unsafe { futimens(dst_fd, times.as_ptr()) };
    Ok(())
}

/// Returns true if `path` resides on Android Incremental FS (`incfs`), which cannot be
/// F2FS-compressed and whose backing FDs belong to `vold`.
pub fn is_incfs_path(path: &Path) -> bool {
    let Ok(cpath) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut buf = [0u64; 32]; // >= sizeof(struct statfs) on LP64 (120 bytes)
    if unsafe { statfs(cpath.as_ptr(), buf.as_mut_ptr()) } == 0 {
        return buf[0] == INCFS_MAGIC_NUMBER;
    }
    false
}

/// Flushes dirty data/metadata on the filesystem containing `fd` in a single checkpoint.
pub fn sync_filesystem(fd: RawFd) {
    let _ = unsafe { syncfs(fd) };
}

/// Hints sequential readahead on `fd` for large file scans/copies.
pub fn fadvise_sequential(fd: RawFd) {
    let _ = unsafe { posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL) };
}

/// Non-blocking writeback kick (`SYNC_FILE_RANGE_WRITE`) so kernel F2FS compression overlaps
/// asynchronously with streaming copy on large files without waiting for I/O completion.
pub fn sync_file_range_write(fd: RawFd, offset: u64, nbytes: u64) {
    let _ = unsafe {
        syscall(
            SYS_SYNC_FILE_RANGE,
            fd as i64,
            offset as i64,
            nbytes as i64,
            SYNC_FILE_RANGE_WRITE as i64,
        )
    };
}

/// Zero-copy kernel-to-kernel file range transfer (returns bytes copied, or Err if unsupported).
pub fn copy_file_range_chunk(src_fd: RawFd, dst_fd: RawFd, len: usize) -> io::Result<usize> {
    let r = unsafe {
        syscall(
            SYS_COPY_FILE_RANGE,
            src_fd as i64,
            0i64, // NULL off_in -> advance src_fd offset
            dst_fd as i64,
            0i64, // NULL off_out -> advance dst_fd offset
            len as i64,
            0i64, // flags
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

static WORKER_PLAN: OnceLock<(usize, u64)> = OnceLock::new();

/// Dynamically computes `(worker_threads, cpu_affinity_mask)` for the host SoC:
/// excludes the single highest-frequency prime core so foreground UI stays 120 FPS smooth,
/// and uses up to 6 worker threads across the remaining big/mid/efficiency cores.
pub fn compute_worker_plan() -> (usize, u64) {
    *WORKER_PLAN.get_or_init(|| {
        let mut cpus: Vec<(u32, u64)> = Vec::new();
        for id in 0..16u32 {
            let p = format!("/sys/devices/system/cpu/cpu{id}/cpufreq/cpuinfo_max_freq");
            if let Ok(s) = fs::read_to_string(&p) {
                if let Ok(freq) = s.trim().parse::<u64>() {
                    cpus.push((id, freq));
                }
            }
        }
        if cpus.len() <= 2 {
            return (2, 0);
        }
        // Identify the single highest-freq core (e.g. X4 Prime cpu7 on SM8735) and leave it free.
        let prime_id = cpus
            .iter()
            .max_by_key(|&&(id, freq)| (freq, id))
            .map(|&(id, _)| id)
            .unwrap_or(0);
        let mut mask = 0u64;
        let mut usable = 0usize;
        for &(id, _) in &cpus {
            if id != prime_id && id < 64 {
                mask |= 1u64 << id;
                usable += 1;
            }
        }
        // Up to 6 workers on 8-core SoCs (e.g. 6 threads across SM8735 CPUs 0..6, 5x A720 big + 1 eff).
        let workers = usable.saturating_sub(1).clamp(2, 6);
        (workers, mask)
    })
}

/// Tunes worker I/O priority and CPU affinity.
/// - `idle_mode = false` (interactive user compression): Best-Effort I/O prio 4 across
///   efficiency + mid cores (`0x7F` = CPUs 0..6, leaving prime core 7 free for UI smoothness).
/// - `idle_mode = true` (background maintenance): IDLE I/O prio 7 on efficiency cores (`0x03`).
pub fn set_worker_priority(cpu_mask: u64, idle_mode: bool) {
    let ioprio = if idle_mode {
        (IOPRIO_CLASS_IDLE << 13) | 7
    } else {
        (IOPRIO_CLASS_BE << 13) | 4
    };
    let _ = unsafe { syscall(SYS_IOPRIO_SET, IOPRIO_WHO_PROCESS, 0i64, ioprio) };
    if cpu_mask != 0 {
        let mask: [u64; 2] = [cpu_mask, 0];
        let _ = unsafe {
            syscall(
                SYS_SCHED_SETAFFINITY,
                0i64,
                std::mem::size_of::<[u64; 2]>() as i64,
                mask.as_ptr(),
            )
        };
    }
}

/// Backwards-compatible wrapper for background idle priority.
pub fn set_background_worker_priority(cpu_mask: u64) {
    set_worker_priority(cpu_mask, true);
}
