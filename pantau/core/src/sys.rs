// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Minimal zero-crate POSIX/Linux syscall bindings (`pread`, `clock_gettime`, `memfd_create`,
//! `mmap`, `epoll`, `timerfd`, `prctl`, `sched_setaffinity`, `setpriority`).

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

pub type RawFd = c_int;

pub const O_RDONLY: c_int = 0;
pub const O_CLOEXEC: c_int = 0o2000000;

pub const CLOCK_MONOTONIC: c_int = 1;
pub const CLOCK_THREAD_CPUTIME_ID: c_int = 3;
pub const CLOCK_BOOTTIME: c_int = 7;

pub const PROT_READ: c_int = 1;
pub const PROT_WRITE: c_int = 2;
pub const MAP_SHARED: c_int = 1;

pub const MFD_CLOEXEC: c_uint = 1;
pub const MFD_ALLOW_SEALING: c_uint = 2;
pub const F_ADD_SEALS: c_int = 1033;
pub const F_SEAL_SEAL: c_int = 1;
pub const F_SEAL_SHRINK: c_int = 2;
pub const F_SEAL_GROW: c_int = 4;

pub const PR_SET_TIMERSLACK: c_int = 29;
pub const PRIO_PROCESS: c_int = 0;

pub const EPOLL_CLOEXEC: c_int = 0o2000000;
pub const EPOLL_CTL_ADD: c_int = 1;
pub const EPOLL_CTL_DEL: c_int = 2;
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;

pub const TFD_NONBLOCK: c_int = 0o4000;
pub const TFD_CLOEXEC: c_int = 0o2000000;

#[cfg(target_arch = "x86_64")]
const SYS_MEMFD_CREATE: c_long = 319;
#[cfg(target_arch = "aarch64")]
const SYS_MEMFD_CREATE: c_long = 279;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Itimerspec {
    pub it_interval: Timespec,
    pub it_value: Timespec,
}

#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Copy, Clone, Default)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

extern "C" {
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn pread(fd: c_int, buf: *mut c_void, count: usize, offset: i64) -> isize;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn clock_gettime(clk_id: c_int, tp: *mut Timespec) -> c_int;
    fn ftruncate(fd: c_int, length: i64) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, length: usize) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn prctl(option: c_int, ...) -> c_int;
    fn setpriority(which: c_int, who: c_uint, prio: c_int) -> c_int;
    fn sched_setaffinity(pid: c_int, cpusetsize: usize, mask: *const c_void) -> c_int;
    fn timerfd_create(clockid: c_int, flags: c_int) -> c_int;
    fn timerfd_settime(
        fd: c_int,
        flags: c_int,
        new_value: *const Itimerspec,
        old_value: *mut Itimerspec,
    ) -> c_int;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, events: *mut EpollEvent, maxevents: c_int, timeout: c_int) -> c_int;
}

/// Opens a NUL-terminated path read-only with `O_CLOEXEC`. Returns `-1` on error.
pub fn open_ro_cstr(path_nul: &[u8]) -> RawFd {
    if path_nul.is_empty() || *path_nul.last().unwrap_or(&1) != 0 {
        return -1;
    }
    // SAFETY: `path_nul` is verified NUL-terminated.
    unsafe { open(path_nul.as_ptr() as *const c_char, O_RDONLY | O_CLOEXEC) }
}

/// Opens a Rust byte path read-only using a stack buffer (0 heap alloc, paths < 256 B).
pub fn open_ro(path: &[u8]) -> RawFd {
    if path.is_empty() || path.len() >= 256 {
        return -1;
    }
    let mut tmp = [0u8; 256];
    tmp[..path.len()].copy_from_slice(path);
    tmp[path.len()] = 0;
    // SAFETY: `tmp` is NUL-terminated at `path.len()`.
    unsafe { open(tmp.as_ptr() as *const c_char, O_RDONLY | O_CLOEXEC) }
}

/// Reads a sysfs/proc file from offset 0 into `buf` in a single `pread` syscall (0 alloc).
#[inline]
pub fn pread_zero<'a>(fd: RawFd, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    if fd < 0 {
        return None;
    }
    // SAFETY: `buf` is valid for `buf.len()` bytes.
    let n = unsafe { pread(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
    if n <= 0 {
        None
    } else {
        Some(&buf[..n as usize])
    }
}

#[inline]
pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> isize {
    if fd < 0 {
        return -1;
    }
    // SAFETY: `buf` is valid for `buf.len()` bytes.
    unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) }
}

#[inline]
pub fn close_fd(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: closing a valid fd.
        unsafe {
            close(fd);
        }
    }
}

#[inline]
pub fn clock_ns(clk: c_int) -> u64 {
    let mut ts = Timespec::default();
    // SAFETY: `ts` is valid writable memory.
    if unsafe { clock_gettime(clk, &mut ts) } == 0 {
        (ts.tv_sec.max(0) as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec.max(0) as u64)
    } else {
        0
    }
}

#[inline]
pub fn boottime_ns() -> u64 {
    clock_ns(CLOCK_BOOTTIME)
}

#[inline]
pub fn thread_cpu_ns() -> u64 {
    clock_ns(CLOCK_THREAD_CPUTIME_ID)
}

/// Creates a sealed `memfd` of `size` bytes and returns `(fd, rw_ptr)`.
pub fn create_sealed_memfd(name_nul: &[u8], size: usize) -> Option<(RawFd, *mut u8)> {
    if name_nul.is_empty() || *name_nul.last()? != 0 || size == 0 {
        return None;
    }
    // SAFETY: `name_nul` is NUL-terminated.
    let fd = unsafe {
        syscall(
            SYS_MEMFD_CREATE,
            name_nul.as_ptr() as *const c_char,
            (MFD_CLOEXEC | MFD_ALLOW_SEALING) as c_ulong,
        ) as RawFd
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: `fd` is a valid memfd.
    let trunc_ok = unsafe { ftruncate(fd, size as i64) } == 0;
    if !trunc_ok {
        close_fd(fd);
        return None;
    }
    // Seal size so read-only clients cannot encounter SIGBUS from shrinking.
    unsafe {
        let _ = fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL);
    }
    // SAFETY: valid fd and non-zero size.
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            0,
        )
    };
    if ptr == (!0usize as *mut c_void) || ptr.is_null() {
        close_fd(fd);
        return None;
    }
    Some((fd, ptr as *mut u8))
}

/// # Safety
/// `ptr` must have been mapped with `size` bytes.
pub unsafe fn munmap_region(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        // SAFETY: per caller contract.
        unsafe {
            munmap(ptr as *mut c_void, size);
        }
    }
}

/// Pins the current thread to the given CPU bitmask (`policy0` little cores), sets `nice(+4)`,
/// and applies kernel timer coalescing slack.
pub fn tune_daemon_thread(little_cpu_mask: u64, timer_slack_ns: u64) {
    if little_cpu_mask != 0 {
        let mask_words = [little_cpu_mask as usize; 1];
        // SAFETY: valid cpu_set_t mask for current thread (pid=0).
        unsafe {
            let _ = sched_setaffinity(
                0,
                core::mem::size_of_val(&mask_words),
                mask_words.as_ptr() as *const c_void,
            );
        }
    }
    // SAFETY: benign niceness & timer slack adjustment on current thread.
    unsafe {
        let _ = setpriority(PRIO_PROCESS, 0, 4);
        let _ = prctl(PR_SET_TIMERSLACK, timer_slack_ns as c_ulong, 0usize, 0usize, 0usize);
    }
}

pub fn create_monotonic_timerfd() -> RawFd {
    // SAFETY: standard timerfd creation.
    unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) }
}

/// Arms or disarms (`period_ms == 0`) a periodic timerfd.
pub fn set_timerfd_ms(fd: RawFd, period_ms: u32) -> bool {
    if fd < 0 {
        return false;
    }
    let ts = if period_ms == 0 {
        Timespec { tv_sec: 0, tv_nsec: 0 }
    } else {
        Timespec {
            tv_sec: (period_ms / 1000) as i64,
            tv_nsec: ((period_ms % 1000) as i64) * 1_000_000,
        }
    };
    let spec = Itimerspec {
        it_interval: ts,
        it_value: ts,
    };
    // SAFETY: valid fd and `Itimerspec`.
    unsafe { timerfd_settime(fd, 0, &spec, ptr::null_mut()) == 0 }
}

pub fn epoll_create() -> RawFd {
    // SAFETY: standard epoll_create1.
    unsafe { epoll_create1(EPOLL_CLOEXEC) }
}

pub fn epoll_add(epfd: RawFd, fd: RawFd, events: u32, token: u64) -> bool {
    let mut ev = EpollEvent { events, data: token };
    // SAFETY: valid fds and EpollEvent pointer.
    unsafe { epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &mut ev) == 0 }
}

pub fn epoll_wait_events(epfd: RawFd, out: &mut [EpollEvent], timeout_ms: i32) -> usize {
    if epfd < 0 || out.is_empty() {
        return 0;
    }
    // SAFETY: `out` is valid writable slice.
    let n = unsafe { epoll_wait(epfd, out.as_mut_ptr(), out.len() as c_int, timeout_ms) };
    if n <= 0 { 0 } else { n as usize }
}
