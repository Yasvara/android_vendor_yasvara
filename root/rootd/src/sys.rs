// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Thin, audited wrappers over the syscalls rootd needs. Every `unsafe` block in the daemon
//! lives in this file or in `session.rs`' child setup, so there is one place to review.

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cvt_s(r: libc::ssize_t) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

pub fn close(fd: RawFd) {
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

pub fn peer_cred(fd: RawFd) -> io::Result<libc::ucred> {
    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    })?;
    Ok(cred)
}

pub fn send_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), libc::MSG_NOSIGNAL) };
        match cvt_s(n) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// One small frame into a fresh connection, never blocking: the socket buffer of a connection
/// that has only just been accepted is empty, so 16 bytes always fit; if they somehow do not
/// the caller treats it as a failed connection rather than waiting on a client.
pub fn send_frame_nowait(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let n = unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    match cvt_s(n) {
        Ok(n) if n == buf.len() => Ok(()),
        Ok(_) => Err(io::ErrorKind::WriteZero.into()),
        Err(e) => Err(e),
    }
}

/// Sends `buf` with `fds` attached (SCM_RIGHTS); returns the bytes written.
pub fn send_with_fds(fd: RawFd, buf: &[u8], fds: &[RawFd]) -> io::Result<usize> {
    let mut iov = libc::iovec { iov_base: buf.as_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let space = unsafe { libc::CMSG_SPACE((fds.len() * mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cbuf = vec![0u8; space.max(1)];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN((fds.len() * mem::size_of::<RawFd>()) as u32) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr() as *const u8,
                libc::CMSG_DATA(c),
                fds.len() * mem::size_of::<RawFd>(),
            );
        }
    }
    loop {
        match cvt_s(unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) }) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            r => return r,
        }
    }
}

/// Receives into `buf`; any fds that arrive are returned close-on-exec. A truncated control
/// message (more fds than `max_fds`) is an error and nothing is leaked.
pub fn recv_with_fds(fd: RawFd, buf: &mut [u8], max_fds: usize) -> io::Result<(usize, Vec<RawFd>)> {
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let space = unsafe { libc::CMSG_SPACE((max_fds * mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    let n = loop {
        match cvt_s(unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) }) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            r => break r?,
        }
    };
    let mut fds = Vec::new();
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c) as *const RawFd;
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / mem::size_of::<RawFd>();
                for i in 0..count {
                    fds.push(std::ptr::read_unaligned(data.add(i)));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        fds.iter().for_each(|&f| close(f));
        return Err(io::Error::new(io::ErrorKind::InvalidData, "control message truncated"));
    }
    Ok((n, fds))
}

/// Waits until `fd` is readable or `deadline` passes. `Ok(false)` on timeout.
pub fn wait_readable(fd: RawFd, deadline: Instant) -> io::Result<bool> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(false);
        }
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let ms = left.as_millis().min(i32::MAX as u128).max(1) as i32;
        match cvt(unsafe { libc::poll(&mut p, 1, ms) }) {
            Ok(0) => {}
            Ok(_) => return Ok(true),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Reads exactly `buf.len()` bytes before `deadline`.
pub fn read_exact_by(fd: RawFd, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        if !wait_readable(fd, deadline)? {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let n = unsafe { libc::recv(fd, buf[at..].as_mut_ptr() as *mut libc::c_void, buf.len() - at, 0) };
        match cvt_s(n) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => at += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A pty pair (master, slave), both close-on-exec.
pub fn open_pty() -> io::Result<(RawFd, RawFd)> {
    unsafe {
        let m = cvt(libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC))?;
        let mut name = [0 as libc::c_char; 64];
        let r = cvt(libc::grantpt(m))
            .and_then(|_| cvt(libc::unlockpt(m)))
            .and_then(|_| cvt(libc::ptsname_r(m, name.as_mut_ptr(), name.len())));
        if let Err(e) = r {
            libc::close(m);
            return Err(e);
        }
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if s < 0 {
            let e = io::Error::last_os_error();
            libc::close(m);
            return Err(e);
        }
        Ok((m, s))
    }
}

pub fn set_winsize(fd: RawFd, rows: u16, cols: u16) {
    if rows == 0 && cols == 0 {
        return;
    }
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, &ws) };
}

pub fn now_wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_millis() as u64
}

pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()).unwrap_or_default()
}

#[cfg(target_os = "android")]
extern "C" {
    fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> libc::c_int;
}

/// A system property, or `None` if unset (always `None` off Android).
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn get_prop(name: &str) -> Option<String> {
    #[cfg(target_os = "android")]
    {
        let n = CString::new(name).ok()?;
        let mut buf = [0 as libc::c_char; 92];
        let len = unsafe { __system_property_get(n.as_ptr(), buf.as_mut_ptr()) };
        if len <= 0 {
            return None;
        }
        let bytes: Vec<u8> = buf[..len as usize].iter().map(|&c| c as u8).collect();
        String::from_utf8(bytes).ok()
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = name;
        None
    }
}

/// Whether credential-encrypted storage of the caller's user is unlocked. Off Android there
/// is no such state, so the answer is yes.
pub fn user_unlocked(uid: u32) -> bool {
    #[cfg(target_os = "android")]
    {
        get_prop(&format!("sys.user.{}.ce_available", uid / 100_000)).as_deref() == Some("true")
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = uid;
        true
    }
}

/// Moves the calling process to SELinux context `ctx` (a dyntransition). Must be called
/// from a single-threaded process.
pub fn setcon(ctx: &str) -> io::Result<()> {
    let path = CString::new("/proc/self/attr/current").unwrap();
    let fd = cvt(unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) })?;
    let mut bytes = ctx.as_bytes().to_vec();
    bytes.push(0);
    let n = unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    let r = cvt_s(n).map(|_| ());
    close(fd);
    r
}

/// One audit line, appended with a single write(2) so concurrent sessions cannot interleave.
/// Two files of at most 128 KiB; the group of both is `system` so system_server can read.
pub fn audit(dir: &Path, line: &str) {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    const MAX: u64 = 128 * 1024;
    let p0 = dir.join("audit.0");
    if std::fs::metadata(&p0).map(|m| m.len() > MAX).unwrap_or(false) {
        let _ = std::fs::rename(&p0, dir.join("audit.1"));
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).mode(0o640).open(&p0) {
        let mut l = line.replace(['\n', '\r'], " ");
        l.truncate(400);
        l.push('\n');
        let _ = f.write_all(l.as_bytes());
        // gid 1000 = system. Harmless failure: the log is still written, just unreadable by it.
        unsafe { libc::fchown(f.as_raw_fd(), u32::MAX, 1000) };
    }
}

/// Replaces anything that would break the `|`-separated audit format.
pub fn clean(s: &[u8], max: usize) -> String {
    String::from_utf8_lossy(&s[..s.len().min(max)])
        .chars()
        .map(|c| if c == '|' || c.is_control() { ' ' } else { c })
        .collect()
}

/// An inotify descriptor watching `dir` for files being renamed into place or removed
/// (non-blocking, close-on-exec). Idle cost is zero: the daemon's epoll wakes on it. Not
/// `IN_CLOSE_WRITE`/`IN_CREATE`: the audit files are appended on every `su` call and would wake
/// the daemon twice each time; the policy is replaced atomically (rename), so `IN_MOVED_TO`
/// is the whole signal.
pub fn watch_dir(dir: &Path) -> io::Result<RawFd> {
    let fd = cvt(unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) })?;
    let c = CString::new(dir.as_os_str().as_encoded_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mask = libc::IN_MOVED_TO | libc::IN_DELETE;
    if let Err(e) = cvt(unsafe { libc::inotify_add_watch(fd, c.as_ptr(), mask) }) {
        close(fd);
        return Err(e);
    }
    Ok(fd)
}

/// Drains a [`watch_dir`] descriptor; returns all affected filenames.
pub fn drain_watch_any(fd: RawFd) -> Vec<String> {
    let mut names = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            return names;
        }
        let mut off = 0usize;
        let n = n as usize;
        let hdr = mem::size_of::<libc::inotify_event>();
        while off + hdr <= n {
            let len = u32::from_ne_bytes(buf[off + 12..off + 16].try_into().unwrap()) as usize;
            let start = off + hdr;
            let end = (start + len).min(n);
            let raw = &buf[start..end];
            let raw = raw.split(|&b| b == 0).next().unwrap_or(&[]);
            if let Ok(s) = std::str::from_utf8(raw) {
                if !s.is_empty() {
                    names.push(s.to_string());
                }
            }
            off = start + len;
        }
    }
}

/// Drains a [`watch_dir`] descriptor; true if any event named `name`.
#[allow(dead_code)]
pub fn drain_watch(fd: RawFd, name: &str) -> bool {
    drain_watch_any(fd).iter().any(|s| s == name)
}

/// Bumped after every change to a set file Zygote reads. Zygote keeps the `prop_info` and
/// compares its serial on each fork: one load, no syscall, files re-read only on change.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub const ZYGOTE_GEN_PROP: &[u8] = b"sys.yasvara.akar.gen\0";

#[cfg(test)]
pub static GEN_BUMPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn bump_zygote_gen() {
    #[cfg(test)]
    GEN_BUMPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(target_os = "android")]
    {
        extern "C" {
            fn __system_property_set(name: *const libc::c_char, value: *const libc::c_char) -> libc::c_int;
        }
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
        let v = format!("{}{:09}\0", ts.tv_sec, ts.tv_nsec);
        unsafe {
            __system_property_set(ZYGOTE_GEN_PROP.as_ptr() as *const libc::c_char, v.as_ptr() as *const libc::c_char)
        };
    }
}

/// Writes (`Some`) or removes (`None`) a Zygote set file, then bumps the generation.
pub fn publish_set(path: &Path, bytes: Option<&[u8]>) -> io::Result<()> {
    let r = match bytes {
        Some(b) => replace_file(path, b),
        None => match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
    };
    bump_zygote_gen();
    r
}

pub const HIDE_MOUNTS: u32 = 1;
pub const HIDE_MAPS: u32 = 2;
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const HIDE_SWITCH: &str = "/sys/kernel/yasvara_hide/akar";

static HIDE_WRITTEN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);

/// Sets Akar's source of the kernel app-view hide filters (`HIDE_*` bits). The kernel
/// starts each boot at 0; one write per change per process.
pub fn write_hide_switch(bits: u32) {
    use std::sync::atomic::Ordering;
    if HIDE_WRITTEN.swap(bits, Ordering::Relaxed) == bits {
        return;
    }
    #[cfg(target_os = "android")]
    if let Err(e) = std::fs::write(HIDE_SWITCH, format!("{bits}\n")) {
        // Kernel without the switch: its filters are unconditional.
        if e.kind() != io::ErrorKind::NotFound {
            eprintln!("yasvara_rootd: {HIDE_SWITCH}: {e}");
        }
    }
}

/// Atomically replaces `path` with `bytes` (mode 0644, readable by zygote): write to
/// `<path>.new`, rename over. SELinux labels the `.new` file through a named type transition.
pub fn replace_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".new");
    let tmp = std::path::PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&tmp)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}
