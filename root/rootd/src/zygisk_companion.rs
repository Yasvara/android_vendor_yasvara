// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Lazy Zygisk Companion launcher hosted inside `yasvara_rootd`'s single epoll loop.
//!
//! `yasvara_rootd` remains a pure static executable (`static_executable: true`) and never
//! maps third-party shared libraries into its own address space. When a Zygisk module calls
//! `api->connectCompanion()`, we read `[AKZC, id_len, id]` and exec the short-lived dynamic
//! helper `/system_ext/bin/yasvara_zygisk_companion <lib_path> <fd>`, which invokes
//! `zygisk_companion_entry(fd)` and exits cleanly. Zero idle process, zero idle battery.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use yasvara_root_proto::modules::validate_module_id;

use crate::sys;

const COMPANION_MAGIC: [u8; 4] = *b"AKZC";
const COMPANION_HELPER: &str = "/system_ext/bin/yasvara_zygisk_companion";
const COMPANION_ABI: &str = "arm64-v8a.so";

struct LiveCompanion {
    pid: libc::pid_t,
    control: RawFd,
}

fn live() -> &'static Mutex<HashMap<String, LiveCompanion>> {
    static LIVE: OnceLock<Mutex<HashMap<String, LiveCompanion>>> = OnceLock::new();
    LIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn bind_companion_socket(data_dir: &Path) -> io::Result<(RawFd, PathBuf)> {
    let run_dir = data_dir.join("run");
    let _ = std::fs::create_dir_all(&run_dir);
    let path = run_dir.join("zygisk.sock");
    let _ = std::fs::remove_file(&path);

    let fd = sys::cvt(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })?;
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        sys::close(fd);
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "companion socket path too long"));
    }
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }
    if let Err(e) = sys::cvt(unsafe {
        libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_un>() as _)
    }) {
        sys::close(fd);
        return Err(e);
    }
    let _ = unsafe { libc::chmod(addr.sun_path.as_ptr(), 0o666) };
    if let Err(e) = sys::cvt(unsafe { libc::listen(fd, 16) }) {
        sys::close(fd);
        return Err(e);
    }
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    Ok((fd, path))
}

fn send_fd(control: RawFd, fd: RawFd) -> bool {
    let mut byte = [b'F'];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut cmsg = [0u8; 64];
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&hdr);
        if c.is_null() {
            return false;
        }
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write(libc::CMSG_DATA(c) as *mut RawFd, fd);
        libc::sendmsg(control, &hdr, libc::MSG_NOSIGNAL) == 1
    }
}

fn spawn_companion(helper: &str, lib: &Path, conn: RawFd) -> Option<LiveCompanion> {
    let mut pair = [0; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, pair.as_mut_ptr()) } != 0 {
        return None;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        sys::close(pair[0]);
        sys::close(pair[1]);
        return None;
    }
    if pid == 0 {
        unsafe {
            libc::fcntl(conn, libc::F_SETFD, 0);
            libc::fcntl(pair[1], libc::F_SETFD, 0);
            let helper_c = CString::new(helper).unwrap();
            let lib_c = CString::new(lib.as_os_str().as_bytes()).unwrap();
            let client_c = CString::new(conn.to_string()).unwrap();
            let ctrl_c = CString::new(pair[1].to_string()).unwrap();
            let argv = [
                helper_c.as_ptr(),
                lib_c.as_ptr(),
                client_c.as_ptr(),
                ctrl_c.as_ptr(),
                std::ptr::null(),
            ];
            libc::execv(helper_c.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    sys::close(pair[1]);
    Some(LiveCompanion { pid, control: pair[0] })
}

/// Handles one incoming companion connection by reading `[AKZC, id_len, id]`.
/// One companion process per module per ABI stays up and receives later fds.
/// It exits itself after 60 s with nothing in flight.
pub fn handle_connection(conn: RawFd, data_dir: &Path, unprivileged_test: bool) {
    let mut hdr = [0u8; 8];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    if sys::read_exact_by(conn, &mut hdr, deadline).is_err() || hdr[0..4] != COMPANION_MAGIC {
        sys::close(conn);
        return;
    }
    let id_len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if id_len == 0 || id_len > 64 {
        sys::close(conn);
        return;
    }
    let mut id_buf = vec![0u8; id_len];
    if sys::read_exact_by(conn, &mut id_buf, deadline).is_err() {
        sys::close(conn);
        return;
    }
    let Ok(mod_id) = std::str::from_utf8(&id_buf) else {
        sys::close(conn);
        return;
    };
    if !validate_module_id(mod_id) {
        sys::close(conn);
        return;
    }

    let helper = COMPANION_HELPER;
    let abi = COMPANION_ABI;
    let lib_path = data_dir.join("modules").join(mod_id).join("zygisk").join(abi);
    if !lib_path.is_file() || unprivileged_test || !Path::new(helper).is_file() {
        sys::close(conn);
        return;
    }

    let key = format!("{mod_id}:{abi}");
    let mut map = live().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(live) = map.get(&key) {
        let alive = unsafe { libc::kill(live.pid, 0) == 0 };
        if alive && send_fd(live.control, conn) {
            sys::close(conn);
            return;
        }
        sys::close(live.control);
        let _ = unsafe { libc::waitpid(live.pid, std::ptr::null_mut(), libc::WNOHANG) };
        map.remove(&key);
    }
    match spawn_companion(helper, &lib_path, conn) {
        Some(live) => {
            map.insert(key, live);
            sys::close(conn);
        }
        None => sys::close(conn),
    }
}
