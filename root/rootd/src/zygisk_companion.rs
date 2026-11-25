// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Lazy Zygisk Companion launcher hosted inside `yasvara_rootd`'s single epoll loop.
//!
//! `yasvara_rootd` remains a pure static executable (`static_executable: true`) and never
//! maps third-party shared libraries into its own address space. When a Zygisk module calls
//! `api->connectCompanion()`, we read `[AKZC, id_len, id]` and exec the short-lived dynamic
//! helper `/system_ext/bin/yasvara_zygisk_companion <lib_path> <fd>`, which invokes
//! `zygisk_companion_entry(fd)` and exits cleanly. Zero idle process, zero idle battery.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

use yasvara_root_proto::modules::validate_module_id;

use crate::sys;

const COMPANION_MAGIC: [u8; 4] = *b"AKZC";
const COMPANION_HELPER: &str = "/system_ext/bin/yasvara_zygisk_companion";

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

/// Handles one incoming companion connection by reading `[AKZC, id_len, id]` and
/// forking+execing `yasvara_zygisk_companion <module_so> <fd>`.
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

    let abi = if cfg!(target_arch = "aarch64") {
        "arm64-v8a.so"
    } else if cfg!(target_arch = "arm") {
        "armeabi-v7a.so"
    } else {
        "arm64-v8a.so"
    };
    let lib_path = data_dir.join("modules").join(mod_id).join("zygisk").join(abi);
    if !lib_path.is_file() || unprivileged_test || !Path::new(COMPANION_HELPER).is_file() {
        sys::close(conn);
        return;
    }

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Clear FD_CLOEXEC on `conn` so the helper inherits it.
        unsafe { libc::fcntl(conn, libc::F_SETFD, 0) };
        let helper_c = CString::new(COMPANION_HELPER).unwrap();
        let lib_c = CString::new(lib_path.as_os_str().as_bytes()).unwrap();
        let fd_c = CString::new(conn.to_string()).unwrap();
        let argv = [helper_c.as_ptr(), lib_c.as_ptr(), fd_c.as_ptr(), std::ptr::null()];
        unsafe {
            libc::execv(helper_c.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    sys::close(conn);
}
