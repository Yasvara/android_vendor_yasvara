// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Privileged control-plane socket (`<data_dir>/run/mgmt.sock`) for `system_server`.
//!
//! Strictly accepts only `SO_PEERCRED` UID 0 (`root`) or UID 1000 (`system_server`), keeping
//! `ctl.sock` untouched (system_server continues to be refused on `ctl.sock` so `selfTest()`
//! stays faithful). Runs inside `yasvara_rootd`'s existing epoll loop with zero idle cost.
//!
//! Wire format:
//!   Request:  `[u32 payload_len][utf8_payload]` (max 64 KiB)
//!   Response: `[i32 exit_code][u32 out_len][utf8_output]`

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use yasvara_root_proto::modules::{modules_to_json, validate_module_id};

use crate::{bootguard, compat_ns, modules, sys};

const MAX_REQ_BYTES: usize = 64 * 1024;
const MAX_OUT_BYTES: usize = 256 * 1024;

pub fn bind_mgmt_socket(data_dir: &Path) -> io::Result<(RawFd, PathBuf)> {
    let run_dir = data_dir.join("run");
    let _ = std::fs::create_dir_all(&run_dir);
    let path = run_dir.join("mgmt.sock");
    let _ = std::fs::remove_file(&path);

    let fd = sys::cvt(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })?;
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        sys::close(fd);
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "mgmt socket path too long"));
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
    // 0660 root:system -> only root and system_server may connect.
    let _ = unsafe { libc::chown(addr.sun_path.as_ptr(), 0, 1000) };
    let _ = unsafe { libc::chmod(addr.sun_path.as_ptr(), 0o660) };
    if let Err(e) = sys::cvt(unsafe { libc::listen(fd, 8) }) {
        sys::close(fd);
        return Err(e);
    }
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    Ok((fd, path))
}

fn send_response(conn: RawFd, code: i32, mut body: String) {
    if body.len() > MAX_OUT_BYTES {
        body.truncate(MAX_OUT_BYTES);
    }
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(&code.to_le_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body.as_bytes());
    let _ = sys::send_all(conn, &frame);
}

/// Validates and dispatches one control-plane request in a forked child so long-running
/// installs or `action.sh` executions never stall `yasvara_rootd`'s main `su` epoll loop.
pub fn handle_connection(conn: RawFd, data_dir: &Path, unprivileged_test: bool) {
    let cred = match sys::peer_cred(conn) {
        Ok(c) => c,
        Err(_) => return sys::close(conn),
    };
    if !unprivileged_test && cred.uid != 0 && cred.uid != 1000 {
        sys::close(conn);
        return;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        sys::close(conn);
        return;
    }
    if pid > 0 {
        sys::close(conn);
        return;
    }
    // Child worker handles the request synchronously and exits.
    let (code, out) = serve_one(conn, data_dir, unprivileged_test);
    send_response(conn, code, out);
    sys::close(conn);
    unsafe { libc::_exit(0) };
}

fn serve_one(conn: RawFd, data_dir: &Path, unprivileged_test: bool) -> (i32, String) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut len_buf = [0u8; 4];
    if sys::read_exact_by(conn, &mut len_buf, deadline).is_err() {
        return (1, "short header".into());
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_REQ_BYTES {
        return (1, "invalid request length".into());
    }
    let mut req_buf = vec![0u8; len];
    if sys::read_exact_by(conn, &mut req_buf, deadline).is_err() {
        return (1, "truncated payload".into());
    }
    let Ok(req) = std::str::from_utf8(&req_buf) else {
        return (1, "non-utf8 payload".into());
    };
    let (head, tail) = req.split_once('\n').unwrap_or((req, ""));
    let parts: Vec<&str> = head.splitn(3, ' ').collect();
    match parts.first().copied().unwrap_or("") {
        "LIST" => (0, modules_to_json(&modules::list_modules(data_dir))),
        "BG_STATUS" => (0, bootguard::read_status(data_dir).to_json()),
        "BG_CLEAR" => {
            let bg = bootguard::BootguardPaths::resolve(data_dir, None);
            match bootguard::clear_safemode(&bg) {
                Ok(()) => (0, "ok".into()),
                Err(e) => (1, e.to_string()),
            }
        }
        "MANAGED_FEATURES" => {
            let feats: Vec<String> = modules::active_managed_features(data_dir).into_iter().collect();
            (0, feats.join(","))
        }
        "INSTALL" => {
            let Some(zip_path) = parts.get(1) else { return (2, "missing zip path".into()) };
            match modules::install_module_zip(data_dir, Path::new(zip_path), unprivileged_test) {
                Ok((_, log, _)) => {
                    sync_managed_features_file(data_dir);
                    (0, log)
                }
                Err(e) => (1, e.to_string()),
            }
        }
        "ENABLE" | "DISABLE" => {
            let Some(id) = parts.get(1) else { return (2, "missing module id".into()) };
            let enable = parts[0] == "ENABLE";
            match modules::set_module_enabled(data_dir, id, enable) {
                Ok(()) => {
                    sync_managed_features_file(data_dir);
                    (0, "ok".into())
                }
                Err(e) => (1, e.to_string()),
            }
        }
        "REMOVE" | "UNDO_REMOVE" => {
            let Some(id) = parts.get(1) else { return (2, "missing module id".into()) };
            match modules::set_module_remove(data_dir, id, parts[0] == "REMOVE") {
                Ok(()) => {
                    sync_managed_features_file(data_dir);
                    (0, "ok".into())
                }
                Err(e) => (1, e.to_string()),
            }
        }
        "ACTION" => {
            let Some(id) = parts.get(1) else { return (2, "missing module id".into()) };
            match modules::run_module_action(data_dir, id, unprivileged_test) {
                Ok((code, out)) => (code, out),
                Err(e) => (1, e.to_string()),
            }
        }
        "EXEC" => {
            let Some(id) = parts.get(1) else { return (2, "missing module id".into()) };
            if !validate_module_id(id) {
                return (2, "invalid module id".into());
            }
            let mod_dir = modules::modules_dir(data_dir).join(id);
            if !mod_dir.is_dir() {
                return (1, "module not found".into());
            }
            let sh = if Path::new("/system/bin/sh").exists() { "/system/bin/sh" } else { "/bin/sh" };
            let mut cmd = std::process::Command::new(sh);
            cmd.arg("-c").arg(tail);
            cmd.current_dir(&mod_dir);
            for (k, v) in compat_ns::compat_env(data_dir, unprivileged_test) {
                cmd.env(k, v);
            }
            cmd.env("MODDIR", mod_dir.display().to_string());
            if !unprivileged_test {
                let dd = data_dir.to_path_buf();
                unsafe {
                    use std::os::unix::process::CommandExt;
                    cmd.pre_exec(move || compat_ns::enter_compat_adb_namespace(&dd, false));
                }
            }
            match cmd.output() {
                Ok(out) => {
                    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                    let err = String::from_utf8_lossy(&out.stderr);
                    if !err.is_empty() {
                        if !text.is_empty() && !text.ends_with('\n') {
                            text.push('\n');
                        }
                        text.push_str(&err);
                    }
                    (out.status.code().unwrap_or(1), text)
                }
                Err(e) => (1, e.to_string()),
            }
        }
        other => (2, format!("unknown command: {other}")),
    }
}

pub fn sync_managed_features_file(data_dir: &Path) {
    let feats: Vec<String> = modules::active_managed_features(data_dir).into_iter().collect();
    let content = format!("{}\n", feats.join(","));
    let _ = sys::replace_file(&data_dir.join("managed_features"), content.as_bytes());
}
