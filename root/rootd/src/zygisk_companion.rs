// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Zygisk companion launcher on `yasvara_rootd`'s epoll loop.
//!
//! rootd is static and never maps module code. On `api->connectCompanion()` it reads
//! `[AKZC, id_len, id]` and hands the fd to `/system/xbin/yasvara_zygisk_companion`, one
//! resident process per module that loads the `.so` once and exits after 60 s idle.
//!
//! A companion lives only as long as the code it loaded: a replaced `.so` (hot install) retires
//! it, so in-flight clients finish on the old code and the next one gets a fresh process; a
//! disabled, removed or deleted module, or Zygisk turned off, kills it.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use yasvara_root_proto::modules::validate_module_id;

use crate::sys;

const COMPANION_MAGIC: [u8; 4] = *b"AKZC";
const COMPANION_HELPER: &str = "/system/xbin/yasvara_zygisk_companion";
const COMPANION_ABI: &str = "arm64-v8a.so";

struct LiveCompanion {
    pid: libc::pid_t,
    control: RawFd,
    lib: LibId,
}

/// Which file a companion loaded. A hot install renames the module dir away, so the path then
/// names a new inode; an in-place rewrite changes mtime or size.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct LibId {
    dev: u64,
    ino: u64,
    mtime_ns: i128,
    size: u64,
}

impl LibId {
    fn of(path: &Path) -> Option<LibId> {
        let m = std::fs::metadata(path).ok()?;
        if !m.is_file() {
            return None;
        }
        Some(LibId {
            dev: m.dev(),
            ino: m.ino(),
            mtime_ns: m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
            size: m.size(),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fate {
    Keep,
    /// Stop handing it fds; it finishes what it has and exits.
    Retire,
    /// Its module must not run any more.
    Kill,
}

fn module_live(data_dir: &Path, mod_id: &str) -> bool {
    let dir = data_dir.join("modules").join(mod_id);
    dir.join("module.prop").is_file() && !dir.join("disable").exists() && !dir.join("remove").exists()
}

fn lib_path(data_dir: &Path, mod_id: &str) -> PathBuf {
    data_dir.join("modules").join(mod_id).join("zygisk").join(COMPANION_ABI)
}

fn fate(data_dir: &Path, mod_id: &str, loaded: LibId) -> Fate {
    if !module_live(data_dir, mod_id) {
        return Fate::Kill;
    }
    match LibId::of(&lib_path(data_dir, mod_id)) {
        None => Fate::Kill,
        Some(now) if now != loaded => Fate::Retire,
        Some(_) => Fate::Keep,
    }
}

/// Closing the control socket is the retire signal (the companion reads EOF). The daemon's
/// SIGCHLD loop reaps both kinds.
fn end(live: LiveCompanion, fate: Fate) {
    if fate == Fate::Kill {
        unsafe { libc::kill(live.pid, libc::SIGKILL) };
    }
    sys::close(live.control);
}

fn reconcile_in(map: &mut HashMap<String, LiveCompanion>, data_dir: &Path, zygisk_on: bool) {
    let mut gone = Vec::new();
    for (mod_id, live) in map.iter() {
        let f = if zygisk_on { fate(data_dir, mod_id, live.lib) } else { Fate::Kill };
        if f != Fate::Keep {
            gone.push((mod_id.clone(), f));
        }
    }
    for (key, f) in gone {
        if let Some(live) = map.remove(&key) {
            end(live, f);
        }
    }
}

/// Ends companions whose module changed. Called after module operations (mgmt workers exit,
/// config or set files replaced); a no-op while none are running.
pub fn reconcile(data_dir: &Path) {
    let mut map = live().lock().unwrap_or_else(|e| e.into_inner());
    if map.is_empty() {
        return;
    }
    reconcile_in(&mut map, data_dir, crate::modules::is_zygisk_enabled(data_dir));
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

fn spawn_companion(helper: &str, lib: &Path, lib_id: LibId, conn: RawFd) -> Option<LiveCompanion> {
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
    Some(LiveCompanion { pid, control: pair[0], lib: lib_id })
}

/// Handles one incoming companion connection by reading `[AKZC, id_len, id]`.
/// One companion per module stays up and receives later fds while its `.so` is unchanged.
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

    let lib_path = lib_path(data_dir, mod_id);
    let Some(lib_id) = LibId::of(&lib_path).filter(|_| module_live(data_dir, mod_id)) else {
        sys::close(conn);
        return;
    };
    if unprivileged_test || !Path::new(COMPANION_HELPER).is_file() {
        sys::close(conn);
        return;
    }

    let key = mod_id.to_string();
    let mut map = live().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(live) = map.remove(&key) {
        let current = live.lib == lib_id;
        let alive = unsafe { libc::kill(live.pid, 0) == 0 };
        if current && alive && send_fd(live.control, conn) {
            map.insert(key, live);
            sys::close(conn);
            return;
        }
        let _ = unsafe { libc::waitpid(live.pid, std::ptr::null_mut(), libc::WNOHANG) };
        end(live, Fate::Retire);
    }
    if let Some(live) = spawn_companion(COMPANION_HELPER, &lib_path, lib_id, conn) {
        map.insert(key, live);
    }
    sys::close(conn);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command};

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("akar_companion_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn module(data: &Path, id: &str, lib: &[u8]) -> PathBuf {
        let dir = data.join("modules").join(id);
        fs::create_dir_all(dir.join("zygisk")).unwrap();
        fs::write(dir.join("module.prop"), format!("id={id}\n")).unwrap();
        fs::write(dir.join("zygisk").join(COMPANION_ABI), lib).unwrap();
        dir
    }

    /// A stand-in companion: a sleeping child plus the far end of its control socket.
    fn fake(data: &Path, id: &str) -> (LiveCompanion, Child, RawFd) {
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let mut pair = [0; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, pair.as_mut_ptr()) }, 0);
        let lib = LibId::of(&lib_path(data, id)).unwrap();
        (LiveCompanion { pid: child.id() as libc::pid_t, control: pair[0], lib }, child, pair[1])
    }

    fn reads_eof(fd: RawFd) -> bool {
        let mut b = [0u8; 1];
        unsafe { libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, 1) == 0 }
    }

    #[test]
    fn fate_follows_the_module_and_its_library() {
        let data = tmp("fate");
        let dir = module(&data, "m", b"v1");
        let loaded = LibId::of(&lib_path(&data, "m")).unwrap();
        assert_eq!(fate(&data, "m", loaded), Fate::Keep);

        // Hot install: the old dir is renamed away and a new one takes its place.
        fs::rename(&dir, data.join("trash")).unwrap();
        module(&data, "m", b"v1");
        assert_eq!(fate(&data, "m", loaded), Fate::Retire);

        let now = LibId::of(&lib_path(&data, "m")).unwrap();
        fs::write(data.join("modules/m/disable"), b"").unwrap();
        assert_eq!(fate(&data, "m", now), Fate::Kill);
        fs::remove_file(data.join("modules/m/disable")).unwrap();
        fs::write(data.join("modules/m/remove"), b"").unwrap();
        assert_eq!(fate(&data, "m", now), Fate::Kill);
        fs::remove_file(data.join("modules/m/remove")).unwrap();
        fs::remove_file(lib_path(&data, "m")).unwrap();
        assert_eq!(fate(&data, "m", now), Fate::Kill);
        fs::remove_dir_all(data.join("modules/m")).unwrap();
        assert_eq!(fate(&data, "m", now), Fate::Kill);
        let _ = fs::remove_dir_all(&data);
    }

    #[test]
    fn reconcile_retires_replaced_and_kills_removed() {
        let data = tmp("reconcile");
        module(&data, "keep", b"k");
        module(&data, "hot", b"h1");
        module(&data, "gone", b"g");
        let mut map = HashMap::new();
        let (keep, mut keep_child, keep_peer) = fake(&data, "keep");
        let (hot, mut hot_child, hot_peer) = fake(&data, "hot");
        let (gone, mut gone_child, gone_peer) = fake(&data, "gone");
        map.insert("keep".to_string(), keep);
        map.insert("hot".to_string(), hot);
        map.insert("gone".to_string(), gone);

        fs::rename(data.join("modules/hot"), data.join("hot.old")).unwrap();
        module(&data, "hot", b"h2");
        fs::write(data.join("modules/gone/disable"), b"").unwrap();
        reconcile_in(&mut map, &data, true);

        assert_eq!(map.keys().collect::<Vec<_>>(), ["keep"]);
        assert!(reads_eof(hot_peer), "retired companion sees EOF on its control socket");
        assert!(hot_child.try_wait().unwrap().is_none(), "retired companion is left to finish");
        assert!(reads_eof(gone_peer));
        assert_eq!(gone_child.wait().unwrap().signal(), Some(libc::SIGKILL));

        reconcile_in(&mut map, &data, false);
        assert!(map.is_empty(), "Zygisk off ends every companion");
        assert!(reads_eof(keep_peer));
        assert_eq!(keep_child.wait().unwrap().signal(), Some(libc::SIGKILL));

        let _ = hot_child.kill();
        let _ = hot_child.wait();
        for fd in [keep_peer, hot_peer, gone_peer] {
            sys::close(fd);
        }
        let _ = fs::remove_dir_all(&data);
    }
}
