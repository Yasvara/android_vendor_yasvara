// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! `yasvara_rootd` — the ROM's root daemon.
//!
//! Started by init once boot is complete, it binds its own socket and sleeps in `epoll_wait`
//! until an app connects. The kernel tells it who is calling (SO_PEERCRED); the policy is a
//! file that system_server rewrites and that is re-read, lazily, only when its inode or
//! mtime changed. An unenrolled caller gets 8 bytes back and is dropped before a single
//! request byte is read. An enrolled one is run by this loop itself when its request is already
//! queued and its shell needs neither a relay nor an in-place domain switch (`live.rs`, shell
//! spawned by vfork); anything else gets a supervisor process (`session.rs`).
//!
//! Nothing here uses timers, alarms or polling: an idle daemon makes no syscalls. One inotify
//! watch on the data directory wakes it when grants.v1 is replaced, so `enrolled.set` (the
//! uids Zygote projects the client to) follows the policy.

mod bootguard;
mod compat_ns;
mod installer;
mod keywatch;
mod live;
mod mgmt;
mod modules;
mod mount;
mod resetprop;
mod sepolicy;
mod session;
mod spawn;
mod sys;
mod zygisk_companion;

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use yasvara_root_proto::grants::{Grants, Refusal, GF_ALLOW_GLOBAL_NS};
use yasvara_root_proto::{self as p, Frame, Reason, TIER_ROOT};

const DEFAULT_DATA_DIR: &str = "/data/misc/yasvara_root";
const MAX_SESSIONS_PER_UID: usize = 16;
const MAX_SESSIONS: usize = 64;
const RATE_PER_SEC: f64 = 20.0;
const EVENT_INTERVAL: Duration = Duration::from_secs(600);
const MAX_GRANTS_FILE: u64 = 1 << 20;

pub struct Config {
    pub data_dir: PathBuf,
    pub grants_path: PathBuf,
    pub events_path: PathBuf,
    /// uids Zygote projects the client into (see `grants::enrolled_set`).
    pub enrolled_path: PathBuf,
    /// `--socket PATH`: bind this socket. Without it, init's inherited socket if there is one
    /// (host tests), else `<data-dir>/run/ctl.sock`.
    pub socket_path: Option<PathBuf>,
    /// Skips every privileged step of the shell setup. Compiled in only for host tests.
    pub unprivileged_test: bool,
}

/// What a lookup of the policy file said about a caller.
enum Decision {
    Allow(session::GrantView),
    Deny(Reason),
}

struct Policy {
    path: PathBuf,
    sig: Option<(u64, i64, i64, u64)>,
    grants: Grants,
    boot_id: String,
    /// Bumped on every reload of the file, so callers can drop state tied to the old policy.
    generation: u64,
}

impl Policy {
    fn new(path: PathBuf) -> Policy {
        Policy { path, sig: None, grants: Grants::default(), boot_id: sys::boot_id(), generation: 0 }
    }

    /// One stat per request; the file is parsed only when it changed. A missing, oversized or
    /// unreadable file means no grants, so everyone is refused.
    fn refresh(&mut self) {
        let sig = std::fs::metadata(&self.path).ok().map(|m| (m.ino(), m.mtime(), m.mtime_nsec(), m.size()));
        if sig == self.sig {
            return;
        }
        self.sig = sig;
        self.generation += 1;
        self.grants = match sig {
            Some((_, _, _, size)) if size <= MAX_GRANTS_FILE => std::fs::read_to_string(&self.path)
                .map(|t| Grants::parse(&t))
                .unwrap_or_default(),
            _ => Grants::default(),
        };
    }

    /// Callers run [`Policy::refresh`] first (one stat per request).
    fn decide(&mut self, uid: u32) -> Decision {
        if self.grants.off {
            return Decision::Deny(Reason::Disabled);
        }
        // A root caller (a root shell running `su`) needs no grant.
        if uid == 0 {
            return Decision::Allow(session::GrantView {
                tier: TIER_ROOT,
                global_ns: true,
                flags: GF_ALLOW_GLOBAL_NS,
                packages: "root".to_string(),
            });
        }
        match self.grants.lookup(uid, sys::now_wall_ms(), &self.boot_id) {
            Err(Refusal::Off) => Decision::Deny(Reason::Disabled),
            Err(Refusal::NotEnrolled) => Decision::Deny(Reason::NotEnrolled),
            Err(Refusal::Frozen) => Decision::Deny(Reason::Frozen),
            Err(Refusal::Expired) => Decision::Deny(Reason::Expired),
            Ok(g) => {
                if g.flags & yasvara_root_proto::grants::GF_ALLOW_BEFORE_UNLOCK == 0 && !sys::user_unlocked(uid) {
                    return Decision::Deny(Reason::Locked);
                }
                Decision::Allow(session::GrantView {
                    tier: g.tier,
                    global_ns: g.global_ns,
                    flags: g.flags,
                    packages: g.packages.join(","),
                })
            }
        }
    }
}

/// A token bucket per uid: a flood from one app cannot starve the others.
struct RateLimit {
    buckets: HashMap<u32, (f64, Instant)>,
}

impl RateLimit {
    fn allow(&mut self, uid: u32) -> bool {
        let now = Instant::now();
        // A bucket idle for a second is full again, i.e. the same as no bucket: drop those once
        // the map grows, so a flood of distinct uids cannot make it grow without bound.
        if self.buckets.len() > 256 {
            self.buckets.retain(|_, b| now.duration_since(b.1) < Duration::from_secs(1));
        }
        let b = self.buckets.entry(uid).or_insert((RATE_PER_SEC, now));
        b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * RATE_PER_SEC).min(RATE_PER_SEC);
        b.1 = now;
        if b.0 >= 1.0 {
            b.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

fn usage() -> ! {
    eprintln!("yasvara_rootd [--version] [--socket PATH] [--data-dir DIR] [--stage keywatch|post-fs-data|services|boot-completed] [module|resetprop|bootguard|zygisk|unmount ...]");
    std::process::exit(2)
}

/// Dispatches multi-call applet names (`resetprop`, `ksud`, `akarctl`) or one-shot CLI /
/// init stage invocations before entering the long-lived daemon loop.
/// Returns `None` when invoked as the normal `yasvara_rootd` daemon.
fn try_dispatch_oneshot() -> Option<i32> {
    let raw_args: Vec<String> = std::env::args().collect();
    let argv0 = raw_args
        .first()
        .and_then(|s| std::path::Path::new(s).file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("yasvara_rootd");

    if argv0 == "resetprop" {
        return Some(resetprop::cli_main(&raw_args[1..]));
    }
    if argv0 == "magisk" {
        return Some(magisk_shim(&raw_args[1..]));
    }
    // Reached through a /data/adb shim (`ksud`, `akarctl`): a tool, never the daemon.
    let as_tool = matches!(argv0, "ksud" | "akarctl");

    let mut data_dir = PathBuf::from(DEFAULT_DATA_DIR);
    let mut meta_dir: Option<PathBuf> = None;
    #[cfg_attr(not(feature = "unprivileged-test"), allow(unused_mut))]
    let mut unpriv = false;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 1usize;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "--data-dir" if i + 1 < raw_args.len() => {
                data_dir = PathBuf::from(&raw_args[i + 1]);
                i += 2;
            }
            "--meta-dir" if i + 1 < raw_args.len() => {
                meta_dir = Some(PathBuf::from(&raw_args[i + 1]));
                i += 2;
            }
            #[cfg(feature = "unprivileged-test")]
            "--test-unprivileged" => {
                unpriv = true;
                i += 1;
            }
            _ => {
                rest.push(raw_args[i].clone());
                i += 1;
            }
        }
    }

    let Some(first) = rest.first().map(String::as_str) else {
        if as_tool {
            eprintln!("usage: {argv0} module|resetprop|bootguard|zygisk|unmount ...");
            return Some(2);
        }
        return None;
    };
    if as_tool && matches!(first, "-V" | "--version" | "-v" | "version") {
        println!("{}", if first == "-V" { compat_ns::AKAR_VER_CODE.to_string() } else { format!("{}:YASVARA-AKAR", p::VERSION_NAME) });
        return Some(0);
    }
    match first {
        "--stage" => {
            let stage = rest.get(1).map(String::as_str).unwrap_or("");
            let rc = match stage {
                "keywatch" => {
                    if keywatch::run_keywatch().is_ok() { 0 } else { 1 }
                }
                "post-fs-data" => {
                    if modules::stage_post_fs_data(&data_dir, meta_dir.as_deref(), unpriv).is_ok() { 0 } else { 1 }
                }
                "services" => {
                    modules::stage_services(&data_dir, unpriv);
                    0
                }
                "boot-completed" => {
                    modules::stage_boot_completed(&data_dir, meta_dir.as_deref(), unpriv);
                    0
                }
                _ => {
                    eprintln!("yasvara_rootd: unknown stage '{stage}'");
                    2
                }
            };
            Some(rc)
        }
        "module" => Some(modules::cli_module(&data_dir, &rest[1..], unpriv)),
        "resetprop" => Some(resetprop::cli_main(&rest[1..])),
        "bootguard" => {
            let sub = rest.get(1).map(String::as_str).unwrap_or("status");
            let bg = bootguard::BootguardPaths::resolve(&data_dir, meta_dir.as_deref());
            match sub {
                "status" => {
                    println!("{}", bootguard::read_status(&data_dir).to_json());
                    Some(0)
                }
                "clear" => Some(if bootguard::clear_safemode(&bg).is_ok() { 0 } else { 1 }),
                _ => Some(2),
            }
        }
        "zygisk" => {
            let sub = rest.get(1).map(String::as_str).unwrap_or("sync");
            match sub {
                "sync" => {
                    let safe = bootguard::read_status(&data_dir).safe_mode;
                    Some(if modules::publish_zygisk_set(&data_dir, safe).is_ok() { 0 } else { 1 })
                }
                "features" => {
                    let feats: Vec<String> = modules::active_managed_features(&data_dir).into_iter().collect();
                    println!("{}", feats.join(","));
                    Some(0)
                }
                _ => Some(2),
            }
        }
        "unmount" => {
            let sub = rest.get(1).map(String::as_str).unwrap_or("sync");
            match sub {
                "sync" => Some(if modules::publish_unmount_set(&data_dir).is_ok() { 0 } else { 1 }),
                _ => Some(2),
            }
        }
        _ if as_tool => {
            eprintln!("{argv0}: unknown command '{first}'");
            Some(2)
        }
        _ => None,
    }
}

/// The parts of Magisk's CLI modules call. There is no Magisk tmpfs, so `--path` fails.
fn magisk_shim(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("-v" | "--version") => {
            println!("28.1-akar:MAGISK:R");
            0
        }
        Some("-V") => {
            println!("28100");
            0
        }
        Some("resetprop") => resetprop::cli_main(&args[1..]),
        Some("--path") => 1,
        _ => {
            eprintln!("magisk: not available on Akar (use ksud / akarctl)");
            1
        }
    }
}

fn parse_config() -> Config {
    let mut cfg = Config {
        data_dir: PathBuf::from(DEFAULT_DATA_DIR),
        grants_path: PathBuf::new(),
        events_path: PathBuf::new(),
        enrolled_path: PathBuf::new(),
        socket_path: None,
        unprivileged_test: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" => {
                println!("{}:YASVARA-ROOTD", p::VERSION_NAME);
                std::process::exit(0)
            }
            "--socket" => cfg.socket_path = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--data-dir" => cfg.data_dir = PathBuf::from(args.next().unwrap_or_else(|| usage())),
            #[cfg(feature = "unprivileged-test")]
            "--test-unprivileged" => cfg.unprivileged_test = true,
            _ => usage(),
        }
    }
    cfg.grants_path = cfg.data_dir.join("grants.v1");
    cfg.events_path = cfg.data_dir.join("events.sock");
    cfg.enrolled_path = cfg.data_dir.join("enrolled.set");
    cfg
}

/// The listening socket: the one we bind ourselves at `--socket` or `<data-dir>/run/ctl.sock`
/// (outside /dev/socket, so apps cannot name it without the Zygote projection), or,
/// for host tests, one inherited from init (`ANDROID_SOCKET_yasvara_su`).
fn listener(cfg: &Config) -> io::Result<(RawFd, Option<PathBuf>)> {
    let default = cfg.data_dir.join("run").join("ctl.sock");
    let inherited = std::env::var("ANDROID_SOCKET_yasvara_su").ok().and_then(|v| v.parse::<RawFd>().ok());
    let bound = cfg.socket_path.as_ref().or(if inherited.is_none() { Some(&default) } else { None });
    if let Some(path) = bound {
        if let Some(dir) = path.parent() {
            // 0711: searchable by whoever SELinux lets in (apps via the Zygote bind, `shell`).
            let _ = std::fs::create_dir(dir);
            let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o711));
        }
        let _ = std::fs::remove_file(path);
        let fd = sys::cvt(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })?;
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as _;
        let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
        if bytes.len() >= addr.sun_path.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long"));
        }
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        sys::cvt(unsafe {
            libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_un>() as _)
        })?;
        sys::cvt(unsafe { libc::chmod(addr.sun_path.as_ptr(), 0o666) })?;
        sys::cvt(unsafe { libc::listen(fd, 8) })?;
        return Ok((fd, Some(path.clone())));
    }
    let fd = inherited.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no socket"))?;
    // init hands it over without close-on-exec; every shell would inherit it.
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    // init binds the socket but, for SOCK_STREAM, leaves listen() to the daemon. Without it
    // clients get ECONNREFUSED and epoll reports EPOLLHUP forever (a busy loop).
    sys::cvt(unsafe { libc::listen(fd, 8) })?;
    Ok((fd, None))
}

/// Best-effort datagram to system_server: "this uid was refused". It rate-limits further
/// and decides whether to bother the owner; nobody listening is fine.
fn send_denied_event(cfg: &Config, uid: u32, reason: Reason) {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return;
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(cfg.events_path.as_os_str());
    if bytes.len() < addr.sun_path.len() {
        for (i, b) in bytes.iter().enumerate() {
            addr.sun_path[i] = *b as libc::c_char;
        }
        let msg = format!("D|{uid}|{}|{}", sys::now_wall_ms(), reason.as_str());
        unsafe {
            libc::sendto(
                fd,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                libc::MSG_NOSIGNAL,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as _,
            );
        }
    }
    sys::close(fd);
}

fn main() {
    if let Some(code) = try_dispatch_oneshot() {
        std::process::exit(code);
    }
    let cfg = parse_config();
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::umask(0o077);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let (lfd, bound) = match listener(&cfg) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("yasvara_rootd: no listening socket: {e}");
            std::process::exit(1);
        }
    };
    unsafe {
        let fl = libc::fcntl(lfd, libc::F_GETFL);
        libc::fcntl(lfd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }

    // SIGCHLD and init's SIGTERM (`gentle_kill`) are consumed through a signalfd so the whole
    // daemon is one epoll loop.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
        libc::sigaddset(&mut mask, libc::SIGTERM);
        libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
    }
    let sfd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC) };
    let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if sfd < 0 || ep < 0 {
        eprintln!("yasvara_rootd: epoll/signalfd: {}", io::Error::last_os_error());
        std::process::exit(1);
    }
    let wfd = sys::watch_dir(&cfg.data_dir).unwrap_or_else(|e| {
        eprintln!("yasvara_rootd: watch {}: {e}", cfg.data_dir.display());
        -1
    });
    // Optional lazy Zygisk companion socket (only bound when Native Zygisk is actually ON)
    // and system_server mgmt socket on the same epoll loop.
    let (mut zfd, mut zpath): (RawFd, Option<PathBuf>) = if modules::is_zygisk_enabled(&cfg.data_dir) {
        match zygisk_companion::bind_companion_socket(&cfg.data_dir) {
            Ok((fd, p)) => (fd, Some(p)),
            Err(_) => (-1, None),
        }
    } else {
        let _ = std::fs::remove_file(cfg.data_dir.join("run/zygisk.sock"));
        (-1, None)
    };
    let (mfd, mpath) = match mgmt::bind_mgmt_socket(&cfg.data_dir) {
        Ok((fd, p)) => (fd, Some(p)),
        Err(_) => (-1, None),
    };
    let mut sources = vec![(lfd, 0u64), (sfd, 1u64)];
    if wfd >= 0 {
        sources.push((wfd, 2u64));
    }
    if zfd >= 0 {
        sources.push((zfd, 3u64));
    }
    if mfd >= 0 {
        sources.push((mfd, 4u64));
    }
    for (fd, token) in sources {
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: token };
        if unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) } < 0 {
            eprintln!("yasvara_rootd: epoll_ctl: {}", io::Error::last_os_error());
            std::process::exit(1);
        }
    }

    let mut policy = Policy::new(cfg.grants_path.clone());
    let mut enrolled_generation = u64::MAX;
    // Publish the set before the first request: an enrolled app is projected from its next start.
    sync_enrolled(&cfg, &mut policy, &mut enrolled_generation);
    if modules::is_module_engine_enabled(&cfg.data_dir) {
        let _ = modules::publish_unmount_set(&cfg.data_dir);
        let _ = modules::publish_zygisk_set(&cfg.data_dir, bootguard::read_status(&cfg.data_dir).safe_mode);
        mgmt::sync_managed_features_file(&cfg.data_dir);
    } else {
        modules::clear_runtime_sets(&cfg.data_dir);
    }
    let mut limit = RateLimit { buckets: HashMap::new() };
    let mut last_event: HashMap<u32, Instant> = HashMap::new();
    let mut event_generation = 0u64;
    let mut sessions: Vec<(libc::pid_t, u32)> = Vec::new();
    sys::audit(&cfg.data_dir, &format!("{}|START|0|{}|-|-|{}", sys::now_wall_ms(), unsafe { libc::getpid() }, p::VERSION_NAME));

    let mut lives = live::Lives::default();
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
    loop {
        // Blocks without a timeout unless a hung-up session's SIGKILL is due.
        let n = unsafe { libc::epoll_wait(ep, events.as_mut_ptr(), events.len() as i32, lives.timeout()) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            std::process::exit(1);
        }
        lives.on_timer();
        for ev in &events[..n as usize] {
            if ev.u64 & live::TOKEN_TAG != 0 {
                lives.on_conn(ep, (ev.u64 & 0xffff_ffff) as RawFd);
                continue;
            }
            if ev.u64 == 2 {
                // grants.v1 / modules.conf / zygisk.conf / unmount.conf replaced atomically.
                let changed = sys::drain_watch_any(wfd);
                if changed.iter().any(|n| n == "grants.v1") {
                    sync_enrolled(&cfg, &mut policy, &mut enrolled_generation);
                }
                if changed.iter().any(|n| n == "modules.conf" || n == "zygisk.conf" || n == "unmount.conf") {
                    if modules::is_module_engine_enabled(&cfg.data_dir) {
                        let _ = modules::publish_unmount_set(&cfg.data_dir);
                        let _ = modules::publish_zygisk_set(
                            &cfg.data_dir,
                            bootguard::read_status(&cfg.data_dir).safe_mode,
                        );
                    } else {
                        modules::clear_runtime_sets(&cfg.data_dir);
                    }
                    let want_zsock = modules::is_zygisk_enabled(&cfg.data_dir);
                    if want_zsock && zfd < 0 {
                        if let Ok((fd, p)) = zygisk_companion::bind_companion_socket(&cfg.data_dir) {
                            let mut zev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: 3 };
                            if unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut zev) } == 0 {
                                zfd = fd;
                                zpath = Some(p);
                            } else {
                                sys::close(fd);
                            }
                        }
                    } else if !want_zsock && zfd >= 0 {
                        unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, zfd, std::ptr::null_mut()) };
                        sys::close(zfd);
                        zfd = -1;
                        if let Some(p) = zpath.take() {
                            let _ = std::fs::remove_file(p);
                        }
                    }
                }
                continue;
            }
            if ev.u64 == 3 {
                loop {
                    let c = unsafe { libc::accept4(zfd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
                    if c < 0 {
                        break;
                    }
                    zygisk_companion::handle_connection(c, &cfg.data_dir, cfg.unprivileged_test);
                }
                continue;
            }
            if ev.u64 == 4 {
                loop {
                    let c = unsafe { libc::accept4(mfd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
                    if c < 0 {
                        break;
                    }
                    mgmt::handle_connection(c, &cfg.data_dir, cfg.unprivileged_test);
                }
                continue;
            }
            if ev.u64 == 1 {
                let mut si: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
                let n = unsafe { libc::read(sfd, &mut si as *mut _ as *mut libc::c_void, std::mem::size_of_val(&si)) };
                if n > 0 && si.ssi_signo == libc::SIGTERM as u32 {
                    // Stopped: a set left behind would keep projecting a client with no daemon
                    // behind it, and a socket file would read as running.
                    let _ = sys::publish_set(&cfg.enrolled_path, None);
                    if let Some(p) = &bound {
                        let _ = std::fs::remove_file(p);
                    }
                    if let Some(zp) = &zpath {
                        let _ = std::fs::remove_file(zp);
                    }
                    if let Some(mp) = &mpath {
                        let _ = std::fs::remove_file(mp);
                    }
                    std::process::exit(0);
                }
                // Reap whoever exited; the supervisor already told its client.
                loop {
                    let mut status = 0;
                    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                    if pid <= 0 {
                        break;
                    }
                    sessions.retain(|&(p, _)| p != pid);
                    lives.on_exit(ep, pid, status, &cfg);
                }
                continue;
            }
            // Drain the backlog: the listener is non-blocking.
            loop {
                let conn = unsafe { libc::accept4(lfd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
                if conn < 0 {
                    match io::Error::last_os_error().raw_os_error() {
                        Some(libc::EAGAIN) => break,
                        Some(libc::EINTR) | Some(libc::ECONNABORTED) | Some(libc::EPROTO) => continue,
                        // Out of fds or memory: the listener stays readable, so back off instead of
                        // spinning; the next epoll round retries.
                        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM) => {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            break;
                        }
                        // Anything else is permanent (EINVAL on a socket that is not listening…):
                        // exit and let init restart us rather than burn CPU.
                        _ => {
                            eprintln!("yasvara_rootd: accept: {}", io::Error::last_os_error());
                            std::process::exit(1);
                        }
                    }
                }
                let daemon_fds: Vec<RawFd> = [lfd, ep, sfd, wfd].into_iter().chain(lives.conns()).collect();
                handle(conn, &cfg, &mut policy, &mut limit, &mut last_event, &mut event_generation, &mut sessions, &mut lives, ep, &daemon_fds);
            }
        }
    }
}

/// Rewrites `enrolled.set` when the policy changed since the last write (zygote reads it).
fn sync_enrolled(cfg: &Config, policy: &mut Policy, written: &mut u64) {
    policy.refresh();
    if policy.generation == *written {
        return;
    }
    match sys::publish_set(&cfg.enrolled_path, Some(&yasvara_root_proto::grants::enrolled_set(&policy.grants))) {
        Ok(()) => *written = policy.generation,
        Err(e) => eprintln!("yasvara_rootd: {}: {e}", cfg.enrolled_path.display()),
    }
}

fn handle(
    conn: RawFd,
    cfg: &Config,
    policy: &mut Policy,
    limit: &mut RateLimit,
    last_event: &mut HashMap<u32, Instant>,
    event_generation: &mut u64,
    sessions: &mut Vec<(libc::pid_t, u32)>,
    lives: &mut live::Lives,
    ep: RawFd,
    daemon_fds: &[RawFd],
) {
    let cred = match sys::peer_cred(conn) {
        Ok(c) => c,
        Err(_) => return sys::close(conn),
    };
    let deny = |reason: Reason| {
        // 16 bytes and done: nothing from the caller has been read.
        let _ = sys::send_all(conn, &Frame::verdict(false, reason, 0, 0).encode());
        sys::close(conn);
    };
    // A policy change (enrolled, revoked, frozen…) makes the next refusal news again: the
    // per-uid limit on events to the owner only suppresses repeats under the same policy.
    policy.refresh();
    if policy.generation != *event_generation {
        *event_generation = policy.generation;
        last_event.clear();
    }
    // The token bucket guards the audit log and the owner's notifications against a flood of
    // refusals. An enrolled caller is bounded by the session caps instead: `su` in a loop is
    // legitimate (builds, scripts) and the app pays for its own spawns.
    let grant = match policy.decide(cred.uid) {
        Decision::Deny(reason) => {
            if !limit.allow(cred.uid) {
                return deny(Reason::Busy);
            }
            deny(reason);
            sys::audit(&cfg.data_dir, &format!("{}|DENY|{}|{}|-|-|{}", sys::now_wall_ms(), cred.uid, cred.pid, reason.as_str()));
            let due = last_event.get(&cred.uid).map(|t| t.elapsed() >= EVENT_INTERVAL).unwrap_or(true);
            if due && reason != Reason::Busy {
                last_event.insert(cred.uid, Instant::now());
                send_denied_event(cfg, cred.uid, reason);
            }
            return;
        }
        Decision::Allow(g) => g,
    };
    if sessions.len() >= MAX_SESSIONS || sessions.iter().filter(|s| s.1 == cred.uid).count() >= MAX_SESSIONS_PER_UID {
        return deny(Reason::Busy);
    }
    // Verdict first, before anything is read.
    if sys::send_frame_nowait(conn, &session::verdict_frame(&grant).encode()).is_err() {
        return sys::close(conn);
    }
    let caller = session::Caller { pid: cred.pid, uid: cred.uid };
    // The request is normally queued already (the client does not wait for the verdict).
    let admitted = match session::take_queued(conn) {
        None => None,
        Some(Err(_)) => return sys::close(conn),
        Some(Ok((req, fds))) => match req.ok_or(Reason::BadRequest).and_then(|r| session::admit(r, &fds, &grant)) {
            Err(reason) => {
                let _ = session::refuse(conn, reason, &fds);
                return sys::close(conn);
            }
            Ok(adm) if session::inline(&adm, cfg) => {
                if let Some(pid) = lives.start(ep, conn, caller, &grant, adm, fds, cfg) {
                    sessions.push((pid, cred.uid));
                }
                return;
            }
            Ok(adm) => Some((adm, fds)),
        },
    };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // The client has its verdict and is about to send a request: answer that with an Ack.
        let _ = sys::send_frame_nowait(conn, &Frame::ack(false, Reason::Internal, 0, false).encode());
        if let Some((_, fds)) = admitted {
            fds.iter().for_each(|&f| sys::close(f));
        }
        return sys::close(conn);
    }
    if pid == 0 {
        match admitted {
            Some((adm, fds)) => session::run_admitted(conn, caller, grant, adm, fds, cfg, daemon_fds),
            None => session::run(conn, caller, grant, cfg, daemon_fds),
        }
    }
    if let Some((_, fds)) = admitted {
        fds.iter().for_each(|&f| sys::close(f));
    }
    sessions.push((pid, cred.uid));
    sys::close(conn);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_map_is_bounded() {
        let mut r = RateLimit { buckets: HashMap::new() };
        let old = Instant::now() - Duration::from_secs(5);
        for uid in 10000..10400u32 {
            r.buckets.insert(uid, (RATE_PER_SEC, old));
        }
        assert!(r.allow(10500));
        assert!(r.buckets.len() <= 2, "stale full buckets are dropped, got {}", r.buckets.len());
    }

    #[test]
    fn rate_limit_is_per_uid_and_refills() {
        let mut r = RateLimit { buckets: HashMap::new() };
        let granted = (0..100).filter(|_| r.allow(10001)).count();
        assert!((20..=22).contains(&granted), "burst is the bucket size, got {granted}");
        assert!(r.allow(10002), "another uid is unaffected");
    }

    #[test]
    fn missing_policy_denies_everyone_but_root() {
        let mut pol = Policy::new(PathBuf::from("/nonexistent/grants.v1"));
        assert!(matches!(pol.decide(10195), Decision::Deny(Reason::NotEnrolled)));
        assert!(matches!(pol.decide(0), Decision::Allow(_)));
    }

    #[test]
    fn policy_reloads_when_the_file_changes() {
        let dir = std::env::temp_dir().join(format!("yrd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("grants.v1");
        std::fs::write(&f, "# yasvara-root grants v1 frozen=0 version=1\n10195 shell req 0 0 - s p\n").unwrap();
        let mut pol = Policy::new(f.clone());
        pol.refresh();
        let g1 = pol.generation;
        assert!(matches!(pol.decide(10195), Decision::Allow(g) if g.tier == p::TIER_SHELL));
        pol.refresh();
        assert_eq!(pol.generation, g1, "an unchanged file is not reloaded");
        // Atomic replace, as system_server does: new inode, revocation visible at once.
        let tmp = dir.join("grants.v1.new");
        std::fs::write(&tmp, "# yasvara-root grants v1 frozen=0 version=2\n").unwrap();
        std::fs::rename(&tmp, &f).unwrap();
        pol.refresh();
        assert!(pol.generation > g1, "a replaced file bumps the generation");
        assert!(matches!(pol.decide(10195), Decision::Deny(Reason::NotEnrolled)));
        std::fs::write(&f, "# yasvara-root grants v1 frozen=1 version=3\n10195 root req 0 0 - s p\n").unwrap();
        pol.refresh();
        assert!(matches!(pol.decide(10195), Decision::Deny(Reason::Frozen)));
        std::fs::remove_dir_all(&dir).ok();
    }
}
