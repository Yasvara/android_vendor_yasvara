// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `yasvara_rootd` — the ROM's root daemon (SPEC-0006).
//!
//! Started by init once boot is complete, it binds its own socket and sleeps in `epoll_wait`
//! until an app connects. The kernel tells it who is calling (SO_PEERCRED); the policy is a
//! file that system_server rewrites and that is re-read, lazily, only when its inode or
//! mtime changed. An unenrolled caller gets 8 bytes back and is dropped before a single
//! request byte is read. An enrolled one gets a supervisor process (see `session.rs`).
//!
//! Nothing here uses timers, alarms or polling: an idle daemon makes no syscalls. One inotify
//! watch on the data directory wakes it when grants.v1 is replaced, so `enrolled.set` (the
//! uids Zygote projects the client to, SPEC-0007) follows the policy.

mod session;
mod sys;

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
    /// SPEC-0007: uids Zygote projects the client into (see `grants::enrolled_set`).
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
    eprintln!("yasvara_rootd [--version] [--socket PATH] [--data-dir DIR]");
    std::process::exit(2)
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
/// (SPEC-0007: outside /dev/socket, so apps cannot name it without the Zygote projection), or,
/// for host tests, one inherited from init (`ANDROID_SOCKET_yasvara_su`).
fn listener(cfg: &Config) -> io::Result<RawFd> {
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
        return Ok(fd);
    }
    let fd = inherited.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no socket"))?;
    // init binds the socket but, for SOCK_STREAM, leaves listen() to the daemon. Without it
    // clients get ECONNREFUSED and epoll reports EPOLLHUP forever (a busy loop).
    sys::cvt(unsafe { libc::listen(fd, 8) })?;
    Ok(fd)
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
    let cfg = parse_config();
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::umask(0o077);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let lfd = match listener(&cfg) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("yasvara_rootd: no listening socket: {e}");
            std::process::exit(1);
        }
    };
    unsafe {
        let fl = libc::fcntl(lfd, libc::F_GETFL);
        libc::fcntl(lfd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }

    // SIGCHLD is consumed through a signalfd so the whole daemon is one epoll loop.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
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
    let mut sources = vec![(lfd, 0u64), (sfd, 1u64)];
    if wfd >= 0 {
        sources.push((wfd, 2u64));
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
    let mut limit = RateLimit { buckets: HashMap::new() };
    let mut last_event: HashMap<u32, Instant> = HashMap::new();
    let mut event_generation = 0u64;
    let mut sessions: Vec<(libc::pid_t, u32)> = Vec::new();
    sys::audit(&cfg.data_dir, &format!("{}|START|0|{}|-|-|{}", sys::now_wall_ms(), unsafe { libc::getpid() }, p::VERSION_NAME));

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
    loop {
        let n = unsafe { libc::epoll_wait(ep, events.as_mut_ptr(), events.len() as i32, -1) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            std::process::exit(1);
        }
        for ev in &events[..n as usize] {
            if ev.u64 == 2 {
                // grants.v1 was replaced (system_server writes it atomically): without this an
                // app enrolled just now would never be projected, hence never reach the daemon.
                if sys::drain_watch(wfd, "grants.v1") {
                    sync_enrolled(&cfg, &mut policy, &mut enrolled_generation);
                }
                continue;
            }
            if ev.u64 == 1 {
                let mut buf = [0u8; 128];
                unsafe { libc::read(sfd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                // Reap whoever exited; the supervisor already told its client.
                loop {
                    let mut status = 0;
                    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                    if pid <= 0 {
                        break;
                    }
                    sessions.retain(|&(p, _)| p != pid);
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
                handle(conn, &cfg, &mut policy, &mut limit, &mut last_event, &mut event_generation, &mut sessions, &[lfd, ep, sfd, wfd]);
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
    match sys::replace_file(&cfg.enrolled_path, &yasvara_root_proto::grants::enrolled_set(&policy.grants)) {
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
    // Verdict first, then fork: the client reads it and prepares its request while the session
    // process starts (one fork off the critical path).
    if sys::send_frame_nowait(conn, &session::verdict_frame(&grant).encode()).is_err() {
        return sys::close(conn);
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // The client has its verdict and is about to send a request: answer that with an Ack.
        let _ = sys::send_frame_nowait(conn, &Frame::ack(false, Reason::Internal, 0, false).encode());
        return sys::close(conn);
    }
    if pid == 0 {
        session::run(conn, session::Caller { pid: cred.pid, uid: cred.uid }, grant, cfg, daemon_fds);
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
