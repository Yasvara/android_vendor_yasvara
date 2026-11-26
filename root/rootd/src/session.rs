// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! One enrolled connection. A request that is already queued (the normal case) is run by the main
//! loop itself (`live.rs`) unless it needs a relay or a shell that is not an exec type; everything
//! else gets a supervisor process that reads the request, starts the shell, relays its exit
//! status and hangs the shell up when the caller goes away. Exec-typed shells are spawned by
//! vfork (`spawn.rs`) on either path; any other shell is forked and switches domain in place.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use yasvara_root_proto::grants::{GF_ALLOW_GLOBAL_NS, GF_LOG_FULL};
use yasvara_root_proto::{
    self as p, Frame, Reason, Request, RF_HAS_CMD, RF_HAS_MNTNS_FD, RF_HAS_SHELL, RF_HAS_STDIO_FDS, RF_HAS_USER,
    RF_INTERACTIVE, RF_LOGIN, RF_MOUNT_MASTER, RF_PRESERVE_ENV, TIER_ROOT, TIER_SHELL, UID_SHELL,
};

use crate::spawn;
use crate::sys;
use crate::Config;

pub const MAX_FDS: usize = 4;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Reading a request that is already queued never waits; this only bounds a misbehaving peer.
const QUEUED_READ: Duration = Duration::from_millis(100);
pub const HUP_GRACE: Duration = Duration::from_secs(3);
const DEFAULT_SHELL: &str = "/system/bin/sh";
const SHELL_HOME: &str = "/data/local/tmp";
const DEFAULT_PATH: &str = "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:\
    /system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin";

// adbd's supplementary groups for the shell user (packages/modules/adb/daemon/main.cpp):
// AID_ADB, LOG, INPUT, INET, NET_BT, NET_BT_ADMIN, SDCARD_R, SDCARD_RW, NET_BW_STATS,
// READPROC, UHID, EXT_DATA_RW, EXT_OBB_RW, READTRACEFS.
const SHELL_GROUPS: [libc::gid_t; 14] = [1011, 1007, 1004, 3003, 3002, 3001, 1028, 1015, 3006, 3009, 3011, 1078, 1079, 3012];

pub struct Caller {
    pub pid: i32,
    pub uid: u32,
}

/// The slice of a grant a session needs, copied before the fork.
pub struct GrantView {
    pub tier: u8,
    pub global_ns: bool,
    pub flags: u32,
    pub packages: String,
}

/// Entry point of the forked supervisor. Never returns.
pub fn run(conn: RawFd, caller: Caller, grant: GrantView, cfg: &Config, parent_fds: &[RawFd]) -> ! {
    parent_fds.iter().for_each(|&f| sys::close(f));
    let code = match serve(conn, &caller, &grant, cfg) {
        Ok(()) => 0,
        Err(_) => 1,
    };
    unsafe { libc::_exit(code) }
}

pub fn refuse(conn: RawFd, reason: Reason, fds: &[RawFd]) -> io::Result<()> {
    fds.iter().for_each(|&f| sys::close(f));
    sys::send_all(conn, &Frame::ack(false, reason, 0, false).encode())
}

/// The first frame of an allowed connection, sent by the daemon's main loop before it forks the
/// session. The client reads it after queueing its request.
pub fn verdict_frame(grant: &GrantView) -> Frame {
    let wants_ns = if grant.global_ns { 0 } else { p::VF_WANTS_MNTNS };
    Frame::verdict(true, Reason::None, grant.tier, grant.flags | wants_ns)
}

fn serve(conn: RawFd, caller: &Caller, grant: &GrantView, cfg: &Config) -> io::Result<()> {
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    if !sys::wait_readable(conn, deadline)? {
        return Err(io::ErrorKind::TimedOut.into());
    }
    let (req, fds) = read_request(conn, deadline)?;
    match req.ok_or(Reason::BadRequest).and_then(|r| admit(r, &fds, grant)) {
        Ok(adm) => serve_admitted(conn, caller, grant, cfg, adm, &fds),
        Err(reason) => refuse(conn, reason, &fds),
    }
}

/// Entry point of a supervisor forked for a request the main loop already read and admitted.
pub fn run_admitted(
    conn: RawFd,
    caller: Caller,
    grant: GrantView,
    adm: Admitted,
    fds: Vec<RawFd>,
    cfg: &Config,
    parent_fds: &[RawFd],
) -> ! {
    parent_fds.iter().for_each(|&f| sys::close(f));
    let code = match serve_admitted(conn, &caller, &grant, cfg, adm, &fds) {
        Ok(()) => 0,
        Err(_) => 1,
    };
    unsafe { libc::_exit(code) }
}

/// The request and the descriptors that came with it; `None` for one that does not parse
/// (the descriptors still need closing). Header first: the fds travel with its first bytes.
pub fn read_request(conn: RawFd, deadline: Instant) -> io::Result<(Option<Request>, Vec<RawFd>)> {
    let mut hdr = [0u8; p::REQUEST_HEADER_LEN];
    let (n, fds) = sys::recv_with_fds(conn, &mut hdr, MAX_FDS)?;
    if n == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if n < hdr.len() {
        if let Err(e) = sys::read_exact_by(conn, &mut hdr[n..], deadline) {
            fds.iter().for_each(|&f| sys::close(f));
            return Err(e);
        }
    }
    let req = p::parse_header(&hdr).ok().and_then(|(mut req, lens)| {
        let mut body = vec![0u8; lens.total()];
        sys::read_exact_by(conn, &mut body, deadline).ok()?;
        p::parse_body(&mut req, &lens, &body).ok()?;
        Some(req)
    });
    Ok((req, fds))
}

/// The whole request if it is already queued, which is the normal case: the client sends it
/// right after connecting. `None` when it is not all there yet; nothing was consumed then.
pub fn take_queued(conn: RawFd) -> Option<io::Result<(Option<Request>, Vec<RawFd>)>> {
    let mut hdr = [0u8; p::REQUEST_HEADER_LEN];
    let n = unsafe { libc::recv(conn, hdr.as_mut_ptr() as *mut libc::c_void, hdr.len(), libc::MSG_PEEK | libc::MSG_DONTWAIT) };
    if n < hdr.len() as isize {
        return None;
    }
    let need = hdr.len() + p::parse_header(&hdr).map(|(_, lens)| lens.total()).unwrap_or(0);
    let mut queued: libc::c_int = 0;
    if unsafe { libc::ioctl(conn, libc::FIONREAD as _, &mut queued) } < 0 || (queued as usize) < need {
        return None;
    }
    Some(read_request(conn, Instant::now() + QUEUED_READ))
}

/// A request that passed every check against the grant.
pub struct Admitted {
    pub req: Request,
    pub tier: u8,
    pub target_uid: u32,
    /// Stay in the daemon's (global) mount namespace instead of joining the caller's.
    pub global: bool,
    pub mntns: Option<RawFd>,
    pub stdio: Option<[RawFd; 3]>,
}

pub fn admit(req: Request, fds: &[RawFd], grant: &GrantView) -> Result<Admitted, Reason> {
    // Which fds came, in a fixed order: [mount namespace] [stdin stdout stderr].
    let want = req.has(RF_HAS_MNTNS_FD) as usize + if req.has(RF_HAS_STDIO_FDS) { 3 } else { 0 };
    if fds.len() != want || (req.has(RF_INTERACTIVE) && req.has(RF_HAS_STDIO_FDS)) {
        return Err(Reason::BadRequest);
    }
    let mut it = fds.iter().copied();
    let mntns = req.has(RF_HAS_MNTNS_FD).then(|| it.next().unwrap());
    let stdio: Option<[RawFd; 3]> = req.has(RF_HAS_STDIO_FDS).then(|| [it.next().unwrap(), it.next().unwrap(), it.next().unwrap()]);
    if stdio.is_some_and(|s| s.iter().any(|&fd| !stdio_fd_ok(fd))) {
        return Err(Reason::BadRequest);
    }

    // What the caller may have.
    let tier = if req.tier == p::TIER_DEFAULT { grant.tier } else { req.tier };
    if tier > grant.tier {
        return Err(Reason::Tier);
    }
    let target_uid = if tier == TIER_SHELL {
        if req.has(RF_HAS_USER) && req.target_uid != UID_SHELL {
            return Err(Reason::Tier);
        }
        UID_SHELL
    } else if req.has(RF_HAS_USER) {
        req.target_uid
    } else {
        0
    };
    // Android hides other apps' data from an app's own mount namespace, so a root shell that
    // joined it could not see /data/data: the default is the global namespace (as with Magisk).
    // A grant can confine the app to its own view instead; `-M` then needs GF_ALLOW_GLOBAL_NS.
    let may_go_global = grant.global_ns || grant.flags & GF_ALLOW_GLOBAL_NS != 0;
    if req.has(RF_MOUNT_MASTER) && !may_go_global {
        return Err(Reason::Tier);
    }
    // `su -t PID`: join that namespace instead. Root tier only, and only for a grant that
    // may leave its own view anyway.
    let target_ns = req.has(p::RF_TARGET_NS);
    if target_ns && (mntns.is_none() || tier != TIER_ROOT || !may_go_global) {
        return Err(if mntns.is_none() { Reason::BadRequest } else { Reason::Tier });
    }
    let global = !target_ns && (grant.global_ns || req.has(RF_MOUNT_MASTER));
    // A confined grant must not be escapable by leaving the descriptor out.
    if !global && mntns.is_none() {
        return Err(Reason::BadRequest);
    }
    Ok(Admitted { req, tier, target_uid, global, mntns, stdio })
}

/// Whether the shell can be spawned by vfork. Its domain is then set for exec, which needs the
/// binary to be an entrypoint of `su`/`shell`, and only exec types can be (custom shells, say
/// Termux's bash, are app data files and keep the fork + setcon path).
pub fn exec_typed(req: &Request, cfg: &Config) -> bool {
    let sh = req.shell.as_slice();
    // Host tests stand /bin/sh in for it, so any other shell takes the fallback there too.
    !req.has(RF_HAS_SHELL) || sh.is_empty() || sh == DEFAULT_SHELL.as_bytes() || (cfg.unprivileged_test && sh == b"/bin/sh")
}

/// Whether the main loop may start this one itself (no supervisor process): an exec-typed shell
/// that needs no relay, i.e. the ROOT tier, or the SHELL tier on a pty.
pub fn inline(adm: &Admitted, cfg: &Config) -> bool {
    exec_typed(&adm.req, cfg) && (adm.tier == TIER_ROOT || adm.stdio.is_none())
}

pub fn audit_exec(cfg: &Config, caller: &Caller, grant: &GrantView, tier: u8, req: &Request) {
    sys::audit(
        &cfg.data_dir,
        &format!(
            "{}|EXEC|{}|{}|{}|{}|{}",
            sys::now_wall_ms(),
            caller.uid,
            caller.pid,
            if tier == TIER_ROOT { "root" } else { "shell" },
            sys::clean(grant.packages.as_bytes(), 60),
            summary(req, grant.flags & GF_LOG_FULL != 0)
        ),
    );
}

pub fn audit_exit(cfg: &Config, caller: &Caller, code: i32, pid: libc::pid_t, started: Instant) {
    sys::audit(
        &cfg.data_dir,
        &format!(
            "{}|EXIT|{}|{}|{}|{}|{}ms",
            sys::now_wall_ms(),
            caller.uid,
            caller.pid,
            code,
            pid,
            started.elapsed().as_millis()
        ),
    );
}

fn serve_admitted(conn: RawFd, caller: &Caller, grant: &GrantView, cfg: &Config, adm: Admitted, fds: &[RawFd]) -> io::Result<()> {
    let pty = if adm.req.has(RF_INTERACTIVE) {
        match sys::open_pty() {
            Ok(pair) => Some(pair),
            Err(_) => return refuse(conn, Reason::Spawn, fds),
        }
    } else {
        None
    };
    if let Some((m, _)) = pty {
        sys::set_winsize(m, adm.req.rows, adm.req.cols);
    }

    // SHELL tier, plain stdio: relay through daemon-owned pipes (see Relay).
    let (child_stdio, relay) = match (adm.tier == TIER_SHELL, adm.stdio) {
        (true, Some(app)) => match make_relay(app) {
            Ok((child, relay)) => (Some(child), Some(relay)),
            Err(_) => return refuse(conn, Reason::Spawn, fds),
        },
        _ => (adm.stdio, None),
    };

    let started = Instant::now();
    let slave = pty.map(|p| p.1);
    // Ok(pid), or the exit status of a shell that never got to exec.
    let spawned: Result<libc::pid_t, i32> = if exec_typed(&adm.req, cfg) {
        let plan = plan(&adm, slave, child_stdio, cfg);
        spawn::spawn(&plan).map_err(|f| {
            report(&f, &plan, slave.or(adm.stdio.map(|s| s[2])));
            f.code()
        })
    } else {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            if let Some((m, s)) = pty {
                sys::close(m);
                sys::close(s);
            }
            return refuse(conn, Reason::Spawn, fds);
        }
        if pid == 0 {
            // The shell never touches the connection or the pty master.
            sys::close(conn);
            if let Some((m, _)) = pty {
                sys::close(m);
            }
            if let Some(r) = &relay {
                // The shell's side only: the supervisor's ends and the caller's descriptors stay out.
                sys::close(r.in_w);
                sys::close(r.out_r);
                sys::close(r.err_r);
                r.app.iter().for_each(|&f| sys::close(f));
            }
            let Admitted { req, tier, target_uid, global, mntns, .. } = &adm;
            exec_shell(&Spec { req, tier: *tier, target_uid: *target_uid, global: *global, slave, stdio: child_stdio, mntns: *mntns, cfg });
        }
        Ok(pid)
    };

    // Supervisor from here on: the shell owns its copies of these. With a relay the caller's
    // stdio stays open here, and the shell's pipe ends are closed so EOF can reach us.
    if let (Some(_), Some(c)) = (&relay, child_stdio) {
        c.iter().for_each(|&f| sys::close(f));
    }
    fds.iter().filter(|f| relay.as_ref().map_or(true, |r| !r.app.contains(f))).for_each(|&f| sys::close(f));
    let ack = Frame::ack(true, Reason::None, spawned.unwrap_or(0) as u32, pty.is_some()).encode();
    let sent = match pty {
        Some((m, s)) => {
            sys::close(s);
            let r = sys::send_with_fds(conn, &ack, &[m]).map(|_| ());
            sys::close(m);
            r
        }
        None => sys::send_all(conn, &ack),
    };
    audit_exec(cfg, caller, grant, adm.tier, &adm.req);
    let pid = match spawned {
        Ok(pid) => pid,
        Err(code) => {
            let _ = sys::send_all(conn, &Frame::exit(code, false).encode());
            audit_exit(cfg, caller, code, 0, started);
            return Ok(());
        }
    };
    if let Err(e) = sent {
        // The caller is already gone: the shell must not outlive it as an orphan.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
        return Err(e);
    }

    let (code, signalled) = supervise(conn, pid, relay);
    let _ = sys::send_all(conn, &Frame::exit(code, signalled).encode());
    audit_exit(cfg, caller, code, pid, started);
    Ok(())
}

/// Writes what a shell that failed before exec would have printed to `to` (its stderr).
pub fn report(f: &spawn::Failure, plan: &spawn::Plan, to: Option<RawFd>) {
    let msg = f.message(plan);
    if let Some(fd) = to {
        unsafe { libc::write(fd, msg.as_ptr() as *const libc::c_void, msg.len()) };
    }
}

/// The SHELL tier runs in the enforcing `shell` domain, which has no business with pipes and
/// files that apps own. Its stdio is therefore a set of pipes the daemon itself creates (labelled
/// with the daemon's domain, so one narrow rule covers them) and the supervisor copies between
/// those and the caller's real descriptors. The ROOT tier is permissive and gets the caller's
/// descriptors directly, with no copying.
struct Relay {
    app: [RawFd; 3],
    in_w: RawFd,
    out_r: RawFd,
    err_r: RawFd,
}

/// Returns (the shell's stdin/stdout/stderr, the supervisor's relay).
fn make_relay(app: [RawFd; 3]) -> io::Result<([RawFd; 3], Relay)> {
    let mut p = [[-1i32; 2]; 3];
    for pair in p.iter_mut() {
        if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            let e = io::Error::last_os_error();
            p.iter().flatten().filter(|&&f| f >= 0).for_each(|&f| sys::close(f));
            return Err(e);
        }
    }
    for fd in [p[1][0], p[2][0]] {
        unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
    Ok(([p[0][0], p[1][1], p[2][1]], Relay { app, in_w: p[0][1], out_r: p[1][0], err_r: p[2][0] }))
}

/// Copies what is readable on `from` to `to`. False at EOF or when the reader is gone.
fn copy_some(from: RawFd, to: RawFd) -> bool {
    let mut buf = [0u8; 16384];
    let n = unsafe { libc::read(from, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock
            || io::Error::last_os_error().kind() == io::ErrorKind::Interrupted;
    }
    if n == 0 {
        return false;
    }
    let mut at = 0usize;
    while at < n as usize {
        let w = unsafe { libc::write(to, buf[at..].as_ptr() as *const libc::c_void, n as usize - at) };
        if w < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        at += w as usize;
    }
    true
}

fn stdio_fd_ok(fd: RawFd) -> bool {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return false;
    }
    matches!(st.st_mode & libc::S_IFMT, libc::S_IFCHR | libc::S_IFIFO | libc::S_IFREG | libc::S_IFSOCK)
}

/// What goes in the audit: the first word of the command, or all of it if the grant says so.
fn summary(req: &Request, full: bool) -> String {
    if !req.has(RF_HAS_CMD) {
        return "(shell)".to_string();
    }
    if full {
        return sys::clean(&req.cmd, 200);
    }
    let first = req.cmd.split(|c| c.is_ascii_whitespace()).next().unwrap_or(&[]);
    sys::clean(first, 80)
}

/// Waits for the shell, forwarding a caller that disappears as SIGHUP and, for the SHELL
/// tier, copying its stdio. Returns the exit code (128 + signal when killed) and whether it
/// was signalled.
fn supervise(conn: RawFd, pid: libc::pid_t, relay: Option<Relay>) -> (i32, bool) {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
    }
    let sfd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC) };
    let mut hup_at: Option<Instant> = None;
    // Which relay legs are still open.
    let (mut in_open, mut out_open, mut err_open) = (relay.is_some(), relay.is_some(), relay.is_some());
    loop {
        // The child may already have exited before signalfd existed.
        if let Some(r) = reap(pid) {
            if let Some(rl) = &relay {
                // Whatever the shell wrote last is still in the pipes.
                while out_open && ready(rl.out_r) && copy_some(rl.out_r, rl.app[1]) {}
                while err_open && ready(rl.err_r) && copy_some(rl.err_r, rl.app[2]) {}
            }
            return r;
        }
        let mut fds: Vec<libc::pollfd> = vec![
            libc::pollfd { fd: conn, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sfd, events: libc::POLLIN, revents: 0 },
        ];
        if let Some(rl) = &relay {
            fds.push(libc::pollfd { fd: if in_open { rl.app[0] } else { -1 }, events: libc::POLLIN, revents: 0 });
            fds.push(libc::pollfd { fd: if out_open { rl.out_r } else { -1 }, events: libc::POLLIN, revents: 0 });
            fds.push(libc::pollfd { fd: if err_open { rl.err_r } else { -1 }, events: libc::POLLIN, revents: 0 });
        }
        let timeout = match hup_at {
            Some(t) => HUP_GRACE.saturating_sub(t.elapsed()).as_millis().max(1) as i32,
            None => -1,
        };
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) };
        if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return (1, false);
        }
        if sfd >= 0 && fds[1].revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 128];
            unsafe { libc::read(sfd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        }
        if let Some(rl) = &relay {
            if in_open && fds[2].revents != 0 && !copy_some(rl.app[0], rl.in_w) {
                // The caller's stdin ended: the shell's stdin ends with it.
                in_open = false;
                sys::close(rl.in_w);
            }
            if out_open && fds[3].revents != 0 && !copy_some(rl.out_r, rl.app[1]) {
                out_open = false;
            }
            if err_open && fds[4].revents != 0 && !copy_some(rl.err_r, rl.app[2]) {
                err_open = false;
            }
        }
        if fds[0].revents != 0 && hup_at.is_none() {
            let mut b = [0u8; 64];
            let r = unsafe { libc::recv(conn, b.as_mut_ptr() as *mut libc::c_void, b.len(), libc::MSG_DONTWAIT) };
            // Data from a client that should be silent is ignored; EOF or an error means it is gone.
            if r <= 0 && !(r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock) {
                unsafe {
                    libc::kill(-pid, libc::SIGHUP);
                    libc::kill(pid, libc::SIGHUP);
                    libc::kill(pid, libc::SIGCONT);
                }
                hup_at = Some(Instant::now());
            }
        }
        if let Some(t) = hup_at {
            if t.elapsed() >= HUP_GRACE {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }
}

/// Whether `fd` has something to read right now.
fn ready(fd: RawFd) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut p, 1, 0) > 0 && p.revents & (libc::POLLIN | libc::POLLHUP) != 0 }
}

fn reap(pid: libc::pid_t) -> Option<(i32, bool)> {
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if r == 0 {
        return None;
    }
    if r < 0 {
        return Some((1, false));
    }
    exit_code(status)
}

/// The exit code (128 + signal when killed) and whether it was a signal.
pub fn exit_code(status: libc::c_int) -> Option<(i32, bool)> {
    if libc::WIFEXITED(status) {
        Some((libc::WEXITSTATUS(status), false))
    } else if libc::WIFSIGNALED(status) {
        Some((128 + libc::WTERMSIG(status), true))
    } else {
        None
    }
}

/// Everything a vfork-spawned shell needs, prepared before it is cloned: what [`exec_shell`]
/// does, with the domain set for exec instead of switched in place.
pub fn plan(adm: &Admitted, slave: Option<RawFd>, stdio: Option<[RawFd; 3]>, cfg: &Config) -> spawn::Plan {
    let req = &adm.req;
    let privileged = !cfg.unprivileged_test;
    let shell = if req.has(RF_HAS_SHELL) && !req.shell.is_empty() { req.shell.clone() } else { DEFAULT_SHELL.as_bytes().to_vec() };
    let base = shell.rsplit(|&c| c == b'/').next().unwrap_or(&shell).to_vec();
    let mut argv0 = Vec::new();
    if req.has(RF_LOGIN) {
        argv0.push(b'-');
    }
    argv0.extend_from_slice(&base);
    let mut argv = vec![cstr(argv0)];
    if req.has(RF_HAS_CMD) {
        argv.push(cstr(b"-c".to_vec()));
        argv.push(cstr(req.cmd.clone()));
        argv.extend(req.args.iter().cloned().map(cstr));
    }
    let cgroups = if privileged {
        p::scheduling_cgroups(&req.cgroup)
            .into_iter()
            .map(|(dir, path)| cstr(format!("{dir}{}/cgroup.procs", if path == "/" { "" } else { path.as_str() }).into_bytes()))
            .collect()
    } else {
        Vec::new()
    };
    let uid = adm.target_uid;
    let shell_tier = adm.tier == TIER_SHELL;
    let ids = privileged.then(|| {
        let (gid, groups) = identity(adm.tier, uid);
        spawn::Ids { groups, gid, uid }
    });
    // The SHELL tier could not enter an app directory anyway: it starts in the shell's home.
    let cwd = if shell_tier && privileged {
        Some(CString::new(SHELL_HOME).unwrap())
    } else {
        CString::new(req.cwd.clone()).ok().filter(|c| !c.as_bytes().is_empty())
    };
    spawn::Plan {
        path: cstr(shell),
        argv,
        envp: build_env(req, uid, adm.tier).into_iter().map(cstr).collect(),
        ctty: slave,
        stdio,
        cgroups,
        mntns: if privileged && !adm.global { adm.mntns } else { None },
        umask: (req.umask & 0o777) as libc::mode_t,
        ids,
        cwd,
        exec_con: privileged.then(|| CString::new(context(adm.tier)).unwrap()),
    }
}

/// The primary and supplementary groups of the shell.
fn identity(tier: u8, uid: u32) -> (libc::gid_t, Vec<libc::gid_t>) {
    match (tier, uid) {
        (TIER_SHELL, _) => (UID_SHELL, SHELL_GROUPS.to_vec()),
        (_, 0) => (0, SHELL_GROUPS.to_vec()),
        _ => (uid, vec![uid]),
    }
}

fn context(tier: u8) -> &'static str {
    if tier == TIER_SHELL { "u:r:shell:s0" } else { "u:r:su:s0" }
}

struct Spec<'a> {
    req: &'a Request,
    tier: u8,
    target_uid: u32,
    /// Stay in the daemon's (global) mount namespace instead of joining the caller's.
    global: bool,
    slave: Option<RawFd>,
    stdio: Option<[RawFd; 3]>,
    mntns: Option<RawFd>,
    cfg: &'a Config,
}

/// Writes `su: <what>` (with errno) to the shell's stderr and exits 126/127.
fn fail(what: &str, err: Option<io::Error>) -> ! {
    let msg = match err {
        Some(e) => format!("su: {what}: {e}\n"),
        None => format!("su: {what}\n"),
    };
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(126)
    }
}

/// The forked shell: wires stdio, joins the caller's scheduling class and mount namespace,
/// drops to the target identity, moves to its SELinux domain and execs. Never returns.
fn exec_shell(s: &Spec) -> ! {
    let req = s.req;
    unsafe {
        // The supervisor blocks SIGCHLD and ignores SIGPIPE/SIGHUP; neither may reach the shell.
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::signal(libc::SIGHUP, libc::SIG_DFL);
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);

        if libc::setsid() < 0 {
            fail("setsid", Some(io::Error::last_os_error()));
        }
        // stdio first, so every later failure reaches the caller.
        if let Some(slave) = s.slave {
            if libc::ioctl(slave, libc::TIOCSCTTY as _, 0) < 0 {
                fail("TIOCSCTTY", Some(io::Error::last_os_error()));
            }
            for t in 0..3 {
                libc::dup2(slave, t);
            }
        } else if let Some(fds) = s.stdio {
            for (t, &fd) in fds.iter().enumerate() {
                if libc::dup2(fd, t as i32) < 0 {
                    fail("dup2", Some(io::Error::last_os_error()));
                }
            }
        }
    }

    if !s.cfg.unprivileged_test {
        // Scheduling class of the caller (cpu/cpuset/blkio), never its lifecycle cgroup.
        let me = unsafe { libc::getpid() }.to_string();
        for (dir, path) in p::scheduling_cgroups(&req.cgroup) {
            let file = format!("{dir}{}/cgroup.procs", if path == "/" { "" } else { path.as_str() });
            let _ = std::fs::write(file, &me);
        }
        if !s.global {
            if let Some(ns) = s.mntns {
                if unsafe { libc::setns(ns, libc::CLONE_NEWNS) } < 0 {
                    fail("setns", Some(io::Error::last_os_error()));
                }
            }
        }
    }
    if let Some(ns) = s.mntns {
        sys::close(ns);
    }
    // The daemon is protected from the low-memory killer (oom_score_adjust -900) and a forked
    // shell would inherit that; a root shell is an ordinary, killable process.
    if !s.cfg.unprivileged_test {
        let _ = std::fs::write("/proc/self/oom_score_adj", b"0");
    }

    unsafe { libc::umask((req.umask & 0o777) as libc::mode_t) };

    if !s.cfg.unprivileged_test {
        let uid = s.target_uid;
        let (gid, groups) = identity(s.tier, uid);
        let ctx = context(s.tier);
        unsafe {
            if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0 {
                fail("setgroups", Some(io::Error::last_os_error()));
            }
            if libc::setresgid(gid, gid, gid) != 0 {
                fail("setresgid", Some(io::Error::last_os_error()));
            }
            if s.tier == TIER_SHELL && libc::setresuid(uid, uid, uid) != 0 {
                // CAP_SETUID is checked against the domain the process is in at that moment and
                // `shell` has none, so the uid is dropped while still in the daemon's domain.
                // Nothing runs between this and the domain switch below.
                fail("setresuid", Some(io::Error::last_os_error()));
            }
        }
        if let Err(e) = sys::setcon(ctx) {
            fail(&format!("setcon {ctx}"), Some(e));
        }
    }

    // ROOT tier: the caller's directory, entered as root in the `su` domain (app directories are
    // 0700, so this precedes dropping to another uid). SHELL tier: the shell domain and uid 2000
    // could not enter an app directory anyway, so it starts in the shell's own home.
    let home = CString::new(SHELL_HOME).unwrap();
    let cwd = CString::new(req.cwd.clone()).ok().filter(|c| !c.as_bytes().is_empty());
    unsafe {
        if s.tier == TIER_SHELL && !s.cfg.unprivileged_test {
            if libc::chdir(home.as_ptr()) != 0 {
                libc::chdir(b"/\0".as_ptr() as *const libc::c_char);
            }
        } else if cwd.is_none() || libc::chdir(cwd.as_ref().unwrap().as_ptr()) != 0 {
            libc::chdir(b"/\0".as_ptr() as *const libc::c_char);
        }
    }
    if !s.cfg.unprivileged_test && s.tier != TIER_SHELL && s.target_uid != 0 {
        let uid = s.target_uid;
        if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
            fail("setresuid", Some(io::Error::last_os_error()));
        }
    }

    let shell = if req.has(RF_HAS_SHELL) && !req.shell.is_empty() {
        req.shell.clone()
    } else {
        DEFAULT_SHELL.as_bytes().to_vec()
    };
    let base = shell.rsplit(|&c| c == b'/').next().unwrap_or(&shell).to_vec();
    let mut argv0 = Vec::new();
    if req.has(RF_LOGIN) {
        argv0.push(b'-');
    }
    argv0.extend_from_slice(&base);

    let mut argv: Vec<CString> = vec![cstr(argv0)];
    if req.has(RF_HAS_CMD) {
        argv.push(cstr(b"-c".to_vec()));
        argv.push(cstr(req.cmd.clone()));
        argv.extend(req.args.iter().cloned().map(cstr));
    }
    let envp: Vec<CString> = build_env(req, s.target_uid, s.tier).into_iter().map(cstr).collect();
    let mut argvp: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argvp.push(std::ptr::null());
    let mut envpp: Vec<*const libc::c_char> = envp.iter().map(|c| c.as_ptr()).collect();
    envpp.push(std::ptr::null());
    let path = cstr(shell.clone());
    unsafe { libc::execve(path.as_ptr(), argvp.as_ptr(), envpp.as_ptr()) };
    let e = io::Error::last_os_error();
    let code = if e.raw_os_error() == Some(libc::ENOENT) { 127 } else { 126 };
    let msg = format!("su: {}: {e}\n", String::from_utf8_lossy(&shell));
    unsafe {
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(code)
    }
}

fn cstr(mut v: Vec<u8>) -> CString {
    v.retain(|&c| c != 0);
    CString::new(v).unwrap()
}

/// System directories first so `/system/bin` always wins, then the caller's own entries
/// (Termux tools stay reachable under `su -c`). Duplicates and empty entries are dropped.
fn merged_path(caller: Option<&[u8]>) -> Vec<u8> {
    let mut out = DEFAULT_PATH.as_bytes().to_vec();
    let mut seen: Vec<&[u8]> = DEFAULT_PATH.as_bytes().split(|&c| c == b':').collect();
    for dir in caller.unwrap_or_default().split(|&c| c == b':') {
        if dir.is_empty() || dir[0] != b'/' || seen.contains(&dir) {
            continue;
        }
        seen.push(dir);
        out.push(b':');
        out.extend_from_slice(dir);
    }
    out
}

/// The environment of the shell:
/// * `-p` keeps the caller's environment untouched;
/// * otherwise the caller's environment, minus every `LD_*`, with `PATH` = system directories
///   then the caller's, and `HOME`/`SHELL`/`USER`/`LOGNAME` set;
/// * a login shell starts from the daemon's own (init-provided) environment plus `TERM`.
fn build_env(req: &Request, uid: u32, tier: u8) -> Vec<Vec<u8>> {
    let login = req.has(RF_LOGIN);
    let keep = req.has(RF_PRESERVE_ENV);
    let mut env: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let split = |e: &[u8]| -> Option<(Vec<u8>, Vec<u8>)> {
        let i = e.iter().position(|&c| c == b'=')?;
        Some((e[..i].to_vec(), e[i + 1..].to_vec()))
    };
    if login {
        for (k, v) in std::env::vars_os() {
            env.push((k.into_vec(), v.into_vec()));
        }
        if let Some(t) = req.env.iter().filter_map(|e| split(e)).find(|(k, _)| k == b"TERM") {
            env.retain(|(k, _)| k != b"TERM");
            env.push(t);
        }
    } else {
        env = req.env.iter().filter_map(|e| split(e)).collect();
        if !keep {
            env.retain(|(k, _)| !k.starts_with(b"LD_"));
        }
    }
    if keep && !login {
        return env.into_iter().map(|(k, v)| [k, b"=".to_vec(), v].concat()).collect();
    }
    let user = match (tier, uid) {
        (TIER_SHELL, _) => "shell".to_string(),
        (_, 0) => "root".to_string(),
        (_, n) => n.to_string(),
    };
    let caller_path = env.iter().find(|(k, _)| k == b"PATH").map(|(_, v)| v.clone());
    let mut set = |k: &str, v: &[u8]| {
        env.retain(|(ek, _)| ek != k.as_bytes());
        env.push((k.as_bytes().to_vec(), v.to_vec()));
    };
    set("PATH", &merged_path(caller_path.as_deref()));
    set("HOME", SHELL_HOME.as_bytes());
    set("SHELL", if req.has(RF_HAS_SHELL) { &req.shell } else { DEFAULT_SHELL.as_bytes() });
    set("USER", user.as_bytes());
    set("LOGNAME", user.as_bytes());
    env.into_iter().map(|(k, v)| [k, b"=".to_vec(), v].concat()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(flags: u16, env: &[&str]) -> Request {
        Request {
            flags,
            env: env.iter().map(|e| e.as_bytes().to_vec()).collect(),
            ..Request::default()
        }
    }

    fn get(env: &[Vec<u8>], key: &str) -> Option<String> {
        env.iter().find_map(|e| {
            let s = String::from_utf8_lossy(e).to_string();
            s.strip_prefix(&format!("{key}=")).map(String::from)
        })
    }

    #[test]
    fn default_env_strips_ld_and_resets_path() {
        let r = req(0, &["PATH=/data/data/com.termux/files/usr/bin", "LD_PRELOAD=/x.so", "LD_LIBRARY_PATH=/y", "TERM=xterm", "FOO=1"]);
        let env = build_env(&r, 0, TIER_ROOT);
        assert_eq!(get(&env, "LD_PRELOAD"), None);
        assert_eq!(get(&env, "LD_LIBRARY_PATH"), None);
        assert_eq!(get(&env, "FOO").as_deref(), Some("1"));
        assert_eq!(get(&env, "TERM").as_deref(), Some("xterm"));
        assert_eq!(
            get(&env, "PATH").unwrap(),
            format!("{DEFAULT_PATH}:/data/data/com.termux/files/usr/bin")
        );
        assert_eq!(get(&env, "USER").as_deref(), Some("root"));
        assert_eq!(get(&env, "HOME").as_deref(), Some("/data/local/tmp"));
    }

    fn gv(tier: u8, global_ns: bool) -> GrantView {
        GrantView { tier, global_ns, flags: 0, packages: String::new() }
    }

    #[test]
    fn target_namespace_is_root_only_and_needs_the_fd() {
        let r = |flags: u16, tier: u8| Request { flags, tier, ..Request::default() };
        let t = RF_HAS_MNTNS_FD | p::RF_TARGET_NS;
        let a = admit(r(t, 0), &[9], &gv(TIER_ROOT, true)).ok().unwrap();
        assert!(!a.global, "joins the target, not the daemon's namespace");
        assert_eq!(a.mntns, Some(9));
        assert_eq!(admit(r(p::RF_TARGET_NS, 0), &[], &gv(TIER_ROOT, true)).err(), Some(Reason::BadRequest));
        assert_eq!(admit(r(t, 0), &[9], &gv(TIER_SHELL, true)).err(), Some(Reason::Tier));
        assert_eq!(admit(r(t, 0), &[9], &gv(TIER_ROOT, false)).err(), Some(Reason::Tier), "confined grant");
        let a = admit(r(0, 0), &[], &gv(TIER_ROOT, true)).ok().unwrap();
        assert!(a.global);
    }

    #[test]
    fn merged_path_keeps_system_first_and_drops_junk() {
        let m = merged_path(Some(b"/system/bin::relative:/t/bin:/t/bin:/system/xbin"));
        assert_eq!(m, format!("{DEFAULT_PATH}:/t/bin").into_bytes());
        assert_eq!(merged_path(None), DEFAULT_PATH.as_bytes().to_vec());
    }

    #[test]
    fn preserve_env_is_untouched() {
        let r = req(RF_PRESERVE_ENV, &["PATH=/a:/b", "LD_PRELOAD=/x.so", "HOME=/h"]);
        let env = build_env(&r, 0, TIER_ROOT);
        assert_eq!(get(&env, "PATH").as_deref(), Some("/a:/b"));
        assert_eq!(get(&env, "LD_PRELOAD").as_deref(), Some("/x.so"));
        assert_eq!(get(&env, "HOME").as_deref(), Some("/h"));
        assert_eq!(get(&env, "USER"), None);
    }

    #[test]
    fn shell_tier_user_name() {
        let env = build_env(&req(0, &[]), 2000, TIER_SHELL);
        assert_eq!(get(&env, "USER").as_deref(), Some("shell"));
        let env = build_env(&req(0, &[]), 10195, TIER_ROOT);
        assert_eq!(get(&env, "USER").as_deref(), Some("10195"));
    }

    fn cfg(unprivileged_test: bool) -> Config {
        Config {
            data_dir: "/d".into(),
            grants_path: "/d/g".into(),
            events_path: "/d/e".into(),
            enrolled_path: "/d/s".into(),
            socket_path: None,
            unprivileged_test,
        }
    }

    fn admitted(tier: u8, shell: Option<&str>, stdio: bool) -> Admitted {
        let mut r = req(if shell.is_some() { RF_HAS_SHELL } else { 0 }, &[]);
        r.shell = shell.unwrap_or("").as_bytes().to_vec();
        r.cwd = b"/data/data/com.termux/files/home".to_vec();
        let target_uid = if tier == TIER_SHELL { UID_SHELL } else { 0 };
        Admitted { req: r, tier, target_uid, global: true, mntns: None, stdio: stdio.then_some([0, 1, 2]) }
    }

    #[test]
    fn main_loop_runs_exec_typed_shells_that_need_no_relay() {
        let c = cfg(false);
        assert!(inline(&admitted(TIER_ROOT, None, true), &c));
        assert!(inline(&admitted(TIER_ROOT, Some("/system/bin/sh"), true), &c));
        assert!(inline(&admitted(TIER_SHELL, None, false), &c), "SHELL tier on a pty needs no relay");
        assert!(!inline(&admitted(TIER_SHELL, None, true), &c), "plain stdio is relayed");
        let bash = "/data/data/com.termux/files/usr/bin/bash";
        assert!(!exec_typed(&admitted(TIER_ROOT, Some(bash), true).req, &c), "no entrypoint for app files");
        assert!(!inline(&admitted(TIER_ROOT, Some(bash), true), &c));
        assert!(!inline(&admitted(TIER_SHELL, Some(bash), false), &c));
    }

    #[test]
    fn shell_tier_plan_is_the_adb_shell_identity() {
        let p = plan(&admitted(TIER_SHELL, None, false), Some(7), None, &cfg(false));
        let ids = p.ids.unwrap();
        assert_eq!((ids.uid, ids.gid), (UID_SHELL, UID_SHELL));
        assert_eq!(ids.groups, SHELL_GROUPS.to_vec());
        assert_eq!(p.exec_con.unwrap().to_str().unwrap(), "u:r:shell:s0");
        assert_eq!(p.cwd.unwrap().to_str().unwrap(), SHELL_HOME, "never the app's directory");
        assert_eq!(p.ctty, Some(7));

        let p = plan(&admitted(TIER_ROOT, None, true), None, Some([3, 4, 5]), &cfg(false));
        assert_eq!(p.exec_con.unwrap().to_str().unwrap(), "u:r:su:s0");
        assert_eq!(p.cwd.unwrap().to_str().unwrap(), "/data/data/com.termux/files/home");
        assert_eq!(p.stdio, Some([3, 4, 5]));
        assert_eq!(p.path.to_str().unwrap(), DEFAULT_SHELL);
    }

    #[test]
    fn audit_summary_hides_arguments_unless_asked() {
        let mut r = req(RF_HAS_CMD, &[]);
        r.cmd = b"cat /data/secret|x".to_vec();
        assert_eq!(summary(&r, false), "cat");
        assert_eq!(summary(&r, true), "cat /data/secret x");
        assert_eq!(summary(&req(0, &[]), false), "(shell)");
    }
}
