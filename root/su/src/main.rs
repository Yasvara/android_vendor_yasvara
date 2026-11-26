// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! `su` — client of the ROM's root daemon.
//!
//! It has no privileges of its own: it only asks `yasvara_rootd` over a socket. The request is
//! queued right after connecting, without waiting for the verdict; the daemon reads none of it
//! from a caller that is not enrolled.
//!
//! Command line (what Termux's `tsu` and Magisk-era scripts use):
//!
//! ```text
//! su [options] [-] [user [arg…]]
//!   -c, --command CMD         run CMD with the shell's -c
//!   -s, --shell SHELL         shell to run (default /system/bin/sh)
//!   -, -l, --login            login shell: environment reset
//!   -p, -m, --preserve-environment
//!   -M, -mm, --mount-master   run in the global mount namespace
//!   -t, --tier shell|root     ask for less than the grant allows
//!   -v / -V / -h              version string / version code / help
//! ```

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::RawFd;

use yasvara_root_proto::{self as p, Frame, Reason, Request};

#[derive(Debug, Default, PartialEq)]
struct Opts {
    cmd: Option<Vec<u8>>,
    shell: Option<Vec<u8>>,
    login: bool,
    preserve: bool,
    master: bool,
    force_pty: bool,
    tier: u8,
    user: Option<u32>,
    target_pid: Option<i32>,
    context: Option<Vec<u8>>,
    extra: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
enum Action {
    Run(Opts),
    Print(&'static str),
    Version,
    VersionCode,
}

const USAGE: &str = "Usage: su [options] [-] [user [command [argument...]]]\n\
Options:\n  \
-c, --command COMMAND       pass COMMAND to the invoked shell\n  \
-s, --shell SHELL           use SHELL instead of /system/bin/sh\n  \
-, -l, --login              pretend the shell to be a login shell\n  \
-p, -m, --preserve-environment\n                              do not change the environment\n  \
-M, -mm, --mount-master     run in the global mount namespace\n  \
-i, --interactive           force a pseudo-terminal when using -c\n  \
-t, --target PID            run in the mount namespace of PID\n  \
-Z, --context CONTEXT       run in SELinux CONTEXT\n  \
-g, -G GROUP                accepted for root only\n  \
    --tier shell|root       request a lower tier than the grant allows\n  \
-v, --version               print the version string\n  \
-V                          print the version code\n  \
-h, --help                  this help\n\
A command after the user runs directly, as with AOSP su: `su 0 id`, `su root ls -l /`.\n";

fn die(msg: &str) -> ! {
    eprintln!("su: {msg}");
    std::process::exit(1)
}

fn parse_tier(v: &[u8]) -> Result<u8, String> {
    match v {
        b"shell" => Ok(p::TIER_SHELL),
        b"root" => Ok(p::TIER_ROOT),
        _ => Err("--tier needs shell or root".into()),
    }
}

fn root_group_only(v: &[u8]) -> Result<(), String> {
    match v {
        b"0" | b"root" => Ok(()),
        _ => Err(format!("group {} is not supported, only root", String::from_utf8_lossy(v))),
    }
}

/// Quotes one word for `sh`.
fn sh_quote(w: &[u8]) -> Vec<u8> {
    let mut o = vec![b'\''];
    for &c in w {
        if c == b'\'' {
            o.extend_from_slice(b"'\\''");
        } else {
            o.push(c);
        }
    }
    o.push(b'\'');
    o
}

/// Magisk/KSU option set plus AOSP's `su USER COMMAND…`. Everything after the first word
/// following the user is the command's own argv, never su options.
fn parse<I: IntoIterator<Item = Vec<u8>>>(args: I) -> Result<Action, String> {
    let mut o = Opts { tier: p::TIER_DEFAULT, ..Opts::default() };
    let mut args = args.into_iter();
    let mut positional_only = false;
    let mut have_user = false;
    let mut command_argv: Vec<Vec<u8>> = Vec::new();
    while let Some(a) = args.next() {
        if !command_argv.is_empty() {
            command_argv.push(a);
            continue;
        }
        if positional_only || a.first() != Some(&b'-') {
            if !have_user {
                have_user = true;
                let s = String::from_utf8_lossy(&a);
                o.user = Some(p::parse_user(&s).ok_or_else(|| format!("unknown user: {s}"))?);
            } else {
                command_argv.push(a);
            }
            continue;
        }
        let mut value = |name: &str, inline: Option<&[u8]>| -> Result<Vec<u8>, String> {
            match inline {
                Some(v) if !v.is_empty() => Ok(v.to_vec()),
                _ => args.next().ok_or_else(|| format!("option {name} needs a value")),
            }
        };
        if let Some(long) = a.strip_prefix(b"--") {
            if long.is_empty() {
                positional_only = true;
                continue;
            }
            let (name, inline) = match long.iter().position(|&c| c == b'=') {
                Some(i) => (&long[..i], Some(&long[i + 1..])),
                None => (long, None),
            };
            match name {
                b"command" => o.cmd = Some(value("--command", inline)?),
                b"shell" => o.shell = Some(value("--shell", inline)?),
                b"login" => o.login = true,
                b"preserve-environment" => o.preserve = true,
                b"mount-master" => o.master = true,
                b"interactive" => o.force_pty = true,
                b"target" => o.target_pid = Some(parse_pid(&value("--target", inline)?)?),
                b"context" => o.context = Some(value("--context", inline)?),
                b"group" | b"supp-group" => root_group_only(&value("--group", inline)?)?,
                b"tier" => o.tier = parse_tier(&value("--tier", inline)?)?,
                b"version" => return Ok(Action::Version),
                b"help" => return Ok(Action::Print(USAGE)),
                _ => return Err(format!("invalid option: {}\n{USAGE}", String::from_utf8_lossy(&a))),
            }
            continue;
        }
        if a == b"-" {
            o.login = true;
            continue;
        }
        if a == b"-mm" {
            o.master = true;
            continue;
        }
        // A cluster of short options; one taking a value ends it (`-lc CMD`, `-cCMD`).
        let cluster = &a[1..];
        let mut i = 0;
        while i < cluster.len() {
            let ch = cluster[i];
            let rest = &cluster[i + 1..];
            let inline = (!rest.is_empty()).then_some(rest);
            match ch {
                b'l' => o.login = true,
                b'p' | b'm' => o.preserve = true,
                b'M' => o.master = true,
                b'i' => o.force_pty = true,
                b'v' => return Ok(Action::Version),
                b'V' => return Ok(Action::VersionCode),
                b'h' => return Ok(Action::Print(USAGE)),
                b'c' | b's' | b't' | b'Z' | b'g' | b'G' => {
                    let v = value(&format!("-{}", ch as char), inline)?;
                    match ch {
                        b'c' => o.cmd = Some(v),
                        b's' => o.shell = Some(v),
                        // `-t shell|root` was this client's tier flag before; Magisk's is a PID.
                        b't' => match v.as_slice() {
                            b"shell" | b"root" => o.tier = parse_tier(&v)?,
                            _ => o.target_pid = Some(parse_pid(&v)?),
                        },
                        b'Z' => o.context = Some(v),
                        _ => root_group_only(&v)?,
                    }
                    break;
                }
                _ => return Err(format!("invalid option: {}\n{USAGE}", String::from_utf8_lossy(&a))),
            }
            i += 1;
        }
    }
    if !command_argv.is_empty() {
        if o.cmd.is_none() {
            // AOSP: `su 0 id -u` runs `id -u`. The shell resolves it through PATH.
            o.cmd = Some(b"exec \"$0\" \"$@\"".to_vec());
        }
        o.extra = command_argv;
    }
    if let Some(ctx) = o.context.take() {
        let shell = o.shell.clone().unwrap_or_else(|| b"/system/bin/sh".to_vec());
        let mut c = b"exec /system/bin/runcon ".to_vec();
        c.extend(sh_quote(&ctx));
        c.push(b' ');
        c.extend(sh_quote(&shell));
        if let Some(inner) = &o.cmd {
            c.extend_from_slice(b" -c ");
            c.extend(sh_quote(inner));
            c.extend_from_slice(b" \"$0\" \"$@\"");
        }
        o.cmd = Some(c);
    }
    Ok(Action::Run(o))
}

fn parse_pid(v: &[u8]) -> Result<i32, String> {
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|&n| n > 0)
        .ok_or_else(|| format!("invalid pid: {}", String::from_utf8_lossy(v)))
}

/// A pty only for a real interactive session: both ends are terminals and there is no
/// command, unless `-i` asks for one. Anything else gets the caller's own fds, so output is
/// byte-exact (no CRLF) and stderr stays separate.
fn wants_pty(stdin_tty: bool, stdout_tty: bool, has_cmd: bool, force: bool) -> bool {
    stdin_tty && stdout_tty && (!has_cmd || force)
}

fn parse_args() -> Opts {
    match parse(std::env::args_os().skip(1).map(OsString::into_vec)) {
        Ok(Action::Run(o)) => o,
        Ok(Action::Print(t)) => {
            print!("{t}");
            std::process::exit(0)
        }
        Ok(Action::Version) => {
            println!("{}:YASVARA", p::VERSION_NAME);
            std::process::exit(0)
        }
        Ok(Action::VersionCode) => {
            println!("{}", p::VERSION_CODE);
            std::process::exit(0)
        }
        Err(e) => die(&e),
    }
}

fn connect() -> io::Result<RawFd> {
    // An enrolled app sees the socket at the projected path; `adb shell` reaches the
    // daemon's own path. Anyone else gets an error from both.
    if let Some(path) = std::env::var_os("YASVARA_SU_SOCKET") {
        return connect_to(&path);
    }
    match connect_to(OsStr::new(p::PROJECTED_SOCKET_PATH)) {
        Ok(fd) => Ok(fd),
        Err(_) => connect_to(OsStr::new(p::SOCKET_PATH)),
    }
}

fn connect_to(path: &OsStr) -> io::Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    for (i, b) in path.as_bytes().iter().take(addr.sun_path.len() - 1).enumerate() {
        addr.sun_path[i] = *b as libc::c_char;
    }
    let r = unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_un>() as _) };
    if r < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

fn send_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), libc::MSG_NOSIGNAL) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// First chunk goes with the fds (SCM_RIGHTS), the rest is plain.
fn send_request(fd: RawFd, buf: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut iov = libc::iovec { iov_base: buf.as_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let space = unsafe { libc::CMSG_SPACE((fds.len() * 4) as u32) } as usize;
    let mut cbuf = vec![0u8; space.max(1)];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN((fds.len() * 4) as u32) as _;
            std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, libc::CMSG_DATA(c), fds.len() * 4);
        }
    }
    let sent = loop {
        let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            break n as usize;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    send_all(fd, &buf[sent..])
}

/// One 16-byte daemon frame, plus a pty master if one came with it.
fn recv_frame(fd: RawFd) -> io::Result<(Frame, Option<RawFd>)> {
    let mut buf = [0u8; p::FRAME_LEN];
    let mut got = 0;
    let mut master = None;
    while got < buf.len() {
        let mut iov = libc::iovec { iov_base: buf[got..].as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() - got };
        let space = unsafe { libc::CMSG_SPACE(4) } as usize;
        let mut cbuf = vec![0u8; space];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        got += n as usize;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            if !c.is_null() && (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                master = Some(std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const RawFd));
            }
        }
    }
    let frame = Frame::decode(&buf).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad frame"))?;
    Ok((frame, master))
}

fn isatty(fd: RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// Apps cannot open their mount namespace (SELinux denies nsfs reads to app domains, and each
/// try would be an audited denial); shell and root can.
fn may_open_mntns(uid: u32) -> bool {
    uid % 100_000 < 10_000
}

fn build_request(o: &Opts, interactive: bool) -> Request {
    let mut flags = 0u16;
    if interactive {
        flags |= p::RF_INTERACTIVE;
    } else {
        flags |= p::RF_HAS_STDIO_FDS;
    }
    if o.login {
        flags |= p::RF_LOGIN;
    }
    if o.preserve {
        flags |= p::RF_PRESERVE_ENV;
    }
    if o.master {
        flags |= p::RF_MOUNT_MASTER;
    }
    if o.cmd.is_some() {
        flags |= p::RF_HAS_CMD;
    }
    if o.shell.is_some() {
        flags |= p::RF_HAS_SHELL;
    }
    if o.user.is_some() {
        flags |= p::RF_HAS_USER;
    }
    let (mut rows, mut cols) = (0, 0);
    if interactive {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(0, libc::TIOCGWINSZ as _, &mut ws) } == 0 {
            rows = ws.ws_row;
            cols = ws.ws_col;
        }
    }
    // The umask can only be read by setting it; this process is single-threaded.
    let umask = unsafe {
        let m = libc::umask(0o077);
        libc::umask(m);
        m as u32
    };
    let mut env: Vec<Vec<u8>> = Vec::new();
    let mut env_bytes = 0;
    for (k, v) in std::env::vars_os() {
        let e = [k.into_vec(), b"=".to_vec(), v.into_vec()].concat();
        if env_bytes + e.len() + 1 > p::MAX_ENV {
            break;
        }
        env_bytes += e.len() + 1;
        env.push(e);
    }
    let cgroup = std::fs::read("/proc/self/cgroup").map(|mut v| {
        v.truncate(8192);
        v
    });
    Request {
        flags,
        target_uid: o.user.unwrap_or(0),
        tier: o.tier,
        rows,
        cols,
        umask,
        shell: o.shell.clone().unwrap_or_default(),
        cmd: o.cmd.clone().unwrap_or_default(),
        cwd: std::env::current_dir().map(|d| d.into_os_string().into_vec()).unwrap_or_default(),
        cgroup: cgroup.unwrap_or_default(),
        env,
        args: o.extra.clone(),
    }
}

/// Connects, queues the request and reads the verdict, which the daemon sends before reading
/// anything. A refused caller's request stays unread; Linux still delivers the verdict ahead of
/// the reset that the daemon's close() leaves. Returns the send result for the Ack to explain.
fn ask(req: &[u8], fds: &[RawFd]) -> (RawFd, Frame, io::Result<()>) {
    let conn = match connect() {
        Ok(fd) => fd,
        Err(e) => match e.raw_os_error() {
            Some(libc::ENOENT) | Some(libc::ECONNREFUSED) => die(Reason::Disabled.message()),
            Some(libc::EACCES) => die("permission denied (SELinux)"),
            _ => die(&format!("cannot reach the root daemon: {e}")),
        },
    };
    let sent = send_request(conn, req, fds);
    let (verdict, _) = recv_frame(conn).unwrap_or_else(|e| match &sent {
        Err(se) => die(&format!("daemon hung up: {se}")),
        Ok(()) => die(&format!("daemon hung up: {e}")),
    });
    if verdict.kind != p::KIND_VERDICT {
        die("protocol error");
    }
    if !verdict.is_ok() {
        die(Reason::from_u8(verdict.reason).message());
    }
    if verdict.a != p::VERSION as u32 {
        die("version mismatch, reboot");
    }
    (conn, verdict, sent)
}

fn main() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    let o = parse_args();
    let interactive = wants_pty(isatty(0), isatty(1), o.cmd.is_some(), o.force_pty);
    // Built before connecting: the daemon is woken by the connect and often lands on this CPU.
    let mut req = build_request(&o, interactive);
    let mut fds: Vec<RawFd> = Vec::new();
    if let Some(pid) = o.target_pid {
        let path = format!("/proc/{pid}/ns/mnt\0");
        let ns = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY | libc::O_CLOEXEC) };
        if ns < 0 {
            die(&format!("cannot open the mount namespace of {pid}: {}", io::Error::last_os_error()));
        }
        req.flags |= p::RF_HAS_MNTNS_FD | p::RF_TARGET_NS;
        fds.push(ns);
    }
    if req.has(p::RF_HAS_STDIO_FDS) {
        fds.extend_from_slice(&[0, 1, 2]);
    }
    let (mut conn, verdict, mut sent) = ask(&req.encode(), &fds);
    if verdict.b & p::VF_WANTS_MNTNS != 0 && !o.master && o.target_pid.is_none() {
        // A confined grant: ask again with the mount namespace. Not opened up front, as nsfs
        // is unlabeled and every descriptor of it passed to the daemon is an audited denial.
        if !may_open_mntns(unsafe { libc::getuid() }) {
            die("this grant confines you to your own mount namespace, which apps cannot open; enroll with the global namespace");
        }
        let ns = unsafe { libc::open(b"/proc/self/ns/mnt\0".as_ptr() as *const libc::c_char, libc::O_RDONLY | libc::O_CLOEXEC) };
        if ns < 0 {
            die(&format!("this grant confines you to your own mount namespace, which cannot be opened here ({}); enroll with the global namespace", io::Error::last_os_error()));
        }
        unsafe { libc::close(conn) };
        req.flags |= p::RF_HAS_MNTNS_FD;
        fds.insert(0, ns);
        (conn, _, sent) = ask(&req.encode(), &fds);
    }
    // A session that refused the request mid-send still left its Ack ahead of the reset.
    let (ack, master) = match (recv_frame(conn), sent) {
        (Ok(f), _) => f,
        (Err(_), Err(e)) | (Err(e), Ok(())) => die(&format!("daemon hung up: {e}")),
    };
    if ack.kind != p::KIND_ACK || !ack.is_ok() {
        die(Reason::from_u8(ack.reason).message());
    }

    let code = match (interactive, master) {
        (true, Some(m)) => pump(m, conn),
        (true, None) => die("daemon did not provide a terminal"),
        (false, _) => wait_exit(conn),
    };
    std::process::exit(code);
}

fn wait_exit(conn: RawFd) -> i32 {
    match recv_frame(conn) {
        Ok((f, _)) if f.kind == p::KIND_EXIT => f.a as i32,
        _ => die("daemon died"),
    }
}

/// Interactive session: the shell has a pty of its own, so this process puts the real
/// terminal in raw mode and copies bytes both ways, forwarding window-size changes.
fn pump(master: RawFd, conn: RawFd) -> i32 {
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let have_tio = unsafe { libc::tcgetattr(0, &mut saved) } == 0;
    if have_tio {
        let mut raw = saved;
        unsafe {
            libc::cfmakeraw(&mut raw);
            // TCSANOW: keep what the user already typed while the shell was starting.
            libc::tcsetattr(0, libc::TCSANOW, &raw);
        }
    }
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGWINCH);
        libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
    }
    let sfd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC) };

    let mut code = 1;
    let mut stdin_open = true;
    let mut buf = [0u8; 8192];
    loop {
        let mut fds = [
            libc::pollfd { fd: if stdin_open { 0 } else { -1 }, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: conn, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sfd, events: libc::POLLIN, revents: 0 },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 4, -1) } < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if fds[3].revents & libc::POLLIN != 0 {
            let mut si = [0u8; 128];
            unsafe { libc::read(sfd, si.as_mut_ptr() as *mut libc::c_void, si.len()) };
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(0, libc::TIOCGWINSZ as _, &mut ws) } == 0 {
                unsafe { libc::ioctl(master, libc::TIOCSWINSZ as _, &ws) };
            }
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 && stdin_open {
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                stdin_open = false;
            } else if send_all_fd(master, &buf[..n as usize]).is_err() {
                // The shell side is gone; the Exit frame follows.
                stdin_open = false;
            }
        }
        if fds[1].revents & libc::POLLIN != 0 && !copy_out(master, &mut buf) {
            // EIO: the shell closed its end. Wait for the status frame below.
        }
        if fds[2].revents != 0 {
            match recv_frame(conn) {
                Ok((f, _)) if f.kind == p::KIND_EXIT => code = f.a as i32,
                _ => {}
            }
            // Whatever the shell wrote last is still in the pty buffer.
            while copy_out(master, &mut buf) {}
            break;
        }
    }
    if have_tio {
        unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &saved) };
    }
    code
}

fn send_all_fd(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// Copies one read of the pty master to stdout. False when there was nothing (EOF/EIO/EAGAIN).
fn copy_out(master: RawFd, buf: &mut [u8]) -> bool {
    let mut p = libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut p, 1, 0) } <= 0 {
        return false;
    }
    let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n <= 0 {
        return false;
    }
    let _ = send_all_fd(1, &buf[..n as usize]);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_shell_and_root_try_to_open_the_mount_namespace() {
        assert!(may_open_mntns(0));
        assert!(may_open_mntns(2000));
        assert!(may_open_mntns(10 * 100_000 + 2000), "shell of a secondary user");
        assert!(!may_open_mntns(10195), "an app");
        assert!(!may_open_mntns(10 * 100_000 + 10195), "an app of a secondary user");
    }

    fn run(args: &[&str]) -> Opts {
        match parse(args.iter().map(|a| a.as_bytes().to_vec())) {
            Ok(Action::Run(o)) => o,
            other => panic!("{args:?} → {other:?}"),
        }
    }

    fn b(s: &str) -> Option<Vec<u8>> {
        Some(s.as_bytes().to_vec())
    }

    #[test]
    fn magisk_command_forms() {
        for args in [&["-c", "id"][..], &["-cid"], &["--command", "id"], &["--command=id"], &["root", "-c", "id"], &["-c", "id", "0"]] {
            let o = run(args);
            assert_eq!(o.cmd, b("id"), "{args:?}");
            assert!(o.extra.is_empty(), "{args:?}");
        }
        assert_eq!(run(&["-c", "id"]).user, None);
        assert_eq!(run(&["root", "-c", "id"]).user, Some(0));
    }

    #[test]
    fn aosp_user_then_command_runs_directly() {
        let o = run(&["0", "id", "-u"]);
        assert_eq!(o.user, Some(0));
        assert_eq!(o.cmd, b("exec \"$0\" \"$@\""));
        assert_eq!(o.extra, vec![b"id".to_vec(), b"-u".to_vec()]);
        // Options after the command belong to the command, not to su.
        let o = run(&["root", "ls", "-l", "/data"]);
        assert!(!o.login);
        assert_eq!(o.extra.len(), 3);
        let o = run(&["root", "sh", "-c", "echo hi"]);
        assert_eq!(o.cmd, b("exec \"$0\" \"$@\""));
        assert_eq!(o.extra, vec![b"sh".to_vec(), b"-c".to_vec(), b"echo hi".to_vec()]);
    }

    #[test]
    fn explicit_command_keeps_trailing_words_as_positional_parameters() {
        let o = run(&["-c", "echo $0 $1", "0", "a", "b"]);
        assert_eq!(o.cmd, b("echo $0 $1"));
        assert_eq!(o.extra, vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn clusters_and_flags() {
        let o = run(&["-lp"]);
        assert!(o.login && o.preserve);
        let o = run(&["-mm"]);
        assert!(o.master && !o.preserve);
        let o = run(&["-M", "-i", "-c", "top"]);
        assert!(o.master && o.force_pty);
        let o = run(&["-lc", "id"]);
        assert!(o.login);
        assert_eq!(o.cmd, b("id"));
        assert!(run(&["-"]).login);
        let o = run(&["-s", "/bin/bash", "--", "root"]);
        assert_eq!(o.shell, b("/bin/bash"));
        assert_eq!(o.user, Some(0));
    }

    #[test]
    fn target_pid_and_tier() {
        assert_eq!(run(&["-t", "1", "-c", "id"]).target_pid, Some(1));
        assert_eq!(run(&["--target=42"]).target_pid, Some(42));
        assert_eq!(run(&["--tier", "shell"]).tier, p::TIER_SHELL);
        assert_eq!(run(&["-t", "shell"]).tier, p::TIER_SHELL, "old client spelling");
        assert!(parse([b"-t".to_vec(), b"abc".to_vec()]).is_err());
        assert!(parse([b"-t".to_vec(), b"0".to_vec()]).is_err());
    }

    #[test]
    fn context_wraps_in_runcon_and_groups_are_root_only() {
        let o = run(&["-Z", "u:r:shell:s0", "-c", "id -Z"]);
        assert_eq!(o.cmd, b("exec /system/bin/runcon 'u:r:shell:s0' '/system/bin/sh' -c 'id -Z' \"$0\" \"$@\""));
        let o = run(&["-Z", "u:r:su:s0"]);
        assert_eq!(o.cmd, b("exec /system/bin/runcon 'u:r:su:s0' '/system/bin/sh'"));
        assert!(run(&["-g", "0", "-G", "root"]).cmd.is_none());
        assert!(parse([b"-g".to_vec(), b"1000".to_vec()]).is_err());
    }

    #[test]
    fn errors_and_info() {
        assert!(parse([b"--bogus".to_vec()]).is_err());
        assert!(parse([b"-x".to_vec()]).is_err());
        assert!(parse([b"-c".to_vec()]).is_err());
        assert!(parse([b"nobody_here".to_vec()]).is_err());
        assert_eq!(parse([b"-v".to_vec()]), Ok(Action::Version));
        assert_eq!(parse([b"-V".to_vec()]), Ok(Action::VersionCode));
        assert_eq!(parse([b"--help".to_vec()]), Ok(Action::Print(USAGE)));
    }

    #[test]
    fn sh_quote_survives_single_quotes() {
        assert_eq!(sh_quote(b"it's"), b"'it'\\''s'".to_vec());
    }

    #[test]
    fn pty_only_for_interactive_terminals() {
        // (stdin tty, stdout tty, has -c, -i) → pty
        assert!(wants_pty(true, true, false, false));
        assert!(!wants_pty(true, true, true, false), "su -c from a terminal: plain fds, no CRLF");
        assert!(wants_pty(true, true, true, true), "-i forces it");
        assert!(!wants_pty(true, false, false, false), "stdout piped");
        assert!(!wants_pty(false, true, false, false), "stdin piped");
        assert!(!wants_pty(false, false, true, true), "-i needs terminals");
    }
}
