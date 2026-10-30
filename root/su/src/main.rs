// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `su` — client of the ROM's root daemon (SPEC-0006).
//!
//! It has no privileges of its own: it only asks `yasvara_rootd` over a socket. The daemon
//! speaks first, so an app that is not enrolled is told so before this process sends a byte.
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

struct Opts {
    cmd: Option<Vec<u8>>,
    shell: Option<Vec<u8>>,
    login: bool,
    preserve: bool,
    master: bool,
    tier: u8,
    user: Option<u32>,
    extra: Vec<Vec<u8>>,
}

const USAGE: &str = "Usage: su [options] [-] [user [argument...]]\n\
Options:\n  \
-c, --command COMMAND       pass COMMAND to the invoked shell\n  \
-s, --shell SHELL           use SHELL instead of /system/bin/sh\n  \
-, -l, --login              pretend the shell to be a login shell\n  \
-p, -m, --preserve-environment\n                              do not change the environment\n  \
-M, -mm, --mount-master     run in the global mount namespace\n  \
-t, --tier shell|root       request a lower tier than the grant allows\n  \
-v, --version               print the version string\n  \
-V                          print the version code\n  \
-h, --help                  this help\n";

fn die(msg: &str) -> ! {
    eprintln!("su: {msg}");
    std::process::exit(1)
}

fn parse_args() -> Opts {
    let mut o = Opts { cmd: None, shell: None, login: false, preserve: false, master: false, tier: p::TIER_DEFAULT, user: None, extra: Vec::new() };
    let mut args = std::env::args_os().skip(1).map(OsString::into_vec);
    let mut positional_only = false;
    let mut have_user = false;
    while let Some(a) = args.next() {
        let s = String::from_utf8_lossy(&a).to_string();
        if positional_only || !s.starts_with('-') {
            // The first positional is the user, the rest are shell arguments.
            if !have_user {
                have_user = true;
                match p::parse_user(&s) {
                    Some(u) => o.user = Some(u),
                    None => die(&format!("unknown user: {s}")),
                }
            } else {
                o.extra.push(a);
            }
            continue;
        }
        match s.as_str() {
            "-" | "-l" | "--login" => o.login = true,
            "-c" | "--command" => o.cmd = Some(args.next().unwrap_or_else(|| die("option -c needs a command"))),
            "-s" | "--shell" => o.shell = Some(args.next().unwrap_or_else(|| die("option -s needs a shell"))),
            "-p" | "-m" | "--preserve-environment" => o.preserve = true,
            "-M" | "-mm" | "--mount-master" => o.master = true,
            "-t" | "--tier" => {
                o.tier = match args.next().as_deref() {
                    Some(b"shell") => p::TIER_SHELL,
                    Some(b"root") => p::TIER_ROOT,
                    _ => die("option -t needs shell or root"),
                }
            }
            "-v" | "--version" => {
                println!("{}:YASVARA", p::VERSION_NAME);
                std::process::exit(0)
            }
            "-V" => {
                println!("{}", p::VERSION_CODE);
                std::process::exit(0)
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0)
            }
            "--" => positional_only = true,
            // A cluster of the value-less short options, e.g. -lp.
            c if c.len() > 2 && !c.starts_with("--") && c[1..].chars().all(|ch| matches!(ch, 'l' | 'p' | 'm' | 'M')) => {
                for ch in c[1..].chars() {
                    match ch {
                        'l' => o.login = true,
                        'p' | 'm' => o.preserve = true,
                        _ => o.master = true,
                    }
                }
            }
            _ => die(&format!("invalid option: {s}\n{USAGE}")),
        }
    }
    o
}

fn connect() -> io::Result<RawFd> {
    // An enrolled app sees the socket at the projected path (SPEC-0007); `adb shell` reaches the
    // daemon's own path. Anyone else gets an error from both.
    if let Some(path) = std::env::var_os("YASVARA_SU_SOCKET").filter(|_| cfg!(feature = "host-test")) {
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

fn build_request(o: &Opts, interactive: bool, wants_ns: bool) -> Request {
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
    } else if wants_ns {
        flags |= p::RF_HAS_MNTNS_FD;
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

fn main() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    let o = parse_args();
    let conn = match connect() {
        Ok(fd) => fd,
        Err(e) => match e.raw_os_error() {
            Some(libc::ENOENT) | Some(libc::ECONNREFUSED) => die(Reason::Disabled.message()),
            Some(libc::EACCES) => die("permission denied (SELinux)"),
            _ => die(&format!("cannot reach the root daemon: {e}")),
        },
    };

    let (verdict, _) = recv_frame(conn).unwrap_or_else(|e| die(&format!("daemon hung up: {e}")));
    if verdict.kind != p::KIND_VERDICT {
        die("protocol error");
    }
    if !verdict.is_ok() {
        die(Reason::from_u8(verdict.reason).message());
    }
    if verdict.a != p::VERSION as u32 {
        die("version mismatch, reboot");
    }

    let interactive = isatty(0);
    let req = build_request(&o, interactive, verdict.b & p::VF_WANTS_MNTNS != 0);
    let mut fds: Vec<RawFd> = Vec::new();
    if req.has(p::RF_HAS_MNTNS_FD) {
        let ns = unsafe { libc::open(b"/proc/self/ns/mnt\0".as_ptr() as *const libc::c_char, libc::O_RDONLY | libc::O_CLOEXEC) };
        if ns < 0 {
            die(&format!("this grant confines you to your own mount namespace, which cannot be opened here ({}); enroll with the global namespace", io::Error::last_os_error()));
        }
        fds.push(ns);
    }
    if req.has(p::RF_HAS_STDIO_FDS) {
        fds.extend_from_slice(&[0, 1, 2]);
    }
    if let Err(e) = send_request(conn, &req.encode(), &fds) {
        die(&format!("daemon hung up: {e}"));
    }

    let (ack, master) = recv_frame(conn).unwrap_or_else(|e| die(&format!("daemon hung up: {e}")));
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
