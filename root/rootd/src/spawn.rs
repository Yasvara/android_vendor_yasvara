// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Starting a shell without copying the daemon: clone(CLONE_VM | CLONE_VFORK) on a stack of its
//! own, so the cost does not grow with the daemon's mappings, and the SELinux domain set for exec
//! (an exec-time transition; switching in place is refused while memory is shared).
//!
//! The child runs on the daemon's heap while the daemon waits, so it only makes system calls on
//! what [`Plan`] prepared: no allocation, no panic, no lock. A failure before exec is reported
//! over a close-on-exec pipe, which a successful exec closes with nothing written.

use std::ffi::{c_char, c_int, c_void, CString};
use std::io;
use std::os::unix::io::RawFd;

use crate::sys;

const STACK: usize = 64 * 1024;

pub struct Ids {
    pub groups: Vec<libc::gid_t>,
    pub gid: libc::gid_t,
    pub uid: libc::uid_t,
}

pub struct Plan {
    pub path: CString,
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    /// A pty slave: the controlling terminal and all three of stdio.
    pub ctty: Option<RawFd>,
    pub stdio: Option<[RawFd; 3]>,
    /// cgroup.procs files to join; "0" moves the writer.
    pub cgroups: Vec<CString>,
    pub mntns: Option<RawFd>,
    pub umask: libc::mode_t,
    /// None in host tests, which run unprivileged.
    pub ids: Option<Ids>,
    pub cwd: Option<CString>,
    pub exec_con: Option<CString>,
}

#[derive(Debug)]
pub struct Failure {
    pub stage: &'static str,
    pub errno: i32,
}

impl Failure {
    /// What the shell would have printed: `su: <stage>: <error>`, the path for a failed exec.
    pub fn message(&self, plan: &Plan) -> String {
        let what = if self.stage == "exec" { plan.path.to_string_lossy().into_owned() } else { self.stage.to_string() };
        format!("su: {what}: {}\n", io::Error::from_raw_os_error(self.errno))
    }

    /// The exit status a forked shell would have had.
    pub fn code(&self) -> i32 {
        if self.stage == "exec" && self.errno == libc::ENOENT { 127 } else { 126 }
    }
}

const STAGES: [&str; 9] = ["setsid", "TIOCSCTTY", "dup2", "setns", "setgroups", "setresgid", "setresuid", "setexeccon", "exec"];

struct Child<'a> {
    plan: &'a Plan,
    argv: &'a [*const c_char],
    envp: &'a [*const c_char],
    err_w: RawFd,
}

/// Returns once the shell has exec'd (or failed to); the daemon is suspended until then.
pub fn spawn(plan: &Plan) -> Result<libc::pid_t, Failure> {
    let argv: Vec<*const c_char> = plan.argv.iter().map(|a| a.as_ptr()).chain(Some(std::ptr::null())).collect();
    let envp: Vec<*const c_char> = plan.envp.iter().map(|e| e.as_ptr()).chain(Some(std::ptr::null())).collect();
    let mut pipe = [-1 as RawFd; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(Failure { stage: "pipe", errno: errno() });
    }
    let mut stack = vec![0u8; STACK];
    let child = Child { plan, argv: &argv, envp: &envp, err_w: pipe[1] };
    let pid = unsafe {
        libc::clone(
            run,
            stack.as_mut_ptr().add(STACK) as *mut c_void,
            libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD,
            &child as *const Child as *mut c_void,
        )
    };
    let clone_errno = errno();
    sys::close(pipe[1]);
    if pid < 0 {
        sys::close(pipe[0]);
        return Err(Failure { stage: "clone", errno: clone_errno });
    }
    let mut report = [0u8; 5];
    let n = unsafe { libc::read(pipe[0], report.as_mut_ptr() as *mut c_void, report.len()) };
    sys::close(pipe[0]);
    if n == report.len() as isize {
        // It has exited (vfork returned and it did not exec): reap it here, nobody tracks it.
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        let stage = STAGES.get(report[0] as usize).copied().unwrap_or("spawn");
        return Err(Failure { stage, errno: i32::from_le_bytes([report[1], report[2], report[3], report[4]]) });
    }
    Ok(pid)
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// In the child: report the stage that failed and exit.
fn fail(c: &Child, stage: u8) -> ! {
    let e = errno().to_le_bytes();
    let report = [stage, e[0], e[1], e[2], e[3]];
    unsafe {
        libc::write(c.err_w, report.as_ptr() as *const c_void, report.len());
        libc::_exit(127)
    }
}

/// Best effort, like the forked path: a cgroup or oom_score_adj that cannot be written is not
/// worth refusing the shell for.
unsafe fn write_file(path: *const c_char, bytes: &[u8]) {
    let fd = libc::open(path, libc::O_WRONLY | libc::O_CLOEXEC);
    if fd >= 0 {
        libc::write(fd, bytes.as_ptr() as *const c_void, bytes.len());
        libc::close(fd);
    }
}

extern "C" fn run(arg: *mut c_void) -> c_int {
    // SAFETY: `arg` is the `Child` on the stack of `spawn`, which is suspended until this
    // process execs or exits (CLONE_VFORK).
    let c = unsafe { &*(arg as *const Child) };
    let p = c.plan;
    unsafe {
        // The daemon blocks SIGCHLD/SIGTERM and ignores SIGPIPE/SIGHUP; none of that is the shell's.
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
        for sig in [libc::SIGPIPE, libc::SIGHUP, libc::SIGCHLD, libc::SIGTERM] {
            libc::signal(sig, libc::SIG_DFL);
        }
        if libc::setsid() < 0 {
            fail(c, 0);
        }
        // stdio first, so every later failure reaches the caller.
        if let Some(t) = p.ctty {
            if libc::ioctl(t, libc::TIOCSCTTY as _, 0) < 0 {
                fail(c, 1);
            }
            for fd in 0..3 {
                libc::dup2(t, fd);
            }
        } else if let Some(fds) = p.stdio {
            for (to, &fd) in fds.iter().enumerate() {
                if libc::dup2(fd, to as c_int) < 0 {
                    fail(c, 2);
                }
            }
        }
        // The caller's scheduling class, never its lifecycle cgroup.
        for f in &p.cgroups {
            write_file(f.as_ptr(), b"0");
        }
        if let Some(ns) = p.mntns {
            if libc::setns(ns, libc::CLONE_NEWNS) < 0 {
                fail(c, 3);
            }
        }
        if p.ids.is_some() {
            // The daemon is protected from the low-memory killer; a root shell is not.
            write_file(b"/proc/self/oom_score_adj\0".as_ptr() as *const c_char, b"0");
        }
        libc::umask(p.umask);
        if let Some(ids) = &p.ids {
            if libc::setgroups(ids.groups.len() as _, ids.groups.as_ptr()) != 0 {
                fail(c, 4);
            }
            if libc::setresgid(ids.gid, ids.gid, ids.gid) != 0 {
                fail(c, 5);
            }
        }
        // Entered as root, before any drop to another uid (app directories are 0700).
        let entered = p.cwd.as_ref().is_some_and(|d| libc::chdir(d.as_ptr()) == 0);
        if !entered {
            libc::chdir(b"/\0".as_ptr() as *const c_char);
        }
        if let Some(ids) = &p.ids {
            if ids.uid != 0 && libc::setresuid(ids.uid, ids.uid, ids.uid) != 0 {
                fail(c, 6);
            }
        }
        if let Some(con) = &p.exec_con {
            let fd = libc::open(b"/proc/self/attr/exec\0".as_ptr() as *const c_char, libc::O_WRONLY | libc::O_CLOEXEC);
            let bytes = con.as_bytes_with_nul();
            if fd < 0 || libc::write(fd, bytes.as_ptr() as *const c_void, bytes.len()) < 0 {
                fail(c, 7);
            }
            libc::close(fd);
        }
        libc::execve(p.path.as_ptr(), c.argv.as_ptr(), c.envp.as_ptr());
    }
    fail(c, 8)
}
