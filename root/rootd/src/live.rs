// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Sessions the main loop runs itself: no supervisor process, the shell spawned straight from the
//! daemon. All of their state is a connection in the epoll set and a child the SIGCHLD loop
//! reaps; the caller going away is an EOF on the connection, answered with SIGHUP and, after the
//! grace period, SIGKILL.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::time::Instant;

use yasvara_root_proto::{Frame, Reason, RF_INTERACTIVE};

use crate::session::{self, Admitted, Caller, GrantView, HUP_GRACE};
use crate::{spawn, sys, Config};

/// epoll tokens of session connections carry this tag above the fd.
pub const TOKEN_TAG: u64 = 1 << 32;

struct Live {
    conn: RawFd,
    caller: Caller,
    started: Instant,
    /// The caller hung up: SIGHUP sent at this time, SIGKILL due after the grace period.
    hup_at: Option<Instant>,
    killed: bool,
}

#[derive(Default)]
pub struct Lives {
    by_pid: HashMap<libc::pid_t, Live>,
    by_conn: HashMap<RawFd, libc::pid_t>,
}

impl Lives {
    pub fn conns(&self) -> impl Iterator<Item = RawFd> + '_ {
        self.by_conn.keys().copied()
    }

    /// Spawns the shell and answers the caller. Returns the shell's pid; the connection (and
    /// every descriptor that came with the request) is the daemon's to forget either way.
    pub fn start(
        &mut self,
        ep: RawFd,
        conn: RawFd,
        caller: Caller,
        grant: &GrantView,
        adm: Admitted,
        fds: Vec<RawFd>,
        cfg: &Config,
    ) -> Option<libc::pid_t> {
        let pty = if adm.req.has(RF_INTERACTIVE) {
            match sys::open_pty() {
                Ok(pair) => Some(pair),
                Err(_) => {
                    let _ = session::refuse(conn, Reason::Spawn, &fds);
                    sys::close(conn);
                    return None;
                }
            }
        } else {
            None
        };
        if let Some((m, _)) = pty {
            sys::set_winsize(m, adm.req.rows, adm.req.cols);
        }
        let plan = session::plan(&adm, pty.map(|p| p.1), adm.stdio, cfg);
        let spawned = spawn::spawn(&plan);
        if let Err(f) = &spawned {
            // What the shell's stderr would have shown; the same exit status follows the ack.
            session::report(f, &plan, pty.map(|p| p.1).or(adm.stdio.map(|s| s[2])));
        }
        fds.iter().for_each(|&f| sys::close(f));
        let pid = spawned.as_ref().copied().unwrap_or(0);
        let ack = Frame::ack(true, Reason::None, pid as u32, pty.is_some()).encode();
        let acked = match pty {
            Some((m, s)) => {
                sys::close(s);
                let r = sys::send_with_fds(conn, &ack, &[m]).map(|_| ());
                sys::close(m);
                r
            }
            None => sys::send_frame_nowait(conn, &ack),
        };
        let started = Instant::now();
        let pid = match spawned {
            Ok(pid) => pid,
            Err(f) => {
                let _ = sys::send_frame_nowait(conn, &Frame::exit(f.code(), false).encode());
                sys::close(conn);
                session::audit_exec(cfg, &caller, grant, adm.tier, &adm.req);
                session::audit_exit(cfg, &caller, f.code(), 0, started);
                return None;
            }
        };
        if acked.is_err() {
            // The caller is already gone: the shell must not outlive it as an orphan.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
        }
        session::audit_exec(cfg, &caller, grant, adm.tier, &adm.req);
        let mut ev = libc::epoll_event { events: (libc::EPOLLIN | libc::EPOLLRDHUP) as u32, u64: TOKEN_TAG | conn as u64 };
        unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, conn, &mut ev) };
        self.by_conn.insert(conn, pid);
        self.by_pid.insert(pid, Live { conn, caller, started, hup_at: None, killed: false });
        Some(pid)
    }

    /// The connection is readable: data from a client that should be silent is dropped, EOF or
    /// an error means it is gone.
    pub fn on_conn(&mut self, ep: RawFd, conn: RawFd) {
        let Some(&pid) = self.by_conn.get(&conn) else { return };
        let mut b = [0u8; 64];
        let r = unsafe { libc::recv(conn, b.as_mut_ptr() as *mut libc::c_void, b.len(), libc::MSG_DONTWAIT) };
        if r > 0 || (r < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock) {
            return;
        }
        unsafe {
            libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, conn, std::ptr::null_mut());
            libc::kill(-pid, libc::SIGHUP);
            libc::kill(pid, libc::SIGHUP);
            libc::kill(pid, libc::SIGCONT);
        }
        if let Some(l) = self.by_pid.get_mut(&pid) {
            l.hup_at = Some(Instant::now());
        }
    }

    /// Milliseconds until the next SIGKILL is due, -1 for none (an epoll_wait timeout).
    pub fn timeout(&self) -> i32 {
        self.by_pid
            .values()
            .filter(|l| !l.killed)
            .filter_map(|l| l.hup_at)
            .map(|t| HUP_GRACE.saturating_sub(t.elapsed()).as_millis().max(1) as i32)
            .min()
            .unwrap_or(-1)
    }

    pub fn on_timer(&mut self) {
        for (&pid, l) in self.by_pid.iter_mut() {
            if !l.killed && l.hup_at.is_some_and(|t| t.elapsed() >= HUP_GRACE) {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                    libc::kill(pid, libc::SIGKILL);
                }
                l.killed = true;
            }
        }
    }

    /// A child was reaped. False if it was not one of these sessions.
    pub fn on_exit(&mut self, ep: RawFd, pid: libc::pid_t, status: libc::c_int, cfg: &Config) -> bool {
        let Some(l) = self.by_pid.remove(&pid) else { return false };
        self.by_conn.remove(&l.conn);
        let (code, signalled) = session::exit_code(status).unwrap_or((1, false));
        if l.hup_at.is_none() {
            let _ = sys::send_frame_nowait(l.conn, &Frame::exit(code, signalled).encode());
            unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, l.conn, std::ptr::null_mut()) };
        }
        sys::close(l.conn);
        session::audit_exit(cfg, &l.caller, code, pid, l.started);
        true
    }
}
