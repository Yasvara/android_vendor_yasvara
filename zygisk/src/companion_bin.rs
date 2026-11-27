// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Resident Zygisk companion. Loads the module `.so` once, runs
//! `zygisk_companion_entry(fd)` for each connection, and exits after 60 s idle.
//!
//! argv: `<lib> <first-client-fd> <control-fd>`
//! Later client fds arrive on the control socket as `SCM_RIGHTS`.

use std::ffi::{c_int, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const IDLE_MS: i32 = 60_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        std::process::exit(2);
    }
    let Ok(lib_c) = CString::new(args[1].as_str()) else { std::process::exit(2) };
    let Ok(client) = args[2].parse::<c_int>() else { std::process::exit(2) };
    let Ok(control) = args[3].parse::<c_int>() else { std::process::exit(2) };

    unsafe {
        let handle = libc::dlopen(lib_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            libc::close(client);
            libc::close(control);
            std::process::exit(1);
        }
        let sym = CString::new("zygisk_companion_entry").unwrap();
        let fptr = libc::dlsym(handle, sym.as_ptr());
        if fptr.is_null() {
            libc::dlclose(handle);
            libc::close(client);
            libc::close(control);
            std::process::exit(1);
        }
        type CompanionFn = unsafe extern "C" fn(c_int);
        let entry: CompanionFn = std::mem::transmute(fptr);
        let inflight = Arc::new(AtomicUsize::new(0));
        let wake_fd = libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK);
        dispatch(entry, client, &inflight, wake_fd);
        loop {
            let wait = if inflight.load(Ordering::SeqCst) == 0 {
                IDLE_MS
            } else if wake_fd >= 0 {
                -1
            } else {
                IDLE_MS
            };
            match recv_client(control, wake_fd, wait) {
                Recv::Fd(fd) => dispatch(entry, fd, &inflight, wake_fd),
                // rootd went away: no new clients can arrive; finish the ones in flight.
                Recv::Closed => break,
                // Last inflight worker finished (or EINTR): re-evaluate wait so IDLE_MS begins.
                Recv::Wake => {}
                Recv::Timeout if inflight.load(Ordering::SeqCst) == 0 => break,
                Recv::Timeout => {}
            }
        }
        // Idle exit: refuse new fds first (rootd's sendmsg then fails with EPIPE and it spawns a
        // fresh companion), then serve any that were already queued.
        libc::shutdown(control, libc::SHUT_RD);
        while let Recv::Fd(fd) = recv_client(control, -1, 0) {
            dispatch(entry, fd, &inflight, wake_fd);
        }
        while inflight.load(Ordering::SeqCst) != 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if wake_fd >= 0 {
            libc::close(wake_fd);
        }
        libc::close(control);
        libc::dlclose(handle);
    }
}

fn notify_idle(wake_fd: c_int) {
    if wake_fd >= 0 {
        let one: u64 = 1;
        unsafe {
            let _ = libc::write(
                wake_fd,
                &one as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }
    }
}

fn dispatch(
    entry: unsafe extern "C" fn(c_int),
    fd: c_int,
    inflight: &Arc<AtomicUsize>,
    wake_fd: c_int,
) {
    inflight.fetch_add(1, Ordering::SeqCst);
    let count = Arc::clone(inflight);
    if std::thread::Builder::new()
        .spawn(move || {
            unsafe { entry(fd) };
            unsafe { libc::close(fd) };
            if count.fetch_sub(1, Ordering::SeqCst) == 1 {
                notify_idle(wake_fd);
            }
        })
        .is_err()
    {
        unsafe { libc::close(fd) };
        if inflight.fetch_sub(1, Ordering::SeqCst) == 1 {
            notify_idle(wake_fd);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Recv {
    Fd(c_int),
    /// Worker transitioned inflight 1 -> 0 (via eventfd) or EINTR; restart poll with updated wait.
    Wake,
    /// Timed out, or a message without an fd.
    Timeout,
    /// Peer closed or the socket failed.
    Closed,
}

fn recv_client(control: c_int, wake_fd: c_int, timeout_ms: i32) -> Recv {
    unsafe {
        let mut pfds = [
            libc::pollfd { fd: control, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: wake_fd, events: libc::POLLIN, revents: 0 },
        ];
        let nfds: libc::nfds_t = if wake_fd >= 0 { 2 } else { 1 };
        let rc = libc::poll(pfds.as_mut_ptr(), nfds, timeout_ms);
        if rc == 0 {
            return Recv::Timeout;
        }
        if rc < 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                Recv::Wake
            } else {
                Recv::Closed
            };
        }
        if wake_fd >= 0 && (pfds[1].revents & libc::POLLIN) != 0 {
            let mut val: u64 = 0;
            let _ = libc::read(
                wake_fd,
                &mut val as *mut u64 as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
            if pfds[0].revents == 0 {
                return Recv::Wake;
            }
        }
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let mut cmsg = [0u8; 64];
        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
        hdr.msg_controllen = cmsg.len() as _;
        let n = libc::recvmsg(control, &mut hdr, libc::MSG_CMSG_CLOEXEC);
        if n <= 0 {
            return Recv::Closed;
        }
        let mut c = libc::CMSG_FIRSTHDR(&hdr);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                return Recv::Fd(std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const c_int));
            }
            c = libc::CMSG_NXTHDR(&hdr, c);
        }
        Recv::Wake
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eventfd_wakes_infinite_poll_when_last_worker_finishes() {
        unsafe {
            let mut sv = [-1; 2];
            assert_eq!(libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()), 0);
            let wake_fd = libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK);
            assert!(wake_fd >= 0);

            let inflight = Arc::new(AtomicUsize::new(1));
            let count = Arc::clone(&inflight);
            let t = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(40));
                if count.fetch_sub(1, Ordering::SeqCst) == 1 {
                    notify_idle(wake_fd);
                }
            });

            // Infinite poll must wake immediately when worker finishes (BUG-Z1 regression).
            assert_eq!(recv_client(sv[0], wake_fd, -1), Recv::Wake);
            assert_eq!(inflight.load(Ordering::SeqCst), 0);
            t.join().unwrap();

            // Next poll with finite timeout expires cleanly instead of hanging.
            assert_eq!(recv_client(sv[0], wake_fd, 30), Recv::Timeout);

            libc::close(wake_fd);
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }
}
