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
        dispatch(entry, client, &inflight);
        loop {
            let wait = if inflight.load(Ordering::SeqCst) == 0 { IDLE_MS } else { -1 };
            match recv_client(control, wait) {
                Recv::Fd(fd) => dispatch(entry, fd, &inflight),
                // rootd went away: no new clients can arrive; finish the ones in flight.
                Recv::Closed => break,
                Recv::Nothing if inflight.load(Ordering::SeqCst) == 0 => break,
                Recv::Nothing => {}
            }
        }
        // Idle exit: refuse new fds first (rootd's sendmsg then fails with EPIPE and it spawns a
        // fresh companion), then serve any that were already queued.
        libc::shutdown(control, libc::SHUT_RD);
        while let Recv::Fd(fd) = recv_client(control, 0) {
            dispatch(entry, fd, &inflight);
        }
        while inflight.load(Ordering::SeqCst) != 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        libc::close(control);
        libc::dlclose(handle);
    }
}

fn dispatch(entry: unsafe extern "C" fn(c_int), fd: c_int, inflight: &Arc<AtomicUsize>) {
    inflight.fetch_add(1, Ordering::SeqCst);
    let count = Arc::clone(inflight);
    if std::thread::Builder::new()
        .spawn(move || {
            unsafe { entry(fd) };
            unsafe { libc::close(fd) };
            count.fetch_sub(1, Ordering::SeqCst);
        })
        .is_err()
    {
        unsafe { libc::close(fd) };
        inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

enum Recv {
    Fd(c_int),
    /// Timed out, or a message without an fd.
    Nothing,
    /// Peer closed or the socket failed.
    Closed,
}

fn recv_client(control: c_int, timeout_ms: i32) -> Recv {
    unsafe {
        let mut pfd = libc::pollfd { fd: control, events: libc::POLLIN, revents: 0 };
        let rc = libc::poll(&mut pfd, 1, timeout_ms);
        if rc == 0 {
            return Recv::Nothing;
        }
        if rc < 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { Recv::Nothing } else { Recv::Closed };
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
        Recv::Nothing
    }
}
