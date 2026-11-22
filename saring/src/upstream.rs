// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Persistent pipelined DNS-over-TLS (DoT) upstream multiplexer.
//!
//! Eliminates all five stock AOSP `DnsTlsSocket` bottlenecks:
//! 1. Sets `TCP_NODELAY = 1` so `A` + `AAAA` pairs never stall on Nagle's algorithm.
//! 2. Coalesces all queued queries into one `SSL_write` frame immediately upon wakeup.
//! 3. Keeps the TLS connection warm for `300 s` with `45 s` TCP keepalives (vs AOSP `20 s`).
//! 4. Shares one `OnceLock` `SSL_CTX` loaded once per `netd` lifetime with session resumption.
//! 5. Applies `SO_MARK = mark` so Android per-network and VPN routing rules stay intact.
//!
//! Framing, coalescing and out-of-order QID demultiplexing compile everywhere and are unit-tested
//! on the host. BoringSSL socket I/O is gated behind `#[cfg(feature = "netd")]` so `libsaring_jni`
//! (Laras) and host tests need no `libssl`.

use std::collections::VecDeque;

pub const DNS_MODE_SYSTEM: u8 = 0;
pub const DNS_MODE_CLOUDFLARE: u8 = 1;
pub const DNS_MODE_GOOGLE: u8 = 2;

pub const MAX_COALESCE_BYTES: usize = 4096;
pub const WARM_IDLE_TIMEOUT_MS: i32 = 300_000;
pub const QUERY_TIMEOUT_MS: u64 = 3_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: [u8; 4],
    pub port: u16,
    pub sni: &'static str,
}

/// Returns `(primary, secondary)` DoT endpoints routed in Singapore/Jakarta on Indonesian links.
#[inline]
pub fn endpoints_for(mode: u8) -> (Endpoint, Endpoint) {
    match mode {
        DNS_MODE_GOOGLE => (
            Endpoint { ip: [8, 8, 8, 8], port: 853, sni: "dns.google" },
            Endpoint { ip: [8, 8, 4, 4], port: 853, sni: "dns.google" },
        ),
        // Default encrypted upstream (Cloudflare: 48 ms TCP on Indosat).
        _ => (
            Endpoint { ip: [1, 1, 1, 1], port: 853, sni: "cloudflare-dns.com" },
            Endpoint { ip: [1, 0, 0, 1], port: 853, sni: "cloudflare-dns.com" },
        ),
    }
}

/// Coalesces as many pending queries as fit in `MAX_COALESCE_BYTES` into `out`, framing each as
/// `[len_be: u16][wire_qid_be: u16][query[2..]]` for a single `SSL_write` record.
pub fn coalesce_frames<T, F>(queue: &mut VecDeque<T>, out: &mut Vec<u8>, mut view: F) -> usize
where
    F: FnMut(&T) -> (u16, &[u8]),
{
    out.clear();
    let mut taken = 0usize;
    while let Some(front) = queue.front() {
        let (wire_qid, pkt) = view(front);
        if pkt.len() < 12 || pkt.len() > 65_535 {
            queue.pop_front();
            continue;
        }
        let frame_len = 2 + pkt.len();
        if taken > 0 && out.len() + frame_len > MAX_COALESCE_BYTES {
            break;
        }
        out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        out.extend_from_slice(&wire_qid.to_be_bytes());
        out.extend_from_slice(&pkt[2..]);
        queue.pop_front();
        taken += 1;
    }
    taken
}

/// Incremental RFC 1035 TCP/TLS length-prefixed DNS response framer.
#[derive(Default)]
pub struct StreamDemux {
    buf: Vec<u8>,
    read_pos: usize,
}

impl StreamDemux {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(4096), read_pos: 0 }
    }

    pub fn push(&mut self, data: &[u8]) {
        if self.read_pos > 0 && self.read_pos == self.buf.len() {
            self.buf.clear();
            self.read_pos = 0;
        } else if self.read_pos > 2048 {
            self.buf.drain(..self.read_pos);
            self.read_pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Returns the next complete `(wire_qid, dns_packet)` if buffered.
    pub fn next_frame(&mut self) -> Option<(u16, &[u8])> {
        let avail = self.buf.len().saturating_sub(self.read_pos);
        if avail < 2 {
            return None;
        }
        let start = self.read_pos;
        let msg_len = u16::from_be_bytes([self.buf[start], self.buf[start + 1]]) as usize;
        if msg_len < 12 {
            // Invalid length; drop stream state so caller reconnects.
            self.buf.clear();
            self.read_pos = 0;
            return None;
        }
        if avail < 2 + msg_len {
            return None;
        }
        let body_start = start + 2;
        let body_end = body_start + msg_len;
        self.read_pos = body_end;
        let qid = u16::from_be_bytes([self.buf[body_start], self.buf[body_start + 1]]);
        Some((qid, &self.buf[body_start..body_end]))
    }

    pub fn reset(&mut self) {
        self.buf.clear();
        self.read_pos = 0;
    }
}

/// Callback target for background Serve-Stale refresh completions.
#[derive(Clone, Copy)]
pub struct RefreshMeta {
    pub netid: u32,
    pub cache_key: u64,
    pub allow_safesearch: bool,
    pub local_name: bool,
}

#[cfg(all(target_os = "android", feature = "netd"))]
pub(crate) fn https_request(ip: [u8; 4], host_nul: &[u8], req: &[u8]) -> Option<Vec<u8>> {
    dot::https_request(ip, host_nul, req)
}

#[cfg(feature = "netd")]
mod dot {
    use super::*;
    use crate::cache::DnsCache;
    use crate::dns::{inspect_answer, AnswerVerdict};
    use std::collections::HashMap;
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
    use std::sync::{Arc, Condvar, Mutex, OnceLock};
    use std::thread;
    use std::time::{Duration, Instant};

    // --- Linux & BoringSSL ABI constants (verified against bionic/libc & external/boringssl) ---
    const AF_INET: c_int = 2;
    const SOCK_STREAM: c_int = 1;
    const SOCK_NONBLOCK: c_int = 0o4000;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const IPPROTO_TCP: c_int = 6;

    const SOL_SOCKET: c_int = 1;
    const SO_KEEPALIVE: c_int = 9;
    const SO_MARK: c_int = 36;
    const SO_ERROR: c_int = 4;

    const TCP_NODELAY: c_int = 1;
    const TCP_MAXSEG: c_int = 2;
    const TCP_KEEPIDLE: c_int = 4;
    const TCP_KEEPINTVL: c_int = 5;
    const TCP_KEEPCNT: c_int = 6;
    const TCP_FASTOPEN_CONNECT: c_int = 30;

    const EFD_NONBLOCK: c_int = 0o4000;
    const EFD_CLOEXEC: c_int = 0o2000000;

    const POLLIN: i16 = 0x0001;
    const POLLOUT: i16 = 0x0004;
    const POLLERR: i16 = 0x0008;
    const POLLHUP: i16 = 0x0010;

    const EINPROGRESS: c_int = 115;

    const TLS1_2_VERSION: u16 = 0x0303;
    const SSL_MODE_ENABLE_FALSE_START: u32 = 0x0000_0080;
    const SSL_SESS_CACHE_CLIENT: c_int = 0x0001;
    const SSL_VERIFY_PEER: c_int = 0x01;
    const SSL_ERROR_WANT_READ: c_int = 2;
    const SSL_ERROR_WANT_WRITE: c_int = 3;
    const SSL_ERROR_EARLY_DATA_REJECTED: c_int = 15;

    #[repr(C)]
    struct SockAddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    enum SslMethod {}
    enum SslCtx {}
    enum Ssl {}
    enum SslSession {}

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn connect(fd: c_int, addr: *const SockAddrIn, len: u32) -> c_int;
        fn setsockopt(fd: c_int, level: c_int, optname: c_int, optval: *const c_void, optlen: u32)
            -> c_int;
        fn getsockopt(fd: c_int, level: c_int, optname: c_int, optval: *mut c_void, optlen: *mut u32)
            -> c_int;
        fn close(fd: c_int) -> c_int;
        fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
        fn eventfd(initval: u32, flags: c_int) -> c_int;
        fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
        fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;

        fn TLS_client_method() -> *const SslMethod;
        fn SSL_CTX_new(method: *const SslMethod) -> *mut SslCtx;
        fn SSL_CTX_set_min_proto_version(ctx: *mut SslCtx, version: u16) -> c_int;
        fn SSL_CTX_load_verify_locations(
            ctx: *mut SslCtx,
            ca_file: *const c_char,
            ca_dir: *const c_char,
        ) -> c_int;
        fn SSL_CTX_set_mode(ctx: *mut SslCtx, mode: u32) -> u32;
        fn SSL_CTX_set_session_cache_mode(ctx: *mut SslCtx, mode: c_int) -> c_int;
        fn SSL_CTX_sess_set_new_cb(
            ctx: *mut SslCtx,
            cb: extern "C" fn(*mut Ssl, *mut SslSession) -> c_int,
        );
        fn SSL_CTX_set_verify(ctx: *mut SslCtx, mode: c_int, cb: *const c_void);

        fn SSL_new(ctx: *mut SslCtx) -> *mut Ssl;
        fn SSL_free(ssl: *mut Ssl);
        fn SSL_set_fd(ssl: *mut Ssl, fd: c_int) -> c_int;
        fn SSL_set_ex_data(ssl: *mut Ssl, idx: c_int, data: *mut c_void) -> c_int;
        fn SSL_get_ex_data(ssl: *const Ssl, idx: c_int) -> *mut c_void;
        fn SSL_set_tlsext_host_name(ssl: *mut Ssl, name: *const c_char) -> c_int;
        fn SSL_set1_host(ssl: *mut Ssl, hostname: *const c_char) -> c_int;
        fn SSL_set_early_data_enabled(ssl: *mut Ssl, enabled: c_int);
        fn SSL_in_early_data(ssl: *const Ssl) -> c_int;
        fn SSL_reset_early_data_reject(ssl: *mut Ssl);
        fn SSL_connect(ssl: *mut Ssl) -> c_int;
        fn SSL_read(ssl: *mut Ssl, buf: *mut c_void, num: c_int) -> c_int;
        fn SSL_write(ssl: *mut Ssl, buf: *const c_void, num: c_int) -> c_int;
        fn SSL_shutdown(ssl: *mut Ssl) -> c_int;
        fn SSL_get_error(ssl: *const Ssl, ret: c_int) -> c_int;
        fn SSL_pending(ssl: *const Ssl) -> c_int;
        fn SSL_set_session(ssl: *mut Ssl, session: *mut SslSession) -> c_int;
        fn SSL_SESSION_free(session: *mut SslSession);
    }

    /// Global IP-keyed TLS 1.3 NewSessionTicket cache populated asynchronously via
    /// `SSL_CTX_sess_set_new_cb` (bounded to 8 DoT endpoints).
    static SESSION_CACHE: Mutex<Vec<([u8; 4], SavedSession)>> = Mutex::new(Vec::new());

    extern "C" fn on_new_session(ssl: *mut Ssl, session: *mut SslSession) -> c_int {
        if ssl.is_null() || session.is_null() {
            return 0;
        }
        // SAFETY: reading integer IP tag placed via SSL_set_ex_data on DoT sockets only.
        let tag = unsafe { SSL_get_ex_data(ssl, 0) } as usize as u32;
        if tag == 0 {
            return 0;
        }
        let ip = tag.to_ne_bytes();
        if let Ok(mut map) = SESSION_CACHE.lock() {
            if let Some(slot) = map.iter_mut().find(|(k, _)| *k == ip) {
                slot.1 = SavedSession(session);
                return 1;
            }
            if map.len() < 8 {
                map.push((ip, SavedSession(session)));
                return 1;
            }
        }
        0
    }

    fn clear_cached_session(ip: [u8; 4]) {
        if let Ok(mut map) = SESSION_CACHE.lock() {
            map.retain(|(k, _)| *k != ip);
        }
    }

    struct SharedCtx(*mut SslCtx);
    // SAFETY: BoringSSL SSL_CTX is thread-safe once initialized read-only.
    unsafe impl Send for SharedCtx {}
    unsafe impl Sync for SharedCtx {}

    fn shared_ssl_ctx() -> Option<*mut SslCtx> {
        static CTX: OnceLock<Option<SharedCtx>> = OnceLock::new();
        let entry = CTX.get_or_init(|| {
            // SAFETY: BoringSSL init with valid static NUL-terminated CA directory path.
            unsafe {
                let method = TLS_client_method();
                if method.is_null() {
                    return None;
                }
                let ctx = SSL_CTX_new(method);
                if ctx.is_null() {
                    return None;
                }
                let _ = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
                let _ = SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_FALSE_START);
                let _ = SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
                SSL_CTX_sess_set_new_cb(ctx, on_new_session);
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, core::ptr::null());
                let ca_dir = b"/system/etc/security/cacerts\0".as_ptr().cast::<c_char>();
                if SSL_CTX_load_verify_locations(ctx, core::ptr::null(), ca_dir) != 1 {
                    return None;
                }
                Some(SharedCtx(ctx))
            }
        });
        entry.as_ref().map(|c| c.0)
    }

    #[cfg(target_os = "android")]
    pub(crate) fn https_request(ip: [u8; 4], host_nul: &[u8], req: &[u8]) -> Option<Vec<u8>> {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
        use std::os::unix::io::AsRawFd;

        let ctx = shared_ssl_ctx()?;
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), 443));
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(6)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(6)));

        // SAFETY: BoringSSL calls on owned SSL handle with verified NUL-terminated host.
        unsafe {
            let ssl = SSL_new(ctx);
            if ssl.is_null() {
                return None;
            }
            let ok = SSL_set_fd(ssl, stream.as_raw_fd()) == 1
                && SSL_set_tlsext_host_name(ssl, host_nul.as_ptr() as *const c_char) == 1
                && SSL_set1_host(ssl, host_nul.as_ptr() as *const c_char) == 1
                && SSL_connect(ssl) == 1;
            let mut resp = Vec::with_capacity(4096);
            if ok {
                let mut written = 0usize;
                while written < req.len() {
                    let n = SSL_write(
                        ssl,
                        req[written..].as_ptr() as *const c_void,
                        (req.len() - written) as c_int,
                    );
                    if n <= 0 {
                        break;
                    }
                    written += n as usize;
                }
                if written == req.len() {
                    let mut buf = [0u8; 1024];
                    loop {
                        let n = SSL_read(ssl, buf.as_mut_ptr() as *mut c_void, buf.len() as c_int);
                        if n <= 0 {
                            break;
                        }
                        resp.extend_from_slice(&buf[..n as usize]);
                        if resp.len() > 16384 {
                            break;
                        }
                    }
                }
            }
            let _ = SSL_shutdown(ssl);
            SSL_free(ssl);
            if resp.is_empty() {
                None
            } else {
                Some(resp)
            }
        }
    }

    struct SavedSession(*mut SslSession);
    // SAFETY: BoringSSL SSL_SESSION is immutable and reference-counted.
    unsafe impl Send for SavedSession {}

    impl Drop for SavedSession {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: owned ref from SSL_get1_session.
                unsafe { SSL_SESSION_free(self.0) };
            }
        }
    }

    struct TlsConn {
        fd: c_int,
        ssl: *mut Ssl,
    }

    impl Drop for TlsConn {
        fn drop(&mut self) {
            // SAFETY: valid owned ssl and fd.
            unsafe {
                if !self.ssl.is_null() {
                    let _ = SSL_shutdown(self.ssl);
                    SSL_free(self.ssl);
                }
                if self.fd >= 0 {
                    let _ = close(self.fd);
                }
            }
        }
    }

    fn set_int_opt(fd: c_int, level: c_int, opt: c_int, val: c_int) {
        // SAFETY: passing valid pointer and size of c_int.
        unsafe {
            let _ = setsockopt(
                fd,
                level,
                opt,
                (&val as *const c_int).cast::<c_void>(),
                core::mem::size_of::<c_int>() as u32,
            );
        }
    }

    fn wait_fd(fd: c_int, events: i16, timeout_ms: c_int) -> bool {
        let mut pfd = PollFd { fd, events, revents: 0 };
        // SAFETY: valid 1-element PollFd array.
        let r = unsafe { poll(&mut pfd, 1, timeout_ms) };
        r > 0 && (pfd.revents & (POLLERR | POLLHUP)) == 0 && (pfd.revents & events) != 0
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum WriteRes {
        Ok,
        EarlyDataRejected,
        Failed,
    }

    fn drive_handshake(conn: &TlsConn) -> bool {
        let deadline = Instant::now() + Duration::from_millis(2500);
        loop {
            // SAFETY: conn.ssl is valid.
            let ret = unsafe { SSL_connect(conn.ssl) };
            if ret == 1 {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now()).as_millis() as c_int;
            if left <= 0 {
                return false;
            }
            let ssl_err = unsafe { SSL_get_error(conn.ssl, ret) };
            match ssl_err {
                SSL_ERROR_WANT_READ => {
                    if !wait_fd(conn.fd, POLLIN, left) {
                        return false;
                    }
                }
                SSL_ERROR_WANT_WRITE => {
                    if !wait_fd(conn.fd, POLLOUT, left) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
    }

    fn connect_tls(ep: Endpoint, mark: u32, allow_early_data: bool) -> Option<TlsConn> {
        let ctx = shared_ssl_ctx()?;
        // SAFETY: POSIX socket creation and configuration.
        let fd = unsafe { socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP) };
        if fd < 0 {
            return None;
        }
        if mark != 0 {
            set_int_opt(fd, SOL_SOCKET, SO_MARK, mark as c_int);
        }
        // Key latency win: disable Nagle so A + AAAA / coalesced records leave immediately.
        set_int_opt(fd, IPPROTO_TCP, TCP_NODELAY, 1);
        set_int_opt(fd, IPPROTO_TCP, TCP_MAXSEG, 1212);
        set_int_opt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1);
        set_int_opt(fd, SOL_SOCKET, SO_KEEPALIVE, 1);
        set_int_opt(fd, IPPROTO_TCP, TCP_KEEPIDLE, 45);
        set_int_opt(fd, IPPROTO_TCP, TCP_KEEPINTVL, 10);
        set_int_opt(fd, IPPROTO_TCP, TCP_KEEPCNT, 3);

        let addr = SockAddrIn {
            sin_family: AF_INET as u16,
            sin_port: ep.port.to_be(),
            sin_addr: u32::from_ne_bytes(ep.ip),
            sin_zero: [0; 8],
        };
        // SAFETY: valid SockAddrIn pointer and size.
        let rc = unsafe { connect(fd, &addr, core::mem::size_of::<SockAddrIn>() as u32) };
        if rc != 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err != EINPROGRESS {
                // SAFETY: closing failed socket.
                unsafe { close(fd) };
                return None;
            }
            if !wait_fd(fd, POLLOUT, 2500) {
                unsafe { close(fd) };
                return None;
            }
            let mut so_err: c_int = 0;
            let mut optlen = core::mem::size_of::<c_int>() as u32;
            unsafe {
                let _ = getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    (&mut so_err as *mut c_int).cast::<c_void>(),
                    &mut optlen,
                );
            }
            if so_err != 0 {
                unsafe { close(fd) };
                return None;
            }
        }

        let sni = CString::new(ep.sni).ok()?;
        let ip_tag = u32::from_ne_bytes(ep.ip) as usize as *mut c_void;
        // SAFETY: ctx is initialized and fd is a valid open TCP socket.
        let ssl = unsafe {
            let ssl = SSL_new(ctx);
            if ssl.is_null() {
                close(fd);
                return None;
            }
            if SSL_set_fd(ssl, fd) != 1
                || SSL_set_tlsext_host_name(ssl, sni.as_ptr()) != 1
                || SSL_set1_host(ssl, sni.as_ptr()) != 1
            {
                SSL_free(ssl);
                close(fd);
                return None;
            }
            let _ = SSL_set_ex_data(ssl, 0, ip_tag);
            if allow_early_data {
                if let Ok(map) = SESSION_CACHE.lock() {
                    if let Some((_, cached)) = map.iter().find(|(k, _)| *k == ep.ip) {
                        if SSL_set_session(ssl, cached.0) == 1 {
                            SSL_set_early_data_enabled(ssl, 1);
                        }
                    }
                }
            }
            ssl
        };

        let conn = TlsConn { fd, ssl };
        if drive_handshake(&conn) {
            Some(conn)
        } else {
            None
        }
    }

    fn ssl_write_all(conn: &TlsConn, mut data: &[u8]) -> WriteRes {
        let deadline = Instant::now() + Duration::from_millis(2000);
        while !data.is_empty() {
            // SAFETY: valid ssl and data pointer.
            let ret = unsafe {
                SSL_write(conn.ssl, data.as_ptr().cast::<c_void>(), data.len() as c_int)
            };
            if ret > 0 {
                data = &data[ret as usize..];
                continue;
            }
            let left = deadline.saturating_duration_since(Instant::now()).as_millis() as c_int;
            if left <= 0 {
                return WriteRes::Failed;
            }
            let err = unsafe { SSL_get_error(conn.ssl, ret) };
            match err {
                SSL_ERROR_WANT_WRITE => {
                    if !wait_fd(conn.fd, POLLOUT, left) {
                        return WriteRes::Failed;
                    }
                }
                SSL_ERROR_WANT_READ => {
                    if !wait_fd(conn.fd, POLLIN, left) {
                        return WriteRes::Failed;
                    }
                }
                SSL_ERROR_EARLY_DATA_REJECTED => return WriteRes::EarlyDataRejected,
                _ => return WriteRes::Failed,
            }
        }
        WriteRes::Ok
    }

    type Waiter = Arc<(Mutex<Option<Option<Vec<u8>>>>, Condvar)>;

    struct Pending {
        wire_qid: u16,
        orig_qid: u16,
        query: Vec<u8>,
        waiter: Option<Waiter>,
        refresh: Option<RefreshMeta>,
        deadline: Instant,
    }

    struct InFlight {
        orig_qid: u16,
        waiter: Option<Waiter>,
        refresh: Option<RefreshMeta>,
        deadline: Instant,
    }

    struct WorkerShared {
        evfd: c_int,
        closed: AtomicBool,
        next_qid: AtomicU16,
        queue: Mutex<VecDeque<Pending>>,
    }

    impl Drop for WorkerShared {
        fn drop(&mut self) {
            if self.evfd >= 0 {
                // SAFETY: closing owned eventfd.
                unsafe { close(self.evfd) };
            }
        }
    }

    impl WorkerShared {
        fn wake(&self) {
            let one: u64 = 1;
            // SAFETY: writing 8-byte counter to valid eventfd.
            unsafe {
                let _ = write(self.evfd, (&one as *const u64).cast::<c_void>(), 8);
            }
        }

        fn drain_evfd(&self) {
            let mut val: u64 = 0;
            // SAFETY: non-blocking read of 8-byte eventfd counter.
            unsafe {
                let _ = read(self.evfd, (&mut val as *mut u64).cast::<c_void>(), 8);
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    struct PoolKey {
        netid: u32,
        mark: u32,
        mode: u8,
    }

    pub struct UpstreamPool {
        workers: Mutex<HashMap<PoolKey, Arc<WorkerShared>>>,
    }

    impl Default for UpstreamPool {
        fn default() -> Self {
            Self::new()
        }
    }

    impl UpstreamPool {
        pub fn new() -> Self {
            Self { workers: Mutex::new(HashMap::new()) }
        }

        fn get_or_spawn(
            &self,
            key: PoolKey,
            cache: Arc<DnsCache>,
            now_fn: fn() -> i64,
        ) -> Option<Arc<WorkerShared>> {
            let mut map = self.workers.lock().ok()?;
            if let Some(w) = map.get(&key) {
                if !w.closed.load(Ordering::Acquire) {
                    return Some(Arc::clone(w));
                }
                map.remove(&key);
            }
            // SAFETY: creating non-blocking eventfd.
            let evfd = unsafe { eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC) };
            if evfd < 0 {
                return None;
            }
            let shared = Arc::new(WorkerShared {
                evfd,
                closed: AtomicBool::new(false),
                next_qid: AtomicU16::new(1),
                queue: Mutex::new(VecDeque::new()),
            });
            let worker_ref = Arc::clone(&shared);
            let spawn_res = thread::Builder::new()
                .name(format!("saring_dot_{}", key.netid))
                .spawn(move || worker_loop(key, worker_ref, cache, now_fn));
            if spawn_res.is_err() {
                shared.closed.store(true, Ordering::Release);
                return None;
            }
            map.insert(key, Arc::clone(&shared));
            Some(shared)
        }

        /// Sends a synchronous query over the coalesced DoT worker for `(netid, mark, mode)`.
        pub fn query(
            &self,
            netid: u32,
            mark: u32,
            mode: u8,
            query: &[u8],
            out: &mut [u8],
            cache: Arc<DnsCache>,
            now_fn: fn() -> i64,
        ) -> Option<usize> {
            if query.len() < 12 {
                return None;
            }
            let worker = self.get_or_spawn(PoolKey { netid, mark, mode }, cache, now_fn)?;
            let wire_qid = worker.next_qid.fetch_add(1, Ordering::Relaxed);
            let orig_qid = u16::from_be_bytes([query[0], query[1]]);
            let waiter: Waiter = Arc::new((Mutex::new(None), Condvar::new()));
            let req = Pending {
                wire_qid,
                orig_qid,
                query: query.to_vec(),
                waiter: Some(Arc::clone(&waiter)),
                refresh: None,
                deadline: Instant::now() + Duration::from_millis(QUERY_TIMEOUT_MS),
            };
            {
                let mut q = worker.queue.lock().ok()?;
                if worker.closed.load(Ordering::Acquire) {
                    return None;
                }
                q.push_back(req);
            }
            worker.wake();

            let (lock, cv) = &*waiter;
            let mut guard = lock.lock().ok()?;
            let deadline = Instant::now() + Duration::from_millis(QUERY_TIMEOUT_MS);
            while guard.is_none() {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return None;
                }
                let (g, res) = cv.wait_timeout(guard, left).ok()?;
                guard = g;
                if res.timed_out() && guard.is_none() {
                    return None;
                }
            }
            let resp = guard.take().flatten()?;
            if resp.len() > out.len() {
                return None;
            }
            out[..resp.len()].copy_from_slice(&resp);
            Some(resp.len())
        }

        /// Enqueues a non-blocking background Serve-Stale refresh on the DoT worker.
        pub fn refresh_async(
            &self,
            netid: u32,
            mark: u32,
            mode: u8,
            query: &[u8],
            meta: RefreshMeta,
            cache: Arc<DnsCache>,
            now_fn: fn() -> i64,
        ) {
            if query.len() < 12 {
                return;
            }
            let Some(worker) = self.get_or_spawn(PoolKey { netid, mark, mode }, cache, now_fn)
            else {
                return;
            };
            let wire_qid = worker.next_qid.fetch_add(1, Ordering::Relaxed);
            let orig_qid = u16::from_be_bytes([query[0], query[1]]);
            if let Ok(mut q) = worker.queue.lock() {
                if !worker.closed.load(Ordering::Acquire) && q.len() < 64 {
                    q.push_back(Pending {
                        wire_qid,
                        orig_qid,
                        query: query.to_vec(),
                        waiter: None,
                        refresh: Some(meta),
                        deadline: Instant::now() + Duration::from_millis(QUERY_TIMEOUT_MS),
                    });
                    drop(q);
                    worker.wake();
                }
            };
        }

        pub fn flush_net(&self, netid: u32) {
            if let Ok(mut map) = self.workers.lock() {
                map.retain(|k, w| {
                    if k.netid == netid {
                        w.closed.store(true, Ordering::Release);
                        w.wake();
                        false
                    } else {
                        !w.closed.load(Ordering::Acquire)
                    }
                });
            }
        }

        pub fn clear_all(&self) {
            if let Ok(mut map) = self.workers.lock() {
                for (_, w) in map.drain() {
                    w.closed.store(true, Ordering::Release);
                    w.wake();
                }
            }
        }
    }

    fn notify_fail_all(inflight: &mut HashMap<u16, InFlight>) {
        for (_, item) in inflight.drain() {
            if let Some(w) = item.waiter {
                if let Ok(mut g) = w.0.lock() {
                    *g = Some(None);
                    w.1.notify_one();
                }
            }
        }
    }

    fn worker_loop(
        key: PoolKey,
        shared: Arc<WorkerShared>,
        cache: Arc<DnsCache>,
        now_fn: fn() -> i64,
    ) {
        let (primary, secondary) = endpoints_for(key.mode);
        let mut use_secondary = false;
        let mut active_ip = primary.ip;
        let mut conn: Option<TlsConn> = None;
        let mut demux = StreamDemux::new();
        let mut inflight: HashMap<u16, InFlight> = HashMap::new();
        let mut local_q: VecDeque<Pending> = VecDeque::new();
        let mut write_buf: Vec<u8> = Vec::with_capacity(MAX_COALESCE_BYTES);
        let mut early_data_replay: Vec<u8> = Vec::new();
        let mut read_buf = [0u8; 4096];
        let mut last_active = Instant::now();

        loop {
            if shared.closed.load(Ordering::Acquire) {
                break;
            }

            // Pull any newly queued requests.
            if let Ok(mut q) = shared.queue.lock() {
                while let Some(item) = q.pop_front() {
                    local_q.push_back(item);
                }
            }

            // Send queued batch immediately (coalesced into one SSL_write record).
            if !local_q.is_empty() {
                last_active = Instant::now();
                if conn.is_none() {
                    let ep = if use_secondary { secondary } else { primary };
                    active_ip = ep.ip;
                    conn = connect_tls(ep, key.mark, true).or_else(|| {
                        use_secondary = !use_secondary;
                        let alt = if use_secondary { secondary } else { primary };
                        active_ip = alt.ip;
                        connect_tls(alt, key.mark, false)
                    });
                    if conn.is_some() {
                        demux.reset();
                        early_data_replay.clear();
                    } else {
                        // Both endpoints unreachable; fail queued requests fast.
                        for item in local_q.drain(..) {
                            if let Some(w) = item.waiter {
                                if let Ok(mut g) = w.0.lock() {
                                    *g = Some(None);
                                    w.1.notify_one();
                                }
                            }
                        }
                    }
                }

                if let Some(ref c) = conn {
                    // Snapshot metadata for the batch we are about to coalesce and send.
                    let mut sent_meta: Vec<(u16, InFlight)> = Vec::new();
                    let mut preview = VecDeque::new();
                    let mut total_bytes = 0usize;
                    while let Some(item) = local_q.pop_front() {
                        let frame_len = 2 + item.query.len();
                        if !preview.is_empty() && total_bytes + frame_len > MAX_COALESCE_BYTES {
                            local_q.push_front(item);
                            break;
                        }
                        total_bytes += frame_len;
                        sent_meta.push((
                            item.wire_qid,
                            InFlight {
                                orig_qid: item.orig_qid,
                                waiter: item.waiter,
                                refresh: item.refresh,
                                deadline: item.deadline,
                            },
                        ));
                        preview.push_back((item.wire_qid, item.query));
                    }

                    let n = coalesce_frames(&mut preview, &mut write_buf, |x| (x.0, x.1.as_slice()));
                    if n > 0 {
                        // SAFETY: checking BoringSSL 0-RTT early-data state on valid ssl.
                        let in_early = unsafe { SSL_in_early_data(c.ssl) } != 0;
                        let write_ok = match ssl_write_all(c, &write_buf) {
                            WriteRes::Ok => {
                                if in_early
                                    && early_data_replay.len() + write_buf.len()
                                        <= MAX_COALESCE_BYTES * 2
                                {
                                    early_data_replay.extend_from_slice(&write_buf);
                                }
                                true
                            }
                            WriteRes::EarlyDataRejected => {
                                clear_cached_session(active_ip);
                                // SAFETY: valid ssl signaling SSL_ERROR_EARLY_DATA_REJECTED.
                                unsafe { SSL_reset_early_data_reject(c.ssl) };
                                let ok = drive_handshake(c)
                                    && (early_data_replay.is_empty()
                                        || ssl_write_all(c, &early_data_replay) == WriteRes::Ok)
                                    && ssl_write_all(c, &write_buf) == WriteRes::Ok;
                                early_data_replay.clear();
                                ok
                            }
                            WriteRes::Failed => false,
                        };
                        if write_ok {
                            for (qid, meta) in sent_meta {
                                inflight.insert(qid, meta);
                            }
                        } else {
                            // Connection died mid-write; drop conn and fail batch + inflight.
                            conn = None;
                            demux.reset();
                            early_data_replay.clear();
                            notify_fail_all(&mut inflight);
                            for (_, meta) in sent_meta {
                                if let Some(w) = meta.waiter {
                                    if let Ok(mut g) = w.0.lock() {
                                        *g = Some(None);
                                        w.1.notify_one();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Expire timed-out in-flight queries.
            let now = Instant::now();
            inflight.retain(|_, item| {
                if now >= item.deadline {
                    if let Some(w) = &item.waiter {
                        if let Ok(mut g) = w.0.lock() {
                            *g = Some(None);
                            w.1.notify_one();
                        }
                    }
                    false
                } else {
                    true
                }
            });

            // Compute next poll timeout.
            let timeout_ms = if !local_q.is_empty() {
                0
            } else if !inflight.is_empty() {
                let earliest = inflight.values().map(|i| i.deadline).min().unwrap_or(now);
                earliest.saturating_duration_since(now).as_millis().clamp(1, 500) as c_int
            } else {
                let idle_ms = last_active.elapsed().as_millis() as i32;
                if idle_ms >= WARM_IDLE_TIMEOUT_MS {
                    break;
                }
                (WARM_IDLE_TIMEOUT_MS - idle_ms).min(15_000)
            };

            let mut pfds = [
                PollFd { fd: shared.evfd, events: POLLIN, revents: 0 },
                PollFd { fd: conn.as_ref().map_or(-1, |c| c.fd), events: POLLIN, revents: 0 },
            ];
            let nfds = if conn.is_some() { 2 } else { 1 };
            // SAFETY: valid PollFd array of length nfds.
            let pr = unsafe { poll(pfds.as_mut_ptr(), nfds, timeout_ms) };
            if pr < 0 {
                continue;
            }
            if pfds[0].revents & POLLIN != 0 {
                shared.drain_evfd();
            }
            if nfds == 2 && (pfds[1].revents & (POLLIN | POLLERR | POLLHUP) != 0) {
                let mut drop_conn = false;
                if let Some(ref c) = conn {
                    loop {
                        // SAFETY: reading into stack buffer from valid ssl.
                        let r = unsafe {
                            SSL_read(
                                c.ssl,
                                read_buf.as_mut_ptr().cast::<c_void>(),
                                read_buf.len() as c_int,
                            )
                        };
                        if r > 0 {
                            last_active = Instant::now();
                            early_data_replay.clear();
                            demux.push(&read_buf[..r as usize]);
                            while let Some((wire_qid, frame)) = demux.next_frame() {
                                if let Some(item) = inflight.remove(&wire_qid) {
                                    let mut pkt = frame.to_vec();
                                    pkt[0..2].copy_from_slice(&item.orig_qid.to_be_bytes());
                                    if let Some(meta) = item.refresh {
                                        if let AnswerVerdict::Clean { ttl, rcode, ancount } =
                                            inspect_answer(
                                                &pkt,
                                                meta.allow_safesearch,
                                                meta.local_name,
                                                false,
                                            )
                                        {
                                            cache.insert(
                                                meta.netid,
                                                meta.cache_key,
                                                &pkt,
                                                rcode,
                                                ancount,
                                                ttl,
                                                now_fn(),
                                            );
                                        }
                                    }
                                    if let Some(w) = item.waiter {
                                        if let Ok(mut g) = w.0.lock() {
                                            *g = Some(Some(pkt));
                                            w.1.notify_one();
                                        }
                                    }
                                }
                            }
                            // SAFETY: check buffered SSL plaintext bytes before returning to poll.
                            if unsafe { SSL_pending(c.ssl) } <= 0 {
                                break;
                            }
                        } else {
                            let err = unsafe { SSL_get_error(c.ssl, r) };
                            if err == SSL_ERROR_EARLY_DATA_REJECTED {
                                clear_cached_session(active_ip);
                                // SAFETY: valid ssl signaling SSL_ERROR_EARLY_DATA_REJECTED.
                                unsafe { SSL_reset_early_data_reject(c.ssl) };
                                let ok = drive_handshake(c)
                                    && (early_data_replay.is_empty()
                                        || ssl_write_all(c, &early_data_replay) == WriteRes::Ok);
                                early_data_replay.clear();
                                if !ok {
                                    drop_conn = true;
                                }
                            } else if err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE {
                                drop_conn = true;
                            }
                            break;
                        }
                    }
                }
                if drop_conn {
                    conn = None;
                    demux.reset();
                    early_data_replay.clear();
                    notify_fail_all(&mut inflight);
                }
            }
        }

        shared.closed.store(true, Ordering::Release);
        notify_fail_all(&mut inflight);
        if let Ok(mut q) = shared.queue.lock() {
            for item in q.drain(..) {
                if let Some(w) = item.waiter {
                    if let Ok(mut g) = w.0.lock() {
                        *g = Some(None);
                        w.1.notify_one();
                    }
                }
            }
        }
    }
}

#[cfg(feature = "netd")]
pub use dot::UpstreamPool;

/// Host/non-netd stub so `libsaring` compiles with zero `libssl` dependency in Laras and tests.
#[cfg(not(feature = "netd"))]
#[derive(Default)]
pub struct UpstreamPool;

#[cfg(not(feature = "netd"))]
impl UpstreamPool {
    pub fn new() -> Self {
        Self
    }

    pub fn query(
        &self,
        _netid: u32,
        _mark: u32,
        _mode: u8,
        _query: &[u8],
        _out: &mut [u8],
        _cache: std::sync::Arc<crate::cache::DnsCache>,
        _now_fn: fn() -> i64,
    ) -> Option<usize> {
        None
    }

    pub fn refresh_async(
        &self,
        _netid: u32,
        _mark: u32,
        _mode: u8,
        _query: &[u8],
        _meta: RefreshMeta,
        _cache: std::sync::Arc<crate::cache::DnsCache>,
        _now_fn: fn() -> i64,
    ) {
    }

    pub fn flush_net(&self, _netid: u32) {}
    pub fn clear_all(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_a_and_aaaa_into_one_record_and_demuxes_out_of_order() {
        let mut q = VecDeque::new();
        let mut qa = vec![0u8; 32];
        qa[0..2].copy_from_slice(&0xAAAAu16.to_be_bytes());
        qa[5] = 1;
        let mut qaaaa = vec![0u8; 36];
        qaaaa[0..2].copy_from_slice(&0xBBBBu16.to_be_bytes());
        qaaaa[5] = 1;

        q.push_back((10u16, qa));
        q.push_back((11u16, qaaaa));

        let mut wire = Vec::new();
        let count = coalesce_frames(&mut q, &mut wire, |x| (x.0, x.1.as_slice()));
        assert_eq!(count, 2);
        assert!(q.is_empty());
        assert_eq!(wire.len(), (2 + 32) + (2 + 36));

        // Feed the stream back in tiny chunks (simulating partial TLS reads) to StreamDemux.
        let mut demux = StreamDemux::new();
        let mut got = Vec::new();
        for chunk in wire.chunks(7) {
            demux.push(chunk);
            while let Some((qid, pkt)) = demux.next_frame() {
                got.push((qid, pkt.len()));
            }
        }
        assert_eq!(got, vec![(10, 32), (11, 36)]);
    }
}
