// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Runtime controller for `netd` and `libnetd_resolv`, replacing C++ `SaringController.cpp`.
//!
//! Owns the read-only `mmap` name table, persistent state file, exempt/blocked appIds, pause
//! timer, 256-entry deduplicating refusal ring log, 16-shard Serve-Stale DNS cache and pipelined
//! DoT upstream pool.

use crate::cache::{DnsCache, Lookup};
use crate::dns::{
    extract_ipv4_answers, inspect_answer, is_boost_host, is_google_search_host, is_local_name,
    parse_question, synthesize_google_safesearch, synthesize_google_unlocked, synthesize_nodata,
    AnswerVerdict, Question, QTYPE_A, RCODE_NOERROR,
};
use crate::upstream::{RefreshMeta, UpstreamPool, DNS_MODE_CLOUDFLARE, DNS_MODE_SYSTEM};
use crate::Names;

use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

const DEFAULT_TABLE_PATH: &str = "/data/misc/net/saring_names.bin";
const DEFAULT_UPLOAD_PATH: &str = "/data/misc/net/saring_names.tmp";
const DEFAULT_STATE_PATH: &str = "/data/misc/net/saring_state";

const MAX_TABLE_BYTES: usize = 64 * 1024 * 1024;
const LOG_CAP: usize = 256;
const AID_USER_OFFSET: u32 = 100_000;
/// Bit flag in `saringSetOptions`'s `dnsMode` parameter enabling selective WARP+ peering boost.
const DNS_FLAG_BOOST: u8 = 0x10;

// Android ResNsendFlags matching bionic / packages/modules/DnsResolver.
const ANDROID_RESOLV_NO_CACHE_STORE: u32 = 1 << 1;
const ANDROID_RESOLV_NO_CACHE_LOOKUP: u32 = 1 << 2;

const PROT_READ: i32 = 1;
const MAP_SHARED: i32 = 1;
const CLOCK_REALTIME: i32 = 0;
const CLOCK_BOOTTIME: i32 = 7;

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
const O_NOFOLLOW: i32 = 0o400000;

#[repr(C)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, length: usize) -> i32;
    fn clock_gettime(clk_id: i32, tp: *mut TimeSpec) -> i32;
}

pub fn boottime_secs() -> i64 {
    let mut ts = TimeSpec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid TimeSpec pointer.
    unsafe {
        let _ = clock_gettime(CLOCK_BOOTTIME, &mut ts);
    }
    ts.tv_sec
}

fn realtime_ms() -> i64 {
    let mut ts = TimeSpec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid TimeSpec pointer.
    unsafe {
        let _ = clock_gettime(CLOCK_REALTIME, &mut ts);
    }
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

struct MmapTable {
    ptr: *const u8,
    len: usize,
    entries: i64,
    created: i64,
}

// SAFETY: Read-only MAP_SHARED memory valid for the lifetime of MmapTable.
unsafe impl Send for MmapTable {}
unsafe impl Sync for MmapTable {}

impl Drop for MmapTable {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            // SAFETY: ptr/len came from mmap.
            unsafe {
                let _ = munmap(self.ptr as *mut c_void, self.len);
            }
        }
    }
}

impl MmapTable {
    fn map_file(path: &Path) -> Option<Arc<Self>> {
        let file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(path).ok()?;
        let len = usize::try_from(file.metadata().ok()?.len()).ok()?;
        if len == 0 || len > MAX_TABLE_BYTES {
            return None;
        }
        // SAFETY: mapping read-only file descriptor for exact file length.
        let raw = unsafe { mmap(core::ptr::null_mut(), len, PROT_READ, MAP_SHARED, file.as_raw_fd(), 0) };
        if raw == (!0usize as *mut c_void) || raw.is_null() {
            return None;
        }
        // SAFETY: mmap succeeded for `len` readable bytes.
        let slice = unsafe { core::slice::from_raw_parts(raw.cast::<u8>(), len) };
        let Some(names) = Names::open(slice) else {
            unsafe {
                let _ = munmap(raw, len);
            }
            return None;
        };
        let entries = names.len() as i64;
        let created = if len >= 24 {
            i64::from_le_bytes(slice[16..24].try_into().unwrap_or([0; 8]))
        } else {
            0
        };
        Some(Arc::new(Self { ptr: raw.cast::<u8>(), len, entries, created }))
    }

    #[inline]
    fn view(&self) -> Option<Names<'_>> {
        // SAFETY: mapping stays alive for `&self`.
        let slice = unsafe { core::slice::from_raw_parts(self.ptr, self.len) };
        Names::view(slice)
    }
}

struct Refusal {
    time_ms: i64,
    uid: u32,
    count: u32,
    name: String,
}

#[derive(Default)]
struct RingLog {
    entries: Vec<Refusal>,
    next: usize,
}

impl RingLog {
    fn note(&mut self, uid: u32, name: &str) {
        let ms = realtime_ms();
        for r in &mut self.entries {
            if r.uid == uid && r.name == name {
                r.time_ms = ms;
                r.count = r.count.saturating_add(1);
                return;
            }
        }
        let clipped = if name.len() > 253 { &name[..253] } else { name };
        let r = Refusal { time_ms: ms, uid, count: 1, name: clipped.to_owned() };
        if self.entries.len() < LOG_CAP {
            self.entries.push(r);
        } else {
            self.entries[self.next] = r;
            self.next = (self.next + 1) % LOG_CAP;
        }
    }

    fn dump(&mut self, clear: bool) -> Vec<String> {
        let mut order: Vec<&Refusal> = self.entries.iter().collect();
        order.sort_by_key(|r| r.time_ms);
        let out = order
            .into_iter()
            .map(|r| format!("{}\t{}\t{}\t{}", r.time_ms, r.uid, r.count, r.name))
            .collect();
        if clear {
            self.entries.clear();
            self.next = 0;
        }
        out
    }
}

struct Config {
    table: Option<Arc<MmapTable>>,
    enabled: bool,
    exempt: Vec<u32>,
    blocked_apps: Vec<u32>,
}

struct Upload {
    file: Option<File>,
    written: usize,
}

pub struct Controller {
    table_path: String,
    upload_path: String,
    state_path: String,

    active: AtomicBool,
    has_blocked_apps: AtomicBool,
    dns_mode: AtomicU8,
    safesearch: AtomicU8,
    boost: AtomicBool,
    pause_until: AtomicI64,

    checked: AtomicU64,
    refused: AtomicU64,
    cache_hits: AtomicU64,
    poison_blocked: AtomicU64,

    cfg: RwLock<Config>,
    log: Mutex<RingLog>,
    upload: Mutex<Upload>,
    cache: Arc<DnsCache>,
    upstream: UpstreamPool,
}

impl Controller {
    pub fn new(table_path: &str, upload_path: &str, state_path: &str) -> Self {
        Self {
            table_path: table_path.to_owned(),
            upload_path: upload_path.to_owned(),
            state_path: state_path.to_owned(),
            active: AtomicBool::new(false),
            has_blocked_apps: AtomicBool::new(false),
            dns_mode: AtomicU8::new(DNS_MODE_SYSTEM),
            safesearch: AtomicU8::new(0),
            boost: AtomicBool::new(false),
            pause_until: AtomicI64::new(0),
            checked: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            poison_blocked: AtomicU64::new(0),
            cfg: RwLock::new(Config {
                table: None,
                enabled: false,
                exempt: Vec::new(),
                blocked_apps: Vec::new(),
            }),
            log: Mutex::new(RingLog::default()),
            upload: Mutex::new(Upload { file: None, written: 0 }),
            cache: Arc::new(DnsCache::new()),
            upstream: UpstreamPool::new(),
        }
    }

    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<Controller> = OnceLock::new();
        GLOBAL.get_or_init(|| {
            Controller::new(DEFAULT_TABLE_PATH, DEFAULT_UPLOAD_PATH, DEFAULT_STATE_PATH)
        })
    }

    fn refresh_atomics(&self, cfg: &Config) {
        let on = cfg.enabled && cfg.table.as_ref().is_some_and(|t| t.entries > 0);
        self.active.store(on, Ordering::Release);
        self.has_blocked_apps.store(!cfg.blocked_apps.is_empty(), Ordering::Release);
    }

    fn save_state(&self, cfg: &Config) {
        let mut out = String::new();
        out.push_str(if cfg.enabled { "1\n" } else { "0\n" });
        out.push_str(&format!("dns_mode={}\n", self.dns_mode.load(Ordering::Relaxed)));
        out.push_str(&format!("safesearch={}\n", self.safesearch.load(Ordering::Relaxed)));
        out.push_str(&format!(
            "boost={}\n",
            u8::from(self.boost.load(Ordering::Relaxed))
        ));
        for &id in &cfg.exempt {
            out.push_str(&format!("{id}\n"));
        }
        for &id in &cfg.blocked_apps {
            out.push_str(&format!("blocked={id}\n"));
        }
        if let Ok(mut f) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&self.state_path)
        {
            let _ = f.write_all(out.as_bytes());
        }
    }

    pub fn init(&self) {
        let Ok(mut cfg) = self.cfg.write() else {
            return;
        };
        cfg.table = MmapTable::map_file(Path::new(&self.table_path));
        if let Ok(text) = fs::read_to_string(&self.state_path) {
            let mut lines = text.lines();
            if let Some(first) = lines.next() {
                cfg.enabled = first.trim() == "1";
            }
            cfg.exempt.clear();
            cfg.blocked_apps.clear();
            for line in lines {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Some(v) = line.strip_prefix("dns_mode=") {
                    if let Ok(m) = v.parse::<u8>() {
                        self.dns_mode.store(m, Ordering::Relaxed);
                    }
                } else if let Some(v) = line.strip_prefix("safesearch=") {
                    if let Ok(s) = v.parse::<u8>() {
                        self.safesearch.store(s, Ordering::Relaxed);
                    }
                } else if let Some(v) = line.strip_prefix("boost=") {
                    self.boost.store(v == "1", Ordering::Relaxed);
                } else if let Some(v) = line.strip_prefix("blocked=") {
                    if let Ok(id) = v.parse::<u32>() {
                        cfg.blocked_apps.push(id);
                    }
                } else if let Ok(id) = line.parse::<u32>() {
                    cfg.exempt.push(id);
                }
            }
            cfg.exempt.sort_unstable();
            cfg.exempt.dedup();
            cfg.blocked_apps.sort_unstable();
            cfg.blocked_apps.dedup();
        }
        self.refresh_atomics(&cfg);
        drop(cfg);
        let mode = self.dns_mode.load(Ordering::Relaxed);
        let strict_ss = self.safesearch.load(Ordering::Relaxed) == 1;
        let boost = self.boost.load(Ordering::Relaxed);
        crate::warp::sync(mode != DNS_MODE_SYSTEM && !strict_ss, boost);
    }

    #[inline]
    fn maybe_boost_answer(&self, app_id: u32, q: &Question, ans: &[u8]) {
        // Keep boost strictly IPv4 (`QTYPE_A`) so Cronet apps on IPv4-only mobile data are never
        // lured into slower IPv6 tunnel routes via `CHROMIUM_V6_PROBE`.
        if q.qtype != QTYPE_A
            || !self.boost.load(Ordering::Relaxed)
            || (app_id != 0 && app_id < 10_000)
            || !is_boost_host(q.name())
        {
            return;
        }
        let mut ips = [[0u8; 4]; 8];
        let count = extract_ipv4_answers(ans, &mut ips);
        if count > 0 {
            crate::warp::add_boost_ips(&ips[..count]);
        }
    }

    /// Evaluates whether a lookup from `uid` for `name` should be refused.
    pub fn is_blocked(&self, uid: u32, name: &[u8]) -> bool {
        if name.is_empty() {
            return false;
        }
        let app_id = uid % AID_USER_OFFSET;

        // Fast check for M4 radio/IMEI telemetry guard packages even if list filtering is paused.
        if self.has_blocked_apps.load(Ordering::Acquire) {
            if let Ok(cfg) = self.cfg.read() {
                if cfg.blocked_apps.binary_search(&app_id).is_ok() {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                    if let (Ok(mut log), Ok(s)) = (self.log.lock(), core::str::from_utf8(name)) {
                        log.note(uid, s);
                    }
                    return true;
                }
            }
        }

        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        let pause = self.pause_until.load(Ordering::Relaxed);
        if pause != 0 && boottime_secs() < pause {
            return false;
        }

        let blocked = {
            let Ok(cfg) = self.cfg.read() else {
                return false;
            };
            let Some(ref table) = cfg.table else {
                return false;
            };
            if cfg.exempt.binary_search(&app_id).is_ok() {
                return false;
            }
            self.checked.fetch_add(1, Ordering::Relaxed);
            table.view().is_some_and(|n| n.blocked(name))
        };

        if blocked {
            self.refused.fetch_add(1, Ordering::Relaxed);
            if let (Ok(mut log), Ok(s)) = (self.log.lock(), core::str::from_utf8(name)) {
                log.note(uid, s);
            }
        }
        blocked
    }

    /// Full Rust DNS resolver hook invoked from `res_send.cpp`.
    /// Returns `Some((answer_len, rcode))` if answered by Saring (block, SafeSearch synthesis,
    /// Serve-Stale cache, or coalesced DoT), or `None` to pass through to stock AOSP.
    pub fn resolve_dns(
        &self,
        netid: u32,
        mark: u32,
        uid: u32,
        flags: u32,
        query: &[u8],
        ans: &mut [u8],
    ) -> Option<(usize, i32)> {
        let q = parse_question(query)?;
        let app_id = uid % AID_USER_OFFSET;

        // 1. Check radio/IMEI telemetry guard & Saring name table using already-computed keys.
        let mut blocked = false;
        if self.has_blocked_apps.load(Ordering::Acquire) {
            if let Ok(cfg) = self.cfg.read() {
                blocked = cfg.blocked_apps.binary_search(&app_id).is_ok();
            }
        }
        if !blocked && self.active.load(Ordering::Acquire) {
            let pause = self.pause_until.load(Ordering::Relaxed);
            if pause == 0 || boottime_secs() >= pause {
                if let Ok(cfg) = self.cfg.read() {
                    if let Some(ref table) = cfg.table {
                        if cfg.exempt.binary_search(&app_id).is_err() {
                            self.checked.fetch_add(1, Ordering::Relaxed);
                            if let Some(names) = table.view() {
                                blocked = q.blocked_by(&names);
                            }
                        }
                    }
                }
            }
        }
        if blocked {
            self.refused.fetch_add(1, Ordering::Relaxed);
            if let (Ok(mut log), Ok(s)) = (self.log.lock(), core::str::from_utf8(q.name())) {
                log.note(uid, s);
            }
            let n = synthesize_nodata(query, &q, ans)?;
            return Some((n, RCODE_NOERROR as i32));
        }

        let strict_ss = self.safesearch.load(Ordering::Relaxed) == 1;
        let mode = self.dns_mode.load(Ordering::Relaxed);
        let now = boottime_secs();
        crate::warp::maybe_check_health(now);

        // 2. Owner-controlled Google SafeSearch synthesis (~300 ns, 0 network I/O).
        // When Unrestricted, only user apps (app_id >= 10_000) and root CLI (app_id == 0)
        // receive the NAT64 AAAA route so NetworkMonitor (uid 1073) validates physical
        // Wi-Fi/Cellular interfaces directly without waiting on wg_saring0.
        if is_google_search_host(q.name()) {
            if strict_ss {
                if let Some(n) = synthesize_google_safesearch(query, &q, ans) {
                    return Some((n, RCODE_NOERROR as i32));
                }
            } else if mode != DNS_MODE_SYSTEM
                && (app_id == 0 || app_id >= 10_000)
                && crate::warp::is_ready()
            {
                if let Some(n) = synthesize_google_unlocked(query, &q, ans) {
                    return Some((n, RCODE_NOERROR as i32));
                }
            }
        }

        // If encrypted upstream is off, check cache only when already populated, else pass through.
        let skip_lookup = (flags & (ANDROID_RESOLV_NO_CACHE_LOOKUP | ANDROID_RESOLV_NO_CACHE_STORE)) != 0;
        let skip_store = (flags & ANDROID_RESOLV_NO_CACHE_STORE) != 0;
        let cache_key = q.cache_key(netid);
        let local = is_local_name(q.name());

        // 3. 16-shard Serve-Stale cache (~500 ns, 0 allocations).
        if !skip_lookup {
            match self.cache.lookup(netid, cache_key, q.qid, now, ans) {
                Lookup::Fresh { len, rcode } => {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    self.maybe_boost_answer(app_id, &q, &ans[..len]);
                    return Some((len, i32::from(rcode)));
                }
                Lookup::Stale { len, rcode, refresh } => {
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    self.maybe_boost_answer(app_id, &q, &ans[..len]);
                    if refresh && mode != DNS_MODE_SYSTEM && !local {
                        self.upstream.refresh_async(
                            netid,
                            mark,
                            mode,
                            query,
                            RefreshMeta {
                                netid,
                                cache_key,
                                allow_safesearch: strict_ss,
                                local_name: local,
                            },
                            Arc::clone(&self.cache),
                            boottime_secs,
                        );
                    }
                    return Some((len, i32::from(rcode)));
                }
                Lookup::Miss => {}
            }
        }

        // 4. Encrypted coalesced DoT upstream when enabled (and not a local/mDNS name).
        if mode == DNS_MODE_SYSTEM || local {
            return None;
        }
        let n = self.upstream.query(
            netid,
            mark,
            mode,
            query,
            ans,
            Arc::clone(&self.cache),
            boottime_secs,
        )?;
        match inspect_answer(&ans[..n], strict_ss, local, false) {
            AnswerVerdict::Clean { ttl, rcode, ancount } => {
                if !skip_store {
                    self.cache.insert(netid, cache_key, &ans[..n], rcode, ancount, ttl, now);
                }
                self.maybe_boost_answer(app_id, &q, &ans[..n]);
                Some((n, i32::from(rcode)))
            }
            _ => None,
        }
    }

    /// Post-hoc guard on AOSP's plaintext UDP/53 answer when `dns_mode == 0` (System) or DoT fell
    /// back. Catches Indosat/Telkomsel sinkholes, forged `TTL=0` replies and spoofed
    /// `216.239.38.120` VIPs, retrying immediately over Cloudflare DoT.
    pub fn inspect_plaintext_answer(
        &self,
        netid: u32,
        mark: u32,
        query: &[u8],
        ans: &mut [u8],
        ans_len: usize,
        rcode: &mut i32,
    ) -> isize {
        if ans_len < 12 || ans_len > ans.len() {
            return ans_len as isize;
        }
        let Some(q) = parse_question(query) else {
            return ans_len as isize;
        };
        let strict_ss = self.safesearch.load(Ordering::Relaxed) == 1;
        let local = is_local_name(q.name());

        match inspect_answer(&ans[..ans_len], strict_ss, local, true) {
            AnswerVerdict::Clean { ttl, rcode: rc, ancount } => {
                // Populate Serve-Stale cache even in System mode for zero-wait repeats.
                self.cache.insert(
                    netid,
                    q.cache_key(netid),
                    &ans[..ans_len],
                    rc,
                    ancount,
                    ttl,
                    boottime_secs(),
                );
                ans_len as isize
            }
            AnswerVerdict::PoisonedSinkhole | AnswerVerdict::PoisonedSafeSearch => {
                self.poison_blocked.fetch_add(1, Ordering::Relaxed);
                let retry_mode = {
                    let m = self.dns_mode.load(Ordering::Relaxed);
                    if m == DNS_MODE_SYSTEM { DNS_MODE_CLOUDFLARE } else { m }
                };
                if let Some(n) = self.upstream.query(
                    netid,
                    mark,
                    retry_mode,
                    query,
                    ans,
                    Arc::clone(&self.cache),
                    boottime_secs,
                ) {
                    if let AnswerVerdict::Clean { ttl, rcode: rc, ancount } =
                        inspect_answer(&ans[..n], strict_ss, local, false)
                    {
                        self.cache.insert(
                            netid,
                            q.cache_key(netid),
                            &ans[..n],
                            rc,
                            ancount,
                            ttl,
                            boottime_secs(),
                        );
                        *rcode = i32::from(rc);
                        return n as isize;
                    }
                }
                ans_len as isize
            }
            AnswerVerdict::Malformed => ans_len as isize,
        }
    }

    pub fn flush_net(&self, netid: u32) {
        self.cache.flush_net(netid);
        self.upstream.flush_net(netid);
    }

    pub fn on_default_network_change(&self, netid: u32, force: bool) {
        crate::warp::on_network_change(netid, force);
    }

    pub fn begin(&self) -> bool {
        let Ok(mut up) = self.upload.lock() else {
            return false;
        };
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&self.upload_path)
            .ok();
        up.written = 0;
        up.file = file;
        up.file.is_some()
    }

    pub fn append(&self, chunk: &[u8]) -> bool {
        let Ok(mut up) = self.upload.lock() else {
            return false;
        };
        if up.file.is_none() || up.written.saturating_add(chunk.len()) > MAX_TABLE_BYTES {
            return false;
        }
        let ok = up.file.as_mut().is_some_and(|f| f.write_all(chunk).is_ok());
        if !ok {
            up.file = None;
            let _ = fs::remove_file(&self.upload_path);
            return false;
        }
        up.written += chunk.len();
        true
    }

    pub fn commit(&self) -> i64 {
        {
            let Ok(mut up) = self.upload.lock() else {
                return -1;
            };
            let Some(f) = up.file.take() else {
                return -1;
            };
            let _ = f.sync_all();
        }
        let Some(table) = MmapTable::map_file(Path::new(&self.upload_path)) else {
            let _ = fs::remove_file(&self.upload_path);
            return -1;
        };
        if fs::rename(&self.upload_path, &self.table_path).is_err() {
            let _ = fs::remove_file(&self.upload_path);
            return -1;
        }
        let entries = table.entries;
        if let Ok(mut cfg) = self.cfg.write() {
            cfg.table = Some(table);
            self.refresh_atomics(&cfg);
        }
        entries
    }

    pub fn configure(&self, enabled: bool, exempt_ids: &[i32], pause_seconds: i32) {
        let Ok(mut cfg) = self.cfg.write() else {
            return;
        };
        cfg.enabled = enabled;
        cfg.exempt.clear();
        for &id in exempt_ids {
            if id >= 0 {
                cfg.exempt.push(id as u32);
            }
        }
        cfg.exempt.sort_unstable();
        cfg.exempt.dedup();
        let pause = if pause_seconds > 0 { boottime_secs() + i64::from(pause_seconds) } else { 0 };
        self.pause_until.store(pause, Ordering::Relaxed);
        self.refresh_atomics(&cfg);
        self.save_state(&cfg);
    }

    pub fn set_options(&self, raw_dns_mode: u8, safesearch: u8, blocked_ids: &[i32]) {
        let dns_mode = raw_dns_mode & 0x0F;
        let boost = (raw_dns_mode & DNS_FLAG_BOOST) != 0;
        let prev_mode = self.dns_mode.swap(dns_mode, Ordering::Relaxed);
        let prev_ss = self.safesearch.swap(safesearch, Ordering::Relaxed);
        self.boost.store(boost, Ordering::Relaxed);
        crate::warp::sync(dns_mode != DNS_MODE_SYSTEM && safesearch == 0, boost);
        if prev_mode != dns_mode || prev_ss != safesearch {
            self.cache.clear();
            self.upstream.clear_all();
        }
        if let Ok(mut cfg) = self.cfg.write() {
            cfg.blocked_apps.clear();
            for &id in blocked_ids {
                if id >= 0 {
                    cfg.blocked_apps.push(id as u32);
                }
            }
            cfg.blocked_apps.sort_unstable();
            cfg.blocked_apps.dedup();
            self.refresh_atomics(&cfg);
            self.save_state(&cfg);
        }
    }

    pub fn stats(&self) -> [i64; 6] {
        let (entries, created) = self
            .cfg
            .read()
            .ok()
            .and_then(|c| c.table.as_ref().map(|t| (t.entries, t.created)))
            .unwrap_or((0, 0));
        [
            self.checked.load(Ordering::Relaxed) as i64,
            self.refused.load(Ordering::Relaxed) as i64,
            entries,
            created,
            self.cache_hits.load(Ordering::Relaxed) as i64,
            self.poison_blocked.load(Ordering::Relaxed) as i64,
        ]
    }

    pub fn log(&self, clear: bool) -> Vec<String> {
        self.log.lock().map(|mut l| l.dump(clear)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::compile;
    use crate::dns::{QCLASS_IN, QTYPE_A};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_controller(tag: &str) -> Controller {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("saring_test_{tag}_{nonce}"));
        let _ = fs::create_dir_all(&dir);
        Controller::new(
            dir.join("names.bin").to_str().unwrap(),
            dir.join("names.tmp").to_str().unwrap(),
            dir.join("state").to_str().unwrap(),
        )
    }

    fn make_query(qid: u16, host: &str) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&qid.to_be_bytes());
        p.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in host.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&QTYPE_A.to_be_bytes());
        p.extend_from_slice(&QCLASS_IN.to_be_bytes());
        p
    }

    #[test]
    fn upload_commit_block_exempt_and_radio_guard_work() {
        let ctl = tmp_controller("basic");
        let (blob, _) = compile(&["||ads.example.com^\n"], 12345);
        assert!(ctl.begin());
        assert!(ctl.append(&blob[..blob.len() / 2]));
        assert!(ctl.append(&blob[blob.len() / 2..]));
        assert_eq!(ctl.commit(), 1);

        ctl.configure(true, &[10099], 0);
        assert!(ctl.is_blocked(10050, b"x.ads.example.com"));
        assert!(!ctl.is_blocked(10099, b"x.ads.example.com")); // exempt
        assert!(!ctl.is_blocked(10050, b"danbooru.donmai.us"));

        // Radio/IMEI guard blocks telemetry uid even for normal domains.
        ctl.set_options(DNS_MODE_SYSTEM, 0, &[10135]);
        assert!(ctl.is_blocked(10135, b"cloud.qti.qualcomm.com"));
        assert_eq!(ctl.stats()[2], 1);
        assert_eq!(ctl.stats()[3], 12345);
        assert!(!ctl.log(true).is_empty());
        assert!(ctl.log(false).is_empty());
    }

    #[test]
    fn resolve_dns_synthesizes_google_safesearch_only_when_strict() {
        let ctl = tmp_controller("ss");
        let q = make_query(0x3344, "www.google.com");
        let mut out = [0u8; 512];

        // Unrestricted (default): passes through (returns None when dns_mode=0).
        ctl.set_options(DNS_MODE_SYSTEM, 0, &[]);
        assert_eq!(ctl.resolve_dns(100, 0, 10050, 0, &q, &mut out), None);

        // Strict (owner enabled): synthesizes 216.239.38.120 locally in ~300 ns.
        ctl.set_options(DNS_MODE_SYSTEM, 1, &[]);
        let (n, rcode) = ctl.resolve_dns(100, 0, 10050, 0, &q, &mut out).unwrap();
        assert_eq!(rcode, 0);
        assert_eq!(&out[n - 4..n], &[216, 239, 38, 120]);
    }
}
