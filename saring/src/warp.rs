// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust kernel WireGuard (`wg_saring0`, Cloudflare WARP+), `/96` NAT64 Google Search unlock,
//! selective `/32` IPv4 anti-throttle & peering boost, and per-device X25519 auto-provisioning.
//!
//! Zero external crates: uses Linux Netlink (`NETLINK_ROUTE`, `NETLINK_GENERIC` `"wireguard"`)
//! and BoringSSL FFI (`libcrypto.so` + `libssl.so`, already linked into `netd`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const IFNAME: &[u8] = b"wg_saring0\0";
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const WG_GENL_NAME: &[u8] = b"wireguard\0";
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const WG_GENL_VERSION: u8 = 1;

const WARP_CONFIG_PATH: &str = "/data/misc/net/saring_warp";
const WARP_CONFIG_TMP: &str = "/data/misc/net/saring_warp.tmp";
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const ROUTE_TABLE_SARING: u32 = 999;
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const RULE_PREF_NAT64: u32 = 5000;
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const RULE_PREF_BOOST: u32 = 5001;
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const WG_MTU: u32 = 1360;
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const SARING_INITCWND: u32 = 32;
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const SARING_INITRWND: u32 = 64;
const BOOST_RING_CAP: usize = 256;
const O_NOFOLLOW: i32 = 0x20000;

/// Ordered Cloudflare WARP anycast endpoints + ports for automatic UDP-shaping failover.
/// Port 4500 (IPsec NAT-T) is primary because Indonesian ISPs (e.g. Telkom/IndiHome) actively
/// drop or heavily shape UDP/2408 while passing IPsec NAT-T 4500 cleanly (0% loss, ~51 ms).
/// Port 2408 is interleaved at index 2 so networks blocking UDP/4500 recover within 30 seconds.
pub(crate) const WARP_ENDPOINTS: &[([u8; 4], u16)] = &[
    ([162, 159, 192, 1], 4500),
    ([188, 114, 97, 1], 4500),
    ([188, 114, 97, 1], 2408),
    ([188, 114, 96, 1], 4500),
    ([162, 159, 192, 1], 500),
    ([162, 159, 192, 1], 2408),
];

/// Primary NAT64 prefix: `2600:70ff:ac2c:64::/96` (Hong Kong APAC, ~240–306 ms TTFB, `loc=HK`).
/// Shares 13 leading bits with `wg_saring0`'s `2606:4700::/32` so RFC 6724 Rule 9 always selects
/// it ahead of the European failover prefix while preserving instant Happy Eyeballs failover.
pub const NAT64_PRIMARY_PREFIX: [u8; 12] = [
    0x26, 0x00, 0x70, 0xff, 0xac, 0x2c, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00,
];
/// Failover NAT64 prefix: `2a01:4f9:c010:3f02:64::/96` (Helsinki FI, `loc=FI`).
pub const NAT64_BACKUP_PREFIX: [u8; 12] = [
    0x2a, 0x01, 0x04, 0xf9, 0xc0, 0x10, 0x3f, 0x02, 0x00, 0x64, 0x00, 0x00,
];
/// Chromium's `HostResolverManager::IsGloballyReachable` dummy UDP `connect()` probe target
/// (`[2001:4860:4860::8888]:443`). Routing this single `/128` to `wg_saring0` makes Chromium
/// request `AF_UNSPEC` (`AAAA`) on IPv4-only networks while Bionic's `2000::` probe stays untouched.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
const CHROMIUM_V6_PROBE: [u8; 16] = [
    0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
];

/// Anycast Google Frontend IPv4 targets embedded into the lower 32 bits of the `/96` NAT64 address.
/// `142.251.150.119` (`8efb:9677`) and `142.251.154.119` (`8efb:9a77`).
pub const GOOGLE_GFE_PRIMARY_V4: [u8; 4] = [142, 251, 150, 119];
pub const GOOGLE_GFE_BACKUP_V4: [u8; 4] = [142, 251, 154, 119];

/// Pre-provisioned Cloudflare WARP fallback credentials used only until per-device auto-provisioning
/// writes unique X25519 credentials to `/data/misc/net/saring_warp`.
const DEFAULT_PRIV_KEY: [u8; 32] = [
    0xb8, 0xda, 0xd5, 0x3d, 0xe6, 0x8b, 0xa9, 0xf1, 0xff, 0x88, 0x70, 0x4b, 0xd0, 0x82, 0x64, 0xe9,
    0xa5, 0x8a, 0xc6, 0x87, 0xa1, 0x7a, 0xff, 0x11, 0xdb, 0x09, 0x5d, 0xf8, 0x38, 0x5e, 0x4e, 0x53,
];
const DEFAULT_PEER_PUB_KEY: [u8; 32] = [
    0x6e, 0x65, 0xce, 0x0b, 0xe1, 0x75, 0x17, 0x11, 0x0c, 0x17, 0xd7, 0x72, 0x88, 0xad, 0x87, 0xe7,
    0xfd, 0x52, 0x52, 0xdc, 0xc7, 0xd0, 0x9b, 0x95, 0xa3, 0x9d, 0x61, 0xdb, 0x03, 0xdf, 0x83, 0x2a,
];
const DEFAULT_CLIENT_V4: [u8; 4] = [172, 16, 0, 2];
const DEFAULT_CLIENT_V6: [u8; 16] = [
    0x26, 0x06, 0x47, 0x00, 0x01, 0x10, 0x82, 0xa9, 0xf2, 0x35, 0xee, 0x15, 0xf2, 0x66, 0x48, 0x9b,
];
const DEFAULT_ENDPOINT_V4: [u8; 4] = [162, 159, 192, 1];
const DEFAULT_ENDPOINT_PORT: u16 = 4500;

static NAT64_READY: AtomicBool = AtomicBool::new(false);
static BOOST_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Fail-open circuit breaker: paused when `wg_saring0` stalls (no handshake or TX without RX) so
/// both `google.com` and boosted apps fail open to direct instead of hanging during roaming or
/// strict UDP-blocking networks; cleared automatically once a handshake succeeds.
static TUNNEL_PAUSED: AtomicBool = AtomicBool::new(false);
static PREV_TX: AtomicU64 = AtomicU64::new(0);
static PREV_RX: AtomicU64 = AtomicU64::new(0);
#[cfg_attr(not(all(target_os = "android", feature = "netd")), allow(dead_code))]
static PROVISIONING: AtomicBool = AtomicBool::new(false);
static WARP_STATE: Mutex<WarpState> = Mutex::new(WarpState::new());

#[inline]
fn reset_health_counters() {
    PREV_TX.store(0, Ordering::Relaxed);
    PREV_RX.store(0, Ordering::Relaxed);
}

struct WarpState {
    wg_up: bool,
    nat64_on: bool,
    boost_on: bool,
    client_v4: [u8; 4],
    client_v6: [u8; 16],
    endpoint_idx: usize,
    endpoint_fails: usize,
    boost_ring_v4: BoostRing<[u8; 4]>,
    boost_ring_v6: BoostRing<[u8; 16]>,
}

impl WarpState {
    const fn new() -> Self {
        Self {
            wg_up: false,
            nat64_on: false,
            boost_on: false,
            client_v4: DEFAULT_CLIENT_V4,
            client_v6: DEFAULT_CLIENT_V6,
            endpoint_idx: 0,
            endpoint_fails: 0,
            boost_ring_v4: BoostRing::new([0; 4]),
            boost_ring_v6: BoostRing::new([0; 16]),
        }
    }
}

/// Bounded 256-slot FIFO ring tracking currently installed `/32` or `/128` boost routes.
struct BoostRing<T: Copy + PartialEq> {
    ips: [T; BOOST_RING_CAP],
    len: usize,
    next: usize,
}

impl<T: Copy + PartialEq> BoostRing<T> {
    const fn new(zero: T) -> Self {
        Self { ips: [zero; BOOST_RING_CAP], len: 0, next: 0 }
    }

    /// Inserts `ip` if absent. Returns `None` if already present, `Some(None)` if inserted without
    /// eviction, or `Some(Some(old_ip))` if `old_ip` was evicted to make room.
    fn insert(&mut self, ip: T) -> Option<Option<T>> {
        if self.ips[..self.len].contains(&ip) {
            return None;
        }
        if self.len < BOOST_RING_CAP {
            self.ips[self.len] = ip;
            self.len += 1;
            Some(None)
        } else {
            let evicted = self.ips[self.next];
            self.ips[self.next] = ip;
            self.next = (self.next + 1) % BOOST_RING_CAP;
            Some(Some(evicted))
        }
    }

    fn drain_all(&mut self) -> Vec<T> {
        let out = self.ips[..self.len].to_vec();
        self.len = 0;
        self.next = 0;
        out
    }
}

/// True when `wg_saring0` and the `/96` NAT64 Google Search policy routes are installed and
/// the tunnel is healthy (not paused by the fail-open circuit breaker).
#[inline]
pub fn is_ready() -> bool {
    NAT64_READY.load(Ordering::Acquire) && !TUNNEL_PAUSED.load(Ordering::Acquire)
}

/// True when selective `/32` IPv4 anti-throttle & peering boost is active and healthy.
#[inline]
pub fn is_boost_active() -> bool {
    BOOST_ACTIVE.load(Ordering::Acquire) && !TUNNEL_PAUSED.load(Ordering::Acquire)
}

/// Returns the two synthesized NAT64 `AAAA` addresses for `www.google.com` / `google.com`:
/// Primary = Hong Kong APAC (`2600:70ff:ac2c:64::8efb:9677`), Backup = Helsinki FI
/// (`2a01:4f9:c010:3f02:64::8efb:9677`) for automatic Happy Eyeballs failover.
#[inline]
pub fn google_nat64_addrs() -> [[u8; 16]; 2] {
    let mut a = [0u8; 16];
    a[..12].copy_from_slice(&NAT64_PRIMARY_PREFIX);
    a[12..16].copy_from_slice(&GOOGLE_GFE_PRIMARY_V4);

    let mut b = [0u8; 16];
    b[..12].copy_from_slice(&NAT64_BACKUP_PREFIX);
    b[12..16].copy_from_slice(&GOOGLE_GFE_PRIMARY_V4);
    [a, b]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) struct WarpCreds {
    priv_key: [u8; 32],
    peer_pub: [u8; 32],
    client_v4: [u8; 4],
    client_v6: [u8; 16],
    endpoint_v4: [u8; 4],
    endpoint_port: u16,
}

impl Default for WarpCreds {
    fn default() -> Self {
        Self {
            priv_key: DEFAULT_PRIV_KEY,
            peer_pub: DEFAULT_PEER_PUB_KEY,
            client_v4: DEFAULT_CLIENT_V4,
            client_v6: DEFAULT_CLIENT_V6,
            endpoint_v4: DEFAULT_ENDPOINT_V4,
            endpoint_port: DEFAULT_ENDPOINT_PORT,
        }
    }
}

fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let bytes = s.as_bytes();
    for i in 0..N {
        let hi = (bytes[2 * i] as char).to_digit(16)? as u8;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg_attr(not(all(target_os = "android", feature = "netd")), allow(dead_code))]
pub(crate) fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() { input[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if i + 1 < input.len() {
            TABLE[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if i + 2 < input.len() {
            TABLE[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
        i += 3;
    }
    out
}

#[cfg_attr(not(all(target_os = "android", feature = "netd")), allow(dead_code))]
pub(crate) fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for chunk in bytes.chunks_exact(4) {
        let a = val(chunk[0])? as u32;
        let b = val(chunk[1])? as u32;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        let c = if pad2 { 0 } else { val(chunk[2])? as u32 };
        let d = if pad3 { 0 } else { val(chunk[3])? as u32 };
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((triple >> 16) & 0xFF) as u8);
        if !pad2 {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if !pad3 {
            out.push((triple & 0xFF) as u8);
        }
    }
    Some(out)
}

#[cfg_attr(not(all(target_os = "android", feature = "netd")), allow(dead_code))]
fn find_json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let mut rest = json;
    while let Some(pos) = rest.find(&needle) {
        let after = &rest[pos + needle.len()..];
        let trimmed = after.trim_start();
        if let Some(after_colon) = trimmed.strip_prefix(':') {
            let val = after_colon.trim_start();
            if let Some(after_quote) = val.strip_prefix('"') {
                if let Some(end) = after_quote.find('"') {
                    return Some(&after_quote[..end]);
                }
            }
        }
        rest = after;
    }
    None
}

/// Parses `v4`, `v6` and peer `public_key` from Cloudflare's `/v0a2158/reg` JSON response.
#[cfg_attr(not(all(target_os = "android", feature = "netd")), allow(dead_code))]
pub(crate) fn parse_warp_reg_json(body: &str, priv_key: [u8; 32]) -> Option<WarpCreds> {
    let addr_section = body.find("\"addresses\"").map(|i| &body[i..])?;
    let v4_str = find_json_str(addr_section, "v4")?;
    let v6_str = find_json_str(addr_section, "v6")?;
    let peers_section = body.find("\"peers\"").map(|i| &body[i..])?;
    let pub_b64 = find_json_str(peers_section, "public_key")?;

    let v4: Ipv4Addr = v4_str.parse().ok()?;
    let v6: Ipv6Addr = v6_str.parse().ok()?;
    let pub_bytes = base64_decode(pub_b64)?;
    if pub_bytes.len() != 32 {
        return None;
    }
    let mut peer_pub = [0u8; 32];
    peer_pub.copy_from_slice(&pub_bytes);

    Some(WarpCreds {
        priv_key,
        peer_pub,
        client_v4: v4.octets(),
        client_v6: v6.octets(),
        endpoint_v4: DEFAULT_ENDPOINT_V4,
        endpoint_port: DEFAULT_ENDPOINT_PORT,
    })
}

fn parse_creds_text(text: &str) -> (WarpCreds, bool) {
    let mut creds = WarpCreds::default();
    let mut has_priv = false;
    let mut has_v6 = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("priv_hex=") {
            if let Some(k) = parse_hex::<32>(v) {
                creds.priv_key = k;
                has_priv = true;
            }
        } else if let Some(v) = line.strip_prefix("peer_pub_hex=") {
            if let Some(k) = parse_hex::<32>(v) {
                creds.peer_pub = k;
            }
        } else if let Some(v) = line.strip_prefix("v4_hex=") {
            if let Some(ip4) = parse_hex::<4>(v) {
                creds.client_v4 = ip4;
            }
        } else if let Some(v) = line.strip_prefix("v6_hex=") {
            if let Some(ip6) = parse_hex::<16>(v) {
                creds.client_v6 = ip6;
                has_v6 = true;
            }
        } else if let Some(v) = line.strip_prefix("endpoint_hex=") {
            if let Some(ep) = parse_hex::<4>(v) {
                creds.endpoint_v4 = ep;
            }
        } else if let Some(v) = line.strip_prefix("endpoint_port=") {
            if let Ok(port) = v.parse::<u16>() {
                if port != 0 {
                    creds.endpoint_port = port;
                }
            }
        }
    }
    (creds, has_priv && has_v6)
}

fn load_creds() -> (WarpCreds, bool) {
    let Ok(text) = fs::read_to_string(WARP_CONFIG_PATH) else {
        return (WarpCreds::default(), false);
    };
    parse_creds_text(&text)
}

#[cfg_attr(not(all(target_os = "android", feature = "netd")), allow(dead_code))]
fn format_creds_text(creds: &WarpCreds) -> String {
    format!(
        "priv_hex={}\npeer_pub_hex={}\nv4_hex={}\nv6_hex={}\nendpoint_hex={}\nendpoint_port={}\n",
        to_hex(&creds.priv_key),
        to_hex(&creds.peer_pub),
        to_hex(&creds.client_v4),
        to_hex(&creds.client_v6),
        to_hex(&creds.endpoint_v4),
        creds.endpoint_port,
    )
}

#[cfg_attr(not(all(target_os = "android", feature = "netd")), allow(dead_code))]
fn save_creds(creds: &WarpCreds) -> bool {
    let content = format_creds_text(creds);
    let Ok(mut f) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(WARP_CONFIG_TMP)
    else {
        return false;
    };
    if f.write_all(content.as_bytes()).is_err() || f.sync_all().is_err() {
        let _ = fs::remove_file(WARP_CONFIG_TMP);
        return false;
    }
    drop(f);
    fs::rename(WARP_CONFIG_TMP, WARP_CONFIG_PATH).is_ok()
}

/// Synchronizes `wg_saring0`, `/96` Google Search NAT64 rules, and `/32`+`/128` boost state.
pub fn sync(enable_google_nat64: bool, enable_boost: bool) {
    let want_wg = enable_google_nat64 || enable_boost;
    let mut trigger_provision = false;

    {
        let Ok(mut st) = WARP_STATE.lock() else {
            return;
        };

        if !want_wg {
            let old_v4 = st.boost_ring_v4.drain_all();
            let old_v6 = st.boost_ring_v6.drain_all();
            if st.wg_up || if_index() != 0 {
                tear_down(&old_v4, &old_v6);
            }
            st.wg_up = false;
            st.nat64_on = false;
            st.boost_on = false;
            NAT64_READY.store(false, Ordering::Release);
            BOOST_ACTIVE.store(false, Ordering::Release);
            TUNNEL_PAUSED.store(false, Ordering::Release);
            reset_health_counters();
            return;
        }

        let (creds, has_persisted) = load_creds();
        if !has_persisted && !Path::new(WARP_CONFIG_PATH).exists() {
            trigger_provision = true;
        }

        if !st.wg_up || if_index() == 0 {
            if bring_up_device(&creds) {
                st.wg_up = true;
                st.client_v4 = creds.client_v4;
                st.client_v6 = creds.client_v6;
                st.endpoint_idx = WARP_ENDPOINTS
                    .iter()
                    .position(|&(ip, p)| ip == creds.endpoint_v4 && p == creds.endpoint_port)
                    .unwrap_or(0);
                st.endpoint_fails = 0;
                st.nat64_on = false;
                reset_health_counters();
            } else {
                NAT64_READY.store(false, Ordering::Release);
                BOOST_ACTIVE.store(false, Ordering::Release);
                return;
            }
        }

        if enable_google_nat64 && !st.nat64_on {
            if set_nat64_routes(&st.client_v6, true) {
                st.nat64_on = true;
            }
        } else if !enable_google_nat64 && st.nat64_on {
            let _ = set_nat64_routes(&st.client_v6, false);
            st.nat64_on = false;
        }

        if !enable_boost && st.boost_on {
            let old_v4 = st.boost_ring_v4.drain_all();
            let old_v6 = st.boost_ring_v6.drain_all();
            clear_boost_routes(&old_v4);
            clear_boost_v6_routes(&old_v6);
        }
        st.boost_on = enable_boost;
        TUNNEL_PAUSED.store(false, Ordering::Release);

        NAT64_READY.store(st.wg_up && st.nat64_on, Ordering::Release);
        BOOST_ACTIVE.store(st.wg_up && st.boost_on, Ordering::Release);
    }

    if trigger_provision {
        spawn_auto_provision(false);
    }
}

/// Installs `/32` IPv4 boost routes (`pref 5001 -> table 999`) for freshly resolved CDN/mirror IPs.
pub fn add_boost_ips(ips: &[[u8; 4]]) {
    if ips.is_empty() || !is_boost_active() {
        return;
    }
    let Ok(mut st) = WARP_STATE.lock() else {
        return;
    };
    if !st.wg_up || !st.boost_on || TUNNEL_PAUSED.load(Ordering::Acquire) {
        return;
    }
    let src_v4 = st.client_v4;
    let mut to_add = Vec::new();
    let mut to_del = Vec::new();
    for &ip in ips {
        if let Some(evicted) = st.boost_ring_v4.insert(ip) {
            to_add.push(ip);
            if let Some(old) = evicted {
                to_del.push(old);
            }
        }
    }
    if !to_add.is_empty() || !to_del.is_empty() {
        apply_boost_delta(&to_add, &to_del, src_v4);
    }
}

/// Installs `/128` IPv6 boost routes (`pref 5001 -> table 999`) for dual-stack Wi-Fi / 5G CDNs.
pub fn add_boost_v6_ips(ips: &[[u8; 16]]) {
    if ips.is_empty() || !is_boost_active() {
        return;
    }
    let Ok(mut st) = WARP_STATE.lock() else {
        return;
    };
    if !st.wg_up || !st.boost_on || TUNNEL_PAUSED.load(Ordering::Acquire) {
        return;
    }
    let src_v6 = st.client_v6;
    let mut to_add = Vec::new();
    let mut to_del = Vec::new();
    for &ip in ips {
        if let Some(evicted) = st.boost_ring_v6.insert(ip) {
            to_add.push(ip);
            if let Some(old) = evicted {
                to_del.push(old);
            }
        }
    }
    if !to_add.is_empty() || !to_del.is_empty() {
        apply_boost_v6_delta(&to_add, &to_del, src_v6);
    }
}

/// Called from `NetdNativeService::networkAddUidRangesParcel(SUB_PRIORITY_LOWEST)` (`force = false`)
/// and `networkAddInterface` on the active default network (`force = true`) at the exact moment
/// rule `29998` switches to the new default interface (Wi-Fi <-> LTE or `rmnet` swap).
/// No-ops immediately when `force == false` and `netid` has not changed (e.g. periodic 3s Wi-Fi
/// `SIGNAL_POLL` / `NetReassign [no changes]` UID-rule refreshes on the same `netId`).
pub fn on_network_change(netid: u32, force: bool) {
    use std::sync::atomic::AtomicU32;
    static LAST_NET: AtomicU32 = AtomicU32::new(0);

    let prev_net = LAST_NET.swap(netid, Ordering::Relaxed);
    if !force && prev_net == netid {
        return;
    }
    if !NAT64_READY.load(Ordering::Acquire) && !BOOST_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    let ep_idx = {
        let Ok(mut st) = WARP_STATE.lock() else {
            return;
        };
        if !st.wg_up {
            return;
        }
        let old_v4 = st.boost_ring_v4.drain_all();
        let old_v6 = st.boost_ring_v6.drain_all();
        clear_boost_routes(&old_v4);
        clear_boost_v6_routes(&old_v6);
        if prev_net != netid {
            // Switched to a different physical network: retry primary UDP/4500 endpoint first.
            st.endpoint_idx = 0;
        }
        st.endpoint_fails = 0;
        st.endpoint_idx
    };
    TUNNEL_PAUSED.store(false, Ordering::Release);
    reset_health_counters();

    let (mut creds, _) = load_creds();
    let (ep_ip, ep_port) = WARP_ENDPOINTS[ep_idx % WARP_ENDPOINTS.len()];
    creds.endpoint_v4 = ep_ip;
    creds.endpoint_port = ep_port;
    let _ = switch_wg_endpoint(&creds);
}

/// Checks whether `wg_saring0` is healthy using delta TX/RX byte counters:
/// 1. Fail-open circuit breaker: immediately pauses `wg_saring0` (`TUNNEL_PAUSED = true`) and
///    flushes `pref 5001` boost rules so both `google.com` and boosted apps fail open to direct
///    instead of stalling on UDP-blocking Wi-Fi/cellular networks.
/// 2. Rotates across fallback Cloudflare WARP endpoints/ports (4500 <-> 2408).
/// 3. Triggers keypair re-registration only after all endpoints fail.
/// Clears the circuit breaker automatically once `keepalive=15s` completes a healthy handshake.
fn check_self_heal() {
    if !NAT64_READY.load(Ordering::Acquire) && !BOOST_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let Some((tx, rx, hs)) = query_peer_stats() else {
        return;
    };
    let prev_tx = PREV_TX.swap(tx, Ordering::Relaxed);
    let prev_rx = PREV_RX.swap(rx, Ordering::Relaxed);
    let dtx = if tx >= prev_tx { tx - prev_tx } else { tx };
    let drx = if rx >= prev_rx { rx - prev_rx } else { rx };

    // WireGuard handshake initiation is 148 bytes every 5s (keepalive=15s initiates immediately).
    // - No handshake yet: >= 296B TX (2 failed initiations) with 0 RX => endpoint/port blocked.
    // - Mid-session blackhole: >= 444B delta TX (3 failed rekeys or active traffic) with 0 delta RX.
    // Idle keepalives are only 32B/15s, so an idle healthy tunnel never false-triggers.
    let stalled = (tx >= 296 && rx == 0 && hs == 0) || (dtx >= 444 && drx == 0);
    if !stalled {
        if hs > 0 && (drx > 0 || (rx > 0 && TUNNEL_PAUSED.load(Ordering::Acquire))) {
            TUNNEL_PAUSED.store(false, Ordering::Release);
        }
        if hs > 0 && rx > 0 {
            if let Ok(mut st) = WARP_STATE.lock() {
                st.endpoint_fails = 0;
            }
        }
        return;
    }

    // Tunnel is stalled: trip fail-open circuit breaker and rotate endpoint/port.
    TUNNEL_PAUSED.store(true, Ordering::Release);
    let (rotate_to, should_renew_key) = {
        let Ok(mut st) = WARP_STATE.lock() else {
            return;
        };
        if !st.wg_up {
            return;
        }
        let old_v4 = st.boost_ring_v4.drain_all();
        let old_v6 = st.boost_ring_v6.drain_all();
        clear_boost_routes(&old_v4);
        clear_boost_v6_routes(&old_v6);
        st.endpoint_fails += 1;
        if st.endpoint_fails < WARP_ENDPOINTS.len() {
            st.endpoint_idx = (st.endpoint_idx + 1) % WARP_ENDPOINTS.len();
            (Some(WARP_ENDPOINTS[st.endpoint_idx]), false)
        } else {
            st.endpoint_fails = 0;
            (None, true)
        }
    };

    if let Some((ep_ip, ep_port)) = rotate_to {
        let (mut creds, _) = load_creds();
        creds.endpoint_v4 = ep_ip;
        creds.endpoint_port = ep_port;
        reset_health_counters();
        let _ = switch_wg_endpoint(&creds);
    } else if should_renew_key {
        spawn_auto_provision(true);
    }
}

#[cfg(not(all(target_os = "android", feature = "netd")))]
fn spawn_auto_provision(_force_replace: bool) {}

#[cfg(all(target_os = "android", feature = "netd"))]
fn spawn_auto_provision(force_replace: bool) {
    if PROVISIONING.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("saring-warp-reg".into())
        .spawn(move || {
            for &delay_secs in &[3u64, 8, 20, 45] {
                std::thread::sleep(std::time::Duration::from_secs(delay_secs));
                if !force_replace && Path::new(WARP_CONFIG_PATH).exists() {
                    break;
                }
                if force_replace && !needs_key_renewal() {
                    break;
                }
                if let Some(mut creds) = android_provision::register_ephemeral_warp() {
                    if let Ok(st) = WARP_STATE.lock() {
                        let (ep_ip, ep_port) = WARP_ENDPOINTS[st.endpoint_idx % WARP_ENDPOINTS.len()];
                        creds.endpoint_v4 = ep_ip;
                        creds.endpoint_port = ep_port;
                    }
                    if save_creds(&creds) {
                        hot_reload_creds(&creds);
                        break;
                    }
                }
            }
            PROVISIONING.store(false, Ordering::Release);
        });
}

#[cfg(all(target_os = "android", feature = "netd"))]
fn hot_reload_creds(creds: &WarpCreds) {
    let Ok(mut st) = WARP_STATE.lock() else {
        return;
    };
    if !st.wg_up {
        return;
    }
    let old_v4 = st.client_v4;
    let old_v6 = st.client_v6;
    let was_nat64 = st.nat64_on;
    let boost_v4 = st.boost_ring_v4.ips[..st.boost_ring_v4.len].to_vec();
    let boost_v6 = st.boost_ring_v6.ips[..st.boost_ring_v6.len].to_vec();
    if bring_up_device(creds) {
        remove_stale_addrs(
            (old_v4 != creds.client_v4).then_some(&old_v4),
            (old_v6 != creds.client_v6).then_some(&old_v6),
        );
        st.client_v4 = creds.client_v4;
        st.client_v6 = creds.client_v6;
        reset_health_counters();
        if was_nat64 {
            let _ = set_nat64_routes(&creds.client_v6, true);
        }
        if st.boost_on && !boost_v4.is_empty() {
            apply_boost_delta(&boost_v4, &[], creds.client_v4);
        }
        if st.boost_on && !boost_v6.is_empty() {
            apply_boost_v6_delta(&boost_v6, &[], creds.client_v6);
        }
    }
}

/// Periodic self-heal entry called lazily from DNS/state paths (throttled to once every 15s).
pub fn maybe_check_health(now_secs: i64) {
    use std::sync::atomic::AtomicI64;
    static LAST_CHECK: AtomicI64 = AtomicI64::new(0);
    if now_secs < 30 || (!NAT64_READY.load(Ordering::Acquire) && !BOOST_ACTIVE.load(Ordering::Acquire)) {
        return;
    }
    let prev = LAST_CHECK.load(Ordering::Relaxed);
    if now_secs.saturating_sub(prev) < 15 {
        return;
    }
    if LAST_CHECK
        .compare_exchange(prev, now_secs, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        check_self_heal();
    }
}

#[cfg(not(target_os = "android"))]
fn if_index() -> u32 {
    0
}

#[cfg(not(target_os = "android"))]
fn bring_up_device(_creds: &WarpCreds) -> bool {
    false
}

#[cfg(not(target_os = "android"))]
fn switch_wg_endpoint(_creds: &WarpCreds) -> bool {
    false
}

#[cfg(not(target_os = "android"))]
fn set_nat64_routes(_src_v6: &[u8; 16], _enable: bool) -> bool {
    false
}

#[cfg(not(target_os = "android"))]
fn apply_boost_delta(_add: &[[u8; 4]], _del: &[[u8; 4]], _src_v4: [u8; 4]) {}

#[cfg(not(target_os = "android"))]
fn clear_boost_routes(_ips: &[[u8; 4]]) {}

#[cfg(not(target_os = "android"))]
fn apply_boost_v6_delta(_add: &[[u8; 16]], _del: &[[u8; 16]], _src_v6: [u8; 16]) {}

#[cfg(not(target_os = "android"))]
fn clear_boost_v6_routes(_ips: &[[u8; 16]]) {}

#[cfg(not(target_os = "android"))]
fn tear_down(_boost_v4: &[[u8; 4]], _boost_v6: &[[u8; 16]]) {}

#[cfg(not(target_os = "android"))]
fn query_peer_stats() -> Option<(u64, u64, i64)> {
    None
}

#[cfg(target_os = "android")]
use android_nl::{
    apply_boost_delta, apply_boost_v6_delta, bring_up_device, clear_boost_routes,
    clear_boost_v6_routes, if_index, query_peer_stats, set_nat64_routes, switch_wg_endpoint,
    tear_down,
};
#[cfg(all(target_os = "android", feature = "netd"))]
use android_nl::{needs_key_renewal, remove_stale_addrs};

#[cfg(all(target_os = "android", feature = "netd"))]
mod android_provision {
    use super::*;

    const API_IPS: [[u8; 4]; 2] = [[104, 16, 192, 82], [104, 16, 24, 84]];

    extern "C" {
        fn X25519_keypair(out_public_value: *mut u8, out_private_key: *mut u8);
    }

    pub fn register_ephemeral_warp() -> Option<WarpCreds> {
        let mut pub_key = [0u8; 32];
        let mut priv_key = [0u8; 32];
        // SAFETY: BoringSSL X25519_keypair fills two 32-byte stack buffers.
        unsafe { X25519_keypair(pub_key.as_mut_ptr(), priv_key.as_mut_ptr()) };

        let pub_b64 = base64_encode(&pub_key);
        let body = format!(
            "{{\"key\":\"{pub_b64}\",\"tos\":\"2023-09-01T00:00:00.000Z\",\"type\":\"Android\",\"model\":\"onyx\"}}"
        );
        let req = format!(
            "POST /v0a2158/reg HTTP/1.1\r\n\
             Host: api.cloudflareclient.com\r\n\
             User-Agent: okhttp/3.12.1\r\n\
             CF-Client-Version: a-6.30-3596\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {body}",
            body.len()
        );

        for &ip in &API_IPS {
            let Some(resp) = crate::upstream::https_request(
                ip,
                b"api.cloudflareclient.com\0",
                req.as_bytes(),
            ) else {
                continue;
            };
            if let Ok(text) = std::str::from_utf8(&resp) {
                if let Some(split) = text.find("\r\n\r\n") {
                    let json_part = &text[split + 4..];
                    if let Some(creds) = parse_warp_reg_json(json_part, priv_key) {
                        return Some(creds);
                    }
                }
            }
        }
        None
    }
}

#[cfg(target_os = "android")]
mod android_nl {
    use super::*;

    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    const AF_NETLINK: i32 = 16;
    const SOCK_RAW: i32 = 3;
    const SOCK_CLOEXEC: i32 = 0o2000000;

    const NETLINK_ROUTE: i32 = 0;
    const NETLINK_GENERIC: i32 = 16;

    const NLM_F_REQUEST: u16 = 0x01;
    const NLM_F_ACK: u16 = 0x04;
    const NLM_F_ROOT: u16 = 0x100;
    const NLM_F_MATCH: u16 = 0x200;
    const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
    const NLM_F_EXCL: u16 = 0x200;
    const NLM_F_CREATE: u16 = 0x400;
    const NLM_F_REPLACE: u16 = 0x100;

    const NLMSG_ERROR: u16 = 0x02;
    const NLMSG_DONE: u16 = 0x03;
    const NLMSG_HDRLEN: usize = 16;
    const GENL_HDRLEN: usize = 4;
    const NLA_HDRLEN: usize = 4;
    const NLA_F_NESTED: u16 = 1 << 15;
    const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | (1 << 14));

    const GENL_ID_CTRL: u16 = 0x10;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;

    const WG_CMD_GET_DEVICE: u8 = 0;
    const WG_CMD_SET_DEVICE: u8 = 1;
    const WGDEVICE_F_REPLACE_PEERS: u32 = 1;
    const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;

    const WGDEVICE_A_IFNAME: u16 = 2;
    const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
    const WGDEVICE_A_FLAGS: u16 = 5;
    const WGDEVICE_A_LISTEN_PORT: u16 = 6;
    const WGDEVICE_A_PEERS: u16 = 8;

    const WGPEER_A_PUBLIC_KEY: u16 = 1;
    const WGPEER_A_FLAGS: u16 = 3;
    const WGPEER_A_ENDPOINT: u16 = 4;
    const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
    const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
    const WGPEER_A_RX_BYTES: u16 = 7;
    const WGPEER_A_TX_BYTES: u16 = 8;
    const WGPEER_A_ALLOWEDIPS: u16 = 9;

    const WGALLOWEDIP_A_FAMILY: u16 = 1;
    const WGALLOWEDIP_A_IPADDR: u16 = 2;
    const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

    const RTM_NEWLINK: u16 = 16;
    const RTM_DELLINK: u16 = 17;
    const RTM_NEWADDR: u16 = 20;
    #[cfg(feature = "netd")]
    const RTM_DELADDR: u16 = 21;
    const RTM_NEWROUTE: u16 = 24;
    const RTM_DELROUTE: u16 = 25;
    const RTM_NEWRULE: u16 = 32;
    const RTM_DELRULE: u16 = 33;
    const RTM_NEWQDISC: u16 = 36;

    const IFF_UP: u32 = 0x1;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_MTU: u16 = 4;
    const IFLA_LINKINFO: u16 = 18;
    const IFLA_INFO_KIND: u16 = 1;

    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    const IFA_F_NODAD: u8 = 0x02;

    const RT_TABLE_UNSPEC: u8 = 0;
    const RTPROT_STATIC: u8 = 4;
    const RT_SCOPE_UNIVERSE: u8 = 0;
    const RT_SCOPE_LINK: u8 = 253;
    const RT_SCOPE_NOWHERE: u8 = 255;
    const RTN_UNICAST: u8 = 1;

    const RTA_DST: u16 = 1;
    const RTA_OIF: u16 = 4;
    const RTA_PREFSRC: u16 = 7;
    const RTA_METRICS: u16 = 8;
    const RTA_TABLE: u16 = 15;

    const RTAX_INITCWND: u16 = 11;
    const RTAX_INITRWND: u16 = 14;

    const TC_H_ROOT: u32 = 0xFFFF_FFFF;
    const TCA_KIND: u16 = 1;

    const FR_ACT_TO_TBL: u8 = 1;
    const FRA_DST: u16 = 1;
    const FRA_PRIORITY: u16 = 6;
    const FRA_TABLE: u16 = 15;

    extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        fn send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
        fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
        fn close(fd: i32) -> i32;
        fn if_nametoindex(ifname: *const u8) -> u32;
    }

    pub fn if_index() -> u32 {
        // SAFETY: IFNAME is NUL-terminated.
        unsafe { if_nametoindex(IFNAME.as_ptr()) }
    }

    struct NlSocket(i32);

    impl NlSocket {
        fn open(proto: i32) -> Option<Self> {
            // SAFETY: standard POSIX socket syscall.
            let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, proto) };
            if fd < 0 {
                None
            } else {
                Some(Self(fd))
            }
        }

        fn request(&self, msg: &mut [u8], len: usize) -> Result<(), i32> {
            let total = len as u32;
            msg[0..4].copy_from_slice(&total.to_ne_bytes());
            // SAFETY: msg[..len] is valid inside buffer.
            let sent = unsafe { send(self.0, msg.as_ptr(), len, 0) };
            if sent < 0 {
                return Err(-1);
            }
            let mut rbuf = [0u8; 512];
            // SAFETY: rbuf is writable on stack.
            let rlen = unsafe { recv(self.0, rbuf.as_mut_ptr(), rbuf.len(), 0) };
            if rlen < (NLMSG_HDRLEN + 4) as isize {
                return Err(-1);
            }
            let nlmsg_type = u16::from_ne_bytes([rbuf[4], rbuf[5]]);
            if nlmsg_type == NLMSG_ERROR {
                let err = i32::from_ne_bytes([rbuf[16], rbuf[17], rbuf[18], rbuf[19]]);
                if err != 0 {
                    return Err(err);
                }
            }
            Ok(())
        }
    }

    impl Drop for NlSocket {
        fn drop(&mut self) {
            // SAFETY: valid owned fd.
            unsafe {
                close(self.0);
            }
        }
    }

    #[inline]
    const fn nla_align(len: usize) -> usize {
        (len + 3) & !3
    }

    fn nla_put(buf: &mut [u8], len: &mut usize, ty: u16, data: &[u8]) {
        let alen = NLA_HDRLEN + data.len();
        let total = nla_align(alen);
        let at = *len;
        buf[at..at + total].fill(0);
        buf[at..at + 2].copy_from_slice(&(alen as u16).to_ne_bytes());
        buf[at + 2..at + 4].copy_from_slice(&ty.to_ne_bytes());
        buf[at + 4..at + 4 + data.len()].copy_from_slice(data);
        *len += total;
    }

    fn nla_nest_start(buf: &mut [u8], len: &mut usize, ty: u16) -> usize {
        let start = *len;
        buf[start..start + 2].copy_from_slice(&(NLA_HDRLEN as u16).to_ne_bytes());
        buf[start + 2..start + 4].copy_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        *len += NLA_HDRLEN;
        start
    }

    fn nla_nest_end(buf: &mut [u8], len: usize, start: usize) {
        let nlen = (len - start) as u16;
        buf[start..start + 2].copy_from_slice(&nlen.to_ne_bytes());
    }

    fn init_nlhdr(buf: &mut [u8], ty: u16, flags: u16, seq: u32) -> usize {
        buf[..NLMSG_HDRLEN].fill(0);
        buf[4..6].copy_from_slice(&ty.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        NLMSG_HDRLEN
    }

    fn wg_family_id(nl: &NlSocket) -> Option<u16> {
        let mut buf = [0u8; 256];
        // Do NOT pass NLM_F_ACK here: CTRL_CMD_GETFAMILY already sends a reply message, so
        // NLM_F_ACK would queue a trailing NLMSG_ERROR(0) that corrupts subsequent recv() calls.
        let mut len = init_nlhdr(&mut buf, GENL_ID_CTRL, NLM_F_REQUEST, 1);
        buf[len] = CTRL_CMD_GETFAMILY;
        buf[len + 1] = 1;
        buf[len + 2..len + 4].fill(0);
        len += GENL_HDRLEN;
        nla_put(&mut buf, &mut len, CTRL_ATTR_FAMILY_NAME, WG_GENL_NAME);

        let total = len as u32;
        buf[0..4].copy_from_slice(&total.to_ne_bytes());
        // SAFETY: sending netlink control query.
        if unsafe { send(nl.0, buf.as_ptr(), len, 0) } < 0 {
            return None;
        }
        let mut rbuf = [0u8; 512];
        // SAFETY: receiving netlink control response.
        let rlen = unsafe { recv(nl.0, rbuf.as_mut_ptr(), rbuf.len(), 0) };
        if rlen < (NLMSG_HDRLEN + GENL_HDRLEN) as isize {
            return None;
        }
        let rlen = rlen as usize;
        if u16::from_ne_bytes([rbuf[4], rbuf[5]]) == NLMSG_ERROR {
            return None;
        }
        let mut off = NLMSG_HDRLEN + GENL_HDRLEN;
        while off + NLA_HDRLEN <= rlen {
            let alen = u16::from_ne_bytes([rbuf[off], rbuf[off + 1]]) as usize;
            let atype = u16::from_ne_bytes([rbuf[off + 2], rbuf[off + 3]]) & NLA_TYPE_MASK;
            if alen < NLA_HDRLEN || off + alen > rlen {
                break;
            }
            if atype == CTRL_ATTR_FAMILY_ID && alen >= NLA_HDRLEN + 2 {
                return Some(u16::from_ne_bytes([rbuf[off + 4], rbuf[off + 5]]));
            }
            off += nla_align(alen);
        }
        None
    }

    /// Queries `WG_CMD_GET_DEVICE` for `(tx_bytes, rx_bytes, last_handshake_sec)`.
    pub fn query_peer_stats() -> Option<(u64, u64, i64)> {
        let genl = NlSocket::open(NETLINK_GENERIC)?;
        let fam = wg_family_id(&genl)?;
        let mut buf = [0u8; 128];
        let mut len = init_nlhdr(&mut buf, fam, NLM_F_REQUEST | NLM_F_DUMP, 99);
        buf[len] = WG_CMD_GET_DEVICE;
        buf[len + 1] = WG_GENL_VERSION;
        buf[len + 2..len + 4].fill(0);
        len += GENL_HDRLEN;
        nla_put(&mut buf, &mut len, WGDEVICE_A_IFNAME, IFNAME);
        buf[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
        // SAFETY: sending netlink dump query.
        if unsafe { send(genl.0, buf.as_ptr(), len, 0) } < 0 {
            return None;
        }

        let mut rbuf = [0u8; 2048];
        // SAFETY: receiving netlink dump response.
        let rlen = unsafe { recv(genl.0, rbuf.as_mut_ptr(), rbuf.len(), 0) };
        if rlen < (NLMSG_HDRLEN + GENL_HDRLEN) as isize {
            return None;
        }
        let rlen = rlen as usize;
        let ty = u16::from_ne_bytes([rbuf[4], rbuf[5]]);
        if ty == NLMSG_ERROR || ty == NLMSG_DONE {
            return None;
        }
        let msg_end =
            (u32::from_ne_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]) as usize).min(rlen);

        let mut tx_bytes = 0u64;
        let mut rx_bytes = 0u64;
        let mut handshake_sec = 0i64;
        let mut off = NLMSG_HDRLEN + GENL_HDRLEN;
        while off + NLA_HDRLEN <= msg_end {
            let alen = u16::from_ne_bytes([rbuf[off], rbuf[off + 1]]) as usize;
            let atype = u16::from_ne_bytes([rbuf[off + 2], rbuf[off + 3]]) & NLA_TYPE_MASK;
            if alen < NLA_HDRLEN || off + alen > msg_end {
                break;
            }
            if atype == WGDEVICE_A_PEERS {
                let mut poff = off + NLA_HDRLEN;
                let pend = off + alen;
                while poff + NLA_HDRLEN <= pend {
                    let plen = u16::from_ne_bytes([rbuf[poff], rbuf[poff + 1]]) as usize;
                    if plen < NLA_HDRLEN || poff + plen > pend {
                        break;
                    }
                    let mut aoff = poff + NLA_HDRLEN;
                    let aend = poff + plen;
                    while aoff + NLA_HDRLEN <= aend {
                        let slen = u16::from_ne_bytes([rbuf[aoff], rbuf[aoff + 1]]) as usize;
                        let stype =
                            u16::from_ne_bytes([rbuf[aoff + 2], rbuf[aoff + 3]]) & NLA_TYPE_MASK;
                        if slen < NLA_HDRLEN || aoff + slen > aend {
                            break;
                        }
                        if stype == WGPEER_A_TX_BYTES && slen >= NLA_HDRLEN + 8 {
                            tx_bytes = u64::from_ne_bytes(
                                rbuf[aoff + 4..aoff + 12].try_into().unwrap_or([0; 8]),
                            );
                        } else if stype == WGPEER_A_RX_BYTES && slen >= NLA_HDRLEN + 8 {
                            rx_bytes = u64::from_ne_bytes(
                                rbuf[aoff + 4..aoff + 12].try_into().unwrap_or([0; 8]),
                            );
                        } else if stype == WGPEER_A_LAST_HANDSHAKE_TIME && slen >= NLA_HDRLEN + 8 {
                            handshake_sec = i64::from_ne_bytes(
                                rbuf[aoff + 4..aoff + 12].try_into().unwrap_or([0; 8]),
                            );
                        }
                        aoff += nla_align(slen);
                    }
                    poff += nla_align(plen);
                }
            }
            off += nla_align(alen);
        }
        Some((tx_bytes, rx_bytes, handshake_sec))
    }

    /// Returns true when handshake initiations were transmitted (`tx >= 296`, i.e. 2× 148B)
    /// with zero RX and zero completed handshakes.
    #[cfg(feature = "netd")]
    pub fn needs_key_renewal() -> bool {
        query_peer_stats()
            .is_some_and(|(tx, rx, hs)| tx >= 296 && rx == 0 && hs == 0)
    }

    fn ensure_wg_link(rtnl: &NlSocket) -> bool {
        let mut buf = [0u8; 256];
        let existing = if_index();
        if existing != 0 {
            let mut len = init_nlhdr(&mut buf, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 10);
            buf[len..len + 16].fill(0);
            buf[len + 4..len + 8].copy_from_slice(&(existing as i32).to_ne_bytes());
            buf[len + 8..len + 12].copy_from_slice(&IFF_UP.to_ne_bytes());
            buf[len + 12..len + 16].copy_from_slice(&IFF_UP.to_ne_bytes());
            len += 16;
            nla_put(&mut buf, &mut len, IFLA_MTU, &WG_MTU.to_ne_bytes());
            return rtnl.request(&mut buf, len).is_ok();
        }
        let mut len = init_nlhdr(
            &mut buf,
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
            10,
        );
        buf[len..len + 16].fill(0);
        buf[len + 8..len + 12].copy_from_slice(&IFF_UP.to_ne_bytes());
        buf[len + 12..len + 16].copy_from_slice(&IFF_UP.to_ne_bytes());
        len += 16;

        nla_put(&mut buf, &mut len, IFLA_IFNAME, IFNAME);
        nla_put(&mut buf, &mut len, IFLA_MTU, &WG_MTU.to_ne_bytes());
        let linkinfo = nla_nest_start(&mut buf, &mut len, IFLA_LINKINFO);
        nla_put(&mut buf, &mut len, IFLA_INFO_KIND, WG_GENL_NAME);
        nla_nest_end(&mut buf, len, linkinfo);

        rtnl.request(&mut buf, len).is_ok()
    }

    fn configure_wg_peer(creds: &WarpCreds) -> bool {
        let Some(genl) = NlSocket::open(NETLINK_GENERIC) else {
            return false;
        };
        let Some(fam) = wg_family_id(&genl) else {
            return false;
        };

        let mut buf = [0u8; 1024];
        let mut len = init_nlhdr(&mut buf, fam, NLM_F_REQUEST | NLM_F_ACK, 20);
        buf[len] = WG_CMD_SET_DEVICE;
        buf[len + 1] = WG_GENL_VERSION;
        buf[len + 2..len + 4].fill(0);
        len += GENL_HDRLEN;

        nla_put(&mut buf, &mut len, WGDEVICE_A_IFNAME, IFNAME);
        nla_put(&mut buf, &mut len, WGDEVICE_A_PRIVATE_KEY, &creds.priv_key);
        // Setting listen_port=0 forces wg_socket_init(wg, 0) to bind a fresh ephemeral UDP source
        // port and clear sticky endpoint src/dst_cache, breaking poisoned NAT/CGNAT 5-tuples on
        // LTE <-> Wi-Fi roaming and ISP UDP flow blackholes.
        nla_put(&mut buf, &mut len, WGDEVICE_A_LISTEN_PORT, &0u16.to_ne_bytes());
        nla_put(
            &mut buf,
            &mut len,
            WGDEVICE_A_FLAGS,
            &WGDEVICE_F_REPLACE_PEERS.to_ne_bytes(),
        );

        let peers = nla_nest_start(&mut buf, &mut len, WGDEVICE_A_PEERS);
        let peer0 = nla_nest_start(&mut buf, &mut len, 0);
        nla_put(&mut buf, &mut len, WGPEER_A_PUBLIC_KEY, &creds.peer_pub);
        nla_put(
            &mut buf,
            &mut len,
            WGPEER_A_FLAGS,
            &WGPEER_F_REPLACE_ALLOWEDIPS.to_ne_bytes(),
        );

        let mut sin = [0u8; 16];
        sin[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        sin[2..4].copy_from_slice(&creds.endpoint_port.to_be_bytes());
        sin[4..8].copy_from_slice(&creds.endpoint_v4);
        nla_put(&mut buf, &mut len, WGPEER_A_ENDPOINT, &sin);

        let keepalive: u16 = 15;
        nla_put(
            &mut buf,
            &mut len,
            WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
            &keepalive.to_ne_bytes(),
        );

        let aips = nla_nest_start(&mut buf, &mut len, WGPEER_A_ALLOWEDIPS);
        let aip4 = nla_nest_start(&mut buf, &mut len, 0);
        nla_put(&mut buf, &mut len, WGALLOWEDIP_A_FAMILY, &AF_INET.to_ne_bytes());
        nla_put(&mut buf, &mut len, WGALLOWEDIP_A_IPADDR, &[0u8; 4]);
        nla_put(&mut buf, &mut len, WGALLOWEDIP_A_CIDR_MASK, &[0u8]);
        nla_nest_end(&mut buf, len, aip4);

        let aip6 = nla_nest_start(&mut buf, &mut len, 1);
        nla_put(&mut buf, &mut len, WGALLOWEDIP_A_FAMILY, &AF_INET6.to_ne_bytes());
        nla_put(&mut buf, &mut len, WGALLOWEDIP_A_IPADDR, &[0u8; 16]);
        nla_put(&mut buf, &mut len, WGALLOWEDIP_A_CIDR_MASK, &[0u8]);
        nla_nest_end(&mut buf, len, aip6);
        nla_nest_end(&mut buf, len, aips);

        nla_nest_end(&mut buf, len, peer0);
        nla_nest_end(&mut buf, len, peers);

        genl.request(&mut buf, len).is_ok()
    }

    fn add_v4_addr(rtnl: &NlSocket, ifindex: u32, v4: &[u8; 4]) -> bool {
        let mut buf = [0u8; 256];
        let mut len = init_nlhdr(
            &mut buf,
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            29,
        );
        buf[len] = AF_INET as u8;
        buf[len + 1] = 32;
        buf[len + 2] = 0;
        buf[len + 3] = RT_SCOPE_UNIVERSE;
        buf[len + 4..len + 8].copy_from_slice(&ifindex.to_ne_bytes());
        len += 8;

        nla_put(&mut buf, &mut len, IFA_LOCAL, v4);
        nla_put(&mut buf, &mut len, IFA_ADDRESS, v4);
        matches!(rtnl.request(&mut buf, len), Ok(()) | Err(-17))
    }

    fn add_v6_addr(rtnl: &NlSocket, ifindex: u32, v6: &[u8; 16]) -> bool {
        let mut buf = [0u8; 256];
        let mut len = init_nlhdr(
            &mut buf,
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            30,
        );
        buf[len] = AF_INET6 as u8;
        buf[len + 1] = 128;
        buf[len + 2] = IFA_F_NODAD;
        buf[len + 3] = RT_SCOPE_UNIVERSE;
        buf[len + 4..len + 8].copy_from_slice(&ifindex.to_ne_bytes());
        len += 8;

        nla_put(&mut buf, &mut len, IFA_LOCAL, v6);
        nla_put(&mut buf, &mut len, IFA_ADDRESS, v6);
        matches!(rtnl.request(&mut buf, len), Ok(()) | Err(-17))
    }

    #[cfg(feature = "netd")]
    fn del_v4_addr(rtnl: &NlSocket, ifindex: u32, v4: &[u8; 4]) {
        let mut buf = [0u8; 256];
        let mut len = init_nlhdr(&mut buf, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, 31);
        buf[len] = AF_INET as u8;
        buf[len + 1] = 32;
        buf[len + 2] = 0;
        buf[len + 3] = RT_SCOPE_UNIVERSE;
        buf[len + 4..len + 8].copy_from_slice(&ifindex.to_ne_bytes());
        len += 8;

        nla_put(&mut buf, &mut len, IFA_LOCAL, v4);
        nla_put(&mut buf, &mut len, IFA_ADDRESS, v4);
        let _ = rtnl.request(&mut buf, len);
    }

    #[cfg(feature = "netd")]
    fn del_v6_addr(rtnl: &NlSocket, ifindex: u32, v6: &[u8; 16]) {
        let mut buf = [0u8; 256];
        let mut len = init_nlhdr(&mut buf, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, 32);
        buf[len] = AF_INET6 as u8;
        buf[len + 1] = 128;
        buf[len + 2] = 0;
        buf[len + 3] = RT_SCOPE_UNIVERSE;
        buf[len + 4..len + 8].copy_from_slice(&ifindex.to_ne_bytes());
        len += 8;

        nla_put(&mut buf, &mut len, IFA_LOCAL, v6);
        nla_put(&mut buf, &mut len, IFA_ADDRESS, v6);
        let _ = rtnl.request(&mut buf, len);
    }

    #[cfg(feature = "netd")]
    pub fn remove_stale_addrs(old_v4: Option<&[u8; 4]>, old_v6: Option<&[u8; 16]>) {
        if old_v4.is_none() && old_v6.is_none() {
            return;
        }
        let Some(rtnl) = NlSocket::open(NETLINK_ROUTE) else {
            return;
        };
        let idx = if_index();
        if idx == 0 {
            return;
        }
        if let Some(v4) = old_v4 {
            del_v4_addr(&rtnl, idx, v4);
        }
        if let Some(v6) = old_v6 {
            del_v6_addr(&rtnl, idx, v6);
        }
    }

    fn put_route_metrics(buf: &mut [u8], len: &mut usize) {
        let metrics = nla_nest_start(buf, len, RTA_METRICS);
        nla_put(buf, len, RTAX_INITCWND, &SARING_INITCWND.to_ne_bytes());
        nla_put(buf, len, RTAX_INITRWND, &SARING_INITRWND.to_ne_bytes());
        nla_nest_end(buf, *len, metrics);
    }

    fn attach_fq_qdisc(rtnl: &NlSocket, ifindex: u32) {
        let mut buf = [0u8; 128];
        let mut len = init_nlhdr(
            &mut buf,
            RTM_NEWQDISC,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            15,
        );
        // struct tcmsg (20 bytes): family/pad(4), ifindex(4), handle(4), parent(4), info(4).
        buf[len..len + 20].fill(0);
        buf[len + 4..len + 8].copy_from_slice(&(ifindex as i32).to_ne_bytes());
        buf[len + 12..len + 16].copy_from_slice(&TC_H_ROOT.to_ne_bytes());
        len += 20;
        nla_put(&mut buf, &mut len, TCA_KIND, b"fq\0");
        let _ = rtnl.request(&mut buf, len);
    }

    fn tune_wg_rps() {
        // Spread WireGuard RX decryption across Cortex-A720 mid/big cores (cpu2..cpu6 = 0x7c)
        // and enable per-queue RFS (netd.te permits writing sysfs_net files).
        let _ = fs::write("/sys/class/net/wg_saring0/queues/rx-0/rps_cpus", "7c");
        let _ = fs::write("/sys/class/net/wg_saring0/queues/rx-0/rps_flow_cnt", "4096");
    }

    fn mod_v4_route(
        rtnl: &NlSocket,
        ifindex: u32,
        dst: &[u8; 4],
        src_v4: &[u8; 4],
        add: bool,
        seq: u32,
    ) -> bool {
        let mut buf = [0u8; 256];
        let ty = if add { RTM_NEWROUTE } else { RTM_DELROUTE };
        let flags = if add {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        } else {
            NLM_F_REQUEST | NLM_F_ACK
        };
        let mut len = init_nlhdr(&mut buf, ty, flags, seq);
        buf[len..len + 12].fill(0);
        buf[len] = AF_INET as u8;
        buf[len + 1] = 32;
        buf[len + 4] = RT_TABLE_UNSPEC;
        buf[len + 5] = if add { RTPROT_STATIC } else { 0 };
        buf[len + 6] = if add { RT_SCOPE_LINK } else { RT_SCOPE_NOWHERE };
        buf[len + 7] = RTN_UNICAST;
        len += 12;

        nla_put(&mut buf, &mut len, RTA_TABLE, &ROUTE_TABLE_SARING.to_ne_bytes());
        nla_put(&mut buf, &mut len, RTA_DST, dst);
        nla_put(&mut buf, &mut len, RTA_OIF, &ifindex.to_ne_bytes());
        if add {
            nla_put(&mut buf, &mut len, RTA_PREFSRC, src_v4);
            put_route_metrics(&mut buf, &mut len);
        }
        rtnl.request(&mut buf, len).is_ok()
    }

    fn mod_v4_rule(rtnl: &NlSocket, dst: &[u8; 4], add: bool, seq: u32) -> bool {
        let mut buf = [0u8; 256];
        let ty = if add { RTM_NEWRULE } else { RTM_DELRULE };
        let flags = if add {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        } else {
            NLM_F_REQUEST | NLM_F_ACK
        };
        let mut len = init_nlhdr(&mut buf, ty, flags, seq);
        buf[len..len + 12].fill(0);
        buf[len] = AF_INET as u8;
        buf[len + 1] = 32;
        buf[len + 4] = RT_TABLE_UNSPEC;
        buf[len + 7] = FR_ACT_TO_TBL;
        len += 12;

        nla_put(&mut buf, &mut len, FRA_PRIORITY, &RULE_PREF_BOOST.to_ne_bytes());
        nla_put(&mut buf, &mut len, FRA_TABLE, &ROUTE_TABLE_SARING.to_ne_bytes());
        nla_put(&mut buf, &mut len, FRA_DST, dst);
        match rtnl.request(&mut buf, len) {
            Ok(()) => true,
            Err(-17) if add => true,
            Err(-2) if !add => true,
            Err(_) => false,
        }
    }

    fn del_v6_route(rtnl: &NlSocket, ifindex: u32, dst: &[u8; 16], prefix_len: u8, seq: u32) {
        let mut buf = [0u8; 256];
        let mut len = init_nlhdr(&mut buf, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, seq);
        buf[len..len + 12].fill(0);
        buf[len] = AF_INET6 as u8;
        buf[len + 1] = prefix_len;
        buf[len + 4] = RT_TABLE_UNSPEC;
        buf[len + 7] = RTN_UNICAST;
        len += 12;

        nla_put(&mut buf, &mut len, RTA_TABLE, &ROUTE_TABLE_SARING.to_ne_bytes());
        nla_put(&mut buf, &mut len, RTA_DST, dst);
        nla_put(&mut buf, &mut len, RTA_OIF, &ifindex.to_ne_bytes());
        let _ = rtnl.request(&mut buf, len);
    }

    fn add_v6_route(
        rtnl: &NlSocket,
        ifindex: u32,
        dst: &[u8; 16],
        prefix_len: u8,
        src_v6: &[u8; 16],
        seq: u32,
    ) -> bool {
        // Delete any stale entry first so RTA_PREFSRC is always updated cleanly on key rotation.
        del_v6_route(rtnl, ifindex, dst, prefix_len, seq.wrapping_add(1000));
        let mut buf = [0u8; 256];
        let mut len = init_nlhdr(
            &mut buf,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            seq,
        );
        buf[len..len + 12].fill(0);
        buf[len] = AF_INET6 as u8;
        buf[len + 1] = prefix_len;
        buf[len + 4] = RT_TABLE_UNSPEC;
        buf[len + 5] = RTPROT_STATIC;
        buf[len + 6] = RT_SCOPE_UNIVERSE;
        buf[len + 7] = RTN_UNICAST;
        len += 12;

        nla_put(&mut buf, &mut len, RTA_TABLE, &ROUTE_TABLE_SARING.to_ne_bytes());
        nla_put(&mut buf, &mut len, RTA_DST, dst);
        nla_put(&mut buf, &mut len, RTA_PREFSRC, src_v6);
        nla_put(&mut buf, &mut len, RTA_OIF, &ifindex.to_ne_bytes());
        put_route_metrics(&mut buf, &mut len);
        rtnl.request(&mut buf, len).is_ok()
    }

    fn mod_v6_rule(
        rtnl: &NlSocket,
        dst: &[u8; 16],
        prefix_len: u8,
        pref: u32,
        add: bool,
        seq: u32,
    ) -> bool {
        let mut buf = [0u8; 256];
        let ty = if add { RTM_NEWRULE } else { RTM_DELRULE };
        let flags = if add {
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        } else {
            NLM_F_REQUEST | NLM_F_ACK
        };
        let mut len = init_nlhdr(&mut buf, ty, flags, seq);
        buf[len..len + 12].fill(0);
        buf[len] = AF_INET6 as u8;
        buf[len + 1] = prefix_len;
        buf[len + 4] = RT_TABLE_UNSPEC;
        buf[len + 7] = FR_ACT_TO_TBL;
        len += 12;

        nla_put(&mut buf, &mut len, FRA_PRIORITY, &pref.to_ne_bytes());
        nla_put(&mut buf, &mut len, FRA_TABLE, &ROUTE_TABLE_SARING.to_ne_bytes());
        nla_put(&mut buf, &mut len, FRA_DST, dst);
        match rtnl.request(&mut buf, len) {
            Ok(()) => true,
            Err(-17) if add => true,
            Err(-2) if !add => true,
            Err(_) => false,
        }
    }

    fn pfx96_to_v6(pfx96: &[u8; 12]) -> [u8; 16] {
        let mut dst = [0u8; 16];
        dst[..12].copy_from_slice(pfx96);
        dst
    }

    pub fn bring_up_device(creds: &WarpCreds) -> bool {
        let Some(rtnl) = NlSocket::open(NETLINK_ROUTE) else {
            return false;
        };
        if !ensure_wg_link(&rtnl) {
            return false;
        }
        let idx = if_index();
        if idx == 0 {
            return false;
        }
        attach_fq_qdisc(&rtnl, idx);
        tune_wg_rps();
        if !configure_wg_peer(creds) {
            return false;
        }
        if !add_v4_addr(&rtnl, idx, &creds.client_v4) {
            return false;
        }
        add_v6_addr(&rtnl, idx, &creds.client_v6)
    }

    pub fn switch_wg_endpoint(creds: &WarpCreds) -> bool {
        if if_index() == 0 {
            return false;
        }
        configure_wg_peer(creds)
    }

    pub fn set_nat64_routes(src_v6: &[u8; 16], enable: bool) -> bool {
        let Some(rtnl) = NlSocket::open(NETLINK_ROUTE) else {
            return false;
        };
        let p1 = pfx96_to_v6(&NAT64_PRIMARY_PREFIX);
        let p2 = pfx96_to_v6(&NAT64_BACKUP_PREFIX);
        if enable {
            let idx = if_index();
            if idx == 0 {
                return false;
            }
            if !add_v6_route(&rtnl, idx, &p1, 96, src_v6, 40) {
                return false;
            }
            let _ = add_v6_route(&rtnl, idx, &p2, 96, src_v6, 41);
            let _ = add_v6_route(&rtnl, idx, &CHROMIUM_V6_PROBE, 128, src_v6, 42);
            if !mod_v6_rule(&rtnl, &p1, 96, RULE_PREF_NAT64, true, 50) {
                return false;
            }
            let _ = mod_v6_rule(&rtnl, &p2, 96, RULE_PREF_NAT64, true, 51);
            let _ = mod_v6_rule(&rtnl, &CHROMIUM_V6_PROBE, 128, RULE_PREF_NAT64, true, 52);
            true
        } else {
            let _ = mod_v6_rule(&rtnl, &p1, 96, RULE_PREF_NAT64, false, 60);
            let _ = mod_v6_rule(&rtnl, &p2, 96, RULE_PREF_NAT64, false, 61);
            let _ = mod_v6_rule(&rtnl, &CHROMIUM_V6_PROBE, 128, RULE_PREF_NAT64, false, 62);
            let idx = if_index();
            if idx != 0 {
                del_v6_route(&rtnl, idx, &p1, 96, 63);
                del_v6_route(&rtnl, idx, &p2, 96, 64);
                del_v6_route(&rtnl, idx, &CHROMIUM_V6_PROBE, 128, 65);
            }
            true
        }
    }

    pub fn apply_boost_delta(add: &[[u8; 4]], del: &[[u8; 4]], src_v4: [u8; 4]) {
        let Some(rtnl) = NlSocket::open(NETLINK_ROUTE) else {
            return;
        };
        let idx = if_index();
        if idx == 0 {
            return;
        }
        let mut seq = 100u32;
        for ip in del {
            let _ = mod_v4_rule(&rtnl, ip, false, seq);
            seq += 1;
            let _ = mod_v4_route(&rtnl, idx, ip, &src_v4, false, seq);
            seq += 1;
        }
        for ip in add {
            if mod_v4_route(&rtnl, idx, ip, &src_v4, true, seq) {
                seq += 1;
                let _ = mod_v4_rule(&rtnl, ip, true, seq);
                seq += 1;
            }
        }
    }

    pub fn clear_boost_routes(ips: &[[u8; 4]]) {
        if ips.is_empty() {
            return;
        }
        let Some(rtnl) = NlSocket::open(NETLINK_ROUTE) else {
            return;
        };
        let idx = if_index();
        let mut seq = 200u32;
        for ip in ips {
            let _ = mod_v4_rule(&rtnl, ip, false, seq);
            seq += 1;
            if idx != 0 {
                let _ = mod_v4_route(&rtnl, idx, ip, &DEFAULT_CLIENT_V4, false, seq);
                seq += 1;
            }
        }
    }

    pub fn apply_boost_v6_delta(add: &[[u8; 16]], del: &[[u8; 16]], src_v6: [u8; 16]) {
        let Some(rtnl) = NlSocket::open(NETLINK_ROUTE) else {
            return;
        };
        let idx = if_index();
        if idx == 0 {
            return;
        }
        let mut seq = 300u32;
        for ip in del {
            let _ = mod_v6_rule(&rtnl, ip, 128, RULE_PREF_BOOST, false, seq);
            seq += 1;
            del_v6_route(&rtnl, idx, ip, 128, seq);
            seq += 1;
        }
        for ip in add {
            if add_v6_route(&rtnl, idx, ip, 128, &src_v6, seq) {
                seq += 1;
                let _ = mod_v6_rule(&rtnl, ip, 128, RULE_PREF_BOOST, true, seq);
                seq += 1;
            }
        }
    }

    pub fn clear_boost_v6_routes(ips: &[[u8; 16]]) {
        if ips.is_empty() {
            return;
        }
        let Some(rtnl) = NlSocket::open(NETLINK_ROUTE) else {
            return;
        };
        let idx = if_index();
        let mut seq = 400u32;
        for ip in ips {
            let _ = mod_v6_rule(&rtnl, ip, 128, RULE_PREF_BOOST, false, seq);
            seq += 1;
            if idx != 0 {
                del_v6_route(&rtnl, idx, ip, 128, seq);
                seq += 1;
            }
        }
    }

    pub fn tear_down(boost_v4: &[[u8; 4]], boost_v6: &[[u8; 16]]) {
        clear_boost_routes(boost_v4);
        clear_boost_v6_routes(boost_v6);
        let _ = set_nat64_routes(&DEFAULT_CLIENT_V6, false);
        let Some(rtnl) = NlSocket::open(NETLINK_ROUTE) else {
            return;
        };
        let mut buf = [0u8; 128];
        let mut len = init_nlhdr(&mut buf, RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, 63);
        buf[len..len + 16].fill(0);
        len += 16;
        nla_put(&mut buf, &mut len, IFLA_IFNAME, IFNAME);
        let _ = rtnl.request(&mut buf, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat64_synthesis_embeds_google_gfe_ipv4() {
        let [primary, backup] = google_nat64_addrs();
        assert_eq!(&primary[..12], &NAT64_PRIMARY_PREFIX);
        assert_eq!(&primary[12..16], &[142, 251, 150, 119]);
        assert_eq!(&backup[..12], &NAT64_BACKUP_PREFIX);
        assert_eq!(&backup[12..16], &[142, 251, 150, 119]);
        // RFC 6724 Rule 9: HK primary (2600:) must share more leading bits with WARP src (2606:)
        // than FI failover (2a01:) so clients always pick HK first and fail over to FI cleanly.
        let src = u128::from_be_bytes(DEFAULT_CLIENT_V6);
        let p_match = (src ^ u128::from_be_bytes(primary)).leading_zeros();
        let b_match = (src ^ u128::from_be_bytes(backup)).leading_zeros();
        assert!(p_match > b_match, "primary={p_match} bits must exceed backup={b_match} bits");
    }

    #[test]
    fn hex_and_base64_roundtrip() {
        let hex = "b8dad53de68ba9f1ff88704bd08264e9a58ac687a17aff11db095df8385e4e53";
        let decoded = parse_hex::<32>(hex).unwrap();
        assert_eq!(decoded, DEFAULT_PRIV_KEY);
        assert_eq!(to_hex(&decoded), hex);

        let b64 = base64_encode(&DEFAULT_PEER_PUB_KEY);
        assert_eq!(b64, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=");
        assert_eq!(base64_decode(&b64).unwrap(), DEFAULT_PEER_PUB_KEY);
    }

    #[test]
    fn parses_cloudflare_warp_reg_json() {
        let sample = r#"{"id":"abc","config":{"peers":[{"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","endpoint":{"v4":"162.159.192.1:0"}}],"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:82a9:f235:ee15:f266:489b"}}}}"#;
        let creds = parse_warp_reg_json(sample, DEFAULT_PRIV_KEY).unwrap();
        assert_eq!(creds.client_v4, [172, 16, 0, 2]);
        assert_eq!(creds.client_v6, DEFAULT_CLIENT_V6);
        assert_eq!(creds.peer_pub, DEFAULT_PEER_PUB_KEY);
    }

    #[test]
    fn creds_text_roundtrip_preserves_endpoint_override() {
        let mut creds = WarpCreds::default();
        creds.endpoint_v4 = [188, 114, 97, 1];
        creds.endpoint_port = 4500;
        let text = format_creds_text(&creds);
        let (parsed, ok) = parse_creds_text(&text);
        assert!(ok);
        assert_eq!(parsed, creds);
        assert!(WARP_ENDPOINTS.contains(&([188, 114, 97, 1], 4500)));
    }

    #[test]
    fn boost_ring_dedups_and_evicts_fifo_v4_and_v6() {
        let mut ring4 = BoostRing::new([0u8; 4]);
        assert_eq!(ring4.insert([5, 223, 7, 195]), Some(None));
        assert_eq!(ring4.insert([5, 223, 7, 195]), None);
        for i in 1..BOOST_RING_CAP {
            assert_eq!(ring4.insert([1, 2, (i >> 8) as u8, (i & 0xFF) as u8]), Some(None));
        }
        assert_eq!(ring4.insert([9, 9, 9, 9]), Some(Some([5, 223, 7, 195])));
        assert_eq!(ring4.drain_all().len(), BOOST_RING_CAP);

        let mut ring6 = BoostRing::new([0u8; 16]);
        let first = [0x2a, 0x03, 0x28, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe, 0x01];
        assert_eq!(ring6.insert(first), Some(None));
        assert_eq!(ring6.insert(first), None);
        for i in 1..BOOST_RING_CAP {
            let mut ip = [0x2a, 0x03, 0x28, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            ip[14] = (i >> 8) as u8;
            ip[15] = (i & 0xFF) as u8;
            assert_eq!(ring6.insert(ip), Some(None));
        }
        let extra = [0x2a, 0x03, 0x28, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9];
        assert_eq!(ring6.insert(extra), Some(Some(first)));
        assert_eq!(ring6.drain_all().len(), BOOST_RING_CAP);
    }
}
