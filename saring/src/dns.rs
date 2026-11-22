// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-copy DNS wire parser, poison detector and Google SafeSearch synthesizer.
//!
//! One pass over a DNS query extracts the dotted lowercase QNAME, QTYPE, QCLASS and Saring's
//! 60-bit suffix keys for both block checks and cache lookups. Answer inspection bounds pointer
//! hops so hostile packets cannot loop or read out of bounds.

use crate::{keys, Names, MAX_LEVELS};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_SOA: u16 = 6;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_HTTPS: u16 = 65;
pub const QCLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;

/// Google's `forcesafesearch.google.com` VIPs.
pub const FORCE_SAFESEARCH_V4: [u8; 4] = [216, 239, 38, 120];
pub const FORCE_SAFESEARCH_V6: [u8; 16] = [
    0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78,
];

/// Known Indonesian ISP censorship / TrustPositif sinkhole IPv4 addresses.
const SINKHOLE_V4: [[u8; 4]; 10] = [
    // Indosat (AS4761) TrustPositif sinkholes
    [114, 7, 173, 245],
    [114, 7, 173, 246],
    [114, 4, 38, 170],
    // Telkomsel / IndiHome / Kominfo in-path DPI & block landing IPs
    [36, 86, 63, 185],
    [195, 35, 23, 222],
    [180, 131, 144, 144],
    [180, 131, 145, 145],
    [202, 3, 218, 131],
    [112, 215, 198, 186],
    [202, 152, 240, 50],
];

const MAX_PTR_HOPS: usize = 16;

/// Parsed DNS question on the stack; zero heap allocations.
pub struct Question {
    pub qid: u16,
    pub qtype: u16,
    pub qclass: u16,
    /// Byte offset right after QCLASS in the original query packet.
    pub qend: usize,
    name: [u8; 256],
    name_len: usize,
    keys: [u64; MAX_LEVELS],
    key_count: usize,
    whole: bool,
}

impl Question {
    #[inline]
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    #[inline]
    pub fn domain_key(&self) -> u64 {
        if self.key_count > 0 {
            self.keys[self.key_count - 1]
        } else {
            0
        }
    }

    /// 64-bit cache key combining the domain hash, QTYPE and netId.
    #[inline]
    pub fn cache_key(&self, netid: u32) -> u64 {
        let mut h = self.domain_key() ^ (u64::from(self.qtype) << 1) ^ (u64::from(netid) << 32);
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^ (h >> 33)
    }

    /// Evaluates Saring's name table using the already-computed suffix keys.
    #[inline]
    pub fn blocked_by(&self, names: &Names<'_>) -> bool {
        names.blocked_keys(&self.keys[..self.key_count], self.whole)
    }
}

/// Parses the first question of a standard DNS query packet (`QDCOUNT == 1`).
pub fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 17 {
        return None;
    }
    // Reject responses (QR=1) or non-standard opcodes.
    if msg[2] & 0xF8 != 0 {
        return None;
    }
    let qid = u16::from_be_bytes([msg[0], msg[1]]);
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount != 1 {
        return None;
    }

    let mut name = [0u8; 256];
    let mut len = 0usize;
    let mut at = 12usize;
    loop {
        let n = *msg.get(at)? as usize;
        if n == 0 {
            at += 1;
            break;
        }
        if n > 63 || len + n + usize::from(len != 0) > 253 {
            return None;
        }
        let label = msg.get(at + 1..at + 1 + n)?;
        if len != 0 {
            name[len] = b'.';
            len += 1;
        }
        for &b in label {
            name[len] = b.to_ascii_lowercase();
            len += 1;
        }
        at += n + 1;
    }
    if len == 0 || at + 4 > msg.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[at], msg[at + 1]]);
    let qclass = u16::from_be_bytes([msg[at + 2], msg[at + 3]]);
    let qend = at + 4;

    let mut key_buf = [0u64; MAX_LEVELS];
    let (key_count, whole) = keys(&name[..len], &mut key_buf);
    if key_count == 0 {
        return None;
    }

    Some(Question {
        qid,
        qtype,
        qclass,
        qend,
        name,
        name_len: len,
        keys: key_buf,
        key_count,
        whole,
    })
}

/// True for Google Search hostnames controlled by the owner's SafeSearch switch.
#[inline]
pub fn is_google_search_host(name: &[u8]) -> bool {
    let name = name.strip_suffix(b".").unwrap_or(name);
    name.eq_ignore_ascii_case(b"www.google.com")
        || name.eq_ignore_ascii_case(b"google.com")
        || name.eq_ignore_ascii_case(b"www.google.co.id")
        || name.eq_ignore_ascii_case(b"google.co.id")
}

/// True for local/private names that legitimately resolve to loopback or unspecified addresses.
#[inline]
pub fn is_local_name(name: &[u8]) -> bool {
    let name = name.strip_suffix(b".").unwrap_or(name);
    name.eq_ignore_ascii_case(b"localhost")
        || name.ends_with(b".local")
        || name.ends_with(b".localhost")
        || name.ends_with(b".lan")
        || name.ends_with(b".internal")
        || !name.contains(&b'.')
}

/// Curated suffixes of video CDNs and international hosts frequently DPI-shaped or tromboned on
/// Indonesian mobile carriers. Local `.id` hosts, banking, game servers, and
/// low-latency local-peered CDNs (Fastly/`twimg.com`, Akamai, CloudFront) stay 100% direct.
const BOOST_SUFFIXES: &[&[u8]] = &[
    // Video & social media CDNs (Netflix, YouTube, Instagram, Facebook, TikTok, Twitch, Reddit)
    b"nflxvideo.net",
    b"googlevideo.com",
    b"cdninstagram.com",
    b"fbcdn.net",
    b"ttvnw.net",
    b"twitchcdn.net",
    b"tiktokv.com",
    b"tiktokcdn.com",
    b"redd.it",
    b"redditmedia.com",
    b"vimeocdn.com",
    b"b-cdn.net",
    // High-RTT / tromboned international mirrors & developer CDNs
    b"hetzner.com",
    b"hetzner.de",
    b"githubusercontent.com",
    b"githubassets.com",
    b"r2.cloudflarestorage.com",
    b"hf.co",
    b"huggingface.co",
    b"steamcontent.com",
    b"archive.org",
    b"sourceforge.net",
];

#[inline]
fn matches_suffix(name: &[u8], suffix: &[u8]) -> bool {
    if name.len() < suffix.len() {
        return false;
    }
    let tail = &name[name.len() - suffix.len()..];
    if !tail.eq_ignore_ascii_case(suffix) {
        return false;
    }
    name.len() == suffix.len() || name[name.len() - suffix.len() - 1] == b'.'
}

/// True when `name` is eligible for selective WARP+ `/32` peering/anti-throttle boost.
#[inline]
pub fn is_boost_host(name: &[u8]) -> bool {
    let name = name.strip_suffix(b".").unwrap_or(name);
    if name.is_empty()
        || is_local_name(name)
        || is_google_search_host(name)
        || matches_suffix(name, b"id")
    {
        return false;
    }
    BOOST_SUFFIXES.iter().any(|s| matches_suffix(name, s))
}

/// Rejects private, loopback, link-local, CGNAT, DoT upstream and WARP endpoint IPv4 addresses
/// so dynamic `/32` boost routes can never create a routing loop or hijack local traffic.
#[inline]
pub fn is_routable_boost_v4(ip: [u8; 4]) -> bool {
    if ip[0] == 0
        || ip[0] == 10
        || ip[0] == 127
        || ip[0] >= 224
        || (ip[0] == 100 && (ip[1] & 0xC0) == 64)
        || (ip[0] == 169 && ip[1] == 254)
        || (ip[0] == 172 && (ip[1] & 0xF0) == 16)
        || (ip[0] == 192 && ip[1] == 168)
    {
        return false;
    }
    // Never boost Cloudflare WARP endpoints (162.159.192.0/21, 188.114.96.0/22) or DoT resolvers.
    if (ip[0] == 162 && ip[1] == 159 && (ip[2] & 0xF8) == 192)
        || (ip[0] == 188 && ip[1] == 114 && (ip[2] & 0xFC) == 96)
        || ip == [1, 1, 1, 1]
        || ip == [1, 0, 0, 1]
        || ip == [8, 8, 8, 8]
        || ip == [8, 8, 4, 4]
    {
        return false;
    }
    true
}

/// Extracts up to `out.len()` routable global IPv4 `A` records from a validated DNS answer packet.
pub fn extract_ipv4_answers(ans: &[u8], out: &mut [[u8; 4]]) -> usize {
    if ans.len() < 12 || (ans[2] & 0x80) == 0 || (ans[3] & 0x0F) != RCODE_NOERROR {
        return 0;
    }
    let qdcount = u16::from_be_bytes([ans[4], ans[5]]) as usize;
    let ancount = u16::from_be_bytes([ans[6], ans[7]]) as usize;
    if ancount == 0 || out.is_empty() {
        return 0;
    }
    let mut at = 12usize;
    for _ in 0..qdcount {
        let Some(next) = skip_name(ans, at) else {
            return 0;
        };
        at = next + 4;
        if at > ans.len() {
            return 0;
        }
    }
    let mut count = 0usize;
    for _ in 0..ancount {
        let Some(next) = skip_name(ans, at) else {
            break;
        };
        if next + 10 > ans.len() {
            break;
        }
        let rtype = u16::from_be_bytes([ans[next], ans[next + 1]]);
        let rclass = u16::from_be_bytes([ans[next + 2], ans[next + 3]]);
        let rdlen = u16::from_be_bytes([ans[next + 8], ans[next + 9]]) as usize;
        let rdata_start = next + 10;
        let Some(rdata_end) = rdata_start.checked_add(rdlen) else {
            break;
        };
        if rdata_end > ans.len() {
            break;
        }
        if rtype == QTYPE_A && rclass == QCLASS_IN && rdlen == 4 {
            let ip = [
                ans[rdata_start],
                ans[rdata_start + 1],
                ans[rdata_start + 2],
                ans[rdata_start + 3],
            ];
            if is_routable_boost_v4(ip) && !out[..count].contains(&ip) {
                out[count] = ip;
                count += 1;
                if count == out.len() {
                    break;
                }
            }
        }
        at = rdata_end;
    }
    count
}

/// Rejects non-global IPv6 addresses, NAT64 prefixes, DoT resolvers, and WARP internal/endpoint
/// subnets so dynamic `/128` IPv6 boost routes can never loop or hijack local/NAT64 traffic.
#[inline]
pub fn is_routable_boost_v6(ip: [u8; 16]) -> bool {
    // Only global unicast (2000::/3) is eligible.
    if (ip[0] & 0xE0) != 0x20 {
        return false;
    }
    // Reject documentation (2001:db8::/32) and Google DoT / Chromium probe (2001:4860:4860::/48).
    if ip[0] == 0x20 && ip[1] == 0x01 {
        if (ip[2] == 0x0d && ip[3] == 0xb8)
            || (ip[2] == 0x48 && ip[3] == 0x60 && ip[4] == 0x48 && ip[5] == 0x60)
        {
            return false;
        }
    }
    // Reject Cloudflare DoT (2606:4700:4700::/48), WARP tunnel client (2606:4700:110::/48),
    // and WARP IPv6 endpoints (2606:4700:d0::/44).
    if ip[0] == 0x26 && ip[1] == 0x06 && ip[2] == 0x47 && ip[3] == 0x00 {
        if (ip[4] == 0x47 && ip[5] == 0x00)
            || (ip[4] == 0x01 && ip[5] == 0x10)
            || (ip[4] == 0x00 && (ip[5] & 0xF0) == 0xd0)
        {
            return false;
        }
    }
    // Reject our own NAT64 prefixes.
    if ip[..12] == crate::warp::NAT64_PRIMARY_PREFIX || ip[..12] == crate::warp::NAT64_BACKUP_PREFIX
    {
        return false;
    }
    true
}

/// Extracts up to `out.len()` routable global IPv6 `AAAA` records from a validated DNS answer.
pub fn extract_ipv6_answers(ans: &[u8], out: &mut [[u8; 16]]) -> usize {
    if ans.len() < 12 || (ans[2] & 0x80) == 0 || (ans[3] & 0x0F) != RCODE_NOERROR {
        return 0;
    }
    let qdcount = u16::from_be_bytes([ans[4], ans[5]]) as usize;
    let ancount = u16::from_be_bytes([ans[6], ans[7]]) as usize;
    if ancount == 0 || out.is_empty() {
        return 0;
    }
    let mut at = 12usize;
    for _ in 0..qdcount {
        let Some(next) = skip_name(ans, at) else {
            return 0;
        };
        at = next + 4;
        if at > ans.len() {
            return 0;
        }
    }
    let mut count = 0usize;
    for _ in 0..ancount {
        let Some(next) = skip_name(ans, at) else {
            break;
        };
        if next + 10 > ans.len() {
            break;
        }
        let rtype = u16::from_be_bytes([ans[next], ans[next + 1]]);
        let rclass = u16::from_be_bytes([ans[next + 2], ans[next + 3]]);
        let rdlen = u16::from_be_bytes([ans[next + 8], ans[next + 9]]) as usize;
        let rdata_start = next + 10;
        let Some(rdata_end) = rdata_start.checked_add(rdlen) else {
            break;
        };
        if rdata_end > ans.len() {
            break;
        }
        if rtype == QTYPE_AAAA && rclass == QCLASS_IN && rdlen == 16 {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&ans[rdata_start..rdata_end]);
            if is_routable_boost_v6(ip) && !out[..count].contains(&ip) {
                out[count] = ip;
                count += 1;
                if count == out.len() {
                    break;
                }
            }
        }
        at = rdata_end;
    }
    count
}

/// Synthesizes a valid `forcesafesearch.google.com` A or AAAA response into `out`.
/// Returns `None` if `q` is not an `IN` `A`/`AAAA` query or `out` is too small.
pub fn synthesize_google_safesearch(query: &[u8], q: &Question, out: &mut [u8]) -> Option<usize> {
    if q.qclass != QCLASS_IN {
        return None;
    }
    let rdata: &[u8] = match q.qtype {
        QTYPE_A => &FORCE_SAFESEARCH_V4,
        QTYPE_AAAA => &FORCE_SAFESEARCH_V6,
        _ => return None,
    };
    let total = q.qend + 12 + rdata.len();
    if total > out.len() || q.qend > query.len() {
        return None;
    }
    out[..q.qend].copy_from_slice(&query[..q.qend]);
    // QR=1, OPCODE=0, AA=0, TC=0, RD=copied, RA=1, Z=0, RCODE=0
    out[2] = 0x80 | (query[2] & 0x01);
    out[3] = 0x80;
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    out[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    out[8..12].fill(0); // NSCOUNT = 0, ARCOUNT = 0

    let a = q.qend;
    out[a] = 0xC0;
    out[a + 1] = 0x0C; // pointer to QNAME at offset 12
    out[a + 2..a + 4].copy_from_slice(&q.qtype.to_be_bytes());
    out[a + 4..a + 6].copy_from_slice(&QCLASS_IN.to_be_bytes());
    out[a + 6..a + 10].copy_from_slice(&60u32.to_be_bytes()); // TTL = 60s
    out[a + 10..a + 12].copy_from_slice(&(rdata.len() as u16).to_be_bytes());
    out[a + 12..total].copy_from_slice(rdata);
    Some(total)
}

/// Synthesizes an empty `NOERROR` (NODATA) response for a blocked domain.
pub fn synthesize_nodata(query: &[u8], q: &Question, out: &mut [u8]) -> Option<usize> {
    if q.qend > out.len() || q.qend > query.len() {
        return None;
    }
    out[..q.qend].copy_from_slice(&query[..q.qend]);
    out[2] = 0x80 | (query[2] & 0x01);
    out[3] = 0x80; // RA=1, RCODE=NOERROR
    out[4..6].copy_from_slice(&1u16.to_be_bytes());
    out[6..12].fill(0); // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    Some(q.qend)
}

/// Synthesizes the NAT64 `AAAA` records (and `NODATA` for `A`/`HTTPS`) for Google Search when
/// `safesearch == 0` and the `/96` WARP+ NAT64 split-route is active, unlocking
/// `SAFESEARCH_OVERRIDE_REGION` without touching any non-Google traffic.
pub fn synthesize_google_unlocked(query: &[u8], q: &Question, out: &mut [u8]) -> Option<usize> {
    if q.qclass != QCLASS_IN {
        return None;
    }
    match q.qtype {
        QTYPE_A | QTYPE_HTTPS => synthesize_nodata(query, q, out),
        QTYPE_AAAA => {
            let addrs = crate::warp::google_nat64_addrs();
            let rr_len = 12 + 16; // 28 bytes per AAAA RR
            let total = q.qend + rr_len * addrs.len();
            if total > out.len() || q.qend > query.len() {
                return None;
            }
            out[..q.qend].copy_from_slice(&query[..q.qend]);
            out[2] = 0x80 | (query[2] & 0x01);
            out[3] = 0x80;
            out[4..6].copy_from_slice(&1u16.to_be_bytes());
            out[6..8].copy_from_slice(&(addrs.len() as u16).to_be_bytes());
            out[8..12].fill(0);

            let mut at = q.qend;
            for ip6 in &addrs {
                out[at] = 0xC0;
                out[at + 1] = 0x0C;
                out[at + 2..at + 4].copy_from_slice(&QTYPE_AAAA.to_be_bytes());
                out[at + 4..at + 6].copy_from_slice(&QCLASS_IN.to_be_bytes());
                out[at + 6..at + 10].copy_from_slice(&60u32.to_be_bytes());
                out[at + 10..at + 12].copy_from_slice(&16u16.to_be_bytes());
                out[at + 12..at + 28].copy_from_slice(ip6);
                at += rr_len;
            }
            Some(total)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerVerdict {
    Clean { ttl: u32, rcode: u8, ancount: u16 },
    PoisonedSinkhole,
    PoisonedSafeSearch,
    Malformed,
}

/// Skips a wire-encoded DNS name starting at `offset`, guarding against malformed labels.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > 128 {
            return None;
        }
        let b = *msg.get(at)?;
        if b == 0 {
            return Some(at + 1);
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer consumes 2 bytes and ends the name in-place.
            if at + 2 > msg.len() {
                return None;
            }
            return Some(at + 2);
        }
        if b & 0xC0 != 0 {
            return None;
        }
        let len = b as usize;
        at = at.checked_add(1 + len)?;
        if at > msg.len() {
            return None;
        }
    }
}

/// Reads a compressed DNS name into `buf` (lowercase dotted ASCII), rejecting pointer loops.
fn read_name<'a>(msg: &[u8], mut at: usize, buf: &'a mut [u8; 256]) -> Option<&'a [u8]> {
    let mut out_len = 0usize;
    let mut hops = 0usize;
    let mut labels = 0usize;
    loop {
        labels += 1;
        if labels > 128 {
            return None;
        }
        let b = *msg.get(at)?;
        if b == 0 {
            break;
        }
        if b & 0xC0 == 0xC0 {
            hops += 1;
            if hops > MAX_PTR_HOPS {
                return None;
            }
            let b2 = *msg.get(at + 1)?;
            let ptr = (usize::from(b & 0x3F) << 8) | usize::from(b2);
            if ptr >= msg.len() {
                return None;
            }
            at = ptr;
            continue;
        }
        if b & 0xC0 != 0 {
            return None;
        }
        let len = b as usize;
        let slice = msg.get(at + 1..at + 1 + len)?;
        if out_len != 0 {
            if out_len >= 253 {
                return None;
            }
            buf[out_len] = b'.';
            out_len += 1;
        }
        if out_len + len > 253 {
            return None;
        }
        for &c in slice {
            buf[out_len] = c.to_ascii_lowercase();
            out_len += 1;
        }
        at += 1 + len;
    }
    Some(&buf[..out_len])
}

#[inline]
fn is_sinkhole_v4(ip: [u8; 4], local: bool) -> bool {
    if !local && (ip == [0, 0, 0, 0] || ip == [127, 0, 0, 1]) {
        return true;
    }
    // Carrier sinkhole /24 subnets (Indosat, Telkomsel internetbaik, IndiHome mercusuar).
    if (ip[0] == 114 && ip[1] == 7 && ip[2] == 173)
        || (ip[0] == 202 && ip[1] == 3 && ip[2] == 218)
        || (ip[0] == 36 && ip[1] == 86 && ip[2] == 63)
        || (ip[0] == 180 && ip[1] == 131 && (ip[2] == 144 || ip[2] == 145))
    {
        return true;
    }
    SINKHOLE_V4.contains(&ip)
}

#[inline]
fn is_sinkhole_cname(target: &[u8]) -> bool {
    target.starts_with(b"internetbaik.")
        || target.starts_with(b"mercusuar.")
        || target.starts_with(b"trustpositif.")
        || target.ends_with(b".uzone.id")
}

#[inline]
fn is_sinkhole_v6(ip: [u8; 16], local: bool) -> bool {
    if !local {
        let unspec = [0u8; 16];
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        if ip == unspec || ip == loopback {
            return true;
        }
    }
    false
}

/// Inspects a DNS answer packet for sinkhole poisoning, unrequested SafeSearch VIPs, and TTL.
///
/// `from_plaintext` enables the `TTL == 0` in-path DPI heuristic for untrusted UDP/53 answers.
pub fn inspect_answer(
    ans: &[u8],
    allow_safesearch_vip: bool,
    local_name: bool,
    from_plaintext: bool,
) -> AnswerVerdict {
    if ans.len() < 12 || (ans[2] & 0x80) == 0 {
        return AnswerVerdict::Malformed;
    }
    let rcode = ans[3] & 0x0F;
    let qdcount = u16::from_be_bytes([ans[4], ans[5]]);
    let ancount = u16::from_be_bytes([ans[6], ans[7]]);
    let nscount = u16::from_be_bytes([ans[8], ans[9]]);

    let mut at = 12usize;
    for _ in 0..qdcount {
        let Some(next) = skip_name(ans, at) else {
            return AnswerVerdict::Malformed;
        };
        if next + 4 > ans.len() {
            return AnswerVerdict::Malformed;
        }
        at = next + 4;
    }

    let mut min_ttl = u32::MAX;
    let mut name_buf = [0u8; 256];

    for _ in 0..ancount {
        let Some(next) = skip_name(ans, at) else {
            return AnswerVerdict::Malformed;
        };
        if next + 10 > ans.len() {
            return AnswerVerdict::Malformed;
        }
        let rtype = u16::from_be_bytes([ans[next], ans[next + 1]]);
        let rclass = u16::from_be_bytes([ans[next + 2], ans[next + 3]]);
        let ttl = u32::from_be_bytes([ans[next + 4], ans[next + 5], ans[next + 6], ans[next + 7]]);
        let rdlen = u16::from_be_bytes([ans[next + 8], ans[next + 9]]) as usize;
        let rdata_start = next + 10;
        let Some(rdata_end) = rdata_start.checked_add(rdlen) else {
            return AnswerVerdict::Malformed;
        };
        if rdata_end > ans.len() {
            return AnswerVerdict::Malformed;
        }

        if rclass == QCLASS_IN {
            if ttl < min_ttl {
                min_ttl = ttl;
            }
            match rtype {
                QTYPE_A if rdlen == 4 => {
                    let ip = [
                        ans[rdata_start],
                        ans[rdata_start + 1],
                        ans[rdata_start + 2],
                        ans[rdata_start + 3],
                    ];
                    if !allow_safesearch_vip && ip == FORCE_SAFESEARCH_V4 {
                        return AnswerVerdict::PoisonedSafeSearch;
                    }
                    if is_sinkhole_v4(ip, local_name) {
                        return AnswerVerdict::PoisonedSinkhole;
                    }
                    if from_plaintext && ttl == 0 && rcode == RCODE_NOERROR {
                        return AnswerVerdict::PoisonedSinkhole;
                    }
                }
                QTYPE_AAAA if rdlen == 16 => {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&ans[rdata_start..rdata_end]);
                    if !allow_safesearch_vip && ip == FORCE_SAFESEARCH_V6 {
                        return AnswerVerdict::PoisonedSafeSearch;
                    }
                    if is_sinkhole_v6(ip, local_name) {
                        return AnswerVerdict::PoisonedSinkhole;
                    }
                }
                QTYPE_CNAME => {
                    let Some(target) = read_name(ans, rdata_start, &mut name_buf) else {
                        return AnswerVerdict::Malformed;
                    };
                    if is_sinkhole_cname(target) {
                        return AnswerVerdict::PoisonedSinkhole;
                    }
                    if !allow_safesearch_vip
                        && target.eq_ignore_ascii_case(b"forcesafesearch.google.com")
                    {
                        return AnswerVerdict::PoisonedSafeSearch;
                    }
                }
                _ => {}
            }
        }
        at = rdata_end;
    }

    // For negative answers (ANCOUNT == 0), inspect SOA in the authority section for negative TTL.
    if ancount == 0 {
        for _ in 0..nscount {
            let Some(next) = skip_name(ans, at) else {
                break;
            };
            if next + 10 > ans.len() {
                break;
            }
            let rtype = u16::from_be_bytes([ans[next], ans[next + 1]]);
            let ttl =
                u32::from_be_bytes([ans[next + 4], ans[next + 5], ans[next + 6], ans[next + 7]]);
            let rdlen = u16::from_be_bytes([ans[next + 8], ans[next + 9]]) as usize;
            let rdata_start = next + 10;
            let Some(rdata_end) = rdata_start.checked_add(rdlen) else {
                break;
            };
            if rdata_end > ans.len() {
                break;
            }
            if rtype == QTYPE_SOA {
                if let Some(mname_end) = skip_name(ans, rdata_start) {
                    if let Some(rname_end) = skip_name(ans, mname_end) {
                        if rname_end + 20 <= rdata_end {
                            let soa_min = u32::from_be_bytes([
                                ans[rname_end + 16],
                                ans[rname_end + 17],
                                ans[rname_end + 18],
                                ans[rname_end + 19],
                            ]);
                            min_ttl = min_ttl.min(ttl.min(soa_min));
                        }
                    }
                }
            }
            at = rdata_end;
        }
    }

    AnswerVerdict::Clean {
        ttl: if min_ttl == u32::MAX { 0 } else { min_ttl },
        rcode,
        ancount,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key;

    fn make_query(qid: u16, host: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&qid.to_be_bytes());
        pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in host.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        pkt
    }

    fn make_a_answer(query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut ans = query.to_vec();
        ans[2] = 0x81;
        ans[3] = 0x80;
        ans[6..8].copy_from_slice(&1u16.to_be_bytes());
        ans.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        ans.extend_from_slice(&ttl.to_be_bytes());
        ans.extend_from_slice(&4u16.to_be_bytes());
        ans.extend_from_slice(&ip);
        ans
    }

    #[test]
    fn question_hash_matches_saring_key() {
        let pkt = make_query(0x1234, "Danbooru.Donmai.US", QTYPE_A);
        let q = parse_question(&pkt).unwrap();
        assert_eq!(q.qid, 0x1234);
        assert_eq!(q.qtype, QTYPE_A);
        assert_eq!(q.name(), b"danbooru.donmai.us");
        assert_eq!(q.domain_key(), key(b"danbooru.donmai.us").unwrap());
    }

    #[test]
    fn detects_indosat_and_telkomsel_sinkholes_and_zero_ttl() {
        let q = make_query(0x4242, "danbooru.donmai.us", QTYPE_A);
        for ip in [[114, 7, 173, 245], [114, 7, 173, 246], [36, 86, 63, 185], [195, 35, 23, 222]] {
            let ans = make_a_answer(&q, ip, 300);
            assert_eq!(inspect_answer(&ans, false, false, false), AnswerVerdict::PoisonedSinkhole);
        }
        // Forged TTL=0 plaintext answer to arbitrary IP is flagged as sinkhole.
        let forged = make_a_answer(&q, [203, 0, 113, 1], 0);
        assert_eq!(inspect_answer(&forged, false, false, true), AnswerVerdict::PoisonedSinkhole);
        // Legitimate Cloudflare answer passes.
        let clean = make_a_answer(&q, [104, 26, 10, 39], 300);
        assert_eq!(
            inspect_answer(&clean, false, false, true),
            AnswerVerdict::Clean { ttl: 300, rcode: 0, ancount: 1 }
        );
    }

    #[test]
    fn detects_unrequested_safesearch_vip_and_synthesizes_when_strict() {
        let q_pkt = make_query(0x7777, "www.google.com", QTYPE_A);
        let q = parse_question(&q_pkt).unwrap();
        assert!(is_google_search_host(q.name()));

        let mut out = [0u8; 512];
        let n = synthesize_google_safesearch(&q_pkt, &q, &mut out).unwrap();
        // Rejected when Unrestricted (allow_safesearch_vip = false)
        assert_eq!(
            inspect_answer(&out[..n], false, false, false),
            AnswerVerdict::PoisonedSafeSearch
        );
        // Accepted when Strict (allow_safesearch_vip = true)
        assert_eq!(
            inspect_answer(&out[..n], true, false, false),
            AnswerVerdict::Clean { ttl: 60, rcode: 0, ancount: 1 }
        );

        // Also test AAAA synthesis.
        let q6_pkt = make_query(0x8888, "www.google.co.id", QTYPE_AAAA);
        let q6 = parse_question(&q6_pkt).unwrap();
        let n6 = synthesize_google_safesearch(&q6_pkt, &q6, &mut out).unwrap();
        assert_eq!(
            inspect_answer(&out[..n6], false, false, false),
            AnswerVerdict::PoisonedSafeSearch
        );
        assert_eq!(
            inspect_answer(&out[..n6], true, false, false),
            AnswerVerdict::Clean { ttl: 60, rcode: 0, ancount: 1 }
        );
    }

    #[test]
    fn rejects_compression_pointer_loop_in_cname() {
        let q = make_query(0x1111, "www.google.com", QTYPE_A);
        let mut bad = q.clone();
        bad[2] = 0x81;
        bad[3] = 0x80;
        bad[6..8].copy_from_slice(&1u16.to_be_bytes());
        let cname_rdata_off = bad.len() + 12;
        bad.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60, 0, 2]);
        // Self-pointer to cname_rdata_off
        bad.push(0xC0 | ((cname_rdata_off >> 8) as u8 & 0x3F));
        bad.push((cname_rdata_off & 0xFF) as u8);
        assert_eq!(inspect_answer(&bad, false, false, false), AnswerVerdict::Malformed);
    }

    #[test]
    fn synthesizes_google_unlocked_nat64_aaaa_and_nodata_a_https() {
        let mut out = [0u8; 512];
        let qa_pkt = make_query(0x2222, "www.google.com", QTYPE_A);
        let qa = parse_question(&qa_pkt).unwrap();
        let na = synthesize_google_unlocked(&qa_pkt, &qa, &mut out).unwrap();
        assert_eq!(
            inspect_answer(&out[..na], false, false, false),
            AnswerVerdict::Clean { ttl: 0, rcode: 0, ancount: 0 }
        );

        let qh_pkt = make_query(0x3333, "www.google.com", QTYPE_HTTPS);
        let qh = parse_question(&qh_pkt).unwrap();
        let nh = synthesize_google_unlocked(&qh_pkt, &qh, &mut out).unwrap();
        assert_eq!(
            inspect_answer(&out[..nh], false, false, false),
            AnswerVerdict::Clean { ttl: 0, rcode: 0, ancount: 0 }
        );

        let q6_pkt = make_query(0x4444, "www.google.com", QTYPE_AAAA);
        let q6 = parse_question(&q6_pkt).unwrap();
        let n6 = synthesize_google_unlocked(&q6_pkt, &q6, &mut out).unwrap();
        assert_eq!(
            inspect_answer(&out[..n6], false, false, false),
            AnswerVerdict::Clean { ttl: 60, rcode: 0, ancount: 2 }
        );
    }

    #[test]
    fn boost_classifier_matches_cdns_and_excludes_local_and_loop_ips() {
        assert!(is_boost_host(b"ipv4-c107-sin001-ix.1.oca.nflxvideo.net"));
        assert!(is_boost_host(b"sin-speed.hetzner.com"));
        assert!(is_boost_host(b"rr1---sn-2uuxa3vh.googlevideo.com"));
        assert!(is_boost_host(b"scontent-sin6-1.cdninstagram.com"));
        assert!(is_boost_host(b"video.fcgk10-1.fna.fbcdn.net"));
        assert!(is_boost_host(b"v.redd.it"));
        assert!(is_boost_host(b"objects.githubusercontent.com"));
        // Exclusions: local .id, Google Search, banking, games, fast local-peered CDNs
        assert!(!is_boost_host(b"video.twimg.com"));
        assert!(!is_boost_host(b"pbs.twimg.com"));
        assert!(!is_boost_host(b"foo.fastly.net"));
        assert!(!is_boost_host(b"cdn.akamaized.net"));
        assert!(!is_boost_host(b"d123.cloudfront.net"));
        assert!(!is_boost_host(b"klikbca.com"));
        assert!(!is_boost_host(b"bri.co.id"));
        assert!(!is_boost_host(b"www.google.com"));
        assert!(!is_boost_host(b"danbooru.donmai.us"));
        assert!(!is_boost_host(b"fakehetzner.com"));

        // Safety: reject private, DoT resolvers, and WARP endpoint subnets
        assert!(is_routable_boost_v4([5, 223, 7, 195]));
        assert!(!is_routable_boost_v4([162, 159, 192, 1]));
        assert!(!is_routable_boost_v4([1, 1, 1, 1]));
        assert!(!is_routable_boost_v4([10, 0, 0, 1]));
        assert!(!is_routable_boost_v4([172, 16, 0, 2]));

        let q = make_query(0x5555, "sin-speed.hetzner.com", QTYPE_A);
        let ans = make_a_answer(&q, [5, 223, 7, 195], 300);
        let mut ips = [[0u8; 4]; 4];
        assert_eq!(extract_ipv4_answers(&ans, &mut ips), 1);
        assert_eq!(ips[0], [5, 223, 7, 195]);

        // IPv6 boost safety & extraction
        let ig_v6 = [
            0x2a, 0x03, 0x28, 0x80, 0xf2, 0x00, 0x00, 0x00, 0xfa, 0xce, 0xb0, 0x0c, 0x00, 0x00,
            0x01, 0x67,
        ];
        assert!(is_routable_boost_v6(ig_v6));
        assert!(!is_routable_boost_v6([0; 16])); // ::
        assert!(!is_routable_boost_v6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        assert!(!is_routable_boost_v6([0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11]));
        assert!(!is_routable_boost_v6([0x26, 0x06, 0x47, 0x00, 0x00, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        assert!(!is_routable_boost_v6([0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88]));
        let [nat64_a, _] = crate::warp::google_nat64_addrs();
        assert!(!is_routable_boost_v6(nat64_a));

        let q6 = make_query(0x6666, "scontent-sin6-1.cdninstagram.com", QTYPE_AAAA);
        let mut ans6 = q6.clone();
        ans6[2] = 0x81;
        ans6[3] = 0x80;
        ans6[7] = 1;
        ans6.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0, 0, 0x01, 0x2C, 0x00, 0x10]);
        ans6.extend_from_slice(&ig_v6);
        let mut ips6 = [[0u8; 16]; 4];
        assert_eq!(extract_ipv6_answers(&ans6, &mut ips6), 1);
        assert_eq!(ips6[0], ig_v6);
    }
}
