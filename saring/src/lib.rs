// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Name table read by the resolver and the web layers.
//!
//! One sorted array of 64-bit entries behind a bucket index. An entry is the 60-bit hash of a
//! domain, a 3-bit kind and a suffix bit. A name is hashed label by label from the right, so
//! every parent domain costs one probe and no second pass over the bytes. Lookups never
//! allocate and never panic on a damaged blob.

pub mod cache;
pub mod clean;
pub mod compile;
pub mod dns;
pub mod ffi;
pub mod state;
pub mod upstream;
pub mod warp;

pub const MAGIC: [u8; 4] = *b"SRNG";
pub const VERSION: u32 = 1;
pub const HEADER: usize = 32;

pub const DENY: u8 = 0;
pub const ALLOW: u8 = 1;
pub const BLOCK: u8 = 2;
pub const THIRD: u8 = 3;
pub const POPUP: u8 = 4;

pub(crate) const MAX_LEVELS: usize = 16;
const MAX_NAME: usize = 253;

#[inline]
fn label_hash(prev: u64, label: &[u8]) -> u64 {
    let mut x = prev ^ 0xcbf2_9ce4_8422_2325;
    for &b in label {
        x = (x ^ u64::from(b.to_ascii_lowercase())).wrapping_mul(0x0000_0100_0000_01b3);
    }
    x ^= x >> 32;
    x = x.wrapping_mul(0xd6e8_feb8_6659_fd93);
    x ^ (x >> 32)
}

/// Keys of every suffix of `name`, shortest first. Returns how many were written and whether
/// the last one is the whole name.
#[inline]
pub(crate) fn keys(name: &[u8], out: &mut [u64; MAX_LEVELS]) -> (usize, bool) {
    let name = match name.last() {
        Some(b'.') => &name[..name.len() - 1],
        _ => name,
    };
    if name.is_empty() || name.len() > MAX_NAME {
        return (0, false);
    }
    let mut h = 0u64;
    let mut n = 0;
    let mut end = name.len();
    loop {
        let start = name[..end].iter().rposition(|&b| b == b'.').map_or(0, |p| p + 1);
        if start == end {
            return (0, false);
        }
        h = label_hash(h, &name[start..end]);
        out[n] = h & !0xF;
        n += 1;
        if start == 0 {
            return (n, true);
        }
        if n == MAX_LEVELS {
            return (n, false);
        }
        end = start - 1;
    }
}

/// Key of a whole domain, for the compiler.
pub fn key(domain: &[u8]) -> Option<u64> {
    let mut k = [0u64; MAX_LEVELS];
    match keys(domain, &mut k) {
        (n, true) if n > 0 => Some(k[n - 1]),
        _ => None,
    }
}

#[derive(Clone, Copy)]
pub struct Names<'a> {
    bits: u32,
    index: &'a [u8],
    entries: &'a [u8],
}

impl<'a> Names<'a> {
    /// Checks the header and the sizes only. Enough for lookups to stay in bounds.
    pub fn view(blob: &'a [u8]) -> Option<Self> {
        if blob.len() < HEADER || blob[..4] != MAGIC || u32_at(blob, 4)? != VERSION {
            return None;
        }
        let bits = u32_at(blob, 8)?;
        let count = u32_at(blob, 12)? as usize;
        if !(1..=24).contains(&bits) {
            return None;
        }
        let index_len = ((1usize << bits) + 1) * 4;
        let entries_at = (HEADER + index_len + 7) & !7;
        if blob.len() != entries_at.checked_add(count.checked_mul(8)?)? {
            return None;
        }
        Some(Self {
            bits,
            index: &blob[HEADER..HEADER + index_len],
            entries: &blob[entries_at..],
        })
    }

    /// `view` plus a full check of the index, for a blob that just arrived.
    pub fn open(blob: &'a [u8]) -> Option<Self> {
        let names = Self::view(blob)?;
        let count = names.len() as u32;
        let mut last = 0u32;
        for chunk in names.index.chunks_exact(4) {
            let v = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if v < last || v > count {
                return None;
            }
            last = v;
        }
        (last == count).then_some(names)
    }

    pub fn len(&self) -> usize {
        self.entries.len() / 8
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    fn probe(&self, key: u64, whole: bool) -> u32 {
        let bucket = (key >> (64 - self.bits)) as usize * 4;
        let (Some(lo), Some(hi)) = (u32_at(self.index, bucket), u32_at(self.index, bucket + 4))
        else {
            return 0;
        };
        let mut mask = 0;
        let mut at = lo as usize * 8;
        let end = (hi as usize * 8).min(self.entries.len());
        while at + 8 <= end {
            let e = u64::from_le_bytes([
                self.entries[at],
                self.entries[at + 1],
                self.entries[at + 2],
                self.entries[at + 3],
                self.entries[at + 4],
                self.entries[at + 5],
                self.entries[at + 6],
                self.entries[at + 7],
            ]);
            let base = e & !0xF;
            if base == key {
                if whole || e & 1 != 0 {
                    mask |= 1 << ((e >> 1) & 7);
                }
            } else if base > key {
                break;
            }
            at += 8;
        }
        mask
    }

    /// Bit per kind that has a rule for `name` or one of its parents.
    #[inline]
    pub fn mask(&self, name: &[u8]) -> u32 {
        let mut k = [0u64; MAX_LEVELS];
        let (n, whole) = keys(name, &mut k);
        let mut mask = 0;
        for (i, &key) in k[..n].iter().enumerate() {
            mask |= self.probe(key, whole && i + 1 == n);
        }
        mask
    }

    /// What the resolver asks.
    #[inline]
    pub fn blocked(&self, name: &[u8]) -> bool {
        name_verdict(self.mask(name))
    }

    /// Evaluates pre-computed suffix keys from a single-pass DNS question parse.
    #[inline]
    pub fn blocked_keys(&self, keys: &[u64], whole: bool) -> bool {
        let mut mask = 0;
        let n = keys.len();
        for (i, &key) in keys.iter().enumerate() {
            mask |= self.probe(key, whole && i + 1 == n);
        }
        name_verdict(mask)
    }

    /// What a web layer asks for a request made by a page on `page_host`. `navigation` is a
    /// new window or a top-level load the owner did not tap.
    pub fn request_blocked(&self, url: &[u8], page_host: &[u8], navigation: bool) -> bool {
        let Some(host) = host_of(url) else { return false };
        let mask = self.mask(host);
        if mask & (1 << DENY) != 0 {
            return true;
        }
        if mask & (1 << ALLOW) != 0 {
            return false;
        }
        if mask & (1 << BLOCK) != 0 {
            return true;
        }
        if navigation && mask & (1 << POPUP) != 0 {
            return true;
        }
        mask & (1 << THIRD) != 0 && !same_site(host, page_host)
    }
}

#[inline]
pub fn name_verdict(mask: u32) -> bool {
    mask & (1 << DENY) != 0 || (mask & (1 << ALLOW) == 0 && mask & (1 << BLOCK) != 0)
}

#[inline]
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Host of an http, https, ws or wss URL, without userinfo and port.
pub fn host_of(url: &[u8]) -> Option<&[u8]> {
    let at = url.windows(3).take(8).position(|w| w == b"://")?;
    let scheme = &url[..at];
    if !(scheme.eq_ignore_ascii_case(b"http")
        || scheme.eq_ignore_ascii_case(b"https")
        || scheme.eq_ignore_ascii_case(b"ws")
        || scheme.eq_ignore_ascii_case(b"wss"))
    {
        return None;
    }
    let rest = &url[at + 3..];
    let end = rest.iter().position(|&b| matches!(b, b'/' | b'?' | b'#')).unwrap_or(rest.len());
    let auth = &rest[..end];
    let auth = auth.iter().rposition(|&b| b == b'@').map_or(auth, |p| &auth[p + 1..]);
    if auth.first() == Some(&b'[') {
        return None;
    }
    let host = auth.iter().position(|&b| b == b':').map_or(auth, |p| &auth[..p]);
    (!host.is_empty()).then_some(host)
}

/// Second-level labels that registries hand out under a country code.
const SECOND_LEVEL: [&[u8]; 14] = [
    b"co", b"com", b"net", b"org", b"ac", b"go", b"gov", b"edu", b"or", b"web", b"sch", b"my",
    b"biz", b"mil",
];

/// The registrable part of `host`, close enough to tell first party from third party.
pub fn site_of(host: &[u8]) -> &[u8] {
    let host = host.strip_suffix(b".").unwrap_or(host);
    let mut dots = host.iter().enumerate().rev().filter(|(_, &b)| b == b'.').map(|(i, _)| i);
    let Some(last) = dots.next() else { return host };
    let Some(second) = dots.next() else { return host };
    let tld = &host[last + 1..];
    let sld = &host[second + 1..last];
    if tld.len() == 2 && SECOND_LEVEL.iter().any(|s| s.eq_ignore_ascii_case(sld)) {
        return dots.next().map_or(host, |third| &host[third + 1..]);
    }
    &host[second + 1..]
}

pub fn same_site(a: &[u8], b: &[u8]) -> bool {
    site_of(a).eq_ignore_ascii_case(site_of(b))
}

/// The first question name of a DNS query, dotted, in `out`.
pub fn query_name<'b>(msg: &[u8], out: &'b mut [u8; 256]) -> Option<&'b [u8]> {
    if msg.len() < 17 || u16::from_be_bytes([msg[4], msg[5]]) == 0 {
        return None;
    }
    let mut at = 12;
    let mut len = 0;
    loop {
        let n = *msg.get(at)? as usize;
        if n == 0 {
            break;
        }
        if n > 63 || len + n + 1 > 254 {
            return None;
        }
        if len != 0 {
            out[len] = b'.';
            len += 1;
        }
        out[len..len + n].copy_from_slice(msg.get(at + 1..at + 1 + n)?);
        len += n;
        at += n + 1;
    }
    (len != 0).then_some(&out[..len])
}

#[cfg(test)]
mod tests {
    use super::compile::{compile, Stats};
    use super::*;

    fn build(text: &str) -> (Vec<u8>, Stats) {
        let (blob, stats) = compile(&[text], 1);
        (blob, stats.into_iter().next().unwrap())
    }

    #[test]
    fn suffix_rule_covers_subdomains() {
        let (blob, _) = build("||ads.example.com^\n");
        let n = Names::open(&blob).unwrap();
        assert!(n.blocked(b"ads.example.com"));
        assert!(n.blocked(b"a.b.ads.example.com"));
        assert!(n.blocked(b"ADS.Example.COM."));
        assert!(!n.blocked(b"example.com"));
        assert!(!n.blocked(b"xads.example.com"));
        assert!(!n.blocked(b"ads.example.com.evil.org"));
    }

    #[test]
    fn hosts_line_is_exact() {
        let (blob, s) = build("0.0.0.0 t.example.net u.example.net # tail\n127.0.0.1 localhost\n");
        let n = Names::open(&blob).unwrap();
        assert_eq!(s.block, 2);
        assert!(n.blocked(b"t.example.net"));
        assert!(n.blocked(b"u.example.net"));
        assert!(!n.blocked(b"x.t.example.net"));
        assert!(!n.blocked(b"localhost"));
    }

    #[test]
    fn exception_beats_block_and_important_beats_exception() {
        let (blob, _) = build(
            "||example.com^\n@@||ok.example.com^\n||bad.ok.example.com^$important\n",
        );
        let n = Names::open(&blob).unwrap();
        assert!(n.blocked(b"example.com"));
        assert!(n.blocked(b"x.example.com"));
        assert!(!n.blocked(b"ok.example.com"));
        assert!(!n.blocked(b"cdn.ok.example.com"));
        assert!(n.blocked(b"bad.ok.example.com"));
    }

    #[test]
    fn badfilter_removes_the_rule() {
        let (blob, _) = build("||a.example^\n||b.example^\n||a.example^$badfilter\n");
        let n = Names::open(&blob).unwrap();
        assert!(!n.blocked(b"a.example"));
        assert!(n.blocked(b"b.example"));
    }

    #[test]
    fn third_party_and_popup_stay_out_of_the_resolver() {
        let (blob, s) = build("||social.example^$third-party\n||pop.example^$popup\n");
        let n = Names::open(&blob).unwrap();
        assert_eq!((s.third, s.popup), (1, 1));
        assert!(!n.blocked(b"social.example"));
        assert!(!n.blocked(b"pop.example"));
        assert!(n.request_blocked(b"https://w.social.example/x.js", b"news.co.id", false));
        assert!(!n.request_blocked(b"https://w.social.example/x.js", b"social.example", false));
        assert!(n.request_blocked(b"https://pop.example/?z=1", b"news.co.id", true));
        assert!(!n.request_blocked(b"https://pop.example/a.png", b"news.co.id", false));
    }

    #[test]
    fn unsupported_rules_are_counted_not_guessed() {
        let (blob, s) = build(
            "! comment\n[Adblock Plus 2.0]\n||x.example^$script\n/banner/*\n||y.example/ads/\n\
             example.org##.ad\n/^ad[0-9]+\\./\n||1.2.3.4^\n||*.wild.example^\n",
        );
        assert_eq!(s.cosmetic, 1);
        assert_eq!(s.unsupported, 6);
        assert_eq!(Names::open(&blob).unwrap().len(), 0);
    }

    #[test]
    fn damaged_blob_is_refused_and_never_panics() {
        let (blob, _) = build("||a.example^\n||b.example^\n||c.example^\n");
        assert!(Names::open(&blob[..blob.len() - 1]).is_none());
        let mut bad = blob.clone();
        bad[HEADER] = 0xff;
        bad[HEADER + 3] = 0xff;
        assert!(Names::open(&bad).is_none());
        // A view skips the index check; lookups must still stay in bounds.
        for i in HEADER..bad.len() {
            let mut b = blob.clone();
            b[i] ^= 0xff;
            if let Some(n) = Names::view(&b) {
                n.blocked(b"a.example");
                n.blocked(b"zz.c.example");
            }
        }
    }

    #[test]
    fn odd_names_do_not_match() {
        let (blob, _) = build("||example.com^\n");
        let n = Names::open(&blob).unwrap();
        for name in [&b""[..], b".", b"..", b"a..example.com", b".example.com"] {
            assert!(!n.blocked(name), "{:?}", name);
        }
        assert!(!n.blocked(&[b'a'; 300]));
        let deep = "a.".repeat(40) + "example.com";
        assert!(n.blocked(deep.as_bytes()));
    }

    #[test]
    fn hosts_and_sites() {
        assert_eq!(host_of(b"https://User@A.example.com:8443/p?q"), Some(&b"A.example.com"[..]));
        assert_eq!(host_of(b"wss://x.example/"), Some(&b"x.example"[..]));
        assert_eq!(host_of(b"intent://x#Intent;end"), None);
        assert_eq!(host_of(b"https://[::1]/"), None);
        assert_eq!(site_of(b"a.b.example.com"), b"example.com");
        assert_eq!(site_of(b"cdn.detik.co.id"), b"detik.co.id");
        assert_eq!(site_of(b"kemdikbud.go.id"), b"kemdikbud.go.id");
        assert_eq!(site_of(b"localhost"), b"localhost");
        assert!(same_site(b"static.Example.com", b"www.example.com"));
        assert!(!same_site(b"a.co.id", b"b.co.id"));
    }

    #[test]
    fn question_name_from_a_packet() {
        let mut msg = vec![0u8; 12];
        msg[5] = 1;
        msg.extend_from_slice(b"\x03ads\x07example\x03com\x00\x00\x01\x00\x01");
        let mut buf = [0u8; 256];
        assert_eq!(query_name(&msg, &mut buf), Some(&b"ads.example.com"[..]));
        msg.truncate(20);
        assert_eq!(query_name(&msg, &mut buf), None);
    }

    #[test]
    fn many_rules_all_found() {
        let mut text = String::new();
        for i in 0..50_000 {
            text.push_str(&format!("||h{i}.net{}.example^\n", i % 97));
        }
        let (blob, s) = build(&text);
        let n = Names::open(&blob).unwrap();
        assert_eq!(s.block, 50_000);
        assert_eq!(n.len(), 50_000);
        for i in (0..50_000).step_by(7) {
            assert!(n.blocked(format!("x.h{i}.net{}.example", i % 97).as_bytes()));
            assert!(!n.blocked(format!("h{i}.net{}.example.org", i % 97).as_bytes()));
        }
    }
}

#[cfg(test)]
mod golden {
    /// The Java lookup in android.webkit must produce these keys.
    #[test]
    fn keys_for_the_java_port() {
        assert_eq!(super::key(b"ads.example.com").unwrap(), super::key(b"ADS.example.COM.").unwrap());
        assert_eq!(super::key(b"ads.example.com"), Some(0xaa41_1675_73ec_7920));
        assert_eq!(super::key(b"com"), Some(0x8c1b_ba72_357f_6830));
    }
}
