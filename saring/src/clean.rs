// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-allocation URL redirect unwrapper and tracking parameter stripper.
//!
//! Unwraps Google click-tracker redirects (`https://www.google.<tld>/url?q=<target>&...`) and
//! strips tracking query parameters (`ved`, `ei`, `gs_lcrp`, `sclient`, `gclid`, `fbclid`,
//! `utm_*`) in one pass into the caller's output buffer. Returns 0 when nothing changed.

use crate::host_of;

const TRACKING_KEYS: [&[u8]; 18] = [
    b"ved",
    b"ei",
    b"oq",
    b"gs_lcrp",
    b"gs_lp",
    b"sclient",
    b"uact",
    b"gclid",
    b"gclsrc",
    b"dclid",
    b"fbclid",
    b"igshid",
    b"mc_eid",
    b"msclkid",
    b"twclid",
    b"ttclid",
    b"yclid",
    b"_hsmi",
];

#[inline]
fn is_tracking_param(key: &[u8]) -> bool {
    if key.len() >= 4 && key[..4].eq_ignore_ascii_case(b"utm_") {
        return true;
    }
    TRACKING_KEYS.iter().any(|k| key.eq_ignore_ascii_case(k))
}

#[inline]
fn is_google_host(host: &[u8]) -> bool {
    let host = host.strip_suffix(b".").unwrap_or(host);
    if let Some(rest) = host.strip_prefix(b"www.") {
        is_google_apex(rest)
    } else {
        is_google_apex(host)
    }
}

#[inline]
fn is_google_apex(host: &[u8]) -> bool {
    let Some(rest) = host.get(..7).filter(|p| p.eq_ignore_ascii_case(b"google.")).map(|_| &host[7..])
    else {
        return false;
    };
    !rest.is_empty() && rest.bytes_valid_tld()
}

trait TldCheck {
    fn bytes_valid_tld(&self) -> bool;
}

impl TldCheck for [u8] {
    #[inline]
    fn bytes_valid_tld(&self) -> bool {
        self.len() <= 10 && self.iter().all(|&b| b.is_ascii_alphabetic() || b == b'.')
    }
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    let mut i = 0usize;
    let mut o = 0usize;
    while i < src.len() {
        let b = if src[i] == b'%' && i + 2 < src.len() {
            if let (Some(hi), Some(lo)) = (hex_val(src[i + 1]), hex_val(src[i + 2])) {
                i += 3;
                (hi << 4) | lo
            } else {
                let c = src[i];
                i += 1;
                c
            }
        } else {
            let c = src[i];
            i += 1;
            c
        };
        if o >= dst.len() {
            return None;
        }
        dst[o] = b;
        o += 1;
    }
    Some(o)
}

/// Attempts to unwrap a Google click-tracker URL (`https://www.google.*/url?q=...` or `url=...`)
/// into `scratch`. Returns `Some(len)` if unwrapped to an `http://` or `https://` target.
fn unwrap_google_redirect(url: &[u8], scratch: &mut [u8; 2048]) -> Option<usize> {
    let host = host_of(url)?;
    if !is_google_host(host) {
        return None;
    }
    let q_pos = url.iter().position(|&b| b == b'?')?;
    let before_q = &url[..q_pos];
    if !before_q.ends_with(b"/url") {
        return None;
    }
    let after_q = &url[q_pos + 1..];
    let query = match after_q.iter().position(|&b| b == b'#') {
        Some(h) => &after_q[..h],
        None => after_q,
    };
    for pair in query.split(|&b| b == b'&') {
        let Some(eq) = pair.iter().position(|&b| b == b'=') else {
            continue;
        };
        let k = &pair[..eq];
        let v = &pair[eq + 1..];
        if (k.eq_ignore_ascii_case(b"q") || k.eq_ignore_ascii_case(b"url")) && !v.is_empty() {
            let len = percent_decode(v, scratch)?;
            let target = &scratch[..len];
            if target.get(..8).is_some_and(|p| p.eq_ignore_ascii_case(b"https://"))
                || target.get(..7).is_some_and(|p| p.eq_ignore_ascii_case(b"http://"))
            {
                return Some(len);
            }
        }
    }
    None
}

/// Cleans `url` (unwrapping Google redirect trackers and stripping tracking query parameters) into
/// `out`. Returns `Some(written_len)` when the URL changed, or `None` when the URL is already
/// clean (or `out` is too small).
pub fn clean_url(url: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut scratch = [0u8; 2048];
    let (work, unwrapped) = match unwrap_google_redirect(url, &mut scratch) {
        Some(n) => (&scratch[..n], true),
        None => (url, false),
    };

    let Some(q_pos) = work.iter().position(|&b| b == b'?') else {
        if unwrapped && work.len() <= out.len() {
            out[..work.len()].copy_from_slice(work);
            return Some(work.len());
        }
        return None;
    };

    let prefix = &work[..q_pos];
    let rest = &work[q_pos + 1..];
    let (query, frag) = match rest.iter().position(|&b| b == b'#') {
        Some(h) => (&rest[..h], &rest[h..]),
        None => (rest, &b""[..]),
    };

    // Fast path: scan first to avoid copying untouched URLs.
    let mut any_stripped = false;
    for pair in query.split(|&b| b == b'&') {
        let key = match pair.iter().position(|&b| b == b'=') {
            Some(eq) => &pair[..eq],
            None => pair,
        };
        if is_tracking_param(key) {
            any_stripped = true;
            break;
        }
    }

    if !any_stripped && !unwrapped {
        return None;
    }

    let mut w = 0usize;
    if prefix.len() > out.len() {
        return None;
    }
    out[..prefix.len()].copy_from_slice(prefix);
    w += prefix.len();

    let mut kept_any = false;
    for pair in query.split(|&b| b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let key = match pair.iter().position(|&b| b == b'=') {
            Some(eq) => &pair[..eq],
            None => pair,
        };
        if is_tracking_param(key) {
            continue;
        }
        let sep = if kept_any { b'&' } else { b'?' };
        if w + 1 + pair.len() > out.len() {
            return None;
        }
        out[w] = sep;
        w += 1;
        out[w..w + pair.len()].copy_from_slice(pair);
        w += pair.len();
        kept_any = true;
    }

    if !frag.is_empty() {
        if w + frag.len() > out.len() {
            return None;
        }
        out[w..w + frag.len()].copy_from_slice(frag);
        w += frag.len();
    }

    Some(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwraps_google_redirect_and_strips_trackers_in_one_pass() {
        let raw = b"https://www.google.com/url?q=https%3A%2F%2Fdanbooru.donmai.us%2Fposts%3Ftags%3Dcat%26utm_source%3Dgoogle%26ved%3D123&sa=U&ved=2ahUKEwj&usg=AOvVaw";
        let mut out = [0u8; 512];
        let n = clean_url(raw, &mut out).unwrap();
        assert_eq!(&out[..n], b"https://danbooru.donmai.us/posts?tags=cat");
    }

    #[test]
    fn strips_all_params_without_trailing_question_mark() {
        let raw = b"https://example.com/article?utm_source=x&fbclid=abc&gclid=xyz#top";
        let mut out = [0u8; 512];
        let n = clean_url(raw, &mut out).unwrap();
        assert_eq!(&out[..n], b"https://example.com/article#top");
    }

    #[test]
    fn untouched_url_returns_none() {
        let raw = b"https://www.google.com/search?q=danbooru&hl=id";
        let mut out = [0u8; 512];
        assert_eq!(clean_url(raw, &mut out), None);
    }

    #[test]
    fn does_not_unwrap_non_http_redirect_targets() {
        let raw = b"https://www.google.com/url?q=javascript%3Aalert(1)&ved=1";
        let mut out = [0u8; 512];
        // Does not unwrap javascript:; only strips `ved`.
        let n = clean_url(raw, &mut out).unwrap();
        assert_eq!(&out[..n], b"https://www.google.com/url?q=javascript%3Aalert(1)");
    }
}
