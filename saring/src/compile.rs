// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Turns filter lists into a name table. Understands hosts files, plain domains and the
//! domain rules of Adblock syntax. Anything else is counted and left out.

use crate::{key, ALLOW, BLOCK, DENY, HEADER, MAGIC, POPUP, THIRD, VERSION};

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub block: u32,
    pub allow: u32,
    pub deny: u32,
    pub third: u32,
    pub popup: u32,
    pub cosmetic: u32,
    pub unsupported: u32,
}

enum Rule<'a> {
    Skip,
    Cosmetic,
    Unsupported,
    Domain { name: &'a str, kind: u8, suffix: bool, bad: bool },
    Hosts(&'a str),
}

fn is_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return false;
    }
    let mut last = "";
    for label in s.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
        last = label;
    }
    !last.bytes().all(|b| b.is_ascii_digit())
}

fn is_address(s: &str) -> bool {
    s == "0" || s.contains(':') || (s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok()))
}

fn parse(line: &str) -> Rule<'_> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
        return Rule::Skip;
    }
    if line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#")
        || line.contains("#%#")
    {
        return Rule::Cosmetic;
    }
    if line.starts_with('#') {
        return Rule::Skip;
    }

    let (exception, body) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let Some(body) = body.strip_prefix("||") else {
        if exception || line.starts_with('|') || line.starts_with('/') {
            return Rule::Unsupported;
        }
        let line = line.split('#').next().unwrap_or("").trim_end();
        let mut tokens = line.split_ascii_whitespace();
        return match (tokens.next(), tokens.next()) {
            (Some(first), Some(_)) if is_address(first) => {
                Rule::Hosts(line[first.len()..].trim_start())
            }
            (Some(only), None) if is_domain(only) => {
                Rule::Domain { name: only, kind: BLOCK, suffix: false, bad: false }
            }
            _ => Rule::Unsupported,
        };
    };

    let (pattern, options) = match body.rfind('$') {
        Some(at) => (&body[..at], &body[at + 1..]),
        None => (body, ""),
    };
    let name = pattern
        .strip_suffix("^|")
        .or_else(|| pattern.strip_suffix('^'))
        .unwrap_or(pattern);
    if !is_domain(name) {
        return Rule::Unsupported;
    }

    let (mut important, mut third, mut popup, mut bad) = (false, false, false, false);
    for option in options.split(',').filter(|o| !o.is_empty()) {
        match option {
            "important" => important = true,
            "third-party" | "3p" => third = true,
            "popup" | "document" | "doc" => popup = true,
            "all" => {}
            "badfilter" => bad = true,
            _ => return Rule::Unsupported,
        }
    }
    let kind = match (exception, popup, third, important) {
        (true, false, false, _) => ALLOW,
        (true, ..) => return Rule::Unsupported,
        (false, true, ..) => POPUP,
        (false, false, true, _) => THIRD,
        (false, false, false, true) => DENY,
        (false, false, false, false) => BLOCK,
    };
    Rule::Domain { name, kind, suffix: true, bad }
}

fn entry(name: &str, kind: u8, suffix: bool) -> Option<u64> {
    Some(key(name.as_bytes())? | u64::from(kind) << 1 | u64::from(suffix))
}

fn count(stats: &mut Stats, kind: u8) {
    match kind {
        DENY => stats.deny += 1,
        ALLOW => stats.allow += 1,
        BLOCK => stats.block += 1,
        THIRD => stats.third += 1,
        _ => stats.popup += 1,
    }
}

const LOCAL: [&str; 8] = [
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-allnodes",
    "ip6-allrouters",
];

/// Compiles `sources` into one blob. Returns it with the per-source counts.
pub fn compile(sources: &[&str], created: u64) -> (Vec<u8>, Vec<Stats>) {
    let mut entries: Vec<u64> = Vec::new();
    let mut removed: Vec<u64> = Vec::new();
    let mut all = Vec::with_capacity(sources.len());

    for text in sources {
        let mut stats = Stats::default();
        for line in text.lines() {
            match parse(line) {
                Rule::Skip => {}
                Rule::Cosmetic => stats.cosmetic += 1,
                Rule::Unsupported => stats.unsupported += 1,
                Rule::Domain { name, kind, suffix, bad } => match entry(name, kind, suffix) {
                    Some(e) if bad => removed.push(e),
                    Some(e) => {
                        entries.push(e);
                        count(&mut stats, kind);
                    }
                    None => stats.unsupported += 1,
                },
                Rule::Hosts(names) => {
                    for name in names.split_ascii_whitespace() {
                        if LOCAL.contains(&name) || is_address(name) {
                            continue;
                        }
                        match entry(name, BLOCK, false).filter(|_| is_domain(name)) {
                            Some(e) => {
                                entries.push(e);
                                stats.block += 1;
                            }
                            None => stats.unsupported += 1,
                        }
                    }
                }
            }
        }
        all.push(stats);
    }

    entries.sort_unstable();
    entries.dedup();
    removed.sort_unstable();
    // An exact rule next to the suffix rule for the same name and kind says nothing new.
    let mut kept = Vec::with_capacity(entries.len());
    for (i, &e) in entries.iter().enumerate() {
        let shadowed = e & 1 == 0 && entries.get(i + 1) == Some(&(e | 1));
        if !shadowed && removed.binary_search(&e).is_err() {
            kept.push(e);
        }
    }

    (write(&kept, created), all)
}

fn write(entries: &[u64], created: u64) -> Vec<u8> {
    let want = (entries.len() / 2).max(2).next_power_of_two().trailing_zeros();
    let bits = want.clamp(4, 24);
    let buckets = 1usize << bits;
    let entries_at = (HEADER + (buckets + 1) * 4 + 7) & !7;

    let mut blob = Vec::with_capacity(entries_at + entries.len() * 8);
    blob.extend_from_slice(&MAGIC);
    blob.extend_from_slice(&VERSION.to_le_bytes());
    blob.extend_from_slice(&bits.to_le_bytes());
    blob.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    blob.extend_from_slice(&created.to_le_bytes());
    blob.resize(HEADER, 0);

    let mut at = 0usize;
    for bucket in 0..buckets {
        while at < entries.len() && (entries[at] >> (64 - bits)) as usize == bucket {
            at += 1;
        }
        if bucket == 0 {
            blob.extend_from_slice(&0u32.to_le_bytes());
        }
        blob.extend_from_slice(&(at as u32).to_le_bytes());
    }
    blob.resize(entries_at, 0);
    for e in entries {
        blob.extend_from_slice(&e.to_le_bytes());
    }
    blob
}
