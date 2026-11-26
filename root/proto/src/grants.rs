// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! `grants.v1`: the policy file YasvaraRootService writes and `yasvara_rootd` trusts
//!
//!
//! ```text
//! # yasvara-root grants v1 enabled=1 frozen=0 version=7
//! uid tier ns flags expires_wall_ms boot_id|- signer pkg[,pkg…]
//! 10195 root req 0 0 - 3f8a91c2d4e5b607 com.termux,com.termux.api
//! ```
//!
//! `tier` is `shell` or `root` (the highest tier the app may ask for), `ns` is `req`
//! (caller's mount namespace) or `global`, `flags` is hex. A line that does not parse is
//! skipped; a file without the header is treated as no grants at all. `enabled=0` is the
//! master switch: everyone is refused and nobody is projected. Without the key the daemon is
//! on, as it only runs while the switch is.

use crate::{TIER_ROOT, TIER_SHELL};

pub const HEADER_PREFIX: &str = "# yasvara-root grants v1";
pub const MAX_LINES: usize = 4096;
pub const MAX_FILE: usize = 1 << 20;

/// Grant flags.
pub const GF_ALLOW_BEFORE_UNLOCK: u32 = 1 << 0;
pub const GF_NOTIFY_ON_USE: u32 = 1 << 1;
pub const GF_LOG_FULL: u32 = 1 << 2;
pub const GF_ALLOW_GLOBAL_NS: u32 = 1 << 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub uid: u32,
    /// [`TIER_SHELL`] or [`TIER_ROOT`]: the highest tier the app may request.
    pub tier: u8,
    pub global_ns: bool,
    pub flags: u32,
    /// Wall-clock milliseconds, 0 for none.
    pub expires_ms: u64,
    /// Valid only for the boot with this id (`until reboot`).
    pub boot_id: Option<String>,
    pub signer: String,
    pub packages: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grants {
    pub off: bool,
    pub frozen: bool,
    pub version: u64,
    pub grants: Vec<Grant>,
}

/// Why a lookup did not yield a usable grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Off,
    NotEnrolled,
    Frozen,
    Expired,
}

impl Grants {
    pub fn parse(text: &str) -> Grants {
        let mut lines = text.lines();
        let Some(head) = lines.next() else { return Grants::default() };
        let Some(rest) = head.strip_prefix(HEADER_PREFIX) else { return Grants::default() };
        let mut out = Grants::default();
        for kv in rest.split_whitespace() {
            match kv.split_once('=') {
                Some(("enabled", v)) => out.off = v == "0",
                Some(("frozen", v)) => out.frozen = v == "1",
                Some(("version", v)) => out.version = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        for line in lines.take(MAX_LINES) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(g) = parse_line(line) {
                out.grants.push(g);
            }
        }
        out
    }

    pub fn find(&self, uid: u32) -> Option<&Grant> {
        self.grants.iter().find(|g| g.uid == uid)
    }

    /// Applies freeze, expiry and `until reboot`. Lazy by design: nothing runs on a timer.
    pub fn lookup(&self, uid: u32, now_wall_ms: u64, boot_id: &str) -> Result<&Grant, Refusal> {
        if self.off {
            return Err(Refusal::Off);
        }
        let g = self.find(uid).ok_or(Refusal::NotEnrolled)?;
        if self.frozen {
            return Err(Refusal::Frozen);
        }
        if g.expires_ms != 0 && now_wall_ms >= g.expires_ms {
            return Err(Refusal::Expired);
        }
        if let Some(id) = &g.boot_id {
            if id != boot_id {
                return Err(Refusal::Expired);
            }
        }
        Ok(g)
    }
}

fn parse_line(line: &str) -> Option<Grant> {
    let mut f = line.split_ascii_whitespace();
    let uid = f.next()?.parse().ok()?;
    let tier = match f.next()? {
        "shell" => TIER_SHELL,
        "root" => TIER_ROOT,
        _ => return None,
    };
    let global_ns = match f.next()? {
        "req" => false,
        "global" => true,
        _ => return None,
    };
    let flags = u32::from_str_radix(f.next()?, 16).ok()?;
    let expires_ms = f.next()?.parse().ok()?;
    let boot = f.next()?;
    let boot_id = (boot != "-").then(|| boot.to_string());
    let signer = f.next()?.to_string();
    let packages = f.next().unwrap_or("").split(',').filter(|p| !p.is_empty()).map(String::from).collect();
    Some(Grant { uid, tier, global_ns, flags, expires_ms, boot_id, signer, packages })
}

/// the set zygote reads at app start to decide whether to project the client into
/// an app's mount namespace: sorted, de-duplicated little-endian `u32` uids, nothing else. A
/// frozen policy projects nothing. Expiry is not applied here (zygote has no clock policy);
/// the daemon refuses an expired grant on its own, so over-inclusion only costs a mount.
pub fn enrolled_set(g: &Grants) -> Vec<u8> {
    if g.off || g.frozen {
        return Vec::new();
    }
    let mut uids: Vec<u32> = g.grants.iter().map(|e| e.uid).collect();
    uids.sort_unstable();
    uids.dedup();
    uids.iter().flat_map(|u| u.to_le_bytes()).collect()
}

/// The serialisation YasvaraRootService mirrors in Java; used by tests and tooling.
pub fn format(g: &Grants) -> String {
    let mut s = format!("{HEADER_PREFIX} enabled={} frozen={} version={}\n", !g.off as u8, g.frozen as u8, g.version);
    for e in &g.grants {
        s.push_str(&format!(
            "{} {} {} {:x} {} {} {} {}\n",
            e.uid,
            if e.tier == TIER_ROOT { "root" } else { "shell" },
            if e.global_ns { "global" } else { "req" },
            e.flags,
            e.expires_ms,
            e.boot_id.as_deref().unwrap_or("-"),
            e.signer,
            e.packages.join(",")
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# yasvara-root grants v1 frozen=0 version=7\n\
        10195 root req 0 0 - 3f8a91c2d4e5b607 com.termux,com.termux.api\n\
        2000 shell req 0 0 - adb shell\n\
        10200 root global 8 1000 abc-123 deadbeef com.x\n\
        garbage line\n";

    #[test]
    fn enrolled_set_is_sorted_unique_and_empty_when_frozen() {
        let mut g = Grants::parse(SAMPLE);
        let mut want = Vec::new();
        for u in [2000u32, 10195, 10200] {
            want.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(enrolled_set(&g), want);
        g.grants.push(g.grants[0].clone());
        assert_eq!(enrolled_set(&g), want, "duplicates collapse");
        g.frozen = true;
        assert!(enrolled_set(&g).is_empty());
        g.frozen = false;
        g.off = true;
        assert!(enrolled_set(&g).is_empty(), "nobody is projected while off");
    }

    #[test]
    fn parses_and_roundtrips() {
        let g = Grants::parse(SAMPLE);
        assert_eq!(g.version, 7);
        assert!(!g.frozen);
        assert_eq!(g.grants.len(), 3);
        let t = g.find(10195).unwrap();
        assert_eq!(t.tier, TIER_ROOT);
        assert_eq!(t.packages, vec!["com.termux", "com.termux.api"]);
        assert_eq!(Grants::parse(&format(&g)), g);
    }

    #[test]
    fn missing_header_means_no_grants() {
        assert_eq!(Grants::parse("10195 root req 0 0 - x p\n"), Grants::default());
        assert_eq!(Grants::parse(""), Grants::default());
    }

    #[test]
    fn lookup_rules() {
        let g = Grants::parse(SAMPLE);
        assert!(g.lookup(10195, 5_000, "b").is_ok());
        assert_eq!(g.lookup(1, 0, "b").unwrap_err(), Refusal::NotEnrolled);
        // Time-limited grant.
        assert!(g.lookup(10200, 999, "abc-123").is_ok());
        assert_eq!(g.lookup(10200, 1000, "abc-123").unwrap_err(), Refusal::Expired);
        // `until reboot`: a different boot id kills it.
        assert_eq!(g.lookup(10200, 1, "other").unwrap_err(), Refusal::Expired);
        let mut frozen = g.clone();
        frozen.frozen = true;
        assert_eq!(frozen.lookup(10195, 0, "b").unwrap_err(), Refusal::Frozen);
        // An unknown uid is NotEnrolled even when frozen: nothing to reveal.
        assert_eq!(frozen.lookup(7, 0, "b").unwrap_err(), Refusal::NotEnrolled);
    }

    #[test]
    fn master_switch() {
        let on = SAMPLE.replacen("v1 ", "v1 enabled=1 ", 1);
        let off = SAMPLE.replacen("v1 ", "v1 enabled=0 ", 1);
        assert!(!Grants::parse(SAMPLE).off, "no key: on");
        assert!(!Grants::parse(&on).off);
        let g = Grants::parse(&off);
        assert!(g.off);
        assert_eq!(g.lookup(10195, 0, "b").unwrap_err(), Refusal::Off);
        assert_eq!(g.lookup(7, 0, "b").unwrap_err(), Refusal::Off);
        assert_eq!(Grants::parse(&format(&g)), g);
    }

    #[test]
    fn caps_the_number_of_lines() {
        let mut s = String::from("# yasvara-root grants v1 frozen=0 version=1\n");
        for i in 0..(MAX_LINES + 10) {
            s.push_str(&format!("{} root req 0 0 - s p\n", 10000 + i));
        }
        assert_eq!(Grants::parse(&s).grants.len(), MAX_LINES);
    }
}
