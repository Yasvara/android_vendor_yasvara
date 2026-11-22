// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Policy model and zero-dependency JSON persistence (`/data/system/padat/policy.json`).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use crate::ioctl::{F2fsCompOptionV2, COMPRESS_LZ4, COMPRESS_ZSTD};

pub const DEFAULT_POLICY_PATH: &str = "/data/system/padat/policy.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompAlgo {
    Lz4,
    Lz4Hc,
    Zstd,
}

impl CompAlgo {
    pub fn as_str(self) -> &'static str {
        match self {
            CompAlgo::Lz4 => "lz4",
            CompAlgo::Lz4Hc => "lz4hc",
            CompAlgo::Zstd => "zstd",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "lz4" => Some(CompAlgo::Lz4),
            "lz4hc" => Some(CompAlgo::Lz4Hc),
            "zstd" => Some(CompAlgo::Zstd),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompProfile {
    pub algo: CompAlgo,
    /// 0 for LZ4, 3..=12 for LZ4HC, 1..=9 for ZSTD.
    pub level: u8,
    /// 16, 32, 64, or 128 KB.
    pub cluster_kb: u16,
}

impl CompProfile {
    pub const FAST: Self = Self {
        algo: CompAlgo::Lz4,
        level: 0,
        cluster_kb: 16,
    };
    pub const BALANCED: Self = Self {
        algo: CompAlgo::Zstd,
        level: 1,
        cluster_kb: 32,
    };
    pub const MAX: Self = Self {
        algo: CompAlgo::Zstd,
        level: 3,
        cluster_kb: 64,
    };

    pub fn normalized(mut self) -> Self {
        self.cluster_kb = match self.cluster_kb {
            0..=24 => 16,
            25..=48 => 32,
            49..=96 => 64,
            _ => 128,
        };
        self.level = match self.algo {
            CompAlgo::Lz4 => 0,
            CompAlgo::Lz4Hc => self.level.clamp(3, 12),
            CompAlgo::Zstd => self.level.clamp(1, 9),
        };
        self
    }

    pub fn cluster_bytes(self) -> usize {
        (self.cluster_kb as usize) * 1024
    }

    pub fn log_cluster_size(self) -> u8 {
        match self.cluster_kb {
            16 => 2,
            32 => 3,
            64 => 4,
            128 => 5,
            _ => 2,
        }
    }

    pub fn to_v2_ioctl(self) -> F2fsCompOptionV2 {
        let p = self.normalized();
        let algorithm = match p.algo {
            CompAlgo::Lz4 | CompAlgo::Lz4Hc => COMPRESS_LZ4,
            CompAlgo::Zstd => COMPRESS_ZSTD,
        };
        F2fsCompOptionV2 {
            algorithm,
            log_cluster_size: p.log_cluster_size(),
            level: p.level,
            flags: 0,
        }
    }

    pub fn from_v2_ioctl(opt: F2fsCompOptionV2) -> Option<Self> {
        let cluster_kb = (4u16).checked_shl(opt.log_cluster_size as u32)?;
        let (algo, level) = match opt.algorithm {
            COMPRESS_LZ4 if opt.level == 0 => (CompAlgo::Lz4, 0),
            COMPRESS_LZ4 => (CompAlgo::Lz4Hc, opt.level),
            COMPRESS_ZSTD => (CompAlgo::Zstd, opt.level.max(1)),
            _ => return None,
        };
        Some(Self {
            algo,
            level,
            cluster_kb,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Off,
    Fast,
    Balanced,
    Max,
    Custom,
}

impl Preset {
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Off => "off",
            Preset::Fast => "fast",
            Preset::Balanced => "balanced",
            Preset::Max => "max",
            Preset::Custom => "custom",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Some(Preset::Off),
            "fast" => Some(Preset::Fast),
            "balanced" => Some(Preset::Balanced),
            "max" => Some(Preset::Max),
            "custom" => Some(Preset::Custom),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scopes {
    pub apk_lib: bool,
    pub art_oat: bool,
    pub external_data: bool,
    pub obb: bool,
    pub internal_files: bool,
}

impl Scopes {
    pub const TIER1_ONLY: Self = Self {
        apk_lib: true,
        art_oat: true,
        external_data: false,
        obb: false,
        internal_files: false,
    };

    pub const FULL_APP: Self = Self {
        apk_lib: true,
        art_oat: true,
        external_data: true,
        obb: true,
        internal_files: false,
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePolicy {
    pub preset: Preset,
    pub profile: CompProfile,
    pub scopes: Scopes,
}

impl PackagePolicy {
    pub fn effective_profile(&self) -> Option<CompProfile> {
        match self.preset {
            Preset::Off => None,
            Preset::Fast => Some(CompProfile::FAST),
            Preset::Balanced => Some(CompProfile::BALANCED),
            Preset::Max => Some(CompProfile::MAX),
            Preset::Custom => Some(self.profile.normalized()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub auto_tier1: bool,
    pub default_tier1: CompProfile,
    pub min_saving_pct: u8,
    pub min_file_bytes: u64,
    pub thermal_pause_mc: i32,
    pub pause_on_game: bool,
    pub packages: BTreeMap<String, PackagePolicy>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            // Default OFF: user explicitly picks which apps/games to compress.
            auto_tier1: false,
            default_tier1: CompProfile::FAST,
            min_saving_pct: 5,
            min_file_bytes: 16384,
            thermal_pause_mc: 42000,
            pause_on_game: true,
            packages: BTreeMap::new(),
        }
    }
}

impl Policy {
    /// Resolves effective `(profile, scopes)` for `pkg` taking `auto_tier1` into account.
    pub fn resolve_for_package(&self, pkg: &str) -> Option<(CompProfile, Scopes)> {
        if let Some(p) = self.packages.get(pkg) {
            return p.effective_profile().map(|prof| (prof, p.scopes));
        }
        if self.auto_tier1 {
            Some((self.default_tier1.normalized(), Scopes::TIER1_ONLY))
        } else {
            None
        }
    }

    pub fn load(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(txt) => Self::from_json(&txt).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save_atomic(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        let data = self.to_json();
        {
            let mut f = File::create(&tmp)?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
    }

    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(512 + self.packages.len() * 128);
        s.push_str("{\n");
        s.push_str(&format!("  \"auto_tier1\": {},\n", self.auto_tier1));
        s.push_str(&format!(
            "  \"default_tier1\": {{\"algo\": \"{}\", \"level\": {}, \"cluster_kb\": {}}},\n",
            self.default_tier1.algo.as_str(),
            self.default_tier1.level,
            self.default_tier1.cluster_kb
        ));
        s.push_str(&format!("  \"min_saving_pct\": {},\n", self.min_saving_pct));
        s.push_str(&format!("  \"min_file_bytes\": {},\n", self.min_file_bytes));
        s.push_str(&format!("  \"thermal_pause_mc\": {},\n", self.thermal_pause_mc));
        s.push_str(&format!("  \"pause_on_game\": {},\n", self.pause_on_game));
        s.push_str("  \"packages\": {");
        if !self.packages.is_empty() {
            s.push('\n');
            let len = self.packages.len();
            for (idx, (pkg, pp)) in self.packages.iter().enumerate() {
                let p = pp.profile.normalized();
                s.push_str(&format!(
                    "    \"{}\": {{\"preset\": \"{}\", \"algo\": \"{}\", \"level\": {}, \"cluster_kb\": {}, \"apk_lib\": {}, \"art_oat\": {}, \"external_data\": {}, \"obb\": {}, \"internal_files\": {}}}",
                    escape_json(pkg),
                    pp.preset.as_str(),
                    p.algo.as_str(),
                    p.level,
                    p.cluster_kb,
                    pp.scopes.apk_lib,
                    pp.scopes.art_oat,
                    pp.scopes.external_data,
                    pp.scopes.obb,
                    pp.scopes.internal_files,
                ));
                if idx + 1 < len {
                    s.push(',');
                }
                s.push('\n');
            }
            s.push_str("  ");
        }
        s.push_str("}\n}\n");
        s
    }

    pub fn from_json(input: &str) -> Result<Self, String> {
        let mut cur = JsonCur::new(input);
        let root = cur.parse_value()?;
        let obj = root.as_obj().ok_or("root must be object")?;
        let mut pol = Policy::default();

        if let Some(v) = obj.get("auto_tier1").and_then(JsonVal::as_bool) {
            pol.auto_tier1 = v;
        }
        if let Some(d) = obj.get("default_tier1").and_then(JsonVal::as_obj) {
            pol.default_tier1 = parse_profile_obj(d, CompProfile::FAST);
        }
        if let Some(v) = obj.get("min_saving_pct").and_then(JsonVal::as_i64) {
            pol.min_saving_pct = v.clamp(1, 90) as u8;
        }
        if let Some(v) = obj.get("min_file_bytes").and_then(JsonVal::as_i64) {
            pol.min_file_bytes = v.max(4096) as u64;
        }
        if let Some(v) = obj.get("thermal_pause_mc").and_then(JsonVal::as_i64) {
            pol.thermal_pause_mc = v.clamp(30000, 60000) as i32;
        }
        if let Some(v) = obj.get("pause_on_game").and_then(JsonVal::as_bool) {
            pol.pause_on_game = v;
        }
        if let Some(pkgs) = obj
            .get("packages")
            .or_else(|| obj.get("apps"))
            .and_then(JsonVal::as_obj)
        {
            for (pkg, val) in pkgs {
                if let Some(po) = val.as_obj() {
                    let preset = po
                        .get("preset")
                        .or_else(|| po.get("mode"))
                        .and_then(JsonVal::as_str)
                        .and_then(Preset::from_str)
                        .unwrap_or(Preset::Fast);
                    let profile = parse_profile_obj(po, CompProfile::FAST);
                    let scopes = Scopes {
                        apk_lib: po.get("apk_lib").and_then(JsonVal::as_bool).unwrap_or(true),
                        art_oat: po.get("art_oat").and_then(JsonVal::as_bool).unwrap_or(true),
                        external_data: po
                            .get("external_data")
                            .and_then(JsonVal::as_bool)
                            .unwrap_or(false),
                        obb: po.get("obb").and_then(JsonVal::as_bool).unwrap_or(false),
                        internal_files: po
                            .get("internal_files")
                            .and_then(JsonVal::as_bool)
                            .unwrap_or(false),
                    };
                    pol.packages.insert(
                        pkg.clone(),
                        PackagePolicy {
                            preset,
                            profile,
                            scopes,
                        },
                    );
                }
            }
        }
        Ok(pol)
    }
}

fn parse_profile_obj(o: &BTreeMap<String, JsonVal>, fallback: CompProfile) -> CompProfile {
    let algo = o
        .get("algo")
        .and_then(JsonVal::as_str)
        .and_then(CompAlgo::from_str)
        .unwrap_or(fallback.algo);
    let level = o
        .get("level")
        .and_then(JsonVal::as_i64)
        .map(|v| v.clamp(0, 12) as u8)
        .unwrap_or(fallback.level);
    let cluster_kb = o
        .get("cluster_kb")
        .and_then(JsonVal::as_i64)
        .map(|v| v.clamp(16, 128) as u16)
        .unwrap_or(fallback.cluster_kb);
    CompProfile {
        algo,
        level,
        cluster_kb,
    }
    .normalized()
}

pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ── Minimal std-only JSON parser ────────────────────────────────────────────

#[allow(dead_code)]
enum JsonVal {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<JsonVal>),
    Obj(BTreeMap<String, JsonVal>),
}

impl JsonVal {
    fn as_bool(&self) -> Option<bool> {
        match self {
            JsonVal::Bool(b) => Some(*b),
            _ => None,
        }
    }
    fn as_i64(&self) -> Option<i64> {
        match self {
            JsonVal::Num(n) => Some(*n),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            JsonVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    fn as_obj(&self) -> Option<&BTreeMap<String, JsonVal>> {
        match self {
            JsonVal::Obj(m) => Some(m),
            _ => None,
        }
    }
}

struct JsonCur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> JsonCur<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            b: s.as_bytes(),
            i: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\n' | b'\r' | b'\t') {
            self.i += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.b.get(self.i).copied()
    }

    fn parse_value(&mut self) -> Result<JsonVal, String> {
        match self.peek().ok_or("unexpected EOF")? {
            b'{' => self.parse_obj(),
            b'[' => self.parse_arr(),
            b'"' => self.parse_str().map(JsonVal::Str),
            b't' => self.expect_lit(b"true").map(|_| JsonVal::Bool(true)),
            b'f' => self.expect_lit(b"false").map(|_| JsonVal::Bool(false)),
            b'n' => self.expect_lit(b"null").map(|_| JsonVal::Null),
            b'-' | b'0'..=b'9' => self.parse_num(),
            c => Err(format!("unexpected char '{}'", c as char)),
        }
    }

    fn expect_lit(&mut self, lit: &[u8]) -> Result<(), String> {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            Ok(())
        } else {
            Err("invalid literal".into())
        }
    }

    fn parse_str(&mut self) -> Result<String, String> {
        self.skip_ws();
        if self.b.get(self.i) != Some(&b'"') {
            return Err("expected '\"'".into());
        }
        self.i += 1;
        let mut out = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            if c == b'"' {
                return Ok(out);
            }
            if c == b'\\' {
                let esc = *self.b.get(self.i).ok_or("unterminated escape")?;
                self.i += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    _ => out.push(esc as char),
                }
            } else {
                out.push(c as char);
            }
        }
        Err("unterminated string".into())
    }

    fn parse_num(&mut self) -> Result<JsonVal, String> {
        self.skip_ws();
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
            self.i += 1;
        }
        // Consume optional fractional/exponent part cleanly.
        if self.b.get(self.i) == Some(&b'.') {
            self.i += 1;
            while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
                self.i += 1;
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "utf8")?;
        let n = s
            .split('.')
            .next()
            .unwrap_or("0")
            .parse::<i64>()
            .map_err(|_| format!("bad num '{s}'"))?;
        Ok(JsonVal::Num(n))
    }

    fn parse_arr(&mut self) -> Result<JsonVal, String> {
        self.i += 1; // '['
        let mut v = Vec::new();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(JsonVal::Arr(v));
        }
        loop {
            v.push(self.parse_value()?);
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(JsonVal::Arr(v));
                }
                _ => return Err("expected ',' or ']'".into()),
            }
        }
    }

    fn parse_obj(&mut self) -> Result<JsonVal, String> {
        self.i += 1; // '{'
        let mut m = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(JsonVal::Obj(m));
        }
        loop {
            let k = self.parse_str()?;
            if self.peek() != Some(b':') {
                return Err("expected ':'".into());
            }
            self.i += 1;
            let v = self.parse_value()?;
            m.insert(k, v);
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(JsonVal::Obj(m));
                }
                _ => return Err("expected ',' or '}'".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        let mut p = Policy::default();
        p.min_saving_pct = 12;
        p.packages.insert(
            "com.HoYoverse.hkrpgoversea".into(),
            PackagePolicy {
                preset: Preset::Custom,
                profile: CompProfile {
                    algo: CompAlgo::Zstd,
                    level: 5,
                    cluster_kb: 64,
                },
                scopes: Scopes::FULL_APP,
            },
        );
        let j = p.to_json();
        let p2 = Policy::from_json(&j).expect("parse");
        assert_eq!(p, p2);
    }

    #[test]
    fn profile_v2_ioctl_mapping() {
        let prof = CompProfile {
            algo: CompAlgo::Zstd,
            level: 6,
            cluster_kb: 64,
        };
        let io = prof.to_v2_ioctl();
        assert_eq!(io.algorithm, COMPRESS_ZSTD);
        assert_eq!(io.log_cluster_size, 4);
        assert_eq!(io.level, 6);
        assert_eq!(CompProfile::from_v2_ioctl(io), Some(prof));

        let hc = CompProfile {
            algo: CompAlgo::Lz4Hc,
            level: 7,
            cluster_kb: 32,
        };
        let hio = hc.to_v2_ioctl();
        assert_eq!(hio.algorithm, COMPRESS_LZ4);
        assert_eq!(hio.log_cluster_size, 3);
        assert_eq!(hio.level, 7);
        assert_eq!(CompProfile::from_v2_ioctl(hio), Some(hc));
    }
}
