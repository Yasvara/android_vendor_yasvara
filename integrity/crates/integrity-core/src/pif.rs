// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-dependency PIF JSON/prop normalizer, fingerprint field expander, Canary release healer,
//! and UTF-8 91-byte staging validator (fixes Audit F2).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::contract::{MAX_PROP_VALUE_BYTES, NATIVE_PIF_STAGING_KEYS};
use crate::version::{
    healed_codename_release, infer_version_from_build_id, parse_decimal, parse_version_number,
    resolve_board_api_level, resolve_pif_os_version,
};

const PIF_KEYS: &[&str] = &[
    "BRAND",
    "DEVICE",
    "FINGERPRINT",
    "ID",
    "MANUFACTURER",
    "MODEL",
    "PRODUCT",
    "SECURITY_PATCH",
    "DEVICE_INITIAL_SDK_INT",
    "FIRST_API_LEVEL",
    "TYPE",
    "TAGS",
    "RELEASE",
    "INCREMENTAL",
    "BOARD_API_LEVEL",
    "API_LEVEL",
];

/// Fully normalized PIF profile + ready-to-stage native properties (`<= 91` UTF-8 bytes each).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedPif {
    pub fields: BTreeMap<String, String>,
    pub os_version: u32,
    pub board_api_level: String,
    pub staging: Vec<(&'static str, String)>,
}

/// Parses a PIF JSON (`{...}` or `{"pif": {...}}`) or `key=value` `.prop` text, derives missing
/// fields from `FINGERPRINT`, heals codename/Canary `RELEASE` against `platform_release`, and
/// produces UTF-8 byte-bounded native staging key-value pairs.
pub fn normalize_pif(raw: &str, platform_release: &str) -> Option<NormalizedPif> {
    let trimmed = raw.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = if trimmed.starts_with('{') {
        parse_pif_json_object(trimmed)?
    } else {
        parse_prop_lines(trimmed)
    };

    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    for &k in PIF_KEYS {
        if let Some(v) = parsed.get(k) {
            let tv = v.trim();
            if !tv.is_empty() {
                fields.insert(k.to_string(), tv.to_string());
            }
        }
    }
    if fields.is_empty() {
        return None;
    }

    derive_fields_from_fingerprint(&mut fields, platform_release);

    if !fields.contains_key("DEVICE_INITIAL_SDK_INT") {
        let mut first_api = fields.get("FIRST_API_LEVEL").cloned().unwrap_or_default();
        if first_api.is_empty() {
            if let Some(api) = fields.get("API_LEVEL") {
                if let Some(n) = parse_decimal(api.trim()) {
                    if n <= 100 {
                        first_api = api.trim().to_string();
                    }
                }
            }
        }
        if !first_api.is_empty() {
            fields.insert("DEVICE_INITIAL_SDK_INT".to_string(), first_api);
        }
    }

    let os_version = resolve_pif_os_version(
        fields.get("FINGERPRINT").map(String::as_str),
        fields.get("RELEASE").map(String::as_str),
        fields.get("ID").map(String::as_str),
        Some(platform_release),
    );
    let board_api_level = resolve_board_api_level(
        fields.get("BOARD_API_LEVEL").map(String::as_str),
        fields.get("API_LEVEL").map(String::as_str),
    )
    .unwrap_or("")
    .to_string();

    let staging = build_staging_pairs(&fields, os_version, &board_api_level);
    Some(NormalizedPif { fields, os_version, board_api_level, staging })
}

fn derive_fields_from_fingerprint(fields: &mut BTreeMap<String, String>, platform_release: &str) {
    let Some(fp) = fields.get("FINGERPRINT").cloned() else {
        return;
    };
    let Some((head_str, after_colon)) = fp.split_once(':') else {
        return;
    };
    let head: Vec<&str> = head_str.split('/').collect();
    let rest: Vec<&str> = after_colon.split('/').collect();
    if rest.len() < 4 {
        return;
    }
    let Some((inc, build_type)) = rest[2].split_once(':') else {
        return;
    };
    if head.len() == 3 {
        insert_if_absent(fields, "BRAND", head[0]);
        insert_if_absent(fields, "PRODUCT", head[1]);
        insert_if_absent(fields, "DEVICE", head[2]);
    }
    insert_if_absent(fields, "RELEASE", rest[0]);
    insert_if_absent(fields, "ID", rest[1]);
    insert_if_absent(fields, "INCREMENTAL", inc);
    insert_if_absent(fields, "TYPE", build_type);
    insert_if_absent(fields, "TAGS", rest[3]);

    if let Some(healed_major) = healed_codename_release(
        Some(&fp),
        fields.get("RELEASE").map(String::as_str),
        fields.get("ID").map(String::as_str),
        Some(platform_release),
    ) {
        fields.insert("RELEASE".to_string(), format!("{}", healed_major));
        return;
    }

    let rel_numeric = fields
        .get("RELEASE")
        .and_then(|r| parse_version_number(r))
        .is_some();
    if !rel_numeric {
        if let Some(inferred) = fields.get("ID").and_then(|id| infer_version_from_build_id(id)) {
            if inferred > 0 {
                fields.insert("RELEASE".to_string(), format!("{}", inferred / 10_000));
            }
        }
    }
}

fn insert_if_absent(fields: &mut BTreeMap<String, String>, key: &str, value: &str) {
    let v = value.trim();
    if !v.is_empty() && !fields.contains_key(key) {
        fields.insert(key.to_string(), v.to_string());
    }
}

/// Strictly validates UTF-8 byte length <= 91 (`MAX_PROP_VALUE_BYTES`) so `SystemProperties.set`
/// can never throw on multi-byte or long fingerprints/descriptions (Bionic assembles >91B
/// fingerprints dynamically from components).
fn fit_prop(value: &str) -> String {
    if value.len() <= MAX_PROP_VALUE_BYTES {
        value.to_string()
    } else {
        String::new()
    }
}

fn build_staging_pairs(
    fields: &BTreeMap<String, String>,
    os_version: u32,
    board_api_level: &str,
) -> Vec<(&'static str, String)> {
    let get = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
    let product = get("PRODUCT");
    let release = get("RELEASE");
    let id = get("ID");
    let incremental = get("INCREMENTAL");
    let build_type = get("TYPE");
    let build_tags = get("TAGS");

    let (flavor, description) = if !product.is_empty() && !build_type.is_empty() {
        let fl = format!("{}-{}", product, build_type);
        let desc = format!("{} {} {} {} {}", fl, release, id, incremental, build_tags);
        (fit_prop(&fl), fit_prop(&desc))
    } else {
        (String::new(), String::new())
    };

    let os_ver_str = format!("{}", os_version);
    let pairs: [(&'static str, String); 17] = [
        ("manufacturer", fit_prop(get("MANUFACTURER"))),
        ("brand", fit_prop(get("BRAND"))),
        ("model", fit_prop(get("MODEL"))),
        ("device", fit_prop(get("DEVICE"))),
        ("name", fit_prop(product)),
        ("fingerprint", fit_prop(get("FINGERPRINT"))),
        ("release", fit_prop(release)),
        ("build_id", fit_prop(id)),
        ("security_patch", fit_prop(get("SECURITY_PATCH"))),
        ("first_api_level", fit_prop(get("DEVICE_INITIAL_SDK_INT"))),
        ("build_type", fit_prop(build_type)),
        ("build_tags", fit_prop(build_tags)),
        ("api_level", fit_prop(board_api_level)),
        ("os_version", fit_prop(&os_ver_str)),
        ("incremental", fit_prop(incremental)),
        ("flavor", flavor),
        ("description", description),
    ];
    debug_assert_eq!(pairs.len(), NATIVE_PIF_STAGING_KEYS.len());
    pairs.into_iter().collect()
}

fn parse_prop_lines(raw: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in raw.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if !k.is_empty() && !v.is_empty() {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

/// Minimal, zero-dependency RFC-8259 JSON object parser supporting flat PIF JSON or
/// `{"pif": { ... }}` wrapper (string and integer/boolean leaf values).
pub(crate) fn parse_pif_json_object(raw: &str) -> Option<BTreeMap<String, String>> {
    let mut p = JsonParser::new(raw.as_bytes());
    p.skip_ws();
    let (top_strings, nested_pif) = p.parse_object_with_optional_sub("pif")?;
    Some(nested_pif.unwrap_or(top_strings))
}

/// Parses a flat JSON string-to-string object (`{"pkg": "YYYY-MM-DD", "*": "YYYY-MM-DD"}`).
pub(crate) fn parse_flat_json_string_map(raw: &str) -> Option<BTreeMap<String, String>> {
    let stripped = raw.trim_start_matches('\u{feff}');
    let mut p = JsonParser::new(stripped.as_bytes());
    p.skip_ws();
    let (map, _) = p.parse_object_with_optional_sub("")?;
    Some(map)
}

struct JsonParser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while let Some(&c) = self.b.get(self.pos) {
            if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn expect(&mut self, ch: u8) -> Option<()> {
        if self.peek() == Some(ch) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    fn parse_object_with_optional_sub(
        &mut self,
        sub_key: &str,
    ) -> Option<(BTreeMap<String, String>, Option<BTreeMap<String, String>>)> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        let mut sub: Option<BTreeMap<String, String>> = None;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Some((map, sub));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            match self.peek()? {
                b'"' => {
                    let val = self.parse_string()?;
                    map.insert(key, val);
                }
                b'{' => {
                    if !sub_key.is_empty() && key == sub_key {
                        let (inner, _) = self.parse_object_with_optional_sub("")?;
                        sub = Some(inner);
                    } else {
                        self.skip_value(0)?;
                    }
                }
                b'[' => {
                    self.skip_value(0)?;
                }
                _ => {
                    let prim = self.parse_primitive()?;
                    if prim != "null" {
                        map.insert(key, prim);
                    }
                }
            }
            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }
        Some((map, sub))
    }

    fn parse_string(&mut self) -> Option<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        while let Some(&c) = self.b.get(self.pos) {
            self.pos += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let esc = *self.b.get(self.pos)?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = core::str::from_utf8(self.b.get(self.pos..self.pos + 4)?)
                                .ok()?;
                            let code = u32::from_str_radix(hex, 16).ok()?;
                            self.pos += 4;
                            if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            }
                        }
                        _ => return None,
                    }
                }
                0x00..=0x1f => return None,
                _ => {
                    // Preserve UTF-8 sequences cleanly.
                    let start = self.pos - 1;
                    while let Some(&next) = self.b.get(self.pos) {
                        if next == b'"' || next == b'\\' || next < 0x20 {
                            break;
                        }
                        self.pos += 1;
                    }
                    let slice = core::str::from_utf8(&self.b[start..self.pos]).ok()?;
                    out.push_str(slice);
                }
            }
        }
        None
    }

    fn parse_primitive(&mut self) -> Option<String> {
        let start = self.pos;
        while let Some(&c) = self.b.get(self.pos) {
            if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                break;
            }
            self.pos += 1;
        }
        if self.pos == start {
            return None;
        }
        core::str::from_utf8(&self.b[start..self.pos]).ok().map(String::from)
    }

    fn skip_value(&mut self, depth: usize) -> Option<()> {
        if depth > 16 {
            return None;
        }
        self.skip_ws();
        match self.peek()? {
            b'"' => {
                self.parse_string()?;
                Some(())
            }
            b'{' => {
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Some(());
                }
                loop {
                    self.skip_ws();
                    self.parse_string()?;
                    self.skip_ws();
                    self.expect(b':')?;
                    self.skip_value(depth + 1)?;
                    self.skip_ws();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Some(());
                }
                loop {
                    self.skip_value(depth + 1)?;
                    self.skip_ws();
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            _ => {
                self.parse_primitive()?;
                Some(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_canary_json_and_bounds_utf8() {
        let json = r#"{
            "MANUFACTURER": "Google",
            "MODEL": "Pixel 9 Pro",
            "FINGERPRINT": "google/caiman_beta/caiman:CANARY/ZP11.251201.001/12345678:user/release-keys",
            "RELEASE": "16",
            "SECURITY_PATCH": "2026-09-05",
            "FIRST_API_LEVEL": 34
        }"#;
        let norm = normalize_pif(json, "17").unwrap();
        assert_eq!(norm.fields.get("BRAND").map(String::as_str), Some("google"));
        assert_eq!(norm.fields.get("PRODUCT").map(String::as_str), Some("caiman_beta"));
        assert_eq!(norm.fields.get("DEVICE").map(String::as_str), Some("caiman"));
        assert_eq!(norm.fields.get("RELEASE").map(String::as_str), Some("17"));
        assert_eq!(norm.fields.get("DEVICE_INITIAL_SDK_INT").map(String::as_str), Some("34"));
        assert_eq!(norm.os_version, 170_000);
        for &(_, ref v) in &norm.staging {
            assert!(v.len() <= MAX_PROP_VALUE_BYTES);
        }
    }

    #[test]
    fn handles_wrapped_pif_and_oversized_fingerprint() {
        let long_inc = "9".repeat(80);
        let json = format!(
            r#"{{"pif":{{"FINGERPRINT":"google/komodo_beta/komodo:17/CP2A.260605.006/{}:user/release-keys"}}}}"#,
            long_inc
        );
        let norm = normalize_pif(&json, "17").unwrap();
        let fp_staged = norm.staging.iter().find(|(k, _)| *k == "fingerprint").unwrap();
        // >91 UTF-8 bytes -> empty so SystemProperties.set never throws; Bionic assembles dynamically.
        assert!(fp_staged.1.is_empty());
        assert_eq!(norm.os_version, 170_000);
    }

    #[test]
    fn strips_utf8_bom_in_json_prop_and_flat_map() {
        let bom_json = "\u{feff}{\"BRAND\":\"google\",\"MODEL\":\"Pixel 6a\"}";
        let norm = normalize_pif(bom_json, "17").unwrap();
        assert_eq!(norm.fields.get("MODEL").map(String::as_str), Some("Pixel 6a"));

        let bom_prop = "\u{feff}BRAND=google\nMODEL=Pixel 6a\n";
        let norm_prop = normalize_pif(bom_prop, "17").unwrap();
        assert_eq!(norm_prop.fields.get("BRAND").map(String::as_str), Some("google"));

        let bom_map = parse_flat_json_string_map("\u{feff}{\"*\":\"2026-10-05\"}").unwrap();
        assert_eq!(bom_map.get("*").map(String::as_str), Some("2026-10-05"));
    }
}
