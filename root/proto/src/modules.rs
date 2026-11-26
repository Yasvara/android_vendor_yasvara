// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Module metadata (`module.prop`), strict ID validation, and JSON serialization.

use crate::bootguard::escape_json;

pub const MAX_MODULE_ID_LEN: usize = 64;

/// Strictly validates a Magisk/KSU/Akar module ID: `^[a-zA-Z][a-zA-Z0-9._-]+$`.
/// Rejects path separators, `..`, whitespace, leading dots, or control characters.
pub fn validate_module_id(id: &str) -> bool {
    if id.is_empty() || id.len() > MAX_MODULE_ID_LEN || id.contains("..") {
        return false;
    }
    let bytes = id.as_bytes();
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Validates a relative icon/asset path inside a module directory (`actionIcon` / `webuiIcon`).
pub fn validate_rel_asset_path(rel: &str) -> bool {
    if rel.is_empty() || rel.len() > 256 || rel.starts_with('/') || rel.contains('\\') || rel.contains('\0') {
        return false;
    }
    rel.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModuleProp {
    pub id: String,
    pub name: String,
    pub version: String,
    pub version_code: String,
    pub author: String,
    pub description: String,
    pub update_json: String,
    pub metamodule: bool,
    pub action_icon: String,
    pub webui_icon: String,
    pub extra: Vec<(String, String)>,
}

impl ModuleProp {
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let mut p = ModuleProp::default();
        for raw in text.lines() {
            let line = raw.trim_end_matches('\r').trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            let key = k.trim();
            let val = v.trim();
            match key {
                "id" => p.id = val.to_string(),
                "name" => p.name = val.to_string(),
                "version" => p.version = val.to_string(),
                "versionCode" => p.version_code = val.to_string(),
                "author" => p.author = val.to_string(),
                "description" => p.description = val.to_string(),
                "updateJson" => p.update_json = val.to_string(),
                "metamodule" => p.metamodule = matches!(val, "1" | "true" | "TRUE" | "yes"),
                "actionIcon" => {
                    if validate_rel_asset_path(val) {
                        p.action_icon = val.to_string();
                    }
                }
                "webuiIcon" => {
                    if validate_rel_asset_path(val) {
                        p.webui_icon = val.to_string();
                    }
                }
                _ => p.extra.push((key.to_string(), val.to_string())),
            }
        }
        if !validate_module_id(&p.id) {
            return Err("invalid or missing module id");
        }
        if p.name.is_empty() {
            p.name = p.id.clone();
        }
        Ok(p)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModuleInfo {
    pub prop: ModuleProp,
    pub enabled: bool,
    pub remove: bool,
    pub update: bool,
    pub has_webroot: bool,
    pub has_action: bool,
    pub has_zygisk: bool,
    pub zygisk_abis: Vec<String>,
    pub config_description: Option<String>,
    pub managed_features: Vec<String>,
    pub mount_strategy: String,
    pub size_bytes: u64,
}

impl ModuleInfo {
    pub fn effective_description(&self) -> &str {
        self.config_description
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.prop.description)
    }

    pub fn to_json(&self) -> String {
        let abis: Vec<String> = self.zygisk_abis.iter().map(|a| format!("\"{}\"", escape_json(a))).collect();
        let feats: Vec<String> = self.managed_features.iter().map(|f| format!("\"{}\"", escape_json(f))).collect();
        format!(
            "{{\"id\":\"{}\",\"name\":\"{}\",\"version\":\"{}\",\"versionCode\":\"{}\",\"author\":\"{}\",\"description\":\"{}\",\"updateJson\":\"{}\",\"metamodule\":{},\"actionIcon\":\"{}\",\"webuiIcon\":\"{}\",\"enabled\":{},\"remove\":{},\"update\":{},\"hasWebroot\":{},\"hasAction\":{},\"hasZygisk\":{},\"zygiskAbis\":[{}],\"managedFeatures\":[{}],\"mountStrategy\":\"{}\",\"sizeBytes\":{}}}",
            escape_json(&self.prop.id),
            escape_json(&self.prop.name),
            escape_json(&self.prop.version),
            escape_json(&self.prop.version_code),
            escape_json(&self.prop.author),
            escape_json(self.effective_description()),
            escape_json(&self.prop.update_json),
            self.prop.metamodule,
            escape_json(&self.prop.action_icon),
            escape_json(&self.prop.webui_icon),
            self.enabled,
            self.remove,
            self.update,
            self.has_webroot,
            self.has_action,
            self.has_zygisk,
            abis.join(","),
            feats.join(","),
            escape_json(&self.mount_strategy),
            self.size_bytes,
        )
    }
}

pub fn modules_to_json(list: &[ModuleInfo]) -> String {
    let items: Vec<String> = list.iter().map(ModuleInfo::to_json).collect();
    format!("[{}]", items.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_validation_strict() {
        assert!(validate_module_id("playintegrityfix"));
        assert!(validate_module_id("tricky_store-1.2"));
        assert!(!validate_module_id(""));
        assert!(!validate_module_id("../etc"));
        assert!(!validate_module_id("foo/bar"));
        assert!(!validate_module_id(".hidden"));
        assert!(!validate_module_id("1starts_with_digit"));
        assert!(!validate_module_id("a..b"));
        assert!(!validate_module_id("bad space"));
    }

    #[test]
    fn prop_parse_and_json() {
        let raw = "# comment\nid=my_mod\r\nname=My Mod\r\nversion=v2.1\r\nversionCode=21\r\n\
                   author=Yasvara\r\ndescription=Hello \"World\"\r\nmetamodule=1\r\n\
                   actionIcon=assets/run.png\r\nwebuiIcon=../escape.png\r\n";
        let p = ModuleProp::parse(raw).unwrap();
        assert_eq!(p.id, "my_mod");
        assert!(p.metamodule);
        assert_eq!(p.action_icon, "assets/run.png");
        assert_eq!(p.webui_icon, ""); // traversal rejected
        let info = ModuleInfo {
            prop: p,
            enabled: true,
            has_webroot: true,
            has_action: true,
            has_zygisk: true,
            zygisk_abis: vec!["arm64-v8a".into()],
            managed_features: vec!["play_integrity".into()],
            mount_strategy: "overlay".into(),
            ..Default::default()
        };
        let j = info.to_json();
        assert!(j.contains("\"id\":\"my_mod\""));
        assert!(j.contains("Hello \\\"World\\\""));
        assert!(j.contains("\"play_integrity\""));
    }
}
