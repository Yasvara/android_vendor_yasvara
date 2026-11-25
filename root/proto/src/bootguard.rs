// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Bootguard and 4-layer Safe Mode state machines & wire codecs.
//!
//! Pure data and deterministic logic (zero I/O, zero `unsafe`) so every recovery branch,
//! bootloop counter transition, hardware shortcut sequence, and Zygisk crash circuit-breaker
//! is exhaustively unit-tested on the host.

use std::collections::HashMap;

/// Strike 1 = Smart Rollback of newly modified modules; Strike 2 = Full Safe Mode.
pub const BOOTGUARD_LIMIT: u32 = 2;
/// Parked value written after entering Full Safe Mode so repeated boots do not overflow.
pub const BOOTGUARD_PARKED: u32 = BOOTGUARD_LIMIT + 1;

pub const KEY_VOLUMEDOWN: u16 = 114;
pub const KEY_POWER: u16 = 116;

pub const VOLDOWN_PRESS_TARGET: u8 = 3;
pub const COMBO_HOLD_MS: u64 = 1500;
pub const VOLDOWN_HOLD_MS: u64 = 1500;
pub const VOLDOWN_DEBOUNCE_MS: u64 = 80;
pub const VOLDOWN_WINDOW_MS: u64 = 6000;

pub const ZYGISK_SS_CRASH_WINDOW_SECS: u64 = 90;
pub const ZYGISK_SS_CRASH_LIMIT: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SafeModeReason {
    None,
    KeyShortcut,
    AndroidSafemode,
    ManualFlag,
    BootloopSmartRollback,
    BootloopFull,
    ZygiskSystemServerCrash,
}

impl SafeModeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SafeModeReason::None => "none",
            SafeModeReason::KeyShortcut => "key_shortcut",
            SafeModeReason::AndroidSafemode => "android_safemode",
            SafeModeReason::ManualFlag => "manual_flag",
            SafeModeReason::BootloopSmartRollback => "bootloop_smart_rollback",
            SafeModeReason::BootloopFull => "bootloop_full",
            SafeModeReason::ZygiskSystemServerCrash => "zygisk_system_server_crash",
        }
    }

    pub fn from_str(s: &str) -> SafeModeReason {
        match s.trim() {
            "key_shortcut" => SafeModeReason::KeyShortcut,
            "android_safemode" => SafeModeReason::AndroidSafemode,
            "manual_flag" => SafeModeReason::ManualFlag,
            "bootloop_smart_rollback" => SafeModeReason::BootloopSmartRollback,
            "bootloop_full" => SafeModeReason::BootloopFull,
            "zygisk_system_server_crash" => SafeModeReason::ZygiskSystemServerCrash,
            _ => SafeModeReason::None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleStamp {
    pub id: String,
    pub mtime_secs: u64,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LastGoodSnapshot {
    pub modules: Vec<ModuleStamp>,
}

impl LastGoodSnapshot {
    pub fn encode(&self) -> String {
        let mut out = String::from("# yasvara-last-good v1\n");
        let mut sorted = self.modules.clone();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        for m in &sorted {
            out.push_str(&format!("{}\t{}\t{}\n", m.id, m.mtime_secs, if m.enabled { 1 } else { 0 }));
        }
        out
    }

    pub fn parse(text: &str) -> LastGoodSnapshot {
        let mut modules = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split('\t');
            let (Some(id), Some(mtime), Some(en)) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            if let Ok(mtime_secs) = mtime.parse::<u64>() {
                modules.push(ModuleStamp {
                    id: id.to_string(),
                    mtime_secs,
                    enabled: en == "1" || en == "true",
                });
            }
        }
        LastGoodSnapshot { modules }
    }

    /// Returns enabled module IDs that were newly installed, newly enabled, or modified
    /// since the last successful `boot_completed`.
    pub fn diff_suspects(&self, current: &[ModuleStamp]) -> Vec<String> {
        let mut prev_map: HashMap<&str, &ModuleStamp> = HashMap::new();
        for m in &self.modules {
            prev_map.insert(m.id.as_str(), m);
        }
        let mut suspects = Vec::new();
        for cur in current {
            if !cur.enabled {
                continue;
            }
            match prev_map.get(cur.id.as_str()) {
                None => suspects.push(cur.id.clone()),
                Some(prev) => {
                    if !prev.enabled || cur.mtime_secs > prev.mtime_secs {
                        suspects.push(cur.id.clone());
                    }
                }
            }
        }
        suspects.sort();
        suspects.dedup();
        suspects
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootcountDecision {
    Normal,
    SmartRollback { suspects: Vec<String> },
    FullSafeMode,
}

/// Evaluates the bootloop strike counter at `post-fs-data` and returns `(next_count, decision)`.
pub fn decide_bootcount(
    prev_count: u32,
    last_good: &LastGoodSnapshot,
    current: &[ModuleStamp],
) -> (u32, BootcountDecision) {
    if prev_count == 0 {
        return (1, BootcountDecision::Normal);
    }
    if prev_count == 1 {
        let suspects = last_good.diff_suspects(current);
        if !suspects.is_empty() {
            return (2, BootcountDecision::SmartRollback { suspects });
        }
        // No newly changed module could be isolated: fall straight to Full Safe Mode
        // so the device never gets trapped in a bootloop.
        return (BOOTGUARD_PARKED, BootcountDecision::FullSafeMode);
    }
    (BOOTGUARD_PARKED, BootcountDecision::FullSafeMode)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootguardStatus {
    pub bootcount: u32,
    pub safe_mode: bool,
    pub reason: SafeModeReason,
    pub key_trigger: String,
    pub disabled_suspects: Vec<String>,
    pub zygisk_bypassed: bool,
    pub timestamp_ms: u64,
}

impl Default for BootguardStatus {
    fn default() -> Self {
        BootguardStatus {
            bootcount: 0,
            safe_mode: false,
            reason: SafeModeReason::None,
            key_trigger: String::new(),
            disabled_suspects: Vec::new(),
            zygisk_bypassed: false,
            timestamp_ms: 0,
        }
    }
}

impl BootguardStatus {
    pub fn encode(&self) -> String {
        format!(
            "bootcount={}\nsafe_mode={}\nreason={}\nkey_trigger={}\ndisabled_suspects={}\nzygisk_bypassed={}\ntimestamp_ms={}\n",
            self.bootcount,
            if self.safe_mode { 1 } else { 0 },
            self.reason.as_str(),
            self.key_trigger,
            self.disabled_suspects.join(","),
            if self.zygisk_bypassed { 1 } else { 0 },
            self.timestamp_ms,
        )
    }

    pub fn parse(text: &str) -> BootguardStatus {
        let mut st = BootguardStatus::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let v = v.trim();
            match k.trim() {
                "bootcount" => st.bootcount = v.parse().unwrap_or(0),
                "safe_mode" => st.safe_mode = v == "1" || v == "true",
                "reason" => st.reason = SafeModeReason::from_str(v),
                "key_trigger" => st.key_trigger = v.to_string(),
                "disabled_suspects" => {
                    st.disabled_suspects = v
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                }
                "zygisk_bypassed" => st.zygisk_bypassed = v == "1" || v == "true",
                "timestamp_ms" => st.timestamp_ms = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        st
    }

    pub fn to_json(&self) -> String {
        let suspects_json: Vec<String> = self
            .disabled_suspects
            .iter()
            .map(|s| format!("\"{}\"", escape_json(s)))
            .collect();
        format!(
            "{{\"bootcount\":{},\"safeMode\":{},\"reason\":\"{}\",\"keyTrigger\":\"{}\",\"disabledSuspects\":[{}],\"zygiskBypassed\":{},\"timestampMs\":{}}}",
            self.bootcount,
            self.safe_mode,
            self.reason.as_str(),
            escape_json(&self.key_trigger),
            suspects_json.join(","),
            self.zygisk_bypassed,
            self.timestamp_ms,
        )
    }
}

pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
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

/// Deterministic hardware key sequence detector shared between keywatch and host tests.
///
/// Triggers Safe Mode when any of the following occurs during early boot:
/// 1. `KEY_VOLUMEDOWN` pressed 3 times within `VOLDOWN_WINDOW_MS` (KernelSU/BakaSU style).
/// 2. `KEY_POWER` + `KEY_VOLUMEDOWN` held simultaneously for >= `COMBO_HOLD_MS`.
/// 3. `KEY_VOLUMEDOWN` held continuously for >= `VOLDOWN_HOLD_MS`.
#[derive(Clone, Debug, Default)]
pub struct KeySequenceDetector {
    voldown_down_since: Option<u64>,
    power_down_since: Option<u64>,
    last_voldown_press: Option<u64>,
    voldown_presses: Vec<u64>,
    triggered: Option<&'static str>,
}

impl KeySequenceDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn triggered_reason(&self) -> Option<&'static str> {
        self.triggered
    }

    /// Feeds a Linux `EV_KEY` event (`value`: 0 = release, 1 = press, 2 = repeat).
    pub fn on_key(&mut self, ts_ms: u64, code: u16, value: i32) -> Option<&'static str> {
        if let Some(r) = self.triggered {
            return Some(r);
        }
        match code {
            KEY_VOLUMEDOWN => {
                if value == 1 {
                    if self.voldown_down_since.is_none() {
                        self.voldown_down_since = Some(ts_ms);
                    }
                    let debounced = self
                        .last_voldown_press
                        .map(|prev| ts_ms.saturating_sub(prev) >= VOLDOWN_DEBOUNCE_MS)
                        .unwrap_or(true);
                    if debounced {
                        self.last_voldown_press = Some(ts_ms);
                        self.voldown_presses.retain(|&t| ts_ms.saturating_sub(t) <= VOLDOWN_WINDOW_MS);
                        self.voldown_presses.push(ts_ms);
                        if self.voldown_presses.len() >= VOLDOWN_PRESS_TARGET as usize {
                            self.triggered = Some("voldown_3x");
                            return self.triggered;
                        }
                    }
                } else if value == 0 {
                    // Check hold duration right before release in case poll_tick wasn't called yet.
                    if let Some(r) = self.poll_tick(ts_ms) {
                        return Some(r);
                    }
                    self.voldown_down_since = None;
                }
            }
            KEY_POWER => {
                if value == 1 {
                    if self.power_down_since.is_none() {
                        self.power_down_since = Some(ts_ms);
                    }
                } else if value == 0 {
                    if let Some(r) = self.poll_tick(ts_ms) {
                        return Some(r);
                    }
                    self.power_down_since = None;
                }
            }
            _ => {}
        }
        self.poll_tick(ts_ms)
    }

    /// Periodic tick (e.g. every 200ms in epoll) to detect sustained holds without needing key repeat.
    pub fn poll_tick(&mut self, now_ms: u64) -> Option<&'static str> {
        if let Some(r) = self.triggered {
            return Some(r);
        }
        if let (Some(p_at), Some(v_at)) = (self.power_down_since, self.voldown_down_since) {
            let both_since = p_at.max(v_at);
            if now_ms.saturating_sub(both_since) >= COMBO_HOLD_MS {
                self.triggered = Some("power_voldown_hold");
                return self.triggered;
            }
        }
        if let Some(v_at) = self.voldown_down_since {
            if now_ms.saturating_sub(v_at) >= VOLDOWN_HOLD_MS {
                self.triggered = Some("voldown_hold");
                return self.triggered;
            }
        }
        None
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelBootkeyState {
    pub triggered: bool,
    pub reason: String,
    pub voldown_presses: u32,
}

/// Parses `/proc/yasvara_bootkey` single-line summary (`triggered=1 reason=voldown_3x voldown_presses=3`).
pub fn parse_kernel_bootkey(text: &str) -> KernelBootkeyState {
    let mut st = KernelBootkeyState::default();
    for tok in text.split_whitespace() {
        let Some((k, v)) = tok.split_once('=') else { continue };
        match k {
            "triggered" => st.triggered = v == "1" || v == "true",
            "reason" => st.reason = v.to_string(),
            "voldown_presses" => st.voldown_presses = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    st
}

/// Tracks `system_server` crashes when Native Zygisk is active; if `system_server` crashes
/// twice inside `ZYGISK_SS_CRASH_WINDOW_SECS`, returns true to auto-bypass Zygisk.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZygiskCrashTracker {
    pub timestamps: Vec<u64>,
}

impl ZygiskCrashTracker {
    pub fn parse(text: &str) -> Self {
        let timestamps = text
            .lines()
            .filter_map(|l| l.trim().parse::<u64>().ok())
            .collect();
        Self { timestamps }
    }

    pub fn encode(&self) -> String {
        self.timestamps.iter().map(|t| format!("{t}\n")).collect()
    }

    /// Records a `system_server` launch/restart at `now_secs` and returns true if the crash threshold tripped.
    pub fn record_and_check(&mut self, now_secs: u64) -> bool {
        self.timestamps.retain(|&t| now_secs.saturating_sub(t) <= ZYGISK_SS_CRASH_WINDOW_SECS);
        self.timestamps.push(now_secs);
        // First start is normal; 2nd + 3rd starts inside 90s means >=2 crashes.
        self.timestamps.len() > ZYGISK_SS_CRASH_LIMIT as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootcount_strike_progression_with_suspect() {
        let good = LastGoodSnapshot {
            modules: vec![ModuleStamp { id: "stable_mod".into(), mtime_secs: 100, enabled: true }],
        };
        let cur = vec![
            ModuleStamp { id: "stable_mod".into(), mtime_secs: 100, enabled: true },
            ModuleStamp { id: "bad_new_mod".into(), mtime_secs: 200, enabled: true },
        ];
        // Normal boot increments 0 -> 1.
        assert_eq!(decide_bootcount(0, &good, &cur), (1, BootcountDecision::Normal));
        // Crash on first try -> Strike 1 isolates newly added module.
        assert_eq!(
            decide_bootcount(1, &good, &cur),
            (2, BootcountDecision::SmartRollback { suspects: vec!["bad_new_mod".into()] })
        );
        // Still crashing -> Strike 2 enters Full Safe Mode and parks at 3.
        assert_eq!(decide_bootcount(2, &good, &cur), (BOOTGUARD_PARKED, BootcountDecision::FullSafeMode));
        assert_eq!(decide_bootcount(3, &good, &cur), (BOOTGUARD_PARKED, BootcountDecision::FullSafeMode));
    }

    #[test]
    fn bootcount_falls_back_to_full_safemode_if_no_suspect_diff() {
        let good = LastGoodSnapshot {
            modules: vec![ModuleStamp { id: "old_mod".into(), mtime_secs: 100, enabled: true }],
        };
        let cur = good.modules.clone();
        assert_eq!(decide_bootcount(1, &good, &cur), (BOOTGUARD_PARKED, BootcountDecision::FullSafeMode));
    }

    #[test]
    fn last_good_snapshot_roundtrip_and_diff() {
        let snap = LastGoodSnapshot {
            modules: vec![
                ModuleStamp { id: "a".into(), mtime_secs: 10, enabled: true },
                ModuleStamp { id: "b".into(), mtime_secs: 20, enabled: false },
            ],
        };
        let parsed = LastGoodSnapshot::parse(&snap.encode());
        assert_eq!(parsed, snap);

        let cur = vec![
            ModuleStamp { id: "a".into(), mtime_secs: 10, enabled: true },
            ModuleStamp { id: "b".into(), mtime_secs: 20, enabled: true }, // newly enabled
            ModuleStamp { id: "c".into(), mtime_secs: 30, enabled: true }, // newly installed
            ModuleStamp { id: "d".into(), mtime_secs: 40, enabled: false }, // disabled -> ignored
        ];
        assert_eq!(parsed.diff_suspects(&cur), vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn key_detector_voldown_3x_with_debounce() {
        let mut d = KeySequenceDetector::new();
        assert_eq!(d.on_key(100, KEY_VOLUMEDOWN, 1), None);
        assert_eq!(d.on_key(120, KEY_VOLUMEDOWN, 1), None); // bounce < 80ms ignored
        assert_eq!(d.on_key(150, KEY_VOLUMEDOWN, 0), None);
        assert_eq!(d.on_key(300, KEY_VOLUMEDOWN, 1), None);
        assert_eq!(d.on_key(350, KEY_VOLUMEDOWN, 0), None);
        assert_eq!(d.on_key(600, KEY_VOLUMEDOWN, 1), Some("voldown_3x"));
    }

    #[test]
    fn key_detector_power_voldown_hold() {
        let mut d = KeySequenceDetector::new();
        assert_eq!(d.on_key(1000, KEY_POWER, 1), None);
        assert_eq!(d.on_key(1100, KEY_VOLUMEDOWN, 1), None);
        assert_eq!(d.poll_tick(2500), None); // 1400ms < 1500ms
        assert_eq!(d.poll_tick(2600), Some("power_voldown_hold"));
    }

    #[test]
    fn key_detector_voldown_single_hold() {
        let mut d = KeySequenceDetector::new();
        assert_eq!(d.on_key(500, KEY_VOLUMEDOWN, 1), None);
        assert_eq!(d.poll_tick(1999), None);
        assert_eq!(d.poll_tick(2000), Some("voldown_hold"));
    }

    #[test]
    fn status_and_kernel_bootkey_codecs() {
        let st = BootguardStatus {
            bootcount: 2,
            safe_mode: true,
            reason: SafeModeReason::KeyShortcut,
            key_trigger: "voldown_3x".into(),
            disabled_suspects: vec!["mod_a".into(), "mod_b".into()],
            zygisk_bypassed: false,
            timestamp_ms: 1732400000000,
        };
        assert_eq!(BootguardStatus::parse(&st.encode()), st);
        assert!(st.to_json().contains("\"safeMode\":true"));
        assert!(st.to_json().contains("\"mod_a\",\"mod_b\""));

        let kb = parse_kernel_bootkey("triggered=1 reason=power_voldown_hold voldown_presses=1\n");
        assert!(kb.triggered);
        assert_eq!(kb.reason, "power_voldown_hold");
        assert_eq!(kb.voldown_presses, 1);
    }

    #[test]
    fn zygisk_crash_tracker_window() {
        let mut t = ZygiskCrashTracker::default();
        assert!(!t.record_and_check(100)); // normal boot start
        assert!(!t.record_and_check(120)); // crash 1
        assert!(t.record_and_check(150));  // crash 2 within 90s -> trip!
        let mut t2 = ZygiskCrashTracker::default();
        assert!(!t2.record_and_check(100));
        assert!(!t2.record_and_check(250)); // outside 90s window
        assert!(!t2.record_and_check(400));
    }
}
