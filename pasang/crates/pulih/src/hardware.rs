// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Hardware control suite for `Pulih` (`SPEC-0051` §5.5–5.6):
//! - USB OTG Dual-Role Port (DRP / Peripheral / Host)
//! - Zero-polling block filesystem superblock magic detector (`vfat`/`exfat`/`ext4`/`f2fs`/`ntfs`)
//! - Live Fast Charging / Xiaomi MCA telemetry + Rust Thermal Safety Governor + Bypass Charge
//! - Dynamic-range OLED Backlight (`max_brightness` auto-scaled — `16383` on `onyx`!) & idle sleep

use pasang_core::safety::{evaluate_thermal_governor, ThermalAction};
use std::fs;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbMode {
    AutoDrp,
    PeripheralAdb,
    OtgHost,
}

impl UsbMode {
    pub fn sysfs_value(self) -> &'static str {
        match self {
            UsbMode::AutoDrp => "none",
            UsbMode::PeripheralAdb => "peripheral",
            UsbMode::OtgHost => "host",
        }
    }
}

/// Apply USB controller mode on `onyx` (`a600000.ssusb`).
pub fn set_usb_mode(mode: UsbMode) -> std::io::Result<()> {
    fs::write(
        "/sys/bus/platform/devices/a600000.ssusb/mode",
        mode.sysfs_value(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsType {
    Fat32,
    ExFat,
    Ext4,
    F2fs,
    Ntfs,
    Erofs,
    Unknown,
}

impl FsType {
    pub fn mount_fstype(self) -> Option<&'static str> {
        match self {
            FsType::Fat32 => Some("vfat"),
            FsType::ExFat => Some("exfat"),
            FsType::Ext4 => Some("ext4"),
            FsType::F2fs => Some("f2fs"),
            FsType::Ntfs => Some("ntfs"),
            FsType::Erofs => Some("erofs"),
            FsType::Unknown => None,
        }
    }
}

/// Identify filesystem type purely from the first 4096 bytes of a block device.
pub fn probe_fs_magic(head_4k: &[u8]) -> FsType {
    if head_4k.len() >= 11 && &head_4k[3..11] == b"EXFAT   " {
        return FsType::ExFat;
    }
    if head_4k.len() >= 11 && &head_4k[3..11] == b"NTFS    " {
        return FsType::Ntfs;
    }
    if head_4k.len() >= 1028
        && u32::from_le_bytes([head_4k[1024], head_4k[1025], head_4k[1026], head_4k[1027]])
            == 0xF2F5_2010
    {
        return FsType::F2fs;
    }
    if head_4k.len() >= 1028
        && u32::from_le_bytes([head_4k[1024], head_4k[1025], head_4k[1026], head_4k[1027]])
            == 0xE0F5_E1E2
    {
        return FsType::Erofs;
    }
    if head_4k.len() >= 1082 && u16::from_le_bytes([head_4k[1080], head_4k[1081]]) == 0xEF53 {
        return FsType::Ext4;
    }
    if head_4k.len() >= 90 && (&head_4k[82..90] == b"FAT32   " || &head_4k[54..62] == b"FAT16   ") {
        return FsType::Fat32;
    }
    FsType::Unknown
}

/// Live battery & charging telemetry read from `/sys/class/power_supply/battery` + Xiaomi MCA.
#[derive(Clone, Debug, Default)]
pub struct PowerTelemetry {
    pub capacity_pct: u8,
    pub voltage_uv: i64,
    pub current_ua: i64,
    pub temp_tenths_c: i32,
    pub status: String,
    pub usb_type: String,
    pub soh_pct: u8,
    pub cycle_count: u32,
    pub bypass_charge: bool,
    pub charging_suspended: bool,
}

impl PowerTelemetry {
    pub fn watts(&self) -> f32 {
        let v = self.voltage_uv as f64 / 1_000_000.0;
        let a = (self.current_ua.abs() as f64) / 1_000_000.0;
        (v * a) as f32
    }

    pub fn is_charging(&self) -> bool {
        matches!(self.status.as_str(), "Charging" | "Full")
    }

    pub fn read_live() -> Self {
        let read_i64 = |p: &str| -> i64 {
            fs::read_to_string(p)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)
        };
        let status = fs::read_to_string("/sys/class/power_supply/battery/status")
            .unwrap_or_else(|_| "Unknown".to_string())
            .trim()
            .to_string();
        let usb_type = fs::read_to_string("/sys/class/power_supply/usb/real_type")
            .or_else(|_| fs::read_to_string("/sys/class/power_supply/usb/type"))
            .unwrap_or_else(|_| "Unknown".to_string())
            .trim()
            .to_string();
        let bypass = read_i64("/sys/class/xm_power/charger/smart_charge/bypass_charge") != 0;
        let soh = read_i64("/sys/class/xm_power/fg_master/soh").clamp(0, 100) as u8;
        let cycles = read_i64("/sys/class/power_supply/battery/cycle_count")
            .max(read_i64("/sys/class/xm_power/fg_master/cyclecount"))
            .max(0) as u32;
        Self {
            capacity_pct: read_i64("/sys/class/power_supply/battery/capacity").clamp(0, 100) as u8,
            voltage_uv: read_i64("/sys/class/power_supply/battery/voltage_now"),
            current_ua: read_i64("/sys/class/power_supply/battery/current_now"),
            temp_tenths_c: read_i64("/sys/class/power_supply/battery/temp") as i32,
            status,
            usb_type,
            soh_pct: soh,
            cycle_count: cycles,
            bypass_charge: bypass,
            charging_suspended: false,
        }
    }

    /// Evaluate and apply the Rust Thermal Safety Governor (`SPEC-0051` §5.6) using
    /// verified live `onyx` Xiaomi MCA sysfs nodes (with generic battery fallback).
    pub fn step_thermal_governor(&mut self) -> ThermalAction {
        let action = evaluate_thermal_governor(self.temp_tenths_c, self.charging_suspended);
        self.charging_suspended = matches!(action, ThermalAction::SuspendCharging);
        let suspend_val = if self.charging_suspended { "1" } else { "0" };
        // Live onyx Xiaomi MCA path first, generic power_supply fallback second.
        if fs::write(
            "/sys/class/xm_power/charger/charge_interface/input_suspend",
            suspend_val,
        )
        .is_err()
        {
            let _ = fs::write("/sys/class/power_supply/battery/input_suspend", suspend_val);
        }
        // Apply thermal charge current cap on StepDown / Cap18W
        match action {
            ThermalAction::Cap18W => {
                let _ = fs::write(
                    "/sys/class/xm_power/charger/charge_interface/power_limit",
                    "18000",
                );
            }
            ThermalAction::StepDown => {
                let _ = fs::write(
                    "/sys/class/xm_power/charger/charge_interface/power_limit",
                    "33000",
                );
            }
            _ => {}
        }
        action
    }
}

/// Toggle Xiaomi hardware Bypass Charge (`SPEC-0051` §5.6).
pub fn set_bypass_charge(enable: bool) -> std::io::Result<()> {
    fs::write(
        "/sys/class/xm_power/charger/smart_charge/bypass_charge",
        if enable { "1" } else { "0" },
    )
}

/// Convert percentage `pct` (`0..=100`) safely into panel raw brightness given `max_brightness`
/// (e.g. `max_brightness = 16383` on `onyx` `panel0-backlight`, never hardcoded `255`!).
pub fn scale_backlight_raw(pct: u8, max_brightness: u32) -> u32 {
    if pct == 0 || max_brightness == 0 {
        return 0;
    }
    let clamped = pct.min(100) as u64;
    ((clamped * max_brightness as u64) / 100).max(1) as u32
}

/// Write backlight percentage safely to `<backlight_dir>/brightness` scaled to `max_brightness`.
pub fn set_backlight_pct(backlight_dir: &Path, pct: u8) -> std::io::Result<u32> {
    let max_b: u32 = fs::read_to_string(backlight_dir.join("max_brightness"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(255);
    let raw = scale_backlight_raw(pct, max_b);
    fs::write(backlight_dir.join("brightness"), raw.to_string())?;
    Ok(raw)
}

/// OLED burn-in & idle dim/sleep state machine (`60s` dim, `180s` screen off).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayPowerState {
    Awake,
    Dimmed,
    Blanked,
}

pub fn evaluate_oled_idle(idle_secs: u64, keep_screen_dim: bool) -> DisplayPowerState {
    if idle_secs >= 180 && !keep_screen_dim {
        DisplayPowerState::Blanked
    } else if idle_secs >= 60 {
        DisplayPowerState::Dimmed
    } else {
        DisplayPowerState::Awake
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_all_supported_filesystems_accurately() {
        let mut buf = vec![0u8; 4096];
        buf[3..11].copy_from_slice(b"EXFAT   ");
        assert_eq!(probe_fs_magic(&buf), FsType::ExFat);

        buf.fill(0);
        buf[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(probe_fs_magic(&buf), FsType::Ntfs);

        buf.fill(0);
        buf[1024..1028].copy_from_slice(&0xF2F5_2010u32.to_le_bytes());
        assert_eq!(probe_fs_magic(&buf), FsType::F2fs);

        buf.fill(0);
        buf[1024..1028].copy_from_slice(&0xE0F5_E1E2u32.to_le_bytes());
        assert_eq!(probe_fs_magic(&buf), FsType::Erofs);

        buf.fill(0);
        buf[1080..1082].copy_from_slice(&0xEF53u16.to_le_bytes());
        assert_eq!(probe_fs_magic(&buf), FsType::Ext4);

        buf.fill(0);
        buf[82..90].copy_from_slice(b"FAT32   ");
        assert_eq!(probe_fs_magic(&buf), FsType::Fat32);
    }

    #[test]
    fn backlight_scales_dynamically_for_onyx_16383_and_oled_idle() {
        // On onyx panel0-backlight max_brightness=16383
        assert_eq!(scale_backlight_raw(0, 16383), 0);
        assert_eq!(scale_backlight_raw(100, 16383), 16383);
        assert_eq!(scale_backlight_raw(50, 16383), 8191);
        assert_eq!(scale_backlight_raw(18, 16383), 2948);
        assert_eq!(scale_backlight_raw(1, 255), 2);

        assert_eq!(evaluate_oled_idle(10, false), DisplayPowerState::Awake);
        assert_eq!(evaluate_oled_idle(60, false), DisplayPowerState::Dimmed);
        assert_eq!(evaluate_oled_idle(180, false), DisplayPowerState::Blanked);
        assert_eq!(evaluate_oled_idle(300, true), DisplayPowerState::Dimmed);

        let pt = PowerTelemetry {
            voltage_uv: 9_000_000,
            current_ua: -7_500_000,
            status: "Charging".into(),
            ..Default::default()
        };
        assert!(pt.is_charging());
        assert!((pt.watts() - 67.5).abs() < 0.01);
    }
}
