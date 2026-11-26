// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Universal Recovery CLI & OpenRecoveryScript (`ORS`) Engine for `Pulih`
//! (`pulih` / `twrp` / `fox` / `ors` multi-call compatibility).
//!
//! Designed so any human, script, or AI agent familiar with TWRP, OrangeFox,
//! or standard AOSP `adb sideload` / BCB flags can drive `Pulih` effortlessly:
//! - Standard BCB flags: `--fastboot`, `--sideload`, `--sideload_auto_reboot`,
//!   `--update_package=<path>`, `--wipe_data`
//! - TWRP/OrangeFox CLI commands: `install`, `flash`, `sideload`, `wipe`,
//!   `mount`, `unmount`, `backup`, `restore`, `slot`, `modules`, `kernel`,
//!   `power`, `passport`, `doctor`, `set`, `get`, `reboot`, `ors`
//! - Machine-readable `--json` output mode for automated tooling / AI agents
//! - Every destructive CLI/ORS command passes through `pasang_core::safety` first!

use pasang_core::safety::{validate_raw_flash, validate_wipe_or_format, SafetyError};
use crate::kernel::PowerProfile;
use std::path::PathBuf;

/// Normalized CLI / BCB / OpenRecoveryScript command parsed safely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    LaunchUi,
    Help,
    SelfCheck { json: bool },
    Doctor { json: bool },
    EnterFastbootd,
    Sideload { auto_reboot: bool },
    InstallZip {
        path: PathBuf,
        clean_overlay: bool,
        dry_run: bool,
    },
    FlashRaw {
        partition: String,
        image_path: PathBuf,
    },
    Wipe {
        target: String,
    },
    Mount {
        target: String,
        rw: bool,
    },
    Unmount {
        target: String,
    },
    SlotGet,
    SlotSwitch {
        target: Option<char>, // None = toggle active -> inactive
    },
    ModulesList { json: bool },
    ModulesDisable { id: String },
    ModulesEnable { id: String },
    ModulesDisableAll,
    KernelInfo { json: bool },
    KernelProfile { profile: PowerProfile },
    KernelCpu {
        policy: String,
        min_khz: u64,
        max_khz: u64,
        governor: Option<String>,
    },
    KernelIo {
        scheduler: String,
        read_ahead_kb: Option<u32>,
    },
    KernelTcp { algo: String },
    PowerStatus { json: bool },
    PowerBypass { enable: bool },
    PowerBacklight { pct: u8 },
    GpuStatus { json: bool },
    GpuEnable,
    GpuDisable,
    GpuLaunch { bin: PathBuf, args: Vec<String> },
    // AI / Android Automation commands (`screencap`, `input`, `pulih ui-dump`)
    Screencap { out_path: String },
    InputTap { x: i32, y: i32 },
    InputSwipe { x1: i32, y1: i32, x2: i32, y2: i32 },
    InputKey { key: String },
    UiDump,
    Vibrate { ms: u32 },
    Passport { reveal: bool, json: bool },
    Backup {
        out_path: PathBuf,
        targets: Vec<String>,
    },
    Restore {
        archive_path: PathBuf,
    },
    RunOrsScript {
        script_path: PathBuf,
    },
    Reboot {
        mode: RebootTarget,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebootTarget {
    System,
    Recovery,
    Bootloader,
    Fastbootd,
    PowerOff,
}

/// Concise, self-documenting help text (also discoverable via `twrp --help` / `fox --help` / `pulih --help`).
pub const CLI_HELP: &str = r#"Pulih Recovery CLI (TWRP / OrangeFox / AOSP sideload compatible)
Aliases: pulih | twrp | fox | ors

Usage: pulih [--json] <command> [args...]

Flashing & Sideload:
  install <zip> [--clean-overlay] [--dry-run]   Install OTA ZIP via Pasang CoW engine
  flash <partition> <image.img>                 Flash raw image (anti-brick magic & size guarded)
  sideload [--auto-reboot]                      Start standard AOSP `adb sideload` receiver
  ors [script_path]                             Execute OpenRecoveryScript (default /cache/recovery/openrecoveryscript)

Partitions, Slot & Backup:
  wipe <userdata|data|metadata|cache>           Safe allowlisted wipe (blocks xbl/abl/persist/modemst/super!)
  mount <path> [--rw]                           Mount partition
  unmount <path>                                Unmount partition
  slot [get|a|b|switch]                         Inspect or switch A/B boot slot
  backup <out.yvbak> [targets...]               Streaming tar.zst backup with SHA-256 manifest
  restore <archive.yvbak>                       Verified restore with path-traversal guard

Kernel, Clocks & Battery Powersave:
  kernel info                                   Show live CPU clusters, GPU, UFS I/O, TCP congestion
  kernel profile <ultrasave|powersave|balanced|turbo>
                                                Apply safe power profile (clocks + core park + 60/120Hz + backlight)
  kernel cpu <policyN> <min_khz> <max_khz> [gov]
                                                Set validated cluster clocks & governor
  kernel io <scheduler> [read_ahead_kb]         Set UFS I/O scheduler & read-ahead (128..4096 KiB)
  kernel tcp <bbr3|bbr|cubic|reno>              Set TCP congestion control
  power status                                  Show battery %, V/I/W, temp, SoH, cycles, bypass state
  power bypass <on|off>                         Toggle Xiaomi hardware Bypass Charge
  power backlight <0..100>                      Set OLED brightness percentage (auto-scaled to max_brightness)
  gpu status | enable | disable                 Lazy Adreno kgsl GPU driver (0B ramdisk bloat, Vulkan/GLES/DRM)
  gpu launch <binary> [args...]                 Launch native DRM/GPU app or DOOM port in recovery!

AI & Android UI Automation (`screencap`, `input`, `ui-dump`):
  screencap [-p] [out.png]                      Capture live 120Hz Pulih UI framebuffer to valid PNG
  input tap <x> <y>                             Inject touch tap into live Pulih UI
  input swipe <x1> <y1> <x2> <y2>               Inject touch drag / swipe-to-confirm / scroll
  input keyevent <BACK|POWER|VOL_UP|VOL_DOWN>   Inject navigation / hardware key event
  ui-dump                                       Dump live JSON UI hierarchy + clickable button rects!

Rescue & Diagnostics:
  modules list                                  List Magisk / Akar / KernelSU modules
  modules disable <id> | enable <id> | disable-all
                                                Toggle or Safe-Mode disable all root modules
  doctor                                        Full recovery health & anti-brick audit
  passport [--reveal]                           Device Passport (identifiers masked unless --reveal)
  reboot [system|recovery|bootloader|fastbootd|poweroff]
  --self-check                                  Headless display + subsystem self-check
"#;

/// Parse command-line arguments (`args[1..]`) supporting AOSP BCB flags,
/// TWRP/OrangeFox CLI syntax, and Pulih native subcommands.
pub fn parse_cli_args(args: &[String]) -> Result<RecoveryAction, String> {
    let mut json = false;
    let mut filtered: Vec<&str> = Vec::new();
    for a in args {
        if a == "--json" {
            json = true;
        } else {
            filtered.push(a.as_str());
        }
    }

    if filtered.is_empty() {
        return Ok(RecoveryAction::LaunchUi);
    }

    // Standard AOSP / BCB flags
    match filtered[0] {
        "-h" | "--help" | "help" => return Ok(RecoveryAction::Help),
        "--fastboot" => return Ok(RecoveryAction::EnterFastbootd),
        "--self-check" => return Ok(RecoveryAction::SelfCheck { json }),
        "--sideload" => return Ok(RecoveryAction::Sideload { auto_reboot: false }),
        "--sideload_auto_reboot" => return Ok(RecoveryAction::Sideload { auto_reboot: true }),
        "--wipe_data" => return Ok(RecoveryAction::Wipe { target: "userdata".into() }),
        "--kernel-info" => return Ok(RecoveryAction::KernelInfo { json }),
        "--ultra-powersave" => {
            return Ok(RecoveryAction::KernelProfile {
                profile: PowerProfile::UltraPowersave,
            })
        }
        "--powersave" => {
            return Ok(RecoveryAction::KernelProfile {
                profile: PowerProfile::Powersave,
            })
        }
        "--balanced" => {
            return Ok(RecoveryAction::KernelProfile {
                profile: PowerProfile::Balanced,
            })
        }
        "--turbo" => {
            return Ok(RecoveryAction::KernelProfile {
                profile: PowerProfile::TurboFlash,
            })
        }
        "--disable-modules" => return Ok(RecoveryAction::ModulesDisableAll),
        flag if flag.starts_with("--update_package=") => {
            let p = flag.trim_start_matches("--update_package=");
            if p.is_empty() {
                return Err("--update_package requires a path".into());
            }
            return Ok(RecoveryAction::InstallZip {
                path: PathBuf::from(p),
                clean_overlay: false,
                dry_run: false,
            });
        }
        _ => {}
    }

    // Subcommands (TWRP / OrangeFox / Pulih unified syntax)
    match filtered[0] {
        "install" => {
            let path = filtered.get(1).ok_or("usage: install <zip> [--clean-overlay] [--dry-run]")?;
            let clean_overlay = filtered.contains(&"--clean-overlay");
            let dry_run = filtered.contains(&"--dry-run");
            Ok(RecoveryAction::InstallZip {
                path: PathBuf::from(path),
                clean_overlay,
                dry_run,
            })
        }
        "flash" => {
            let part = filtered.get(1).ok_or("usage: flash <partition> <image.img>")?;
            let img = filtered.get(2).ok_or("usage: flash <partition> <image.img>")?;
            Ok(RecoveryAction::FlashRaw {
                partition: (*part).to_string(),
                image_path: PathBuf::from(img),
            })
        }
        "sideload" => {
            let auto_reboot = filtered.contains(&"--auto-reboot");
            Ok(RecoveryAction::Sideload { auto_reboot })
        }
        "wipe" => {
            let target = filtered.get(1).ok_or("usage: wipe <userdata|data|metadata|cache>")?;
            // Map TWRP shorthand (`dalvik` -> `cache`)
            let normalized = match target.to_ascii_lowercase().as_str() {
                "dalvik" | "dalvikcache" => "cache".to_string(),
                other => other.to_string(),
            };
            Ok(RecoveryAction::Wipe { target: normalized })
        }
        "mount" => {
            let target = filtered.get(1).ok_or("usage: mount <partition> [--rw]")?;
            let rw = filtered.contains(&"--rw");
            Ok(RecoveryAction::Mount {
                target: (*target).to_string(),
                rw,
            })
        }
        "unmount" | "umount" => {
            let target = filtered.get(1).ok_or("usage: unmount <partition>")?;
            Ok(RecoveryAction::Unmount {
                target: (*target).to_string(),
            })
        }
        "slot" => match filtered.get(1).copied().unwrap_or("get") {
            "get" | "status" => Ok(RecoveryAction::SlotGet),
            "a" | "A" | "_a" => Ok(RecoveryAction::SlotSwitch { target: Some('A') }),
            "b" | "B" | "_b" => Ok(RecoveryAction::SlotSwitch { target: Some('B') }),
            "switch" | "toggle" => Ok(RecoveryAction::SlotSwitch { target: None }),
            other => Err(format!("unknown slot subcommand '{other}' (expected get|a|b|switch)")),
        },
        "modules" | "module" => match filtered.get(1).copied().unwrap_or("list") {
            "list" | "ls" => Ok(RecoveryAction::ModulesList { json }),
            "disable-all" | "safe-mode" => Ok(RecoveryAction::ModulesDisableAll),
            "disable" => {
                let id = filtered.get(2).ok_or("usage: modules disable <id>")?;
                Ok(RecoveryAction::ModulesDisable { id: (*id).to_string() })
            }
            "enable" => {
                let id = filtered.get(2).ok_or("usage: modules enable <id>")?;
                Ok(RecoveryAction::ModulesEnable { id: (*id).to_string() })
            }
            other => Err(format!("unknown modules subcommand '{other}'")),
        },
        "kernel" => match filtered.get(1).copied().unwrap_or("info") {
            "info" | "status" => Ok(RecoveryAction::KernelInfo { json }),
            "profile" => {
                let p = filtered
                    .get(2)
                    .ok_or("usage: kernel profile <ultrasave|powersave|balanced|turbo>")?;
                let profile = parse_power_profile(p)?;
                Ok(RecoveryAction::KernelProfile { profile })
            }
            "cpu" => {
                let policy = filtered
                    .get(2)
                    .ok_or("usage: kernel cpu <policyN> <min_khz> <max_khz> [gov]")?;
                let min_khz: u64 = filtered
                    .get(3)
                    .ok_or("missing min_khz")?
                    .parse()
                    .map_err(|_| "invalid min_khz")?;
                let max_khz: u64 = filtered
                    .get(4)
                    .ok_or("missing max_khz")?
                    .parse()
                    .map_err(|_| "invalid max_khz")?;
                let governor = filtered.get(5).map(|s| (*s).to_string());
                Ok(RecoveryAction::KernelCpu {
                    policy: (*policy).to_string(),
                    min_khz,
                    max_khz,
                    governor,
                })
            }
            "io" => {
                let scheduler = filtered
                    .get(2)
                    .ok_or("usage: kernel io <scheduler> [read_ahead_kb]")?;
                let read_ahead_kb = filtered
                    .get(3)
                    .map(|s| s.parse::<u32>().map_err(|_| "invalid read_ahead_kb"))
                    .transpose()?;
                Ok(RecoveryAction::KernelIo {
                    scheduler: (*scheduler).to_string(),
                    read_ahead_kb,
                })
            }
            "tcp" => {
                let algo = filtered.get(2).ok_or("usage: kernel tcp <bbr3|bbr|cubic|reno>")?;
                Ok(RecoveryAction::KernelTcp {
                    algo: (*algo).to_string(),
                })
            }
            other => Err(format!("unknown kernel subcommand '{other}'")),
        },
        "power" => match filtered.get(1).copied().unwrap_or("status") {
            "status" | "info" => Ok(RecoveryAction::PowerStatus { json }),
            "bypass" => {
                let v = filtered.get(2).ok_or("usage: power bypass <on|off>")?;
                let enable = match v.to_ascii_lowercase().as_str() {
                    "on" | "1" | "true" => true,
                    "off" | "0" | "false" => false,
                    _ => return Err("usage: power bypass <on|off>".into()),
                };
                Ok(RecoveryAction::PowerBypass { enable })
            }
            "backlight" | "brightness" => {
                let pct: u8 = filtered
                    .get(2)
                    .ok_or("usage: power backlight <0..100>")?
                    .parse()
                    .map_err(|_| "backlight must be 0..100")?;
                if pct > 100 {
                    return Err("backlight percentage must be 0..=100".into());
                }
                Ok(RecoveryAction::PowerBacklight { pct })
            }
            other => Err(format!("unknown power subcommand '{other}'")),
        },
        "gpu" => match filtered.get(1).copied().unwrap_or("status") {
            "status" | "info" => Ok(RecoveryAction::GpuStatus { json }),
            "enable" | "on" | "load" => Ok(RecoveryAction::GpuEnable),
            "disable" | "off" | "unload" => Ok(RecoveryAction::GpuDisable),
            "launch" | "run" => {
                let bin = filtered.get(2).ok_or("usage: gpu launch <binary> [args...]")?;
                let args = filtered[3..].iter().map(|s| (*s).to_string()).collect();
                Ok(RecoveryAction::GpuLaunch {
                    bin: PathBuf::from(bin),
                    args,
                })
            }
            other => Err(format!("unknown gpu subcommand '{other}' (expected status|enable|disable|launch)")),
        },
        "screencap" => {
            let mut out = "/tmp/pulih-screen.png";
            for &a in &filtered[1..] {
                if a != "-p" {
                    out = a;
                }
            }
            Ok(RecoveryAction::Screencap {
                out_path: out.to_string(),
            })
        }
        "input" => match filtered.get(1).copied().unwrap_or("") {
            "tap" => {
                let x: i32 = filtered.get(2).ok_or("usage: input tap <x> <y>")?.parse().map_err(|_| "bad x")?;
                let y: i32 = filtered.get(3).ok_or("usage: input tap <x> <y>")?.parse().map_err(|_| "bad y")?;
                Ok(RecoveryAction::InputTap { x, y })
            }
            "swipe" => {
                let x1: i32 = filtered.get(2).ok_or("usage: input swipe <x1> <y1> <x2> <y2>")?.parse().map_err(|_| "bad x1")?;
                let y1: i32 = filtered.get(3).ok_or("missing y1")?.parse().map_err(|_| "bad y1")?;
                let x2: i32 = filtered.get(4).ok_or("missing x2")?.parse().map_err(|_| "bad x2")?;
                let y2: i32 = filtered.get(5).ok_or("missing y2")?.parse().map_err(|_| "bad y2")?;
                Ok(RecoveryAction::InputSwipe { x1, y1, x2, y2 })
            }
            "keyevent" | "key" => {
                let key = filtered.get(2).ok_or("usage: input keyevent <BACK|POWER|VOL_UP|VOL_DOWN>")?.to_string();
                Ok(RecoveryAction::InputKey { key })
            }
            other => Err(format!("unknown input subcommand '{other}' (expected tap|swipe|keyevent)")),
        },
        "tap" => {
            let x: i32 = filtered.get(1).ok_or("usage: tap <x> <y>")?.parse().map_err(|_| "bad x")?;
            let y: i32 = filtered.get(2).ok_or("usage: tap <x> <y>")?.parse().map_err(|_| "bad y")?;
            Ok(RecoveryAction::InputTap { x, y })
        }
        "swipe" => {
            let x1: i32 = filtered.get(1).ok_or("usage: swipe <x1> <y1> <x2> <y2>")?.parse().map_err(|_| "bad x1")?;
            let y1: i32 = filtered.get(2).ok_or("missing y1")?.parse().map_err(|_| "bad y1")?;
            let x2: i32 = filtered.get(3).ok_or("missing x2")?.parse().map_err(|_| "bad x2")?;
            let y2: i32 = filtered.get(4).ok_or("missing y2")?.parse().map_err(|_| "bad y2")?;
            Ok(RecoveryAction::InputSwipe { x1, y1, x2, y2 })
        }
        "ui-dump" | "uiautomator" => Ok(RecoveryAction::UiDump),
        "vibrate" | "haptic" => {
            let ms: u32 = filtered
                .get(1)
                .map(|s| s.parse::<u32>().unwrap_or(30))
                .unwrap_or(30);
            Ok(RecoveryAction::Vibrate { ms: ms.clamp(8, 200) })
        }
        "passport" | "sysinfo" => Ok(RecoveryAction::Passport {
            reveal: filtered.contains(&"--reveal"),
            json,
        }),
        "doctor" | "check" => Ok(RecoveryAction::Doctor { json }),
        "backup" => {
            let out_path = filtered.get(1).ok_or("usage: backup <out.yvbak> [targets...]")?;
            let targets = filtered[2..].iter().map(|s| (*s).to_string()).collect();
            Ok(RecoveryAction::Backup {
                out_path: PathBuf::from(out_path),
                targets,
            })
        }
        "restore" => {
            let archive_path = filtered.get(1).ok_or("usage: restore <archive.yvbak>")?;
            Ok(RecoveryAction::Restore {
                archive_path: PathBuf::from(archive_path),
            })
        }
        "ors" => {
            let p = filtered
                .get(1)
                .copied()
                .unwrap_or("/cache/recovery/openrecoveryscript");
            Ok(RecoveryAction::RunOrsScript {
                script_path: PathBuf::from(p),
            })
        }
        "reboot" => {
            let mode = match filtered.get(1).copied().unwrap_or("system") {
                "system" | "os" => RebootTarget::System,
                "recovery" => RebootTarget::Recovery,
                "bootloader" => RebootTarget::Bootloader,
                "fastboot" | "fastbootd" => RebootTarget::Fastbootd,
                "poweroff" | "shutdown" => RebootTarget::PowerOff,
                other => return Err(format!("unknown reboot target '{other}'")),
            };
            Ok(RecoveryAction::Reboot { mode })
        }
        "poweroff" | "shutdown" => Ok(RecoveryAction::Reboot {
            mode: RebootTarget::PowerOff,
        }),
        unknown => Err(format!(
            "unknown command '{unknown}'. Run `pulih --help` (or `twrp --help`) for usage."
        )),
    }
}

pub fn parse_power_profile(name: &str) -> Result<PowerProfile, String> {
    match name.to_ascii_lowercase().as_str() {
        "ultrasave" | "ultra" | "ultra-powersave" | "ultra_powersave" => {
            Ok(PowerProfile::UltraPowersave)
        }
        "powersave" | "save" | "battery" => Ok(PowerProfile::Powersave),
        "balanced" | "default" | "normal" => Ok(PowerProfile::Balanced),
        "turbo" | "performance" | "perf" | "turboflash" => Ok(PowerProfile::TurboFlash),
        _ => Err(format!(
            "unknown power profile '{name}' (expected ultrasave|powersave|balanced|turbo)"
        )),
    }
}

/// Parse & pre-validate a TWRP / OrangeFox `openrecoveryscript` file.
/// Every `wipe` line is immediately validated against `pasang_core::safety` so a
/// malicious or mistyped ORS script can NEVER wipe `xbl`/`abl`/`persist`/`super`!
pub fn parse_openrecoveryscript(script: &str) -> Result<Vec<RecoveryAction>, String> {
    let mut actions = Vec::new();
    for (idx, raw_line) in script.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
        let action = parse_cli_args(&tokens)
            .map_err(|e| format!("openrecoveryscript line {}: {e}", idx + 1))?;
        if let RecoveryAction::Wipe { ref target } = action {
            validate_wipe_or_format(target)
                .map_err(|e| format!("openrecoveryscript line {}: {e}", idx + 1))?;
        }
        actions.push(action);
    }
    Ok(actions)
}

/// Pre-flight guard helper for CLI `flash` action.
pub fn preflight_cli_flash(
    partition: &str,
    header: &[u8],
    image_len: u64,
    part_len: u64,
    active_slot_suffix: &str,
    ro_vendor_mounted: bool,
) -> Result<(), SafetyError> {
    validate_raw_flash(
        partition,
        header,
        image_len,
        part_len,
        active_slot_suffix,
        ro_vendor_mounted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn parses_standard_aosp_bcb_and_twrp_orangefox_commands() {
        assert_eq!(parse_cli_args(&s(&[])).unwrap(), RecoveryAction::LaunchUi);
        assert_eq!(parse_cli_args(&s(&["--fastboot"])).unwrap(), RecoveryAction::EnterFastbootd);
        assert_eq!(
            parse_cli_args(&s(&["--sideload"])).unwrap(),
            RecoveryAction::Sideload { auto_reboot: false }
        );
        assert_eq!(
            parse_cli_args(&s(&["--sideload_auto_reboot"])).unwrap(),
            RecoveryAction::Sideload { auto_reboot: true }
        );
        assert_eq!(
            parse_cli_args(&s(&["--update_package=/sdcard/Yasvara.zip"])).unwrap(),
            RecoveryAction::InstallZip {
                path: PathBuf::from("/sdcard/Yasvara.zip"),
                clean_overlay: false,
                dry_run: false,
            }
        );
        assert_eq!(
            parse_cli_args(&s(&["install", "/sdcard/rom.zip", "--clean-overlay"])).unwrap(),
            RecoveryAction::InstallZip {
                path: PathBuf::from("/sdcard/rom.zip"),
                clean_overlay: true,
                dry_run: false,
            }
        );
        assert_eq!(
            parse_cli_args(&s(&["wipe", "dalvik"])).unwrap(),
            RecoveryAction::Wipe { target: "cache".into() }
        );
        assert_eq!(
            parse_cli_args(&s(&["--json", "kernel", "info"])).unwrap(),
            RecoveryAction::KernelInfo { json: true }
        );
        assert_eq!(
            parse_cli_args(&s(&["kernel", "profile", "ultrasave"])).unwrap(),
            RecoveryAction::KernelProfile {
                profile: PowerProfile::UltraPowersave
            }
        );
        assert_eq!(
            parse_cli_args(&s(&["kernel", "cpu", "policy7", "480000", "2400000", "walt"])).unwrap(),
            RecoveryAction::KernelCpu {
                policy: "policy7".into(),
                min_khz: 480000,
                max_khz: 2400000,
                governor: Some("walt".into()),
            }
        );
        assert_eq!(
            parse_cli_args(&s(&["power", "bypass", "on"])).unwrap(),
            RecoveryAction::PowerBypass { enable: true }
        );
        assert_eq!(
            parse_cli_args(&s(&["power", "backlight", "25"])).unwrap(),
            RecoveryAction::PowerBacklight { pct: 25 }
        );
        assert!(parse_cli_args(&s(&["power", "backlight", "150"])).is_err());
        assert_eq!(
            parse_cli_args(&s(&["reboot", "fastbootd"])).unwrap(),
            RecoveryAction::Reboot {
                mode: RebootTarget::Fastbootd
            }
        );
    }

    #[test]
    fn openrecoveryscript_parses_valid_script_and_blocks_hardbrick_wipe() {
        let good = "# Yasvara OTA script\ninstall /sdcard/Yasvara.zip\nwipe cache\nreboot system\n";
        let actions = parse_openrecoveryscript(good).unwrap();
        assert_eq!(actions.len(), 3);
        assert!(matches!(actions[0], RecoveryAction::InstallZip { .. }));
        assert_eq!(actions[1], RecoveryAction::Wipe { target: "cache".into() });
        assert_eq!(actions[2], RecoveryAction::Reboot { mode: RebootTarget::System });

        // Malicious or mistyped ORS script attempting to wipe xbl/persist/super MUST be rejected!
        for bad_target in ["xbl_a", "abl_b", "persist", "modemst1", "super"] {
            let bad = format!("wipe {bad_target}\nreboot system\n");
            assert!(
                parse_openrecoveryscript(&bad).is_err(),
                "ORS MUST reject wiping {bad_target}"
            );
        }
    }
}
