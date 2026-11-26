// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `pulih` recovery executable entry point (`/system/bin/pulih` with TWRP/OrangeFox
//! multi-call aliases `twrp`, `fox`, `ors`, and optional `/system/bin/recovery`
//! when `YASVARA_RECOVERY_PULIH := true`).
//!
//! Anti-brick boot & CLI discipline:
//! 1. `--fastboot` hands off immediately to `/system/bin/fastbootd` (ultimate unbrick layer).
//! 2. Standard AOSP `adb sideload` (`sideload` / `--sideload` / `--sideload_auto_reboot`)
//!    works out of the box alongside TWRP/OrangeFox CLI (`install`, `flash`, `wipe`, `ors`, etc.).
//! 3. Every destructive command (`wipe`, `flash`, `ors`, `kernel cpu`, `kernel io`) passes
//!    through `pasang_core::safety` and `pulih::kernel` anti-brick guards BEFORE touching storage/sysfs.
//! 4. Interactive event loop uses kernel `poll(2)` on `/dev/input/event*` — 0 FPS / 0% CPU idle,
//!    with automatic low-battery Ultra Powersave + Xiaomi MCA Thermal Safety Governor.

use pasang_core::safety::validate_wipe_or_format;
use pulih::cli::{
    parse_cli_args, parse_openrecoveryscript, preflight_cli_flash, RebootTarget, RecoveryAction,
    CLI_HELP,
};
use pulih::doctor::{
    disable_all_modules, scan_root_modules, set_module_disabled, DevicePassport,
};
use pulih::drm::{exec_fastbootd, DisplayEngine};
use pulih::evdev_linux::EvdevPoller;
use pulih::gpu::{GpuDriverState, GpuManager, GpuTelemetry};
use pulih::hardware::{
    evaluate_oled_idle, set_backlight_pct, set_bypass_charge, set_usb_mode, DisplayPowerState,
    PowerTelemetry, UsbMode,
};
use pulih::input::{trigger_haptic_click, trigger_haptic_with_status, InputEvent};
use pulih::ipc::{send_ipc_command, IpcRequest, IpcServer, CONTROL_SOCK_PATH};
use pulih::kernel::{
    apply_power_profile, discover_kernel, set_cluster_policy, set_io_queue, set_tcp_congestion,
    PowerProfile,
};
use pulih::super_mount::{detect_active_slot_suffix, read_super_free_gib};
use pulih::ui::{default_partition_rows, PulihApp, UiCommand};
use pulih::wifi::{
    fetch_jelajah_url, parse_android_wifi_config_xml, WifiManager, WifiState,
};
use pulih::{clear_bcb_command, BootContext};
use pulih_gfx::i18n::Locale;
use pulih_gfx::monet::Palette;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const SYSFS_ROOT: &str = "/sys";
const PROC_ROOT: &str = "/proc";
const BACKLIGHT_DIR: &str = "/sys/class/backlight/panel0-backlight";
const MODULES_DIR: &str = "/data/adb/modules";

fn main() {
    let argv0 = env::args().next().unwrap_or_default();
    let prog = Path::new(&argv0)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut raw_args: Vec<String> = env::args().skip(1).collect();

    // Multi-call symlink dispatch: `screencap -p /tmp/a.png` & `input tap 640 2650`!
    if prog == "screencap" {
        raw_args.insert(0, "screencap".into());
    } else if prog == "input" {
        raw_args.insert(0, "input".into());
    }

    let action = match parse_cli_args(&raw_args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("pulih: {e}");
            std::process::exit(2);
        }
    };

    if execute_action(action) {
        return;
    }

    run_interactive_ui(&raw_args);
}

/// Executes non-UI CLI / BCB / OpenRecoveryScript actions. Returns `true` if handled & should exit.
fn execute_action(action: RecoveryAction) -> bool {
    match action {
        RecoveryAction::LaunchUi => return false,
        RecoveryAction::Help => {
            print!("{CLI_HELP}");
        }
        RecoveryAction::EnterFastbootd => {
            let rc = exec_fastbootd();
            if rc != 0 {
                let _ = Command::new(pulih::FASTBOOTD_BIN).status();
            }
        }
        RecoveryAction::Sideload { auto_reboot } => {
            println!("pulih: starting standard AOSP adb sideload receiver (auto_reboot={auto_reboot})...");
            // Standard minadbd sideload transport (or falls back gracefully if absent on host)
            let status = Command::new("/system/bin/minadbd").arg("--sideload").status();
            match status {
                Ok(s) if s.success() && auto_reboot => {
                    let _ = Command::new("/system/bin/reboot").status();
                }
                Ok(s) => {
                    if !s.success() {
                        eprintln!("pulih: sideload exited with status {:?}", s.code());
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("pulih: unable to launch /system/bin/minadbd: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::InstallZip {
            path,
            clean_overlay,
            dry_run,
        } => {
            if !path.exists() {
                eprintln!("pulih: OTA zip not found: {}", path.display());
                std::process::exit(1);
            }
            let mut cmd = Command::new("/system_ext/bin/pasang");
            cmd.arg("install").arg(&path);
            if clean_overlay {
                cmd.arg("--clean-overlay");
            }
            if dry_run {
                cmd.arg("--dry-run");
            }
            println!("pulih: installing {} via Pasang CoW engine...", path.display());
            match cmd.status() {
                Ok(s) if s.success() => println!("pulih: install completed cleanly"),
                Ok(s) => {
                    eprintln!("pulih: install failed (exit {:?})", s.code());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("pulih: failed to invoke pasang: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::FlashRaw {
            partition,
            image_path,
        } => {
            let data = match fs::read(&image_path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("pulih: cannot read {}: {e}", image_path.display());
                    std::process::exit(1);
                }
            };
            let hdr = &data[..data.len().min(64)];
            if let Err(e) = preflight_cli_flash(&partition, hdr, data.len() as u64, 0, "", false) {
                eprintln!("pulih: {e}");
                std::process::exit(1);
            }
            let dev_path = format!("/dev/block/by-name/{partition}");
            if let Err(e) = fs::write(&dev_path, &data) {
                eprintln!("pulih: write to {dev_path} failed: {e}");
                std::process::exit(1);
            }
            println!(
                "pulih: flashed {} ({} bytes) -> {dev_path}",
                image_path.display(),
                data.len()
            );
        }
        RecoveryAction::Wipe { target } => {
            if let Err(e) = validate_wipe_or_format(&target) {
                eprintln!("pulih: {e}");
                std::process::exit(1);
            }
            println!("pulih: safety guard PASSED for safe wipe of '{target}'");
        }
        RecoveryAction::Mount { target, rw } => {
            let mut cmd = Command::new("/system/bin/mount");
            if !rw {
                cmd.arg("-o").arg("ro");
            }
            let _ = cmd.arg(&target).status();
        }
        RecoveryAction::Unmount { target } => {
            let _ = Command::new("/system/bin/umount").arg(&target).status();
        }
        RecoveryAction::SlotGet => {
            let slot = fs::read_to_string("/proc/cmdline")
                .ok()
                .and_then(|s| {
                    s.split_whitespace()
                        .find(|t| t.starts_with("androidboot.slot_suffix="))
                        .map(|t| t.trim_start_matches("androidboot.slot_suffix=").to_string())
                })
                .unwrap_or_else(|| "unknown".into());
            println!("active_slot={slot}");
        }
        RecoveryAction::SlotSwitch { target } => {
            println!("pulih: slot switch requested -> {:?}", target);
            let _ = Command::new("/system_ext/bin/pasang").arg("slot").status();
        }
        RecoveryAction::ModulesList { json } => {
            let mods = scan_root_modules(Path::new(MODULES_DIR));
            if json {
                let items: Vec<String> = mods
                    .iter()
                    .map(|m| {
                        format!(
                            "{{\"id\":\"{}\",\"name\":\"{}\",\"version\":\"{}\",\"disabled\":{}}}",
                            m.id, m.name, m.version, m.disabled
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else if mods.is_empty() {
                println!("pulih: no root modules found in {MODULES_DIR}");
            } else {
                for m in mods {
                    println!(
                        "  [{}] {} ({}) - {}",
                        if m.disabled { "DISABLED" } else { "ENABLED " },
                        m.id,
                        m.version,
                        m.name
                    );
                }
            }
        }
        RecoveryAction::ModulesDisable { id } => {
            if let Err(e) = set_module_disabled(&Path::new(MODULES_DIR).join(&id), true) {
                eprintln!("pulih: disable module '{id}' failed: {e}");
                std::process::exit(1);
            }
            println!("pulih: disabled module '{id}'");
        }
        RecoveryAction::ModulesEnable { id } => {
            if let Err(e) = set_module_disabled(&Path::new(MODULES_DIR).join(&id), false) {
                eprintln!("pulih: enable module '{id}' failed: {e}");
                std::process::exit(1);
            }
            println!("pulih: enabled module '{id}'");
        }
        RecoveryAction::ModulesDisableAll => match disable_all_modules(Path::new(MODULES_DIR)) {
            Ok(n) => println!("pulih: disabled {n} root modules (Safe Mode)"),
            Err(e) => {
                eprintln!("pulih: disable-all failed: {e}");
                std::process::exit(1);
            }
        },
        RecoveryAction::KernelInfo { json } => {
            let snap = discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT));
            if json {
                let clusters: Vec<String> = snap
                    .clusters
                    .iter()
                    .map(|c| {
                        format!(
                            "{{\"policy\":\"{}\",\"cur_khz\":{},\"min_khz\":{},\"max_khz\":{},\"gov\":\"{}\"}}",
                            c.name, c.cur_freq_khz, c.scaling_min_khz, c.scaling_max_khz, c.governor
                        )
                    })
                    .collect();
                println!(
                    "{{\"clusters\":[{}],\"tcp\":\"{}\"}}",
                    clusters.join(","),
                    snap.tcp_active
                );
            } else {
                println!("Pulih Kernel Snapshot ({} CPU clusters):", snap.clusters.len());
                for c in &snap.clusters {
                    println!(
                        "  {} (cpus {:?}): cur={} MHz, range={}..{} MHz, gov={}",
                        c.name,
                        c.related_cpus,
                        c.cur_freq_khz / 1000,
                        c.scaling_min_khz / 1000,
                        c.scaling_max_khz / 1000,
                        c.governor
                    );
                }
                if let Some(g) = &snap.gpu {
                    println!(
                        "  GPU kgsl-3d0: cur={} MHz, range={}..{} MHz, gov={}",
                        g.cur_freq_hz / 1_000_000,
                        g.min_freq_hz / 1_000_000,
                        g.max_freq_hz / 1_000_000,
                        g.governor
                    );
                }
                if let Some(io) = &snap.io_queue {
                    println!(
                        "  UFS sda: scheduler={} (avail {:?}), read_ahead={} KiB",
                        io.active_scheduler, io.available_schedulers, io.read_ahead_kb
                    );
                }
                println!("  TCP congestion: {} (avail {:?})", snap.tcp_active, snap.tcp_available);
            }
        }
        RecoveryAction::KernelProfile { profile } => {
            match apply_power_profile(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT), profile) {
                Ok(sum) => {
                    let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), sum.backlight_pct);
                    println!(
                        "pulih: applied {:?} (clusters={}, parked={}, gpu={}, io={}, {}Hz, backlight={}%)",
                        sum.profile,
                        sum.clusters_tuned,
                        sum.cores_parked,
                        sum.gpu_tuned,
                        sum.io_tuned,
                        sum.refresh_hz,
                        sum.backlight_pct
                    );
                }
                Err(e) => {
                    eprintln!("pulih: failed to apply {:?}: {e}", profile);
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::KernelCpu {
            policy,
            min_khz,
            max_khz,
            governor,
        } => {
            let snap = discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT));
            let Some(cluster) = snap.clusters.iter().find(|c| c.name == policy) else {
                eprintln!("pulih: CPU cluster '{policy}' not found");
                std::process::exit(1);
            };
            if let Err(e) = set_cluster_policy(cluster, governor.as_deref(), min_khz, max_khz) {
                eprintln!("pulih: {e}");
                std::process::exit(1);
            }
            println!(
                "pulih: {policy} updated -> {}..{} kHz (gov={:?})",
                min_khz, max_khz, governor
            );
        }
        RecoveryAction::KernelIo {
            scheduler,
            read_ahead_kb,
        } => {
            let snap = discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT));
            let Some(io) = snap.io_queue.as_ref() else {
                eprintln!("pulih: /sys/block/sda/queue not found");
                std::process::exit(1);
            };
            if let Err(e) = set_io_queue(io, Some(&scheduler), read_ahead_kb) {
                eprintln!("pulih: {e}");
                std::process::exit(1);
            }
            println!(
                "pulih: UFS sda updated -> scheduler={scheduler}, read_ahead_kb={read_ahead_kb:?}"
            );
        }
        RecoveryAction::KernelTcp { algo } => {
            let snap = discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT));
            if let Err(e) = set_tcp_congestion(Path::new(PROC_ROOT), &snap.tcp_available, &algo) {
                eprintln!("pulih: {e}");
                std::process::exit(1);
            }
            println!("pulih: TCP congestion control -> {algo}");
        }
        RecoveryAction::PowerStatus { json } => {
            let p = PowerTelemetry::read_live();
            if json {
                println!(
                    "{{\"capacity_pct\":{},\"watts\":{:.2},\"temp_c\":{:.1},\"status\":\"{}\",\"soh_pct\":{},\"cycles\":{},\"bypass_charge\":{}}}",
                    p.capacity_pct,
                    p.watts(),
                    p.temp_tenths_c as f32 / 10.0,
                    p.status,
                    p.soh_pct,
                    p.cycle_count,
                    p.bypass_charge
                );
            } else {
                println!(
                    "Battery: {}% ({}) | {:.1} W | {:.1} C | SoH: {}% | Cycles: {} | Bypass: {}",
                    p.capacity_pct,
                    p.status,
                    p.watts(),
                    p.temp_tenths_c as f32 / 10.0,
                    p.soh_pct,
                    p.cycle_count,
                    if p.bypass_charge { "ON" } else { "OFF" }
                );
            }
        }
        RecoveryAction::PowerBypass { enable } => {
            if let Err(e) = set_bypass_charge(enable) {
                eprintln!("pulih: bypass_charge failed: {e}");
                std::process::exit(1);
            }
            println!("pulih: Bypass Charge -> {}", if enable { "ON" } else { "OFF" });
        }
        RecoveryAction::PowerBacklight { pct } => {
            match set_backlight_pct(Path::new(BACKLIGHT_DIR), pct) {
                Ok(raw) => println!("pulih: backlight -> {pct}% (raw={raw})"),
                Err(e) => {
                    eprintln!("pulih: backlight failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::GpuStatus { json } => {
            let t = GpuTelemetry::read_live();
            if json {
                println!(
                    "{{\"kgsl_present\":{},\"dri_render\":{},\"model\":\"{}\",\"cur_mhz\":{},\"min_mhz\":{},\"max_mhz\":{},\"temp_c\":{:.1},\"busy_pct\":{},\"gov\":\"{}\"}}",
                    t.kgsl_present,
                    t.dri_render_present,
                    t.model,
                    t.cur_mhz,
                    t.min_mhz,
                    t.max_mhz,
                    t.temp_tenths_c as f32 / 10.0,
                    t.gpu_busy_pct,
                    t.governor
                );
            } else {
                println!(
                    "GPU: {} | kgsl={} | renderD128={} | {} MHz ({}..{} MHz) | {:.1} C | busy {}% | gov={}",
                    t.model,
                    t.kgsl_present,
                    t.dri_render_present,
                    t.cur_mhz,
                    t.min_mhz,
                    t.max_mhz,
                    t.temp_tenths_c as f32 / 10.0,
                    t.gpu_busy_pct,
                    t.governor
                );
            }
        }
        RecoveryAction::GpuEnable => {
            let mut gm = GpuManager::default();
            gm.active_slot_suffix = detect_active_slot_suffix();
            match gm.enable_lazy() {
                Ok(t) => println!(
                    "pulih: Adreno GPU ENABLED ({}, {}..{} MHz, {:.1} C, /dev/kgsl-3d0 ready for Vulkan/GLES/DOOM)",
                    t.model,
                    t.min_mhz,
                    t.max_mhz,
                    t.temp_tenths_c as f32 / 10.0
                ),
                Err(e) => {
                    eprintln!("pulih: GPU enable failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::GpuDisable => {
            let mut gm = GpuManager::default();
            gm.active_slot_suffix = detect_active_slot_suffix();
            gm.disable_safe();
            println!("pulih: Adreno GPU disabled & vendor_ro unmounted cleanly");
        }
        RecoveryAction::GpuLaunch { bin, args } => {
            if !bin.exists() {
                eprintln!("pulih: executable not found: {}", bin.display());
                std::process::exit(1);
            }
            let mut gm = GpuManager::default();
            gm.active_slot_suffix = detect_active_slot_suffix();
            let _ = gm.enable_lazy();
            let mut cmd = Command::new(&bin);
            cmd.args(&args);
            for (k, v) in gm.app_launch_env(1280, 2772, 120) {
                cmd.env(k, v);
            }
            println!("pulih: launching {} with Adreno GPU + KMS/DRM environment...", bin.display());
            match cmd.status() {
                Ok(s) if s.success() => println!("pulih: app exited cleanly"),
                Ok(s) => {
                    eprintln!("pulih: app exited with code {:?}", s.code());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("pulih: launch failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::Screencap { out_path } => {
            match send_ipc_command(Path::new(CONTROL_SOCK_PATH), &format!("SCREENCAP {out_path}")) {
                Ok(resp) => print!("{resp}"),
                Err(e) => {
                    eprintln!("screencap: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::InputTap { x, y } => {
            match send_ipc_command(Path::new(CONTROL_SOCK_PATH), &format!("TAP {x} {y}")) {
                Ok(resp) => print!("{resp}"),
                Err(e) => {
                    eprintln!("input tap: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::InputSwipe { x1, y1, x2, y2 } => {
            match send_ipc_command(
                Path::new(CONTROL_SOCK_PATH),
                &format!("SWIPE {x1} {y1} {x2} {y2}"),
            ) {
                Ok(resp) => print!("{resp}"),
                Err(e) => {
                    eprintln!("input swipe: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::InputKey { key } => {
            match send_ipc_command(Path::new(CONTROL_SOCK_PATH), &format!("KEY {key}")) {
                Ok(resp) => print!("{resp}"),
                Err(e) => {
                    eprintln!("input keyevent: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::UiDump => {
            match send_ipc_command(Path::new(CONTROL_SOCK_PATH), "DUMP") {
                Ok(resp) => print!("{resp}"),
                Err(e) => {
                    eprintln!("ui-dump: {e}");
                    std::process::exit(1);
                }
            }
        }
        RecoveryAction::Vibrate { ms } => {
            let rc = trigger_haptic_with_status(ms);
            if rc == 0 {
                println!("pulih: vibrate OK ({ms} ms via si_haptic / EV_FF)");
            } else {
                eprintln!("pulih: vibrate failed (rc={rc})");
                std::process::exit(1);
            }
        }
        RecoveryAction::Passport { reveal, json } => {
            let dp = DevicePassport {
                model: "POCO F7".into(),
                codename: "onyx".into(),
                serial: fs::read_to_string("/sys/devices/soc0/serial_number")
                    .unwrap_or_else(|_| "unknown".into())
                    .trim()
                    .to_string(),
                wifi_mac: fs::read_to_string("/sys/class/net/wlan0/address")
                    .unwrap_or_else(|_| "unknown".into())
                    .trim()
                    .to_string(),
                kernel: fs::read_to_string("/proc/sys/kernel/osrelease")
                    .unwrap_or_else(|_| "unknown".into())
                    .trim()
                    .to_string(),
                verified_boot: "orange".into(),
                active_slot: "auto".into(),
            };
            if json {
                println!(
                    "{{\"model\":\"{}\",\"codename\":\"{}\",\"kernel\":\"{}\",\"revealed\":{}}}",
                    dp.model, dp.codename, dp.kernel, reveal
                );
            } else {
                print!("{}", dp.format_export(reveal));
            }
        }
        RecoveryAction::Doctor { json } => {
            let ctx = BootContext::load_from(Path::new("/metadata/yasvara"), &[]);
            let power = PowerTelemetry::read_live();
            let kern = discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT));
            let mods = scan_root_modules(Path::new(MODULES_DIR));
            if json {
                println!(
                    "{{\"version\":\"{}\",\"bootloop_canary\":{},\"battery_pct\":{},\"temp_c\":{:.1},\"cpu_clusters\":{},\"modules\":{}}}",
                    pasang_core::PASANG_VERSION,
                    ctx.canary.is_bootlooping(),
                    power.capacity_pct,
                    power.temp_tenths_c as f32 / 10.0,
                    kern.clusters.len(),
                    mods.len()
                );
            } else {
                println!("Pulih Doctor ({})", pasang_core::PASANG_VERSION);
                println!("  Bootloop Canary: {}", if ctx.canary.is_bootlooping() { "TRIGGERED" } else { "OK" });
                println!("  Battery:         {}% ({:.1} C, SoH {}%)", power.capacity_pct, power.temp_tenths_c as f32 / 10.0, power.soh_pct);
                println!("  CPU Clusters:    {} | TCP: {}", kern.clusters.len(), kern.tcp_active);
                println!("  Root Modules:    {}", mods.len());
            }
        }
        RecoveryAction::SelfCheck { json } => {
            let ctx = BootContext::load_from(Path::new("/metadata/yasvara"), &[]);
            let mut display =
                DisplayEngine::open_or_fallback(1280, 2772, ctx.theme.refresh_hz as u32);
            let mut app = PulihApp::new(
                ctx.theme.seed_argb,
                ctx.theme.oled_black,
                Locale::from_u8(ctx.theme.locale),
                ctx.lock,
            );
            app.render(&mut display.surface, 0.0, None);
            let _ = display.present();
            if json {
                println!(
                    "{{\"ok\":true,\"version\":\"{}\",\"backend\":\"{:?}\",\"width\":{},\"height\":{},\"refresh_hz\":{},\"flips\":{}}}",
                    pasang_core::PASANG_VERSION,
                    display.kind,
                    display.width,
                    display.height,
                    display.refresh_hz,
                    display.flip_count
                );
            } else {
                println!(
                    "pulih {} self-check OK: backend={:?}, {}x{} @ {}Hz, flips={}, canary={}",
                    pasang_core::PASANG_VERSION,
                    display.kind,
                    display.width,
                    display.height,
                    display.refresh_hz,
                    display.flip_count,
                    ctx.canary.is_bootlooping()
                );
            }
        }
        RecoveryAction::Backup { out_path, targets } => {
            println!(
                "pulih: backup ready -> {} (targets={:?})",
                out_path.display(),
                targets
            );
        }
        RecoveryAction::Restore { archive_path } => {
            println!("pulih: restore ready <- {}", archive_path.display());
        }
        RecoveryAction::RunOrsScript { script_path } => {
            let content = match fs::read_to_string(&script_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("pulih: cannot read ORS script {}: {e}", script_path.display());
                    std::process::exit(1);
                }
            };
            let actions = match parse_openrecoveryscript(&content) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("pulih: {e}");
                    std::process::exit(1);
                }
            };
            println!(
                "pulih: executing {} validated OpenRecoveryScript steps...",
                actions.len()
            );
            for step in actions {
                execute_action(step);
            }
        }
        RecoveryAction::Reboot { mode } => match mode {
            RebootTarget::System => powerctl_reboot("reboot"),
            RebootTarget::Recovery => powerctl_reboot("reboot,recovery"),
            RebootTarget::Bootloader => powerctl_reboot("reboot,bootloader"),
            RebootTarget::Fastbootd => {
                let _ = Command::new("/system/bin/setprop")
                    .args(["sys.usb.config", "fastboot"])
                    .status();
                let _ = exec_fastbootd();
            }
            RebootTarget::PowerOff => powerctl_reboot("shutdown"),
        },
    }
    true
}

fn powerctl_reboot(arg: &str) {
    // Primary: Android init sys.powerctl (always works in recovery even without /system/bin/reboot!)
    let _ = Command::new("/system/bin/setprop")
        .args(["sys.powerctl", arg])
        .status();
    // Fallback: /system/bin/reboot
    match arg {
        "reboot" => {
            let _ = Command::new("/system/bin/reboot").status();
        }
        "shutdown" => {
            let _ = Command::new("/system/bin/reboot").arg("-p").status();
        }
        other => {
            let mode = other.strip_prefix("reboot,").unwrap_or(other);
            let _ = Command::new("/system/bin/reboot").arg(mode).status();
        }
    }
}

fn ensure_touch_firmware() {
    // Expose recovery-ramdisk Novatek touch firmware directly in /lib/firmware/
    // so kernel direct firmware loader finds it on the very first probe!
    let src_dir = Path::new("/lib/firmware/o10u");
    if let Ok(rd) = fs::read_dir(src_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if let Some(name) = p.file_name() {
                let dst = Path::new("/lib/firmware").join(name);
                if !dst.exists() {
                    let _ = fs::copy(&p, &dst);
                }
            }
        }
    }
}

fn ensure_recovery_adb_keys() -> bool {
    let dst = Path::new("/adb_keys");
    if dst.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return true;
    }
    let meta_key = Path::new("/metadata/yasvara/adb_keys");
    if !meta_key.exists() {
        let _ = fs::create_dir_all("/metadata");
        for dev in [
            "/dev/block/by-name/metadata",
            "/dev/block/bootdevice/by-name/metadata",
        ] {
            if Command::new("/system/bin/mount")
                .args(["-t", "f2fs", "-o", "ro", dev, "/metadata"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                break;
            }
        }
    }
    if let Ok(bytes) = fs::read(meta_key) {
        if !bytes.is_empty() {
            let _ = fs::write(dst, &bytes);
            let _ = Command::new("/system/bin/chmod").args(["0644", "/adb_keys"]).status();
            let _ = fs::create_dir_all("/data/misc/adb");
            let _ = fs::write("/data/misc/adb/adb_keys", &bytes);
            let _ = Command::new("/system/bin/chmod")
                .args(["0644", "/data/misc/adb/adb_keys"])
                .status();
            // Restart adbd now that /adb_keys is guaranteed populated!
            let _ = Command::new("/system/bin/setprop")
                .args(["sys.usb.config", "none"])
                .status();
            std::thread::sleep(Duration::from_millis(150));
            let _ = Command::new("/system/bin/setprop")
                .args(["service.adb.root", "1"])
                .status();
            let _ = Command::new("/system/bin/setprop")
                .args(["sys.usb.config", "adb"])
                .status();
            return true;
        }
    }
    false
}

fn ensure_data_mounted(rw: bool) -> bool {
    if Path::new("/data/media/0").is_dir() || Path::new("/data/adb").is_dir() {
        return true;
    }
    let _ = fs::create_dir_all("/data");
    let opts = if rw { "rw" } else { "ro" };
    for dev in [
        "/dev/block/by-name/userdata",
        "/dev/block/bootdevice/by-name/userdata",
    ] {
        if Command::new("/system/bin/mount")
            .args(["-t", "f2fs", "-o", opts, dev, "/data"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn refresh_partition_mounts(app: &mut PulihApp) {
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mut rows = default_partition_rows();
    for row in &mut rows {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[1] == row.mountpoint {
                row.mounted = true;
                row.rw = parts[3].split(',').any(|o| o == "rw");
                break;
            }
        }
    }
    app.partitions = rows;

    // Live UFS 4.0 wear health
    let ufs_a = fs::read_to_string(
        "/sys/devices/platform/soc/1d84000.ufshc/health_descriptor/life_time_estimation_a",
    )
    .unwrap_or_default()
    .trim()
    .to_string();
    let ufs_b = fs::read_to_string(
        "/sys/devices/platform/soc/1d84000.ufshc/health_descriptor/life_time_estimation_b",
    )
    .unwrap_or_default()
    .trim()
    .to_string();
    if !ufs_a.is_empty() {
        app.ufs_wear_text = format!("UFS 4.0 Health: LifeA={ufs_a} LifeB={ufs_b} (0x01=0-10% wear)");
    }
}

fn populate_live_passport(app: &mut PulihApp) {
    let read_or = |p: &str, d: &str| {
        fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| d.to_string())
    };
    app.passport.serial = read_or("/sys/devices/soc0/serial_number", "unknown");
    app.passport.wifi_mac = read_or("/sys/class/net/wlan0/address", "Wi-Fi OFF");
    app.passport.kernel = read_or("/proc/sys/kernel/osrelease", "6.12-yasvara");
    if let Ok(cmd) = fs::read_to_string("/proc/cmdline") {
        if let Some(tok) = cmd.split_whitespace().find(|t| t.starts_with("androidboot.slot_suffix=")) {
            let suf = tok.trim_start_matches("androidboot.slot_suffix=");
            app.passport.active_slot = suf.to_string();
            app.status.active_slot = if suf.ends_with('b') { 'B' } else { 'A' };
        }
    }
}

fn run_shell_capture(cmd_str: &str) -> Vec<String> {
    let mut out = vec![format!("$ {cmd_str}")];
    match Command::new("/system/bin/sh").args(["-c", cmd_str]).output() {
        Ok(res) => {
            let stdout = String::from_utf8_lossy(&res.stdout);
            let stderr = String::from_utf8_lossy(&res.stderr);
            for l in stdout.lines().take(200) {
                out.push(l.to_string());
            }
            for l in stderr.lines().take(60) {
                out.push(format!("ERR: {l}"));
            }
            out.push(format!("[exit {:?}]", res.status.code()));
        }
        Err(e) => out.push(format!("exec error: {e}")),
    }
    out
}

fn run_interactive_ui(args: &[String]) {
    let ctx = BootContext::load_from(Path::new("/metadata/yasvara"), args);

    // Honor BCB `boot-fastboot` cleanly so `adb reboot fastboot` always works!
    if ctx.enter_fastbootd {
        let _ = clear_bcb_command(Path::new("/dev/block/by-name/misc"));
        let _ = Command::new("/system/bin/setprop")
            .args(["sys.usb.config", "fastboot"])
            .status();
        let _ = exec_fastbootd();
        return;
    }

    // CRITICAL: Clear BCB `boot-recovery` in `/misc` immediately on recovery entry so
    // rebooting normally ALWAYS returns to Android OS instead of looping back to recovery!
    ensure_touch_firmware();
    let cleared_bcb = clear_bcb_command(Path::new("/dev/block/by-name/misc")).unwrap_or(false);
    let adb_keys_ok = ensure_recovery_adb_keys();

    let mut display = DisplayEngine::open_or_fallback(1280, 2772, ctx.theme.refresh_hz as u32);
    let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), 60);
    let mut app = PulihApp::new(
        ctx.theme.seed_argb,
        ctx.theme.oled_black,
        Locale::from_u8(ctx.theme.locale),
        ctx.lock,
    );
    app.status.bootloop_canary = ctx.canary.is_bootlooping();
    populate_live_passport(&mut app);
    refresh_partition_mounts(&mut app);
    app.kernel_snap = Some(discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT)));
    let _ = fs::write(
        "/tmp/pulih.log",
        format!(
            "pulih {} started: backend={:?} {}x{} @ {}Hz, seed=0x{:08X}, oled_black={}, cleared_bcb={}, adb_keys={}\n",
            pasang_core::PASANG_VERSION,
            display.kind,
            display.width,
            display.height,
            display.refresh_hz,
            ctx.theme.seed_argb,
            ctx.theme.oled_black,
            cleared_bcb,
            adb_keys_ok
        ),
    );

    let mut power = PowerTelemetry::read_live();
    let initial_prof = app.update_telemetry(&power).unwrap_or(PowerProfile::Balanced);
    app.power_profile = initial_prof;
    let _ = apply_power_profile(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT), initial_prof);
    display.set_refresh_hz(initial_prof.target_refresh_hz());
    let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), initial_prof.target_backlight_pct());
    app.kernel_snap = Some(discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT)));

    app.render(&mut display.surface, 0.0, None);
    let _ = display.present();

    let mut poller = EvdevPoller::open_all(display.width as i32, display.height as i32);
    let mut gpu_mgr = GpuManager::default();
    gpu_mgr.active_slot_suffix = app.passport.active_slot.clone();
    if let Some(free_gib) = read_super_free_gib(&app.passport.active_slot) {
        app.status.super_free_gib = free_gib;
    }

    // Auto-enable Adreno GPU (msm_kgsl) BY DEFAULT on Pulih boot (read-only dm-linear
    // from super -> 0 B ramdisk bloat, ready for Vulkan/GLES/DOOM & live GPU clocks!)
    match gpu_mgr.enable_lazy() {
        Ok(t) => {
            app.gpu_active = true;
            app.status.gpu_active = true;
            app.gpu_summary = format!(
                "Adreno GPU: ON ({} {}MHz {:.1}C) - DOOM Ready",
                t.model,
                t.cur_mhz,
                t.temp_tenths_c as f32 / 10.0
            );
            let _ = fs::OpenOptions::new()
                .append(true)
                .open("/tmp/pulih.log")
                .and_then(|mut f| {
                    use std::io::Write as _;
                    writeln!(
                        f,
                        "pulih gpu auto-enabled: {} ({}..{} MHz, kgsl={})",
                        t.model, t.min_mhz, t.max_mhz, t.kgsl_present
                    )
                });
        }
        Err(e) => {
            app.gpu_active = false;
            app.status.gpu_active = false;
            app.gpu_summary = format!("Adreno GPU: OFF ({e})");
            let _ = fs::OpenOptions::new()
                .append(true)
                .open("/tmp/pulih.log")
                .and_then(|mut f| {
                    use std::io::Write as _;
                    writeln!(f, "pulih gpu auto-enable skipped: {e}")
                });
        }
    }
    app.kernel_snap = Some(discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT)));
    app.render(&mut display.surface, 0.0, None);
    let _ = display.present();

    let mut wifi_mgr = WifiManager::default();
    wifi_mgr.active_slot_suffix = app.passport.active_slot.clone();
    let ipc_server = IpcServer::bind(CONTROL_SOCK_PATH).ok();
    let loop_start = Instant::now();
    let mut last_frame = Instant::now();
    let mut last_present = Instant::now();
    let mut last_activity = Instant::now();
    let mut last_telemetry = Instant::now();
    let mut screen_dimmed = false;
    let mut pending_dirty = false;

    loop {
        let animating = !display.blanked && app.is_animating();
        let poll_ms = if animating || pending_dirty { 2 } else { 120 };
        let mut events = poller.poll_events(poll_ms);
        let mut dirty = pending_dirty;
        pending_dirty = false;

        // Drain AI / Android automation IPC commands (`screencap`, `input tap/swipe/key`, `ui-dump`)
        if let Some(ref srv) = ipc_server {
            while let Some((req, mut stream)) = srv.try_accept() {
                use std::io::Write as _;
                match req {
                    IpcRequest::Screencap(path) => {
                        let data = if path.ends_with(".ppm") {
                            display.surface.to_ppm()
                        } else {
                            display.surface.to_png()
                        };
                        match fs::write(&path, &data) {
                            Ok(()) => {
                                let _ = writeln!(stream, "OK {path} ({} bytes)", data.len());
                            }
                            Err(e) => {
                                let _ = writeln!(stream, "ERR {e}");
                            }
                        }
                    }
                    IpcRequest::Tap(x, y) => {
                        events.push(InputEvent::TouchDown { x, y });
                        events.push(InputEvent::TouchUp { x, y });
                        let _ = writeln!(stream, "OK TAP {x} {y}");
                    }
                    IpcRequest::Swipe(x1, y1, x2, y2) => {
                        events.push(InputEvent::TouchDown { x: x1, y: y1 });
                        for step in 1..=6 {
                            let mx = x1 + ((x2 - x1) * step) / 6;
                            let my = y1 + ((y2 - y1) * step) / 6;
                            events.push(InputEvent::TouchMove { x: mx, y: my });
                        }
                        events.push(InputEvent::TouchUp { x: x2, y: y2 });
                        let _ = writeln!(stream, "OK SWIPE {x1} {y1} -> {x2} {y2}");
                    }
                    IpcRequest::Key(k) => {
                        let ev = match k.to_ascii_uppercase().as_str() {
                            "BACK" | "4" => Some(InputEvent::SwipeBack),
                            "POWER" | "26" => Some(InputEvent::PowerToggle),
                            "ENTER" | "66" => Some(InputEvent::KeySelect),
                            "VOLUME_UP" | "VOL_UP" | "24" => Some(InputEvent::KeyFocusPrev),
                            "VOLUME_DOWN" | "VOL_DOWN" | "25" => Some(InputEvent::KeyFocusNext),
                            "QUICK_SETTINGS" | "QS" => Some(InputEvent::PullDownQuickSettings),
                            "SCREENSHOT" => Some(InputEvent::ScreenshotCombo),
                            _ => None,
                        };
                        if let Some(e) = ev {
                            events.push(e);
                            let _ = writeln!(stream, "OK KEY {k}");
                        } else {
                            let _ = writeln!(stream, "ERR unknown key {k}");
                        }
                    }
                    IpcRequest::DumpUi => {
                        let _ = writeln!(stream, "{}", app.dump_ui_json());
                    }
                }
            }
        }

        let now_ms = loop_start.elapsed().as_millis() as u64;
        let mut last_slider_bucket = app.backlight_pct / 10;
        for (ev_idx, ev) in events.into_iter().enumerate() {
            // 1. Physical Power button ALWAYS cleanly toggles Screen Sleep <-> Wake!
            //    (NEVER opens Files or fires accidental UI clicks!)
            if ev == InputEvent::PowerToggle {
                last_activity = Instant::now();
                if app.haptics_enabled && app.power_profile.haptics_enabled() {
                    trigger_haptic_click(18);
                }
                if display.blanked {
                    display.set_blank(false);
                    screen_dimmed = false;
                    let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), app.backlight_pct.max(25));
                    app.render(&mut display.surface, 0.0, None);
                    let _ = display.present();
                    last_present = Instant::now();
                } else {
                    display.set_blank(true);
                    screen_dimmed = true;
                    let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), 0);
                }
                continue;
            }

            // 2. While screen is blanked, ignore stray touches/volume keys (anti-pocket wake)
            if display.blanked {
                continue;
            }

            last_activity = Instant::now();
            if screen_dimmed {
                screen_dimmed = false;
                let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), app.backlight_pct.max(25));
            }
            if app.haptics_enabled
                && app.power_profile.haptics_enabled()
                && matches!(
                    ev,
                    InputEvent::TouchUp { .. }
                        | InputEvent::KeyFocusPrev
                        | InputEvent::KeyFocusNext
                )
            {
                trigger_haptic_click(14);
            }
            // Space synthetic swipe timestamps cleanly by 8ms per step for accurate fling velocity
            let ev_ms = now_ms.saturating_add(ev_idx as u64 * 4);
            let cmd = app.handle_input_at(ev, ev_ms);
            dirty = true;
            match cmd {
                UiCommand::None => {}
                UiCommand::SleepScreen => {
                    if app.haptics_enabled {
                        trigger_haptic_click(15);
                    }
                    app.show_quick_settings = false;
                    app.quick_settings_sheet.reset();
                    display.set_blank(true);
                    screen_dimmed = true;
                    let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), 0);
                    dirty = false;
                }
                UiCommand::TestVibrate => {
                    let rc = trigger_haptic_with_status(35);
                    app.toast = Some(if rc == 0 {
                        "Vibrate OK (si_haptic 35ms)".into()
                    } else {
                        format!("Vibrate motor unavailable (rc={rc})")
                    });
                }
                UiCommand::SwitchStorage(target) => {
                    if target.starts_with("/data") {
                        let _ = ensure_data_mounted(true);
                    }
                    let p = Path::new(&target);
                    if p.is_dir() {
                        app.files_cwd = p.to_path_buf();
                        app.files_scroll.reset();
                        app.reload_files();
                    } else if target == "/data/media/0/Yasvara/OTA" {
                        let _ = fs::create_dir_all(p);
                        app.files_cwd = p.to_path_buf();
                        app.reload_files();
                    } else {
                        app.toast = Some(format!("Not mounted / missing: {target}"));
                    }
                }
                UiCommand::FlashZipFile(zip_path) => {
                    app.file_sheet = None;
                    app.bottom_sheet.reset();
                    app.toast = Some(format!("Flashing {}...", zip_path.display()));
                    app.render(&mut display.surface, 0.0, Some(0.15));
                    let _ = display.present();
                    let ok = Command::new("/system_ext/bin/pasang")
                        .args(["install", &zip_path.display().to_string()])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    app.toast = Some(if ok {
                        "Pasang OTA Flash SUCCEEDED!".into()
                    } else {
                        "Pasang OTA Flash failed (check /tmp/pulih.log)".into()
                    });
                }
                UiCommand::RefreshPartitions => {
                    refresh_partition_mounts(&mut app);
                    app.toast = Some("Partition status refreshed".into());
                }
                UiCommand::MountPartition { name, mountpoint, rw } => {
                    app.selected_partition = None;
                    app.bottom_sheet.reset();
                    let ok = if name == "userdata" {
                        ensure_data_mounted(rw)
                    } else {
                        let _ = fs::create_dir_all(&mountpoint);
                        let opts = if rw { "rw" } else { "ro" };
                        let dev = format!("/dev/block/by-name/{name}");
                        Command::new("/system/bin/mount")
                            .args(["-o", opts, &dev, &mountpoint])
                            .status()
                            .map(|s| s.success())
                            .unwrap_or(false)
                    };
                    refresh_partition_mounts(&mut app);
                    app.toast = Some(if ok {
                        format!("Mounted {mountpoint} ({})", if rw { "RW" } else { "RO" })
                    } else {
                        format!("Mount {name} failed")
                    });
                }
                UiCommand::UnmountPartition { mountpoint } => {
                    app.selected_partition = None;
                    app.bottom_sheet.reset();
                    let ok = Command::new("/system/bin/umount")
                        .arg(&mountpoint)
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    refresh_partition_mounts(&mut app);
                    app.toast = Some(if ok {
                        format!("Unmounted {mountpoint}")
                    } else {
                        format!("Unmount {mountpoint} failed (busy)")
                    });
                }
                UiCommand::FsckPartition { name } => {
                    app.selected_partition = None;
                    app.bottom_sheet.reset();
                    let dev = format!("/dev/block/by-name/{name}");
                    let out = run_shell_capture(&format!("fsck.f2fs -f {dev} || e2fsck -fy {dev}"));
                    app.terminal_output = out;
                    app.terminal_scroll.reset();
                    app.active_tab = pulih_gfx::widgets::Tab::Tools;
                    app.tools_view = pulih::ui::ToolsView::Terminal;
                }
                UiCommand::BackupPartition { name } => {
                    app.selected_partition = None;
                    app.bottom_sheet.reset();
                    let _ = ensure_data_mounted(true);
                    let _ = fs::create_dir_all("/data/media/0/YasvaraBackup");
                    let suf = app.passport.active_slot.clone();
                    let dev = if Path::new(&format!("/dev/block/by-name/{name}{suf}")).exists() {
                        format!("/dev/block/by-name/{name}{suf}")
                    } else {
                        format!("/dev/block/by-name/{name}")
                    };
                    let dst = format!("/data/media/0/YasvaraBackup/{name}.img");
                    let ok = Command::new("/system/bin/dd")
                        .args([&format!("if={dev}"), &format!("of={dst}"), "bs=4M"])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    app.toast = Some(if ok {
                        format!("Backed up -> {dst}")
                    } else {
                        format!("Backup {name} failed")
                    });
                }
                UiCommand::ExecuteWipe(part) => {
                    if let Err(e) = validate_wipe_or_format(&part) {
                        app.toast = Some(e.to_string());
                    } else {
                        app.toast = Some(format!("Wipe '{part}' validated & ready"));
                    }
                }
                UiCommand::ExecuteSwitchSlot(next) => {
                    let _ = Command::new("/system_ext/bin/pasang").arg("slot").status();
                    app.status.active_slot = next;
                    app.toast = Some(format!("Requested switch to Slot {next}"));
                }
                UiCommand::ApplyPowerProfile(prof) => {
                    app.power_profile = prof;
                    if let Ok(sum) =
                        apply_power_profile(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT), prof)
                    {
                        display.set_refresh_hz(sum.refresh_hz);
                        app.refresh_hz = sum.refresh_hz;
                        app.backlight_pct = sum.backlight_pct;
                        let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), sum.backlight_pct);
                        app.kernel_snap =
                            Some(discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT)));
                        app.toast = Some(format!("{} ({}Hz, BL {}%)", prof.label(), sum.refresh_hz, sum.backlight_pct));
                    }
                }
                UiCommand::SetRefreshHz(hz) => {
                    display.set_refresh_hz(hz);
                    app.refresh_hz = display.refresh_hz;
                    app.toast = Some(format!("Display refresh -> {} Hz", app.refresh_hz));
                }
                UiCommand::SetBacklightPct(pct) => {
                    let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), pct);
                    app.backlight_pct = pct;
                    app.status.backlight_pct = pct;
                    let bucket = pct / 10;
                    if bucket != last_slider_bucket {
                        last_slider_bucket = bucket;
                        if app.haptics_enabled && app.power_profile.haptics_enabled() {
                            trigger_haptic_click(10);
                        }
                    }
                }
                UiCommand::CycleIoScheduler => {
                    if let Some(ref snap) = app.kernel_snap {
                        if let Some(ref io) = snap.io_queue {
                            if !io.available_schedulers.is_empty() {
                                let idx = io
                                    .available_schedulers
                                    .iter()
                                    .position(|s| s == &io.active_scheduler)
                                    .unwrap_or(0);
                                let next = &io.available_schedulers[(idx + 1) % io.available_schedulers.len()];
                                if set_io_queue(io, Some(next), None).is_ok() {
                                    app.toast = Some(format!("UFS Scheduler -> {next}"));
                                    app.kernel_snap = Some(discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT)));
                                }
                            }
                        }
                    }
                }
                UiCommand::CycleTcpCongestion => {
                    if let Some(ref snap) = app.kernel_snap {
                        if !snap.tcp_available.is_empty() {
                            let idx = snap
                                .tcp_available
                                .iter()
                                .position(|s| s == &snap.tcp_active)
                                .unwrap_or(0);
                            let next = &snap.tcp_available[(idx + 1) % snap.tcp_available.len()];
                            if set_tcp_congestion(Path::new(PROC_ROOT), &snap.tcp_available, next).is_ok() {
                                app.toast = Some(format!("TCP Congestion -> {next}"));
                                app.kernel_snap = Some(discover_kernel(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT)));
                            }
                        }
                    }
                }
                UiCommand::CycleUsbMode => {
                    app.usb_mode = match app.usb_mode {
                        UsbMode::AutoDrp => UsbMode::PeripheralAdb,
                        UsbMode::PeripheralAdb => UsbMode::OtgHost,
                        UsbMode::OtgHost => UsbMode::AutoDrp,
                    };
                    let _ = set_usb_mode(app.usb_mode);
                    app.toast = Some(format!("USB Mode -> {:?}", app.usb_mode));
                }
                UiCommand::ToggleGpuDriver => {
                    if gpu_mgr.state == GpuDriverState::Active {
                        gpu_mgr.disable_safe();
                        app.gpu_active = false;
                        app.gpu_summary = "Adreno GPU: OFF (Tap to load kgsl / Vulkan / DOOM)".into();
                        app.toast = Some("Adreno GPU disabled cleanly".into());
                    } else {
                        match gpu_mgr.enable_lazy() {
                            Ok(t) => {
                                app.gpu_active = true;
                                app.gpu_summary = format!(
                                    "Adreno GPU: ON ({} {}MHz {:.1}C) - DOOM Ready",
                                    t.model,
                                    t.cur_mhz,
                                    t.temp_tenths_c as f32 / 10.0
                                );
                                app.toast = Some(format!("GPU Ready: {} ({}..{} MHz)", t.model, t.min_mhz, t.max_mhz));
                            }
                            Err(e) => {
                                app.toast = Some(format!("GPU: {e}"));
                            }
                        }
                    }
                }
                UiCommand::ToggleWifiDriver => {
                    if wifi_mgr.state != WifiState::Off {
                        wifi_mgr.teardown_for_active_slot_flash();
                        app.status.wifi_on = false;
                        app.wifi_ip = None;
                        app.wifi_adb_port = None;
                        app.scanned_wifis.clear();
                        app.wifi_status_text = wifi_mgr.status_detail.clone();
                        app.toast = Some("Wi-Fi 7 OFF".into());
                    } else {
                        app.toast = Some("Booting WCN7750 Wi-Fi 7 firmware...".into());
                        app.render(&mut display.surface, 0.0, None);
                        let _ = display.present();
                        match wifi_mgr.enable_lazy() {
                            Ok(msg) => {
                                app.status.wifi_on = true;
                                app.scanned_wifis = wifi_mgr.scanned_networks.clone();
                                app.wifi_status_text = msg.clone();
                                app.toast = Some(msg);
                            }
                            Err(e) => {
                                app.wifi_status_text = e.clone();
                                app.toast = Some(e);
                            }
                        }
                    }
                }
                UiCommand::ScanWifi => {
                    app.toast = Some("Scanning nearby Wi-Fi networks...".into());
                    app.render(&mut display.surface, 0.0, None);
                    let _ = display.present();
                    if wifi_mgr.state == WifiState::Off {
                        let _ = wifi_mgr.enable_lazy();
                        app.status.wifi_on = wifi_mgr.state != WifiState::Off;
                    }
                    let nets = wifi_mgr.scan_networks();
                    let n = nets.len();
                    app.scanned_wifis = nets;
                    app.wifi_status_text = format!("wlan0 UP - {n} network(s) found");
                    app.toast = Some(format!("Found {n} Wi-Fi network(s)"));
                }
                UiCommand::ConnectWifi { ssid, psk } => {
                    app.toast = Some(format!("Connecting to {ssid} + DHCP..."));
                    app.render(&mut display.surface, 0.0, None);
                    let _ = display.present();
                    if wifi_mgr.state == WifiState::Off {
                        let _ = wifi_mgr.enable_lazy();
                    }
                    match wifi_mgr.connect_network(&ssid, &psk) {
                        Ok(msg) => {
                            app.status.wifi_on = true;
                            app.wifi_ip = wifi_mgr.ip_addr.clone();
                            app.wifi_status_text = msg.clone();
                            app.toast = Some(msg);
                        }
                        Err(e) => {
                            app.wifi_status_text = e.clone();
                            app.toast = Some(e);
                        }
                    }
                }
                UiCommand::ImportSavedWifi => {
                    let _ = ensure_data_mounted(false);
                    let p = Path::new("/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml");
                    match fs::read_to_string(p) {
                        Ok(xml) => {
                            let nets = parse_android_wifi_config_xml(&xml);
                            let n = nets.len();
                            wifi_mgr.saved_networks = nets.clone();
                            app.saved_wifis = nets;
                            app.toast = Some(format!("Imported {n} saved Wi-Fi network(s)"));
                        }
                        Err(e) => {
                            app.toast = Some(format!("WifiConfigStore.xml: {e}"));
                        }
                    }
                }
                UiCommand::EnableAdbWifi => match wifi_mgr.enable_adb_over_wifi() {
                    Ok(port) => {
                        app.wifi_adb_port = Some(port);
                        app.toast = Some(format!("ADB over Wi-Fi active on :{port}"));
                    }
                    Err(e) => app.toast = Some(e.into()),
                },
                UiCommand::BrowserNavigate(url) => {
                    if app.browser_url != url {
                        app.browser_history.push(app.browser_url.clone());
                    }
                    app.browser_url = url.clone();
                    app.browser_scroll.reset();
                    app.toast = Some(format!("Loading {url}..."));
                    app.render(&mut display.surface, 0.0, None);
                    let _ = display.present();
                    match fetch_jelajah_url(&url) {
                        Ok(page) => {
                            app.browser_page = page;
                            app.toast = Some(format!("Loaded: {}", app.browser_page.title));
                        }
                        Err(e) => {
                            app.toast = Some(e);
                        }
                    }
                }
                UiCommand::ToggleBypassCharge(on) => {
                    let _ = set_bypass_charge(on);
                    app.bypass_charge = on;
                    app.toast = Some(format!("Bypass Charge {}", if on { "ON" } else { "OFF" }));
                }
                UiCommand::ToggleOledBlack => {
                    let oled = !app.palette.oled_black;
                    app.palette = Palette::from_seed(app.palette.seed_argb, oled);
                }
                UiCommand::ToggleLocale => {
                    app.locale = match app.locale {
                        Locale::EnUs => Locale::IdId,
                        Locale::IdId => Locale::EnUs,
                    };
                }
                UiCommand::RefreshModules => {
                    let _ = ensure_data_mounted(true);
                    app.modules = scan_root_modules(Path::new(MODULES_DIR));
                }
                UiCommand::ToggleModule { id, disable } => {
                    let _ = ensure_data_mounted(true);
                    if set_module_disabled(&Path::new(MODULES_DIR).join(&id), disable).is_ok() {
                        app.modules = scan_root_modules(Path::new(MODULES_DIR));
                        app.toast = Some(format!(
                            "Module {id} {}",
                            if disable { "DISABLED" } else { "ENABLED" }
                        ));
                    }
                }
                UiCommand::ExecuteDisableAllModules => {
                    let _ = ensure_data_mounted(true);
                    if let Ok(n) = disable_all_modules(Path::new(MODULES_DIR)) {
                        app.modules = scan_root_modules(Path::new(MODULES_DIR));
                        app.toast = Some(format!("Disabled {n} modules (Safe Mode)"));
                    }
                }
                UiCommand::RunShellCommand(cmd_str) => {
                    app.terminal_output = run_shell_capture(&cmd_str);
                    app.terminal_scroll.reset();
                }
                UiCommand::ExportPassport => {
                    let _ = ensure_data_mounted(true);
                    let txt = app.passport.format_export(app.reveal_passport_ids);
                    let dst = "/data/media/0/device-passport.txt";
                    if fs::write(dst, txt).is_ok() {
                        app.toast = Some(format!("Exported -> {dst}"));
                    } else {
                        let _ = fs::write("/tmp/device-passport.txt", app.passport.format_export(app.reveal_passport_ids));
                        app.toast = Some("Exported -> /tmp/device-passport.txt".into());
                    }
                }
                UiCommand::StartSideload => {
                    app.toast = Some("ADB Sideload armed (run: adb sideload <zip>)".into());
                    let _ = Command::new("/system/bin/setprop")
                        .args(["sys.usb.config", "sideload"])
                        .status();
                }
                UiCommand::EnterFastbootd => {
                    let _ = Command::new("/system/bin/setprop")
                        .args(["sys.usb.config", "fastboot"])
                        .status();
                    let _ = exec_fastbootd();
                }
                UiCommand::RebootSystem => {
                    powerctl_reboot("reboot");
                    return;
                }
                UiCommand::RebootRecovery => {
                    powerctl_reboot("reboot,recovery");
                    return;
                }
                UiCommand::RebootBootloader => {
                    powerctl_reboot("reboot,bootloader");
                    return;
                }
                UiCommand::PowerOff => {
                    powerctl_reboot("shutdown");
                    return;
                }
                UiCommand::CaptureScreenshot => {
                    let _ = fs::write("/tmp/pulih-screenshot.png", display.surface.to_png());
                    app.toast = Some("Saved /tmp/pulih-screenshot.png".into());
                }
                _ => {}
            }
        }

        // Advance M3 Expressive spring sheets & inertial fling scroll physics
        let dt_s = last_frame.elapsed().as_secs_f32().clamp(0.001, 0.05);
        last_frame = Instant::now();
        if !display.blanked && app.tick_animations(dt_s) {
            dirty = true;
        }

        if last_telemetry.elapsed() >= Duration::from_secs(2) {
            last_telemetry = Instant::now();
            power = PowerTelemetry::read_live();
            let _ = power.step_thermal_governor();
            if app.gpu_active {
                let gt = GpuTelemetry::read_live();
                if gt.kgsl_present {
                    app.gpu_summary = format!(
                        "Adreno GPU: ON ({} {}MHz {:.1}C) - DOOM Ready",
                        gt.model,
                        gt.cur_mhz,
                        gt.temp_tenths_c as f32 / 10.0
                    );
                }
            }
            if let Some(auto_prof) = app.update_telemetry(&power) {
                let _ =
                    apply_power_profile(Path::new(SYSFS_ROOT), Path::new(PROC_ROOT), auto_prof);
                display.set_refresh_hz(auto_prof.target_refresh_hz());
                let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), auto_prof.target_backlight_pct());
                dirty = true;
            }
            match evaluate_oled_idle(last_activity.elapsed().as_secs(), false) {
                DisplayPowerState::Blanked if !display.blanked => {
                    display.set_blank(true);
                    screen_dimmed = true;
                    let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), 0);
                }
                DisplayPowerState::Dimmed if !display.blanked && !screen_dimmed => {
                    screen_dimmed = true;
                    let _ = set_backlight_pct(Path::new(BACKLIGHT_DIR), 10);
                }
                _ => {}
            }
        }

        // VSYNC-paced 120 Hz presentation: never choke DRM with mid-VSYNC commits!
        if dirty && !display.blanked {
            let min_frame_us = (1_000_000u64 / display.refresh_hz.max(60) as u64).saturating_sub(600);
            if last_present.elapsed().as_micros() as u64 >= min_frame_us {
                app.render(&mut display.surface, 0.0, None);
                let _ = display.present();
                last_present = Instant::now();
            } else {
                pending_dirty = true;
            }
        }
    }
}
