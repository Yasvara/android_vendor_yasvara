// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Standalone operator & `yv ota push` CLI (`/system_ext/bin/pasang`).

use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::Mutex;

use pasang_core::cow_ota::{run_ota, OtaEnvironment, OtaProgress};
use pasang_core::crypto::hex_encode;
use pasang_core::ffi::build_slot_info_json;
use pasang_core::overlay::{clean_overlays, inspect_overlays, DEFAULT_OVERLAY_ROOT, DEFAULT_PROC_MOUNTS};
use pasang_core::payload::parse_payload;
use pasang_core::slot::{
    write_recovery_theme_atomic, BootControlOps, OtaOptions, RecoveryThemeSeed,
    DEFAULT_RECOVERY_THEME_PATH,
};

const HELP: &str = r#"pasang -- Yasvara Live CoW OTA & Recovery Bridge CLI

USAGE:
  pasang slot
  pasang inspect <ota.zip|payload.bin>
  pasang plan [--no-alias] [--allow-dev-key] <ota.zip|payload.bin>
  pasang apply [--clean-overlay] [--keep-overlay] [--fast-verify] [--allow-dev-key] [--no-alias] [--dry-run] <ota.zip|payload.bin>
  pasang overlay status | clean
  pasang theme write <argb_hex> <oled_black:0|1> [locale]
"#;

/// Lightweight CLI BootControl implementation backed by `/system/bin/bootctl` / `getprop`.
struct CliBootControl;

impl CliBootControl {
    fn bootctl(args: &[&str]) -> Result<String, String> {
        let out = Command::new("bootctl")
            .args(args)
            .output()
            .map_err(|e| format!("exec bootctl {:?}: {e}", args))?;
        if !out.status.success() {
            return Err(format!(
                "bootctl {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

impl BootControlOps for CliBootControl {
    fn current_slot(&self) -> Result<u32, String> {
        if let Ok(s) = Self::bootctl(&["get-current-slot"]) {
            if let Ok(n) = s.parse::<u32>() {
                return Ok(n);
            }
        }
        if let Ok(cmd) = std::fs::read_to_string("/proc/cmdline") {
            if cmd.contains("slot_suffix=_b") {
                return Ok(1);
            }
            if cmd.contains("slot_suffix=_a") {
                return Ok(0);
            }
        }
        Err("Cannot determine current A/B slot".into())
    }

    fn active_boot_slot(&self) -> Result<u32, String> {
        Self::bootctl(&["get-active-boot-slot"])
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Ok)
            .unwrap_or_else(|| self.current_slot())
    }

    fn is_slot_bootable(&self, slot: u32) -> Result<bool, String> {
        Ok(Self::bootctl(&["is-slot-bootable", &slot.to_string()]).is_ok())
    }

    fn is_slot_successful(&self, slot: u32) -> Result<bool, String> {
        Ok(Self::bootctl(&["is-slot-marked-successful", &slot.to_string()]).is_ok())
    }

    fn set_active_boot_slot(&self, slot: u32) -> Result<(), String> {
        Self::bootctl(&["set-active-boot-slot", &slot.to_string()]).map(|_| ())
    }

    fn mark_boot_successful(&self) -> Result<(), String> {
        Self::bootctl(&["mark-boot-successful"]).map(|_| ())
    }

    fn snapshot_merge_status(&self) -> String {
        Self::bootctl(&["get-snapshot-merge-status"]).unwrap_or_else(|_| "none".into())
    }
}

fn cmd_inspect(path: &Path) -> i32 {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: open {}: {e}", path.display());
            return 1;
        }
    };
    let manifest = match parse_payload(&mut f) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    println!(
        "CrAU v{}  block_size={}  minor={}  data_offset={}  sigs={}  meta_sha256={}",
        manifest.version,
        manifest.block_size,
        manifest.minor_version,
        manifest.data_blob_offset,
        manifest.metadata_signatures.len(),
        &hex_encode(&manifest.metadata_sha256)[..16]
    );
    println!(
        "dynamic: snapshot={} vabc={} comp={} cow_v={}",
        manifest.dynamic_metadata.snapshot_enabled,
        manifest.dynamic_metadata.vabc_enabled,
        manifest.dynamic_metadata.vabc_compression,
        manifest.dynamic_metadata.cow_version
    );
    println!(
        "{:<20} {:>10} {:>10} {:>6}  {:>7}  ops",
        "PARTITION", "SIZE MiB", "BLOB MiB", "OPS", "CLASS"
    );
    let mut total_sz = 0u64;
    let mut total_blob = 0u64;
    for p in &manifest.partitions {
        let sz = p.new_info.size;
        let blob = p.payload_bytes();
        total_sz += sz;
        total_blob += blob;
        let cls = if manifest.dynamic_metadata.is_dynamic(&p.name) {
            "dynamic"
        } else {
            "raw"
        };
        let mut by_type: BTreeMap<&str, usize> = BTreeMap::new();
        for o in &p.operations {
            *by_type.entry(o.op_type.as_str()).or_insert(0) += 1;
        }
        let ops_s: Vec<String> = by_type.iter().map(|(k, v)| format!("{k}:{v}")).collect();
        println!(
            "{:<20} {:>10.1} {:>10.1} {:>6}  {:>7}  {}",
            p.name,
            sz as f64 / (1024.0 * 1024.0),
            blob as f64 / (1024.0 * 1024.0),
            p.operations.len(),
            cls,
            ops_s.join(",")
        );
    }
    println!(
        "TOTAL: {} partitions, {:.1} MiB logical, {:.1} MiB payload",
        manifest.partitions.len(),
        total_sz as f64 / (1024.0 * 1024.0),
        total_blob as f64 / (1024.0 * 1024.0)
    );
    0
}

fn parse_ota_args(args: &[String], force_dry_run: bool) -> Result<(PathBuf, OtaOptions), String> {
    let mut opts = OtaOptions {
        dry_run: force_dry_run,
        ..Default::default()
    };
    let mut path = None;
    for a in args {
        match a.as_str() {
            "--clean-overlay" => opts.clean_overlay = true,
            "--keep-overlay" => opts.keep_overlay = true,
            "--fast-verify" => opts.fast_verify = true,
            "--allow-dev-key" => opts.allow_dev_key = true,
            "--no-alias" => opts.enable_extent_aliasing = false,
            "--dry-run" => opts.dry_run = true,
            s if s.starts_with('-') => return Err(format!("Unknown flag: {s}")),
            s => path = Some(PathBuf::from(s)),
        }
    }
    let path = path.ok_or_else(|| "Missing <ota.zip|payload.bin> path".to_string())?;
    Ok((path, opts))
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print!("{HELP}");
        return;
    }

    let rc = match args[0].as_str() {
        "slot" | "status" => {
            let env = OtaEnvironment::android_default();
            println!("{}", build_slot_info_json(&env, &CliBootControl));
            0
        }
        "inspect" => match args.get(1) {
            Some(p) => cmd_inspect(Path::new(p)),
            None => {
                eprintln!("usage: pasang inspect <ota.zip|payload.bin>");
                2
            }
        },
        "plan" => match parse_ota_args(&args[1..], true) {
            Ok((p, opts)) => {
                let env = OtaEnvironment::android_default();
                match run_ota(&env, &CliBootControl, &p, &opts, None, None) {
                    Ok(r) => {
                        println!("{}", r.plan.to_json());
                        0
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        1
                    }
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
        },
        "apply" => match parse_ota_args(&args[1..], false) {
            Ok((p, opts)) => {
                let env = OtaEnvironment::android_default();
                let prog = Mutex::new(OtaProgress::default());
                match run_ota(&env, &CliBootControl, &p, &opts, Some(&prog), None) {
                    Ok(r) => {
                        println!(
                            "{{\"ok\":true,\"committed_slot\":{},\"elapsed_ms\":{},\"bytes_written\":{},\"plan\":{}}}",
                            r.committed_slot,
                            r.elapsed_ms,
                            r.bytes_written,
                            r.plan.to_json()
                        );
                        0
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        1
                    }
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
        },
        "overlay" => match args.get(1).map(|s| s.as_str()) {
            Some("status") | None => {
                let st = inspect_overlays(
                    Path::new(DEFAULT_PROC_MOUNTS),
                    Path::new(DEFAULT_OVERLAY_ROOT),
                );
                println!("{}", st.to_json());
                0
            }
            Some("clean") => {
                let rep = clean_overlays(Path::new(DEFAULT_OVERLAY_ROOT), None);
                println!("{}", rep.to_json());
                if rep.errors.is_empty() { 0 } else { 1 }
            }
            Some(other) => {
                eprintln!("Unknown overlay subcommand: {other}");
                2
            }
        },
        "theme" => match args.get(1).map(|s| s.as_str()) {
            Some("write") if args.len() >= 4 => {
                let hex = args[2].trim_start_matches("0x").trim_start_matches('#');
                let argb = u32::from_str_radix(hex, 16).unwrap_or(0xFF6750A4);
                let oled = args[3] == "1" || args[3] == "true";
                let locale = args.get(4).map(|s| s.as_str()).unwrap_or("en_US");
                let seed = RecoveryThemeSeed::new(argb, oled, locale);
                match write_recovery_theme_atomic(Path::new(DEFAULT_RECOVERY_THEME_PATH), &seed) {
                    Ok(()) => {
                        println!("wrote {DEFAULT_RECOVERY_THEME_PATH} (seed=0x{argb:08X} oled={oled} locale={locale})");
                        0
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        1
                    }
                }
            }
            _ => {
                eprintln!("usage: pasang theme write <argb_hex> <oled_black:0|1> [locale]");
                2
            }
        },
        other => {
            eprintln!("Unknown command: {other}\n{HELP}");
            2
        }
    };
    process::exit(rc);
}
