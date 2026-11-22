// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Standalone CLI for Padat (`padat status|scan|compress|decompress|release|policy|stats`).

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use padat::engine::{self, RootPaths, RunControl};
use padat::policy::{CompAlgo, CompProfile, PackagePolicy, Policy, Preset, Scopes, DEFAULT_POLICY_PATH};

fn usage() {
    eprintln!(
        "Usage: padat <command> [args]\n\
         \n\
         Commands:\n\
           status\n\
           scan <pkg> [--algo lz4|lz4hc|zstd] [--level N] [--cluster 16k|32k|64k|128k] [--full]\n\
           compress <pkg> [--algo lz4|lz4hc|zstd] [--level N] [--cluster 16k|32k|64k|128k] [--full|--tier1|--all] [--force-running]\n\
           decompress <pkg> [--full|--tier1|--all] [--force-running]\n\
           release <path>\n\
           policy get | set <pkg> <off|fast|balanced|max|custom> [--algo ...] [--level N] [--cluster ...] [--full|--tier1]\n\
           stats [<pkg>]\n\
           cleanup <dir>"
    );
}

fn parse_cluster_kb(s: &str) -> Option<u16> {
    let t = s.trim().to_ascii_lowercase();
    let num = t.strip_suffix('k').or_else(|| t.strip_suffix("kb")).unwrap_or(&t);
    num.parse().ok()
}

fn parse_opts(args: &[String]) -> (CompProfile, Scopes, bool) {
    let mut prof = CompProfile::FAST;
    let mut scopes = Scopes::TIER1_ONLY;
    let mut allow_running = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--algo" if i + 1 < args.len() => {
                if let Some(a) = CompAlgo::from_str(&args[i + 1]) {
                    prof.algo = a;
                }
                i += 2;
            }
            "--level" if i + 1 < args.len() => {
                if let Ok(l) = args[i + 1].parse::<u8>() {
                    prof.level = l;
                }
                i += 2;
            }
            "--cluster" if i + 1 < args.len() => {
                if let Some(kb) = parse_cluster_kb(&args[i + 1]) {
                    prof.cluster_kb = kb;
                }
                i += 2;
            }
            "--preset" if i + 1 < args.len() => {
                match Preset::from_str(&args[i + 1]) {
                    Some(Preset::Fast) => prof = CompProfile::FAST,
                    Some(Preset::Balanced) => prof = CompProfile::BALANCED,
                    Some(Preset::Max) => prof = CompProfile::MAX,
                    _ => {}
                }
                i += 2;
            }
            "--tier1" => {
                scopes = Scopes::TIER1_ONLY;
                i += 1;
            }
            "--full" => {
                scopes = Scopes::FULL_APP;
                i += 1;
            }
            "--all" => {
                scopes = Scopes {
                    apk_lib: true,
                    art_oat: true,
                    external_data: true,
                    obb: true,
                    internal_files: true,
                };
                i += 1;
            }
            "--force-running" => {
                allow_running = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    (prof.normalized(), scopes, allow_running)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return ExitCode::from(2);
    }

    let roots = RootPaths::default();
    let pol_path = Path::new(DEFAULT_POLICY_PATH);
    let cancel = AtomicBool::new(false);
    let paused = AtomicBool::new(false);
    let progress = engine::JobProgress::new();

    match args[0].as_str() {
        "status" => {
            println!("{}", engine::status_json(false, &progress));
            ExitCode::SUCCESS
        }
        "scan" => {
            if args.len() < 2 {
                usage();
                return ExitCode::from(2);
            }
            let pkg = &args[1];
            let pol = Policy::load(pol_path);
            let (prof, scopes, _) = parse_opts(&args[2..]);
            let st = engine::scan_package(&roots, pkg, prof, scopes, &pol);
            println!("{}", st.to_json());
            ExitCode::SUCCESS
        }
        "compress" => {
            if args.len() < 2 {
                usage();
                return ExitCode::from(2);
            }
            let pkg = &args[1];
            let pol = Policy::load(pol_path);
            let (prof, scopes, allow_running) = parse_opts(&args[2..]);
            let ctl = RunControl {
                cancel: &cancel,
                paused: &paused,
                allow_running,
                thermal_pause_mc: pol.thermal_pause_mc,
                progress: None,
            };
            let rep = engine::compress_package(&roots, pkg, prof, scopes, &pol, &ctl);
            println!("{}", rep.to_json());
            if rep.refused_running || rep.errors > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        "decompress" => {
            if args.len() < 2 {
                usage();
                return ExitCode::from(2);
            }
            let pkg = &args[1];
            let pol = Policy::load(pol_path);
            let (_, scopes, allow_running) = parse_opts(&args[2..]);
            let ctl = RunControl {
                cancel: &cancel,
                paused: &paused,
                allow_running,
                thermal_pause_mc: pol.thermal_pause_mc,
                progress: None,
            };
            let rep = engine::decompress_package(&roots, pkg, scopes, &ctl);
            println!("{}", rep.to_json());
            ExitCode::SUCCESS
        }
        "release" => {
            if args.len() < 2 {
                usage();
                return ExitCode::from(2);
            }
            let rep = engine::release_path(Path::new(&args[1]));
            println!("{}", rep.to_json());
            ExitCode::SUCCESS
        }
        "policy" => {
            if args.get(1).map(String::as_str) == Some("get") {
                let pol = Policy::load(pol_path);
                print!("{}", pol.to_json());
                return ExitCode::SUCCESS;
            }
            if args.get(1).map(String::as_str) == Some("set") && args.len() >= 4 {
                let pkg = args[2].clone();
                let Some(preset) = Preset::from_str(&args[3]) else {
                    eprintln!("invalid preset: {}", args[3]);
                    return ExitCode::from(2);
                };
                let (mut prof, scopes, _) = parse_opts(&args[4..]);
                prof = match preset {
                    Preset::Fast => CompProfile::FAST,
                    Preset::Balanced => CompProfile::BALANCED,
                    Preset::Max => CompProfile::MAX,
                    _ => prof,
                };
                let mut pol = Policy::load(pol_path);
                pol.packages.insert(
                    pkg,
                    PackagePolicy {
                        preset,
                        profile: prof,
                        scopes,
                    },
                );
                if let Err(e) = pol.save_atomic(pol_path) {
                    eprintln!("save policy failed: {e}");
                    return ExitCode::from(1);
                }
                print!("{}", pol.to_json());
                return ExitCode::SUCCESS;
            }
            usage();
            ExitCode::from(2)
        }
        "stats" => {
            let pol = Policy::load(pol_path);
            if let Some(pkg) = args.get(1) {
                let (prof, scopes) = pol
                    .resolve_for_package(pkg)
                    .unwrap_or((CompProfile::FAST, Scopes::FULL_APP));
                let st = engine::scan_package(&roots, pkg, prof, scopes, &pol);
                println!("{}", st.to_json());
            } else {
                let all = engine::stat_all_packages_parallel(&roots);
                let mut total_logical = 0u64;
                let mut total_phys = 0u64;
                let mut total_saved = 0u64;
                let mut total_compr = 0u64;
                for st in &all {
                    total_logical += st.logical_bytes;
                    total_phys += st.physical_bytes;
                    total_saved += st.saved_bytes;
                    total_compr += st.compressed_files;
                }
                println!(
                    "{{\"packages\":{},\"total_logical_bytes\":{},\"total_physical_bytes\":{},\"total_saved_bytes\":{},\"compressed_files\":{}}}",
                    all.len(),
                    total_logical,
                    total_phys,
                    total_saved,
                    total_compr,
                );
            }
            ExitCode::SUCCESS
        }
        "cleanup" => {
            if args.len() < 2 {
                usage();
                return ExitCode::from(2);
            }
            let n = engine::cleanup_stale_temps(Path::new(&args[1]));
            println!("{{\"removed\":{n}}}");
            ExitCode::SUCCESS
        }
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}
