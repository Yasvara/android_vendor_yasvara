// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Full Akar Module Engine: ZIP installation (`customize.sh`, legacy `install.sh`, `REMOVE`,
//! `REPLACE`, `SKIPUNZIP`, `MODULE_HOT_INSTALL_REQUEST`), lifecycle stages (`post-fs-data`,
//! `services`, `boot-completed`), bounded script timeouts, `action.sh`, `module_config`,
//! `unmount.set`, and `zygisk.set` publishing.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use yasvara_root_proto::module_config::ModuleConfig;
use yasvara_root_proto::modules::{modules_to_json, validate_module_id, ModuleInfo, ModuleProp};
use yasvara_root_proto::mounts::{
    MountsSet, UnmountSet, ZygiskModuleEntry, ZygiskSet, SCOPE_ALL_NON_DENYLIST,
    SCOPE_EXPLICIT_ONLY,
};
use yasvara_root_proto::zip::ZipArchive;

use crate::{bootguard, compat_ns, mount, resetprop, sepolicy, sys};

const SCRIPT_PER_TIMEOUT: Duration = Duration::from_secs(10);
const SCRIPT_STAGE_BUDGET: Duration = Duration::from_secs(35);

pub fn modules_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("modules")
}

pub fn modules_update_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("modules_update")
}

pub fn module_config_dir(data_dir: &Path, id: &str) -> PathBuf {
    data_dir.join("config").join(id)
}

/// Master switch for the Akar Module Engine (`<data_dir>/modules.conf`).
/// Default is `false` (zero overhead: zero mounts, zero scripts, zero sepolicy reload,
/// zero Zygisk) until the user enables it in Laras or installs a module.
pub fn is_module_engine_enabled(data_dir: &Path) -> bool {
    let Ok(text) = fs::read_to_string(data_dir.join("modules.conf")) else {
        return false;
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "enabled" {
                return matches!(v.trim(), "1" | "true");
            }
        }
    }
    false
}

pub fn set_module_engine_enabled(data_dir: &Path, enabled: bool) -> io::Result<()> {
    let content = format!("# yasvara-modules v1\nenabled={}\n", if enabled { 1 } else { 0 });
    sys::replace_file(&data_dir.join("modules.conf"), content.as_bytes())
}

/// True only when BOTH Module Engine and Native Zygisk are enabled.
pub fn is_zygisk_enabled(data_dir: &Path) -> bool {
    if !is_module_engine_enabled(data_dir) {
        return false;
    }
    let Ok(text) = fs::read_to_string(data_dir.join("zygisk.conf")) else {
        return false;
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "enabled" {
                return matches!(v.trim(), "1" | "true");
            }
        }
    }
    false
}

/// Removes all Zygote projection sets for modules/Zygisk so Zygote pays zero overhead when off.
pub fn clear_runtime_sets(data_dir: &Path) {
    let _ = fs::remove_file(data_dir.join("mounts.set"));
    let _ = fs::remove_file(data_dir.join("unmount.set"));
    let _ = fs::remove_file(data_dir.join("zygisk.set"));
}

pub fn load_module_config(data_dir: &Path, id: &str) -> ModuleConfig {
    let dir = module_config_dir(data_dir, id);
    let persist = fs::read(dir.join("persist.config"))
        .ok()
        .and_then(|b| ModuleConfig::decode(&b).ok())
        .unwrap_or_default();
    let tmp = fs::read(dir.join("tmp.config"))
        .ok()
        .and_then(|b| ModuleConfig::decode(&b).ok())
        .unwrap_or_default();
    persist.merge_overlay(&tmp)
}

pub fn save_module_config_key(
    data_dir: &Path,
    id: &str,
    key: &str,
    val: Option<&str>,
    temp: bool,
) -> io::Result<()> {
    if !validate_module_id(id) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid module id"));
    }
    let dir = module_config_dir(data_dir, id);
    fs::create_dir_all(&dir)?;
    let path = dir.join(if temp { "tmp.config" } else { "persist.config" });
    let mut cfg = fs::read(&path)
        .ok()
        .and_then(|b| ModuleConfig::decode(&b).ok())
        .unwrap_or_default();
    match val {
        Some(v) => cfg.set(key, v).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        None => {
            cfg.delete(key);
        }
    }
    sys::replace_file(&path, &cfg.encode())
}

fn dir_size_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    for ent in rd.flatten() {
        let p = ent.path();
        if let Ok(m) = fs::symlink_metadata(&p) {
            if m.is_dir() {
                total = total.saturating_add(dir_size_bytes(&p));
            } else {
                total = total.saturating_add(m.len());
            }
        }
    }
    total
}

/// Lists all installed modules (sorted by ID) with live status flags and effective config.
pub fn list_modules(data_dir: &Path) -> Vec<ModuleInfo> {
    let mut out = Vec::new();
    let root = modules_dir(data_dir);
    let Ok(rd) = fs::read_dir(&root) else { return out };
    let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();

    for dir in dirs {
        let Ok(raw_prop) = fs::read_to_string(dir.join("module.prop")) else { continue };
        let Ok(prop) = ModuleProp::parse(&raw_prop) else { continue };
        let cfg = load_module_config(data_dir, &prop.id);

        let mut zygisk_abis = Vec::new();
        let zdir = dir.join("zygisk");
        for abi in ["arm64-v8a", "armeabi-v7a"] {
            if zdir.join(format!("{abi}.so")).is_file() {
                zygisk_abis.push(abi.to_string());
            }
        }

        let has_system_files = mount::PARTITIONS.iter().any(|p| dir.join(p).is_dir());
        let mount_strategy = if prop.metamodule {
            "metamodule".to_string()
        } else if dir.join("skip_mount").exists() || !has_system_files {
            "none".to_string()
        } else {
            "overlay".to_string()
        };

        out.push(ModuleInfo {
            enabled: !dir.join("disable").exists(),
            remove: dir.join("remove").exists(),
            update: modules_update_dir(data_dir).join(&prop.id).is_dir() || dir.join("update").exists(),
            has_webroot: dir.join("webroot/index.html").is_file(),
            has_action: dir.join("action.sh").is_file(),
            has_zygisk: !zygisk_abis.is_empty(),
            zygisk_abis,
            config_description: cfg.override_description().map(String::from),
            managed_features: cfg.managed_features(),
            mount_strategy,
            size_bytes: dir_size_bytes(&dir),
            prop,
        });
    }
    out
}

/// Returns enabled module directories in deterministic alphabetical order.
fn enabled_module_dirs(data_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(modules_dir(data_dir)) else { return out };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir()
            && p.join("module.prop").is_file()
            && !p.join("disable").exists()
            && !p.join("remove").exists()
        {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// Finds an enabled module declaring `metamodule=1`, if any.
fn find_active_metamodule(data_dir: &Path) -> Option<PathBuf> {
    for dir in enabled_module_dirs(data_dir) {
        if let Ok(raw) = fs::read_to_string(dir.join("module.prop")) {
            if let Ok(prop) = ModuleProp::parse(&raw) {
                if prop.metamodule {
                    return Some(dir);
                }
            }
        }
    }
    None
}

/// Runs a shell script inside the private `/data/adb` compat namespace with a strict timeout.
fn run_script_bounded(
    data_dir: &Path,
    script: &Path,
    extra_env: &[(&str, &str)],
    timeout: Duration,
    unprivileged_test: bool,
) -> io::Result<(i32, String)> {
    let sh = if Path::new("/system/bin/sh").exists() { "/system/bin/sh" } else { "/bin/sh" };
    let mut cmd = Command::new(sh);
    cmd.arg(script);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    for (k, v) in compat_ns::compat_env(data_dir, unprivileged_test) {
        cmd.env(k, v);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if let Some(parent) = script.parent() {
        cmd.current_dir(parent);
    }
    // Enter private /data/adb compat namespace inside the child right before exec.
    if !unprivileged_test {
        let dd = data_dir.to_path_buf();
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(move || compat_ns::enter_compat_adb_namespace(&dd, false));
        }
    }
    let mut child = cmd.spawn()?;
    let start = Instant::now();
    loop {
        if let Some(st) = child.try_wait()? {
            let output = child.wait_with_output()?;
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            let err = String::from_utf8_lossy(&output.stderr);
            if !err.is_empty() {
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&err);
            }
            return Ok((st.code().unwrap_or(1), text));
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((124, format!("script timed out after {}s", timeout.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Runs a stage's scripts (`post-fs-data.sh`, `post-mount.sh`, `service.sh`, `boot-completed.sh`)
/// across all enabled modules and global `<adb_compat>/<stage>.d/` scripts within a shared budget.
fn run_stage_scripts(
    data_dir: &Path,
    module_script_name: &str,
    global_dir_name: &str,
    unprivileged_test: bool,
) {
    let stage_start = Instant::now();
    let mut scripts: Vec<PathBuf> = Vec::new();
    let global_dir = data_dir.join("adb_compat").join(global_dir_name);
    if let Ok(rd) = fs::read_dir(&global_dir) {
        let mut g: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("sh"))
            .collect();
        g.sort();
        scripts.extend(g);
    }
    for mdir in enabled_module_dirs(data_dir) {
        let s = mdir.join(module_script_name);
        if s.is_file() {
            scripts.push(s);
        }
    }
    for s in scripts {
        let remaining = SCRIPT_STAGE_BUDGET.saturating_sub(stage_start.elapsed());
        if remaining.is_zero() {
            break;
        }
        let budget = remaining.min(SCRIPT_PER_TIMEOUT);
        let mod_dir_str = s.parent().map(|p| p.display().to_string()).unwrap_or_default();
        let _ = run_script_bounded(
            data_dir,
            &s,
            &[("MODDIR", &mod_dir_str)],
            budget,
            unprivileged_test,
        );
    }
}

/// Promotes pending module updates from `modules_update/` and executes pending removals.
pub fn process_pending_updates_and_removals(data_dir: &Path, unprivileged_test: bool) {
    let mroot = modules_dir(data_dir);
    let uroot = modules_update_dir(data_dir);
    let _ = fs::create_dir_all(&mroot);

    // 1. Apply pending removals (`remove` flag file).
    if let Ok(rd) = fs::read_dir(&mroot) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() && p.join("remove").exists() {
                let uninstall = p.join("uninstall.sh");
                if uninstall.is_file() {
                    let _ = run_script_bounded(data_dir, &uninstall, &[], SCRIPT_PER_TIMEOUT, unprivileged_test);
                }
                if let Some(id) = p.file_name().and_then(|s| s.to_str()) {
                    let _ = fs::remove_dir_all(module_config_dir(data_dir, id));
                }
                let _ = fs::remove_dir_all(&p);
            }
        }
    }

    // 2. Promote staged updates from `modules_update/<id>` -> `modules/<id>`.
    if let Ok(rd) = fs::read_dir(&uroot) {
        for ent in rd.flatten() {
            let src = ent.path();
            if !src.is_dir() {
                continue;
            }
            let Some(id) = src.file_name().and_then(|s| s.to_str()) else { continue };
            if !validate_module_id(id) {
                continue;
            }
            let dst = mroot.join(id);
            let was_disabled = dst.join("disable").exists();
            let _ = fs::remove_dir_all(&dst);
            if fs::rename(&src, &dst).is_ok() {
                let _ = fs::remove_file(dst.join("update"));
                if was_disabled {
                    let _ = fs::write(dst.join("disable"), b"");
                }
            }
        }
    }

    // 3. Clear volatile `tmp.config` files on every boot.
    if let Ok(rd) = fs::read_dir(data_dir.join("config")) {
        for ent in rd.flatten() {
            let _ = fs::remove_file(ent.path().join("tmp.config"));
        }
    }
}

/// Parses `<data_dir>/zygisk.conf` and enabled modules to write binary `<data_dir>/zygisk.set`.
/// When Module Engine or Native Zygisk is OFF (default), removes `zygisk.set` completely so
/// Zygote never allocates or parses Zygisk tables and never dlopens `libyasvara_zygisk.so`.
pub fn publish_zygisk_set(data_dir: &Path, safe_bypass: bool) -> io::Result<()> {
    if !is_module_engine_enabled(data_dir) {
        let _ = fs::remove_file(data_dir.join("zygisk.set"));
        return Ok(());
    }
    let conf_text = fs::read_to_string(data_dir.join("zygisk.conf")).unwrap_or_default();
    let mut enabled = false;
    let mut denylist_uids: Vec<u32> = Vec::new();
    let mut scopes: std::collections::HashMap<String, (u8, Vec<u32>)> = std::collections::HashMap::new();

    for line in conf_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        let v = v.trim();
        if k == "enabled" {
            enabled = matches!(v, "1" | "true");
        } else if k == "denylist" {
            denylist_uids = v.split(',').filter_map(|s| s.trim().parse::<u32>().ok()).collect();
        } else if let Some(mod_id) = k.strip_prefix("scope.") {
            if v == "*" || v.is_empty() {
                scopes.insert(mod_id.to_string(), (SCOPE_ALL_NON_DENYLIST, Vec::new()));
            } else {
                let uids: Vec<u32> = v.split(',').filter_map(|s| s.trim().parse::<u32>().ok()).collect();
                scopes.insert(mod_id.to_string(), (SCOPE_EXPLICIT_ONLY, uids));
            }
        }
    }

    if !enabled || safe_bypass {
        let _ = fs::remove_file(data_dir.join("zygisk.set"));
        return Ok(());
    }

    let mut modules = Vec::new();
    let mut has_ss = false;
    if enabled && !safe_bypass {
        for mdir in enabled_module_dirs(data_dir) {
            let Ok(raw) = fs::read_to_string(mdir.join("module.prop")) else { continue };
            let Ok(prop) = ModuleProp::parse(&raw) else { continue };
            let zdir = mdir.join("zygisk");
            let lib64 = zdir.join("arm64-v8a.so");
            let lib32 = zdir.join("armeabi-v7a.so");
            if !lib64.is_file() && !lib32.is_file() {
                continue;
            }
            let (scope_mode, scope_uids) = scopes
                .get(&prop.id)
                .cloned()
                .unwrap_or((SCOPE_ALL_NON_DENYLIST, Vec::new()));
            if scope_mode == SCOPE_ALL_NON_DENYLIST || scope_uids.contains(&1000) {
                has_ss = true;
            }
            modules.push(ZygiskModuleEntry {
                id: prop.id,
                mod_dir: mdir.display().to_string(),
                lib64_path: if lib64.is_file() { lib64.display().to_string() } else { String::new() },
                lib32_path: if lib32.is_file() { lib32.display().to_string() } else { String::new() },
                scope_mode,
                scope_uids,
            });
        }
    }

    let set = ZygiskSet {
        enabled,
        safe_bypass,
        has_system_server_modules: has_ss,
        denylist_uids,
        modules,
    };
    sys::replace_file(&data_dir.join("zygisk.set"), &set.encode())
}

/// Parses `<data_dir>/unmount.conf` and publishes binary `<data_dir>/unmount.set`.
pub fn publish_unmount_set(data_dir: &Path) -> io::Result<()> {
    let text = fs::read_to_string(data_dir.join("unmount.conf")).unwrap_or_default();
    let mut set = UnmountSet::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        match k.trim() {
            "default_unmount" => set.default_unmount_non_root = matches!(v.trim(), "1" | "true"),
            "force" => {
                set.force_unmount_uids = v.split(',').filter_map(|s| s.trim().parse::<u32>().ok()).collect();
            }
            "exempt" => {
                set.exempt_uids = v.split(',').filter_map(|s| s.trim().parse::<u32>().ok()).collect();
            }
            _ => {}
        }
    }
    sys::replace_file(&data_dir.join("unmount.set"), &set.encode())
}

/// Full synchronous `post-fs-data` boot stage.
/// Zero-overhead short-circuit: when Module Engine is OFF (default) or no modules exist,
/// immediately disarms kernel bootkey & keywatch, removes runtime sets, and returns with
/// zero mounts, zero scripts, zero sepolicy reload, and zero Zygisk activity.
pub fn stage_post_fs_data(data_dir: &Path, meta_override: Option<&Path>, unprivileged_test: bool) -> io::Result<()> {
    if !is_module_engine_enabled(data_dir) {
        if !unprivileged_test {
            crate::keywatch::signal_keywatch_done(data_dir);
            let _ = crate::keywatch::consume_kernel_bootkey();
        }
        clear_runtime_sets(data_dir);
        return Ok(());
    }

    let _ = fs::create_dir_all(modules_dir(data_dir));
    let _ = fs::create_dir_all(modules_update_dir(data_dir));
    let _ = compat_ns::prepare_compat_tree(data_dir, Path::new(compat_ns::REAL_ROOTD_BIN));

    let bg_paths = bootguard::BootguardPaths::resolve(data_dir, meta_override);
    let bg_status = bootguard::evaluate_post_fs_data(&bg_paths, unprivileged_test);

    if bg_status.safe_mode {
        // Safe Mode: zero mounts, zero scripts, zero sepolicy patches, bypass Zygisk.
        clear_runtime_sets(data_dir);
        return Ok(());
    }

    // 1. Apply pending module removals and staged updates.
    process_pending_updates_and_removals(data_dir, unprivileged_test);

    // 2. Apply runtime `sepolicy.rule` from enabled modules before services/mounts start.
    let active_dirs = enabled_module_dirs(data_dir);
    if !unprivileged_test {
        sepolicy::apply_module_sepolicy_rules(&active_dirs);
    }

    // 3. Run `post-fs-data.d/*.sh` and per-module `post-fs-data.sh`.
    run_stage_scripts(data_dir, "post-fs-data.sh", "post-fs-data.d", unprivileged_test);

    // 4. Apply per-module `system.prop` via pure-Rust resetprop.
    if !unprivileged_test {
        for mdir in &active_dirs {
            let prop_file = mdir.join("system.prop");
            if prop_file.is_file() {
                let _ = resetprop::load_prop_file(Path::new("/dev/__properties__"), &prop_file);
            }
        }
    }

    // 5. Mount modules: delegate to active `metamodule=1` if it provides `metamount.sh`,
    //    otherwise run built-in Hybrid OverlayFS + Magic Mount.
    let mounts_set = if let Some(meta_dir) = find_active_metamodule(data_dir) {
        let metamount = meta_dir.join("metamount.sh");
        if metamount.is_file() {
            let before = mount::snapshot_mountpoints();
            let _ = run_script_bounded(data_dir, &metamount, &[], Duration::from_secs(20), unprivileged_test);
            let after = mount::snapshot_mountpoints();
            let added: Vec<String> = after.difference(&before).cloned().collect();
            MountsSet { paths: added }
        } else {
            mount::execute_hybrid_mount(&active_dirs, unprivileged_test).0
        }
    } else {
        mount::execute_hybrid_mount(&active_dirs, unprivileged_test).0
    };
    let _ = sys::replace_file(&data_dir.join("mounts.set"), &mounts_set.encode());
    let _ = publish_unmount_set(data_dir);
    let _ = publish_zygisk_set(data_dir, false);

    // 6. Run `post-mount.d/*.sh` and per-module `post-mount.sh`.
    run_stage_scripts(data_dir, "post-mount.sh", "post-mount.d", unprivileged_test);
    Ok(())
}

/// Asynchronous `services` boot stage (`nonencrypted` / `vold.decrypt`).
pub fn stage_services(data_dir: &Path, unprivileged_test: bool) {
    if !is_module_engine_enabled(data_dir) {
        return;
    }
    let status = bootguard::read_status(data_dir);
    if status.safe_mode {
        return;
    }
    run_stage_scripts(data_dir, "service.sh", "service.d", unprivileged_test);
}

/// Asynchronous `boot-completed` stage: runs `boot-completed.sh`, waits stability window, resets Bootguard.
pub fn stage_boot_completed(data_dir: &Path, meta_override: Option<&Path>, unprivileged_test: bool) {
    if !is_module_engine_enabled(data_dir) {
        return;
    }
    let bg_paths = bootguard::BootguardPaths::resolve(data_dir, meta_override);
    let status = bootguard::read_status(data_dir);
    if !status.safe_mode {
        run_stage_scripts(data_dir, "boot-completed.sh", "boot-completed.d", unprivileged_test);
    }
    if !unprivileged_test {
        // Stability window: confirm system stays up 30s after boot_completed before clearing bootcount.
        std::thread::sleep(Duration::from_secs(30));
    }
    bootguard::mark_boot_stable(&bg_paths);
}

/// Extracts and installs a Magisk/KSU/Akar module ZIP using pure-Rust hardened ZIP extraction,
/// running `customize.sh` (or legacy `install.sh`), supporting `SKIPUNZIP`, `REPLACE`, `REMOVE`,
/// `metainstall.sh`, and `MODULE_HOT_INSTALL_REQUEST=true`.
pub fn install_module_zip(
    data_dir: &Path,
    zip_path: &Path,
    unprivileged_test: bool,
) -> io::Result<(ModuleProp, String, bool)> {
    let raw = fs::read(zip_path)?;
    let arch = ZipArchive::parse(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let prop_meta = arch
        .find("module.prop")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "zip missing module.prop"))?;
    let prop_bytes = arch
        .read_entry(prop_meta)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let prop_text = String::from_utf8_lossy(&prop_bytes);
    let prop = ModuleProp::parse(&prop_text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut log = String::new();
    log.push_str(&format!("- Installing {} ({} {})\n", prop.name, prop.id, prop.version));

    // Stage into `modules_update/<id>` (clean directory).
    let stage_dir = modules_update_dir(data_dir).join(&prop.id);
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir)?;

    let has_customize = arch.find("customize.sh").is_some();
    let skip_unzip = if let Some(cm) = arch.find("customize.sh") {
        let cb = arch.read_entry(cm).unwrap_or_default();
        let cs = String::from_utf8_lossy(&cb);
        cs.lines().any(|l| {
            let t = l.trim();
            t == "SKIPUNZIP=1" || t.starts_with("SKIPUNZIP=1 ")
        })
    } else {
        false
    };

    // Unpack entries safely unless SKIPUNZIP=1 (in which case only module.prop + customize.sh are unpacked).
    for entry in &arch.entries {
        if entry.name.starts_with("META-INF/") {
            continue;
        }
        if skip_unzip && entry.name != "module.prop" && entry.name != "customize.sh" {
            continue;
        }
        let target = stage_dir.join(entry.name.trim_end_matches('/'));
        if entry.is_dir {
            fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = arch
            .read_entry(entry)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if entry.is_symlink {
            let link_target = String::from_utf8_lossy(&content);
            // Reject symlinks escaping outside the module tree unless pointing to standard system paths.
            if link_target.contains("..") {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "unsafe symlink in zip"));
            }
            let _ = std::os::unix::fs::symlink(link_target.as_ref(), &target);
        } else {
            fs::write(&target, &content)?;
            let mode = entry.unix_mode & 0o777;
            if mode != 0 {
                let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode));
            }
        }
    }

    // Build wrapper script implementing Magisk/KSU `util_functions.sh` helpers (`ui_print`,
    // `set_perm`, `set_perm_recursive`, `mktouch`, `REPLACE`, `REMOVE`, `MODULE_HOT_INSTALL_REQUEST`).
    let mut hot_installed = false;
    if has_customize || arch.find("install.sh").is_some() {
        let wrapper = stage_dir.join(".akar_install_wrapper.sh");
        let hot_flag = stage_dir.join(".akar_hot_install");
        let zip_abs = fs::canonicalize(zip_path).unwrap_or_else(|_| zip_path.to_path_buf());
        let wrapper_src = format!(
            "#!/system/bin/sh\n\
             set -o pipefail 2>/dev/null || true\n\
             BOOTMODE=true\n\
             MODPATH=\"{modpath}\"\n\
             ZIPFILE=\"{zipfile}\"\n\
             TMPDIR=\"$MODPATH/.tmp\"\n\
             mkdir -p \"$TMPDIR\"\n\
             ui_print() {{ printf '%s\\n' \"$*\"; }}\n\
             abort() {{ ui_print \"! $*\"; exit 1; }}\n\
             mktouch() {{ mkdir -p \"$(dirname \"$1\")\" && touch \"$1\"; }}\n\
             set_perm() {{ chown \"$2:$3\" \"$1\" 2>/dev/null || true; chmod \"$4\" \"$1\" 2>/dev/null || true; [ -n \"$5\" ] && chcon \"$5\" \"$1\" 2>/dev/null || true; }}\n\
             set_perm_recursive() {{\n\
               find \"$1\" -type d 2>/dev/null | while read -r d; do set_perm \"$d\" \"$2\" \"$3\" \"$4\" \"$6\"; done\n\
               find \"$1\" -type f -o -type l 2>/dev/null | while read -r f; do set_perm \"$f\" \"$2\" \"$3\" \"$5\" \"$6\"; done\n\
             }}\n\
             REPLACE=\"\"\n\
             REMOVE=\"\"\n\
             MODULE_HOT_INSTALL_REQUEST=false\n\
             if [ -f \"$MODPATH/customize.sh\" ]; then . \"$MODPATH/customize.sh\"; fi\n\
             for r in $REPLACE; do mkdir -p \"$MODPATH$r\" && touch \"$MODPATH$r/.replace\"; done\n\
             for rm_p in $REMOVE; do mkdir -p \"$(dirname \"$MODPATH$rm_p\")\"; mknod \"$MODPATH$rm_p\" c 0 0 2>/dev/null || true; done\n\
             if [ \"$MODULE_HOT_INSTALL_REQUEST\" = \"true\" ] || [ \"$MODULE_HOT_INSTALL_REQUEST\" = \"1\" ]; then touch \"{hot}\"; fi\n\
             rm -rf \"$TMPDIR\"\n",
            modpath = stage_dir.display(),
            zipfile = zip_abs.display(),
            hot = hot_flag.display(),
        );
        fs::write(&wrapper, wrapper_src)?;
        let _ = fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700));
        let (code, script_out) = run_script_bounded(
            data_dir,
            &wrapper,
            &[("MODPATH", &stage_dir.display().to_string())],
            Duration::from_secs(60),
            unprivileged_test,
        )?;
        let _ = fs::remove_file(&wrapper);
        log.push_str(&script_out);
        if code != 0 {
            let _ = fs::remove_dir_all(&stage_dir);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("installer script failed (exit {code}):\n{log}"),
            ));
        }
        if hot_flag.exists() {
            let _ = fs::remove_file(&hot_flag);
            hot_installed = true;
        }
    }

    // If the module has NO system/vendor/product/system_ext/odm/zygisk files OR explicitly
    // requested hot-install, promote immediately to `modules/<id>` without requiring a reboot.
    let needs_mount = mount::PARTITIONS.iter().any(|p| stage_dir.join(p).is_dir());
    let has_zygisk = stage_dir.join("zygisk").is_dir();
    if hot_installed || (!needs_mount && !has_zygisk) {
        let live_dir = modules_dir(data_dir).join(&prop.id);
        let _ = fs::remove_dir_all(&live_dir);
        fs::create_dir_all(modules_dir(data_dir))?;
        fs::rename(&stage_dir, &live_dir)?;
        hot_installed = true;
        log.push_str("- Module activated immediately (hot-install)\n");
    } else {
        // Also ensure a placeholder entry exists in `modules/<id>` with `update` marker so
        // Laras shows the newly installed module immediately before reboot.
        let live_dir = modules_dir(data_dir).join(&prop.id);
        fs::create_dir_all(&live_dir)?;
        fs::copy(stage_dir.join("module.prop"), live_dir.join("module.prop"))?;
        fs::write(live_dir.join("update"), b"")?;
        log.push_str("- Staged for activation on next reboot\n");
    }

    // Auto-enable the module engine when the user explicitly installs a module.
    let _ = set_module_engine_enabled(data_dir, true);
    let _ = publish_zygisk_set(data_dir, bootguard::read_status(data_dir).safe_mode);
    Ok((prop, log, hot_installed))
}

pub fn set_module_enabled(data_dir: &Path, id: &str, enabled: bool) -> io::Result<()> {
    if !validate_module_id(id) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid module id"));
    }
    let dir = modules_dir(data_dir).join(id);
    if !dir.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "module not found"));
    }
    let flag = dir.join("disable");
    if enabled {
        let _ = fs::remove_file(flag);
    } else {
        fs::write(flag, b"")?;
    }
    let _ = publish_zygisk_set(data_dir, bootguard::read_status(data_dir).safe_mode);
    Ok(())
}

pub fn set_module_remove(data_dir: &Path, id: &str, remove: bool) -> io::Result<()> {
    if !validate_module_id(id) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid module id"));
    }
    let dir = modules_dir(data_dir).join(id);
    if !dir.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "module not found"));
    }
    let flag = dir.join("remove");
    if remove {
        fs::write(flag, b"")?;
    } else {
        let _ = fs::remove_file(flag);
    }
    Ok(())
}

pub fn run_module_action(data_dir: &Path, id: &str, unprivileged_test: bool) -> io::Result<(i32, String)> {
    if !validate_module_id(id) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid module id"));
    }
    let dir = modules_dir(data_dir).join(id);
    let script = dir.join("action.sh");
    if !script.is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "module has no action.sh"));
    }
    run_script_bounded(
        data_dir,
        &script,
        &[("MODDIR", &dir.display().to_string())],
        Duration::from_secs(60),
        unprivileged_test,
    )
}

/// CLI entrypoint for `yasvara_rootd module ...` / `akarctl module ...` / `ksud module ...`.
pub fn cli_module(data_dir: &Path, args: &[String], unprivileged_test: bool) -> i32 {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    match sub {
        "list" => {
            println!("{}", modules_to_json(&list_modules(data_dir)));
            0
        }
        "install" => {
            let Some(zip) = args.get(1) else {
                eprintln!("usage: module install <zip>");
                return 2;
            };
            match install_module_zip(data_dir, Path::new(zip), unprivileged_test) {
                Ok((_, log, _)) => {
                    print!("{log}");
                    0
                }
                Err(e) => {
                    eprintln!("install failed: {e}");
                    1
                }
            }
        }
        "enable" | "disable" => {
            let Some(id) = args.get(1) else {
                eprintln!("usage: module {sub} <id>");
                return 2;
            };
            match set_module_enabled(data_dir, id, sub == "enable") {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        "uninstall" | "remove" => {
            let Some(id) = args.get(1) else {
                eprintln!("usage: module uninstall <id>");
                return 2;
            };
            match set_module_remove(data_dir, id, true) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        "undo-uninstall" => {
            let Some(id) = args.get(1) else {
                eprintln!("usage: module undo-uninstall <id>");
                return 2;
            };
            match set_module_remove(data_dir, id, false) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        "action" => {
            let Some(id) = args.get(1) else {
                eprintln!("usage: module action <id>");
                return 2;
            };
            match run_module_action(data_dir, id, unprivileged_test) {
                Ok((code, out)) => {
                    print!("{out}");
                    code
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        "config" => {
            // module config <get|set|delete|list> <id> [key] [val] [--temp]
            let op = args.get(1).map(String::as_str).unwrap_or("");
            let id = args.get(2).map(String::as_str).unwrap_or("");
            let temp = args.iter().any(|a| a == "--temp" || a == "-t");
            match op {
                "get" => {
                    let key = args.get(3).map(String::as_str).unwrap_or("");
                    match load_module_config(data_dir, id).get(key) {
                        Some(v) => {
                            println!("{v}");
                            0
                        }
                        None => 1,
                    }
                }
                "set" => {
                    let (Some(k), Some(v)) = (args.get(3), args.get(4)) else { return 2 };
                    if save_module_config_key(data_dir, id, k, Some(v), temp).is_ok() { 0 } else { 1 }
                }
                "delete" => {
                    let Some(k) = args.get(3) else { return 2 };
                    if save_module_config_key(data_dir, id, k, None, temp).is_ok() { 0 } else { 1 }
                }
                "list" => {
                    let cfg = load_module_config(data_dir, id);
                    for (k, v) in cfg.entries {
                        println!("{k}={v}");
                    }
                    0
                }
                _ => 2,
            }
        }
        _ => {
            eprintln!("unknown module subcommand: {sub}");
            2
        }
    }
}

/// Lists all active `manage.<feature>` claims across enabled modules (used by PIF arbitration).
pub fn active_managed_features(data_dir: &Path) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for m in list_modules(data_dir) {
        if m.enabled && !m.remove {
            for f in m.managed_features {
                set.insert(f);
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use yasvara_root_proto::zip::crc32;

    fn build_test_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut cd = Vec::new();
        for &(name, content) in entries {
            let off = buf.len() as u32;
            let c = crc32(content);
            let nlen = name.len() as u16;
            let sz = content.len() as u32;
            buf.extend_from_slice(b"PK\x03\x04");
            buf.extend_from_slice(&20u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&c.to_le_bytes());
            buf.extend_from_slice(&sz.to_le_bytes());
            buf.extend_from_slice(&sz.to_le_bytes());
            buf.extend_from_slice(&nlen.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(content);

            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&0x0314u16.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u32.to_le_bytes());
            cd.extend_from_slice(&c.to_le_bytes());
            cd.extend_from_slice(&sz.to_le_bytes());
            cd.extend_from_slice(&sz.to_le_bytes());
            cd.extend_from_slice(&nlen.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&(0o100755u32 << 16).to_le_bytes());
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = buf.len() as u32;
        let cd_sz = cd.len() as u32;
        buf.extend_from_slice(&cd);
        buf.extend_from_slice(b"PK\x05\x06");
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        buf.extend_from_slice(&cd_sz.to_le_bytes());
        buf.extend_from_slice(&cd_off.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf
    }

    #[test]
    fn install_hot_action_disable_and_stage_lifecycle() {
        let tmp = std::env::temp_dir().join(format!("yasvara-mod-e2e-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let data = tmp.join("data");
        let meta = tmp.join("meta");
        fs::create_dir_all(&data).unwrap();

        let zip_file = tmp.join("sample.zip");
        let zbytes = build_test_zip(&[
            ("module.prop", b"id=hello_mod\nname=Hello Mod\nversion=1.0\nauthor=Yasvara\ndescription=Test\n"),
            ("customize.sh", b"ui_print \"customizing ok\"\n"),
            ("action.sh", b"echo action-ran\n"),
        ]);
        fs::write(&zip_file, zbytes).unwrap();

        let (prop, log, hot) = install_module_zip(&data, &zip_file, true).unwrap();
        assert_eq!(prop.id, "hello_mod");
        assert!(hot);
        assert!(log.contains("customizing ok"));

        let list = list_modules(&data);
        assert_eq!(list.len(), 1);
        assert!(list[0].enabled);
        assert!(list[0].has_action);

        let (code, out) = run_module_action(&data, "hello_mod", true).unwrap();
        assert_eq!(code, 0);
        assert!(out.contains("action-ran"));

        save_module_config_key(&data, "hello_mod", "manage.play_integrity", Some("true"), false).unwrap();
        assert!(active_managed_features(&data).contains("play_integrity"));

        // When module engine is enabled (auto-enabled on install), post-fs-data publishes mounts/unmount.
        // Native Zygisk stays OFF by default (zero zygisk.set until explicitly enabled!).
        stage_post_fs_data(&data, Some(&meta), true).unwrap();
        assert!(data.join("mounts.set").is_file());
        assert!(data.join("unmount.set").is_file());
        assert!(!data.join("zygisk.set").exists(), "Zygisk must be OFF by default");

        // Enabling Zygisk explicitly publishes zygisk.set; disabling Module Engine clears all sets.
        fs::write(data.join("zygisk.conf"), "enabled=1\n").unwrap();
        publish_zygisk_set(&data, false).unwrap();
        assert!(data.join("zygisk.set").is_file());

        set_module_engine_enabled(&data, false).unwrap();
        stage_post_fs_data(&data, Some(&meta), true).unwrap();
        assert!(!data.join("mounts.set").exists(), "disabled engine must leave zero mounts.set");
        assert!(!data.join("zygisk.set").exists(), "disabled engine must leave zero zygisk.set");

        let _ = fs::remove_dir_all(&tmp);
    }
}
