// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

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

use crate::{bootguard, compat_ns, installer, mount, resetprop, sepolicy, sys};

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
    let present = ["mounts.set", "unmount.set", "zygisk.set"].iter().any(|n| data_dir.join(n).exists());
    if !present {
        return;
    }
    let _ = fs::remove_file(data_dir.join("mounts.set"));
    let _ = fs::remove_file(data_dir.join("unmount.set"));
    let _ = sys::publish_set(&data_dir.join("zygisk.set"), None);
    sys::write_hide_switch(0);
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
        // arm64-only device: a 32-bit-only Zygisk module cannot load, so it is not listed.
        if zdir.join("arm64-v8a.so").is_file() {
            zygisk_abis.push("arm64-v8a".to_string());
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

const LOG_ROTATE_BYTES: u64 = 64 * 1024;
const INSTALL_TIMEOUT: Duration = Duration::from_secs(300);
const HOT_SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a script may hold up its caller.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Wait {
    /// Wait up to the budget, then stop waiting (the script keeps running, as with KSU/Magisk).
    Upto(Duration),
    /// Wait up to the budget, then kill the script's whole process group (installers).
    KillAfter(Duration),
    /// Start it in its own session and return at once (`service`, `boot-completed`).
    Detached,
}

/// `<data_dir>/log/<name>.log`, rotated to `.log.1` past 64 KiB.
pub fn open_log(data_dir: &Path, name: &str) -> Option<fs::File> {
    let dir = data_dir.join("log");
    fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!("{name}.log"));
    if fs::metadata(&path).is_ok_and(|m| m.len() > LOG_ROTATE_BYTES) {
        let _ = fs::rename(&path, dir.join(format!("{name}.log.1")));
    }
    fs::OpenOptions::new().create(true).append(true).read(true).open(path).ok()
}

/// Runs `sh <script>` with the module contract in its environment, output appended to
/// `log/<log_name>.log`. Returns the exit code (124 when a budget ran out) and, for waited
/// runs, what this run wrote to the log.
pub fn run_script(
    data_dir: &Path,
    script: &Path,
    extra_env: &[(&str, &str)],
    log_name: &str,
    wait: Wait,
    unprivileged_test: bool,
) -> io::Result<(i32, String)> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::process::CommandExt;

    let sh = if Path::new("/system/bin/sh").exists() { "/system/bin/sh" } else { "/bin/sh" };
    let mut log = open_log(data_dir, log_name);
    let start_off = log.as_mut().and_then(|f| f.seek(SeekFrom::End(0)).ok()).unwrap_or(0);
    let mut cmd = Command::new(sh);
    cmd.arg(script).stdin(Stdio::null());
    match log.as_ref().and_then(|f| Some((f.try_clone().ok()?, f.try_clone().ok()?))) {
        Some((o, e)) => {
            cmd.stdout(o).stderr(e);
        }
        None => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    for (k, v) in compat_ns::compat_env(data_dir, unprivileged_test) {
        cmd.env(k, v);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if let Some(parent) = script.parent() {
        cmd.current_dir(parent);
    }
    let detached = wait == Wait::Detached;
    unsafe {
        cmd.pre_exec(move || {
            // Own process group (killable as a whole); a detached script also leaves our session.
            if detached {
                libc::setsid();
            } else {
                libc::setpgid(0, 0);
            }
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let budget = match wait {
        Wait::Detached => return Ok((0, String::new())),
        Wait::Upto(d) | Wait::KillAfter(d) => d,
    };
    let start = Instant::now();
    let code = loop {
        if let Some(st) = child.try_wait()? {
            break st.code().unwrap_or(1);
        }
        if start.elapsed() >= budget {
            if let Wait::KillAfter(_) = wait {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.wait();
            }
            break 124;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut out = String::new();
    if let Some(mut f) = log.and_then(|f| f.try_clone().ok()) {
        if f.seek(SeekFrom::Start(start_off)).is_ok() {
            let mut buf = Vec::new();
            let _ = f.take(256 * 1024).read_to_end(&mut buf);
            out = String::from_utf8_lossy(&buf).into_owned();
        }
    }
    if code == 124 {
        out.push_str(&format!("script still running after {}s\n", budget.as_secs()));
    }
    Ok((code, out))
}

fn module_id_of(script: &Path) -> String {
    script
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Runs a stage's global `<stage>.d/*.sh` then each enabled module's script. Blocking stages
/// share one budget and give each script at most 10 s; detached stages never wait.
fn run_stage_scripts(
    data_dir: &Path,
    module_script_name: &str,
    global_dir_name: &str,
    detached: bool,
    unprivileged_test: bool,
) {
    let stage = module_script_name.trim_end_matches(".sh");
    let stage_start = Instant::now();
    let mut scripts: Vec<(PathBuf, Option<String>)> = Vec::new();
    let global_dir = data_dir.join("adb_compat").join(global_dir_name);
    if let Ok(rd) = fs::read_dir(&global_dir) {
        let mut g: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("sh"))
            .collect();
        g.sort();
        scripts.extend(g.into_iter().map(|p| (p, None)));
    }
    for mdir in enabled_module_dirs(data_dir) {
        let s = mdir.join(module_script_name);
        if s.is_file() {
            let id = module_id_of(&s);
            scripts.push((s, Some(id)));
        }
    }
    for (s, id) in scripts {
        let wait = if detached {
            Wait::Detached
        } else {
            let remaining = SCRIPT_STAGE_BUDGET.saturating_sub(stage_start.elapsed());
            if remaining.is_zero() {
                break;
            }
            Wait::Upto(remaining.min(SCRIPT_PER_TIMEOUT))
        };
        let mod_dir = s.parent().map(|p| p.display().to_string()).unwrap_or_default();
        let log_name = match &id {
            Some(id) => format!("{id}.{stage}"),
            None => format!("common.{stage}"),
        };
        let mut env: Vec<(&str, &str)> = vec![("MODDIR", &mod_dir)];
        if let Some(id) = &id {
            env.push(("KSU_MODULE", id));
        }
        let _ = run_script(data_dir, &s, &env, &log_name, wait, unprivileged_test);
    }
}

pub const ZYGISK_FILE_CON: &str = "u:object_r:yasvara_zygisk_file:s0";

fn set_label(path: &Path, con: &str) {
    let (Ok(p), Ok(c)) = (std::ffi::CString::new(path.as_os_str().as_encoded_bytes()), std::ffi::CString::new(con)) else {
        return;
    };
    let name = b"security.selinux\0";
    unsafe {
        libc::lsetxattr(p.as_ptr(), name.as_ptr() as *const libc::c_char, c.as_ptr() as *const libc::c_void, con.len() + 1, 0);
    }
}

/// Gives `<module>/zygisk` and its files the label Zygote may read. Renames keep the label of
/// the staging tree and the /data sehash skips later restorecons, so this runs after every
/// promote, install and hot install.
pub fn label_zygisk_tree(module_dir: &Path) {
    let z = module_dir.join("zygisk");
    if !z.is_dir() {
        return;
    }
    set_label(&z, ZYGISK_FILE_CON);
    if let Ok(rd) = fs::read_dir(&z) {
        for e in rd.flatten() {
            set_label(&e.path(), ZYGISK_FILE_CON);
        }
    }
}

fn hot_trash_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("hot_install_trash")
}

/// Drops module dirs replaced by hot installs during the previous boot, in the background.
fn clean_hot_trash(data_dir: &Path, unprivileged_test: bool) {
    let trash = hot_trash_dir(data_dir);
    if !trash.exists() {
        return;
    }
    let old = data_dir.join("hot_install_trash.old");
    let _ = fs::remove_dir_all(&old);
    if fs::rename(&trash, &old).is_err() {
        return;
    }
    if unprivileged_test {
        let _ = fs::remove_dir_all(&old);
        return;
    }
    let spawned = Command::new("/system/bin/rm")
        .arg("-rf")
        .arg(&old)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if spawned.is_err() {
        let _ = fs::remove_dir_all(&old);
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
                let id = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
                let dir = p.display().to_string();
                if let Some(meta) = find_active_metamodule(data_dir).filter(|m| *m != p) {
                    let script = meta.join("metauninstall.sh");
                    if script.is_file() {
                        let meta_dir = meta.display().to_string();
                        let _ = run_script(
                            data_dir,
                            &script,
                            &[("MODDIR", &meta_dir), ("MODULE_ID", &id)],
                            "metamodule.metauninstall",
                            Wait::Upto(SCRIPT_PER_TIMEOUT),
                            unprivileged_test,
                        );
                    }
                }
                let uninstall = p.join("uninstall.sh");
                if uninstall.is_file() {
                    let _ = run_script(
                        data_dir,
                        &uninstall,
                        &[("MODDIR", &dir), ("KSU_MODULE", &id)],
                        &format!("{id}.uninstall"),
                        Wait::Upto(SCRIPT_PER_TIMEOUT),
                        unprivileged_test,
                    );
                }
                if !id.is_empty() {
                    let _ = fs::remove_dir_all(module_config_dir(data_dir, &id));
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
                if !unprivileged_test {
                    label_zygisk_tree(&dst);
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

/// `denylist=` of zygisk.conf: the apps Tabir protects.
pub fn denylist_uids(data_dir: &Path) -> Vec<u32> {
    let text = fs::read_to_string(data_dir.join("zygisk.conf")).unwrap_or_default();
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("denylist="))
        .flat_map(|v| v.split(',').filter_map(|u| u.trim().parse::<u32>().ok()).collect::<Vec<_>>())
        .collect()
}

/// Rewrites a set only when its bytes change, so an unchanged publish costs Zygote nothing.
fn publish_if_changed(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    sys::publish_set(path, Some(bytes))
}

/// Parses `<data_dir>/zygisk.conf` and enabled modules to write binary `<data_dir>/zygisk.set`.
/// When Module Engine or Native Zygisk is OFF (default), removes `zygisk.set` completely so
/// Zygote never allocates or parses Zygisk tables and never dlopens `libyasvara_zygisk.so`.
pub fn publish_zygisk_set(data_dir: &Path, safe_bypass: bool) -> io::Result<()> {
    let r = write_zygisk_set(data_dir, safe_bypass);
    sync_hide_switch(data_dir);
    r
}

/// What the kernel hide filters must cover. Mounts: an active module (its overlays and
/// whatever its scripts mount). Maps: a Zygisk module that may load. Engine off, safe mode
/// or no module leaves both off, so `mountinfo` and `maps` reads cost what stock costs.
pub fn hide_bits(data_dir: &Path) -> u32 {
    let mut bits = 0;
    if data_dir.join("mounts.set").exists() && !enabled_module_dirs(data_dir).is_empty() {
        bits |= sys::HIDE_MOUNTS;
    }
    let zygisk_live = fs::read(data_dir.join("zygisk.set"))
        .ok()
        .and_then(|b| ZygiskSet::decode(&b).ok())
        .is_some_and(|z| z.enabled && !z.safe_bypass && !z.modules.is_empty());
    if zygisk_live {
        bits |= sys::HIDE_MAPS;
    }
    bits
}

pub fn sync_hide_switch(data_dir: &Path) {
    sys::write_hide_switch(hide_bits(data_dir));
}

fn write_zygisk_set(data_dir: &Path, safe_bypass: bool) -> io::Result<()> {
    if !is_module_engine_enabled(data_dir) {
        if data_dir.join("zygisk.set").exists() {
            let _ = sys::publish_set(&data_dir.join("zygisk.set"), None);
        }
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
        if data_dir.join("zygisk.set").exists() {
            let _ = sys::publish_set(&data_dir.join("zygisk.set"), None);
        }
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
            if !lib64.is_file() {
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
                lib64_path: lib64.display().to_string(),
                lib32_path: String::new(), // wire field kept; no zygote32
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
    publish_if_changed(&data_dir.join("zygisk.set"), &set.encode())
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
    // The DenyList (Tabir-protected apps) is unmounted whether or not Zygisk is on.
    set.force_unmount_uids.extend(denylist_uids(data_dir));
    set.force_unmount_uids.sort_unstable();
    set.force_unmount_uids.dedup();
    publish_if_changed(&data_dir.join("unmount.set"), &set.encode())
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
    clean_hot_trash(data_dir, unprivileged_test);

    let bg_paths = bootguard::BootguardPaths::resolve(data_dir, meta_override);
    let bg_status = bootguard::evaluate_post_fs_data(&bg_paths, unprivileged_test);

    if bg_status.safe_mode {
        // Safe Mode: zero mounts, zero scripts, zero sepolicy patches, bypass Zygisk.
        clear_runtime_sets(data_dir);
        return Ok(());
    }

    // 1. Apply pending module removals and staged updates.
    process_pending_updates_and_removals(data_dir, unprivileged_test);
    sync_adb_links(data_dir, unprivileged_test);

    // 2. Apply runtime `sepolicy.rule` from enabled modules before services/mounts start.
    let active_dirs = enabled_module_dirs(data_dir);
    if !unprivileged_test {
        sepolicy::apply_module_sepolicy_rules(&active_dirs);
    }

    // 3. Run `post-fs-data.d/*.sh` and per-module `post-fs-data.sh`.
    run_stage_scripts(data_dir, "post-fs-data.sh", "post-fs-data.d", false, unprivileged_test);

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
            let meta = meta_dir.display().to_string();
            let _ = run_script(
                data_dir,
                &metamount,
                &[("MODDIR", &meta), ("MODULE_DIR", &modules_dir(data_dir).display().to_string())],
                "metamodule.metamount",
                Wait::Upto(Duration::from_secs(20)),
                unprivileged_test,
            );
            let after = mount::snapshot_mountpoints();
            let added: Vec<String> = after.difference(&before).cloned().collect();
            MountsSet { paths: added }
        } else {
            mount::execute_hybrid_mount(&active_dirs, unprivileged_test).0
        }
    } else {
        mount::execute_hybrid_mount(&active_dirs, unprivileged_test).0
    };
    let _ = publish_if_changed(&data_dir.join("mounts.set"), &mounts_set.encode());
    let _ = publish_unmount_set(data_dir);
    let _ = publish_zygisk_set(data_dir, false);

    // 6. Run `post-mount.d/*.sh` and per-module `post-mount.sh`.
    run_stage_scripts(data_dir, "post-mount.sh", "post-mount.d", false, unprivileged_test);
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
    run_stage_scripts(data_dir, "service.sh", "service.d", true, unprivileged_test);
}

/// Asynchronous `boot-completed` stage: runs `boot-completed.sh`, waits stability window, resets Bootguard.
pub fn stage_boot_completed(data_dir: &Path, meta_override: Option<&Path>, unprivileged_test: bool) {
    if !is_module_engine_enabled(data_dir) {
        return;
    }
    let bg_paths = bootguard::BootguardPaths::resolve(data_dir, meta_override);
    let status = bootguard::read_status(data_dir);
    if !status.safe_mode {
        run_stage_scripts(data_dir, "boot-completed.sh", "boot-completed.d", true, unprivileged_test);
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
    check_install_safety(data_dir, prop.metamodule, &prop.id).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Stage into `modules_update/<id>` (clean directory).
    let stage_dir = modules_update_dir(data_dir).join(&prop.id);
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir)?;

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

    // The installer script always runs (a module without customize.sh still gets the default
    // permissions and REPLACE/REMOVE handling), through the metamodule's metainstall.sh if any.
    let metainstall = if prop.metamodule {
        None
    } else {
        find_active_metamodule(data_dir).and_then(|m| fs::read_to_string(m.join("metainstall.sh")).ok())
    };
    let script_path = stage_dir.join(".akar_installer.sh");
    fs::write(&script_path, installer::script(metainstall.as_deref()))?;
    let zip_abs = fs::canonicalize(zip_path).unwrap_or_else(|_| zip_path.to_path_buf());
    let (modpath, zipfile) = (stage_dir.display().to_string(), zip_abs.display().to_string());
    let mut env: Vec<(&str, &str)> = vec![("MODPATH", &modpath), ("ZIPFILE", &zipfile), ("OUTFD", "1")];
    if skip_unzip {
        env.push(("AKAR_SKIPUNZIP", "1"));
    }
    let (code, script_out) = run_script(
        data_dir,
        &script_path,
        &env,
        &format!("{}.install", prop.id),
        Wait::KillAfter(INSTALL_TIMEOUT),
        unprivileged_test,
    )?;
    let _ = fs::remove_file(&script_path);
    log.push_str(&script_out);
    if code != 0 {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(io::Error::new(io::ErrorKind::Other, format!("installer script failed (exit {code}):\n{log}")));
    }

    let hot_request = fs::read_to_string(stage_dir.join(installer::HOT_MARKER)).ok();
    let _ = fs::remove_file(stage_dir.join(installer::HOT_MARKER));
    let live_dir = modules_dir(data_dir).join(&prop.id);
    fs::create_dir_all(modules_dir(data_dir))?;
    let mut hot_installed = false;
    if let Some(run) = hot_request {
        match hot_install(data_dir, &prop, run.trim(), unprivileged_test) {
            Ok(note) => {
                log.push_str(&note);
                hot_installed = true;
            }
            Err(e) => {
                log.push_str(&format!("- Hot install skipped: {e}\n- Reboot to apply the module\n"));
            }
        }
    }
    if !hot_installed {
        // Visible in the list right away, with the new version; promoted at the next boot.
        fs::create_dir_all(&live_dir)?;
        fs::copy(stage_dir.join("module.prop"), live_dir.join("module.prop"))?;
        fs::write(live_dir.join("update"), b"")?;
        let _ = fs::remove_file(live_dir.join("remove"));
        let _ = fs::remove_file(live_dir.join("disable"));
        log.push_str("- Staged for activation on next reboot\n");
    }

    // Auto-enable the module engine when the user explicitly installs a module.
    let _ = set_module_engine_enabled(data_dir, true);
    if !unprivileged_test {
        sync_adb_links(data_dir, false);
    }
    let _ = publish_zygisk_set(data_dir, bootguard::read_status(data_dir).safe_mode);
    Ok((prop, log, hot_installed))
}

/// Resolves `MODULE_HOT_RUN_SCRIPT` to a file inside the staged module. `Ok(None)` when empty
/// or missing (skipped, like the metamodule implementations do).
pub fn check_hot_run_script(stage_dir: &Path, script: &str) -> Result<Option<PathBuf>, String> {
    if script.is_empty() {
        return Ok(None);
    }
    let rel: PathBuf = Path::new(script).components().filter(|c| !matches!(c, std::path::Component::CurDir)).collect();
    if rel.as_os_str().is_empty() || !rel.components().all(|c| matches!(c, std::path::Component::Normal(_))) {
        return Err(format!("invalid MODULE_HOT_RUN_SCRIPT '{script}'"));
    }
    let path = stage_dir.join(&rel);
    if fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    let resolved = fs::canonicalize(&path).map_err(|e| e.to_string())?;
    let root = fs::canonicalize(stage_dir).map_err(|e| e.to_string())?;
    if !resolved.is_file() || !resolved.starts_with(&root) {
        return Err(format!("MODULE_HOT_RUN_SCRIPT '{script}' is not a file inside the module"));
    }
    Ok(Some(rel))
}

/// Makes a staged module live without a reboot. The old live dir is moved to the trash (its
/// scripts or mounts may still use it) and deleted at the next boot. Partition files are
/// mounted at the next boot.
fn hot_install(data_dir: &Path, prop: &ModuleProp, run_script_name: &str, unprivileged_test: bool) -> Result<String, String> {
    if prop.metamodule {
        return Err("metamodules are always applied at boot".into());
    }
    if bootguard::read_status(data_dir).safe_mode {
        return Err("modules are disabled in safe mode".into());
    }
    let stage_dir = modules_update_dir(data_dir).join(&prop.id);
    let live_dir = modules_dir(data_dir).join(&prop.id);
    let run = check_hot_run_script(&stage_dir, run_script_name)?;

    let stashed = if live_dir.exists() {
        let trash = hot_trash_dir(data_dir);
        fs::create_dir_all(&trash).map_err(|e| e.to_string())?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let target = trash.join(format!("{}.{nanos}", prop.id));
        fs::rename(&live_dir, &target).map_err(|e| format!("cannot stash the live module: {e}"))?;
        Some(target)
    } else {
        None
    };
    if let Err(e) = fs::rename(&stage_dir, &live_dir) {
        if let Some(old) = stashed {
            let _ = fs::rename(old, &live_dir);
        }
        return Err(format!("cannot activate: {e}"));
    }

    let mut note = String::from("- Module activated without reboot (hot install)\n");
    if !unprivileged_test {
        label_zygisk_tree(&live_dir);
        if live_dir.join("sepolicy.rule").is_file() {
            // The policy is rebuilt from every enabled module, so earlier rules stay.
            sepolicy::apply_module_sepolicy_rules(&enabled_module_dirs(data_dir));
        }
        let props = live_dir.join("system.prop");
        if props.is_file() {
            let _ = resetprop::load_prop_file(Path::new("/dev/__properties__"), &props);
        }
    }
    if !live_dir.join("skip_mount").exists() && mount::PARTITIONS.iter().any(|p| live_dir.join(p).is_dir()) {
        note.push_str("- Note: partition files are mounted on the next boot\n");
    }
    if let Some(rel) = run {
        let dir = live_dir.display().to_string();
        note.push_str(&format!("- Running {}\n", rel.display()));
        if let Ok((_, out)) = run_script(
            data_dir,
            &live_dir.join(&rel),
            &[("MODDIR", &dir), ("KSU_MODULE", &prop.id)],
            &format!("{}.hot", prop.id),
            Wait::Upto(HOT_SCRIPT_TIMEOUT),
            unprivileged_test,
        ) {
            note.push_str(&out);
        }
    }
    Ok(note)
}

/// `/data/adb` links, including `metamodule` for the active one.
fn sync_adb_links(data_dir: &Path, unprivileged_test: bool) {
    if unprivileged_test {
        return;
    }
    let meta = find_active_metamodule(data_dir);
    let links = compat_ns::plan_links(data_dir, Path::new(compat_ns::REAL_ROOTD_BIN), meta.as_deref());
    let _ = compat_ns::sync_adb_links(Path::new(compat_ns::ADB_DIR), &links);
}

/// KSU's rule: a regular install waits while the metamodule that would run it is mid-change.
pub fn check_install_safety(data_dir: &Path, installing_metamodule: bool, id: &str) -> Result<(), String> {
    let Some(meta) = find_any_metamodule(data_dir) else { return Ok(()) };
    let meta_id = meta.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if installing_metamodule {
        if meta_id != id && !meta.join("remove").exists() {
            return Err(format!("metamodule {meta_id} is installed; remove it before installing another"));
        }
        return Ok(());
    }
    let has_metainstall = meta.join("metainstall.sh").is_file()
        || modules_update_dir(data_dir).join(&meta_id).join("metainstall.sh").is_file();
    if !has_metainstall {
        return Ok(());
    }
    if meta.join("update").exists() || meta.join("remove").exists() {
        return Err(format!("metamodule {meta_id} changes at the next boot; reboot first"));
    }
    Ok(())
}

/// Any installed metamodule, enabled or not.
fn find_any_metamodule(data_dir: &Path) -> Option<PathBuf> {
    let rd = fs::read_dir(modules_dir(data_dir)).ok()?;
    let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    dirs.sort();
    dirs.into_iter().find(|d| {
        fs::read_to_string(d.join("module.prop"))
            .ok()
            .and_then(|r| ModuleProp::parse(&r).ok())
            .is_some_and(|p| p.metamodule)
    })
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
    let d = dir.display().to_string();
    run_script(
        data_dir,
        &script,
        &[("MODDIR", &d), ("KSU_MODULE", id)],
        &format!("{id}.action"),
        Wait::Upto(Duration::from_secs(60)),
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
        "config" => cli_config(data_dir, &args[1..], std::env::var("KSU_MODULE").ok()),
        _ => {
            eprintln!("unknown module subcommand: {sub}");
            2
        }
    }
}

/// `module config <get|set|delete|list|clear> …`. Inside a module script (KSU_MODULE set) the
/// module is implied, as with ksud; otherwise the first operand names it (Laras, adb).
pub fn cli_config(data_dir: &Path, args: &[String], ksu_module: Option<String>) -> i32 {
    let op = args.first().map(String::as_str).unwrap_or("");
    let temp = args.iter().any(|a| a == "--temp" || a == "-t");
    let stdin = args.iter().any(|a| a == "--stdin");
    let mut rest: Vec<&str> = args.iter().skip(1).map(String::as_str).filter(|a| !matches!(*a, "--temp" | "-t" | "--stdin")).collect();
    let id = match ksu_module.filter(|m| validate_module_id(m)) {
        Some(m) => m,
        None if rest.is_empty() => return 2,
        None => rest.remove(0).to_string(),
    };
    if !validate_module_id(&id) {
        eprintln!("invalid module id: {id}");
        return 2;
    }
    match (op, rest.as_slice()) {
        ("get", [key]) => match load_module_config(data_dir, &id).get(key) {
            Some(v) => {
                println!("{v}");
                0
            }
            None => 1,
        },
        ("set", [key, rest_v @ ..]) => {
            let value = match rest_v.first() {
                Some(v) if !stdin => v.to_string(),
                _ => {
                    let mut v = String::new();
                    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut v).is_err() {
                        return 1;
                    }
                    v
                }
            };
            if save_module_config_key(data_dir, &id, key, Some(&value), temp).is_ok() { 0 } else { 1 }
        }
        ("delete", [key]) => {
            if save_module_config_key(data_dir, &id, key, None, temp).is_ok() { 0 } else { 1 }
        }
        ("list", []) => {
            for (k, v) in load_module_config(data_dir, &id).entries {
                println!("{k}={v}");
            }
            0
        }
        ("clear", []) => {
            let f = module_config_dir(data_dir, &id).join(if temp { "tmp.config" } else { "persist.config" });
            let _ = fs::remove_file(f);
            0
        }
        _ => 2,
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

    fn tmp(tag: &str) -> PathBuf {
        let t = std::env::temp_dir().join(format!("yasvara-mod-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&t);
        fs::create_dir_all(t.join("data")).unwrap();
        t
    }

    fn prop(id: &str, extra: &str) -> Vec<u8> {
        format!("id={id}\nname=N {id}\nversion=1.0\nversionCode=1\nauthor=Y\ndescription=D\n{extra}").into_bytes()
    }

    fn install(data: &Path, tmp: &Path, entries: &[(&str, &[u8])]) -> io::Result<(ModuleProp, String, bool)> {
        let zip_file = tmp.join(format!("m{}.zip", entries.len()));
        fs::write(&zip_file, build_test_zip(entries)).unwrap();
        install_module_zip(data, &zip_file, true)
    }

    #[test]
    fn install_stages_until_boot_then_actions_and_sets() {
        let t = tmp("life");
        let data = t.join("data");
        let meta = t.join("meta");
        let p = prop("hello_mod", "");
        let (prop, log, hot) = install(&data, &t, &[
            ("module.prop", &p),
            ("customize.sh", b"ui_print \"customizing $ARCH\"\n"),
            ("action.sh", b"echo action-ran\n"),
        ])
        .unwrap();
        assert_eq!(prop.id, "hello_mod");
        assert!(!hot, "no opt-in, no hot install");
        assert!(log.contains("customizing arm") || log.contains("customizing x") || log.contains("customizing"), "{log}");
        assert!(data.join("modules/hello_mod/update").is_file(), "listed with the update marker");
        assert!(data.join("modules_update/hello_mod/action.sh").is_file());
        assert!(data.join("log/hello_mod.install.log").is_file());

        // Next boot promotes it.
        stage_post_fs_data(&data, Some(&meta), true).unwrap();
        assert!(data.join("modules/hello_mod/action.sh").is_file());
        assert!(!data.join("modules/hello_mod/update").exists());
        assert!(!data.join("modules_update/hello_mod").exists());

        let (code, out) = run_module_action(&data, "hello_mod", true).unwrap();
        assert_eq!(code, 0);
        assert!(out.contains("action-ran"));

        save_module_config_key(&data, "hello_mod", "manage.play_integrity", Some("true"), false).unwrap();
        assert!(active_managed_features(&data).contains("play_integrity"));
        assert!(data.join("mounts.set").is_file());
        assert!(data.join("unmount.set").is_file());
        assert!(!data.join("zygisk.set").exists(), "Zygisk must be OFF by default");
        assert_eq!(hide_bits(&data), sys::HIDE_MOUNTS, "active module: mount filter only");

        fs::write(data.join("zygisk.conf"), "enabled=1\n").unwrap();
        publish_zygisk_set(&data, false).unwrap();
        assert!(data.join("zygisk.set").is_file());
        assert_eq!(hide_bits(&data), sys::HIDE_MOUNTS, "Zygisk on with no Zygisk module: no maps filter");
        fs::create_dir_all(data.join("modules/hello_mod/zygisk")).unwrap();
        fs::write(data.join("modules/hello_mod/zygisk/arm64-v8a.so"), b"\x7fELF").unwrap();
        publish_zygisk_set(&data, false).unwrap();
        assert_eq!(hide_bits(&data), sys::HIDE_MOUNTS | sys::HIDE_MAPS);
        publish_zygisk_set(&data, true).unwrap();
        assert_eq!(hide_bits(&data), sys::HIDE_MOUNTS, "safe bypass drops the maps filter");

        set_module_engine_enabled(&data, false).unwrap();
        stage_post_fs_data(&data, Some(&meta), true).unwrap();
        assert!(!data.join("mounts.set").exists(), "disabled engine must leave zero mounts.set");
        assert!(!data.join("zygisk.set").exists(), "disabled engine must leave zero zygisk.set");
        assert_eq!(hide_bits(&data), 0, "engine off: both kernel filters off");
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn hot_install_is_opt_in_stashes_the_old_dir_and_runs_the_script() {
        let t = tmp("hot");
        let data = t.join("data");
        let p1 = prop("hot_mod", "");
        install(&data, &t, &[("module.prop", &p1), ("customize.sh", b"MODULE_HOT_INSTALL_REQUEST=true\n")]).unwrap();
        assert!(data.join("modules/hot_mod/module.prop").is_file());
        fs::write(data.join("modules/hot_mod/in_use"), b"x").unwrap();

        let p2 = prop("hot_mod", "");
        let (_, log, hot) = install(&data, &t, &[
            ("module.prop", &p2),
            ("customize.sh", b"MODULE_HOT_INSTALL_REQUEST=true\nMODULE_HOT_RUN_SCRIPT=service.sh\n"),
            ("service.sh", b"echo hot-script-ran\n"),
        ])
        .unwrap();
        assert!(hot, "{log}");
        assert!(log.contains("hot-script-ran"), "{log}");
        assert!(!data.join("modules/hot_mod/in_use").exists(), "new dir is live");
        let trash: Vec<_> = fs::read_dir(data.join("hot_install_trash")).unwrap().flatten().collect();
        assert_eq!(trash.len(), 1, "old dir stashed, not deleted");
        assert!(trash[0].path().join("in_use").is_file());

        // The trash goes at the next boot.
        stage_post_fs_data(&data, None, true).unwrap();
        assert!(!data.join("hot_install_trash").exists());
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn hot_run_script_must_stay_inside_the_module() {
        let t = tmp("hotscript");
        let d = t.join("m");
        fs::create_dir_all(d.join("bin")).unwrap();
        fs::write(d.join("bin/run.sh"), b"").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.join("evil")).unwrap();
        assert_eq!(check_hot_run_script(&d, "").unwrap(), None);
        assert_eq!(check_hot_run_script(&d, "./bin/run.sh").unwrap(), Some(PathBuf::from("bin/run.sh")));
        assert_eq!(check_hot_run_script(&d, "missing.sh").unwrap(), None);
        assert!(check_hot_run_script(&d, "../x.sh").is_err());
        assert!(check_hot_run_script(&d, "/system/bin/sh").is_err());
        assert!(check_hot_run_script(&d, "evil").is_err());
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn failing_installer_leaves_nothing_behind() {
        let t = tmp("abort");
        let data = t.join("data");
        let p = prop("bad_mod", "");
        let e = install(&data, &t, &[("module.prop", &p), ("customize.sh", b"abort \"! nope\"\n")]).unwrap_err();
        assert!(e.to_string().contains("nope"));
        assert!(!data.join("modules_update/bad_mod").exists());
        assert!(!data.join("modules/bad_mod").exists());
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn detached_stages_return_at_once_and_log_per_module() {
        let t = tmp("stages");
        let data = t.join("data");
        let m = data.join("modules/slow_mod");
        fs::create_dir_all(&m).unwrap();
        fs::write(m.join("module.prop"), prop("slow_mod", "")).unwrap();
        fs::write(m.join("service.sh"), b"echo started:$KSU_MODULE\nsleep 30\n").unwrap();
        set_module_engine_enabled(&data, true).unwrap();
        let start = Instant::now();
        stage_services(&data, true);
        assert!(start.elapsed() < Duration::from_secs(2), "service.sh must not block the stage");
        let log = data.join("log/slow_mod.service.log");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !fs::read_to_string(&log).unwrap_or_default().contains("started:slow_mod") {
            assert!(Instant::now() < deadline, "service.sh never started");
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = Command::new("pkill").args(["-f", "[s]leep 30"]).status();
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn blocking_stage_stops_waiting_at_the_budget() {
        let t = tmp("budget");
        let data = t.join("data");
        let s = data.join("hang.sh");
        fs::write(&s, b"echo begin\nsleep 5\n").unwrap();
        let start = Instant::now();
        let (code, out) = run_script(&data, &s, &[], "hang", Wait::Upto(Duration::from_millis(300)), true).unwrap();
        assert_eq!(code, 124);
        assert!(out.contains("begin"));
        assert!(start.elapsed() < Duration::from_secs(2));
        let (code, _) = run_script(&data, &s, &[], "hang", Wait::KillAfter(Duration::from_millis(200)), true).unwrap();
        assert_eq!(code, 124);
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn logs_rotate() {
        let t = tmp("rotate");
        let data = t.join("data");
        fs::create_dir_all(data.join("log")).unwrap();
        fs::write(data.join("log/x.log"), vec![b'a'; (LOG_ROTATE_BYTES + 1) as usize]).unwrap();
        drop(open_log(&data, "x"));
        assert!(data.join("log/x.log.1").is_file());
        assert_eq!(fs::metadata(data.join("log/x.log")).unwrap().len(), 0);
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn config_cli_ksu_form_and_explicit_form() {
        let t = tmp("config");
        let data = t.join("data");
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(cli_config(&data, &a(&["set", "override.description", "hello"]), Some("ksu_mod".into())), 0);
        assert_eq!(load_module_config(&data, "ksu_mod").get("override.description"), Some("hello"));
        assert_eq!(cli_config(&data, &a(&["set", "ksu_mod", "k", "v", "--temp"]), None), 0);
        assert_eq!(load_module_config(&data, "ksu_mod").get("k"), Some("v"));
        assert_eq!(cli_config(&data, &a(&["delete", "k", "--temp"]), Some("ksu_mod".into())), 0);
        assert_eq!(load_module_config(&data, "ksu_mod").get("k"), None);
        assert_eq!(cli_config(&data, &a(&["clear"]), Some("ksu_mod".into())), 0);
        assert_eq!(load_module_config(&data, "ksu_mod").get("override.description"), None);
        assert_eq!(cli_config(&data, &a(&["get", "../evil", "k"]), None), 2);
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn metamodule_guard_metainstall_and_metauninstall() {
        let t = tmp("meta");
        let data = t.join("data");
        let mm = data.join("modules/meta_a");
        fs::create_dir_all(&mm).unwrap();
        fs::write(mm.join("module.prop"), prop("meta_a", "metamodule=1\n")).unwrap();
        fs::write(mm.join("metainstall.sh"), b"ui_print via-metainstall\ninstall_module\n").unwrap();
        fs::write(mm.join("metauninstall.sh"), b"echo uninstalling:$MODULE_ID\n").unwrap();
        set_module_engine_enabled(&data, true).unwrap();

        // A second metamodule is refused.
        let pb = prop("meta_b", "metamodule=1\n");
        assert!(install(&data, &t, &[("module.prop", &pb)]).unwrap_err().to_string().contains("meta_a"));

        // Regular installs go through metainstall.sh.
        let pr = prop("reg_mod", "");
        let (_, log, _) = install(&data, &t, &[("module.prop", &pr), ("customize.sh", b"ui_print from-customize\n")]).unwrap();
        assert!(log.contains("via-metainstall") && log.contains("from-customize"), "{log}");

        // While the metamodule is mid-update, regular installs wait.
        fs::write(mm.join("update"), b"").unwrap();
        assert!(install(&data, &t, &[("module.prop", &pr)]).is_err());
        fs::remove_file(mm.join("update")).unwrap();

        // Removal runs metauninstall.sh with MODULE_ID.
        stage_post_fs_data(&data, None, true).unwrap();
        set_module_remove(&data, "reg_mod", true).unwrap();
        process_pending_updates_and_removals(&data, true);
        assert!(!data.join("modules/reg_mod").exists());
        let log = fs::read_to_string(data.join("log/metamodule.metauninstall.log")).unwrap();
        assert!(log.contains("uninstalling:reg_mod"), "{log}");
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn sets_bump_the_generation_only_when_their_bytes_change() {
        use std::sync::atomic::Ordering;
        let t = tmp("gen");
        let data = t.join("data");
        fs::write(data.join("unmount.conf"), "default_unmount=0\n").unwrap();
        // Other tests bump too (shared counter): compare a monotonic delta around our calls.
        let before = sys::GEN_BUMPS.load(Ordering::SeqCst);
        publish_unmount_set(&data).unwrap();
        let after_first = sys::GEN_BUMPS.load(Ordering::SeqCst);
        assert!(after_first > before, "first publish bumps");
        let raw = fs::read(data.join("unmount.set")).unwrap();
        publish_unmount_set(&data).unwrap();
        assert_eq!(fs::read(data.join("unmount.set")).unwrap(), raw);
        assert_eq!(fs::metadata(data.join("unmount.set.new")).ok().map(|_| ()), None);
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn unchanged_publish_does_not_rewrite_the_file() {
        let t = tmp("same");
        let data = t.join("data");
        publish_if_changed(&data.join("x.set"), b"abc").unwrap();
        let m1 = fs::metadata(data.join("x.set")).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        publish_if_changed(&data.join("x.set"), b"abc").unwrap();
        assert_eq!(fs::metadata(data.join("x.set")).unwrap().modified().unwrap(), m1);
        publish_if_changed(&data.join("x.set"), b"abd").unwrap();
        assert_eq!(fs::read(data.join("x.set")).unwrap(), b"abd");
        let _ = fs::remove_dir_all(&t);
    }

    #[test]
    fn denylist_apps_are_unmounted_even_with_zygisk_off_and_others_keep_modules() {
        let t = tmp("d1");
        let data = t.join("data");
        fs::write(data.join("zygisk.conf"), "enabled=0\ndenylist=10200,10300\n").unwrap();
        publish_unmount_set(&data).unwrap();
        let set = UnmountSet::decode(&fs::read(data.join("unmount.set")).unwrap()).unwrap();
        assert!(!set.default_unmount_non_root, "D1: Magisk semantics by default");
        assert!(set.should_unmount(10200, false), "protected app");
        assert!(set.should_unmount(110300, false), "protected app, secondary user");
        assert!(!set.should_unmount(10999, false), "unprotected app keeps module files");
        // The KSU-style option stays available.
        fs::write(data.join("unmount.conf"), "default_unmount=1\nexempt=10999\n").unwrap();
        publish_unmount_set(&data).unwrap();
        let set = UnmountSet::decode(&fs::read(data.join("unmount.set")).unwrap()).unwrap();
        assert!(set.should_unmount(10500, false));
        assert!(!set.should_unmount(10500, true), "enrolled root app");
        assert!(!set.should_unmount(10999, false), "exempt");
        let _ = fs::remove_dir_all(&t);
    }
}
