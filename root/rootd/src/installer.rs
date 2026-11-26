// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! The shell side of module installation: the variables and helper functions Magisk and
//! KernelSU modules expect from `customize.sh` / legacy `install.sh`. Paths reach the script
//! only through the environment (`MODPATH`, `ZIPFILE`, ...), never through string formatting.

/// Helpers, then `install_module` (the default flow a metamodule's `metainstall.sh` calls).
pub const PRELUDE: &str = r#"umask 022
OUTFD=${OUTFD:-1}
BOOTMODE=true
NVBASE=/data/adb
TMPDIR="$MODPATH/.akar_tmp"
mkdir -p "$TMPDIR"

ui_print() { echo "$1"; }
abort() { ui_print "$1"; rm -rf "$TMPDIR"; exit 1; }
toupper() { echo "$@" | tr '[:lower:]' '[:upper:]'; }
grep_prop() {
  _gp_key="$1"; shift
  [ $# -eq 0 ] && set -- /system/build.prop
  sed -n "s/^$_gp_key=//p" "$@" 2>/dev/null | head -n 1
}
grep_get_prop() {
  _gp_val=$(getprop "$1" 2>/dev/null)
  if [ -n "$_gp_val" ]; then echo "$_gp_val"; else grep_prop "$1"; fi
}
grep_cmdline() {
  for _gc in $(cat /proc/cmdline 2>/dev/null) $(sed 's/ = /=/' /proc/bootconfig 2>/dev/null | tr -d '"'); do
    case "$_gc" in "$1"=*) echo "${_gc#*=}"; return;; esac
  done
}
is_mounted() { grep -q " $(readlink -f "$1") " /proc/mounts 2>/dev/null; }
set_perm() {
  chown -h "$2:$3" "$1" || return 1
  [ -L "$1" ] || chmod "$4" "$1" || return 1
  _sp_con="$5"; [ -z "$_sp_con" ] && _sp_con=u:object_r:system_file:s0
  chcon -h "$_sp_con" "$1" 2>/dev/null || true
}
set_perm_recursive() {
  find "$1" -type d 2>/dev/null | while read -r _sp_d; do set_perm "$_sp_d" "$2" "$3" "$4" "$6"; done
  find "$1" \( -type f -o -type l \) 2>/dev/null | while read -r _sp_f; do set_perm "$_sp_f" "$2" "$3" "$5" "$6"; done
}
mktouch() {
  mkdir -p "${1%/*}" 2>/dev/null
  if [ -z "$2" ]; then touch "$1"; else echo "$2" > "$1"; fi
  chmod 644 "$1"
}
mark_remove() { mkdir -p "${1%/*}" 2>/dev/null; mknod "$1" c 0 0; chmod 644 "$1"; }
mark_replace() { mkdir -p "$1"; touch "$1/.replace"; }
# The mount engine maps system/<partition> onto /<partition> itself.
handle_partition() { :; }
request_size_check() { reqSizeM=0; }
request_zip_size_check() { reqSizeM=0; }
check_managed_features() { :; }

case "$(getprop ro.product.cpu.abi)" in
  arm64*) ARCH=arm64; ABI=arm64-v8a; ABI32=armeabi-v7a; IS64BIT=true;;
  armeabi*|arm*) ARCH=arm; ABI=armeabi-v7a; ABI32=armeabi-v7a; IS64BIT=false;;
  x86_64*) ARCH=x64; ABI=x86_64; ABI32=x86; IS64BIT=true;;
  x86*) ARCH=x86; ABI=x86; ABI32=x86; IS64BIT=false;;
  riscv64*) ARCH=riscv64; ABI=riscv64; ABI32=; IS64BIT=true;;
  *) ARCH=arm64; ABI=arm64-v8a; ABI32=armeabi-v7a; IS64BIT=true;;
esac
API=$(getprop ro.build.version.sdk)
MODID=$(grep_prop id "$MODPATH/module.prop")
MODNAME=$(grep_prop name "$MODPATH/module.prop")
MODAUTH=$(grep_prop author "$MODPATH/module.prop")
KSU_MODULE="$MODID"
export ARCH ABI ABI32 IS64BIT API MODID KSU_MODULE

install_module() {
  REPLACE=""; REMOVE=""
  if [ ! -f "$MODPATH/customize.sh" ] && [ -f "$MODPATH/install.sh" ]; then
    SKIPMOUNT=false; PROPFILE=false; POSTFSDATA=false; LATESTARTSERVICE=false
    . "$MODPATH/install.sh"
    command -v print_modname >/dev/null 2>&1 && print_modname
    command -v on_install >/dev/null 2>&1 && on_install
    [ "$SKIPMOUNT" = true ] && touch "$MODPATH/skip_mount"
    [ "$PROPFILE" = true ] || rm -f "$MODPATH/system.prop"
    [ "$POSTFSDATA" = true ] || rm -f "$MODPATH/post-fs-data.sh"
    [ "$LATESTARTSERVICE" = true ] || rm -f "$MODPATH/service.sh"
    command -v set_permissions >/dev/null 2>&1 && set_permissions
    rm -f "$MODPATH/install.sh"
  else
    if [ "$AKAR_SKIPUNZIP" != 1 ]; then
      set_perm_recursive "$MODPATH" 0 0 0755 0644
      for _d in system/bin system/xbin system/system_ext/bin; do
        [ -d "$MODPATH/$_d" ] && set_perm_recursive "$MODPATH/$_d" 0 2000 0755 0755
      done
      [ -d "$MODPATH/system/vendor" ] && set_perm_recursive "$MODPATH/system/vendor" 0 2000 0755 0755 u:object_r:vendor_file:s0
    fi
    [ -f "$MODPATH/customize.sh" ] && . "$MODPATH/customize.sh"
  fi
  for _t in $REPLACE; do mark_replace "$MODPATH$_t"; done
  for _t in $REMOVE; do mark_remove "$MODPATH$_t"; done
  if [ "$MODULE_HOT_INSTALL_REQUEST" = true ]; then
    printf '%s' "$MODULE_HOT_RUN_SCRIPT" > "$MODPATH/.akar_hot_install"
  else
    rm -f "$MODPATH/.akar_hot_install"
  fi
  rm -rf "$MODPATH/customize.sh" "$MODPATH/README.md" "$MODPATH/system/placeholder" "$TMPDIR"
  rm -rf "$MODPATH"/.git*
}
"#;

/// The script the installer runs: helpers, then either the active metamodule's
/// `metainstall.sh` (which calls `install_module` itself) or the default flow.
pub fn script(metainstall: Option<&str>) -> String {
    let mut s = String::with_capacity(PRELUDE.len() + 256);
    s.push_str(PRELUDE);
    match metainstall {
        Some(meta) => {
            s.push_str(meta);
            s.push('\n');
        }
        None => s.push_str("install_module\n"),
    }
    s.push_str("exit 0\n");
    s
}

/// Marker written by the prelude when the module asked for a hot install; its content is
/// `MODULE_HOT_RUN_SCRIPT` (may be empty).
pub const HOT_MARKER: &str = ".akar_hot_install";

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    fn run(modpath: &Path, extra: &[(&str, &str)]) -> (i32, String) {
        let script = modpath.join(".installer.sh");
        fs::write(&script, script_body(None)).unwrap();
        let mut c = Command::new("/bin/sh");
        c.arg(&script).env("MODPATH", modpath).env("PATH", "/usr/bin:/bin");
        for (k, v) in extra {
            c.env(k, v);
        }
        let out = c.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
        (out.status.code().unwrap_or(-1), text)
    }

    fn script_body(meta: Option<&str>) -> String {
        // getprop is absent on the host; give the prelude a stub.
        format!("getprop() {{ case \"$1\" in ro.product.cpu.abi) echo arm64-v8a;; ro.build.version.sdk) echo 36;; esac; }}\n{}", script(meta))
    }

    fn module(tag: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("akar-inst-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("module.prop"), "id=test_mod\nname=Test\nversion=1\nauthor=me\n").unwrap();
        for (p, c) in files {
            let f = d.join(p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, c).unwrap();
        }
        d
    }

    #[test]
    fn customize_sees_the_contract() {
        let d = module(
            "env",
            &[(
                "customize.sh",
                "ui_print \"arch=$ARCH abi=$ABI api=$API 64=$IS64BIT id=$MODID ksu=$KSU_MODULE\"\n\
                 ui_print \"name=$(grep_prop name \"$MODPATH/module.prop\")\"\n",
            )],
        );
        let (code, out) = run(&d, &[]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("arch=arm64 abi=arm64-v8a api=36 64=true id=test_mod ksu=test_mod"), "{out}");
        assert!(out.contains("name=Test"), "{out}");
        assert!(!d.join("customize.sh").exists(), "customize.sh is removed like KSU does");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn abort_fails_the_install() {
        let d = module("abort", &[("customize.sh", "abort \"! wrong arch\"\necho not-reached\n")]);
        let (code, out) = run(&d, &[]);
        assert_eq!(code, 1);
        assert!(out.contains("wrong arch") && !out.contains("not-reached"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn replace_remove_and_hot_marker() {
        let d = module(
            "markers",
            &[(
                "customize.sh",
                "REPLACE=\"/system/app/Foo\"\nMODULE_HOT_INSTALL_REQUEST=true\nMODULE_HOT_RUN_SCRIPT=service.sh\n",
            )],
        );
        let (code, out) = run(&d, &[]);
        assert_eq!(code, 0, "{out}");
        assert!(d.join("system/app/Foo/.replace").is_file());
        assert_eq!(fs::read_to_string(d.join(HOT_MARKER)).unwrap(), "service.sh");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn legacy_install_sh_callbacks_run() {
        let d = module(
            "legacy",
            &[
                ("install.sh", "SKIPMOUNT=true\nprint_modname() { ui_print legacy-name; }\non_install() { ui_print legacy-install; }\nset_permissions() { ui_print legacy-perms; }\n"),
                ("service.sh", "true\n"),
            ],
        );
        let (code, out) = run(&d, &[]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("legacy-name") && out.contains("legacy-install") && out.contains("legacy-perms"));
        assert!(d.join("skip_mount").is_file());
        assert!(!d.join("service.sh").exists(), "LATESTARTSERVICE=false drops service.sh");
        assert!(!d.join("install.sh").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn metainstall_replaces_the_default_flow() {
        let d = module("meta", &[("customize.sh", "ui_print from-customize\n")]);
        let script = d.join(".installer.sh");
        fs::write(&script, script_body(Some("ui_print meta-before\ninstall_module\nui_print meta-after"))).unwrap();
        let out = Command::new("/bin/sh").arg(&script).env("MODPATH", &d).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success());
        let (a, b, c) = (text.find("meta-before").unwrap(), text.find("from-customize").unwrap(), text.find("meta-after").unwrap());
        assert!(a < b && b < c, "{text}");
        let _ = fs::remove_dir_all(&d);
    }
}
