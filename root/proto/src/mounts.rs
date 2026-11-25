// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Compact binary sets published by `yasvara_rootd` and read by Zygote / Native Zygisk.
//!
//! All three files (`mounts.set`, `unmount.set`, `zygisk.set`) use simple little-endian
//! fixed headers + sorted UID arrays so Zygote's single-threaded `ForkCommon()` can parse
//! them in microseconds without dynamic linking or JSON parsers, and forked children inherit
//! the warm read-only CoW memory with zero syscalls.

pub const MOUNTS_MAGIC: [u8; 4] = *b"AKMT";
pub const UNMOUNT_MAGIC: [u8; 4] = *b"AKUM";
pub const ZYGISK_MAGIC: [u8; 4] = *b"AKZG";
pub const SET_VERSION: u32 = 1;

pub const UMF_DEFAULT_UNMOUNT_NON_ROOT: u32 = 1 << 0;

pub const ZGF_ENABLED: u32 = 1 << 0;
pub const ZGF_SAFE_BYPASS: u32 = 1 << 1;
pub const ZGF_HAS_SYSTEM_SERVER: u32 = 1 << 2;

pub const SCOPE_ALL_NON_DENYLIST: u8 = 0;
pub const SCOPE_EXPLICIT_ONLY: u8 = 1;

fn read_u32(buf: &[u8], at: &mut usize) -> Result<u32, &'static str> {
    if *at + 4 > buf.len() {
        return Err("truncated u32");
    }
    let v = u32::from_le_bytes([buf[*at], buf[*at + 1], buf[*at + 2], buf[*at + 3]]);
    *at += 4;
    Ok(v)
}

fn read_str(buf: &[u8], at: &mut usize, max_len: usize) -> Result<String, &'static str> {
    let len = read_u32(buf, at)? as usize;
    if len > max_len || *at + len > buf.len() {
        return Err("bad string length");
    }
    let s = std::str::from_utf8(&buf[*at..*at + len]).map_err(|_| "bad utf8")?;
    *at += len;
    Ok(s.to_string())
}

fn write_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Active module mountpoints written at `post-fs-data` and detached inside unmounted app namespaces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountsSet {
    pub paths: Vec<String>,
}

impl MountsSet {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.paths.len() * 32);
        out.extend_from_slice(&MOUNTS_MAGIC);
        out.extend_from_slice(&SET_VERSION.to_le_bytes());
        out.extend_from_slice(&(self.paths.len() as u32).to_le_bytes());
        for p in &self.paths {
            write_str(&mut out, p);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 12 || buf[0..4] != MOUNTS_MAGIC {
            return Err("bad mounts.set magic");
        }
        let mut at = 4;
        if read_u32(buf, &mut at)? != SET_VERSION {
            return Err("unsupported mounts.set version");
        }
        let count = read_u32(buf, &mut at)? as usize;
        if count > 4096 {
            return Err("too many mount paths");
        }
        let mut paths = Vec::with_capacity(count);
        for _ in 0..count {
            paths.push(read_str(buf, &mut at, 4096)?);
        }
        Ok(Self { paths })
    }
}

/// Per-UID unmount policy read by `Zygote.cpp` `TabirUnmount`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmountSet {
    pub default_unmount_non_root: bool,
    pub force_unmount_uids: Vec<u32>,
    pub exempt_uids: Vec<u32>,
}

impl Default for UnmountSet {
    fn default() -> Self {
        Self {
            default_unmount_non_root: true,
            force_unmount_uids: Vec::new(),
            exempt_uids: Vec::new(),
        }
    }
}

impl UnmountSet {
    pub fn encode(&self) -> Vec<u8> {
        let mut force = self.force_unmount_uids.clone();
        force.sort_unstable();
        force.dedup();
        let mut exempt = self.exempt_uids.clone();
        exempt.sort_unstable();
        exempt.dedup();
        let flags = if self.default_unmount_non_root { UMF_DEFAULT_UNMOUNT_NON_ROOT } else { 0 };
        let mut out = Vec::with_capacity(20 + (force.len() + exempt.len()) * 4);
        out.extend_from_slice(&UNMOUNT_MAGIC);
        out.extend_from_slice(&SET_VERSION.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&(force.len() as u32).to_le_bytes());
        for u in force {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&(exempt.len() as u32).to_le_bytes());
        for u in exempt {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 20 || buf[0..4] != UNMOUNT_MAGIC {
            return Err("bad unmount.set magic");
        }
        let mut at = 4;
        if read_u32(buf, &mut at)? != SET_VERSION {
            return Err("unsupported unmount.set version");
        }
        let flags = read_u32(buf, &mut at)?;
        let fc = read_u32(buf, &mut at)? as usize;
        if fc > 65536 {
            return Err("too many force uids");
        }
        let mut force_unmount_uids = Vec::with_capacity(fc);
        for _ in 0..fc {
            force_unmount_uids.push(read_u32(buf, &mut at)?);
        }
        let ec = read_u32(buf, &mut at)? as usize;
        if ec > 65536 {
            return Err("too many exempt uids");
        }
        let mut exempt_uids = Vec::with_capacity(ec);
        for _ in 0..ec {
            exempt_uids.push(read_u32(buf, &mut at)?);
        }
        Ok(Self {
            default_unmount_non_root: (flags & UMF_DEFAULT_UNMOUNT_NON_ROOT) != 0,
            force_unmount_uids,
            exempt_uids,
        })
    }

    pub fn should_unmount(&self, uid: u32, is_enrolled_root: bool) -> bool {
        let app_id = uid % 100_000;
        if app_id < 10_000 {
            return false;
        }
        if self.force_unmount_uids.binary_search(&uid).is_ok()
            || self.force_unmount_uids.binary_search(&app_id).is_ok()
        {
            return true;
        }
        if self.exempt_uids.binary_search(&uid).is_ok()
            || self.exempt_uids.binary_search(&app_id).is_ok()
        {
            return false;
        }
        self.default_unmount_non_root && !is_enrolled_root
    }
}

/// One Zygisk module entry inside `zygisk.set`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZygiskModuleEntry {
    pub id: String,
    pub mod_dir: String,
    pub lib64_path: String,
    pub lib32_path: String,
    pub scope_mode: u8,
    pub scope_uids: Vec<u32>,
}

/// Complete ROM-Native Zygisk dispatch table (`zygisk.set`) read by Zygote + `libyasvara_zygisk.so`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZygiskSet {
    pub enabled: bool,
    pub safe_bypass: bool,
    pub has_system_server_modules: bool,
    pub denylist_uids: Vec<u32>,
    pub modules: Vec<ZygiskModuleEntry>,
}

impl ZygiskSet {
    pub fn encode(&self) -> Vec<u8> {
        let mut deny = self.denylist_uids.clone();
        deny.sort_unstable();
        deny.dedup();
        let mut flags = 0u32;
        if self.enabled {
            flags |= ZGF_ENABLED;
        }
        if self.safe_bypass {
            flags |= ZGF_SAFE_BYPASS;
        }
        if self.has_system_server_modules {
            flags |= ZGF_HAS_SYSTEM_SERVER;
        }
        let mut out = Vec::with_capacity(64 + deny.len() * 4 + self.modules.len() * 128);
        out.extend_from_slice(&ZYGISK_MAGIC);
        out.extend_from_slice(&SET_VERSION.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&(deny.len() as u32).to_le_bytes());
        for u in deny {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&(self.modules.len() as u32).to_le_bytes());
        for m in &self.modules {
            write_str(&mut out, &m.id);
            write_str(&mut out, &m.mod_dir);
            write_str(&mut out, &m.lib64_path);
            write_str(&mut out, &m.lib32_path);
            out.push(m.scope_mode);
            let mut scope = m.scope_uids.clone();
            scope.sort_unstable();
            scope.dedup();
            out.extend_from_slice(&(scope.len() as u32).to_le_bytes());
            for u in scope {
                out.extend_from_slice(&u.to_le_bytes());
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 20 || buf[0..4] != ZYGISK_MAGIC {
            return Err("bad zygisk.set magic");
        }
        let mut at = 4;
        if read_u32(buf, &mut at)? != SET_VERSION {
            return Err("unsupported zygisk.set version");
        }
        let flags = read_u32(buf, &mut at)?;
        let dc = read_u32(buf, &mut at)? as usize;
        if dc > 65536 {
            return Err("too many denylist uids");
        }
        let mut denylist_uids = Vec::with_capacity(dc);
        for _ in 0..dc {
            denylist_uids.push(read_u32(buf, &mut at)?);
        }
        let mc = read_u32(buf, &mut at)? as usize;
        if mc > 256 {
            return Err("too many zygisk modules");
        }
        let mut modules = Vec::with_capacity(mc);
        for _ in 0..mc {
            let id = read_str(buf, &mut at, 128)?;
            let mod_dir = read_str(buf, &mut at, 1024)?;
            let lib64_path = read_str(buf, &mut at, 1024)?;
            let lib32_path = read_str(buf, &mut at, 1024)?;
            if at >= buf.len() {
                return Err("truncated scope_mode");
            }
            let scope_mode = buf[at];
            at += 1;
            let sc = read_u32(buf, &mut at)? as usize;
            if sc > 65536 {
                return Err("too many scope uids");
            }
            let mut scope_uids = Vec::with_capacity(sc);
            for _ in 0..sc {
                scope_uids.push(read_u32(buf, &mut at)?);
            }
            modules.push(ZygiskModuleEntry {
                id,
                mod_dir,
                lib64_path,
                lib32_path,
                scope_mode,
                scope_uids,
            });
        }
        Ok(Self {
            enabled: (flags & ZGF_ENABLED) != 0,
            safe_bypass: (flags & ZGF_SAFE_BYPASS) != 0,
            has_system_server_modules: (flags & ZGF_HAS_SYSTEM_SERVER) != 0,
            denylist_uids,
            modules,
        })
    }

    pub fn is_on_denylist(&self, uid: u32) -> bool {
        let app_id = uid % 100_000;
        self.denylist_uids.binary_search(&uid).is_ok()
            || self.denylist_uids.binary_search(&app_id).is_ok()
    }

    /// True if at least one Zygisk module targets this app UID (and the app is not on DenyList).
    /// When false, Zygote skips `dlopen("libyasvara_zygisk.so")` completely (zero overhead!).
    pub fn should_load_for_app(&self, uid: u32, is_64bit: bool) -> bool {
        if !self.enabled || self.safe_bypass || self.modules.is_empty() {
            return false;
        }
        if self.is_on_denylist(uid) {
            return false;
        }
        let app_id = uid % 100_000;
        self.modules.iter().any(|m| {
            let has_abi = if is_64bit { !m.lib64_path.is_empty() } else { !m.lib32_path.is_empty() };
            if !has_abi {
                return false;
            }
            if m.scope_mode == SCOPE_ALL_NON_DENYLIST {
                true
            } else {
                m.scope_uids.binary_search(&uid).is_ok() || m.scope_uids.binary_search(&app_id).is_ok()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounts_and_unmount_roundtrip() {
        let m = MountsSet { paths: vec!["/system/app".into(), "/vendor/etc".into()] };
        assert_eq!(MountsSet::decode(&m.encode()).unwrap(), m);

        let u = UnmountSet {
            default_unmount_non_root: true,
            force_unmount_uids: vec![10200, 10100],
            exempt_uids: vec![10300],
        };
        let dec = UnmountSet::decode(&u.encode()).unwrap();
        assert!(dec.should_unmount(10100, true)); // force unmount overrides enrolled root
        assert!(!dec.should_unmount(10300, false)); // explicit exempt
        assert!(dec.should_unmount(10400, false)); // default unmount for non-root
        assert!(!dec.should_unmount(10400, true)); // enrolled root keeps mounts by default
        assert!(!dec.should_unmount(1000, false)); // system uid never unmounted
    }

    #[test]
    fn zygisk_set_roundtrip_and_scope_skip() {
        let z = ZygiskSet {
            enabled: true,
            safe_bypass: false,
            has_system_server_modules: false,
            denylist_uids: vec![10500],
            modules: vec![ZygiskModuleEntry {
                id: "scoped_mod".into(),
                mod_dir: "/data/misc/yasvara_root/modules/scoped_mod".into(),
                lib64_path: "/data/misc/yasvara_root/modules/scoped_mod/zygisk/arm64-v8a.so".into(),
                lib32_path: String::new(),
                scope_mode: SCOPE_EXPLICIT_ONLY,
                scope_uids: vec![10222],
            }],
        };
        let dec = ZygiskSet::decode(&z.encode()).unwrap();
        assert_eq!(dec, z);
        assert!(dec.should_load_for_app(10222, true));
        assert!(!dec.should_load_for_app(10222, false)); // no 32-bit lib
        assert!(!dec.should_load_for_app(10333, true)); // out of scope -> zero dlopen!
        assert!(!dec.should_load_for_app(10500, true)); // denylist -> zero dlopen!
    }
}
