// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! ELF64 PLT/GOT hooker for Zygisk `pltHookRegister` (v4+: dev/ino, v1–v3: path regex) and
//! `pltHookCommit`. Walks loaded objects with `dl_iterate_phdr`, reads `PT_DYNAMIC` in memory
//! (`DT_JMPREL`, `DT_RELA`, packed `DT_ANDROID_RELA`) and swaps GLOB_DAT / JUMP_SLOT slots,
//! restoring each page's original protection.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::sync::Mutex;

#[derive(Clone)]
enum HookSel {
    DevIno { dev: u64, ino: u64 },
    /// v1/v2: POSIX regex matched against the loaded object's path.
    Regex(String),
}

#[derive(Clone)]
struct PltHookReq {
    sel: HookSel,
    symbol: String,
    new_func: usize,
    old_func_out: usize,
}

#[derive(Clone)]
struct PltExclude {
    regex: String,
    /// Empty means every symbol in a matching library.
    symbol: String,
}

static PENDING_HOOKS: Mutex<Vec<PltHookReq>> = Mutex::new(Vec::new());
static PENDING_EXCLUDES: Mutex<Vec<PltExclude>> = Mutex::new(Vec::new());

pub unsafe fn register(
    dev: libc::dev_t,
    ino: libc::ino_t,
    symbol: *const c_char,
    new_func: *mut c_void,
    old_func: *mut *mut c_void,
) {
    if symbol.is_null() || new_func.is_null() {
        return;
    }
    let Ok(sym_str) = CStr::from_ptr(symbol).to_str() else { return };
    if let Ok(mut list) = PENDING_HOOKS.lock() {
        list.push(PltHookReq {
            sel: HookSel::DevIno { dev: dev as u64, ino: ino as u64 },
            symbol: sym_str.to_string(),
            new_func: new_func as usize,
            old_func_out: old_func as usize,
        });
    }
}

/// v1 `pltHookRegister(regex, symbol, new, old)`.
pub unsafe fn register_regex(
    regex: *const c_char,
    symbol: *const c_char,
    new_func: *mut c_void,
    old_func: *mut *mut c_void,
) {
    if regex.is_null() || symbol.is_null() || new_func.is_null() {
        return;
    }
    let Ok(re) = CStr::from_ptr(regex).to_str() else { return };
    let Ok(sym) = CStr::from_ptr(symbol).to_str() else { return };
    if let Ok(mut list) = PENDING_HOOKS.lock() {
        list.push(PltHookReq {
            sel: HookSel::Regex(re.to_string()),
            symbol: sym.to_string(),
            new_func: new_func as usize,
            old_func_out: old_func as usize,
        });
    }
}

/// v1 `pltHookExclude(regex, symbol)`. An empty symbol excludes the whole library.
pub unsafe fn exclude(regex: *const c_char, symbol: *const c_char) {
    if regex.is_null() {
        return;
    }
    let Ok(re) = CStr::from_ptr(regex).to_str() else { return };
    let sym = if symbol.is_null() {
        String::new()
    } else {
        CStr::from_ptr(symbol).to_str().unwrap_or("").to_string()
    };
    if let Ok(mut list) = PENDING_EXCLUDES.lock() {
        list.push(PltExclude { regex: re.to_string(), symbol: sym });
    }
}

pub unsafe fn commit() -> bool {
    let hooks = match PENDING_HOOKS.lock() {
        Ok(mut list) => std::mem::take(&mut *list),
        Err(_) => return false,
    };
    if hooks.is_empty() {
        return true;
    }
    let excludes = PENDING_EXCLUDES.lock().map(|mut l| std::mem::take(&mut *l)).unwrap_or_default();
    // One maps read and one regcomp per pattern per commit; no stat per loaded object.
    let maps = Maps::read_self();
    let regexes = Regexes::compile(
        hooks
            .iter()
            .filter_map(|h| match &h.sel {
                HookSel::Regex(r) => Some(r.as_str()),
                HookSel::DevIno { .. } => None,
            })
            .chain(excludes.iter().map(|e| e.regex.as_str())),
    );
    let mut state = CommitCtx { hooks: &hooks, excludes: &excludes, maps: &maps, regexes: &regexes, applied: 0, backups_written: Vec::new() };
    libc::dl_iterate_phdr(Some(phdr_cb), &mut state as *mut CommitCtx as *mut c_void);
    // A library that is not loaded yet is not an error. Callers that treat false as fatal
    // would otherwise disable themselves. mprotect failures are counted, not fatal.
    let _ = state.applied;
    true
}

struct CommitCtx<'a> {
    hooks: &'a [PltHookReq],
    excludes: &'a [PltExclude],
    maps: &'a Maps,
    regexes: &'a Regexes,
    applied: usize,
    backups_written: Vec<usize>,
}

struct MapEntry {
    start: usize,
    end: usize,
    prot: i32,
    dev: u64,
    ino: u64,
    path: String,
}

/// `/proc/self/maps`, read once per commit. Sorted by address (kernel order).
pub(crate) struct Maps(Vec<MapEntry>);

impl Maps {
    fn read_self() -> Self {
        Self::parse(&std::fs::read_to_string("/proc/self/maps").unwrap_or_default())
    }

    pub(crate) fn parse(text: &str) -> Self {
        let mut out = Vec::new();
        for line in text.lines() {
            let mut it = line.split_ascii_whitespace();
            let (Some(range), Some(perms), Some(_off), Some(dev), Some(ino)) =
                (it.next(), it.next(), it.next(), it.next(), it.next())
            else {
                continue;
            };
            let Some((a, b)) = range.split_once('-') else { continue };
            let (Ok(start), Ok(end)) = (usize::from_str_radix(a, 16), usize::from_str_radix(b, 16)) else {
                continue;
            };
            let p = perms.as_bytes();
            let mut prot = 0;
            if p.first() == Some(&b'r') {
                prot |= libc::PROT_READ;
            }
            if p.get(1) == Some(&b'w') {
                prot |= libc::PROT_WRITE;
            }
            if p.get(2) == Some(&b'x') {
                prot |= libc::PROT_EXEC;
            }
            let (maj, min) = dev.split_once(':').unwrap_or(("0", "0"));
            let maj = u32::from_str_radix(maj, 16).unwrap_or(0);
            let min = u32::from_str_radix(min, 16).unwrap_or(0);
            let ino: u64 = ino.parse().unwrap_or(0);
            let path = if ino == 0 {
                String::new()
            } else {
                let mut s = String::new();
                for tok in it {
                    if !s.is_empty() {
                        s.push(' ');
                    }
                    s.push_str(tok);
                }
                s
            };
            out.push(MapEntry {
                start,
                end,
                prot,
                dev: libc::makedev(maj, min) as u64,
                ino,
                path,
            });
        }
        Self(out)
    }

    /// Protection of the mapping holding `addr`; `PROT_READ` (RELRO) when unknown.
    pub(crate) fn prot_at(&self, addr: usize) -> i32 {
        let i = self.0.partition_point(|m| m.end <= addr);
        match self.0.get(i) {
            Some(m) if m.start <= addr && m.prot != 0 => m.prot,
            _ => libc::PROT_READ,
        }
    }

    /// File identity of a loaded object, from the mapping at its load base.
    pub(crate) fn dev_ino(&self, base: usize, path: &str) -> Option<(u64, u64)> {
        let i = self.0.partition_point(|m| m.end <= base);
        if let Some(m) = self.0.get(i) {
            if m.start <= base && m.ino != 0 && m.path == path {
                return Some((m.dev, m.ino));
            }
        }
        self.0.iter().find(|m| m.ino != 0 && m.path == path).map(|m| (m.dev, m.ino))
    }
}

struct Regexes(Vec<(String, Option<Box<libc::regex_t>>)>);

impl Regexes {
    fn compile<'a>(patterns: impl Iterator<Item = &'a str>) -> Self {
        let mut out: Vec<(String, Option<Box<libc::regex_t>>)> = Vec::new();
        for p in patterns {
            if out.iter().any(|(k, _)| k == p) {
                continue;
            }
            let re = std::ffi::CString::new(p).ok().and_then(|c| unsafe {
                let mut re: Box<libc::regex_t> = Box::new(std::mem::zeroed());
                (libc::regcomp(&mut *re, c.as_ptr(), libc::REG_NOSUB | libc::REG_EXTENDED) == 0).then_some(re)
            });
            out.push((p.to_string(), re));
        }
        Self(out)
    }

    fn is_match(&self, pattern: &str, text: &str) -> bool {
        let Some((_, Some(re))) = self.0.iter().find(|(k, _)| k == pattern) else { return false };
        let Ok(hay) = std::ffi::CString::new(text) else { return false };
        unsafe { libc::regexec(&**re, hay.as_ptr(), 0, std::ptr::null_mut(), 0) == 0 }
    }
}

impl Drop for Regexes {
    fn drop(&mut self) {
        for (_, re) in self.0.iter_mut() {
            if let Some(re) = re {
                unsafe { libc::regfree(&mut **re) };
            }
        }
    }
}

mod elf_arch {
    pub const PT_DYNAMIC: u32 = 2;
    pub const DT_NULL: i64 = 0;
    pub const DT_PLTRELSZ: i64 = 2;
    pub const DT_STRTAB: i64 = 5;
    pub const DT_SYMTAB: i64 = 6;
    pub const DT_RELA: i64 = 7;
    pub const DT_RELASZ: i64 = 8;
    pub const DT_JMPREL: i64 = 23;
    pub const DT_ANDROID_RELA: i64 = 0x6000_0011;
    pub const DT_ANDROID_RELASZ: i64 = 0x6000_0012;
    pub const R_JUMP_SLOT_AARCH64: u32 = 1026;
    pub const R_GLOB_DAT_AARCH64: u32 = 1025;
    pub const R_JUMP_SLOT_X86_64: u32 = 7;
    pub const R_GLOB_DAT_X86_64: u32 = 6;

    #[repr(C)]
    pub struct Dyn {
        pub d_tag: i64,
        pub d_val: u64,
    }

    #[repr(C)]
    pub struct Sym {
        pub st_name: u32,
        pub st_info: u8,
        pub st_other: u8,
        pub st_shndx: u16,
        pub st_value: u64,
        pub st_size: u64,
    }

    #[repr(C)]
    pub struct Rela {
        pub r_offset: u64,
        pub r_info: u64,
        pub r_addend: i64,
    }

    pub fn rel_sym(info: u64) -> usize {
        (info >> 32) as usize
    }

    pub fn rel_type(info: u64) -> u32 {
        (info & 0xffff_ffff) as u32
    }

    pub fn is_got_or_plt_rel(ty: u32) -> bool {
        matches!(
            ty,
            R_JUMP_SLOT_AARCH64 | R_GLOB_DAT_AARCH64 | R_JUMP_SLOT_X86_64 | R_GLOB_DAT_X86_64
        )
    }
}


fn page_size() -> usize {
    static PAGE_SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PAGE_SIZE.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE).max(4096) as usize })
}

/// Swaps one GOT slot and returns its previous value, restoring `restore` afterwards.
unsafe fn patch_got_slot(slot_addr: usize, new_fn: usize, restore: i32) -> Option<usize> {
    let page_size = page_size();
    let page_start = slot_addr & !(page_size - 1);
    if libc::mprotect(page_start as *mut c_void, page_size, libc::PROT_READ | libc::PROT_WRITE) != 0 {
        return None;
    }
    let slot = slot_addr as *mut usize;
    let prev = std::ptr::read_volatile(slot);
    std::ptr::write_volatile(slot, new_fn);
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    let _ = libc::mprotect(page_start as *mut c_void, page_size, restore);
    Some(prev)
}

impl CommitCtx<'_> {
    /// Patches `slot` for `h`. The module's backup receives the first original seen in this
    /// commit (a symbol may sit in both JMPREL and RELA), whatever the backup held before.
    unsafe fn hook_slot(&mut self, slot: usize, h: &PltHookReq) {
        if h.new_func == 0 {
            return;
        }
        let Some(prev) = patch_got_slot(slot, h.new_func, self.maps.prot_at(slot)) else { return };
        self.applied += 1;
        if h.old_func_out != 0 && !self.backups_written.contains(&h.old_func_out) {
            self.backups_written.push(h.old_func_out);
            *(h.old_func_out as *mut usize) = prev;
        }
    }
}

fn excluded(ctx: &CommitCtx<'_>, path: &str, symbol: &str) -> bool {
    ctx.excludes.iter().any(|e| {
        (e.symbol.is_empty() || e.symbol == symbol) && ctx.regexes.is_match(&e.regex, path)
    })
}

unsafe extern "C" fn phdr_cb(
    info: *mut libc::dl_phdr_info,
    _size: libc::size_t,
    data: *mut c_void,
) -> c_int {
    let ctx = &mut *(data as *mut CommitCtx<'_>);
    let info = &*info;
    if info.dlpi_name.is_null() || *info.dlpi_name == 0 {
        return 0;
    }
    let path = CStr::from_ptr(info.dlpi_name).to_str().unwrap_or("");
    let base = info.dlpi_addr as usize;
    let id = ctx.maps.dev_ino(base, path).or_else(|| {
        let mut st: libc::stat = std::mem::zeroed();
        (libc::stat(info.dlpi_name, &mut st) == 0).then_some((st.st_dev as u64, st.st_ino as u64))
    });
    let matching: Vec<&PltHookReq> = ctx
        .hooks
        .iter()
        .filter(|h| match &h.sel {
            HookSel::DevIno { dev: d, ino: i } => id == Some((*d, *i)),
            HookSel::Regex(re) => ctx.regexes.is_match(re, path) && !excluded(ctx, path, &h.symbol),
        })
        .collect();
    if matching.is_empty() {
        return 0;
    }

    let phdrs = std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);
    let mut dyn_ptr: *const elf_arch::Dyn = std::ptr::null();
    for ph in phdrs {
        if ph.p_type == elf_arch::PT_DYNAMIC {
            dyn_ptr = (base.wrapping_add(ph.p_vaddr as usize)) as *const elf_arch::Dyn;
            break;
        }
    }
    if dyn_ptr.is_null() {
        return 0;
    }

    let mut strtab: usize = 0;
    let mut symtab: usize = 0;
    let mut jmprel: usize = 0;
    let mut pltrelsz: usize = 0;
    let mut rel_tab: usize = 0;
    let mut rel_sz: usize = 0;
    let mut android_rela: usize = 0;
    let mut android_relasz: usize = 0;
    let mut d = dyn_ptr;
    while (*d).d_tag != elf_arch::DT_NULL {
        let val = (*d).d_val as usize;
        // On Android/Bionic, DT_* pointers in memory may already be relocated absolute addresses
        // or still relative to `base`; normalize safely.
        let norm = |v: usize| -> usize { if v < base { base.wrapping_add(v) } else { v } };
        match (*d).d_tag {
            elf_arch::DT_STRTAB => strtab = norm(val),
            elf_arch::DT_SYMTAB => symtab = norm(val),
            elf_arch::DT_JMPREL => jmprel = norm(val),
            elf_arch::DT_PLTRELSZ => pltrelsz = val,
            elf_arch::DT_RELA => rel_tab = norm(val),
            elf_arch::DT_RELASZ => rel_sz = val,
            elf_arch::DT_ANDROID_RELA => android_rela = norm(val),
            elf_arch::DT_ANDROID_RELASZ => android_relasz = val,
            _ => {}
        }
        d = d.add(1);
    }
    if strtab == 0 || symtab == 0 {
        return 0;
    }

    for (tab, sz) in [(jmprel, pltrelsz), (rel_tab, rel_sz)] {
        if tab == 0 || sz == 0 {
            continue;
        }
        let rels = std::slice::from_raw_parts(tab as *const elf_arch::Rela, sz / std::mem::size_of::<elf_arch::Rela>());
        for r in rels {
            hook_reloc(ctx, &matching, base, symtab, strtab, r.r_offset, r.r_info);
        }
    }
    if android_rela != 0 && android_relasz > 4 && strtab != 0 && symtab != 0 {
        apply_packed_rela(base, android_rela, android_relasz, symtab, strtab, &matching, ctx);
    }
    0
}

/// Hooks one relocation when it is a GLOB_DAT / JUMP_SLOT for a requested symbol.
/// Names compare as bytes: no UTF-8 pass per relocation.
#[inline]
unsafe fn hook_reloc(
    ctx: &mut CommitCtx<'_>,
    matching: &[&PltHookReq],
    base: usize,
    symtab: usize,
    strtab: usize,
    offset: u64,
    info: u64,
) {
    if !elf_arch::is_got_or_plt_rel(elf_arch::rel_type(info)) {
        return;
    }
    let sym = &*(symtab as *const elf_arch::Sym).add(elf_arch::rel_sym(info));
    let name = CStr::from_ptr((strtab + sym.st_name as usize) as *const c_char).to_bytes();
    for h in matching {
        if h.symbol.as_bytes() == name {
            ctx.hook_slot(base.wrapping_add(offset as usize), h);
        }
    }
}

/// Walk an Android packed RELA blob (`APS2`) and patch GLOB_DAT / JUMP_SLOT slots.
unsafe fn apply_packed_rela(
    base: usize,
    start: usize,
    size: usize,
    symtab: usize,
    strtab: usize,
    matching: &[&PltHookReq],
    ctx: &mut CommitCtx<'_>,
) {
    let bytes = std::slice::from_raw_parts(start as *const u8, size);
    if bytes.len() < 4 || &bytes[..4] != b"APS2" {
        return;
    }
    let mut p = 4usize;
    let Some(num_relocs) = pop_sleb(bytes, &mut p) else { return };
    if (num_relocs as i64) < 0 {
        return;
    }
    let Some(mut offset) = pop_sleb(bytes, &mut p) else { return };
    let mut info: u64 = 0;
    let mut done = 0u64;
    while done < num_relocs {
        let Some(group_size) = pop_sleb(bytes, &mut p) else { return };
        let Some(group_flags) = pop_sleb(bytes, &mut p) else { return };
        if (group_size as i64) <= 0 {
            return;
        }
        let mut group_delta = 0u64;
        if group_flags & 2 != 0 {
            let Some(d) = pop_sleb(bytes, &mut p) else { return };
            group_delta = d;
        }
        if group_flags & 1 != 0 {
            let Some(inf) = pop_sleb(bytes, &mut p) else { return };
            info = inf;
        }
        let has_addend = group_flags & 8 != 0;
        let grouped_addend = group_flags & 4 != 0;
        if has_addend && grouped_addend && pop_sleb(bytes, &mut p).is_none() {
            return;
        }
        if !has_addend && grouped_addend {
            return;
        }
        for _ in 0..group_size {
            if group_flags & 2 != 0 {
                offset = offset.wrapping_add(group_delta);
            } else {
                let Some(d) = pop_sleb(bytes, &mut p) else { return };
                offset = offset.wrapping_add(d);
            }
            if group_flags & 1 == 0 {
                let Some(inf) = pop_sleb(bytes, &mut p) else { return };
                info = inf;
            }
            if has_addend && !grouped_addend && pop_sleb(bytes, &mut p).is_none() {
                return;
            }
            hook_reloc(ctx, matching, base, symtab, strtab, offset, info);
        }
        done += group_size;
    }
}

fn pop_sleb(bytes: &[u8], p: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        if *p >= bytes.len() || shift >= 64 {
            return None;
        }
        let byte = bytes[*p];
        *p += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0u64 << shift;
            }
            return Some(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
7a0000000000-7a0000010000 r--p 00000000 fd:2b 1234 /system/lib64/libc.so
7a0000010000-7a0000020000 r-xp 00010000 fd:2b 1234 /system/lib64/libc.so
7a0000020000-7a0000021000 rw-p 00020000 fd:2b 1234 /system/lib64/libc.so
7a0000030000-7a0000031000 ---p 00000000 00:00 0
7a0000040000-7a0000041000 r--p 00000000 00:01 99 /memfd:jit-cache (deleted)
";

    #[test]
    fn maps_give_exact_protection_to_restore() {
        let m = Maps::parse(MAPS);
        assert_eq!(m.prot_at(0x7a0000000100), libc::PROT_READ);
        assert_eq!(m.prot_at(0x7a0000010100), libc::PROT_READ | libc::PROT_EXEC);
        assert_eq!(m.prot_at(0x7a0000020008), libc::PROT_READ | libc::PROT_WRITE);
        // No access or unmapped: fall back to read-only (RELRO), never leave it writable.
        assert_eq!(m.prot_at(0x7a0000030000), libc::PROT_READ);
        assert_eq!(m.prot_at(0x10), libc::PROT_READ);
    }

    #[test]
    fn maps_identify_objects_without_stat() {
        let m = Maps::parse(MAPS);
        let want = (libc::makedev(0xfd, 0x2b) as u64, 1234);
        assert_eq!(m.dev_ino(0x7a0000000000, "/system/lib64/libc.so"), Some(want));
        // Bias that is not a mapping start still resolves through the path.
        assert_eq!(m.dev_ino(0x1000, "/system/lib64/libc.so"), Some(want));
        assert_eq!(m.dev_ino(0x7a0000040000, "/memfd:jit-cache (deleted)"), Some((libc::makedev(0, 1) as u64, 99)));
        assert_eq!(m.dev_ino(0x7a0000030000, ""), None);
    }

    #[test]
    fn sleb128_sign_extends_negative_deltas() {
        let enc = |val: i64| -> Vec<u8> {
            let mut out = Vec::new();
            let mut v = val;
            loop {
                let mut byte = (v & 0x7f) as u8;
                v >>= 7;
                let done = (v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0);
                if !done {
                    byte |= 0x80;
                }
                out.push(byte);
                if done {
                    break;
                }
            }
            out
        };
        for sample in [0i64, 1, 63, 64, 127, 128, -1, -8, -64, -65, -128, -4096, i64::MAX, i64::MIN] {
            let bytes = enc(sample);
            let mut p = 0;
            let got = pop_sleb(&bytes, &mut p).expect("valid sleb128");
            assert_eq!(p, bytes.len());
            assert_eq!(got as i64, sample, "mismatch for {sample}");
        }
        // Negative delta wrapping_add moves relocation offset backward accurately (BUG-Z2).
        let base_off: u64 = 0x2000;
        let neg8 = enc(-8);
        let mut p = 0;
        let delta = pop_sleb(&neg8, &mut p).unwrap();
        assert_eq!(base_off.wrapping_add(delta), 0x1ff8);

        // Truncated stream returns None instead of panicking.
        let mut p = 0;
        assert_eq!(pop_sleb(&[0x80], &mut p), None);
    }

    #[test]
    fn maps_skips_path_alloc_for_anonymous_entries() {
        let anon_maps = "7a0000000000-7a0000001000 rw-p 00000000 00:00 0 [anon:dalvik-main space]\n";
        let m = Maps::parse(anon_maps);
        assert_eq!(m.0.len(), 1);
        assert_eq!(m.0[0].ino, 0);
        assert!(m.0[0].path.is_empty());
        assert_eq!(m.prot_at(0x7a0000000008), libc::PROT_READ | libc::PROT_WRITE);
    }

    #[test]
    fn regexes_compile_once_and_match() {
        let r = Regexes::compile(["libc\\.so$", "libc\\.so$", "^/vendor/"].into_iter());
        assert_eq!(r.0.len(), 2, "duplicates compiled once");
        assert!(r.is_match("libc\\.so$", "/system/lib64/libc.so"));
        assert!(!r.is_match("^/vendor/", "/system/lib64/libc.so"));
        assert!(!r.is_match("not-compiled", "x"));
        let bad = Regexes::compile(["("].into_iter());
        assert!(!bad.is_match("(", "("), "invalid pattern never matches");
    }

    #[test]
    fn patch_restores_original_protection_and_keeps_first_original() {
        unsafe {
            let page = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            ) as usize;
            assert_ne!(page as *mut c_void, libc::MAP_FAILED);
            let maps = Maps::read_self();
            let regexes = Regexes::compile(std::iter::empty());
            let mut ctx = CommitCtx {
                hooks: &[],
                excludes: &[],
                maps: &maps,
                regexes: &regexes,
                applied: 0,
                backups_written: Vec::new(),
            };
            // Stack garbage in the module's backup must not stop the original being stored.
            let mut old: usize = 0xdead_beef;
            let out = &mut old as *mut usize as usize;
            let req = |f| PltHookReq {
                sel: HookSel::DevIno { dev: 0, ino: 0 },
                symbol: String::new(),
                new_func: f,
                old_func_out: out,
            };
            ctx.hook_slot(page + 8, &req(0x1111));
            ctx.hook_slot(page + 8, &req(0x2222));
            assert_eq!(*((page + 8) as *const usize), 0x2222);
            assert_eq!(old, 0, "backup holds the true original, not garbage or the first hook");
            assert_eq!(ctx.applied, 2);
            assert_eq!(Maps::read_self().prot_at(page), libc::PROT_READ, "page back to read-only");
            libc::munmap(page as *mut c_void, 4096);
        }
    }
}
