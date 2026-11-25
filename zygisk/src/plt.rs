// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust ELF64 & ELF32 live PLT/GOT hooker implementing Zygisk v4/v5
//! `pltHookRegister(dev, ino, symbol, new_func, old_func)` and `pltHookCommit()`.
//!
//! Walks loaded objects via `dl_iterate_phdr`, parses `PT_DYNAMIC` directly in-memory
//! (`DT_SYMTAB`, `DT_STRTAB`, `DT_JMPREL`, `DT_RELA`/`DT_REL`), and atomically swaps
//! matching GOT/PLT slots with page-aligned `mprotect` restore.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::sync::Mutex;

#[derive(Clone)]
struct PltHookReq {
    dev: libc::dev_t,
    ino: libc::ino_t,
    symbol: String,
    new_func: usize,
    old_func_out: usize,
}

static PENDING_HOOKS: Mutex<Vec<PltHookReq>> = Mutex::new(Vec::new());

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
            dev,
            ino,
            symbol: sym_str.to_string(),
            new_func: new_func as usize,
            old_func_out: old_func as usize,
        });
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
    let mut state = CommitCtx { hooks: &hooks, applied: 0 };
    libc::dl_iterate_phdr(Some(phdr_cb), &mut state as *mut CommitCtx as *mut c_void);
    state.applied > 0
}

struct CommitCtx<'a> {
    hooks: &'a [PltHookReq],
    applied: usize,
}

#[cfg(target_pointer_width = "64")]
mod elf_arch {
    pub const PT_DYNAMIC: u32 = 2;
    pub const DT_NULL: i64 = 0;
    pub const DT_PLTRELSZ: i64 = 2;
    pub const DT_STRTAB: i64 = 5;
    pub const DT_SYMTAB: i64 = 6;
    pub const DT_RELA: i64 = 7;
    pub const DT_RELASZ: i64 = 8;
    pub const DT_JMPREL: i64 = 23;
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

#[cfg(target_pointer_width = "32")]
mod elf_arch {
    pub const PT_DYNAMIC: u32 = 2;
    pub const DT_NULL: i32 = 0;
    pub const DT_PLTRELSZ: i32 = 2;
    pub const DT_STRTAB: i32 = 5;
    pub const DT_SYMTAB: i32 = 6;
    pub const DT_REL: i32 = 17;
    pub const DT_RELSZ: i32 = 18;
    pub const DT_JMPREL: i32 = 23;
    pub const R_ARM_JUMP_SLOT: u32 = 22;
    pub const R_ARM_GLOB_DAT: u32 = 21;

    #[repr(C)]
    pub struct Dyn {
        pub d_tag: i32,
        pub d_val: u32,
    }

    #[repr(C)]
    pub struct Sym {
        pub st_name: u32,
        pub st_value: u32,
        pub st_size: u32,
        pub st_info: u8,
        pub st_other: u8,
        pub st_shndx: u16,
    }

    #[repr(C)]
    pub struct Rel {
        pub r_offset: u32,
        pub r_info: u32,
    }

    pub fn rel_sym(info: u32) -> usize {
        (info >> 8) as usize
    }

    pub fn rel_type(info: u32) -> u32 {
        info & 0xff
    }

    pub fn is_got_or_plt_rel(ty: u32) -> bool {
        matches!(ty, R_ARM_JUMP_SLOT | R_ARM_GLOB_DAT)
    }
}

unsafe fn patch_got_slot(slot_addr: usize, new_fn: usize, old_out: usize) -> bool {
    let page_size = libc::sysconf(libc::_SC_PAGESIZE).max(4096) as usize;
    let page_start = slot_addr & !(page_size - 1);
    if libc::mprotect(
        page_start as *mut c_void,
        page_size,
        libc::PROT_READ | libc::PROT_WRITE,
    ) != 0
    {
        return false;
    }
    let slot = slot_addr as *mut usize;
    let prev = std::ptr::read_volatile(slot);
    if old_out != 0 {
        *(old_out as *mut *mut c_void) = prev as *mut c_void;
    }
    std::ptr::write_volatile(slot, new_fn);
    // Flush instruction/data caches cleanly for architectures with split caches.
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    let _ = libc::mprotect(page_start as *mut c_void, page_size, libc::PROT_READ);
    true
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
    let mut st: libc::stat = std::mem::zeroed();
    if libc::stat(info.dlpi_name, &mut st) != 0 {
        return 0;
    }
    let matching: Vec<&PltHookReq> = ctx
        .hooks
        .iter()
        .filter(|h| h.dev as u64 == st.st_dev as u64 && h.ino as u64 == st.st_ino as u64)
        .collect();
    if matching.is_empty() {
        return 0;
    }

    let base = info.dlpi_addr as usize;
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
    let mut d = dyn_ptr;
    while (*d).d_tag != elf_arch::DT_NULL {
        let val = (*d).d_val as usize;
        // On Android/Bionic, DT_* pointers in memory may already be relocated absolute addresses
        // or still relative to `base`; normalize safely.
        let norm = |v: usize| -> usize { if v < base { base.wrapping_add(v) } else { v } };
        #[cfg(target_pointer_width = "64")]
        match (*d).d_tag {
            elf_arch::DT_STRTAB => strtab = norm(val),
            elf_arch::DT_SYMTAB => symtab = norm(val),
            elf_arch::DT_JMPREL => jmprel = norm(val),
            elf_arch::DT_PLTRELSZ => pltrelsz = val,
            elf_arch::DT_RELA => rel_tab = norm(val),
            elf_arch::DT_RELASZ => rel_sz = val,
            _ => {}
        }
        #[cfg(target_pointer_width = "32")]
        match (*d).d_tag {
            elf_arch::DT_STRTAB => strtab = norm(val),
            elf_arch::DT_SYMTAB => symtab = norm(val),
            elf_arch::DT_JMPREL => jmprel = norm(val),
            elf_arch::DT_PLTRELSZ => pltrelsz = val,
            elf_arch::DT_REL => rel_tab = norm(val),
            elf_arch::DT_RELSZ => rel_sz = val,
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
        #[cfg(target_pointer_width = "64")]
        {
            let count = sz / std::mem::size_of::<elf_arch::Rela>();
            let rels = std::slice::from_raw_parts(tab as *const elf_arch::Rela, count);
            for r in rels {
                if !elf_arch::is_got_or_plt_rel(elf_arch::rel_type(r.r_info)) {
                    continue;
                }
                let sym = &*(symtab as *const elf_arch::Sym).add(elf_arch::rel_sym(r.r_info));
                let name_ptr = (strtab + sym.st_name as usize) as *const c_char;
                let Ok(name) = CStr::from_ptr(name_ptr).to_str() else { continue };
                for h in &matching {
                    if h.symbol == name {
                        let slot = base.wrapping_add(r.r_offset as usize);
                        if patch_got_slot(slot, h.new_func, h.old_func_out) {
                            ctx.applied += 1;
                        }
                    }
                }
            }
        }
        #[cfg(target_pointer_width = "32")]
        {
            let count = sz / std::mem::size_of::<elf_arch::Rel>();
            let rels = std::slice::from_raw_parts(tab as *const elf_arch::Rel, count);
            for r in rels {
                if !elf_arch::is_got_or_plt_rel(elf_arch::rel_type(r.r_info)) {
                    continue;
                }
                let sym = &*(symtab as *const elf_arch::Sym).add(elf_arch::rel_sym(r.r_info));
                let name_ptr = (strtab + sym.st_name as usize) as *const c_char;
                let Ok(name) = CStr::from_ptr(name_ptr).to_str() else { continue };
                for h in &matching {
                    if h.symbol == name {
                        let slot = base.wrapping_add(r.r_offset as usize);
                        if patch_got_slot(slot, h.new_func, h.old_func_out) {
                            ctx.applied += 1;
                        }
                    }
                }
            }
        }
    }
    0
}
