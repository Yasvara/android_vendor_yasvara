// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounds-checked ELF64 & ELF32 parser and module base locator for Kait.
//!
//! Used lazily only when a module registers native libraries (`native_init`), and dropped
//! immediately after symbol resolution so zero file mappings or symbol tables linger in RSS.

use std::collections::BTreeMap;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_HASH: u32 = 5;
const SHT_DYNSYM: u32 = 11;
const SHT_GNU_HASH: u32 = 0x6fff_fff6;

const SHF_ALLOC: u64 = 0x2;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    UnsupportedClass(u8),
    UnsupportedEndian(u8),
    OutOfBounds,
}

#[derive(Debug, Clone)]
pub struct ElfView<'a> {
    data: &'a [u8],
    is_64: bool,
    bias: i64,
    dynsym: Option<(usize, usize, usize)>, // (offset, count, entsize)
    dynstr: Option<(usize, usize)>,        // (offset, size)
    symtab: Option<(usize, usize, usize)>, // (offset, count, entsize)
    strtab: Option<(usize, usize)>,        // (offset, size)
    sysv_hash: Option<(usize, usize)>,     // (offset, size)
    gnu_hash: Option<(usize, usize)>,      // (offset, size)
}

impl<'a> ElfView<'a> {
    /// Parses an ELF32 or ELF64 little-endian image with full bounds validation.
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < 52 {
            return Err(ElfError::TooSmall);
        }
        if data[0..4] != ELF_MAGIC {
            return Err(ElfError::BadMagic);
        }
        let class = data[4];
        let is_64 = match class {
            ELFCLASS32 => false,
            ELFCLASS64 => true,
            other => return Err(ElfError::UnsupportedClass(other)),
        };
        if data[5] != ELFDATA2LSB {
            return Err(ElfError::UnsupportedEndian(data[5]));
        }

        let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
            if data.len() < 64 {
                return Err(ElfError::TooSmall);
            }
            (
                read_u64(data, 40)? as usize,
                read_u16(data, 58)? as usize,
                read_u16(data, 60)? as usize,
                read_u16(data, 62)? as usize,
            )
        } else {
            (
                read_u32(data, 32)? as usize,
                read_u16(data, 46)? as usize,
                read_u16(data, 48)? as usize,
                read_u16(data, 50)? as usize,
            )
        };

        let min_shent = if is_64 { 64 } else { 40 };
        if e_shnum == 0 || e_shentsize < min_shent || e_shstrndx >= e_shnum {
            return Err(ElfError::OutOfBounds);
        }
        let sh_total = e_shnum.checked_mul(e_shentsize).ok_or(ElfError::OutOfBounds)?;
        check_range(data, e_shoff, sh_total)?;

        let shstr_hdr = read_shdr(data, is_64, e_shoff + e_shstrndx * e_shentsize)?;
        check_range(data, shstr_hdr.offset, shstr_hdr.size)?;
        let shstrtab = &data[shstr_hdr.offset..shstr_hdr.offset + shstr_hdr.size];

        let mut view = Self {
            data,
            is_64,
            bias: 0,
            dynsym: None,
            dynstr: None,
            symtab: None,
            strtab: None,
            sysv_hash: None,
            gnu_hash: None,
        };
        let mut bias_set = false;

        for i in 0..e_shnum {
            let sh = read_shdr(data, is_64, e_shoff + i * e_shentsize)?;
            let name = read_cstr(shstrtab, sh.name).unwrap_or("");
            match sh.ty {
                SHT_DYNSYM if view.dynsym.is_none() => {
                    let sym_size = if is_64 { 24 } else { 16 };
                    if sh.entsize >= sym_size && check_range(data, sh.offset, sh.size).is_ok() {
                        view.dynsym = Some((sh.offset, sh.size / sh.entsize, sh.entsize));
                        if sh.link < e_shnum {
                            let linked = read_shdr(data, is_64, e_shoff + sh.link * e_shentsize)?;
                            if check_range(data, linked.offset, linked.size).is_ok() {
                                view.dynstr = Some((linked.offset, linked.size));
                            }
                        }
                    }
                }
                SHT_SYMTAB if name == ".symtab" => {
                    let sym_size = if is_64 { 24 } else { 16 };
                    if sh.entsize >= sym_size && check_range(data, sh.offset, sh.size).is_ok() {
                        view.symtab = Some((sh.offset, sh.size / sh.entsize, sh.entsize));
                        if sh.link < e_shnum {
                            let linked = read_shdr(data, is_64, e_shoff + sh.link * e_shentsize)?;
                            if check_range(data, linked.offset, linked.size).is_ok() {
                                view.strtab = Some((linked.offset, linked.size));
                            }
                        }
                    }
                }
                SHT_STRTAB => {
                    if view.dynstr.is_none()
                        && view.dynsym.is_some()
                        && check_range(data, sh.offset, sh.size).is_ok()
                    {
                        view.dynstr = Some((sh.offset, sh.size));
                    }
                    if name == ".strtab" && check_range(data, sh.offset, sh.size).is_ok() {
                        view.strtab = Some((sh.offset, sh.size));
                    }
                }
                SHT_HASH if view.sysv_hash.is_none() => {
                    if check_range(data, sh.offset, sh.size).is_ok() {
                        view.sysv_hash = Some((sh.offset, sh.size));
                    }
                }
                SHT_GNU_HASH if view.gnu_hash.is_none() => {
                    if check_range(data, sh.offset, sh.size).is_ok() {
                        view.gnu_hash = Some((sh.offset, sh.size));
                    }
                }
                SHT_PROGBITS if !bias_set && view.dynsym.is_some() && view.dynstr.is_some() => {
                    if (sh.flags & SHF_ALLOC) != 0 && sh.addr > 0 {
                        view.bias = (sh.addr as i64).wrapping_sub(sh.offset as i64);
                        bias_set = true;
                    }
                }
                _ => {}
            }
        }

        Ok(view)
    }

    pub fn bias(&self) -> i64 {
        self.bias
    }

    /// Resolves symbol virtual offset (relative to module load base: `base + offset - bias`).
    pub fn symbol_offset(&self, name: &str) -> Option<u64> {
        if let Some(off) = self.gnu_lookup(name) {
            return Some(off);
        }
        if let Some(off) = self.sysv_lookup(name) {
            return Some(off);
        }
        self.linear_lookup(name)
    }

    /// Resolves the first symbol in `.symtab` or `.dynsym` whose name starts with `prefix`.
    pub fn prefix_lookup_first(&self, prefix: &str) -> Option<u64> {
        let mut table: BTreeMap<&str, u64> = BTreeMap::new();
        for (sym_opt, str_opt) in [(self.symtab, self.strtab), (self.dynsym, self.dynstr)] {
            let (Some((s_off, count, ent)), Some((st_off, st_size))) = (sym_opt, str_opt) else {
                continue;
            };
            let strtab = &self.data[st_off..st_off + st_size];
            for i in 0..count {
                if let Some(sym) = self.read_sym(s_off + i * ent) {
                    let st_type = sym.info & 0x0f;
                    if (st_type == STT_FUNC || st_type == STT_OBJECT) && sym.value != 0 {
                        if let Some(sname) = read_cstr(strtab, sym.name) {
                            if sname.starts_with(prefix) {
                                table.entry(sname).or_insert(sym.value);
                            }
                        }
                    }
                }
            }
        }
        table.into_values().next()
    }

    fn gnu_lookup(&self, name: &str) -> Option<u64> {
        let (h_off, h_size) = self.gnu_hash?;
        let (dynsym_off, dynsym_cnt, dynsym_ent) = self.dynsym?;
        let (dynstr_off, dynstr_size) = self.dynstr?;
        if h_size < 16 {
            return None;
        }
        let nbuckets = read_u32(self.data, h_off).ok()? as usize;
        let symoffset = read_u32(self.data, h_off + 4).ok()? as usize;
        let bloom_size = read_u32(self.data, h_off + 8).ok()? as usize;
        let bloom_shift = read_u32(self.data, h_off + 12).ok()?;
        if nbuckets == 0 || bloom_size == 0 {
            return None;
        }

        let word_bytes = if self.is_64 { 8usize } else { 4usize };
        let bloom_off = h_off + 16;
        let buckets_off = bloom_off.checked_add(bloom_size.checked_mul(word_bytes)?)?;
        let chains_off = buckets_off.checked_add(nbuckets.checked_mul(4)?)?;
        let h_end = h_off.checked_add(h_size)?;
        if chains_off > h_end {
            return None;
        }

        let hash = gnu_hash(name);
        let word_bits = (word_bytes * 8) as u32;
        let bloom_idx = ((hash / word_bits) as usize) % bloom_size;
        let bloom_word = if self.is_64 {
            read_u64(self.data, bloom_off + bloom_idx * 8).ok()?
        } else {
            read_u32(self.data, bloom_off + bloom_idx * 4).ok()? as u64
        };
        let mask = (1u64 << (hash % word_bits))
            | (1u64 << ((hash.wrapping_shr(bloom_shift)) % word_bits));
        if (bloom_word & mask) != mask {
            return None;
        }

        let mut sym_idx = read_u32(self.data, buckets_off + (hash as usize % nbuckets) * 4).ok()? as usize;
        if sym_idx < symoffset {
            return None;
        }
        let dynstr = &self.data[dynstr_off..dynstr_off + dynstr_size];
        while sym_idx < dynsym_cnt {
            let chain_pos = chains_off.checked_add((sym_idx - symoffset).checked_mul(4)?)?;
            if chain_pos + 4 > h_end {
                return None;
            }
            let chain = read_u32(self.data, chain_pos).ok()?;
            if ((chain ^ hash) >> 1) == 0 {
                if let Some(sym) = self.read_sym(dynsym_off + sym_idx * dynsym_ent) {
                    if read_cstr(dynstr, sym.name) == Some(name) && sym.value != 0 {
                        return Some(sym.value);
                    }
                }
            }
            if (chain & 1) != 0 {
                break;
            }
            sym_idx += 1;
        }
        None
    }

    fn sysv_lookup(&self, name: &str) -> Option<u64> {
        let (h_off, h_size) = self.sysv_hash?;
        let (dynsym_off, dynsym_cnt, dynsym_ent) = self.dynsym?;
        let (dynstr_off, dynstr_size) = self.dynstr?;
        if h_size < 8 {
            return None;
        }
        let nbucket = read_u32(self.data, h_off).ok()? as usize;
        let nchain = read_u32(self.data, h_off + 4).ok()? as usize;
        if nbucket == 0 || nchain == 0 {
            return None;
        }
        let buckets_off = h_off + 8;
        let chains_off = buckets_off.checked_add(nbucket.checked_mul(4)?)?;
        let h_end = h_off.checked_add(h_size)?;
        if chains_off.checked_add(nchain.checked_mul(4)?)? > h_end {
            return None;
        }
        let hash = elf_hash(name);
        let dynstr = &self.data[dynstr_off..dynstr_off + dynstr_size];
        let mut n = read_u32(self.data, buckets_off + (hash as usize % nbucket) * 4).ok()? as usize;
        let mut guard = 0usize;
        while n != 0 && n < nchain && n < dynsym_cnt && guard < nchain {
            if let Some(sym) = self.read_sym(dynsym_off + n * dynsym_ent) {
                if read_cstr(dynstr, sym.name) == Some(name) && sym.value != 0 {
                    return Some(sym.value);
                }
            }
            n = read_u32(self.data, chains_off + n * 4).ok()? as usize;
            guard += 1;
        }
        None
    }

    fn linear_lookup(&self, name: &str) -> Option<u64> {
        for (sym_opt, str_opt) in [(self.symtab, self.strtab), (self.dynsym, self.dynstr)] {
            let (Some((s_off, count, ent)), Some((st_off, st_size))) = (sym_opt, str_opt) else {
                continue;
            };
            let strtab = &self.data[st_off..st_off + st_size];
            for i in 0..count {
                if let Some(sym) = self.read_sym(s_off + i * ent) {
                    if sym.value != 0 && read_cstr(strtab, sym.name) == Some(name) {
                        return Some(sym.value);
                    }
                }
            }
        }
        None
    }

    fn read_sym(&self, off: usize) -> Option<SymEntry> {
        if self.is_64 {
            if off + 24 > self.data.len() {
                return None;
            }
            Some(SymEntry {
                name: read_u32(self.data, off).ok()? as usize,
                info: self.data[off + 4],
                value: read_u64(self.data, off + 8).ok()?,
            })
        } else {
            if off + 16 > self.data.len() {
                return None;
            }
            Some(SymEntry {
                name: read_u32(self.data, off).ok()? as usize,
                value: read_u32(self.data, off + 4).ok()? as u64,
                info: self.data[off + 12],
            })
        }
    }
}

struct Shdr {
    name: usize,
    ty: u32,
    flags: u64,
    addr: u64,
    offset: usize,
    size: usize,
    link: usize,
    entsize: usize,
}

struct SymEntry {
    name: usize,
    info: u8,
    value: u64,
}

fn read_shdr(data: &[u8], is_64: bool, off: usize) -> Result<Shdr, ElfError> {
    if is_64 {
        check_range(data, off, 64)?;
        Ok(Shdr {
            name: read_u32(data, off)? as usize,
            ty: read_u32(data, off + 4)?,
            flags: read_u64(data, off + 8)?,
            addr: read_u64(data, off + 16)?,
            offset: read_u64(data, off + 24)? as usize,
            size: read_u64(data, off + 32)? as usize,
            link: read_u32(data, off + 40)? as usize,
            entsize: read_u64(data, off + 56)? as usize,
        })
    } else {
        check_range(data, off, 40)?;
        Ok(Shdr {
            name: read_u32(data, off)? as usize,
            ty: read_u32(data, off + 4)?,
            flags: read_u32(data, off + 8)? as u64,
            addr: read_u32(data, off + 12)? as u64,
            offset: read_u32(data, off + 16)? as usize,
            size: read_u32(data, off + 20)? as usize,
            link: read_u32(data, off + 24)? as usize,
            entsize: read_u32(data, off + 36)? as usize,
        })
    }
}

fn check_range(data: &[u8], off: usize, len: usize) -> Result<(), ElfError> {
    let end = off.checked_add(len).ok_or(ElfError::OutOfBounds)?;
    if end > data.len() {
        return Err(ElfError::OutOfBounds);
    }
    Ok(())
}

fn read_u16(data: &[u8], off: usize) -> Result<u16, ElfError> {
    check_range(data, off, 2)?;
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, ElfError> {
    check_range(data, off, 4)?;
    Ok(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

fn read_u64(data: &[u8], off: usize) -> Result<u64, ElfError> {
    check_range(data, off, 8)?;
    Ok(u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ]))
}

fn read_cstr(table: &[u8], off: usize) -> Option<&str> {
    if off >= table.len() {
        return None;
    }
    let slice = &table[off..];
    let nul = slice.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&slice[..nul]).ok()
}

pub fn gnu_hash(name: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in name.bytes() {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(b as u32);
    }
    h
}

pub fn elf_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for b in name.bytes() {
        h = (h << 4).wrapping_add(b as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

pub fn basename_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Corroborated `/proc/self/maps` parser (fallback when `dl_iterate_phdr` doesn't cover a binary).
/// Ignores `MAP_SHARED` decoys and prefers exact basename match + executable segment corroboration.
pub fn find_module_base_in_maps(maps_text: &str, wanted: &str) -> Option<(usize, String)> {
    struct Entry<'a> {
        start: usize,
        offset: usize,
        perms: &'a str,
        path: &'a str,
    }

    let mut entries: Vec<Entry<'_>> = Vec::new();
    for line in maps_text.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let perms = parts.next()?;
        let offset_hex = parts.next()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let Some(path) = parts.next() else { continue };
        if !path.contains(wanted) {
            continue;
        }
        let Some((start_hex, _)) = range.split_once('-') else { continue };
        let Ok(start) = usize::from_str_radix(start_hex, 16) else { continue };
        let Ok(offset) = usize::from_str_radix(offset_hex, 16) else { continue };
        entries.push(Entry {
            start,
            offset,
            perms,
            path,
        });
    }
    if entries.is_empty() {
        return None;
    }

    let mut chosen = entries[0].path;
    let mut best_exact = basename_of(chosen) == wanted;
    for e in &entries[1..] {
        if e.path == chosen {
            continue;
        }
        let exact = basename_of(e.path) == wanted;
        if exact != best_exact {
            if exact {
                chosen = e.path;
                best_exact = true;
            }
            continue;
        }
        if e.path.len() < chosen.len() {
            chosen = e.path;
        }
    }

    const MAX_SEG_PADDING: usize = 0x10000;
    let mut best_base: Option<usize> = None;
    let mut best_score: isize = -1;
    for cand in &entries {
        if cand.path != chosen || cand.offset != 0 || !cand.perms.ends_with('p') {
            continue;
        }
        let mut score: isize = 0;
        for seg in &entries {
            if seg.path != chosen {
                continue;
            }
            let pb = seg.perms.as_bytes();
            if pb.len() < 4 || pb[2] != b'x' || pb[3] != b'p' {
                continue;
            }
            if seg.start < cand.start {
                continue;
            }
            let dist = seg.start - cand.start;
            if dist >= seg.offset && dist - seg.offset <= MAX_SEG_PADDING {
                score += 1;
            }
        }
        if score > best_score {
            best_score = score;
            best_base = Some(cand.start);
        }
    }

    best_base.map(|b| (b, chosen.to_owned()))
}

/// Locates a loaded shared object via the dynamic linker (`dl_iterate_phdr`), avoiding `/proc/self/maps`.
#[cfg(target_os = "android")]
pub fn find_module_base_via_linker(wanted: &str) -> Option<(usize, String)> {
    use std::ffi::CStr;

    struct Query<'a> {
        wanted: &'a str,
        base: usize,
        path: String,
        found: bool,
        exact: bool,
    }

    unsafe extern "C" fn cb(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        let info = unsafe { &*info };
        let q = unsafe { &mut *(data as *mut Query<'_>) };
        if info.dlpi_name.is_null() {
            return 0;
        }
        let Ok(name) = unsafe { CStr::from_ptr(info.dlpi_name) }.to_str() else {
            return 0;
        };
        if name.is_empty() || !name.contains(q.wanted) {
            return 0;
        }
        let exact = basename_of(name) == q.wanted;
        if q.found && (q.exact || !exact) {
            return 0;
        }
        let phdrs = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) };
        #[cfg(target_pointer_width = "64")]
        {
            let mut first_load: Option<&libc::Elf64_Phdr> = None;
            for ph in phdrs {
                if ph.p_type != libc::PT_LOAD {
                    continue;
                }
                if first_load.map_or(true, |cur| ph.p_vaddr < cur.p_vaddr) {
                    first_load = Some(ph);
                }
            }
            let Some(fl) = first_load else { return 0 };
            q.base = (info.dlpi_addr as usize)
                .wrapping_add(fl.p_vaddr as usize)
                .wrapping_sub(fl.p_offset as usize);
        }
        #[cfg(target_pointer_width = "32")]
        {
            let mut fl32: Option<&libc::Elf32_Phdr> = None;
            for ph in phdrs {
                if ph.p_type != libc::PT_LOAD {
                    continue;
                }
                if fl32.map_or(true, |cur| ph.p_vaddr < cur.p_vaddr) {
                    fl32 = Some(ph);
                }
            }
            let Some(fl) = fl32 else { return 0 };
            q.base = (info.dlpi_addr as usize)
                .wrapping_add(fl.p_vaddr as usize)
                .wrapping_sub(fl.p_offset as usize);
        }
        q.path.clear();
        q.path.push_str(name);
        q.found = true;
        q.exact = exact;
        if exact { 1 } else { 0 }
    }

    let mut q = Query {
        wanted,
        base: 0,
        path: String::new(),
        found: false,
        exact: false,
    };
    unsafe {
        libc::dl_iterate_phdr(Some(cb), &mut q as *mut Query<'_> as *mut libc::c_void);
    }
    q.found.then_some((q.base, q.path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_synthetic_elf64(sym_name: &str, sym_val: u64, with_gnu_hash: bool) -> Vec<u8> {
        let mut buf = vec![0u8; 64]; // Ehdr
        // shstrtab: \0.shstrtab\0.dynsym\0.dynstr\0.gnu.hash\0.hash\0.text\0
        let shstrtab_off = buf.len();
        let shstrtab = b"\0.shstrtab\0.dynsym\0.dynstr\0.gnu.hash\0.hash\0.text\0";
        buf.extend_from_slice(shstrtab);

        let dynstr_off = buf.len();
        let mut dynstr = vec![0u8];
        let name_off = dynstr.len() as u32;
        dynstr.extend_from_slice(sym_name.as_bytes());
        dynstr.push(0);
        buf.extend_from_slice(&dynstr);

        while buf.len() % 8 != 0 {
            buf.push(0);
        }
        let dynsym_off = buf.len();
        buf.extend_from_slice(&[0u8; 24]); // STN_UNDEF
        buf.extend_from_slice(&name_off.to_le_bytes());
        buf.push((1 << 4) | STT_FUNC); // STB_GLOBAL | STT_FUNC
        buf.push(0);
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&sym_val.to_le_bytes());
        buf.extend_from_slice(&16u64.to_le_bytes());

        let gnu_off = buf.len();
        if with_gnu_hash {
            let h = gnu_hash(sym_name);
            buf.extend_from_slice(&1u32.to_le_bytes()); // nbuckets
            buf.extend_from_slice(&1u32.to_le_bytes()); // symoffset
            buf.extend_from_slice(&1u32.to_le_bytes()); // bloom_size
            buf.extend_from_slice(&6u32.to_le_bytes()); // bloom_shift
            let bloom: u64 = (1u64 << (h % 64)) | (1u64 << ((h >> 6) % 64));
            buf.extend_from_slice(&bloom.to_le_bytes());
            buf.extend_from_slice(&1u32.to_le_bytes()); // bucket[0] = sym 1
            buf.extend_from_slice(&(h | 1).to_le_bytes()); // chain[0], end bit set
        }
        let gnu_size = buf.len() - gnu_off;

        let sysv_off = buf.len();
        if !with_gnu_hash {
            buf.extend_from_slice(&1u32.to_le_bytes()); // nbucket
            buf.extend_from_slice(&2u32.to_le_bytes()); // nchain
            buf.extend_from_slice(&1u32.to_le_bytes()); // bucket[0] = 1
            buf.extend_from_slice(&0u32.to_le_bytes()); // chain[0]
            buf.extend_from_slice(&0u32.to_le_bytes()); // chain[1]
        }
        let sysv_size = buf.len() - sysv_off;

        while buf.len() % 8 != 0 {
            buf.push(0);
        }
        let shoff = buf.len();

        let push_shdr = |b: &mut Vec<u8>,
                         name: u32,
                         ty: u32,
                         flags: u64,
                         addr: u64,
                         off: usize,
                         size: usize,
                         link: u32,
                         entsize: u64| {
            b.extend_from_slice(&name.to_le_bytes());
            b.extend_from_slice(&ty.to_le_bytes());
            b.extend_from_slice(&flags.to_le_bytes());
            b.extend_from_slice(&addr.to_le_bytes());
            b.extend_from_slice(&(off as u64).to_le_bytes());
            b.extend_from_slice(&(size as u64).to_le_bytes());
            b.extend_from_slice(&link.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&8u64.to_le_bytes());
            b.extend_from_slice(&entsize.to_le_bytes());
        };

        // 0: NULL
        push_shdr(&mut buf, 0, 0, 0, 0, 0, 0, 0, 0);
        // 1: .shstrtab
        push_shdr(&mut buf, 1, SHT_STRTAB, 0, 0, shstrtab_off, shstrtab.len(), 0, 0);
        // 2: .dynsym (link -> 3)
        push_shdr(&mut buf, 11, SHT_DYNSYM, SHF_ALLOC, dynsym_off as u64, dynsym_off, 48, 3, 24);
        // 3: .dynstr
        push_shdr(&mut buf, 19, SHT_STRTAB, SHF_ALLOC, dynstr_off as u64, dynstr_off, dynstr.len(), 0, 0);
        // 4: hash section
        if with_gnu_hash {
            push_shdr(&mut buf, 27, SHT_GNU_HASH, SHF_ALLOC, gnu_off as u64, gnu_off, gnu_size, 2, 0);
        } else {
            push_shdr(&mut buf, 37, SHT_HASH, SHF_ALLOC, sysv_off as u64, sysv_off, sysv_size, 2, 0);
        }
        // 5: .text (PROGBITS with SHF_ALLOC, load bias = 0x1000)
        push_shdr(&mut buf, 43, SHT_PROGBITS, SHF_ALLOC, 0x2000, 0x1000, 0, 0, 0);

        // Fill Ehdr64.
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = ELFCLASS64;
        buf[5] = ELFDATA2LSB;
        buf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());
        buf[60..62].copy_from_slice(&6u16.to_le_bytes());
        buf[62..64].copy_from_slice(&1u16.to_le_bytes());
        buf
    }

    #[test]
    fn test_parse_and_lookup_gnu_and_sysv_hash() {
        let elf_gnu = build_synthetic_elf64("__loader_android_dlopen_ext", 0x4200, true);
        let view = ElfView::parse(&elf_gnu).unwrap();
        assert_eq!(view.bias(), 0x1000);
        assert_eq!(view.symbol_offset("__loader_android_dlopen_ext"), Some(0x4200));
        assert_eq!(view.symbol_offset("nonexistent"), None);
        assert_eq!(view.prefix_lookup_first("__loader_android"), Some(0x4200));

        let elf_sysv = build_synthetic_elf64("__loader_dlopen", 0x5500, false);
        let view2 = ElfView::parse(&elf_sysv).unwrap();
        assert_eq!(view2.symbol_offset("__loader_dlopen"), Some(0x5500));
    }

    #[test]
    fn test_rejects_corrupt_or_truncated_elf() {
        assert_eq!(ElfView::parse(b"PK\x03\x04not-an-elf").unwrap_err(), ElfError::TooSmall);
        let mut fake_apk = vec![0u8; 128];
        fake_apk[0..4].copy_from_slice(b"PK\x03\x04");
        assert_eq!(ElfView::parse(&fake_apk).unwrap_err(), ElfError::BadMagic);

        let mut bad_shoff = build_synthetic_elf64("foo", 0x100, true);
        bad_shoff[40..48].copy_from_slice(&0xffff_ffffu64.to_le_bytes());
        assert_eq!(ElfView::parse(&bad_shoff).unwrap_err(), ElfError::OutOfBounds);
    }

    #[test]
    fn test_maps_corroboration_ignores_shared_decoy_and_handles_execute_only() {
        let maps = "\
7000000000-7000010000 r--s 00000000 fe:01 123 /apex/com.android.runtime/bin/linker64\n\
7100000000-7100010000 r--p 00000000 fe:01 999 /vendor/lib64/libfoo_linker64.so\n\
7200000000-7200010000 r--p 00000000 fe:01 123 /apex/com.android.runtime/bin/linker64\n\
720004c000-72001b0000 --xp 0004c000 fe:01 123 /apex/com.android.runtime/bin/linker64\n";

        let (base, path) = find_module_base_in_maps(maps, "linker64").unwrap();
        assert_eq!(base, 0x72_0000_0000);
        assert_eq!(path, "/apex/com.android.runtime/bin/linker64");
    }
}
