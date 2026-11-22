// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Compact AArch64 (and ARM32) inline hooker + instruction relocator in pure Rust.
//!
//! Only used for third-party native Xposed modules (`NativeAPIEntries::{hookFunc, unhookFunc}`
//! and `__loader_dlopen` / `__loader_android_dlopen_ext`). ART method hooking itself does NOT
//! use inline hooking at all — it uses the ROM-native `YasvaraKaitOps` seam.

use hashbrown::HashMap;
use parking_lot::Mutex;
use std::sync::OnceLock;

/// Result of relocating a single AArch64 32-bit instruction from `orig_pc` into `tramp_pc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelocResult {
    /// Emitted replacement instructions (1..=6 u32 words).
    Words(Vec<u32>),
}

/// Emits an AArch64 16-byte absolute branch via `x16`:
/// `ldr x16, #8; br x16; .quad target`.
pub fn encode_arm64_abs_jump(target: u64) -> [u32; 4] {
    let ldr_x16_8: u32 = 0x5800_0050; // ldr x16, [pc, #8]
    let br_x16: u32 = 0xd61f_0200; // br x16
    let lo = (target & 0xffff_ffff) as u32;
    let hi = (target >> 32) as u32;
    [ldr_x16_8, br_x16, lo, hi]
}

/// Emits an AArch64 4-instruction `movz/movk` sequence loading a 64-bit immediate into `rd`.
pub fn encode_arm64_load_imm64(rd: u32, imm: u64) -> [u32; 4] {
    let rd = rd & 0x1f;
    let hw0 = (imm & 0xffff) as u32;
    let hw1 = ((imm >> 16) & 0xffff) as u32;
    let hw2 = ((imm >> 32) & 0xffff) as u32;
    let hw3 = ((imm >> 48) & 0xffff) as u32;
    [
        0xd280_0000 | (hw0 << 5) | rd, // movz xd, #hw0, lsl #0
        0xf2a0_0000 | (hw1 << 5) | rd, // movk xd, #hw1, lsl #16
        0xf2c0_0000 | (hw2 << 5) | rd, // movk xd, #hw2, lsl #32
        0xf2e0_0000 | (hw3 << 5) | rd, // movk xd, #hw3, lsl #48
    ]
}

fn sign_extend(val: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((val as u64) << shift) as i64 >> shift
}

/// Relocates one AArch64 instruction originally at `orig_pc` so it executes identically inside a
/// trampoline at an arbitrary distance (`> ±4 GiB` safe).
pub fn relocate_arm64_insn(insn: u32, orig_pc: u64) -> RelocResult {
    // 1. ADR / ADRP: op (bit 31), immlo (30..29), 10000 (28..24), immhi (23..5), Rd (4..0)
    if (insn & 0x1f00_0000) == 0x1000_0000 {
        let is_adrp = (insn & 0x8000_0000) != 0;
        let rd = insn & 0x1f;
        let immlo = (insn >> 29) & 0x3;
        let immhi = (insn >> 5) & 0x7_ffff;
        let imm21 = (immhi << 2) | immlo;
        let offset = sign_extend(imm21, 21);
        let target = if is_adrp {
            ((orig_pc & !0xfff) as i64).wrapping_add(offset << 12) as u64
        } else {
            (orig_pc as i64).wrapping_add(offset) as u64
        };
        return RelocResult::Words(encode_arm64_load_imm64(rd, target).to_vec());
    }

    // 2. B / BL: op (31), 00101 (30..26), imm26 (25..0)
    if (insn & 0x7c00_0000) == 0x1400_0000 {
        let is_bl = (insn & 0x8000_0000) != 0;
        let imm26 = insn & 0x03ff_ffff;
        let target = (orig_pc as i64).wrapping_add(sign_extend(imm26, 26) * 4) as u64;
        if is_bl {
            // ldr x16, #12; blr x16; b #12; .quad target
            let lo = (target & 0xffff_ffff) as u32;
            let hi = (target >> 32) as u32;
            return RelocResult::Words(vec![
                0x5800_0070, // ldr x16, [pc, #12]
                0xd63f_0200, // blr x16
                0x1400_0003, // b +12 (skip 8-byte literal)
                lo,
                hi,
            ]);
        }
        return RelocResult::Words(encode_arm64_abs_jump(target).to_vec());
    }

    // 3. B.cond: 01010100 (31..24), imm19 (23..5), 0 (4), cond (3..0)
    if (insn & 0xff00_0010) == 0x5400_0000 {
        let cond = insn & 0xf;
        let imm19 = (insn >> 5) & 0x7_ffff;
        let target = (orig_pc as i64).wrapping_add(sign_extend(imm19, 19) * 4) as u64;
        let inv_cond = cond ^ 1;
        // b.!cond +20 (skip 4-word abs jump); ldr x16, #8; br x16; .quad target
        let skip_branch = 0x5400_0000 | (5u32 << 5) | inv_cond;
        let mut out = vec![skip_branch];
        out.extend_from_slice(&encode_arm64_abs_jump(target));
        return RelocResult::Words(out);
    }

    // 4. CBZ / CBNZ: sf (31), 011010 (30..25), op (24), imm19 (23..5), Rt (4..0)
    if (insn & 0x7e00_0000) == 0x3400_0000 {
        let imm19 = (insn >> 5) & 0x7_ffff;
        let target = (orig_pc as i64).wrapping_add(sign_extend(imm19, 19) * 4) as u64;
        // Invert bit 24 (CBZ <-> CBNZ) and branch +20 (+5 insns) past the abs jump.
        let inv_branch = (insn ^ 0x0100_0000) & !0x00ff_ffe0 | (5u32 << 5);
        let mut out = vec![inv_branch];
        out.extend_from_slice(&encode_arm64_abs_jump(target));
        return RelocResult::Words(out);
    }

    // 5. TBZ / TBNZ: b5 (31), 011011 (30..25), op (24), b40 (23..19), imm14 (18..5), Rt (4..0)
    if (insn & 0x7e00_0000) == 0x3600_0000 {
        let imm14 = (insn >> 5) & 0x3fff;
        let target = (orig_pc as i64).wrapping_add(sign_extend(imm14, 14) * 4) as u64;
        let inv_branch = (insn ^ 0x0100_0000) & !0x0007_ffe0 | (5u32 << 5);
        let mut out = vec![inv_branch];
        out.extend_from_slice(&encode_arm64_abs_jump(target));
        return RelocResult::Words(out);
    }

    // 6. LDR (literal) GP 32/64/SW: opc (31..30), 011 (29..27), V=0 (26), 00 (25..24), imm19 (23..5), Rt (4..0)
    if (insn & 0x3f00_0000) == 0x1800_0000 {
        let opc = (insn >> 30) & 0x3;
        let rt = insn & 0x1f;
        let imm19 = (insn >> 5) & 0x7_ffff;
        let addr = (orig_pc as i64).wrapping_add(sign_extend(imm19, 19) * 4) as u64;
        if opc <= 2 {
            // Load address into x16 (scratch) or rt, then dereference [x16].
            let mut out = encode_arm64_load_imm64(16, addr).to_vec();
            let load_insn = match opc {
                0 => 0xb940_0200 | rt, // ldr wt, [x16]
                1 => 0xf940_0200 | rt, // ldr xt, [x16]
                _ => 0xb980_0200 | rt, // ldrsw xt, [x16]
            };
            out.push(load_insn);
            return RelocResult::Words(out);
        }
    }

    // Non-PC-relative instruction: copy verbatim.
    RelocResult::Words(vec![insn])
}

/// Builds a complete relocated trampoline word sequence for 4 AArch64 prologue instructions
/// (16 bytes) at `target_addr`, ending with an absolute jump back to `target_addr + 16`.
pub fn build_arm64_trampoline(prologue: [u32; 4], target_addr: u64) -> Vec<u32> {
    let mut out = Vec::with_capacity(24);
    for (i, &insn) in prologue.iter().enumerate() {
        let pc = target_addr + (i as u64) * 4;
        match relocate_arm64_insn(insn, pc) {
            RelocResult::Words(words) => out.extend_from_slice(&words),
        }
    }
    out.extend_from_slice(&encode_arm64_abs_jump(target_addr + 16));
    out
}

#[derive(Debug, Clone)]
struct InstalledHook {
    orig_bytes: Vec<u8>,
    #[allow(dead_code)]
    trampoline: usize,
}

#[cfg_attr(not(any(target_arch = "aarch64", target_arch = "arm")), allow(dead_code))]
struct InlineState {
    hooks: HashMap<usize, InstalledHook>,
    pool_exec: usize,
    pool_rw: usize,
    pool_used: usize,
    page_size: usize,
}

fn state() -> &'static Mutex<InlineState> {
    static STATE: OnceLock<Mutex<InlineState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(InlineState {
            hooks: HashMap::new(),
            pool_exec: 0,
            pool_rw: 0,
            pool_used: 0,
            page_size: 4096,
        })
    })
}

/// Installs an inline hook at `target` redirecting to `replacement`, writing the original
/// trampoline callable address into `*backup`. Returns `0` on success, `-1` on error.
pub unsafe fn hook_inline(
    target: *mut std::ffi::c_void,
    replacement: *mut std::ffi::c_void,
    backup: *mut *mut std::ffi::c_void,
) -> i32 {
    if target.is_null() || replacement.is_null() {
        return -1;
    }
    #[cfg(target_arch = "aarch64")]
    {
        return unsafe { hook_inline_arm64(target, replacement, backup) };
    }
    #[cfg(target_arch = "arm")]
    {
        return unsafe { hook_inline_arm32(target, replacement, backup) };
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
    {
        let _ = backup;
        -1
    }
}

/// Removes an inline hook installed via `hook_inline`, restoring the original prologue bytes.
pub unsafe fn unhook_inline(target: *mut std::ffi::c_void) -> i32 {
    if target.is_null() {
        return -1;
    }
    let key = target as usize;
    let mut guard = state().lock();
    let Some(info) = guard.hooks.remove(&key) else {
        return -1;
    };
    if unsafe { patch_code(key, &info.orig_bytes) } {
        0
    } else {
        -1
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
unsafe fn alloc_trampoline(st: &mut InlineState, bytes: &[u8]) -> Option<usize> {
    let aligned = (bytes.len() + 15) & !15;
    if st.pool_exec == 0 || st.pool_used + aligned > st.page_size {
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let ps = if ps == 0 { 4096 } else { ps };
        st.page_size = ps;
        // Allocate dual-mapped anonymous memfd (r-x + rw-) if supported, else rwx fallback.
        let memfd = unsafe {
            libc::syscall(libc::SYS_memfd_create, b"\0".as_ptr(), 0usize) as libc::c_int
        };
        if memfd >= 0 {
            if unsafe { libc::ftruncate(memfd, ps as libc::off_t) } == 0 {
                let reserved = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        ps * 2,
                        libc::PROT_NONE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if reserved != libc::MAP_FAILED {
                    let rx = unsafe {
                        libc::mmap(
                            reserved,
                            ps,
                            libc::PROT_READ | libc::PROT_EXEC,
                            libc::MAP_SHARED | libc::MAP_FIXED,
                            memfd,
                            0,
                        )
                    };
                    let rw = unsafe {
                        libc::mmap(
                            (reserved as usize + ps) as *mut libc::c_void,
                            ps,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_SHARED | libc::MAP_FIXED,
                            memfd,
                            0,
                        )
                    };
                    unsafe { libc::close(memfd) };
                    if rx != libc::MAP_FAILED && rw != libc::MAP_FAILED {
                        st.pool_exec = rx as usize;
                        st.pool_rw = rw as usize;
                        st.pool_used = 0;
                    } else {
                        unsafe { libc::munmap(reserved, ps * 2) };
                        return None;
                    }
                } else {
                    unsafe { libc::close(memfd) };
                    return None;
                }
            } else {
                unsafe { libc::close(memfd) };
                return None;
            }
        } else {
            let mem = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    ps,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if mem == libc::MAP_FAILED {
                return None;
            }
            st.pool_exec = mem as usize;
            st.pool_rw = mem as usize;
            st.pool_used = 0;
        }
    }
    let exec_addr = st.pool_exec + st.pool_used;
    let rw_addr = st.pool_rw + st.pool_used;
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), rw_addr as *mut u8, bytes.len());
        clear_icache(exec_addr, exec_addr + bytes.len());
    }
    st.pool_used += aligned;
    Some(exec_addr)
}

unsafe fn patch_code(addr: usize, bytes: &[u8]) -> bool {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let ps = if ps == 0 { 4096 } else { ps };
    let start = addr & !(ps - 1);
    let end = (addr + bytes.len() + ps - 1) & !(ps - 1);
    let len = end - start;
    if unsafe {
        libc::mprotect(
            start as *mut libc::c_void,
            len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    } != 0
    {
        return false;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
        clear_icache(addr, addr + bytes.len());
        libc::mprotect(start as *mut libc::c_void, len, libc::PROT_READ | libc::PROT_EXEC);
    }
    true
}

unsafe fn clear_icache(start: usize, end: usize) {
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        extern "C" {
            fn __clear_cache(beg: *mut std::ffi::c_void, end: *mut std::ffi::c_void);
        }
        unsafe {
            __clear_cache(start as *mut std::ffi::c_void, end as *mut std::ffi::c_void);
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
    {
        let _ = (start, end);
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn hook_inline_arm64(
    target: *mut std::ffi::c_void,
    replacement: *mut std::ffi::c_void,
    backup: *mut *mut std::ffi::c_void,
) -> i32 {
    let addr = target as usize;
    let mut guard = state().lock();
    if guard.hooks.contains_key(&addr) {
        return -1;
    }
    let mut prologue = [0u32; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(addr as *const u32, prologue.as_mut_ptr(), 4);
    }
    let orig_bytes: Vec<u8> = prologue.iter().flat_map(|w| w.to_le_bytes()).collect();
    let tramp_words = build_arm64_trampoline(prologue, addr as u64);
    let tramp_bytes: Vec<u8> = tramp_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let Some(tramp_addr) = (unsafe { alloc_trampoline(&mut guard, &tramp_bytes) }) else {
        return -1;
    };
    let stub = encode_arm64_abs_jump(replacement as u64);
    let stub_bytes: Vec<u8> = stub.iter().flat_map(|w| w.to_le_bytes()).collect();
    if !unsafe { patch_code(addr, &stub_bytes) } {
        return -1;
    }
    guard.hooks.insert(
        addr,
        InstalledHook {
            orig_bytes,
            trampoline: tramp_addr,
        },
    );
    if !backup.is_null() {
        unsafe {
            *backup = tramp_addr as *mut std::ffi::c_void;
        }
    }
    0
}

#[cfg(target_arch = "arm")]
unsafe fn hook_inline_arm32(
    target: *mut std::ffi::c_void,
    replacement: *mut std::ffi::c_void,
    backup: *mut *mut std::ffi::c_void,
) -> i32 {
    let raw = target as usize;
    let is_thumb = (raw & 1) != 0;
    let addr = raw & !1;
    let mut guard = state().lock();
    if guard.hooks.contains_key(&addr) {
        return -1;
    }
    if is_thumb {
        // Thumb-2 8-byte stub: ldr.w pc, [pc, #0] (0xf000f8df); .word replacement
        let mut orig = [0u8; 8];
        unsafe { std::ptr::copy_nonoverlapping(addr as *const u8, orig.as_mut_ptr(), 8) };
        let mut tramp = Vec::with_capacity(16);
        tramp.extend_from_slice(&orig);
        tramp.extend_from_slice(&0xf8dfu16.to_le_bytes());
        tramp.extend_from_slice(&0xf000u16.to_le_bytes());
        tramp.extend_from_slice(&((raw + 8) as u32).to_le_bytes());
        let Some(tramp_addr) = (unsafe { alloc_trampoline(&mut guard, &tramp) }) else {
            return -1;
        };
        let mut stub = [0u8; 8];
        stub[0..2].copy_from_slice(&0xf8dfu16.to_le_bytes());
        stub[2..4].copy_from_slice(&0xf000u16.to_le_bytes());
        stub[4..8].copy_from_slice(&(replacement as u32).to_le_bytes());
        if !unsafe { patch_code(addr, &stub) } {
            return -1;
        }
        guard.hooks.insert(
            addr,
            InstalledHook {
                orig_bytes: orig.to_vec(),
                trampoline: tramp_addr | 1,
            },
        );
        if !backup.is_null() {
            unsafe { *backup = (tramp_addr | 1) as *mut std::ffi::c_void };
        }
        return 0;
    }

    // ARM32 8-byte stub: ldr pc, [pc, #-4] (0xe51ff004); .word replacement
    let mut orig = [0u8; 8];
    unsafe { std::ptr::copy_nonoverlapping(addr as *const u8, orig.as_mut_ptr(), 8) };
    let mut tramp = Vec::with_capacity(16);
    tramp.extend_from_slice(&orig);
    tramp.extend_from_slice(&0xe51f_f004u32.to_le_bytes());
    tramp.extend_from_slice(&((addr + 8) as u32).to_le_bytes());
    let Some(tramp_addr) = (unsafe { alloc_trampoline(&mut guard, &tramp) }) else {
        return -1;
    };
    let mut stub = [0u8; 8];
    stub[0..4].copy_from_slice(&0xe51f_f004u32.to_le_bytes());
    stub[4..8].copy_from_slice(&(replacement as u32).to_le_bytes());
    if !unsafe { patch_code(addr, &stub) } {
        return -1;
    }
    guard.hooks.insert(
        addr,
        InstalledHook {
            orig_bytes: orig.to_vec(),
            trampoline: tramp_addr,
        },
    );
    if !backup.is_null() {
        unsafe { *backup = tramp_addr as *mut std::ffi::c_void };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_imm64(words: &[u32]) -> (u32, u64) {
        assert_eq!(words.len(), 4);
        let rd = words[0] & 0x1f;
        let hw0 = ((words[0] >> 5) & 0xffff) as u64;
        let hw1 = ((words[1] >> 5) & 0xffff) as u64;
        let hw2 = ((words[2] >> 5) & 0xffff) as u64;
        let hw3 = ((words[3] >> 5) & 0xffff) as u64;
        (rd, hw0 | (hw1 << 16) | (hw2 << 32) | (hw3 << 48))
    }

    #[test]
    fn test_relocate_adrp_and_adr() {
        // ADRP x8, #0x3000 at pc = 0x70_0001_2344 -> page base 0x70_0001_2000 + 0x3000 = 0x70_0001_5000
        // imm21 = 3 -> immlo = 3, immhi = 0
        let adrp = 0x9000_0000 | (3u32 << 29) | 8;
        let RelocResult::Words(w) = relocate_arm64_insn(adrp, 0x70_0001_2344);
        assert_eq!(decode_imm64(&w), (8, 0x70_0001_5000));

        // ADR x1, #-16 at pc = 0x1000 -> 0x0ff0
        let neg16 = (-16i32 as u32) & 0x1f_ffff;
        let immlo = neg16 & 0x3;
        let immhi = neg16 >> 2;
        let adr = 0x1000_0000 | (immlo << 29) | (immhi << 5) | 1;
        let RelocResult::Words(w2) = relocate_arm64_insn(adr, 0x1000);
        assert_eq!(decode_imm64(&w2), (1, 0x0ff0));
    }

    #[test]
    fn test_relocate_b_and_bl() {
        // B +0x100 from 0x2000 -> target 0x2100 (imm26 = 0x40)
        let b_insn = 0x1400_0040;
        let RelocResult::Words(w) = relocate_arm64_insn(b_insn, 0x2000);
        assert_eq!(w, encode_arm64_abs_jump(0x2100).to_vec());

        // BL -0x20 from 0x2000 -> target 0x1fe0 (imm26 = -8)
        let imm26 = (-8i32 as u32) & 0x03ff_ffff;
        let bl_insn = 0x9400_0000 | imm26;
        let RelocResult::Words(w2) = relocate_arm64_insn(bl_insn, 0x2000);
        assert_eq!(w2.len(), 5);
        assert_eq!(w2[1], 0xd63f_0200); // blr x16
        assert_eq!((w2[3] as u64) | ((w2[4] as u64) << 32), 0x1fe0);
    }

    #[test]
    fn test_relocate_cond_cbz_tbz_and_ldr_literal() {
        // B.EQ +0x40 at 0x4000 -> skips on B.NE (+5 insns) then jumps to 0x4040
        let beq = 0x5400_0000 | (16u32 << 5) | 0;
        let RelocResult::Words(w) = relocate_arm64_insn(beq, 0x4000);
        assert_eq!(w.len(), 5);
        assert_eq!(w[0] & 0xf, 1); // inverted EQ -> NE
        assert_eq!((w[3] as u64) | ((w[4] as u64) << 32), 0x4040);

        // CBZ x0, +0x20 at 0x8000 -> inverted to CBNZ x0, +20 then jump to 0x8020
        let cbz = 0xb400_0000 | (8u32 << 5) | 0;
        let RelocResult::Words(w2) = relocate_arm64_insn(cbz, 0x8000);
        assert_eq!(w2.len(), 5);
        assert_eq!(w2[0] & 0x0100_0000, 0x0100_0000); // CBNZ
        assert_eq!((w2[3] as u64) | ((w2[4] as u64) << 32), 0x8020);

        // TBZ x2, #3, +0x10 at 0x9000 -> inverted to TBNZ then jump to 0x9010
        let tbz = 0x3600_0000 | (3u32 << 19) | (4u32 << 5) | 2;
        let RelocResult::Words(w3) = relocate_arm64_insn(tbz, 0x9000);
        assert_eq!(w3.len(), 5);
        assert_eq!(w3[0] & 0x0100_0000, 0x0100_0000); // TBNZ
        assert_eq!((w3[3] as u64) | ((w3[4] as u64) << 32), 0x9010);

        // LDR x5, [pc, #0x20] at 0xa000 -> loads 0xa020 into x16 then ldr x5, [x16]
        let ldr64 = 0x5800_0000 | (8u32 << 5) | 5;
        let RelocResult::Words(w4) = relocate_arm64_insn(ldr64, 0xa000);
        assert_eq!(w4.len(), 5);
        assert_eq!(decode_imm64(&w4[0..4]), (16, 0xa020));
        assert_eq!(w4[4], 0xf940_0205); // ldr x5, [x16]
    }

    #[test]
    fn test_build_arm64_trampoline_standard_prologue() {
        // Standard AArch64 prologue: bti c; stp x29, x30, [sp, #-32]!; mov x29, sp; sub sp, sp, #16
        let prologue = [0xd503_245f, 0xa9be_7bfd, 0x9100_03fd, 0xd100_43ff];
        let tramp = build_arm64_trampoline(prologue, 0x7000_0000);
        assert_eq!(tramp.len(), 8);
        assert_eq!(&tramp[0..4], &prologue);
        assert_eq!(&tramp[4..8], &encode_arm64_abs_jump(0x7000_0010));
    }
}
