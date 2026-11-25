// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust Android `__properties__` direct reader/editor (`resetprop`).
//!
//! Operates directly on Android Bionic's shared-memory property areas (`/dev/__properties__/*`)
//! without triggering `init`'s property service (`-n`), while supporting `-f <system.prop>`,
//! `-d <name>` (tombstone delete), and `-c` (in-place area compaction).
//!
//! Layout reference: AOSP `system/core/init/property_service` & `bionic/libc/system_properties`:
//!   `prop_area` header (128 bytes):
//!     0..4:  bytes_used (u32)
//!     4..8:  serial (u32)
//!     8..12: magic (0x504f5250 "PROP")
//!     12..16: version (0xfc6ed0ab)
//!     16..128: reserved[28]
//!     128..: data[] (starts with root `prop_bt` at offset 0 of `data`)
//!   `prop_bt` (20 bytes + namelen + 1):
//!     0..4:  namelen (u32)
//!     4..8:  prop (u32 offset into `data`, 0 = none)
//!     8..12: left (u32 offset into `data`)
//!     12..16: right (u32 offset into `data`)
//!     16..20: children (u32 offset into `data`)
//!     20..:  name[namelen + 1] (NUL-terminated)
//!   `prop_info` (96 bytes + name):
//!     0..4:  serial (u32; top byte = value len, bit 0 = dirty, bit 16 = long_flag)
//!     4..96: value[92] (or for long property: error_msg[56] + u32 offset at 56..60)
//!     96..:  name (NUL-terminated)

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

pub const PROP_AREA_MAGIC: u32 = 0x504f_5250;
pub const PROP_AREA_VERSION: u32 = 0xfc6e_d0ab;
pub const PROP_AREA_HEADER_SIZE: usize = 128;
pub const PROP_VALUE_MAX: usize = 92;
pub const K_LONG_FLAG: u32 = 1 << 16;
pub const K_LONG_LEGACY_ERROR: &[u8] = b"Must use __system_property_read_callback() to read";

const DEFAULT_PROP_DIR: &str = "/dev/__properties__";

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    if off + 4 > buf.len() {
        return None;
    }
    Some(u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]))
}

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn cstr_slice(buf: &[u8], off: usize) -> Option<&[u8]> {
    if off >= buf.len() {
        return None;
    }
    let tail = &buf[off..];
    let end = tail.iter().position(|&b| b == 0)?;
    Some(&tail[..end])
}

/// Compares a trie node's name component using Bionic's exact `cmp_prop_name` ordering:
/// shorter length first, then lexicographic `memcmp`.
fn cmp_prop_name(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Safe slice-based accessor over a mapped or in-memory `prop_area` buffer.
pub struct PropAreaMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> PropAreaMut<'a> {
    pub fn open(buf: &'a mut [u8]) -> Result<Self, &'static str> {
        if buf.len() < PROP_AREA_HEADER_SIZE + 24 {
            return Err("prop_area too small");
        }
        let magic = read_u32_le(buf, 8).ok_or("truncated")?;
        let ver = read_u32_le(buf, 12).ok_or("truncated")?;
        if magic != PROP_AREA_MAGIC || ver != PROP_AREA_VERSION {
            return Err("invalid prop_area header");
        }
        Ok(Self { buf })
    }

    /// Initializes a brand-new empty `prop_area` (used for tests and `-c` compaction).
    pub fn init_empty(buf: &'a mut [u8]) -> Result<Self, &'static str> {
        if buf.len() < PROP_AREA_HEADER_SIZE + 64 {
            return Err("prop_area buffer too small");
        }
        buf.fill(0);
        // Root prop_bt occupies 24 bytes (namelen=0, NUL byte, aligned to 4).
        write_u32_le(buf, 0, 24);
        write_u32_le(buf, 4, 0);
        write_u32_le(buf, 8, PROP_AREA_MAGIC);
        write_u32_le(buf, 12, PROP_AREA_VERSION);
        Ok(Self { buf })
    }

    fn data_cap(&self) -> usize {
        self.buf.len() - PROP_AREA_HEADER_SIZE
    }

    fn bytes_used(&self) -> usize {
        read_u32_le(self.buf, 0).unwrap_or(0) as usize
    }

    fn alloc_obj(&mut self, size: usize) -> Result<u32, &'static str> {
        let aligned = align4(size);
        let used = self.bytes_used();
        if used + aligned > self.data_cap() {
            return Err("prop_area full");
        }
        let off = used as u32;
        self.buf[PROP_AREA_HEADER_SIZE + used..PROP_AREA_HEADER_SIZE + used + aligned].fill(0);
        write_u32_le(self.buf, 0, (used + aligned) as u32);
        Ok(off)
    }

    fn bump_area_serial(&mut self) {
        let cur = read_u32_le(self.buf, 4).unwrap_or(0);
        write_u32_le(self.buf, 4, cur.wrapping_add(1));
    }

    fn find_bt(&mut self, name: &str, alloc_if_needed: bool) -> Result<Option<u32>, &'static str> {
        let mut current = 0u32; // root prop_bt at data offset 0
        for part in name.split('.') {
            let part_bytes = part.as_bytes();
            let children_field = PROP_AREA_HEADER_SIZE + current as usize + 16;
            let mut node = read_u32_le(self.buf, children_field).ok_or("bad bt offset")?;
            if node == 0 {
                if !alloc_if_needed {
                    return Ok(None);
                }
                let new_node = self.alloc_bt(part_bytes)?;
                write_u32_le(self.buf, children_field, new_node);
                current = new_node;
                continue;
            }
            loop {
                let base = PROP_AREA_HEADER_SIZE + node as usize;
                let namelen = read_u32_le(self.buf, base).ok_or("bad bt")? as usize;
                if base + 20 + namelen > self.buf.len() {
                    return Err("corrupt bt name");
                }
                let existing = &self.buf[base + 20..base + 20 + namelen];
                match cmp_prop_name(part_bytes, existing) {
                    std::cmp::Ordering::Equal => {
                        current = node;
                        break;
                    }
                    std::cmp::Ordering::Less => {
                        let left_field = base + 8;
                        let left = read_u32_le(self.buf, left_field).ok_or("bad left")?;
                        if left == 0 {
                            if !alloc_if_needed {
                                return Ok(None);
                            }
                            let new_node = self.alloc_bt(part_bytes)?;
                            write_u32_le(self.buf, left_field, new_node);
                            current = new_node;
                            break;
                        }
                        node = left;
                    }
                    std::cmp::Ordering::Greater => {
                        let right_field = base + 12;
                        let right = read_u32_le(self.buf, right_field).ok_or("bad right")?;
                        if right == 0 {
                            if !alloc_if_needed {
                                return Ok(None);
                            }
                            let new_node = self.alloc_bt(part_bytes)?;
                            write_u32_le(self.buf, right_field, new_node);
                            current = new_node;
                            break;
                        }
                        node = right;
                    }
                }
            }
        }
        Ok(Some(current))
    }

    fn alloc_bt(&mut self, part: &[u8]) -> Result<u32, &'static str> {
        let off = self.alloc_obj(20 + part.len() + 1)?;
        let base = PROP_AREA_HEADER_SIZE + off as usize;
        write_u32_le(self.buf, base, part.len() as u32);
        self.buf[base + 20..base + 20 + part.len()].copy_from_slice(part);
        self.buf[base + 20 + part.len()] = 0;
        Ok(off)
    }

    pub fn get(&mut self, name: &str) -> Option<String> {
        let bt = self.find_bt(name, false).ok()??;
        let prop_off = read_u32_le(self.buf, PROP_AREA_HEADER_SIZE + bt as usize + 4)?;
        if prop_off == 0 {
            return None;
        }
        let base = PROP_AREA_HEADER_SIZE + prop_off as usize;
        let serial = read_u32_le(self.buf, base)?;
        if serial & K_LONG_FLAG != 0 {
            let long_rel = read_u32_le(self.buf, base + 4 + 56)? as usize;
            let bytes = cstr_slice(self.buf, base + long_rel)?;
            Some(String::from_utf8_lossy(bytes).into_owned())
        } else {
            let len = ((serial >> 24) as usize).min(PROP_VALUE_MAX - 1);
            if base + 4 + len > self.buf.len() {
                return None;
            }
            Some(String::from_utf8_lossy(&self.buf[base + 4..base + 4 + len]).into_owned())
        }
    }

    /// Updates an existing property in-place (preserving readers via atomic dirty-bit serial
    /// protocol) or creates a new `prop_info` node if `create` is true.
    pub fn set(&mut self, name: &str, value: &str, create: bool) -> Result<bool, &'static str> {
        let Some(bt) = self.find_bt(name, create)? else {
            return Ok(false);
        };
        let prop_field = PROP_AREA_HEADER_SIZE + bt as usize + 4;
        let mut prop_off = read_u32_le(self.buf, prop_field).ok_or("bad bt")?;
        let val_bytes = value.as_bytes();
        let is_long = val_bytes.len() >= PROP_VALUE_MAX;

        if prop_off == 0 {
            if !create {
                return Ok(false);
            }
            prop_off = self.alloc_obj(96 + name.len() + 1)?;
            let base = PROP_AREA_HEADER_SIZE + prop_off as usize;
            self.buf[base + 96..base + 96 + name.len()].copy_from_slice(name.as_bytes());
            self.buf[base + 96 + name.len()] = 0;
            if is_long {
                let long_off = self.alloc_obj(val_bytes.len() + 1)?;
                let lbase = PROP_AREA_HEADER_SIZE + long_off as usize;
                self.buf[lbase..lbase + val_bytes.len()].copy_from_slice(val_bytes);
                self.buf[lbase + val_bytes.len()] = 0;
                self.buf[base + 4..base + 4 + K_LONG_LEGACY_ERROR.len()].copy_from_slice(K_LONG_LEGACY_ERROR);
                let rel = (long_off as usize).saturating_sub(prop_off as usize) as u32;
                write_u32_le(self.buf, base + 4 + 56, rel);
                write_u32_le(self.buf, base, K_LONG_FLAG);
            } else {
                self.buf[base + 4..base + 4 + val_bytes.len()].copy_from_slice(val_bytes);
                self.buf[base + 4 + val_bytes.len()] = 0;
                write_u32_le(self.buf, base, (val_bytes.len() as u32) << 24);
            }
            write_u32_le(self.buf, prop_field, prop_off);
            self.bump_area_serial();
            return Ok(true);
        }

        let base = PROP_AREA_HEADER_SIZE + prop_off as usize;
        let cur_serial = read_u32_le(self.buf, base).ok_or("bad prop")?;
        let dirty_serial = cur_serial | 1;
        // Mark dirty (atomic release).
        unsafe {
            let ptr = self.buf.as_mut_ptr().add(base) as *const AtomicU32;
            (*ptr).store(dirty_serial, Ordering::Release);
        }

        let new_serial = if is_long || (cur_serial & K_LONG_FLAG != 0) {
            let long_off = self.alloc_obj(val_bytes.len() + 1)?;
            let lbase = PROP_AREA_HEADER_SIZE + long_off as usize;
            self.buf[lbase..lbase + val_bytes.len()].copy_from_slice(val_bytes);
            self.buf[lbase + val_bytes.len()] = 0;
            self.buf[base + 4..base + 96].fill(0);
            self.buf[base + 4..base + 4 + K_LONG_LEGACY_ERROR.len()].copy_from_slice(K_LONG_LEGACY_ERROR);
            let rel = (long_off as usize).saturating_sub(prop_off as usize) as u32;
            write_u32_le(self.buf, base + 4 + 56, rel);
            (((cur_serial & 0x00ff_ffff) + 2) & !1) | K_LONG_FLAG
        } else {
            self.buf[base + 4..base + 96].fill(0);
            self.buf[base + 4..base + 4 + val_bytes.len()].copy_from_slice(val_bytes);
            (((cur_serial & 0x00ff_ffff) + 2) & !1) | ((val_bytes.len() as u32) << 24)
        };

        unsafe {
            let ptr = self.buf.as_mut_ptr().add(base) as *const AtomicU32;
            (*ptr).store(new_serial, Ordering::Release);
        }
        self.bump_area_serial();
        Ok(true)
    }

    /// Deletes a property by clearing its `prop` pointer in the trie node (Bionic readers
    /// immediately see `nullptr` from `__system_property_find`).
    pub fn delete(&mut self, name: &str) -> Result<bool, &'static str> {
        let Some(bt) = self.find_bt(name, false)? else {
            return Ok(false);
        };
        let prop_field = PROP_AREA_HEADER_SIZE + bt as usize + 4;
        let prop_off = read_u32_le(self.buf, prop_field).ok_or("bad bt")?;
        if prop_off == 0 {
            return Ok(false);
        }
        write_u32_le(self.buf, prop_field, 0);
        self.bump_area_serial();
        Ok(true)
    }

    /// Enumerates all live `(name, value)` pairs inside this area (used for `-c` compaction).
    pub fn list_all(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        self.walk_bt(0, &mut out, 0);
        out
    }

    fn walk_bt(&self, node: u32, out: &mut Vec<(String, String)>, depth: usize) {
        if depth > 64 {
            return;
        }
        let base = PROP_AREA_HEADER_SIZE + node as usize;
        if base + 20 > self.buf.len() {
            return;
        }
        let prop_off = read_u32_le(self.buf, base + 4).unwrap_or(0);
        if prop_off != 0 {
            let pbase = PROP_AREA_HEADER_SIZE + prop_off as usize;
            if let (Some(serial), Some(name_b)) = (read_u32_le(self.buf, pbase), cstr_slice(self.buf, pbase + 96)) {
                let name = String::from_utf8_lossy(name_b).into_owned();
                let val = if serial & K_LONG_FLAG != 0 {
                    read_u32_le(self.buf, pbase + 4 + 56)
                        .and_then(|rel| cstr_slice(self.buf, pbase + rel as usize))
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .unwrap_or_default()
                } else {
                    let len = ((serial >> 24) as usize).min(PROP_VALUE_MAX - 1);
                    if pbase + 4 + len <= self.buf.len() {
                        String::from_utf8_lossy(&self.buf[pbase + 4..pbase + 4 + len]).into_owned()
                    } else {
                        String::new()
                    }
                };
                out.push((name, val));
            }
        }
        let left = read_u32_le(self.buf, base + 8).unwrap_or(0);
        let right = read_u32_le(self.buf, base + 12).unwrap_or(0);
        let children = read_u32_le(self.buf, base + 16).unwrap_or(0);
        if left != 0 { self.walk_bt(left, out, depth + 1); }
        if children != 0 { self.walk_bt(children, out, depth + 1); }
        if right != 0 { self.walk_bt(right, out, depth + 1); }
    }

    /// Compacts the property area in-place (`resetprop -c`), reclaiming dead tombstones
    /// left behind by deleted properties.
    pub fn compact(&mut self) -> Result<usize, &'static str> {
        let live = self.list_all();
        let old_serial = read_u32_le(self.buf, 4).unwrap_or(0);
        let mut scratch = vec![0u8; self.buf.len()];
        {
            let mut fresh = PropAreaMut::init_empty(&mut scratch)?;
            for (k, v) in &live {
                fresh.set(k, v, true)?;
            }
        }
        self.buf.copy_from_slice(&scratch);
        write_u32_le(self.buf, 4, old_serial.wrapping_add(2));
        Ok(live.len())
    }
}

fn with_mapped_area<F, R>(path: &Path, write: bool, f: F) -> io::Result<R>
where
    F: FnOnce(&mut PropAreaMut<'_>) -> Result<R, &'static str>,
{
    let file = OpenOptions::new().read(true).write(write).open(path)?;
    let len = file.metadata()?.len() as usize;
    if len < PROP_AREA_HEADER_SIZE + 24 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "area file too small"));
    }
    let prot = if write { libc::PROT_READ | libc::PROT_WRITE } else { libc::PROT_READ };
    let ptr = unsafe {
        libc::mmap(std::ptr::null_mut(), len, prot, libc::MAP_SHARED, file.as_raw_fd(), 0)
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, len) };
    let res = PropAreaMut::open(slice)
        .and_then(|mut area| f(&mut area))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
    unsafe { libc::munmap(ptr, len) };
    res
}

fn prop_area_files(prop_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(rd) = fs::read_dir(prop_dir) else { return files };
    for ent in rd.flatten() {
        let p = ent.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else { continue };
        if name == "property_info" || name == "properties_serial" || !p.is_file() {
            continue;
        }
        files.push(p);
    }
    files.sort();
    files
}

/// Scans `/dev/__properties__/*` to locate and update `name = value` directly in memory.
pub fn set_prop_direct(prop_dir: &Path, name: &str, value: &str) -> io::Result<bool> {
    let files = prop_area_files(prop_dir);
    for f in &files {
        if let Ok(true) = with_mapped_area(f, true, |area| area.set(name, value, false)) {
            return Ok(true);
        }
    }
    // Not found in existing areas -> create inside default `u:object_r:default_prop:s0` if present.
    let default_area = prop_dir.join("u:object_r:default_prop:s0");
    if default_area.is_file() {
        return with_mapped_area(&default_area, true, |area| area.set(name, value, true));
    }
    Ok(false)
}

pub fn get_prop_direct(prop_dir: &Path, name: &str) -> Option<String> {
    for f in prop_area_files(prop_dir) {
        if let Ok(Some(v)) = with_mapped_area(&f, false, |area| Ok(area.get(name))) {
            return Some(v);
        }
    }
    None
}

pub fn delete_prop_direct(prop_dir: &Path, name: &str) -> io::Result<bool> {
    for f in prop_area_files(prop_dir) {
        if let Ok(true) = with_mapped_area(&f, true, |area| area.delete(name)) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn compact_all_areas(prop_dir: &Path) -> usize {
    let mut total = 0usize;
    for f in prop_area_files(prop_dir) {
        if let Ok(n) = with_mapped_area(&f, true, |area| area.compact()) {
            total += n;
        }
    }
    total
}

/// Applies a module `system.prop` file (`key=value` lines, ignoring `#` comments).
pub fn load_prop_file(prop_dir: &Path, file: &Path) -> io::Result<usize> {
    let text = fs::read_to_string(file)?;
    let mut count = 0usize;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let val = v.trim();
            if !key.is_empty() && set_prop_direct(prop_dir, key, val).unwrap_or(false) {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// CLI entrypoint for `resetprop` / `yasvara_rootd resetprop`.
pub fn cli_main(args: &[String]) -> i32 {
    let prop_dir = Path::new(DEFAULT_PROP_DIR);
    let mut delete_mode = false;
    let mut file_mode = false;
    let mut compact_mode = false;
    let mut pos: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" | "-v" | "-p" => {}
            "-d" | "--delete" => delete_mode = true,
            "-f" | "--file" => file_mode = true,
            "-c" | "--compact" => compact_mode = true,
            "-h" | "--help" => {
                println!("Usage: resetprop [-n] [-d NAME] [-f FILE] [-c] [NAME [VALUE]]");
                return 0;
            }
            s => pos.push(s),
        }
        i += 1;
    }
    if compact_mode {
        let n = compact_all_areas(prop_dir);
        println!("compacted {n} properties");
        return 0;
    }
    if file_mode {
        let Some(path) = pos.first() else {
            eprintln!("resetprop: -f requires a file path");
            return 1;
        };
        return match load_prop_file(prop_dir, Path::new(path)) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("resetprop: {e}");
                1
            }
        };
    }
    if delete_mode {
        let Some(name) = pos.first() else {
            eprintln!("resetprop: -d requires a property name");
            return 1;
        };
        return match delete_prop_direct(prop_dir, name) {
            Ok(true) => 0,
            _ => 1,
        };
    }
    match pos.as_slice() {
        [name] => match get_prop_direct(prop_dir, name) {
            Some(v) => {
                println!("{v}");
                0
            }
            None => 1,
        },
        [name, value] => match set_prop_direct(prop_dir, name, value) {
            Ok(true) => 0,
            Ok(false) => 1,
            Err(e) => {
                eprintln!("resetprop: {e}");
                1
            }
        },
        _ => {
            eprintln!("resetprop: invalid arguments");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prop_area_set_get_long_delete_and_compact() {
        let mut mem = vec![0u8; 64 * 1024];
        let mut area = PropAreaMut::init_empty(&mut mem).unwrap();
        assert!(area.set("ro.build.fingerprint", "google/oriole/oriole:15/AP3A", true).unwrap());
        assert!(area.set("ro.boot.verifiedbootstate", "orange", true).unwrap());
        let long_val = "x".repeat(140);
        assert!(area.set("ro.yasvara.longprop", &long_val, true).unwrap());

        assert_eq!(area.get("ro.boot.verifiedbootstate").as_deref(), Some("orange"));
        assert_eq!(area.get("ro.yasvara.longprop").as_deref(), Some(long_val.as_str()));

        // Direct in-place mutation (`resetprop -n`)
        assert!(area.set("ro.boot.verifiedbootstate", "green", false).unwrap());
        assert_eq!(area.get("ro.boot.verifiedbootstate").as_deref(), Some("green"));

        // Delete + compact reclaims deleted entry cleanly.
        assert!(area.delete("ro.yasvara.longprop").unwrap());
        assert_eq!(area.get("ro.yasvara.longprop"), None);
        let live_after = area.compact().unwrap();
        assert_eq!(live_after, 2);
        assert_eq!(area.get("ro.boot.verifiedbootstate").as_deref(), Some("green"));
        assert_eq!(area.get("ro.build.fingerprint").as_deref(), Some("google/oriole/oriole:15/AP3A"));
    }
}
