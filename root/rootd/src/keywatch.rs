// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Early-boot hardware shortcut listener (`yasvara_rootd --stage keywatch`).
//!
//! Runs from `on init` until `post-fs-data` finishes (or 25s safety cap). Monitors only
//! `/dev/input/event*` devices advertising `KEY_VOLUMEDOWN` or `KEY_POWER` via `epoll`
//! plus the optional KABI-clean kernel early latch `/proc/yasvara_bootkey`.
//! Zero CPU when idle; exits cleanly once `post-fs-data` writes the completion sentinel.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use yasvara_root_proto::bootguard::{
    parse_kernel_bootkey, KeySequenceDetector, KEY_POWER, KEY_VOLUMEDOWN,
};

use crate::sys;

pub const VOLATILE_SAFEMODE_NAME: &str = ".safemode_boot";
pub const KEYWATCH_DONE_NAME: &str = ".kw_boot";
pub const DEFAULT_ROOT_DATA_DIR: &str = "/data/misc/yasvara_root";
pub const KERNEL_BOOTKEY_PROC: &str = "/proc/yasvara_bootkey";

const EV_KEY: u16 = 0x01;
const KEY_MAX: usize = 0x2ff;
const KEY_BYTES: usize = (KEY_MAX / 8) + 1;
const MAX_KEYWATCH_DURATION: Duration = Duration::from_secs(25);

#[repr(C)]
#[derive(Clone, Copy)]
struct InputEvent {
    tv_sec: libc::c_long,
    tv_usec: libc::c_long,
    type_: u16,
    code: u16,
    value: i32,
}

// Linux _IOC encoding (generic across arm64/x86_64/arm).
const fn ioc(dir: u32, typ: u32, nr: u32, size: u32) -> libc::c_ulong {
    (((dir) << 30) | ((size) << 16) | ((typ) << 8) | (nr)) as libc::c_ulong
}

const fn eviocgbit(ev: u32, len: usize) -> libc::c_ulong {
    ioc(2, b'E' as u32, 0x20 + ev, len as u32)
}

const fn eviocgkey(len: usize) -> libc::c_ulong {
    ioc(2, b'E' as u32, 0x18, len as u32)
}

fn bit_set(bits: &[u8], code: u16) -> bool {
    let idx = (code as usize) / 8;
    let bit = (code as usize) % 8;
    bits.get(idx).map_or(false, |&b| (b & (1 << bit)) != 0)
}

fn open_key_devices(detector: &mut KeySequenceDetector, start_ms: u64) -> Vec<RawFd> {
    let mut fds = Vec::new();
    let Ok(entries) = fs::read_dir("/dev/input") else {
        return fds;
    };
    for ent in entries.flatten() {
        let name = ent.file_name();
        let Some(name_str) = name.to_str() else { continue };
        if !name_str.starts_with("event") {
            continue;
        }
        let path = ent.path();
        let Ok(cpath) = CString::new(path.to_string_lossy().as_bytes()) else { continue };
        let fd = unsafe {
            libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        };
        if fd < 0 {
            continue;
        }
        let mut key_bits = [0u8; KEY_BYTES];
        let rc = unsafe {
            libc::ioctl(fd, eviocgbit(EV_KEY as u32, key_bits.len()) as _, key_bits.as_mut_ptr())
        };
        if rc < 0 || (!bit_set(&key_bits, KEY_VOLUMEDOWN) && !bit_set(&key_bits, KEY_POWER)) {
            sys::close(fd);
            continue;
        }
        // Snapshot keys already held down before `keywatch` started.
        let mut cur_keys = [0u8; KEY_BYTES];
        if unsafe { libc::ioctl(fd, eviocgkey(cur_keys.len()) as _, cur_keys.as_mut_ptr()) } >= 0 {
            if bit_set(&cur_keys, KEY_POWER) {
                detector.on_key(start_ms, KEY_POWER, 1);
            }
            if bit_set(&cur_keys, KEY_VOLUMEDOWN) {
                detector.on_key(start_ms, KEY_VOLUMEDOWN, 1);
            }
        }
        fds.push(fd);
    }
    fds
}

/// Marks `post-fs-data` complete for this boot inside `<data_dir>` (strictly invisible to apps).
pub fn signal_keywatch_done(data_dir: &Path) {
    let boot_id = sys::boot_id();
    let _ = fs::write(data_dir.join(KEYWATCH_DONE_NAME), boot_id.as_bytes());
}

fn is_keywatch_done(boot_id: &str) -> bool {
    let path = Path::new(DEFAULT_ROOT_DATA_DIR).join(KEYWATCH_DONE_NAME);
    fs::read_to_string(path).map_or(false, |s| s.trim() == boot_id)
}

/// Reads and clears a current-boot hardware shortcut trigger written by `keywatch`.
pub fn consume_volatile_safemode(data_dir: &Path) -> Option<String> {
    let path = data_dir.join(VOLATILE_SAFEMODE_NAME);
    let raw = fs::read_to_string(&path).ok()?;
    let _ = fs::remove_file(&path);
    let trimmed = raw.trim();
    let (stored_boot, reason) = trimmed.split_once('|')?;
    if stored_boot == sys::boot_id() && !reason.is_empty() {
        Some(reason.to_string())
    } else {
        None
    }
}

fn write_volatile_trigger(boot_id: &str, reason: &str) {
    use std::io::Write;
    let dir = Path::new(DEFAULT_ROOT_DATA_DIR);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !dir.is_dir() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if let Ok(mut f) = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dir.join(VOLATILE_SAFEMODE_NAME))
    {
        let _ = writeln!(f, "{}|{}", boot_id, reason);
    }
}

/// Best-effort double haptic buzz so the user feels Safe Mode confirmation even with a black screen.
fn haptic_confirm() {
    let vib_candidates = [
        ("/sys/class/leds/vibrator/duration", "/sys/class/leds/vibrator/activate"),
        ("/sys/class/timed_output/vibrator/enable", ""),
    ];
    for (dur_path, act_path) in vib_candidates {
        if Path::new(dur_path).exists() {
            for _ in 0..2 {
                let _ = fs::write(dur_path, b"120");
                if !act_path.is_empty() {
                    let _ = fs::write(act_path, b"1");
                }
                std::thread::sleep(Duration::from_millis(220));
            }
            return;
        }
    }
}

/// Reads and disarms `/proc/yasvara_bootkey` if present.
pub fn consume_kernel_bootkey() -> Option<String> {
    let text = fs::read_to_string(KERNEL_BOOTKEY_PROC).ok()?;
    let st = parse_kernel_bootkey(&text);
    if st.triggered {
        Some(if st.reason.is_empty() { "kernel_bootkey".to_string() } else { st.reason })
    } else {
        None
    }
}

/// Entrypoint for `yasvara_rootd --stage keywatch`.
pub fn run_keywatch() -> io::Result<()> {
    let started = Instant::now();
    let boot_id = sys::boot_id();
    // Check if the kernel early latch already captured a shortcut during bootloader→init handoff.
    if let Ok(text) = fs::read_to_string(KERNEL_BOOTKEY_PROC) {
        let st = parse_kernel_bootkey(&text);
        if st.triggered {
            let reason = if st.reason.is_empty() { "kernel_bootkey" } else { st.reason.as_str() };
            write_volatile_trigger(&boot_id, reason);
            haptic_confirm();
            return Ok(());
        }
    }

    let mut detector = KeySequenceDetector::new();
    let fds = open_key_devices(&mut detector, 0);
    if let Some(reason) = detector.triggered_reason() {
        write_volatile_trigger(&boot_id, reason);
        haptic_confirm();
        fds.iter().for_each(|&fd| sys::close(fd));
        return Ok(());
    }

    let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if ep < 0 {
        fds.iter().for_each(|&fd| sys::close(fd));
        return Err(io::Error::last_os_error());
    }
    for &fd in &fds {
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: fd as u64 };
        unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) };
    }

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
    let mut ev_buf = [InputEvent { tv_sec: 0, tv_usec: 0, type_: 0, code: 0, value: 0 }; 16];

    while started.elapsed() < MAX_KEYWATCH_DURATION {
        if is_keywatch_done(&boot_id) {
            break;
        }
        let n = unsafe { libc::epoll_wait(ep, events.as_mut_ptr(), events.len() as i32, 200) };
        let now_ms = started.elapsed().as_millis() as u64;
        if n > 0 {
            for ev in &events[..n as usize] {
                let fd = ev.u64 as RawFd;
                loop {
                    let bytes = unsafe {
                        libc::read(
                            fd,
                            ev_buf.as_mut_ptr() as *mut libc::c_void,
                            std::mem::size_of_val(&ev_buf),
                        )
                    };
                    if bytes <= 0 {
                        break;
                    }
                    let count = (bytes as usize) / std::mem::size_of::<InputEvent>();
                    for item in &ev_buf[..count] {
                        if item.type_ == EV_KEY {
                            if let Some(reason) = detector.on_key(now_ms, item.code, item.value) {
                                write_volatile_trigger(&boot_id, reason);
                                haptic_confirm();
                                sys::close(ep);
                                fds.iter().for_each(|&f| sys::close(f));
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
        if let Some(reason) = detector.poll_tick(now_ms) {
            write_volatile_trigger(&boot_id, reason);
            haptic_confirm();
            break;
        }
    }

    sys::close(ep);
    fds.iter().for_each(|&fd| sys::close(fd));
    Ok(())
}
