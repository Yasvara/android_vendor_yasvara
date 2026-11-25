// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `libyasvara_zygisk.so` — ROM-Native Zygisk runtime (API v4 & v5).
//!
//! Zero-overhead, zero-detection architecture:
//!   - NEVER loaded inside the Zygote parent process (Zygote stays 100% stock!).
//!   - Loaded via `dlopen("libyasvara_zygisk.so")` ONLY inside forked children that match
//!     at least one active Zygisk module scope in `zygisk.set` and are NOT on the DenyList.
//!   - Phase 1 (`yasvara_zygisk_pre`): runs before `setresuid` / SELinux drop so `getModuleDir()`
//!     and `connectCompanion()` work cleanly without granting apps search on `/data/misc/yasvara_root`.
//!   - Phase 2 (`yasvara_zygisk_post`): runs after `gCallPostForkChildHooks`; honors
//!     `DLCLOSE_MODULE_LIBRARY` (with Bionic's zero-hole `atexit` recompaction).

pub mod abi;
pub mod plt;

use std::ffi::{c_char, c_int, c_void, CString};
use std::os::unix::io::RawFd;
use std::sync::Mutex;

use yasvara_root_proto::mounts::{ZygiskSet, SCOPE_ALL_NON_DENYLIST};

use crate::abi::{
    ApiTable, AppSpecializeArgs, JniEnvPtr, JniNativeMethod, ModuleAbi, ServerSpecializeArgs,
    ZygiskModuleEntryFn, OPTION_DLCLOSE_MODULE_LIBRARY, OPTION_FORCE_DENYLIST_UNMOUNT,
    STATE_FLAG_PROCESS_GRANTED_ROOT, STATE_FLAG_PROCESS_ON_DENYLIST, ZYGISK_OUT_FORCE_UNMOUNT,
};

pub const COMPANION_MAGIC: [u8; 4] = *b"AKZC";
const COMPANION_SOCK_PRIMARY: &str = "/data/misc/yasvara_root/run/zygisk.sock";
const COMPANION_SOCK_PROJECTED: &str = "/system/xbin/.s/zygisk.sock";

/// Minimal JNIEnv function table offsets needed for `hookJniNativeMethods`:
/// `FindClass` = index 6, `ExceptionClear` = index 17, `RegisterNatives` = index 215.
const JNI_FIND_CLASS_IDX: usize = 6;
const JNI_EXCEPTION_CLEAR_IDX: usize = 17;
const JNI_REGISTER_NATIVES_IDX: usize = 215;

struct LoadedModule {
    id: String,
    dl_handle: usize,
    mod_dir_fd: RawFd,
    state_flags: u32,
    dlclose_requested: bool,
    force_unmount: bool,
    abi: Option<ModuleAbi>,
    api_table: Box<ApiTable>,
}

// SAFETY: LoadedModule holds raw C ABI handles exclusively accessed under `LOADED_MODULES`
// on the single-threaded Zygote child during specialization.
unsafe impl Send for LoadedModule {}

static LOADED_MODULES: Mutex<Vec<Box<LoadedModule>>> = Mutex::new(Vec::new());

unsafe extern "C" fn api_register_module(table: *mut ApiTable, module: *mut ModuleAbi) -> bool {
    if table.is_null() || module.is_null() {
        return false;
    }
    let mod_ctx = &mut *((*table).impl_ptr as *mut LoadedModule);
    mod_ctx.abi = Some(std::ptr::read(module));
    true
}

unsafe extern "C" fn api_hook_jni_native_methods(
    env: JniEnvPtr,
    class_name: *const c_char,
    methods: *mut JniNativeMethod,
    num_methods: c_int,
) {
    if env.is_null() || class_name.is_null() || methods.is_null() || num_methods <= 0 {
        return;
    }
    let vtable = *(env as *const *const *const c_void);
    if vtable.is_null() {
        return;
    }
    type FindClassFn = unsafe extern "C" fn(JniEnvPtr, *const c_char) -> *mut c_void;
    type ExceptionClearFn = unsafe extern "C" fn(JniEnvPtr);
    type RegisterNativesFn =
        unsafe extern "C" fn(JniEnvPtr, *mut c_void, *const JniNativeMethod, c_int) -> c_int;

    let find_class: FindClassFn = std::mem::transmute(*vtable.add(JNI_FIND_CLASS_IDX));
    let exc_clear: ExceptionClearFn = std::mem::transmute(*vtable.add(JNI_EXCEPTION_CLEAR_IDX));
    let reg_natives: RegisterNativesFn =
        std::mem::transmute(*vtable.add(JNI_REGISTER_NATIVES_IDX));

    let cls = find_class(env, class_name);
    if cls.is_null() {
        exc_clear(env);
        return;
    }
    if reg_natives(env, cls, methods, num_methods) != 0 {
        exc_clear(env);
    }
}

unsafe extern "C" fn api_plt_hook_register(
    dev: libc::dev_t,
    ino: libc::ino_t,
    symbol: *const c_char,
    new_func: *mut c_void,
    old_func: *mut *mut c_void,
) {
    plt::register(dev, ino, symbol, new_func, old_func);
}

unsafe extern "C" fn api_exempt_fd(_fd: c_int) -> bool {
    // Because Native Zygisk runs inside the forked child (not Zygote parent),
    // Zygote's FileDescriptorTable check has already completed; every fd opened by
    // the module is inherently exempt!
    true
}

unsafe extern "C" fn api_plt_hook_commit() -> bool {
    plt::commit()
}

fn connect_unix(path: &str) -> RawFd {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return -1;
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    let bytes = path.as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        unsafe { libc::close(fd) };
        return -1;
    }
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as _,
        )
    };
    if rc != 0 {
        unsafe { libc::close(fd) };
        return -1;
    }
    fd
}

unsafe extern "C" fn api_connect_companion(impl_ptr: *mut c_void) -> c_int {
    if impl_ptr.is_null() {
        return -1;
    }
    let mod_ctx = &*(impl_ptr as *const LoadedModule);
    let mut fd = connect_unix(COMPANION_SOCK_PRIMARY);
    if fd < 0 {
        fd = connect_unix(COMPANION_SOCK_PROJECTED);
    }
    if fd < 0 {
        return -1;
    }
    let id_bytes = mod_ctx.id.as_bytes();
    let mut hdr = Vec::with_capacity(8 + id_bytes.len());
    hdr.extend_from_slice(&COMPANION_MAGIC);
    hdr.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
    hdr.extend_from_slice(id_bytes);
    let mut off = 0;
    while off < hdr.len() {
        let n = libc::send(
            fd,
            hdr[off..].as_ptr() as *const c_void,
            hdr.len() - off,
            libc::MSG_NOSIGNAL,
        );
        if n <= 0 {
            libc::close(fd);
            return -1;
        }
        off += n as usize;
    }
    fd
}

unsafe extern "C" fn api_set_option(impl_ptr: *mut c_void, opt: c_int) {
    if impl_ptr.is_null() {
        return;
    }
    let mod_ctx = &mut *(impl_ptr as *mut LoadedModule);
    match opt {
        OPTION_FORCE_DENYLIST_UNMOUNT => mod_ctx.force_unmount = true,
        OPTION_DLCLOSE_MODULE_LIBRARY => mod_ctx.dlclose_requested = true,
        _ => {}
    }
}

unsafe extern "C" fn api_get_module_dir(impl_ptr: *mut c_void) -> c_int {
    if impl_ptr.is_null() {
        return -1;
    }
    let mod_ctx = &*(impl_ptr as *const LoadedModule);
    if mod_ctx.mod_dir_fd < 0 {
        return -1;
    }
    libc::fcntl(mod_ctx.mod_dir_fd, libc::F_DUPFD_CLOEXEC, 0)
}

unsafe extern "C" fn api_get_flags(impl_ptr: *mut c_void) -> u32 {
    if impl_ptr.is_null() {
        return 0;
    }
    let mod_ctx = &*(impl_ptr as *const LoadedModule);
    mod_ctx.state_flags
}

fn make_api_table(impl_ptr: *mut c_void) -> Box<ApiTable> {
    Box::new(ApiTable {
        impl_ptr,
        register_module: api_register_module,
        hook_jni_native_methods: api_hook_jni_native_methods,
        plt_hook_register: api_plt_hook_register,
        exempt_fd: api_exempt_fd,
        plt_hook_commit: api_plt_hook_commit,
        connect_companion: api_connect_companion,
        set_option: api_set_option,
        get_module_dir: api_get_module_dir,
        get_flags: api_get_flags,
    })
}

#[cfg(target_os = "android")]
#[repr(C)]
struct AndroidDlextInfo {
    flags: u64,
    reserved_addr: *mut c_void,
    reserved_size: libc::size_t,
    relro_fd: c_int,
    library_fd: c_int,
    library_fd_offset: i64,
    library_namespace: *mut c_void,
}

#[cfg(target_os = "android")]
const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;

#[cfg(target_os = "android")]
extern "C" {
    fn android_dlopen_ext(
        filename: *const c_char,
        flags: c_int,
        extinfo: *const AndroidDlextInfo,
    ) -> *mut c_void;
}

/// Loads a Zygisk module shared object from disk via a private `memfd_create` buffer so:
///   1. Zygote only needs read-only (`r_file_perms`) on `/data/misc/yasvara_root/...`
///      (zero AOSP `data_file_type:file execute` neverallow exemptions needed).
///   2. On Android, `android_dlopen_ext(ANDROID_DLEXT_USE_LIBRARY_FD)` maps the `zygote_tmpfs`
///      memfd directly using stock AOSP `allow zygote zygote_tmpfs:file { read write getattr map execute }`.
///   3. No `/data/misc/yasvara_root/modules/...` file path leaks into `/proc/self/maps`.
unsafe fn dlopen_from_readonly_file(lib_path: &str) -> *mut c_void {
    let Ok(bytes) = std::fs::read(lib_path) else {
        return std::ptr::null_mut();
    };
    let name = CString::new("jit-cache").unwrap();
    let mfd = libc::syscall(libc::SYS_memfd_create, name.as_ptr(), libc::MFD_CLOEXEC) as RawFd;
    if mfd >= 0 {
        let mut off = 0usize;
        let mut ok = true;
        while off < bytes.len() {
            let n = libc::write(mfd, bytes[off..].as_ptr() as *const c_void, bytes.len() - off);
            if n <= 0 {
                ok = false;
                break;
            }
            off += n as usize;
        }
        if ok {
            let _ = libc::lseek(mfd, 0, libc::SEEK_SET);
            #[cfg(target_os = "android")]
            let handle = {
                let ext = AndroidDlextInfo {
                    flags: ANDROID_DLEXT_USE_LIBRARY_FD,
                    reserved_addr: std::ptr::null_mut(),
                    reserved_size: 0,
                    relro_fd: -1,
                    library_fd: mfd,
                    library_fd_offset: 0,
                    library_namespace: std::ptr::null_mut(),
                };
                android_dlopen_ext(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL, &ext)
            };
            #[cfg(not(target_os = "android"))]
            let handle = {
                let fd_path = CString::new(format!("/proc/self/fd/{mfd}")).unwrap();
                libc::dlopen(fd_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL)
            };
            libc::close(mfd);
            if !handle.is_null() {
                return handle;
            }
        } else {
            libc::close(mfd);
        }
    }
    // Fallback to direct path if memfd_create is unavailable.
    let Ok(c_lib) = CString::new(lib_path) else {
        return std::ptr::null_mut();
    };
    libc::dlopen(c_lib.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL)
}

/// Phase 1 entrypoint called by `Zygote.cpp` `SpecializeCommon` before UID/SELinux drop.
/// Returns `ZYGISK_OUT_*` flags (e.g., `ZYGISK_OUT_FORCE_UNMOUNT`).
#[no_mangle]
pub unsafe extern "C" fn yasvara_zygisk_pre(
    env: JniEnvPtr,
    uid: u32,
    is_system_server: bool,
    is_enrolled_root: bool,
    is_on_denylist: bool,
    args_ptr: *mut c_void,
    zygisk_set_bytes: *const u8,
    zygisk_set_len: usize,
) -> u32 {
    if env.is_null() || args_ptr.is_null() || zygisk_set_bytes.is_null() || zygisk_set_len == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(zygisk_set_bytes, zygisk_set_len);
    let Ok(set) = ZygiskSet::decode(slice) else { return 0 };
    if !set.enabled || set.safe_bypass {
        return 0;
    }

    let is_64bit = cfg!(target_pointer_width = "64");
    let app_id = uid % 100_000;
    let mut state_flags = 0u32;
    if is_enrolled_root {
        state_flags |= STATE_FLAG_PROCESS_GRANTED_ROOT;
    }
    if is_on_denylist {
        state_flags |= STATE_FLAG_PROCESS_ON_DENYLIST;
    }

    let mut out_flags = 0u32;
    let Ok(mut loaded) = LOADED_MODULES.lock() else { return 0 };
    loaded.clear();

    for entry in &set.modules {
        let lib_path = if is_64bit { &entry.lib64_path } else { &entry.lib32_path };
        if lib_path.is_empty() {
            continue;
        }
        // Scope check: skip modules not targeting this process.
        if !is_system_server && entry.scope_mode != SCOPE_ALL_NON_DENYLIST {
            if entry.scope_uids.binary_search(&uid).is_err()
                && entry.scope_uids.binary_search(&app_id).is_err()
            {
                continue;
            }
        }
        if is_system_server
            && entry.scope_mode != SCOPE_ALL_NON_DENYLIST
            && entry.scope_uids.binary_search(&1000).is_err()
        {
            continue;
        }

        let Ok(c_dir) = CString::new(entry.mod_dir.as_str()) else { continue };
        let mod_dir_fd = libc::open(c_dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC);
        let handle = dlopen_from_readonly_file(lib_path.as_str());
        if handle.is_null() {
            if mod_dir_fd >= 0 {
                libc::close(mod_dir_fd);
            }
            continue;
        }
        let entry_sym = CString::new("zygisk_module_entry").unwrap();
        let raw_entry = libc::dlsym(handle, entry_sym.as_ptr());
        if raw_entry.is_null() {
            libc::dlclose(handle);
            if mod_dir_fd >= 0 {
                libc::close(mod_dir_fd);
            }
            continue;
        }

        let mut boxed = Box::new(LoadedModule {
            id: entry.id.clone(),
            dl_handle: handle as usize,
            mod_dir_fd,
            state_flags,
            dlclose_requested: false,
            force_unmount: false,
            abi: None,
            api_table: make_api_table(std::ptr::null_mut()),
        });
        let self_ptr = boxed.as_mut() as *mut LoadedModule as *mut c_void;
        boxed.api_table.impl_ptr = self_ptr;

        let entry_fn: ZygiskModuleEntryFn = std::mem::transmute(raw_entry);
        let table_ptr = boxed.api_table.as_mut() as *mut ApiTable;
        entry_fn(table_ptr, env);

        if let Some(ref abi) = boxed.abi {
            if is_system_server {
                if let Some(pre) = abi.pre_server_specialize {
                    pre(abi.impl_ptr, args_ptr as *mut ServerSpecializeArgs);
                }
            } else if let Some(pre) = abi.pre_app_specialize {
                pre(abi.impl_ptr, args_ptr as *mut AppSpecializeArgs);
            }
        }
        if boxed.force_unmount {
            out_flags |= ZYGISK_OUT_FORCE_UNMOUNT;
        }
        loaded.push(boxed);
    }
    out_flags
}

/// Phase 2 entrypoint called by `Zygote.cpp` `SpecializeCommon` after `gCallPostForkChildHooks`.
/// Runs `postAppSpecialize` / `postServerSpecialize` and unloads any module requesting
/// `DLCLOSE_MODULE_LIBRARY`.
#[no_mangle]
pub unsafe extern "C" fn yasvara_zygisk_post(
    _env: JniEnvPtr,
    is_system_server: bool,
    args_ptr: *const c_void,
) {
    let Ok(mut loaded) = LOADED_MODULES.lock() else { return };
    for m in loaded.iter_mut() {
        if let Some(ref abi) = m.abi {
            if is_system_server {
                if let Some(post) = abi.post_server_specialize {
                    post(abi.impl_ptr, args_ptr as *const ServerSpecializeArgs);
                }
            } else if let Some(post) = abi.post_app_specialize {
                post(abi.impl_ptr, args_ptr as *const AppSpecializeArgs);
            }
        }
        if m.mod_dir_fd >= 0 {
            libc::close(m.mod_dir_fd);
            m.mod_dir_fd = -1;
        }
    }
    // Unload modules that requested DLCLOSE_MODULE_LIBRARY (Bionic's atexit.cpp automatically
    // recompacts extracted slots so zero hole runs remain in "atexit handlers").
    loaded.retain(|m| {
        if m.dlclose_requested && m.dl_handle != 0 {
            libc::dlclose(m.dl_handle as *mut c_void);
            false
        } else {
            true
        }
    });
}
