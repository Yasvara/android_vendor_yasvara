// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Binary-compatible Zygisk C-ABI definitions (API v1..v5).
//!
//! Field ordering and types match the public Zygisk v4/v5 header ABI so standard
//! precompiled Zygisk modules (`arm64-v8a.so` / `armeabi-v7a.so`) load unmodified.

use std::ffi::{c_char, c_int, c_long, c_void};

pub const ZYGISK_API_VERSION_4: c_long = 4;
pub const ZYGISK_API_VERSION_5: c_long = 5;

pub const STATE_FLAG_PROCESS_GRANTED_ROOT: u32 = 1 << 0;
pub const STATE_FLAG_PROCESS_ON_DENYLIST: u32 = 1 << 1;

pub const OPTION_FORCE_DENYLIST_UNMOUNT: c_int = 0;
pub const OPTION_DLCLOSE_MODULE_LIBRARY: c_int = 1;

/// Return flags from `yasvara_zygisk_pre` back to `Zygote.cpp`.
pub const ZYGISK_OUT_FORCE_UNMOUNT: u32 = 1 << 0;

pub type JniEnvPtr = *mut c_void;
pub type JObject = *mut c_void;
pub type JString = JObject;
pub type JIntArray = JObject;
pub type JObjectArray = JObject;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct JniNativeMethod {
    pub name: *const c_char,
    pub signature: *const c_char,
    pub fn_ptr: *mut c_void,
}

/// Exact Zygisk API v5 `AppSpecializeArgs` layout (prefix-compatible with v1..v4).
#[repr(C)]
pub struct AppSpecializeArgs {
    // v1
    pub uid: *mut i32,
    pub gid: *mut i32,
    pub gids: *mut JIntArray,
    pub runtime_flags: *mut i32,
    pub rlimits: *mut JObjectArray,
    pub mount_external: *mut i32,
    pub se_info: *mut JString,
    pub nice_name: *mut JString,
    pub instruction_set: *mut JString,
    pub app_data_dir: *mut JString,
    // v2
    pub fds_to_ignore: *mut JIntArray,
    // v3
    pub is_child_zygote: *mut u8,
    pub is_top_app: *mut u8,
    pub pkg_data_info_list: *mut JObjectArray,
    pub whitelisted_data_info_list: *mut JObjectArray,
    pub mount_data_dirs: *mut u8,
    pub mount_storage_dirs: *mut u8,
    // v5
    pub mount_sysprop_overrides: *mut u8,
}

/// Exact Zygisk API v1..v5 `ServerSpecializeArgs` layout.
#[repr(C)]
pub struct ServerSpecializeArgs {
    pub uid: *mut i32,
    pub gid: *mut i32,
    pub gids: *mut JIntArray,
    pub runtime_flags: *mut i32,
    pub permitted_capabilities: *mut i64,
    pub effective_capabilities: *mut i64,
}

/// Module callback table passed to `ApiTable::register_module`.
#[repr(C)]
pub struct ModuleAbi {
    pub api_version: c_long,
    pub impl_ptr: *mut c_void,
    pub pre_app_specialize: Option<unsafe extern "C" fn(*mut c_void, *mut AppSpecializeArgs)>,
    pub post_app_specialize: Option<unsafe extern "C" fn(*mut c_void, *const AppSpecializeArgs)>,
    pub pre_server_specialize: Option<unsafe extern "C" fn(*mut c_void, *mut ServerSpecializeArgs)>,
    pub post_server_specialize: Option<unsafe extern "C" fn(*mut c_void, *const ServerSpecializeArgs)>,
}

/// Exact Zygisk API v4/v5 `api_table` passed to `zygisk_module_entry(api_table*, JNIEnv*)`.
#[repr(C)]
pub struct ApiTable {
    pub impl_ptr: *mut c_void,
    pub register_module: unsafe extern "C" fn(*mut ApiTable, *mut ModuleAbi) -> bool,
    pub hook_jni_native_methods:
        unsafe extern "C" fn(JniEnvPtr, *const c_char, *mut JniNativeMethod, c_int),
    pub plt_hook_register:
        unsafe extern "C" fn(libc::dev_t, libc::ino_t, *const c_char, *mut c_void, *mut *mut c_void),
    pub exempt_fd: unsafe extern "C" fn(c_int) -> bool,
    pub plt_hook_commit: unsafe extern "C" fn() -> bool,
    pub connect_companion: unsafe extern "C" fn(*mut c_void) -> c_int,
    pub set_option: unsafe extern "C" fn(*mut c_void, c_int),
    pub get_module_dir: unsafe extern "C" fn(*mut c_void) -> c_int,
    pub get_flags: unsafe extern "C" fn(*mut c_void) -> u32,
}

pub type ZygiskModuleEntryFn = unsafe extern "C" fn(*mut ApiTable, JniEnvPtr);

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn api_table_has_exact_v4_v5_slot_order() {
        let ptr = size_of::<*mut c_void>();
        assert_eq!(offset_of!(ApiTable, impl_ptr), 0);
        assert_eq!(offset_of!(ApiTable, register_module), ptr);
        assert_eq!(offset_of!(ApiTable, hook_jni_native_methods), 2 * ptr);
        assert_eq!(offset_of!(ApiTable, plt_hook_register), 3 * ptr);
        assert_eq!(offset_of!(ApiTable, exempt_fd), 4 * ptr);
        assert_eq!(offset_of!(ApiTable, plt_hook_commit), 5 * ptr);
        assert_eq!(offset_of!(ApiTable, connect_companion), 6 * ptr);
        assert_eq!(offset_of!(ApiTable, set_option), 7 * ptr);
        assert_eq!(offset_of!(ApiTable, get_module_dir), 8 * ptr);
        assert_eq!(offset_of!(ApiTable, get_flags), 9 * ptr);
    }

    #[test]
    fn module_abi_slot_order() {
        let ptr = size_of::<*mut c_void>();
        assert_eq!(offset_of!(ModuleAbi, api_version), 0);
        assert_eq!(offset_of!(ModuleAbi, impl_ptr), ptr);
        assert_eq!(offset_of!(ModuleAbi, pre_app_specialize), 2 * ptr);
        assert_eq!(offset_of!(ModuleAbi, post_app_specialize), 3 * ptr);
        assert_eq!(offset_of!(ModuleAbi, pre_server_specialize), 4 * ptr);
        assert_eq!(offset_of!(ModuleAbi, post_server_specialize), 5 * ptr);
    }
}
