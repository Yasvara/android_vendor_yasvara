// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Short-lived dynamic helper spawned on demand by `yasvara_rootd` when a Zygisk module
//! invokes `api->connectCompanion()`. Loads the module `.so`, runs `zygisk_companion_entry(fd)`,
//! closes the socket, and exits immediately (zero persistent `zygiskd`).

use std::ffi::{c_int, CString};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        std::process::exit(2);
    }
    let Ok(lib_c) = CString::new(args[1].as_str()) else { std::process::exit(2) };
    let Ok(fd) = args[2].parse::<c_int>() else { std::process::exit(2) };

    unsafe {
        let handle = libc::dlopen(lib_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if !handle.is_null() {
            let sym = CString::new("zygisk_companion_entry").unwrap();
            let fptr = libc::dlsym(handle, sym.as_ptr());
            if !fptr.is_null() {
                type CompanionFn = unsafe extern "C" fn(c_int);
                let entry: CompanionFn = std::mem::transmute(fptr);
                entry(fd);
            }
            libc::dlclose(handle);
        }
        libc::close(fd);
    }
}
