// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! `libyasvara_kait.so` — In-tree Rust native core for Yasvara Kait.
//!
//! Exports a single C symbol (`yasvara_kait_attach`) invoked by Zygote's `SpecializeCommon`
//! only for processes flagged with `Zygote.YASVARA_KAIT`.

use kait_dex::{HookDexSpec, build_dummy_resources_dex, build_hook_dex, classname_to_descriptor};
use kait_hook::{HookRegistry, HookSnapshotData, validate_shorty_len, widens};
use jni_sys::*;
use parking_lot::Mutex;
use smallvec::SmallVec;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const LOG_TAG: &[u8] = b"YasvaraKait\0";
const FRAMEWORK_JAR: &[u8] = b"/system_ext/framework/yasvara-kait.jar\0";
const ENTRY_CLASS: &str = "org.yasvara.kait.core.Main";
const HOOK_BRIDGE_CLASS: &str = "org.yasvara.kait.nativebridge.HookBridge";
const RESOURCES_HOOK_CLASS: &str = "org.yasvara.kait.nativebridge.ResourcesHook";
const NATIVE_API_CLASS: &str = "org.yasvara.kait.nativebridge.NativeAPI";
const HOOK_SNAPSHOT_CLASS: &str = "org.yasvara.kait.impl.hooks.HookSnapshot";
const HOOK_RECORD_CLASS: &str = "org.yasvara.kait.impl.hooks.KaitHookRecord";
const XRESOURCES_CLASS: &str = "android.content.res.XResources";

const KAIT_OPS_MAGIC: jint = 0x594B_4149; // 'YKAI'
const KAIT_OPS_ABI_VERSION: u32 = 1;

#[allow(dead_code)]
const ANDROID_LOG_DEBUG: c_int = 3;
const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_WARN: c_int = 5;
const ANDROID_LOG_ERROR: c_int = 6;

extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

fn log_msg(prio: c_int, msg: &str) {
    if let Ok(c) = CString::new(msg) {
        unsafe {
            __android_log_write(prio, LOG_TAG.as_ptr() as *const c_char, c.as_ptr());
        }
    }
}

macro_rules! log_i { ($($t:tt)*) => { log_msg(ANDROID_LOG_INFO, &format!($($t)*)) }; }
macro_rules! log_w { ($($t:tt)*) => { log_msg(ANDROID_LOG_WARN, &format!($($t)*)) }; }
macro_rules! log_e { ($($t:tt)*) => { log_msg(ANDROID_LOG_ERROR, &format!($($t)*)) }; }
#[allow(unused_macros)]
macro_rules! log_d { ($($t:tt)*) => { log_msg(ANDROID_LOG_DEBUG, &format!($($t)*)) }; }

// --- ROM-Native ART Seam C-ABI (`art/runtime/yasvara_kait.h`) ---

#[repr(C)]
struct KaitArtOps {
    version: u32,
    reserved: u32,
    hook_method: unsafe extern "C" fn(*mut JNIEnv, jobject, jobject, jobject) -> jboolean,
    unhook_method: unsafe extern "C" fn(*mut JNIEnv, jobject, jobject) -> jboolean,
    deoptimize_method: unsafe extern "C" fn(*mut JNIEnv, jobject) -> jboolean,
    make_dex_trusted: unsafe extern "C" fn(*mut JNIEnv, jobject) -> jboolean,
    make_class_inheritable: unsafe extern "C" fn(*mut JNIEnv, jclass) -> jboolean,
    clear_field_final: unsafe extern "C" fn(*mut JNIEnv, jobject) -> jboolean,
    find_static_initializer: unsafe extern "C" fn(*mut JNIEnv, jclass) -> jobject,
    get_method_shorty: unsafe extern "C" fn(*mut JNIEnv, jobject, *mut c_char, usize) -> usize,
    get_art_method_ptr: unsafe extern "C" fn(*mut JNIEnv, jobject) -> usize,
    is_proxy_method: unsafe extern "C" fn(*mut JNIEnv, jobject) -> jboolean,
}

struct SendPtr<T>(*mut T);
impl<T> Clone for SendPtr<T> {
    fn clone(&self) -> Self { *self }
}
impl<T> Copy for SendPtr<T> {}
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

struct SendConstPtr<T>(*const T);
impl<T> Clone for SendConstPtr<T> {
    fn clone(&self) -> Self { *self }
}
impl<T> Copy for SendConstPtr<T> {}
unsafe impl<T> Send for SendConstPtr<T> {}
unsafe impl<T> Sync for SendConstPtr<T> {}

// Wrapper around a JNI GlobalRef stored inside HookRegistry.
#[derive(Clone, Copy, PartialEq, Eq)]
struct GlobalObj(usize);
impl GlobalObj {
    fn from_raw(obj: jobject) -> Self {
        Self(obj as usize)
    }
    fn as_raw(self) -> jobject {
        self.0 as jobject
    }
}

struct CachedJni {
    framework_cl: SendPtr<_jobject>,
    cls_object: SendPtr<_jobject>,
    cls_object_array: SendPtr<_jobject>,
    cls_dex_file: SendPtr<_jobject>,
    cls_byte_buffer: SendPtr<_jobject>,
    cls_path_cl: SendPtr<_jobject>,
    cls_in_mem_cl: SendPtr<_jobject>,
    cls_ite: SendPtr<_jobject>,
    cls_hook_snapshot: SendPtr<_jobject>,
    cls_hook_record: SendPtr<_jobject>,
    mid_cl_load_class: SendPtr<_jmethodID>,
    mid_method_invoke: SendPtr<_jmethodID>,
    mid_exec_get_name: SendPtr<_jmethodID>,
    mid_exec_set_accessible: SendPtr<_jmethodID>,
    mid_class_get_name: SendPtr<_jmethodID>,
    mid_class_get_type_name: SendPtr<_jmethodID>,
    mid_class_get_cl: SendPtr<_jmethodID>,
    mid_class_is_interface: SendPtr<_jmethodID>,
    mid_class_is_array: SendPtr<_jmethodID>,
    mid_class_is_primitive: SendPtr<_jmethodID>,
    mid_class_get_modifiers: SendPtr<_jmethodID>,
    mid_dex_file_init: SendPtr<_jmethodID>,
    mid_dex_file_load_class: SendPtr<_jmethodID>,
    mid_path_cl_init: SendPtr<_jmethodID>,
    mid_in_mem_cl_init: SendPtr<_jmethodID>,
    mid_ite_init: SendPtr<_jmethodID>,
    mid_snapshot_init: SendPtr<_jmethodID>,
    wrappers: [PrimitiveWrapper; 8],
}

#[derive(Clone, Copy)]
struct PrimitiveWrapper {
    shorty: char,
    clazz: SendPtr<_jobject>,
    unbox: SendPtr<_jmethodID>,
    box_mid: SendPtr<_jmethodID>,
}

struct XmlApi {
    next: unsafe extern "C" fn(*mut c_void) -> i32,
    restart: unsafe extern "C" fn(*mut c_void),
    cur_ext: unsafe extern "C" fn(*mut c_void) -> *const c_void,
    attr_name_id: unsafe extern "C" fn(*mut c_void, usize) -> i32,
    attr_name_res_id: unsafe extern "C" fn(*mut c_void, usize) -> u32,
    mutable_attr_slot: unsafe extern "C" fn(*mut c_void, i32) -> *mut u32,
    attr_name_utf16: unsafe extern "C" fn(*mut c_void, i32, *mut usize) -> *const u16,
    cls_xresources: SendPtr<_jobject>,
    mid_translate_res_id: SendPtr<_jmethodID>,
    mid_translate_attr_id: SendPtr<_jmethodID>,
}

static ATTACHED: AtomicBool = AtomicBool::new(false);
static ART_OPS: OnceLock<SendConstPtr<KaitArtOps>> = OnceLock::new();
static CACHED_JNI: OnceLock<CachedJni> = OnceLock::new();
static XML_API: OnceLock<XmlApi> = OnceLock::new();
static HOOK_REGISTRY: OnceLock<HookRegistry<GlobalObj, GlobalObj, GlobalObj>> = OnceLock::new();
static DEX_COUNTER: AtomicU64 = AtomicU64::new(0);
static PINNED_DEXES: OnceLock<Mutex<Vec<Box<[u8]>>>> = OnceLock::new();

fn art_ops() -> Option<&'static KaitArtOps> {
    ART_OPS.get().map(|p| unsafe { &*p.0 })
}

fn jni_cache() -> &'static CachedJni {
    CACHED_JNI.get().expect("Kait JNI cache not initialized")
}

fn registry() -> &'static HookRegistry<GlobalObj, GlobalObj, GlobalObj> {
    HOOK_REGISTRY.get_or_init(HookRegistry::new)
}

fn pin_dex_buffer(bytes: Vec<u8>) -> (*mut c_void, jlong) {
    let boxed = bytes.into_boxed_slice();
    let ptr = boxed.as_ptr() as *mut c_void;
    let len = boxed.len() as jlong;
    PINNED_DEXES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .push(boxed);
    (ptr, len)
}

// --- Tiny Safe JNI Helpers ---

#[inline]
unsafe fn jni_fn(env: *mut JNIEnv) -> &'static JNINativeInterface_ {
    unsafe { &**env }
}

unsafe fn clear_exception(env: *mut JNIEnv) -> bool {
    let f = unsafe { jni_fn(env) };
    if unsafe { (f.ExceptionCheck.unwrap())(env) } != 0 {
        unsafe { (f.ExceptionClear.unwrap())(env) };
        true
    } else {
        false
    }
}

unsafe fn find_global_class(env: *mut JNIEnv, name: &[u8]) -> Option<jclass> {
    let f = unsafe { jni_fn(env) };
    let local = unsafe { (f.FindClass.unwrap())(env, name.as_ptr() as *const c_char) };
    if local.is_null() || unsafe { clear_exception(env) } {
        return None;
    }
    let global = unsafe { (f.NewGlobalRef.unwrap())(env, local) } as jclass;
    unsafe { (f.DeleteLocalRef.unwrap())(env, local) };
    if global.is_null() { None } else { Some(global) }
}

unsafe fn get_mid(env: *mut JNIEnv, cls: jclass, name: &[u8], sig: &[u8]) -> Option<jmethodID> {
    let f = unsafe { jni_fn(env) };
    let mid = unsafe {
        (f.GetMethodID.unwrap())(
            env,
            cls,
            name.as_ptr() as *const c_char,
            sig.as_ptr() as *const c_char,
        )
    };
    if mid.is_null() || unsafe { clear_exception(env) } {
        None
    } else {
        Some(mid)
    }
}

unsafe fn get_static_mid(
    env: *mut JNIEnv,
    cls: jclass,
    name: &[u8],
    sig: &[u8],
) -> Option<jmethodID> {
    let f = unsafe { jni_fn(env) };
    let mid = unsafe {
        (f.GetStaticMethodID.unwrap())(
            env,
            cls,
            name.as_ptr() as *const c_char,
            sig.as_ptr() as *const c_char,
        )
    };
    if mid.is_null() || unsafe { clear_exception(env) } {
        None
    } else {
        Some(mid)
    }
}

unsafe fn get_fid(env: *mut JNIEnv, cls: jclass, name: &[u8], sig: &[u8]) -> Option<jfieldID> {
    let f = unsafe { jni_fn(env) };
    let fid = unsafe {
        (f.GetFieldID.unwrap())(
            env,
            cls,
            name.as_ptr() as *const c_char,
            sig.as_ptr() as *const c_char,
        )
    };
    if fid.is_null() || unsafe { clear_exception(env) } {
        None
    } else {
        Some(fid)
    }
}

unsafe fn jstring_to_string(env: *mut JNIEnv, s: jstring) -> Option<String> {
    if s.is_null() {
        return None;
    }
    let f = unsafe { jni_fn(env) };
    let chars = unsafe { (f.GetStringUTFChars.unwrap())(env, s, ptr::null_mut()) };
    if chars.is_null() {
        unsafe { clear_exception(env) };
        return None;
    }
    let out = unsafe { CStr::from_ptr(chars) }.to_string_lossy().into_owned();
    unsafe { (f.ReleaseStringUTFChars.unwrap())(env, s, chars) };
    Some(out)
}

unsafe fn throw_new(env: *mut JNIEnv, class_name: &[u8], msg: &str) {
    let f = unsafe { jni_fn(env) };
    let cls = unsafe { (f.FindClass.unwrap())(env, class_name.as_ptr() as *const c_char) };
    if !cls.is_null() {
        if let Ok(cmsg) = CString::new(msg) {
            unsafe { (f.ThrowNew.unwrap())(env, cls, cmsg.as_ptr()) };
        }
        unsafe { (f.DeleteLocalRef.unwrap())(env, cls) };
    }
}

unsafe fn load_class_from_loader(env: *mut JNIEnv, loader: jobject, dotted_name: &str) -> jclass {
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    let Ok(cname) = CString::new(dotted_name) else {
        return ptr::null_mut();
    };
    let jname = unsafe { (f.NewStringUTF.unwrap())(env, cname.as_ptr()) };
    if jname.is_null() {
        unsafe { clear_exception(env) };
        return ptr::null_mut();
    }
    let arg = jvalue { l: jname };
    let cls = unsafe {
        (f.CallObjectMethodA.unwrap())(env, loader, cache.mid_cl_load_class.0, &arg)
    } as jclass;
    unsafe { (f.DeleteLocalRef.unwrap())(env, jname) };
    if cls.is_null() || unsafe { clear_exception(env) } {
        return ptr::null_mut();
    }
    cls
}

// --- Initialization & Framework Boot ---

unsafe fn init_cached_jni(env: *mut JNIEnv, framework_cl_global: jobject) -> Option<()> {
    let f = unsafe { jni_fn(env) };
    let cls_object = unsafe { find_global_class(env, b"java/lang/Object\0") }?;
    let dummy_arr = unsafe { (f.NewObjectArray.unwrap())(env, 0, cls_object, ptr::null_mut()) };
    if dummy_arr.is_null() {
        return None;
    }
    let arr_cls_local = unsafe { (f.GetObjectClass.unwrap())(env, dummy_arr) };
    let cls_object_array = unsafe { (f.NewGlobalRef.unwrap())(env, arr_cls_local) } as jclass;
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, arr_cls_local);
        (f.DeleteLocalRef.unwrap())(env, dummy_arr);
    }

    let cls_class = unsafe { find_global_class(env, b"java/lang/Class\0") }?;
    let cls_cl = unsafe { find_global_class(env, b"java/lang/ClassLoader\0") }?;
    let cls_method = unsafe { find_global_class(env, b"java/lang/reflect/Method\0") }?;
    let cls_exec = unsafe { find_global_class(env, b"java/lang/reflect/Executable\0") }?;
    let cls_acc = unsafe { find_global_class(env, b"java/lang/reflect/AccessibleObject\0") }?;
    let cls_dex_file = unsafe { find_global_class(env, b"dalvik/system/DexFile\0") }?;
    let cls_byte_buffer = unsafe { find_global_class(env, b"java/nio/ByteBuffer\0") }?;
    let cls_path_cl = unsafe { find_global_class(env, b"dalvik/system/PathClassLoader\0") }?;
    let cls_in_mem_cl =
        unsafe { find_global_class(env, b"dalvik/system/InMemoryDexClassLoader\0") }?;
    let cls_ite =
        unsafe { find_global_class(env, b"java/lang/reflect/InvocationTargetException\0") }?;

    let mid_cl_load_class = unsafe {
        get_mid(
            env,
            cls_cl,
            b"loadClass\0",
            b"(Ljava/lang/String;)Ljava/lang/Class;\0",
        )
    }?;
    unsafe { (f.DeleteGlobalRef.unwrap())(env, cls_cl) };

    let mid_method_invoke = unsafe {
        get_mid(
            env,
            cls_method,
            b"invoke\0",
            b"(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;\0",
        )
    }?;
    let mid_exec_get_name = unsafe { get_mid(env, cls_exec, b"getName\0", b"()Ljava/lang/String;\0") }?;
    let mid_exec_set_accessible = unsafe { get_mid(env, cls_acc, b"setAccessible\0", b"(Z)V\0") }?;
    unsafe {
        (f.DeleteGlobalRef.unwrap())(env, cls_method);
        (f.DeleteGlobalRef.unwrap())(env, cls_exec);
        (f.DeleteGlobalRef.unwrap())(env, cls_acc);
    }

    let mid_class_get_name =
        unsafe { get_mid(env, cls_class, b"getName\0", b"()Ljava/lang/String;\0") }?;
    let mid_class_get_type_name =
        unsafe { get_mid(env, cls_class, b"getTypeName\0", b"()Ljava/lang/String;\0") }?;
    let mid_class_get_cl =
        unsafe { get_mid(env, cls_class, b"getClassLoader\0", b"()Ljava/lang/ClassLoader;\0") }?;
    let mid_class_is_interface = unsafe { get_mid(env, cls_class, b"isInterface\0", b"()Z\0") }?;
    let mid_class_is_array = unsafe { get_mid(env, cls_class, b"isArray\0", b"()Z\0") }?;
    let mid_class_is_primitive = unsafe { get_mid(env, cls_class, b"isPrimitive\0", b"()Z\0") }?;
    let mid_class_get_modifiers = unsafe { get_mid(env, cls_class, b"getModifiers\0", b"()I\0") }?;
    unsafe { (f.DeleteGlobalRef.unwrap())(env, cls_class) };

    let mid_dex_file_init = unsafe {
        get_mid(
            env,
            cls_dex_file,
            b"<init>\0",
            b"([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;[Ldalvik/system/DexPathList$Element;)V\0",
        )
    }?;
    let mid_dex_file_load_class = unsafe {
        get_mid(
            env,
            cls_dex_file,
            b"loadClass\0",
            b"(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Class;\0",
        )
    }?;
    let mid_path_cl_init = unsafe {
        get_mid(
            env,
            cls_path_cl,
            b"<init>\0",
            b"(Ljava/lang/String;Ljava/lang/ClassLoader;)V\0",
        )
    }?;
    let mid_in_mem_cl_init = unsafe {
        get_mid(
            env,
            cls_in_mem_cl,
            b"<init>\0",
            b"(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V\0",
        )
    }?;
    let mid_ite_init =
        unsafe { get_mid(env, cls_ite, b"<init>\0", b"(Ljava/lang/Throwable;)V\0") }?;

    // Load Kait's own HookSnapshot & KaitHookRecord classes from framework_cl.
    let load_fw_global = |name: &str| -> Option<jclass> {
        let cname = CString::new(name).ok()?;
        let jname = unsafe { (f.NewStringUTF.unwrap())(env, cname.as_ptr()) };
        let arg = jvalue { l: jname };
        let local = unsafe {
            (f.CallObjectMethodA.unwrap())(env, framework_cl_global, mid_cl_load_class, &arg)
        } as jclass;
        unsafe { (f.DeleteLocalRef.unwrap())(env, jname) };
        if local.is_null() || unsafe { clear_exception(env) } {
            return None;
        }
        let g = unsafe { (f.NewGlobalRef.unwrap())(env, local) } as jclass;
        unsafe { (f.DeleteLocalRef.unwrap())(env, local) };
        if g.is_null() { None } else { Some(g) }
    };

    let cls_hook_snapshot = load_fw_global(HOOK_SNAPSHOT_CLASS)?;
    let cls_hook_record = load_fw_global(HOOK_RECORD_CLASS)?;
    let mid_snapshot_init = unsafe {
        get_mid(
            env,
            cls_hook_snapshot,
            b"<init>\0",
            b"([Lorg/yasvara/kait/impl/hooks/KaitHookRecord;[Ljava/lang/Object;)V\0",
        )
    }?;

    // Primitive wrapper table ordered by frequency.
    const SPECS: [(char, &[u8], &[u8], &[u8], &[u8]); 8] = [
        ('I', b"java/lang/Integer\0", b"intValue\0", b"()I\0", b"(I)Ljava/lang/Integer;\0"),
        ('Z', b"java/lang/Boolean\0", b"booleanValue\0", b"()Z\0", b"(Z)Ljava/lang/Boolean;\0"),
        ('J', b"java/lang/Long\0", b"longValue\0", b"()J\0", b"(J)Ljava/lang/Long;\0"),
        ('D', b"java/lang/Double\0", b"doubleValue\0", b"()D\0", b"(D)Ljava/lang/Double;\0"),
        ('F', b"java/lang/Float\0", b"floatValue\0", b"()F\0", b"(F)Ljava/lang/Float;\0"),
        ('C', b"java/lang/Character\0", b"charValue\0", b"()C\0", b"(C)Ljava/lang/Character;\0"),
        ('B', b"java/lang/Byte\0", b"byteValue\0", b"()B\0", b"(B)Ljava/lang/Byte;\0"),
        ('S', b"java/lang/Short\0", b"shortValue\0", b"()S\0", b"(S)Ljava/lang/Short;\0"),
    ];
    let mut wrappers = [PrimitiveWrapper {
        shorty: 'I',
        clazz: SendPtr(ptr::null_mut()),
        unbox: SendPtr(ptr::null_mut()),
        box_mid: SendPtr(ptr::null_mut()),
    }; 8];
    for (i, &(sh, cname, acc, acc_sig, box_sig)) in SPECS.iter().enumerate() {
        let wc = unsafe { find_global_class(env, cname) }?;
        let unbox = unsafe { get_mid(env, wc, acc, acc_sig) }?;
        let box_mid = unsafe { get_static_mid(env, wc, b"valueOf\0", box_sig) }?;
        wrappers[i] = PrimitiveWrapper {
            shorty: sh,
            clazz: SendPtr(wc),
            unbox: SendPtr(unbox),
            box_mid: SendPtr(box_mid),
        };
    }

    let _ = CACHED_JNI.set(CachedJni {
        framework_cl: SendPtr(framework_cl_global),
        cls_object: SendPtr(cls_object),
        cls_object_array: SendPtr(cls_object_array),
        cls_dex_file: SendPtr(cls_dex_file),
        cls_byte_buffer: SendPtr(cls_byte_buffer),
        cls_path_cl: SendPtr(cls_path_cl),
        cls_in_mem_cl: SendPtr(cls_in_mem_cl),
        cls_ite: SendPtr(cls_ite),
        cls_hook_snapshot: SendPtr(cls_hook_snapshot),
        cls_hook_record: SendPtr(cls_hook_record),
        mid_cl_load_class: SendPtr(mid_cl_load_class),
        mid_method_invoke: SendPtr(mid_method_invoke),
        mid_exec_get_name: SendPtr(mid_exec_get_name),
        mid_exec_set_accessible: SendPtr(mid_exec_set_accessible),
        mid_class_get_name: SendPtr(mid_class_get_name),
        mid_class_get_type_name: SendPtr(mid_class_get_type_name),
        mid_class_get_cl: SendPtr(mid_class_get_cl),
        mid_class_is_interface: SendPtr(mid_class_is_interface),
        mid_class_is_array: SendPtr(mid_class_is_array),
        mid_class_is_primitive: SendPtr(mid_class_is_primitive),
        mid_class_get_modifiers: SendPtr(mid_class_get_modifiers),
        mid_dex_file_init: SendPtr(mid_dex_file_init),
        mid_dex_file_load_class: SendPtr(mid_dex_file_load_class),
        mid_path_cl_init: SendPtr(mid_path_cl_init),
        mid_in_mem_cl_init: SendPtr(mid_in_mem_cl_init),
        mid_ite_init: SendPtr(mid_ite_init),
        mid_snapshot_init: SendPtr(mid_snapshot_init),
        wrappers,
    });
    Some(())
}

unsafe fn elevate_framework_dex_trust(env: *mut JNIEnv, loader: jobject, ops: &KaitArtOps) {
    let f = unsafe { jni_fn(env) };
    let cl_cls = unsafe { (f.GetObjectClass.unwrap())(env, loader) };
    let Some(fid_path_list) =
        (unsafe { get_fid(env, cl_cls, b"pathList\0", b"Ldalvik/system/DexPathList;\0") })
    else {
        unsafe { (f.DeleteLocalRef.unwrap())(env, cl_cls) };
        return;
    };
    let path_list = unsafe { (f.GetObjectField.unwrap())(env, loader, fid_path_list) };
    unsafe { (f.DeleteLocalRef.unwrap())(env, cl_cls) };
    if path_list.is_null() {
        return;
    }
    let pl_cls = unsafe { (f.GetObjectClass.unwrap())(env, path_list) };
    let Some(fid_elems) = (unsafe {
        get_fid(
            env,
            pl_cls,
            b"dexElements\0",
            b"[Ldalvik/system/DexPathList$Element;\0",
        )
    }) else {
        unsafe {
            (f.DeleteLocalRef.unwrap())(env, pl_cls);
            (f.DeleteLocalRef.unwrap())(env, path_list);
        }
        return;
    };
    let elems = unsafe { (f.GetObjectField.unwrap())(env, path_list, fid_elems) } as jobjectArray;
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, pl_cls);
        (f.DeleteLocalRef.unwrap())(env, path_list);
    }
    if elems.is_null() {
        return;
    }
    let len = unsafe { (f.GetArrayLength.unwrap())(env, elems) };
    for i in 0..len {
        let elem = unsafe { (f.GetObjectArrayElement.unwrap())(env, elems, i) };
        if elem.is_null() {
            continue;
        }
        let e_cls = unsafe { (f.GetObjectClass.unwrap())(env, elem) };
        if let Some(fid_dex) =
            unsafe { get_fid(env, e_cls, b"dexFile\0", b"Ldalvik/system/DexFile;\0") }
        {
            let dex_obj = unsafe { (f.GetObjectField.unwrap())(env, elem, fid_dex) };
            if !dex_obj.is_null() {
                let d_cls = unsafe { (f.GetObjectClass.unwrap())(env, dex_obj) };
                if let Some(fid_cookie) =
                    unsafe { get_fid(env, d_cls, b"mCookie\0", b"Ljava/lang/Object;\0") }
                {
                    let cookie = unsafe { (f.GetObjectField.unwrap())(env, dex_obj, fid_cookie) };
                    if !cookie.is_null() {
                        unsafe { (ops.make_dex_trusted)(env, cookie) };
                        unsafe { (f.DeleteLocalRef.unwrap())(env, cookie) };
                    }
                }
                unsafe {
                    (f.DeleteLocalRef.unwrap())(env, d_cls);
                    (f.DeleteLocalRef.unwrap())(env, dex_obj);
                }
            }
        }
        unsafe {
            (f.DeleteLocalRef.unwrap())(env, e_cls);
            (f.DeleteLocalRef.unwrap())(env, elem);
        }
    }
    unsafe { (f.DeleteLocalRef.unwrap())(env, elems) };
}

/// Publishes a new immutable `HookSnapshot` onto `KaitNativeHooker.snapshot` (`@Volatile`).
unsafe fn publish_snapshot(
    env: *mut JNIEnv,
    hooker_obj: jobject,
    snap: &HookSnapshotData<GlobalObj>,
) {
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    let modern_arr = unsafe {
        (f.NewObjectArray.unwrap())(
            env,
            snap.modern.len() as jsize,
            cache.cls_hook_record.0,
            ptr::null_mut(),
        )
    };
    let legacy_arr = unsafe {
        (f.NewObjectArray.unwrap())(
            env,
            snap.legacy.len() as jsize,
            cache.cls_object.0,
            ptr::null_mut(),
        )
    };
    if modern_arr.is_null() || legacy_arr.is_null() {
        unsafe {
            clear_exception(env);
            if !modern_arr.is_null() {
                (f.DeleteLocalRef.unwrap())(env, modern_arr);
            }
            if !legacy_arr.is_null() {
                (f.DeleteLocalRef.unwrap())(env, legacy_arr);
            }
        }
        return;
    }
    for (i, &cb) in snap.modern.iter().enumerate() {
        unsafe { (f.SetObjectArrayElement.unwrap())(env, modern_arr, i as jsize, cb.as_raw()) };
    }
    for (i, &cb) in snap.legacy.iter().enumerate() {
        unsafe { (f.SetObjectArrayElement.unwrap())(env, legacy_arr, i as jsize, cb.as_raw()) };
    }
    let ctor_args = [jvalue { l: modern_arr }, jvalue { l: legacy_arr }];
    let snapshot_obj = unsafe {
        (f.NewObjectA.unwrap())(
            env,
            cache.cls_hook_snapshot.0,
            cache.mid_snapshot_init.0,
            ctor_args.as_ptr(),
        )
    };
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, modern_arr);
        (f.DeleteLocalRef.unwrap())(env, legacy_arr);
    }
    if snapshot_obj.is_null() || unsafe { clear_exception(env) } {
        return;
    }
    let h_cls = unsafe { (f.GetObjectClass.unwrap())(env, hooker_obj) };
    if let Some(fid) = unsafe {
        get_fid(
            env,
            h_cls,
            b"snapshot\0",
            b"Lorg/yasvara/kait/impl/hooks/HookSnapshot;\0",
        )
    } {
        unsafe { (f.SetObjectField.unwrap())(env, hooker_obj, fid, snapshot_obj) };
    }
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, h_cls);
        (f.DeleteLocalRef.unwrap())(env, snapshot_obj);
    }
}

// --- Native Hook Installation (Kait DEX + ROM-Native ART Seam) ---

unsafe fn install_art_hook(
    env: *mut JNIEnv,
    target_method: jobject,
    hooker_class: jclass,
) -> Option<(GlobalObj, GlobalObj)> {
    let ops = art_ops()?;
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();

    // 1. Query method shorty & modifiers directly from ART (handles Proxy methods cleanly).
    let mut shorty_buf = [0 as c_char; 300];
    let shorty_len =
        unsafe { (ops.get_method_shorty)(env, target_method, shorty_buf.as_mut_ptr(), shorty_buf.len()) };
    if shorty_len == 0 {
        log_e!("install_art_hook: failed to obtain method shorty");
        return None;
    }
    let shorty = unsafe { CStr::from_ptr(shorty_buf.as_ptr()) }.to_str().ok()?;

    // Read modifiers via Java Executable.getModifiers() to know static & constructor status cleanly.
    let target_cls = unsafe { (f.GetObjectClass.unwrap())(env, target_method) };
    let mid_get_mod = unsafe { get_mid(env, target_cls, b"getModifiers\0", b"()I\0") }?;
    let mods = unsafe { (f.CallIntMethodA.unwrap())(env, target_method, mid_get_mod, ptr::null()) };
    unsafe { (f.DeleteLocalRef.unwrap())(env, target_cls) };
    if unsafe { clear_exception(env) } {
        return None;
    }
    const ACC_STATIC: jint = 0x0008;
    let is_static = (mods & ACC_STATIC) != 0;

    let j_target_name = unsafe {
        (f.CallObjectMethodA.unwrap())(env, target_method, cache.mid_exec_get_name.0, ptr::null())
    } as jstring;
    let mut target_name = unsafe { jstring_to_string(env, j_target_name) }.unwrap_or_else(|| "m".into());
    if !j_target_name.is_null() {
        unsafe { (f.DeleteLocalRef.unwrap())(env, j_target_name) };
    }
    if target_name.contains('.') || target_name.contains('<') || target_name.contains('>') {
        target_name = "constructor".to_owned();
    } else if target_name == "backup" {
        target_name = "hook_backup".to_owned();
    }

    let j_hooker_name = unsafe {
        (f.CallObjectMethodA.unwrap())(env, hooker_class, cache.mid_class_get_name.0, ptr::null())
    } as jstring;
    let hooker_name = unsafe { jstring_to_string(env, j_hooker_name) }?;
    unsafe { (f.DeleteLocalRef.unwrap())(env, j_hooker_name) };

    let hooker_cl = unsafe {
        (f.CallObjectMethodA.unwrap())(env, hooker_class, cache.mid_class_get_cl.0, ptr::null())
    };
    if hooker_cl.is_null() || unsafe { clear_exception(env) } {
        return None;
    }

    // 2. Emit minimal verified DEX trampoline in pure Rust.
    let gen_id = DEX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let gen_class_name = format!("Kait_{gen_id}");
    let gen_class_desc = format!("L{gen_class_name};");
    let hooker_desc = classname_to_descriptor(&hooker_name);

    let dex_img = match build_hook_dex(&HookDexSpec {
        class_descriptor: &gen_class_desc,
        source_file: "Kait",
        hooker_field_name: "h",
        hooker_class_descriptor: &hooker_desc,
        callback_name: "callback",
        hook_method_name: &target_name,
        backup_method_name: "backup",
        shorty,
        is_static,
    }) {
        Ok(img) => img,
        Err(e) => {
            log_e!("build_hook_dex failed for {target_name} ({shorty}): {e:?}");
            unsafe { (f.DeleteLocalRef.unwrap())(env, hooker_cl) };
            return None;
        }
    };

    // Pin DEX memory and open via dalvik.system.DexFile(ByteBuffer[], null, null).
    let (dex_ptr, dex_len) = pin_dex_buffer(dex_img.bytes);
    let direct_buf = unsafe { (f.NewDirectByteBuffer.unwrap())(env, dex_ptr, dex_len) };
    let buf_arr = unsafe { (f.NewObjectArray.unwrap())(env, 1, cache.cls_byte_buffer.0, direct_buf) };
    let dex_args = [
        jvalue { l: buf_arr },
        jvalue { l: ptr::null_mut() },
        jvalue { l: ptr::null_mut() },
    ];
    let java_dex = unsafe {
        (f.NewObjectA.unwrap())(
            env,
            cache.cls_dex_file.0,
            cache.mid_dex_file_init.0,
            dex_args.as_ptr(),
        )
    };
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, buf_arr);
        (f.DeleteLocalRef.unwrap())(env, direct_buf);
    }
    if java_dex.is_null() || unsafe { clear_exception(env) } {
        unsafe { (f.DeleteLocalRef.unwrap())(env, hooker_cl) };
        log_e!("install_art_hook: failed to construct DexFile for {gen_class_name}");
        return None;
    }

    // Create child PathClassLoader(".", hooker_cl) and load the generated class.
    let dot = unsafe { (f.NewStringUTF.unwrap())(env, b".\0".as_ptr() as *const c_char) };
    let pcl_args = [jvalue { l: dot }, jvalue { l: hooker_cl }];
    let child_cl = unsafe {
        (f.NewObjectA.unwrap())(
            env,
            cache.cls_path_cl.0,
            cache.mid_path_cl_init.0,
            pcl_args.as_ptr(),
        )
    };
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, dot);
        (f.DeleteLocalRef.unwrap())(env, hooker_cl);
    }
    if child_cl.is_null() || unsafe { clear_exception(env) } {
        unsafe { (f.DeleteLocalRef.unwrap())(env, java_dex) };
        return None;
    }

    let c_gen_name = CString::new(gen_class_name.as_str()).ok()?;
    let j_gen_name = unsafe { (f.NewStringUTF.unwrap())(env, c_gen_name.as_ptr()) };
    let load_args = [jvalue { l: j_gen_name }, jvalue { l: child_cl }];
    let built_cls = unsafe {
        (f.CallObjectMethodA.unwrap())(
            env,
            java_dex,
            cache.mid_dex_file_load_class.0,
            load_args.as_ptr(),
        )
    } as jclass;
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, j_gen_name);
        (f.DeleteLocalRef.unwrap())(env, child_cl);
        (f.DeleteLocalRef.unwrap())(env, java_dex);
    }
    if built_cls.is_null() || unsafe { clear_exception(env) } {
        log_e!("install_art_hook: failed to load {gen_class_name}");
        return None;
    }

    // Resolve generated static field `h` and static methods `<target_name>` & `backup`.
    let c_hooker_desc = CString::new(hooker_desc).ok()?;
    let c_hook_name = CString::new(target_name.as_str()).ok()?;
    let c_sig = CString::new(dex_img.hook_signature.as_str()).ok()?;

    let hooker_fid = unsafe {
        (f.GetStaticFieldID.unwrap())(
            env,
            built_cls,
            b"h\0".as_ptr() as *const c_char,
            c_hooker_desc.as_ptr(),
        )
    };
    let hook_mid = unsafe {
        (f.GetStaticMethodID.unwrap())(env, built_cls, c_hook_name.as_ptr(), c_sig.as_ptr())
    };
    let backup_mid = unsafe {
        (f.GetStaticMethodID.unwrap())(
            env,
            built_cls,
            b"backup\0".as_ptr() as *const c_char,
            c_sig.as_ptr(),
        )
    };
    if hooker_fid.is_null()
        || hook_mid.is_null()
        || backup_mid.is_null()
        || unsafe { clear_exception(env) }
    {
        unsafe { (f.DeleteLocalRef.unwrap())(env, built_cls) };
        log_e!("install_art_hook: failed to resolve generated members");
        return None;
    }

    // Instantiate `KaitNativeHooker(target_method)` and store it into static field `h`.
    let hooker_ctor = unsafe {
        get_mid(
            env,
            hooker_class,
            b"<init>\0",
            b"(Ljava/lang/reflect/Executable;)V\0",
        )
    }?;
    let init_arg = jvalue { l: target_method };
    let hooker_obj = unsafe { (f.NewObjectA.unwrap())(env, hooker_class, hooker_ctor, &init_arg) };
    if hooker_obj.is_null() || unsafe { clear_exception(env) } {
        unsafe { (f.DeleteLocalRef.unwrap())(env, built_cls) };
        return None;
    }
    unsafe { (f.SetStaticObjectField.unwrap())(env, built_cls, hooker_fid, hooker_obj) };

    let reflected_hook = unsafe { (f.ToReflectedMethod.unwrap())(env, built_cls, hook_mid, 1) };
    let reflected_backup = unsafe { (f.ToReflectedMethod.unwrap())(env, built_cls, backup_mid, 1) };
    unsafe { (f.DeleteLocalRef.unwrap())(env, built_cls) };
    if reflected_hook.is_null() || reflected_backup.is_null() || unsafe { clear_exception(env) } {
        unsafe {
            if !reflected_hook.is_null() {
                (f.DeleteLocalRef.unwrap())(env, reflected_hook);
            }
            if !reflected_backup.is_null() {
                (f.DeleteLocalRef.unwrap())(env, reflected_backup);
            }
            (f.DeleteLocalRef.unwrap())(env, hooker_obj);
        }
        return None;
    }

    // Mark backup accessible and wire it directly onto `KaitNativeHooker.backup` for zero-JNI dispatch.
    let acc_arg = jvalue { z: JNI_TRUE };
    unsafe {
        (f.CallVoidMethodA.unwrap())(
            env,
            reflected_backup,
            cache.mid_exec_set_accessible.0,
            &acc_arg,
        );
        clear_exception(env);
    }

    // Install the ROM-native ART hook (zero Dobby, zero memfd, selective JIT caller deopt).
    let ok = unsafe { (ops.hook_method)(env, target_method, reflected_hook, reflected_backup) };
    unsafe { (f.DeleteLocalRef.unwrap())(env, reflected_hook) };
    if ok != JNI_TRUE {
        unsafe {
            (f.DeleteLocalRef.unwrap())(env, reflected_backup);
            (f.DeleteLocalRef.unwrap())(env, hooker_obj);
        }
        return None;
    }

    // Store backup Method directly onto KaitNativeHooker.backup (avoids JNI round-trip on hot path).
    if let Some(fid_backup) =
        unsafe { get_fid(env, hooker_class, b"backup\0", b"Ljava/lang/reflect/Method;\0") }
    {
        unsafe { (f.SetObjectField.unwrap())(env, hooker_obj, fid_backup, reflected_backup) };
    }

    let global_backup = unsafe { (f.NewGlobalRef.unwrap())(env, reflected_backup) };
    let global_hooker = unsafe { (f.NewGlobalRef.unwrap())(env, hooker_obj) };
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, reflected_backup);
        (f.DeleteLocalRef.unwrap())(env, hooker_obj);
    }
    if global_backup.is_null() || global_hooker.is_null() {
        return None;
    }
    Some((
        GlobalObj::from_raw(global_backup),
        GlobalObj::from_raw(global_hooker),
    ))
}

// --- HookBridge JNI Methods ---

unsafe extern "C" fn jni_hook_method(
    env: *mut JNIEnv,
    _cls: jclass,
    use_modern_api: jboolean,
    hook_method: jobject,
    hooker: jclass,
    priority: jint,
    callback: jobject,
) -> jboolean {
    let Some(ops) = art_ops() else { return JNI_FALSE };
    if hook_method.is_null() || hooker.is_null() || callback.is_null() {
        return JNI_FALSE;
    }
    let key = unsafe { (ops.get_art_method_ptr)(env, hook_method) };
    if key == 0 {
        return JNI_FALSE;
    }
    let f = unsafe { jni_fn(env) };
    let cb_global = unsafe { (f.NewGlobalRef.unwrap())(env, callback) };
    if cb_global.is_null() {
        return JNI_FALSE;
    }
    let Some((hooker_ref, snap)) = registry().add_callback(
        key,
        use_modern_api != 0,
        priority,
        GlobalObj::from_raw(cb_global),
        || unsafe { install_art_hook(env, hook_method, hooker) },
    ) else {
        unsafe { (f.DeleteGlobalRef.unwrap())(env, cb_global) };
        return JNI_FALSE;
    };
    unsafe { publish_snapshot(env, hooker_ref.as_raw(), &snap) };
    JNI_TRUE
}

unsafe extern "C" fn jni_unhook_method(
    env: *mut JNIEnv,
    _cls: jclass,
    use_modern_api: jboolean,
    hook_method: jobject,
    callback: jobject,
) -> jboolean {
    let Some(ops) = art_ops() else { return JNI_FALSE };
    if hook_method.is_null() || callback.is_null() {
        return JNI_FALSE;
    }
    let key = unsafe { (ops.get_art_method_ptr)(env, hook_method) };
    if key == 0 {
        return JNI_FALSE;
    }
    let f = unsafe { jni_fn(env) };
    let Some((removed, hooker_ref, snap)) =
        registry().remove_callback(key, use_modern_api != 0, |stored| {
            unsafe { (f.IsSameObject.unwrap())(env, stored.as_raw(), callback) == JNI_TRUE }
        })
    else {
        return JNI_FALSE;
    };
    unsafe {
        publish_snapshot(env, hooker_ref.as_raw(), &snap);
        (f.DeleteGlobalRef.unwrap())(env, removed.as_raw());
    }
    JNI_TRUE
}

unsafe extern "C" fn jni_replace_callback(
    env: *mut JNIEnv,
    _cls: jclass,
    use_modern_api: jboolean,
    hook_method: jobject,
    old_callback: jobject,
    new_callback: jobject,
    new_priority: jint,
) -> jboolean {
    let Some(ops) = art_ops() else { return JNI_FALSE };
    if hook_method.is_null() || old_callback.is_null() || new_callback.is_null() {
        return JNI_FALSE;
    }
    let key = unsafe { (ops.get_art_method_ptr)(env, hook_method) };
    if key == 0 {
        return JNI_FALSE;
    }
    let f = unsafe { jni_fn(env) };
    let new_global = unsafe { (f.NewGlobalRef.unwrap())(env, new_callback) };
    if new_global.is_null() {
        return JNI_FALSE;
    }
    let Some((old_global, hooker_ref, snap)) = registry().replace_callback(
        key,
        use_modern_api != 0,
        |stored| unsafe { (f.IsSameObject.unwrap())(env, stored.as_raw(), old_callback) == JNI_TRUE },
        GlobalObj::from_raw(new_global),
        new_priority,
    ) else {
        unsafe { (f.DeleteGlobalRef.unwrap())(env, new_global) };
        return JNI_FALSE;
    };
    unsafe {
        publish_snapshot(env, hooker_ref.as_raw(), &snap);
        (f.DeleteGlobalRef.unwrap())(env, old_global.as_raw());
    }
    JNI_TRUE
}

unsafe extern "C" fn jni_deoptimize_method(
    env: *mut JNIEnv,
    _cls: jclass,
    method: jobject,
) -> jboolean {
    match art_ops() {
        Some(ops) => unsafe { (ops.deoptimize_method)(env, method) },
        None => JNI_FALSE,
    }
}

unsafe extern "C" fn jni_invoke_original_method(
    env: *mut JNIEnv,
    _cls: jclass,
    hook_method: jobject,
    thiz: jobject,
    args: jobjectArray,
) -> jobject {
    let Some(ops) = art_ops() else { return ptr::null_mut() };
    let key = unsafe { (ops.get_art_method_ptr)(env, hook_method) };
    let method_to_invoke = registry()
        .backup_of(key)
        .map(|b| b.as_raw())
        .unwrap_or(hook_method);
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    let call_args = [jvalue { l: thiz }, jvalue { l: args }];
    unsafe {
        (f.CallObjectMethodA.unwrap())(
            env,
            method_to_invoke,
            cache.mid_method_invoke.0,
            call_args.as_ptr(),
        )
    }
}

unsafe extern "C" fn jni_allocate_object(env: *mut JNIEnv, _cls: jclass, target_cls: jclass) -> jobject {
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    const ACC_ABSTRACT: jint = 0x0400;
    let invalid = target_cls.is_null()
        || unsafe { (f.CallBooleanMethodA.unwrap())(env, target_cls, cache.mid_class_is_interface.0, ptr::null()) } == JNI_TRUE
        || unsafe { (f.CallBooleanMethodA.unwrap())(env, target_cls, cache.mid_class_is_array.0, ptr::null()) } == JNI_TRUE
        || unsafe { (f.CallBooleanMethodA.unwrap())(env, target_cls, cache.mid_class_is_primitive.0, ptr::null()) } == JNI_TRUE
        || (unsafe { (f.CallIntMethodA.unwrap())(env, target_cls, cache.mid_class_get_modifiers.0, ptr::null()) } & ACC_ABSTRACT) != 0;
    if invalid {
        unsafe {
            throw_new(
                env,
                b"java/lang/InstantiationException\0",
                "no instance of this class can be allocated",
            );
        }
        return ptr::null_mut();
    }
    unsafe { (f.AllocObject.unwrap())(env, target_cls) }
}

unsafe fn pretty_name(env: *mut JNIEnv, cls: jclass) -> String {
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    let jname = unsafe {
        (f.CallObjectMethodA.unwrap())(env, cls, cache.mid_class_get_type_name.0, ptr::null())
    } as jstring;
    if jname.is_null() {
        unsafe { clear_exception(env) };
        return "?".to_owned();
    }
    let s = unsafe { jstring_to_string(env, jname) }.unwrap_or_else(|| "?".to_owned());
    unsafe { (f.DeleteLocalRef.unwrap())(env, jname) };
    s
}

unsafe fn wrapper_of(env: *mut JNIEnv, val: jobject) -> Option<&'static PrimitiveWrapper> {
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    let vcls = unsafe { (f.GetObjectClass.unwrap())(env, val) };
    let mut found = None;
    for w in &cache.wrappers {
        if unsafe { (f.IsSameObject.unwrap())(env, vcls, w.clazz.0) == JNI_TRUE } {
            found = Some(w);
            break;
        }
    }
    unsafe { (f.DeleteLocalRef.unwrap())(env, vcls) };
    found
}

fn wrapper_for(shorty: char) -> Option<&'static PrimitiveWrapper> {
    jni_cache().wrappers.iter().find(|w| w.shorty == shorty)
}

unsafe fn unbox_widened(
    env: *mut JNIEnv,
    from: &PrimitiveWrapper,
    to: char,
    val: jobject,
) -> jvalue {
    let f = unsafe { jni_fn(env) };
    if from.shorty == 'Z' {
        return jvalue {
            z: unsafe { (f.CallBooleanMethodA.unwrap())(env, val, from.unbox.0, ptr::null()) },
        };
    }
    let mut integral: i64 = 0;
    let mut floating: f64 = 0.0;
    match from.shorty {
        'B' => integral = unsafe { (f.CallByteMethodA.unwrap())(env, val, from.unbox.0, ptr::null()) } as i64,
        'C' => integral = unsafe { (f.CallCharMethodA.unwrap())(env, val, from.unbox.0, ptr::null()) } as i64,
        'S' => integral = unsafe { (f.CallShortMethodA.unwrap())(env, val, from.unbox.0, ptr::null()) } as i64,
        'I' => integral = unsafe { (f.CallIntMethodA.unwrap())(env, val, from.unbox.0, ptr::null()) } as i64,
        'J' => integral = unsafe { (f.CallLongMethodA.unwrap())(env, val, from.unbox.0, ptr::null()) },
        'F' => floating = unsafe { (f.CallFloatMethodA.unwrap())(env, val, from.unbox.0, ptr::null()) } as f64,
        _ => floating = unsafe { (f.CallDoubleMethodA.unwrap())(env, val, from.unbox.0, ptr::null()) },
    }
    let is_fp = matches!(from.shorty, 'F' | 'D');
    match to {
        'B' => jvalue { b: integral as jbyte },
        'C' => jvalue { c: integral as jchar },
        'S' => jvalue { s: integral as jshort },
        'I' => jvalue { i: integral as jint },
        'J' => jvalue { j: integral as jlong },
        'F' => jvalue { f: if is_fp { floating as jfloat } else { integral as jfloat } },
        _ => jvalue { d: if is_fp { floating } else { integral as jdouble } },
    }
}

unsafe extern "C" fn jni_invoke_original(
    env: *mut JNIEnv,
    _cls: jclass,
    executable: jobject,
    shorty: jcharArray,
    parameter_types: jobjectArray,
    declaring_class: jclass,
    is_static: jboolean,
    non_virtual: jboolean,
    mut thiz: jobject,
    args: jobjectArray,
) -> jobject {
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    if let Some(ops) = art_ops() {
        let key = unsafe { (ops.get_art_method_ptr)(env, executable) };
        if let Some(backup) = registry().backup_of(key) {
            let call_args = [jvalue { l: thiz }, jvalue { l: args }];
            return unsafe {
                (f.CallObjectMethodA.unwrap())(
                    env,
                    backup.as_raw(),
                    cache.mid_method_invoke.0,
                    call_args.as_ptr(),
                )
            };
        }
    }

    if is_static != 0 {
        thiz = ptr::null_mut();
    } else if thiz.is_null() {
        unsafe { throw_new(env, b"java/lang/NullPointerException\0", "null receiver") };
        return ptr::null_mut();
    } else if unsafe { (f.IsInstanceOf.unwrap())(env, thiz, declaring_class) } != JNI_TRUE {
        let actual = unsafe { (f.GetObjectClass.unwrap())(env, thiz) };
        let msg = format!(
            "Expected receiver of type {}, but got {}",
            unsafe { pretty_name(env, declaring_class) },
            unsafe { pretty_name(env, actual) }
        );
        unsafe {
            (f.DeleteLocalRef.unwrap())(env, actual);
            throw_new(env, b"java/lang/IllegalArgumentException\0", &msg);
        }
        return ptr::null_mut();
    }

    let param_len = if parameter_types.is_null() {
        0usize
    } else {
        unsafe { (f.GetArrayLength.unwrap())(env, parameter_types) as usize }
    };
    let args_len = if args.is_null() {
        0usize
    } else {
        unsafe { (f.GetArrayLength.unwrap())(env, args) as usize }
    };
    if args_len != param_len {
        let msg = format!("Wrong number of arguments; expected {param_len}, got {args_len}");
        unsafe { throw_new(env, b"java/lang/IllegalArgumentException\0", &msg) };
        return ptr::null_mut();
    }
    let shorty_len = if shorty.is_null() {
        0usize
    } else {
        unsafe { (f.GetArrayLength.unwrap())(env, shorty) as usize }
    };
    if !validate_shorty_len(param_len, shorty_len) {
        unsafe {
            throw_new(
                env,
                b"java/lang/IllegalArgumentException\0",
                "parameter types and shorty do not describe the same executable",
            );
        }
        return ptr::null_mut();
    }

    let mut shorty_chars: SmallVec<[jchar; 16]> = SmallVec::from_elem(0, shorty_len);
    unsafe {
        (f.GetCharArrayRegion.unwrap())(env, shorty, 0, shorty_len as jsize, shorty_chars.as_mut_ptr());
    }
    if unsafe { (f.ExceptionCheck.unwrap())(env) } != 0 {
        return ptr::null_mut();
    }

    let mut jvals: SmallVec<[jvalue; 8]> = SmallVec::with_capacity(param_len);
    for i in 0..param_len {
        let elem = unsafe { (f.GetObjectArrayElement.unwrap())(env, args, i as jsize) };
        if unsafe { (f.ExceptionCheck.unwrap())(env) } != 0 {
            return ptr::null_mut();
        }
        let declared = char::from_u32(shorty_chars[i + 1] as u32).unwrap_or('?');
        if declared == 'L' {
            if !elem.is_null() {
                let param_cls =
                    unsafe { (f.GetObjectArrayElement.unwrap())(env, parameter_types, i as jsize) } as jclass;
                let ok = unsafe { (f.IsInstanceOf.unwrap())(env, elem, param_cls) == JNI_TRUE };
                unsafe { (f.DeleteLocalRef.unwrap())(env, param_cls) };
                if !ok {
                    unsafe {
                        (f.DeleteLocalRef.unwrap())(env, elem);
                        throw_new(env, b"java/lang/IllegalArgumentException\0", "argument type mismatch");
                    }
                    return ptr::null_mut();
                }
            }
            jvals.push(jvalue { l: elem });
            continue;
        }
        if elem.is_null() {
            unsafe {
                throw_new(env, b"java/lang/IllegalArgumentException\0", "null primitive argument");
            }
            return ptr::null_mut();
        }
        let Some(w) = (unsafe { wrapper_of(env, elem) }) else {
            unsafe {
                (f.DeleteLocalRef.unwrap())(env, elem);
                throw_new(env, b"java/lang/IllegalArgumentException\0", "argument type mismatch");
            }
            return ptr::null_mut();
        };
        if !widens(w.shorty, declared) {
            unsafe {
                (f.DeleteLocalRef.unwrap())(env, elem);
                throw_new(env, b"java/lang/IllegalArgumentException\0", "argument type mismatch");
            }
            return ptr::null_mut();
        }
        let v = unsafe { unbox_widened(env, w, declared, elem) };
        unsafe { (f.DeleteLocalRef.unwrap())(env, elem) };
        if unsafe { (f.ExceptionCheck.unwrap())(env) } != 0 {
            return ptr::null_mut();
        }
        jvals.push(v);
    }

    let target = unsafe { (f.FromReflectedMethod.unwrap())(env, executable) };
    let args_ptr = if jvals.is_empty() { ptr::null() } else { jvals.as_ptr() };
    let returns = char::from_u32(shorty_chars[0] as u32).unwrap_or('V');
    let mut ret_val = jvalue { j: 0 };

    macro_rules! dispatch {
        ($static_fn:ident, $nonvirt_fn:ident, $virt_fn:ident, $field:ident) => {{
            ret_val.$field = if is_static != 0 {
                unsafe { (f.$static_fn.unwrap())(env, declaring_class, target, args_ptr) }
            } else if non_virtual != 0 {
                unsafe { (f.$nonvirt_fn.unwrap())(env, thiz, declaring_class, target, args_ptr) }
            } else {
                unsafe { (f.$virt_fn.unwrap())(env, thiz, target, args_ptr) }
            };
        }};
    }

    match returns {
        'I' => dispatch!(CallStaticIntMethodA, CallNonvirtualIntMethodA, CallIntMethodA, i),
        'J' => dispatch!(CallStaticLongMethodA, CallNonvirtualLongMethodA, CallLongMethodA, j),
        'D' => dispatch!(CallStaticDoubleMethodA, CallNonvirtualDoubleMethodA, CallDoubleMethodA, d),
        'F' => dispatch!(CallStaticFloatMethodA, CallNonvirtualFloatMethodA, CallFloatMethodA, f),
        'S' => dispatch!(CallStaticShortMethodA, CallNonvirtualShortMethodA, CallShortMethodA, s),
        'B' => dispatch!(CallStaticByteMethodA, CallNonvirtualByteMethodA, CallByteMethodA, b),
        'C' => dispatch!(CallStaticCharMethodA, CallNonvirtualCharMethodA, CallCharMethodA, c),
        'Z' => dispatch!(CallStaticBooleanMethodA, CallNonvirtualBooleanMethodA, CallBooleanMethodA, z),
        'L' => dispatch!(CallStaticObjectMethodA, CallNonvirtualObjectMethodA, CallObjectMethodA, l),
        _ => {
            if is_static != 0 {
                unsafe { (f.CallStaticVoidMethodA.unwrap())(env, declaring_class, target, args_ptr) };
            } else if non_virtual != 0 {
                unsafe { (f.CallNonvirtualVoidMethodA.unwrap())(env, thiz, declaring_class, target, args_ptr) };
            } else {
                unsafe { (f.CallVoidMethodA.unwrap())(env, thiz, target, args_ptr) };
            }
        }
    }

    let thrown = unsafe { (f.ExceptionOccurred.unwrap())(env) };
    if !thrown.is_null() {
        unsafe { (f.ExceptionClear.unwrap())(env) };
        let ite_arg = jvalue { l: thrown };
        let ite = unsafe { (f.NewObjectA.unwrap())(env, cache.cls_ite.0, cache.mid_ite_init.0, &ite_arg) };
        unsafe { (f.DeleteLocalRef.unwrap())(env, thrown) };
        if !ite.is_null() {
            unsafe { (f.Throw.unwrap())(env, ite as jthrowable) };
        }
        return ptr::null_mut();
    }

    if returns == 'L' {
        return unsafe { ret_val.l };
    }
    if returns == 'V' {
        return ptr::null_mut();
    }
    if let Some(w) = wrapper_for(returns) {
        return unsafe { (f.CallStaticObjectMethodA.unwrap())(env, w.clazz.0, w.box_mid.0, &ret_val) };
    }
    ptr::null_mut()
}

unsafe extern "C" fn jni_instance_of(env: *mut JNIEnv, _cls: jclass, obj: jobject, expected: jclass) -> jboolean {
    let f = unsafe { jni_fn(env) };
    unsafe { (f.IsInstanceOf.unwrap())(env, obj, expected) }
}

unsafe extern "C" fn jni_set_trusted(env: *mut JNIEnv, _cls: jclass, cookie: jobject) -> jboolean {
    match art_ops() {
        Some(ops) => unsafe { (ops.make_dex_trusted)(env, cookie) },
        None => JNI_FALSE,
    }
}

unsafe extern "C" fn jni_make_field_writable(
    env: *mut JNIEnv,
    _cls: jclass,
    field: jobject,
    _modifiers: jint,
) -> jboolean {
    match art_ops() {
        Some(ops) => unsafe { (ops.clear_field_final)(env, field) },
        None => JNI_FALSE,
    }
}

unsafe extern "C" fn jni_callback_snapshot(
    env: *mut JNIEnv,
    _cls: jclass,
    callback_class: jclass,
    method: jobject,
) -> jobjectArray {
    let Some(ops) = art_ops() else { return ptr::null_mut() };
    let key = unsafe { (ops.get_art_method_ptr)(env, method) };
    let Some(snap) = registry().snapshot_of(key) else {
        return ptr::null_mut();
    };
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    let res = unsafe { (f.NewObjectArray.unwrap())(env, 2, cache.cls_object_array.0, ptr::null_mut()) };
    let modern = unsafe {
        (f.NewObjectArray.unwrap())(env, snap.modern.len() as jsize, callback_class, ptr::null_mut())
    };
    let legacy = unsafe {
        (f.NewObjectArray.unwrap())(env, snap.legacy.len() as jsize, cache.cls_object.0, ptr::null_mut())
    };
    if res.is_null() || modern.is_null() || legacy.is_null() {
        unsafe { clear_exception(env) };
        return ptr::null_mut();
    }
    for (i, &cb) in snap.modern.iter().enumerate() {
        unsafe { (f.SetObjectArrayElement.unwrap())(env, modern, i as jsize, cb.as_raw()) };
    }
    for (i, &cb) in snap.legacy.iter().enumerate() {
        unsafe { (f.SetObjectArrayElement.unwrap())(env, legacy, i as jsize, cb.as_raw()) };
    }
    unsafe {
        (f.SetObjectArrayElement.unwrap())(env, res, 0, modern);
        (f.SetObjectArrayElement.unwrap())(env, res, 1, legacy);
        (f.DeleteLocalRef.unwrap())(env, modern);
        (f.DeleteLocalRef.unwrap())(env, legacy);
    }
    res
}

unsafe extern "C" fn jni_find_static_initializer(
    env: *mut JNIEnv,
    _cls: jclass,
    target_class: jclass,
    _art_methods: jlongArray,
    _art_method_size: jlong,
) -> jobject {
    match art_ops() {
        Some(ops) => unsafe { (ops.find_static_initializer)(env, target_class) },
        None => ptr::null_mut(),
    }
}

unsafe extern "C" fn jni_legacy_api_prefixes(env: *mut JNIEnv, _cls: jclass) -> jobjectArray {
    let f = unsafe { jni_fn(env) };
    let Some(str_cls) = (unsafe { find_global_class(env, b"java/lang/String\0") }) else {
        return ptr::null_mut();
    };
    let val = unsafe { (f.NewStringUTF.unwrap())(env, b"de.robv.android.xposed.\0".as_ptr() as *const c_char) };
    let arr = unsafe { (f.NewObjectArray.unwrap())(env, 1, str_cls, val) };
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, val);
        (f.DeleteGlobalRef.unwrap())(env, str_cls);
    }
    arr
}

// --- ResourcesHook JNI Methods (Deterministic `androidfw` C-ABI) ---

#[repr(C)]
struct ResXmlAttrExt {
    ns: u32,
    name: u32,
    attribute_start: u16,
    attribute_size: u16,
    attribute_count: u16,
    id_index: u16,
    class_index: u16,
    style_index: u16,
}

#[repr(C)]
struct ResValue {
    size: u16,
    res0: u8,
    data_type: u8,
    data: u32,
}

#[repr(C)]
struct ResXmlAttribute {
    ns: u32,
    name: u32,
    raw_value: u32,
    typed_value: ResValue,
}

unsafe fn dlsym_default(sym: &[u8]) -> *mut c_void {
    unsafe { libc::dlsym(libc::RTLD_DEFAULT, sym.as_ptr() as *const c_char) }
}

unsafe extern "C" fn jni_init_xresources_native(env: *mut JNIEnv, _cls: jclass) -> jboolean {
    if XML_API.get().is_some() {
        return JNI_TRUE;
    }
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    let local_xres = unsafe { load_class_from_loader(env, cache.framework_cl.0, XRESOURCES_CLASS) };
    if local_xres.is_null() {
        log_e!("initXResourcesNative: XResources class not found");
        return JNI_FALSE;
    }
    let cls_xres = unsafe { (f.NewGlobalRef.unwrap())(env, local_xres) } as jclass;
    unsafe { (f.DeleteLocalRef.unwrap())(env, local_xres) };

    let Some(mid_res) = (unsafe {
        get_static_mid(
            env,
            cls_xres,
            b"translateResId\0",
            b"(ILandroid/content/res/XResources;Landroid/content/res/Resources;)I\0",
        )
    }) else {
        log_e!("initXResourcesNative: translateResId not found");
        return JNI_FALSE;
    };
    let Some(mid_attr) = (unsafe {
        get_static_mid(
            env,
            cls_xres,
            b"translateAttrId\0",
            b"(Ljava/lang/String;Landroid/content/res/XResources;)I\0",
        )
    }) else {
        log_e!("initXResourcesNative: translateAttrId not found");
        return JNI_FALSE;
    };

    let p_next = unsafe { dlsym_default(b"yasvara_kait_xml_next\0") };
    let p_restart = unsafe { dlsym_default(b"yasvara_kait_xml_restart\0") };
    let p_cur_ext = unsafe { dlsym_default(b"yasvara_kait_xml_cur_ext\0") };
    let p_attr_id = unsafe { dlsym_default(b"yasvara_kait_xml_attr_name_id\0") };
    let p_attr_res = unsafe { dlsym_default(b"yasvara_kait_xml_attr_name_res_id\0") };
    let p_slot = unsafe { dlsym_default(b"yasvara_kait_xml_mutable_attr_slot\0") };
    let p_utf16 = unsafe { dlsym_default(b"yasvara_kait_xml_attr_name_utf16\0") };
    if p_next.is_null()
        || p_restart.is_null()
        || p_cur_ext.is_null()
        || p_attr_id.is_null()
        || p_attr_res.is_null()
        || p_slot.is_null()
        || p_utf16.is_null()
    {
        log_e!("initXResourcesNative: androidfw Kait helpers unavailable");
        return JNI_FALSE;
    }

    let _ = XML_API.set(XmlApi {
        next: unsafe { std::mem::transmute(p_next) },
        restart: unsafe { std::mem::transmute(p_restart) },
        cur_ext: unsafe { std::mem::transmute(p_cur_ext) },
        attr_name_id: unsafe { std::mem::transmute(p_attr_id) },
        attr_name_res_id: unsafe { std::mem::transmute(p_attr_res) },
        mutable_attr_slot: unsafe { std::mem::transmute(p_slot) },
        attr_name_utf16: unsafe { std::mem::transmute(p_utf16) },
        cls_xresources: SendPtr(cls_xres),
        mid_translate_res_id: SendPtr(mid_res),
        mid_translate_attr_id: SendPtr(mid_attr),
    });
    JNI_TRUE
}

unsafe extern "C" fn jni_make_inheritable(env: *mut JNIEnv, _cls: jclass, target: jclass) -> jboolean {
    match art_ops() {
        Some(ops) => unsafe { (ops.make_class_inheritable)(env, target) },
        None => JNI_FALSE,
    }
}

unsafe extern "C" fn jni_build_dummy_class_loader(
    env: *mut JNIEnv,
    _cls: jclass,
    parent: jobject,
    res_super: jstring,
    ta_super: jstring,
) -> jobject {
    let Some(res_name) = (unsafe { jstring_to_string(env, res_super) }) else {
        return ptr::null_mut();
    };
    let Some(ta_name) = (unsafe { jstring_to_string(env, ta_super) }) else {
        return ptr::null_mut();
    };
    let Ok(dex_bytes) = build_dummy_resources_dex(&res_name, &ta_name) else {
        return ptr::null_mut();
    };
    let (ptr_buf, len) = pin_dex_buffer(dex_bytes);
    let f = unsafe { jni_fn(env) };
    let cache = jni_cache();
    let direct_buf = unsafe { (f.NewDirectByteBuffer.unwrap())(env, ptr_buf, len) };
    if direct_buf.is_null() {
        unsafe { clear_exception(env) };
        return ptr::null_mut();
    }
    let args = [jvalue { l: direct_buf }, jvalue { l: parent }];
    let loader = unsafe {
        (f.NewObjectA.unwrap())(env, cache.cls_in_mem_cl.0, cache.mid_in_mem_cl_init.0, args.as_ptr())
    };
    unsafe { (f.DeleteLocalRef.unwrap())(env, direct_buf) };
    if unsafe { clear_exception(env) } {
        return ptr::null_mut();
    }
    loader
}

unsafe extern "C" fn jni_rewrite_xml_references_native(
    env: *mut JNIEnv,
    _cls: jclass,
    parser_ptr: jlong,
    orig_res: jobject,
    rep_res: jobject,
) {
    if parser_ptr == 0 {
        return;
    }
    let Some(xml) = XML_API.get() else { return };
    let parser = parser_ptr as *mut c_void;
    let f = unsafe { jni_fn(env) };

    const START_TAG: i32 = 2;
    const END_DOCUMENT: i32 = 1;
    const BAD_DOCUMENT: i32 = -1;
    const TYPE_REFERENCE: u8 = 0x01;

    loop {
        let ev = unsafe { (xml.next)(parser) };
        if ev == END_DOCUMENT || ev == BAD_DOCUMENT {
            break;
        }
        if ev != START_TAG {
            continue;
        }
        let ext_ptr = unsafe { (xml.cur_ext)(parser) } as *const ResXmlAttrExt;
        if ext_ptr.is_null() {
            continue;
        }
        let ext = unsafe { &*ext_ptr };
        let attr_count = ext.attribute_count as usize;
        let attr_start = ext.attribute_start as usize;
        let attr_size = ext.attribute_size as usize;

        for idx in 0..attr_count {
            let attr = unsafe {
                &mut *((ext_ptr as *const u8).add(attr_start + attr_size * idx) as *mut ResXmlAttribute)
            };

            let name_id = unsafe { (xml.attr_name_id)(parser, idx) };
            let old_attr_res = unsafe { (xml.attr_name_res_id)(parser, idx) };
            if name_id >= 0 && old_attr_res >= 0x7f00_0000 {
                let slot = unsafe { (xml.mutable_attr_slot)(parser, name_id) };
                if !slot.is_null() {
                    let mut u16_len: usize = 0;
                    let u16_ptr = unsafe { (xml.attr_name_utf16)(parser, name_id, &mut u16_len) };
                    if !u16_ptr.is_null() && u16_len > 0 {
                        let jstr = unsafe { (f.NewString.unwrap())(env, u16_ptr, u16_len as jsize) };
                        if unsafe { (f.ExceptionCheck.unwrap())(env) } != 0 {
                            unsafe { (xml.restart)(parser) };
                            return;
                        }
                        let args = [jvalue { l: jstr }, jvalue { l: orig_res }];
                        let new_attr_id = unsafe {
                            (f.CallStaticIntMethodA.unwrap())(
                                env,
                                xml.cls_xresources.0,
                                xml.mid_translate_attr_id.0,
                                args.as_ptr(),
                            )
                        };
                        unsafe { (f.DeleteLocalRef.unwrap())(env, jstr) };
                        if unsafe { (f.ExceptionCheck.unwrap())(env) } != 0 {
                            unsafe { (xml.restart)(parser) };
                            return;
                        }
                        unsafe { *slot = new_attr_id as u32 };
                    }
                }
            }

            if attr.typed_value.data_type != TYPE_REFERENCE {
                continue;
            }
            let old_val = attr.typed_value.data;
            if old_val < 0x7f00_0000 {
                continue;
            }
            let args = [
                jvalue { i: old_val as jint },
                jvalue { l: orig_res },
                jvalue { l: rep_res },
            ];
            let new_val = unsafe {
                (f.CallStaticIntMethodA.unwrap())(
                    env,
                    xml.cls_xresources.0,
                    xml.mid_translate_res_id.0,
                    args.as_ptr(),
                )
            } as u32;
            if unsafe { (f.ExceptionCheck.unwrap())(env) } != 0 {
                unsafe { (xml.restart)(parser) };
                return;
            }
            if new_val != old_val {
                attr.typed_value.data = new_val;
            }
        }
    }
    unsafe { (xml.restart)(parser) };
}

// --- Native Module API (`native_init` / `__loader_android_dlopen_ext` + `__loader_dlopen`) ---

type HookFuncType = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> c_int;
type UnhookFuncType = unsafe extern "C" fn(*mut c_void) -> c_int;
type NativeOnModuleLoaded = unsafe extern "C" fn(*const c_char, *mut c_void);
type NativeInitFn = unsafe extern "C" fn(*const NativeApiEntries) -> Option<NativeOnModuleLoaded>;

#[repr(C)]
struct NativeApiEntries {
    version: u32,
    hook_func: HookFuncType,
    unhook_func: UnhookFuncType,
}

unsafe extern "C" fn kait_hook_func(
    target: *mut c_void,
    replace: *mut c_void,
    backup: *mut *mut c_void,
) -> c_int {
    unsafe { kait_inline::hook_inline(target, replace, backup) }
}

unsafe extern "C" fn kait_unhook_func(target: *mut c_void) -> c_int {
    unsafe { kait_inline::unhook_inline(target) }
}

struct NativeModState {
    libs: Vec<String>,
    callbacks: Vec<NativeOnModuleLoaded>,
    api_page: *const NativeApiEntries,
    installed: bool,
}
unsafe impl Send for NativeModState {}

static NATIVE_MODS: OnceLock<Mutex<NativeModState>> = OnceLock::new();
static ORIG_DLOPEN: OnceLock<usize> = OnceLock::new();
static ORIG_DLOPEN_EXT: OnceLock<usize> = OnceLock::new();

fn native_mods() -> &'static Mutex<NativeModState> {
    NATIVE_MODS.get_or_init(|| {
        Mutex::new(NativeModState {
            libs: Vec::new(),
            callbacks: Vec::new(),
            api_page: ptr::null(),
            installed: false,
        })
    })
}

fn on_library_opened(name: *const c_char, handle: *mut c_void) {
    if name.is_null() || handle.is_null() {
        return;
    }
    let Ok(lib_name) = unsafe { CStr::from_ptr(name) }.to_str() else {
        return;
    };
    let mut guard = native_mods().lock();
    let matched = guard.libs.iter().any(|suffix| lib_name.ends_with(suffix));
    if matched {
        let init_sym = unsafe { libc::dlsym(handle, b"native_init\0".as_ptr() as *const c_char) };
        if !init_sym.is_null() && !guard.api_page.is_null() {
            let init_fn: NativeInitFn = unsafe { std::mem::transmute(init_sym) };
            let api_page = guard.api_page;
            if let Some(cb) = unsafe { init_fn(api_page) } {
                guard.callbacks.push(cb);
            }
        }
    }
    let cbs = guard.callbacks.clone();
    drop(guard);
    for cb in cbs {
        unsafe { cb(name, handle) };
    }
}

unsafe extern "C" fn hooked_loader_dlopen(
    filename: *const c_char,
    flag: c_int,
    caller_addr: *const c_void,
) -> *mut c_void {
    type FnTy = unsafe extern "C" fn(*const c_char, c_int, *const c_void) -> *mut c_void;
    let orig: FnTy = unsafe { std::mem::transmute(*ORIG_DLOPEN.get().unwrap()) };
    let handle = unsafe { orig(filename, flag, caller_addr) };
    on_library_opened(filename, handle);
    handle
}

unsafe extern "C" fn hooked_loader_android_dlopen_ext(
    filename: *const c_char,
    flag: c_int,
    extinfo: *const c_void,
    caller_addr: *const c_void,
) -> *mut c_void {
    type FnTy =
        unsafe extern "C" fn(*const c_char, c_int, *const c_void, *const c_void) -> *mut c_void;
    let orig: FnTy = unsafe { std::mem::transmute(*ORIG_DLOPEN_EXT.get().unwrap()) };
    let handle = unsafe { orig(filename, flag, extinfo, caller_addr) };
    on_library_opened(filename, handle);
    handle
}

unsafe extern "C" fn jni_record_native_entrypoint(
    env: *mut JNIEnv,
    _cls: jclass,
    jlib: jstring,
) {
    let Some(lib_name) = (unsafe { jstring_to_string(env, jlib) }) else {
        return;
    };
    let mut guard = native_mods().lock();
    if !guard.installed {
        // Allocate read-only page for NativeApiEntries.
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let ps = if ps == 0 { 4096 } else { ps };
        let page = unsafe {
            libc::mmap(
                ptr::null_mut(),
                ps,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if page != libc::MAP_FAILED {
            unsafe {
                *(page as *mut NativeApiEntries) = NativeApiEntries {
                    version: 2,
                    hook_func: kait_hook_func,
                    unhook_func: kait_unhook_func,
                };
                libc::mprotect(page, ps, libc::PROT_READ);
            }
            guard.api_page = page as *const NativeApiEntries;
        }
        // Hook exported bionic loader entrypoints directly (zero .gnu_debugdata XZ needed!).
        let dlopen_sym = unsafe { dlsym_default(b"__loader_dlopen\0") };
        if !dlopen_sym.is_null() {
            let mut backup = ptr::null_mut();
            if unsafe {
                kait_inline::hook_inline(dlopen_sym, hooked_loader_dlopen as *mut c_void, &mut backup)
            } == 0
            {
                let _ = ORIG_DLOPEN.set(backup as usize);
            }
        }
        let ext_sym = unsafe { dlsym_default(b"__loader_android_dlopen_ext\0") };
        if !ext_sym.is_null() {
            let mut backup = ptr::null_mut();
            if unsafe {
                kait_inline::hook_inline(
                    ext_sym,
                    hooked_loader_android_dlopen_ext as *mut c_void,
                    &mut backup,
                )
            } == 0
            {
                let _ = ORIG_DLOPEN_EXT.set(backup as usize);
            }
        }
        guard.installed = true;
    }
    if !guard.libs.iter().any(|s| s == &lib_name) {
        guard.libs.push(lib_name);
    }
}

// --- JNI Registration ---

unsafe fn register_natives_on(
    env: *mut JNIEnv,
    loader: jobject,
    class_name: &str,
    methods: &[JNINativeMethod],
) -> bool {
    let f = unsafe { jni_fn(env) };
    let cls = unsafe { load_class_from_loader(env, loader, class_name) };
    if cls.is_null() {
        log_e!("register_natives: class not found: {class_name}");
        return false;
    }
    let rc = unsafe {
        (f.RegisterNatives.unwrap())(env, cls, methods.as_ptr(), methods.len() as jint)
    };
    unsafe { (f.DeleteLocalRef.unwrap())(env, cls) };
    if rc != 0 || unsafe { clear_exception(env) } {
        log_e!("register_natives failed for {class_name} (rc={rc})");
        return false;
    }
    true
}

macro_rules! jni_method {
    ($name:literal, $sig:literal, $func:ident) => {
        JNINativeMethod {
            name: concat!($name, "\0").as_ptr() as *mut c_char,
            signature: concat!($sig, "\0").as_ptr() as *mut c_char,
            fnPtr: $func as *mut c_void,
        }
    };
}

unsafe fn register_all_bridges(env: *mut JNIEnv, loader: jobject) -> bool {
    let hook_methods = [
        jni_method!(
            "hookMethod",
            "(ZLjava/lang/reflect/Executable;Ljava/lang/Class;ILjava/lang/Object;)Z",
            jni_hook_method
        ),
        jni_method!(
            "unhookMethod",
            "(ZLjava/lang/reflect/Executable;Ljava/lang/Object;)Z",
            jni_unhook_method
        ),
        jni_method!(
            "replaceCallback",
            "(ZLjava/lang/reflect/Executable;Ljava/lang/Object;Ljava/lang/Object;I)Z",
            jni_replace_callback
        ),
        jni_method!(
            "deoptimizeMethod",
            "(Ljava/lang/reflect/Executable;)Z",
            jni_deoptimize_method
        ),
        jni_method!(
            "invokeOriginalMethod",
            "(Ljava/lang/reflect/Executable;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
            jni_invoke_original_method
        ),
        jni_method!(
            "invokeOriginal",
            "(Ljava/lang/reflect/Executable;[C[Ljava/lang/Class;Ljava/lang/Class;ZZLjava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
            jni_invoke_original
        ),
        jni_method!(
            "allocateObject",
            "(Ljava/lang/Class;)Ljava/lang/Object;",
            jni_allocate_object
        ),
        jni_method!(
            "instanceOf",
            "(Ljava/lang/Object;Ljava/lang/Class;)Z",
            jni_instance_of
        ),
        jni_method!("setTrusted", "(Ljava/lang/Object;)Z", jni_set_trusted),
        jni_method!(
            "makeFieldWritable",
            "(Ljava/lang/reflect/Field;I)Z",
            jni_make_field_writable
        ),
        jni_method!(
            "callbackSnapshot",
            "(Ljava/lang/Class;Ljava/lang/reflect/Executable;)[[Ljava/lang/Object;",
            jni_callback_snapshot
        ),
        jni_method!(
            "findStaticInitializer",
            "(Ljava/lang/Class;[JJ)Ljava/lang/reflect/Executable;",
            jni_find_static_initializer
        ),
        jni_method!(
            "legacyApiPrefixes",
            "()[Ljava/lang/String;",
            jni_legacy_api_prefixes
        ),
    ];

    let res_methods = [
        jni_method!("initXResourcesNative", "()Z", jni_init_xresources_native),
        jni_method!("makeInheritable", "(Ljava/lang/Class;)Z", jni_make_inheritable),
        jni_method!(
            "buildDummyClassLoader",
            "(Ljava/lang/ClassLoader;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/ClassLoader;",
            jni_build_dummy_class_loader
        ),
        jni_method!(
            "rewriteXmlReferencesNative",
            "(JLjava/lang/Object;Landroid/content/res/Resources;)V",
            jni_rewrite_xml_references_native
        ),
    ];

    let native_api_methods = [jni_method!(
        "recordNativeEntrypoint",
        "(Ljava/lang/String;)V",
        jni_record_native_entrypoint
    )];

    unsafe {
        register_natives_on(env, loader, HOOK_BRIDGE_CLASS, &hook_methods)
            && register_natives_on(env, loader, RESOURCES_HOOK_CLASS, &res_methods)
            && register_natives_on(env, loader, NATIVE_API_CLASS, &native_api_methods)
    }
}

// --- Single Exported Entrypoint (Called by Zygote SpecializeCommon) ---

#[no_mangle]
pub unsafe extern "C" fn yasvara_kait_attach(
    env: *mut JNIEnv,
    nice_name: jstring,
    app_data_dir: jstring,
    is_system_server: jboolean,
) -> jboolean {
    if env.is_null() || ATTACHED.swap(true, Ordering::AcqRel) {
        return JNI_FALSE;
    }

    let f = unsafe { jni_fn(env) };

    // 1. Claim the one-shot ROM-native ART operations table via JavaVM::GetEnv.
    let mut vm: *mut JavaVM = ptr::null_mut();
    if unsafe { (f.GetJavaVM.unwrap())(env, &mut vm) } != JNI_OK || vm.is_null() {
        log_e!("GetJavaVM failed");
        return JNI_FALSE;
    }
    let mut raw_ops: *mut c_void = ptr::null_mut();
    let get_env_fn = unsafe { (**vm).GetEnv.unwrap() };
    if unsafe { get_env_fn(vm, &mut raw_ops, KAIT_OPS_MAGIC) } != JNI_OK || raw_ops.is_null() {
        log_e!("ROM ART KaitOps unavailable");
        return JNI_FALSE;
    }
    let ops = unsafe { &*(raw_ops as *const KaitArtOps) };
    if ops.version != KAIT_OPS_ABI_VERSION {
        log_e!("KaitOps ABI mismatch: got {}", ops.version);
        return JNI_FALSE;
    }
    let _ = ART_OPS.set(SendConstPtr(ops as *const KaitArtOps));

    // 2. Open /system_ext/framework/yasvara-kait.jar with DexClassLoader.
    let Some(cls_cl) = (unsafe { find_global_class(env, b"java/lang/ClassLoader\0") }) else {
        return JNI_FALSE;
    };
    let Some(mid_get_sys) = (unsafe {
        get_static_mid(
            env,
            cls_cl,
            b"getSystemClassLoader\0",
            b"()Ljava/lang/ClassLoader;\0",
        )
    }) else {
        unsafe { (f.DeleteGlobalRef.unwrap())(env, cls_cl) };
        return JNI_FALSE;
    };
    let parent_cl = unsafe { (f.CallStaticObjectMethodA.unwrap())(env, cls_cl, mid_get_sys, ptr::null()) };
    unsafe { (f.DeleteGlobalRef.unwrap())(env, cls_cl) };
    if parent_cl.is_null() || unsafe { clear_exception(env) } {
        log_e!("cannot obtain system ClassLoader");
        return JNI_FALSE;
    }

    let Some(cls_dcl) = (unsafe { find_global_class(env, b"dalvik/system/DexClassLoader\0") }) else {
        unsafe { (f.DeleteLocalRef.unwrap())(env, parent_cl) };
        return JNI_FALSE;
    };
    let Some(mid_dcl_init) = (unsafe {
        get_mid(
            env,
            cls_dcl,
            b"<init>\0",
            b"(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V\0",
        )
    }) else {
        unsafe {
            (f.DeleteGlobalRef.unwrap())(env, cls_dcl);
            (f.DeleteLocalRef.unwrap())(env, parent_cl);
        }
        return JNI_FALSE;
    };
    let jpath = unsafe { (f.NewStringUTF.unwrap())(env, FRAMEWORK_JAR.as_ptr() as *const c_char) };
    let dcl_args = [
        jvalue { l: jpath },
        jvalue { l: ptr::null_mut() },
        jvalue { l: ptr::null_mut() },
        jvalue { l: parent_cl },
    ];
    let loader = unsafe { (f.NewObjectA.unwrap())(env, cls_dcl, mid_dcl_init, dcl_args.as_ptr()) };
    unsafe {
        (f.DeleteLocalRef.unwrap())(env, jpath);
        (f.DeleteLocalRef.unwrap())(env, parent_cl);
        (f.DeleteGlobalRef.unwrap())(env, cls_dcl);
    }
    if loader.is_null() || unsafe { clear_exception(env) } {
        log_e!("cannot open /system_ext/framework/yasvara-kait.jar");
        return JNI_FALSE;
    }
    let global_loader = unsafe { (f.NewGlobalRef.unwrap())(env, loader) };
    unsafe { (f.DeleteLocalRef.unwrap())(env, loader) };
    if global_loader.is_null() {
        return JNI_FALSE;
    }

    // 3. Elevate DEX trust (hidden-API kCorePlatform) directly via ART seam, cache JNI IDs, register natives.
    unsafe { elevate_framework_dex_trust(env, global_loader, ops) };
    if unsafe { init_cached_jni(env, global_loader) }.is_none() {
        log_e!("init_cached_jni failed");
        return JNI_FALSE;
    }
    if !unsafe { register_all_bridges(env, global_loader) } {
        return JNI_FALSE;
    }

    // 4. Hand off to org.yasvara.kait.core.Main.forkCommon(isSystem, niceName, appDataDir).
    let entry_cls = unsafe { load_class_from_loader(env, global_loader, ENTRY_CLASS) };
    if entry_cls.is_null() {
        log_e!("entry class {ENTRY_CLASS} not found");
        return JNI_FALSE;
    }
    let Some(mid_fork) = (unsafe {
        get_static_mid(
            env,
            entry_cls,
            b"forkCommon\0",
            b"(ZLjava/lang/String;Ljava/lang/String;)V\0",
        )
    }) else {
        unsafe { (f.DeleteLocalRef.unwrap())(env, entry_cls) };
        log_e!("forkCommon method not found on {ENTRY_CLASS}");
        return JNI_FALSE;
    };
    let call_args = [
        jvalue { z: is_system_server },
        jvalue { l: nice_name },
        jvalue { l: app_data_dir },
    ];
    unsafe {
        (f.CallStaticVoidMethodA.unwrap())(env, entry_cls, mid_fork, call_args.as_ptr());
        (f.DeleteLocalRef.unwrap())(env, entry_cls);
    }
    if unsafe { clear_exception(env) } {
        log_w!("forkCommon threw an exception");
        return JNI_FALSE;
    }
    log_i!("attached Kait runtime (Rust + ROM-ART)");
    JNI_TRUE
}
