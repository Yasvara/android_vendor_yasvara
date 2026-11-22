// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! The list compiler for Laras.

use jni::objects::{JClass, JObjectArray, JString};
use jni::sys::{jlong, jlongArray};
use jni::JNIEnv;
use saring::compile::compile;
use saring::Names;
use std::{fs, ptr};

fn run(env: &mut JNIEnv, inputs: &JObjectArray, output: &JString, created: jlong) -> Option<Vec<jlong>> {
    let count = env.get_array_length(inputs).ok()?;
    let mut texts = Vec::with_capacity(count as usize);
    for i in 0..count {
        let item = JString::from(env.get_object_array_element(inputs, i).ok()?);
        let path: String = env.get_string(&item).ok()?.into();
        texts.push(String::from_utf8_lossy(&fs::read(path).ok()?).into_owned());
    }
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let (blob, stats) = compile(&refs, created as u64);
    let mut out = vec![Names::open(&blob)?.len() as jlong];
    for s in stats {
        out.extend(
            [s.block, s.allow, s.deny, s.third, s.popup, s.cosmetic, s.unsupported]
                .map(jlong::from),
        );
    }
    let path: String = env.get_string(output).ok()?.into();
    fs::write(path, blob).ok()?;
    Some(out)
}

/// Compiles the list files into one table. Returns the entry count followed by seven counts
/// per input (block, allow, deny, third party, pop-up, cosmetic, unsupported), or null.
#[no_mangle]
pub extern "system" fn Java_org_yasvara_laras_data_saring_SaringNative_compile<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    inputs: JObjectArray<'l>,
    output: JString<'l>,
    created: jlong,
) -> jlongArray {
    let Some(out) = run(&mut env, &inputs, &output, created) else {
        return ptr::null_mut();
    };
    match env.new_long_array(out.len() as i32) {
        Ok(array) if env.set_long_array_region(&array, 0, &out).is_ok() => array.into_raw(),
        _ => ptr::null_mut(),
    }
}
