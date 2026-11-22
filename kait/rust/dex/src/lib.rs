// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pure-Rust DEX v035 emitter for Kait.
//!
//! Generates verified, minimal in-memory DEX images for:
//! 1. Per-method hook trampoline classes calling `hooker.callback(Object thisObj, Object[] args)`
//!    directly (eliminating `sliceArray` copies and allocating zero arrays for 0-arg methods).
//! 2. Dynamic `xposed.dummy.XResourcesSuperClass` and `XTypedArraySuperClass` classes.

use std::collections::BTreeSet;

const DEX_MAGIC: &[u8; 8] = b"dex\n035\0";
const HEADER_SIZE: u32 = 0x70;
const ENDIAN_CONSTANT: u32 = 0x1234_5678;
const NO_INDEX: u32 = 0xffff_ffff;

const ACC_PUBLIC: u32 = 0x0001;
const ACC_STATIC: u32 = 0x0008;

// Map item type codes (DEX spec).
const TYPE_HEADER_ITEM: u16 = 0x0000;
const TYPE_STRING_ID_ITEM: u16 = 0x0001;
const TYPE_TYPE_ID_ITEM: u16 = 0x0002;
const TYPE_PROTO_ID_ITEM: u16 = 0x0003;
const TYPE_FIELD_ID_ITEM: u16 = 0x0004;
const TYPE_METHOD_ID_ITEM: u16 = 0x0005;
const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
const TYPE_MAP_LIST: u16 = 0x1000;
const TYPE_TYPE_LIST: u16 = 0x1001;
const TYPE_CLASS_DATA_ITEM: u16 = 0x2000;
const TYPE_CODE_ITEM: u16 = 0x2001;
const TYPE_STRING_DATA_ITEM: u16 = 0x2002;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexError {
    EmptyShorty,
    InvalidShortyChar(char),
    TooManyParameters(usize),
    EmptyIdentifier,
    DuplicateMethodName,
    InvalidSimpleName,
}

/// Parameters describing a generated hook trampoline DEX.
pub struct HookDexSpec<'a> {
    pub class_descriptor: &'a str,       // e.g. "LKait_0;"
    pub source_file: &'a str,            // e.g. "Kait"
    pub hooker_field_name: &'a str,      // e.g. "h"
    pub hooker_class_descriptor: &'a str,// e.g. "Lorg/yasvara/kait/impl/hooks/KaitNativeHooker;"
    pub callback_name: &'a str,          // e.g. "callback"
    pub hook_method_name: &'a str,       // target method name (or "constructor")
    pub backup_method_name: &'a str,     // e.g. "backup"
    pub shorty: &'a str,                 // return char + param chars (V/Z/B/C/S/I/J/F/D/L)
    pub is_static: bool,
}

/// Result metadata matching what the generated DEX encodes, used by JNI to resolve IDs.
#[derive(Debug, Clone)]
pub struct HookDexImage {
    pub bytes: Vec<u8>,
    pub hook_signature: String,
    pub backup_signature: String,
}

/// Converts a dotted Java class name (`foo.Bar`) or slash name (`foo/Bar`) into a DEX descriptor (`Lfoo/Bar;`).
pub fn classname_to_descriptor(name: &str) -> String {
    if name.starts_with('L') && name.ends_with(';') {
        return name.replace('.', "/");
    }
    let mut out = String::with_capacity(name.len() + 2);
    out.push('L');
    for ch in name.chars() {
        out.push(if ch == '.' { '/' } else { ch });
    }
    out.push(';');
    out
}

fn shorty_to_descriptor(ch: char) -> Result<&'static str, DexError> {
    match ch {
        'V' => Ok("V"),
        'Z' => Ok("Z"),
        'B' => Ok("B"),
        'C' => Ok("C"),
        'S' => Ok("S"),
        'I' => Ok("I"),
        'J' => Ok("J"),
        'F' => Ok("F"),
        'D' => Ok("D"),
        'L' => Ok("Ljava/lang/Object;"),
        other => Err(DexError::InvalidShortyChar(other)),
    }
}

fn is_wide(ch: char) -> bool {
    matches!(ch, 'J' | 'D')
}

struct BoxInfo {
    box_desc: &'static str,
    unbox_name: &'static str,
    prim_desc: &'static str,
    value_of_shorty: &'static str,
    unbox_shorty: &'static str,
}

fn box_info(ch: char) -> Option<BoxInfo> {
    Some(match ch {
        'Z' => BoxInfo {
            box_desc: "Ljava/lang/Boolean;",
            unbox_name: "booleanValue",
            prim_desc: "Z",
            value_of_shorty: "LZ",
            unbox_shorty: "Z",
        },
        'B' => BoxInfo {
            box_desc: "Ljava/lang/Byte;",
            unbox_name: "byteValue",
            prim_desc: "B",
            value_of_shorty: "LB",
            unbox_shorty: "B",
        },
        'C' => BoxInfo {
            box_desc: "Ljava/lang/Character;",
            unbox_name: "charValue",
            prim_desc: "C",
            value_of_shorty: "LC",
            unbox_shorty: "C",
        },
        'S' => BoxInfo {
            box_desc: "Ljava/lang/Short;",
            unbox_name: "shortValue",
            prim_desc: "S",
            value_of_shorty: "LS",
            unbox_shorty: "S",
        },
        'I' => BoxInfo {
            box_desc: "Ljava/lang/Integer;",
            unbox_name: "intValue",
            prim_desc: "I",
            value_of_shorty: "LI",
            unbox_shorty: "I",
        },
        'J' => BoxInfo {
            box_desc: "Ljava/lang/Long;",
            unbox_name: "longValue",
            prim_desc: "J",
            value_of_shorty: "LJ",
            unbox_shorty: "J",
        },
        'F' => BoxInfo {
            box_desc: "Ljava/lang/Float;",
            unbox_name: "floatValue",
            prim_desc: "F",
            value_of_shorty: "LF",
            unbox_shorty: "F",
        },
        'D' => BoxInfo {
            box_desc: "Ljava/lang/Double;",
            unbox_name: "doubleValue",
            prim_desc: "D",
            value_of_shorty: "LD",
            unbox_shorty: "D",
        },
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProtoKey {
    return_type: String,
    params: Vec<String>,
    shorty: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FieldKey {
    class_desc: String,
    name: String,
    type_desc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MethodKey {
    class_desc: String,
    name: String,
    proto: ProtoKey,
}

struct CodeDef {
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    insns: Vec<u16>,
}

struct ClassDefInput {
    class_desc: String,
    super_desc: String,
    source_file: Option<String>,
    static_fields: Vec<(FieldKey, u32)>,
    direct_methods: Vec<(MethodKey, u32, CodeDef)>,
}

struct DexBuilder {
    strings: BTreeSet<String>,
    types: BTreeSet<String>,
    protos: BTreeSet<ProtoKey>,
    fields: BTreeSet<FieldKey>,
    methods: BTreeSet<MethodKey>,
    classes: Vec<ClassDefInput>,
}

impl DexBuilder {
    fn new() -> Self {
        Self {
            strings: BTreeSet::new(),
            types: BTreeSet::new(),
            protos: BTreeSet::new(),
            fields: BTreeSet::new(),
            methods: BTreeSet::new(),
            classes: Vec::new(),
        }
    }

    fn add_string(&mut self, s: &str) {
        self.strings.insert(s.to_owned());
    }

    fn add_type(&mut self, desc: &str) {
        self.add_string(desc);
        self.types.insert(desc.to_owned());
    }

    fn add_proto(&mut self, shorty: &str, ret_desc: &str, params: &[&str]) -> ProtoKey {
        self.add_string(shorty);
        self.add_type(ret_desc);
        let mut pvec = Vec::with_capacity(params.len());
        for &p in params {
            self.add_type(p);
            pvec.push(p.to_owned());
        }
        let key = ProtoKey {
            return_type: ret_desc.to_owned(),
            params: pvec,
            shorty: shorty.to_owned(),
        };
        self.protos.insert(key.clone());
        key
    }

    fn add_field(&mut self, class_desc: &str, name: &str, type_desc: &str) -> FieldKey {
        self.add_type(class_desc);
        self.add_string(name);
        self.add_type(type_desc);
        let key = FieldKey {
            class_desc: class_desc.to_owned(),
            name: name.to_owned(),
            type_desc: type_desc.to_owned(),
        };
        self.fields.insert(key.clone());
        key
    }

    fn add_method(&mut self, class_desc: &str, name: &str, proto: ProtoKey) -> MethodKey {
        self.add_type(class_desc);
        self.add_string(name);
        let key = MethodKey {
            class_desc: class_desc.to_owned(),
            name: name.to_owned(),
            proto,
        };
        self.methods.insert(key.clone());
        key
    }

    fn finalize_tables(&self) -> DexTables {
        let strings: Vec<String> = self.strings.iter().cloned().collect();
        let types: Vec<String> = self.types.iter().cloned().collect();

        // Sort protos by (return_type_idx, param_type_indices) per DEX specification.
        let mut protos: Vec<ProtoKey> = self.protos.iter().cloned().collect();
        protos.sort_by(|a, b| {
            let ra = types.binary_search(&a.return_type).unwrap();
            let rb = types.binary_search(&b.return_type).unwrap();
            ra.cmp(&rb).then_with(|| {
                let pa = a.params.iter().map(|p| types.binary_search(p).unwrap());
                let pb = b.params.iter().map(|p| types.binary_search(p).unwrap());
                pa.cmp(pb)
            })
        });

        let mut fields: Vec<FieldKey> = self.fields.iter().cloned().collect();
        fields.sort_by(|a, b| {
            let ca = types.binary_search(&a.class_desc).unwrap();
            let cb = types.binary_search(&b.class_desc).unwrap();
            let na = strings.binary_search(&a.name).unwrap();
            let nb = strings.binary_search(&b.name).unwrap();
            let ta = types.binary_search(&a.type_desc).unwrap();
            let tb = types.binary_search(&b.type_desc).unwrap();
            (ca, na, ta).cmp(&(cb, nb, tb))
        });

        let mut methods: Vec<MethodKey> = self.methods.iter().cloned().collect();
        methods.sort_by(|a, b| {
            let ca = types.binary_search(&a.class_desc).unwrap();
            let cb = types.binary_search(&b.class_desc).unwrap();
            let na = strings.binary_search(&a.name).unwrap();
            let nb = strings.binary_search(&b.name).unwrap();
            let pa = protos.iter().position(|p| p == &a.proto).unwrap();
            let pb = protos.iter().position(|p| p == &b.proto).unwrap();
            (ca, na, pa).cmp(&(cb, nb, pb))
        });

        DexTables {
            strings,
            types,
            protos,
            fields,
            methods,
        }
    }

    fn emit(self, tables: &DexTables) -> Vec<u8> {
        let string_ids_off = HEADER_SIZE;
        let type_ids_off = string_ids_off + (tables.strings.len() as u32) * 4;
        let proto_ids_off = type_ids_off + (tables.types.len() as u32) * 4;
        let field_ids_off = proto_ids_off + (tables.protos.len() as u32) * 12;
        let method_ids_off = field_ids_off + (tables.fields.len() as u32) * 8;
        let class_defs_off = method_ids_off + (tables.methods.len() as u32) * 8;
        let data_off = class_defs_off + (self.classes.len() as u32) * 32;

        let mut buf = vec![0u8; data_off as usize];

        let mut map_items: Vec<(u16, u32, u32)> = Vec::new();
        map_items.push((TYPE_HEADER_ITEM, 1, 0));
        if !tables.strings.is_empty() {
            map_items.push((TYPE_STRING_ID_ITEM, tables.strings.len() as u32, string_ids_off));
        }
        if !tables.types.is_empty() {
            map_items.push((TYPE_TYPE_ID_ITEM, tables.types.len() as u32, type_ids_off));
        }
        if !tables.protos.is_empty() {
            map_items.push((TYPE_PROTO_ID_ITEM, tables.protos.len() as u32, proto_ids_off));
        }
        if !tables.fields.is_empty() {
            map_items.push((TYPE_FIELD_ID_ITEM, tables.fields.len() as u32, field_ids_off));
        }
        if !tables.methods.is_empty() {
            map_items.push((TYPE_METHOD_ID_ITEM, tables.methods.len() as u32, method_ids_off));
        }
        if !self.classes.is_empty() {
            map_items.push((TYPE_CLASS_DEF_ITEM, self.classes.len() as u32, class_defs_off));
        }

        // 1. Emit type_lists (4-byte aligned) for protos that have parameters.
        align4(&mut buf);
        let type_list_start = buf.len() as u32;
        let mut type_list_count = 0u32;
        let mut proto_param_offs = vec![0u32; tables.protos.len()];
        for (i, proto) in tables.protos.iter().enumerate() {
            if proto.params.is_empty() {
                continue;
            }
            align4(&mut buf);
            proto_param_offs[i] = buf.len() as u32;
            push_u32(&mut buf, proto.params.len() as u32);
            for p in &proto.params {
                push_u16(&mut buf, tables.type_idx(p) as u16);
            }
            type_list_count += 1;
        }
        if type_list_count > 0 {
            map_items.push((TYPE_TYPE_LIST, type_list_count, type_list_start));
        }

        // 2. Emit code_items (4-byte aligned).
        align4(&mut buf);
        let code_items_start = buf.len() as u32;
        let mut code_item_count = 0u32;
        let mut class_method_code_offs: Vec<Vec<u32>> = Vec::with_capacity(self.classes.len());
        for cls in &self.classes {
            let mut offs = Vec::with_capacity(cls.direct_methods.len());
            for (_, _, code) in &cls.direct_methods {
                align4(&mut buf);
                offs.push(buf.len() as u32);
                push_u16(&mut buf, code.registers_size);
                push_u16(&mut buf, code.ins_size);
                push_u16(&mut buf, code.outs_size);
                push_u16(&mut buf, 0); // tries_size
                push_u32(&mut buf, 0); // debug_info_off
                push_u32(&mut buf, code.insns.len() as u32);
                for &unit in &code.insns {
                    push_u16(&mut buf, unit);
                }
                code_item_count += 1;
            }
            class_method_code_offs.push(offs);
        }
        if code_item_count > 0 {
            map_items.push((TYPE_CODE_ITEM, code_item_count, code_items_start));
        }

        // 3. Emit string_data_items.
        let string_data_start = buf.len() as u32;
        let mut string_data_offs = Vec::with_capacity(tables.strings.len());
        for s in &tables.strings {
            string_data_offs.push(buf.len() as u32);
            let utf16_len = s.encode_utf16().count() as u32;
            push_uleb128(&mut buf, utf16_len);
            push_mutf8(&mut buf, s);
            buf.push(0);
        }
        if !tables.strings.is_empty() {
            map_items.push((TYPE_STRING_DATA_ITEM, tables.strings.len() as u32, string_data_start));
        }

        // 4. Emit class_data_items.
        let class_data_start = buf.len() as u32;
        let mut class_data_count = 0u32;
        let mut class_data_offs = vec![0u32; self.classes.len()];
        for (ci, cls) in self.classes.iter().enumerate() {
            if cls.static_fields.is_empty() && cls.direct_methods.is_empty() {
                continue;
            }
            class_data_offs[ci] = buf.len() as u32;
            push_uleb128(&mut buf, cls.static_fields.len() as u32);
            push_uleb128(&mut buf, 0); // instance_fields
            push_uleb128(&mut buf, cls.direct_methods.len() as u32);
            push_uleb128(&mut buf, 0); // virtual_methods

            let mut sorted_fields: Vec<(u32, u32)> = cls
                .static_fields
                .iter()
                .map(|(fk, acc)| (tables.field_idx(fk), *acc))
                .collect();
            sorted_fields.sort_by_key(|(idx, _)| *idx);
            let mut prev = 0u32;
            for (idx, acc) in sorted_fields {
                push_uleb128(&mut buf, idx - prev);
                push_uleb128(&mut buf, acc);
                prev = idx;
            }

            let mut sorted_methods: Vec<(u32, u32, u32)> = cls
                .direct_methods
                .iter()
                .enumerate()
                .map(|(mi, (mk, acc, _))| {
                    (tables.method_idx(mk), *acc, class_method_code_offs[ci][mi])
                })
                .collect();
            sorted_methods.sort_by_key(|(idx, _, _)| *idx);
            let mut prev = 0u32;
            for (idx, acc, code_off) in sorted_methods {
                push_uleb128(&mut buf, idx - prev);
                push_uleb128(&mut buf, acc);
                push_uleb128(&mut buf, code_off);
                prev = idx;
            }
            class_data_count += 1;
        }
        if class_data_count > 0 {
            map_items.push((TYPE_CLASS_DATA_ITEM, class_data_count, class_data_start));
        }

        // 5. Emit map_list (4-byte aligned).
        align4(&mut buf);
        let map_off = buf.len() as u32;
        map_items.push((TYPE_MAP_LIST, 1, map_off));
        push_u32(&mut buf, map_items.len() as u32);
        for (ty, size, off) in &map_items {
            push_u16(&mut buf, *ty);
            push_u16(&mut buf, 0);
            push_u32(&mut buf, *size);
            push_u32(&mut buf, *off);
        }

        // 6. Backfill string_ids, type_ids, proto_ids, field_ids, method_ids, class_defs.
        for (i, &off) in string_data_offs.iter().enumerate() {
            write_u32(&mut buf, string_ids_off as usize + i * 4, off);
        }
        for (i, ty) in tables.types.iter().enumerate() {
            write_u32(&mut buf, type_ids_off as usize + i * 4, tables.string_idx(ty));
        }
        for (i, p) in tables.protos.iter().enumerate() {
            let base = proto_ids_off as usize + i * 12;
            write_u32(&mut buf, base, tables.string_idx(&p.shorty));
            write_u32(&mut buf, base + 4, tables.type_idx(&p.return_type));
            write_u32(&mut buf, base + 8, proto_param_offs[i]);
        }
        for (i, f) in tables.fields.iter().enumerate() {
            let base = field_ids_off as usize + i * 8;
            write_u16(&mut buf, base, tables.type_idx(&f.class_desc) as u16);
            write_u16(&mut buf, base + 2, tables.type_idx(&f.type_desc) as u16);
            write_u32(&mut buf, base + 4, tables.string_idx(&f.name));
        }
        for (i, m) in tables.methods.iter().enumerate() {
            let base = method_ids_off as usize + i * 8;
            write_u16(&mut buf, base, tables.type_idx(&m.class_desc) as u16);
            write_u16(&mut buf, base + 2, tables.proto_idx(&m.proto) as u16);
            write_u32(&mut buf, base + 4, tables.string_idx(&m.name));
        }
        for (i, cls) in self.classes.iter().enumerate() {
            let base = class_defs_off as usize + i * 32;
            write_u32(&mut buf, base, tables.type_idx(&cls.class_desc));
            write_u32(&mut buf, base + 4, ACC_PUBLIC);
            write_u32(&mut buf, base + 8, tables.type_idx(&cls.super_desc));
            write_u32(&mut buf, base + 12, 0); // interfaces_off
            let src_idx = cls
                .source_file
                .as_deref()
                .map(|s| tables.string_idx(s))
                .unwrap_or(NO_INDEX);
            write_u32(&mut buf, base + 16, src_idx);
            write_u32(&mut buf, base + 20, 0); // annotations_off
            write_u32(&mut buf, base + 24, class_data_offs[i]);
            write_u32(&mut buf, base + 28, 0); // static_values_off
        }

        // 7. Write header + SHA-1 + Adler-32.
        let file_size = buf.len() as u32;
        let data_size = file_size - data_off;
        buf[0..8].copy_from_slice(DEX_MAGIC);
        write_u32(&mut buf, 32, file_size);
        write_u32(&mut buf, 36, HEADER_SIZE);
        write_u32(&mut buf, 40, ENDIAN_CONSTANT);
        write_u32(&mut buf, 44, 0);
        write_u32(&mut buf, 48, 0);
        write_u32(&mut buf, 52, map_off);
        write_u32(&mut buf, 56, tables.strings.len() as u32);
        write_u32(&mut buf, 60, if tables.strings.is_empty() { 0 } else { string_ids_off });
        write_u32(&mut buf, 64, tables.types.len() as u32);
        write_u32(&mut buf, 68, if tables.types.is_empty() { 0 } else { type_ids_off });
        write_u32(&mut buf, 72, tables.protos.len() as u32);
        write_u32(&mut buf, 76, if tables.protos.is_empty() { 0 } else { proto_ids_off });
        write_u32(&mut buf, 80, tables.fields.len() as u32);
        write_u32(&mut buf, 84, if tables.fields.is_empty() { 0 } else { field_ids_off });
        write_u32(&mut buf, 88, tables.methods.len() as u32);
        write_u32(&mut buf, 92, if tables.methods.is_empty() { 0 } else { method_ids_off });
        write_u32(&mut buf, 96, self.classes.len() as u32);
        write_u32(&mut buf, 100, if self.classes.is_empty() { 0 } else { class_defs_off });
        write_u32(&mut buf, 104, data_size);
        write_u32(&mut buf, 108, data_off);

        let sha1 = sha1_digest(&buf[32..]);
        buf[12..32].copy_from_slice(&sha1);
        let checksum = adler32(&buf[12..]);
        write_u32(&mut buf, 8, checksum);

        buf
    }
}

struct DexTables {
    strings: Vec<String>,
    types: Vec<String>,
    protos: Vec<ProtoKey>,
    fields: Vec<FieldKey>,
    methods: Vec<MethodKey>,
}

impl DexTables {
    fn string_idx(&self, s: &str) -> u32 {
        self.strings
            .binary_search_by(|cand| cand.as_str().cmp(s))
            .expect("missing string in DEX table") as u32
    }

    fn type_idx(&self, desc: &str) -> u32 {
        self.types
            .binary_search_by(|cand| cand.as_str().cmp(desc))
            .expect("missing type in DEX table") as u32
    }

    fn proto_idx(&self, proto: &ProtoKey) -> u32 {
        self.protos
            .iter()
            .position(|p| p == proto)
            .expect("missing proto in DEX table") as u32
    }

    fn field_idx(&self, field: &FieldKey) -> u32 {
        self.fields
            .iter()
            .position(|f| f == field)
            .expect("missing field in DEX table") as u32
    }

    fn method_idx(&self, method: &MethodKey) -> u32 {
        self.methods
            .iter()
            .position(|m| m == method)
            .expect("missing method in DEX table") as u32
    }
}

/// Builds a verified DEX image containing the hook trampoline method and dummy backup slot.
pub fn build_hook_dex(spec: &HookDexSpec<'_>) -> Result<HookDexImage, DexError> {
    if spec.shorty.is_empty() {
        return Err(DexError::EmptyShorty);
    }
    if spec.class_descriptor.is_empty()
        || spec.hooker_class_descriptor.is_empty()
        || spec.hook_method_name.is_empty()
        || spec.backup_method_name.is_empty()
        || spec.callback_name.is_empty()
        || spec.hooker_field_name.is_empty()
    {
        return Err(DexError::EmptyIdentifier);
    }
    if spec.hook_method_name == spec.backup_method_name {
        return Err(DexError::DuplicateMethodName);
    }
    let is_valid_simple = |s: &str| {
        !s.bytes().any(|b| matches!(b, b'.' | b'/' | b';' | b'[' | b'<' | b'>'))
    };
    if !is_valid_simple(spec.hook_method_name)
        || !is_valid_simple(spec.backup_method_name)
        || !is_valid_simple(spec.hooker_field_name)
    {
        return Err(DexError::InvalidSimpleName);
    }

    let chars: Vec<char> = spec.shorty.chars().collect();
    let ret_char = chars[0];
    let ret_desc = shorty_to_descriptor(ret_char)?;
    let actual_params = &chars[1..];
    if actual_params.len() > 255 {
        return Err(DexError::TooManyParameters(actual_params.len()));
    }

    // Validate all parameter shorty chars (V is invalid as a parameter).
    let mut full_param_chars: Vec<char> = Vec::with_capacity(actual_params.len() + 1);
    let mut full_param_descs: Vec<&'static str> = Vec::with_capacity(actual_params.len() + 1);
    if !spec.is_static {
        full_param_chars.push('L');
        full_param_descs.push("Ljava/lang/Object;");
    }
    for &ch in actual_params {
        if ch == 'V' {
            return Err(DexError::InvalidShortyChar('V'));
        }
        full_param_descs.push(shorty_to_descriptor(ch)?);
        full_param_chars.push(ch);
    }

    let mut full_shorty = String::with_capacity(1 + full_param_chars.len());
    full_shorty.push(ret_char);
    for &c in &full_param_chars {
        full_shorty.push(c);
    }

    let mut jni_sig = String::from("(");
    for d in &full_param_descs {
        jni_sig.push_str(d);
    }
    jni_sig.push(')');
    jni_sig.push_str(ret_desc);

    let mut builder = DexBuilder::new();
    builder.add_type("Ljava/lang/Object;");
    builder.add_type("[Ljava/lang/Object;");
    builder.add_type(spec.class_descriptor);
    builder.add_type(spec.hooker_class_descriptor);
    if !spec.source_file.is_empty() {
        builder.add_string(spec.source_file);
    }

    let hooker_field = builder.add_field(
        spec.class_descriptor,
        spec.hooker_field_name,
        spec.hooker_class_descriptor,
    );

    let target_proto = builder.add_proto(&full_shorty, ret_desc, &full_param_descs);
    let hook_method = builder.add_method(spec.class_descriptor, spec.hook_method_name, target_proto.clone());
    let backup_method = builder.add_method(spec.class_descriptor, spec.backup_method_name, target_proto);

    // callback(Object thisObj, Object[] args): Object
    let cb_proto = builder.add_proto(
        "LLL",
        "Ljava/lang/Object;",
        &["Ljava/lang/Object;", "[Ljava/lang/Object;"],
    );
    let cb_method = builder.add_method(spec.hooker_class_descriptor, spec.callback_name, cb_proto);

    // Register boxing valueOf methods for any primitive parameters.
    let mut box_methods: Vec<Option<MethodKey>> = Vec::with_capacity(actual_params.len());
    for &ch in actual_params {
        if let Some(info) = box_info(ch) {
            let p = builder.add_proto(info.value_of_shorty, info.box_desc, &[info.prim_desc]);
            let m = builder.add_method(info.box_desc, "valueOf", p);
            box_methods.push(Some(m));
        } else {
            box_methods.push(None);
        }
    }

    // Register unboxing method if return type is primitive.
    let unbox_target = box_info(ret_char).map(|info| {
        let p = builder.add_proto(info.unbox_shorty, info.prim_desc, &[]);
        let m = builder.add_method(info.box_desc, info.unbox_name, p);
        (info.box_desc, m)
    });

    // Freeze table indices now so we can emit Dalvik bytecode referencing exact indices.
    let tables = builder.finalize_tables();

    // Compute ins_size and register layout.
    let ins_size: u16 = full_param_chars
        .iter()
        .map(|&c| if is_wide(c) { 2u16 } else { 1u16 })
        .sum();
    // Fixed low locals: v0 (hooker/result), v1 (thisObj), v2 (args[]), v3 & v4 (scratch/wide pair).
    const LOCALS: u16 = 5;
    let registers_size = LOCALS + ins_size;

    let mut insns: Vec<u16> = Vec::with_capacity(32 + actual_params.len() * 8);

    // 1. v0 = hooker_field
    emit_sget_object(&mut insns, 0, tables.field_idx(&hooker_field) as u16);

    // 2. v1 = thisObj (p0 if instance, else null)
    let mut next_param_reg: u16 = LOCALS;
    if !spec.is_static {
        emit_move_object_from16(&mut insns, 1, next_param_reg);
        next_param_reg += 1;
    } else {
        emit_const4(&mut insns, 1, 0);
    }

    // 3. v2 = Object[] args (null when 0 actual args -> zero allocation!)
    if actual_params.is_empty() {
        emit_const4(&mut insns, 2, 0);
    } else {
        emit_const16(&mut insns, 3, actual_params.len() as i16);
        let obj_arr_type = tables.type_idx("[Ljava/lang/Object;") as u16;
        emit_new_array(&mut insns, 2, 3, obj_arr_type);

        for (idx, &ch) in actual_params.iter().enumerate() {
            if let Some(ref box_m) = box_methods[idx] {
                let mid = tables.method_idx(box_m) as u16;
                if is_wide(ch) {
                    emit_move_wide_from16(&mut insns, 3, next_param_reg);
                    emit_invoke_static_2(&mut insns, mid, 3, 4);
                    next_param_reg += 2;
                } else {
                    emit_move_from16(&mut insns, 3, next_param_reg);
                    emit_invoke_static_1(&mut insns, mid, 3);
                    next_param_reg += 1;
                }
                emit_move_result_object(&mut insns, 3);
            } else {
                emit_move_object_from16(&mut insns, 3, next_param_reg);
                next_param_reg += 1;
            }
            emit_const16(&mut insns, 4, idx as i16);
            emit_aput_object(&mut insns, 3, 2, 4);
        }
    }

    // 4. v0 = hooker.callback(v1, v2)
    emit_invoke_virtual_3(&mut insns, tables.method_idx(&cb_method) as u16, 0, 1, 2);

    // 5. Unbox / return.
    if ret_char == 'V' {
        emit_return_void(&mut insns);
    } else if let Some((box_desc, ref unbox_m)) = unbox_target {
        emit_move_result_object(&mut insns, 0);
        emit_check_cast(&mut insns, 0, tables.type_idx(box_desc) as u16);
        emit_invoke_virtual_1(&mut insns, tables.method_idx(unbox_m) as u16, 0);
        if is_wide(ret_char) {
            emit_move_result_wide(&mut insns, 0);
            emit_return_wide(&mut insns, 0);
        } else {
            emit_move_result(&mut insns, 0);
            emit_return(&mut insns, 0);
        }
    } else {
        emit_move_result_object(&mut insns, 0);
        emit_return_object(&mut insns, 0);
    }

    // Dummy backup method body (only needs to pass verification before CopyFrom overwrites it).
    let mut backup_insns: Vec<u16> = Vec::with_capacity(4);
    let backup_locals: u16 = if is_wide(ret_char) { 2 } else { 1 };
    if ret_char == 'V' {
        emit_return_void(&mut backup_insns);
    } else if is_wide(ret_char) {
        emit_const_wide16(&mut backup_insns, 0, 0);
        emit_return_wide(&mut backup_insns, 0);
    } else if ret_char == 'L' {
        emit_const4(&mut backup_insns, 0, 0);
        emit_return_object(&mut backup_insns, 0);
    } else {
        emit_const4(&mut backup_insns, 0, 0);
        emit_return(&mut backup_insns, 0);
    }

    builder.classes.push(ClassDefInput {
        class_desc: spec.class_descriptor.to_owned(),
        super_desc: "Ljava/lang/Object;".to_owned(),
        source_file: if spec.source_file.is_empty() {
            None
        } else {
            Some(spec.source_file.to_owned())
        },
        static_fields: vec![(hooker_field, ACC_PUBLIC | ACC_STATIC)],
        direct_methods: vec![
            (
                hook_method,
                ACC_PUBLIC | ACC_STATIC,
                CodeDef {
                    registers_size,
                    ins_size,
                    outs_size: 3,
                    insns,
                },
            ),
            (
                backup_method,
                ACC_PUBLIC | ACC_STATIC,
                CodeDef {
                    registers_size: backup_locals + ins_size,
                    ins_size,
                    outs_size: 0,
                    insns: backup_insns,
                },
            ),
        ],
    });

    let bytes = builder.emit(&tables);
    Ok(HookDexImage {
        bytes,
        hook_signature: jni_sig.clone(),
        backup_signature: jni_sig,
    })
}

/// Builds the in-memory DEX defining `xposed.dummy.XResourcesSuperClass` and
/// `xposed.dummy.XTypedArraySuperClass` with dynamic runtime superclasses.
pub fn build_dummy_resources_dex(res_super: &str, ta_super: &str) -> Result<Vec<u8>, DexError> {
    if res_super.is_empty() || ta_super.is_empty() {
        return Err(DexError::EmptyIdentifier);
    }
    let res_super_desc = classname_to_descriptor(res_super);
    let ta_super_desc = classname_to_descriptor(ta_super);
    let res_dummy = "Lxposed/dummy/XResourcesSuperClass;";
    let ta_dummy = "Lxposed/dummy/XTypedArraySuperClass;";

    let mut builder = DexBuilder::new();
    builder.add_type(res_dummy);
    builder.add_type(&res_super_desc);
    builder.add_type(ta_dummy);
    builder.add_type(&ta_super_desc);

    let tables = builder.finalize_tables();
    builder.classes.push(ClassDefInput {
        class_desc: res_dummy.to_owned(),
        super_desc: res_super_desc,
        source_file: None,
        static_fields: Vec::new(),
        direct_methods: Vec::new(),
    });
    builder.classes.push(ClassDefInput {
        class_desc: ta_dummy.to_owned(),
        super_desc: ta_super_desc,
        source_file: None,
        static_fields: Vec::new(),
        direct_methods: Vec::new(),
    });

    Ok(builder.emit(&tables))
}

// --- Dalvik instruction emitters ---

fn emit_move_from16(out: &mut Vec<u16>, dst: u8, src: u16) {
    out.push(0x02 | ((dst as u16) << 8));
    out.push(src);
}

fn emit_move_wide_from16(out: &mut Vec<u16>, dst: u8, src: u16) {
    out.push(0x05 | ((dst as u16) << 8));
    out.push(src);
}

fn emit_move_object_from16(out: &mut Vec<u16>, dst: u8, src: u16) {
    out.push(0x08 | ((dst as u16) << 8));
    out.push(src);
}

fn emit_move_result(out: &mut Vec<u16>, dst: u8) {
    out.push(0x0a | ((dst as u16) << 8));
}

fn emit_move_result_wide(out: &mut Vec<u16>, dst: u8) {
    out.push(0x0b | ((dst as u16) << 8));
}

fn emit_move_result_object(out: &mut Vec<u16>, dst: u8) {
    out.push(0x0c | ((dst as u16) << 8));
}

fn emit_return_void(out: &mut Vec<u16>) {
    out.push(0x000e);
}

fn emit_return(out: &mut Vec<u16>, reg: u8) {
    out.push(0x0f | ((reg as u16) << 8));
}

fn emit_return_wide(out: &mut Vec<u16>, reg: u8) {
    out.push(0x10 | ((reg as u16) << 8));
}

fn emit_return_object(out: &mut Vec<u16>, reg: u8) {
    out.push(0x11 | ((reg as u16) << 8));
}

fn emit_const4(out: &mut Vec<u16>, dst: u8, val: i8) {
    out.push(0x12 | (((dst as u16) & 0x0f) << 8) | (((val as u16) & 0x0f) << 12));
}

fn emit_const16(out: &mut Vec<u16>, dst: u8, val: i16) {
    out.push(0x13 | ((dst as u16) << 8));
    out.push(val as u16);
}

fn emit_const_wide16(out: &mut Vec<u16>, dst: u8, val: i16) {
    out.push(0x16 | ((dst as u16) << 8));
    out.push(val as u16);
}

fn emit_check_cast(out: &mut Vec<u16>, reg: u8, type_idx: u16) {
    out.push(0x1f | ((reg as u16) << 8));
    out.push(type_idx);
}

fn emit_new_array(out: &mut Vec<u16>, dst: u8, size_reg: u8, type_idx: u16) {
    out.push(0x23 | (((dst as u16) & 0x0f) << 8) | (((size_reg as u16) & 0x0f) << 12));
    out.push(type_idx);
}

fn emit_aput_object(out: &mut Vec<u16>, val_reg: u8, arr_reg: u8, idx_reg: u8) {
    out.push(0x4d | ((val_reg as u16) << 8));
    out.push((arr_reg as u16) | ((idx_reg as u16) << 8));
}

fn emit_sget_object(out: &mut Vec<u16>, dst: u8, field_idx: u16) {
    out.push(0x62 | ((dst as u16) << 8));
    out.push(field_idx);
}

fn emit_invoke_virtual_1(out: &mut Vec<u16>, method_idx: u16, r0: u8) {
    out.push(0x6e | (1u16 << 12));
    out.push(method_idx);
    out.push((r0 as u16) & 0x0f);
}

fn emit_invoke_virtual_3(out: &mut Vec<u16>, method_idx: u16, r0: u8, r1: u8, r2: u8) {
    out.push(0x6e | (3u16 << 12));
    out.push(method_idx);
    out.push(((r0 as u16) & 0x0f) | (((r1 as u16) & 0x0f) << 4) | (((r2 as u16) & 0x0f) << 8));
}

fn emit_invoke_static_1(out: &mut Vec<u16>, method_idx: u16, r0: u8) {
    out.push(0x71 | (1u16 << 12));
    out.push(method_idx);
    out.push((r0 as u16) & 0x0f);
}

fn emit_invoke_static_2(out: &mut Vec<u16>, method_idx: u16, r0: u8, r1: u8) {
    out.push(0x71 | (2u16 << 12));
    out.push(method_idx);
    out.push(((r0 as u16) & 0x0f) | (((r1 as u16) & 0x0f) << 4));
}

// --- Binary encoding helpers ---

fn align4(buf: &mut Vec<u8>) {
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn push_uleb128(buf: &mut Vec<u8>, mut v: u32) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn push_mutf8(buf: &mut Vec<u8>, s: &str) {
    for unit in s.encode_utf16() {
        match unit {
            0x0001..=0x007f => buf.push(unit as u8),
            0x0000 | 0x0080..=0x07ff => {
                buf.push(0xc0 | ((unit >> 6) as u8 & 0x1f));
                buf.push(0x80 | (unit as u8 & 0x3f));
            }
            _ => {
                buf.push(0xe0 | ((unit >> 12) as u8 & 0x0f));
                buf.push(0x80 | ((unit >> 6) as u8 & 0x3f));
                buf.push(0x80 | (unit as u8 & 0x3f));
            }
        }
    }
}

/// Standard Adler-32 checksum used in DEX headers.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// FIPS 180-4 SHA-1 used exclusively for DEX header integrity signatures.
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xefcd_ab89;
    let mut h2: u32 = 0x98ba_dcfe;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xc3d2_e1f0;

    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for block in padded.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([b[off], b[off + 1]])
    }

    fn read_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    fn read_uleb128(b: &[u8], off: &mut usize) -> u32 {
        let mut res = 0u32;
        let mut shift = 0u32;
        loop {
            let byte = b[*off];
            *off += 1;
            res |= ((byte & 0x7f) as u32) << shift;
            if byte & 0x80 == 0 {
                return res;
            }
            shift += 7;
        }
    }

    fn verify_dex_structure(bytes: &[u8]) {
        assert!(bytes.len() >= HEADER_SIZE as usize);
        assert_eq!(&bytes[0..8], DEX_MAGIC);
        assert_eq!(read_u32(bytes, 32) as usize, bytes.len());
        assert_eq!(read_u32(bytes, 36), HEADER_SIZE);
        assert_eq!(read_u32(bytes, 40), ENDIAN_CONSTANT);

        // Verify SHA-1 & Adler-32.
        assert_eq!(&bytes[12..32], &sha1_digest(&bytes[32..]));
        assert_eq!(read_u32(bytes, 8), adler32(&bytes[12..]));

        // Verify string_ids are strictly sorted.
        let str_cnt = read_u32(bytes, 56) as usize;
        let str_off = read_u32(bytes, 60) as usize;
        let mut strings = Vec::with_capacity(str_cnt);
        for i in 0..str_cnt {
            let mut d_off = read_u32(bytes, str_off + i * 4) as usize;
            let _utf16_len = read_uleb128(bytes, &mut d_off);
            let nul = bytes[d_off..].iter().position(|&c| c == 0).unwrap();
            let s = std::str::from_utf8(&bytes[d_off..d_off + nul]).unwrap().to_owned();
            strings.push(s);
        }
        for pair in strings.windows(2) {
            assert!(pair[0] < pair[1], "unsorted strings: {} >= {}", pair[0], pair[1]);
        }

        // Verify type_ids are strictly sorted by string_idx.
        let ty_cnt = read_u32(bytes, 64) as usize;
        let ty_off = read_u32(bytes, 68) as usize;
        let mut ty_str_idxs = Vec::with_capacity(ty_cnt);
        for i in 0..ty_cnt {
            ty_str_idxs.push(read_u32(bytes, ty_off + i * 4));
        }
        for pair in ty_str_idxs.windows(2) {
            assert!(pair[0] < pair[1], "unsorted type_ids");
        }

        // Verify proto_ids are strictly sorted by (return_type_idx, params).
        let proto_cnt = read_u32(bytes, 72) as usize;
        let proto_off = read_u32(bytes, 76) as usize;
        let mut proto_keys = Vec::with_capacity(proto_cnt);
        for i in 0..proto_cnt {
            let base = proto_off + i * 12;
            let ret = read_u32(bytes, base + 4);
            let p_off = read_u32(bytes, base + 8) as usize;
            let mut params = Vec::new();
            if p_off != 0 {
                assert_eq!(p_off % 4, 0, "unaligned type_list");
                let n = read_u32(bytes, p_off) as usize;
                for j in 0..n {
                    params.push(read_u16(bytes, p_off + 4 + j * 2) as u32);
                }
            }
            proto_keys.push((ret, params));
        }
        for pair in proto_keys.windows(2) {
            assert!(pair[0] < pair[1], "unsorted proto_ids: {:?} >= {:?}", pair[0], pair[1]);
        }

        // Verify field_ids sorted.
        let fld_cnt = read_u32(bytes, 80) as usize;
        let fld_off = read_u32(bytes, 84) as usize;
        let mut fld_keys = Vec::with_capacity(fld_cnt);
        for i in 0..fld_cnt {
            let base = fld_off + i * 8;
            let cls = read_u16(bytes, base);
            let ty = read_u16(bytes, base + 2);
            let name = read_u32(bytes, base + 4);
            fld_keys.push((cls, name, ty));
        }
        for pair in fld_keys.windows(2) {
            assert!(pair[0] < pair[1], "unsorted field_ids");
        }

        // Verify method_ids sorted.
        let m_cnt = read_u32(bytes, 88) as usize;
        let m_off = read_u32(bytes, 92) as usize;
        let mut m_keys = Vec::with_capacity(m_cnt);
        for i in 0..m_cnt {
            let base = m_off + i * 8;
            let cls = read_u16(bytes, base);
            let proto = read_u16(bytes, base + 2);
            let name = read_u32(bytes, base + 4);
            m_keys.push((cls, name, proto));
        }
        for pair in m_keys.windows(2) {
            assert!(pair[0] < pair[1], "unsorted method_ids");
        }

        // Verify map_list alignment and bounds.
        let map_off = read_u32(bytes, 52) as usize;
        assert_eq!(map_off % 4, 0);
        let map_cnt = read_u32(bytes, map_off) as usize;
        assert_eq!(map_off + 4 + map_cnt * 12, bytes.len());
    }

    #[test]
    fn test_sha1_and_adler32_known_vectors() {
        // FIPS 180-4 SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        assert_eq!(
            sha1_digest(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
        // Adler-32("Wikipedia") = 0x11e60398
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }

    #[test]
    fn test_hook_dex_zero_arg_static_and_instance() {
        for is_static in [true, false] {
            let img = build_hook_dex(&HookDexSpec {
                class_descriptor: "LKait_0;",
                source_file: "Kait",
                hooker_field_name: "h",
                hooker_class_descriptor: "Lorg/yasvara/kait/impl/hooks/KaitNativeHooker;",
                callback_name: "callback",
                hook_method_name: "run",
                backup_method_name: "backup",
                shorty: "V",
                is_static,
            })
            .unwrap();
            verify_dex_structure(&img.bytes);
            if is_static {
                assert_eq!(img.hook_signature, "()V");
            } else {
                assert_eq!(img.hook_signature, "(Ljava/lang/Object;)V");
            }
        }
    }

    #[test]
    fn test_hook_dex_all_primitives_and_wide_returns() {
        for ret in ['V', 'Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D', 'L'] {
            let shorty = format!("{ret}ZBCSIJFDL");
            let img = build_hook_dex(&HookDexSpec {
                class_descriptor: "LKait_42;",
                source_file: "Kait",
                hooker_field_name: "h",
                hooker_class_descriptor: "Lorg/yasvara/kait/impl/hooks/KaitNativeHooker;",
                callback_name: "callback",
                hook_method_name: "target",
                backup_method_name: "backup",
                shorty: &shorty,
                is_static: false,
            })
            .unwrap();
            verify_dex_structure(&img.bytes);
            assert!(img.hook_signature.starts_with("(Ljava/lang/Object;ZBCSIJFDLjava/lang/Object;)"));
        }
    }

    #[test]
    fn test_hook_dex_over_16_registers_wide_params() {
        // 12 longs = 24 param registers + 1 this + 5 locals = 30 registers (> 16).
        let img = build_hook_dex(&HookDexSpec {
            class_descriptor: "LKait_wide;",
            source_file: "Kait",
            hooker_field_name: "h",
            hooker_class_descriptor: "Lorg/yasvara/kait/impl/hooks/KaitNativeHooker;",
            callback_name: "callback",
            hook_method_name: "manyLongs",
            backup_method_name: "backup",
            shorty: "DJJJJJJJJJJJJ",
            is_static: false,
        })
        .unwrap();
        verify_dex_structure(&img.bytes);
    }

    #[test]
    fn test_hook_dex_rejects_invalid_shorty() {
        assert_eq!(
            build_hook_dex(&HookDexSpec {
                class_descriptor: "LKait_err;",
                source_file: "Kait",
                hooker_field_name: "h",
                hooker_class_descriptor: "LFoo;",
                callback_name: "callback",
                hook_method_name: "m",
                backup_method_name: "backup",
                shorty: "",
                is_static: true,
            })
            .unwrap_err(),
            DexError::EmptyShorty
        );
        assert_eq!(
            build_hook_dex(&HookDexSpec {
                class_descriptor: "LKait_err;",
                source_file: "Kait",
                hooker_field_name: "h",
                hooker_class_descriptor: "LFoo;",
                callback_name: "callback",
                hook_method_name: "m",
                backup_method_name: "backup",
                shorty: "IV",
                is_static: true,
            })
            .unwrap_err(),
            DexError::InvalidShortyChar('V')
        );
    }

    #[test]
    fn test_dummy_resources_dex() {
        let dex = build_dummy_resources_dex(
            "android.content.res.Resources",
            "android.content.res.TypedArray",
        )
        .unwrap();
        verify_dex_structure(&dex);
        assert_eq!(read_u32(&dex, 96), 2); // 2 class defs
    }

    #[test]
    fn test_hook_dex_rejects_duplicate_or_dotted_method_name() {
        // Method named "backup" must be rejected if not remapped by caller.
        assert_eq!(
            build_hook_dex(&HookDexSpec {
                class_descriptor: "LKait_dup;",
                source_file: "Kait",
                hooker_field_name: "h",
                hooker_class_descriptor: "LFoo;",
                callback_name: "callback",
                hook_method_name: "backup",
                backup_method_name: "backup",
                shorty: "V",
                is_static: false,
            })
            .unwrap_err(),
            DexError::DuplicateMethodName
        );
        // Constructor.getName() style dotted name ("java.lang.String") or "<init>" must be rejected.
        for bad in ["java.lang.String", "<init>", "foo/bar", "a;b"] {
            assert_eq!(
                build_hook_dex(&HookDexSpec {
                    class_descriptor: "LKait_bad;",
                    source_file: "Kait",
                    hooker_field_name: "h",
                    hooker_class_descriptor: "LFoo;",
                    callback_name: "callback",
                    hook_method_name: bad,
                    backup_method_name: "backup",
                    shorty: "V",
                    is_static: false,
                })
                .unwrap_err(),
                DexError::InvalidSimpleName
            );
        }
    }
}
