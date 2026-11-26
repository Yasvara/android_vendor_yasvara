// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! `pasang-core` — Unified, zero-dependency (`std` + `core`) Rust engine shared by:
//! - Host `yv` CLI (`yv install kernel`, `yv ota ...`)
//! - In-OS live CoW OTA daemon (`pasangd`) and CLI (`/system_ext/bin/pasang`)
//! - `Pulih` 120 Hz Material You Recovery (`M2-M6`)

pub mod avb;
pub mod backup;
pub mod codec;
pub mod cow_ota;
pub mod crypto;
pub mod dedup;
pub mod ffi;
pub mod html;
pub mod lp;
pub mod meta;
pub mod net;
pub mod overlay;
pub mod payload;
pub mod safety;
pub mod slot;

pub const PASANG_VERSION: &str = "1.0.0-m3";
