// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Stat-fingerprinted cache for `/data/misc/yasvara_attest/policy.bin` consumed by `keystore2`.
//! Fast path: 1 `lstat` syscall per attestation, zero JSON parsing, zero multi-property reads.

use std::io;
use std::path::Path;
use std::sync::{LazyLock, RwLock};
use std::time::Instant;

use log::{info, warn};
use yasvara_integrity_core::contract::{ATTEST_DIR, POLICY_FILENAME};
use yasvara_integrity_core::policy::PolicySnapshot;

use crate::cache::{Failure, FileCache};

static GLOBAL_POLICY: LazyLock<RwLock<FileCache<PolicySnapshot>>> =
    LazyLock::new(|| RwLock::new(FileCache::new()));

/// Returns the cached `PolicySnapshot` from `/data/misc/yasvara_attest/policy.bin`, or `None`
/// if not yet published (e.g. very early boot before `YasvaraAttestationService` starts).
pub fn current() -> Option<PolicySnapshot> {
    let path = format!("{ATTEST_DIR}/{POLICY_FILENAME}");
    let mut store = match GLOBAL_POLICY.write() {
        Ok(s) => s,
        Err(e) => {
            warn!("YasvaraPolicy: lock poisoned: {:?}", e);
            return None;
        }
    };
    let lookup = store.current_bytes(Path::new(&path), Instant::now(), PolicySnapshot::decode);
    if let Some(failure) = lookup.diagnostic {
        if !matches!(failure, Failure::Io { kind: io::ErrorKind::NotFound, .. }) {
            warn!("YasvaraPolicy: {} unavailable: {}", path, failure);
        }
    }
    if lookup.loaded {
        if let Some(snap) = lookup.entry {
            info!(
                "YasvaraPolicy: loaded gen={} tricky={} pif={} targets={} overrides={}",
                snap.generation,
                snap.is_tricky_enabled(),
                snap.is_pif_enabled(),
                snap.targets.len(),
                snap.patch_overrides.len(),
            );
        }
    }
    lookup.entry.cloned()
}
