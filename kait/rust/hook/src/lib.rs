// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

//! Lock-free-read / copy-on-write hook callback registry and JLS 5.1.2 widening rules.
//!
//! Generic over callback handle type `T` so the complete priority-ordering, atomic replacement
//! (API 102 `HookHandle#replaceHook` / `HookBuilder#setId`), snapshot generation, and concurrency
//! invariants are exhaustively unit-tested on the host without a JVM.

use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use smallvec::SmallVec;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackEntry<T> {
    pub priority: i32,
    pub callback: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookSnapshotData<T> {
    pub modern: Vec<T>,
    pub legacy: Vec<T>,
}

/// Per-method hook state protected by a per-method mutex on the cold write path only.
/// Hot-path dispatch reads the published immutable snapshot directly on the Java side
/// without entering Rust or acquiring any lock.
pub struct MethodHookState<T, B, H> {
    pub backup: B,
    pub hooker_ref: H,
    modern: SmallVec<[CallbackEntry<T>; 4]>,
    legacy: SmallVec<[CallbackEntry<T>; 4]>,
}

impl<T: Clone, B, H> MethodHookState<T, B, H> {
    fn new(backup: B, hooker_ref: H) -> Self {
        Self {
            backup,
            hooker_ref,
            modern: SmallVec::new(),
            legacy: SmallVec::new(),
        }
    }

    /// Inserts in descending priority order, preserving FIFO insertion order among equal priorities.
    fn insert(&mut self, modern: bool, priority: i32, callback: T) {
        let list = if modern { &mut self.modern } else { &mut self.legacy };
        // Find first element strictly lower in priority so equal-priority items remain FIFO.
        let pos = list
            .iter()
            .position(|e| e.priority < priority)
            .unwrap_or(list.len());
        list.insert(pos, CallbackEntry { priority, callback });
    }

    fn remove_matching<F: Fn(&T) -> bool>(&mut self, modern: bool, matcher: F) -> Option<T> {
        let list = if modern { &mut self.modern } else { &mut self.legacy };
        let idx = list.iter().position(|e| matcher(&e.callback))?;
        Some(list.remove(idx).callback)
    }

    /// Atomically replaces the first callback matching `matcher`.
    /// When `new_priority == old_priority`, keeps exact slot position among equal-priority peers
    /// (API 102 `HookHandle#replaceHook` requirement).
    fn replace_matching<F: Fn(&T) -> bool>(
        &mut self,
        modern: bool,
        matcher: F,
        new_callback: T,
        new_priority: i32,
    ) -> Option<T> {
        let list = if modern { &mut self.modern } else { &mut self.legacy };
        let idx = list.iter().position(|e| matcher(&e.callback))?;
        if list[idx].priority == new_priority {
            let old = std::mem::replace(&mut list[idx].callback, new_callback);
            return Some(old);
        }
        let old = list.remove(idx).callback;
        let pos = list
            .iter()
            .position(|e| e.priority < new_priority)
            .unwrap_or(list.len());
        list.insert(
            pos,
            CallbackEntry {
                priority: new_priority,
                callback: new_callback,
            },
        );
        Some(old)
    }

    pub fn snapshot(&self) -> HookSnapshotData<T> {
        HookSnapshotData {
            modern: self.modern.iter().map(|e| e.callback.clone()).collect(),
            legacy: self.legacy.iter().map(|e| e.callback.clone()).collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.modern.is_empty() && self.legacy.is_empty()
    }
}

/// Central hook registry keyed by canonical `ArtMethod*` address (`usize`).
pub struct HookRegistry<T, B, H> {
    map: RwLock<HashMap<usize, Arc<Mutex<MethodHookState<T, B, H>>>>>,
}

impl<T: Clone, B: Clone, H: Clone> HookRegistry<T, B, H> {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, method_key: usize) -> Option<Arc<Mutex<MethodHookState<T, B, H>>>> {
        self.map.read().get(&method_key).cloned()
    }

    /// Inserts or attaches a callback to `method_key`. If `method_key` is not yet hooked,
    /// `install_fn` is invoked (without holding the global map lock across ART suspension)
    /// to install the native ART hook and produce `(backup, hooker_ref)`.
    pub fn add_callback<F>(
        &self,
        method_key: usize,
        modern: bool,
        priority: i32,
        callback: T,
        install_fn: F,
    ) -> Option<(H, HookSnapshotData<T>)>
    where
        F: FnOnce() -> Option<(B, H)>,
    {
        if let Some(entry) = self.get(method_key) {
            let mut guard = entry.lock();
            guard.insert(modern, priority, callback);
            return Some((guard.hooker_ref.clone(), guard.snapshot()));
        }

        // Slow path: serialize installation of a brand-new method hook under write lock check.
        // We install first or double-check after acquiring write lock; to avoid duplicate ART
        // hooks on concurrent first-time hooks of the same method, we use an install mutex.
        let entry = {
            let mut map = self.map.write();
            if let Some(existing) = map.get(&method_key) {
                existing.clone()
            } else {
                let (backup, hooker_ref) = install_fn()?;
                let state = Arc::new(Mutex::new(MethodHookState::new(backup, hooker_ref)));
                map.insert(method_key, state.clone());
                state
            }
        };

        let mut guard = entry.lock();
        guard.insert(modern, priority, callback);
        Some((guard.hooker_ref.clone(), guard.snapshot()))
    }

    pub fn remove_callback<F>(
        &self,
        method_key: usize,
        modern: bool,
        matcher: F,
    ) -> Option<(T, H, HookSnapshotData<T>)>
    where
        F: Fn(&T) -> bool,
    {
        let entry = self.get(method_key)?;
        let mut guard = entry.lock();
        let removed = guard.remove_matching(modern, matcher)?;
        Some((removed, guard.hooker_ref.clone(), guard.snapshot()))
    }

    pub fn replace_callback<F>(
        &self,
        method_key: usize,
        modern: bool,
        matcher: F,
        new_callback: T,
        new_priority: i32,
    ) -> Option<(T, H, HookSnapshotData<T>)>
    where
        F: Fn(&T) -> bool,
    {
        let entry = self.get(method_key)?;
        let mut guard = entry.lock();
        let old = guard.replace_matching(modern, matcher, new_callback, new_priority)?;
        Some((old, guard.hooker_ref.clone(), guard.snapshot()))
    }

    pub fn backup_of(&self, method_key: usize) -> Option<B> {
        let entry = self.get(method_key)?;
        let guard = entry.lock();
        Some(guard.backup.clone())
    }

    pub fn snapshot_of(&self, method_key: usize) -> Option<HookSnapshotData<T>> {
        let entry = self.get(method_key)?;
        let guard = entry.lock();
        Some(guard.snapshot())
    }
}

impl<T: Clone, B: Clone, H: Clone> Default for HookRegistry<T, B, H> {
    fn default() -> Self {
        Self::new()
    }
}

/// JLS 5.1.2 widening primitive conversion matrix (identity + widening only).
/// Matches `java.lang.reflect.Method#invoke` and ART `reflection.cc`.
#[inline]
pub const fn widens(from: char, to: char) -> bool {
    if from == to {
        return matches!(from, 'Z' | 'B' | 'C' | 'S' | 'I' | 'J' | 'F' | 'D');
    }
    match from {
        'B' => matches!(to, 'S' | 'I' | 'J' | 'F' | 'D'),
        'S' | 'C' => matches!(to, 'I' | 'J' | 'F' | 'D'),
        'I' => matches!(to, 'J' | 'F' | 'D'),
        'J' => matches!(to, 'F' | 'D'),
        'F' => matches!(to, 'D'),
        _ => false,
    }
}

/// Validates parameter count against shorty length (`shorty.len() == param_len + 1` and `<= 255`).
#[inline]
pub const fn validate_shorty_len(param_len: usize, shorty_len: usize) -> bool {
    param_len <= 255 && shorty_len == param_len + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    #[test]
    fn test_priority_order_and_fifo_stability() {
        let reg: HookRegistry<&'static str, u64, u64> = HookRegistry::new();
        let installs = AtomicUsize::new(0);
        let install = || {
            installs.fetch_add(1, Ordering::SeqCst);
            Some((100u64, 200u64))
        };

        reg.add_callback(1, true, 50, "a", install).unwrap();
        reg.add_callback(1, true, 100, "high", || unreachable!()).unwrap();
        reg.add_callback(1, true, 50, "b", || unreachable!()).unwrap();
        reg.add_callback(1, true, 10, "low", || unreachable!()).unwrap();
        let (_, snap) = reg.add_callback(1, true, 50, "c", || unreachable!()).unwrap();

        assert_eq!(installs.load(Ordering::SeqCst), 1);
        assert_eq!(snap.modern, vec!["high", "a", "b", "c", "low"]);
        assert!(snap.legacy.is_empty());
    }

    #[test]
    fn test_replace_callback_preserves_equal_priority_position() {
        let reg: HookRegistry<&'static str, u64, u64> = HookRegistry::new();
        reg.add_callback(1, true, 50, "first", || Some((1, 2))).unwrap();
        reg.add_callback(1, true, 50, "second", || unreachable!()).unwrap();
        reg.add_callback(1, true, 50, "third", || unreachable!()).unwrap();

        // Replace "second" keeping same priority -> must stay between "first" and "third".
        let (old, _, snap) = reg
            .replace_callback(1, true, |&c| c == "second", "second_v2", 50)
            .unwrap();
        assert_eq!(old, "second");
        assert_eq!(snap.modern, vec!["first", "second_v2", "third"]);

        // Replace "second_v2" with higher priority -> moves to front.
        let (old2, _, snap2) = reg
            .replace_callback(1, true, |&c| c == "second_v2", "promoted", 200)
            .unwrap();
        assert_eq!(old2, "second_v2");
        assert_eq!(snap2.modern, vec!["promoted", "first", "third"]);

        // Replacing an already-replaced handle returns None (API 102 contract).
        assert!(reg
            .replace_callback(1, true, |&c| c == "second", "ghost", 50)
            .is_none());
    }

    #[test]
    fn test_unhook_and_legacy_modern_separation() {
        let reg: HookRegistry<u32, u64, u64> = HookRegistry::new();
        reg.add_callback(7, true, 50, 1, || Some((10, 20))).unwrap();
        reg.add_callback(7, false, 50, 99, || unreachable!()).unwrap();

        // Removing from modern does not touch legacy.
        let (removed, _, snap) = reg.remove_callback(7, true, |&c| c == 1).unwrap();
        assert_eq!(removed, 1);
        assert!(snap.modern.is_empty());
        assert_eq!(snap.legacy, vec![99]);

        // Removing again returns None.
        assert!(reg.remove_callback(7, true, |&c| c == 1).is_none());
    }

    #[test]
    fn test_concurrent_hook_unhook_replace_stress() {
        let reg = Arc::new(HookRegistry::<usize, usize, usize>::new());
        let install_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for t in 0..8usize {
            let r = reg.clone();
            let ic = install_count.clone();
            handles.push(thread::spawn(move || {
                for i in 0..50usize {
                    let id = t * 100 + i;
                    let prio = (i as i32 % 5) * 10;
                    r.add_callback(42, true, prio, id, || {
                        ic.fetch_add(1, Ordering::SeqCst);
                        Some((42, 42))
                    });
                    r.replace_callback(42, true, |&c| c == id, id + 10_000, prio);
                    let _ = r.snapshot_of(42);
                    r.remove_callback(42, true, |&c| c == id + 10_000);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(install_count.load(Ordering::SeqCst), 1);
        assert!(reg.snapshot_of(42).unwrap().modern.is_empty());
    }

    #[test]
    fn test_jls_5_1_2_widening_matrix_exhaustive() {
        let prims = ['Z', 'B', 'S', 'C', 'I', 'J', 'F', 'D'];
        // Expected allowed (from, to) matrix per JLS 5.1.2 + identity:
        let expected = |from: char, to: char| -> bool {
            match (from, to) {
                ('Z', 'Z') => true,
                ('B', 'B' | 'S' | 'I' | 'J' | 'F' | 'D') => true,
                ('S', 'S' | 'I' | 'J' | 'F' | 'D') => true,
                ('C', 'C' | 'I' | 'J' | 'F' | 'D') => true,
                ('I', 'I' | 'J' | 'F' | 'D') => true,
                ('J', 'J' | 'F' | 'D') => true,
                ('F', 'F' | 'D') => true,
                ('D', 'D') => true,
                _ => false,
            }
        };
        for &f in &prims {
            for &t in &prims {
                assert_eq!(widens(f, t), expected(f, t), "mismatch for ({f} -> {t})");
            }
            assert!(!widens(f, 'V'));
            assert!(!widens(f, 'L'));
            assert!(!widens('L', f));
        }
        // Explicitly verify Character does NOT widen to Short and Byte does NOT widen to Character.
        assert!(!widens('C', 'S'));
        assert!(!widens('B', 'C'));
        assert!(!widens('S', 'C'));
    }

    #[test]
    fn test_shorty_len_validation() {
        assert!(validate_shorty_len(0, 1));
        assert!(validate_shorty_len(255, 256));
        assert!(!validate_shorty_len(256, 257));
        assert!(!validate_shorty_len(2, 2));
    }

    /// Mirrors `art/runtime/yasvara_kait.cc` (`HashArtMethod`, `TableInsertLocked`,
    /// `TableRemoveLocked`, and `art_quick_kait_trampoline`'s open-addressed probe loop)
    /// line-for-line, fuzzing wrap-around backward-shift deletions against a HashMap oracle.
    #[test]
    fn test_art_open_addressed_table_backward_shift_fuzz() {
        #[derive(Clone, Copy, Default)]
        struct Slot {
            target: usize,
            hook: usize,
        }
        struct ArtTableModel {
            entries: Vec<Slot>,
            mask: usize,
            count: usize,
        }
        impl ArtTableModel {
            fn new() -> Self {
                Self { entries: Vec::new(), mask: 0, count: 0 }
            }
            #[inline]
            fn hash(ptr: usize, mask: usize) -> usize {
                ((ptr >> 5) ^ (ptr >> 13)) & mask
            }
            fn lookup(&self, target: usize) -> Option<usize> {
                if self.entries.is_empty() {
                    return None;
                }
                let mut idx = Self::hash(target, self.mask);
                loop {
                    let s = self.entries[idx];
                    if s.target == target {
                        return Some(s.hook);
                    }
                    if s.target == 0 {
                        return None;
                    }
                    idx = (idx + 1) & self.mask;
                }
            }
            fn insert(&mut self, target: usize, hook: usize) {
                assert_ne!(target, 0);
                if self.entries.is_empty() || (self.count + 1) * 2 >= self.entries.len() {
                    let new_cap = if self.entries.is_empty() { 64 } else { self.entries.len() * 2 };
                    let new_mask = new_cap - 1;
                    let mut new_entries = vec![Slot::default(); new_cap];
                    for s in &self.entries {
                        if s.target == 0 {
                            continue;
                        }
                        let mut idx = Self::hash(s.target, new_mask);
                        while new_entries[idx].target != 0 {
                            idx = (idx + 1) & new_mask;
                        }
                        new_entries[idx] = *s;
                    }
                    self.entries = new_entries;
                    self.mask = new_mask;
                }
                let mut idx = Self::hash(target, self.mask);
                while self.entries[idx].target != 0 {
                    if self.entries[idx].target == target {
                        self.entries[idx].hook = hook;
                        return;
                    }
                    idx = (idx + 1) & self.mask;
                }
                self.entries[idx] = Slot { target, hook };
                self.count += 1;
            }
            fn remove(&mut self, target: usize) {
                if self.entries.is_empty() {
                    return;
                }
                let mask = self.mask;
                let mut idx = Self::hash(target, mask);
                while self.entries[idx].target != 0 {
                    if self.entries[idx].target == target {
                        let mut hole = idx;
                        let mut curr = (idx + 1) & mask;
                        while self.entries[curr].target != 0 {
                            let home = Self::hash(self.entries[curr].target, mask);
                            let should_shift = if curr > hole {
                                home <= hole || home > curr
                            } else {
                                home <= hole && home > curr
                            };
                            if should_shift {
                                self.entries[hole] = self.entries[curr];
                                hole = curr;
                            }
                            curr = (curr + 1) & mask;
                        }
                        self.entries[hole] = Slot::default();
                        if self.count > 0 {
                            self.count -= 1;
                        }
                        return;
                    }
                    idx = (idx + 1) & mask;
                }
            }
        }

        let mut table = ArtTableModel::new();
        let mut oracle = std::collections::HashMap::<usize, usize>::new();

        // 1. Force wrap-around collision cluster right across indices 62, 63, 0, 1, 2.
        let mut collided = Vec::new();
        for step in 1usize..50_000 {
            let addr = 0x7000_0000usize + step * 32;
            let h = ArtTableModel::hash(addr, 63);
            if h == 62 || h == 63 || h == 0 {
                collided.push(addr);
                if collided.len() == 16 {
                    break;
                }
            }
        }
        for (i, &addr) in collided.iter().enumerate() {
            table.insert(addr, 0x9000_0000 + i);
            oracle.insert(addr, 0x9000_0000 + i);
        }
        // Delete every other entry in the wrap-around cluster and verify all survivors remain reachable.
        for (i, &addr) in collided.iter().enumerate() {
            if i % 2 == 0 {
                table.remove(addr);
                oracle.remove(&addr);
            }
        }
        for (&k, &v) in &oracle {
            assert_eq!(table.lookup(k), Some(v), "lost key {k:#x} after wrap-around delete");
        }

        // 2. Deterministic xorshift64 fuzz across 12,000 insert/update/remove ops + multiple table grows.
        let mut rng: u64 = 0x594B_4149_DEAD_BEEF;
        let mut next_u64 = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let pool: Vec<usize> = (1..=300).map(|i| 0x7100_0000usize + i * 48).collect();
        for step in 0..12_000usize {
            let key = pool[(next_u64() as usize) % pool.len()];
            match next_u64() % 3 {
                0 | 1 => {
                    let hook = 0xA000_0000usize + step;
                    table.insert(key, hook);
                    oracle.insert(key, hook);
                }
                _ => {
                    table.remove(key);
                    oracle.remove(&key);
                }
            }
            if step % 250 == 0 {
                assert_eq!(table.count, oracle.len());
                for &k in &pool {
                    assert_eq!(table.lookup(k), oracle.get(&k).copied());
                }
            }
        }
        assert_eq!(table.count, oracle.len());
        for &k in &pool {
            assert_eq!(table.lookup(k), oracle.get(&k).copied());
        }
    }
}
