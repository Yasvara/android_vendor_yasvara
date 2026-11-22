// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yasvara.kait.impl.hooks

/**
 * Immutable Copy-on-Write callback snapshot published atomically onto [KaitNativeHooker.snapshot]
 * by `libyasvara_kait.so` whenever hooks are registered, removed, or replaced.
 *
 * Reading this volatile reference costs a single acquire load on ARM64 — zero JNI calls, zero
 * native lock acquisitions, and zero array copies on the hooked method hot path.
 */
class HookSnapshot(
    @JvmField val modern: Array<KaitHookRecord>,
    @JvmField val legacy: Array<Any?>,
) {
    companion object {
        @JvmField
        val EMPTY = HookSnapshot(emptyArray(), emptyArray())
    }
}
