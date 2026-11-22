/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.monet

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith

/** The fingerprint Laras and SystemUI compare after an apply. */
@RunWith(AndroidJUnit4::class)
class FingerprintTest {
    private val seed = Seeds.presets[2]

    @Test
    fun sameSpecSameFingerprint() {
        val spec = YasColorSpec.Builder().setPrimary(seed).setStyle(YasStyle.EXPRESSIVE).build()
        val a = YasvaraMonet.resolve(spec, seed, 0.0, false).fingerprint
        val b = YasvaraMonet.resolve(YasColorSpec.parse(spec.toJson(true))!!, seed, 0.0, false).fingerprint
        assertThat(a).matches("[0-9a-f]{12}")
        assertThat(b).isEqualTo(a)
    }

    @Test
    fun anyChangeChangesIt() {
        val base = YasColorSpec.Builder().setPrimary(seed).build()
        val fp = YasvaraMonet.resolve(base, seed, 0.0, false).fingerprint
        val variants = listOf(
            YasvaraMonet.resolve(base, seed, 0.5, false),
            YasvaraMonet.resolve(base, seed, 0.0, true),
            YasvaraMonet.resolve(base.toBuilder().setStyle(YasStyle.VIBRANT).build(), seed, 0.0, false),
            YasvaraMonet.resolve(base.toBuilder().setChroma(YasColorSpec.A1, 1.5).build(), seed, 0.0, false),
            YasvaraMonet.resolve(base.toBuilder().setTones(2.0, 0.0).build(), seed, 0.0, false),
        ).map { it.fingerprint }
        assertThat(variants).doesNotContain(fp)
        assertThat(variants.toSet()).hasSize(variants.size)
    }
}
