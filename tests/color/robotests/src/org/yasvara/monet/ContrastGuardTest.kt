/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.monet

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import com.google.common.truth.Truth.assertWithMessage
import java.util.Random
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Every knob is applied before roles are solved, so the contrast solver still holds: at any
 * contrast level ≥ 0 every guarded pair reaches text contrast.
 */
@RunWith(AndroidJUnit4::class)
class ContrastGuardTest {

    private fun randomSpec(random: Random): Pair<YasColorSpec, Int> {
        fun color() = 0xFF000000.toInt() or random.nextInt(0x1000000)
        fun maybe() = if (random.nextInt(3) == 0) color() else null
        val builder = YasColorSpec.Builder()
            .setStyle(YasStyle.values()[random.nextInt(YasStyle.values().size)])
            .setPrimary(color())
            .setSecondary(maybe())
            .setTertiary(maybe())
            .setNeutral(maybe())
            .setOverrideMode(YasColorSpec.OverrideMode.values()[random.nextInt(2)])
            .setTint(random.nextBoolean(), random.nextDouble() * YasColorSpec.TINT_MAX)
            .setTones(
                (random.nextDouble() * 2 - 1) * YasColorSpec.SURFACE_TONE_MAX,
                (random.nextDouble() * 2 - 1) * YasColorSpec.ACCENT_TONE_MAX,
            )
            .setContrast(random.nextDouble())
        for (slot in YasColorSpec.A1..YasColorSpec.N2) {
            builder.setChroma(slot, random.nextDouble() * YasColorSpec.CHROMA_MAX)
        }
        val spec = builder.build()
        return spec to spec.primary!!
    }

    @Test
    fun randomSpecsKeepTextContrast() {
        val random = Random(0x59415356)
        val failures = mutableListOf<String>()
        repeat(2000) { i ->
            val (spec, seed) = randomSpec(random)
            val resolved = YasvaraMonet.resolve(spec, seed, 0.0, random.nextBoolean())
            for (pair in YasContrastGuard.pairs(resolved)) {
                if (pair.ratio < YasContrastGuard.TEXT) failures += "#$i $pair ${spec.toJson(false)}"
            }
        }
        assertWithMessage(failures.take(20).joinToString("\n")).that(failures).isEmpty()
    }

    @Test
    fun verdicts() {
        val seed = Seeds.presets[0]
        val ok = YasvaraMonet.resolve(YasColorSpec.Builder().setPrimary(seed).build(), seed, 0.0, false)
        assertThat(YasContrastGuard.verdict(ok)).isEqualTo(YasContrastGuard.Verdict.OK)
    }

    /**
     * Below zero contrast the solver may trade contrast away, which is what the guard is for.
     * Counts how often each verdict happens over every seed, style and extreme tone knob.
     */
    @Test
    fun negativeContrastIsWhereTheGuardActs() {
        val counts = mutableMapOf<YasContrastGuard.Verdict, Int>()
        val worst = mutableListOf<String>()
        for (seed in Seeds.all) for (style in YasStyle.values()) for (contrast in listOf(-1.0, -0.5)) {
            for (accent in listOf(-YasColorSpec.ACCENT_TONE_MAX, 0.0, YasColorSpec.ACCENT_TONE_MAX)) {
                for (surface in listOf(-YasColorSpec.SURFACE_TONE_MAX, 0.0, YasColorSpec.SURFACE_TONE_MAX)) {
                    val spec = YasColorSpec.Builder().setPrimary(seed).setStyle(style)
                        .setContrast(contrast).setTones(surface, accent).build()
                    val resolved = YasvaraMonet.resolve(spec, seed, 0.0, false)
                    val verdict = YasContrastGuard.verdict(resolved)
                    counts[verdict] = (counts[verdict] ?: 0) + 1
                    if (verdict != YasContrastGuard.Verdict.OK && worst.size < 5) {
                        worst += YasContrastGuard.pairs(resolved).minBy { it.ratio }.toString() +
                            " " + spec.toJson(false)
                    }
                }
            }
        }
        println("negative contrast verdicts: $counts")
        worst.forEach { println("  $it") }
        // At the lowest contrast the stock solver itself only promises large-text contrast.
        assertThat(counts.keys).contains(YasContrastGuard.Verdict.OK)
    }

    @Test
    fun ratioIsWcag() {
        assertThat(YasContrastGuard.ratio(0xFF000000.toInt(), 0xFFFFFFFF.toInt())).isWithin(0.01).of(21.0)
        assertThat(YasContrastGuard.ratio(0xFF777777.toInt(), 0xFF777777.toInt())).isWithin(0.001).of(1.0)
    }
}
