/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.monet

import android.util.Pair
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.android.systemui.monet.ColorScheme
import com.android.systemui.monet.DynamicColors
import com.google.common.truth.Truth.assertWithMessage
import com.google.ux.material.libmonet.dynamiccolor.DynamicColor
import java.util.Locale
import org.junit.Test
import org.junit.runner.RunWith

/**
 * With every knob neutral, the engine must produce exactly what stock SystemUI applies
 * same resource names, same order, same bits.
 */
@RunWith(AndroidJUnit4::class)
class StockParityTest {

    /** ThemeOverlayController.createOverlays + assignColorsToOverlay, as stock runs them. */
    private fun stock(seed: Int, style: Int, contrast: Double): List<String> {
        val dark = ColorScheme(seed, true, style, contrast)
        val light = ColorScheme(seed, false, style, contrast)
        val out = mutableListOf<String>()
        fun assign(colors: List<Pair<String, DynamicColor>>) = colors.forEach { p ->
            val prefix = "android:color/system_" + p.first
            out += "${prefix}_light=" + hex(p.second.getArgb(light.materialScheme))
            out += "${prefix}_dark=" + hex(p.second.getArgb(dark.materialScheme))
        }
        assign(DynamicColors.getAllAccentPalette())
        assign(DynamicColors.getAllNeutralPalette())
        assign(DynamicColors.getAllDynamicColorsMapped())
        assign(DynamicColors.getFixedColorsMapped())
        assign(DynamicColors.getCustomColorsMapped())
        return out
    }

    private fun ours(seed: Int, style: YasStyle, contrast: Double): List<String> {
        val spec = YasColorSpec.Builder().setStyle(style).setPrimary(seed).build()
        val resolved = YasvaraMonet.resolve(spec, seed, contrast, false)
        return (resolved.accent + resolved.neutral + resolved.dynamic).map {
            "${it.resourceName}=" + hex(it.argb)
        }
    }

    @Test
    fun neutralSpecIsByteIdenticalToStock() {
        var cases = 0
        for (style in YasStyle.values().filter { it.isStock() }) {
            for (seed in Seeds.all) {
                for (contrast in Seeds.contrasts) {
                    assertWithMessage("style=$style seed=${hex(seed)} contrast=$contrast")
                        .that(ours(seed, style, contrast))
                        .containsExactlyElementsIn(stock(seed, style.themeStyle, contrast))
                        .inOrder()
                    cases++
                }
            }
        }
        // 9 AOSP styles × 24 seeds × 4 contrast levels, light and dark in each.
        assertWithMessage("cases").that(cases).isEqualTo(9 * 24 * 4)
    }

    @Test
    fun specContrastWinsOverTheSystemContrast() {
        val seed = Seeds.presets[0]
        val spec = YasColorSpec.Builder().setPrimary(seed).setContrast(1.0).build()
        val resolved = YasvaraMonet.resolve(spec, seed, 0.0, false)
        assertWithMessage("contrast").that(resolved.contrast).isEqualTo(1.0)
        assertWithMessage("values")
            .that((resolved.accent + resolved.neutral + resolved.dynamic).map {
                "${it.resourceName}=" + hex(it.argb)
            })
            .containsExactlyElementsIn(stock(seed, YasStyle.TONAL_SPOT.themeStyle, 1.0))
            .inOrder()
    }

    private fun hex(argb: Int) = String.format(Locale.ROOT, "%08X", argb)
}
