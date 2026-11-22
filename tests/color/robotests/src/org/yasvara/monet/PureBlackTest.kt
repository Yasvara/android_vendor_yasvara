/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.monet

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import com.google.common.truth.Truth.assertWithMessage
import com.google.ux.material.libmonet.hct.Hct
import org.junit.Test
import org.junit.runner.RunWith

/** Pure black lives in the generated overlays and keeps the tint (step 7). */
@RunWith(AndroidJUnit4::class)
class PureBlackTest {
    private val seed = Seeds.presets[5]

    private fun resolve(spec: YasColorSpec, pureBlack: Boolean) =
        YasvaraMonet.resolve(spec, seed, 0.0, pureBlack)

    @Test
    fun darkSurfacesGoBlackWithElevationSteps() {
        val black = resolve(YasColorSpec.Builder().setPrimary(seed).build(), true)
        for (role in listOf("background", "surface", "surface_dim", "surface_container_lowest")) {
            assertWithMessage(role).that(black.role(role, true)).isEqualTo(0xFF000000.toInt())
        }
        val steps = listOf("surface_container_low", "surface_container", "surface_container_high",
            "surface_container_highest", "surface_bright").map { Hct.fromInt(black.role(it, true)!!).tone }
        assertThat(steps).isInStrictOrder()
        assertThat(steps.first()).isGreaterThan(0.0)
    }

    @Test
    fun lightSchemeIsUntouched() {
        val spec = YasColorSpec.Builder().setPrimary(seed).build()
        val plain = resolve(spec, false)
        val black = resolve(spec, true)
        val light = { r: YasResolvedScheme ->
            (r.accent + r.neutral + r.dynamic).filter { it.resourceName.endsWith("_light") }
                .map { it.toString() }
        }
        assertThat(light(black)).containsExactlyElementsIn(light(plain)).inOrder()
    }

    @Test
    fun legacyDarkShadesGoBlack() {
        val black = resolve(YasColorSpec.Builder().setPrimary(seed).build(), true)
        assertThat(black.role("neutral1_900", true)).isEqualTo(0xFF000000.toInt())
        assertThat(black.role("neutral2_900", true)).isEqualTo(0xFF000000.toInt())
    }

    @Test
    fun textStaysReadableOnBlack() {
        val black = resolve(YasColorSpec.Builder().setPrimary(seed).build(), true)
        for (pair in YasContrastGuard.pairs(black).filter { it.dark }) {
            assertWithMessage(pair.toString()).that(pair.ratio).isAtLeast(YasContrastGuard.TEXT)
        }
    }

    @Test
    fun tintSurvivesOnElevatedSurfaces() {
        val tinted = YasColorSpec.Builder().setPrimary(seed).setTint(true, 16.0).build()
        val hct = Hct.fromInt(resolve(tinted, true).role("surface_container_highest", true)!!)
        val primaryHue = Hct.fromInt(seed).hue
        assertThat(hct.chroma).isGreaterThan(4.0)
        val distance = Math.abs(hct.hue - primaryHue) % 360.0
        assertThat(minOf(distance, 360.0 - distance)).isLessThan(30.0)
    }
}
