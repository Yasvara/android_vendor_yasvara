/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.monet

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import com.google.ux.material.libmonet.dynamiccolor.ColorSpec.SpecVersion
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

/** The `yasvara_color` document never breaks a reader. */
@RunWith(AndroidJUnit4::class)
class ColorSpecCodecTest {

    private val full = """
        {"v":1,
         "source":{"type":"preset","which":"lock","index":2},
         "seeds":{"primary":"#FF3D6BE0","secondary":null,"tertiary":"#FFE0913D","neutral":null},
         "overrideMode":"exact",
         "style":"VIBRANT","spec":"2025",
         "chroma":{"a1":1.2,"a2":0.8,"a3":1.0,"n1":1.0,"n2":2.0},
         "wholePalette":true,
         "tint":{"enabled":true,"strength":12},
         "tone":{"surface":-3,"accent":4},
         "contrast":0.5,
         "preset":"laut",
         "fp":"a41c09d2e7b3"}
    """.trimIndent()

    @Test
    fun readsEveryField() {
        val spec = YasColorSpec.parse(full)!!
        assertThat(spec.source).isEqualTo(YasColorSpec.Source.PRESET)
        assertThat(spec.lockWallpaper).isTrue()
        assertThat(spec.sourceIndex).isEqualTo(2)
        assertThat(spec.primary).isEqualTo(0xFF3D6BE0.toInt())
        assertThat(spec.secondary).isNull()
        assertThat(spec.tertiary).isEqualTo(0xFFE0913D.toInt())
        assertThat(spec.overrideMode).isEqualTo(YasColorSpec.OverrideMode.EXACT)
        assertThat(spec.style).isEqualTo(YasStyle.VIBRANT)
        assertThat(spec.specVersion).isEqualTo(SpecVersion.SPEC_2025)
        assertThat(spec.chroma(YasColorSpec.A1)).isEqualTo(1.2)
        assertThat(spec.chroma(YasColorSpec.N2)).isEqualTo(2.0)
        assertThat(spec.wholePalette).isTrue()
        assertThat(spec.tint).isTrue()
        assertThat(spec.tintStrength).isEqualTo(12.0)
        assertThat(spec.surfaceTone).isEqualTo(-3.0)
        assertThat(spec.accentTone).isEqualTo(4.0)
        assertThat(spec.contrast).isEqualTo(0.5)
        assertThat(spec.preset).isEqualTo("laut")
        assertThat(spec.fingerprint).isEqualTo("a41c09d2e7b3")
    }

    @Test
    fun roundTripsExactly() {
        val spec = YasColorSpec.parse(full)!!
        val again = YasColorSpec.parse(spec.toJson(true))!!
        assertThat(again).isEqualTo(spec)
        assertThat(again.toJson(true)).isEqualTo(spec.toJson(true))
    }

    @Test
    fun malformedTextIsNoSpec() {
        for (junk in listOf(null, "", "  ", "{", "[1,2]", "\"text\"", "nope")) {
            assertThat(YasColorSpec.parse(junk)).isNull()
        }
    }

    @Test
    fun emptyObjectIsTheStockSpec() {
        val spec = YasColorSpec.parse("{}")!!
        assertThat(spec.source).isEqualTo(YasColorSpec.Source.WALLPAPER)
        assertThat(spec.style).isEqualTo(YasStyle.TONAL_SPOT)
        assertThat(spec.specVersion).isEqualTo(SpecVersion.SPEC_2026)
        assertThat(spec.contrast).isNull()
        assertThat(spec.changesPalettes()).isFalse()
        assertThat(spec.changesTones()).isFalse()
    }

    @Test
    fun wrongTypesAndRangesFallBackPerField() {
        val spec = YasColorSpec.parse("""
            {"source":{"type":7,"index":99},
             "seeds":{"primary":"blue","tertiary":"#12"},
             "overrideMode":true,"style":"SPARKLY","spec":1999,
             "chroma":{"a1":"much","a2":-4,"a3":1e9,"n1":null},
             "tint":{"enabled":"yes","strength":400},
             "tone":{"surface":-80,"accent":"x"},
             "contrast":7}
        """.trimIndent())!!
        assertThat(spec.source).isEqualTo(YasColorSpec.Source.WALLPAPER)
        assertThat(spec.sourceIndex).isEqualTo(YasColorSpec.MAX_SOURCE_INDEX)
        assertThat(spec.primary).isNull()
        assertThat(spec.tertiary).isNull()
        assertThat(spec.overrideMode).isEqualTo(YasColorSpec.OverrideMode.HUE)
        assertThat(spec.style).isEqualTo(YasStyle.TONAL_SPOT)
        assertThat(spec.specVersion).isEqualTo(SpecVersion.SPEC_2026)
        assertThat(spec.chroma(YasColorSpec.A1)).isEqualTo(1.0)
        assertThat(spec.chroma(YasColorSpec.A2)).isEqualTo(YasColorSpec.CHROMA_MIN)
        assertThat(spec.chroma(YasColorSpec.A3)).isEqualTo(YasColorSpec.CHROMA_MAX)
        assertThat(spec.chroma(YasColorSpec.N1)).isEqualTo(1.0)
        assertThat(spec.tintStrength).isEqualTo(YasColorSpec.TINT_MAX)
        assertThat(spec.surfaceTone).isEqualTo(-YasColorSpec.SURFACE_TONE_MAX)
        assertThat(spec.accentTone).isEqualTo(0.0)
        assertThat(spec.contrast).isEqualTo(1.0)
    }

    @Test
    fun aospStyleNamesAreAccepted() {
        assertThat(YasColorSpec.parse("""{"style":"SPRITZ"}""")!!.style).isEqualTo(YasStyle.NEUTRAL)
    }

    @Test
    fun futureVersionsKeepWhatTheyAdd() {
        val spec = YasColorSpec.parse("""{"v":3,"style":"CMF","sparkle":{"level":2},"z":[1]}""")!!
        assertThat(spec.style).isEqualTo(YasStyle.CMF)
        val written = JSONObject(spec.toJson(true))
        assertThat(written.getJSONObject("sparkle").getInt("level")).isEqualTo(2)
        assertThat(written.getJSONArray("z").getInt(0)).isEqualTo(1)
        assertThat(written.getInt("v")).isEqualTo(YasColorSpec.VERSION)
    }

    @Test
    fun canonicalFormLeavesTheFingerprintOut() {
        val spec = YasColorSpec.parse(full)!!
        assertThat(JSONObject(spec.toJson(false)).has("fp")).isFalse()
        assertThat(JSONObject(spec.toJson(true)).getString("fp")).isEqualTo("a41c09d2e7b3")
    }

    @Test
    fun colours() {
        assertThat(YasColorSpec.parseColor("#3D6BE0")).isEqualTo(0xFF3D6BE0.toInt())
        assertThat(YasColorSpec.parseColor("803D6BE0")).isEqualTo(0x803D6BE0.toInt())
        assertThat(YasColorSpec.parseColor("#GGGGGG")).isNull()
        assertThat(YasColorSpec.formatColor(0xFF3D6BE0.toInt())).isEqualTo("#FF3D6BE0")
    }
}
