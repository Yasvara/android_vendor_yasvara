/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.monet

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PresetsAndMirrorTest {

    @Test
    fun sixteenPresetsWithSeeds() {
        val presets = YasPresets.all()
        assertThat(presets).hasSize(16)
        assertThat(presets.map { it.id }.toSet()).hasSize(16)
        for (preset in presets) {
            assertThat(preset.spec.source).isEqualTo(YasColorSpec.Source.PRESET)
            assertThat(preset.spec.primary).isNotNull()
            assertThat(preset.spec.preset).isEqualTo(preset.id)
        }
        assertThat(YasPresets.find("laut")!!.name).isEqualTo("Laut")
        assertThat(YasPresets.find("nope")).isNull()
    }

    @Test
    fun presetSeedsAreTheTestSeeds() {
        assertThat(YasPresets.all().map { it.spec.primary }).containsExactlyElementsIn(Seeds.presets)
    }

    @Test
    fun mirrorWritesBaseFieldsAndKeepsTheRest() {
        val aosp = """{"android.theme.customization.font":"com.example.font",
            "android.theme.customization.adaptive_icon_shape":"com.example.shape",
            "android.theme.customization.color_both":"0"}"""
        val spec = YasColorSpec.Builder().setSource(YasColorSpec.Source.WALLPAPER, true, 2)
            .setStyle(YasStyle.FIDELITY).build()
        val out = JSONObject(YasAospMirror.mirror(aosp, spec, 0xFF123456.toInt(), 42L))
        assertThat(out.getString("android.theme.customization.font")).isEqualTo("com.example.font")
        assertThat(out.getString("android.theme.customization.adaptive_icon_shape"))
            .isEqualTo("com.example.shape")
        assertThat(out.getString(YasAospMirror.COLOR_BOTH)).isEqualTo("0")
        assertThat(out.getString(YasAospMirror.COLOR_SOURCE)).isEqualTo("lock_wallpaper")
        assertThat(out.getString(YasAospMirror.COLOR_INDEX)).isEqualTo("2")
        assertThat(out.getString(YasAospMirror.SYSTEM_PALETTE)).isEqualTo("123456")
        assertThat(out.getString(YasAospMirror.ACCENT_COLOR)).isEqualTo("123456")
        // AOSP has no Fidelity; the nearest stock style is Content.
        assertThat(out.getString(YasAospMirror.THEME_STYLE)).isEqualTo("CONTENT")
        assertThat(out.getLong(YasAospMirror.TIMESTAMP)).isEqualTo(42L)
    }

    @Test
    fun presetSourcesMirrorAsPreset() {
        val spec = YasPresets.find("hutan")!!.spec
        val out = JSONObject(YasAospMirror.mirror(null, spec, spec.primary!!, 1L))
        assertThat(out.getString(YasAospMirror.COLOR_SOURCE)).isEqualTo("preset")
        assertThat(out.has(YasAospMirror.COLOR_INDEX)).isFalse()
        assertThat(out.getString(YasAospMirror.THEME_STYLE)).isEqualTo("TONAL_SPOT")
    }

    @Test
    fun migratesStockAndOtherRoms() {
        val stock = YasAospMirror.migrate("""{"android.theme.customization.system_palette":"3D6BE0",
            "android.theme.customization.theme_style":"SPRITZ",
            "android.theme.customization.color_source":"preset"}""")
        assertThat(stock.source).isEqualTo(YasColorSpec.Source.CUSTOM)
        assertThat(stock.primary).isEqualTo(0xFF3D6BE0.toInt())
        assertThat(stock.style).isEqualTo(YasStyle.NEUTRAL)

        val evox = YasAospMirror.migrate("""{"android.theme.customization.color_source":"lock_wallpaper",
            "android.theme.customization.color_index":"3","_chroma_boost":50,"_luminance_factor":0.9}""")
        assertThat(evox.source).isEqualTo(YasColorSpec.Source.WALLPAPER)
        assertThat(evox.lockWallpaper).isTrue()
        assertThat(evox.sourceIndex).isEqualTo(3)
        assertThat(evox.chroma(YasColorSpec.A1)).isEqualTo(1.5)
        assertThat(evox.changesTones()).isFalse()

        assertThat(YasAospMirror.migrate("not json").style).isEqualTo(YasStyle.TONAL_SPOT)
    }
}
