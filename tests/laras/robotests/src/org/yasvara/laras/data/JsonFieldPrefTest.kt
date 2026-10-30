/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.laras.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class JsonFieldPrefTest {

    private enum class IconSet(val id: String) : ChoiceOption {
        DEFAULT("aosp"),
        DOTS("yas-dots");

        override val value: Int get() = ordinal
        override val label: Int get() = 0
    }

    private val pref =
        JsonFieldPref(
            Namespace.SECURE, "yasvara_theme", "statusIcons",
            IconSet.entries, IconSet.DEFAULT, IconSet::id,
        )

    @Test
    fun mergeKeepsTheOtherFields() {
        val merged = JSONObject(pref.merge("""{"v":1,"iconShape":"cookie9"}""", IconSet.DOTS)!!)

        assertThat(merged.getString("statusIcons")).isEqualTo("yas-dots")
        assertThat(merged.getString("iconShape")).isEqualTo("cookie9")
        assertThat(merged.getInt("v")).isEqualTo(1)
    }

    @Test
    fun theDefaultRemovesTheField() {
        val merged =
            JSONObject(
                pref.merge("""{"v":1,"statusIcons":"yas-dots","iconShape":"cookie9"}""", IconSet.DEFAULT)!!
            )

        assertThat(merged.has("statusIcons")).isFalse()
        assertThat(merged.getString("iconShape")).isEqualTo("cookie9")
    }

    @Test
    fun removingTheLastFieldDeletesTheSetting() {
        assertThat(pref.merge("""{"v":1,"statusIcons":"yas-dots"}""", IconSet.DEFAULT)).isNull()
        assertThat(pref.merge(null, IconSet.DEFAULT)).isNull()
    }

    @Test
    fun anUnreadableObjectIsReplaced() {
        val merged = JSONObject(pref.merge("{not json", IconSet.DOTS)!!)

        assertThat(merged.getString("statusIcons")).isEqualTo("yas-dots")
        assertThat(merged.getInt("v")).isEqualTo(1)
    }

    @Test
    fun decodeFallsBackToTheDefault() {
        assertThat(pref.decode(null)).isEqualTo(IconSet.DEFAULT)
        assertThat(pref.decode("{not json")).isEqualTo(IconSet.DEFAULT)
        assertThat(pref.decode("""{"statusIcons":"from-a-newer-build"}""")).isEqualTo(IconSet.DEFAULT)
        assertThat(pref.decode("""{"v":1,"statusIcons":"yas-dots"}""")).isEqualTo(IconSet.DOTS)
    }
}
