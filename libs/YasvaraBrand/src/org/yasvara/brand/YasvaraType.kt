/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

@file:OptIn(ExperimentalTextApi::class)

package org.yasvara.brand

import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import java.io.File

/**
 * Google Sans Flex at an exact weight and roundness, for the expressive numbers and titles of
 * Yasvara surfaces (the wordmark's face, `ROND` 100). The system ships the variable font in
 * /system/fonts; a build without it falls back to the default family at the nearest weight.
 * Families are cached per (weight, roundness): each one is a separate typeface.
 */
object YasvaraType {
    private val file = File("/system/fonts/GoogleSansFlex-Regular.ttf")
    private val available by lazy { file.canRead() }
    private val cache = HashMap<Long, FontFamily>()

    /** Google Sans Flex at [weight] (1–1000) and [round] (0 square … 100 fully round). */
    fun flex(weight: Int, round: Int = 100): FontFamily {
        if (!available) return FontFamily.Default
        val key = (weight.toLong() shl 32) or round.toLong()
        return synchronized(cache) {
            cache.getOrPut(key) {
                FontFamily(
                    Font(
                        file,
                        FontWeight(weight.coerceIn(1, 1000)),
                        variationSettings = FontVariation.Settings(
                            FontVariation.weight(weight.coerceIn(1, 1000)),
                            FontVariation.Setting("ROND", round.toFloat()),
                        ),
                    ),
                )
            }
        }
    }
}
