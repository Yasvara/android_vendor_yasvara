/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.brand

import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.MotionDurationScale
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.withContext

/**
 * The motion rules every Yasvara surface shares. Springs come only from
 * `MaterialTheme.motionScheme` (the expressive scheme): defaultSpatialSpec for morphs and
 * position, fastSpatialSpec for press, slowSpatialSpec for entrances, the effects specs for
 * fades. This object holds the rules that are schedules rather than springs.
 */
object YasvaraMotion {
    /** Delay between the groups of a surface rising in on its entrance. */
    const val STAGGER_MILLIS = 40L
}

/**
 * True when the user turned animations off (animator duration scale 0). Surfaces then replace
 * movement with short fades, snap morphs and keep the mark at rest.
 */
val LocalReducedMotion = staticCompositionLocalOf { false }

/**
 * Runs [block] at the normal animation speed even when the system scale is 0. Compose would
 * otherwise finish every animation in one frame; the reduced-motion fades use this so they
 * still read as a fade rather than a cut.
 */
suspend fun <T> atUnitSpeed(block: suspend CoroutineScope.() -> T): T =
    withContext(UnitSpeed, block)

private object UnitSpeed : MotionDurationScale {
    override val scaleFactor = 1f
}
