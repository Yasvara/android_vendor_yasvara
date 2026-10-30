/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.brand

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.AnimationVector1D
import androidx.compose.animation.core.FiniteAnimationSpec
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.geometry.center
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Density
import kotlin.math.sqrt
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * The boot animation's voice ripple: a ring leaves a point, widens and fades out. Each [emit]
 * sends one ring, and once the last one has faded nothing is drawn, so a surface at rest draws
 * no frames (SPEC-0004 §4.1).
 */
@Stable
class VoiceRippleState internal constructor(private val scope: CoroutineScope) {
    internal var spec: FiniteAnimationSpec<Float>? = null
    internal var enabled = true
    internal val rings = mutableStateListOf<Animatable<Float, AnimationVector1D>>()

    /** Whether a ring is on screen. */
    val isRippling: Boolean
        get() = rings.isNotEmpty()

    /** Sends one ring after [delayMillis]. Reduced motion sends none. */
    fun emit(delayMillis: Long = 0L) {
        val spec = spec ?: return
        if (!enabled) return
        scope.launch {
            if (delayMillis > 0) delay(delayMillis)
            val ring = Animatable(0f)
            rings += ring
            try {
                ring.animateTo(1f, spec)
            } finally {
                rings -= ring
            }
        }
    }
}

/** A [VoiceRippleState] whose rings travel with the theme's slow spatial spring. */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun rememberVoiceRippleState(): VoiceRippleState {
    val scope = rememberCoroutineScope()
    val state = remember(scope) { VoiceRippleState(scope) }
    val spec = MaterialTheme.motionScheme.slowSpatialSpec<Float>()
    val enabled = !LocalReducedMotion.current
    SideEffect {
        state.spec = spec
        state.enabled = enabled
    }
    return state
}

/**
 * Draws [state]'s rings behind the content: each starts at [startRadius] around [origin] and
 * fades out as it reaches [reach]. The ring thins as it travels, like the boot animation's.
 */
fun Modifier.voiceRipple(
    state: VoiceRippleState,
    color: Color,
    origin: Density.(Size) -> Offset = { it.center },
    reach: Density.(Size) -> Float = { it.minDimension },
    startRadius: Density.(Size) -> Float = { 0f },
): Modifier = drawBehind {
    val rings = state.rings
    if (rings.isEmpty()) return@drawBehind
    val center = origin(size)
    val end = reach(size)
    val start = startRadius(size)
    for (ring in rings) {
        val p = ring.value.coerceIn(0f, 1f)
        val left = 1f - p
        val alpha = left * sqrt(left)
        if (alpha <= 0f) continue
        drawCircle(
            color = color,
            radius = start + (end - start) * p,
            center = center,
            alpha = alpha,
            style = Stroke(width = end * (RING_END + (RING_START - RING_END) * left)),
        )
    }
}

// Ring width as a fraction of its reach, at the start and at the end of its travel.
private const val RING_START = 0.03f
private const val RING_END = 0.008f
