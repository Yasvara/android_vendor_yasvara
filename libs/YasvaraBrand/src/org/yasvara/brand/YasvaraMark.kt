/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.brand

import androidx.compose.animation.core.Animatable
import androidx.compose.foundation.layout.Spacer
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.min
import kotlin.math.sin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.yasvara.brand.YasvaraMarkGeometry.BOX
import org.yasvara.brand.YasvaraMarkGeometry.JUNCTION_X
import org.yasvara.brand.YasvaraMarkGeometry.JUNCTION_Y
import org.yasvara.brand.YasvaraMarkGeometry.STROKE

/** What the Yasvara mark shows (SPEC-0004 §4.1). */
enum class MarkState {
    /** Draws itself from the junction outward, like the boot animation. Played once. */
    Draw,

    /** The mark at rest. */
    Rest,

    /** Charging: a wave travels out along the trough once, then holds as a still pose. */
    Flow,

    /** Battery low: the trough flattens to 40% of its depth. */
    Low,

    /** One voice ripple from the trough's lowest point. Played once. */
    Ripple,

    /** Three ripples and a colour sweep, for the easter egg and Welcome. Played once. */
    Celebrate,
}

/**
 * The mark's pose ([MarkState.Rest], [MarkState.Flow] or [MarkState.Low]) plus the one-shot
 * states played on top of it. Everything settles after each change: the mark never loops.
 */
@Stable
class YasvaraMarkState internal constructor(pose: MarkState, drawn: Float) {
    private var _pose by mutableStateOf(pose.coerceToPose())

    /** The resting pose. One-shot states passed here are ignored; use [play]. */
    var pose: MarkState
        get() = _pose
        set(value) {
            _pose = value.coerceToPose()
        }

    internal var draws by mutableIntStateOf(0)
    internal var celebrations by mutableIntStateOf(0)
    internal var ripple: VoiceRippleState? = null

    internal val drawn = Animatable(drawn)
    internal val depth = Animatable(pose.coerceToPose().depth)
    internal val flow = Animatable(if (pose == MarkState.Flow) 1f else 0f)
    internal val phase = Animatable(0f)
    internal val sweep = Animatable(0f)

    /** Plays [state]: a one-shot state runs once, a pose becomes the new [pose]. */
    fun play(state: MarkState) {
        when (state) {
            MarkState.Draw -> draws++
            MarkState.Ripple -> ripple?.emit()
            MarkState.Celebrate -> celebrations++
            else -> pose = state
        }
    }
}

/**
 * A [YasvaraMarkState] at [pose]. With [drawOnStart] the mark starts undrawn and draws itself
 * on its first frame (callers still [YasvaraMarkState.play] [MarkState.Draw] to run it).
 */
@Composable
fun rememberYasvaraMarkState(
    pose: MarkState = MarkState.Rest,
    drawOnStart: Boolean = false,
): YasvaraMarkState {
    val reduced = LocalReducedMotion.current
    return remember { YasvaraMarkState(pose, if (drawOnStart && !reduced) 0f else 1f) }
}

/**
 * The Yasvara mark in [color], drawn to fit its bounds. Motion comes from the theme's motion
 * scheme; under reduced motion the mark stays at rest and one-shot states do nothing.
 */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun YasvaraMark(
    state: YasvaraMarkState,
    modifier: Modifier = Modifier,
    color: Color = MaterialTheme.colorScheme.primary,
    rippleColor: Color = color,
    sweepColor: Color = MaterialTheme.colorScheme.tertiary,
    /** How far ripples travel from the junction, as a fraction of the mark's size. */
    rippleReach: Float = 0.9f,
    contentDescription: String? = null,
) {
    val motion = MaterialTheme.motionScheme
    val reduced = LocalReducedMotion.current
    val ripple = rememberVoiceRippleState()
    SideEffect { state.ripple = ripple }

    LaunchedEffect(state, reduced) {
        var first = true
        snapshotFlow { state.pose }.collectLatest { pose ->
            val depth = if (reduced) 1f else pose.depth
            val flow = if (!reduced && pose == MarkState.Flow) 1f else 0f
            if (first || reduced) {
                first = false
                state.depth.snapTo(depth)
                state.flow.snapTo(flow)
                return@collectLatest
            }
            // One ripple per state change (§4.1), then the new pose holds still.
            ripple.emit()
            coroutineScope {
                launch { state.depth.animateTo(depth, motion.defaultSpatialSpec()) }
                launch { state.flow.animateTo(flow, motion.defaultSpatialSpec()) }
                if (flow > 0f) {
                    state.phase.snapTo(0f)
                    state.phase.animateTo(1f, motion.slowSpatialSpec())
                }
            }
        }
    }
    LaunchedEffect(state.draws, reduced) {
        if (state.draws == 0) return@LaunchedEffect
        if (reduced) {
            state.drawn.snapTo(1f)
            return@LaunchedEffect
        }
        state.drawn.snapTo(0f)
        state.drawn.animateTo(1f, motion.slowSpatialSpec())
    }
    LaunchedEffect(state.celebrations, reduced) {
        if (state.celebrations == 0 || reduced) return@LaunchedEffect
        repeat(CELEBRATE_RIPPLES) { ripple.emit(it * CELEBRATE_GAP * YasvaraMotion.STAGGER_MILLIS) }
        state.sweep.animateTo(1f, motion.slowSpatialSpec())
        state.sweep.animateTo(0f, motion.slowEffectsSpec())
    }

    val described = if (contentDescription != null) {
        Modifier.semantics {
            this.contentDescription = contentDescription
            role = Role.Image
        }
    } else {
        Modifier
    }
    Spacer(
        modifier
            .then(described)
            .voiceRipple(
                ripple,
                rippleColor,
                origin = { markFrame(it).junction },
                reach = { min(it.width, it.height) * rippleReach },
                startRadius = { markFrame(it).stroke / 2f },
            )
            .drawWithCache {
                val frame = markFrame(size)
                val path = Path()
                val stroke = Stroke(
                    width = frame.stroke,
                    cap = StrokeCap.Round,
                    join = StrokeJoin.Round,
                )
                onDrawBehind {
                    buildMarkPath(
                        path,
                        frame,
                        drawn = state.drawn.value,
                        depth = state.depth.value,
                        flow = state.flow.value,
                        phase = state.phase.value,
                    )
                    val sweep = state.sweep.value
                    if (sweep > 0.001f) {
                        val edge = sweep.coerceIn(0f, 1f)
                        val brush = Brush.radialGradient(
                            0f to sweepColor,
                            edge to sweepColor,
                            (edge + SWEEP_SOFTNESS).coerceAtMost(1f) to color,
                            center = frame.junction,
                            radius = frame.scale * BOX,
                        )
                        drawPath(path, brush, style = stroke)
                    } else {
                        drawPath(path, color, style = stroke)
                    }
                }
            },
    )
}

/** Where the design box sits in a drawing area: centred, as large as fits. */
internal class MarkFrame(val scale: Float, val left: Float, val top: Float) {
    val stroke = STROKE * scale
    val junction = Offset(left + JUNCTION_X * scale, top + JUNCTION_Y * scale)
}

internal fun markFrame(size: Size): MarkFrame {
    val scale = min(size.width, size.height) / BOX
    return MarkFrame(scale, (size.width - BOX * scale) / 2f, (size.height - BOX * scale) / 2f)
}

/**
 * Builds the mark into [path]: each stroke trimmed to [drawn] by arc length from the junction,
 * the arms flattened towards the junction by [depth] and rippled by [flow] at [phase].
 */
internal fun buildMarkPath(
    path: Path,
    frame: MarkFrame,
    drawn: Float,
    depth: Float,
    flow: Float,
    phase: Float,
) {
    path.rewind()
    for (i in MarkPolylines.strokes.indices) {
        val arm = i < 2
        val t = if (arm) segment(drawn, 0f, ARM_DRAW_END) else segment(drawn, STEM_DRAW_START, 1f)
        if (t <= 0f) continue
        val pts = MarkPolylines.strokes[i]
        val cum = MarkPolylines.lengths[i]
        val last = cum.size - 1
        var k = 0
        while (k < last && cum[k + 1] <= t) k++
        for (j in 0..k) {
            point(pts[j * 2], pts[j * 2 + 1], arm, depth, flow, phase, frame) { x, y ->
                if (j == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
        }
        if (k < last && t > cum[k]) {
            val f = (t - cum[k]) / (cum[k + 1] - cum[k])
            val x = pts[k * 2] + (pts[k * 2 + 2] - pts[k * 2]) * f
            val y = pts[k * 2 + 1] + (pts[k * 2 + 3] - pts[k * 2 + 1]) * f
            point(x, y, arm, depth, flow, phase, frame) { px, py -> path.lineTo(px, py) }
        }
    }
}

private inline fun point(
    x: Float,
    y: Float,
    arm: Boolean,
    depth: Float,
    flow: Float,
    phase: Float,
    frame: MarkFrame,
    out: (Float, Float) -> Unit,
) {
    var py = y
    if (arm) {
        py = JUNCTION_Y - (JUNCTION_Y - y) * depth
        if (flow > 0f) {
            // A standing-still wave along the arm, zero at the junction so the stem stays on.
            val d = abs(x - JUNCTION_X) / MarkPolylines.armReach
            py += FLOW_DEPTH * flow * d * sin((2 * PI * (d * FLOW_CYCLES - phase)).toFloat())
        }
    }
    out(frame.left + x * frame.scale, frame.top + py * frame.scale)
}

private fun segment(t: Float, from: Float, to: Float) = ((t - from) / (to - from)).coerceIn(0f, 1f)

/** The generated strokes plus their normalized cumulative arc lengths, computed once. */
private object MarkPolylines {
    val strokes: List<FloatArray> = YasvaraMarkGeometry.Strokes
    val lengths: List<FloatArray> = strokes.map { pts ->
        val n = pts.size / 2
        val cum = FloatArray(n)
        for (i in 1 until n) {
            val dx = pts[i * 2] - pts[i * 2 - 2]
            val dy = pts[i * 2 + 1] - pts[i * 2 - 1]
            cum[i] = cum[i - 1] + kotlin.math.sqrt(dx * dx + dy * dy)
        }
        val total = cum[n - 1]
        if (total > 0f) for (i in 0 until n) cum[i] /= total
        cum
    }
    val armReach: Float = strokes.take(2).maxOf { pts ->
        (0 until pts.size / 2).maxOf { abs(pts[it * 2] - JUNCTION_X) }
    }
}

private fun MarkState.coerceToPose() = when (this) {
    MarkState.Flow, MarkState.Low -> this
    else -> MarkState.Rest
}

private val MarkState.depth
    get() = if (this == MarkState.Low) LOW_DEPTH else 1f

/** Trough depth at [MarkState.Low] (§4.1: "amplitude eases to 40%"). */
private const val LOW_DEPTH = 0.4f

// Flow's still pose: wave height in design units and waves per arm.
private const val FLOW_DEPTH = 26f
private const val FLOW_CYCLES = 1.5f

// Draw: the arms lead and the stem follows, as in the boot animation's outro.
private const val ARM_DRAW_END = 0.85f
private const val STEM_DRAW_START = 0.2f

// Celebrate: three ripples, three stagger steps apart; the sweep's soft edge.
private const val CELEBRATE_RIPPLES = 3
private const val CELEBRATE_GAP = 3
private const val SWEEP_SOFTNESS = 0.2f
