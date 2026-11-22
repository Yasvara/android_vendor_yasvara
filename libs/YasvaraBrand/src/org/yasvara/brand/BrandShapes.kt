/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.brand

import androidx.compose.animation.core.FiniteAnimationSpec
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.snap
import androidx.compose.foundation.interaction.InteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.toPath
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Matrix
import androidx.compose.ui.graphics.Outline
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.asComposePath
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import androidx.graphics.shapes.Morph
import androidx.graphics.shapes.RoundedPolygon
import androidx.graphics.shapes.toPath as toAndroidPath

/**
 * The Material 3 Expressive shapes Yasvara surfaces put icons in, and cached morphs between
 * them. Each group of the Settings home owns one shape; a press morphs it to
 * a circle.
 */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
object BrandShapes {
    val Cookie9: RoundedPolygon
        get() = MaterialShapes.Cookie9Sided

    val Clover: RoundedPolygon
        get() = MaterialShapes.Clover4Leaf

    val Pill: RoundedPolygon
        get() = MaterialShapes.Pill

    val Sunny: RoundedPolygon
        get() = MaterialShapes.Sunny

    val Circle: RoundedPolygon
        get() = MaterialShapes.Circle

    private val morphs = HashMap<Pair<RoundedPolygon, RoundedPolygon>, Morph>()

    /** The morph from [from] to [to]. Matching two shapes' features is costly, so it is kept. */
    fun morph(from: RoundedPolygon, to: RoundedPolygon): Morph =
        synchronized(morphs) { morphs.getOrPut(from to to) { Morph(from, to) } }
}

/**
 * Fills this node's bounds with [morph] at [progress], scaled around its centre by [scale].
 * The lambdas are read only while drawing, so animating them redraws without recomposing.
 */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
fun Modifier.morphFill(
    morph: Morph,
    color: () -> Color,
    progress: () -> Float,
    scale: () -> Float = { 1f },
): Modifier = drawWithCache {
    val path = Path()
    val matrix = Matrix()
    var lastProgress = Float.NaN
    onDrawBehind {
        val p = progress()
        if (p != lastProgress) {
            morph.toPath(p, path)
            matrix.reset()
            matrix.scale(size.width, size.height)
            path.transform(matrix)
            lastProgress = p
        }
        val s = scale()
        if (s == 1f) drawPath(path, color()) else scale(s) { drawPath(path, color()) }
    }
}

/** [morph] at a fixed [progress] as a [Shape], for clips and outlines. */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
class MorphShape(private val morph: Morph, private val progress: Float = 0f) : Shape {
    override fun createOutline(size: Size, layoutDirection: LayoutDirection, density: Density):
        Outline {
        val path = morph.toPath(progress, Path())
        path.transform(Matrix().apply { scale(size.width, size.height) })
        return Outline.Generic(path)
    }
}

/**
 * [polygon] (in the unit square, as `MaterialShapes` gives them) as a [Shape], for a container
 * that never morphs. Unlike [MorphShape] it builds no [Morph]: matching a shape's features to
 * itself costs a few milliseconds on a cold start.
 */
class PolygonShape(polygon: RoundedPolygon) : Shape {
    private val unit = polygon.toAndroidPath()

    override fun createOutline(size: Size, layoutDirection: LayoutDirection, density: Density):
        Outline {
        val path = android.graphics.Path(unit)
        path.transform(android.graphics.Matrix().apply { setScale(size.width, size.height) })
        return Outline.Generic(path.asComposePath())
    }
}

/**
 * 0 at rest and 1 while [interactionSource] is pressed or [held], moved with the theme's fast
 * spatial spring (press). Reduced motion snaps.
 */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun pressProgress(interactionSource: InteractionSource, held: Boolean = false): State<Float> {
    val pressed by interactionSource.collectIsPressedAsState()
    val spec: FiniteAnimationSpec<Float> =
        if (LocalReducedMotion.current) snap() else MaterialTheme.motionScheme.fastSpatialSpec()
    return animateFloatAsState(if (pressed || held) 1f else 0f, spec, label = "press")
}
