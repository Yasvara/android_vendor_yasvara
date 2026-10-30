/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.laras.depth

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import java.io.File
import java.nio.file.Files
import kotlin.math.abs
import kotlin.math.sqrt
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DepthBuildTest {

    private fun build(): DepthBuild {
        val w = 40
        val h = 70
        val parts = ByteArray(DepthBuild.PARTS * DepthBuild.PARTS)
        // The character in the middle, prop 1 bottom-left, prop 2 top-right.
        for (y in 0 until 256) for (x in 0 until 256) {
            val i = y * 256 + x
            parts[i] = when {
                x in 100..150 && y in 60..200 -> 1
                x in 10..40 && y in 210..250 -> 2
                x in 200..230 && y in 5..30 -> 3
                else -> 0
            }
        }
        return DepthBuild(
            w, h, ByteArray(w * h) { (it % 256).toByte() }, parts, 2,
            listOf(intArrayOf(0, 0, 32, 32), intArrayOf(8, 30, 40, 62)), 12345,
        )
    }

    @Test
    fun buildSurvivesARoundTrip() {
        val dir = Files.createTempDirectory("build").toFile()
        val b = build()
        b.write(dir)
        val read = DepthBuild.read(dir)!!
        assertThat(read.width).isEqualTo(40)
        assertThat(read.height).isEqualTo(70)
        assertThat(read.alpha).isEqualTo(b.alpha)
        assertThat(read.parts).isEqualTo(b.parts)
        assertThat(read.props).isEqualTo(2)
        assertThat(read.tiles.map { it.toList() }).isEqualTo(b.tiles.map { it.toList() })
        assertThat(read.millis).isEqualTo(12345)
        dir.deleteRecursively()
    }

    @Test
    fun unfinishedOrForeignBuildsAreIgnored() {
        val dir = Files.createTempDirectory("build").toFile()
        assertThat(DepthBuild.read(dir)).isNull()
        build().write(dir)
        File(dir, "build.json").writeText(JSONObject(File(dir, "build.json").readText()).put("format", 99).toString())
        assertThat(DepthBuild.read(dir)).isNull()
        dir.deleteRecursively()
    }

    @Test
    fun propsAreFoundByIndex() {
        val b = build()
        assertThat(b.propBounds(1).toList()).isEqualTo(listOf(10, 210, 41, 251))
        assertThat(b.propBounds(2).toList()).isEqualTo(listOf(200, 5, 231, 31))
        assertThat(b.prop(1).count { it == 1f }).isEqualTo(31 * 41)
    }

    @Test
    fun autoAndPartStepsSurviveAProjectRoundTrip() {
        val b = build()
        val project = DepthProject(
            Fingerprint("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 7L),
            400, 700,
            listOf(SelectionOp.Auto(b), SelectionOp.Part(false, 2, b), SelectionOp.Part(true, 2, b)),
            400, 700, 1, 2,
        )
        val json = project.toJson { "op-$it.grid" }
        val read = DepthProject.fromJson(JSONObject(json.toString()), { b }) { _, _, _ -> null }!!
        assertThat(read.ops.map { it::class }).isEqualTo(project.ops.map { it::class })
        val parts = read.ops.filterIsInstance<SelectionOp.Part>()
        assertThat(parts.map { it.index to it.add }).isEqualTo(listOf(2 to false, 2 to true))
        // Without the build those steps cannot be read.
        assertThat(DepthProject.fromJson(JSONObject(json.toString()), { null }) { _, _, _ -> null }).isNull()
    }

    @Test
    fun distanceIsEuclidean() {
        val w = 37
        val h = 23
        val mask = BooleanArray(w * h)
        val seeds = listOf(3 to 4, 30 to 20, 18 to 11)
        seeds.forEach { (x, y) -> mask[y * w + x] = true }
        val d = Raster.distance(mask, w, h)
        for (y in 0 until h) for (x in 0 until w) {
            val want = seeds.minOf { (sx, sy) -> sqrt(((x - sx) * (x - sx) + (y - sy) * (y - sy)).toFloat()) }
            assertThat(abs(d[y * w + x] - want)).isLessThan(1e-3f)
        }
    }

    @Test
    fun areaAveragesWholeBlocksAndInterpolatesWhenEnlarging() {
        // 4x2 -> 2x1: each output is the mean of a 2x2 block.
        val src = floatArrayOf(0f, 2f, 4f, 6f, 2f, 4f, 6f, 8f)
        assertThat(Raster.area(src, 4, 2, 2, 1).toList()).isEqualTo(listOf(2f, 6f))
        // 3 -> 2 (fractional): first output covers 1.5 samples.
        val third = Raster.area(floatArrayOf(0f, 3f, 6f), 3, 1, 2, 1)
        assertThat(third[0]).isWithin(1e-5f).of(1f)
        assertThat(third[1]).isWithin(1e-5f).of(5f)
        // Enlarging 2 -> 4: linear, edges clamped, pixel centres aligned.
        val up = Raster.area(floatArrayOf(0f, 4f), 2, 1, 4, 1)
        assertThat(up.toList()).isEqualTo(listOf(0f, 1f, 3f, 4f))
    }

    @Test
    fun opensAndLabelsComponents() {
        val w = 10
        val h = 6
        val mask = BooleanArray(w * h)
        // A 3x3 block, a lone speck, and a 2x3 bar touching the block's corner diagonally.
        for (y in 1..3) for (x in 1..3) mask[y * w + x] = true
        mask[5 * w + 8] = true
        for (y in 0..2) for (x in 6..7) mask[y * w + x] = true
        val (label, sizes) = Raster.components(mask, w, h)
        assertThat(sizes.sorted()).isEqualTo(listOf(1, 6, 9))
        assertThat(label[5 * w + 8]).isNotEqualTo(label[1 * w + 1])
        val opened = Raster.open3(mask, w, h)
        assertThat(opened[5 * w + 8]).isFalse()
        assertThat(opened[2 * w + 2]).isTrue()
    }

    @Test
    fun foregroundKeepsSolidPixelsAndLiftsTheBackgroundOutOfSoftOnes() {
        // Red subject on a blue background with a soft edge column between them.
        val w = 64
        val h = 48
        val alpha = FloatArray(w * h) { val x = it % w; if (x < 30) 1f else if (x == 30) 0.5f else 0f }
        val red = (0xFF shl 24) or (220 shl 16)
        val blue = (0xFF shl 24) or 220
        // The soft column is half red, half blue, as a picture would show it.
        val mixed = (0xFF shl 24) or (110 shl 16) or 110
        val pixels = IntArray(w * h) { val x = it % w; if (x < 30) red else if (x == 30) mixed else blue }
        val out = Foreground.subject(pixels, alpha, w, h)
        assertThat(out[10 * w + 5]).isEqualTo(red)
        assertThat(out[10 * w + 50]).isEqualTo(0)
        val soft = out[10 * w + 30]
        assertThat(soft ushr 24).isIn(126..129)
        // Its colour is the subject's: far more red than blue.
        assertThat((soft shr 16) and 0xFF).isGreaterThan(180)
        assertThat(soft and 0xFF).isLessThan(60)
    }
}
