/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.laras.depth

import android.graphics.PointF
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DepthProjectTest {

    private val sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    @Test
    fun sha256MatchesTheStandardVector() {
        assertThat(Fingerprint.sha256("abc".toByteArray())).isEqualTo(sha)
        assertThat(Fingerprint.isSha(sha)).isTrue()
        assertThat(Fingerprint.isSha(sha.uppercase())).isFalse()
    }

    @Test
    fun dhashSetsABitWhereTheLeftIsBrighter() {
        // Brightness falling left to right: every comparison is "brighter on the left".
        val falling = FloatArray(72) { 255f - (it % 9) * 10f }
        assertThat(Fingerprint.dhash(falling)).isEqualTo(-1L)
        val rising = FloatArray(72) { (it % 9) * 10f }
        assertThat(Fingerprint.dhash(rising)).isEqualTo(0L)
        assertThat(Fingerprint.distance(-1L, 0L)).isEqualTo(64)
        assertThat(Fingerprint.parseHex(Fingerprint.hex(-2L))).isEqualTo(-2L)
    }

    @Test
    fun projectSurvivesARoundTrip() {
        val grid = FloatArray(SelectionOp.SIDE * SelectionOp.SIDE) { (it % 256) / 255f }
        val project = DepthProject(
            Fingerprint(sha, 0x0123456789abcdefL),
            2312, 4096,
            listOf(
                SelectionOp.Matte(true, 3, 2, floatArrayOf(0f, 0.5f, 1f, 1f, 0.5f, 0f)),
                SelectionOp.Region(true, grid),
                SelectionOp.Brush(false, listOf(PointF(0.25f, 0.5f), PointF(0.125f, 0.75f)), 0.03f),
            ),
            2312, 4096,
            created = 1000L,
            modified = 2000L,
        )
        val grids = HashMap<String, ByteArray>()
        val json = project.toJson { n -> "op-$n.grid" }
        project.ops.forEachIndexed { n, op ->
            if (op is SelectionOp.Region) grids["op-$n.grid"] = DepthProject.encodeGrid(op.coverage)
            if (op is SelectionOp.Matte) grids["op-$n.grid"] = DepthProject.encodeGrid(op.coverage)
        }

        val back = DepthProject.fromJson(JSONObject(json.toString())) { name, w, h ->
            grids[name]?.let { DepthProject.decodeGrid(it, w, h) }
        }!!

        assertThat(back.fingerprint).isEqualTo(project.fingerprint)
        assertThat(back.pictureHeight).isEqualTo(4096)
        assertThat(back.created).isEqualTo(1000L)
        val matte = back.ops[0] as SelectionOp.Matte
        assertThat(matte.width to matte.height).isEqualTo(3 to 2)
        assertThat(matte.coverage[1]).isWithin(1f / 255).of(0.5f)
        val region = back.ops[1] as SelectionOp.Region
        assertThat(region.add).isTrue()
        assertThat(region.coverage[255]).isWithin(1f / 255).of(1f)
        assertThat(region.coverage[128]).isWithin(1f / 255).of(128f / 255)
        val brush = back.ops[2] as SelectionOp.Brush
        assertThat(brush.add).isFalse()
        assertThat(brush.radius).isWithin(1e-6f).of(0.03f)
        assertThat(brush.points.map { it.x to it.y }).containsExactly(0.25f to 0.5f, 0.125f to 0.75f).inOrder()
    }

    @Test
    fun aMissingGridOrNewerFormatIsUnreadable() {
        val project = DepthProject(
            Fingerprint(sha, 0L), 10, 20,
            listOf(SelectionOp.Region(true, FloatArray(SelectionOp.SIDE * SelectionOp.SIDE))),
            10, 20, 0L, 0L,
        )
        val json = project.toJson { "op-$it.grid" }
        assertThat(DepthProject.fromJson(json) { _, _, _ -> null }).isNull()
        json.put("format", DepthProject.FORMAT + 1)
        assertThat(DepthProject.fromJson(json) { _, w, h -> FloatArray(w * h) }).isNull()
        assertThat(DepthProject.decodeGrid(ByteArray(10), 3, 3)).isNull()
    }
}
