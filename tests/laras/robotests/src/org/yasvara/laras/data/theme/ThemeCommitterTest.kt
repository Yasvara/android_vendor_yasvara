/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.laras.data.theme

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ThemeCommitterTest {

    /** An in-memory store that records writes and can fail on one key. */
    private class FakeStore(initial: Map<ThemeKey, String?> = emptyMap()) : ThemeStore {
        val values = initial.toMutableMap()
        val writes = mutableListOf<Pair<ThemeKey, String?>>()
        var failOn: ThemeKey? = null

        override fun read(key: ThemeKey) = values[key]

        override fun write(key: ThemeKey, value: String?) {
            if (key == failOn) {
                failOn = null
                values[key] = "half-written"
                throw IllegalStateException("provider died")
            }
            writes += key to value
            values[key] = value
        }

        override var undo: String? = null
    }

    private class FakeAssets(private val failStage: Boolean = false) : ThemeAssets {
        val calls = mutableListOf<String>()

        override fun stage() {
            calls += "stage"
            if (failStage) throw IllegalStateException("no space")
        }

        override fun promote() {
            calls += "promote"
        }

        override fun discard() {
            calls += "discard"
        }
    }

    private val initial =
        mapOf(
            ThemeKey.COLOR to """{"v":1,"style":"VIBRANT"}""",
            ThemeKey.BATTERY_STYLE to "1",
            ThemeKey.THEME to null,
        )

    @Test
    fun writesChangedKeysInOrder() {
        val store = FakeStore(initial)
        val change =
            ThemeChange(
                mapOf(
                    ThemeKey.PACK to "p",
                    ThemeKey.BATTERY_STYLE to "100",
                    ThemeKey.COLOR to "c",
                    ThemeKey.THEME to "t",
                )
            )

        assertThat(ThemeCommitter(store).commit(change)).isEqualTo(CommitResult.Applied)

        assertThat(store.writes.map { it.first })
            .containsExactly(ThemeKey.COLOR, ThemeKey.THEME, ThemeKey.BATTERY_STYLE, ThemeKey.PACK)
            .inOrder()
    }

    @Test
    fun keysLeftOutAreNotTouched() {
        val store = FakeStore(initial)
        ThemeCommitter(store).commit(ThemeChange(mapOf(ThemeKey.THEME to "t")))

        assertThat(store.writes).containsExactly(ThemeKey.THEME to "t")
    }

    @Test
    fun failedWriteRestoresEverythingWritten() {
        val store = FakeStore(initial).apply { failOn = ThemeKey.BATTERY_STYLE }
        store.undo = "previous"
        val change =
            ThemeChange(
                mapOf(ThemeKey.COLOR to "c", ThemeKey.THEME to "t", ThemeKey.BATTERY_STYLE to "100")
            )

        val result = ThemeCommitter(store).commit(change)

        assertThat(result).isInstanceOf(CommitResult.RolledBack::class.java)
        assertThat((result as CommitResult.RolledBack).key).isEqualTo(ThemeKey.BATTERY_STYLE)
        assertThat(store.values[ThemeKey.COLOR]).isEqualTo(initial[ThemeKey.COLOR])
        assertThat(store.values[ThemeKey.THEME]).isNull()
        assertThat(store.values[ThemeKey.BATTERY_STYLE]).isEqualTo("1")
        // The undo slot still points at what came before the failed apply.
        assertThat(store.undo).isEqualTo("previous")
    }

    @Test
    fun undoRestoresTheSnapshotOnce() {
        val store = FakeStore(initial)
        val committer = ThemeCommitter(store)
        committer.commit(
            ThemeChange(mapOf(ThemeKey.COLOR to null, ThemeKey.THEME to "t", ThemeKey.PACK to "p"))
        )
        assertThat(committer.canUndo()).isTrue()

        assertThat(committer.undo()).isEqualTo(CommitResult.Applied)

        assertThat(store.values[ThemeKey.COLOR]).isEqualTo(initial[ThemeKey.COLOR])
        assertThat(store.values[ThemeKey.THEME]).isNull()
        assertThat(store.values[ThemeKey.PACK]).isNull()
        assertThat(store.values[ThemeKey.BATTERY_STYLE]).isEqualTo("1")
        assertThat(committer.canUndo()).isFalse()
        assertThat(committer.undo()).isInstanceOf(CommitResult.Refused::class.java)
    }

    @Test
    fun undoWritesOnlyWhatDiffers() {
        val store = FakeStore(initial)
        val committer = ThemeCommitter(store)
        committer.commit(ThemeChange(mapOf(ThemeKey.THEME to "t")))
        store.writes.clear()

        committer.undo()

        assertThat(store.writes).containsExactly(ThemeKey.THEME to null)
    }

    @Test
    fun assetsArePromotedAfterTheWrites() {
        val assets = FakeAssets()
        ThemeCommitter(FakeStore(initial)).commit(ThemeChange(mapOf(ThemeKey.THEME to "t")), assets)

        assertThat(assets.calls).containsExactly("stage", "promote").inOrder()
    }

    @Test
    fun assetsThatCannotBeStagedRefuseTheApply() {
        val store = FakeStore(initial)
        val assets = FakeAssets(failStage = true)

        val result = ThemeCommitter(store).commit(ThemeChange(mapOf(ThemeKey.THEME to "t")), assets)

        assertThat(result).isInstanceOf(CommitResult.Refused::class.java)
        assertThat(store.writes).isEmpty()
        assertThat(store.undo).isNull()
        assertThat(assets.calls).containsExactly("stage", "discard").inOrder()
    }

    @Test
    fun failedWriteDiscardsStagedAssets() {
        val store = FakeStore(initial).apply { failOn = ThemeKey.THEME }
        val assets = FakeAssets()

        ThemeCommitter(store).commit(ThemeChange(mapOf(ThemeKey.THEME to "t")), assets)

        assertThat(assets.calls).containsExactly("stage", "discard").inOrder()
    }

    @Test
    fun emptyChangeIsRefused() {
        val store = FakeStore(initial)
        assertThat(ThemeCommitter(store).commit(ThemeChange(emptyMap())))
            .isInstanceOf(CommitResult.Refused::class.java)
        assertThat(store.undo).isNull()
    }

    @Test
    fun unreadableUndoIsNothingToUndo() {
        val store = FakeStore(initial)
        val committer = ThemeCommitter(store)
        for (junk in listOf("", "{", "[]", """{"v":1}""", """{"values":3}""")) {
            store.undo = junk
            assertThat(committer.canUndo()).isFalse()
            assertThat(committer.undo()).isInstanceOf(CommitResult.Refused::class.java)
        }
    }

    @Test
    fun undoSnapshotFromAnOlderBuildKeepsKeysItDoesNotList() {
        val store = FakeStore(initial + (ThemeKey.PACK to "current"))
        store.undo = """{"v":1,"values":{"yasvara_theme":"old"}}"""

        ThemeCommitter(store).undo()

        assertThat(store.values[ThemeKey.THEME]).isEqualTo("old")
        assertThat(store.values[ThemeKey.PACK]).isEqualTo("current")
    }
}
