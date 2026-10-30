/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.settings.home

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import com.google.common.truth.Truth.assertWithMessage
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Test
import org.junit.runner.RunWith
import org.w3c.dom.Element

/**
 * SPEC-0004 §10: the Yasvara home's key → group mapping against the stock homepage XMLs of
 * packages/apps/Settings (phone, expressive and desktop). A key a rebase adds fails
 * [everyStockKeyHasASlot] until it is placed on purpose.
 */
@RunWith(AndroidJUnit4::class)
class HomeLayoutTest {

    /** A preference of a homepage XML and the category it sits in (null: the screen root). */
    private data class XmlEntry(val file: String, val key: String, val parentKey: String?)

    private val xmls = listOf(
        "top_level_settings.xml",
        "top_level_settings_expressive.xml",
        "top_level_settings_expressive_desktop.xml",
    )

    private val preferences: List<XmlEntry> by lazy { xmls.flatMap { parse(it).first } }
    private val categories: List<String> by lazy { xmls.flatMap { parse(it).second } }

    @Test
    fun everyStockKeyHasASlot() {
        assertThat(preferences).isNotEmpty()
        for (entry in preferences) {
            assertWithMessage("${entry.file}: ${entry.key} is not placed by HomeLayout")
                .that(HomeLayout.STOCK_KEYS)
                .contains(entry.key)
        }
    }

    @Test
    fun everyStockCategoryIsKnown() {
        assertThat(categories).isNotEmpty()
        assertThat(HomeLayout.STOCK_CATEGORIES).containsAtLeastElementsIn(categories.toSet())
    }

    @Test
    fun layoutPlacesNoKeyTheXmlsLack() {
        assertThat(preferences.map { it.key }.toSet())
            .containsAtLeastElementsIn(HomeLayout.STOCK_KEYS)
    }

    @Test
    fun groupsFollowTheSpec() {
        val expected = mapOf(
            "top_level_network" to HomeGroup.CONNECT,
            "top_level_connected_devices" to HomeGroup.CONNECT,
            "top_level_display" to HomeGroup.DEVICE,
            "top_level_sound" to HomeGroup.DEVICE,
            "top_level_battery" to HomeGroup.DEVICE,
            "top_level_storage" to HomeGroup.DEVICE,
            "top_level_notifications" to HomeGroup.DEVICE,
            "top_level_apps" to HomeGroup.DEVICE,
            "top_level_safety_center" to HomeGroup.PRIVACY,
            "top_level_security" to HomeGroup.PRIVACY,
            "top_level_privacy" to HomeGroup.PRIVACY,
            "top_level_location" to HomeGroup.PRIVACY,
            "top_level_accounts" to HomeGroup.SYSTEM,
            "top_level_accessibility" to HomeGroup.SYSTEM,
            "top_level_emergency" to HomeGroup.SYSTEM,
            "top_level_system" to HomeGroup.SYSTEM,
            "top_level_about_device" to HomeGroup.SYSTEM,
            HomeLayout.LARAS_KEY to HomeGroup.LARAS,
        )
        for ((key, group) in expected) {
            assertWithMessage(key).that(HomeLayout.groupOf(key, null)).isEqualTo(group)
        }
    }

    @Test
    fun stockKeysKeepTheirGroupInAnyCategory() {
        for (entry in preferences) {
            assertWithMessage(entry.key)
                .that(HomeLayout.groupOf(entry.key, entry.parentKey))
                .isEqualTo(HomeLayout.groupOf(entry.key, null))
        }
    }

    @Test
    fun unknownKeyGoesToMore() {
        assertThat(HomeLayout.groupOf("top_level_brand_new", null)).isEqualTo(HomeGroup.MORE)
        assertThat(HomeLayout.groupOf("dashboard_tile_pref_com.example.Tile", "elsewhere"))
            .isEqualTo(HomeGroup.MORE)
        assertThat(HomeLayout.groupOf(null, null)).isEqualTo(HomeGroup.MORE)
    }

    @Test
    fun injectedTileInAStockCategoryJoinsSystem() {
        // Digital Wellbeing and Google inject into stock categories (SPEC-0004 §4.2: System).
        for (category in HomeLayout.STOCK_CATEGORIES) {
            assertWithMessage(category)
                .that(HomeLayout.groupOf("dashboard_tile_pref_com.example.Tile", category))
                .isEqualTo(HomeGroup.SYSTEM)
        }
    }

    @Test
    fun arrangeKeepsEveryEntryOnce() {
        val items = preferences.distinctBy { it.key } +
            XmlEntry("injected", "wellbeing", "top_level_security_privacy_category") +
            XmlEntry("injected", HomeLayout.LARAS_KEY, "top_level_personalize_category") +
            XmlEntry("unknown", "top_level_brand_new", null)
        val arranged = HomeLayout.arrange(items, { it.key }, { it.parentKey })
        val placed = arranged.values.flatten()
        assertThat(placed).containsExactlyElementsIn(items)
        assertThat(arranged.getValue(HomeGroup.MORE).map { it.key }).contains("top_level_brand_new")
    }

    @Test
    fun arrangeFollowsSpecOrderAndStockOrderForTheRest() {
        val stock = listOf(
            XmlEntry("x", "top_level_about_device", "top_level_system_info_category"),
            XmlEntry("x", "top_level_battery", "top_level_system_info_category"),
            XmlEntry("x", "top_level_display", "top_level_personalize_category"),
            XmlEntry("x", "top_level_accounts", "top_level_security_privacy_category"),
            XmlEntry("x", "tile_b", "top_level_account_category"),
            XmlEntry("x", "tile_a", "top_level_support_category"),
            XmlEntry("x", "top_level_priority_modes", "top_level_personalize_category"),
            XmlEntry("x", "top_level_wallpaper", "top_level_personalize_category"),
            XmlEntry("x", "top_level_support", "top_level_support_category"),
            XmlEntry("x", "top_level_communal", "top_level_personalize_category"),
        )
        val arranged = HomeLayout.arrange(stock, { it.key }, { it.parentKey })
        assertThat(arranged.getValue(HomeGroup.DEVICE).map { it.key })
            .containsExactly(
                "top_level_display",
                "top_level_wallpaper",
                "top_level_priority_modes",
                "top_level_battery",
            ).inOrder()
        // System: accounts, injected tiles in stock order, then about.
        assertThat(arranged.getValue(HomeGroup.SYSTEM).map { it.key })
            .containsExactly("top_level_accounts", "tile_b", "tile_a", "top_level_about_device")
            .inOrder()
        // More keeps stock order.
        assertThat(arranged.getValue(HomeGroup.MORE).map { it.key })
            .containsExactly("top_level_support", "top_level_communal").inOrder()
    }

    /** The preferences (with their category) and the category keys of one homepage XML. */
    private fun parse(name: String): Pair<List<XmlEntry>, List<String>> {
        val stream = RESOURCE_DIRS.firstNotNullOfOrNull {
            javaClass.classLoader!!.getResourceAsStream("$it$name")
        }
        assertWithMessage("$name is not among the test's resources").that(stream).isNotNull()
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val root = stream!!.use { factory.newDocumentBuilder().parse(it).documentElement }
        val entries = mutableListOf<XmlEntry>()
        val categoryKeys = mutableListOf<String>()
        fun walk(element: Element, parentKey: String?) {
            val children = element.childNodes
            for (i in 0 until children.length) {
                val child = children.item(i) as? Element ?: continue
                val key = child.getAttributeNS(ANDROID_NS, "key").takeIf { it.isNotEmpty() }
                if (child.tagName.endsWith("PreferenceCategory")) {
                    key?.let(categoryKeys::add)
                    walk(child, key)
                } else if (key != null) {
                    entries += XmlEntry(name, key, parentKey)
                }
            }
        }
        walk(root, null)
        return entries to categoryKeys
    }

    private companion object {
        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
        val RESOURCE_DIRS = listOf("res/xml/", "xml/", "")
    }
}
