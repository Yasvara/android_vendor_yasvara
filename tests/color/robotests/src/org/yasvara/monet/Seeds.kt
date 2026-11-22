/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.yasvara.monet

import com.android.systemui.monet.ColorScheme
import com.google.ux.material.libmonet.hct.Hct

/** The 24 test seeds: the 16 preset seeds and 8 edge cases. */
object Seeds {
    val presets = listOf(
        0xFF1E6FA8.toInt(), // Laut
        0xFF2E7D32.toInt(), // Hutan
        0xFFE0663D.toInt(), // Senja
        0xFF6F4E37.toInt(), // Kopi
        0xFFF4EBD0.toInt(), // Melati
        0xFF3F51B5.toInt(), // Batik Indigo
        0xFFE3A018.toInt(), // Kunyit
        0xFF5B7083.toInt(), // Gunung
        0xFFC2A878.toInt(), // Pasir
        0xFF5C8DAE.toInt(), // Hujan
        0xFFF2A7C3.toInt(), // Sakura
        0xFF9C4DCC.toInt(), // Anggrek
        0xFF36454F.toInt(), // Arang
        0xFFD81B60.toInt(), // Pelangi
        0xFF00897B.toInt(), // Nusantara
        0xFF3D6BE0.toInt(), // Yasvara
    )

    val edges = listOf(
        0xFF808080.toInt(), // pure grey
        0xFFFF0000.toInt(),
        0xFF0000FF.toInt(),
        0xFF0A0A0A.toInt(), // near black
        0xFFF5F5F5.toInt(), // near white
        Hct.from(250.0, 4.9, 50.0).toInt(), // just under the grey-seed threshold
        Hct.from(250.0, 5.1, 50.0).toInt(), // just over it
        ColorScheme.GOOGLE_BLUE,
    )

    val all = presets + edges

    val contrasts = listOf(-1.0, 0.0, 0.5, 1.0)
}
