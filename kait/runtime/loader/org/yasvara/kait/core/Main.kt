// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yasvara.kait.core

import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.os.ServiceManager
import org.yasvara.kait.Startup
import org.yasvara.kait.impl.core.KaitServiceClient
import org.yasvara.kait.ipc.IFrameworkService
import org.yasvara.kait.util.Log
import org.yasvara.kait.util.Utils

/**
 * Entry point of the Java/Kotlin half of Kait, called through JNI from `libyasvara_kait.so`.
 *
 * The native seam only runs in processes `system_server` flagged with `Zygote.YASVARA_KAIT`.
 * This claims the per-process [IFrameworkService] via a stealth transaction on `activity` and
 * boots the Kait runtime.
 */
object Main {

    /** `ActivityManagerService.onTransact` answers `'_YKP'` only for flagged processes. */
    private const val RENDEZVOUS_CODE =
        ('_'.code shl 24) or ('Y'.code shl 16) or ('K'.code shl 8) or 'P'.code

    @JvmStatic
    fun forkCommon(isSystem: Boolean, niceName: String, appDir: String?) {
        val binder = claimService(niceName)
        if (binder == null) {
            Utils.logD("No Kait service for $niceName; running unhooked")
            return
        }

        val appService = IFrameworkService.Stub.asInterface(binder)
        Startup.initXposed(isSystem, niceName, appDir, appService)

        runCatching { Log.muted = KaitServiceClient.isLogMuted }
            .onFailure { t -> Utils.logE("Failed to configure logs from service", t) }

        Utils.logV("Loading Kait for $niceName (UID: ${Process.myUid()})")
        Startup.bootstrapXposed(false)
    }

    private fun claimService(niceName: String): IBinder? {
        val activity = ServiceManager.getService("activity") ?: return null
        val heartbeat = android.os.Binder()
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        try {
            data.writeString(niceName)
            data.writeStrongBinder(heartbeat)
            if (!activity.transact(RENDEZVOUS_CODE, data, reply, 0)) return null
            reply.readException()
            val service = reply.readStrongBinder() ?: return null
            // Keep the heartbeat alive so system_server observes process death for circuit breaker
            // tracking and active process accounting.
            heartbeats.add(heartbeat)
            return service
        } catch (t: Throwable) {
            Utils.logE("Rendezvous with system_server failed", t)
            return null
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    private val heartbeats = java.util.concurrent.CopyOnWriteArrayList<IBinder>()
}
