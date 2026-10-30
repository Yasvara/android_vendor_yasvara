package org.matrix.vector.core

import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.os.ServiceManager
import org.matrix.vector.Startup
import org.matrix.vector.impl.core.VectorServiceClient
import org.matrix.vector.ipc.IFrameworkService
import org.matrix.vector.util.Log
import org.matrix.vector.util.Utils

/**
 * Entry point of the Java half of the framework, called through JNI from libyasvara_xposed.so.
 *
 * Yasvara: replaces the Zygisk driven `Main` of upstream Vector. The native seam only runs in a
 * process system_server flagged as scoped when it was started, so the one thing left to do here is
 * to claim this process' framework service from system_server and, when it is handed over, boot
 * the Xposed bridge the way upstream does.
 */
object Main {

    /** `ActivityManagerService.onTransact` answers this code for processes it flagged, and only those. */
    private const val RENDEZVOUS_CODE = ('_'.code shl 24) or ('Y'.code shl 16) or ('X'.code shl 8) or 'P'.code

    @JvmStatic
    fun forkCommon(isSystem: Boolean, niceName: String, appDir: String?) {
        val binder = claimService(niceName)
        if (binder == null) {
            Utils.logD("No Xposed service for $niceName; running unhooked")
            return
        }

        val appService = IFrameworkService.Stub.asInterface(binder)
        Startup.initXposed(isSystem, niceName, appDir, appService)

        runCatching { Log.muted = VectorServiceClient.isLogMuted }
            .onFailure { t -> Utils.logE("Failed to configure logs from service", t) }

        Utils.logV("Loading Xposed for $niceName (UID: ${Process.myUid()})")
        Startup.bootstrapXposed(false)
    }

    /**
     * Asks system_server for this process' service. The caller is authenticated by its binder
     * credentials on the other side; a process that was not flagged gets `false` back, which is
     * exactly what an unknown transaction code gets from stock Android.
     */
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
            // Keep the heartbeat alive for the life of the process: system_server watches it to
            // learn the process is gone.
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
