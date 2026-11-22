// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yasvara.kait.impl.core

import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import io.github.libxposed.service.HookedProcess
import io.github.libxposed.service.IHotReloadCallback
import io.github.libxposed.service.IXposedService
import org.yasvara.kait.ipc.IFrameworkService
import org.yasvara.kait.ipc.IProcessChannel
import org.yasvara.kait.ipc.LoadedModule
import org.yasvara.kait.util.Log

/**
 * Singleton client for IPC communication with Kait's per-process service in `system_server`.
 * Handles Binder death gracefully and attaches [KaitProcessChannel] during bootstrap.
 */
object KaitServiceClient : IFrameworkService, IBinder.DeathRecipient {

    private const val TAG = "KaitServiceClient"

    private var service: IFrameworkService? = null
    var processName: String = ""
        private set

    @Synchronized
    fun init(appService: IFrameworkService?, niceName: String) {
        val binder = appService?.asBinder()
        if (service == null && binder != null) {
            runCatching {
                    service = appService
                    processName = niceName
                    binder.linkToDeath(this, 0)
                }
                .onFailure {
                    Log.e(TAG, "Failed to link to death for service in process: $niceName", it)
                    service = null
                }

            service?.let {
                try {
                    it.attachProcessChannel(KaitProcessChannel)
                } catch (t: Throwable) {
                    Log.e(TAG, "Failed to attach the process channel in process: $niceName", t)
                }
            }
        }
    }

    override fun attachProcessChannel(channel: IProcessChannel?) {
        try {
            service?.attachProcessChannel(channel)
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to attach the process channel", t)
        }
    }

    override fun isLogMuted(): Boolean =
        runCatching { service?.isLogMuted == true }.getOrDefault(false)

    override fun getLegacyModules(): List<LoadedModule> =
        runCatching { service?.legacyModules }.getOrNull() ?: emptyList()

    override fun getModules(): List<LoadedModule> =
        runCatching { service?.modules }.getOrNull() ?: emptyList()

    override fun getPrefsPath(packageName: String): String? =
        runCatching { service?.getPrefsPath(packageName) }.getOrNull()

    override fun openManagerApk(): ParcelFileDescriptor? =
        runCatching { service?.openManagerApk() }.getOrNull()

    override fun openAppDataFile(path: String): ParcelFileDescriptor? =
        runCatching { service?.openAppDataFile(path) }.getOrNull()

    override fun getModuleScope(module: String): List<String> =
        runCatching { service?.getModuleScope(module) }.getOrNull() ?: emptyList()

    override fun setModuleScope(module: String, packages: List<String>) {
        runCatching { service?.setModuleScope(module, packages) }
    }

    override fun getRunningTargets(module: String): List<HookedProcess> =
        runCatching { service?.getRunningTargets(module) }.getOrNull() ?: emptyList()

    override fun hotReloadModule(
        module: String,
        targetId: Long,
        data: Bundle?,
        callback: IHotReloadCallback?,
    ) {
        val svc = service
        if (svc == null) {
            runCatching {
                callback?.onHotReloadResult(
                    IXposedService.HOT_RELOAD_FAILED,
                    "Kait framework service disconnected",
                )
            }
            return
        }
        runCatching { svc.hotReloadModule(module, targetId, data, callback) }
            .onFailure { t ->
                Log.w(TAG, "hotReloadModule failed for $module target=$targetId", t)
                runCatching {
                    callback?.onHotReloadResult(
                        IXposedService.HOT_RELOAD_FAILED,
                        t.message ?: "IPC failure",
                    )
                }
            }
    }

    override fun notifyRemotePreferencesChanged(module: String, group: String, diff: Bundle) {
        runCatching { service?.notifyRemotePreferencesChanged(module, group, diff) }
            .onFailure { Log.w(TAG, "notifyRemotePreferencesChanged failed for $module/$group", it) }
    }

    override fun requestManagerService(): IBinder? =
        runCatching { service?.requestManagerService() }.getOrNull()

    override fun asBinder(): IBinder? = service?.asBinder()

    override fun binderDied() {
        service?.asBinder()?.unlinkToDeath(this, 0)
        service = null
    }
}
