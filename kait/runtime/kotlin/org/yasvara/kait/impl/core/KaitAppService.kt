// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yasvara.kait.impl.core

import android.app.ActivityThread
import android.content.Context
import android.os.Bundle
import android.os.ParcelFileDescriptor
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.service.HookedProcess
import io.github.libxposed.service.IHotReloadCallback
import io.github.libxposed.service.IXposedScopeCallback
import io.github.libxposed.service.IXposedService
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import org.yasvara.kait.impl.BuildConfig
import org.yasvara.kait.impl.hooks.KaitHookBuilder
import org.yasvara.kait.util.Log

private const val TAG = "KaitAppService"
private val GROUP_PATTERN = Regex("[A-Za-z0-9._-]{1,128}")
private val FILE_PATTERN = Regex("[A-Za-z0-9._-]{1,128}")

/**
 * The module UI's end of the modern libxposed API 101/102 service, delivered via `XposedProvider`
 * inside a self-injected module process.
 *
 * - Preferences & remote files are stored locally under the module's own uid, AND diffs are
 *   broadcast live to all hooked processes via [KaitServiceClient.notifyRemotePreferencesChanged].
 * - Running targets & live hot reload route directly through `system_server` over
 *   [KaitServiceClient.getRunningTargets] and [KaitServiceClient.hotReloadModule].
 */
class KaitAppService(
    private val packageName: String,
) : IXposedService.Stub() {

    companion object {
        private val delivered = AtomicBoolean(false)

        @JvmStatic
        fun deliverForSelf(modulePackageName: String, processName: String) {
            if (modulePackageName != processName || !delivered.compareAndSet(false, true)) return
            runCatching {
                ActivityThread::class.java.declaredMethods
                    .filter { it.name == "handleBindApplication" }
                    .forEach { KaitHookBuilder(it).intercept(BindHooker(modulePackageName)) }
            }.onFailure { Log.w(TAG, "Cannot arm UI service for $modulePackageName", it) }
        }

        private fun sendBinder(modulePackageName: String) {
            val app = ActivityThread.currentApplication() ?: return
            val authority = modulePackageName + IXposedService.AUTHORITY_SUFFIX
            val provider = app.packageManager.resolveContentProvider(authority, 0)
            if (provider?.packageName != modulePackageName) return
            val extras = Bundle().apply { putBinder("binder", KaitAppService(modulePackageName)) }
            app.contentResolver.call(authority, IXposedService.SEND_BINDER, null, extras)
        }
    }

    private class BindHooker(private val modulePackageName: String) : XposedInterface.Hooker {
        override fun intercept(chain: XposedInterface.Chain): Any? {
            val result = chain.proceed()
            runCatching { sendBinder(modulePackageName) }
                .onFailure { Log.w(TAG, "Cannot deliver UI service to $modulePackageName", it) }
            return result
        }
    }

    private fun app(): Context? =
        runCatching { ActivityThread.currentApplication() }.getOrNull()

    private fun validGroup(group: String?): String? =
        group?.takeIf { GROUP_PATTERN.matches(it) }

    private fun validFile(name: String?): String? =
        name?.takeIf { FILE_PATTERN.matches(it) && !it.startsWith(".") }

    override fun getApiVersion(): Int = IXposedService.LIB_API

    override fun getFrameworkName(): String = BuildConfig.FRAMEWORK_NAME

    override fun getFrameworkVersion(): String = BuildConfig.VERSION_NAME

    override fun getFrameworkVersionCode(): Long = BuildConfig.VERSION_CODE

    override fun getFrameworkProperties(): Long =
        IXposedService.PROP_CAP_SYSTEM or IXposedService.PROP_CAP_REMOTE

    override fun getScope(): List<String> =
        runCatching { KaitServiceClient.getModuleScope(packageName) }
            .getOrDefault(emptyList())

    override fun requestScope(packages: List<String>?, callback: IXposedScopeCallback?) {
        // Widening a module's own scope bypasses the user's consent surface (Laras manager),
        // so it is refused here; removals go through removeScope instead.
        runCatching {
            callback?.onScopeRequestFailed("Ubah scope modul lewat Laras manager")
        }
    }

    override fun removeScope(packages: List<String>?) {
        if (packages.isNullOrEmpty()) return
        runCatching {
            val current = KaitServiceClient.getModuleScope(packageName)
            KaitServiceClient.setModuleScope(packageName, current - packages.toSet())
        }.onFailure { Log.w(TAG, "removeScope failed", it) }
    }

    override fun getRunningTargets(): List<HookedProcess> =
        KaitServiceClient.getRunningTargets(packageName)

    override fun hotReloadModule(targetId: Long, data: Bundle?, callback: IHotReloadCallback?) {
        KaitServiceClient.hotReloadModule(packageName, targetId, data, callback)
    }

    @Suppress("DEPRECATION")
    override fun requestRemotePreferences(group: String?): Bundle {
        val map = HashMap<String, Any?>()
        val name = validGroup(group)
        val prefs = name?.let { app()?.getSharedPreferences(it, Context.MODE_PRIVATE) }
        prefs?.all?.forEach { (k, v) -> map[k] = v }
        return Bundle().apply { putSerializable("map", map) }
    }

    @Suppress("DEPRECATION")
    override fun updateRemotePreferences(group: String?, diff: Bundle?) {
        val name = validGroup(group) ?: return
        val prefs = app()?.getSharedPreferences(name, Context.MODE_PRIVATE) ?: return
        if (diff == null) return
        val editor = prefs.edit()
        if (diff.getBoolean("clear", false)) editor.clear()
        (diff.getSerializable("delete") as? Set<*>)
            ?.forEach { if (it is String) editor.remove(it) }
        @Suppress("UNCHECKED_CAST")
        (diff.getSerializable("put") as? Map<String, Any?>)
            ?.forEach { (k, v) -> putValue(editor, k, v) }
        editor.apply()
        // Broadcast diff live to hooked processes subscribed to this preference group.
        KaitServiceClient.notifyRemotePreferencesChanged(packageName, name, diff)
    }

    private fun putValue(editor: android.content.SharedPreferences.Editor, key: String, value: Any?) {
        when (value) {
            is String -> editor.putString(key, value)
            is Int -> editor.putInt(key, value)
            is Long -> editor.putLong(key, value)
            is Float -> editor.putFloat(key, value)
            is Boolean -> editor.putBoolean(key, value)
            is Set<*> -> {
                @Suppress("UNCHECKED_CAST")
                editor.putStringSet(key, (value as? Set<String>)?.let { HashSet(it) })
            }
            else -> Log.w(TAG, "Dropping preference $key of unsupported type ${value?.javaClass}")
        }
    }

    override fun deleteRemotePreferences(group: String?) {
        val name = validGroup(group) ?: return
        runCatching {
            app()?.getSharedPreferences(name, Context.MODE_PRIVATE)?.edit()?.clear()?.apply()
            val clearDiff = Bundle().apply { putBoolean("clear", true) }
            KaitServiceClient.notifyRemotePreferencesChanged(packageName, name, clearDiff)
        }
    }

    override fun listRemoteFiles(): Array<String> {
        val dir = app()?.filesDir ?: return emptyArray()
        return dir.listFiles { f -> f.isFile && validFile(f.name) != null }
            ?.map { it.name }?.toTypedArray() ?: emptyArray()
    }

    override fun openRemoteFile(name: String?): ParcelFileDescriptor? {
        val safe = validFile(name) ?: return null
        val file = app()?.filesDir?.let { File(it, safe) } ?: return null
        if (!file.isFile) return null
        return runCatching {
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
        }.getOrNull()
    }

    override fun deleteRemoteFile(name: String?): Boolean {
        val safe = validFile(name) ?: return false
        val file = app()?.filesDir?.let { File(it, safe) } ?: return false
        return runCatching { file.delete() }.getOrDefault(false)
    }
}
