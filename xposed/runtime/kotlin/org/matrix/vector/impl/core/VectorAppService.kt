package org.matrix.vector.impl.core

import android.app.ActivityThread
import android.content.Context
import android.os.Bundle
import android.os.ParcelFileDescriptor
import io.github.libxposed.service.HookedProcess
import io.github.libxposed.service.IHotReloadCallback
import io.github.libxposed.service.IXposedService
import io.github.libxposed.service.IXposedScopeCallback
import io.github.libxposed.service.XposedServiceHelper
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import org.matrix.vector.impl.BuildConfig
import org.matrix.vector.util.Log

private const val TAG = "VectorAppService"
private val GROUP_PATTERN = Regex("[A-Za-z0-9._-]{1,128}")
private val FILE_PATTERN = Regex("[A-Za-z0-9._-]{1,128}")

/**
 * The module UI's end of the modern API: what `XposedServiceHelper.registerListener` delivers
 * `onServiceBind` for.
 *
 * Upstream pushes this binder from a daemon through the module's `XposedProvider`. This runtime
 * has no daemon, so the module's self-injected process builds it locally instead: preferences
 * and files are the module's own (this process runs as the module uid, so plain `Context`
 * access applies), while scope reads/writes travel over [VectorServiceClient] to system_server.
 */
class VectorAppService(
    private val packageName: String,
) : IXposedService.Stub() {

    companion object {
        private val delivered = AtomicBoolean(false)

        /**
         * Hands a self-injected module's main process its UI service, once per process.
         *
         * Called from the module-loading paths (modern and legacy) where the loaded module
         * and the process name are both already known — unlike `attach()`, where the bound
         * application (and thus the package name) does not exist yet. Delivery is
         * order-independent: `XposedServiceHelper` caches the binder until the UI registers
         * its listener, and the service itself resolves the app lazily per call.
         */
        @JvmStatic
        fun deliverForSelf(modulePackageName: String, processName: String) {
            if (modulePackageName != processName || !delivered.compareAndSet(false, true)) return
            runCatching { XposedServiceHelper.deliverBinder(VectorAppService(modulePackageName)) }
                .onFailure { Log.w(TAG, "Cannot deliver UI service to $modulePackageName", it) }
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
        runCatching { VectorServiceClient.getModuleScope(packageName) }
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
            val current = VectorServiceClient.getModuleScope(packageName)
            VectorServiceClient.setModuleScope(packageName, current - packages.toSet())
        }.onFailure { Log.w(TAG, "removeScope failed", it) }
    }

    override fun getRunningTargets(): List<HookedProcess> = emptyList()

    override fun hotReloadModule(targetId: Long, data: Bundle?, callback: IHotReloadCallback?) {
        runCatching {
            callback?.onHotReloadResult(
                IXposedService.HOT_RELOAD_UNSUPPORTED,
                "Hot reload is not supported",
            )
        }
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
