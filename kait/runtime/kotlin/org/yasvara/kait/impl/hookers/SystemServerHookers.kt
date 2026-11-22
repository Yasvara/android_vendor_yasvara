package org.yasvara.kait.impl.hookers

import io.github.libxposed.api.XposedInterface
import org.yasvara.kait.impl.KaitLifecycleManager
import org.yasvara.kait.impl.core.KaitDeopter
import org.yasvara.kait.impl.di.KaitBootstrap
import org.yasvara.kait.impl.hooks.KaitHookBuilder

/**
 * Intercepts the system server initialization process to deoptimize targets and attach bootstrap
 * hookers dynamically.
 */
object HandleSystemServerProcessHooker : XposedInterface.Hooker {

    interface Callback {
        fun onSystemServerLoaded(classLoader: ClassLoader)
    }

    @Volatile var callback: Callback? = null

    @Volatile
    var systemServerCL: ClassLoader? = null
        private set

    override fun intercept(chain: XposedInterface.Chain): Any? {
        val result = chain.proceed()
        val classLoader = Thread.currentThread().contextClassLoader
        if (classLoader != null) {
            initSystemServer(classLoader)
        }
        return result
    }

    /** Performs system server initialization. */
    fun initSystemServer(classLoader: ClassLoader, isLate: Boolean = false) {
        if (systemServerCL != null) return // Ensure this only runs once
        systemServerCL = classLoader

        // Deoptimize heavily inlined system server paths
        KaitDeopter.deoptSystemServerMethods(classLoader)

        if (!isLate) {
            // Dynamically locate and hook the bootstrap service initializer
            val sysServerClass =
                Class.forName("com.android.server.SystemServer", false, classLoader)
            val startMethod =
                sysServerClass.declaredMethods.find { it.name == "startBootstrapServices" }
                    ?: throw NoSuchMethodException(
                        "com.android.server.SystemServer.startBootstrapServices not found"
                    )

            // Ensure we can hook the private method
            startMethod.isAccessible = true
            KaitHookBuilder(startMethod).intercept(StartBootstrapServicesHooker)
        }

        callback?.onSystemServerLoaded(classLoader)
    }
}

/** Dispatches the core system server bootstrap event to the module engines. */
object StartBootstrapServicesHooker : XposedInterface.Hooker {

    override fun intercept(chain: XposedInterface.Chain): Any? {
        HandleSystemServerProcessHooker.systemServerCL?.let { dispatchSystemServerLoaded(it) }
        return chain.proceed()
    }

    /** Dispatches module loading events. */
    fun dispatchSystemServerLoaded(classLoader: ClassLoader) {
        // Dispatch to modern framework modules
        KaitLifecycleManager.dispatchSystemServerStarting(classLoader)

        // Dispatch to legacy framework modules
        KaitBootstrap.withLegacy { delegate -> delegate.onSystemServerLoaded(classLoader) }
    }
}
