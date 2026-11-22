// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yasvara.kait.impl.hooks

import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedInterface.ExceptionMode
import io.github.libxposed.api.XposedInterface.HookBuilder
import io.github.libxposed.api.XposedInterface.HookHandle
import io.github.libxposed.api.XposedInterface.Hooker
import io.github.libxposed.api.error.HookFailedError
import java.lang.reflect.Constructor
import java.lang.reflect.Executable
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import org.yasvara.kait.impl.di.KaitBootstrap
import org.yasvara.kait.nativebridge.HookBridge
import org.yasvara.kait.util.Utils

/**
 * Builder for configuring and registering hooks. [moduleId] scopes hook ids per module and is null
 * for framework hooks; [frozen] gates registration only, so a retired generation can still unhook.
 */
class KaitHookBuilder(
    private val origin: Executable,
    private val moduleId: String? = null,
    private val frozen: (() -> Boolean)? = null,
    private val defaultExceptionMode: ExceptionMode = ExceptionMode.PROTECTIVE,
) : HookBuilder {

    private var priority = XposedInterface.PRIORITY_DEFAULT
    private var exceptionMode = ExceptionMode.DEFAULT
    private var id: String? = null

    override fun setPriority(priority: Int): HookBuilder = apply { this.priority = priority }

    override fun setExceptionMode(mode: ExceptionMode): HookBuilder = apply {
        this.exceptionMode = mode
    }

    override fun setId(id: String?): HookBuilder = apply { this.id = id }

    override fun intercept(hooker: Hooker): HookHandle {
        ensureNotFrozen()
        if (Modifier.isAbstract(origin.modifiers)) {
            throw IllegalArgumentException(
                "$origin is abstract: it has no body to hook. Hook the concrete override instead."
            )
        } else if (origin.declaringClass.classLoader == KaitHookBuilder::class.java.classLoader) {
            throw IllegalArgumentException(
                "$origin belongs to Kait itself. Hooking the framework would hook the code running your hook."
            )
        } else if (
            origin is Method &&
                origin.declaringClass == Method::class.java &&
                origin.name == "invoke"
        ) {
            throw IllegalArgumentException(
                "Method.invoke cannot be hooked: Kait calls it to run the original of every hooked method, so a hook here would call itself forever."
            )
        } else if (
            origin is Method &&
                origin.declaringClass == Constructor::class.java &&
                origin.name == "newInstance"
        ) {
            throw IllegalArgumentException(
                "Constructor.newInstance cannot be hooked: Kait reflects through it the same way it does Method.invoke, so a hook here would recurse."
            )
        } else if (
            origin is Method &&
                origin.declaringClass == Any::class.java &&
                origin.name == "getClass"
        ) {
            throw IllegalArgumentException(
                "Object.getClass cannot be hooked: Kait's dispatch calls it entering every hooked method, so a hook here would call itself forever."
            )
        }

        val resolvedMode =
            if (exceptionMode == ExceptionMode.DEFAULT) defaultExceptionMode else exceptionMode
        val id = this.id
        val record = KaitHookRecord(hooker, priority, resolvedMode, id)

        val moduleId = this.moduleId ?: return register(record, null)

        synchronized(KaitHookRegistry.lockOf(moduleId)) {
            ensureNotFrozen()
            if (id != null) {
                KaitHookRegistry.findId(moduleId, origin, id)?.takeIf { it.isLive }?.let {
                    return it.swapLocked(record)
                }
            }
            return register(record, moduleId)
        }
    }

    private fun ensureNotFrozen() {
        if (frozen?.invoke() == true) {
            throw IllegalStateException(
                "This module generation has been retired by a hot reload and cannot register hooks"
            )
        }
    }

    private fun register(record: KaitHookRecord, moduleId: String?): HookHandle {
        if (
            !HookBridge.hookMethod(
                true,
                origin,
                KaitNativeHooker::class.java,
                record.priority,
                record,
            )
        ) {
            throw HookFailedError("Cannot hook $origin")
        }

        val handle = KaitHookHandle(origin, moduleId, record)
        if (moduleId != null) {
            KaitHookRegistry.track(moduleId, handle)
            record.id?.let { KaitHookRegistry.claimId(moduleId, origin, it, handle) }
        }
        return handle
    }

    companion object {
        fun snapshotHandles(moduleId: String): List<HookHandle> =
            KaitHookRegistry.liveHandles(moduleId)

        fun lockOf(moduleId: String): Any = KaitHookRegistry.lockOf(moduleId)
    }
}

/**
 * The Kait trampoline callback entrypoint.
 *
 * Instantiated once per hooked method by `libyasvara_kait.so`, which also populates [backup]
 * and atomically publishes immutable [HookSnapshot] instances into [snapshot] whenever hooks
 * are added, removed, or replaced.
 *
 * Hot path guarantees:
 * - **Zero JNI crossings** per invocation (`snapshot` volatile read, direct `backup.invoke`,
 *   ART intrinsic `Class.isInstance`).
 * - **Zero argument array slicing** (`thisObject` is passed separately by the DEX trampoline,
 *   and 0-argument methods pass `null` mapped to shared [EMPTY_ARGS]).
 * - **Minimal allocation** via dedicated fast paths for 0-hook, 1-modern-hook, and legacy-only.
 */
class KaitNativeHooker<T : Executable>(private val method: T) {

    /** Immutable Copy-on-Write callback snapshot published by `libyasvara_kait.so`. */
    @JvmField
    @Volatile
    var snapshot: HookSnapshot = HookSnapshot.EMPTY

    /** Direct handle to the backup ArtMethod (private/direct, accessible) wired by native code. */
    @JvmField
    @Volatile
    var backup: Method? = null

    /** Optional test-only invoker override for host JVM unit tests without ART JNI. */
    internal var testOriginalInvoker: ((Any?, Array<Any?>) -> Any?)? = null

    private val returnType: Class<*>? = if (method is Method) method.returnType else null

    /**
     * Invoked directly by the generated DEX trampoline (`libkait_dex`).
     *
     * [thisObject] is `null` for static methods and the receiver for instance methods/constructors.
     * [rawArgs] is `null` for 0-parameter methods, avoiding any array allocation in the trampoline.
     */
    fun callback(thisObject: Any?, rawArgs: Array<Any?>?): Any? {
        val actualArgs = rawArgs ?: EMPTY_ARGS
        val snap = snapshot
        val modernHooks = snap.modern
        val legacyHooks = snap.legacy

        // Fast path 0: All hooks removed while trampoline was entered.
        if (modernHooks.isEmpty() && legacyHooks.isEmpty()) {
            return invokeOriginalSafely(thisObject, actualArgs)
        }

        val result: Any? =
            when {
                // Fast path 1: Single modern hook, no legacy hooks (most common case).
                modernHooks.size == 1 && legacyHooks.isEmpty() -> {
                    dispatchSingleModern(modernHooks[0], thisObject, actualArgs)
                }
                // Fast path 2: Legacy-only hooks, no modern hooks.
                modernHooks.isEmpty() -> {
                    val delegate = KaitBootstrap.delegate
                    if (delegate != null) {
                        delegate.processLegacyHook(method, thisObject, actualArgs, legacyHooks) {
                            invokeOriginalSafely(thisObject, actualArgs)
                        }
                    } else {
                        invokeOriginalSafely(thisObject, actualArgs)
                    }
                }
                // General path: Multi-hook modern chain (with optional legacy terminal).
                else -> {
                    val terminal: (Any?, Array<Any?>) -> Any? = { tObj, tArgs ->
                        val delegate = KaitBootstrap.delegate
                        if (legacyHooks.isNotEmpty() && delegate != null) {
                            delegate.processLegacyHook(method, tObj, tArgs, legacyHooks) {
                                invokeOriginalSafely(tObj, tArgs)
                            }
                        } else {
                            invokeOriginalSafely(tObj, tArgs)
                        }
                    }
                    KaitChain(method, thisObject, actualArgs, modernHooks, 0, terminal).proceed()
                }
            }

        validateReturnType(result)
        return result
    }

    private fun dispatchSingleModern(
        record: KaitHookRecord,
        thisObject: Any?,
        actualArgs: Array<Any?>,
    ): Any? {
        val chain = SingleModernChain(method, thisObject, actualArgs, this)
        return try {
            record.hooker.intercept(chain)
        } catch (t: Throwable) {
            // Re-throw exceptions originating from the original method untouched.
            if (chain.proceedCalled && t === chain.downstreamThrowable) {
                throw t
            }
            if (record.exceptionMode == ExceptionMode.PASSTHROUGH) {
                throw t
            }
            val hookerName = record.hooker.javaClass.name
            if (!chain.proceedCalled) {
                Utils.logD("Hooker [$hookerName] crashed before proceed. Skipping.", t)
                chain.invokeOriginal(thisObject, actualArgs)
            } else {
                Utils.logD("Hooker [$hookerName] crashed after proceed. Restoring state.", t)
                chain.downstreamThrowable?.let { throw it }
                chain.downstreamResult
            }
        }
    }

    private fun validateReturnType(result: Any?) {
        val rt = returnType ?: return
        if (rt == Void.TYPE) return
        if (result == null) {
            if (rt.isPrimitive) {
                throw NullPointerException(
                    "Hook returned null for a primitive return type: $method"
                )
            }
            return
        }
        // Fast ART intrinsic check before any fallback; avoids JNI crossing on hot path.
        if (!rt.isInstance(result) && !isBoxingCompatible(result, rt)) {
            Utils.logD(
                "Hook return type mismatch. Expected ${rt.name}, got ${result.javaClass.name}"
            )
        }
    }

    private fun isBoxingCompatible(obj: Any, targetType: Class<*>): Boolean {
        if (!targetType.isPrimitive) return false
        return when (targetType) {
            Int::class.javaPrimitiveType -> obj is Int
            Long::class.javaPrimitiveType -> obj is Long
            Boolean::class.javaPrimitiveType -> obj is Boolean
            Double::class.javaPrimitiveType -> obj is Double
            Float::class.javaPrimitiveType -> obj is Float
            Byte::class.javaPrimitiveType -> obj is Byte
            Char::class.javaPrimitiveType -> obj is Char
            Short::class.javaPrimitiveType -> obj is Short
            else -> false
        }
    }

    /** Safely invokes the original backup method, unwrapping [InvocationTargetException]. */
    internal fun invokeOriginalSafely(tObj: Any?, tArgs: Array<Any?>): Any? {
        testOriginalInvoker?.let { return it(tObj, tArgs) }
        return try {
            val b = backup
            if (b != null) {
                b.invoke(tObj, *tArgs)
            } else {
                HookBridge.invokeOriginalMethod(method, tObj, *tArgs)
            }
        } catch (ite: InvocationTargetException) {
            throw ite.cause ?: ite
        }
    }

    companion object {
        @JvmField
        val EMPTY_ARGS: Array<Any?> = emptyArray()
    }
}
