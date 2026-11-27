// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yasvara.kait.impl.hooks

import io.github.libxposed.api.XposedInterface.Chain
import io.github.libxposed.api.XposedInterface.ExceptionMode
import io.github.libxposed.api.XposedInterface.Hooker
import java.lang.reflect.Executable
import java.util.Collections
import org.yasvara.kait.util.Utils

/**
 * An immutable registered hook configuration, stored natively by [HookBridge] and referenced by
 * [HookSnapshot] instances published onto [KaitNativeHooker.snapshot].
 *
 * Because this record is immutable, replacing a hook swaps the record inside a newly published
 * [HookSnapshot] so calls already in flight keep running the record they started with.
 */
class KaitHookRecord(
    val hooker: Hooker,
    val priority: Int,
    val exceptionMode: ExceptionMode,
    val id: String?,
)

/**
 * Lightweight single-hook [Chain] for the dominant case (1 modern hook, 0 legacy hooks).
 *
 * Calls [KaitNativeHooker.invokeOriginalSafely] directly without allocating a terminal closure
 * or a second recursive [KaitChain] node, while preserving 100% identical [ExceptionMode] semantics.
 */
internal class SingleModernChain(
    private val executable: Executable,
    private val thisObj: Any?,
    private val args: Array<Any?>,
    private val owner: KaitNativeHooker<*>,
) : Chain {

    internal var proceedCalled: Boolean = false
        private set

    internal var downstreamResult: Any? = null
    internal var downstreamThrowable: Throwable? = null

    override fun getExecutable(): Executable = executable

    override fun getThisObject(): Any? = thisObj

    override fun getArgs(): List<Any?> = Collections.unmodifiableList(args.asList())

    override fun getArg(index: Int): Any? = args[index]

    override fun proceed(): Any? = invokeOriginal(thisObj, args)

    override fun proceed(currentArgs: Array<Any?>): Any? = invokeOriginal(thisObj, currentArgs)

    override fun proceedWith(thisObject: Any): Any? = invokeOriginal(thisObject, args)

    override fun proceedWith(thisObject: Any, currentArgs: Array<Any?>): Any? =
        invokeOriginal(thisObject, currentArgs)

    internal fun invokeOriginal(thisObject: Any?, currentArgs: Array<Any?>): Any? {
        proceedCalled = true
        return try {
            val result = owner.invokeOriginalSafely(thisObject, currentArgs)
            downstreamResult = result
            downstreamThrowable = null
            result
        } catch (t: Throwable) {
            downstreamResult = null
            downstreamThrowable = t
            throw t
        }
    }
}

/**
 * Core interceptor chain engine. Manages multi-hook execution and enforces [ExceptionMode]
 * protections (`PROTECTIVE` vs `PASSTHROUGH`).
 */
class KaitChain(
    private val executable: Executable,
    private val thisObj: Any?,
    private val args: Array<Any?>,
    private val hooks: Array<KaitHookRecord>,
    private val hookIndex: Int,
    private val terminal: (thisObj: Any?, args: Array<Any?>) -> Any?,
) : Chain {

    // Tracks if this specific chain node has forwarded execution downstream
    internal var proceedCalled: Boolean = false
        private set

    // Stores the actual result/exception from the rest of the chain/original method
    internal var downstreamResult: Any? = null
    internal var downstreamThrowable: Throwable? = null

    override fun getExecutable(): Executable = executable

    override fun getThisObject(): Any? = thisObj

    override fun getArgs(): List<Any?> = Collections.unmodifiableList(args.asList())

    override fun getArg(index: Int): Any? = args[index]

    override fun proceed(): Any? = internalProceed(thisObj, args)

    override fun proceed(currentArgs: Array<Any?>): Any? = internalProceed(thisObj, currentArgs)

    override fun proceedWith(thisObject: Any): Any? = internalProceed(thisObject, args)

    override fun proceedWith(thisObject: Any, currentArgs: Array<Any?>): Any? =
        internalProceed(thisObject, currentArgs)

    private fun internalProceed(thisObject: Any?, currentArgs: Array<Any?>): Any? {
        proceedCalled = true

        // Reached the end of the modern hooks; trigger the original executable (and legacy hooks)
        if (hookIndex >= hooks.size) {
            return executeDownstream { terminal(thisObject, currentArgs) }
        }

        val record = hooks[hookIndex]
        val hooker = record.hooker
        val exceptionMode = record.exceptionMode
        val nextChain =
            KaitChain(executable, thisObject, currentArgs, hooks, hookIndex + 1, terminal)

        return try {
            executeDownstream { hooker.intercept(nextChain) }
        } catch (t: Throwable) {
            executeDownstream {
                handleInterceptorException(
                    t,
                    hooker,
                    exceptionMode,
                    nextChain,
                    thisObject,
                    currentArgs,
                )
            }
        }
    }

    /**
     * Executes the block and caches the downstream state so parent chains can recover it if the
     * current interceptor crashes during post-processing.
     */
    private inline fun executeDownstream(block: () -> Any?): Any? {
        return try {
            val result = block()
            downstreamResult = result
            downstreamThrowable = null
            result
        } catch (t: Throwable) {
            downstreamResult = null
            downstreamThrowable = t
            throw t
        }
    }

    /** Handles exceptions thrown by a hooker according to its [ExceptionMode]. */
    private fun handleInterceptorException(
        t: Throwable,
        hooker: Hooker,
        exceptionMode: ExceptionMode,
        nextChain: KaitChain,
        recoveryThis: Any?,
        recoveryArgs: Array<Any?>,
    ): Any? {
        // Check if the exception originated from downstream (lower hooks or original method)
        if (nextChain.proceedCalled && t === nextChain.downstreamThrowable) {
            throw t
        }

        // Passthrough mode does not rescue the process from hooker crashes
        if (exceptionMode == ExceptionMode.PASSTHROUGH) {
            throw t
        }

        val hookerName = hooker.javaClass.name
        if (!nextChain.proceedCalled) {
            // Crash occurred before calling proceed(); skip hooker and continue the chain
            Utils.logD("Hooker [$hookerName] crashed before proceed. Skipping.", t)
            return nextChain.internalProceed(recoveryThis, recoveryArgs)
        } else {
            // Crash occurred after calling proceed(); suppress and restore downstream state
            Utils.logD("Hooker [$hookerName] crashed after proceed. Restoring state.", t)
            nextChain.downstreamThrowable?.let { throw it }
            return nextChain.downstreamResult
        }
    }
}
