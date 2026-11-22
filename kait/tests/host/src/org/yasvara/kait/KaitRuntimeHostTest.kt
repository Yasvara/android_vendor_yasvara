// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yasvara.kait

import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedInterface.ExceptionMode
import io.github.libxposed.api.XposedInterface.Hooker
import io.github.libxposed.api.error.HookFailedError
import java.lang.reflect.Constructor
import java.lang.reflect.Method
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.yasvara.kait.impl.hooks.HookSnapshot
import org.yasvara.kait.impl.hooks.KaitHookBuilder
import org.yasvara.kait.impl.hooks.KaitHookRecord
import org.yasvara.kait.impl.hooks.KaitNativeHooker
import org.yasvara.kait.nativebridge.HookBridge

class KaitRuntimeHostTest {

    @Suppress("unused")
    class TargetSample {
        fun add(a: Int, b: Int): Int = a + b
        fun zeroArgs(): String = "hello"
        fun greet(name: String): String = "hi $name"
        fun throwingMethod(): Int {
            throw IllegalStateException("original boom")
        }
        companion object {
            @JvmStatic
            fun staticDouble(x: Int): Int = x * 2
        }
    }

    abstract class AbstractSample {
        abstract fun noBody(): Int
    }

    @Before
    fun setUp() {
        HookBridge.reset()
    }

    @Test
    fun emptySnapshotCallsOriginalDirectlyViaBackup() {
        val method = TargetSample::class.java.getDeclaredMethod("add", Int::class.java, Int::class.java)
        val hooker = KaitNativeHooker(method)
        hooker.backup = method
        hooker.snapshot = HookSnapshot.EMPTY

        val sample = TargetSample()
        val result = hooker.callback(sample, arrayOf(19, 23))
        assertEquals(42, result)
    }

    @Test
    fun zeroArgMethodAcceptsNullRawArgsWithoutAllocation() {
        val method = TargetSample::class.java.getDeclaredMethod("zeroArgs")
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        var observedArgsSize = -1
        val rec = KaitHookRecord(
            hooker = Hooker { chain ->
                observedArgsSize = chain.args.size
                chain.proceed()
            },
            priority = 50,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = null,
        )
        hooker.snapshot = HookSnapshot(arrayOf(rec), emptyArray())

        val result = hooker.callback(TargetSample(), null)
        assertEquals("hello", result)
        assertEquals(0, observedArgsSize)
    }

    @Test
    fun singleModernHookCanModifyArgsAndResult() {
        val method = TargetSample::class.java.getDeclaredMethod("add", Int::class.java, Int::class.java)
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        val rec = KaitHookRecord(
            hooker = Hooker { chain ->
                val a = chain.getArg(0) as Int
                val b = chain.getArg(1) as Int
                val orig = chain.proceed(arrayOf(a + 1, b + 2)) as Int
                orig * 10
            },
            priority = 50,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = "mod-add",
        )
        hooker.snapshot = HookSnapshot(arrayOf(rec), emptyArray())

        // (3+1) + (4+2) = 10 -> * 10 = 100
        assertEquals(100, hooker.callback(TargetSample(), arrayOf(3, 4)))
    }

    @Test
    fun singleModernHookProtectiveRecoversBeforeProceedCrash() {
        val method = TargetSample::class.java.getDeclaredMethod("add", Int::class.java, Int::class.java)
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        val rec = KaitHookRecord(
            hooker = Hooker { throw RuntimeException("buggy hook before proceed") },
            priority = 50,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = null,
        )
        hooker.snapshot = HookSnapshot(arrayOf(rec), emptyArray())

        assertEquals(15, hooker.callback(TargetSample(), arrayOf(7, 8)))
    }

    @Test
    fun singleModernHookProtectiveRecoversAfterProceedCrash() {
        val method = TargetSample::class.java.getDeclaredMethod("add", Int::class.java, Int::class.java)
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        val rec = KaitHookRecord(
            hooker = Hooker { chain ->
                chain.proceed()
                throw RuntimeException("buggy hook after proceed")
            },
            priority = 50,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = null,
        )
        hooker.snapshot = HookSnapshot(arrayOf(rec), emptyArray())

        // Original result 15 must be restored instead of crashing.
        assertEquals(15, hooker.callback(TargetSample(), arrayOf(7, 8)))
    }

    @Test
    fun singleModernHookProtectivePreservesOriginalException() {
        val method = TargetSample::class.java.getDeclaredMethod("throwingMethod")
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        val rec = KaitHookRecord(
            hooker = Hooker { chain -> chain.proceed() },
            priority = 50,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = null,
        )
        hooker.snapshot = HookSnapshot(arrayOf(rec), emptyArray())

        try {
            hooker.callback(TargetSample(), null)
            fail("Expected IllegalStateException from original method")
        } catch (e: IllegalStateException) {
            assertEquals("original boom", e.message)
        }
    }

    @Test
    fun singleModernHookPassthroughPropagatesHookerException() {
        val method = TargetSample::class.java.getDeclaredMethod("zeroArgs")
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        val rec = KaitHookRecord(
            hooker = Hooker { throw ArithmeticException("intentional passthrough") },
            priority = 50,
            exceptionMode = ExceptionMode.PASSTHROUGH,
            id = null,
        )
        hooker.snapshot = HookSnapshot(arrayOf(rec), emptyArray())

        try {
            hooker.callback(TargetSample(), null)
            fail("Expected ArithmeticException in PASSTHROUGH mode")
        } catch (e: ArithmeticException) {
            assertEquals("intentional passthrough", e.message)
        }
    }

    @Test
    fun multiHookChainOrderAndIsolationOnSnapshotSwap() {
        val method = TargetSample::class.java.getDeclaredMethod("greet", String::class.java)
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        val trace = mutableListOf<String>()
        val h1 = KaitHookRecord(
            hooker = Hooker { chain ->
                trace.add("h1-before")
                // Mutate hooker.snapshot mid-call to verify Copy-on-Write isolation!
                hooker.snapshot = HookSnapshot.EMPTY
                val res = chain.proceed(arrayOf("${chain.getArg(0)}!"))
                trace.add("h1-after")
                "[$res]"
            },
            priority = 100,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = "h1",
        )
        val h2 = KaitHookRecord(
            hooker = Hooker { chain ->
                trace.add("h2-before")
                val res = chain.proceed()
                trace.add("h2-after")
                "$res-2"
            },
            priority = 50,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = "h2",
        )
        hooker.snapshot = HookSnapshot(arrayOf(h1, h2), emptyArray())

        val firstRes = hooker.callback(TargetSample(), arrayOf("Kait"))
        assertEquals("[hi Kait!-2]", firstRes)
        assertEquals(listOf("h1-before", "h2-before", "h2-after", "h1-after"), trace)

        // Next call sees the newly swapped EMPTY snapshot.
        val secondRes = hooker.callback(TargetSample(), arrayOf("Kait"))
        assertEquals("hi Kait", secondRes)
    }

    @Test
    fun multiHookProtectiveMiddleHookCrashDoesNotBreakOuterOrInnerHooks() {
        val method = TargetSample::class.java.getDeclaredMethod("greet", String::class.java)
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        val hOuter = KaitHookRecord(
            hooker = Hooker { chain -> "<${chain.proceed()}>" },
            priority = 100,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = null,
        )
        val hBroken = KaitHookRecord(
            hooker = Hooker { throw IllegalArgumentException("broken middle hook") },
            priority = 50,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = null,
        )
        val hInner = KaitHookRecord(
            hooker = Hooker { chain -> "${chain.proceed()}*" },
            priority = 10,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = null,
        )
        hooker.snapshot = HookSnapshot(arrayOf(hOuter, hBroken, hInner), emptyArray())

        assertEquals("<hi Yasvara*>", hooker.callback(TargetSample(), arrayOf("Yasvara")))
    }

    @Test
    fun returningNullForPrimitiveMethodThrowsNullPointerException() {
        val method = TargetSample::class.java.getDeclaredMethod("add", Int::class.java, Int::class.java)
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        val rec = KaitHookRecord(
            hooker = Hooker { null },
            priority = 50,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = null,
        )
        hooker.snapshot = HookSnapshot(arrayOf(rec), emptyArray())

        try {
            hooker.callback(TargetSample(), arrayOf(1, 2))
            fail("Expected NullPointerException for null return on int method")
        } catch (_: NullPointerException) {
            // Expected
        }
    }

    @Test
    fun staticMethodAllowsNullReceiver() {
        val method = TargetSample::class.java.getDeclaredMethod("staticDouble", Int::class.java)
        val hooker = KaitNativeHooker(method)
        hooker.backup = method
        hooker.snapshot = HookSnapshot.EMPTY

        assertEquals(84, hooker.callback(null, arrayOf(42)))
    }

    @Test
    fun builderRejectsForbiddenTargetsAndAbstractMethods() {
        val noop = Hooker { it.proceed() }

        // Abstract method
        val absMethod = AbstractSample::class.java.getDeclaredMethod("noBody")
        assertThrowsIllegalArg { KaitHookBuilder(absMethod).intercept(noop) }

        // Method.invoke
        val invokeMethod = Method::class.java.getDeclaredMethod(
            "invoke",
            Any::class.java,
            Array<Any>::class.java,
        )
        assertThrowsIllegalArg { KaitHookBuilder(invokeMethod).intercept(noop) }

        // Constructor.newInstance
        val newInst = Constructor::class.java.getDeclaredMethod(
            "newInstance",
            Array<Any>::class.java,
        )
        assertThrowsIllegalArg { KaitHookBuilder(newInst).intercept(noop) }

        // Object.getClass
        val getCls = Any::class.java.getDeclaredMethod("getClass")
        assertThrowsIllegalArg { KaitHookBuilder(getCls).intercept(noop) }
    }

    @Test
    fun builderFrozenGenerationBlocksNewHooksAndHandleReplaceInvalidatesOldHandle() {
        val method = String::class.java.getDeclaredMethod("length")
        var isFrozen = false
        val h1 = KaitHookBuilder(method, moduleId = "com.example.mod", frozen = { isFrozen })
            .setPriority(80)
            .setId("str-len")
            .intercept(Hooker { it.proceed() })

        assertEquals("str-len", h1.id)
        assertSame(method, h1.executable)
        assertEquals(1, HookBridge.registered.size)

        // Replace hook via handle -> mints new handle, invalidates old handle.
        val h2 = h1.replaceHook(Hooker { 99 })
        assertEquals("str-len", h2.id)
        assertEquals(1, HookBridge.registered.size)

        // Old handle is now dead: calling replaceHook again must throw IllegalStateException.
        try {
            h1.replaceHook(Hooker { 100 })
            fail("Superseded handle must reject replaceHook")
        } catch (_: IllegalStateException) {
            // Expected
        }

        // Old handle unhook must be a silent no-op and must NOT remove h2!
        h1.unhook()
        assertEquals(1, HookBridge.registered.size)

        // Freezing generation blocks new registrations, but existing handle can still unhook!
        isFrozen = true
        try {
            KaitHookBuilder(method, moduleId = "com.example.mod", frozen = { isFrozen })
                .intercept(Hooker { it.proceed() })
            fail("Frozen generation must throw IllegalStateException")
        } catch (_: IllegalStateException) {
            // Expected
        }

        h2.unhook()
        assertEquals(0, HookBridge.registered.size)
        // Idempotent second unhook
        h2.unhook()
        assertEquals(0, HookBridge.registered.size)
    }

    @Test
    fun builderSameIdReplacesAtomicallyWithNewPriority() {
        val method = String::class.java.getDeclaredMethod("isEmpty")
        val h1 = KaitHookBuilder(method, moduleId = "com.example.mod2")
            .setPriority(10)
            .setId("same-id")
            .intercept(Hooker { false })

        val h2 = KaitHookBuilder(method, moduleId = "com.example.mod2")
            .setPriority(90)
            .setId("same-id")
            .intercept(Hooker { true })

        assertEquals(1, HookBridge.registered.size)
        val activeRec = HookBridge.registered[0] as KaitHookRecord
        assertEquals(90, activeRec.priority)

        // h1 is invalidated; h2 is live
        h1.unhook()
        assertEquals(1, HookBridge.registered.size)
        h2.unhook()
        assertEquals(0, HookBridge.registered.size)
    }

    @Test
    fun hookFailedErrorWhenNativeBridgeRejects() {
        val method = String::class.java.getDeclaredMethod("trim")
        HookBridge.nextHookResult = false
        try {
            KaitHookBuilder(method, moduleId = "com.example.fail").intercept(Hooker { it.proceed() })
            fail("Expected HookFailedError")
        } catch (_: HookFailedError) {
            // Expected
        }
    }

    @Test
    fun proceedWithSubstitutesReceiver() {
        val method = TargetSample::class.java.getDeclaredMethod("greet", String::class.java)
        val hooker = KaitNativeHooker(method)
        val seenReceivers = mutableListOf<Any?>()
        hooker.testOriginalInvoker = { recv, args ->
            seenReceivers.add(recv)
            "ok:${args[0]}"
        }

        val alt = TargetSample()
        val rec = KaitHookRecord(
            hooker = Hooker { chain -> chain.proceedWith(alt, arrayOf("alt")) },
            priority = 50,
            exceptionMode = ExceptionMode.PROTECTIVE,
            id = null,
        )
        hooker.snapshot = HookSnapshot(arrayOf(rec), emptyArray())

        val orig = TargetSample()
        assertEquals("ok:alt", hooker.callback(orig, arrayOf("orig")))
        assertEquals(1, seenReceivers.size)
        assertSame(alt, seenReceivers[0])
    }

    @Test
    fun concurrentSnapshotReadsDuringSwapsStayConsistent() {
        val method = TargetSample::class.java.getDeclaredMethod("staticDouble", Int::class.java)
        val hooker = KaitNativeHooker(method)
        hooker.backup = method

        val snapA = HookSnapshot(
            arrayOf(KaitHookRecord(Hooker { (it.proceed() as Int) + 1 }, 50, ExceptionMode.PROTECTIVE, null)),
            emptyArray(),
        )
        val snapB = HookSnapshot(
            arrayOf(KaitHookRecord(Hooker { (it.proceed() as Int) + 2 }, 50, ExceptionMode.PROTECTIVE, null)),
            emptyArray(),
        )
        hooker.snapshot = snapA

        val failures = AtomicInteger(0)
        val writer = Thread {
            repeat(5_000) { i ->
                hooker.snapshot = if ((i and 1) == 0) snapA else snapB
            }
        }
        val readers = List(4) {
            Thread {
                repeat(5_000) {
                    val v = hooker.callback(null, arrayOf(10)) as Int
                    if (v != 21 && v != 22) failures.incrementAndGet()
                }
            }
        }
        writer.start()
        readers.forEach { it.start() }
        writer.join()
        readers.forEach { it.join() }
        assertEquals(0, failures.get())
    }

    private fun assertThrowsIllegalArg(block: () -> Unit) {
        try {
            block()
            fail("Expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }
}
