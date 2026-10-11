package com.bifrost.client

import java.util.concurrent.Executors
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BifrostProbeRoundControllerTest {
    @Test
    fun aBurstIsDebouncedAndOldGenerationCannotPublish() {
        val executor = Executors.newSingleThreadScheduledExecutor()
        val controller = BifrostProbeRoundController(executor, 20)
        val delivered = mutableListOf<Int>()
        val second = controller.request { generation, token ->
            if (controller.isCurrent(generation) && !token.isCancelled()) delivered += generation
        }
        controller.request { generation, token ->
            if (controller.isCurrent(generation) && !token.isCancelled()) delivered += generation
        }
        executor.shutdown()
        executor.awaitTermination(1, TimeUnit.SECONDS)
        assertTrue(second < delivered.single())
        controller.close()
    }

    @Test
    fun cancelClosesRegisteredResourcesAndInvalidatesGeneration() {
        val executor = Executors.newSingleThreadScheduledExecutor()
        val controller = BifrostProbeRoundController(executor, 200)
        val closed = AtomicInteger(0)
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val generation = controller.runNow { _, token ->
            token.register(java.io.Closeable { closed.incrementAndGet() })
            started.countDown()
            try {
                release.await()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
        assertTrue(started.await(1, TimeUnit.SECONDS))
        controller.cancel()
        assertFalse(controller.isCurrent(generation))
        assertEquals(1, closed.get())
        release.countDown()
        executor.shutdownNow()
    }

    @Test
    fun sharedApplicationBudgetIsAtomicAndNeverExceedsLimit() {
        val budget = ProbeRoundBudget(128)
        val pool = Executors.newFixedThreadPool(3)
        val values = (0 until 12).map { pool.submit<Boolean> { runCatching { budget.consume(16); true }.getOrDefault(false) } }
            .map { it.get() }
        pool.shutdownNow()
        assertEquals(8, values.count { it })
        assertEquals(128, budget.consumed)
        assertTrue(budget.remaining >= 0)
    }
}
