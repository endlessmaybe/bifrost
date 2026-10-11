package com.bifrost.client

import java.util.concurrent.Executors
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.CountDownLatch
import org.junit.Assert.assertEquals
import org.junit.Test

class BifrostProbeCompletionTest {
    @Test fun stalledFirstCandidateDoesNotDiscardCompletedSuccess() {
        val pool = Executors.newFixedThreadPool(2)
        val hold = CountDownLatch(1)
        try {
            val completion = ExecutorCompletionService<String>(pool)
            completion.submit { hold.await(); "stalled" }
            completion.submit { "healthy" }
            assertEquals(listOf("healthy"), BifrostProbeCompletion.collect(completion, 2, 250) {})
        } finally { hold.countDown(); pool.shutdownNow() }
    }

    @Test(expected = InterruptedException::class)
    fun cancelledRoundCannotReturnSuccessEvidence() {
        val pool = Executors.newSingleThreadExecutor()
        try {
            val completion = ExecutorCompletionService<String>(pool)
            completion.submit { "healthy" }
            BifrostProbeCompletion.collect(completion, 1, 250) { throw InterruptedException("cancelled") }
        } finally { pool.shutdownNow() }
    }
}
