package com.bifrost.client

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BifrostUpdateCleanupTest {
    private val age = 24L * 60 * 60 * 1000
    private val now = 10L * age

    @Test
    fun api28UsesLegacyPendingTimestampAndCleansStaleSession() {
        assertFalse(BifrostUpdateCleanup.usesSessionCreatedMillis(28))
        assertTrue(BifrostUpdateCleanup.shouldAbandonLegacySession(28, now, now - age - 1, age))
        assertFalse(BifrostUpdateCleanup.shouldAbandonLegacySession(28, now, now - age + 1, age))
    }

    @Test
    fun api29UsesLegacyPendingTimestampAndDoesNotTouchRecentSession() {
        assertFalse(BifrostUpdateCleanup.usesSessionCreatedMillis(29))
        assertTrue(BifrostUpdateCleanup.shouldAbandonLegacySession(29, now, now - age - 1, age))
        assertFalse(BifrostUpdateCleanup.shouldAbandonLegacySession(29, now, now - 1, age))
    }

    @Test
    fun api30AndLaterUseFrameworkSessionTimestamp() {
        assertTrue(BifrostUpdateCleanup.usesSessionCreatedMillis(30))
        assertTrue(BifrostUpdateCleanup.usesSessionCreatedMillis(35))
        assertFalse(BifrostUpdateCleanup.shouldAbandonLegacySession(30, now, now - age - 1, age))
    }
}
