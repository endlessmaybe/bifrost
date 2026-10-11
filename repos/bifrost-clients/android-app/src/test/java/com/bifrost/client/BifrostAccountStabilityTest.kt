package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test
import java.io.IOException

class BifrostAccountStabilityTest {
    private val enrolled = BifrostAccountSnapshot("BF-TEST-ACCOUNT", true, false)

    @Test fun coldStartReadFailureDoesNotOfferNewActivation() {
        val state = BifrostAccountDisplay().accept(Result.failure(IllegalStateException("BF-SECURE-STORE-READ")))
        assertFalse(state.ready)
        assertNull(state.snapshot)
        assertTrue(state.unavailable)
        assertTrue(state.message.contains("重试"))
    }

    @Test fun foregroundReadFailurePreservesKnownAccountAndRecovers() {
        var state = BifrostAccountDisplay().accept(Result.success(enrolled))
        repeat(20) {
            state = state.accept(Result.failure(IllegalStateException("BF-SECURE-STORE-READ")))
            assertEquals(enrolled, state.snapshot)
            assertFalse(state.ready)
        }
        state = state.accept(Result.success(enrolled))
        assertTrue(state.ready)
        assertTrue(state.snapshot!!.enrolled)
    }

    @Test fun confirmedEmptyStoreAfterLogoutDoesClearPresentation() {
        val state = BifrostAccountDisplay(enrolled).accept(Result.success(BifrostAccountSnapshot.from(emptyMap())))
        assertTrue(state.ready)
        assertFalse(state.snapshot!!.enrolled)
        assertFalse(state.snapshot.hasRecovery)
    }

    @Test fun lostEnrollmentResponseAndPartialMetadataRemainRecoverable() {
        for (evidence in listOf("session_token" to "TEST-ONLY", "config_version" to "17", "enrollment_pending_origin" to "https://example.test")) {
            val account = BifrostAccountSnapshot.from(mapOf(evidence))
            assertTrue(account.needsResume)
            assertFalse(BifrostAccountDisplay(account).ready)
        }
        assertFalse(BifrostAccountSnapshot.from(emptyMap()).needsResume)
    }

    @Test fun missingConfigDoesNotMeanMissingAccount() {
        assertTrue(BifrostAccountSnapshot.from(mapOf("public_id" to enrolled.publicId)).enrolled)
        BifrostAccountSnapshot.requireSessionIdentity("", enrolled.publicId)
        BifrostAccountSnapshot.requireSessionIdentity(enrolled.publicId, enrolled.publicId)
        for (other in listOf("", "BF-OTHER-ACCOUNT")) {
            assertThrows(IllegalStateException::class.java) {
                BifrostAccountSnapshot.requireSessionIdentity(enrolled.publicId, other)
            }
        }
    }

    @Test fun interruptedCacheAllowsVerifiedRefetchWithoutSuppressingOtherFailures() {
        assertNull(BifrostConfigRepairPolicy.readForOnlineRepair<String> { throw IllegalStateException("BF-CONFIG-CACHE-CORRUPT") })
        assertEquals("verified", BifrostConfigRepairPolicy.readForOnlineRepair { "verified" })
        assertThrows(IllegalStateException::class.java) {
            BifrostConfigRepairPolicy.readForOnlineRepair<String> { throw IllegalStateException("BF-SECURE-STORE-READ") }
        }
        assertThrows(IOException::class.java) {
            BifrostConfigRepairPolicy.readForOnlineRepair<String> { throw IOException("TEST-ONLY") }
        }
    }

    @Test fun damagedCacheDoesNotPermitSameVersionEquivocation() {
        BifrostConfigRepairPolicy.requireSameVersionDigest(17, 17, "a".repeat(64), "a".repeat(64))
        assertThrows(IllegalStateException::class.java) {
            BifrostConfigRepairPolicy.requireSameVersionDigest(17, 17, "b".repeat(64), "a".repeat(64))
        }
    }
}
