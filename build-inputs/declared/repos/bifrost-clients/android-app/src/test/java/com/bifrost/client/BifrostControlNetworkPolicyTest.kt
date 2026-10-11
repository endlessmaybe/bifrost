package com.bifrost.client

import java.io.IOException
import java.net.ConnectException
import javax.net.ssl.SSLHandshakeException
import org.junit.Assert.*
import org.junit.Test

class BifrostControlNetworkPolicyTest {
    @Test fun verifiedOtaRouteRemainsUsableWhenPhysicalNetworkIsUnavailable() {
        for (state in listOf(BifrostLeakState.STOPPED, BifrostLeakState.HEALTHY, BifrostLeakState.UNPROTECTED)) {
            var physicalCalls = 0
            val result = BifrostControlNetworkPolicy.open(state, 0,
                system = { "signed-manifest-from-working-network" },
                physical = { physicalCalls++; throw ConnectException("TEST-ONLY physical route unavailable") })
            assertEquals("signed-manifest-from-working-network", result)
            assertEquals(0, physicalCalls)
        }
    }
    @Test fun aFailedTunnelCannotCaptureItsOwnRecoveryRequest() {
        for (state in listOf(BifrostLeakState.STARTING, BifrostLeakState.BLOCKING, BifrostLeakState.ERROR)) {
            var systemCalls = 0
            assertEquals("physical", BifrostControlNetworkPolicy.open(state, 0,
                system = { systemCalls++; "unusable-tunnel" }, physical = { "physical" }))
            assertEquals(0, systemCalls)
            assertTrue(runCatching { BifrostControlNetworkPolicy.open(state, 0, system = { systemCalls++; "tunnel" }, physical = { null }) }.exceptionOrNull() is BifrostTransportUnavailableException)
            assertEquals(0, systemCalls)
        }
    }
    @Test fun manifestRetryMovesFromFailedSystemRouteToPhysicalRouteOnce() {
        var systemCalls = 0
        var physicalCalls = 0
        val result = BifrostControlReadRetry.run { attempt, received ->
            BifrostControlNetworkPolicy.open(BifrostLeakState.HEALTHY, attempt,
                system = { systemCalls++; throw ConnectException("TEST-ONLY") },
                physical = { physicalCalls++; received(); "manifest" })
        }
        assertEquals("manifest", result)
        assertEquals(1, systemCalls)
        assertEquals(1, physicalCalls)
    }
    @Test fun tlsAndReceivedHttpResponsesAreNeverRelabeledAsConnectivityRetries() {
        for (tls in listOf(false, true)) {
            var calls = 0
            val failure = runCatching { BifrostControlReadRetry.run<Unit> { _, received ->
                calls++
                if (tls) throw SSLHandshakeException("TEST-ONLY")
                received()
                throw IOException("TEST-ONLY body failed after status")
            } }.exceptionOrNull()
            assertNotNull(failure)
            assertEquals(1, calls)
        }
    }
}
