package com.bifrost.client

import com.bifrost.client.ui.model.*
import org.junit.Assert.*
import org.junit.Test

class ConnectedPresentationTest {
    @Test fun ownedTunnelWithoutSystemLockdownIsConnectedAndCanBeStopped() {
        val evidence = BifrostRuntimeEvidence(true, true, "tx", "digest", "generation", "[]", BifrostRuntimeSignal.CONNECTED)
        val state = BifrostUiReducer.fromRuntimeSignal(BifrostRuntimeSignal.CONNECTED, evidence, "tx", "digest", "generation", "[]")
        assertTrue(state.isConnected)
        assertFalse(state.isProtected)
        assertTrue(BifrostUiActions.canStop(state.state))
        val stale = BifrostUiReducer.fromRuntimeSignal(BifrostRuntimeSignal.CONNECTED, evidence, "newer", "digest", "generation", "[]")
        assertFalse(stale.isConnected)
        assertEquals(BifrostConnectionState.ERROR, stale.state)
    }
}
