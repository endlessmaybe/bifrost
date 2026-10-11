package com.bifrost.client

import com.bifrost.client.ui.model.BifrostRoutingContract
import org.junit.Assert.assertEquals
import org.junit.Test

class BifrostBackgroundSelectionTest {
    @Test fun savedPerAppSelectionUsesSmartPresentationAndKeepsApplicationRoutes() {
        val selection = BifrostConnectionRouteContract.parse("direct-vmess", "per-app")
        assertEquals("smart", BifrostConnectionRouteContract.presentationMode(selection))
        val routing = BifrostRoutingContract.select(selection,
            BifrostBackgroundConnection.restoredAppPolicy("exclude"), emptyList(), listOf("com.example.direct"))
        assertEquals("per-app", routing.wireMode)
        assertEquals("exclude", routing.policyMode)
        assertEquals(listOf("com.example.direct"), routing.exclude)
    }
    @Test fun persistedEffectiveNonePolicyCanReconnectSmartAndGlobal() {
        for (mode in listOf("smart", "global")) {
            val selection = BifrostConnectionRouteContract.parse("direct-vmess", mode)
            assertEquals(mode, BifrostConnectionRouteContract.presentationMode(selection))
            val routing = BifrostRoutingContract.select(selection,
                BifrostBackgroundConnection.restoredAppPolicy("none"), emptyList(), emptyList())
            assertEquals(mode, routing.wireMode)
            assertEquals("none", routing.policyMode)
        }
    }
    @Test fun smartGateKeepsItsConnectionTypeWhenRestoringEitherRouteMode() {
        for (mode in listOf("smart", "per-app")) {
            val selection = BifrostConnectionRouteContract.parse("smartgate", mode)
            assertEquals("smartgate", BifrostConnectionRouteContract.presentationMode(selection))
            assertEquals("smartgate", selection.connectionType.wireValue)
            assertEquals(mode, selection.routeMode.wireValue)
        }
    }
}
