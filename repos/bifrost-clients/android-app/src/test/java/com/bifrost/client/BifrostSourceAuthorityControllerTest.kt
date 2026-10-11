package com.bifrost.client

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BifrostSourceAuthorityControllerTest {
    @Test
    fun revokedSelectionClearsPersistedSourceCandidateAndOwner() {
        val persisted = mutableListOf<String>()
        val ownerUpdates = mutableListOf<String>()
        val controller = BifrostSourceAuthorityController(
            persistSource = { persisted += it; true },
            updateOwner = { ownerUpdates += it },
        )
        val current = BifrostSourceAuthorityState(true, listOf("A"), listOf("auto", "A"), "A", "A-01")
        val authority = BifrostSourceAuthority.fromVerifiedConfig(
            JSONObject().put("sources", org.json.JSONArray()
                .put(JSONObject().put("code", "B").put("configured", true))).toString(),
        )
        val result = controller.apply(current, authority)
        assertFalse(result.accepted)
        assertTrue(result.persistenceOk)
        assertEquals(listOf("B"), result.state.sources)
        assertEquals("", result.state.selectedSource)
        assertEquals(null, result.state.selectedCandidate)
        assertEquals(listOf(""), persisted)
        assertEquals(listOf(""), ownerUpdates)
    }

    @Test
    fun invalidClickCannotLeaveSplitBrainState() {
        val persisted = mutableListOf<String>()
        val ownerUpdates = mutableListOf<String>()
        val controller = BifrostSourceAuthorityController(
            persistSource = { persisted += it; true },
            updateOwner = { ownerUpdates += it },
        )
        val current = BifrostSourceAuthorityState(true, listOf("A"), listOf("auto", "A"), "A", "A-01")
        val authority = BifrostSourceAuthority.fromVerifiedConfig(
            JSONObject().put("sources", org.json.JSONArray()
                .put(JSONObject().put("code", "B").put("configured", true))).toString(),
        )
        val result = controller.apply(current, authority, requestedSource = "A", persistSelection = true)
        assertFalse(result.accepted)
        assertEquals("", result.state.selectedSource)
        assertEquals(listOf(""), persisted)
        assertEquals(listOf(""), ownerUpdates)
    }

    @Test
    fun validAuthoritySelectionPersistsAndUpdatesOwnerOnce() {
        val persisted = mutableListOf<String>()
        val ownerUpdates = mutableListOf<String>()
        val controller = BifrostSourceAuthorityController(
            persistSource = { persisted += it; true },
            updateOwner = { ownerUpdates += it },
        )
        val current = BifrostSourceAuthorityState(true, listOf("A"), listOf("auto", "A"), "A", "A-01")
        val authority = BifrostSourceAuthority.fromVerifiedConfig(
            JSONObject().put("sources", org.json.JSONArray()
                .put(JSONObject().put("code", "B").put("configured", true))).toString(),
        )
        val result = controller.apply(current, authority, requestedSource = "b", persistSelection = true)
        assertTrue(result.accepted)
        assertEquals("B", result.state.selectedSource)
        assertEquals(null, result.state.selectedCandidate)
        assertEquals(listOf("B"), persisted)
        assertEquals(listOf("B"), ownerUpdates)
    }
}
