package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test

class ConnectionPersistenceTest {
    @Test fun completedConnectionSelectionCanBeReadBackAndRolledBackAsOneTuple() {
        val stored = mutableMapOf<String, String?>()
        val backend = object : BifrostSecureStore.Backend {
            override fun secureValue(key: String) = stored[key]
            override fun legacyValue(key: String): String? = null
            override fun commitSecure(values: Map<String, String?>): Boolean {
                stored.putAll(values)
                return true
            }
            override fun scrubLegacy(keys: Set<String>) = true
        }
        val previous = BifrostSecureStore.Transaction.readBatch(backend, BifrostSecureStore.UiKeys)
        val selected = mapOf("connection_type" to "direct-vmess", "route_mode" to "smart",
            "candidate_mode" to "auto", "candidate_label" to null, "source" to "A")
        BifrostSecureStore.Transaction.apply(backend, selected)
        val readback = BifrostSecureStore.Transaction.readBatch(backend, BifrostSecureStore.UiKeys)
        selected.forEach { (key, value) ->
            assertTrue("Connection field is absent from the atomic readback: $key", readback.containsKey(key))
            assertEquals(value, readback[key])
        }
        BifrostSecureStore.Transaction.apply(backend, previous)
        assertEquals(previous, BifrostSecureStore.Transaction.readBatch(backend, BifrostSecureStore.UiKeys))
    }
}
