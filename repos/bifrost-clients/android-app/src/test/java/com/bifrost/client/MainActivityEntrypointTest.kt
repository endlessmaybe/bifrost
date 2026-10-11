package com.bifrost.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier

/** Verifies the compiled Compose entrypoint, rather than only searching source text. */
class MainActivityEntrypointTest {
    @Test
    fun compiledUiHasOneCurrentComposeHomeAndNoLegacyEntrypoints() {
        // This is intentionally a classloader/bytecode assertion.  It must
        // fail if the production class is renamed, removed, duplicated, or if
        // a stale MainActivityKt/legacy top-level screen comes back.
        val current = Class.forName("com.bifrost.client.ui.screens.BifrostAHomeScreenKt")
        val currentEntrypoints = current.declaredMethods.filter { it.name == "BifrostAHomeScreen" }
        assertEquals(1, currentEntrypoints.size)
        val entrypoint = currentEntrypoints.single()
        assertTrue(Modifier.isPublic(entrypoint.modifiers))
        assertTrue(Modifier.isStatic(entrypoint.modifiers))
        assertEquals(Void.TYPE, entrypoint.returnType)

        val forbiddenNames = setOf("BifrostScreen", "LegacyBifrostScreen", "LegacyBifrostScreen2")
        val owners = listOf(
            "com.bifrost.client.MainActivityKt",
            "com.bifrost.client.ui.screens.MainActivityKt",
            "com.bifrost.client.ui.screens.BifrostAHomeScreenKt",
        )
        val productionMethods = owners.flatMap { className ->
            runCatching { Class.forName(className).declaredMethods.asSequence().map { it.name }.toList() }
                .getOrDefault(emptyList())
        }
        assertEquals(1, productionMethods.count { it == "BifrostAHomeScreen" })
        productionMethods.forEach { methodName -> assertFalse(methodName in forbiddenNames) }
    }
}
