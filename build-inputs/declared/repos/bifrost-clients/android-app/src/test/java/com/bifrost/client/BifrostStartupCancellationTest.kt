package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class BifrostStartupCancellationTest {
    @Test fun cancelClosesAnUnresponsiveStartupSocketBeforeItsNetworkDeadline() {
        val health = BifrostDataPlaneHealth()
        val config = JSONObject().put("inbounds", JSONArray())
            .put("route", JSONObject().put("rules", JSONArray()).put("final", "proxy"))
        health.configure(config)
        val port = config.getJSONArray("inbounds").getJSONObject(0).getInt("listen_port")
        val worker = Executors.newSingleThreadExecutor()
        val cancelled = AtomicBoolean(false)
        try {
            ServerSocket().use { server ->
                server.bind(InetSocketAddress("127.0.0.1", port))
                server.soTimeout = 2000
                val result = worker.submit<Boolean> { health.check(30_000) { cancelled.get() } }
                server.accept().use { peer ->
                    // The real checker is now waiting for a SOCKS handshake.
                    assertEquals(5, peer.getInputStream().read())
                    cancelled.set(true)
                    assertFalse(result.get(2, TimeUnit.SECONDS))
                }
            }
        } finally {
            health.close()
            worker.shutdownNow()
        }
    }

    @Test fun cancelledTransactionNeverCreatesANewFenceOrStartsTheCore() {
        val policy = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
        var fences = 0
        var starts = 0
        val boundary = BifrostLeakBoundary(object : BifrostBlackholeController {
            override fun enter(): Boolean { fences++; return true }
            override fun release() = Unit
        })
        val runtime = BifrostRuntimeCoordinator(boundary, {}, { false })
        val core = object : BifrostConnectionCorePort {
            override fun start(connection: BifrostCompiledConnection) { starts++ }
            override fun readback(expectedBindings: List<BifrostApplicationPackageBinding>?) = policy
        }
        try {
            BifrostConnectionTransaction(runtime, core).connect(
                BifrostCompiledConnection("{}", "auto", policy, emptyList(), cancelled = { true }))
            fail("Cancelled transaction must not start")
        } catch (expected: java.io.IOException) {
            assertEquals("BF-CONNECTION-RELEASED", expected.message)
        }
        assertEquals(0, fences)
        assertEquals(0, starts)
    }

    @Test fun cancellationAfterNativeStartCannotPublishHealthy() {
        val policy = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
        val cancelled = AtomicBoolean(false)
        var releases = 0
        val boundary = BifrostLeakBoundary(object : BifrostBlackholeController {
            override fun enter() = true
            override fun release() { releases++ }
        })
        val runtime = BifrostRuntimeCoordinator(boundary, {}, { false })
        val core = object : BifrostConnectionCorePort {
            override fun start(connection: BifrostCompiledConnection) { cancelled.set(true) }
            override fun readback(expectedBindings: List<BifrostApplicationPackageBinding>?) = policy
        }
        try {
            BifrostConnectionTransaction(runtime, core).connect(
                BifrostCompiledConnection("{}", "auto", policy, emptyList(), cancelled = { cancelled.get() }))
            fail("Late cancellation must not publish ready")
        } catch (expected: java.io.IOException) {
            assertEquals("BF-CONNECTION-RELEASED", expected.message)
        }
        assertEquals(BifrostLeakState.STARTING, runtime.snapshot.state)
        assertEquals(0, releases)
        assertTrue(runtime.disconnect().success)
        assertEquals(BifrostLeakState.STOPPED, runtime.snapshot.state)
    }
}
