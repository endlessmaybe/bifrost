package com.bifrost.client

import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.net.ServerSocket
import android.content.ContextWrapper
import kotlin.io.path.createTempDirectory
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Lifecycle acceptance seam.  The harness supplies exact bytes emitted by the
 * live Control package endpoint.  Consumption goes through the production
 * package verifier and the production encrypted cache binding/read gate; the
 * only injected values are TEST-ONLY X25519 key/root material.
 */
class BifrostLifecycleEnvelopeTest {
    @Test
    fun liveControlConfigEnvelopeUsesProductionVerifyDecryptAndLkg() {
        // The harness passes this as a JVM property because a reused Gradle
        // daemon may not inherit arbitrary process environment variables.
        val bindingFile = System.getProperty("bifrost.lifecycle.envelopes.file")
        val raw = bindingFile?.let { File(it).readText(Charsets.UTF_8) }
            ?: System.getProperty("bifrost.lifecycle.envelopes")
            ?: System.getenv("BIFROST_LIFECYCLE_ENVELOPES")
        if (bindingFile != null) check(!raw.isNullOrBlank()) { "lifecycle bindings are required for the dedicated harness" }
        if (raw.isNullOrBlank()) {
            // The ordinary unit suite still executes a real production
            // rejection path; the lifecycle invocation is never a no-op.
            val client = BifrostControlClient(ContextWrapper(null), true)
            val root = createTempDirectory("bifrost-lifecycle-negative-").toFile()
            val key = ByteArray(32) { (it + 17).toByte() }
            try {
                try {
                    client.consumePackageForLifecycleTest(JSONObject().put("config_version", 1L), 1L, ByteArray(32), root, key)
                    throw AssertionError("malformed package was accepted")
                } catch (error: AssertionError) {
                    throw error
                } catch (_: Throwable) {
                    assertTrue(true)
                }
            } finally { root.deleteRecursively(); key.fill(0) }
            return
        }
        val entries = raw.split(';').filter { it.isNotBlank() }
        check(entries.size >= 3) { "lifecycle requires V1/V2/V3 production envelopes" }
        val client = BifrostControlClient(ContextWrapper(null), true)
        val cacheKey = MessageDigest.getInstance("SHA-256").digest("TEST-ONLY-android-lifecycle-cache".toByteArray())
        var stable: BifrostControlClient.LifecyclePackageResult? = null
        var v2: BifrostControlClient.LifecyclePackageResult? = null
        var v3: BifrostControlClient.LifecyclePackageResult? = null
        try {
            entries.forEachIndexed { index, entry ->
                val fields = entry.split('|')
                check(fields.size == 5) { "lifecycle envelope binding" }
                val version = fields[0].toLongOrNull() ?: throw AssertionError("lifecycle version missing")
                val path = fields[1]; val keyPath = fields[2]; val root = File(fields[3]); val trustedPath = fields[4]
                check(version > 0 && File(path).isFile && File(keyPath).isFile) { "lifecycle files missing" }
                val bytes = File(path).readBytes(); val value = JSONObject(bytes.toString(Charsets.UTF_8))
                BifrostProtocolContract.validateResponse("/v1/config/packages/$version", value, "GET", 200)
                assertEquals(version, value.optLong("config_version"))
                val privateKey = File(keyPath).readBytes(); val trustedKey = File(trustedPath).readBytes()
                try {
                    when (index) {
                        0 -> {
                            stable = client.consumePackageForLifecycleTest(value, version, privateKey, root, cacheKey, trustedKey)
                            assertEquals("stable", stable!!.commitState)
                            assertTrue(stable!!.lkgPreserved)
                            writeMarker(root, index, stable!!.version, stable!!.digest, stable!!.content, stable!!.commitState, stable!!.lkgPreserved, false)
                        }
                        1 -> {
                            try {
                                client.consumePackageForLifecycleTest(value, version, privateKey, root, cacheKey, trustedKey, failureAfterCacheWrite = true)
                                throw AssertionError("injected post-cache failure was accepted")
                            } catch (error: IllegalStateException) {
                                assertTrue("injected failure code=${error.message}", error.message?.startsWith("BF-") == true)
                            }
                            val restored = BifrostConfigStore.loadForTest(root, cacheKey, stable!!.version, stable!!.digest, stable!!.version)
                            assertEquals(semanticContent(stable!!.content), semanticContent(restored!!.content))
                            v2 = client.consumePackageForLifecycleTest(value, version, privateKey, root, cacheKey, trustedKey)
                            assertNotEquals(semanticContent(stable!!.content), semanticContent(v2!!.content))
                            assertTrue(v2!!.lkgPreserved)
                            val unavailable = runCatching {
                                BifrostConfigCompiler.compile(
                                    v2!!.content,
                                    "A",
                                    "XX",
                                    "smart",
                                    "sing-box",
                                    applicationPolicy = BifrostApplicationPolicy.normalize("smart", "none", emptyList(), emptyList()),
                                )
                            }.exceptionOrNull()
                            assertTrue(unavailable is IllegalStateException && unavailable.message in setOf("BF-COUNTRY-NOT-AVAILABLE", "BF-COUNTRY-NOT_FOUND"))
                            writeMarker(root, index, v2!!.version, v2!!.digest, v2!!.content, v2!!.commitState, v2!!.lkgPreserved, false)
                        }
                        2 -> {
                            v3 = client.consumePackageForLifecycleTest(value, version, privateKey, root, cacheKey, trustedKey)
                            assertEquals(semanticContent(stable!!.content), semanticContent(v3!!.content))
                            assertNotEquals(semanticContent(v2!!.content), semanticContent(v3!!.content))
                            assertTrue(v3!!.lkgPreserved)
                            val restored = BifrostConfigCompiler.compile(
                                v3!!.content,
                                "A",
                                "XX",
                                "smart",
                                "sing-box",
                                applicationPolicy = BifrostApplicationPolicy.normalize("smart", "none", emptyList(), emptyList()),
                            )
                            assertTrue(restored.isNotBlank())
                            writeMarker(root, index, v3!!.version, v3!!.digest, v3!!.content, v3!!.commitState, v3!!.lkgPreserved, false)
                        }
                        else -> {
                            try {
                                client.consumePackageForLifecycleTest(value, version, privateKey, root, cacheKey, trustedKey)
                                throw AssertionError("stale package replay accepted")
                            } catch (error: IllegalStateException) { assertTrue(error.message?.startsWith("BF-") == true) }
                            val read = BifrostConfigStore.loadForTest(root, cacheKey, v3!!.version, v3!!.digest, v3!!.version)
                            assertEquals(semanticContent(v3!!.content), semanticContent(read!!.content))
                            writeMarker(root, index, read!!.version, read.digest, read.content, read.commitState, true, true)
                        }
                    }
                } finally { privateKey.fill(0); trustedKey.fill(0); bytes.fill(0) }
            }
            val expired = JSONObject(v3!!.content)
            expired.getJSONObject("account").put("plan", "time_limited").put("expires_at", "2025-01-01T00:00:00Z")
            assertTrue(runCatching {
                BifrostConfigGraphValidator.validate(expired, v3!!.version, Instant.parse("2026-01-01T00:00:00Z"))
            }.isFailure)
            val last = entries[2].split('|'); val lastValue = JSONObject(File(last[1]).readText())
            val corrupt = JSONObject(lastValue.toString()).put("ciphertext", "AA")
            try {
                client.consumePackageForLifecycleTest(corrupt, last[0].toLong(), File(last[2]).readBytes(), File(last[3]), cacheKey, File(last[4]).readBytes())
                throw AssertionError("tampered package accepted")
            } catch (_: IllegalStateException) {
                val read = BifrostConfigStore.loadForTest(File(last[3]), cacheKey, v3!!.version, v3!!.digest, v3!!.version)
                assertEquals(v3!!.content, read!!.content)
            }
            val stoppedPort = ServerSocket(0).use { it.localPort }
            val offlineClient = BifrostControlClient(ContextWrapper(null), true)
            val offline = offlineClient.refreshUnavailableForLifecycleTest("http://127.0.0.1:$stoppedPort") {
                BifrostConfigStore.loadForTest(File(last[3]), cacheKey, v3!!.version, v3!!.digest, v3!!.version)
            }
            assertEquals("offline", offline.state)
            assertEquals(v3!!.version, offline.configVersion)
            val persistedOffline = BifrostConfigStore.loadForTest(File(last[3]), cacheKey, v3!!.version, v3!!.digest, v3!!.version)
            assertEquals(v3!!.digest, persistedOffline!!.digest)
            File(File(last[3]), "offline-lkg-marker.txt").writeText(
                "CLIENT-OFFLINE-LKG PASS outcome=${offline.state} version=${offline.configVersion} digest=${persistedOffline.digest}",
                Charsets.UTF_8,
            )
            val matrix = listOf(
                Triple("A", "auto", "smart") to Triple("sing-box", emptyList<String>(), emptyList<String>()),
                Triple("B", "auto", "global") to Triple("xray", emptyList<String>(), emptyList<String>()),
                Triple("A", "XX", "per-app") to Triple("sing-box", listOf("test.only.allow"), emptyList<String>()),
                Triple("B", "auto", "per-app") to Triple("xray", emptyList<String>(), listOf("test.only.exclude")),
            )
            val matrixDigests = matrix.map { (selection, options) ->
                val (source, country, mode) = selection
                val (core, include, exclude) = options
                val policyMode = if (mode == "per-app") if (include.isNotEmpty()) "allow" else "exclude" else "none"
                val snapshot = if (mode == "per-app") {
                    BifrostApplicationPolicy.normalize(mode, policyMode, include.toList(), exclude.toList())
                } else {
                    BifrostApplicationPolicy.normalize(mode, "none", emptyList(), emptyList())
                }
                val compiled = BifrostConfigCompiler.compile(v3!!.content, source, country, mode, core, include, exclude, selectedCandidate = null, xrayPort = if (core == "xray") 10808 else 0, applicationPolicy = snapshot, appPolicyMode = policyMode)
                val compiledJson = JSONObject(compiled)
                assertTrue(compiledJson.has("route"))
                assertTrue(!compiled.contains("socks5://", ignoreCase = true))
                assertTrue(!compiled.contains("TEST-ONLY-user") && !compiled.contains("TEST-ONLY-pass"))
                MessageDigest.getInstance("SHA-256").digest(compiled.toByteArray()).joinToString("") { "%02x".format(it) }
            }
            val v3Json = JSONObject(v3!!.content)
            val sourceACandidate = v3Json.getJSONArray("sources").let { sources ->
                (0 until sources.length()).asSequence().mapNotNull { sources.optJSONObject(it) }
                    .first { it.optString("code") == "A" }.getJSONArray("candidates").getJSONObject(0).optString("label")
            }
            var crossSourceRejected = false
            try {
                val snapshot = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
                BifrostConfigCompiler.compile(v3!!.content, "B", "auto", "global", "sing-box", selectedCandidate = sourceACandidate, applicationPolicy = snapshot, appPolicyMode = "allow")
            } catch (error: IllegalStateException) {
                crossSourceRejected = error.message == "BF-SOURCE-CANDIDATE-NOT_FOUND"
            }
            assertTrue(crossSourceRejected)
            File(File(last[3]), "selection-matrix-marker.txt").writeText(
                "CLIENT-SELECTION-MATRIX PASS cases=${matrixDigests.size} cross_source_rejected=$crossSourceRejected digests=${matrixDigests.joinToString(",")}", Charsets.UTF_8
            )
            var controlledCases = 0
            val routes = matrix.map { (selection, options) ->
                val blackhole = object : BifrostBlackholeController {
                    var held = false
                    override fun enter(): Boolean { held = true; return true }
                    override fun release() { held = false }
                }
                val boundary = BifrostLeakBoundary(blackhole)
                var stopped = 0
                val runtime = BifrostRuntimeCoordinator(boundary, { stopped++ }, { true })
                var active: BifrostCompiledConnection? = null
                val corePort = object : BifrostConnectionCorePort {
                    override fun start(connection: BifrostCompiledConnection) { active = connection }
                    override fun readback(expectedBindings: List<BifrostApplicationPackageBinding>?): BifrostApplicationPolicySnapshot =
                        active?.applicationPolicy ?: error("BF-APP-POLICY-READBACK")
                }
                val (source, country, mode) = selection
                val (core, include, exclude) = options
                val policyMode = if (mode == "per-app") if (include.isNotEmpty()) "allow" else "exclude" else "none"
                val snapshot = if (mode == "per-app") {
                    BifrostApplicationPolicy.normalize(mode, policyMode, include.toList(), exclude.toList())
                } else BifrostApplicationPolicy.normalize(mode, "none", emptyList(), emptyList())
                val compiled = BifrostConfigCompiler.compile(
                    v3!!.content, source, country, mode, core,
                    include, exclude, selectedCandidate = null,
                    xrayPort = if (core == "xray") 10808 else 0,
                    applicationPolicy = snapshot, appPolicyMode = policyMode,
                )
                val readback = BifrostConnectionTransaction(runtime, corePort).connect(
                    BifrostCompiledConnection(compiled, core, snapshot, null),
                )
                assertEquals(snapshot.digest, readback.digest)
                assertEquals(BifrostLeakState.HEALTHY, runtime.snapshot.state)
                val outcome = runtime.disconnect()
                assertTrue(outcome.success)
                assertEquals(BifrostLeakState.STOPPED, runtime.snapshot.state)
                assertEquals(1, stopped)
                controlledCases++
                "${selection.first}:${options.first}"
            }
            val failedBlackhole = object : BifrostBlackholeController {
                var held = false
                override fun enter(): Boolean { held = true; return true }
                override fun release() { held = false }
            }
            val failedBoundary = BifrostLeakBoundary(failedBlackhole)
            var failedStops = 0
            val failedRuntime = BifrostRuntimeCoordinator(failedBoundary, { failedStops++ }, { true })
            val failedPolicy = BifrostApplicationPolicy.normalize("smart", "none", emptyList(), emptyList())
            val failedCore = object : BifrostConnectionCorePort {
                override fun start(connection: BifrostCompiledConnection) = error("BF-TEST-CORE-FAIL")
                override fun readback(expectedBindings: List<BifrostApplicationPackageBinding>?) = failedPolicy
            }
            var failedStart = false
            try {
                BifrostConnectionTransaction(failedRuntime, failedCore).connect(
                    BifrostCompiledConnection("{\"inbounds\":[{\"type\":\"tun\"}]}", "sing-box", failedPolicy, null),
                )
            } catch (_: Exception) {
                failedStart = true
            }
            assertTrue(failedStart)
            val failed = failedRuntime.coreFailureOutcome()
            assertTrue(failed.blocked)
            assertEquals("BF-CORE-BLOCKED", failed.code)
            assertEquals(1, failedStops)
            assertEquals(BifrostLeakState.BLOCKING, failedRuntime.snapshot.state)
            File(File(last[3]), "controlled-runtime-marker.txt").writeText(
                "CLIENT-CONTROLLED-RUNTIME PASS cases=$controlledCases fail_closed=1 routes=${routes.joinToString(",")}", Charsets.UTF_8
            )
        } finally { cacheKey.fill(0) }
    }

    @Test
    fun revokedAndroidRefreshBlocksInsteadOfOffline() {
        val specPath = System.getProperty("bifrost.lifecycle.revoked.file")
            ?: System.getenv("BIFROST_LIFECYCLE_REVOKED_FILE")
        if (specPath.isNullOrBlank()) {
            if ((System.getProperty("bifrost.lifecycle.revoked.required")
                    ?: System.getenv("BIFROST_LIFECYCLE_REVOKED_REQUIRED")) == "true")
                throw AssertionError("revoked refresh binding is required for the dedicated lifecycle invocation")
            // The ordinary unit suite still exercises the same production
            // classifier without a lifecycle root; the dedicated lifecycle
            // invocation supplies the real Control origin/token binding.
            try {
                BifrostControlClient(ContextWrapper(null), true).refreshStatusForLifecycleTest(403) { null }
                throw AssertionError("reachable security rejection became offline")
            } catch (error: Throwable) {
                assertTrue(error.message?.startsWith("BF-") == true)
                assertTrue(error.message?.contains("offline", ignoreCase = true) != true)
            }
            return
        }
        val spec = JSONObject(File(specPath).readText(Charsets.UTF_8))
        val root = File(spec.getString("lkg_root"))
        val version = spec.getLong("version")
        val digest = spec.getString("digest")
        val cacheKey = MessageDigest.getInstance("SHA-256").digest("TEST-ONLY-android-lifecycle-cache".toByteArray())
        val before = BifrostConfigStore.loadForTest(root, cacheKey, version, digest, version)!!
        try {
            BifrostControlClient(ContextWrapper(null), true).refreshReachableForLifecycleTest(
                spec.getString("base_url"),
                spec.getString("session_token"),
            ) { BifrostConfigStore.loadForTest(root, cacheKey, version, digest, version) }
            throw AssertionError("revoked Android refresh unexpectedly became offline")
        } catch (error: Throwable) {
            assertTrue(error.message?.startsWith("BF-") == true)
            assertTrue(error.message?.contains("offline", ignoreCase = true) != true)
        }
        val after = BifrostConfigStore.loadForTest(root, cacheKey, version, digest, version)!!
        assertEquals(before.version, after.version)
        assertEquals(before.digest, after.digest)
        assertEquals(before.content, after.content)
        File(root, "revoked-refresh-marker.txt").writeText(
            "CLIENT-REVOKED-REFRESH PASS outcome=blocked version=${after.version} digest=${after.digest}",
            Charsets.UTF_8,
        )
        cacheKey.fill(0)
    }

    private fun writeMarker(root: File, index: Int, version: Long, digest: String, content: String, commitState: String, lkgPreserved: Boolean, stale: Boolean) {
        val contentDigest = MessageDigest.getInstance("SHA-256").digest(semanticContent(content).toByteArray()).joinToString("") { "%02x".format(it) }
        File(root, "production-marker-$index.txt").writeText(
            "CLIENT-PACKAGE-COMMIT PASS device=android version=$version digest=$digest content_digest=$contentDigest commit_state=$commitState lkg_preserved=$lkgPreserved stale_replay_rejected=$stale",
            Charsets.UTF_8,
        )
    }

    private fun semanticContent(content: String): String {
        val value = JSONObject(content)
        value.remove("config_version"); value.remove("anti_rollback"); value.remove("generated_at")
        return canonical(value)
    }

    private fun canonical(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(",", "{", "}") { key -> JSONObject.quote(key) + ":" + canonical(value.get(key)) }
        is org.json.JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { canonical(value.get(it)) }
        is String -> JSONObject.quote(value)
        is Boolean, is Number -> value.toString()
        else -> JSONObject.quote(value.toString())
    }
}
