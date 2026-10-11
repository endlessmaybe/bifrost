package com.bifrost.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.json.JSONObject
import java.nio.file.Files
import java.time.Instant
import java.net.ProtocolException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.io.InputStream
import java.io.OutputStream
import java.io.ByteArrayOutputStream
import javax.net.ssl.SSLHandshakeException
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

class BifrostSecurityValidationTest {
    @Test
    fun importedVmessOptionalDefaultsMatchWindowsAndRequiredFieldsStayStrict() {
        for (value in listOf("", JSONObject.NULL)) {
            val config = testConfig(7)
            val transport = config.getJSONArray("sources").getJSONObject(0).getJSONObject("transport")
            for (field in listOf("alpn", "fingerprint", "header_type")) transport.put(field, value)
            BifrostConfigGraphValidator.validate(config, 7)
        }
        for (field in listOf("alpn", "fingerprint", "header_type")) {
            for (invalid in listOf<Any>(42, true, "\n", " ", "x".repeat(129))) {
                val config = testConfig(7)
                config.getJSONArray("sources").getJSONObject(0).getJSONObject("transport").put(field, invalid)
                assertGraphRejects(config, 7)
            }
        }
        for (field in listOf("host", "sni")) {
            val config = testConfig(7)
            config.getJSONArray("sources").getJSONObject(0).getJSONObject("transport").put(field, "")
            assertGraphRejects(config, 7)
        }
    }

    @Test
    fun unenrolledBootstrapOriginDoesNotDependOnPersistedControlState() {
        // ContextWrapper(null) deliberately has no usable SharedPreferences.
        // The bootstrap override must therefore validate the trusted release
        // origin without consulting any stale persisted control_base_url.
        val client = BifrostControlClient(android.content.ContextWrapper(null), true)
        client.requireBootstrapOriginForTest(
            "https://edge.bifrostlog.com/v1/enrollment/redeem",
            "https://edge.bifrostlog.com",
        )

        try {
            client.requireBootstrapOriginForTest(
                "https://other.invalid/v1/enrollment/redeem",
                "https://edge.bifrostlog.com",
            )
            fail("bootstrap origin mismatch was accepted")
        } catch (error: IllegalStateException) {
            assertEquals("BF-CONTROL-ORIGIN", error.message)
        }
    }

    @Test
    fun successfulLogoutCanProduceAFreshValidEnrollmentIdentity() {
        val first = DeviceKeys.freshEnrollmentIdentityRecord()
        val second = DeviceKeys.freshEnrollmentIdentityRecord()
        DeviceKeys.validateIdentityRecord(first)
        DeviceKeys.validateIdentityRecord(second)
        val a = JSONObject(first)
        val b = JSONObject(second)
        assertFalse(a.getString("device_id") == b.getString("device_id"))
        assertFalse(a.getString("signing_public") == b.getString("signing_public"))
        assertFalse(a.getString("encryption_public") == b.getString("encryption_public"))
    }

    @Test
    fun offlineFallbackAllowListRejectsReachableSecurityFailures() {
        assertTrue(BifrostAvailabilityClassifier.canUseOffline(BifrostTransportUnavailableException(BifrostTransportReason.DNS)))
        assertTrue(BifrostAvailabilityClassifier.canUseOffline(BifrostTransportUnavailableException(BifrostTransportReason.CONNECTION)))
        assertTrue(BifrostAvailabilityClassifier.canUseOffline(BifrostTransportUnavailableException(BifrostTransportReason.DEADLINE)))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(IllegalStateException("BF-CONTROL-HTTP")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(IllegalStateException("BF-CONTROL-503")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(IllegalStateException("BF-CONTROL-401")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(IllegalStateException("BF-CONTROL-403")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(IllegalStateException("BF-CONTROL-410")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(IllegalStateException("BF-CONFIG-SIGNATURE")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(IllegalStateException("BF-ENTITLEMENT-EXPIRED")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(SSLHandshakeException("certificate")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(ProtocolException("protocol")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(SecurityException("keystore")))
        assertFalse(BifrostAvailabilityClassifier.canUseOffline(BifrostTransportUnavailableException(BifrostTransportReason.CONNECTION, SSLHandshakeException("certificate"))))
        assertTrue(BifrostAvailabilityClassifier.canUseOfflineStatus(502))
        assertFalse(BifrostAvailabilityClassifier.canUseOfflineStatus(401))
        assertFalse(BifrostAvailabilityClassifier.canUseOfflineStatus(403))
        assertFalse(BifrostAvailabilityClassifier.canUseOfflineStatus(410))
        assertTrue(BifrostAvailabilityClassifier.canUseOfflineStatus(503))
        assertTrue(BifrostAvailabilityClassifier.canUseOfflineStatus(504))
    }

    @Test
    fun onlyKnownSocketFailuresBecomeTypedTransportUnavailable() {
        fun assertMapped(failure: Throwable) {
            try {
                mapBifrostTransportFailure(failure)
                fail("transport failure was not mapped")
            } catch (mapped: BifrostTransportUnavailableException) {
                assertTrue(mapped.message?.startsWith("BF-CONTROL-") == true)
            }
        }
        assertMapped(java.net.UnknownHostException("TEST-ONLY.invalid"))
        assertMapped(java.net.ConnectException("TEST-ONLY refused"))
        assertMapped(java.net.NoRouteToHostException("TEST-ONLY route"))
        assertMapped(java.net.SocketTimeoutException("TEST-ONLY timeout"))
        try { mapBifrostTransportFailure(SSLHandshakeException("certificate")); fail("TLS failure mapped offline") }
        catch (_: SSLHandshakeException) { }
    }

    @Test
    fun productionRefreshDoesNotTurnReachableRejectionIntoOffline() {
        val cached = BifrostConfigStore.Cached("sing-box", "{\"config_version\":1}", 1L, "a".repeat(64))
        listOf(401, 403, 410, 500).forEach { status ->
            val client = BifrostControlClient(android.content.ContextWrapper(null), true)
            try {
                client.refreshStatusForLifecycleTest(status) { cached }
                fail("status $status was relabelled offline")
            } catch (error: IllegalStateException) {
                assertTrue(error.message?.startsWith("BF-") == true)
            }
        }
        listOf(502, 503, 504).forEach { status ->
            val before = cached.content to cached.digest
            val offline = BifrostControlClient(android.content.ContextWrapper(null), true).refreshStatusForLifecycleTest(status) { cached }
            assertEquals("offline", offline.state)
            assertEquals(1L, offline.configVersion)
            assertEquals(before, cached.content to cached.digest)
        }
    }

    @Test
    fun productionHttpStatusWinsOverErrorBodyTimeoutAndRetryableStatusesUseTheCommonLkgGate() {
        val cached = BifrostConfigStore.Cached("sing-box", "{\"config_version\":1}", 1L, "a".repeat(64))
        for (status in listOf(403, 410)) {
            val client = BifrostControlClient(android.content.ContextWrapper(null), true)
            val error: Throwable = try {
                client.withLifecycleHttpConnectionFactory(
                    BifrostLifecycleHttpConnectionFactory { url -> TimeoutErrorBodyConnection(url, status) },
                ) {
                    client.refreshReachableForLifecycleTest("http://127.0.0.1:18181", "TEST-ONLY-session", { cached })
                }
                throw AssertionError("reachable status $status was accepted")
            } catch (failure: Throwable) { failure }
            assertFalse(error is BifrostTransportUnavailableException)
            assertEquals("BF-CONTROL-$status", error.message)
        }

        for (status in listOf(502, 503, 504, 530)) {
            val client = BifrostControlClient(android.content.ContextWrapper(null), true)
            val result = client.withLifecycleHttpConnectionFactory(
                BifrostLifecycleHttpConnectionFactory { url -> TimeoutErrorBodyConnection(url, status) },
            ) {
                client.refreshReachableForLifecycleTest("http://127.0.0.1:18181", "TEST-ONLY-session", { cached })
            }
            assertEquals("offline", result.state)
            assertEquals(cached.version, result.configVersion)
        }

        var reads = 0
        val mutated = cached.copy(content = "{\"config_version\":1,\"changed\":true}")
        val client = BifrostControlClient(android.content.ContextWrapper(null), true)
        try {
            client.withLifecycleHttpConnectionFactory(
                BifrostLifecycleHttpConnectionFactory { url -> TimeoutErrorBodyConnection(url, 503) },
            ) {
                client.refreshReachableForLifecycleTest("http://127.0.0.1:18181", "TEST-ONLY-session") {
                    reads++
                    if (reads >= 3) mutated else cached
                }
            }
            fail("mutated LKG was accepted")
        } catch (error: IllegalStateException) {
            assertEquals("BF-CONFIG-OFFLINE-MUTATED", error.message)
        }
    }

    @Test
    fun sensitiveClipboardIsEqualityBoundAndFailureVisible() {
        val clipboard = FakeSensitiveClipboard()
        val controller = BifrostSensitiveClipboardController(clipboard)
        assertTrue(controller.copy("TEST-ONLY-RECOVERY"))
        clipboard.value = "user replacement"
        assertTrue(controller.clearOwned())
        assertEquals("user replacement", clipboard.value)
        // Losing ownership is a safe no-op; a later explicit copy must not
        // be blocked or clear the user's replacement first.
        assertTrue(controller.copy("TEST-ONLY-NEW"))
        assertEquals("TEST-ONLY-NEW", clipboard.value)

        clipboard.value = "user replacement"
        clipboard.writeSucceeds = false
        assertFalse(controller.copy("TEST-ONLY-PAIRING"))
        assertEquals("user replacement", clipboard.value)

        clipboard.value = null
        clipboard.writeSucceeds = true
        assertTrue(controller.copy("TEST-ONLY-PAIRING"))
        assertTrue(controller.clearOwned())
        assertNull(clipboard.value)
    }

    @Test
    fun sensitiveValuesHaveIndependentSlotsAndExpire() {
        var now = 1_000L
        val values = BifrostSensitiveValueStore({ now }, ttlMs = 100L)
        assertTrue(values.publishRecovery("TEST-ONLY-RECOVERY"))
        assertTrue(values.publishPairing("TEST-ONLY-PAIRING"))
        assertTrue(values.acknowledgePairing())
        assertNull(values.revealPairing())
        assertEquals("TEST-ONLY-RECOVERY", values.revealRecovery())
        assertTrue(values.acknowledgeRecovery())
        assertNull(values.revealRecovery())
        assertFalse(values.acknowledgeRecovery())
        assertTrue(values.publishRecovery("TEST-ONLY-EXPIRING"))
        now += 101L
        assertNull(values.revealRecovery())
    }

    @Test
    fun sensitiveDisplayRemasksEachSlotBeforeOverallExpiry() {
        var now = 1_000L
        val display = BifrostSensitiveDisplayController({ now }, ttlMs = 100L)
        assertTrue(display.revealRecovery(true))
        assertTrue(display.recoveryVisible(true))
        assertTrue(display.revealPairing(true))
        now += 99L
        assertTrue(display.recoveryVisible(true))
        assertTrue(display.pairingVisible(true))
        now += 1L
        assertFalse(display.recoveryVisible(true))
        assertFalse(display.pairingVisible(true))
        assertFalse(display.revealRecovery(false))
    }

    @Test
    fun invalidSensitiveReplacementClearsOnlyItsSlot() {
        val values = BifrostSensitiveValueStore({ 1_000L }, ttlMs = 1_000L)
        assertTrue(values.publishRecovery("TEST-ONLY-RECOVERY"))
        assertTrue(values.publishPairing("TEST-ONLY-PAIRING"))
        assertFalse(values.publishRecovery("bad\nsecret"))
        assertNull(values.revealRecovery())
        assertEquals("TEST-ONLY-PAIRING", values.revealPairing())
        assertFalse(values.publishPairing("x".repeat(257)))
        assertNull(values.revealPairing())
    }

    @Test
    fun uiErrorMappingNeverLeaksRawExceptionText() {
        val secret = "https://node.test.invalid/uuid?token=TEST-ONLY"
        val generic = BifrostUiErrorMapper.message("激活", IllegalStateException(secret))
        assertEquals("激活失败，请检查网络或稍后重试", generic)
        assertFalse(generic.contains("node.test", ignoreCase = true))
        assertFalse(generic.contains("TEST-ONLY"))

        val known = BifrostUiErrorMapper.message("连接", IllegalStateException("BF-CONFIG-CACHE-MISSING"))
        assertEquals("没有可用的已验证配置，请先完成设备激活", known)
        assertFalse(known.contains("node.test", ignoreCase = true))

        val tainted = BifrostUiErrorMapper.message(
            "连接",
            IllegalStateException("BF-CONFIG-CACHE-MISSING: $secret"),
        )
        assertEquals("连接失败，请检查网络或稍后重试", tainted)
        assertFalse(tainted.contains("node.test", ignoreCase = true))
        assertFalse(tainted.contains("TEST-ONLY"))
    }

    @Test
    fun uiErrorMappingUsesAClosedStableCodeBoundary() {
        val valid = BifrostUiErrorMapper.message(
            "连接",
            IllegalStateException("BF-SOURCE-SELECTION-REQUIRED"),
        )
        assertEquals("请先选择源站 A 或 B", valid)

        val invalidInputs = listOf(
            "BF-" + "A".repeat(62),
            "bf-source-selection-required",
            "BF-SOURCE-SELECTION-REQUIRED: https://node.test.invalid/secret",
        )
        invalidInputs.forEach { raw ->
            val message = BifrostUiErrorMapper.message("连接", IllegalStateException(raw))
            assertEquals("连接失败，请检查网络或稍后重试", message)
            assertFalse(message.contains("node.test", ignoreCase = true))
            assertFalse(message.contains("secret", ignoreCase = true))
        }
    }

    @Test
    fun genericActivationFailureRetainsOnlyRegisteredDiagnostic() {
        val diagnostic = BifrostUiErrorMapper.message("激活", IllegalStateException("BF-CONTROL-ORIGIN"))
        assertTrue(diagnostic.contains("BF-CONTROL-ORIGIN"))
        assertFalse(diagnostic.contains("请检查输入"))
        val tainted = BifrostUiErrorMapper.message("激活", IllegalStateException("BF-CONTROL-ORIGIN: TEST-ONLY-SECRET"))
        assertFalse(tainted.contains("BF-CONTROL-ORIGIN"))
        assertFalse(tainted.contains("TEST-ONLY-SECRET"))
    }

    @Test
    fun networkFailuresExposeOnlyFixedDiagnosticDescriptions() {
        val secret = "https://private.invalid/?token=TEST-ONLY-SECRET"
        for (error in listOf(javax.net.ssl.SSLHandshakeException(secret), java.net.SocketException(secret), java.net.UnknownHostException(secret), java.net.SocketTimeoutException(secret))) {
            val message = BifrostUiErrorMapper.message("节点更新", error)
            assertTrue(message.contains("BF-CONTROL-"))
            assertFalse(message.contains("private.invalid"))
            assertFalse(message.contains("TEST-ONLY-SECRET"))
        }

        assertFalse(BifrostAvailabilityClassifier.canUseOffline(javax.net.ssl.SSLHandshakeException(secret)))
        assertTrue(BifrostUiErrorMapper.message("节点更新", BifrostReachableStatusException(403)).contains("认证"))
        assertFalse(BifrostUiErrorMapper.message("节点更新", BifrostReachableStatusException(403)).contains("检查网络"))
    }

    @Test
    fun unavailableTunnelPreservesStatusWithoutParsingGatewayHtml() {
        val cached = BifrostConfigStore.Cached("sing-box", "{\"config_version\":1}", 1L, "a".repeat(64))
        val client = BifrostControlClient(android.content.ContextWrapper(null), true)
        val result = client.withLifecycleHttpConnectionFactory(
            BifrostLifecycleHttpConnectionFactory { url -> object : HttpURLConnection(url) {
                override fun connect() = Unit
                override fun disconnect() = Unit
                override fun usingProxy() = false
                override fun getResponseCode() = 530
                override fun getErrorStream(): InputStream = throw AssertionError("Gateway HTML must not be parsed as a Bifrost response")
                override fun getOutputStream(): OutputStream = ByteArrayOutputStream()
            } },
        ) { client.refreshReachableForLifecycleTest("http://127.0.0.1:18181", "TEST-ONLY-session", { cached }) }
        assertEquals("offline", result.state)
    }

    @Test
    fun nodeRefreshRetriesTransientConnectionButNeverReplaysHttpRejectionsOrTlsFailures() {
        val cached = BifrostConfigStore.Cached("sing-box", "{\"config_version\":1}", 1L, "a".repeat(64))
        for (tls in listOf(false, true)) {
            var calls = 0
            val client = BifrostControlClient(android.content.ContextWrapper(null), true)
            val error = runCatching {
                client.withLifecycleHttpConnectionFactory(BifrostLifecycleHttpConnectionFactory { url ->
                    calls++
                    if (calls == 1) {
                        if (tls) throw javax.net.ssl.SSLHandshakeException("TEST-ONLY")
                        throw java.net.ConnectException("TEST-ONLY")
                    }
                    TimeoutErrorBodyConnection(url, 403)
                }) { client.refreshReachableForLifecycleTest("http://127.0.0.1:18181", "TEST-ONLY-session") { cached } }
            }.exceptionOrNull()
            assertTrue(error != null)
            assertEquals(if (tls) 1 else 2, calls)
            assertFalse(BifrostAvailabilityClassifier.canUseOffline(error!!))
            if (!tls) assertEquals("BF-CONTROL-403", error.message)
        }
    }

    @Test(expected = IllegalStateException::class)
    fun partialIdentityRecordCannotBeAcceptedOrRegenerated() {
        DeviceKeys.validateIdentityRecord(
            """{"version":1,"device_id":"00000000-0000-4000-8000-000000000001","signing_private":""}"""
        )
    }

    @Test(expected = IllegalStateException::class)
    fun duplicateStrictJsonMemberIsRejected() {
        StrictJsonValidator("{" + "\"a\":1,\"a\":2" + "}", "BF-JSON").validate()
    }

    @Test(expected = IllegalStateException::class)
    fun trailingJsonIsRejected() {
        StrictJsonValidator("{\"a\":1}{\"b\":2}", "BF-JSON").validate()
    }

    @Test(expected = IllegalStateException::class)
    fun escapedDuplicateJsonMemberIsRejectedAfterDecoding() {
        StrictJsonValidator("{\"version\":1,\"\\u0076ersion\":2}", "BF-JSON").validate()
    }

    @Test
    fun whitespaceIdentityIsNotAnInitialState() {
        assertFalse(DeviceKeys.isInitialIdentityState(" ", List(5) { "" }))
        assertFalse(DeviceKeys.isInitialIdentityState("", listOf(" ", "", "", "", "")))
    }

    @Test(expected = IllegalStateException::class)
    fun whitespaceIdentityBlobCannotTriggerRegeneration() {
        DeviceKeys.validateIdentityRecord(
            """{"version":1,"device_id":" ","signing_private":"","signing_public":"","encryption_private":"","encryption_public":""}"""
        )
    }

    @Test
    fun x25519FormatDoesNotAcceptEd25519Spki() {
        val ed = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x03, 0x21, 0x00,
        ) + ByteArray(32)
        val x = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x03, 0x21, 0x00,
        ) + ByteArray(32)
        assertFalse(DeviceKeys.isX25519PublicEncoding(ed))
        assertTrue(DeviceKeys.isX25519PublicEncoding(x))
        assertFalse(DeviceKeys.isX25519PublicEncoding(ByteArray(32)))
    }

    @Test
    fun releaseVersionOrderingDoesNotCollapsePrereleases() {
        assertTrue(compareBifrostReleaseVersions("1.0.0-alpha", "1.0.0-beta") < 0)
        assertTrue(compareBifrostReleaseVersions("1.0.0-beta", "1.0.0") < 0)
        assertTrue(compareBifrostReleaseVersions("1.0.0-alpha.2", "1.0.0-alpha.10") < 0)
        assertEquals(0, compareBifrostReleaseVersions("1.0.0", "1.0.0"))
    }

    @Test
    fun malformedReleaseVersionsFailClosed() {
        listOf("1.0", "1.0.0-", "1.0.0-01", "01.0.0", "1.0.0+build").forEach { value ->
            try {
                compareBifrostReleaseVersions(value, "1.0.0")
                fail("malformed release version accepted: $value")
            } catch (error: IllegalStateException) {
                assertEquals("BF-RELEASE-VERSION", error.message)
            }
        }
    }

    @Test
    fun secureValueWithLegacyScrubFailureFailsClosed() {
        val backend = FakeBackend().apply {
            secure["session"] = "encrypted"
            legacy["session"] = "plaintext"
            scrubSucceeds = false
        }
        try {
            BifrostSecureStore.Transaction.read(backend, "session")
            fail("legacy scrub failure must be visible")
        } catch (error: IllegalStateException) {
            assertEquals("BF-SECURE-STORE-WRITE", error.message)
        }
        assertEquals("encrypted", backend.secure["session"])
        assertEquals("plaintext", backend.legacy["session"])
    }

    @Test
    fun deletionDoesNotRemoveEncryptedValueBeforeLegacyScrub() {
        val backend = FakeBackend().apply {
            secure["session"] = "encrypted"
            legacy["session"] = "plaintext"
            scrubSucceeds = false
        }
        try {
            BifrostSecureStore.Transaction.apply(backend, mapOf("session" to null))
            fail("legacy scrub failure must be visible")
        } catch (error: IllegalStateException) {
            assertEquals("BF-SECURE-STORE-WRITE", error.message)
        }
        assertEquals("encrypted", backend.secure["session"])
        assertEquals("plaintext", backend.legacy["session"])
    }

    @Test
    fun migrationWriteFailureRetainsLegacy() {
        val backend = FakeBackend().apply {
            legacy["session"] = "plaintext"
            commitSucceeds = false
        }
        try {
            BifrostSecureStore.Transaction.read(backend, "session")
            fail("failed encrypted commit must be visible")
        } catch (error: IllegalStateException) {
            assertEquals("BF-SECURE-STORE-WRITE", error.message)
        }
        assertNull(backend.secure["session"])
        assertEquals("plaintext", backend.legacy["session"])
    }

    @Test
    fun migrationRetryLeavesOnlyEncryptedAuthority() {
        val backend = FakeBackend().apply { legacy["session"] = "plaintext" }
        assertEquals("plaintext", BifrostSecureStore.Transaction.read(backend, "session"))
        assertEquals("plaintext", backend.secure["session"])
        assertNull(backend.legacy["session"])
    }

    @Test
    fun mutateThenFalseCommitCannotBeReportedAsSuccessful() {
        val backend = FakeBackend().apply {
            legacy["session"] = "plaintext"
            mutateThenFalse = true
        }
        try {
            BifrostSecureStore.Transaction.read(backend, "session")
            fail("a commit that reports false must fail closed")
        } catch (error: IllegalStateException) {
            assertEquals("BF-SECURE-STORE-WRITE", error.message)
        }
        assertEquals("plaintext", backend.legacy["session"])
    }

    @Test
    fun identityTupleMigrationCommitsAndScrubsAsOneBatch() {
        val backend = FakeBackend().apply {
            legacy["device"] = "id"
            legacy["sign"] = "signing"
            legacy["x"] = "encryption"
        }
        val values = BifrostSecureStore.Transaction.readBatch(backend, setOf("device", "sign", "x"))
        assertEquals("id", values["device"])
        assertEquals("signing", values["sign"])
        assertEquals("encryption", values["x"])
        assertTrue(backend.secure.keys.containsAll(setOf("device", "sign", "x")))
        assertTrue(backend.legacy.isEmpty())
    }

    @Test
    fun uiStateMigrationUsesEncryptedAuthorityAndScrubsPlaintextNamespace() {
        val backend = FakeBackend().apply {
            legacy["mode"] = "smart"
            legacy["source"] = "A"
            legacy["theme"] = "dark"
        }

        val values = BifrostSecureStore.Transaction.readBatch(backend, BifrostSecureStore.UiKeys)

        assertEquals("smart", values["mode"])
        assertEquals("A", values["source"])
        assertEquals("dark", values["theme"])
        assertTrue(backend.secure.keys.containsAll(setOf("mode", "source", "theme")))
        assertTrue("legacy UI preferences must be scrubbed", backend.legacy.isEmpty())
    }

    @Test
    fun uiStateMigrationScrubFailureNeverReportsSuccessfulPlaintextPersistence() {
        val backend = FakeBackend().apply {
            legacy["source"] = "A"
            scrubSucceeds = false
        }

        try {
            BifrostSecureStore.Transaction.readBatch(backend, BifrostSecureStore.UiKeys)
            fail("plaintext UI migration must fail when scrub is not durable")
        } catch (error: IllegalStateException) {
            assertEquals("BF-SECURE-STORE-WRITE", error.message)
        }
        assertEquals("A", backend.secure["source"])
        assertEquals("A", backend.legacy["source"])
    }

    @Test
    fun uiStateMigrationNeverOverwritesEncryptedAuthorityWithStaleLegacyValue() {
        val backend = FakeBackend().apply {
            secure["source"] = "new-source"
            legacy["source"] = "old-source"
        }

        val values = BifrostSecureStore.Transaction.readBatch(backend, BifrostSecureStore.UiKeys)

        assertEquals("new-source", values["source"])
        assertEquals("new-source", backend.secure["source"])
        assertNull(backend.legacy["source"])
    }

    @Test
    fun protectedCacheBoundaryIncludesGcmOverhead() {
        val max = BifrostConfigStore.protectedSizeForPlaintext(BifrostConfigStore.MAX_PLAINTEXT_BYTES)
        assertEquals(BifrostConfigStore.MAX_PROTECTED_BYTES, max)
        assertTrue(BifrostConfigStore.isProtectedSizeAllowed(max))
        assertFalse(BifrostConfigStore.isProtectedSizeAllowed(max + 1))
    }

    @Test
    fun maximumConfigCodecPayloadRoundTripsAndClearRemovesStaging() {
        val plaintext = ByteArray(BifrostConfigStore.MAX_PLAINTEXT_BYTES) { (it * 31).toByte() }
        val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
        val iv = ByteArray(12) { (it + 1).toByte() }
        val protected = BifrostConfigCodec.encode(plaintext, key, iv)
        try {
            assertEquals(BifrostConfigStore.MAX_PROTECTED_BYTES, protected.size)
            assertArrayEquals(plaintext, BifrostConfigCodec.decode(protected, key))
        } finally {
            plaintext.fill(0)
            protected.fill(0)
        }
        val directory = Files.createTempDirectory("bifrost-cache-test").toFile()
        try {
            java.io.File(directory, "config.cache").writeBytes(byteArrayOf(1))
            java.io.File(directory, ".config.cache.tmp-test").writeBytes(byteArrayOf(1))
            BifrostConfigStore.clearDirectory(directory)
            assertTrue(directory.listFiles()!!.isEmpty())
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test(expected = IllegalStateException::class)
    fun unexpectedCacheEntryFailsClosedInsteadOfBeingIgnored() {
        val directory = Files.createTempDirectory("bifrost-cache-extra").toFile()
        try {
            java.io.File(directory, "unexpected").writeText("x")
            BifrostConfigStore.clearDirectory(directory)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun signedCountryHopIsValidatedBeforeEitherCompiler() {
        val config = testConfig(7)
        val country = config.getJSONArray("countries").getJSONObject(0)
        val socks = JSONObject().put("scheme", "socks5h").put("host", "egress.example.com")
            .put("port", 1080).put("user", "TEST-user").put("password", "TEST-password")
        country.put("socks", socks)
        BifrostConfigGraphValidator.validate(config, 7)
        for ((key, value) in listOf("port" to "1080", "port" to 0, "scheme" to "http",
            "host" to "user@egress.example.com", "user" to "", "password" to "bad\nvalue", "extra" to true)) {
            val invalid = JSONObject(config.toString())
            invalid.getJSONArray("countries").getJSONObject(0).getJSONObject("socks").put(key, value)
            assertGraphRejects(invalid, 7)
        }
    }

    @Test
    fun validConfigGraphIsAcceptedAndUnsafeVariantsRejected() {
        val valid = testConfig(7)
        BifrostConfigGraphValidator.validate(valid, 7)
        val unknown = JSONObject(valid.toString()).put("unexpected", true)
        assertGraphRejects(unknown, 7)
        val badUuidConfig = JSONObject(valid.toString())
        val badUuid = badUuidConfig
            .getJSONArray("sources").getJSONObject(0)
            .getJSONObject("profiles").getJSONObject("direct")
            .put("uuid", "abcdefab-cdef-4abc-8def-abcdefabcdef".uppercase())
        assertGraphRejects(badUuidConfig, 7)
        val badTransportConfig = JSONObject(valid.toString())
        val badTransport = badTransportConfig.getJSONArray("sources").getJSONObject(0).getJSONObject("transport")
        badTransport.put("alter_id", 1)
        assertGraphRejects(badTransportConfig, 7)
        val unconfiguredFront = JSONObject(valid.toString())
        val source = unconfiguredFront.getJSONArray("sources").getJSONObject(0)
        source.put("configured", false).put("candidates", org.json.JSONArray()).put("transport", JSONObject.NULL).put("ws_path", JSONObject.NULL)
        assertGraphRejects(unconfiguredFront, 7)

        val documentationIp = JSONObject(valid.toString())
        documentationIp.getJSONArray("sources").getJSONObject(0)
            .getJSONArray("candidates").getJSONObject(0)
            .put("dial_address", "198.51.100.10")
        assertGraphRejects(documentationIp, 7)

        val timeLimitedMissingExpiry = JSONObject(valid.toString())
        timeLimitedMissingExpiry.getJSONObject("account")
            .put("plan", "time_limited").put("expires_at", JSONObject.NULL)
        assertGraphRejects(timeLimitedMissingExpiry, 7)

        val optionWithoutProfile = JSONObject(valid.toString())
        optionWithoutProfile.getJSONArray("countries").getJSONObject(0)
            .getJSONArray("front_source_options").put("B")
        assertGraphRejects(optionWithoutProfile, 7)
    }

    @Test
    fun publicLiteralAcceptsOnlyGlobalUnicastAndNeverResolvesNames() {
        val valid = listOf(
            "93.184.216.34",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        )
        valid.forEach { assertTrue("expected global literal: $it", BifrostConfigGraphValidator.isPublicLiteral(it)) }
        val invalid = listOf(
            "100.64.0.1", "198.18.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
            "0.1.2.3", "127.0.0.1", "224.0.0.1", "240.0.0.1", "example.test",
            "::", "::1", "::ffff", "100::1", "2001:2::1", "2001:db8::1", "2001::1",
            "2002::1", "3fff::1", "fc00::1", "fe80::1", "fec0::1", "ff00::1", "4000::1",
        )
        invalid.forEach { assertFalse("unexpected non-global literal: $it", BifrostConfigGraphValidator.isPublicLiteral(it)) }
    }

    @Test
    fun expiresAtIsStrictUtcAndMustBeInTheFuture() {
        val now = Instant.parse("2026-01-01T00:00:00Z")
        listOf(
            "2026-01-01T00:00:01Z",
            "2026-01-01T00:00:00.123Z",
            "2026-01-01T00:00:00.123456Z",
            "2026-01-01T00:00:00.123456789Z",
        ).forEach { value ->
            BifrostConfigGraphValidator.validate(
                JSONObject(testConfig(7).toString()).putAccount("time_limited", value),
                7,
                now,
            )
        }

        val permanentString = JSONObject(testConfig(7).toString())
            .putAccount("permanent", "2026-01-02T00:00:00Z")
        assertGraphRejects(permanentString, 7, now)
        val timedNull = JSONObject(testConfig(7).toString()).putAccount("time_limited", JSONObject.NULL)
        assertGraphRejects(timedNull, 7, now)
        val malformed = JSONObject(testConfig(7).toString()).putAccount("time_limited", "2026-01-02T00:00:00+08:00")
        assertGraphRejects(malformed, 7, now)
        val expired = JSONObject(testConfig(7).toString()).putAccount("time_limited", "2025-12-31T23:59:59Z")
        assertGraphRejects(expired, 7, now)
        val equal = JSONObject(testConfig(7).toString()).putAccount("time_limited", "2026-01-01T00:00:00Z")
        assertGraphRejects(equal, 7, now)
        listOf(
            "2026-01-01T00:00:00.0Z",
            "2026-01-01T00:00:00.1230Z",
            "2026-01-01T00:00:00.1234560Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:60Z",
        ).forEach { value ->
            assertGraphRejects(JSONObject(testConfig(7).toString()).putAccount("time_limited", value), 7, now)
        }
    }

    @Test
    fun rollbackFloorNeverDecreases() {
        assertEquals(9L, BifrostRollback.advance(7, 9))
        try {
            BifrostRollback.advance(9, 8)
            fail("rollback must be rejected")
        } catch (_: IllegalStateException) {
            // expected
        }
    }

    @Test
    fun manifestValidatorRejectsEquivocationAndRollback() {
        val digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val valid = JSONObject()
            .put("schema_version", "1.0")
            .put("config_version", 9)
            .put("digest", digest)
            .put("rollback_floor", 8)
        assertEquals(9L, BifrostManifestValidator.validate(valid, 7).version)
        assertManifestRejects(JSONObject(valid.toString()).put("unexpected", true), 7)
        assertManifestRejects(JSONObject(valid.toString()).put("digest", digest.uppercase()), 7)
        assertManifestRejects(JSONObject(valid.toString()).put("config_version", 6), 7)
        assertManifestRejects(JSONObject(valid.toString()).put("rollback_floor", 10), 7)
    }

    @Test
    fun newerConfigurationAcceptsUnchangedServerMinimumWithoutLoweringLocalFloor() {
        assertEquals(70L, BifrostRollback.acceptManifest(64, 1, 70))
        assertEquals(70L, BifrostRollback.acceptManifest(70, 1, 70))
        for ((local, server, version) in listOf(Triple(70L, 1L, 69L), Triple(64L, 71L, 70L))) {
            try { BifrostRollback.acceptManifest(local, server, version); fail("rollback accepted") }
            catch (_: IllegalStateException) { }
        }
    }

    @Test
    fun cacheBindingRejectsLegacyAndMismatchedMetadata() {
        val digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val encoded = BifrostCacheBindingCodec.encode("sing-box", "{\"schema_version\":\"1.0\"}", 9, digest)
        val decoded = BifrostCacheBindingCodec.decode(encoded.toString(Charsets.UTF_8))
        assertEquals(9L, decoded.version)
        assertEquals(digest, decoded.digest)
        BifrostCacheReadPolicy.validate(decoded, BifrostCacheCommitState.STABLE, 9, digest, 9)
        try {
            BifrostCacheBindingCodec.decode("{\"schema_version\":\"1.0\"}")
            fail("unbound legacy cache must be rejected")
        } catch (_: IllegalStateException) { }
        val mismatched = BifrostCacheBindingCodec.decode(
            "9\u0000${digest.dropLast(1)}0\u0000stable\u0000sing-box\u0000x",
        )
        assertPolicyRejects(mismatched, BifrostCacheCommitState.STABLE, 9, digest, 9)
        assertPolicyRejects(decoded, BifrostCacheCommitState.PENDING, 9, digest, 9)
        assertPolicyRejects(decoded, BifrostCacheCommitState.STABLE, 8, digest, 8)
        assertPolicyRejects(decoded, BifrostCacheCommitState.STABLE, 9, digest.uppercase(), 9)
        assertPolicyRejects(decoded, BifrostCacheCommitState.STABLE, 9, digest, 0)
    }

    @Test
    fun commitCoordinatorLeavesNoCommittedCacheWhenMetadataFails() {
        val store = FakeCommitStore(cache = null, metadata = mutableMapOf(), metadataResult = false)
        try {
            BifrostCommitCoordinator.commit(store, "new-cache", mapOf("v" to "9"), "BF-TEST-COMMIT")
            fail("metadata failure must be visible")
        } catch (error: IllegalStateException) {
            assertEquals("BF-TEST-COMMIT", error.message)
        }
        assertNull(store.cache)
        assertTrue(store.metadata.isEmpty())
    }

    @Test
    fun commitCoordinatorRestoresOldBindingAfterFailure() {
        val store = FakeCommitStore(cache = "old-cache", metadata = mutableMapOf("v" to "8", "floor" to "7"), metadataResult = false)
        try {
            BifrostCommitCoordinator.commit(store, "new-cache", mapOf("v" to "9"), "BF-TEST-COMMIT")
            fail("metadata failure must be visible")
        } catch (_: IllegalStateException) { }
        assertEquals("old-cache", store.cache)
        assertEquals("8", store.metadata["v"])
        assertEquals("7", store.metadata["floor"])
    }

    @Test
    fun commitCoordinatorHandlesMutateThenFalseAndFinalReadback() {
        val cacheFailure = FakeCommitStore(cache = null, metadata = mutableMapOf(), metadataResult = true).apply {
            cacheMutateThenFalse = true
        }
        assertCommitFails(cacheFailure)
        assertFalse(cacheFailure.isReadable())

        val metadataFailure = FakeCommitStore(cache = null, metadata = mutableMapOf(), metadataResult = true).apply {
            metadataMutateThenFalse = true
        }
        assertCommitFails(metadataFailure)
        assertFalse(metadataFailure.isReadable())

        val finalFalse = FakeCommitStore(cache = null, metadata = mutableMapOf(), metadataResult = true).apply {
            stableResult = false
        }
        BifrostCommitCoordinator.commit(finalFalse, "new-cache", mapOf("v" to "9"), "BF-TEST-COMMIT")
        assertTrue(finalFalse.isReadable())
    }

    @Test
    fun commitCoordinatorFailureInjectionMatrixRestoresOrQuarantinesDeterministically() {
        val stageFailures = listOf<(FakeCommitStore) -> Unit>(
            { it.pendingNoChangeFalse = true },
            { it.pendingMutateThenFalse = true },
            { it.cacheNoChangeFalse = true },
            { it.cacheMutateThenFalse = true },
            { it.metadataNoChangeFalse = true },
            { it.metadataMutateThenFalse = true },
            { it.finalizeNoChangeFalse = true },
            { it.finalizeMutateThenFalse = true },
            { it.stableNoChangeFalse = true },
        )
        stageFailures.forEach { configure ->
            val store = FakeCommitStore("old-cache", mutableMapOf("v" to "8", "floor" to "7"))
            configure(store)
            assertCommitFails(store)
            assertEquals("old-cache", store.cache)
            assertEquals("8", store.metadata["v"])
            assertEquals("7", store.metadata["floor"])
            assertTrue(store.isReadable())
        }

        val stableMutateFalse = FakeCommitStore("old-cache", mutableMapOf("v" to "8", "floor" to "7"))
        stableMutateFalse.stableMutateThenFalse = true
        BifrostCommitCoordinator.commit(stableMutateFalse, "new-cache", mapOf("v" to "9", "floor" to "9"), "BF-TEST-COMMIT")
        assertEquals("new-cache", stableMutateFalse.cache)
        assertTrue(stableMutateFalse.isReadable())

        val noOldCache = FakeCommitStore(null, mutableMapOf())
        noOldCache.metadataMutateThenFalse = true
        assertCommitFails(noOldCache)
        assertNull(noOldCache.cache)
        assertFalse(noOldCache.isReadable())

        val mismatchedReadback = FakeCommitStore("old-cache", mutableMapOf("v" to "8", "floor" to "7"))
        mismatchedReadback.stableMutateThenFalse = true
        mismatchedReadback.corruptStableReadback = true
        assertCommitFails(mismatchedReadback)
        assertEquals("old-cache", mismatchedReadback.cache)
        assertEquals("7", mismatchedReadback.metadata["floor"])
        assertTrue(mismatchedReadback.isReadable())

        listOf<(FakeCommitStore) -> Unit>(
            { it.quarantineResult = false },
            { it.quarantineMutateThenFalse = true },
            { it.clearResult = false },
            { it.clearMutateThenFalse = true },
            { it.restoreMetadataResult = false },
            { it.restoreMetadataMutateThenFalse = true },
            { it.restoreCacheResult = false },
            { it.restoreCacheMutateThenFalse = true },
        ).forEach { configure ->
            val store = FakeCommitStore("old-cache", mutableMapOf("v" to "8", "floor" to "7"), metadataResult = false)
            configure(store)
            assertTransactionFailure(store)
            assertFalse(store.isReadable())
        }
    }

    @Test
    fun commitCoordinatorQuarantinesWhenClearOrRestoreFails() {
        val clearFailure = FakeCommitStore(cache = null, metadata = mutableMapOf(), metadataResult = false).apply {
            clearResult = false
        }
        assertTransactionFailure(clearFailure)
        assertFalse(clearFailure.isReadable())

        val metadataRestoreFailure = FakeCommitStore(cache = "old-cache", metadata = mutableMapOf("v" to "8"), metadataResult = false).apply {
            restoreMetadataResult = false
        }
        assertTransactionFailure(metadataRestoreFailure)
        assertFalse(metadataRestoreFailure.isReadable())

        val cacheRestoreFailure = FakeCommitStore(cache = "old-cache", metadata = mutableMapOf("v" to "8"), metadataResult = false).apply {
            restoreCacheResult = false
        }
        assertTransactionFailure(cacheRestoreFailure)
        assertFalse(cacheRestoreFailure.isReadable())
    }

    @Test
    fun sessionGateDoesNotRunCommitWithoutSession() {
        var called = false
        try {
            BifrostSessionCommitGate.commit("", "BF-SESSION-GATE") { called = true }
            fail("empty session must fail closed")
        } catch (error: IllegalStateException) {
            assertEquals("BF-SESSION-GATE", error.message)
        }
        assertFalse(called)
    }

    @Test
    fun logoutClearsCacheBeforeAccountAndReportsRemoteFailure() {
        val order = mutableListOf<String>()
        val store = object : BifrostLogoutStore {
            override fun clearCache(): Boolean { order += "cache"; return true }
            override fun clearAccount(): Boolean { order += "account"; return true }
        }
        BifrostLogoutCoordinator.clearLocal(store)
        assertEquals(listOf("cache", "account"), order)
        try {
            BifrostLogoutCoordinator.remoteFailure(302)
            fail("redirect logout must be a remote failure")
        } catch (error: IllegalStateException) {
            assertEquals("BF-LOGOUT-REMOTE", error.message)
        }
    }

    @Test
    fun logoutFailureModesNeverClaimSuccessOrReverseClearOrder() {
        var accountCalled = false
        val cacheFailure = object : BifrostLogoutStore {
            override fun clearCache(): Boolean = false
            override fun clearAccount(): Boolean { accountCalled = true; return true }
        }
        try {
            BifrostLogoutCoordinator.clearLocal(cacheFailure)
            fail("cache failure must stop account deletion")
        } catch (_: IllegalStateException) { }
        assertFalse(accountCalled)

        val accountFailure = object : BifrostLogoutStore {
            override fun clearCache(): Boolean = true
            override fun clearAccount(): Boolean = false
        }
        try {
            BifrostLogoutCoordinator.clearLocal(accountFailure)
            fail("account failure must be visible")
        } catch (_: IllegalStateException) { }

        listOf(301, 302, 401, 500).forEach { status ->
            try {
                BifrostLogoutCoordinator.remoteFailure(status)
                fail("status $status must fail")
            } catch (_: IllegalStateException) { }
        }
        BifrostLogoutCoordinator.remoteFailure(204)
    }

    @Test
    fun packageShapeRejectsUnknownAndAcceptsOnlyExactEnvelope() {
        val b64 = { bytes: ByteArray -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) }
        val envelope = JSONObject()
            .put("alg", "X25519-HKDF-SHA256-AES-256-GCM")
            .put("key_id", "config-signing-v1")
            .put("config_version", 9)
            .put("anti_rollback", 9)
            .put("content_digest", "a".repeat(64))
            .put("ephemeral_public_key", b64(byteArrayOf(
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
                0x03, 0x21, 0x00,
            ) + ByteArray(32)))
            .put("salt", b64(ByteArray(16)))
            .put("iv", b64(ByteArray(12)))
            .put("tag", b64(ByteArray(16)))
            .put("ciphertext", b64(byteArrayOf(1)))
            .put("signature", b64(ByteArray(64)))
        assertEquals(11, BifrostPackageShapeValidator.validate(envelope, 9).size)
        assertPackageRejects(JSONObject(envelope.toString()).put("unknown", true), 9)
        assertPackageRejects(JSONObject(envelope.toString()).put("config_version", "9"), 9)
        assertPackageRejects(JSONObject(envelope.toString()).put("content_digest", "A".repeat(64)), 9)
        assertPackageRejects(JSONObject(envelope.toString()).put("ciphertext", b64(ByteArray(BifrostConfigStore.MAX_PLAINTEXT_BYTES + 1))), 9)
    }

    @Test
    fun responsePolicyRejectsRedirectAndNonSuccess() {
        try {
            BifrostHttpResponsePolicy.rejectRedirect(301)
            fail("redirect must fail closed")
        } catch (error: IllegalStateException) {
            assertEquals("BF-CONTROL-REDIRECT", error.message)
        }
        assertFalse(BifrostHttpResponsePolicy.isSuccess(500))
        assertTrue(BifrostHttpResponsePolicy.isSuccess(204))
    }

    private fun assertGraphRejects(value: JSONObject, version: Long) {
        assertGraphRejects(value, version, Instant.now())
    }

    private fun assertGraphRejects(value: JSONObject, version: Long, now: Instant) {
        try {
            BifrostConfigGraphValidator.validate(value, version, now)
            fail("unsafe graph was accepted")
        } catch (_: IllegalStateException) {
            // expected
        }
    }

    private fun assertPolicyRejects(
        binding: BifrostCacheBinding,
        state: String,
        version: Long,
        digest: String,
        floor: Long,
    ) {
        try {
            BifrostCacheReadPolicy.validate(binding, state, version, digest, floor)
            fail("invalid cache binding was accepted")
        } catch (_: IllegalStateException) { }
    }

    private fun assertCommitFails(store: FakeCommitStore) {
        try {
            BifrostCommitCoordinator.commit(store, "new-cache", mapOf("v" to "9"), "BF-TEST-COMMIT")
            fail("transaction failure must be visible")
        } catch (_: IllegalStateException) { }
    }

    private fun assertTransactionFailure(store: FakeCommitStore) {
        try {
            BifrostCommitCoordinator.commit(store, "new-cache", mapOf("v" to "9"), "BF-TEST-COMMIT")
            fail("unrecoverable transaction must fail closed")
        } catch (error: IllegalStateException) {
            assertEquals("BF-CONFIG-TRANSACTION", error.message)
        }
    }

    private fun JSONObject.putAccount(plan: String, expires: Any): JSONObject = apply {
        getJSONObject("account").put("plan", plan).put("expires_at", expires)
    }

    private fun assertManifestRejects(value: JSONObject, floor: Long) {
        try {
            BifrostManifestValidator.validate(value, floor)
            fail("invalid manifest was accepted")
        } catch (_: IllegalStateException) {
            // expected
        }
    }

    private fun assertPackageRejects(value: JSONObject, version: Long) {
        try {
            BifrostPackageShapeValidator.validate(value, version)
            fail("invalid envelope was accepted")
        } catch (_: IllegalStateException) { }
    }

    private fun testConfig(version: Long): JSONObject {
        val directProfile = JSONObject().put("profile_id", "test-direct").put("uuid", "00000000-0000-4000-8000-000000000001")
        val countryProfile = JSONObject().put("profile_id", "test-country").put("uuid", "00000000-0000-4000-8000-000000000002")
        val source = JSONObject()
            .put("code", "A").put("display_name", "Test A").put("server_name", "source-a.test")
            .put("configured", true).put("ws_path", "/test-only-vmess")
            .put("transport", JSONObject().put("type", "vmess").put("network", "ws").put("tls", true).put("security", "auto").put("alter_id", 0).put("host", "source-a.test").put("sni", "source-a.test"))
            .put("candidates", org.json.JSONArray().put(JSONObject().put("label", "A-01").put("dial_address", "93.184.216.34").put("port", 443)))
            .put("profiles", JSONObject().put("direct", directProfile).put("countries", JSONObject().put("US", countryProfile)))
        return JSONObject()
            .put("schema_version", "1.0").put("config_version", version).put("anti_rollback", version)
            .put("account", JSONObject().put("public_id", "BF-TEST-0001").put("plan", "permanent").put("expires_at", JSONObject.NULL))
            .put("sources", org.json.JSONArray().put(source))
            .put("countries", org.json.JSONArray().put(JSONObject().put("code", "US").put("name_zh", "测试").put("tcp", true).put("udp", true).put("status", "enabled").put("front_source_code", "A").put("front_source_options", org.json.JSONArray().put("A"))))
            .put("routing", JSONObject().put("ruleset_version", "test-1").put("smart_gate_remote_dns", true).put("kill_switch_default", "normal").put("dns_policy", JSONObject().put("version", "dns-policy-v1").put("remote", "https://remote.example.invalid/dns-query").put("direct", "https://direct.example.invalid/dns-query").put("smart_gate_remote", true).put("plaintext_fallback", false).put("ipv4", "proxy").put("ipv6", "proxy").put("failure", "block")).put("ipv6_policy", "proxy_or_block").put("udp_policy", "capability"))
            .put("core_policy", JSONObject().put("allowed", org.json.JSONArray().put("sing-box").put("xray")).put("default", "sing-box"))
    }

    @Test
    fun bootstrapStateMachineIsCasLikeAndCrashSafe() {
        val digest = MessageDigest.getInstance("SHA-256").digest("{\"operation_id\":\"record-1\",\"sequence\":0}".toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val record = JSONObject().put("operation_id", "record-1").put("sequence", 0).put("record_digest", digest).toString()
        var persisted: String? = record
        var now = 1_000L
        var failWrite = false
        val machine = ReleaseBootstrapStateMachine({ persisted }, { next -> if (failWrite) false else { persisted = next; true } }, { now })
        assertTrue(machine.reserve(record, 0, "op-a-0001"))
        assertFalse(machine.reserve(persisted!!, 0, "op-b-0001"))
        assertFalse(machine.commit(persisted!!, "op-b-0001"))
        failWrite = true
        assertFalse(machine.commit(persisted!!, "op-a-0001"))
        failWrite = false
        val recovered = ReleaseBootstrapStateMachine({ persisted }, { next -> persisted = next; true }, { now })
        assertTrue(recovered.commit(persisted!!, "op-a-0001"))
        assertFalse(recovered.reserve(persisted!!, 0, "op-c-0001"))
        now += 700_000L
        assertFalse(recovered.recoverStale(persisted!!, ReleaseBootstrapRecoveryProof("op-a-0001", 7, sessionTerminal = true, sessionAbandoned = true, sessionAbsent = false)))
        assertFalse(recovered.abort(persisted!!, "op-c-0001"))
        var stalePersisted: String? = record
        val stale = ReleaseBootstrapStateMachine({ stalePersisted }, { next -> stalePersisted = next; true }, { now })
        assertTrue(stale.reserve(record, 0, "op-stale-1"))
        // TTL expiry alone never reopens a reservation, even across a second
        // owner attempt or an active/pending installer session.
        now += 700_000L
        assertFalse(stale.reserve(stalePersisted!!, 0, "op-stale-2"))
        assertFalse(stale.recoverStale(stalePersisted!!, ReleaseBootstrapRecoveryProof("op-stale-1", 9, sessionTerminal = false, sessionAbandoned = false, sessionAbsent = false)))
        assertFalse(stale.recoverStale(stalePersisted!!, ReleaseBootstrapRecoveryProof("wrong-op", 9, sessionTerminal = true, sessionAbandoned = true, sessionAbsent = false)))
        assertFalse(stale.recoverStale(stalePersisted!!, ReleaseBootstrapRecoveryProof("op-stale-1", 9, sessionTerminal = true, sessionAbandoned = false, sessionAbsent = false)))
        assertTrue(stale.recoverStale(stalePersisted!!, ReleaseBootstrapRecoveryProof("op-stale-1", 9, sessionTerminal = true, sessionAbandoned = true, sessionAbsent = false)))
        assertTrue(stale.reserve(stalePersisted!!, 0, "op-stale-2"))
        // A terminal proof is owner-bound; a second recovery cannot reopen a
        // new reservation while the matching operation is active.
        assertFalse(stale.recoverStale(stalePersisted!!, ReleaseBootstrapRecoveryProof("op-stale-1", 9, sessionTerminal = true, sessionAbandoned = true, sessionAbsent = false)))
    }

    private class FakeBackend : BifrostSecureStore.Backend {
        val secure = linkedMapOf<String, String>()
        val legacy = linkedMapOf<String, String>()
        var commitSucceeds = true
        var scrubSucceeds = true
        var mutateThenFalse = false
        override fun secureValue(key: String): String? = secure[key]
        override fun legacyValue(key: String): String? = legacy[key]
        override fun commitSecure(values: Map<String, String?>): Boolean {
            if (!commitSucceeds && !mutateThenFalse) return false
            values.forEach { (key, value) -> if (value == null) secure.remove(key) else secure[key] = value }
            if (mutateThenFalse) return false
            return true
        }
        override fun scrubLegacy(keys: Set<String>): Boolean {
            if (!scrubSucceeds) return false
            keys.forEach { legacy.remove(it) }
            return true
        }
    }

    private class FakeCommitStore(
        var cache: String?,
        val metadata: MutableMap<String, String>,
        private val metadataResult: Boolean = true,
    ) : BifrostCommitStore<String, Map<String, String>> {
        var pendingResult = true
        var pendingNoChangeFalse = false
        var pendingMutateThenFalse = false
        var cacheResult = true
        var cacheNoChangeFalse = false
        var cacheMutateThenFalse = false
        var metadataNoChangeFalse = false
        var metadataMutateThenFalse = false
        var finalizeResult = true
        var finalizeNoChangeFalse = false
        var finalizeMutateThenFalse = false
        var stableResult = true
        var stableNoChangeFalse = false
        var stableMutateThenFalse = false
        var corruptStableReadback = false
        var quarantineResult = true
        var quarantineMutateThenFalse = false
        var clearResult = true
        var clearMutateThenFalse = false
        var restoreCacheResult = true
        var restoreCacheMutateThenFalse = false
        var restoreMetadataResult = true
        var restoreMetadataMutateThenFalse = false
        private var expectedMetadata: Map<String, String> = emptyMap()

        init {
            if (cache != null) {
                metadata.putIfAbsent("state", BifrostCacheCommitState.STABLE)
                metadata.putIfAbsent("cache_state", BifrostCacheCommitState.STABLE)
            }
            expectedMetadata = stableMetadata()
        }

        override fun snapshot() = BifrostCommitSnapshot(cache, metadata.toMap())
        override fun markPending(): Boolean {
            if (pendingNoChangeFalse) return false
            metadata["state"] = BifrostCacheCommitState.PENDING
            return if (pendingMutateThenFalse) false else pendingResult
        }
        override fun writeCache(value: String): Boolean {
            if (cacheNoChangeFalse) return false
            cache = value
            metadata["cache_state"] = BifrostCacheCommitState.PENDING
            return if (cacheMutateThenFalse) false else cacheResult
        }
        override fun writeMetadata(value: Map<String, String>): Boolean {
            if (metadataNoChangeFalse) return false
            metadata.clear(); metadata.putAll(value); metadata["state"] = BifrostCacheCommitState.PENDING
            expectedMetadata = value.toMap()
            return if (metadataMutateThenFalse) false else metadataResult
        }
        override fun finalizeCache(value: String): Boolean {
            if (finalizeNoChangeFalse) return false
            cache = value
            metadata["cache_state"] = BifrostCacheCommitState.STABLE
            return if (finalizeMutateThenFalse) false else finalizeResult
        }
        override fun markStable(): Boolean {
            if (stableNoChangeFalse) return false
            metadata["state"] = BifrostCacheCommitState.STABLE
            if (corruptStableReadback) metadata["v"] = "corrupt"
            return if (stableMutateThenFalse) false else stableResult
        }
        override fun quarantine(): Boolean {
            if (quarantineResult || quarantineMutateThenFalse) metadata["state"] = BifrostCacheCommitState.QUARANTINE
            return if (quarantineMutateThenFalse) false else quarantineResult
        }
        override fun clearCache(): Boolean {
            if (clearMutateThenFalse) { cache = null; return false }
            if (!clearResult) return false
            cache = null
            return true
        }
        override fun restoreCache(value: String?): Boolean {
            if (restoreCacheMutateThenFalse) { cache = value; return false }
            if (!restoreCacheResult) return false
            cache = value
            if (value != null) metadata["cache_state"] = BifrostCacheCommitState.STABLE
            return true
        }
        override fun restoreMetadata(value: Map<String, String>): Boolean {
            if (restoreMetadataMutateThenFalse) {
                metadata.clear(); metadata.putAll(value)
                expectedMetadata = value.filterKeys { it != "state" && it != "cache_state" }
                return false
            }
            if (!restoreMetadataResult) return false
            metadata.clear(); metadata.putAll(value)
            expectedMetadata = value.filterKeys { it != "state" && it != "cache_state" }
            return true
        }
        override fun isCommitted(candidate: String): Boolean =
            cache == candidate && metadata["state"] == BifrostCacheCommitState.STABLE &&
                metadata["cache_state"] == BifrostCacheCommitState.STABLE && stableMetadata() == expectedMetadata

        override fun isReadable(): Boolean =
            cache != null && metadata["state"] == BifrostCacheCommitState.STABLE &&
                metadata["cache_state"] == BifrostCacheCommitState.STABLE

        private fun stableMetadata(): Map<String, String> =
            metadata.filterKeys { it != "state" && it != "cache_state" }
    }

    private class FakeSensitiveClipboard : BifrostClipboard {
        var value: String? = null
        var writeSucceeds = true

        override fun readText(): String? = value

        override fun writeText(value: String): Boolean {
            if (!writeSucceeds) return false
            this.value = value
            return true
        }

        override fun clearIfMatches(expected: String): Boolean {
            if (value != expected) return false
            value = null
            return true
        }
    }

    private class TimeoutErrorBodyConnection(url: URL, private val status: Int) : HttpURLConnection(url) {
        override fun connect() = Unit
        override fun disconnect() = Unit
        override fun usingProxy(): Boolean = false
        override fun getResponseCode(): Int = status
        override fun getErrorStream(): InputStream = throw SocketTimeoutException("TEST-ONLY error body timeout")
        override fun getOutputStream(): OutputStream = ByteArrayOutputStream()
    }
}
