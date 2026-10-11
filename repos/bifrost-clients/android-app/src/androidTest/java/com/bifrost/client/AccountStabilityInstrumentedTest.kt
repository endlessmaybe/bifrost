package com.bifrost.client

import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

/** Runs only in com.bifrost.client.test, with real Android Keystore storage. */
@RunWith(AndroidJUnit4::class)
class AccountStabilityInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun activityReopensThroughStorageFailureWithoutLosingIdentity() {
        assertTrue(BuildConfig.DEBUG && BuildConfig.BIFROST_TEST_VARIANT)
        assertEquals("com.bifrost.client.test", context.packageName)
        DeviceKeys.ensure(context)
        val device = DeviceKeys.deviceId(context)
        context.getSharedPreferences("node-update-notifications", android.content.Context.MODE_PRIVATE)
            .edit().putBoolean("permission_requested", true).commit()
        BifrostSecureStore.putBatch(context, mapOf("public_id" to "BF-TEST-STARTUP", "account_recovery_code" to "TEST-ONLY-RECOVERY",
            "session_token" to null, "config_version" to "0", "enrollment_pending_origin" to null, "control_base_url" to null))
        BifrostSecureStore.failReadsForTest(true)
        try {
            ActivityScenario.launch(MainActivity::class.java).use { activity ->
                activity.onActivity { assertFalse(it.isFinishing) }
                activity.recreate()
                activity.onActivity { assertFalse(it.isFinishing) }
                BifrostSecureStore.failReadsForTest(false)
                activity.recreate()
                activity.onActivity { assertFalse(it.isFinishing) }
            }
        } finally { BifrostSecureStore.failReadsForTest(false) }
        assertEquals(device, DeviceKeys.deviceId(context))
        assertEquals("BF-TEST-STARTUP", BifrostSecureStore.get(context, "public_id"))
        assertEquals("TEST-ONLY-RECOVERY", BifrostSecureStore.get(context, "account_recovery_code"))
    }

    @Test fun interruptedEnrollmentProvesExistingKeyAndRestoresPublicIdentity() {
        assertTrue(BuildConfig.DEBUG && BuildConfig.BIFROST_TEST_VARIANT)
        DeviceKeys.ensure(context)
        val device = DeviceKeys.deviceId(context)
        val expected = "BF-TEST-RESUME"
        BifrostSecureStore.putBatch(context, mapOf("public_id" to null, "session_token" to null,
            "config_version" to "0", "enrollment_pending_origin" to "http://127.0.0.1:18183",
            "control_base_url" to null))
        val paths = mutableListOf<String>()
        val control = BifrostControlClient(context)
        control.withLifecycleHttpConnectionFactory(BifrostLifecycleHttpConnectionFactory { url ->
            paths += url.path
            object : HttpURLConnection(url) {
                val request = ByteArrayOutputStream()
                override fun connect() { }
                override fun disconnect() { }
                override fun usingProxy() = false
                override fun getOutputStream() = request
                override fun getHeaderField(name: String?) = if (name.equals("Content-Type", true)) "application/json" else null
                override fun getResponseCode(): Int {
                    if (url.path == "/v1/device/session") {
                        assertEquals("public-id-v1", getRequestProperty("X-Bifrost-Session-Identity"))
                        val body = JSONObject(request.toString("UTF-8"))
                        assertEquals(device, body.getString("device_id"))
                        val signed = "TEST-ONLY-challenge|${body.getLong("timestamp")}|${body.getString("nonce")}|${body.getString("request_digest")}"
                        val key = java.util.Base64.getUrlDecoder().decode(DeviceKeys.signingPublicKey(context)).takeLast(32).toByteArray()
                        com.google.crypto.tink.subtle.Ed25519Verify(key).verify(java.util.Base64.getUrlDecoder().decode(body.getString("signature")), signed.toByteArray())
                    }
                    return if (url.path == "/v1/config/manifest") 503 else 200
                }
                override fun getInputStream() = when (url.path) {
                    "/v1/device/challenge" -> """{"challenge":"TEST-ONLY-challenge","expires_in":120}"""
                    "/v1/device/session" -> """{"session_token":"TEST-ONLY-session-0000000000000000","expires_at":"2099-01-01T00:00:00Z","public_id":"$expected"}"""
                    else -> error("unexpected endpoint")
                }.byteInputStream()
            }
        }) {
            try { control.refresh(); fail("503 must be surfaced") }
            catch (error: BifrostReachableStatusException) { assertEquals(503, error.status) }
        }
        assertEquals(listOf("/v1/device/challenge", "/v1/device/session", "/v1/config/manifest"), paths)
        assertEquals(device, DeviceKeys.deviceId(context))
        assertEquals(expected, control.accountSnapshot().publicId)
        assertEquals("", BifrostSecureStore.get(context, "enrollment_pending_origin"))
    }
}
