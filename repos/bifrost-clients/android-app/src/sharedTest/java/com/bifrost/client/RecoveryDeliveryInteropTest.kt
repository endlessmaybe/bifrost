package com.bifrost.client

import android.content.ContextWrapper
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class RecoveryDeliveryInteropTest {
    private fun assertRejected(client: BifrostControlClient, envelope: JSONObject, trust: ConfigKeyTrust.VerifiedState, privateKey: ByteArray) {
        val error = assertThrows(IllegalStateException::class.java) {
            client.decryptRecoveryDeliveryForTest(envelope, trust, privateKey)
        }
        assertEquals("BF-RECOVERY-DELIVERY", error.message)
    }

    @Test
    fun decryptsActualControlRecoveryEnvelopeWithBoundAad() {
        val vector = JSONObject(javaClass.getResource("/com/bifrost/client/recovery-delivery-interop.json")!!.readText())
        val root = vector.getJSONObject("root")
        val trust = ConfigKeyTrust.verify(vector.getJSONObject("state"), rootKeyId = "bifrost-root-v1",
            rootPem = root.getString("pem"), rootFingerprint = root.getString("fingerprint"))
        val client = BifrostControlClient(ContextWrapper(null), lifecycleOnly = true)
        val privateKey = Base64.getUrlDecoder().decode(vector.getString("private_key_raw"))
        try {
            val envelope = vector.getJSONObject("envelope")
            assertEquals(vector.getString("recovery_code"), client.decryptRecoveryDeliveryForTest(envelope, trust, privateKey))

            val wrongAad = JSONObject(envelope.toString()).put("aad", "wrong-purpose")
            assertRejected(client, wrongAad, trust, privateKey)

            val changedVersion = envelope.getLong("config_version") + 1
            val wrongVersion = JSONObject(envelope.toString())
                .put("config_version", changedVersion)
                .put("aad", "bifrost|recovery-delivery|$changedVersion|${envelope.getLong("expires_at")}")
            assertRejected(client, wrongVersion, trust, privateKey)

            val expiredAt = System.currentTimeMillis() - 1
            val expired = JSONObject(envelope.toString())
                .put("expires_at", expiredAt)
                .put("aad", "bifrost|recovery-delivery|${envelope.getLong("config_version")}|$expiredAt")
            assertRejected(client, expired, trust, privateKey)

            val signature = Base64.getUrlDecoder().decode(envelope.getString("signature"))
            try {
                signature[0] = (signature[0].toInt() xor 1).toByte()
                val tamperedSignature = JSONObject(envelope.toString()).put(
                    "signature",
                    Base64.getUrlEncoder().withoutPadding().encodeToString(signature),
                )
                assertRejected(client, tamperedSignature, trust, privateKey)
            } finally { signature.fill(0) }

            val wrongKey = privateKey.copyOf().apply { this[12] = (this[12].toInt() xor 1).toByte() }
            try { assertRejected(client, envelope, trust, wrongKey) }
            finally { wrongKey.fill(0) }
        } finally { privateKey.fill(0) }
    }
}
