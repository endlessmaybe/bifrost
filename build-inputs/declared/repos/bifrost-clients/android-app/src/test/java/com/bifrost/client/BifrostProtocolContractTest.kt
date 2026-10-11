package com.bifrost.client

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class BifrostProtocolContractTest {
    @Test
    fun generatedContractBindingIsStable() {
        assertEquals("bifrost.protocol", BifrostProtocolContract.ID)
        assertEquals("1.0.0", BifrostProtocolContract.VERSION)
        assertTrue(BifrostProtocolContract.FINGERPRINT.matches(Regex("[0-9a-f]{64}")))
        BifrostProtocolContract.requireFingerprint()
        BifrostProtocolContract.requireErrorRegistry()
        assertThrows(IllegalArgumentException::class.java) { BifrostProtocolContract.requireFingerprint("0".repeat(64)) }
        assertThrows(IllegalArgumentException::class.java) { BifrostProtocolContract.requireErrorRegistry("0".repeat(64)) }
    }

    @Test
    fun nodeAckGoldenVectorUsesExactUtf8Bytes() {
        val canonical = "{\"completed_at\":\"2026-01-01T00:00:00.000Z\",\"core_binary_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"generation\":\"gen-TEST-ONLY-ACK-0001\",\"node_id\":\"node-a\",\"operation_id\":\"gen-TEST-ONLY-ACK-0001\",\"probe_digest\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"version\":7}"
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        assertEquals("9398e17c71ecdb5d820026c75e9c28329fa600f22e8428fb194f383c045f9349", digest)
    }

    @Test
    fun sharedVectorResourceContainsPositiveAndNegativeCases() {
        val text = javaClass.classLoader!!.getResourceAsStream("com/bifrost/client/protocol-golden-vectors-v1.json")!!.bufferedReader().use { it.readText() }
        val root = JSONObject(text)
        val vectors = root.getJSONArray("vectors")
        var verifiedSignature = false
        for (index in 0 until vectors.length()) {
            val vector = vectors.getJSONObject(index)
            val canonical = vector.getString("canonical_json")
            val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
            assertEquals(vector.getString("sha256"), digest)
            if (vector.optString("schema") != "" && vector.optString("schema") != "SignedBytes" && canonical.isNotEmpty()) {
                BifrostProtocolContract.validateSchema(vector.getString("schema"), JSONObject(canonical))
            }
            if (vector.has("signature_base64url")) {
                val raw = Base64.getUrlDecoder().decode(vector.getString("public_key_raw_base64url"))
                val spkiPrefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
                val spki = spkiPrefix + raw
                val verifier = Signature.getInstance("Ed25519")
                verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki)))
                verifier.update(canonical.toByteArray(Charsets.UTF_8))
                assertTrue(verifier.verify(Base64.getUrlDecoder().decode(vector.getString("signature_base64url"))))
                verifiedSignature = true
            }
        }
        assertTrue(verifiedSignature)
        val signed = (0 until vectors.length()).map { vectors.getJSONObject(it) }.first { it.optString("id") == "node-ack-signed-test-only" }
        val signedBytes = Base64.getUrlDecoder().decode(signed.getString("signature_base64url"))
        val signedMessage = signed.getString("canonical_json").toByteArray(Charsets.UTF_8)
        val signedPublic = Base64.getUrlDecoder().decode(signed.getString("public_key_raw_base64url"))
        val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
        fun verifies(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean = runCatching {
            val verifier = Signature.getInstance("Ed25519")
            verifier.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(prefix + publicKey)))
            verifier.update(message); verifier.verify(signature)
        }.getOrDefault(false)
        assertTrue(verifies(signedMessage, signedBytes, signedPublic))
        val alteredMessage = signedMessage.copyOf(); alteredMessage[alteredMessage.lastIndex] = (alteredMessage.last().toInt() xor 1).toByte(); assertTrue(!verifies(alteredMessage, signedBytes, signedPublic))
        val alteredSignature = signedBytes.copyOf(); alteredSignature[0] = (alteredSignature[0].toInt() xor 1).toByte(); assertTrue(!verifies(signedMessage, alteredSignature, signedPublic))
        assertTrue(!verifies(signedMessage, signedBytes, ByteArray(32)))
        assertTrue(!verifies(signedMessage, signedBytes.copyOf(63), signedPublic))
        val signatureVectors = root.getJSONArray("signature_vectors")
        for (index in 0 until signatureVectors.length()) {
            val vector = signatureVectors.getJSONObject(index)
            assertEquals("NodeAckSignedBytes", vector.getString("schema"))
            assertEquals("canonical-utf8", vector.getString("input_encoding"))
            assertEquals("signature-verification", vector.getString("expected_crypto_stage"))
            var candidateMessage = signedMessage
            var candidateSignature = signedBytes
            var candidatePublic = signedPublic
            when (vector.getString("mutation")) {
                "message-byte" -> candidateMessage = signedMessage.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
                "signature-byte" -> candidateSignature = signedBytes.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
                "wrong-key" -> candidatePublic = ByteArray(32)
                "truncate-signature" -> candidateSignature = signedBytes.copyOf(63)
                else -> throw AssertionError("unknown signature vector mutation")
            }
            assertTrue(vector.getString("id"), !verifies(candidateMessage, candidateSignature, candidatePublic))
        }
        val schemaVectors = root.getJSONArray("schema_vectors")
        for (index in 0 until schemaVectors.length()) {
            val vector = schemaVectors.getJSONObject(index)
            val value = JSONObject(vector.getString("json"))
            if (vector.getString("expected") == "accept") {
                BifrostProtocolContract.validateSchema(vector.getString("schema"), value)
            } else {
                assertThrows(Exception::class.java) { BifrostProtocolContract.validateSchema(vector.getString("schema"), value) }
            }
        }
        assertThrows(Exception::class.java) { BifrostProtocolContract.validateSchema("Page", JSONObject()) }
        BifrostProtocolContract.validateSchema("Page", JSONObject("{\"next_cursor\":null}"))
        val negatives = root.getJSONArray("negative_vectors")
        assertTrue(negatives.length() >= 8)
        for (index in 0 until negatives.length()) {
            val vector = negatives.getJSONObject(index)
            val id = vector.getString("id")
            if (vector.has("raw_utf8_base64")) {
                val bytes = Base64.getDecoder().decode(vector.getString("raw_utf8_base64"))
                assertThrows(Exception::class.java) {
                    val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
                    StrictJsonValidator(text, "BF-CONTRACT-VECTOR").validate()
                }
            } else if (vector.has("json")) {
                val text = if (id == "oversize-string") vector.getString("json").replace("<oversize>", "X".repeat(5000)) else vector.getString("json")
                if (id == "unicode-non-normalized") {
                    val value = JSONObject(text)
                    assertTrue(value.getString("message") != text)
                } else assertThrows(Exception::class.java) {
                    StrictJsonValidator(text, "BF-CONTRACT-VECTOR").validate()
                    val value = JSONObject(text)
                    if (vector.optString("schema") != "SignedBytes") BifrostProtocolContract.validateSchema(vector.getString("schema"), value)
                }
            }
        }
    }
}
