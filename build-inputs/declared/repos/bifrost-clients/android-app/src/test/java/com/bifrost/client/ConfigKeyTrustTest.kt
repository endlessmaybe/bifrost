package com.bifrost.client

import android.content.ContextWrapper
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64

class ConfigKeyTrustTest {
    private val generator = KeyPairGenerator.getInstance("Ed25519")
    private val root = generator.generateKeyPair()
    private val v1 = generator.generateKeyPair()
    private val v2 = generator.generateKeyPair()

    private fun pem(pair: KeyPair): String = "-----BEGIN PUBLIC KEY-----\n" +
        Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(pair.public.encoded) +
        "\n-----END PUBLIC KEY-----\n"

    private fun fingerprint(pair: KeyPair): String = MessageDigest.getInstance("SHA-256")
        .digest(pair.public.encoded)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun trusted(id: String, pair: KeyPair, activation: Long, retirement: Long? = null): JSONObject = JSONObject()
        .put("key_id", id)
        .put("public_key_pem", pem(pair))
        .put("fingerprint", fingerprint(pair))
        .put("activation_floor", activation)
        .put("retirement_floor", retirement ?: JSONObject.NULL)

    private fun signedState(
        generation: Long = 1,
        active: String = "config-signing-v1",
        trusted: List<JSONObject> = listOf(trusted("config-signing-v1", v1, 1)),
        previous: String? = null,
    ): JSONObject {
        val unsigned = JSONObject()
            .put("version", 1)
            .put("purpose", "config-signing-key-state")
            .put("root_key_id", "bifrost-root-v1")
            .put("root_fingerprint", fingerprint(root))
            .put("generation", generation)
            .put("active_key_id", active)
            .put("trusted_keys", JSONArray(trusted))
            .put("previous_state_digest", previous ?: JSONObject.NULL)
        val bytes = ConfigKeyTrust.canonicalJson(unsigned).toByteArray(StandardCharsets.UTF_8)
        val signer = Signature.getInstance("Ed25519")
        signer.initSign(root.private)
        signer.update(bytes)
        val signature = signer.sign()
        return try {
            JSONObject(unsigned.toString()).put("signature", Base64.getUrlEncoder().withoutPadding().encodeToString(signature))
        } finally {
            bytes.fill(0)
            signature.fill(0)
        }
    }

    private fun verify(
        state: JSONObject,
        previousGeneration: Long = 0,
        previousDigest: String? = null,
        currentVersion: Long = 0,
    ) = ConfigKeyTrust.verify(
        state,
        rootKeyId = "bifrost-root-v1",
        rootPem = pem(root),
        rootFingerprint = fingerprint(root),
        previousGeneration = previousGeneration,
        previousDigest = previousDigest,
        currentConfigVersion = currentVersion,
    )

    @Test
    fun unenrolledBootstrapDoesNotConsultStalePersistedTrustHistory() {
        // ContextWrapper(null) cannot open SharedPreferences. If bootstrap
        // accidentally consults persisted trust again this test fails before
        // returning the neutral root-bootstrap history.
        val previous = ConfigKeyTrust.previousForResponse(ContextWrapper(null), bootstrap = true)
        assertEquals(0L, previous.generation)
        assertEquals(null, previous.digest)

        val current = verify(
            signedState(generation = 3, previous = "c".repeat(64)),
            previousGeneration = previous.generation,
            previousDigest = previous.digest,
            currentVersion = 1,
        )
        assertEquals(3L, current.generation)
    }

    @Test
    fun rotationOverlapActivationAndRetirementAreEnforced() {
        val first = verify(signedState(), currentVersion = 1)
        assertEquals("config-signing-v1", first.select("config-signing-v1", 1).keyId)

        val overlapState = signedState(
            generation = 2,
            trusted = listOf(
                trusted("config-signing-v1", v1, 1),
                trusted("config-signing-v2", v2, 20),
            ),
            previous = first.digest,
        )
        val overlap = verify(overlapState, first.generation, first.digest, 19)
        assertThrows(IllegalStateException::class.java) { overlap.select("config-signing-v2", 19) }
        assertEquals("config-signing-v2", overlap.select("config-signing-v2", 20).keyId)

        val activeV2State = signedState(
            generation = 3,
            active = "config-signing-v2",
            trusted = listOf(
                trusted("config-signing-v1", v1, 1, 40),
                trusted("config-signing-v2", v2, 20),
            ),
            previous = overlap.digest,
        )
        val activeV2 = verify(activeV2State, overlap.generation, overlap.digest, 20)
        assertEquals("config-signing-v2", activeV2.activeKeyId)
        assertEquals("config-signing-v1", activeV2.select("config-signing-v1", 39).keyId)
        assertThrows(IllegalStateException::class.java) { activeV2.select("config-signing-v1", 40) }
    }

    @Test
    fun staleEquivocatedAndMisChainedStateAreRejected() {
        val first = verify(signedState())
        val other = signedState(active = "config-signing-v1")
        assertThrows(IllegalStateException::class.java) {
            verify(other, previousGeneration = 1, previousDigest = "a".repeat(64))
        }

        // A device can miss one or more root-signed state generations while
        // offline. The current state is still independently authenticated by
        // the immutable root and must be able to advance monotonically.
        val skipped = signedState(generation = 3, previous = "c".repeat(64))
        val jumped = verify(skipped, previousGeneration = 1, previousDigest = first.digest)
        assertEquals(3, jumped.generation)

        val wrongChain = signedState(generation = 2, previous = "b".repeat(64))
        assertThrows(IllegalStateException::class.java) {
            verify(wrongChain, previousGeneration = 1, previousDigest = first.digest)
        }
    }

    @Test
    fun wrongRootTamperAndUnknownLeafAreRejected() {
        val state = signedState(
            active = "config-signing-v2",
            trusted = listOf(
                trusted("config-signing-v1", v1, 1),
                trusted("config-signing-v2", v2, 1),
            ),
        )
        val verified = verify(state, currentVersion = 1)
        assertThrows(IllegalStateException::class.java) { verified.select("config-signing-v3", 1) }

        val tampered = JSONObject(state.toString()).put("active_key_id", "config-signing-v1")
        assertThrows(IllegalStateException::class.java) { verify(tampered) }

        val wrongRoot = generator.generateKeyPair()
        assertThrows(IllegalStateException::class.java) {
            ConfigKeyTrust.verify(
                state,
                rootKeyId = "bifrost-root-v1",
                rootPem = pem(wrongRoot),
                rootFingerprint = fingerprint(wrongRoot),
            )
        }
    }

}
