package com.bifrost.client

import android.content.Context
import com.google.crypto.tink.subtle.Ed25519Verify
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/**
 * Root-anchored trust set for online config signing leaves.
 *
 * The compiled release trust root is the immutable bootstrap authority. Online
 * config leaves may rotate only through a root-signed, generation-chained
 * ConfigKeyState. The state is verified before any config/recovery signature is
 * accepted and is committed only after the caller completes the whole response
 * transaction successfully.
 */
internal object ConfigKeyTrust {
    internal const val STATE_KEY = "config_key_state_v1"
    internal const val STATE_DIGEST_KEY = "config_key_state_digest_v1"
    internal const val STATE_GENERATION_KEY = "config_key_state_generation_v1"
    internal val STORAGE_KEYS = setOf(STATE_KEY, STATE_DIGEST_KEY, STATE_GENERATION_KEY)
    private val keyId = Regex("^[A-Za-z0-9._-]{1,64}$")
    private val hex64 = Regex("^[0-9a-f]{64}$")
    private val signature64 = Regex("^[A-Za-z0-9_-]{86}$")
    private val ed25519SpkiPrefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)

    data class TrustedKey(
        val keyId: String,
        val publicKeyPem: String,
        val fingerprint: String,
        val activationFloor: Long,
        val retirementFloor: Long?,
    )

    data class VerifiedState(
        val generation: Long,
        val activeKeyId: String,
        val digest: String,
        val canonicalState: String,
        val keys: List<TrustedKey>,
    ) {
        fun select(signingKeyId: String, configVersion: Long): TrustedKey {
            check(signingKeyId.matches(keyId) && configVersion > 0) { "BF-CONFIG-KEY-STATE" }
            val selected = keys.firstOrNull { it.keyId == signingKeyId }
                ?: throw IllegalStateException("BF-CONFIG-KEY-UNKNOWN")
            check(configVersion >= selected.activationFloor) { "BF-CONFIG-KEY-NOT-ACTIVE" }
            check(selected.retirementFloor == null || configVersion < selected.retirementFloor) { "BF-CONFIG-KEY-RETIRED" }
            return selected
        }
    }

    data class PreviousState(val generation: Long, val digest: String?)

    fun previous(context: Context): PreviousState {
        val values = BifrostSecureStore.readBatch(context, setOf(STATE_GENERATION_KEY, STATE_DIGEST_KEY))
        val generationText = values[STATE_GENERATION_KEY].orEmpty()
        val digest = values[STATE_DIGEST_KEY]?.takeIf { it.isNotBlank() }
        if (generationText.isBlank() && digest == null) return PreviousState(0, null)
        val generation = generationText.toLongOrNull()
            ?: throw IllegalStateException("BF-CONFIG-KEY-ROLLBACK")
        check(generation > 0 && digest != null && digest.matches(hex64)) { "BF-CONFIG-KEY-ROLLBACK" }
        return PreviousState(generation, digest)
    }

    fun verifyResponseState(
        context: Context,
        state: JSONObject?,
        configVersion: Long,
        bootstrap: Boolean = false,
    ): VerifiedState? {
        if (state == null) {
            check(!ReleaseContract.TRUST_ROOT_PROVISIONED) { "BF-CONFIG-KEY-STATE" }
            return null
        }
        check(ReleaseContract.TRUST_ROOT_PROVISIONED) { "BF-CONFIG-TRUST-ROOT" }
        val rootPem = ReleaseContract.TRUST_ROOT_PEM ?: throw IllegalStateException("BF-CONFIG-TRUST-ROOT")
        val rootFingerprint = ReleaseContract.TRUST_ROOT_FINGERPRINT ?: throw IllegalStateException("BF-CONFIG-TRUST-ROOT")
        // Enrollment bootstrap has no committed account/config authority yet.
        // A trust tuple left behind by an interrupted historical activation
        // must therefore not outrank the immutable release root and brick a
        // new root-signed enrollment response. Once enrollment commits, the
        // verified state is written atomically with the config and every
        // subsequent enrolled operation keeps the strict generation/digest
        // anti-rollback checks through previous(context).
        val previous = previousForResponse(context, bootstrap)
        return verify(
            state,
            rootKeyId = ReleaseContract.TRUST_ROOT_KEY_ID,
            rootPem = rootPem,
            rootFingerprint = rootFingerprint,
            previousGeneration = previous.generation,
            previousDigest = previous.digest,
            currentConfigVersion = configVersion,
        )
    }

    internal fun previousForResponse(context: Context, bootstrap: Boolean): PreviousState =
        if (bootstrap) PreviousState(0, null) else previous(context)

    fun storageValues(verified: VerifiedState): Map<String, String?> = mapOf(
        STATE_KEY to verified.canonicalState,
        STATE_DIGEST_KEY to verified.digest,
        STATE_GENERATION_KEY to verified.generation.toString(),
    )

    fun commit(context: Context, verified: VerifiedState) {
        BifrostSecureStore.putBatch(context, storageValues(verified))
        val after = previous(context)
        check(after.generation == verified.generation && after.digest == verified.digest) { "BF-CONFIG-KEY-STATE" }
    }

    internal fun verify(
        state: JSONObject,
        rootKeyId: String,
        rootPem: String,
        rootFingerprint: String,
        previousGeneration: Long = 0,
        previousDigest: String? = null,
        currentConfigVersion: Long = 0,
    ): VerifiedState {
        exactKeys(
            state,
            setOf("version", "purpose", "root_key_id", "root_fingerprint", "generation", "active_key_id", "trusted_keys", "previous_state_digest", "signature"),
            "BF-CONFIG-KEY-STATE",
        )
        check(state.getInt("version") == 1 && state.getString("purpose") == "config-signing-key-state") { "BF-CONFIG-KEY-STATE" }
        check(state.getString("root_key_id") == rootKeyId && rootKeyId.matches(keyId)) { "BF-CONFIG-TRUST-ROOT" }
        val actualRootFingerprint = publicKeyFingerprint(rootPem)
        check(rootFingerprint.matches(hex64) && actualRootFingerprint == rootFingerprint && state.getString("root_fingerprint") == rootFingerprint) { "BF-CONFIG-TRUST-ROOT" }

        val generation = state.getLong("generation")
        val activeKeyId = state.getString("active_key_id")
        check(generation > 0 && activeKeyId.matches(keyId)) { "BF-CONFIG-KEY-STATE" }
        val previousStateDigest = if (state.isNull("previous_state_digest")) null else state.getString("previous_state_digest")
        if (previousStateDigest != null) check(previousStateDigest.matches(hex64)) { "BF-CONFIG-KEY-STATE" }
        if (generation == 1L) check(previousStateDigest == null) { "BF-CONFIG-KEY-ROLLBACK" }
        else check(previousStateDigest != null) { "BF-CONFIG-KEY-ROLLBACK" }

        val signatureText = state.getString("signature")
        check(signatureText.matches(signature64)) { "BF-CONFIG-KEY-SIGNATURE" }
        val unsigned = JSONObject(state.toString()).apply { remove("signature") }
        val signedBytes = canonicalJson(unsigned).toByteArray(StandardCharsets.UTF_8)
        val signature = decodeBase64UrlCanonical(signatureText)
        try {
            check(signature.size == 64 && verifyEd25519(signature, signedBytes, rootPem)) { "BF-CONFIG-KEY-SIGNATURE" }
        } finally {
            signedBytes.fill(0)
            signature.fill(0)
        }

        val trusted = state.getJSONArray("trusted_keys")
        check(trusted.length() in 1..4) { "BF-CONFIG-KEY-STATE" }
        val keys = ArrayList<TrustedKey>(trusted.length())
        var priorId: String? = null
        for (index in 0 until trusted.length()) {
            val item = trusted.getJSONObject(index)
            exactKeys(item, setOf("key_id", "public_key_pem", "fingerprint", "activation_floor", "retirement_floor"), "BF-CONFIG-KEY-STATE")
            val id = item.getString("key_id")
            val pem = item.getString("public_key_pem")
            val fingerprint = item.getString("fingerprint")
            val activation = item.getLong("activation_floor")
            val retirement = if (item.isNull("retirement_floor")) null else item.getLong("retirement_floor")
            check(id.matches(keyId) && pem.length <= 2048 && pem.isNotBlank() && fingerprint.matches(hex64) && activation > 0) { "BF-CONFIG-KEY-STATE" }
            check(priorId == null || priorId!! < id) { "BF-CONFIG-KEY-STATE" }
            check(retirement == null || retirement > activation) { "BF-CONFIG-KEY-STATE" }
            check(publicKeyFingerprint(pem) == fingerprint) { "BF-CONFIG-KEY-MISMATCH" }
            keys += TrustedKey(id, pem, fingerprint, activation, retirement)
            priorId = id
        }
        check(keys.map { it.keyId }.toSet().size == keys.size && keys.any { it.keyId == activeKeyId }) { "BF-CONFIG-KEY-STATE" }

        val canonical = canonicalJson(state)
        val digest = sha256(canonical)
        check(previousGeneration >= 0 && (previousDigest == null || previousDigest.matches(hex64))) { "BF-CONFIG-KEY-ROLLBACK" }
        if (previousGeneration > 0) {
            when {
                generation < previousGeneration -> throw IllegalStateException("BF-CONFIG-KEY-ROLLBACK")
                generation == previousGeneration -> check(previousDigest != null && digest == previousDigest) { "BF-CONFIG-KEY-EQUIVOCATION" }
                // When the immediately following state is observed, retain
                // the hash-chain check. A device may, however, legitimately
                // be offline across more than one root-signed key-state
                // generation. In that case the missing intermediate digest
                // cannot be reconstructed locally; the immutable compiled
                // root signature on this strictly newer state is the
                // bootstrap authority. Rejecting such a jump permanently
                // bricks otherwise valid offline devices after key rotation.
                generation == previousGeneration + 1 -> check(previousDigest != null && previousStateDigest == previousDigest) { "BF-CONFIG-KEY-ROLLBACK" }
                else -> check(generation > previousGeneration + 1) { "BF-CONFIG-KEY-ROLLBACK" }
            }
        }

        val verified = VerifiedState(generation, activeKeyId, digest, canonical, java.util.Collections.unmodifiableList(keys))
        if (currentConfigVersion > 0) verified.select(activeKeyId, currentConfigVersion)
        return verified
    }

    internal fun publicKeyFingerprint(pem: String): String {
        val der = decodeEd25519Spki(pem)
        return try { sha256(der) } finally { der.fill(0) }
    }

    internal fun rawEd25519PublicKey(pem: String): ByteArray {
        val der = decodeEd25519Spki(pem)
        return try { der.copyOfRange(der.size - 32, der.size) } finally { der.fill(0) }
    }

    private fun verifyEd25519(signature: ByteArray, payload: ByteArray, pem: String): Boolean {
        val der = try { decodeEd25519Spki(pem) } catch (_: Throwable) { return false }
        val raw = der.copyOfRange(der.size - 32, der.size)
        return try {
            Ed25519Verify(raw).verify(signature, payload)
            true
        } catch (_: Throwable) {
            false
        } finally {
            raw.fill(0)
            der.fill(0)
        }
    }

    private fun decodeEd25519Spki(pem: String): ByteArray {
        val body = pem.lineSequence().map(String::trim).filter { it.isNotBlank() && !it.startsWith("-----") }.joinToString("")
        val der = try { Base64.getDecoder().decode(body) } catch (_: Throwable) { throw IllegalStateException("BF-CONFIG-KEY-STATE") }
        check(der.size == ed25519SpkiPrefix.size + 32 && der.copyOfRange(0, ed25519SpkiPrefix.size).contentEquals(ed25519SpkiPrefix)) { "BF-CONFIG-KEY-STATE" }
        return der
    }

    private fun decodeBase64UrlCanonical(value: String): ByteArray {
        val decoded = try { Base64.getUrlDecoder().decode(value) } catch (_: Throwable) { throw IllegalStateException("BF-CONFIG-KEY-SIGNATURE") }
        check(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == value) { "BF-CONFIG-KEY-SIGNATURE" }
        return decoded
    }

    private fun exactKeys(value: JSONObject, required: Set<String>, error: String) {
        val actual = value.keys().asSequence().toSet()
        check(actual == required) { error }
    }

    private fun sha256(value: String): String {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        return try { sha256(bytes) } finally { bytes.fill(0) }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    internal fun canonicalJson(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(separator = ",", prefix = "{", postfix = "}") { key -> BifrostJsonString.quote(key) + ":" + canonicalJson(value.get(key)) }
        is JSONArray -> (0 until value.length()).joinToString(separator = ",", prefix = "[", postfix = "]") { canonicalJson(value.get(it)) }
        is String -> BifrostJsonString.quote(value)
        is Boolean -> value.toString()
        is Byte, is Short, is Int, is Long -> value.toString()
        else -> throw IllegalStateException("BF-CONFIG-KEY-STATE")
    }
}
