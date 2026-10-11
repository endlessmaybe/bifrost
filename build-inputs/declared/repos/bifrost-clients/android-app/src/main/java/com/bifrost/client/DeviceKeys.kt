package com.bifrost.client

import android.content.Context
import com.google.crypto.tink.subtle.Ed25519Sign
import com.google.crypto.tink.subtle.Ed25519Verify
import com.google.crypto.tink.subtle.X25519
import java.security.MessageDigest
import java.util.UUID
import java.util.Base64
import org.json.JSONObject

/**
 * Keystore-backed device identity.  The versioned identity record is the
 * authority; the old five preference keys are accepted only for a strict,
 * one-time migration and are removed after the encrypted record commits.
 */
object DeviceKeys {
    private const val DEVICE_ID = "device_id"
    private const val SIGNING_PRIVATE = "device_ed25519_private"
    private const val SIGNING_PUBLIC = "device_ed25519_public"
    private const val ENCRYPTION_PRIVATE = "device_x25519_private"
    private const val ENCRYPTION_PUBLIC = "device_x25519_public"
    private const val IDENTITY_BLOB = "device_identity_v1"
    private const val IDENTITY_VERSION = 1
    private const val ERROR = "BF-DEVICE-KEYS-CORRUPT"
    private const val FIXED_PROOF = "bifrost-device-key-consistency-v1"

    // RFC 8410 SubjectPublicKeyInfo prefixes for raw 32-byte keys.
    private val ED25519_SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00
    )
    private val X25519_SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
        0x03, 0x21, 0x00
    )

    private data class Identity(
        val deviceId: String,
        val signingPrivate: String,
        val signingPublic: String,
        val encryptionPrivate: String,
        val encryptionPublic: String,
    )

    @Synchronized
    fun ensure(context: Context) {
        readIdentity(context)
    }

    /** Compatibility shim used by older call sites; it never rotates a bad identity. */
    fun ensureSigningKey(context: Context): Boolean {
        ensure(context)
        return true
    }

    fun deviceId(context: Context): String = readIdentity(context).deviceId

    /** Explicit successful logout starts a new enrollment identity. Never
     * invoked during startup, an invalid key migration, or a failed logout. */
    internal fun renewAfterLogout(context: Context) {
        check(listOf("public_id", "session_token", "config_digest").all {
            BifrostSecureStore.get(context, it, "").isEmpty()
        }) { "BF-LOGOUT-LOCAL" }
        val fresh = freshEnrollmentIdentityRecord()
        BifrostSecureStore.putBatch(context, mapOf(
            IDENTITY_BLOB to fresh, DEVICE_ID to null, SIGNING_PRIVATE to null,
            SIGNING_PUBLIC to null, ENCRYPTION_PRIVATE to null, ENCRYPTION_PUBLIC to null,
        ))
    }

    internal fun freshEnrollmentIdentityRecord(): String = serialize(generateIdentity())

    fun signingPublicKey(context: Context): String {
        val identity = readIdentity(context)
        var raw: ByteArray? = null
        var spki: ByteArray? = null
        return try {
            raw = decodeExact(identity.signingPublic, 32)
            spki = ED25519_SPKI_PREFIX + raw
            encode(spki)
        } finally {
            raw?.let { java.util.Arrays.fill(it, 0) }
            spki?.let { java.util.Arrays.fill(it, 0) }
        }
    }

    fun encryptionPublicKey(context: Context): String {
        val identity = readIdentity(context)
        var raw: ByteArray? = null
        var spki: ByteArray? = null
        return try {
            raw = decodeExact(identity.encryptionPublic, 32)
            spki = X25519_SPKI_PREFIX + raw
            encode(spki)
        } finally {
            raw?.let { java.util.Arrays.fill(it, 0) }
            spki?.let { java.util.Arrays.fill(it, 0) }
        }
    }

    /**
     * Perform X25519 inside the device-identity boundary. Production callers
     * never receive the long-lived private key bytes; only the derived shared
     * secret crosses this boundary and the private material is wiped before
     * returning.
     */
    fun deriveEncryptionSharedSecret(context: Context, peerPublicKey: ByteArray): ByteArray =
        deriveEncryptionSharedSecret(peerPublicKey) { decodeExact(readIdentity(context).encryptionPrivate, 32) }

    internal fun deriveEncryptionSharedSecret(peerPublicKey: ByteArray, privateKeyProvider: () -> ByteArray): ByteArray {
        // Envelope parsing has already validated RFC 8410 and removed the
        // 12-byte SPKI prefix. X25519 operates on the resulting 32 raw bytes.
        // Requiring another 44-byte SPKI here rejects every real-device
        // recovery/config decryption before the private key is even read.
        if (peerPublicKey.size != 32) throw IllegalStateException(ERROR)
        var privateKey: ByteArray? = null
        return try {
            privateKey = privateKeyProvider()
            check(privateKey.size == 32)
            X25519.computeSharedSecret(privateKey, peerPublicKey)
        } catch (_: Throwable) {
            throw IllegalStateException(ERROR)
        } finally {
            privateKey?.let { java.util.Arrays.fill(it, 0) }
        }
    }

    fun sign(context: Context, message: String): String {
        val identity = readIdentity(context)
        var privateKey: ByteArray? = null
        var messageBytes: ByteArray? = null
        var signature: ByteArray? = null
        return try {
            privateKey = decodeExact(identity.signingPrivate, 32)
            messageBytes = message.toByteArray(Charsets.UTF_8)
            signature = Ed25519Sign(privateKey).sign(messageBytes)
            encode(signature)
        } catch (_: Throwable) {
            throw IllegalStateException(ERROR)
        } finally {
            privateKey?.let { java.util.Arrays.fill(it, 0) }
            messageBytes?.let { java.util.Arrays.fill(it, 0) }
            signature?.let { java.util.Arrays.fill(it, 0) }
        }
    }

    /** Accept a raw Ed25519 public key or its exact RFC8410 SPKI. */
    fun decodePublicRaw(spkiB64: String): ByteArray {
        val der = decodeCanonical(spkiB64)
        try {
            if (der.size == 32) return der.copyOf()
            if (der.size == 44 && hasPrefix(der, ED25519_SPKI_PREFIX)) return der.copyOfRange(12, 44)
            throw IllegalArgumentException(ERROR)
        } finally {
            java.util.Arrays.fill(der, 0)
        }
    }

    /** Envelope ephemeral keys are X25519 only; an Ed25519 SPKI is invalid. */
    internal fun decodeX25519PublicRaw(spkiB64: String): ByteArray {
        val der = decodeCanonical(spkiB64)
        try {
            check(isX25519PublicEncoding(der))
            return der.copyOfRange(12, 44)
        } finally {
            java.util.Arrays.fill(der, 0)
        }
    }

    /** Envelope authority has one canonical RFC8410 representation. */
    internal fun isX25519PublicEncoding(value: ByteArray): Boolean =
        value.size == 44 && hasPrefix(value, X25519_SPKI_PREFIX)

    /** Shared pure validation entry point used by JVM contract tests. */
    internal fun validateIdentityRecord(blob: String) {
        parseBlob(blob)
    }

    internal fun isInitialIdentityState(blob: String, legacy: List<String>): Boolean =
        blob == "" && legacy.size == 5 && legacy.all { it == "" }

    private fun readIdentity(context: Context): Identity {
        val blob = BifrostSecureStore.get(context, IDENTITY_BLOB, "")
        if (blob != "") {
            val identity = parseBlob(blob)
            // A crash can leave legacy fields beside a valid blob.  Scrub
            // those fields only after the blob has been fully validated; a
            // failed scrub is reported instead of silently retaining a
            // second identity authority.
            val legacyKeys = listOf(DEVICE_ID, SIGNING_PRIVATE, SIGNING_PUBLIC, ENCRYPTION_PRIVATE, ENCRYPTION_PUBLIC)
            // Remove any legacy plaintext and any encrypted duplicate fields
            // left by an interrupted pre-blob migration.  Transaction.apply
            // scrubs legacy first and only then commits encrypted removals.
            try { BifrostSecureStore.clear(context, legacyKeys) } catch (_: Throwable) { throw IllegalStateException(ERROR) }
            return identity
        }

        val legacyKeys = listOf(DEVICE_ID, SIGNING_PRIVATE, SIGNING_PUBLIC, ENCRYPTION_PRIVATE, ENCRYPTION_PUBLIC)
        val legacyValues = try { BifrostSecureStore.readBatch(context, legacyKeys.toSet()) } catch (_: Throwable) { throw IllegalStateException(ERROR) }
        val legacy = legacyKeys.map { legacyValues[it] ?: "" }
        val allEmpty = isInitialIdentityState(blob, legacy)
        val identity = if (allEmpty) generateIdentity() else {
            if (legacy.any { it == "" }) throw IllegalStateException(ERROR)
            Identity(legacy[0], legacy[1], legacy[2], legacy[3], legacy[4]).also(::validateIdentity)
        }
        val serialized = serialize(identity)
        try {
            val values = linkedMapOf<String, String?>(IDENTITY_BLOB to serialized)
            // New identities and migrated identities have one authority: the
            // versioned encrypted blob.  Legacy fields are removed in the
            // same checked encrypted/legacy commit; a failed commit leaves
            // the old recoverable tuple intact.
            values[DEVICE_ID] = null
            values[SIGNING_PRIVATE] = null
            values[SIGNING_PUBLIC] = null
            values[ENCRYPTION_PRIVATE] = null
            values[ENCRYPTION_PUBLIC] = null
            BifrostSecureStore.putBatch(context, values)
            return identity
        } catch (_: Throwable) {
            throw IllegalStateException(ERROR)
        }
    }

    private fun generateIdentity(): Identity {
        var sign: Ed25519Sign.KeyPair? = null
        var signingPrivate: ByteArray? = null
        var signingPublic: ByteArray? = null
        var xPrivate: ByteArray? = null
        var xPublic: ByteArray? = null
        return try {
            sign = Ed25519Sign.KeyPair.newKeyPair()
            signingPrivate = sign.getPrivateKey()
            signingPublic = sign.getPublicKey()
            xPrivate = X25519.generatePrivateKey()
            xPublic = X25519.publicFromPrivate(xPrivate)
            Identity(
                UUID.randomUUID().toString(),
                encode(signingPrivate),
                encode(signingPublic),
                encode(xPrivate),
                encode(xPublic),
            ).also(::validateIdentity)
        } catch (_: Throwable) {
            throw IllegalStateException(ERROR)
        } finally {
            signingPrivate?.let { java.util.Arrays.fill(it, 0) }
            signingPublic?.let { java.util.Arrays.fill(it, 0) }
            xPrivate?.let { java.util.Arrays.fill(it, 0) }
            xPublic?.let { java.util.Arrays.fill(it, 0) }
        }
    }

    private fun parseBlob(blob: String): Identity {
        if (blob.length > 16 * 1024) throw IllegalStateException(ERROR)
        return try {
            StrictJsonValidator(blob, ERROR).validate()
            val root = JSONObject(blob)
            val allowed = setOf("version", "device_id", "signing_private", "signing_public", "encryption_private", "encryption_public")
            val names = root.keys().asSequence().toSet()
            val rawVersion = root.opt("version")
            if (names != allowed || rawVersion !is Number || rawVersion.toString() != IDENTITY_VERSION.toString()) throw IllegalStateException(ERROR)
            listOf("device_id", "signing_private", "signing_public", "encryption_private", "encryption_public")
                .forEach { if (root.opt(it) !is String) throw IllegalStateException(ERROR) }
            Identity(
                root.getString("device_id"),
                root.getString("signing_private"),
                root.getString("signing_public"),
                root.getString("encryption_private"),
                root.getString("encryption_public"),
            ).also(::validateIdentity)
        } catch (_: Throwable) {
            throw IllegalStateException(ERROR)
        }
    }

    private fun serialize(identity: Identity): String = JSONObject()
        .put("version", IDENTITY_VERSION)
        .put("device_id", identity.deviceId)
        .put("signing_private", identity.signingPrivate)
        .put("signing_public", identity.signingPublic)
        .put("encryption_private", identity.encryptionPrivate)
        .put("encryption_public", identity.encryptionPublic)
        .toString()

    private fun validateIdentity(identity: Identity) {
        val uuid = runCatching { UUID.fromString(identity.deviceId) }.getOrNull()
        if (uuid == null || uuid.toString() != identity.deviceId || !identity.deviceId.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))) {
            throw IllegalStateException(ERROR)
        }
        var signingPrivate: ByteArray? = null
        var signingPublic: ByteArray? = null
        var derivedSigning: ByteArray? = null
        var encryptionPrivate: ByteArray? = null
        var encryptionPublic: ByteArray? = null
        var derivedEncryption: ByteArray? = null
        var proof: ByteArray? = null
        var signature: ByteArray? = null
        try {
            signingPrivate = decodeExact(identity.signingPrivate, 32)
            signingPublic = decodeExact(identity.signingPublic, 32)
            encryptionPrivate = decodeExact(identity.encryptionPrivate, 32)
            encryptionPublic = decodeExact(identity.encryptionPublic, 32)
            derivedSigning = Ed25519Sign.KeyPair.newKeyPairFromSeed(signingPrivate).getPublicKey()
            if (!MessageDigest.isEqual(derivedSigning, signingPublic)) throw IllegalStateException(ERROR)
            derivedEncryption = X25519.publicFromPrivate(encryptionPrivate)
            if (!MessageDigest.isEqual(derivedEncryption, encryptionPublic)) {
                throw IllegalStateException(ERROR)
            }
            proof = FIXED_PROOF.toByteArray(Charsets.UTF_8)
            signature = Ed25519Sign(signingPrivate).sign(proof)
            Ed25519Verify(signingPublic).verify(signature, proof)
        } catch (_: Throwable) {
            throw IllegalStateException(ERROR)
        } finally {
            signingPrivate?.let { java.util.Arrays.fill(it, 0) }
            signingPublic?.let { java.util.Arrays.fill(it, 0) }
            derivedSigning?.let { java.util.Arrays.fill(it, 0) }
            encryptionPrivate?.let { java.util.Arrays.fill(it, 0) }
            encryptionPublic?.let { java.util.Arrays.fill(it, 0) }
            derivedEncryption?.let { java.util.Arrays.fill(it, 0) }
            proof?.let { java.util.Arrays.fill(it, 0) }
            signature?.let { java.util.Arrays.fill(it, 0) }
        }
    }

    private fun decodeExact(value: String, expected: Int): ByteArray {
        val decoded = decodeCanonical(value)
        if (decoded.size != expected) {
            java.util.Arrays.fill(decoded, 0)
            throw IllegalStateException(ERROR)
        }
        return decoded
    }

    private fun decodeCanonical(value: String): ByteArray {
        if (value.isEmpty() || value.length > 4096 || !value.matches(Regex("[A-Za-z0-9_-]+"))) throw IllegalStateException(ERROR)
        return try {
            val decoded = Base64.getUrlDecoder().decode(value)
            val canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded)
            if (canonical != value) {
                java.util.Arrays.fill(decoded, 0)
                throw IllegalStateException(ERROR)
            }
            decoded
        } catch (_: Throwable) {
            throw IllegalStateException(ERROR)
        }
    }

    private fun hasPrefix(value: ByteArray, prefix: ByteArray): Boolean {
        if (value.size != 44 || prefix.size > value.size) return false
        for (index in prefix.indices) if (value[index] != prefix[index]) return false
        return true
    }

    private fun encode(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)
}
