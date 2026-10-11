package com.bifrost.client

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/** Encrypted-at-rest last-known-good configuration cache. */
object BifrostConfigStore {
    private const val ALIAS = "bifrost-config-cache-v1"
    private const val FILE_NAME = "config.cache"
    private const val DIRECTORY = "bifrost-config"
    const val MAX_PLAINTEXT_BYTES = 2 * 1024 * 1024
    const val MAX_PROTECTED_BYTES = 1 + 12 + 16 + MAX_PLAINTEXT_BYTES
    const val MAX_CACHE_CONTENT_BYTES = MAX_PLAINTEXT_BYTES - 256
    private const val HEADER_BYTES = 1 + 12
    private const val GCM_TAG_BYTES = 16
    private const val IV_BYTES = 12
    private const val VERSION: Byte = 1
    private const val ERROR = "BF-CONFIG-CACHE-CORRUPT"
    private const val CLEAR_ERROR = "BF-CONFIG-CACHE-CLEAR"
    private const val BINDING_ERROR = "BF-CONFIG-CACHE-BINDING"

    /** A cache is only meaningful together with the signed package binding. */
    data class Cached(
        val core: String,
        val content: String,
        val version: Long = 0L,
        val digest: String = "",
        val commitState: String = BifrostCacheCommitState.STABLE,
    )

    /**
     * An unbound cache is never written.  Keeping this overload makes stale
     * callers fail closed instead of silently creating a cache which cannot be
     * authenticated after a process crash.
     */
    fun save(context: Context, core: String, content: String): Nothing {
        throw IllegalStateException(BINDING_ERROR)
    }

    /** Write a cache which is atomically bound to the signed package metadata. */
    internal fun saveBound(
        context: Context,
        core: String,
        content: String,
        version: Long,
        digest: String,
        commitState: String = BifrostCacheCommitState.STABLE,
    ) {
        require(core in setOf("auto", "sing-box", "xray")) { "BF-CORE-UNSUPPORTED-ANDROID" }
        require(version > 0L && digest.matches(Regex("[0-9a-f]{64}"))) { BINDING_ERROR }
        require(commitState in BifrostCacheCommitState.ALL) { BINDING_ERROR }
        var payload: ByteArray? = null
        var iv: ByteArray? = null
        var container: ByteArray? = null
        var tmp: File? = null
        try {
            payload = BifrostCacheBindingCodec.encode(core, content, version, digest, commitState)
            require(payload!!.isNotEmpty() && payload!!.size <= MAX_PLAINTEXT_BYTES) { "BF-CONFIG-CACHE-TOO-LARGE" }
            val directory = cacheDirectory(context, create = true)
            val target = File(directory, FILE_NAME)
            rejectReparse(target, ERROR)
            val key = key()
            // AndroidKeyStore requires the provider to generate encryption
            // IVs for keys created with randomized encryption enforced.
            container = BifrostConfigCodec.encode(payload!!, key)
            tmp = File(directory, ".${FILE_NAME}.tmp-${System.nanoTime()}")
            writeAtomic(tmp, target, container)
        } catch (error: IllegalArgumentException) {
            if (error.message == "BF-CONFIG-CACHE-TOO-LARGE") throw error
            throw IllegalStateException(ERROR)
        } catch (_: Throwable) {
            throw IllegalStateException(ERROR)
        } finally {
            payload?.fill(0)
            iv?.fill(0)
            container?.fill(0)
            tmp?.let { if (it.exists() && !it.delete()) throw IllegalStateException(ERROR) }
        }
    }

    fun load(context: Context): Cached? {
        val directory = cacheDirectory(context, create = false)
        if (!directory.exists()) return null
        val source = File(directory, FILE_NAME)
        rejectReparse(source, ERROR)
        if (!source.exists()) return null
        if (!source.isFile) throw IllegalStateException(ERROR)
        var container: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            FileInputStream(source).use { input ->
                val size = input.channel.size()
                if (size > Int.MAX_VALUE || !isProtectedSizeAllowed(size.toInt())) throw IllegalStateException(ERROR)
                container = ByteArray(size.toInt())
                var offset = 0
                while (offset < container!!.size) {
                    val read = input.read(container!!, offset, container!!.size - offset)
                    if (read <= 0) throw IllegalStateException(ERROR)
                    offset += read
                }
                if (input.read() != -1 || input.channel.size() != size) throw IllegalStateException(ERROR)
            }
            plaintext = BifrostConfigCodec.decode(container ?: throw IllegalStateException(ERROR), key())
            if (plaintext!!.isEmpty() || plaintext!!.size > MAX_PLAINTEXT_BYTES) throw IllegalStateException(ERROR)
            val decoded = strictUtf8(plaintext!!)
            val bound = BifrostCacheBindingCodec.decode(decoded)
            val metadataVersion = BifrostSecureStore.get(context, "config_version", "").toLongOrNull()
                ?: throw IllegalStateException(BINDING_ERROR)
            val metadataDigest = BifrostSecureStore.get(context, "config_digest", "")
            val metadataState = BifrostSecureStore.get(context, "config_commit_state", "")
            val metadataFloor = BifrostSecureStore.get(context, "rollback_floor", "").toLongOrNull()
                ?: throw IllegalStateException(BINDING_ERROR)
            BifrostCacheReadPolicy.validate(bound, metadataState, metadataVersion, metadataDigest, metadataFloor)
            val config = JSONObject(bound.content)
            BifrostConfigGraphValidator.validate(config, bound.version)
            return Cached(bound.core, bound.content, bound.version, bound.digest, bound.commitState)
        } catch (_: Throwable) {
            throw IllegalStateException(ERROR)
        } finally {
            container?.fill(0)
            plaintext?.fill(0)
        }
    }

    /** Logout/cache invalidation is checked and removes formal plus orphan files. */
    fun clear(context: Context) {
        val directory = cacheDirectory(context, create = false)
        if (!directory.exists()) return
        clearDirectory(directory)
    }

    /** Production file operation exposed to JVM tests through the same path. */
    internal fun clearDirectory(directory: File) {
        try {
            rejectReparse(directory, CLEAR_ERROR)
            if (!directory.exists() || !directory.isDirectory) {
                if (!directory.exists()) return
                throw IllegalStateException(CLEAR_ERROR)
            }
            val files = directory.listFiles() ?: throw IllegalStateException(CLEAR_ERROR)
            for (file in files) {
                rejectReparse(file, CLEAR_ERROR)
                if (file.name == FILE_NAME || file.name.startsWith(".$FILE_NAME.tmp-")) {
                    if (!file.isFile || !file.delete()) throw IllegalStateException(CLEAR_ERROR)
                } else {
                    // An unexpected entry can be a stale staging artifact or
                    // an attacker-controlled file.  Never claim clear while
                    // anything remains in the cache directory.
                    throw IllegalStateException(CLEAR_ERROR)
                }
            }
        } catch (error: IllegalStateException) {
            if (error.message == CLEAR_ERROR) throw error
            throw IllegalStateException(CLEAR_ERROR)
        } catch (_: Throwable) {
            throw IllegalStateException(CLEAR_ERROR)
        }
    }

    /** Pure size contract shared with tests; AES-GCM adds one tag to payload. */
    internal fun protectedSizeForPlaintext(plaintextBytes: Int): Int {
        if (plaintextBytes !in 1..MAX_PLAINTEXT_BYTES) throw IllegalArgumentException(ERROR)
        return HEADER_BYTES + GCM_TAG_BYTES + plaintextBytes
    }

    internal fun isProtectedSizeAllowed(protectedBytes: Int): Boolean =
        protectedBytes in (HEADER_BYTES + GCM_TAG_BYTES)..MAX_PROTECTED_BYTES

    /**
     * Production store seam used by the isolated lifecycle harness.  It uses
     * the same binding codec, AES-GCM codec, atomic writer and read policy as
     * the AndroidKeyStore-backed path; only the root/key are injected by the
     * TEST-ONLY caller.  No release code can select this root or key.
     */
    internal fun saveBoundForTest(
        root: File,
        keyBytes: ByteArray,
        core: String,
        content: String,
        version: Long,
        digest: String,
        commitState: String = BifrostCacheCommitState.STABLE,
    ) {
        require(keyBytes.size == 32) { BINDING_ERROR }
        val directory = File(root, DIRECTORY)
        if (!directory.exists() && !directory.mkdirs()) throw IllegalStateException(ERROR)
        rejectReparse(directory, ERROR)
        val payload = BifrostCacheBindingCodec.encode(core, content, version, digest, commitState)
        val iv = ByteArray(IV_BYTES).also(SecureRandom()::nextBytes)
        val container = try {
            BifrostConfigCodec.encode(payload, SecretKeySpec(keyBytes.copyOf(), "AES"), iv)
        } finally {
            payload.fill(0); iv.fill(0)
        }
        try {
            writeAtomic(File(directory, ".${FILE_NAME}.tmp-${System.nanoTime()}"), File(directory, FILE_NAME), container)
        } finally { container.fill(0) }
    }

    internal fun loadForTest(
        root: File,
        keyBytes: ByteArray,
        metadataVersion: Long,
        metadataDigest: String,
        metadataFloor: Long,
        metadataState: String = BifrostCacheCommitState.STABLE,
    ): Cached? {
        require(keyBytes.size == 32) { BINDING_ERROR }
        val source = File(File(root, DIRECTORY), FILE_NAME)
        if (!source.exists()) return null
        rejectReparse(source, ERROR)
        val container = source.readBytes()
        require(isProtectedSizeAllowed(container.size)) { ERROR }
        val plaintext = try { BifrostConfigCodec.decode(container, SecretKeySpec(keyBytes.copyOf(), "AES")) } finally { container.fill(0) }
        return try {
            val bound = BifrostCacheBindingCodec.decode(strictUtf8(plaintext))
            BifrostCacheReadPolicy.validate(bound, metadataState, metadataVersion, metadataDigest, metadataFloor)
            BifrostConfigGraphValidator.validate(JSONObject(bound.content), bound.version)
            Cached(bound.core, bound.content, bound.version, bound.digest, bound.commitState)
        } finally { plaintext.fill(0) }
    }

    /**
     * TEST-ONLY readback used by the lifecycle harness before a new package is
     * committed.  It still decrypts and validates the production cache
     * binding; the caller cannot supply a version/digest to make an older or
     * equivocal package look current.
     */
    internal fun readBoundForTest(root: File, keyBytes: ByteArray): Cached? {
        require(keyBytes.size == 32) { BINDING_ERROR }
        val source = File(File(root, DIRECTORY), FILE_NAME)
        if (!source.exists()) return null
        rejectReparse(source, ERROR)
        val container = source.readBytes()
        require(isProtectedSizeAllowed(container.size)) { ERROR }
        val plaintext = try {
            BifrostConfigCodec.decode(container, SecretKeySpec(keyBytes.copyOf(), "AES"))
        } finally { container.fill(0) }
        return try {
            val bound = BifrostCacheBindingCodec.decode(strictUtf8(plaintext))
            BifrostConfigGraphValidator.validate(JSONObject(bound.content), bound.version)
            Cached(bound.core, bound.content, bound.version, bound.digest, bound.commitState)
        } finally { plaintext.fill(0) }
    }

    private fun cacheDirectory(context: Context, create: Boolean): File {
        val root = context.noBackupFilesDir
        rejectReparse(root, ERROR)
        val directory = File(root, DIRECTORY)
        rejectReparse(directory, ERROR)
        if (directory.exists() && !directory.isDirectory) throw IllegalStateException(ERROR)
        if (create && !directory.exists() && !directory.mkdirs()) throw IllegalStateException(ERROR)
        if (directory.exists()) rejectReparse(directory, ERROR)
        return directory
    }

    private fun rejectReparse(file: File, code: String) {
        try {
            if (Files.isSymbolicLink(file.toPath())) throw IllegalStateException(code)
        } catch (error: IllegalStateException) {
            throw error
        } catch (_: Throwable) {
            throw IllegalStateException(code)
        }
    }

    private fun writeAtomic(tmp: File, target: File, container: ByteArray) {
        FileOutputStream(tmp, false).use { output ->
            output.write(container)
            output.flush()
            output.fd.sync()
        }
        rejectReparse(tmp, ERROR)
        try {
            Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
            if (!tmp.renameTo(target)) throw IllegalStateException(ERROR)
        }
        rejectReparse(target, ERROR)
    }

    private fun strictUtf8(value: ByteArray): String {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return decoder.decode(ByteBuffer.wrap(value)).toString()
    }

    private fun key(): SecretKey {
        var store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!store.containsAlias(ALIAS)) {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            generator.init(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generator.generateKey()
            store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        }
        return (store.getKey(ALIAS, null) as? SecretKey) ?: throw IllegalStateException(ERROR)
    }
}

internal data class BifrostCacheBinding(
    val core: String,
    val content: String,
    val version: Long,
    val digest: String,
    val commitState: String,
)

internal object BifrostCacheCommitState {
    const val PENDING = "pending"
    const val STABLE = "stable"
    const val QUARANTINE = "quarantine"
    val ALL = setOf(PENDING, STABLE, QUARANTINE)
}

/** Production read gate shared by the Android cache and JVM failure tests. */
internal object BifrostCacheReadPolicy {
    fun validate(
        binding: BifrostCacheBinding,
        metadataState: String,
        metadataVersion: Long,
        metadataDigest: String,
        metadataFloor: Long,
    ) {
        check(binding.commitState == BifrostCacheCommitState.STABLE) { "BF-CONFIG-CACHE-BINDING" }
        check(metadataState == BifrostCacheCommitState.STABLE) { "BF-CONFIG-CACHE-BINDING" }
        check(metadataVersion > 0L && metadataDigest.matches(Regex("[0-9a-f]{64}"))) { "BF-CONFIG-CACHE-BINDING" }
        check(metadataFloor > 0L && metadataFloor <= metadataVersion) { "BF-CONFIG-CACHE-BINDING" }
        check(binding.version == metadataVersion && binding.digest == metadataDigest) { "BF-CONFIG-CACHE-BINDING" }
    }
}

/** Pure, versioned cache envelope used by the production store and JVM tests. */
internal object BifrostCacheBindingCodec {
    private const val SEPARATOR = '\u0000'
    private const val ERROR = "BF-CONFIG-CACHE-BINDING"

    fun encode(
        core: String,
        content: String,
        version: Long,
        digest: String,
        commitState: String = BifrostCacheCommitState.STABLE,
    ): ByteArray {
        require(core in setOf("auto", "sing-box", "xray") && version > 0L && digest.matches(Regex("[0-9a-f]{64}"))) { ERROR }
        require(commitState in BifrostCacheCommitState.ALL) { ERROR }
        val bytes = "$version$SEPARATOR$digest$SEPARATOR$commitState$SEPARATOR$core$SEPARATOR$content".toByteArray(Charsets.UTF_8)
        require(bytes.size <= BifrostConfigStore.MAX_PLAINTEXT_BYTES) { "BF-CONFIG-CACHE-TOO-LARGE" }
        return bytes
    }

    fun decode(value: String): BifrostCacheBinding {
        val first = value.indexOf(SEPARATOR)
        val second = if (first >= 0) value.indexOf(SEPARATOR, first + 1) else -1
        val third = if (second >= 0) value.indexOf(SEPARATOR, second + 1) else -1
        val fourth = if (third >= 0) value.indexOf(SEPARATOR, third + 1) else -1
        check(first > 0 && second > first + 1 && third > second + 1 && fourth > third + 1 && fourth < value.length - 1) { ERROR }
        val version = value.substring(0, first).toLongOrNull() ?: throw IllegalStateException(ERROR)
        val digest = value.substring(first + 1, second)
        val commitState = value.substring(second + 1, third)
        val core = value.substring(third + 1, fourth)
        val content = value.substring(fourth + 1)
        check(version > 0L && digest.matches(Regex("[0-9a-f]{64}"))) { ERROR }
        check(commitState in BifrostCacheCommitState.ALL) { ERROR }
        check(core in setOf("auto", "sing-box", "xray") && content.isNotBlank() && content.length <= BifrostConfigStore.MAX_CACHE_CONTENT_BYTES) { ERROR }
        return BifrostCacheBinding(core, content, version, digest, commitState)
    }
}

/** Versioned AES-GCM codec.  Kept Android-free so the exact production codec
 * can be exercised by JVM tests with a generated test key. */
internal object BifrostConfigCodec {
    private const val IV_BYTES = 12
    private const val TAG_BYTES = 16
    private const val HEADER_BYTES = 13
    private const val VERSION: Byte = 1

    fun encode(plaintext: ByteArray, key: SecretKey, iv: ByteArray? = null): ByteArray {
        require(plaintext.isNotEmpty() && plaintext.size <= BifrostConfigStore.MAX_PLAINTEXT_BYTES)
        require(iv == null || iv.size == IV_BYTES)
        var encrypted: ByteArray? = null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            // Explicit IVs are retained for deterministic software-key test
            // vectors. Production AndroidKeyStore callers use the default.
            if (iv == null) cipher.init(Cipher.ENCRYPT_MODE, key)
            else cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            val generatedIv = cipher.iv
            require(generatedIv.size == IV_BYTES)
            encrypted = cipher.doFinal(plaintext)
            require(encrypted!!.size == plaintext.size + TAG_BYTES)
            val result = ByteArray(HEADER_BYTES + encrypted!!.size)
            result[0] = VERSION
            generatedIv.copyInto(result, 1)
            encrypted!!.copyInto(result, HEADER_BYTES)
            require(result.size <= BifrostConfigStore.MAX_PROTECTED_BYTES)
            result
        } finally {
            encrypted?.fill(0)
        }
    }

    fun decode(container: ByteArray, key: SecretKey): ByteArray {
        require(container.size in (HEADER_BYTES + TAG_BYTES)..BifrostConfigStore.MAX_PROTECTED_BYTES)
        require(container[0] == VERSION)
        val iv = container.copyOfRange(1, HEADER_BYTES)
        val encrypted = container.copyOfRange(HEADER_BYTES, container.size)
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                doFinal(encrypted)
            }.also { require(it.size <= BifrostConfigStore.MAX_PLAINTEXT_BYTES) }
        } finally {
            iv.fill(0)
            encrypted.fill(0)
        }
    }
}
