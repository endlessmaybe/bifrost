package com.bifrost.client

import android.content.Context
import android.os.Build
import com.google.crypto.tink.subtle.Ed25519Verify
import com.google.crypto.tink.subtle.X25519
import java.io.BufferedInputStream
import java.io.File
import java.io.FileOutputStream
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.NoRouteToHostException
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.URI
import java.net.URL
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.Locale
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject

internal fun interface BifrostLifecycleHttpConnectionFactory {
    fun open(url: URL): HttpURLConnection
}

/** Blocking control-plane client. Callers run it on an IO dispatcher. */
class BifrostControlClient(private val context: Context, private val lifecycleOnly: Boolean = false) {
    data class Outcome(
        val state: String,
        val message: String,
        val publicId: String = "",
        val recoveryCode: String = "",
        val pairingCode: String = "",
        val configVersion: Long = 0,
    )

    private data class Response(val status: Int, val body: String, val path: String, val method: String)

    private data class VerifiedPackage(
        val version: Long,
        val core: String,
        val content: String,
        val digest: String,
    )

    private var lifecycleBaseUrl: String? = null
    private var lifecycleStableReader: (() -> BifrostConfigStore.Cached?)? = null
    private var lifecycleForcedStatus: Int? = null
    private var lifecycleSessionToken: String? = null
    private var lifecycleConnectionFactory: BifrostLifecycleHttpConnectionFactory? = null

    private val transactionKeys = listOf(
        "control_base_url", "public_id", "session_token", "config_version",
        "rollback_floor", "config_digest", "config_signing_public_key",
        "recovery_code", "account_recovery_code", "pairing_code", "manifest_sequence", "manifest_digest",
        "config_commit_state", "enrollment_pending_origin",
    )
    private val configCommitKeys = (transactionKeys + ConfigKeyTrust.STORAGE_KEYS).distinct()

    fun enroll(baseUrl: String, inviteCode: String): Outcome = synchronized(configRefreshLock) {
        check(!isEnrolled()) { "BF-ENROLL-003" }
        try {
            enrollOnce(baseUrl, inviteCode)
        } catch (error: IllegalStateException) {
            if (error.message != "BF-ENROLL-003") throw error
            // A missing local account field does not authorize revoking an
            // existing server binding. Prove and resume that device first.
            establishSession(normalizeBase(baseUrl), persist = true)
            val refreshed = refreshOnline()
            Outcome("resumed", "Existing device registration restored", accountSnapshot().publicId,
                configVersion = refreshed.configVersion)
        }
    }

    private fun enrollOnce(baseUrl: String, inviteCode: String): Outcome {
        require(inviteCode.trim().isNotEmpty() && inviteCode.length <= 256) { "BF-ENROLL-INVITE" }
        val normalized = normalizeBase(baseUrl)
        DeviceKeys.ensure(context)
        val body = JSONObject()
            .put("invite_code", inviteCode.trim())
            .put("platform", "android")
            .put("device_id", DeviceKeys.deviceId(context))
            .put("signing_public_key", DeviceKeys.signingPublicKey(context))
            .put("encryption_public_key", DeviceKeys.encryptionPublicKey(context))
            .put("key_level", "software")
        // Keep retries of this exact activation bound to the same operation,
        // including after a restart or a lost response. Never log the code.
        val activationKey = "android-activate-" + sha256(DeviceKeys.deviceId(context) + "|" + inviteCode.trim()).take(48)
        // A phone can be locally unenrolled while still retaining an older
        // control_base_url from an interrupted/legacy enrollment.  Bootstrap
        // activation is already pinned to the caller-supplied trusted base
        // (production UI passes BuildConfig.CONTROL_BASE_URL), so that stale
        // persisted origin must not block the request before it reaches
        // Control.  Once enrolled, normal requests remain bound to the
        // persisted origin as before.
        val bootstrapOrigin = if (isEnrolled()) null else normalized
        BifrostSecureStore.put(context, "enrollment_pending_origin", normalized)
        val response = request(
            normalized + "/v1/enrollment/redeem",
            "POST",
            body.toString(),
            "",
            idempotencyKey = activationKey,
            bootstrapOrigin = bootstrapOrigin,
        )
        if (response.status !in 200..299) {
            val error = response.body.takeIf { it.isNotBlank() }?.let {
                parseResponse(response, "BF-ENROLL-RESPONSE")
            }
            val failure = BifrostEnrollmentFailure.code(response.status, error)
            // An explicit invalid/expired code did not create a registration.
            // Preserve the marker for ambiguous transport failures instead.
            if (failure in setOf("BF-ENROLL-001", "BF-ENROLL-002"))
                BifrostSecureStore.remove(context, "enrollment_pending_origin")
            throw IllegalStateException(failure)
        }
        val result = parseResponse(response, "BF-ENROLL-RESPONSE")
        val publicId = boundedString(strictStringField(result, "public_id", "BF-ENROLL-RESPONSE"), 256)
        val version = strictLongField(result, "config_version", "BF-ENROLL-RESPONSE")
        check(publicId.isNotBlank() && version > 0) { "BF-ENROLL-RESPONSE" }
        val trustState = ConfigKeyTrust.verifyResponseState(
            context,
            result.optJSONObject("config_key_state"),
            version,
            bootstrap = !isEnrolled(),
        )
        // A brand-new registration carries the one-time recovery delivery.
        // A reused invitation may omit delivery. Recovery-code activation
        // seals the unchanged account code to this device; it never rotates
        // the credential on the other platform.
        val recoveryEnvelope = result.optJSONObject("recovery_delivery")
        val recovery = if (recoveryEnvelope == null) "" else decryptRecoveryDelivery(recoveryEnvelope, trustState).also {
            check(it.isNotBlank()) { "BF-ENROLL-RESPONSE" }
        }

        // Verify the signed/decrypted package and establish a session before
        // committing any account metadata. The encrypted recovery value and
        // new trust state are committed atomically with the verified config.
        val previousFloor = readVersion("rollback_floor")
        val verified = verifyPackage(result.optJSONObject("config_package"), version, trustState)
        check(verified.version >= previousFloor) { "BF-CONFIG-ROLLBACK" }
        val sessionToken = establishSession(normalized, persist = false)
        val floor = BifrostRollback.advance(previousFloor, verified.version)
        val metadata = mutableMapOf<String, String?>(
            "control_base_url" to normalized,
            "public_id" to publicId,
            "session_token" to sessionToken,
            "config_version" to verified.version.toString(),
            "rollback_floor" to floor.toString(),
            "config_digest" to verified.digest,
            "config_signing_public_key" to null,
            "recovery_code" to null,
            "account_recovery_code" to recovery.takeIf { it.isNotBlank() },
            "enrollment_pending_origin" to null,
        )
        if (trustState != null) metadata.putAll(ConfigKeyTrust.storageValues(trustState))
        commitVerifiedPackage(verified, metadata, "BF-ENROLL-COMMIT")
        return Outcome("enrolled", "Device enrolled", publicId, recovery, configVersion = verified.version)
    }

    fun recover(baseUrl: String, recoveryCode: String): Outcome {
        require(recoveryCode.trim().isNotEmpty() && recoveryCode.length <= 256) { "BF-RECOVERY-INPUT" }
        val result = enroll(baseUrl, recoveryCode)
        // Enrollment verifies and atomically saves the device-sealed recovery
        // delivery together with its signed configuration and session.
        return result.copy(state = "paired", message = "Account activated on Android")
    }

    fun savedRecoveryCode(): String = if (isEnrolled()) BifrostSecureStore.get(context, "account_recovery_code", "") else ""

    fun rotateRecoveryCode(): Outcome {
        val base = configuredBase() ?: throw IllegalStateException("BF-RECOVERY-DELIVERY")
        check(isEnrolled()) { "BF-PAIR-NOT-ENROLLED" }
        val operation = randomToken(18)
        var response = authorizedRequest(base + "/v1/recovery/rotate", "POST", "{}", idempotencyKey = operation)
        if (response.status == 401) {
            establishSession(base, persist = true)
            response = authorizedRequest(base + "/v1/recovery/rotate", "POST", "{}", idempotencyKey = operation)
        }
        check(response.status in 200..299) { "BF-RECOVERY-DELIVERY" }
        val result = parseResponse(response, "BF-RECOVERY-DELIVERY")
        val version = strictLongField(result, "config_version", "BF-RECOVERY-DELIVERY")
        val trust = ConfigKeyTrust.verifyResponseState(context, result.optJSONObject("config_key_state"), version)
        val code = decryptRecoveryDelivery(result.optJSONObject("recovery_delivery"), trust)
        val metadata = mutableMapOf<String, String?>("account_recovery_code" to code)
        if (trust != null) metadata.putAll(ConfigKeyTrust.storageValues(trust))
        BifrostSecureStore.putBatch(context, metadata)
        return Outcome("recovery-ready", "Recovery code renewed", publicId = BifrostSecureStore.get(context, "public_id", ""), recoveryCode = code, configVersion = version)
    }

    /**
     * Fetches the administrator-approved recovery delivery.  The control
     * plane returns only a signed, device-encrypted envelope; this method
     * decrypts it once in memory and never persists the plaintext.  A 401 is
     * handled by one explicit session establishment, after which the request
     * is retried with a fresh sender-constrained proof.
     */
    fun retrieveRecoveryDelivery(): Outcome {
        val base = configuredBase() ?: throw IllegalStateException("BF-RECOVERY-DELIVERY")
        val deliveryIdempotency = randomToken(18)
        var response = authorizedRequest(base + "/v1/recovery/delivery", "GET", null, deliveryIdempotency)
        if (response.status == 401) {
            establishSession(base, persist = true)
            response = authorizedRequest(base + "/v1/recovery/delivery", "GET", null, deliveryIdempotency)
        }
        check(response.status in 200..299) { "BF-RECOVERY-DELIVERY" }
        val result = parseResponse(response, "BF-RECOVERY-DELIVERY")
        val version = strictLongField(result, "config_version", "BF-RECOVERY-DELIVERY")
        check(version > 0) { "BF-RECOVERY-DELIVERY" }
        val trustState = ConfigKeyTrust.verifyResponseState(
            context,
            result.optJSONObject("config_key_state"),
            version,
            bootstrap = !isEnrolled(),
        )
        val code = decryptRecoveryDelivery(result.optJSONObject("recovery_delivery"), trustState)
        if (trustState != null) ConfigKeyTrust.commit(context, trustState)
        return Outcome("recovery-ready", "Recovery code is ready for one-time display", publicId = BifrostSecureStore.get(context, "public_id", ""), recoveryCode = code, configVersion = version)
    }

    fun createPairing(targetPlatform: String): Outcome {
        require(targetPlatform == "android" || targetPlatform == "windows") { "BF-PAIR-PLATFORM" }
        val base = configuredBase() ?: throw IllegalStateException("BF-PAIR-NOT-ENROLLED")
        check(isEnrolled()) { "BF-PAIR-NOT-ENROLLED" }
        val operation = randomToken(18)
        val body = JSONObject().put("target_platform", targetPlatform).toString()
        var response = authorizedRequest(base + "/v1/pairing/create", "POST", body, idempotencyKey = operation)
        if (response.status == 401) {
            establishSession(base, persist = true)
            response = authorizedRequest(base + "/v1/pairing/create", "POST", body, idempotencyKey = operation)
        }
        check(response.status in 200..299) { "BF-PAIR-CREATE-HTTP-${response.status}" }
        val code = strictStringField(parseResponse(response, "BF-PAIR-CREATE-RESPONSE"), "pairing_code", "BF-PAIR-CREATE-RESPONSE")
        check(code.isNotBlank() && code.length <= 512) { "BF-PAIR-CREATE-RESPONSE" }
        return Outcome("pairing-created", "Pairing code created; it expires in ten minutes", pairingCode = code)
    }

    fun redeemPairing(baseUrl: String, pairingCode: String): Outcome {
        require(pairingCode.trim().isNotEmpty() && pairingCode.length <= 512) { "BF-PAIR-CODE" }
        val normalized = normalizeBase(baseUrl)
        DeviceKeys.ensure(context)
        val body = JSONObject()
            .put("pairing_code", pairingCode.trim())
            .put("platform", "android")
            .put("device_id", DeviceKeys.deviceId(context))
            .put("signing_public_key", DeviceKeys.signingPublicKey(context))
            .put("encryption_public_key", DeviceKeys.encryptionPublicKey(context))
            .put("key_level", "software")
        val operation = "android-pair-" + sha256(DeviceKeys.deviceId(context) + "|" + pairingCode.trim()).take(48)
        val response = request(normalized + "/v1/pairing/redeem", "POST", body.toString(), "", idempotencyKey = operation)
        check(response.status in 200..299) { "BF-PAIR-REDEEM-HTTP-${response.status}" }
        val result = parseResponse(response, "BF-PAIR-REDEEM-RESPONSE")
        val publicId = boundedString(strictStringField(result, "public_id", "BF-PAIR-REDEEM-RESPONSE"), 256)
        val version = strictLongField(result, "config_version", "BF-PAIR-REDEEM-RESPONSE")
        check(publicId.isNotBlank() && version > 0) { "BF-PAIR-REDEEM-RESPONSE" }
        val trustState = ConfigKeyTrust.verifyResponseState(context, result.optJSONObject("config_key_state"), version)
        val previousFloor = readVersion("rollback_floor")
        val verified = verifyPackage(result.optJSONObject("config_package"), version, trustState)
        check(verified.version >= previousFloor) { "BF-CONFIG-ROLLBACK" }
        val sessionToken = establishSession(normalized, persist = false)
        val floor = BifrostRollback.advance(previousFloor, verified.version)
        val metadata = mutableMapOf<String, String?>(
            "control_base_url" to normalized,
            "public_id" to publicId,
            "session_token" to sessionToken,
            "config_version" to verified.version.toString(),
            "rollback_floor" to floor.toString(),
            "config_digest" to verified.digest,
            "config_signing_public_key" to null,
            "recovery_code" to null,
        )
        if (trustState != null) metadata.putAll(ConfigKeyTrust.storageValues(trustState))
        commitVerifiedPackage(verified, metadata, "BF-PAIR-REDEEM-COMMIT")
        return Outcome("paired", "Device paired", publicId = publicId, configVersion = verified.version)
    }

    internal fun renewReleaseSession(): String {
        val base = normalizeBase(BifrostSecureStore.get(context, "control_base_url", ""))
        return establishSession(base, persist = true)
    }

    fun refresh(): Outcome = synchronized(configRefreshLock) {
        val previousVersion = if (lifecycleOnly) 0L else readVersion("config_version")
        val previousNodes = if (lifecycleOnly) null else runCatching {
            BifrostNodeUpdateNotifications.fingerprint(loadCached()?.content)
        }.getOrNull()
        val offlineGate = BifrostOfflineUpdateCoordinator(
            readStable = { loadCached() },
            identity = { cached -> Triple(cached.version, cached.digest, sha256(cached.content)) },
        )
        val outcome = try {
            refreshOnline()
        } catch (error: Throwable) {
            if (error is BifrostDeviceRevokedException && !lifecycleOnly) {
                clearLoggedOutIdentity()
                throw error
            }
            if (!BifrostAvailabilityClassifier.canUseOffline(error) || loadCached() == null) throw error
            val offline = offlineGate.run(update = { throw error })
            Outcome("offline", "Control plane unavailable; continuing with the last known-good configuration", configVersion = offline.version)
        }
        if (!lifecycleOnly) runCatching {
            val currentNodes = BifrostNodeUpdateNotifications.fingerprint(loadCached()?.content)
            BifrostNodeUpdateNotifications.updated(context, previousVersion, outcome.configVersion,
                previousNodes != null && currentNodes != null && previousNodes != currentNodes)
        }
        outcome
    }

    /** Test-only transport injection still executes this production request path. */
    internal fun <T> withLifecycleHttpConnectionFactory(
        factory: BifrostLifecycleHttpConnectionFactory,
        action: () -> T,
    ): T {
        check(lifecycleOnly || BuildConfig.DEBUG && BuildConfig.BIFROST_TEST_VARIANT) { "BF-TEST-SCOPE" }
        check(lifecycleConnectionFactory == null) { "BF-TEST-SCOPE" }
        lifecycleConnectionFactory = factory
        return try { action() } finally { lifecycleConnectionFactory = null }
    }

    /**
     * Test-only invocation of the same refresh path against a stopped
     * loopback Control endpoint.  The cache reader is the encrypted test
     * store, while URL validation, HTTP request, classifier and LKG gate stay
     * in this production client.
     */
    internal fun refreshUnavailableForLifecycleTest(baseUrl: String, readStable: () -> BifrostConfigStore.Cached?): Outcome {
        check(lifecycleOnly) { "BF-TEST-SCOPE" }
        lifecycleBaseUrl = normalizeBase(baseUrl)
        lifecycleStableReader = readStable
        return try { refresh() } finally {
            lifecycleBaseUrl = null
            lifecycleStableReader = null
        }
    }

    /** Reachable-Control lifecycle check for a revoked/expired old session. */
    internal fun refreshReachableForLifecycleTest(
        baseUrl: String,
        sessionToken: String,
        readStable: () -> BifrostConfigStore.Cached?,
    ): Outcome {
        check(lifecycleOnly && sessionToken.isNotBlank()) { "BF-TEST-SCOPE" }
        lifecycleBaseUrl = normalizeBase(baseUrl)
        lifecycleSessionToken = sessionToken
        lifecycleStableReader = readStable
        return try { refresh() } finally {
            lifecycleBaseUrl = null
            lifecycleSessionToken = null
            lifecycleStableReader = null
        }
    }

    internal fun refreshStatusForLifecycleTest(status: Int, readStable: () -> BifrostConfigStore.Cached?): Outcome {
        check(lifecycleOnly && status in 400..599) { "BF-TEST-SCOPE" }
        lifecycleBaseUrl = "http://127.0.0.1:1"
        lifecycleStableReader = readStable
        lifecycleForcedStatus = status
        return try { refresh() } finally {
            lifecycleBaseUrl = null
            lifecycleStableReader = null
            lifecycleForcedStatus = null
        }
    }

    private fun refreshOnline(): Outcome {
        if (!lifecycleOnly) {
            val account = accountSnapshot()
            if (!account.enrolled) {
                if (!account.needsResume) return Outcome("not-enrolled", "Device is not enrolled")
                val pending = BifrostSecureStore.get(context, "enrollment_pending_origin", "")
                val base = normalizeBase(pending.ifBlank { configuredBase().orEmpty() })
                establishSession(base, persist = true)
            }
        }
        val base = configuredBase() ?: return Outcome("disabled", "Control plane URL is not configured")
        val manifestResponse = authorizedRequest(base + "/v1/config/manifest", "GET", null)
        if (manifestResponse.status == 401) {
            if (lifecycleOnly && !lifecycleSessionToken.isNullOrBlank())
                return cachedFailure(401, "Control authentication failed")
            val token = establishSession(base, persist = true)
            check(token.isNotBlank()) { "BF-SESSION-HTTP" }
            return refreshWithSession(base)
        }
        if (manifestResponse.status !in 200..299) return cachedFailure(manifestResponse.status, "Control plane request failed (${manifestResponse.status})")
        val manifest = parseResponse(manifestResponse, "BF-CONFIG-MANIFEST")
        val validated = BifrostManifestValidator.validate(manifest, readVersion("rollback_floor"))
        val trustState = ConfigKeyTrust.verifyResponseState(context, manifest.optJSONObject("config_key_state"), validated.version)
        return applyManifest(base, manifest, trustState)
    }

    fun logout(): Outcome = synchronized(configRefreshLock) {
        BifrostRootConnectionIntent.stop(context)
        val base = normalizeBase(BifrostSecureStore.get(context, "control_base_url", BuildConfig.CONTROL_BASE_URL))
        // Keep the identity and credentials until Control confirms revocation.
        // A timeout must remain retryable, including after a process restart.
        // Renew first: an expired bearer alone is not evidence of revocation.
        BifrostLogoutCoordinator.complete(remote = {
            val token = establishSession(base, persist = false)
            val response = request(base + "/v1/device/logout", "POST", "{}", token, senderConstrained = true)
            BifrostLogoutCoordinator.remoteFailure(response.status)
        }, clear = ::clearLoggedOutIdentity)
        Outcome("logged-out", "This device has been logged out")
    }

    private fun clearLoggedOutIdentity() {
        val localStore = object : BifrostLogoutStore {
            override fun clearCache(): Boolean = try {
                BifrostConfigStore.clear(context)
                true
            } catch (_: Throwable) { false }

            override fun clearAccount(): Boolean = try {
                BifrostSecureStore.clear(context, transactionKeys)
                true
            } catch (_: Throwable) { false }
        }
        BifrostLogoutCoordinator.clearLocal(localStore)
        DeviceKeys.renewAfterLogout(context)
    }

    fun isEnrolled(): Boolean = BifrostSecureStore.get(context, "public_id", "").isNotBlank()

    internal fun accountSnapshot(): BifrostAccountSnapshot {
        return BifrostAccountSnapshot.from(BifrostSecureStore.readBatch(context, BifrostAccountSnapshot.KEYS))
    }

    private fun configuredBase(): String? {
        if (lifecycleOnly) return lifecycleBaseUrl
        val configured = BifrostSecureStore.get(context, "control_base_url", BuildConfig.CONTROL_BASE_URL)
        return if (configured.isBlank()) null else normalizeBase(configured)
    }

    private fun loadCached(): BifrostConfigStore.Cached? = lifecycleStableReader?.invoke() ?: BifrostConfigStore.load(context)

    private fun refreshWithSession(base: String): Outcome {
        val response = authorizedRequest(base + "/v1/config/manifest", "GET", null)
        if (response.status !in 200..299) return cachedFailure(response.status, "Session refresh failed (${response.status})")
        val manifest = parseResponse(response, "BF-CONFIG-MANIFEST")
        val validated = BifrostManifestValidator.validate(manifest, readVersion("rollback_floor"))
        val trustState = ConfigKeyTrust.verifyResponseState(context, manifest.optJSONObject("config_key_state"), validated.version)
        return applyManifest(base, manifest, trustState)
    }

    private fun applyManifest(base: String, manifest: JSONObject, trustState: ConfigKeyTrust.VerifiedState?): Outcome {
        val storedFloor = readVersion("rollback_floor")
        val validatedManifest = BifrostManifestValidator.validate(manifest, storedFloor)
        val version = validatedManifest.version
        val manifestFloor = validatedManifest.rollbackFloor
        val manifestDigest = validatedManifest.digest
        val cached = BifrostConfigRepairPolicy.readForOnlineRepair { loadCached() }
        val cachedVersion = readVersion("config_version")
        if (version < cachedVersion) throw IllegalStateException("BF-CONFIG-ROLLBACK")
        val storedDigest = BifrostSecureStore.get(context, "config_digest", "")
        BifrostConfigRepairPolicy.requireSameVersionDigest(version, cachedVersion, manifestDigest, storedDigest)
        if (cached != null && version == cachedVersion) {
            if (trustState != null) ConfigKeyTrust.commit(context, trustState)
            return Outcome("cached", "Using the last known-good configuration", configVersion = cachedVersion)
        }
        val packageResponse = authorizedRequest(base + "/v1/config/packages/$version", "GET", null)
        if (packageResponse.status !in 200..299) return cachedFailure(packageResponse.status, "Configuration package request failed (${packageResponse.status})")
        val verified = verifyPackage(parseResponse(packageResponse, "BF-CONFIG-PACKAGE"), version, trustState)
        check(verified.digest == manifestDigest) { "BF-CONFIG-DIGEST" }
        val newFloor = BifrostRollback.acceptManifest(storedFloor, manifestFloor, verified.version)
        val metadata = mutableMapOf<String, String?>(
            "config_version" to verified.version.toString(),
            "rollback_floor" to newFloor.toString(),
            "config_digest" to verified.digest,
        )
        if (trustState != null) metadata.putAll(ConfigKeyTrust.storageValues(trustState))
        commitVerifiedPackage(verified, metadata, "BF-CONFIG-METADATA")
        return Outcome("updated", "Node configuration updated", configVersion = verified.version)
    }

    /** Commits a fully verified package through the shared production coordinator. */
    private fun commitVerifiedPackage(verified: VerifiedPackage, metadata: Map<String, String?>, code: String) {
        val previousCache = BifrostConfigRepairPolicy.readForOnlineRepair { loadCached() }
        val previousMetadata = configCommitKeys.associateWith { key ->
            try { BifrostSecureStore.get(context, key, "") } catch (_: Throwable) {
                throw IllegalStateException("BF-CONFIG-TRANSACTION")
            }
        }.mapValues { (_, value) -> if (value.isEmpty()) null else value }
        try {
            val store = object : BifrostCommitStore<BifrostConfigStore.Cached, Map<String, String?>> {
                private var expectedMetadata = metadata
                override fun snapshot() = BifrostCommitSnapshot(previousCache, previousMetadata)
                override fun markPending(): Boolean = try {
                    BifrostSecureStore.put(context, "config_commit_state", BifrostCacheCommitState.PENDING)
                    true
                } catch (_: Throwable) { false }
                override fun writeCache(value: BifrostConfigStore.Cached): Boolean = try {
                    BifrostConfigStore.saveBound(
                        context,
                        value.core,
                        value.content,
                        value.version,
                        value.digest,
                        BifrostCacheCommitState.PENDING,
                    )
                    true
                } catch (_: Throwable) { false }
                override fun writeMetadata(value: Map<String, String?>): Boolean = try {
                    BifrostSecureStore.putBatch(context, value + ("config_commit_state" to BifrostCacheCommitState.PENDING))
                    true
                } catch (_: Throwable) { false }
                override fun finalizeCache(value: BifrostConfigStore.Cached): Boolean = try {
                    BifrostConfigStore.saveBound(context, value.core, value.content, value.version, value.digest, BifrostCacheCommitState.STABLE)
                    true
                } catch (_: Throwable) { false }
                override fun markStable(): Boolean = try {
                    BifrostSecureStore.put(context, "config_commit_state", BifrostCacheCommitState.STABLE)
                    true
                } catch (_: Throwable) { false }
                override fun quarantine(): Boolean = try {
                    BifrostSecureStore.put(context, "config_commit_state", BifrostCacheCommitState.QUARANTINE)
                    true
                } catch (_: Throwable) { false }
                override fun clearCache(): Boolean = try { BifrostConfigStore.clear(context); true } catch (_: Throwable) { false }
                override fun restoreCache(value: BifrostConfigStore.Cached?): Boolean = try {
                    if (value == null) BifrostConfigStore.clear(context)
                    else BifrostConfigStore.saveBound(context, value.core, value.content, value.version, value.digest, BifrostCacheCommitState.STABLE)
                    true
                } catch (_: Throwable) { false }
                override fun restoreMetadata(value: Map<String, String?>): Boolean = try {
                    BifrostSecureStore.putBatch(context, value)
                    expectedMetadata = value
                    true
                } catch (_: Throwable) { false }
                override fun isCommitted(candidate: BifrostConfigStore.Cached): Boolean = try {
                    val current = BifrostConfigStore.load(context)
                    val stable = BifrostSecureStore.get(context, "config_commit_state", "") == BifrostCacheCommitState.STABLE
                    val contentMatches = current?.core == candidate.core &&
                        current.content == candidate.content &&
                        current.version == candidate.version &&
                        current.digest == candidate.digest &&
                        current.commitState == BifrostCacheCommitState.STABLE
                    val metadataMatches = expectedMetadata.all { (key, expected) ->
                        val actual = BifrostSecureStore.get(context, key, "")
                        if (expected == null) actual.isEmpty() else actual == expected
                    }
                    stable && contentMatches && metadataMatches
                } catch (_: Throwable) { false }
                override fun isReadable(): Boolean = try { loadCached() != null } catch (_: Throwable) { false }
            }
            val sessionToken = metadata["session_token"]
                ?: BifrostSecureStore.get(context, "session_token", "")
            commitVerifiedPackageThroughCoordinator(verified, metadata, code, store, sessionToken)
        } catch (error: IllegalStateException) {
            if (error.message == code || error.message == "BF-CONFIG-TRANSACTION") throw error
            throw IllegalStateException(code)
        } catch (_: Throwable) {
            throw IllegalStateException(code)
        }
    }

    /**
     * The one production commit entry point shared by refresh/enrollment and
     * the isolated lifecycle consumer.  Only the store implementation and
     * session seam vary; ordering, readback and rollback always come from the
     * production BifrostCommitCoordinator.
     */
    private fun <M> commitVerifiedPackageThroughCoordinator(
        verified: VerifiedPackage,
        metadata: M,
        code: String,
        store: BifrostCommitStore<BifrostConfigStore.Cached, M>,
        sessionToken: String,
    ) {
        val candidate = BifrostConfigStore.Cached(
            verified.core,
            verified.content,
            verified.version,
            verified.digest,
        )
        BifrostSessionCommitGate.commit(sessionToken, code) {
            BifrostCommitCoordinator.commit(store, candidate, metadata, code)
        }
    }

    private fun readVersion(key: String): Long {
        val raw = BifrostSecureStore.get(context, key, "0")
        val value = raw.toLongOrNull() ?: throw IllegalStateException("BF-CONFIG-METADATA")
        check(value >= 0) { "BF-CONFIG-METADATA" }
        return value
    }

    private fun verifyPackage(envelope: JSONObject?, expectedVersion: Long, trustState: ConfigKeyTrust.VerifiedState?): VerifiedPackage =
        verifyPackageWithPrivateKey(envelope, expectedVersion, null, null, trustState)

    /**
     * The isolated lifecycle invokes this exact production verifier and then
     * the exact production cache binding/read gate with only TEST-ONLY key and
     * root seams.  It is internal so no release API can select it.
     */
    internal fun consumePackageForLifecycleTest(
        envelope: JSONObject,
        expectedVersion: Long,
        encryptionPrivateKey: ByteArray,
        root: File,
        cacheKey: ByteArray,
        trustedConfigPublicKey: ByteArray? = null,
        failureAfterCacheWrite: Boolean = false,
    ): LifecyclePackageResult {
        require(lifecycleOnly) { "BF-TEST-SCOPE" }
        val verified = verifyPackageWithPrivateKey(envelope, expectedVersion, encryptionPrivateKey, trustedConfigPublicKey, null)
        val digest = verified.digest
        val store = BifrostLifecycleCommitStore(root, cacheKey, failureAfterCacheWrite)
        val previous = try {
            store.snapshot().cache
        } catch (error: IllegalStateException) {
            if (error.message?.startsWith("BF-") == true) throw error
            throw IllegalStateException("BF-CONFIG-TRANSACTION")
        }
        if (previous != null) {
            check(verified.version >= previous.version) { "BF-CONFIG-ANTI-ROLLBACK" }
            check(verified.version != previous.version || digest == previous.digest) { "BF-CONFIG-EQUIVOCATION" }
        }
        val floor = maxOf(previous?.version ?: 0L, verified.version)
        val metadata = mapOf(
            "config_version" to verified.version.toString(),
            "rollback_floor" to floor.toString(),
            "config_digest" to digest,
        )
        val candidate = BifrostConfigStore.Cached(verified.core, verified.content, verified.version, digest)
        try {
            commitVerifiedPackageThroughCoordinator(verified, metadata, "BF-CONFIG-LIFECYCLE", store, "TEST-ONLY-lifecycle-session")
            check(store.isCommitted(candidate)) { "BF-CONFIG-LKG" }
            val read = store.snapshot().cache ?: throw IllegalStateException("BF-CONFIG-CACHE-MISSING")
            check(read.version == verified.version && read.digest == digest && read.content == verified.content && read.commitState == BifrostCacheCommitState.STABLE) { "BF-CONFIG-LKG" }
            return LifecyclePackageResult(read.version, read.digest, read.content, read.commitState, store.isReadable())
        } catch (error: IllegalStateException) {
            if (error.message?.startsWith("BF-") == true) throw error
            throw IllegalStateException("BF-CONFIG-LIFECYCLE")
        }
    }

    internal data class LifecyclePackageResult(val version: Long, val digest: String, val content: String, val commitState: String, val lkgPreserved: Boolean)

    private fun verifyPackageWithPrivateKey(envelope: JSONObject?, expectedVersion: Long, overridePrivateKey: ByteArray?, trustedConfigPublicKey: ByteArray?, trustState: ConfigKeyTrust.VerifiedState?): VerifiedPackage {
        val names = BifrostPackageShapeValidator.validate(envelope, expectedVersion)
        val packageObject = envelope ?: throw IllegalStateException("BF-CONFIG-PACKAGE")
        val version = strictLongField(packageObject, "config_version", "BF-CONFIG-PACKAGE")
        check(version == expectedVersion && strictLongField(packageObject, "anti_rollback", "BF-CONFIG-ROLLBACK") == version) { "BF-CONFIG-ROLLBACK" }
        check(strictStringField(packageObject, "alg", "BF-CONFIG-ALG") == "X25519-HKDF-SHA256-AES-256-GCM") { "BF-CONFIG-ALG" }
        val signingKeyId = strictStringField(packageObject, "key_id", "BF-CONFIG-KEY-ID")
        check(signingKeyId.matches(Regex("^[A-Za-z0-9._-]{1,64}$"))) { "BF-CONFIG-KEY-ID" }
        val contentDigest = strictStringField(packageObject, "content_digest", "BF-CONFIG-DIGEST")
        check(contentDigest.matches(Regex("^[0-9a-f]{64}$"))) { "BF-CONFIG-DIGEST" }
        var signature: ByteArray? = null
        var signedBytes: ByteArray? = null
        var privateKey: ByteArray? = null
        var ephemeral: ByteArray? = null
        var shared: ByteArray? = null
        var salt: ByteArray? = null
        var derivedKey: ByteArray? = null
        var iv: ByteArray? = null
        var ciphertext: ByteArray? = null
        var tag: ByteArray? = null
        var sealed: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            signature = decodeExact(strictStringField(packageObject, "signature", "BF-CONFIG-SIGNATURE"), 64, "BF-CONFIG-SIGNATURE")
            val unsigned = JSONObject()
            names.filter { it != "signature" }.sorted().forEach { unsigned.put(it, packageObject.get(it)) }
            signedBytes = canonical(unsigned).toByteArray(StandardCharsets.UTF_8)
            val trustedKey = when {
                trustedConfigPublicKey != null -> trustedConfigPublicKey.copyOf()
                trustState != null -> ConfigKeyTrust.rawEd25519PublicKey(trustState.select(signingKeyId, version).publicKeyPem)
                else -> {
                    check(!ReleaseContract.TRUST_ROOT_PROVISIONED && signingKeyId == "config-signing-v1") { "BF-CONFIG-KEY-STATE" }
                    rawTrustedConfigKey()
                }
            }
            try {
                Ed25519Verify(trustedKey).verify(signature, signedBytes)
            } finally {
                trustedKey.fill(0)
            }
            ephemeral = DeviceKeys.decodeX25519PublicRaw(strictStringField(packageObject, "ephemeral_public_key", "BF-CONFIG-ENVELOPE"))
            salt = decodeExact(strictStringField(packageObject, "salt", "BF-CONFIG-ENVELOPE"), 16, "BF-CONFIG-ENVELOPE")
            iv = decodeExact(strictStringField(packageObject, "iv", "BF-CONFIG-ENVELOPE"), 12, "BF-CONFIG-ENVELOPE")
            tag = decodeExact(strictStringField(packageObject, "tag", "BF-CONFIG-ENVELOPE"), 16, "BF-CONFIG-ENVELOPE")
            ciphertext = decodeBounded(strictStringField(packageObject, "ciphertext", "BF-CONFIG-ENVELOPE"), MAX_CIPHERTEXT_BYTES, "BF-CONFIG-ENVELOPE")
            shared = if (overridePrivateKey != null) {
                privateKey = overridePrivateKey.copyOf()
                X25519.computeSharedSecret(privateKey, ephemeral)
            } else {
                DeviceKeys.deriveEncryptionSharedSecret(context, ephemeral)
            }
            val info = "bifrost-config-v1".toByteArray(StandardCharsets.UTF_8)
            try {
                derivedKey = hkdfSha256(shared, salt, info, 32)
            } finally {
                info.fill(0)
            }
            sealed = ciphertext + tag
            plaintext = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(derivedKey, "AES"), GCMParameterSpec(128, iv))
                doFinal(sealed)
            }
            check(plaintext.size <= MAX_PLAINTEXT_BYTES) { "BF-CONFIG-SIZE" }
            val configText = strictUtf8(plaintext)
            StrictJsonValidator(configText, "BF-CONFIG-SCHEMA").validate()
            val config = JSONObject(configText)
            validateConfig(config, version)
            check(sha256(canonical(config)) == contentDigest) { "BF-CONFIG-DIGEST" }
            val core = config.optJSONObject("core_policy")?.optString("default", "sing-box") ?: "sing-box"
            check(core == "sing-box" || core == "auto" || core == "xray") { "BF-CORE-UNSUPPORTED-ANDROID" }
            val digest = sha256(canonical(packageObject))
            return VerifiedPackage(version, core, configText, digest)
        } catch (error: IllegalStateException) {
            throw error
        } catch (_: Throwable) {
            throw IllegalStateException("BF-CONFIG-PACKAGE")
        } finally {
            listOf(signature, signedBytes, privateKey, ephemeral, shared, salt, derivedKey, iv, ciphertext, tag, sealed, plaintext)
                .forEach { it?.fill(0) }
        }
    }

    internal fun decryptRecoveryDeliveryForTest(envelope: JSONObject, trustState: ConfigKeyTrust.VerifiedState, privateKey: ByteArray): String {
        check(lifecycleOnly) { "BF-TEST-SCOPE" }
        return decryptRecoveryDelivery(envelope, trustState, privateKey)
    }

    private fun decryptRecoveryDelivery(envelope: JSONObject?, trustState: ConfigKeyTrust.VerifiedState?, overridePrivateKey: ByteArray? = null): String {
        check(envelope != null) { "BF-RECOVERY-DELIVERY" }
        val allowed = setOf("version", "alg", "key_id", "signing_key_id", "purpose", "aad", "config_version", "expires_at", "ephemeral_public_key", "salt", "iv", "tag", "ciphertext", "signature")
        check(envelope.keys().asSequence().toSet() == allowed) { "BF-RECOVERY-DELIVERY" }
        check(envelope.getInt("version") == 2 && envelope.getString("alg") == "A256GCM" && envelope.getString("key_id") == "recovery-delivery-v1" && envelope.getString("purpose") == "recovery-delivery") { "BF-RECOVERY-DELIVERY" }
        val expires = envelope.getLong("expires_at")
        val configVersion = envelope.getLong("config_version")
        val signingKeyId = envelope.getString("signing_key_id")
        check(expires > System.currentTimeMillis() && configVersion > 0 && signingKeyId.matches(Regex("^[A-Za-z0-9._-]{1,64}$"))) { "BF-RECOVERY-DELIVERY" }
        val aad = envelope.getString("aad")
        check(aad == "bifrost|recovery-delivery|$configVersion|$expires") { "BF-RECOVERY-DELIVERY" }
        var signature: ByteArray? = null
        var signed: ByteArray? = null
        var ephemeral: ByteArray? = null
        var shared: ByteArray? = null
        var salt: ByteArray? = null
        var iv: ByteArray? = null
        var tag: ByteArray? = null
        var ciphertext: ByteArray? = null
        var key: ByteArray? = null
        var sealed: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            signature = decodeExact(envelope.getString("signature"), 64, "BF-RECOVERY-DELIVERY")
            val unsigned = JSONObject()
            allowed.filter { it != "signature" }.sorted().forEach { unsigned.put(it, envelope.get(it)) }
            signed = canonical(unsigned).toByteArray(StandardCharsets.UTF_8)
            val trustedKey = if (trustState != null) {
                ConfigKeyTrust.rawEd25519PublicKey(trustState.select(signingKeyId, configVersion).publicKeyPem)
            } else {
                check(!ReleaseContract.TRUST_ROOT_PROVISIONED && signingKeyId == "config-signing-v1") { "BF-CONFIG-KEY-STATE" }
                rawTrustedConfigKey()
            }
            try { Ed25519Verify(trustedKey).verify(signature, signed) } finally { trustedKey.fill(0) }
            ephemeral = DeviceKeys.decodeX25519PublicRaw(envelope.getString("ephemeral_public_key"))
            shared = if (overridePrivateKey != null) X25519.computeSharedSecret(overridePrivateKey, ephemeral)
                else DeviceKeys.deriveEncryptionSharedSecret(context, ephemeral)
            salt = decodeExact(envelope.getString("salt"), 16, "BF-RECOVERY-DELIVERY")
            iv = decodeExact(envelope.getString("iv"), 12, "BF-RECOVERY-DELIVERY")
            tag = decodeExact(envelope.getString("tag"), 16, "BF-RECOVERY-DELIVERY")
            ciphertext = decodeBounded(envelope.getString("ciphertext"), MAX_CIPHERTEXT_BYTES, "BF-RECOVERY-DELIVERY")
            val info = "bifrost-recovery-delivery-v1".toByteArray(StandardCharsets.UTF_8)
            try { key = hkdfSha256(shared, salt, info, 32) } finally { info.fill(0) }
            sealed = ciphertext + tag
            plaintext = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
                val authenticatedData = aad.toByteArray(StandardCharsets.UTF_8)
                try { updateAAD(authenticatedData) } finally { authenticatedData.fill(0) }
                doFinal(sealed)
            }
            val text = strictUtf8(plaintext)
            val payload = parseObject(text, "BF-RECOVERY-DELIVERY")
            check(payload.keys().asSequence().toSet() == setOf("delivery_type", "delivery_version", "expires_at", "recovery_code")) { "BF-RECOVERY-DELIVERY" }
            check(payload.getString("delivery_type") == "recovery-code" && payload.getInt("delivery_version") == 1 && payload.getLong("expires_at") == expires && payload.getLong("expires_at") > System.currentTimeMillis()) { "BF-RECOVERY-DELIVERY" }
            return boundedString(payload.getString("recovery_code"), 512)
        } catch (error: IllegalStateException) { throw error } catch (_: Throwable) { throw IllegalStateException("BF-RECOVERY-DELIVERY") }
        finally { listOf(signature, signed, ephemeral, shared, salt, iv, tag, ciphertext, key, sealed, plaintext).forEach { it?.fill(0) } }
    }

    private fun validateConfig(config: JSONObject, version: Long) =
        BifrostConfigGraphValidator.validate(config, version)

    private fun establishSession(base: String, persist: Boolean): String = synchronized(configRefreshLock) {
        DeviceKeys.ensure(context)
        val id = DeviceKeys.deviceId(context)
        val challengeResponse = request(base + "/v1/device/challenge", "POST", JSONObject().put("device_id", id).toString(), "", bootstrapOrigin = base)
        val rejection = challengeResponse.body.takeIf { it.isNotBlank() && challengeResponse.status !in 200..299 }
            ?.let { parseResponse(challengeResponse, "BF-SESSION-CHALLENGE").optJSONObject("error")?.optString("code") }
        if (BifrostDeviceRevokedException.confirmed(challengeResponse.status, rejection)) throw BifrostDeviceRevokedException()
        if (challengeResponse.status !in 200..299) throw BifrostReachableStatusException(challengeResponse.status)
        val challenge = boundedString(strictStringField(parseResponse(challengeResponse, "BF-SESSION-CHALLENGE"), "challenge", "BF-SESSION-CHALLENGE"), 1024)
        val timestamp = System.currentTimeMillis()
        val nonce = randomToken(18)
        val requestDigest = sha256(canonical(JSONObject().put("method", "GET").put("path", "/v1/config/manifest").put("body", "")))
        val signedMessage = "$challenge|$timestamp|$nonce|$requestDigest"
        val body = JSONObject()
            .put("device_id", id).put("challenge", challenge).put("timestamp", timestamp).put("nonce", nonce)
            .put("request_digest", requestDigest).put("signature", DeviceKeys.sign(context, signedMessage))
        val sessionResponse = request(base + "/v1/device/session", "POST", body.toString(), "", bootstrapOrigin = base)
        if (sessionResponse.status !in 200..299) throw BifrostReachableStatusException(sessionResponse.status)
        val session = parseResponse(sessionResponse, "BF-SESSION-RESPONSE")
        val token = boundedString(strictStringField(session, "session_token", "BF-SESSION-RESPONSE"), 4096)
        check(token.isNotBlank()) { "BF-SESSION-RESPONSE" }
        if (persist) {
            val publicId = boundedString(strictStringField(session, "public_id", "BF-SESSION-RESPONSE"), 256)
            val priorId = BifrostSecureStore.get(context, "public_id", "")
            BifrostAccountSnapshot.requireSessionIdentity(priorId, publicId)
            BifrostSecureStore.putBatch(context, mapOf("session_token" to token, "public_id" to publicId,
                "control_base_url" to base, "enrollment_pending_origin" to null))
        }
        return token
    }

    private fun authorizedRequest(endpoint: String, method: String, body: String?, idempotencyKey: String? = null): Response =
        request(endpoint, method, body, if (lifecycleOnly) lifecycleSessionToken ?: "TEST-ONLY-lifecycle-session" else BifrostSecureStore.get(context, "session_token", ""), senderConstrained = true, idempotencyKey = idempotencyKey)

    private fun request(
        endpoint: String,
        method: String,
        body: String?,
        token: String,
        senderConstrained: Boolean = false,
        idempotencyKey: String? = null,
        bootstrapOrigin: String? = null,
    ): Response {
        // Only a read that failed before an HTTP response can be replayed.
        // Each attempt constructs fresh sender proof; auth and signed-data
        // rejections never enter this retry path.
        try {
            return requestOnce(endpoint, method, body, token, senderConstrained, idempotencyKey, bootstrapOrigin)
        } catch (error: java.io.IOException) {
            if (method != "GET" || body != null || Thread.currentThread().isInterrupted ||
                error is javax.net.ssl.SSLException || error is java.net.ProtocolException) throw error
            return requestOnce(endpoint, method, body, token, senderConstrained, idempotencyKey, bootstrapOrigin, networkAttempt = 1)
        }
    }

    private fun requestOnce(
        endpoint: String,
        method: String,
        body: String?,
        token: String,
        senderConstrained: Boolean = false,
        idempotencyKey: String? = null,
        bootstrapOrigin: String? = null,
        networkAttempt: Int = 0,
    ): Response {
        requireSecureUrl(endpoint, bootstrapOrigin)
        lifecycleForcedStatus?.let { forced ->
            val path = try { URI(endpoint).rawPath ?: "/" } catch (_: Throwable) { "/" }
            return Response(forced, "", path, method)
        }
        val deadline = System.nanoTime() + 30_000_000_000L
        // URL/proof construction is deliberately outside the transport
        // catches.  Keystore/signature, TLS policy and protocol failures must
        // never be relabelled as an offline network loss.
        val connection = (lifecycleConnectionFactory?.open(URL(endpoint))
            ?: BifrostUnderlyingNetwork.openControlConnection(context, URL(endpoint), networkAttempt)).apply {
            instanceFollowRedirects = false
            requestMethod = method
            connectTimeout = 10_000
            readTimeout = 20_000
            useCaches = false
            setRequestProperty("Accept", "application/json")
            setRequestProperty("X-Bifrost-Client-Version", BuildConfig.VERSION_NAME)
            if (method == "POST" && URI(endpoint).rawPath == "/v1/device/session")
                setRequestProperty("X-Bifrost-Session-Identity", "public-id-v1")
            if (token.isNotBlank()) setRequestProperty("Authorization", "Bearer $token")
            if (!idempotencyKey.isNullOrBlank()) setRequestProperty("X-Bifrost-Idempotency-Key", idempotencyKey)
            if (senderConstrained && token.isNotBlank() && !lifecycleOnly) {
                val uri = URI(endpoint)
                val pathAndQuery = (uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
                val bodyDigest = if (body == null) sha256("") else sha256(body)
                val timestamp = System.currentTimeMillis().toString()
                val nonce = randomToken(18)
                val operation = randomToken(12)
                val proofVersion = if (!idempotencyKey.isNullOrBlank()) "2" else "1"
                val message = if (proofVersion == "2") {
                    "BIFROST-PROOF-v2|${sha256(token)}|${method.uppercase(Locale.US)}|$pathAndQuery|$bodyDigest|$timestamp|$nonce|$operation|$idempotencyKey"
                } else {
                    "BIFROST-PROOF-v1|${sha256(token)}|${method.uppercase(Locale.US)}|$pathAndQuery|$bodyDigest|$timestamp|$nonce|$operation"
                }
                setRequestProperty("X-Bifrost-Proof-Version", proofVersion)
                setRequestProperty("X-Bifrost-Proof-Timestamp", timestamp)
                setRequestProperty("X-Bifrost-Proof-Nonce", nonce)
                setRequestProperty("X-Bifrost-Proof-Operation", operation)
                setRequestProperty("X-Bifrost-Proof-Digest", bodyDigest)
                setRequestProperty("X-Bifrost-Proof-Signature", DeviceKeys.sign(context, message))
            }
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
        }
        var bodyBytes: ByteArray? = null
        return try {
            ensureTransportDeadline(deadline)
            bodyBytes = body?.toByteArray(StandardCharsets.UTF_8)
            check(bodyBytes == null || bodyBytes!!.size <= MAX_REQUEST_BYTES) { "BF-CONTROL-REQUEST-SIZE" }
            if (bodyBytes != null) connection.outputStream.use { it.write(bodyBytes!!) }
            ensureTransportDeadline(deadline)
            val status = connection.responseCode
            BifrostHttpResponsePolicy.rejectRedirect(status)
            // A disconnected CDN tunnel returns HTML (Cloudflare 530/1033).
            // Preserve the outage status before JSON parsing; enrollment stays
            // pending with its existing idempotency key until an actual reply.
            if (BifrostAvailabilityClassifier.canUseOfflineStatus(status)) statusFailure(status)
            val responsePath = URI(endpoint).rawPath ?: "/"
            if (!BifrostHttpResponsePolicy.isSuccess(status)) {
                val errorStream = try {
                    connection.errorStream
                } catch (error: Throwable) {
                    throw statusFailure(status, error)
                }
                if (errorStream == null) return Response(status, "", responsePath, method)
                val errorBytes = try {
                    readLimited(errorStream, MAX_RESPONSE_BYTES, deadline)
                } catch (error: Throwable) {
                    throw statusFailure(status, error)
                }
                val errorBody = try { strictUtf8(errorBytes) } finally { errorBytes.fill(0) }
                if (errorBody.isNotBlank()) {
                    val parsedError = parseObject(errorBody, "BF-CONTROL-ERROR")
                    BifrostProtocolContract.validateResponse(responsePath, parsedError, method, status)
                }
                return Response(status, errorBody, responsePath, method)
            }
            val contentType = connection.getHeaderField("Content-Type")?.trim()?.lowercase(Locale.US) ?: throw IllegalStateException("BF-CONTROL-CONTENT-TYPE")
            check(contentType.matches(Regex("application/json(?:;\\s*charset=utf-8)?"))) { "BF-CONTROL-CONTENT-TYPE" }
            ensureTransportDeadline(deadline)
            val declaredLength = connection.getHeaderField("Content-Length")?.toLongOrNull()
            check(declaredLength == null || declaredLength in 0..MAX_RESPONSE_BYTES.toLong()) { "BF-CONTROL-RESPONSE-SIZE" }
            val bytes = try {
                readLimited(connection.inputStream, MAX_RESPONSE_BYTES, deadline)
            } catch (error: Throwable) {
                throw statusFailure(status, error)
            }
            val bodyText = try { strictUtf8(bytes) } finally { bytes.fill(0) }
            Response(status, bodyText, responsePath, method)
        } catch (error: UnknownHostException) { mapBifrostTransportFailure(error) }
        catch (error: NoRouteToHostException) { mapBifrostTransportFailure(error) }
        catch (error: ConnectException) { mapBifrostTransportFailure(error) }
        catch (error: SocketTimeoutException) { mapBifrostTransportFailure(error) }
        finally {
            bodyBytes?.fill(0)
            connection.disconnect()
        }
    }

    private fun ensureTransportDeadline(deadlineNanos: Long) {
        if (System.nanoTime() > deadlineNanos)
            throw BifrostTransportUnavailableException(BifrostTransportReason.DEADLINE)
    }

    private fun statusFailure(status: Int, cause: Throwable? = null): Nothing =
        if (BifrostAvailabilityClassifier.canUseOfflineStatus(status)) throw BifrostRetryableStatusException(status, cause)
        else throw BifrostReachableStatusException(status, cause)

    private fun cachedFailure(status: Int, message: String): Nothing = statusFailure(status)

    private fun normalizeBase(value: String): String {
        val raw = value.trim()
        require(raw.isNotBlank() && raw.length <= 512) { "BF-CONTROL-URL" }
        val uri = try { URI(raw) } catch (_: Throwable) { throw IllegalArgumentException("BF-CONTROL-URL") }
        check(uri.userInfo == null && uri.query == null && uri.fragment == null && (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/")) { "BF-CONTROL-URL" }
        val scheme = uri.scheme?.lowercase(Locale.US) ?: throw IllegalArgumentException("BF-CONTROL-URL")
        val host = uri.host ?: throw IllegalArgumentException("BF-CONTROL-URL")
        check(host.isNotEmpty() && host.all { it.code in 0x21..0x7e && it != '/' && it != ':' }) { "BF-CONTROL-URL" }
        val loopback = host == "127.0.0.1" || host.equals("localhost", true) || host == "::1"
        val port = uri.port
        if (scheme == "https") check(port == -1 || port == 443) { "BF-CONTROL-URL" }
        else check((lifecycleOnly || BuildConfig.DEBUG && BuildConfig.BIFROST_TEST_VARIANT) &&
            loopback && scheme == "http" && port in 1..65535) { "BF-CONTROL-HTTPS" }
        return "$scheme://$host" + if (port > 0 && !(scheme == "https" && port == 443)) ":$port" else ""
    }

    private fun requireSecureUrl(value: String, bootstrapOrigin: String? = null) {
        val parsed = try { URI(value) } catch (_: Throwable) { throw IllegalStateException("BF-CONTROL-ORIGIN") }
        val authority = parsed.rawAuthority ?: throw IllegalStateException("BF-CONTROL-ORIGIN")
        check(parsed.userInfo == null && parsed.query == null && parsed.fragment == null && parsed.rawPath?.startsWith("/") == true) { "BF-CONTROL-ORIGIN" }
        val origin = normalizeBase("${parsed.scheme}://$authority")
        val configured = bootstrapOrigin ?: if (lifecycleOnly) lifecycleBaseUrl.orEmpty() else BifrostSecureStore.get(context, "control_base_url", "")
        if (configured.isNotBlank()) check(origin == normalizeBase(configured)) { "BF-CONTROL-ORIGIN" }
    }

    internal fun requireBootstrapOriginForTest(endpoint: String, bootstrapOrigin: String) =
        requireSecureUrl(endpoint, bootstrapOrigin)

    private fun readLimited(input: java.io.InputStream, limit: Int, deadlineNanos: Long = System.nanoTime() + 30_000_000_000L): ByteArray {
        require(limit > 0) { "BF-CONTROL-RESPONSE-SIZE" }
        var result: ByteArray? = ByteArray(limit)
        val buffer = ByteArray(minOf(16 * 1024, limit))
        var count = 0
        BufferedInputStream(input).use { source ->
            try {
                while (true) {
                    ensureTransportDeadline(deadlineNanos)
                    val read = source.read(buffer)
                    if (read < 0) break
                    if (read > limit - count) throw IllegalStateException("BF-CONTROL-RESPONSE-SIZE")
                    buffer.copyInto(result!!, count, 0, read)
                    count += read
                }
                return result!!.copyOf(count).also { result!!.fill(0) }
            } finally {
                buffer.fill(0)
                result?.fill(0)
            }
        }
        result?.fill(0)
        throw IllegalStateException("BF-CONTROL-RESPONSE")
    }

    private fun parseResponse(response: Response, code: String): JSONObject {
        val parsed = parseObject(response.body, code)
        return try { BifrostProtocolContract.validateResponse(response.path, parsed, response.method, response.status) } catch (_: Throwable) { throw IllegalStateException(code) }
    }

    private fun parseObject(body: String, code: String): JSONObject {
        check(body.isNotEmpty() && body.length <= MAX_RESPONSE_BYTES) { code }
        return try {
            StrictJsonValidator(body, code, allowPackageCiphertext = true).validate()
            JSONObject(body)
        } catch (_: Throwable) { throw IllegalStateException(code) }
    }

    private fun strictUtf8(value: ByteArray): String = try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(value)).toString()
    } catch (_: Throwable) { throw IllegalStateException("BF-CONTROL-UTF8") }

    private fun boundedString(value: String, max: Int): String {
        check(value.isNotBlank() && value.length <= max && value.none(Char::isISOControl)) { "BF-CONTROL-FORMAT" }
        return value
    }

    private fun strictStringField(value: JSONObject, key: String, code: String): String {
        val field = value.opt(key) as? String ?: throw IllegalStateException(code)
        check(field.isNotEmpty() && field.length <= MAX_RESPONSE_BYTES && field.none(Char::isISOControl)) { code }
        return field
    }

    private fun strictLongField(value: JSONObject, key: String, code: String): Long {
        val field = value.opt(key) as? Number ?: throw IllegalStateException(code)
        val text = field.toString()
        check(text.matches(Regex("[0-9]+"))) { code }
        return text.toLongOrNull() ?: throw IllegalStateException(code)
    }

    private fun decodeBounded(value: String, max: Int, code: String): ByteArray {
        val decoded = decode(value)
        if (decoded.isEmpty() || decoded.size > max) {
            decoded.fill(0)
            throw IllegalStateException(code)
        }
        return decoded
    }

    private fun decodeExact(value: String, expected: Int, code: String): ByteArray {
        val decoded = decode(value)
        if (decoded.size != expected) {
            decoded.fill(0)
            throw IllegalStateException(code)
        }
        return decoded
    }

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(32 * 255)) { "BF-CONFIG-CRYPTO" }
        var prk: ByteArray? = null
        var previous = ByteArray(0)
        val result = ByteArray(length)
        var offset = 0
        var block: ByteArray? = null
        try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            prk = mac.doFinal(ikm)
            var counter = 1
            while (offset < length) {
                val prkBytes = prk ?: throw IllegalStateException("BF-CONFIG-CRYPTO")
                mac.init(SecretKeySpec(prkBytes, "HmacSHA256"))
                mac.update(previous)
                mac.update(info)
                mac.update(counter.toByte())
                previous.fill(0)
                block = mac.doFinal()
                val copy = minOf(block!!.size, length - offset)
                block!!.copyInto(result, offset, 0, copy)
                offset += copy
                previous = block!!
                block = null
                counter += 1
            }
            return result
        } finally {
            prk?.fill(0)
            previous.fill(0)
            block?.fill(0)
        }
    }

    private fun rawTrustedConfigKey(): ByteArray {
        val pem = TRUSTED_CONFIG_PUBLIC_PEM.replace(Regex("-----[^-]+-----"), "").replace(Regex("\\s"), "")
        val der = try { Base64.getMimeDecoder().decode(pem) } catch (_: Throwable) { throw IllegalStateException("BF-CONFIG-TRUST-ROOT") }
        try {
            val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
            check(der.size == 44 && der.copyOfRange(0, 12).contentEquals(prefix)) { "BF-CONFIG-TRUST-ROOT" }
            return der.copyOfRange(12, 44)
        } finally { der.fill(0) }
    }

    private fun decode(value: String): ByteArray {
        if (value.isEmpty() || value.length > MAX_CIPHERTEXT_BYTES * 2 + 64 || !value.matches(Regex("[A-Za-z0-9_-]+"))) throw IllegalStateException("BF-CONFIG-ENVELOPE")
        val decoded = try { Base64.getUrlDecoder().decode(value) } catch (_: Throwable) { throw IllegalStateException("BF-CONFIG-ENVELOPE") }
        val canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded)
        if (canonical != value) { decoded.fill(0); throw IllegalStateException("BF-CONFIG-ENVELOPE") }
        return decoded
    }

    private fun randomToken(bytes: Int): String {
        val value = ByteArray(bytes).also(SecureRandom()::nextBytes)
        return try { Base64.getUrlEncoder().withoutPadding().encodeToString(value) } finally { value.fill(0) }
    }

    private fun sha256(value: String): String {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        return try { MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(Locale.US, it) } } finally { bytes.fill(0) }
    }

    private fun canonical(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(",", "{", "}") { key -> BifrostJsonString.quote(key) + ":" + canonical(value.get(key)) }
        is JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { canonical(value.get(it)) }
        is String -> BifrostJsonString.quote(value)
        is Boolean, is Number -> value.toString()
        else -> BifrostJsonString.quote(value.toString())
    }

    companion object {
        private val configRefreshLock = Any()
        private const val MAX_REQUEST_BYTES = 256 * 1024
        private const val MAX_RESPONSE_BYTES = 1 * 1024 * 1024
        internal const val MAX_CONFIG_PACKAGE_BYTES = 512 * 1024
        private const val MAX_CIPHERTEXT_BYTES = MAX_CONFIG_PACKAGE_BYTES
        private const val MAX_PLAINTEXT_BYTES = MAX_CONFIG_PACKAGE_BYTES
        private const val TRUSTED_CONFIG_PUBLIC_PEM = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAEfImTB3NTAc2b44XLcA0a67Dj3+Ohh0js+AhJkizsBo=
-----END PUBLIC KEY-----
"""
    }
}

internal data class BifrostCommitSnapshot<C, M>(val cache: C?, val metadata: M)

internal interface BifrostCommitStore<C, M> {
    fun snapshot(): BifrostCommitSnapshot<C, M>
    fun markPending(): Boolean
    fun writeCache(value: C): Boolean
    fun writeMetadata(value: M): Boolean
    fun finalizeCache(value: C): Boolean
    fun markStable(): Boolean
    fun quarantine(): Boolean
    fun clearCache(): Boolean
    fun restoreCache(value: C?): Boolean
    fun restoreMetadata(value: M): Boolean
    fun isCommitted(candidate: C): Boolean
    fun isReadable(): Boolean
}

/**
 * Production commit ordering: a cache may be written first, but it is only
 * usable when its binding metadata is committed.  Rollback clears the cache
 * before restoring metadata and only then restores an old cache.  If any
 * recovery step fails the cache remains absent/unusable and the operation
 * fails closed.
 */
internal object BifrostCommitCoordinator {
    fun <C, M> commit(store: BifrostCommitStore<C, M>, candidate: C, metadata: M, code: String) {
        val previous = store.snapshot()
        var transactionStarted = false
        var stableAttempted = false
        try {
            transactionStarted = true
            if (!store.markPending()) {
                // If the underlying commit mutated despite returning false,
                // this is still a failed transaction.  Quarantine is the
                // only safe response before returning the stable error.
                throw IllegalStateException(code)
            }
            check(store.writeCache(candidate)) { code }
            check(store.writeMetadata(metadata)) { code }
            check(store.finalizeCache(candidate)) { code }
            stableAttempted = true
            val stableWritten = store.markStable()
            if (!stableWritten && store.isCommitted(candidate)) return
            check(stableWritten) { code }
            check(store.isCommitted(candidate)) { code }
        } catch (_: Throwable) {
            // A final commit may have returned false after fully landing.  A
            // fresh production readback is the only promotion path.
            if (transactionStarted && stableAttempted) {
                try {
                    if (store.isCommitted(candidate)) return
                } catch (_: Throwable) { }
            }
            // Quarantine first so residual candidate bytes are unreadable
            // even when a later cleanup/restore operation fails.
            var recovered = try { store.quarantine() } catch (_: Throwable) { false }
            if (recovered) recovered = try { store.clearCache() } catch (_: Throwable) { false }
            if (recovered) recovered = try { store.restoreMetadata(previous.metadata) } catch (_: Throwable) { false }
            if (recovered && previous.cache != null) {
                recovered = try { store.restoreCache(previous.cache) } catch (_: Throwable) { false }
            }
            if (recovered) {
                recovered = try {
                    if (previous.cache == null) !store.isReadable() else store.isCommitted(previous.cache)
                } catch (_: Throwable) { false }
            }
            if (!recovered) {
                // Best effort final quarantine/clear.  The caller still gets
                // a transaction error when storage cannot be repaired.
                try { store.quarantine() } catch (_: Throwable) { }
                try { store.clearCache() } catch (_: Throwable) { }
                throw IllegalStateException("BF-CONFIG-TRANSACTION")
            }
            throw IllegalStateException(code)
        }
    }
}

/**
 * TEST-ONLY storage adapter for the lifecycle harness.  It deliberately uses
 * the production encrypted cache codec/reader and a small atomic metadata
 * binding, while delegating every transition and rollback decision to the
 * same BifrostCommitCoordinator used by the AndroidKeyStore path.
 */
internal class BifrostLifecycleCommitStore(
    private val root: File,
    private val cacheKey: ByteArray,
    private val failAfterCacheWrite: Boolean = false,
) : BifrostCommitStore<BifrostConfigStore.Cached, Map<String, String?>> {
    private val metadataFile = File(root, "config-commit.metadata")
    private var injectedFailureUsed = false
    private val allowedMetadata = setOf("config_version", "rollback_floor", "config_digest", "config_commit_state")

    init {
        require(cacheKey.size == 32) { "BF-TEST-SCOPE" }
        if (!root.exists() && !root.mkdirs()) throw IllegalStateException("BF-TEST-SCOPE")
        if (!root.isDirectory || Files.isSymbolicLink(root.toPath())) throw IllegalStateException("BF-TEST-SCOPE")
    }

    override fun snapshot(): BifrostCommitSnapshot<BifrostConfigStore.Cached, Map<String, String?>> =
        BifrostCommitSnapshot(
            try { BifrostConfigStore.readBoundForTest(root, cacheKey) } catch (_: Throwable) { null },
            readMetadata(),
        )

    override fun markPending(): Boolean = try {
        persistMetadata(readMetadata().toMutableMap().also { it["config_commit_state"] = BifrostCacheCommitState.PENDING })
        true
    } catch (_: Throwable) { false }

    override fun writeCache(value: BifrostConfigStore.Cached): Boolean = try {
        BifrostConfigStore.saveBoundForTest(root, cacheKey, value.core, value.content, value.version, value.digest, BifrostCacheCommitState.PENDING)
        if (failAfterCacheWrite && !injectedFailureUsed) {
            injectedFailureUsed = true
            false
        } else true
    } catch (_: Throwable) { false }

    override fun writeMetadata(value: Map<String, String?>): Boolean = try {
        val merged = readMetadata().toMutableMap()
        value.forEach { (key, item) ->
            require(key in allowedMetadata) { "BF-CONFIG-TRANSACTION" }
            merged[key] = item
        }
        merged["config_commit_state"] = BifrostCacheCommitState.PENDING
        persistMetadata(merged)
        true
    } catch (_: Throwable) { false }

    override fun finalizeCache(value: BifrostConfigStore.Cached): Boolean = try {
        BifrostConfigStore.saveBoundForTest(root, cacheKey, value.core, value.content, value.version, value.digest, BifrostCacheCommitState.STABLE)
        true
    } catch (_: Throwable) { false }

    override fun markStable(): Boolean = try {
        persistMetadata(readMetadata().toMutableMap().also { it["config_commit_state"] = BifrostCacheCommitState.STABLE })
        true
    } catch (_: Throwable) { false }

    override fun quarantine(): Boolean = try {
        persistMetadata(readMetadata().toMutableMap().also { it["config_commit_state"] = BifrostCacheCommitState.QUARANTINE })
        true
    } catch (_: Throwable) { false }

    override fun clearCache(): Boolean = try {
        val directory = File(root, "bifrost-config")
        if (directory.exists()) BifrostConfigStore.clearDirectory(directory)
        true
    } catch (_: Throwable) { false }

    override fun restoreCache(value: BifrostConfigStore.Cached?): Boolean = try {
        if (value == null) clearCache()
        else BifrostConfigStore.saveBoundForTest(root, cacheKey, value.core, value.content, value.version, value.digest, BifrostCacheCommitState.STABLE)
        true
    } catch (_: Throwable) { false }

    override fun restoreMetadata(value: Map<String, String?>): Boolean = try {
        persistMetadata(value)
        true
    } catch (_: Throwable) { false }

    override fun isCommitted(candidate: BifrostConfigStore.Cached): Boolean = try {
        val metadata = readMetadata()
        val version = metadata["config_version"]?.toLongOrNull() ?: return false
        val digest = metadata["config_digest"] ?: return false
        val floor = metadata["rollback_floor"]?.toLongOrNull() ?: return false
        val state = metadata["config_commit_state"] ?: return false
        val current = BifrostConfigStore.loadForTest(root, cacheKey, version, digest, floor, state) ?: return false
        state == BifrostCacheCommitState.STABLE && current.version == candidate.version && current.digest == candidate.digest && current.core == candidate.core && current.content == candidate.content
    } catch (_: Throwable) { false }

    override fun isReadable(): Boolean = try {
        val metadata = readMetadata()
        val version = metadata["config_version"]?.toLongOrNull() ?: return false
        val digest = metadata["config_digest"] ?: return false
        val floor = metadata["rollback_floor"]?.toLongOrNull() ?: return false
        val state = metadata["config_commit_state"] ?: return false
        BifrostConfigStore.loadForTest(root, cacheKey, version, digest, floor, state) != null
    } catch (_: Throwable) { false }

    private fun readMetadata(): MutableMap<String, String?> {
        val values = allowedMetadata.associateWith { null as String? }.toMutableMap()
        if (!metadataFile.exists()) return values
        if (Files.isSymbolicLink(metadataFile.toPath())) throw IllegalStateException("BF-CONFIG-TRANSACTION")
        val json = JSONObject(metadataFile.readText(Charsets.UTF_8))
        json.keys().forEach { key -> if (key !in allowedMetadata) throw IllegalStateException("BF-CONFIG-TRANSACTION") }
        json.keys().forEach { key -> values[key] = if (json.isNull(key)) null else json.getString(key) }
        return values
    }

    private fun persistMetadata(values: Map<String, String?>) {
        require(values.keys.all { it in allowedMetadata }) { "BF-CONFIG-TRANSACTION" }
        require(values["config_commit_state"] == null || values["config_commit_state"] in BifrostCacheCommitState.ALL) { "BF-CONFIG-TRANSACTION" }
        if (values.values.all { it == null }) {
            if (metadataFile.exists() && !metadataFile.delete()) throw IllegalStateException("BF-CONFIG-TRANSACTION")
            return
        }
        val json = JSONObject()
        allowedMetadata.sorted().forEach { key -> values[key]?.let { json.put(key, it) } }
        val temp = File(root, ".config-commit.metadata.tmp-${System.nanoTime()}")
        try {
            FileOutputStream(temp, false).use { output ->
                output.write(json.toString().toByteArray(Charsets.UTF_8))
                output.flush(); output.fd.sync()
            }
            if (Files.isSymbolicLink(temp.toPath())) throw IllegalStateException("BF-CONFIG-TRANSACTION")
            try {
                Files.move(temp.toPath(), metadataFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
                if (!temp.renameTo(metadataFile)) throw IllegalStateException("BF-CONFIG-TRANSACTION")
            }
        } finally { if (temp.exists()) temp.delete() }
    }
}

/** A verified package is committed only after the authenticated session exists. */
internal object BifrostSessionCommitGate {
    fun <T> commit(sessionToken: String, code: String, action: () -> T): T {
        check(sessionToken.isNotBlank()) { code }
        return try { action() } catch (error: IllegalStateException) {
            if (error.message == code || error.message == "BF-CONFIG-TRANSACTION") throw error
            throw IllegalStateException(code)
        } catch (_: Throwable) {
            throw IllegalStateException(code)
        }
    }
}

internal interface BifrostLogoutStore {
    fun clearCache(): Boolean
    fun clearAccount(): Boolean
}

/** Local cache is removed first; account/session metadata is never cleared if
 * the cache scrub failed.  Remote HTTP status is independently fail-closed. */
internal object BifrostLogoutCoordinator {
    fun complete(remote: () -> Unit, clear: () -> Unit) {
        try { remote() } catch (_: BifrostDeviceRevokedException) {
            // Repeating logout after a lost successful response is safe.
        }
        clear()
    }

    fun clearLocal(store: BifrostLogoutStore) {
        check(store.clearCache()) { "BF-LOGOUT-LOCAL" }
        check(store.clearAccount()) { "BF-LOGOUT-LOCAL" }
    }

    fun remoteFailure(status: Int) {
        check(status in 200..299) { "BF-LOGOUT-REMOTE" }
    }
}

internal object BifrostHttpResponsePolicy {
    fun isSuccess(status: Int): Boolean = status in 200..299

    fun rejectRedirect(status: Int) {
        if (status in 300..399) throw IllegalStateException("BF-CONTROL-REDIRECT")
    }
}

/** Shape checks run before signature verification/decryption.  They are
 * intentionally independent of the fixed signing root so malformed or
 * ambiguous envelopes cannot reach crypto providers. */
internal object BifrostPackageShapeValidator {
    private const val ERROR = "BF-CONFIG-ENVELOPE"
    private val fields = setOf(
        "alg", "key_id", "config_version", "anti_rollback", "content_digest", "ephemeral_public_key",
        "salt", "iv", "tag", "ciphertext", "signature",
    )
    private val b64 = Regex("[A-Za-z0-9_-]+")

    fun validate(envelope: JSONObject?, expectedVersion: Long): Set<String> {
        val value = envelope ?: fail()
        val names = value.keys().asSequence().toSet()
        check(names == fields)
        check(expectedVersion > 0L)
        val version = integer(value, "config_version")
        val anti = integer(value, "anti_rollback")
        check(version == expectedVersion && anti == version)
        check(string(value, "alg", 64) == "X25519-HKDF-SHA256-AES-256-GCM")
        check(string(value, "key_id", 64).matches(Regex("^[A-Za-z0-9._-]{1,64}$")))
        check(string(value, "content_digest", 64).matches(Regex("^[0-9a-f]{64}$")))
        val signature = encoded(value, "signature", 86..86)
        val ephemeral = encoded(value, "ephemeral_public_key", 59..59)
        check(ephemeral.length == 59)
        check(encoded(value, "salt", 22..22).isNotEmpty())
        check(encoded(value, "iv", 16..16).isNotEmpty())
        check(encoded(value, "tag", 22..22).isNotEmpty())
        val ciphertext = encoded(
            value,
            "ciphertext",
            2..699051,
            maxDecoded = BifrostControlClient.MAX_CONFIG_PACKAGE_BYTES,
        )
        check(signature.isNotEmpty() && ciphertext.isNotEmpty())
        return names
    }

    private fun integer(value: JSONObject, key: String): Long {
        val raw = value.opt(key) as? Number ?: fail()
        val text = raw.toString()
        check(text.matches(Regex("[0-9]+")))
        return text.toLongOrNull() ?: fail()
    }

    private fun string(value: JSONObject, key: String, max: Int): String {
        val raw = value.opt(key) as? String ?: fail()
        check(raw.isNotEmpty() && raw.length <= max && raw.none(Char::isISOControl))
        return raw
    }

    private fun encoded(
        value: JSONObject,
        key: String,
        lengths: IntRange,
        maxDecoded: Int = Int.MAX_VALUE,
    ): String {
        val raw = string(value, key, BifrostConfigStore.MAX_PLAINTEXT_BYTES * 2 + 128)
        check(raw.length in lengths && b64.matches(raw))
        val decoded = try {
            java.util.Base64.getUrlDecoder().decode(raw)
        } catch (_: Throwable) { fail() }
        try {
            check(decoded.size <= maxDecoded)
            val canonical = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(decoded)
            check(canonical == raw)
        } finally { decoded.fill(0) }
        return raw
    }

    private fun fail(): Nothing = throw IllegalStateException(ERROR)
}

/** Monotonic configuration floor shared by enrollment, pairing and refresh. */
internal object BifrostRollback {
    /** The server floor is a minimum, not a candidate version to install. */
    fun acceptManifest(current: Long, serverFloor: Long, verifiedVersion: Long): Long {
        check(current >= 0L && serverFloor > 0L) { "BF-CONFIG-ROLLBACK" }
        return advance(maxOf(current, serverFloor), verifiedVersion)
    }
    fun advance(current: Long, candidate: Long): Long {
        check(current >= 0L && candidate > 0L && candidate >= current) { "BF-CONFIG-ROLLBACK" }
        return candidate
    }
}

internal data class BifrostValidatedManifest(
    val version: Long,
    val rollbackFloor: Long,
    val digest: String,
)

internal object BifrostManifestValidator {
    private const val ERROR = "BF-CONFIG-MANIFEST"
    private val fields = setOf("schema_version", "config_version", "digest", "rollback_floor")

    fun validate(value: JSONObject, storedFloor: Long): BifrostValidatedManifest {
        val names = value.keys().asSequence().toSet()
        check(names.containsAll(fields) && names.all { it in fields || it == "config_key_state" }) { ERROR }
        if (value.has("config_key_state")) {
            check(value.opt("config_key_state") is JSONObject) { ERROR }
        }
        check(value.opt("schema_version") is String && value.getString("schema_version") == "1.0") { ERROR }
        val version = integer(value, "config_version")
        val floor = integer(value, "rollback_floor")
        val digest = value.opt("digest") as? String ?: throw IllegalStateException(ERROR)
        check(digest.matches(Regex("[0-9a-f]{64}"))) { ERROR }
        check(version > 0L && floor > 0L && version >= floor && version >= storedFloor) { ERROR }
        return BifrostValidatedManifest(version, floor, digest)
    }

    private fun integer(value: JSONObject, key: String): Long {
        val raw = value.opt(key) as? Number ?: throw IllegalStateException(ERROR)
        val text = raw.toString()
        check(text.matches(Regex("[0-9]+"))) { ERROR }
        return text.toLongOrNull() ?: throw IllegalStateException(ERROR)
    }
}

/**
 * Runtime configuration graph validator.  This is deliberately stricter than
 * org.json: exact object members, exact primitive types, bounded collections,
 * public-IP candidate literals and cross references are checked before a
 * package can reach either compiler. Optional country SOCKS fields are
 * accepted only with their exact typed schema inside the verified package.
 */
internal object BifrostConfigGraphValidator {
    private const val ERROR = "BF-CONFIG-SCHEMA"
    private val topRequired = setOf("schema_version", "config_version", "anti_rollback", "account", "sources", "countries", "routing", "core_policy")
    private val accountKeys = setOf("public_id", "plan", "expires_at")
    private val sourceRequired = setOf("code", "display_name", "server_name", "candidates", "profiles")
    private val sourceOptional = setOf("configured", "ws_path", "transport")
    private val transportRequired = setOf("type", "network", "tls", "security", "alter_id")
    private val transportOptional = setOf("host", "sni", "alpn", "fingerprint", "header_type")
    private val candidateKeys = setOf("label", "dial_address", "port")
    private val profilesKeys = setOf("direct", "countries")
    private val profileKeys = setOf("profile_id", "uuid")
    private val countryKeys = setOf("code", "name_zh", "tcp", "udp", "status", "front_source_code", "front_source_options")
    private val routingKeys = setOf("ruleset_version", "smart_gate_remote_dns", "kill_switch_default", "dns_policy", "ipv6_policy", "udp_policy")
    private val dnsKeys = setOf("version", "remote", "direct", "smart_gate_remote", "plaintext_fallback", "ipv4", "ipv6", "failure")
    private val coreKeys = setOf("allowed", "default")

    fun validate(config: JSONObject, expectedVersion: Long, now: Instant = Instant.now()) {
        exact(config, topRequired, emptySet())
        check(string(config, "schema_version", 16) == "1.0")
        val version = integer(config, "config_version")
        check(version > 0L && version == expectedVersion)
        check(integer(config, "anti_rollback") == version)

        val account = objectValue(config, "account")
        exact(account, accountKeys, emptySet())
        check(string(account, "public_id", 64).matches(Regex("BF-[A-Z0-9]{4}-[A-Z0-9]{4}")))
        val plan = string(account, "plan", 32)
        check(plan in setOf("permanent", "time_limited"))
        val expires = account.opt("expires_at")
        if (plan == "permanent") {
            check(expires == JSONObject.NULL)
        } else {
            val expiresText = expires as? String ?: fail()
            check(expiresText.length in 20..35 && expiresText.none(Char::isISOControl))
            check(expiresText.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?Z")))
            val expiry = try {
                Instant.parse(expiresText)
            } catch (_: Throwable) { fail() }
            check(expiry.toString() == expiresText)
            check(expiry.isAfter(now))
        }

        val sourceArray = arrayValue(config, "sources")
        check(sourceArray.length() in 1..2)
        val sources = LinkedHashMap<String, JSONObject>()
        val profileIds = HashSet<String>()
        for (index in 0 until sourceArray.length()) {
            val source = sourceArray.get(index) as? JSONObject ?: fail()
            exact(source, sourceRequired, sourceOptional)
            val code = string(source, "code", 2)
            check(code == "A" || code == "B")
            check(sources.put(code, source) == null)
            string(source, "display_name", 128)
            val serverName = string(source, "server_name", 255)
            safeHost(serverName)
            val candidates = arrayValue(source, "candidates")
            val configured = if (source.has("configured")) bool(source, "configured") else candidates.length() > 0 || source.has("transport")
            val wsPath = optionalString(source, "ws_path", 2048)
            if (configured) {
                check(wsPath != null && wsPath.startsWith("/") && !wsPath.startsWith("//") && !wsPath.contains('?') && !wsPath.contains('#') && !wsPath.contains('\\') && wsPath.none { it.isWhitespace() || it.isISOControl() })
                check(candidates.length() in 1..300)
                transport(objectValue(source, "transport"), serverName)
            } else {
                check(candidates.length() == 0)
                check(!source.has("transport") || source.isNull("transport"))
                check(wsPath == null)
            }
            val seenLabels = HashSet<String>()
            for (candidateIndex in 0 until candidates.length()) {
                val candidate = candidates.get(candidateIndex) as? JSONObject ?: fail()
                exact(candidate, candidateKeys, emptySet())
                val label = string(candidate, "label", 32)
                check(label.matches(Regex("${code}-[0-9]{2,6}")) && seenLabels.add(label))
                check(isPublicLiteral(string(candidate, "dial_address", 128)))
                check(integer(candidate, "port") in 1L..65535L)
            }
            val profiles = objectValue(source, "profiles")
            exact(profiles, profilesKeys, emptySet())
            profile(profiles.opt("direct"), required = configured, profileIds = profileIds)
            val countryProfiles = profiles.opt("countries") as? JSONObject ?: fail()
            val profileNames = countryProfiles.keys().asSequence().toList()
            check(profileNames.size <= 256)
            profileNames.forEach { countryCode ->
                check(countryCode.matches(Regex("[A-Z]{2}")))
                profile(countryProfiles.get(countryCode), required = true, profileIds = profileIds)
            }
        }
        check(sources.isNotEmpty())

        val countryArray = arrayValue(config, "countries")
        check(countryArray.length() in 1..256)
        val countries = LinkedHashMap<String, JSONObject>()
        for (index in 0 until countryArray.length()) {
            val country = countryArray.get(index) as? JSONObject ?: fail()
            exact(country, countryKeys, setOf("socks"))
            if (country.has("socks")) {
                val socks = objectValue(country, "socks")
                exact(socks, setOf("scheme", "host", "port", "user", "password"), emptySet())
                check(string(socks, "scheme", 16) in setOf("socks5", "socks5h"))
                safeHost(string(socks, "host", 253))
                check(integer(socks, "port") in 1L..65535L)
                string(socks, "user", 128)
                string(socks, "password", 256)
            }
            val code = string(country, "code", 2)
            check(code.matches(Regex("[A-Z]{2}")) && countries.put(code, country) == null)
            string(country, "name_zh", 128)
            val tcp = bool(country, "tcp")
            val udp = bool(country, "udp")
            check(tcp || udp)
            val status = string(country, "status", 32)
            check(status in setOf("enabled", "maintenance", "fault", "disabled"))
            val front = optionalEnum(country, "front_source_code", setOf("A", "B"))
            val options = arrayValue(country, "front_source_options")
            check(options.length() <= 2)
            val seenOptions = HashSet<String>()
            for (optionIndex in 0 until options.length()) {
                val option = options.get(optionIndex) as? String ?: fail()
                check(option in sources.keys && seenOptions.add(option))
                val optionSource = sources[option] ?: fail()
                val optionConfigured = if (optionSource.has("configured")) bool(optionSource, "configured")
                else arrayValue(optionSource, "candidates").length() > 0 || optionSource.has("transport")
                check(optionConfigured)
                val optionProfiles = objectValue(objectValue(optionSource, "profiles"), "countries")
                check(optionProfiles.has(code))
                profile(optionProfiles.get(code), required = true, profileIds = null)
            }
            if (front != null) check(front in seenOptions)
            if (status == "enabled") check(front != null && options.length() > 0)
            if (front != null) {
                val selected = sources[front] ?: fail()
                val selectedConfigured = if (selected.has("configured")) bool(selected, "configured")
                else arrayValue(selected, "candidates").length() > 0 || selected.has("transport")
                if (status == "enabled") check(selectedConfigured)
                val countryProfiles = objectValue(objectValue(selected, "profiles"), "countries")
                check(countryProfiles.has(code))
            }
        }
        check(countries.isNotEmpty())
        for (source in sources.values) {
            val countryProfiles = objectValue(objectValue(source, "profiles"), "countries")
            countryProfiles.keys().forEach { code -> check(countries.containsKey(code)) }
        }

        val routing = objectValue(config, "routing")
        exact(routing, routingKeys, emptySet())
        string(routing, "ruleset_version", 128)
        check(bool(routing, "smart_gate_remote_dns"))
        check(string(routing, "kill_switch_default", 32) in setOf("normal", "strict"))
        val dns = objectValue(routing, "dns_policy")
        exact(dns, dnsKeys, emptySet())
        check(string(dns, "version", 32) == "dns-policy-v1")
        check(bool(dns, "smart_gate_remote"))
        safeDnsUri(string(dns, "remote", 512))
        safeDnsUri(string(dns, "direct", 512))
        check(!bool(dns, "plaintext_fallback"))
        check(string(dns, "ipv4", 16) in setOf("proxy", "block"))
        check(string(dns, "ipv6", 16) in setOf("proxy", "block"))
        check(string(dns, "failure", 16) == "block")
        check(string(routing, "ipv6_policy", 32) in setOf("proxy_or_block", "direct", "block"))
        check(string(routing, "udp_policy", 32) in setOf("capability", "block", "proxy"))

        val core = objectValue(config, "core_policy")
        exact(core, coreKeys, emptySet())
        val allowed = arrayValue(core, "allowed")
        check(allowed.length() in 1..2)
        val allowedSet = HashSet<String>()
        for (index in 0 until allowed.length()) {
            val value = allowed.get(index) as? String ?: fail()
            check(value in setOf("sing-box", "xray") && allowedSet.add(value))
        }
        val defaultCore = string(core, "default", 32)
        check(defaultCore in setOf("auto", "sing-box", "xray"))
        check(defaultCore == "auto" || defaultCore in allowedSet)
    }

    private fun transport(value: JSONObject, serverName: String) {
        exact(value, transportRequired, transportOptional)
        check(string(value, "type", 32) == "vmess")
        check(string(value, "network", 32) == "ws")
        check(bool(value, "tls"))
        check(string(value, "security", 64).lowercase(Locale.US) in setOf("auto", "aes-128-gcm", "chacha20-poly1305"))
        check(integer(value, "alter_id") == 0L)
        val host = string(value, "host", 255)
        val sni = string(value, "sni", 255)
        safeHost(host)
        safeHost(sni)
        check(serverName.isNotBlank())
        optionalTransportString(value, "alpn", 128)
        optionalTransportString(value, "fingerprint", 64)
        optionalTransportString(value, "header_type", 64)
    }

    // Control preserves empty optional VMess import fields. They mean that
    // the transport uses its default, as on Windows; required host/SNI/path
    // fields still use the nonblank validator above.
    private fun optionalTransportString(parent: JSONObject, key: String, max: Int) {
        if (!parent.has(key) || parent.isNull(key)) return
        val value = parent.opt(key) as? String ?: fail()
        check(value.length <= max && value.none { it.isISOControl() })
        check(value.isEmpty() || value.isNotBlank())
    }

    private fun profile(value: Any?, required: Boolean, profileIds: MutableSet<String>?) {
        if (value == null || value == JSONObject.NULL) {
            check(!required)
            return
        }
        val profile = value as? JSONObject ?: fail()
        exact(profile, profileKeys, emptySet())
        val profileId = string(profile, "profile_id", 128)
        check(profileId.matches(Regex("[A-Za-z0-9_-]{8,128}")))
        if (profileIds != null) check(profileIds.add(profileId))
        val uuid = string(profile, "uuid", 64)
        val parsed = try { java.util.UUID.fromString(uuid) } catch (_: Throwable) { fail() }
        check(uuid == parsed.toString())
    }

    private fun safeHost(value: String) {
        check(value.length in 1..255 && value.matches(Regex("[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")))
        check(!value.contains(".."))
    }

    internal fun isPublicLiteral(value: String): Boolean {
        if (value.length !in 1..128 || value.any { it.isWhitespace() || it.isISOControl() } || value.contains('/')) return false
        val ipv4 = value.split('.')
        if (ipv4.size == 4 && ipv4.all { it.isNotEmpty() && it.length <= 3 && (it == "0" || !it.startsWith("0")) && it.all(Char::isDigit) && it.toIntOrNull() in 0..255 }) {
            val octets = ipv4.map { it.toInt() }
            if (octets[0] == 0 || octets[0] == 10 || octets[0] == 127 || octets[0] >= 224) return false
            if (octets[0] == 169 && octets[1] == 254) return false
            if (octets[0] == 172 && octets[1] in 16..31) return false
            if (octets[0] == 192 && octets[1] == 168) return false
            if (octets[0] == 100 && octets[1] in 64..127) return false
            if (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) return false
            if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) return false
            if (octets[0] == 192 && octets[1] == 88 && octets[2] == 99) return false
            if (octets[0] == 192 && octets[1] == 31 && octets[2] == 196) return false
            if (octets[0] == 192 && octets[1] == 52 && octets[2] == 193) return false
            if (octets[0] == 192 && octets[1] == 175 && octets[2] == 48) return false
            if (octets[0] == 198 && octets[1] == 18 || octets[0] == 198 && octets[1] == 19) return false
            if (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) return false
            if (octets[0] == 203 && octets[1] == 0 && octets[2] == 113) return false
            return true
        }
        if (!value.contains(':') || value.contains('.') || value.any { !(it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':') }) return false
        val words = parseIpv6(value) ?: return false
        val first = words[0]
        // Only the global-unicast 2000::/3 allocation is eligible.  This
        // rejects 100::, 4000:: and every non-global/special allocation before
        // any DNS-capable API is reached.
        if (first !in 0x2000..0x3fff) return false
        if (first == 0x2001 && (words[1] and 0xfe00) == 0) return false // IETF protocol/special 2001::/23
        if (first == 0x2001 && words[1] == 0x0db8) return false // documentation
        if (first == 0x2001 && words[1] == 0x0002) return false // benchmark 2001:2::/48
        if (first == 0x2002) return false // 6to4 protocol assignment
        if (first == 0x3fff && (words[1] and 0xf000) == 0) return false // 3fff::/20 special
        if (words[0] == 0 && words[1] == 0 && words[2] == 0 && words[3] == 0 && words[4] == 0 && words[5] == 0xffff) return false // IPv4-mapped
        return true
    }

    /** Parse an IPv6 literal without InetAddress, which may perform DNS. */
    private fun parseIpv6(value: String): IntArray? {
        if (value.isEmpty() || value.startsWith(":") && !value.startsWith("::") || value.endsWith(":") && !value.endsWith("::")) return null
        val marker = value.indexOf("::")
        if (marker >= 0 && value.indexOf("::", marker + 2) >= 0) return null
        val leftText = if (marker >= 0) value.substring(0, marker) else value
        val rightText = if (marker >= 0) value.substring(marker + 2) else ""
        fun parsePart(text: String): List<Int>? {
            if (text.isEmpty()) return emptyList()
            val parts = text.split(':')
            if (parts.any { it.isEmpty() || it.length > 4 || it.any { ch -> ch.lowercaseChar() !in '0'..'9' && ch.lowercaseChar() !in 'a'..'f' } }) return null
            return parts.map { it.toInt(16) }
        }
        val left = parsePart(leftText) ?: return null
        val right = parsePart(rightText) ?: return null
        if (marker < 0) {
            if (left.size != 8) return null
            return left.toIntArray()
        }
        if (left.size + right.size >= 8) return null
        return (left + List(8 - left.size - right.size) { 0 } + right).toIntArray()
    }

    private fun safeDnsUri(value: String) {
        val uri = try { URI(value) } catch (_: Throwable) { fail() }
        val scheme = uri.scheme?.lowercase(Locale.US)
        check(scheme == "https")
        check(uri.userInfo == null && uri.query == null && uri.fragment == null && uri.host != null)
        check(uri.port == -1 || uri.port == 443)
        val host = uri.host.lowercase(Locale.US).trimEnd('.')
        check(!host.equals("localhost") && !host.endsWith(".localhost") && !host.equals("test") && !host.endsWith(".test"))
        check(!host.matches(Regex("(?:\\d{1,3}\\.){3}\\d{1,3}")) && !host.startsWith("[") && !host.contains(":"))
        check(uri.rawPath?.startsWith("/") == true && uri.rawPath.length <= 256)
    }

    private fun exact(value: JSONObject, required: Set<String>, optional: Set<String>) {
        val names = value.keys().asSequence().toSet()
        check(names.containsAll(required) && names.all { it in required || it in optional })
    }

    private fun objectValue(parent: JSONObject, key: String): JSONObject = parent.opt(key) as? JSONObject ?: fail()
    private fun arrayValue(parent: JSONObject, key: String): JSONArray = parent.opt(key) as? JSONArray ?: fail()
    private fun string(parent: JSONObject, key: String, max: Int): String {
        val value = parent.opt(key) as? String ?: fail()
        check(value.isNotBlank() && value.length <= max && value.none { it.isISOControl() })
        return value
    }
    private fun optionalString(parent: JSONObject, key: String, max: Int): String? {
        if (!parent.has(key) || parent.isNull(key)) return null
        return string(parent, key, max)
    }
    private fun integer(parent: JSONObject, key: String): Long {
        val value = parent.opt(key) as? Number ?: fail()
        val text = value.toString()
        check(text.matches(Regex("-?[0-9]+")))
        return text.toLongOrNull() ?: fail()
    }
    private fun bool(parent: JSONObject, key: String): Boolean = parent.opt(key) as? Boolean ?: fail()
    private fun optionalEnum(parent: JSONObject, key: String, allowed: Set<String>): String? {
        if (!parent.has(key) || parent.isNull(key)) return null
        val value = parent.opt(key) as? String ?: fail()
        check(value in allowed)
        return value
    }
    private fun fail(): Nothing = throw IllegalStateException(ERROR)
}

/** Small strict JSON pre-parser used before org.json.  org.json accepts the
 * last occurrence of duplicate object members; the control protocol rejects
 * that ambiguity and also enforces depth/item/string limits before allocation
 * of the object graph. */
internal class StrictJsonValidator(
    private val input: String,
    private val errorCode: String,
    private val allowPackageCiphertext: Boolean = false,
) {
    private val duplicateErrorCode: String = if (errorCode == "BF-RELEASE-MANIFEST") "BF-RELEASE-DUPLICATE-KEY" else errorCode
    private var index = 0

    fun validate() {
        parseValue(0)
        skipWhitespace()
        if (index != input.length) fail()
    }

    private fun parseValue(level: Int, stringLimit: Int = 16384) {
        if (level > 16) fail()
        skipWhitespace()
        if (index >= input.length) fail()
        when (input[index]) {
            '{' -> parseObject(level + 1)
            '[' -> parseArray(level + 1)
            '"' -> parseString(stringLimit)
            't' -> parseLiteral("true")
            'f' -> parseLiteral("false")
            'n' -> parseLiteral("null")
            '-', in '0'..'9' -> parseNumber()
            else -> fail()
        }
    }

    private fun parseObject(level: Int) {
        index++
        skipWhitespace()
        val names = HashSet<String>()
        if (consume('}')) return
        var count = 0
        while (true) {
            if (++count > 4096) fail()
            skipWhitespace()
            val name = parseString()
            if (!names.add(name)) throw IllegalStateException(duplicateErrorCode)
            skipWhitespace()
            if (!consume(':')) fail()
            // Only the encrypted package payload needs the larger bound.
            // Object names and ordinary response strings retain their limit.
            val stringLimit = if (allowPackageCiphertext && name == "ciphertext")
                ((BifrostControlClient.MAX_CONFIG_PACKAGE_BYTES + 2) / 3) * 4 else 16384
            parseValue(level, stringLimit)
            skipWhitespace()
            if (consume('}')) return
            if (!consume(',')) fail()
        }
    }

    private fun parseArray(level: Int) {
        index++
        skipWhitespace()
        if (consume(']')) return
        var count = 0
        while (true) {
            if (++count > 4096) fail()
            parseValue(level)
            skipWhitespace()
            if (consume(']')) return
            if (!consume(',')) fail()
        }
    }

    private fun parseString(limit: Int = 16384): String {
        if (!consume('"')) fail()
        val value = StringBuilder()
        while (index < input.length) {
            val c = input[index++]
            when {
                c == '"' -> {
                    if (value.length > limit) fail()
                    return value.toString()
                }
                c == '\\' -> {
                    if (index >= input.length) fail()
                    when (val escaped = input[index++]) {
                        '"', '\\', '/' -> value.append(escaped)
                        'b' -> value.append('\b')
                        'f' -> value.append('\u000c')
                        'n' -> value.append('\n')
                        'r' -> value.append('\r')
                        't' -> value.append('\t')
                        'u' -> {
                            if (index + 4 > input.length) fail()
                            val hex = input.substring(index, index + 4)
                            if (!hex.all { it in "0123456789abcdefABCDEF" }) fail()
                            value.append(hex.toInt(16).toChar())
                            index += 4
                        }
                        else -> fail()
                    }
                }
                c.code < 0x20 -> fail()
                else -> value.append(c)
            }
            if (value.length > limit) fail()
        }
        fail()
    }

    private fun parseLiteral(literal: String) {
        if (!input.startsWith(literal, index)) fail()
        index += literal.length
    }

    private fun parseNumber() {
        val start = index
        if (input[index] == '-') index++
        if (index >= input.length) fail()
        if (input[index] == '0') {
            index++
        } else {
            if (input[index] !in '1'..'9') fail()
            while (index < input.length && input[index] in '0'..'9') index++
        }
        if (index < input.length && input[index] == '.') {
            index++
            if (index >= input.length || input[index] !in '0'..'9') fail()
            while (index < input.length && input[index] in '0'..'9') index++
        }
        if (index < input.length && (input[index] == 'e' || input[index] == 'E')) {
            index++
            if (index < input.length && (input[index] == '+' || input[index] == '-')) index++
            if (index >= input.length || input[index] !in '0'..'9') fail()
            while (index < input.length && input[index] in '0'..'9') index++
        }
        if (index == start) fail()
    }

    private fun skipWhitespace() {
        while (index < input.length && input[index] in charArrayOf(' ', '\t', '\r', '\n')) index++
    }

    private fun consume(expected: Char): Boolean {
        if (index < input.length && input[index] == expected) {
            index++
            return true
        }
        return false
    }

    private fun fail(): Nothing = throw IllegalStateException(errorCode)
}
