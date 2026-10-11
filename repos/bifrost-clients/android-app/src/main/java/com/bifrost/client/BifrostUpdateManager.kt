package com.bifrost.client

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Base64
import com.google.crypto.tink.subtle.Ed25519Verify
import com.bifrost.client.ui.model.BifrostUiText
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import java.util.concurrent.TimeUnit

internal fun bifrostSafeReleasePath(value: String): String {
    check(value.isNotBlank() && value.length <= 240 && !value.startsWith('/') && !value.contains('\\') && !value.contains('\u0000') && !value.contains(':')) { "BF-RELEASE-PATH" }
    val parts = value.split('/')
    check(value == java.text.Normalizer.normalize(value, java.text.Normalizer.Form.NFC)) { "BF-RELEASE-PATH" }
    check(parts.none { it.isBlank() || it == "." || it == ".." || it.endsWith(' ') || it.endsWith('.') || it.any(Char::isISOControl) || it.substringBefore('.').uppercase(Locale.US) in setOf("CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9") }) { "BF-RELEASE-PATH" }
    return parts.joinToString("/")
}

/**
 * Native Android release/config updater.  The signed manifest is verified
 * using Tink (API 28 compatible), and artifact bytes are never accumulated in
 * memory: they stream through a same-volume staging file with size and hash
 * checks before PackageInstaller consumes them.
 */
/** The installed, signed APK supplies the immutable first-release anchor. */
internal interface ReleaseBootstrapStore {
    /** Reserve without burning the one-shot record.  The operation remains
     * recoverable until commit; every failure path must call abort. */
    fun reserve(expectedPreviousSequence: Long, operationId: String): Boolean
    fun commit(operationId: String): Boolean = true
    fun abort(operationId: String) {}
    /**
     * Reconcile a stale reservation only after the owner/session has been
     * observed terminal.  A timestamp alone is never sufficient to reopen a
     * one-shot record.
     */
    fun recoverStale(proof: ReleaseBootstrapRecoveryProof): Boolean = false
}

internal data class ReleaseBootstrapRecoveryProof(
    val operationId: String,
    val sessionId: Int?,
    val sessionTerminal: Boolean,
    val sessionAbandoned: Boolean,
    val sessionAbsent: Boolean,
) {
    fun isValid(): Boolean = operationId.matches(Regex("^[A-Za-z0-9._-]{8,128}$")) &&
        sessionTerminal && (sessionAbandoned || sessionAbsent) && !(sessionAbandoned && sessionAbsent) &&
        (sessionId == null || sessionId > 0)
}

/**
 * Durable one-shot bootstrap state machine.  The persisted value is one
 * protected record, not a record plus a separately deleted reservation.  A
 * successful commit writes a tombstone before any cleanup, so a crash can
 * never make the original bootstrap usable again.  The persistence adapter
 * is a single-key encrypted/CAS seam in production and a deterministic fake
 * in JVM tests.
 */
internal class ReleaseBootstrapStateMachine(
    private val read: () -> String?,
    private val write: (String) -> Boolean,
    private val now: () -> Long = { System.currentTimeMillis() },
) {
    private val lock = Any()
    private val staleAfterMillis = TimeUnit.MINUTES.toMillis(10)

    /** Provision only an empty store. Existing reservations, corruption and
     * terminal tombstones must never be replaced by a new APK's anchor. */
    fun initializeInstalledApk(sequence: Long): Boolean = synchronized(lock) {
        if (sequence <= 0L || !read().isNullOrEmpty()) return false
        val record = JSONObject().put("operation_id", "installed-apk-$sequence").put("sequence", sequence)
        record.put("record_digest", sha256(canonical(record)))
        write(record.toString())
    }

    /** A signed APK installed outside the updater can supersede an unused
     * older anchor. This is never a recovery path for an owned reservation,
     * a spent bootstrap, or malformed storage. The adapter must establish
     * that there is no pending installation before calling this method. */
    fun advanceUnusedInstalledApkAnchor(sequence: Long): Boolean = synchronized(lock) {
        val previous = parse(read()) ?: return false
        if (sequence <= previous.sequence || previous.phase != "available" ||
            previous.reservation != null || previous.tombstone != null) return false
        val record = JSONObject().put("operation_id", "installed-apk-$sequence").put("sequence", sequence)
        record.put("record_digest", sha256(canonical(record)))
        write(record.toString())
    }

    fun reserve(record: String, expectedPreviousSequence: Long, operationId: String): Boolean = synchronized(lock) {
        if (!operationId.matches(Regex("^[A-Za-z0-9._-]{8,128}$"))) return false
        val parsed = parse(record) ?: return false
        if (parsed.sequence != expectedPreviousSequence || parsed.phase == "committed") return false
        val reservation = parsed.reservation
        if (reservation != null) {
            // Reservation expiry is only a candidate for reconciliation.  It
            // never grants a second owner by itself.  Retrying the same
            // operation remains idempotent; a different operation must wait
            // for a terminal-session proof through recoverStale().
            if (reservation.operationId != operationId) return false
            return true
        }
        val reserved = parsed.copy(phase = "reserved", reservation = Reservation(operationId, now()))
        write(encode(reserved))
    }

    fun commit(record: String, operationId: String): Boolean = synchronized(lock) {
        val parsed = parse(record) ?: return false
        if (parsed.phase != "reserved" || parsed.reservation?.operationId != operationId) return false
        // Tombstone is the terminal state.  Never remove the source record as
        // part of this transition; a later cleanup may discard only stale
        // storage after the durable release state is visible.
        write(encode(parsed.copy(phase = "committed", tombstone = Tombstone(operationId, parsed.sequence, now()))))
    }

    fun abort(record: String, operationId: String): Boolean = synchronized(lock) {
        val parsed = parse(record) ?: return false
        if (parsed.phase != "reserved" || parsed.reservation?.operationId != operationId) return false
        write(encode(parsed.copy(phase = "available", reservation = null)))
    }

    fun recoverStale(record: String, proof: ReleaseBootstrapRecoveryProof): Boolean = synchronized(lock) {
        if (!proof.isValid()) return false
        val parsed = parse(record) ?: return false
        val reservation = parsed.reservation ?: return parsed.phase != "reserved"
        if (parsed.phase != "reserved" || reservation.operationId != proof.operationId) return false
        // TTL only marks the reservation eligible; the external terminal
        // proof above is what permits the transition back to available.
        if (now() - reservation.reservedAt <= staleAfterMillis) return false
        write(encode(parsed.copy(phase = "available", reservation = null)))
    }

    private data class Reservation(val operationId: String, val reservedAt: Long)
    private data class Tombstone(val operationId: String, val sequence: Long, val committedAt: Long)
    private data class State(val phase: String, val operationId: String, val sequence: Long, val recordDigest: String, val reservation: Reservation?, val tombstone: Tombstone?)

    private fun parse(raw: String?): State? = try {
        val value = JSONObject(raw ?: return null)
        val keys = value.keys().asSequence().toSet()
        val legacy = keys == setOf("operation_id", "sequence", "record_digest")
        if (legacy) {
            val digest = value.getString("record_digest")
            val unsigned = JSONObject(value.toString()).apply { remove("record_digest") }
            check(digest == sha256(canonical(unsigned)))
            State("available", value.getString("operation_id"), value.getLong("sequence"), digest, null, null)
        } else {
            check(keys == setOf("version", "phase", "operation_id", "sequence", "record_digest", "reservation", "tombstone"))
            check(value.getInt("version") == 1)
            val reservationValue = value.optJSONObject("reservation")
            val tombstoneValue = value.optJSONObject("tombstone")
            State(value.getString("phase"), value.getString("operation_id"), value.getLong("sequence"), value.getString("record_digest"), reservationValue?.let { Reservation(it.getString("operation_id"), it.getLong("reserved_at")) }, tombstoneValue?.let { Tombstone(it.getString("operation_id"), it.getLong("sequence"), it.getLong("committed_at")) })
        }.also { state ->
            check(state.phase in setOf("available", "reserved", "committed"))
            check(state.operationId.matches(Regex("^[A-Za-z0-9._-]{8,128}$")))
            check(state.sequence >= 0 && state.recordDigest.matches(Regex("^[0-9a-f]{64}$")))
            state.reservation?.let { check(it.operationId.matches(Regex("^[A-Za-z0-9._-]{8,128}$")) && it.reservedAt > 0) }
            if (state.phase == "committed") check(state.tombstone?.operationId == state.reservation?.operationId || state.tombstone?.operationId == state.operationId)
        }
    } catch (_: Throwable) { null }

    private fun encode(state: State): String {
        val reservation = state.reservation?.let { JSONObject().put("operation_id", it.operationId).put("reserved_at", it.reservedAt) } ?: JSONObject.NULL
        val tombstone = state.tombstone?.let { JSONObject().put("operation_id", it.operationId).put("sequence", it.sequence).put("committed_at", it.committedAt) } ?: JSONObject.NULL
        return JSONObject().put("version", 1).put("phase", state.phase).put("operation_id", state.operationId).put("sequence", state.sequence).put("record_digest", state.recordDigest).put("reservation", reservation).put("tombstone", tombstone).toString()
    }

    private fun canonical(value: JSONObject): String = value.keys().asSequence().toList().sorted().joinToString(separator = ",", prefix = "{", postfix = "}") { key -> JSONObject.quote(key) + ":" + when (val field = value.get(key)) { is Number, is Boolean -> field.toString(); else -> JSONObject.quote(field.toString()) } }
    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

private class SecureReleaseBootstrapStore(private val context: Context) : ReleaseBootstrapStore {
    private val stateKey = "release_bootstrap_state"
    private companion object { val processLock = Any() }
    private fun record(): String {
        val state = BifrostSecureStore.get(context, stateKey, "")
        return if (state.isNotBlank()) state else BifrostSecureStore.get(context, "release_bootstrap_record", "")
    }
    private fun machine(): ReleaseBootstrapStateMachine = ReleaseBootstrapStateMachine({ record() }, { value -> runCatching { BifrostSecureStore.put(context, stateKey, value); true }.getOrDefault(false) })
    override fun reserve(expectedPreviousSequence: Long, operationId: String): Boolean = synchronized(processLock) {
        val machine = machine()
        if (record().isEmpty()) {
            check(BuildConfig.RELEASE_SIGNING_SCOPE == "signed" && expectedPreviousSequence == BuildConfig.RELEASE_SEQUENCE) { "BF-RELEASE-BOOTSTRAP-ANCHOR" }
            if (!machine.initializeInstalledApk(BuildConfig.RELEASE_SEQUENCE)) return false
        }
        if (machine.reserve(record(), expectedPreviousSequence, operationId)) return true
        val preferences = context.getSharedPreferences("bifrost-release", Context.MODE_PRIVATE)
        val hasPendingInstall = preferences.contains("pending_session_id") ||
            preferences.contains("pending_sequence") ||
            !preferences.getString("pending_bootstrap_operation", "").isNullOrBlank() ||
            BifrostSecureStore.get(context, "release_pending_envelope", "").isNotBlank() ||
            context.packageManager.packageInstaller.mySessions.isNotEmpty()
        // The floor comes from the installed signed APK, never the offered
        // manifest. A failed download followed by a same-signer manual upgrade
        // otherwise leaves the old, unused bootstrap permanently unusable.
        if (!hasPendingInstall && BuildConfig.RELEASE_SIGNING_SCOPE == "signed" &&
            expectedPreviousSequence == BuildConfig.RELEASE_SEQUENCE &&
            machine.advanceUnusedInstalledApkAnchor(BuildConfig.RELEASE_SEQUENCE)) {
            return machine.reserve(record(), expectedPreviousSequence, operationId)
        }
        android.util.Log.w("BifrostUpdate", "Bootstrap reservation rejected for installed sequence $expectedPreviousSequence; pending=$hasPendingInstall")
        false
    }
    override fun commit(operationId: String): Boolean = synchronized(processLock) { machine().commit(record(), operationId) }
    override fun abort(operationId: String) { synchronized(processLock) { machine().abort(record(), operationId) } }
    override fun recoverStale(proof: ReleaseBootstrapRecoveryProof): Boolean = synchronized(processLock) {
        val pendingSessionId = context.getSharedPreferences("bifrost-release", Context.MODE_PRIVATE).getInt("pending_session_id", -1).takeIf { it > 0 }
        if (proof.sessionId != null && pendingSessionId != proof.sessionId) return false
        machine().recoverStale(record(), proof)
    }
}

class BifrostUpdateManager internal constructor(
    private val context: Context,
    bootstrapStoreOverride: ReleaseBootstrapStore? = null,
) {
    data class Result(val state: String, val sequence: Long = 0, val message: String = "")

    private val releasePreferences = context.getSharedPreferences(RELEASE_PREFS, Context.MODE_PRIVATE)
    private val bootstrapStore: ReleaseBootstrapStore = bootstrapStoreOverride ?: SecureReleaseBootstrapStore(context)
    @Volatile private var trustedOrigin: URI? = null

    @Synchronized
    fun checkAndStage(stageArtifacts: Boolean = true, automatic: Boolean = false,
        permitted: () -> Boolean = { true }, progress: (Long, Long) -> Unit = { _, _ -> }): Result =
        synchronized(BifrostAutomaticUpdate.operationGate) {
            checkAndStageLocked(stageArtifacts, automatic, permitted, progress)
        }

    private fun checkAndStageLocked(stageArtifacts: Boolean, automatic: Boolean,
        permitted: () -> Boolean, progress: (Long, Long) -> Unit): Result {
        if (automatic && !permitted()) return Result("deferred")
        cleanupStaleState()
        val existingSession = releasePreferences.getInt("pending_session_id", -1)
        if (existingSession > 0 && context.packageManager.packageInstaller.getSessionInfo(existingSession) != null)
            return Result("pending")
        if (!ReleaseContract.TRUST_ROOT_PROVISIONED || ReleaseContract.TRUST_ROOT_PEM.isNullOrBlank()) {
            return Result("disabled", message = "BF-RELEASE-TRUST-ROOT")
        }
        val base = BifrostSecureStore.get(context, "control_base_url", BuildConfig.CONTROL_BASE_URL).trimEnd('/')
        val token = BifrostSecureStore.get(context, "session_token", "")
        if (base.isBlank() || token.isBlank()) return Result("disabled", message = "control plane not enrolled")
        trustedOrigin = requireSecureUrl(base)
        val canonicalBase = trustedOrigin!!.toString().trimEnd('/')

        val envelope = requestJson("$canonicalBase/v1/releases/manifest", token)
        requireExactKeys(envelope, setOf("manifest_text", "signature", "delegation", "root_signature", "key_state", "transition_signature"), setOf("manifest_text", "signature", "delegation", "root_signature"), "BF-RELEASE-ENVELOPE")
        val manifestText = envelope.get("manifest_text") as? String ?: error("BF-RELEASE-ENVELOPE")
        check(manifestText.toByteArray(StandardCharsets.UTF_8).size <= MAX_MANIFEST_BYTES) { "BF-RELEASE-MANIFEST-SIZE" }
        val signatureText = envelope.get("signature") as? String ?: error("BF-RELEASE-ENVELOPE")
        val installed = readDurableReleaseState()
        val verified = verifyManifest(manifestText, signatureText, envelope, installed)
        val sequence = verified.sequence
        val manifestDigest = sha256(manifestText)
        // This floor is part of the APK signature, independent of mutable
        // preferences and of the release sequence offered by the server.
        if (BuildConfig.RELEASE_SEQUENCE > 0L && sequence < BuildConfig.RELEASE_SEQUENCE) error("BF-RELEASE-ROLLBACK")
        if (installed != null) {
            if (sequence < installed.sequence || sequence < installed.floor) throw IllegalStateException("BF-RELEASE-ROLLBACK")
            if (sequence == installed.sequence) {
                if (manifestDigest != installed.manifestDigest) throw IllegalStateException("BF-RELEASE-EQUIVOCATION")
                return Result("up-to-date", sequence, "release already installed")
            }
            val incomingAuthorityGeneration = verified.plan?.authorityGeneration ?: error("BF-RELEASE-KEY-STATE")
            val incomingAuthorityDigest = verified.plan.authorityDigest
            if (incomingAuthorityGeneration < installed.authorityGeneration) throw IllegalStateException("BF-RELEASE-AUTHORITY-ROLLBACK")
            if (incomingAuthorityGeneration == installed.authorityGeneration && incomingAuthorityDigest != installed.authorityDigest) throw IllegalStateException("BF-RELEASE-AUTHORITY-EQUIVOCATION")
            if (incomingAuthorityGeneration > installed.authorityGeneration && verified.signingKeyFingerprint != installed.signingKeyFingerprint && !envelope.has("transition_signature")) throw IllegalStateException("BF-RELEASE-TRANSITION")
            if (envelope.has("transition_signature")) {
                val transition = envelope.getJSONObject("transition_signature")
                check(publicKeyFingerprint(transition.getString("old_public_key_pem")) == installed.signingKeyFingerprint) { "BF-RELEASE-TRANSITION" }
            }
        }

        val selected = selectAndroidArtifacts(verified.plan?.artifactMetadata.orEmpty()).map { artifact ->
            JSONObject().put("id", artifact.id).put("path", artifact.path).put("install_path", artifact.installPath).put("platform", artifact.platform).put("arch", artifact.arch).put("kind", artifact.kind).put("bytes", artifact.bytes).put("sha256", artifact.sha256).put("source_bundle", artifact.sourceBundle).put("notice", artifact.notice).put("dependencies", artifact.dependencies)
        }
        if (selected.isEmpty()) return Result("unavailable", sequence, "no Android artifact for this ABI")
        if (sequence == BuildConfig.RELEASE_SEQUENCE && sequence > 0L) {
            val currentApk = selected.singleOrNull { it.getString("kind") == "apk" } ?: error("BF-RELEASE-APK")
            verifyArtifactFile(File(context.applicationInfo.sourceDir), currentApk)
            // A signed manual upgrade can leave an older updater record.
            // Adopt the exact installed APK after hash/signature verification
            // instead of replacing an already-running identical package.
            if (installed == null) {
                val operation = "initial-apk-$sequence"
                check(bootstrapStore.reserve(BuildConfig.RELEASE_SEQUENCE, operation) && bootstrapStore.commit(operation)) { "BF-RELEASE-STATE-CORRUPT" }
            }
            commitReleaseState(verified, manifestDigest)
            return Result("up-to-date", sequence, "release already installed")
        }
        if (!stageArtifacts) return Result("available", sequence, BifrostUiText.updateAvailable)
        if (selected.count { it.getString("kind") == "apk" } > 1) error("BF-RELEASE-MULTIPLE-APK")
        val total = selected.sumOf { it.getLong("bytes") }
        check(total <= MAX_TOTAL_BYTES) { "BF-RELEASE-TOTAL-SIZE" }
        val hasApk = selected.any { it.getString("kind") == "apk" }
        if (hasApk && !context.packageManager.canRequestPackageInstalls()) {
            if (automatic) BifrostAutomaticUpdate.showUpdateRequired(context, permission = true)
            return Result("permission-required", sequence, BifrostUiText.updatePermissionRequired)
        }
        if (automatic && releasePreferences.getBoolean("automatic_confirmation_required", false)) {
            BifrostAutomaticUpdate.showUpdateRequired(context)
            return Result("confirmation-required", sequence, BifrostUiText.updateConfirmInstall)
        }

        val bootstrapOperation = "release-${sequence}-${System.nanoTime()}"
        var bootstrapReserved = false
        val root =
            File(context.noBackupFilesDir, "bifrost-updates").apply {
                check(exists() || mkdirs()) { "BF-RELEASE-STORAGE" }
                check(isDirectory && !Files.isSymbolicLink(toPath())) { "BF-RELEASE-STORAGE" }
            }
        // A deferred download owns no installer/bootstrap reservation. It is
        // reused only after a fresh signed-manifest check and another byte hash.
        val staging = File(root, ".staging-" + sequence + "-" + manifestDigest.take(16))
        var apk: File? = null
        try {
            for (artifact in selected) {
                val relative = safeRelative(artifact.getString("path"))
                val destination = File(staging, relative)
                val endpoint = "$canonicalBase/v1/releases/artifacts/${relative.split('/').joinToString("/") { URLEncoder.encode(it, "UTF-8") }}"
                if (BifrostUpdateStaging.reuse(root, destination) { verifyArtifactFile(it, artifact) }) {
                    progress(destination.length(), destination.length())
                } else {
                    downloadArtifactToFile(endpoint, token, artifact, destination, progress)
                }
                if (artifact.getString("kind") == "apk") apk = destination
            }

            if (apk != null) {
                if (automatic && !permitted()) return Result("deferred", sequence)
                if (installed == null) {
                    check(bootstrapStore.reserve(BuildConfig.RELEASE_SEQUENCE, bootstrapOperation)) { "BF-RELEASE-STATE-CORRUPT" }
                    bootstrapReserved = true
                    commitOrThrow(releasePreferences.edit().putString("pending_bootstrap_operation", bootstrapOperation))
                }
                // The receiver owns this pending record until the system
                // reports STATUS_SUCCESS or a terminal failure.
                BifrostSecureStore.put(context, "release_pending_envelope", canonicalJson(envelope))
                commitOrThrow(releasePreferences.edit()
                    .putString("pending_bootstrap_operation", if (installed == null) bootstrapOperation else "")
                    .putLong("pending_sequence", sequence)
                    .putBoolean("pending_automatic", automatic)
                    .putString("pending_manifest_digest", manifestDigest)
                    .putString("pending_envelope_digest", verified.envelopeDigest)
                    .putString("pending_authority_digest", verified.plan?.authorityDigest)
                    .putLong("pending_authority_generation", verified.plan?.authorityGeneration ?: 0L)
                    .putString("pending_signing_key_id", verified.signingKeyId)
                    .putString("pending_signing_key_fingerprint", verified.signingKeyFingerprint)
                    .putLong("pending_delegation_generation", verified.delegationGeneration)
                    .putString("pending_channel", verified.channel)
                    .putLong("pending_floor", verified.floor)
                    .putString("pending_stage", staging.absolutePath)
                    .putString("pending_artifact", apk!!.let { JSONObject().put("path", staging.toPath().relativize(it.toPath()).toString().replace('\\', '/')).put("bytes", selected.first { item -> item.getString("kind") == "apk" }.getLong("bytes")).put("sha256", selected.first { item -> item.getString("kind") == "apk" }.getString("sha256")).toString() })
                    .remove("last_update_error")
                    )
                try {
                    BifrostUpdateResume.record(context, BifrostRuntimeStatus.current.state == BifrostLeakState.HEALTHY, automatic)
                    installApk(apk!!, sequence, selected.first { it.getString("kind") == "apk" }, automatic)
                } catch (error: Throwable) {
                    finalizePackageInstall(sequence, success = false)
                    throw error
                }
                /*
                return Result("pending", sequence, BifrostUiText.updateFound)
                */
                return Result("pending", sequence, BifrostUiText.updateFound)
            }

            if (staging.exists()) promoteStaging(staging, sequence)
            val stateEditor = releasePreferences.edit()
            if (installed == null && !bootstrapStore.commit(bootstrapOperation)) throw IllegalStateException("BF-RELEASE-STATE-CORRUPT")
            // A terminal bootstrap tombstone is durable before the release
            // state becomes visible.  If the state write fails, retry is
            // blocked rather than reusing the one-shot record.
            commitReleaseState(verified, manifestDigest)
            BifrostSecureStore.remove(context, "release_pending_envelope")
            commitOrThrow(stateEditor
                .remove("pending_sequence").remove("pending_stage")
                .remove("pending_session_id").remove("pending_session_started_at")
                .remove("pending_artifact").remove("pending_manifest_digest").remove("last_update_error"))
            /*
            return Result("staged", sequence, BifrostUiText.updateDownloaded)
            */
            return Result("staged", sequence, BifrostUiText.updateDownloaded)
        } catch (error: Throwable) {
            if (bootstrapReserved) runCatching { bootstrapStore.abort(bootstrapOperation) }
            if (installed == null) runCatching { commitOrThrow(releasePreferences.edit().remove("pending_bootstrap_operation")) }
            if (staging.exists()) staging.deleteRecursively()
            runCatching { BifrostSecureStore.remove(context, "release_pending_envelope") }
            throw error
        }
    }

    /** An Activity can launch this when checkAndStage returns permission-required. */
    fun installPermissionIntent(): Intent? = if (!context.packageManager.canRequestPackageInstalls()) {
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
    } else null

    /** Package selection is derived solely from the verifier-owned plan graph;
     * the signed envelope/manifest is never re-read here. */
    private fun selectAndroidArtifacts(planArtifacts: List<ArtifactPlan>): List<ArtifactPlan> {
        val supported = Build.SUPPORTED_ABIS.map { it.lowercase(Locale.US) }.toSet()
        val result = planArtifacts.filter { artifact ->
            val arch = artifact.arch.lowercase(Locale.US)
            val unsupported = arch !in supported
            artifact.platform == "android" && artifact.kind == "apk" && !unsupported
        }
        if (result.isEmpty()) return emptyList()
        val byArch = result.groupBy { it.arch.lowercase(Locale.US) }
        val selectedArch = Build.SUPPORTED_ABIS.map { it.lowercase(Locale.US) }.firstOrNull { byArch.containsKey(it) } ?: return emptyList()
        val selected = byArch.getValue(selectedArch)
        check(selected.size == 1) { "BF-RELEASE-DUPLICATE-ABI" }
        return selected
    }

    /** Immutable, verifier-owned plan.  Callers never receive the mutable
     * manifest/build JSON and package selection consumes this graph only. */
    internal class VerifiedReleasePlan internal constructor(
        val envelopeDigest: String,
        val manifestDigest: String,
        val allowlistDigest: String,
        val sequence: Long,
        val channel: String,
        val floor: Long,
        val rootKeyId: String,
        val rootFingerprint: String,
        val authorityDigest: String,
        val authorityGeneration: Long,
        val delegationGeneration: Long,
        val signingKeyId: String,
        val signingKeyFingerprint: String,
        artifacts: List<String>,
        artifactMetadata: List<ArtifactPlan>
    ) {
        val artifacts: List<String> = java.util.Collections.unmodifiableList(artifacts.toList())
        val artifactMetadata: List<ArtifactPlan> = java.util.Collections.unmodifiableList(artifactMetadata.map { it.immutableCopy() })
    }
    internal class ArtifactPlan internal constructor(val id: String, val path: String, val installPath: String, val platform: String, val arch: String, val kind: String, val bytes: Long, val sha256: String, val sourceBundle: String, val notice: String, dependencies: List<String>) {
        val dependencies: List<String> = java.util.Collections.unmodifiableList(dependencies.toList())
        fun immutableCopy(): ArtifactPlan = ArtifactPlan(id, path, installPath, platform, arch, kind, bytes, sha256, sourceBundle, notice, dependencies)
    }
    internal data class VerifiedManifest(val sequence: Long, val manifestDigest: String, val envelopeDigest: String, val signingKeyId: String, val signingKeyFingerprint: String, val delegationGeneration: Long, val channel: String, val floor: Long, val plan: VerifiedReleasePlan? = null)

    private fun verifyManifest(text: String, signatureText: String, envelope: JSONObject = JSONObject(), previousState: DurableReleaseState? = null): VerifiedManifest =
        verifyManifestWithCompiledRoot(text, signatureText, envelope, BuildConfig.VERSION_NAME, null, previousState, 1L)

    /** Same production parser/crypto/plan path, using only the compiled trust binding. */
    private fun verifyManifestWithCompiledRoot(text: String, signatureText: String, envelope: JSONObject, currentClientVersion: String, expectedChannel: String?, previousState: DurableReleaseState?, currentConfigVersion: Long): VerifiedManifest =
        verifyManifestWithTrustRoot(text, signatureText, envelope, currentClientVersion, expectedChannel, previousState, currentConfigVersion, ReleaseContract.TRUST_ROOT_KEY_ID, ReleaseContract.TRUST_ROOT_PEM, ReleaseContract.TRUST_ROOT_FINGERPRINT)

    /**
     * TEST-ONLY corpus seam. The normal production path above always uses the
     * immutable compiled ceremony binding. This overload is reachable only in
     * a DEBUG test process, takes the checked-in corpus public root explicitly,
     * and never participates in update/download flows. Release builds fail
     * closed before any supplied test material is considered.
     */
    internal fun verifyManifestWithTestRoot(text: String, signatureText: String, envelope: JSONObject, currentClientVersion: String, expectedChannel: String?, previousState: DurableReleaseState?, currentConfigVersion: Long, testRootKeyId: String, testRootPem: String, testRootFingerprint: String): VerifiedManifest {
        check(BuildConfig.DEBUG) { "BF-RELEASE-TEST-ROOT" }
        check(testRootKeyId == "bifrost-root-v1" && testRootFingerprint.matches(Regex("^[0-9a-f]{64}$")) && testRootPem.isNotBlank()) { "BF-RELEASE-TEST-ROOT" }
        check(publicKeyFingerprint(testRootPem) == testRootFingerprint) { "BF-RELEASE-TEST-ROOT" }
        return verifyManifestWithTrustRoot(text, signatureText, envelope, currentClientVersion, expectedChannel, previousState, currentConfigVersion, testRootKeyId, testRootPem, testRootFingerprint)
    }

    private fun verifyManifestWithTrustRoot(text: String, signatureText: String, envelope: JSONObject, currentClientVersion: String, expectedChannel: String?, previousState: DurableReleaseState?, currentConfigVersion: Long, rootKeyId: String, rootPem: String?, rootFingerprint: String?): VerifiedManifest {
         check(rootKeyId.isNotBlank() && !rootPem.isNullOrBlank() && rootFingerprint?.matches(Regex("^[0-9a-f]{64}$")) == true) { "BF-RELEASE-TRUST-ROOT" }
        check(text.isNotEmpty() && text.toByteArray(StandardCharsets.UTF_8).size <= MAX_MANIFEST_BYTES) { "BF-RELEASE-MANIFEST-SIZE" }
        StrictJsonValidator(text, "BF-RELEASE-MANIFEST").validate()
        rejectNonCanonicalNumbers(text)
        val payload = text.toByteArray(StandardCharsets.UTF_8)
        check(strictUtf8(payload) == text) { "BF-RELEASE-UTF8" }
        val signature = try { decodeBase64Url(signatureText) } catch (_: Throwable) { throw IllegalStateException("BF-RELEASE-SIGNATURE") }
        try {
            check(signature.size == 64) { "BF-RELEASE-SIGNATURE" }
            val manifest = JSONObject(text)
            requireExactKeys(manifest,
                setOf("format", "generated_at", "release_sequence", "minimum_client_version", "minimum_config_version", "channel", "rollback_floor", "build", "sbom_sha256", "licenses_sha256", "source_bundle_id", "notice_artifact_id", "signing_algorithm", "signing_key_id", "trust_root_key_id", "rollback_policy", "source_manifest_sha256", "build_plan_sha256", "source_policy_sha256", "core_provenance_sha256", "build_inputs_sha256", "toolchain_sha256", "dependency_license_manifest_sha256"),
                setOf("format", "generated_at", "release_sequence", "minimum_client_version", "minimum_config_version", "channel", "rollback_floor", "build", "sbom_sha256", "licenses_sha256", "source_bundle_id", "notice_artifact_id", "signing_algorithm", "signing_key_id", "trust_root_key_id", "rollback_policy"), "BF-RELEASE-FIELDS")
            check(manifest.opt("format") is String && manifest.getString("format") == "BIFROST-RELEASE-MANIFEST-2") { "BF-RELEASE-FORMAT" }
            check(manifest.opt("signing_algorithm") is String && manifest.getString("signing_algorithm") == "Ed25519") { "BF-RELEASE-ALGORITHM" }
             check(manifest.getString("trust_root_key_id") == rootKeyId) { "BF-RELEASE-KEY" }
             if (expectedChannel != null) check(manifest.getString("channel") == expectedChannel) { "BF-RELEASE-METADATA" }
            check(manifest.getString("signing_key_id").matches(Regex("^[A-Za-z0-9._-]{1,64}$"))) { "BF-RELEASE-KEY" }
             check(manifest.getString("channel") in setOf("stable", "beta", "test")) { "BF-RELEASE-METADATA" }
             if (manifest.getString("channel") == "stable") {
                 for (field in listOf("source_manifest_sha256", "build_plan_sha256", "source_policy_sha256", "core_provenance_sha256", "build_inputs_sha256", "toolchain_sha256", "dependency_license_manifest_sha256")) {
                     check(manifest.optString(field, "").matches(Regex("^[0-9a-f]{64}$"))) { "BF-RELEASE-METADATA" }
                 }
             }
             val minimum = manifest.opt("minimum_client_version")
             check(minimum is String && minimum.isNotBlank()) { "BF-RELEASE-MIN-VERSION" }
             check(compareVersions(currentClientVersion, minimum as String) >= 0) { "BF-RELEASE-MIN-VERSION" }
             val minimumConfig = manifest.opt("minimum_config_version")
             check(isIntegralJsonNumber(minimumConfig) && (minimumConfig as Number).toLong() in 0..currentConfigVersion) { "BF-RELEASE-MIN-CONFIG-VERSION" }
             val sequenceValue = manifest.opt("release_sequence")
             check(isIntegralJsonNumber(sequenceValue) && (sequenceValue as Number).toLong() > 0) { "BF-RELEASE-SEQUENCE" }
             val rollbackFloorValue = manifest.opt("rollback_floor")
             check(isIntegralJsonNumber(rollbackFloorValue) && (rollbackFloorValue as Number).toLong() in 1..(sequenceValue as Number).toLong()) { "BF-RELEASE-METADATA" }
             val delegation = envelope.opt("delegation") as? JSONObject ?: error("BF-RELEASE-FIELDS")
            requireExactKeys(delegation, setOf("root_key_id", "key_id", "purpose", "algorithm", "public_key_pem", "public_key_fingerprint", "channel", "activation_sequence", "retirement_sequence", "generation"), setOf("root_key_id", "key_id", "purpose", "algorithm", "public_key_pem", "public_key_fingerprint", "channel", "activation_sequence", "retirement_sequence", "generation"), "BF-RELEASE-FIELDS")
            val delegatedPem = delegation.getString("public_key_pem")
            val signingKeyId = delegation.getString("key_id")
            check(signingKeyId == manifest.getString("signing_key_id") && delegation.getString("root_key_id") == manifest.getString("trust_root_key_id") && delegation.getString("purpose") == "release-signing" && delegation.getString("algorithm") == "Ed25519" && delegation.getString("channel") == manifest.getString("channel")) { "BF-RELEASE-KEY" }
            val activationValue = delegation.get("activation_sequence"); val retirementValue = delegation.get("retirement_sequence"); val generationValue = delegation.get("generation")
            check(activationValue is Number && activationValue.toDouble() == activationValue.toLong().toDouble() && retirementValue is Number && retirementValue.toDouble() == retirementValue.toLong().toDouble() && generationValue is Number && generationValue.toDouble() == generationValue.toLong().toDouble()) { "BF-RELEASE-KEY" }
            val activation = delegation.getLong("activation_sequence"); val retirement = delegation.getLong("retirement_sequence")
            val delegationGeneration = delegation.optLong("generation", -1L)
            check(activation > 0 && retirement > activation && (sequenceValue as Number).toLong() in activation until retirement && delegation.get("generation") !is String && delegationGeneration > 0 && delegation.getString("public_key_fingerprint").matches(Regex("^[0-9a-f]{64}$")) && delegation.getString("public_key_fingerprint") == publicKeyFingerprint(delegatedPem)) { "BF-RELEASE-KEY" }
            val delegationText = "{\"activation_sequence\":$activation,\"algorithm\":\"Ed25519\",\"channel\":${BifrostJsonString.quote(delegation.getString("channel"))},\"generation\":$delegationGeneration,\"key_id\":${BifrostJsonString.quote(signingKeyId)},\"public_key_fingerprint\":${BifrostJsonString.quote(delegation.getString("public_key_fingerprint"))},\"public_key_pem\":${BifrostJsonString.quote(delegatedPem)},\"purpose\":\"release-signing\",\"retirement_sequence\":$retirement,\"root_key_id\":${BifrostJsonString.quote(delegation.getString("root_key_id"))}}"
            val rootSig = decodeBase64Url(envelope.getString("root_signature"))
             try { check(rootSig.size == 64 && verifyEd25519(rootSig, delegationText.toByteArray(StandardCharsets.UTF_8), rootPem ?: error("BF-RELEASE-TRUST-ROOT"))) { "BF-RELEASE-KEY" } } finally { rootSig.fill(0) }
            val verificationKeys = listOf(delegatedPem)
            check(verificationKeys.any { pem -> verifyEd25519(signature, payload, pem) }) { "BF-RELEASE-SIGNATURE" }
            val keyState = envelope.optJSONObject("key_state") ?: error("BF-RELEASE-FIELDS")
            var signedStateDigest = ""
            keyState.let {
                 requireExactKeys(keyState, setOf("root_key_id", "generation", "channel", "active_key_ids", "revoked_key_ids", "signature"), setOf("root_key_id", "generation", "channel", "active_key_ids", "revoked_key_ids", "signature"), "BF-RELEASE-FIELDS")
                 check(keyState.getString("root_key_id") == rootKeyId && keyState.getLong("generation") > 0 && keyState.getString("channel") == manifest.getString("channel")) { "BF-RELEASE-KEY-STATE" }
                val active = keyState.getJSONArray("active_key_ids"); val revoked = keyState.getJSONArray("revoked_key_ids"); val activeList = (0 until active.length()).map { active.getString(it) }; val revokedList = (0 until revoked.length()).map { revoked.getString(it) }
                check(activeList == activeList.sorted() && revokedList == revokedList.sorted() && activeList.distinct().size == activeList.size && revokedList.distinct().size == revokedList.size) { "BF-RELEASE-KEY-STATE" }
                val activeIds = activeList.toSet(); val revokedIds = revokedList.toSet()
                check(activeIds.intersect(revokedIds).isEmpty() && activeIds.contains(signingKeyId) && !revokedIds.contains(signingKeyId)) { "BF-RELEASE-KEY-STATE" }
                 val signedState = JSONObject().put("active_key_ids", org.json.JSONArray(activeList)).put("channel", keyState.getString("channel")).put("generation", keyState.getLong("generation")).put("revoked_key_ids", org.json.JSONArray(revokedList)).put("root_key_id", keyState.getString("root_key_id"))
                signedStateDigest = sha256(canonicalJson(signedState))
                 val stateSignature = decodeBase64Url(keyState.getString("signature")); val signedStateBytes = canonicalJson(signedState).toByteArray(StandardCharsets.UTF_8)
                  try { check(stateSignature.size == 64 && verifyEd25519(stateSignature, signedStateBytes, rootPem ?: error("BF-RELEASE-TRUST-ROOT"))) { "BF-RELEASE-KEY-STATE" } }
                 finally { stateSignature.fill(0); signedStateBytes.fill(0) }
            }
            envelope.optJSONObject("transition_signature")?.let { validateTransition(it, manifest.getString("channel"), keyState.getLong("generation"), signingKeyId, publicKeyFingerprint(delegatedPem), previousState?.signingKeyId, previousState?.signingKeyFingerprint, (sequenceValue as Number).toLong()) }
            val build = manifest.opt("build") as? JSONObject ?: error("BF-RELEASE-BUILD")
            requireExactKeys(build,
                setOf("format", "generated_at", "configuration", "android_signing_scope", "android_signing_key_alias", "artifact_root", "artifacts"),
                setOf("artifact_root", "artifacts"), "BF-RELEASE-BUILD")
            check(build.opt("artifact_root") is String && build.getString("artifact_root") == "releases") { "BF-RELEASE-ROOT" }
            val artifacts = build.opt("artifacts") as? org.json.JSONArray ?: error("BF-RELEASE-ARTIFACTS")
            check(artifacts.length() in 1..MAX_ARTIFACTS) { "BF-RELEASE-ARTIFACTS" }
            val paths = mutableSetOf<String>()
            val installPaths = mutableSetOf<String>()
            val artifactIds = mutableSetOf<String>()
            val dependencyGraph = mutableMapOf<String, List<String>>()
            var total = 0L
            for (index in 0 until artifacts.length()) {
                val item = artifacts.opt(index) as? JSONObject ?: error("BF-RELEASE-ARTIFACT")
                requireExactKeys(item, setOf("id", "path", "install_path", "platform", "arch", "kind", "bytes", "sha256", "source_bundle", "notice", "dependencies"), setOf("id", "path", "install_path", "platform", "arch", "kind", "bytes", "sha256", "source_bundle", "notice", "dependencies"), "BF-RELEASE-ARTIFACT")
                val id = item.getString("id")
                check(artifactIds.add(id)) { "BF-RELEASE-ARTIFACT" }
                val relative = safeRelative(item.getString("path"))
                check(paths.add(relative.lowercase(Locale.US))) { "BF-RELEASE-DUPLICATE-PATH" }
                val installPath = safeRelative(item.getString("install_path"))
                check(installPaths.add(installPath.lowercase(Locale.US))) { "BF-RELEASE-DUPLICATE-INSTALL" }
                check(item.get("platform") is String && item.getString("platform") in setOf("android", "windows", "linux")) { "BF-RELEASE-PLATFORM" }
                check(item.get("arch") is String && item.getString("arch").matches(Regex("[A-Za-z0-9._-]+"))) { "BF-RELEASE-ARCH" }
                check(item.get("kind") is String && item.getString("kind") in setOf("apk", "exe", "service-exe", "core", "core-manifest", "installer", "metadata", "notice", "source", "node-agent")) { "BF-RELEASE-KIND" }
                val bytes = item.get("bytes")
                check(isIntegralJsonNumber(bytes) && (bytes as Number).toLong() in 1..MAX_ARTIFACT_BYTES) { "BF-RELEASE-METADATA" }
                total = Math.addExact(total, bytes.toLong())
                check(total <= MAX_TOTAL_BYTES) { "BF-RELEASE-TOTAL-SIZE" }
                val sha = item.get("sha256")
                check(sha is String && sha.matches(Regex("[0-9a-f]{64}"))) { "BF-RELEASE-METADATA" }
                val dependencies = item.get("dependencies") as? org.json.JSONArray ?: error("BF-RELEASE-METADATA")
                check(dependencies.length() <= 32) { "BF-RELEASE-METADATA" }
                dependencyGraph[id] = (0 until dependencies.length()).map { dependencies.getString(it) }
            }
            for (index in 0 until artifacts.length()) {
                val item = artifacts.getJSONObject(index); val id = item.getString("id")
                check(item.getString("source_bundle") in artifactIds && item.getString("notice") in artifactIds) { "BF-RELEASE-METADATA" }
                check(artifacts.getJSONObject((0 until artifacts.length()).first { artifacts.getJSONObject(it).getString("id") == item.getString("source_bundle") }).getString("kind") == "source" && artifacts.getJSONObject((0 until artifacts.length()).first { artifacts.getJSONObject(it).getString("id") == item.getString("notice") }).getString("kind") == "notice") { "BF-RELEASE-METADATA" }
                check(dependencyGraph.getValue(id).all { dependencyId ->
                    if (dependencyId !in artifactIds || dependencyId == id) return@all false
                    val dependency = artifacts.getJSONObject((0 until artifacts.length()).first { artifacts.getJSONObject(it).getString("id") == dependencyId })
                    dependency.getString("kind") in setOf("source", "notice") || (dependency.getString("platform") == item.getString("platform") && dependency.getString("arch") == item.getString("arch"))
                }) { "BF-RELEASE-METADATA" }
            }
            val visiting = mutableSetOf<String>(); val visited = mutableSetOf<String>()
            fun visit(id: String) { check(id !in visiting) { "BF-RELEASE-METADATA" }; if (!visited.add(id)) return; visiting += id; dependencyGraph.getValue(id).forEach(::visit); visiting -= id }
            artifactIds.forEach(::visit)
            check(artifactIds.contains(manifest.getString("source_bundle_id")) && artifactIds.contains(manifest.getString("notice_artifact_id"))) { "BF-RELEASE-METADATA" }
            if (manifest.getString("channel") == "stable") {
                val windows = (0 until artifacts.length()).map { artifacts.getJSONObject(it) }.filter { it.getString("platform") == "windows" && it.getString("arch") == "x64" }
                val payloadWindows = windows.filter { it.getString("kind") !in setOf("source", "notice") }
                val payloadIds = payloadWindows.map { it.getString("id") }.toSet()
                val androidPayloadIds = (0 until artifacts.length()).map { artifacts.getJSONObject(it) }.filter { it.getString("platform") == "android" && it.getString("kind") !in setOf("source", "notice") }.map { it.getString("id") }.toSet()
                if (payloadWindows.isNotEmpty()) check(payloadWindows.size == payloadIds.size && ReleaseArtifactPolicy.isWindowsX64Stable(payloadIds)) { "BF-RELEASE-WINDOWS-SET" }
                if (androidPayloadIds.isNotEmpty()) check(androidPayloadIds == ReleaseArtifactPolicy.ANDROID_STABLE) { "BF-RELEASE-ANDROID-SET" }
                if (androidPayloadIds.isNotEmpty()) for (androidId in ReleaseArtifactPolicy.ANDROID_STABLE) {
                    val item = (0 until artifacts.length()).map { artifacts.getJSONObject(it) }.singleOrNull { it.getString("id") == androidId }
                    check(item != null && item.getString("platform") == "android" && item.getString("kind") == "apk" && androidId == "android-${item.getString("arch")}-apk") { "BF-RELEASE-ANDROID-SET" }
                }
                check(payloadWindows.isNotEmpty() || androidPayloadIds.isNotEmpty()) { "BF-RELEASE-REQUIRED-SET" }
            }
            val planArtifacts = (0 until artifacts.length()).map { index ->
                val item = artifacts.getJSONObject(index)
                val dependencies = item.getJSONArray("dependencies")
                ArtifactPlan(item.getString("id"), item.getString("path"), item.getString("install_path"), item.getString("platform"), item.getString("arch"), item.getString("kind"), item.getLong("bytes"), item.getString("sha256"), item.getString("source_bundle"), item.getString("notice"), (0 until dependencies.length()).map { dependencyIndex -> dependencies.getString(dependencyIndex) }.toList())
            }
            val planArtifactIds = planArtifacts.map { it.id }
            val manifestDigest = sha256(text)
            val envelopeDigest = sha256(canonicalJson(envelope))
            previousState?.let { previous ->
                check((sequenceValue as Number).toLong() >= previous.sequence && (sequenceValue as Number).toLong() >= previous.floor && ((sequenceValue as Number).toLong() != previous.sequence || manifestDigest == previous.manifestDigest)) { if ((sequenceValue as Number).toLong() == previous.sequence) "BF-RELEASE-EQUIVOCATION" else "BF-RELEASE-ROLLBACK" }
                check(keyState.getLong("generation") >= previous.authorityGeneration) { "BF-RELEASE-AUTHORITY-ROLLBACK" }
                if (keyState.getLong("generation") == previous.authorityGeneration) check(signedStateDigest == previous.authorityDigest) { "BF-RELEASE-AUTHORITY-EQUIVOCATION" }
                if ((signingKeyId != previous.signingKeyId || publicKeyFingerprint(delegatedPem) != previous.signingKeyFingerprint) && previous.authorityGeneration > 0) check(envelope.has("transition_signature")) { "BF-RELEASE-TRANSITION" }
            }
            return VerifiedManifest(
                (sequenceValue as Number).toLong(),
                manifestDigest,
                envelopeDigest,
                signingKeyId,
                publicKeyFingerprint(delegatedPem),
                delegationGeneration,
                manifest.getString("channel"),
                manifest.getLong("rollback_floor"),
                    VerifiedReleasePlan(envelopeDigest, manifestDigest, sha256(canonicalJson(artifacts)), (sequenceValue as Number).toLong(), manifest.getString("channel"), manifest.getLong("rollback_floor"), rootKeyId, rootFingerprint ?: error("BF-RELEASE-TRUST-ROOT"), signedStateDigest, keyState.getLong("generation"), delegationGeneration, signingKeyId, publicKeyFingerprint(delegatedPem), java.util.Collections.unmodifiableList(planArtifactIds), java.util.Collections.unmodifiableList(planArtifacts))
            )
        } finally {
            payload.fill(0)
            signature.fill(0)
        }
    }

    private fun decodePublicKeyDer(pem: String): ByteArray {
        val der = try {
            val body = pem.lineSequence().filter { !it.startsWith("-----") }.joinToString("")
            val decoded = java.util.Base64.getDecoder().decode(body)
            val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
            check(decoded.size == prefix.size + 32 && decoded.copyOfRange(0, prefix.size).contentEquals(prefix)) { "BF-RELEASE-KEY" }
            decoded
        } catch (_: Throwable) { throw IllegalStateException("BF-RELEASE-KEY") }
        return der
    }

    private fun publicKeyFingerprint(pem: String): String {
        val der = decodePublicKeyDer(pem)
        return try { MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) } } finally { der.fill(0) }
    }

    private fun validateTransition(value: JSONObject, channel: String, keyStateGeneration: Long, signingKeyId: String, signingKeyFingerprint: String, previousSigningKeyId: String?, previousSigningKeyFingerprint: String?, releaseSequence: Long) {
        requireExactKeys(value, setOf("old_key_id", "new_key_id", "purpose", "algorithm", "channel", "from_generation", "to_generation", "activation_sequence", "retirement_sequence", "old_public_key_pem", "new_public_key_pem", "old_signature", "new_signature"), setOf("old_key_id", "new_key_id", "purpose", "algorithm", "channel", "from_generation", "to_generation", "activation_sequence", "retirement_sequence", "old_public_key_pem", "new_public_key_pem", "old_signature", "new_signature"), "BF-RELEASE-TRANSITION")
        val oldId = value.getString("old_key_id"); val newId = value.getString("new_key_id"); val purpose = value.getString("purpose"); val algorithm = value.getString("algorithm"); val transitionChannel = value.getString("channel")
        val from = value.getLong("from_generation"); val to = value.getLong("to_generation"); val activation = value.getLong("activation_sequence"); val retirement = value.getLong("retirement_sequence")
        check(oldId.matches(Regex("^[A-Za-z0-9._-]{1,64}$")) && newId.matches(Regex("^[A-Za-z0-9._-]{1,64}$")) && oldId != newId && newId == signingKeyId && (previousSigningKeyId == null || oldId == previousSigningKeyId) && purpose == "release-signing" && algorithm == "Ed25519" && transitionChannel == channel && from > 0 && to == from + 1 && to == keyStateGeneration && activation > 0 && retirement > activation && releaseSequence >= activation && releaseSequence < retirement) { "BF-RELEASE-TRANSITION" }
        val unsigned = JSONObject().put("activation_sequence", activation).put("algorithm", algorithm).put("channel", transitionChannel).put("from_generation", from).put("new_key_id", newId).put("new_public_key_pem", value.getString("new_public_key_pem")).put("old_key_id", oldId).put("old_public_key_pem", value.getString("old_public_key_pem")).put("purpose", purpose).put("retirement_sequence", retirement).put("to_generation", to)
        val bytes = canonicalJson(unsigned).toByteArray(StandardCharsets.UTF_8)
        val oldSignature = decodeBase64Url(value.getString("old_signature")); val newSignature = decodeBase64Url(value.getString("new_signature"))
        try { check(oldSignature.size == 64 && newSignature.size == 64 && publicKeyFingerprint(value.getString("new_public_key_pem")) == signingKeyFingerprint && (previousSigningKeyFingerprint == null || publicKeyFingerprint(value.getString("old_public_key_pem")) == previousSigningKeyFingerprint) && verifyEd25519(oldSignature, bytes, value.getString("old_public_key_pem")) && verifyEd25519(newSignature, bytes, value.getString("new_public_key_pem"))) { "BF-RELEASE-TRANSITION" } }
        finally { bytes.fill(0); oldSignature.fill(0); newSignature.fill(0) }
    }

    private fun verifyEd25519(signature: ByteArray, payload: ByteArray, pem: String): Boolean {
        val der = try { decodePublicKeyDer(pem) } catch (_: Throwable) { return false }
        val raw = der.copyOfRange(der.size - 32, der.size)
        return try {
            Ed25519Verify(raw).verify(signature, payload)
            true
        } catch (_: Throwable) { false } finally { raw.fill(0); der.fill(0) }
    }

    private fun downloadArtifactToFile(endpoint: String, token: String, metadata: JSONObject, destination: File, progress: (Long, Long) -> Unit) {
        validateEndpoint(endpoint)
        val expectedBytes = metadata.getLong("bytes")
        check(expectedBytes in 1..MAX_ARTIFACT_BYTES) { "BF-RELEASE-SIZE" }
        check(!destination.exists()) { "BF-RELEASE-DUPLICATE-PATH" }
        val parent = destination.parentFile ?: error("BF-RELEASE-PATH")
        check(parent.exists() || parent.mkdirs()) { "BF-RELEASE-STORAGE" }
        check(parent.isDirectory && !Files.isSymbolicLink(parent.toPath())) { "BF-RELEASE-STORAGE" }
        val temporary = File(destination.parentFile, ".${destination.name}.download-${System.nanoTime()}")
        try {
            val activeToken = java.util.concurrent.atomic.AtomicReference(BifrostSecureStore.get(context, "session_token", token))
            val mirror = BifrostReleaseMirror.endpoint(canonicalBaseFor(endpoint), metadata.getString("sha256"), metadata.getString("path"))
            BifrostArtifactDownloader.download(temporary, expectedBytes, metadata.getString("sha256"),
                connect = { openConnection(endpoint, activeToken.get()) }, progress = progress,
                renewSession = { activeToken.set(BifrostControlClient(context).renewReleaseSession()) },
                connectMirror = mirror?.let { url -> { openMirrorConnection(url) } })
            check(!Files.exists(destination.toPath()) && temporary.renameTo(destination)) { "BF-RELEASE-ATOMIC-WRITE" }
            check(!Files.isSymbolicLink(destination.toPath())) { "BF-RELEASE-PATH" }
        } catch (error: Throwable) {
            temporary.delete()
            throw error
        }
    }

    private fun verifyArtifactFile(file: File, metadata: JSONObject) {
        check(file.isFile && !Files.isSymbolicLink(file.toPath())) { "BF-RELEASE-PATH" }
        check(file.length() == metadata.getLong("bytes")) { "BF-RELEASE-SIZE" }
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buffer = ByteArray(BUFFER_BYTES)
            try {
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            } finally { buffer.fill(0) }
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        check(actual == metadata.getString("sha256")) { "BF-RELEASE-DIGEST" }
    }

    @Suppress("DEPRECATION")
    private fun installApk(file: File, sequence: Long, metadata: JSONObject, automatic: Boolean = false) {
        // Re-read the signed expected metadata immediately before handing the
        // file to PackageInstaller.  Never derive expectations from the file
        // itself: a staging replacement must fail closed.
        verifyArtifactFile(file, metadata)
        val packageFlags = PackageManager.GET_SIGNING_CERTIFICATES
        val archive = context.packageManager.getPackageArchiveInfo(file.absolutePath, packageFlags) ?: error("BF-RELEASE-APK-IDENTITY")
        check(archive.packageName == context.packageName) { "BF-RELEASE-APK-IDENTITY" }
        val installed = context.packageManager.getPackageInfo(context.packageName, packageFlags)
        val archiveSigners = signerSet(archive.signingInfo?.apkContentsSigners)
        val installedSigners = signerSet(installed.signingInfo?.apkContentsSigners)
        check(archiveSigners.isNotEmpty() && archiveSigners == installedSigners) { "BF-RELEASE-APK-SIGNER" }
        check(BifrostUpdateInstallGate.begin()) { "BF-CONNECTION-IN-FLIGHT" }
        try {
            BifrostUpdateVpnShutdown.awaitStopped(context)
            installVerifiedApk(file, sequence, automatic)
        } catch (error: Throwable) {
            BifrostUpdateInstallGate.end()
            BifrostUpdateResume.start(context, failure = true)
            throw error
        }
    }

    private fun installVerifiedApk(file: File, sequence: Long, automatic: Boolean) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(if (automatic)
                PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED else PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
        }
        val sessionId = installer.createSession(params)
        try {
            // API 28/29 do not expose SessionInfo.createdMillis. Persist a
            // local creation time so stale pending sessions can be abandoned
            // safely on those releases after a process restart.
            commitOrThrow(releasePreferences.edit()
                .putInt("pending_session_id", sessionId)
                .putLong("pending_session_started_at", System.currentTimeMillis()))
            installer.openSession(sessionId).use { session ->
                FileInputStream(file).use { input ->
                    session.openWrite("Bifrost-$sequence.apk", 0, file.length()).use { output ->
                        input.copyTo(output, BUFFER_BYTES)
                        session.fsync(output)
                    }
                }
                val callbackIntent = Intent(context, UpdateInstallReceiver::class.java).putExtra(EXTRA_SEQUENCE, sequence)
                val flags = PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
                val callback = PendingIntent.getBroadcast(context, sessionId, callbackIntent, flags)
                session.commit(callback.intentSender)
            }
        } catch (error: Throwable) {
            runCatching { installer.abandonSession(sessionId) }
            throw error
        }
    }

    /** Called only after PackageInstaller has reached a terminal state. */
    fun finalizePackageInstall(sequence: Long, success: Boolean) = synchronized(BifrostAutomaticUpdate.operationGate) {
        if (releasePreferences.getLong("pending_sequence", 0) != sequence) return@synchronized
        BifrostUpdateInstallGate.end()
        val root = File(context.noBackupFilesDir, "bifrost-updates").canonicalFile
        check(root.exists() || root.mkdirs()) { "BF-RELEASE-STORAGE" }
        check(root.isDirectory && !Files.isSymbolicLink(root.toPath())) { "BF-RELEASE-STORAGE" }
        val stagePath = releasePreferences.getString("pending_stage", "").orEmpty()
        val stage = if (stagePath.isBlank()) null else File(stagePath).canonicalFile.also {
            check(it.path.startsWith(root.path + File.separator)) { "BF-RELEASE-PATH" }
            check(!Files.isSymbolicLink(it.toPath())) { "BF-RELEASE-PATH" }
        }
        if (success) {
            if (stage != null && stage.exists()) promoteStaging(stage, sequence)
            val digest = releasePreferences.getString("pending_manifest_digest", "").orEmpty()
            check(digest.matches(Regex("[0-9a-f]{64}"))) { "BF-RELEASE-STATE" }
            val stateEditor = releasePreferences.edit()
            val verified = VerifiedManifest(
                sequence,
                digest,
                releasePreferences.getString("pending_envelope_digest", "").orEmpty(),
                releasePreferences.getString("pending_signing_key_id", "").orEmpty(),
                releasePreferences.getString("pending_signing_key_fingerprint", "").orEmpty(),
                releasePreferences.getLong("pending_delegation_generation", 0),
                releasePreferences.getString("pending_channel", "").orEmpty(),
                releasePreferences.getLong("pending_floor", 0)
            )
            val bootstrapOperation = releasePreferences.getString("pending_bootstrap_operation", "").orEmpty()
            if (bootstrapOperation.isNotBlank() && !bootstrapStore.commit(bootstrapOperation)) throw IllegalStateException("BF-RELEASE-STATE-CORRUPT")
            // Consume the one-shot bootstrap into a terminal tombstone before
            // publishing the durable state.  A crash between these writes is
            // fail-closed (no replay), never a reusable bootstrap record.
            commitReleaseState(verified, digest)
            commitOrThrow(stateEditor
                .remove("pending_sequence").remove("pending_stage").remove("pending_automatic")
                .remove("automatic_confirmation_required")
                .remove("pending_bootstrap_operation")
                .remove("pending_session_id").remove("pending_session_started_at")
                .remove("pending_artifact").remove("pending_envelope_digest").remove("pending_signing_key_id")
                .remove("pending_authority_digest").remove("pending_authority_generation")
                .remove("pending_delegation_generation").remove("pending_signing_key_fingerprint").remove("pending_channel").remove("pending_floor").remove("last_update_error"))
            BifrostSecureStore.remove(context, "release_pending_envelope")
        } else {
            val bootstrapOperation = releasePreferences.getString("pending_bootstrap_operation", "").orEmpty()
            if (bootstrapOperation.isNotBlank()) bootstrapStore.abort(bootstrapOperation)
            if (stage != null && stage.exists()) check(stage.deleteRecursively()) { "BF-RELEASE-CLEANUP" }
            commitOrThrow(releasePreferences.edit().remove("pending_sequence").remove("pending_stage").remove("pending_bootstrap_operation").remove("pending_manifest_digest").remove("pending_automatic")
                .remove("pending_session_id").remove("pending_session_started_at")
                .remove("pending_artifact"))
            BifrostSecureStore.remove(context, "release_pending_envelope")
        }
    }

    private fun cleanupStaleState() {
        val root = File(context.noBackupFilesDir, "bifrost-updates").apply {
            check(exists() || mkdirs()) { "BF-RELEASE-STORAGE" }
            check(isDirectory && !Files.isSymbolicLink(toPath())) { "BF-RELEASE-STORAGE" }
        }
        val now = System.currentTimeMillis()
        val ownedStage = releasePreferences.getString("pending_stage", "")
        root.listFiles()?.filter { it.absolutePath != ownedStage && it.name.startsWith(".staging-") && now - it.lastModified() > STALE_AGE_MS }
            ?.forEach { rejectUpdatePath(root, it); check(it.deleteRecursively()) { "BF-RELEASE-CLEANUP" } }
        val installer = context.packageManager.packageInstaller
        val pendingSessionId = releasePreferences.getInt("pending_session_id", -1).takeIf { it > 0 }
        val pendingOperation = releasePreferences.getString("pending_bootstrap_operation", "").orEmpty()
        var terminalProof: ReleaseBootstrapRecoveryProof? = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val owned = pendingSessionId?.let { id -> installer.mySessions.firstOrNull { it.sessionId == id } }
            if (pendingSessionId != null && owned == null) {
                // A missing session is a terminal/absent proof only for the
                // exact persisted owner.  The state machine still requires
                // its reservation TTL to have elapsed.
                terminalProof = ReleaseBootstrapRecoveryProof(pendingOperation, pendingSessionId, sessionTerminal = true, sessionAbandoned = false, sessionAbsent = true)
            } else if (owned != null && BifrostUpdateCleanup.isStale(now, owned.createdMillis, STALE_AGE_MS)) {
                check(runCatching { installer.abandonSession(owned.sessionId) }.isSuccess) { "BF-RELEASE-CLEANUP" }
                terminalProof = ReleaseBootstrapRecoveryProof(pendingOperation, owned.sessionId, sessionTerminal = true, sessionAbandoned = true, sessionAbsent = false)
            } else if (pendingSessionId == null && pendingOperation.isNotBlank()) {
                // Crash before PackageInstaller session creation: there is no
                // external owner, but the persisted reservation must still be
                // old enough before this explicit absence proof can release it.
                terminalProof = ReleaseBootstrapRecoveryProof(pendingOperation, null, sessionTerminal = true, sessionAbandoned = false, sessionAbsent = true)
            }
        } else {
            // SessionInfo has no creation timestamp before API 30. Only
            // abandon the session created by this client using its local time.
            val startedAt = releasePreferences.getLong("pending_session_started_at", 0)
            if (pendingSessionId != null && BifrostUpdateCleanup.shouldAbandonLegacySession(Build.VERSION.SDK_INT, now, startedAt, STALE_AGE_MS)) {
                check(runCatching { installer.abandonSession(pendingSessionId) }.isSuccess) { "BF-RELEASE-CLEANUP" }
                terminalProof = ReleaseBootstrapRecoveryProof(pendingOperation, pendingSessionId, sessionTerminal = true, sessionAbandoned = true, sessionAbsent = false)
            } else if (pendingSessionId == null && pendingOperation.isNotBlank() && now - startedAt > STALE_AGE_MS) {
                terminalProof = ReleaseBootstrapRecoveryProof(pendingOperation, null, sessionTerminal = true, sessionAbandoned = false, sessionAbsent = true)
            }
        }
        if (terminalProof != null) {
            val recovered = pendingOperation.isBlank() || bootstrapStore.recoverStale(terminalProof!!)
            if (recovered) clearPendingInstallState(root)
        }
    }

    /** Clear only after a matching terminal PackageInstaller/absence proof and
     * (for a bootstrap) a successful state-machine recovery. */
    private fun clearPendingInstallState(root: File) {
        val stagePath = releasePreferences.getString("pending_stage", "").orEmpty()
        if (stagePath.isNotBlank()) {
            val stage = File(stagePath).canonicalFile
            rejectUpdatePath(root, stage)
            check(!stage.exists() || stage.deleteRecursively()) { "BF-RELEASE-CLEANUP" }
        }
        commitOrThrow(releasePreferences.edit()
            .remove("pending_sequence").remove("pending_stage").remove("pending_bootstrap_operation")
            .remove("pending_session_id").remove("pending_session_started_at")
            .remove("pending_artifact").remove("pending_manifest_digest")
            .remove("pending_envelope_digest").remove("pending_authority_digest")
            .remove("pending_authority_generation").remove("pending_delegation_generation")
            .remove("pending_signing_key_id").remove("pending_signing_key_fingerprint")
            .remove("pending_channel").remove("pending_floor"))
        BifrostSecureStore.remove(context, "release_pending_envelope")
    }

    private fun promoteStaging(staging: File, sequence: Long) {
        val root = File(context.noBackupFilesDir, "bifrost-updates").canonicalFile
        val active = File(root, "active").canonicalFile
        val backup = File(root, "backup-$sequence-${System.nanoTime()}").canonicalFile
        check(staging.canonicalPath.startsWith(root.path + File.separator)) { "BF-RELEASE-PATH" }
        check(!Files.isSymbolicLink(staging.toPath()) && !Files.isSymbolicLink(root.toPath())) { "BF-RELEASE-PATH" }
        var moved = false
        try {
            if (active.exists()) { check(active.renameTo(backup)) { "BF-RELEASE-BACKUP" }; moved = true }
            check(staging.renameTo(active)) { "BF-RELEASE-PROMOTE" }
        } catch (error: Throwable) {
            if (moved && !active.exists() && backup.exists()) check(backup.renameTo(active)) { "BF-RELEASE-ROLLBACK" }
            throw error
        }
    }

    private fun requestJson(endpoint: String, token: String): JSONObject {
        val response = requestBytes(endpoint, token)
        val bytes = response.bytes
        return try {
            val text = strictUtf8(bytes)
            check(text.toByteArray(StandardCharsets.UTF_8).contentEquals(bytes)) { "BF-RELEASE-UTF8" }
            check(response.contentType == "application/json") { "BF-RELEASE-CONTENT-TYPE" }
            StrictJsonValidator(text, "BF-RELEASE-JSON").validate()
            JSONObject(text)
        } finally { bytes.fill(0) }
    }

    private data class HttpResponseBytes(val bytes: ByteArray, val contentType: String?)

    private fun requestBytes(endpoint: String, token: String): HttpResponseBytes =
        BifrostControlReadRetry.run { attempt, received -> requestBytesOnce(endpoint, token, attempt, received) }

    private fun requestBytesOnce(endpoint: String, token: String, networkAttempt: Int, received: () -> Unit): HttpResponseBytes {
        validateEndpoint(endpoint)
        var connection = openConnection(endpoint, token, networkAttempt)
        try {
            val initialStatus = connection.responseCode
            received()
            if (initialStatus == 401) {
                connection.disconnect()
                connection = openConnection(endpoint, BifrostControlClient(context).renewReleaseSession(), networkAttempt)
            }
            val status = connection.responseCode
            check(status in 200..299) { if (status in 300..399) "BF-RELEASE-REDIRECT" else "BF-RELEASE-HTTP" }
            val contentType = connection.contentType?.substringBefore(';')?.trim()?.lowercase(Locale.US)
            check(connection.contentLengthLong <= MAX_MANIFEST_BYTES || connection.contentLengthLong < 0) { "BF-RELEASE-MANIFEST-SIZE" }
            return connection.inputStream.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(BUFFER_BYTES)
                try {
                    var count = 0L
                    while (true) { val read = input.read(buffer); if (read < 0) break; count += read; check(count <= MAX_MANIFEST_BYTES) { "BF-RELEASE-MANIFEST-SIZE" }; output.write(buffer, 0, read) }
                    HttpResponseBytes(output.toByteArray(), contentType)
                } finally { buffer.fill(0); output.reset() }
            }
        } finally { connection.disconnect() }
    }

    private fun canonicalBaseFor(endpoint: String): String = URI(endpoint).let { "${it.scheme}://${it.rawAuthority}" }

    private fun openMirrorConnection(endpoint: String): HttpURLConnection {
        BifrostReleaseMirror.validate(endpoint)
        return BifrostUnderlyingNetwork.openControlConnection(context, URL(endpoint)).apply {
            requestMethod = "GET"
            instanceFollowRedirects = false
            connectTimeout = 10_000
            readTimeout = 20_000
            useCaches = false
            setRequestProperty("Accept", "application/octet-stream")
            // Deliberately no Authorization or sender-proof headers on the public mirror.
        }
    }

    private fun openConnection(endpoint: String, token: String, networkAttempt: Int = 0): HttpURLConnection = BifrostUnderlyingNetwork.openControlConnection(context, URL(endpoint), networkAttempt).apply {
        validateEndpoint(endpoint)
        requestMethod = "GET"
        instanceFollowRedirects = false
        connectTimeout = TimeUnit.SECONDS.toMillis(10).toInt()
        readTimeout = TimeUnit.SECONDS.toMillis(30).toInt()
        useCaches = false
        setRequestProperty("Authorization", "Bearer $token")
        setRequestProperty("Accept", "application/json, application/octet-stream")
        this@BifrostUpdateManager.addSenderProof(this, endpoint, token)
    }

    internal data class DurableReleaseState(
        val sequence: Long,
        val manifestDigest: String,
        val envelopeDigest: String,
        val authorityDigest: String,
        val authorityGeneration: Long,
        val rootKeyId: String,
        val rootFingerprint: String,
        val delegationGeneration: Long,
        val signingKeyId: String,
        val signingKeyFingerprint: String,
        val channel: String,
        val floor: Long,
        val stateGeneration: Long,
        val slot: String,
        val checksum: String
    )

    private fun readDurableReleaseState(): DurableReleaseState? {
        val present = mutableListOf<DurableReleaseState>()
        var malformed = false
        for (slot in listOf("a", "b")) {
            val secureText = BifrostSecureStore.get(context, "release_state_$slot", "")
            val legacyText = releasePreferences.getString("release_state_$slot", null)
            if (legacyText != null && secureText.isBlank()) { malformed = true; continue }
            val text = secureText.takeIf { it.isNotBlank() } ?: continue
            try {
                val value = JSONObject(text); val names = value.keys().asSequence().toSet()
            check(names == setOf("sequence", "manifest_digest", "envelope_digest", "authority_digest", "authority_generation", "root_key_id", "root_fingerprint", "delegation_generation", "signing_key_id", "signing_key_fingerprint", "channel", "floor", "state_generation", "slot", "checksum"))
                val sequence = value.getLong("sequence"); val generation = value.getLong("state_generation"); val digest = value.getString("manifest_digest")
                val envelopeDigest = value.getString("envelope_digest"); val authorityDigest = value.getString("authority_digest"); val authorityGeneration = value.getLong("authority_generation"); val rootId = value.getString("root_key_id"); val rootFingerprint = value.getString("root_fingerprint")
                val delegationGeneration = value.getLong("delegation_generation"); val signingKeyId = value.getString("signing_key_id"); val signingKeyFingerprint = value.getString("signing_key_fingerprint"); val channel = value.getString("channel"); val floor = value.getLong("floor"); val slotName = value.getString("slot"); val checksum = value.getString("checksum")
                check(sequence >= 0 && generation > 0 && delegationGeneration > 0 && authorityGeneration > 0 && floor > 0 && slotName in setOf("a", "b") && digest.matches(Regex("[0-9a-f]{64}")) && envelopeDigest.matches(Regex("[0-9a-f]{64}")) && authorityDigest.matches(Regex("[0-9a-f]{64}")) && rootFingerprint.matches(Regex("[0-9a-f]{64}")) && signingKeyFingerprint.matches(Regex("[0-9a-f]{64}")) && checksum.matches(Regex("[0-9a-f]{64}")) && channel in setOf("stable", "beta", "test"))
                val expected = sha256(canonicalJson(JSONObject(text).apply { remove("checksum") }))
                check(expected == checksum)
                present += DurableReleaseState(sequence, digest, envelopeDigest, authorityDigest, authorityGeneration, rootId, rootFingerprint, delegationGeneration, signingKeyId, signingKeyFingerprint, channel, floor, generation, slotName, checksum)
            } catch (_: Throwable) { malformed = true }
        }
        if (malformed || releasePreferences.contains("release_sequence")) error("BF-RELEASE-STATE")
        val securePointer = BifrostSecureStore.get(context, "release_state_pointer", "")
        if (releasePreferences.contains("release_state_pointer") && securePointer.isBlank()) malformed = true
        securePointer.takeIf { it.isNotBlank() }?.let { pointer ->
            val parts = pointer.split(":")
            check(parts.size == 2 && parts[0] in setOf("a", "b") && parts[1].toLongOrNull()?.let { it > 0 } == true) { "BF-RELEASE-STATE" }
        }
        if (malformed) error("BF-RELEASE-STATE")
        if (present.isEmpty()) {
            check(securePointer.isBlank()) { "BF-RELEASE-STATE" }
            return null
        }
        return present.maxBy { it.stateGeneration }
    }

    private fun commitReleaseState(verified: VerifiedManifest, manifestDigest: String) {
        check(verified.sequence > 0 && manifestDigest.matches(Regex("[0-9a-f]{64}")) && verified.envelopeDigest.matches(Regex("[0-9a-f]{64}")) && !ReleaseContract.TRUST_ROOT_FINGERPRINT.isNullOrBlank()) { "BF-RELEASE-STATE" }
        val previous = readDurableReleaseState(); val generation = (previous?.stateGeneration ?: 0L) + 1
        val slot = if (generation % 2L == 0L) "a" else "b"
        val authorityDigest = verified.plan?.authorityDigest ?: releasePreferences.getString("pending_authority_digest", "").orEmpty()
        val authorityGeneration = verified.plan?.authorityGeneration ?: releasePreferences.getLong("pending_authority_generation", 0L)
        check(authorityDigest.matches(Regex("[0-9a-f]{64}")) && authorityGeneration > 0) { "BF-RELEASE-STATE" }
        val base = JSONObject().put("sequence", verified.sequence).put("manifest_digest", manifestDigest).put("envelope_digest", verified.envelopeDigest).put("authority_digest", authorityDigest).put("authority_generation", authorityGeneration).put("root_key_id", ReleaseContract.TRUST_ROOT_KEY_ID).put("root_fingerprint", ReleaseContract.TRUST_ROOT_FINGERPRINT).put("delegation_generation", verified.delegationGeneration).put("signing_key_id", verified.signingKeyId).put("signing_key_fingerprint", verified.signingKeyFingerprint).put("channel", verified.channel).put("floor", verified.floor).put("state_generation", generation).put("slot", slot)
        val checksum = sha256(canonicalJson(base))
        base.put("checksum", checksum)
        BifrostSecureStore.putBatch(context, mapOf("release_state_$slot" to base.toString(), "release_state_pointer" to "$slot:$generation"))
    }

    private fun addSenderProof(connection: HttpURLConnection, endpoint: String, token: String) {
        val uri = try { URI(endpoint) } catch (_: Throwable) { throw IllegalStateException("BF-RELEASE-URL") }
        val pathAndQuery = (uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
        val timestamp = System.currentTimeMillis().toString()
        val nonce = randomToken(18)
        val operation = randomToken(12)
        val digest = sha256("")
        val message = "BIFROST-PROOF-v1|${sha256(token)}|GET|$pathAndQuery|$digest|$timestamp|$nonce|$operation"
        connection.setRequestProperty("X-Bifrost-Proof-Version", "1")
        connection.setRequestProperty("X-Bifrost-Proof-Timestamp", timestamp)
        connection.setRequestProperty("X-Bifrost-Proof-Nonce", nonce)
        connection.setRequestProperty("X-Bifrost-Proof-Operation", operation)
        connection.setRequestProperty("X-Bifrost-Proof-Digest", digest)
        connection.setRequestProperty("X-Bifrost-Proof-Signature", DeviceKeys.sign(context, message))
    }

    private fun requireSecureUrl(value: String): URI {
        val uri = try { URI(value) } catch (_: Throwable) { throw IllegalStateException("BF-RELEASE-URL") }
        check(uri.userInfo == null && uri.query == null && uri.fragment == null && !uri.host.isNullOrBlank()) { "BF-RELEASE-URL" }
        val loopback = uri.host.equals("127.0.0.1", true) || uri.host.equals("localhost", true) || uri.host == "::1"
        val https = uri.scheme.equals("https", true)
        val httpDebug = BuildConfig.DEBUG && loopback && uri.scheme.equals("http", true)
        check(https || httpDebug) { "BF-RELEASE-HTTPS" }
        check(uri.path.isNullOrEmpty() || uri.path == "/") { "BF-RELEASE-URL" }
        val port = if (uri.port == -1) if (https) 443 else 80 else uri.port
        if (https) check(port == 443) { "BF-RELEASE-URL" }
        return URI(uri.scheme.lowercase(Locale.US), null, uri.host.lowercase(Locale.US), port, "/", null, null)
    }

    private fun validateEndpoint(value: String) {
        val uri = try { URI(value) } catch (_: Throwable) { throw IllegalStateException("BF-RELEASE-URL") }
        check(uri.userInfo == null && uri.query == null && uri.fragment == null && !uri.host.isNullOrBlank()) { "BF-RELEASE-URL" }
        val loopback = uri.host.equals("127.0.0.1", true) || uri.host.equals("localhost", true) || uri.host == "::1"
        val https = uri.scheme.equals("https", true)
        val httpDebug = BuildConfig.DEBUG && loopback && uri.scheme.equals("http", true)
        check(https || httpDebug) { "BF-RELEASE-HTTPS" }
        val port = if (uri.port == -1) if (https) 443 else 80 else uri.port
        if (https) check(port == 443) { "BF-RELEASE-URL" }
        val expected = trustedOrigin
        if (expected != null) {
            check(expected.scheme.equals(uri.scheme, true) && expected.host.equals(uri.host, true) && expected.port == port) { "BF-RELEASE-ORIGIN" }
        }
    }

    private fun compareVersions(left: String, right: String): Int = compareBifrostReleaseVersions(left, right)

    private fun randomToken(bytes: Int): String {
        require(bytes in 8..64) { "BF-RELEASE-PROOF" }
        val value = ByteArray(bytes)
        return try {
            SecureRandom().nextBytes(value)
            Base64.encodeToString(value, Base64.NO_WRAP or Base64.NO_PADDING)
                .replace('+', '-').replace('/', '_')
        } finally { value.fill(0) }
    }

    private fun sha256(value: String): String {
        val input = value.toByteArray(StandardCharsets.UTF_8)
        return try {
            MessageDigest.getInstance("SHA-256").digest(input).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
        } finally { input.fill(0) }
    }

    private fun canonicalJson(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(separator = ",", prefix = "{", postfix = "}") { key -> BifrostJsonString.quote(key) + ":" + canonicalJson(value.get(key)) }
        is org.json.JSONArray -> (0 until value.length()).joinToString(separator = ",", prefix = "[", postfix = "]") { canonicalJson(value.get(it)) }
        is String -> BifrostJsonString.quote(value)
        is Boolean, is Number -> value.toString()
        else -> error("BF-RELEASE-JSON")
    }

        private fun safeRelative(value: String): String = bifrostSafeReleasePath(value)

    /** Compare the complete APK signer set canonically; certificate order is not identity. */
    private fun signerSet(signers: Array<android.content.pm.Signature>?): List<String> =
        signers.orEmpty().map { signer ->
            val bytes = signer.toByteArray()
            try {
                val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
                try { digest.joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) } }
                finally { digest.fill(0) }
            } finally { bytes.fill(0) }
        }.sorted()

    private fun decodeBase64Url(value: String): ByteArray {
        check(value.isNotEmpty() && value.length <= 4096 && value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) { "BF-RELEASE-BASE64" }
        val decoded = try { java.util.Base64.getUrlDecoder().decode(value) } catch (_: Throwable) { throw IllegalStateException("BF-RELEASE-BASE64") }
        val canonical = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(decoded)
        check(canonical == value) { "BF-RELEASE-BASE64" }
        return decoded
    }

    private fun requireExactKeys(value: JSONObject, allowed: Set<String>, required: Set<String>, code: String) {
        val keys = mutableSetOf<String>()
        val iterator = value.keys()
        while (iterator.hasNext()) {
            val key = iterator.next()
            check(keys.add(key) && key in allowed) { code }
        }
        check(required.all { it in keys }) { code }
    }

    private fun isIntegralJsonNumber(value: Any?): Boolean =
        value is Int || value is Long || value is Short || value is Byte

    private fun rejectNonCanonicalNumbers(text: String) {
        var index = 0
        while (index < text.length) {
            if (text[index] == '"') {
                index += 1
                while (index < text.length) {
                    val ch = text[index++]
                    if (ch == '\\') index += if (index < text.length && text[index] == 'u') 4 else 1
                    else if (ch == '"') break
                }
                continue
            }
            if (text[index] == '-' || text[index].isDigit()) {
                val start = index++
                while (index < text.length && (text[index].isDigit() || text[index] in ".eE+-")) index += 1
                val token = text.substring(start, index)
                if (!token.matches(Regex("(?:0|-?[1-9][0-9]*)"))) throw IllegalStateException("BF-RELEASE-FIELDS")
                continue
            }
            index += 1
        }
    }

    private fun strictUtf8(bytes: ByteArray): String = try {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: Throwable) { throw IllegalStateException("BF-RELEASE-UTF8") }

    private fun commitOrThrow(editor: android.content.SharedPreferences.Editor) {
        check(editor.commit()) { "BF-RELEASE-STATE" }
    }

    private fun rejectUpdatePath(root: File, candidate: File) {
        val rootPath = root.canonicalPath + File.separator
        check(candidate.canonicalPath.startsWith(rootPath) && !Files.isSymbolicLink(candidate.toPath())) { "BF-RELEASE-PATH" }
    }

    companion object {
        internal const val EXTRA_SEQUENCE = "bifrost.release.sequence"
        private const val RELEASE_PREFS = "bifrost-release"
        private const val BUFFER_BYTES = 64 * 1024
        private const val MAX_MANIFEST_BYTES = 1L * 1024 * 1024
        private const val MAX_ARTIFACTS = 64
        private const val MAX_ARTIFACT_BYTES = 512L * 1024 * 1024
        private const val MAX_TOTAL_BYTES = 1L * 1024 * 1024 * 1024
        private const val STALE_AGE_MS = 24L * 60 * 60 * 1000
    }
}

/**
 * Pure, deterministic release ordering shared by the update path and JVM tests.
 * It intentionally implements the SemVer 2.0 precedence rules needed by the
 * signed manifest contract and rejects ambiguous spellings instead of
 * normalising them.
 */
internal fun compareBifrostReleaseVersions(left: String, right: String): Int {
    data class Parsed(val core: IntArray, val pre: List<String>)
    fun parse(value: String): Parsed {
        check(value.length in 5..128) { "BF-RELEASE-VERSION" }
        val split = value.split('-', limit = 2)
        val core = split[0].split('.')
        check(core.size == 3 && core.all { it.isNotEmpty() && (it == "0" || !it.startsWith('0')) && it.all(Char::isDigit) }) { "BF-RELEASE-VERSION" }
        val coreInts = core.map { it.toIntOrNull() ?: error("BF-RELEASE-VERSION") }.toIntArray()
        val pre = if (split.size == 1) emptyList() else split[1].split('.')
        check(split.size == 1 || (pre.isNotEmpty() && pre.all { it.isNotEmpty() && it.all { ch -> ch.isLetterOrDigit() || ch == '-' } && !(it.length > 1 && it.all(Char::isDigit) && it.startsWith('0')) })) { "BF-RELEASE-VERSION" }
        return Parsed(coreInts, pre)
    }
    val a = parse(left)
    val b = parse(right)
    for (index in 0..2) a.core[index].compareTo(b.core[index]).also { if (it != 0) return it }
    if (a.pre.isEmpty() && b.pre.isEmpty()) return 0
    if (a.pre.isEmpty()) return 1
    if (b.pre.isEmpty()) return -1
    for (index in 0 until maxOf(a.pre.size, b.pre.size)) {
        if (index >= a.pre.size) return -1
        if (index >= b.pre.size) return 1
        val ai = a.pre[index]
        val bi = b.pre[index]
        val an = ai.all(Char::isDigit)
        val bn = bi.all(Char::isDigit)
        if (an && bn) {
            ai.length.compareTo(bi.length).also { if (it != 0) return it }
            ai.compareTo(bi).also { if (it != 0) return it }
        } else if (an != bn) return if (an) -1 else 1
        else ai.compareTo(bi).also { if (it != 0) return it }
    }
    return 0
}

/** Pure cleanup policy kept separate so API 28/29 behavior is executable in JVM tests. */
internal object BifrostUpdateCleanup {
    internal fun usesSessionCreatedMillis(apiLevel: Int): Boolean = apiLevel >= 30

    internal fun isStale(nowMillis: Long, timestampMillis: Long, staleAgeMillis: Long): Boolean =
        timestampMillis > 0 && nowMillis >= timestampMillis && nowMillis - timestampMillis > staleAgeMillis

    internal fun shouldAbandonLegacySession(apiLevel: Int, nowMillis: Long, startedAtMillis: Long, staleAgeMillis: Long): Boolean =
        !usesSessionCreatedMillis(apiLevel) && isStale(nowMillis, startedAtMillis, staleAgeMillis)
}

class UpdateInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        java.util.concurrent.Executors.newSingleThreadExecutor().let { worker ->
            worker.execute {
                try {
                    synchronized(BifrostAutomaticUpdate.operationGate) { handle(context, intent) }
                } catch (error: Throwable) {
                    BifrostUpdateInstallGate.end()
                    BifrostDiagnostics.record(context, "update-install-result", error)
                    BifrostUpdateResume.start(context, failure = true)
                } finally { pending.finish(); worker.shutdown() }
            }
        }
    }
    private fun handle(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val sequence = intent.getLongExtra(BifrostUpdateManager.EXTRA_SEQUENCE, 0)
        val prefs = context.getSharedPreferences("bifrost-release", Context.MODE_PRIVATE)
        if (sequence <= 0 || prefs.getLong("pending_sequence", 0) != sequence) return
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            val confirmation = if (Build.VERSION.SDK_INT >= 33) {
                intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(Intent.EXTRA_INTENT) as? Intent
            }
            if (confirmation != null && !prefs.getBoolean("pending_automatic", false) &&
                BifrostAppVisibility.visible && runCatching {
                    context.startActivity(confirmation.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                }.isSuccess) {
                return
            }
            // OEMs may require confirmation even for a self-update. Abandon the
            // exact session and restore connectivity; a later tap starts a new
            // verified manual installation instead of holding the tunnel down.
            val session = prefs.getInt("pending_session_id", -1)
            if (session > 0) context.packageManager.packageInstaller.abandonSession(session)
            check(prefs.edit().putBoolean("automatic_confirmation_required", true).commit()) { "BF-RELEASE-STATE" }
            BifrostUpdateManager(context).finalizePackageInstall(sequence, success = false)
            BifrostUpdateResume.start(context, failure = true)
            BifrostAutomaticUpdate.showUpdateRequired(context)
            return
        }
        val success = status == PackageInstaller.STATUS_SUCCESS
        BifrostUpdateManager(context).finalizePackageInstall(sequence, success)
        BifrostUpdateResume.start(context, failure = !success)
        if (success) context.getSystemService(android.app.NotificationManager::class.java).cancel(1004)
        if (!success) check(context.getSharedPreferences("bifrost-release", Context.MODE_PRIVATE).edit()
            .putString("last_update_error", "BF-RELEASE-INSTALL-FAILED")
            .commit()) { "BF-RELEASE-STATE" }
    }
}
