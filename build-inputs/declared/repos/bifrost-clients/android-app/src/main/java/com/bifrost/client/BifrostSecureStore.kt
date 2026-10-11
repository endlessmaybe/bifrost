package com.bifrost.client

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Keystore-backed storage for enrollment/session material.  The encrypted
 * preference set is authoritative.  Legacy values are only a recoverable
 * migration source and are scrubbed before any encrypted deletion is
 * committed, so a failed cleanup cannot resurrect a logged-out value.
 */
object BifrostSecureStore {
    private const val NAME = "bifrost-secure-v1"
    private const val LEGACY = "bifrost-control"
    private const val WRITE_ERROR = "BF-SECURE-STORE-WRITE"
    private const val READ_ERROR = "BF-SECURE-STORE-READ"
    @Volatile private var testReadFailure = false

    internal fun failReadsForTest(value: Boolean) {
        check(BuildConfig.DEBUG && BuildConfig.BIFROST_TEST_VARIANT) { "BF-TEST-SCOPE" }
        testReadFailure = value
    }

    /**
     * UI preferences are part of the same encrypted authority as account
     * state.  Keeping the allow-list here prevents a new UI field from
     * silently falling back to a plaintext preference namespace.
     */
    internal val UiKeys: Set<String> = setOf(
        "core", "mode", "source", "country", "front_source", "app_policy", "app_policy_enabled",
        "connection_type", "route_mode", "candidate_mode", "candidate_label",
        "include_apps", "exclude_apps", "theme", "design_direction", "application_policy_snapshot",
        "application_policy_bindings", "connection_transaction_id",
        "release_state_a", "release_state_b", "release_state_pointer",
        "release_pending_envelope", "release_bootstrap_record", "release_bootstrap_state", "update_resume_intent",
    )

    private fun preferences(context: Context): SharedPreferences = EncryptedSharedPreferences.create(
        context,
        NAME,
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    /** Minimal seam shared by production and JVM failure-injection tests. */
    internal interface Backend {
        fun secureValue(key: String): String?
        fun legacyValue(key: String): String?
        fun commitSecure(values: Map<String, String?>): Boolean
        fun scrubLegacy(keys: Set<String>): Boolean
    }

    /** The state machine is intentionally independent of Android preferences. */
    internal object Transaction {
        fun read(backend: Backend, key: String): String? {
            return readBatch(backend, setOf(key))[key]
        }

        /**
         * Read/migrate a tuple as one transaction.  Device identity must not
         * be migrated one preference at a time: if a later legacy field is
         * corrupt, an earlier field must remain recoverable rather than being
         * silently scrubbed.  The encrypted writes happen as one commit and
         * legacy removal happens only after that commit succeeds.
         */
        fun readBatch(backend: Backend, keys: Set<String>): Map<String, String?> {
            val secure = keys.associateWith { backend.secureValue(it) }
            val legacy = keys.associateWith { backend.legacyValue(it) }
            val toMigrate = keys.filter { secure[it] == null && legacy[it] != null }
            if (toMigrate.isNotEmpty() && !backend.commitSecure(toMigrate.associateWith { legacy[it] })) {
                throw IllegalStateException(WRITE_ERROR)
            }
            if (legacy.values.any { it != null } && !backend.scrubLegacy(keys)) {
                throw IllegalStateException(WRITE_ERROR)
            }
            return keys.associateWith { secure[it] ?: legacy[it] }
        }

        fun apply(backend: Backend, values: Map<String, String?>) {
            val secureValues = values.filterValues { it != null }
            if (secureValues.isNotEmpty() && !backend.commitSecure(secureValues)) {
                throw IllegalStateException(WRITE_ERROR)
            }
            // Null entries are deletions, but deletion is deferred until all
            // legacy copies have been synchronously scrubbed.
            if (!backend.scrubLegacy(values.keys)) {
                throw IllegalStateException(WRITE_ERROR)
            }
            val removals = values.filterValues { it == null }.keys
            if (removals.isNotEmpty() && !backend.commitSecure(removals.associateWith { null })) {
                throw IllegalStateException(WRITE_ERROR)
            }
        }
    }

    private class PreferencesBackend(
        private val secure: SharedPreferences,
        private val legacy: SharedPreferences,
    ) : Backend {
        override fun secureValue(key: String): String? = secure.getString(key, null)

        override fun legacyValue(key: String): String? = legacy.getString(key, null)

        override fun commitSecure(values: Map<String, String?>): Boolean {
            val editor = secure.edit()
            values.forEach { (key, value) ->
                if (value == null) editor.remove(key) else editor.putString(key, value)
            }
            return editor.commit()
        }

        override fun scrubLegacy(keys: Set<String>): Boolean {
            val editor = legacy.edit()
            keys.forEach { editor.remove(it) }
            return editor.commit()
        }
    }

    @Synchronized
    fun get(context: Context, key: String, default: String = ""): String {
        requireKey(key)
        if (BuildConfig.DEBUG && BuildConfig.BIFROST_TEST_VARIANT && testReadFailure) throw IllegalStateException(READ_ERROR)
        try {
            val backend = PreferencesBackend(
                preferences(context),
                context.getSharedPreferences(LEGACY, Context.MODE_PRIVATE),
            )
            return Transaction.read(backend, key) ?: default
        } catch (error: IllegalStateException) {
            if (error.message == WRITE_ERROR) throw error
            throw IllegalStateException(READ_ERROR)
        } catch (_: Throwable) {
            throw IllegalStateException(READ_ERROR)
        }
    }

    /** Checked tuple read used for all-or-nothing legacy identity migration. */
    @Synchronized
    internal fun readBatch(context: Context, keys: Set<String>): Map<String, String?> {
        require(keys.isNotEmpty() && keys.all(::validKey)) { READ_ERROR }
        if (BuildConfig.DEBUG && BuildConfig.BIFROST_TEST_VARIANT && testReadFailure) throw IllegalStateException(READ_ERROR)
        try {
            val backend = PreferencesBackend(
                preferences(context),
                context.getSharedPreferences(LEGACY, Context.MODE_PRIVATE),
            )
            return Transaction.readBatch(backend, keys)
        } catch (error: IllegalStateException) {
            if (error.message == WRITE_ERROR) throw error
            throw IllegalStateException(READ_ERROR)
        } catch (_: Throwable) {
            throw IllegalStateException(READ_ERROR)
        }
    }

    /** Scrub legacy plaintext without migrating it into the encrypted store. */
    @Synchronized
    internal fun scrubLegacy(context: Context, keys: Set<String>) {
        require(keys.isNotEmpty() && keys.all(::validKey)) { WRITE_ERROR }
        try {
            val backend = PreferencesBackend(
                preferences(context),
                context.getSharedPreferences(LEGACY, Context.MODE_PRIVATE),
            )
            if (!backend.scrubLegacy(keys)) throw IllegalStateException(WRITE_ERROR)
        } catch (error: IllegalStateException) {
            if (error.message == WRITE_ERROR) throw error
            throw IllegalStateException(WRITE_ERROR)
        } catch (_: Throwable) {
            throw IllegalStateException(WRITE_ERROR)
        }
    }

    @Synchronized
    fun put(context: Context, key: String, value: String) {
        putBatch(context, mapOf(key to value))
    }

    @Synchronized
    fun remove(context: Context, key: String) {
        putBatch(context, mapOf(key to null))
    }

    @Synchronized
    fun putBatch(context: Context, values: Map<String, String?>) {
        require(values.isNotEmpty() && values.keys.all(::validKey)) { WRITE_ERROR }
        try {
            val backend = PreferencesBackend(
                preferences(context),
                context.getSharedPreferences(LEGACY, Context.MODE_PRIVATE),
            )
            Transaction.apply(backend, values)
        } catch (error: IllegalStateException) {
            if (error.message == WRITE_ERROR) throw error
            throw IllegalStateException(WRITE_ERROR)
        } catch (_: Throwable) {
            throw IllegalStateException(WRITE_ERROR)
        }
    }

    @Synchronized
    fun clear(context: Context, keys: Iterable<String>) {
        val selected = keys.toList()
        require(selected.isNotEmpty() && selected.all(::validKey)) { WRITE_ERROR }
        try {
            val backend = PreferencesBackend(
                preferences(context),
                context.getSharedPreferences(LEGACY, Context.MODE_PRIVATE),
            )
            Transaction.apply(backend, selected.associateWith { null })
        } catch (error: IllegalStateException) {
            if (error.message == WRITE_ERROR) throw error
            throw IllegalStateException(WRITE_ERROR)
        } catch (_: Throwable) {
            throw IllegalStateException(WRITE_ERROR)
        }
    }

    /**
     * Migrate a legacy preference namespace into the encrypted store.  The
     * secure commit is verified before the legacy namespace is scrubbed; a
     * failed scrub is surfaced and never reported as a successful migration.
     */
    @Synchronized
    internal fun migrateLegacyPreferences(context: Context, legacyName: String, keys: Set<String>) {
        require(legacyName.isNotBlank() && legacyName.length <= 64 && keys.isNotEmpty() && keys.all(::validKey)) { WRITE_ERROR }
        try {
            val legacy = context.getSharedPreferences(legacyName, Context.MODE_PRIVATE)
            val values = keys.mapNotNull { key ->
                val value = legacy.getString(key, null)
                if (value == null) null else key to value
            }.toMap()
            if (values.isEmpty()) return
            val backend = PreferencesBackend(preferences(context), legacy)
            // The encrypted preference set is authoritative.  readBatch only
            // fills missing encrypted keys; a stale legacy value can never
            // overwrite a value already protected by the current keystore.
            Transaction.readBatch(backend, keys)
        } catch (error: IllegalStateException) {
            if (error.message == WRITE_ERROR) throw error
            throw IllegalStateException(WRITE_ERROR)
        } catch (_: Throwable) {
            throw IllegalStateException(WRITE_ERROR)
        }
    }

    private fun requireKey(key: String) {
        require(validKey(key)) { READ_ERROR }
    }

    private fun validKey(key: String): Boolean = key.isNotBlank() && key.length <= 128 && key.none(Char::isISOControl)
}
