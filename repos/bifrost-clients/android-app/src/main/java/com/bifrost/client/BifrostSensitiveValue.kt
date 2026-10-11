package com.bifrost.client

/**
 * Owns short-lived recovery/pairing values that may be shown by the UI.
 * Values are never persisted and are invalidated on expiry or backgrounding.
 */
internal class BifrostSensitiveValueStore(
    private val now: () -> Long = { System.currentTimeMillis() },
    private val ttlMs: Long = DEFAULT_TTL_MS,
) {
    private var recovery: String? = null
    private var pairing: String? = null
    private var recoveryExpiry = 0L
    private var pairingExpiry = 0L

    fun publishRecovery(value: String): Boolean {
        if (!isSafe(value) || ttlMs <= 0L) {
            recovery = null
            recoveryExpiry = 0L
            return false
        }
        recovery = value
        recoveryExpiry = now() + ttlMs
        return true
    }

    fun publishPairing(value: String): Boolean {
        if (!isSafe(value) || ttlMs <= 0L) {
            pairing = null
            pairingExpiry = 0L
            return false
        }
        pairing = value
        pairingExpiry = now() + ttlMs
        return true
    }

    fun revealRecovery(): String? = reveal(recovery, recoveryExpiry) {
        recovery = null
        recoveryExpiry = 0L
    }

    fun revealPairing(): String? = reveal(pairing, pairingExpiry) {
        pairing = null
        pairingExpiry = 0L
    }

    fun acknowledgeRecovery(): Boolean {
        if (revealRecovery() == null) return false
        recovery = null
        recoveryExpiry = 0L
        return true
    }

    fun acknowledgePairing(): Boolean {
        if (revealPairing() == null) return false
        pairing = null
        pairingExpiry = 0L
        return true
    }

    /** Clear only the recovery slot; the pairing slot is intentionally independent. */
    fun clearRecovery() {
        recovery = null
        recoveryExpiry = 0L
    }

    /** Clear only the pairing slot; the recovery slot is intentionally independent. */
    fun clearPairing() {
        pairing = null
        pairingExpiry = 0L
    }

    fun clearAll() {
        recovery = null
        pairing = null
        recoveryExpiry = 0L
        pairingExpiry = 0L
    }

    fun onBackground() = clearAll()

    private fun reveal(value: String?, expiry: Long, clear: () -> Unit): String? {
        if (value == null) return null
        if (now() >= expiry) {
            clear()
            return null
        }
        return value
    }

    companion object {
        const val DEFAULT_TTL_MS = 10 * 60 * 1000L
        const val DISPLAY_TTL_MS = 30 * 1000L

        private fun isSafe(value: String): Boolean =
            value.isNotEmpty() && value.length <= 256 && value.none { it.isISOControl() }
    }
}

/**
 * UI-only reveal state.  The value store owns the secret and this controller
 * owns only the short-lived decision to render it unmasked.  Keeping this
 * separate makes the remask deadline deterministic in JVM tests and prevents
 * a reveal action from extending the value's overall lifetime.
 */
internal class BifrostSensitiveDisplayController(
    private val now: () -> Long = { System.currentTimeMillis() },
    private val ttlMs: Long = BifrostSensitiveValueStore.DISPLAY_TTL_MS,
) {
    private var recoveryUntil = 0L
    private var pairingUntil = 0L

    fun revealRecovery(valueAvailable: Boolean): Boolean = reveal(valueAvailable) {
        recoveryUntil = now() + ttlMs
    }

    fun revealPairing(valueAvailable: Boolean): Boolean = reveal(valueAvailable) {
        pairingUntil = now() + ttlMs
    }

    fun recoveryVisible(valueAvailable: Boolean): Boolean = visible(valueAvailable, recoveryUntil) {
        recoveryUntil = 0L
    }

    fun pairingVisible(valueAvailable: Boolean): Boolean = visible(valueAvailable, pairingUntil) {
        pairingUntil = 0L
    }

    fun clearRecovery() {
        recoveryUntil = 0L
    }

    fun clearPairing() {
        pairingUntil = 0L
    }

    fun clearAll() {
        recoveryUntil = 0L
        pairingUntil = 0L
    }

    private fun reveal(valueAvailable: Boolean, setUntil: () -> Unit): Boolean {
        if (!valueAvailable || ttlMs <= 0L) return false
        setUntil()
        return true
    }

    private fun visible(valueAvailable: Boolean, until: Long, clear: () -> Unit): Boolean {
        if (!valueAvailable || until == 0L || now() >= until) {
            if (until != 0L) clear()
            return false
        }
        return true
    }
}
