package com.bifrost.client

/** Small seam around the platform clipboard so lifecycle behavior is testable without Android. */
internal interface BifrostClipboard {
    fun readText(): String?
    fun writeText(value: String): Boolean
    fun clearIfMatches(expected: String): Boolean
}

/**
 * Owns only the value this process copied.  A user replacement is never
 * overwritten or cleared, and a failed clipboard operation is never reported
 * as success.  Strings cannot be zeroed by the platform; their lifetime is
 * bounded by this controller and the UI lifecycle.
 */
internal class BifrostSensitiveClipboardController(
    private val clipboard: BifrostClipboard,
) {
    private var ownedValue: String? = null

    @Synchronized
    fun copy(value: String): Boolean {
        if (value.isEmpty() || value.length > 256 || value.any { it.isISOControl() }) return false
        if (!clearOwned()) return false
        return try {
            if (!clipboard.writeText(value)) return false
            ownedValue = value
            true
        } catch (_: Throwable) {
            false
        }
    }

    /** Clear only if the clipboard still contains the value owned by Bifrost. */
    @Synchronized
    fun clearOwned(): Boolean {
        val expected = ownedValue ?: return true
        return try {
            if (clipboard.readText() != expected) {
                // The user replaced our value.  Drop ownership without
                // touching their clipboard; this is a safe no-op and must
                // not prevent the next explicit copy operation.
                ownedValue = null
                true
            } else if (clipboard.clearIfMatches(expected)) {
                ownedValue = null
                true
            } else {
                false
            }
        } catch (_: Throwable) {
            false
        }
    }

    fun onBackground(): Boolean = clearOwned()
}
