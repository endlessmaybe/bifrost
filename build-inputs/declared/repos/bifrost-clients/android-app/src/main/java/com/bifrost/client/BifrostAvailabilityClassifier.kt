package com.bifrost.client

import java.io.IOException
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.net.ProtocolException
import java.security.GeneralSecurityException
import javax.net.ssl.SSLException

internal enum class BifrostTransportReason { DNS, CONNECTION, NO_ROUTE, DEADLINE }

/** Only narrowly identified socket failures may authorize an LKG fallback. */
internal class BifrostTransportUnavailableException(
    val reason: BifrostTransportReason,
    cause: Throwable? = null,
) : IOException(
    when (reason) {
        BifrostTransportReason.DEADLINE -> "BF-CONTROL-DEADLINE"
        else -> "BF-CONTROL-CONNECT"
    },
    cause,
)

/** A response status was already observed; body I/O cannot turn it into transport loss. */
internal open class BifrostReachableStatusException(
    val status: Int,
    cause: Throwable? = null,
) : IllegalStateException("BF-CONTROL-$status", cause)

/** Only an explicit retryable upstream status may enter the common offline gate. */
internal class BifrostRetryableStatusException(
    status: Int,
    cause: Throwable? = null,
) : BifrostReachableStatusException(status, cause)

internal fun mapBifrostTransportFailure(error: Throwable): Nothing = when (error) {
    is UnknownHostException -> throw BifrostTransportUnavailableException(BifrostTransportReason.DNS, error)
    is ConnectException -> throw BifrostTransportUnavailableException(BifrostTransportReason.CONNECTION, error)
    is NoRouteToHostException -> throw BifrostTransportUnavailableException(BifrostTransportReason.NO_ROUTE, error)
    is SocketTimeoutException -> throw BifrostTransportUnavailableException(BifrostTransportReason.DEADLINE, error)
    else -> throw error
}

/**
 * The only failures that may use an already verified LKG are transport loss,
 * deadline exhaustion, or an explicitly retryable gateway outage. Reachable auth,
 * revocation, entitlement, schema, signature, digest and rollback failures
 * are never re-labelled as offline.
 */
internal object BifrostAvailabilityClassifier {
    fun canUseOffline(error: Throwable): Boolean {
        var transport = false
        var retryableStatus = false
        var reachableStatus = false
        var current: Throwable? = error
        while (current != null) {
            if (current is BifrostTransportUnavailableException) transport = true
            if (current is BifrostRetryableStatusException) retryableStatus = true
            if (current is BifrostReachableStatusException && current !is BifrostRetryableStatusException) reachableStatus = true
            if (current is SecurityException || current is GeneralSecurityException || current is SSLException || current is ProtocolException) return false
            val code = current.message?.substringBefore(' ')?.substringBefore(':') ?: ""
            if (code in setOf("BF-CONTROL-HTTP", "BF-CONTROL-SSL", "BF-CONTROL-CERT", "BF-CONTROL-PROTOCOL")) return false
            if (code.startsWith("BF-CONTROL-4") || code in setOf("BF-CONTROL-REDIRECT", "BF-CONTROL-UTF8", "BF-CONTROL-CONTENT-TYPE", "BF-CONTROL-RESPONSE", "BF-CONTROL-JSON")) return false
            if (code.startsWith("BF-CONFIG-") || code.startsWith("BF-SESSION-") || code.startsWith("BF-AUTH-") ||
                code.startsWith("BF-ENTITLEMENT-") || code.startsWith("BF-SENDER-") || code.startsWith("BF-KEYS-") ||
                code.startsWith("BF-CRYPTO-") || code.startsWith("BF-PROTOCOL-")) return false
            current = current.cause
        }
        return (transport || retryableStatus) && !reachableStatus
    }

    fun canUseOfflineStatus(status: Int): Boolean = status in 502..504 || status == 530

    fun rejectedStatus(status: Int): Nothing = throw IllegalStateException("BF-CONTROL-REJECT-$status")
}
