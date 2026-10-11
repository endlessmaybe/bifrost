package com.bifrost.client

import java.io.IOException
import java.net.ProtocolException
import javax.net.ssl.SSLException

/** Preserve the system-network path verified by the 2.1.75 -> 2.1.76 OTA.
 * Only a failed/starting Bifrost tunnel or an explicit retry needs a physical
 * network. A healthy VPN can be the only working route to Control. */
internal object BifrostControlNetworkPolicy {
    fun <T> open(state: BifrostLeakState, attempt: Int,
                 system: () -> T, physical: () -> T?): T {
        val fenced = state in setOf(BifrostLeakState.STARTING, BifrostLeakState.BLOCKING, BifrostLeakState.ERROR)
        if (fenced || attempt > 0) {
            physical()?.let { return it }
            if (fenced) throw BifrostTransportUnavailableException(BifrostTransportReason.CONNECTION)
        }
        return system()
    }
}

/** A manifest GET may retry on a different network only before a response.
 * An HTTP rejection, malformed body, or TLS failure keeps its original meaning. */
internal object BifrostControlReadRetry {
    fun <T> run(read: (attempt: Int, responseReceived: () -> Unit) -> T): T {
        var received = false
        try { return read(0) { received = true } }
        catch (error: IOException) {
            if (received || Thread.currentThread().isInterrupted || error is SSLException || error is ProtocolException) throw error
            return read(1) {}
        }
    }
}
