package com.bifrost.client

import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.XrayEngine
import java.io.IOException
import java.util.concurrent.TimeUnit

/** In-process Xray transport exported by the unified libbox gomobile runtime. */
class BifrostXrayTransport {
    /**
     * The compiler emits this loopback listener explicitly.  We deliberately
     * do not probe a free port and rewrite JSON at runtime: that is a
     * check-then-use race and makes the transport contract impossible to
     * validate before the engine starts.  A conflicting listener is a hard
     * start failure, which is safe and visible to the user.
     */
    companion object { const val LOOPBACK_PORT = 10808 }

    private var engine: XrayEngine? = null
    private var port: Int = 0

    @Synchronized
    @Throws(IOException::class)
    fun start(xrayConfig: String): Int {
        if (engine != null && port > 0) return port
        require(xrayConfig.contains("\"port\":$LOOPBACK_PORT")) { "BF-XRAY-PORT-CONTRACT" }
        val instance = runCatching { Libbox.newXrayEngine() }.getOrElse { throw IOException("BF-XRAY-LIBBOX", it) }
        try {
            instance.start(xrayConfig)
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (System.nanoTime() < deadline && !instance.isRunning()) Thread.sleep(25)
            check(instance.isRunning()) { "BF-XRAY-NOT-RUNNING" }
            engine = instance
            port = LOOPBACK_PORT
            return LOOPBACK_PORT
        } catch (error: Exception) {
            val terms = listOf("address already in use", "unknown", "unsupported", "invalid", "not found", "failed to load", "geoip", "geosite", "permission", "dns", "routing", "proxySettings", "transportLayer")
                .filter { term -> generateSequence<Throwable>(error) { it.cause }.take(5).any { it.message.orEmpty().contains(term, true) } }.joinToString(",")
            runCatching { android.util.Log.w("BifrostXrayDiagnostic", "terms=$terms type=${error.javaClass.simpleName}") }
            runCatching { instance.stop() }
            throw if (error is IOException) error else IOException("BF-XRAY-START", error)
        }
    }

    @Synchronized
    fun stop() {
        engine?.stop()
        engine = null
        port = 0
    }

    @Synchronized fun isReady(): Boolean = engine?.isRunning == true && port > 0
    @Synchronized fun port(): Int = port
}
