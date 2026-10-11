package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject
import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Authenticated loopback probe through the exact core outbound, never a
 * default-network request that could succeed while the tunnel is broken. */
internal class BifrostDataPlaneHealth {
    private val password = UUID.randomUUID().toString()
    private var port = 0
    private var preferredHost = "www.gstatic.com"
    @Volatile private var socket: Socket? = null
    @Volatile private var closed = false
    @Volatile var lastFailure: String = "BF-TRANSPORT-PROBE-UNAVAILABLE"
        private set
    private val deadlineExecutor = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "bifrost-health-deadline").apply { isDaemon = true }
    }

    fun configure(config: JSONObject) {
        port = ServerSocket().use { it.bind(InetSocketAddress("127.0.0.1", 0)); it.localPort }
        config.getJSONArray("inbounds").put(JSONObject().put("type", "socks").put("tag", "health-in")
            .put("listen", "127.0.0.1").put("listen_port", port)
            .put("users", JSONArray().put(JSONObject().put("username", "health").put("password", password))))
        val route = config.getJSONObject("route")
        val rules = JSONArray().put(JSONObject().put("inbound", JSONArray().put("health-in"))
            .put("outbound", route.getString("final")))
        val original = route.getJSONArray("rules")
        for (index in 0 until original.length()) rules.put(original.get(index))
        route.put("rules", rules)
    }

    fun close() {
        closed = true
        runCatching { socket?.close() }
        deadlineExecutor.shutdownNow()
    }

    @Synchronized fun check(budgetMs: Long = 12000, cancelled: (() -> Boolean)? = null): Boolean {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(budgetMs.coerceAtLeast(0))
        for (host in (listOf(preferredHost) + listOf("www.gstatic.com", "cp.cloudflare.com")).distinct()) {
            val remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
            if (remaining < 250 || closed || cancelled?.invoke() == true) return false
            if (checkEndpoint(host, minOf(6000, remaining), cancelled)) { preferredHost = host; return true }
        }
        return false
    }

    private fun checkEndpoint(hostName: String, budgetMs: Long, cancelled: (() -> Boolean)?): Boolean {
        if (closed || port == 0) return false
        val raw = Socket()
        socket = raw
        if (closed) { raw.close(); return false }
        val deadline = try { deadlineExecutor.schedule({ runCatching { raw.close() } }, budgetMs, TimeUnit.MILLISECONDS) }
            catch (_: Exception) { raw.close(); return false }
        // The service serializes native startup and teardown. An exact cancel
        // must close the pending read without waiting behind that startup.
        val cancellation = if (cancelled == null) null else try {
            deadlineExecutor.scheduleWithFixedDelay({
                if (cancelled()) runCatching { raw.close() }
            }, 0, 100, TimeUnit.MILLISECONDS)
        } catch (_: Exception) { deadline.cancel(false); raw.close(); return false }
        var stage = "loopback"
        return try {
            raw.soTimeout = minOf(6000L, budgetMs).toInt()
            raw.connect(InetSocketAddress("127.0.0.1", port), 1000)
            stage = "authentication"
            val output = raw.getOutputStream()
            val input = DataInputStream(raw.getInputStream())
            output.write(byteArrayOf(5, 1, 2)); output.flush()
            check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 2)
            val user = "health".toByteArray(Charsets.US_ASCII)
            val pass = password.toByteArray(Charsets.US_ASCII)
            output.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass)
            output.flush()
            check(input.readUnsignedByte() == 1 && input.readUnsignedByte() == 0)
            stage = "proxy-connect"
            val host = hostName.toByteArray(Charsets.US_ASCII)
            output.write(byteArrayOf(5, 1, 0, 3, host.size.toByte()) + host + byteArrayOf(1, 0xbb.toByte()))
            output.flush()
            check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 0)
            check(input.readUnsignedByte() == 0)
            val addressSize = when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; 3 -> input.readUnsignedByte(); else -> error("invalid SOCKS reply") }
            input.readFully(ByteArray(addressSize + 2))
            stage = "tls"
            ((SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, hostName, 443, true) as SSLSocket).use { tls ->
                tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                tls.soTimeout = minOf(6000L, budgetMs).toInt()
                tls.startHandshake()
                stage = "http"
                tls.outputStream.write("HEAD /generate_204 HTTP/1.1\r\nHost: $hostName\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                tls.outputStream.flush()
                val line = StringBuilder()
                val stream = tls.inputStream
                while (line.length < 256) {
                    val next = stream.read()
                    if (next < 0) throw java.io.EOFException()
                    if (next == 10) {
                        val healthy = isExpectedStatus(line.toString())
                        if (!healthy) lastFailure = "BF-TRANSPORT-PROBE-HTTP"
                        return healthy
                    }
                    line.append(next.toChar())
                }
                false
            }
        } catch (error: Exception) {
            lastFailure = when (stage) {
                "loopback" -> "BF-TRANSPORT-PROBE-UNAVAILABLE"
                "authentication", "proxy-connect" -> "BF-TRANSPORT-PROBE-PROXY"
                "tls" -> "BF-TRANSPORT-PROBE-TLS"
                else -> "BF-TRANSPORT-PROBE-HTTP"
            }
            // Only fixed stages and exception types; never exception messages,
            // hostnames, proxy credentials or native config values.
            runCatching {
                val causes = generateSequence<Throwable>(error) { it.cause }.take(5).toList()
                val kinds = causes.map { it.javaClass.simpleName }.distinct().joinToString(",")
                val terms = listOf("closed", "reset", "certificate", "trust anchor", "expired", "timeout", "protocol", "EOF")
                    .filter { term -> causes.any { it.message.orEmpty().contains(term, true) } }.joinToString(",")
                android.util.Log.w("BifrostHealthDiagnostic", "stage=$stage types=$kinds terms=$terms")
            }
            false
        }
        finally { cancellation?.cancel(false); deadline.cancel(false); runCatching { raw.close() }; socket = null }
    }

    companion object {
        internal fun startupBudgetMs(config: JSONObject): Long {
            val outbounds = config.optJSONArray("outbounds") ?: return 30_000L
            val count = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }
                .filter { it.optString("type") == "urltest" }.sumOf { it.optJSONArray("outbounds")?.length() ?: 0 }
            return (30_000L + ((count + 11) / 12) * 5000L).coerceAtMost(300_000L)
        }
        internal fun isExpectedStatus(line: String): Boolean = Regex("HTTP/1\\.[01] 204(?: [^\\r\\n]*)?").matches(line.removeSuffix("\r"))
    }
}
