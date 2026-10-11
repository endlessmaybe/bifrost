package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject
import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Separate authenticated loopback selector; measuring a candidate never changes user routes. */
internal class BifrostQualityTransport(private val port: Int, private val password: String) : AutoCloseable {
    @Volatile private var closed = false
    private val active = ConcurrentHashMap.newKeySet<Socket>()
    private val receivedBodyBytes = java.util.concurrent.atomic.AtomicLong()
    private val sampleIndex = AtomicInteger()
    fun takeReceivedBodyBytes(): Long = receivedBodyBytes.getAndSet(0)
    @Volatile var allowAdaptiveDownload = true
    private val deadlines = Executors.newSingleThreadScheduledExecutor { Thread(it, "bifrost-quality-deadline").apply { isDaemon = true } }
    fun measure(bytes: Int = BYTES): BifrostQualitySample {
        require(bytes == STABLE_RECHECK_BYTES || bytes == BYTES || bytes == OBJECT_BYTES)
        val adaptive = bytes == BYTES && allowAdaptiveDownload
        val requested = if (adaptive) OBJECT_BYTES else bytes
        sampleIndex.getAndIncrement()
        return measureInternal(requested, CACHEFLY_HOST, CACHEFLY_PATH, adaptive)
    }

    fun measureLong(pass: Int): BifrostQualitySample {
        require(pass in 0 until LONG_FORM_PASSES)
        val host = if (pass % 2 == 0) CACHEFLY_HOST else OVH_HOST
        val path = if (pass % 2 == 0) CACHEFLY_PATH else OVH_PATH
        return measureInternal(LONG_FORM_BYTES, host, path, adaptive = false)
    }

    private fun measureInternal(requested: Int, targetHost: String, targetPath: String, adaptive: Boolean): BifrostQualitySample {
        val at = System.currentTimeMillis()
        if (closed) return BifrostQualitySample(at, false, 0.0, 0.0, 0.0)
        val raw = Socket(); active.add(raw)
        if (closed) { active.remove(raw); raw.close(); return BifrostQualitySample(at, false, 0.0, 0.0, 0.0) }
        val deadline = deadlines.schedule({ runCatching { raw.close() } }, when {
            requested >= LONG_FORM_BYTES -> 30L
            requested >= BYTES -> 12L
            else -> 6L
        }, TimeUnit.SECONDS)
        return try {
            val start = System.nanoTime()
            raw.soTimeout = 3000; raw.connect(InetSocketAddress("127.0.0.1", port), 1000)
            val input = DataInputStream(raw.getInputStream()); val output = raw.getOutputStream()
            output.write(byteArrayOf(5, 1, 2)); output.flush()
            check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 2)
            val user = "quality".toByteArray(); val pass = password.toByteArray()
            output.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass); output.flush()
            check(input.readUnsignedByte() == 1 && input.readUnsignedByte() == 0)
            val host = targetHost.toByteArray()
            output.write(byteArrayOf(5, 1, 0, 3, host.size.toByte()) + host + byteArrayOf(1, 0xbb.toByte())); output.flush()
            check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 0 && input.readUnsignedByte() == 0)
            val size = when(input.readUnsignedByte()) { 1 -> 4; 4 -> 16; 3 -> input.readUnsignedByte(); else -> error("SOCKS") }
            input.readFully(ByteArray(size + 2))
            (SSLSocketFactory.getDefault().let { it as SSLSocketFactory }.createSocket(raw, targetHost, 443, true) as SSLSocket).use { tls ->
                tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                tls.soTimeout = if (requested >= LONG_FORM_BYTES) 15_000 else 5_000; tls.startHandshake()
                val objectBytes = 10 * 1024 * 1024
                val maxOffset = (objectBytes - requested).coerceAtLeast(0)
                val offset = if (maxOffset == 0) 0 else java.util.concurrent.ThreadLocalRandom.current().nextInt(maxOffset + 1)
                val end = offset + requested - 1
                tls.outputStream.write(("GET $targetPath HTTP/1.1\r\nHost: $targetHost\r\nUser-Agent: BifrostQuality/1.0\r\nRange: bytes=$offset-$end\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII)); tls.outputStream.flush()
                val stream = tls.inputStream
                val header = StringBuilder()
                while (!header.endsWith("\r\n\r\n")) { check(header.length < 8192); val next = stream.read(); check(next >= 0); header.append(next.toChar()) }
                check(header.startsWith("HTTP/1.1 206 ") || header.startsWith("HTTP/1.0 206 "))
                val fields = header.toString().lowercase()
                val range = Regex("\\r\\ncontent-range: bytes $offset-$end/([0-9]+)\\r\\n").find(fields)
                check((range?.groupValues?.get(1)?.toLongOrNull() ?: 0L) >= offset.toLong() + requested)
                val contentLength = Regex("\\r\\ncontent-length: ([0-9]+)\\r\\n").find(fields)
                check(contentLength?.groupValues?.get(1)?.toIntOrNull() == requested)
                check(!fields.contains("\r\ntransfer-encoding:") && !fields.contains("\r\ncontent-encoding:"))
                var bodyAt = System.nanoTime(); var last = bodyAt; var stall = 0.0; var count = 0; var warmup = 0
                val buffer = ByteArray(16 * 1024)
                while (count < requested) {
                    val n = stream.read(buffer, 0, minOf(buffer.size, requested - count)); check(n > 0)
                    receivedBodyBytes.addAndGet(n.toLong())
                    val now = System.nanoTime(); stall = maxOf(stall, (now - last) / 1e6); last = now; count += n
                    if (warmup < 16 * 1024) { warmup = count; bodyAt = now }
                    if (adaptive && !BifrostNodeQuality.continueDownload(count, (now - bodyAt) / 1e9)) break
                }
                val bodySeconds = (last - bodyAt) / 1e9
                val goodput = BifrostNodeQuality.bodyGoodput(count, warmup, bodySeconds)
                BifrostQualitySample(at, goodput > 0, (bodyAt - start) / 1e6, goodput, stall)
            }
        } catch (_: Exception) { BifrostQualitySample(at, false, 0.0, 0.0, 0.0) }
        finally { deadline.cancel(false); active.remove(raw); runCatching { raw.close() } }
    }
    /** Capacity sample equivalent to the Windows end-of-sweep championship.
     * Four independent range requests run concurrently; at least three must
     * complete. Summing per-flow goodput approximates usable aggregate path
     * capacity while preventing one lucky TCP flow from becoming champion. */
    fun measureParallel(bytes: Int = OBJECT_BYTES, streams: Int = CAPACITY_STREAMS): BifrostQualitySample {
        require(bytes == OBJECT_BYTES)
        require(streams in 1..CAPACITY_STREAMS)
        val at = System.currentTimeMillis()
        if (closed) return BifrostQualitySample(at, false, 0.0, 0.0, 0.0)
        val pool = Executors.newFixedThreadPool(streams) { work ->
            Thread(work, "bifrost-quality-capacity").apply { isDaemon = true }
        }
        return try {
            val futures = (0 until streams).map { pool.submit<BifrostQualitySample> { measure(bytes) } }
            val samples = futures.mapNotNull { future ->
                runCatching { future.get(7, TimeUnit.SECONDS) }.getOrNull()
            }
            aggregateCapacity(samples, streams)
        } finally {
            pool.shutdownNow()
            runCatching { pool.awaitTermination(1, TimeUnit.SECONDS) }
        }
    }
    fun cancelActive() { active.toList().forEach { socket -> runCatching { socket.close() } } }
    override fun close() { closed = true; cancelActive(); deadlines.shutdownNow() }
    companion object {
        const val GROUP = "bifrost-quality"
        // Windows 2.2.62 parity: quiet health checks stay tiny, ordinary
        // winner comparisons cross the 1 MiB slow-start boundary, and every
        // prospective winner must survive four alternating 5 MiB bodies.
        const val STABLE_RECHECK_BYTES = 256 * 1024
        const val BYTES = 1 * 1024 * 1024
        const val OBJECT_BYTES = 512 * 1024
        const val LONG_FORM_BYTES = 5 * 1024 * 1024
        const val LONG_FORM_PASSES = 4
        const val CAPACITY_STREAMS = 4
        const val CACHEFLY_HOST = "cachefly.cachefly.net"
        const val CACHEFLY_PATH = "/10mb.test"
        const val OVH_HOST = "proof.ovh.net"
        const val OVH_PATH = "/files/10Mb.dat"
        internal fun aggregateCapacity(samples: List<BifrostQualitySample>, requestedStreams: Int): BifrostQualitySample {
            val minimumSuccess = if (requestedStreams >= 4) 3 else requestedStreams
            val successful = samples.filter { it.ok && it.bytesPerSecond.isFinite() && it.bytesPerSecond > 0 }
            val at = samples.minOfOrNull { it.at } ?: System.currentTimeMillis()
            if (successful.size < minimumSuccess) return BifrostQualitySample(at, false, 0.0, 0.0, 0.0)
            return BifrostQualitySample(
                at = at,
                ok = true,
                latencyMs = successful.map { it.latencyMs }.filter { it.isFinite() && it > 0 }.average().takeIf { it.isFinite() } ?: 1.0,
                bytesPerSecond = successful.sumOf { it.bytesPerSecond },
                stallMs = successful.maxOfOrNull { it.stallMs } ?: 0.0,
            )
        }
        fun configure(config: JSONObject) {
            val outbounds = config.getJSONArray("outbounds")
            val root = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }.firstOrNull { it.optString("tag") == "proxy" && it.optString("type") == "selector" } ?: return
            val tags = root.getJSONArray("outbounds").let { a -> (0 until a.length()).map { a.getString(it) } }
            if ("proxy-auto" !in tags) return
            val leaves = tags.filter { it.startsWith("proxy-candidate-") }; if (leaves.isEmpty()) return
            val port = ServerSocket().use { it.bind(InetSocketAddress("127.0.0.1", 0)); it.localPort }
            val password = UUID.randomUUID().toString()
            outbounds.put(JSONObject().put("type", "selector").put("tag", GROUP).put("outbounds", JSONArray(leaves)).put("default", leaves.first()).put("interrupt_exist_connections", false))
            config.getJSONArray("inbounds").put(JSONObject().put("type", "socks").put("tag", GROUP).put("listen", "127.0.0.1").put("listen_port", port)
                .put("users", JSONArray().put(JSONObject().put("username", "quality").put("password", password))))
            val route = config.getJSONObject("route"); val prior = route.getJSONArray("rules")
            val rules = JSONArray().put(JSONObject().put("inbound", JSONArray().put(GROUP)).put("outbound", GROUP))
            for(i in 0 until prior.length()) rules.put(prior.get(i)); route.put("rules", rules)
        }
        fun fromConfig(config: JSONObject): BifrostQualityTransport? {
            val inbounds = config.getJSONArray("inbounds")
            val inbound = (0 until inbounds.length()).map { inbounds.getJSONObject(it) }.firstOrNull { it.optString("tag") == GROUP } ?: return null
            return BifrostQualityTransport(inbound.getInt("listen_port"), inbound.getJSONArray("users").getJSONObject(0).getString("password"))
        }
    }
}
