package com.bifrost.client

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlin.io.path.createTempDirectory

class BifrostArtifactDownloaderTest {
    private class Response(val body: ByteArray, val status: Int = 206, val range: String? = null,
                           val truncate: Boolean = false) : HttpURLConnection(URL("https://origin.invalid/artifact")) {
        var closed = false
        override fun connect() {}
        override fun disconnect() { closed = true }
        override fun usingProxy() = false
        override fun getResponseCode() = status
        override fun getContentLengthLong() = body.size.toLong()
        override fun getHeaderField(name: String?) = if (name.equals("Content-Range", true)) range else null
        override fun getInputStream(): InputStream = ByteArrayInputStream(if (truncate) body.copyOf(body.size / 2) else body)
    }
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun run(block: (File) -> Unit) {
        val dir = createTempDirectory("bifrost-download-").toFile()
        try { block(File(dir, "apk.part")) } finally { dir.deleteRecursively() }
    }
    @Test fun retriesOnlyInterruptedChunkAndReportsCommittedProgress() = run { file ->
        val bytes = ByteArray(4 * 1024 * 1024 + 127) { (it % 251).toByte() }
        val first = bytes.copyOfRange(0, 4 * 1024 * 1024)
        val range = "bytes 0-4194303/${bytes.size}"
        val responses = listOf(Response(first, range = range, truncate = true), Response(first, range = range),
            Response(bytes.copyOfRange(first.size, bytes.size), range = "bytes 4194304-${bytes.lastIndex}/${bytes.size}"))
        val progress = mutableListOf<Long>()
        var calls = 0
        BifrostArtifactDownloader.download(file, bytes.size.toLong(), sha(bytes), { responses[calls++] }, { done, _ -> progress += done })
        assertArrayEquals(bytes, file.readBytes())
        assertEquals(0L, progress.first())
        assertEquals(bytes.size.toLong(), progress.last())
        assertTrue(progress.zipWithNext().all { (a, b) -> b >= a })
        assertTrue(responses.all { it.closed && !it.instanceFollowRedirects })
        assertEquals("bytes=0-4194303", responses[1].getRequestProperty("Range"))
        assertEquals("bytes=4194304-${bytes.lastIndex}", responses[2].getRequestProperty("Range"))
    }
    @Test fun refusesRedirectsWrongRangesAndCorruptedPayloads() {
        val body = byteArrayOf(1, 2, 3)
        for (response in listOf(Response(body, 302), Response(body, range = "bytes 1-3/3"), Response(byteArrayOf(3,2,1), range = "bytes 0-2/3"))) run { file ->
            assertTrue(runCatching { BifrostArtifactDownloader.download(file, 3, sha(body), { response }) }.isFailure)
            assertFalse(file.exists())
            assertTrue(response.closed)
        }
    }
    @Test fun retriesConnectionCreationAndFallsBackFromPublicMirror() = run { file ->
        val body = byteArrayOf(1, 2, 3)
        var calls = 0
        var mirrorCalls = 0
        BifrostArtifactDownloader.download(file, 3, sha(body), {
            if (++calls == 1) throw java.net.ConnectException("TEST-ONLY")
            Response(body, range = "bytes 0-2/3")
        }, connectMirror = { mirrorCalls++; Response(byteArrayOf(), 404) })
        assertEquals(1, mirrorCalls)
        assertEquals(2, calls)
        assertArrayEquals(body, file.readBytes())
    }
    @Test fun parallelRangesAreBoundedAndWrittenAtTheirOwnOffsets() = run { file ->
        val body = ByteArray(16 * 1024 * 1024 + 17) { (it % 251).toByte() }
        val active = java.util.concurrent.atomic.AtomicInteger()
        val peak = java.util.concurrent.atomic.AtomicInteger()
        val overlapped = java.util.concurrent.CountDownLatch(3)
        val requests = java.util.Collections.synchronizedList(mutableListOf<Long>())
        val progress = java.util.Collections.synchronizedList(mutableListOf<Long>())
        BifrostArtifactDownloader.download(file, body.size.toLong(), sha(body), {
            object : HttpURLConnection(URL("https://origin.invalid/artifact")) {
                var entered = false
                val start get() = getRequestProperty("Range").substringAfter("=").substringBefore("-").toInt()
                val end get() = getRequestProperty("Range").substringAfter("-").toInt()
                override fun connect() {}
                override fun disconnect() { if (entered) { entered = false; active.decrementAndGet() } }
                override fun usingProxy() = false
                override fun getResponseCode(): Int {
                    entered = true
                    val count = active.incrementAndGet()
                    peak.updateAndGet { maxOf(it, count) }
                    requests.add(start.toLong())
                    if (start > 0) { overlapped.countDown(); check(overlapped.await(5, java.util.concurrent.TimeUnit.SECONDS)) }
                    return 206
                }
                override fun getHeaderField(name: String?) = if (name.equals("Content-Range", true)) "bytes $start-$end/${body.size}" else null
                override fun getContentLengthLong() = (end - start + 1).toLong()
                override fun getInputStream(): InputStream {
                    if (start > 0) Thread.sleep(if (start == 4194304) 80 else 10)
                    return ByteArrayInputStream(body, start, end - start + 1)
                }
            }
        }, { done, _ -> progress.add(done) })
        assertEquals(3, peak.get())
        assertEquals(0, active.get())
        assertEquals(5, requests.distinct().size)
        assertArrayEquals(body, file.readBytes())
        assertTrue(progress.zipWithNext().all { (a,b) -> b >= a })
        assertEquals(body.size.toLong(), progress.last())
    }
    @Test fun mirrorIsLimitedToPublicContentOnTheProductionHost() {
        val digest = "a".repeat(64)
        val endpoint = BifrostReleaseMirror.endpoint("https://edge.bifrostlog.com", digest, "android/app.apk")!!
        assertEquals("https://bifrostlog.com/v1/releases/blobs/$digest/app.apk.bin", endpoint)
        // The production updater normalizes HTTPS to an explicit port and
        // trailing slash before building its authenticated artifact endpoint.
        val canonicalOrigin = java.net.URI("https", null, "edge.bifrostlog.com", 443, "/", null, null).toString()
        assertEquals(endpoint, BifrostReleaseMirror.endpoint(canonicalOrigin, digest, "android/app.apk"))
        assertEquals(endpoint, BifrostReleaseMirror.endpoint(canonicalOrigin.trimEnd('/'), digest, "android/app.apk"))
        for (untrusted in listOf("https://edge.bifrostlog.com:444", "https://user@edge.bifrostlog.com", "https://edge.bifrostlog.com?token=secret", "https://edge.bifrostlog.com/path"))
            assertNull(BifrostReleaseMirror.endpoint(untrusted, digest, "android/app.apk"))
        BifrostReleaseMirror.validate(endpoint)
        assertNull(BifrostReleaseMirror.endpoint("https://custom.invalid", digest, "app.apk"))
        for (url in listOf(endpoint.replace("bifrostlog.com/", "bifrostlog.com.evil.invalid/"), endpoint + "?token=secret", endpoint.replace("https:", "http:"), "https://bifrostlog.com/v1/config/manifest"))
            assertTrue(runCatching { BifrostReleaseMirror.validate(url) }.isFailure)
    }
    @Test fun supportsWholeLegacyResponseButRejectsOversize() = run { file ->
        val body = byteArrayOf(1, 2, 3)
        BifrostArtifactDownloader.download(file, 3, sha(body), { Response(body, 200) })
        assertArrayEquals(body, file.readBytes())
        assertTrue(runCatching { BifrostArtifactDownloader.download(file, 2, sha(body), { Response(body, 200) }) }.isFailure)
        assertFalse(file.exists())
    }
    @Test fun renewsExpiredSessionOnceAndRetainsRange() = run { file ->
        val body = byteArrayOf(1, 2, 3)
        var renewed = 0
        var calls = 0
        BifrostArtifactDownloader.download(file, 3, sha(body), {
            calls++
            if (renewed == 0) Response(byteArrayOf(), 401) else Response(body, range = "bytes 0-2/3")
        }, renewSession = { renewed++ })
        assertEquals(1, renewed); assertEquals(2, calls); assertArrayEquals(body, file.readBytes())
    }
}
