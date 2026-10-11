package com.bifrost.client

import java.io.File
import java.io.IOException
import java.io.InterruptedIOException
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Bounded range downloads. Public mirror requests carry no credentials; the
 * independent authenticated origin resumes failed ranges. Only a complete
 * signed digest permits promotion. At most three 64 KiB buffers are active. */
internal object BifrostArtifactDownloader {
    private const val CHUNK = 4L * 1024 * 1024
    private const val WORKERS = 3

    fun download(file: File, bytes: Long, sha256: String,
                 connect: () -> HttpURLConnection, progress: (Long, Long) -> Unit = { _, _ -> },
                 renewSession: (() -> Unit)? = null, connectMirror: (() -> HttpURLConnection)? = null) {
        require(bytes > 0 && sha256.matches(Regex("[0-9a-f]{64}"))) { "BF-RELEASE-SIZE" }
        val mirrorAvailable = AtomicBoolean(connectMirror != null)
        val sessionGeneration = AtomicInteger()
        val renewalGate = Any()
        val progressGate = Any()
        val active = ConcurrentHashMap.newKeySet<HttpURLConnection>()
        val committed = AtomicLong()
        val inFlight = ConcurrentHashMap<Long, Long>()
        var reported = 0L
        var lastReport = 0L
        fun report(force: Boolean = false) = synchronized(progressGate) {
            val current = minOf(bytes, committed.get() + inFlight.values.sum())
            val now = System.nanoTime()
            if (current > reported && (force || now - lastReport >= 100_000_000L)) {
                reported = current
                lastReport = now
                progress(current, bytes)
            }
        }
        fun interrupted() {
            if (Thread.currentThread().isInterrupted) throw InterruptedIOException()
        }
        fun chunk(offset: Long): Long {
            val end = minOf(bytes - 1, offset + CHUNK - 1)
            val buffer = ByteArray(64 * 1024)
            try {
                RandomAccessFile(file, "rw").use { output ->
                    for (attempt in 0..3) {
                        interrupted()
                        val mirror = mirrorAvailable.get()
                        val generation = sessionGeneration.get()
                        var connection: HttpURLConnection? = null
                        try {
                            connection = if (mirror) connectMirror!!.invoke() else connect()
                            active.add(connection)
                            interrupted()
                            connection.instanceFollowRedirects = false
                            connection.setRequestProperty("Range", "bytes=$offset-$end")
                            connection.setRequestProperty("Accept-Encoding", "identity")
                            val status = connection.responseCode
                            if (!mirror && status == 401 && attempt < 3 && renewSession != null) {
                                synchronized(renewalGate) {
                                    if (generation == sessionGeneration.get()) {
                                        renewSession()
                                        sessionGeneration.incrementAndGet()
                                    }
                                }
                                continue
                            }
                            if (status == 429 || status in 500..599 || mirror && status !in listOf(200, 206)) throw IOException("BF-RELEASE-HTTP")
                            val whole = status == 200 && offset == 0L
                            check(whole || status == 206) { if (status in 300..399) "BF-RELEASE-REDIRECT" else "BF-RELEASE-RANGE" }
                            val length = if (whole) bytes else end - offset + 1
                            check(if (whole) connection.getHeaderField("Content-Range") == null
                                  else connection.getHeaderField("Content-Range") == "bytes $offset-$end/$bytes") { "BF-RELEASE-RANGE" }
                            check(connection.contentLengthLong < 0 || connection.contentLengthLong == length) { "BF-RELEASE-SIZE" }
                            check(connection.getHeaderField("Content-Encoding").let { it == null || it.equals("identity", true) }) { "BF-RELEASE-RANGE" }
                            output.seek(offset)
                            var received = 0L
                            connection.inputStream.use { input ->
                                while (received < length) {
                                    interrupted()
                                    val count = input.read(buffer, 0, minOf(buffer.size.toLong(), length - received).toInt())
                                    if (count < 0) throw IOException("BF-RELEASE-SIZE")
                                    output.write(buffer, 0, count)
                                    received += count
                                    synchronized(progressGate) { inFlight[offset] = received; report() }
                                }
                                check(input.read() == -1) { "BF-RELEASE-SIZE" }
                            }
                            synchronized(progressGate) {
                                inFlight.remove(offset)
                                committed.addAndGet(received)
                                report(true)
                            }
                            return received
                        } catch (error: IOException) {
                            if (Thread.currentThread().isInterrupted) throw error
                            if (mirror) mirrorAvailable.set(false)
                            if (attempt == 3) throw error
                        } catch (error: IllegalStateException) {
                            if (!mirror || error.message !in setOf("BF-RELEASE-RANGE", "BF-RELEASE-SIZE", "BF-RELEASE-REDIRECT") || attempt == 3) throw error
                            mirrorAvailable.set(false)
                        } finally {
                            synchronized(progressGate) { inFlight.remove(offset) }
                            connection?.let { active.remove(it); it.disconnect() }
                        }
                    }
                    error("BF-RELEASE-RANGE")
                }
            } finally { buffer.fill(0) }
        }
        try {
            RandomAccessFile(file, "rw").use { it.setLength(0) }
            progress(0, bytes)
            // Establish Range support first; a legacy whole-file 200 is accepted
            // only here, before any concurrent writer exists.
            val first = chunk(0)
            if (first < bytes) {
                val next = AtomicLong(first)
                val pool = Executors.newFixedThreadPool(WORKERS)
                val completion = ExecutorCompletionService<Unit>(pool)
                val futures = (0 until WORKERS).map {
                    completion.submit(java.util.concurrent.Callable {
                        while (true) {
                            interrupted()
                            val offset = next.getAndAdd(CHUNK)
                            if (offset >= bytes) break
                            chunk(offset)
                        }
                    })
                }
                try {
                    repeat(WORKERS) {
                        try { completion.take().get() }
                        catch (error: ExecutionException) { throw error.cause ?: error }
                    }
                } catch (error: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw InterruptedIOException().apply { initCause(error) }
                } finally {
                    futures.forEach { it.cancel(true) }
                    active.forEach { it.disconnect() }
                    pool.shutdownNow()
                    // No worker may write after cleanup/hash validation. Preserve
                    // caller cancellation while waiting for bounded socket teardown.
                    var cancelled = Thread.interrupted()
                    while (!pool.isTerminated) {
                        try { pool.awaitTermination(100, TimeUnit.MILLISECONDS) }
                        catch (_: InterruptedException) { cancelled = true; active.forEach { it.disconnect() } }
                    }
                    if (cancelled) Thread.currentThread().interrupt()
                }
            }
            interrupted()
            RandomAccessFile(file, "rw").use { it.fd.sync() }
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(64 * 1024)
            try {
                file.inputStream().use { input ->
                    while (true) {
                        interrupted()
                        val count = input.read(buffer)
                        if (count < 0) break
                        digest.update(buffer, 0, count)
                    }
                }
            } finally { buffer.fill(0) }
            check(file.length() == bytes && committed.get() == bytes) { "BF-RELEASE-SIZE" }
            check(digest.digest().joinToString("") { "%02x".format(it) } == sha256) { "BF-RELEASE-DIGEST" }
        } catch (error: Throwable) {
            file.delete()
            throw error
        }
    }
}
