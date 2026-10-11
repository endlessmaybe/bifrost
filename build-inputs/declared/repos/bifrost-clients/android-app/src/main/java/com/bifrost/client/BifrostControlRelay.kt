package com.bifrost.client

import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.TimeUnit

/** A compiled, operator-owned transport alias. Logical origin, sender proof,
 * config encryption, release signatures and rollback validation do not change.
 * Select with credential-free health reads BEFORE sending a mutating request;
 * never replay POST bodies when choosing a reachable entry. */
internal object BifrostControlRelay {
    const val ORIGIN = "https://bifrost-client-entry.pages.dev"
    private data class Choice(val key: String, val relay: Boolean, val expires: Long)
    @Volatile private var choice: Choice? = null

    internal fun alternate(url: URL): URL? {
        if (url.protocol != "https" || url.port !in setOf(-1, 443) || url.userInfo != null || url.query != null || url.ref != null) return null
        val control = url.host.equals("edge.bifrostlog.com", true) && url.path.startsWith("/v1/") && !url.path.startsWith("/v1/admin/")
        val blob = url.host.equals("bifrostlog.com", true) && url.path.matches(Regex("/v1/releases/blobs/[0-9a-f]{64}/[A-Za-z0-9._-]+\\.bin"))
        return if (control || blob) URL(ORIGIN + url.path) else null
    }

    @Synchronized fun resolve(url: URL, key: String, retry: Boolean, open: (URL) -> HttpURLConnection): URL {
        val alternate = alternate(url) ?: return url
        val now = System.nanoTime()
        choice?.takeIf { !retry && it.key == key && now < it.expires }?.let { return if (it.relay) alternate else url }
        val pool = Executors.newFixedThreadPool(2)
        val sockets = java.util.concurrent.ConcurrentHashMap.newKeySet<HttpURLConnection>()
        val completed = ExecutorCompletionService<Boolean?>(pool)
        val futures = listOf(false, true).map { relay -> completed.submit(java.util.concurrent.Callable {
            val probe = open(URL(if (relay) "$ORIGIN/health" else "https://edge.bifrostlog.com/health"))
            sockets.add(probe)
            try {
                probe.requestMethod = "GET"
                probe.instanceFollowRedirects = false
                probe.connectTimeout = 2500
                probe.readTimeout = 2500
                probe.useCaches = false
                if (probe.responseCode == 200) relay else null
            } catch (_: java.io.IOException) { null }
            finally { probe.disconnect(); sockets.remove(probe) }
        }) }
        try {
            val deadline = now + TimeUnit.SECONDS.toNanos(5)
            repeat(2) {
                val remaining = deadline - System.nanoTime()
                if (remaining > 0) {
                    val result = completed.poll(remaining, TimeUnit.NANOSECONDS)
                    val relay = result?.let { runCatching { it.get() }.getOrNull() }
                    if (relay != null) {
                        choice = Choice(key, relay, System.nanoTime() + TimeUnit.MINUTES.toNanos(2))
                        return if (relay) alternate else url
                    }
                }
            }
            // No reachability evidence: retain the canonical failure semantics.
            return url
        } finally {
            futures.forEach { it.cancel(true) }
            sockets.forEach { it.disconnect() }
            pool.shutdownNow()
        }
    }
}
