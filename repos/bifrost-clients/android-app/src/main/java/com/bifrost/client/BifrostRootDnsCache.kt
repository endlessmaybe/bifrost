package com.bifrost.client

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Process
import java.util.concurrent.TimeUnit

/** Root routing reuses Android's underlying network, unlike VpnService's new
 * netId. Invalidate cached real/fake answers when that routing boundary changes.
 * Only flush existing Internet-network caches; never destroy/reconfigure them.
 */
internal object BifrostRootDnsCache {
    fun flush(context: Context) {
        if (Process.myUid() != 0) return
        runCatching {
            // Stable IDnsResolver v10 freezes flushNetworkCache as transaction
            // 11. Check the version first; never guess on an older OEM service.
            val version = command("16777215") ?: return
            val words = Regex("[0-9a-fA-F]{8}").findAll(version).map { it.value }.toList()
            if (words.size < 2 || words[0] != "00000000" || words[1].toInt(16) < 10) return
            val manager = context.getSystemService(ConnectivityManager::class.java)
            manager.allNetworks.filter { network ->
                manager.getNetworkCapabilities(network)?.let {
                    it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        (!it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                            manager.getLinkProperties(network)?.dnsServers?.any { address ->
                                address.hostAddress.orEmpty() in setOf("100.100.100.100", "fd7a:115c:a1e0:0:0:0:0:53", "fd7a:115c:a1e0::53")
                            } == true)
                } == true
            }.mapNotNull { it.toString().toIntOrNull() }.filter { it > 0 }.distinct().forEach { netId ->
                val result = command("11", "i32", netId.toString())
                check(result != null && Regex("Parcel\\(\\s*00000000\\s").containsMatchIn(result)) { "BF-ROOT-DNS-CACHE" }
            }
        }.onFailure { BifrostDiagnostics.record(context, "root-dns-cache-retry", it) }
    }

    private fun command(vararg args: String): String? {
        val child = ProcessBuilder(listOf("/system/bin/service", "call", "dnsresolver") + args)
            .redirectErrorStream(true).start()
        return try {
            // These calls return only a small Binder status/version parcel.
            if (!child.waitFor(3, TimeUnit.SECONDS) || child.exitValue() != 0) null
            else child.inputStream.bufferedReader().use { it.readText().take(1024) }
        } finally {
            child.inputStream.close(); child.outputStream.close(); child.errorStream.close()
            if (child.isAlive) child.destroy()
        }
    }
}
