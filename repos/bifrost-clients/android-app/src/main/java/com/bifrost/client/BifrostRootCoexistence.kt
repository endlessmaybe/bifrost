package com.bifrost.client

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager

/** Infrastructure transport exceptions stay separate from the user's app list. */
internal object BifrostRootCoexistence {
    fun physicalDns(context: Context): List<String> {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val network = BifrostUnderlyingNetwork.select(manager) ?: return emptyList()
        return manager.getLinkProperties(network)?.dnsServers.orEmpty()
            .filterNot { it.isAnyLocalAddress || it.isLoopbackAddress || it.isLinkLocalAddress || it.isMulticastAddress }
            .mapNotNull { it.hostAddress?.substringBefore('%') }.distinct().sorted().also {
                check(it.size <= 16) { "BF-ROOT-POLICY" }
            }
    }
    fun infrastructureUids(context: Context, owner: Int): List<Int> {
        val uid = try { context.packageManager.getApplicationInfo("com.tailscale.ipn", 0).uid }
        catch (_: PackageManager.NameNotFoundException) { return emptyList() }
        check(uid != owner && uid / 100000 == owner / 100000 && uid % 100000 >= 10000) { "BF-ROOT-POLICY" }
        return listOf(uid)
    }

    fun wire(owner: Int, mode: String, uids: List<Int>, infrastructure: List<Int>, physicalDns: List<String> = emptyList(), hotspotMode: String = "smart"): String {
        check(mode in setOf("none", "allow", "exclude")) { "BF-ROOT-POLICY" }
        val bypass = infrastructure.distinct().sorted()
        check(bypass.size <= 16 && bypass.all { it != owner && it / 100000 == owner / 100000 && it % 100000 >= 10000 }) { "BF-ROOT-POLICY" }
        val dns = physicalDns.distinct().sorted()
        check(dns.size <= 16 && dns.all { Regex("[0-9a-fA-F:.]{2,45}").matches(it) }) { "BF-ROOT-POLICY" }
        check(hotspotMode in setOf("smart", "direct")) { "BF-ROOT-POLICY" }
        // Keep the helper protocol aligned with BifrostRootDnsRouting: BFR12
        // owns IPv4 DNS with mark + policy-route + TPROXY, while BFR11 is the
        // legacy DNAT/direct-inbound path. Do not mix the two generations.
        return (listOf("BFR13", owner.toString(), mode, uids.size.toString()) + uids.map(Int::toString) +
            listOf(bypass.size.toString()) + bypass.map(Int::toString) + listOf(dns.size.toString()) + dns + listOf(hotspotMode)).joinToString(" ") + "\n"
    }
}
