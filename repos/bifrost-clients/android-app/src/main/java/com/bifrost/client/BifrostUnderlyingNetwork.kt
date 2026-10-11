package com.bifrost.client

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.content.Context
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL

/** Shared physical-network selection for the core and candidate probes. */
internal object BifrostUnderlyingNetwork {
    /** Use the known-working system network first. Physical binding is a
     * recovery route, not a prerequisite for every authenticated request. */
    fun openControlConnection(context: Context, url: URL, attempt: Int = 0): HttpURLConnection {
        val key = AndroidNetworkBucket.fingerprint(context) + ":" + BifrostRuntimeStatus.current.state.name
        val endpoint = BifrostControlRelay.resolve(url, key, attempt > 0) { probe -> openDirect(context, probe, attempt) }
        return openDirect(context, endpoint, attempt)
    }

    private fun openDirect(context: Context, url: URL, attempt: Int): HttpURLConnection {
        return BifrostControlNetworkPolicy.open(BifrostRuntimeStatus.current.state, attempt,
            system = { url.openConnection(Proxy.NO_PROXY) as HttpURLConnection },
            physical = {
                val manager = context.getSystemService(ConnectivityManager::class.java)
                val network = manager?.let(::select)
                network?.openConnection(url, Proxy.NO_PROXY) as? HttpURLConnection
            })
    }

    fun select(manager: ConnectivityManager): Network? = available(manager).firstOrNull()

    fun isMetered(context: Context): Boolean {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val capabilities = select(manager)?.let(manager::getNetworkCapabilities)
        return capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) != true
    }

    private fun available(manager: ConnectivityManager): List<Network> {
        val active = manager.activeNetwork
        // A Root session has a physical default network unless another VPN
        // owns it. In the former case prefer that active network immediately;
        // otherwise fall back to validated physical networks below.
        return manager.allNetworks.mapNotNull { network ->
            val caps = manager.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return@mapNotNull null
            network to caps
        }.sortedWith(compareByDescending<Pair<Network, NetworkCapabilities>> { (network, caps) ->
            (if (network == active) 16 else 0) +
                (if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 8 else 0) +
                (if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) 2 else 0)
        }.thenBy { it.first.hashCode() }).map { it.first }
    }
}
