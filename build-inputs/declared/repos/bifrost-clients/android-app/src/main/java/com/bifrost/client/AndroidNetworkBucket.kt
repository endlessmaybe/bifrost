package com.bifrost.client

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.io.Closeable
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Produces a local-only network bucket for candidate probing.  The process
 * epoch and network-generation are local-only.  Android network
 * handles are intentionally not used as a persisted or cross-process
 * identity: after a process restart (or an ambiguous callback) we retest.
 * No SSID/BSSID/MAC/IP is persisted, logged, uploaded, or returned to the
 * control plane. The app salt is Keystore-backed; Root uses a process-local salt.
 */
internal object AndroidNetworkBucket {
    private const val SALT_KEY = "probe_network_hmac_salt"
    private val random = SecureRandom()
    private val sessionEpoch = java.util.UUID.randomUUID().toString()
    private val generation = AtomicLong(0L)
    private val rootSessionSalt = ByteArray(32).also(random::nextBytes)

    fun fingerprint(context: Context): String {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val network = manager?.let(BifrostUnderlyingNetwork::select)
        val capabilities = network?.let { manager.getNetworkCapabilities(it) }
        val material = stableMaterial(network, capabilities) ?: "epoch:$sessionEpoch:unknown:${generation.get()}"
        val salt = salt(context)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        return "net-" + mac.doFinal(material.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    /** Register a physical-network callback. The callback only signals a
     * refresh; callers must recompute the fingerprint and cancel old work. */
    fun observe(context: Context, onChanged: () -> Unit): Closeable? {
        val manager = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val callback = object : ConnectivityManager.NetworkCallback() {
            private var lastMaterial = observedMaterial()
            override fun onAvailable(network: android.net.Network) = changed()
            override fun onLost(network: android.net.Network) = changed()
            override fun onCapabilitiesChanged(network: android.net.Network, caps: NetworkCapabilities) = changed()
            override fun onLinkPropertiesChanged(network: android.net.Network, linkProperties: android.net.LinkProperties) = changed()
            private fun observedMaterial(): String {
                val network = BifrostUnderlyingNetwork.select(manager)
                val links = network?.let(manager::getLinkProperties)
                return "${network?.hashCode()}|${links?.interfaceName}|${links?.linkAddresses}|${links?.dnsServers}"
            }
            @Synchronized private fun changed() {
                val material = observedMaterial()
                if (material == lastMaterial) return
                lastMaterial = material
                generation.incrementAndGet()
                onChanged()
            }
        }
        return runCatching {
            manager.registerNetworkCallback(android.net.NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
            Closeable { runCatching { manager.unregisterNetworkCallback(callback) } }
        }.getOrNull()
    }

    private fun stableMaterial(network: android.net.Network?, caps: NetworkCapabilities?): String? {
        if (network == null || caps == null || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return null
        val transport = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
        // ConnectivityManager unparcels a new Network wrapper on every read.
        // Its value equality identifies the network; object identity would
        // invalidate a probe even when the underlying network never changed.
        // The random process epoch prevents reuse across process restarts.
        val localIdentity = network.hashCode()
        return "epoch:$sessionEpoch|generation:${generation.get()}|object:$localIdentity|transport:$transport|" +
            "metered:${!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)}|" +
            "validated:${caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)}|roaming:${!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)}"
    }

    private fun salt(context: Context): ByteArray {
        // Root owns only ephemeral network identity. Android Keystore keys
        // belong to the app UID and must never be opened from the daemon.
        if (android.os.Process.myUid() == 0) return rootSessionSalt
        val existing = BifrostSecureStore.get(context, SALT_KEY, "")
        val decoded = runCatching { android.util.Base64.decode(existing, android.util.Base64.NO_WRAP) }
            .getOrNull()?.takeIf { it.size >= 32 }
        if (decoded != null) return decoded
        val created = ByteArray(32).also(random::nextBytes)
        BifrostSecureStore.put(context, SALT_KEY, android.util.Base64.encodeToString(created, android.util.Base64.NO_WRAP))
        return created
    }
}
