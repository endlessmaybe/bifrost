package com.bifrost.client

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Network
import android.net.NetworkRequest
import android.net.LinkProperties
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterface
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.Notification
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.RoutePrefix
import io.nekohasekai.libbox.RoutePrefixIterator
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import io.nekohasekai.libbox.XraySocketProtector
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.NetworkInterface as JavaNetworkInterface
import java.security.KeyStore
import java.util.Base64
import java.util.Collections

/** Platform bridge used by the official libbox/mobile API. */
class BifrostLibboxPlatform internal constructor(private val context: android.content.Context,
    private val vpn: VpnService?, private val root: BifrostRootTunnel? = null) : PlatformInterface, XraySocketProtector {
    internal constructor(vpn: VpnService, root: BifrostRootTunnel? = null) : this(vpn, vpn, root)
    @Volatile private var active = false
    private var tunDescriptor: ParcelFileDescriptor? = null
    @Volatile var tunOpened = false
        internal set
    private var applicationPolicyMode: String = "none"
    private var applicationAllowList: List<String> = emptyList()
    private var applicationExcludeList: List<String> = emptyList()
    @Volatile private var applicationPolicySnapshot: BifrostApplicationPolicySnapshot? = null
    private val applicationPackageCatalog = AndroidApplicationPackageCatalog(context)
    private val applicationPackageValidator = BifrostApplicationPolicyPackageValidator(
        applicationPackageCatalog, context.packageName,
    )
    private var applicationPolicyBindings: List<BifrostApplicationPackageBinding>? = null

    internal fun activate() { active = true }
    internal fun deactivate() {
        active = false
        val callbacks = synchronized(monitorGate) { interfaceMonitors.values.toList().also { interfaceMonitors.clear() } }
        val manager = context.getSystemService(ConnectivityManager::class.java)
        callbacks.forEach { callback -> runCatching { manager.unregisterNetworkCallback(callback) } }
        // libbox duplicates the supplied descriptor. We still own the original
        // and must release it after the core closes its duplicate.
        tunDescriptor?.close()
        root?.detach()
        tunDescriptor = null
        tunOpened = false
        applicationPolicySnapshot = null
        applicationPolicyMode = "none"
        applicationAllowList = emptyList()
        applicationExcludeList = emptyList()
        applicationPolicyBindings = null
    }

    /** Configure the one immutable Android VPN package policy. */
    internal fun configureApplicationPolicy(
        snapshot: BifrostApplicationPolicySnapshot,
        expectedBindings: List<BifrostApplicationPackageBinding>? = null,
    ) {
        val verified = BifrostApplicationPolicy.verify(snapshot)
        check(snapshot.includePackages == verified.includePackages && snapshot.excludePackages == verified.excludePackages) { "BF-APP-POLICY-SNAPSHOT" }
        applicationPolicyBindings = applicationPackageValidator.validate(verified, expectedBindings)
        applicationPolicySnapshot = verified
        applicationPolicyMode = verified.policyMode
        applicationAllowList = verified.includePackages
        applicationExcludeList = verified.excludePackages
    }

    internal fun applicationPolicyReadback(
        expectedBindings: List<BifrostApplicationPackageBinding>? = null,
    ): BifrostApplicationPolicySnapshot? {
        val snapshot = applicationPolicySnapshot?.let(BifrostApplicationPolicy::verify) ?: return null
        val currentBindings = applicationPackageValidator.validate(snapshot, applicationPolicyBindings)
        if (expectedBindings != null && currentBindings != expectedBindings) {
            throw IllegalStateException("BF-APP-PACKAGE-INVALID:changed")
        }
        return snapshot
    }

    /** Xray's dialer controller calls this for every upstream socket. */
    override fun protect(fd: Long): Boolean = fd in 0..Int.MAX_VALUE.toLong() && protectSocket(fd.toInt())

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    /** Protect every core/control socket so it cannot re-enter the VPN. */
    override fun autoDetectInterfaceControl(fd: Int) {
        check(protectSocket(fd)) { "BF-ANDROID-PROTECT" }
    }

    private fun protectSocket(fd: Int): Boolean {
        if (!active) return false
        if (root != null) {
            if (fd < 0) return false
            if (android.os.Process.myUid() != 0) return true
            // Our dedicated mark excludes only core sockets. Android's shared
            // protectedFromVpn bit must not exempt netd/resolver DNS queries
            // from the Root TUN policy.
            return runCatching { BifrostRootSocket.protect(fd) }.getOrDefault(false)
        }
        return runCatching { vpn?.protect(fd) == true }.getOrDefault(false)
    }

    override fun openTun(options: TunOptions): Int {
        check(!tunOpened) { "BF-TUN-ALREADY-OPEN" }
        val snapshot = applicationPolicySnapshot ?: error("BF-APP-POLICY-MISSING")
        val bindings = applicationPackageValidator.validate(snapshot, applicationPolicyBindings)
        if (root != null) {
            check(options.getMTU() == 1500) { "BF-ROOT-MTU" }
            val descriptor = root.attach()
            tunDescriptor = descriptor
            tunOpened = true
            return descriptor.fd
        }
        val builder = checkNotNull(vpn) { "BF-TUN-VPN-MISSING" }.Builder()
            .setSession("Bifrost")
            .setMtu(options.getMTU())
        // false means inherit the current underlying network's meteredness.
        // Capturing true on cellular makes the VPN stay metered after moving
        // to Wi-Fi and prevents Play/DownloadManager's unmetered jobs running.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        addAddresses(builder, options.getInet4Address())
        addAddresses(builder, options.getInet6Address())
        // The core has already subtracted exclusions from these ranges.
        // Adding the unfiltered routes as well would undo those exclusions.
        addRoutes(builder, options.getInet4RouteRange())
        addRoutes(builder, options.getInet6RouteRange())
        if (options.isHTTPProxyEnabled()) {
            // libbox owns the proxy; Android's Builder HTTP proxy is not used.
            check(options.getHTTPProxyServer().isBlank()) { "BF-TUN-HTTP-PROXY-UNSUPPORTED" }
        }
        val dns = options.getDNSServerAddress()?.value?.trim()
        check(!dns.isNullOrEmpty()) { "BF-TUN-DNS-MISSING" }
        // addDnsServer may reject malformed or non-IP values.  Let that
        // exception abort establish instead of silently creating a tunnel
        // with platform/default DNS and leaking queries.
        builder.addDnsServer(dns)
        // VpnService rejects a builder that receives both methods.  Use the
        // explicitly configured policy and fail closed on any package error.
        when (applicationPolicyMode) {
            "allow" -> addPackages(builder, bindings, allow = true)
            "exclude" -> {
                builder.addDisallowedApplication(context.packageName)
                addPackages(builder, bindings, allow = false)
            }
            "none" -> builder.addDisallowedApplication(context.packageName)
            else -> error("BF-APP-POLICY")
        }

        // The package manager state is mutable.  Re-read the complete signer,
        // version and update-time binding after all Builder mutations and
        // immediately before establish; a replacement/update in this TOCTOU
        // window must fail closed rather than widening the VPN policy.
        val finalBindings = applicationPackageValidator.validate(snapshot, bindings)
        check(finalBindings == bindings) { "BF-APP-PACKAGE-INVALID:changed" }

        val descriptor = builder.establish() ?: error("BF-TUN-ESTABLISH")
        tunDescriptor = descriptor
        tunOpened = true
        return descriptor.fd
    }

    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): ConnectionOwner {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) error("BF-OWNER-UNSUPPORTED")
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val uid = root?.owner(ipProtocol, sourceAddress, sourcePort, destinationAddress, destinationPort)
            ?: cm.getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort),
        )
        check(uid >= 0) { "BF-OWNER-NOT-FOUND" }
        val owner = ConnectionOwner().apply {
            userId = uid
            val packages = context.packageManager.getPackagesForUid(uid).orEmpty()
            userName = packages.firstOrNull().orEmpty()
            setAndroidPackageNames(StringArray(packages.asList()))
        }
        return owner
    }

    private val monitorGate = Any()
    private val interfaceMonitors = mutableMapOf<InterfaceUpdateListener, ConnectivityManager.NetworkCallback>()

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            private fun update() = synchronized(monitorGate) {
                if (interfaceMonitors[listener] === this) updateDefaultInterface(manager, listener)
            }
            override fun onAvailable(network: Network) = update()
            override fun onLost(network: Network) = update()
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) = update()
            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) = update()
        }
        synchronized(monitorGate) {
            check(!interfaceMonitors.containsKey(listener)) { "BF-NETWORK-OBSERVER-UNAVAILABLE" }
            interfaceMonitors[listener] = callback
            try {
                manager.registerNetworkCallback(NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
                updateDefaultInterface(manager, listener)
            } catch (error: Exception) {
                interfaceMonitors.remove(listener)
                runCatching { manager.unregisterNetworkCallback(callback) }
                throw error
            }
        }
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        val callback = synchronized(monitorGate) { interfaceMonitors.remove(listener) } ?: return
        runCatching { context.getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback) }
    }

    private fun updateDefaultInterface(manager: ConnectivityManager, listener: InterfaceUpdateListener) {
        val network = BifrostUnderlyingNetwork.select(manager)
        val capabilities = network?.let(manager::getNetworkCapabilities)
        val name = network?.let { manager.getLinkProperties(it)?.interfaceName }
        val index = name?.let { runCatching { JavaNetworkInterface.getByName(it)?.index }.getOrNull() }
        if (name == null || index == null || index <= 0) {
            listener.updateDefaultInterface("", -1, false, false)
            return
        }
        listener.updateDefaultInterface(name, index,
            capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) != true, false)
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val result = mutableListOf<NetworkInterface>()
        val all = runCatching { Collections.list(JavaNetworkInterface.getNetworkInterfaces()) }.getOrDefault(emptyList())
        all.forEach { iface ->
            val item = NetworkInterface().apply {
                index = iface.index
                name = iface.name
                mtu = runCatching { iface.mtu }.getOrDefault(0)
                flags = if (iface.isUp) OsConstants.IFF_UP or OsConstants.IFF_RUNNING else 0
                if (iface.isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
                if (iface.isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
                if (iface.supportsMulticast()) flags = flags or OsConstants.IFF_MULTICAST
                addresses = StringArray(iface.interfaceAddresses.map {
                    BifrostInterfaceAddress.prefix(it.address, it.networkPrefixLength.toInt())
                })
                dnsServer = EmptyStrings
                type = Libbox.InterfaceTypeOther
                metered = true
            }
            result += item
        }
        return InterfaceArray(result)
    }

    override fun underNetworkExtension(): Boolean = false
    override fun includeAllNetworks(): Boolean = false
    override fun readWIFIState(): WIFIState? = null
    override fun clearDNSCache() = Unit
    override fun sendNotification(notification: Notification) = Unit
    override fun localDNSTransport(): LocalDNSTransport? = null
    override fun systemCertificates(): StringIterator {
        val pem = runCatching {
            val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            store.aliases().toList().mapNotNull { alias ->
                val certificate = store.getCertificate(alias) ?: return@mapNotNull null
                val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(certificate.encoded)
                "-----BEGIN CERTIFICATE-----\n$encoded\n-----END CERTIFICATE-----"
            }
        }.getOrDefault(emptyList())
        return StringArray(pem)
    }

    private fun addAddresses(builder: VpnService.Builder, iterator: io.nekohasekai.libbox.RoutePrefixIterator) {
        while (iterator.hasNext()) {
            val prefix = iterator.next()
            builder.addAddress(prefix.address(), prefix.prefix())
        }
    }

    private fun addRoutes(builder: VpnService.Builder, iterator: io.nekohasekai.libbox.RoutePrefixIterator) {
        while (iterator.hasNext()) {
            val prefix = iterator.next()
            builder.addRoute(prefix.address(), prefix.prefix())
        }
    }

    private fun addPackages(builder: VpnService.Builder, packages: List<BifrostApplicationPackageBinding>, allow: Boolean) {
        packages.forEach { binding ->
            // Re-read the complete installed-image binding immediately before
            // adding each package.  Removal, update or signer replacement
            // cannot race into establish, and no all-app fallback is allowed.
            val packageName = applicationPackageValidator.validateBinding(binding).packageName
            if (packageName.isBlank()) throw IllegalArgumentException("BF-APP-PACKAGE-INVALID:blank")
            if (packageName == context.packageName) throw IllegalArgumentException("BF-APP-PACKAGE-INVALID:self")
            try {
                if (allow) builder.addAllowedApplication(packageName) else builder.addDisallowedApplication(packageName)
            } catch (error: Exception) {
                throw IllegalArgumentException("BF-APP-PACKAGE-INVALID:$packageName", error)
            }
        }
    }

    private class StringArray(values: Collection<String>) : StringIterator {
        private val entries = values.toList()
        private val iterator = entries.iterator()
        override fun len(): Int = entries.size
        override fun hasNext(): Boolean = iterator.hasNext()
        override fun next(): String = iterator.next()
    }

    private object EmptyStrings : StringIterator {
        override fun len(): Int = 0
        override fun hasNext(): Boolean = false
        override fun next(): String = ""
    }

    private class InterfaceArray(private val values: List<NetworkInterface>) : NetworkInterfaceIterator {
        private val iterator = values.iterator()
        override fun hasNext(): Boolean = iterator.hasNext()
        override fun next(): NetworkInterface = iterator.next()
    }
}
