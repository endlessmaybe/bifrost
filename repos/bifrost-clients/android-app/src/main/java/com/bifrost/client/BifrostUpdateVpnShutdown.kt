package com.bifrost.client

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Process
import java.util.concurrent.atomic.AtomicBoolean

/** Prevent a new native startup while PackageInstaller owns an update. */
internal object BifrostUpdateInstallGate {
    private val installing = AtomicBoolean(false)
    val pending: Boolean get() = installing.get()
    fun begin(): Boolean = synchronized(BifrostFeaturePreferences.transitionGate) {
        !BifrostFeaturePreferences.changing &&
            !(BifrostRuntimeStatus.current.state == BifrostLeakState.STOPPED &&
                BifrostApplicationPolicySnapshotRegistry.count() > 0) &&
            installing.compareAndSet(false, true)
    }
    fun end() { installing.set(false) }
}

internal object BifrostUpdateVpnShutdown {
    /** Runs on the updater's IO worker, never on Android's main thread. */
    fun awaitStopped(context: Context) {
        val owner = BifrostServiceOwnershipRegistry.current()
        if (owner != null) {
            val token = owner.token
            BifrostServiceOwnershipRegistry.requestDisconnect(token)
            context.startForegroundService(Intent(context, BifrostVpnService::class.java)
                .putExtra(BifrostVpnService.EXTRA_ACTION, BifrostVpnService.ACTION_DISCONNECT)
                .putExtra(BifrostVpnService.EXTRA_TRANSACTION_ID, token.transactionId)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_GENERATION, token.generation)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_DIGEST, token.digest)
                .putExtra(BifrostVpnService.EXTRA_APPLICATION_POLICY_BINDINGS, token.bindings))
        }
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val deadline = android.os.SystemClock.elapsedRealtime() + 15_000L
        do {
            val ownedVpn = manager.allNetworks.any { network ->
                val caps = manager.getNetworkCapabilities(network)
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
                    (if (android.os.Build.VERSION.SDK_INT >= 30) caps.ownerUid == Process.myUid()
                    else owner != null)
            }
            if (BifrostServiceOwnershipRegistry.current() == null &&
                BifrostRuntimeStatus.current.state == BifrostLeakState.STOPPED && !ownedVpn) return
            Thread.sleep(50)
        } while (android.os.SystemClock.elapsedRealtime() < deadline)
        error("BF-CONNECTION-TIMEOUT")
    }
}
