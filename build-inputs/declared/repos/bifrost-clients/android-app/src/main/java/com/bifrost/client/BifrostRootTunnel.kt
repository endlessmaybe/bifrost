package com.bifrost.client

import android.content.Context
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import java.io.BufferedReader
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
internal interface BifrostRootProcess {
    val isAlive: Boolean
    fun awaitExit(seconds: Long)
    fun failureCode(): String? = null
    fun cancel() = Unit
}

/**
 * Root supplies a kernel TUN descriptor to the independent native runtime.
 * An authenticated socket ties privileged routes to that runtime's lifetime;
 * the ordinary app retains Keystore, account checks and explicit user control.
 */
internal class BifrostRootTunnel(private val context: Context,
    private val testLauncher: ((List<String>) -> BifrostRootProcess)? = null,
    private val allowTestVpn: Boolean = false,
    private val ownerUid: Int = Process.myUid()) : BifrostRootBoundary {
    init { check(testLauncher == null && !allowTestVpn || BuildConfig.BIFROST_TEST_VARIANT) { "BF-RELEASE-TEST-ONLY" } }
    private var policy: BifrostApplicationPolicySnapshot? = null
    private var socket: LocalSocket? = null
    private var reader: BufferedReader? = null
    private var process: BifrostRootProcess? = null
    private var descriptor: ParcelFileDescriptor? = null
    @Volatile var attached = false
        private set
    private var lastReadback = 0L
    private var fenceReleased = false
    private var infrastructureUids: List<Int>? = null
    private var physicalDns: List<String>? = null
    private var hotspotMode = BifrostFeaturePreferences.hotspotMode(context)

    @Synchronized override fun configure(snapshot: BifrostApplicationPolicySnapshot) {
        val verified = BifrostApplicationPolicy.verify(snapshot)
        if (descriptor != null) check(policy?.digest == verified.digest) { "BF-ROOT-POLICY-CHANGED" }
        policy = verified
    }
    @Synchronized override fun block(): Boolean {
        ensureStarted()
        request("BLOCK")
        fenceReleased = false
        return true
    }
    @Synchronized override fun releaseFence() {
        if (attached) {
            request("READY")
            if (!fenceReleased) BifrostRootDnsCache.flush(context)
            fenceReleased = true
        } else close()
    }
    @Synchronized fun attach(): ParcelFileDescriptor {
        check(!attached) { "BF-TUN-ALREADY-OPEN" }
        val current = descriptor ?: error("BF-ROOT-NOT-READY")
        return ParcelFileDescriptor.dup(current.fileDescriptor).also { attached = true }
    }
    @Synchronized fun detach() { attached = false }
    @Synchronized fun setHotspotMode(mode: String) {
        check(mode in setOf("smart", "direct")) { "BF-ROOT-POLICY" }
        if (socket != null) request("HOTSPOT $mode")
        hotspotMode = mode
    }
    @Synchronized fun refreshHotspot() {
        if (socket != null) request("TETHER")
    }
    @Synchronized fun networkChanged() {
        lastReadback = 0L
        if (descriptor != null && socket != null) {
            refreshPhysicalDns()
            request("NETWORK")
        }
    }
    @Synchronized override fun alive(): Boolean {
        if (descriptor == null || socket == null) return false
        val now = android.os.SystemClock.elapsedRealtime()
        if (now - lastReadback >= 30_000) {
            // The authenticated helper socket owns the tunnel. A su relay can
            // exit independently; its Java Process is not a tunnel health test.
            val result = runCatching { request("STATUS") }
            if (result.isFailure) {
                BifrostDiagnostics.record(context, "root-health-failed", result.exceptionOrNull())
                return false
            }
            if (runCatching { BifrostRootCoexistence.infrastructureUids(context, ownerUid) }.getOrNull() != infrastructureUids) {
                BifrostDiagnostics.record(context, "root-infrastructure-changed")
                return false
            }
            val dnsUpdated = runCatching { refreshPhysicalDns() }
            if (dnsUpdated.isFailure) {
                BifrostDiagnostics.record(context, "root-dns-refresh-failed", dnsUpdated.exceptionOrNull())
                return false
            }
            lastReadback = now
        }
        return true
    }

    fun owner(protocol: Int, source: String, sourcePort: Int, target: String, targetPort: Int): Int {
        check(protocol in setOf(6, 17) && sourcePort in 0..65535 && targetPort in 0..65535) { "BF-OWNER-NOT-FOUND" }
        val ip = Regex("[0-9a-fA-F:.]{2,45}")
        check(ip.matches(source) && ip.matches(target)) { "BF-OWNER-NOT-FOUND" }
        if (Process.myUid() == 0) return BifrostRootSocket.owner(protocol, source, sourcePort, target, targetPort)
            .also { check(it >= 0) { "BF-OWNER-NOT-FOUND" } }
        return synchronized(this) { legacyOwner(protocol, source, sourcePort, target, targetPort) }
    }
    private fun legacyOwner(protocol: Int, source: String, sourcePort: Int, target: String, targetPort: Int): Int {
        val response = request("OWNER $protocol $source $sourcePort $target $targetPort", requireOk = false)
        check(response.startsWith("UID ")) { "BF-OWNER-NOT-FOUND" }
        return response.removePrefix("UID ").toInt().also { check(it >= 0) { "BF-OWNER-NOT-FOUND" } }
    }
    @Synchronized override fun close() {
        if (socket == null) return
        check(!attached) { "BF-ROOT-CORE-ACTIVE" }
        try { request("STOP") } finally {
            // Closing IPC also triggers exact journal-based cleanup if the
            // acknowledgement is lost. Never retain a stale helper/socket.
            runCatching { descriptor?.close() }; descriptor = null
            runCatching { socket?.close() }; socket = null; reader = null
            runCatching { process?.awaitExit(10) }; process = null
            fenceReleased = false
            infrastructureUids = null
            physicalDns = null
            BifrostRootDnsCache.flush(context)
        }
    }
    private fun refreshPhysicalDns() {
        val current = BifrostRootCoexistence.physicalDns(context)
        // Losing a network transiently does not invalidate a live TUN. New
        // scoped DNS routes are installed in place once the next network exists.
        if (current.isEmpty() || current == physicalDns) return
        request("DNS " + current.joinToString(" "))
        physicalDns = current
        BifrostDiagnostics.record(context, "root-dns-refreshed")
    }
    private fun request(command: String, requireOk: Boolean = true): String {
        val connection = socket ?: error("BF-ROOT-NOT-READY")
        connection.outputStream.write((command + "\n").toByteArray(Charsets.US_ASCII))
        connection.outputStream.flush()
        val response = reader?.readLine() ?: error("BF-ROOT-CLOSED")
        if (requireOk) check(response == "OK") { response.takeIf { it.startsWith("BF-") } ?: "BF-ROOT-READBACK" }
        return response
    }
    private fun ensureStarted() {
        if (descriptor != null) {
            if (alive()) return
            check(!attached) { "BF-ROOT-CORE-ACTIVE" }
            // After core teardown, discard only our dead IPC/FD. The next
            // authenticated helper recovers its exact journal before fencing.
            runCatching { close() }
        }
        val snapshot = policy ?: error("BF-APP-POLICY-MISSING")
        // Root does not acquire the VPN slot. A Tailscale network appearing
        // after startup must not prohibit recreating a failed Root boundary.
        val currentInfrastructure = BifrostRootCoexistence.infrastructureUids(context, ownerUid)
        val currentDns = BifrostRootCoexistence.physicalDns(context)
        val packages = when (snapshot.policyMode) {
            "allow" -> snapshot.includePackages
            "exclude" -> snapshot.excludePackages
            else -> emptyList()
        }
        val uids = packages.map { context.packageManager.getApplicationInfo(it, 0).uid }.distinct().sorted()
        check(uids.size <= 256) { "BF-ROOT-POLICY" }
        val executable = prepareExecutable(context)
        val name = "bifrost-root-" + ByteArray(32).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
        val server = LocalServerSocket(name)
        val acceptor = Executors.newSingleThreadExecutor()
        val accepted = acceptor.submit<LocalSocket> { server.accept() }
        var connection: LocalSocket? = null
        var helper: BifrostRootProcess? = null
        try {
            val args = listOf(executable.absolutePath, name, ownerUid.toString(), executable.parentFile!!.canonicalPath) +
                if (Process.myUid() == 0) listOf("--daemon") else emptyList()
            helper = testLauncher?.invoke(args) ?: run {
                RootProcess(args)
            }
            val deadline = android.os.SystemClock.elapsedRealtime() + 30_000
            while (connection == null) {
                try { connection = accepted.get(100, TimeUnit.MILLISECONDS) }
                catch (_: TimeoutException) {
                    helper.failureCode()?.let { error(it) }
                    check(android.os.SystemClock.elapsedRealtime() < deadline) { "BF-ROOT-PERMISSION" }
                }
            }
            check(connection.peerCredentials.uid == 0) { "BF-ROOT-PEER" }
            connection.soTimeout = 30_000
            val wire = BifrostRootCoexistence.wire(ownerUid, snapshot.policyMode, uids, currentInfrastructure, currentDns, hotspotMode)
            connection.outputStream.write(wire.toByteArray(Charsets.US_ASCII)); connection.outputStream.flush()
            val first = connection.inputStream.read()
            if (first != 'T'.code) {
                val failure = StringBuilder().apply { if (first >= 0) append(first.toChar()) }
                while (failure.length < 100) {
                    val byte = connection.inputStream.read()
                    if (byte < 0 || byte == 10) break
                    failure.append(byte.toChar())
                }
                error(rootFailure(failure.toString()) ?: "BF-ROOT-START")
            }
            val descriptors = connection.ancillaryFileDescriptors
            check(descriptors?.size == 1) { "BF-ROOT-FD" }
            val fd = try { ParcelFileDescriptor.dup(descriptors[0]) } finally { Os.close(descriptors[0]) }
            socket = connection; reader = connection.inputStream.bufferedReader(Charsets.US_ASCII)
            descriptor = fd; process = helper
            infrastructureUids = currentInfrastructure
            physicalDns = currentDns
            request("STATUS")
            lastReadback = android.os.SystemClock.elapsedRealtime()
            BifrostDiagnostics.record(context, "root-tunnel-ready")
        } catch (error: Throwable) {
            runCatching { connection?.close() }
            descriptor?.close(); descriptor = null; socket = null; reader = null; process = null
            infrastructureUids = null
            // Closing IPC gives the helper time to remove its exact routes.
            helper?.awaitExit(10)
            helper?.cancel()
            throw error
        } finally { server.close(); accepted.cancel(true); acceptor.shutdownNow() }
    }
    companion object {
        private val executableGate = Any()
        private const val CAPABILITIES = "BFR1 ROOT TCP UDP IPV6"
        private fun rootFailure(line: String): String? = line.trim().takeIf {
            it.matches(Regex("BF-ROOT-[A-Z-]{1,45}"))
        }
        /** Drain su output without recording its text, paths or manager messages. */
        private class RootProcess(args: List<String>) : BifrostRootProcess {
            private val child = try {
                // The independent daemon already has Root. Starting its helper
                // directly avoids a second su session and manager dependency.
                ProcessBuilder(if (Process.myUid() == 0) args else listOf("su", "-c",
                    "exec " + args.joinToString(" ", transform = ::shellQuote))).redirectErrorStream(true).start()
                    .also { it.outputStream.close() }
            } catch (error: java.io.IOException) { throw IllegalStateException("BF-ROOT-PERMISSION", error) }
            @Volatile private var failure: String? = null
            @Volatile var capabilities = false
                private set
            private val drain = Thread({
                runCatching {
                    child.inputStream.bufferedReader(Charsets.US_ASCII).use { input ->
                        val line = StringBuilder()
                        while (true) {
                            val next = input.read()
                            if (next < 0) break
                            if (next == 10) {
                                if (line.toString().trim() == CAPABILITIES) capabilities = true
                                rootFailure(line.toString())?.let { failure = it }
                                line.setLength(0)
                            } else if (line.length < 512) line.append(next.toChar())
                        }
                    }
                }
            }, "bifrost-root-output").apply { isDaemon = true; start() }
            override val isAlive get() = child.isAlive
            override fun awaitExit(seconds: Long) { child.waitFor(seconds, TimeUnit.SECONDS); if (!child.isAlive) drain.join(1000) }
            override fun failureCode(): String? {
                if (!child.isAlive) drain.join(1000)
                return failure ?: if (!child.isAlive && child.exitValue() != 0) "BF-ROOT-PERMISSION" else null
            }
            fun probe(): Boolean {
                val exited = child.waitFor(30, TimeUnit.SECONDS)
                if (exited) drain.join(1000)
                return exited && child.exitValue() == 0 && capabilities
            }
            override fun cancel() { if (child.isAlive) child.destroy() }
        }
        private fun shellQuote(value: String): String {
            check(value.none { it == '\n' || it == '\r' || it == '\u0000' }) { "BF-ROOT-PATH" }
            return "'" + value.replace("'", "'\"'\"'") + "'"
        }
        internal fun prepareExecutable(context: Context): File = synchronized(executableGate) {
            val abi = Build.SUPPORTED_ABIS.firstOrNull { it in setOf("arm64-v8a", "armeabi-v7a", "x86_64") }
                ?: error("BF-ROOT-UNSUPPORTED")
            val directory = File(context.noBackupFilesDir, "root").canonicalFile
            check(directory.isDirectory || directory.mkdirs()) { "BF-ROOT-STORAGE" }
            check(!Files.isSymbolicLink(directory.toPath())) { "BF-ROOT-STORAGE" }
            Os.chmod(directory.absolutePath, 0x1c0)
            if (Process.myUid() == 0) Os.chown(directory.absolutePath, context.applicationInfo.uid, -1)
            val target = File(directory, "bifrost-root")
            check(!Files.isSymbolicLink(target.toPath())) { "BF-ROOT-STORAGE" }
            val bytes = context.assets.open("root/$abi/bifrost-root").use { it.readBytes() }
            fun digest(content: ByteArray) = MessageDigest.getInstance("SHA-256").digest(content)
            if (!target.isFile || !digest(target.readBytes()).contentEquals(digest(bytes))) {
                val temp = File.createTempFile("root-", ".tmp", directory)
                try {
                    temp.outputStream().use { it.write(bytes); it.fd.sync() }
                    Os.chmod(temp.absolutePath, 0x1c0)
                    Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                } finally { temp.delete() }
            }
            Os.chmod(target.absolutePath, 0x1c0)
            if (Process.myUid() == 0) Os.chown(target.absolutePath, context.applicationInfo.uid, -1)
            target
        }
        /** Runs only after an explicit user opt-in, on a worker thread. */
        fun probe(context: Context) {
            val executable = prepareExecutable(context)
            val process = RootProcess(listOf(executable.absolutePath, "--probe"))
            try {
                check(process.probe()) { process.failureCode() ?: "BF-ROOT-PERMISSION" }
            } finally { process.cancel() }
        }
    }
}
