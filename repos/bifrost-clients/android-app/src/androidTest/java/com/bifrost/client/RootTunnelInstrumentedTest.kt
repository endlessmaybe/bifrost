package com.bifrost.client

import android.os.ParcelFileDescriptor
import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.FileInputStream
import java.io.File
import java.lang.reflect.Proxy
import java.net.InetAddress
import java.net.DatagramSocket
import java.net.DatagramPacket
import java.net.ServerSocket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import io.nekohasekai.libbox.*

/** Scoped to com.android.shell; ordinary apps and accounts are never routed. */
@RunWith(AndroidJUnit4::class)
class RootTunnelInstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private fun shell(command: String): ByteArray = ParcelFileDescriptor.AutoCloseInputStream(
        instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes() }
    private fun quote(value: String) = "'" + value.replace("'", "'\"'\"'") + "'"
    private val rootAdb by lazy { String(shell("id")).contains("uid=0(") }
    private fun rootCommand(script: File): String = if (rootAdb) "su 0 sh " + script.absolutePath
        else "su -c " + script.absolutePath
    private fun traffic(command: String): ByteArray {
        val pipes = instrumentation.uiAutomation.executeShellCommandRw(if (rootAdb) "su 2000 sh" else "sh")
        ParcelFileDescriptor.AutoCloseOutputStream(pipes[1]).use { it.write((command + "\n").toByteArray()) }
        return ParcelFileDescriptor.AutoCloseInputStream(pipes[0]).use { it.readBytes() }
    }
    private fun root(): BifrostRootTunnel {
        assumeTrue(BuildConfig.BIFROST_TEST_VARIANT)
        return BifrostRootTunnel(context, testLauncher = { args ->
            val script = File.createTempFile("root-launch-", ".sh", context.noBackupFilesDir)
            script.writeText("#!/system/bin/sh\nexec " + args.joinToString(" ", transform = ::quote) + "\n")
            script.setExecutable(true, true)
            val pipe = instrumentation.uiAutomation.executeShellCommand(rootCommand(script))
            object : BifrostRootProcess {
                // The relay may already have detached while the authenticated
                // helper still owns the descriptor. Exercise that real IPC path.
                override val isAlive get() = false
                override fun awaitExit(seconds: Long) { pipe.close(); script.delete() }
            }
        }, allowTestVpn = true)
    }
    private fun configure(tunnel: BifrostRootTunnel) = tunnel.configure(
        BifrostApplicationPolicy.normalize("per-app", "allow", listOf("com.android.shell"), emptyList()))
    private fun assertDnsReleased() {
        val table = 130000 + Process.myUid()
        assertFalse(String(shell("ip -6 rule show")).contains("lookup $table"))
        assertTrue(String(shell("ip -6 route show table $table")).isBlank())
        assertFalse(String(shell("ip6tables -t mangle -S")).contains("BFR_${Process.myUid()}_dns"))
    }
    @Test fun rootRemainsReadyAcrossBackgroundAndRepeatedHealthReadback() {
        val tunnel = root()
        configure(tunnel)
        try {
            assertTrue(tunnel.block())
            tunnel.attach().use {
                tunnel.releaseFence()
                shell("input keyevent KEYCODE_HOME")
                BifrostAppVisibility.update(false)
                repeat(7) {
                    Thread.sleep(10_000)
                    assertTrue("Detached relay must not stop the Root tunnel", tunnel.alive())
                }
            }
        } finally { tunnel.detach(); tunnel.close() }
        val table = "lookup " + (30000 + Process.myUid())
        for (family in listOf(4, 6)) assertFalse(String(shell("ip -$family rule show")).contains(table))
        assertDnsReleased()
    }
    @Test fun rootBoundaryRestartsAndCleansBothFamilies() {
        val uid = Process.myUid()
        repeat(2) {
            val tunnel = root()
            configure(tunnel)
            try {
                assertTrue(tunnel.block())
                tunnel.attach().use { descriptor ->
                    assertTrue(descriptor.fd > 0)
                    tunnel.releaseFence()
                    assertTrue(tunnel.alive())
                    for (family in listOf(4, 6)) {
                        val rules = String(shell("ip -$family rule show"))
                        assertTrue(rules.contains("uidrange 2000-2000 lookup " + (30000 + uid)))
                    }
                    tunnel.block()
                }
            } finally { tunnel.detach(); tunnel.close() }
            for (family in listOf(4, 6)) assertFalse(String(shell("ip -$family rule show")).contains("lookup " + (30000 + uid)))
            assertFalse(String(shell("ip link show")).contains("bfr$uid:"))
            assertDnsReleased()
        }
    }
    @Test fun youtubeUdpKeepsItsEgressAcrossBufferedPause() {
        assumeTrue("Uses only a disposable rooted emulator", rootAdb && android.os.Build.HARDWARE in listOf("ranchu", "goldfish"))
        val tunnel = root()
        configure(tunnel)
        var tun: ParcelFileDescriptor? = null
        var server: CommandServer? = null
        val worker = Executors.newSingleThreadExecutor()
        try {
            assertTrue(tunnel.block())
            (context.applicationContext as BifrostApplication).ensureLibboxInitialized()
            val platform = Proxy.newProxyInstance(PlatformInterface::class.java.classLoader,
                arrayOf(PlatformInterface::class.java)) { _, method, args ->
                when (method.name) {
                    "openTun" -> tunnel.attach().also { tun = it }.fd
                    "findConnectionOwner" -> ConnectionOwner().apply {
                        userId = tunnel.owner(args!![0] as Int, args[1] as String, args[2] as Int,
                            args[3] as String, args[4] as Int)
                        userName = "com.android.shell"
                        setAndroidPackageNames(object : StringIterator {
                            private var available = true
                            override fun hasNext() = available
                            override fun next(): String { available = false; return "com.android.shell" }
                            override fun len() = 1
                        })
                    }
                    "getInterfaces" -> object : NetworkInterfaceIterator {
                        override fun hasNext() = false
                        override fun next(): NetworkInterface? = null
                    }
                    "systemCertificates" -> object : StringIterator {
                        override fun hasNext() = false
                        override fun next() = ""
                        override fun len() = 0
                    }
                    else -> when (method.returnType) {
                        java.lang.Boolean.TYPE -> false
                        java.lang.Integer.TYPE -> 0
                        java.lang.Long.TYPE -> 0L
                        else -> null
                    }
                }
            } as PlatformInterface
            val handler = object : CommandServerHandler {
                override fun serviceStop() = Unit
                override fun serviceReload() = Unit
                override fun getSystemProxyStatus() = SystemProxyStatus()
                override fun setSystemProxyEnabled(enabled: Boolean) = Unit
                override fun writeDebugMessage(message: String) = Unit
            }
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { echo ->
                echo.soTimeout = 48_000
                val echoed = worker.submit<List<Int>> {
                    (0..1).map {
                        val packet = DatagramPacket(ByteArray(2048), 2048)
                        echo.receive(packet)
                        val port = packet.port
                        echo.send(packet)
                        port
                    }
                }
                val json = org.json.JSONObject("""{
                  "log":{"level":"warn"},
                  "dns":{"servers":[{"type":"hosts","tag":"remote-dns","predefined":{"buffer-test.googlevideo.com":["127.0.0.1"]}},{"type":"hosts","tag":"direct-dns","predefined":{"buffer-test.googlevideo.com":["127.0.0.1"]}}],"final":"remote-dns"},
                  "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"stack":"gvisor","auto_route":true}],
                  "outbounds":[{"type":"direct","tag":"direct"}],
                  "route":{"rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"}],"final":"direct"}
                }""")
                val trace = File(context.cacheDir, "youtube-udp-test.log")
                trace.delete()
                json.getJSONObject("log").put("level", "debug").put("output", trace.absolutePath)
                val rules = json.getJSONObject("route").getJSONArray("rules")
                // Optional legacy mode proves this regression against the
                // exact bundled runtime without rebuilding another native AAR.
                if (InstrumentationRegistry.getArguments().getString("legacyVideoPolicy") != "true")
                    BifrostRoutingRules.preserveYoutubeUdp(rules)
                rules.put(org.json.JSONObject().put("outbound", "direct")
                    .put("override_port", echo.localPort))
                BifrostDualStackDns.configure(json.getJSONObject("dns"), json.getJSONObject("route"), json.getJSONArray("outbounds"))
                server = Libbox.newCommandServer(handler, platform)
                server!!.start()
                Libbox.checkConfig(json.toString())
                server!!.startOrReloadService(json.toString(), OverrideOptions())
                tunnel.releaseFence()
                val hostname = "buffer-test.googlevideo.com"
                var query = byteArrayOf(0x12,0x34,1,0,0,1,0,0,0,0,0,0)
                hostname.split('.').forEach { query += byteArrayOf(it.length.toByte()) + it.toByteArray() }
                query += byteArrayOf(0,0,1,0,1)
                val octal = query.joinToString("") { "\\" + (it.toInt() and 255).toString(8).padStart(3,'0') }
                val answer = traffic("printf '" + octal + "' | timeout 5 nc -u -W 1 172.19.0.2 53")
                assertTrue("Fake A response missing", answer.size >= 4)
                val address = InetAddress.getByAddress(answer.takeLast(4).toByteArray()).hostAddress!!
                assertTrue(address.startsWith("198.18."))
                val initial = java.util.Base64.getDecoder().decode(javaClass.getResourceAsStream("youtube-quic-initial.txt")!!.bufferedReader().use { it.readText().trim() })
                val initialOctal = initial.joinToString("") { "\\" + (it.toInt() and 255).toString(8).padStart(3,'0') }
                // Use a real QUIC Initial so the native sniffer selects its
                // actual protocol timeout, even with a loopback test endpoint.
                val reply = traffic("{ printf '" + initialOctal + "'; sleep 35; printf second; sleep 1; } | timeout 44 nc -u -4 -w 42 " + address + " 443")
                assertArrayEquals("Both bursts must be returned through the TUN\n" + trace.readText().takeLast(6000), initial + "second".toByteArray(), reply)
                val ports = echoed.get(2, TimeUnit.SECONDS)
                assertEquals("The upstream UDP mapping must survive a 35-second playback gap", ports[0], ports[1])
            }
        } finally {
            if (tunnel.alive()) runCatching { tunnel.block() }
            runCatching { server?.closeService(); server?.close() }
            tun?.close(); tunnel.detach(); tunnel.close()
            worker.shutdownNow()
        }
        assertDnsReleased()
    }

    @Test fun virtualIpv6TcpUsesIpv4OnlyDestinationAndUdpRemainsAvailable() {
        val tunnel = root()
        configure(tunnel)
        var tun: ParcelFileDescriptor? = null
        var server: CommandServer? = null
        val worker = Executors.newSingleThreadExecutor()
        try {
            assertTrue(tunnel.block())
            (context.applicationContext as BifrostApplication).ensureLibboxInitialized()
            val platform = Proxy.newProxyInstance(PlatformInterface::class.java.classLoader,
                arrayOf(PlatformInterface::class.java)) { _, method, args ->
                when (method.name) {
                    "openTun" -> tunnel.attach().also { tun = it }.fd
                    "usePlatformAutoDetectInterfaceControl" -> false
                    "findConnectionOwner" -> ConnectionOwner().apply {
                        userId = tunnel.owner(args!![0] as Int, args[1] as String, args[2] as Int,
                            args[3] as String, args[4] as Int)
                        userName = "com.android.shell"
                        setAndroidPackageNames(object : StringIterator {
                            private var available = true
                            override fun hasNext() = available
                            override fun next(): String { available = false; return "com.android.shell" }
                            override fun len() = 1
                        })
                    }
                    "getInterfaces" -> object : NetworkInterfaceIterator {
                        override fun hasNext() = false
                        override fun next(): NetworkInterface? = null
                    }
                    "systemCertificates" -> object : StringIterator {
                        override fun hasNext() = false
                        override fun next() = ""
                        override fun len() = 0
                    }
                    else -> when (method.returnType) {
                        java.lang.Boolean.TYPE -> false
                        java.lang.Integer.TYPE -> 0
                        java.lang.Long.TYPE -> 0L
                        else -> null
                    }
                }
            } as PlatformInterface
            val handler = object : CommandServerHandler {
                override fun serviceStop() = Unit
                override fun serviceReload() = Unit
                override fun getSystemProxyStatus() = SystemProxyStatus()
                override fun setSystemProxyEnabled(enabled: Boolean) = Unit
                override fun writeDebugMessage(message: String) = Unit
            }
            ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { echo ->
                echo.soTimeout = 15_000
                val echoed = worker.submit {
                    echo.accept().use { peer ->
                        peer.soTimeout = 5000
                        val bytes = ByteArray(4); peer.inputStream.read(bytes)
                        peer.outputStream.write(bytes); peer.outputStream.flush()
                    }
                }
                val config = """{
                  "log":{"level":"warn"},
                  "dns":{"servers":[
                    {"type":"hosts","tag":"remote-dns","predefined":{"bifrost-dual.test":["127.0.0.1"]}},
                    {"type":"hosts","tag":"direct-dns","predefined":{"bifrost-dual.test":["127.0.0.1"]}}],
                    "final":"remote-dns","strategy":"ipv4_only"},
                  "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"stack":"gvisor","auto_route":true}],
                  "outbounds":[{"type":"direct","tag":"direct"}],
                  "route":{"rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"}],"final":"direct"}
                }"""
                val json = org.json.JSONObject(config)
                val trace = File(context.cacheDir, "root-dual-test.log")
                trace.delete()
                json.getJSONObject("log").put("level", "debug").put("output", trace.absolutePath)
                BifrostDualStackDns.configure(json.getJSONObject("dns"), json.getJSONObject("route"), json.getJSONArray("outbounds"))
                server = Libbox.newCommandServer(handler, platform)
                server!!.start()
                Libbox.checkConfig(json.toString())
                server!!.startOrReloadService(json.toString(), OverrideOptions())
                tunnel.releaseFence()
                // Issue an AAAA query via the shell UID, inside the root TUN.
                val query = byteArrayOf(0x12,0x34,1,0,0,1,0,0,0,0,0,0,12) +
                    "bifrost-dual".toByteArray() + byteArrayOf(4) + "test".toByteArray() + byteArrayOf(0,0,28,0,1)
                val octal = query.joinToString("") { "\\" + (it.toInt() and 255).toString(8).padStart(3,'0') }
                val answer = traffic("printf '" + octal + "' | timeout 5 nc -u -W 1 172.19.0.2 53")
                assertTrue("UDP DNS must return a virtual IPv6 answer: " + answer.size, answer.size >= 16)
                val virtual = InetAddress.getByAddress(answer.takeLast(16).toByteArray()).hostAddress!!
                assertTrue(virtual.startsWith("fc00:"))
                val reply = traffic("{ printf ping; sleep 1; } | timeout 6 nc -6 -w 4 -W 2 " + virtual + " " + echo.localPort)
                assertEquals("virtual=" + virtual + "\n" + trace.readText().takeLast(6000), "ping", String(reply))
                echoed.get(5, TimeUnit.SECONDS)
                // Exercise repeated UDP payloads through the same dual-stack
                // TUN, including packets large enough to require fragmentation.
                val queryA = query.copyOf().also { it[it.size - 3] = 1 }
                val octalA = queryA.joinToString("") { "\\" + (it.toInt() and 255).toString(8).padStart(3,'0') }
                val answerA = traffic("printf '" + octalA + "' | timeout 5 nc -u -W 1 172.19.0.2 53")
                assertTrue(answerA.size >= 4)
                val virtual4 = InetAddress.getByAddress(answerA.takeLast(4).toByteArray()).hostAddress!!
                assertTrue(virtual4.startsWith("198.18."))
                DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { udp ->
                    udp.soTimeout = 10_000
                    for ((family, address) in listOf("-6" to virtual, "-4" to virtual4)) {
                        val datagrams = worker.submit {
                            repeat(3) {
                                val packet = DatagramPacket(ByteArray(4096), 4096)
                                udp.receive(packet); udp.send(packet)
                            }
                        }
                        val payload = "bifrost-udp-".repeat(150)
                        val received = traffic("{ printf %s " + quote(payload) + "; sleep 1; printf %s " +
                            quote(payload) + "; sleep 1; printf %s " + quote(payload) +
                            "; sleep 1; } | timeout 8 nc -u " + family + " -w 4 -W 2 " + address + " " + udp.localPort)
                        assertEquals("UDP $family\n" + trace.readText().takeLast(6000), payload.repeat(3), String(received))
                        datagrams.get(3, TimeUnit.SECONDS)
                    }
                }
            }
        } finally {
            if (tunnel.alive()) runCatching { tunnel.block() }
            runCatching { server?.closeService(); server?.close() }
            tun?.close(); tunnel.detach(); tunnel.close()
            worker.shutdownNow()
        }
    }
}
