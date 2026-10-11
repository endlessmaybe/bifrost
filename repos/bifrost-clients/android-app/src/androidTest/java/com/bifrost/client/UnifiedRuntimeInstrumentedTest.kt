package com.bifrost.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.XraySocketProtector
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.json.JSONObject

/**
 * Runs on an API-28+ emulator/device.  The test intentionally does not
 * establish a production VPN or touch system routes; it only loads the one
 * bundled gomobile runtime, exercises its raw-socket protection probe, and
 * verifies a second start/stop lifecycle.  android-unified-runtime-smoke.ps1
 * installs the release APK and invokes this test when an emulator is present.
 */
@RunWith(AndroidJUnit4::class)
class UnifiedRuntimeInstrumentedTest {
    @Test
    fun compiledVmessDnsAndRoutingStartAndRestartInBundledRuntime() {
        // The minimal SOCKS echo config cannot detect missing VMess, TLS,
        // WebSocket, DNS or routing registrations. Exercise compiler output
        // with synthetic endpoints; startup must not dial them.
        val payload = """
            {"routing":{"dns_policy":{"version":"dns-policy-v1","remote":"https://remote.example.invalid/dns-query","direct":"https://direct.example.invalid/dns-query","smart_gate_remote":true,"plaintext_fallback":false,"ipv4":"proxy","ipv6":"proxy","failure":"block"}},
             "sources":[{"code":"A","configured":true,"server_name":"source.example.invalid","ws_path":"/vmess",
               "transport":{"network":"ws","tls":true},
               "candidates":[{"id":"a-1","label":"A-01","dial_address":"127.0.0.1","port":443}],
               "profiles":{"direct":{"uuid":"00000000-0000-4000-8000-000000000001"}}}]}
        """.trimIndent()
        Libbox.setXraySocketProtector(XraySocketProtector { _ -> false })
        for (mode in listOf("smart", "global")) {
            val policy = BifrostApplicationPolicy.normalize(mode, "none", emptyList(), emptyList())
            val config = BifrostXrayConfigCompiler.compile(payload, "A", "auto", mode = mode, applicationPolicy = policy)
            assertTrue(JSONObject(config).has("routing"))
            val transport = BifrostXrayTransport()
            repeat(2) {
                try {
                    transport.start(config)
                    assertTrue(transport.isReady())
                } finally {
                    transport.stop()
                }
                assertFalse(transport.isReady())
            }
        }
    }

    @Test
    fun unifiedRuntimeLoadsProtectsAndRestarts() {
        Libbox.touch()
        var callbackCount = 0
        Libbox.setXraySocketProtector(XraySocketProtector { _ -> callbackCount++; true })
        assertTrue("the real raw-socket controller must call the VpnService protector", Libbox.xrayProtectProbe())

        val first = Libbox.newXrayEngine()
        assertFalse(first.isRunning)
        first.stop()
        val second = Libbox.newXrayEngine()
        assertFalse(second.isRunning)
        second.stop()
        assertTrue("protect callback was not exercised", callbackCount > 0)
    }

    /**
     * The second half of the smoke test is deliberately loopback-only.  It
     * starts the actual in-process Xray binding, sends one SOCKS5 CONNECT and
     * a small payload to a local echo server, then stops and restarts the
     * binding.  No VPN, route, DNS or external socket is touched.
     */
    @Test
    fun xrayBindingCarriesTestOnlyLoopbackTraffic() {
        var callbackCount = 0
        Libbox.setXraySocketProtector(XraySocketProtector { _ -> callbackCount++; true })
        assertTrue(Libbox.xrayProtectProbe())

        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { upstream ->
            val received = CountDownLatch(1)
            val worker = Thread {
                runCatching {
                    upstream.accept().use { socket ->
                        val input = BufferedInputStream(socket.getInputStream())
                        val output = BufferedOutputStream(socket.getOutputStream())
                        val payload = ByteArray(4)
                        input.readFully(payload)
                        check(String(payload, Charsets.US_ASCII) == "ping")
                        output.write("pong".toByteArray(Charsets.US_ASCII))
                        output.flush()
                    }
                }.also { received.countDown() }
            }
            worker.start()

            val transport = BifrostXrayTransport()
            val config = """
                {"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],"outbounds":[{"protocol":"freedom","settings":{}}]}
            """.trimIndent()
            val proxyPort = transport.start(config)
            try {
                Socket("127.0.0.1", proxyPort).use { proxy ->
                    proxy.soTimeout = 5_000
                    val input = BufferedInputStream(proxy.getInputStream())
                    val output = BufferedOutputStream(proxy.getOutputStream())
                    output.write(byteArrayOf(0x05, 0x01, 0x00))
                    output.flush()
                    check(input.read() == 0x05 && input.read() == 0x00)
                    val port = upstream.localPort
                    output.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
                        (port shr 8).toByte(), port.toByte()))
                    output.flush()
                    check(input.read() == 0x05 && input.read() == 0x00)
                    check(input.read() == 0x00) // RSV
                    val atyp = input.read() // ATYP
                    val addressLength = when (atyp) {
                        0x01 -> 4
                        0x03 -> input.read()
                        0x04 -> 16
                        else -> error("unexpected SOCKS5 ATYP $atyp")
                    }
                    repeat(addressLength + 2) { input.read() } // BND.ADDR + BND.PORT
                    output.write("ping".toByteArray(Charsets.US_ASCII))
                    output.flush()
                    val response = ByteArray(4)
                    input.readFully(response)
                    check(String(response, Charsets.US_ASCII) == "pong")
                }
            } finally {
                transport.stop()
                check(!transport.isReady())
            }
            check(received.await(5, TimeUnit.SECONDS))
            check(callbackCount > 0)
        }
    }

    private fun java.io.InputStream.readFully(target: ByteArray) {
        var offset = 0
        while (offset < target.size) {
            val count = read(target, offset, target.size - offset)
            check(count > 0) { "unexpected EOF" }
            offset += count
        }
    }
}
