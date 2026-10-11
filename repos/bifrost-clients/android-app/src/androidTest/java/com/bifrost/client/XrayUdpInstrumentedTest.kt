package com.bifrost.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.XraySocketProtector
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Uses the production compiler's SOCKS listener and the bundled native Xray.
 * IPv4/IPv6 UDP echoes stay on loopback and require no account or VPN routes. */
@RunWith(AndroidJUnit4::class)
class XrayUdpInstrumentedTest {
    @Test fun compiledSocksCarriesIpv4AndIpv6Datagrams() {
        val source = """{"routing":{"dns_policy":{"version":"dns-policy-v1","remote":"https://remote.example.invalid/dns-query","direct":"https://direct.example.invalid/dns-query","smart_gate_remote":true,"plaintext_fallback":false,"ipv4":"proxy","ipv6":"proxy","failure":"block"}},"sources":[{"code":"A","configured":true,"server_name":"source.example.invalid","ws_path":"/vmess",
            "transport":{"network":"ws","tls":true},"candidates":[{"id":"a-1","label":"A-01","dial_address":"127.0.0.1","port":443}],
            "profiles":{"direct":{"uuid":"00000000-0000-4000-8000-000000000001"}}}]}"""
        val policy = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
        val compiled = JSONObject(BifrostXrayConfigCompiler.compile(source, "A", "auto", mode="global", applicationPolicy=policy))
        val config = JSONObject().put("log", JSONObject().put("loglevel", "none"))
            .put("inbounds", compiled.getJSONArray("inbounds"))
            .put("outbounds", JSONArray().put(JSONObject().put("protocol", "freedom").put("settings", JSONObject())))
        Libbox.setXraySocketProtector(XraySocketProtector { true })
        val engine = BifrostXrayTransport()
        try {
            val proxyPort = engine.start(config.toString())
            for (address in listOf("127.0.0.1", "::1")) {
                DatagramSocket(0, InetAddress.getByName(address)).use { echo ->
                    echo.soTimeout = 5000
                    val result = CompletableFuture<Unit>()
                    val worker = Thread {
                        try {
                            val packet = DatagramPacket(ByteArray(2048), 2048)
                            echo.receive(packet); echo.send(packet); result.complete(Unit)
                        } catch (error: Throwable) { result.completeExceptionally(error) }
                    }.apply { isDaemon = true; start() }
                    Socket("127.0.0.1", proxyPort).use { control ->
                        control.soTimeout = 5000
                        val input = control.getInputStream(); val output = control.getOutputStream()
                        output.write(byteArrayOf(5,1,0)); output.flush()
                        assertEquals(5,input.read()); assertEquals(0,input.read())
                        output.write(byteArrayOf(5,3,0,1,127,0,0,1,0,0)); output.flush()
                        assertEquals(5,input.read()); assertEquals(0,input.read()); assertEquals(0,input.read())
                        val type = input.read()
                        val size = when(type) {1 -> 4; 4 -> 16; else -> error("Unexpected relay address type: $type")}
                        val relayAddress = ByteArray(size) { input.read().also { assertTrue(it >= 0) }.toByte() }
                        val port = (input.read() shl 8) or input.read()
                        DatagramSocket().use { client ->
                            client.soTimeout = 5000
                            val target = echo.localAddress.address
                            val payload = "bifrost-native-udp-$address".toByteArray()
                            val header = byteArrayOf(0,0,0,if(target.size==4) 1 else 4) + target +
                                byteArrayOf((echo.localPort shr 8).toByte(), echo.localPort.toByte())
                            val bytes = header + payload
                            client.send(DatagramPacket(bytes,bytes.size,InetAddress.getByAddress(relayAddress),port))
                            val response = DatagramPacket(ByteArray(2048),2048); client.receive(response)
                            assertEquals(0,response.data[2].toInt())
                            val offset = when(response.data[3].toInt()) {1 -> 10; 4 -> 22; else -> error("Unexpected UDP reply address")}
                            assertArrayEquals(payload,response.data.copyOfRange(offset,response.length))
                        }
                    }
                    result.get(5,TimeUnit.SECONDS); worker.join(1000)
                }
            }
        } finally { engine.stop() }
    }
}
