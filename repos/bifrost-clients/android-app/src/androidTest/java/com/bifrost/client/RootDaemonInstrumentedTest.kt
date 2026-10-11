package com.bifrost.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import android.os.ParcelFileDescriptor
import android.os.Process
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Three separate instrumentation processes prove daemon ownership survives
 * client exit, then an authenticated new client rebinds and stops exact rules.
 * The only captured UID is the disposable shell test traffic. No account data.
 */
@RunWith(AndroidJUnit4::class)
class RootDaemonInstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val record get() = File(context.noBackupFilesDir, "root-daemon-test.json")
    private fun shell(command: String): ByteArray = ParcelFileDescriptor.AutoCloseInputStream(
        instrumentation.uiAutomation.executeShellCommand(command)).use { it.readBytes() }
    private val rootAdb by lazy { String(shell("id")).contains("uid=0(") }
    private fun launcher() {
        assumeTrue(BuildConfig.BIFROST_TEST_VARIANT)
        BifrostRootIpc.testTaskRunner = { task ->
            val pipes = instrumentation.uiAutomation.executeShellCommandRwe(if (rootAdb) "su 0 sh" else "su -c sh")
            ParcelFileDescriptor.AutoCloseInputStream(pipes[0]).use { stdout ->
                ParcelFileDescriptor.AutoCloseOutputStream(pipes[1]).use { stdin ->
                    ParcelFileDescriptor.AutoCloseInputStream(pipes[2]).use { stderr ->
                        task.run(stdin, stdout, stderr)
                    }
                }
            }
        }
    }
    @Test fun startIndependentCore() {
        launcher()
        val epoch = java.util.UUID.randomUUID().toString().replace("-", "")
        val policy = BifrostApplicationPolicy.normalize("per-app", "allow", listOf("com.android.shell"), emptyList())
        val bindings = BifrostApplicationPolicyPackageValidator(AndroidApplicationPackageCatalog(context), context.packageName).validate(policy)
        val remote = BifrostRootRemote(context, epoch)
        remote.configure(policy)
        assertTrue(remote.block())
        val config = """{"log":{"level":"debug","output":"${File(context.noBackupFilesDir, "root-dns-test.log").absolutePath}"},
            "dns":{"servers":[{"type":"hosts","tag":"dns-test","predefined":{"bifrost-root-dns.test":["192.0.2.18"]}},{"type":"https","tag":"resolver","server":"223.5.5.5","path":"/dns-query"}],"rules":[{"domain":["bifrost-root-dns.test"],"server":"dns-test"}],"final":"resolver","strategy":"ipv4_only"},
            "inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"mtu":1500,"stack":"gvisor","auto_route":true}],
            "outbounds":[{"type":"direct","tag":"direct"}],
            "route":{"default_domain_resolver":"resolver","rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"}],"final":"direct"}}
        """.trimIndent()
        try {
            assertTrue(remote.start(config, "sing-box", policy, bindings))
            assertEquals(policy.canonicalJson, remote.applicationPolicyReadback(bindings).canonicalJson)
            remote.releaseFence()
            val state = BifrostRootIpc.call(context,"status",epoch)
            assertTrue(state.getBoolean("ready")); assertTrue(state.getBoolean("alive"))
            assertNotEquals(Process.myPid(),state.getInt("pid"))
            record.writeText(JSONObject().put("epoch",epoch).put("pid",state.getInt("pid")).toString())
        } catch (error: Throwable) { runCatching { remote.stop(); remote.releaseFence() }; throw error }
    }
    @Test fun rebindAfterClientDeath() {
        launcher()
        val saved=JSONObject(record.readText())
        val state=BifrostRootIpc.call(context,"status",saved.getString("epoch"))
        assertTrue("Native core must survive the previous app process",state.getBoolean("ready"))
        assertTrue(state.getBoolean("alive"))
        assertEquals(saved.getInt("pid"),state.getInt("pid"))
        assertTrue(BifrostRootIpc.call(context,"health",saved.getString("epoch")).getBoolean("healthy"))
    }
    @Test fun explicitStopClosesDaemonBoundary() {
        launcher()
        val saved=JSONObject(record.readText()); val epoch=saved.getString("epoch")
        BifrostRootIpc.call(context,"block",epoch)
        BifrostRootIpc.call(context,"stop-core",epoch)
        BifrostRootIpc.call(context,"release",epoch)
        val state=BifrostRootIpc.call(context,"status",epoch)
        assertFalse(state.getBoolean("ready"));assertFalse(state.getBoolean("alive"))
        record.delete()
    }
}
