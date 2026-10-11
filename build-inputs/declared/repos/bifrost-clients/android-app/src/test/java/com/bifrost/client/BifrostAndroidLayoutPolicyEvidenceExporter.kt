package com.bifrost.client

import com.bifrost.client.ui.model.BifrostAndroidLayoutPolicy
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale

/**
 * Test/build-only exporter.  It calls the production policy for every
 * required viewport; no copy of its threshold logic is allowed here.  The
 * JSON is consumed by the WPF evidence merger and never ships in release.
 */
object BifrostAndroidLayoutPolicyEvidenceExporter {
    private val required = listOf(
        360 to 640,
        412 to 915,
    )
    private val fontScales = listOf(1f, 1.3f, 2f)

    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size in 1..2) { "usage: exporter <output.json> [policy-source.kt]" }
        val source = args.getOrNull(1)?.let(::File)
            ?: File("src/main/java/com/bifrost/client/ui/model/BifrostAndroidLayoutPolicy.kt")
        File(args[0]).apply {
            parentFile?.mkdirs()
            writeText(exportJson(source), StandardCharsets.UTF_8)
        }
    }

    fun exportJson(policySource: File = File("src/main/java/com/bifrost/client/ui/model/BifrostAndroidLayoutPolicy.kt")): String {
        val className = BifrostAndroidLayoutPolicy::class.java.name
        val classHash = policyClassHash()
        val sourceHash = sha256(policySource.readBytes())
        val rows = required.flatMap { (width, height) ->
            fontScales.map { fontScale ->
                val plan = BifrostAndroidLayoutPolicy.forWidth(width, fontScale, height)
                val payload = canonicalPolicyPayload(plan)
                Row(width, height, fontScale, className, classHash, sourceHash, payload, sha256(payload.toByteArray(StandardCharsets.UTF_8)))
            }
        }
        val payloadDigest = sha256(rows.joinToString("\n") { it.payload }.toByteArray(StandardCharsets.UTF_8))
        return buildString {
            append("{\"schemaVersion\":1,\"policyClassName\":\"").append(className)
                .append("\",\"policyClassHash\":\"").append(classHash)
                .append("\",\"policySourceHash\":\"").append(sourceHash)
                .append("\",\"policyPayloadDigest\":\"").append(payloadDigest)
                .append("\",\"rows\":[")
            rows.forEachIndexed { index, row -> if (index > 0) append(','); append(row.toJson()) }
            append("]}")
        }
    }

    private data class Row(
        val width: Int,
        val height: Int,
        val fontScale: Float,
        val className: String,
        val classHash: String,
        val sourceHash: String,
        val payload: String,
        val payloadDigest: String,
    ) {
        fun toJson(): String = buildString {
            append("{\"width\":").append(width)
                .append(",\"height\":").append(height)
                .append(",\"fontScale\":").append(fontScale.toString().trimEnd('0').trimEnd('.'))
                .append(",\"policyClassName\":\"").append(className)
                .append("\",\"policyClassHash\":\"").append(classHash)
                .append("\",\"policySourceHash\":\"").append(sourceHash)
                .append("\",\"measurementSource\":\"production-policy-exporter\"")
                .append(",\"realMeasured\":false,\"status\":\"PENDING-EXTERNAL\"")
                .append(",\"reason\":\"No locked Compose measure/emulator is available; this row is derived by executing the production policy only.\"")
                .append(",\"policy\":").append(payload)
                .append(",\"payloadDigest\":\"").append(payloadDigest).append("\"}")
        }
    }

    private fun canonicalPolicyPayload(plan: com.bifrost.client.ui.model.BifrostAndroidLayoutPlan): String = buildString {
        append("{\"summaryLayout\":\"").append(plan.summaryLayout.name.lowercase(Locale.ROOT))
            .append("\",\"metricLayout\":\"").append(plan.metricLayout.name.lowercase(Locale.ROOT))
            .append("\",\"targetMinDp\":").append(plan.targetMinDp)
            .append(",\"usesScroll\":").append(plan.usesScroll)
            .append(",\"wrapsText\":").append(plan.wrapsText)
            .append(",\"navigation\":").append(plan.navigation.toJsonArray())
            .append(",\"homeModes\":").append(plan.homeModes.toJsonArray()).append('}')
    }

    private fun policyClassHash(): String {
        val resource = BifrostAndroidLayoutPolicy::class.java.classLoader
            ?.getResourceAsStream("com/bifrost/client/ui/model/BifrostAndroidLayoutPolicy.class")
            ?: error("production policy bytecode is unavailable")
        resource.use { return sha256(it.readBytes()) }
    }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(value).toHex()

    private fun List<String>.toJsonArray(): String = joinToString(separator = ",", prefix = "[", postfix = "]") { "\"${it.replace("\\", "\\\\").replace("\"", "\\\"")}\"" }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
