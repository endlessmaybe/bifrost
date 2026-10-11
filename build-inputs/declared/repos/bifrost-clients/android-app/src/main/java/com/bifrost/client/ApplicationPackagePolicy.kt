package com.bifrost.client

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/** The installed image identity captured at the UI/service boundary. */
data class BifrostApplicationPackageBinding(
    val packageName: String,
    val imageIdentity: String,
)

data class BifrostApplicationPackageOption(
    val packageName: String,
    val label: String,
    val isSystem: Boolean = false,
)

/** Small catalog seam used by production validation and deterministic tests. */
interface BifrostApplicationPackageCatalog {
    fun installed(packageName: String): BifrostApplicationPackageBinding?
    fun selectable(): List<BifrostApplicationPackageOption> = emptyList()
}

/**
 * Canonical installed-image identity.  Every signer is hashed, sorted and
 * length-prefixed so signer ordering, count, additions, removals and
 * replacements all change the binding without ambiguous concatenation.
 */
internal object BifrostApplicationPackageImageIdentity {
    private val digestPattern = Regex("[0-9a-f]{64}")

    fun compose(versionCode: Long, lastUpdateTime: Long, signerDigests: Iterable<String>): String {
        if (versionCode < 0 || lastUpdateTime < 0) invalid()
        val sorted = signerDigests.toList().also { values ->
            if (values.isEmpty() || values.any { !digestPattern.matches(it) }) invalid()
        }.sorted()
        if (sorted.size > 32 || sorted.zipWithNext().any { it.first == it.second }) invalid()
        return buildString {
            append("v1|version:").append(versionCode)
            append("|updated:").append(lastUpdateTime)
            append("|signers:").append(sorted.size)
            sorted.forEach { digest -> append('|').append(digest.length).append(':').append(digest) }
        }
    }

    /** Strictly parse the transport form before it can become an expectation. */
    fun isCanonical(value: String): Boolean {
        if (value.length > 4096) return false
        val parts = value.split('|')
        if (parts.size < 5 || parts[0] != "v1") return false
        fun decimal(field: String, name: String): Long? = field.removePrefix("$name:")
            .takeIf { field.startsWith("$name:") && it.isNotEmpty() && it.all(Char::isDigit) }
            ?.toLongOrNull()
        val version = decimal(parts[1], "version") ?: return false
        val updated = decimal(parts[2], "updated") ?: return false
        val count = decimal(parts[3], "signers") ?: return false
        if (version < 0 || updated < 0 || count !in 1L..32L || parts.size != 4 + count.toInt()) return false
        val signers = ArrayList<String>(count.toInt())
        for (entry in parts.drop(4)) {
            val separator = entry.indexOf(':')
            if (separator <= 0) return false
            val length = entry.substring(0, separator).toIntOrNull() ?: return false
            val digest = entry.substring(separator + 1)
            if (length != digest.length || !digestPattern.matches(digest)) return false
            signers += digest
        }
        if (signers != signers.sorted() || signers.zipWithNext().any { it.first == it.second }) return false
        return compose(version, updated, signers) == value
    }

    private fun invalid(): Nothing = throw IllegalArgumentException("BF-APP-PACKAGE-INVALID:signers")
}

/** PackageManager-backed catalog. A missing signing identity is not usable. */
class AndroidApplicationPackageCatalog(private val context: Context) : BifrostApplicationPackageCatalog {
    override fun selectable(): List<BifrostApplicationPackageOption> {
        val manager = context.packageManager
        val applications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            manager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(PackageManager.MATCH_DISABLED_COMPONENTS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            manager.getInstalledApplications(PackageManager.MATCH_DISABLED_COMPONENTS)
        }
        return applications.mapNotNull { application ->
            val packageName = application.packageName?.trim().orEmpty()
            // The framework package is not an independently selectable app.
            if (packageName.isBlank() || packageName == "android" || packageName == context.packageName) null
            else BifrostApplicationPackageOption(packageName,
                runCatching { application.loadLabel(manager)?.toString()?.trim().orEmpty() }.getOrDefault("").ifBlank { packageName },
                application.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0)
        }.distinctBy { it.packageName }.sortedWith(compareBy<BifrostApplicationPackageOption> { it.isSystem }
            .thenBy(String.CASE_INSENSITIVE_ORDER) { it.label }.thenBy { it.packageName })
    }

    override fun installed(packageName: String): BifrostApplicationPackageBinding? = runCatching {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.packageManager.getPackageInfo(
                packageName,
                PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
            )
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        }
        val signingInfo = info.signingInfo ?: return@runCatching null
        val signerDigests = signingInfo.apkContentsSigners.map { signer ->
            val signerBytes = signer.toByteArray()
            try {
                val digestBytes = MessageDigest.getInstance("SHA-256").digest(signerBytes)
                try {
                    digestBytes.joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
                } finally {
                    digestBytes.fill(0)
                }
            } finally {
                signerBytes.fill(0)
            }
        }
        if (signerDigests.isEmpty()) return@runCatching null
        val imageIdentity = BifrostApplicationPackageImageIdentity.compose(
            info.longVersionCode,
            info.lastUpdateTime,
            signerDigests,
        )
        BifrostApplicationPackageBinding(packageName, imageIdentity)
    }.getOrNull()
}

/**
 * Validates every selected package before persistence and again immediately
 * before a VPN builder is established. Expected bindings make removal,
 * replacement and update races fail closed instead of silently changing the
 * effective application set.
 */
class BifrostApplicationPolicyPackageValidator(
    private val catalog: BifrostApplicationPackageCatalog,
    private val ownPackageName: String,
) {
    private val packagePattern = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")

    fun validate(
        snapshot: BifrostApplicationPolicySnapshot,
        expectedBindings: List<BifrostApplicationPackageBinding>? = null,
    ): List<BifrostApplicationPackageBinding> {
        val verified = BifrostApplicationPolicy.verify(snapshot)
        val identities = verified.identities
        if (expectedBindings != null && expectedBindings.size != identities.size) invalid("count")
        if (identities.isEmpty()) {
            if (!expectedBindings.isNullOrEmpty()) invalid("unexpected")
            return emptyList()
        }
        val current = identities.map(::readCurrent)
        expectedBindings?.forEachIndexed { index, expected ->
            val actual = current[index]
            if (expected.packageName != actual.packageName || expected.imageIdentity != actual.imageIdentity) {
                invalid("changed")
            }
        }
        return current.toList()
    }

    /** Re-read one expected image immediately before the establish boundary. */
    fun validateBinding(expected: BifrostApplicationPackageBinding): BifrostApplicationPackageBinding {
        if (!packagePattern.matches(expected.packageName)) invalid("id")
        val actual = readCurrent(expected.packageName)
        if (actual != expected) invalid("changed")
        return actual
    }

    private fun readCurrent(packageName: String): BifrostApplicationPackageBinding {
        if (!packagePattern.matches(packageName)) invalid("id")
        if (packageName == ownPackageName) invalid("self")
        return catalog.installed(packageName) ?: invalid(packageName)
    }

    private fun invalid(detail: String): Nothing = throw IllegalArgumentException("BF-APP-PACKAGE-INVALID:$detail")
}

/** Strict, deterministic Intent transport for the package-image bindings. */
object BifrostApplicationPackageBindings {
    private val exactFields = setOf("package_name", "image_identity")
    private val packagePattern = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")

    fun encode(bindings: List<BifrostApplicationPackageBinding>): String = JSONArray().apply {
        val seen = HashSet<String>()
        bindings.forEach { binding ->
            if (!packagePattern.matches(binding.packageName) ||
                !BifrostApplicationPackageImageIdentity.isCanonical(binding.imageIdentity) ||
                !seen.add(binding.packageName)) invalid("json")
            put(JSONObject().put("package_name", binding.packageName).put("image_identity", binding.imageIdentity))
        }
    }.toString()

    fun decode(input: String?): List<BifrostApplicationPackageBinding> {
        if (input.isNullOrBlank()) return emptyList()
        return try {
            StrictJsonValidator(input, "BF-APP-PACKAGE-INVALID").validate()
            val array = JSONArray(input)
            val seen = HashSet<String>()
            List(array.length()) { index ->
                val obj = array.optJSONObject(index) ?: invalid("json")
                if (obj.keys().asSequence().toSet() != exactFields || obj.length() != exactFields.size) invalid("json")
                val packageName = obj.optString("package_name", "")
                val imageIdentity = obj.optString("image_identity", "")
                if (!packagePattern.matches(packageName) || !seen.add(packageName) ||
                    !BifrostApplicationPackageImageIdentity.isCanonical(imageIdentity)) invalid("json")
                BifrostApplicationPackageBinding(packageName, imageIdentity)
            }
        } catch (error: IllegalArgumentException) {
            throw error
        } catch (error: Throwable) {
            throw IllegalArgumentException("BF-APP-PACKAGE-INVALID:json", error)
        }
    }

    private fun invalid(detail: String): Nothing = throw IllegalArgumentException("BF-APP-PACKAGE-INVALID:$detail")
}
