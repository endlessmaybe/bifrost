package com.bifrost.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.lang.reflect.Modifier

class ApplicationPolicyTest {

    @Test
    fun canonicalLimitsAndModeContractAreFailClosed() {
        val one = BifrostApplicationPolicy.normalize(
            routeMode = "per-app",
            policyMode = "allow",
            include = listOf("com.example.alpha"),
            exclude = emptyList(),
        )
        assertEquals(listOf("com.example.alpha"), one.includePackages)
        assertEquals(emptyList<String>(), one.excludePackages)

        val sixtyFour = (0 until 64).map { "com.example.app$it" }
        assertEquals(64, BifrostApplicationPolicy.normalize("per-app", "allow", sixtyFour, emptyList()).identities.size)
        reject("BF-APP-LIMIT") {
            BifrostApplicationPolicy.normalize("per-app", "allow", sixtyFour + "com.example.overflow", emptyList())
        }
        reject("BF-APP-ALLOW-EMPTY") { BifrostApplicationPolicy.normalize("per-app", "allow", emptyList(), emptyList()) }
        reject("BF-APP-POLICY-CONFLICT") {
            BifrostApplicationPolicy.normalize("per-app", "allow", listOf("com.example.a"), listOf("com.example.b"))
        }
        reject("BF-APP-POLICY") { BifrostApplicationPolicy.normalize("smart", "allow", listOf("com.example.a"), emptyList()) }
        val none = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
        assertTrue(none.identities.isEmpty())
    }

    @Test
    fun androidIdentityRulesPreserveCaseAndRejectUnicodeOrUnsafeBytes() {
        val snapshot = BifrostApplicationPolicy.normalize(
            "per-app", "allow",
            listOf("com.Example.App", "com.example.app", "com.Example.App"), emptyList(),
        )
        assertEquals(listOf("com.Example.App", "com.example.app"), snapshot.identities)
        reject("BF-APP-ID") { BifrostApplicationPolicy.normalize("per-app", "allow", listOf("com.example.\u5e94\u7528"), emptyList()) }
        reject("BF-APP-ID") { BifrostApplicationPolicy.normalize("per-app", "allow", listOf("com.example/app"), emptyList()) }
        reject("BF-APP-ID") { BifrostApplicationPolicy.parseUiList("com.example.a,,com.example.b") }
        reject("BF-APP-ID") { BifrostApplicationPolicy.normalize("per-app", "allow", listOf("a." + "b".repeat(255)), emptyList()) }
    }

    @Test
    fun digestBindsRoutePolicyGenerationAndOrderedIdentityBytes() {
        val a = BifrostApplicationPolicy.normalize("per-app", "allow", listOf("com.example.a", "com.example.b"), emptyList())
        val reordered = BifrostApplicationPolicy.normalize("per-app", "allow", listOf("com.example.b", "com.example.a"), emptyList())
        val exclude = BifrostApplicationPolicy.normalize("per-app", "exclude", emptyList(), listOf("com.example.a", "com.example.b"))
        assertNotEquals(a.digest, reordered.digest)
        assertNotEquals(a.digest, exclude.digest)
    }

    @Test
    fun uiListAndTotalUtf8BoundsAreNotTruncated() {
        assertEquals(emptyList<String>(), BifrostApplicationPolicy.parseUiList(""))
        assertEquals(listOf("com.example.one"), BifrostApplicationPolicy.parseUiList("com.example.one"))
        val sixtyFour = (0 until 64).map { "com.example.ui$it" }
        assertEquals(64, BifrostApplicationPolicy.parseUiList(sixtyFour.joinToString("\n")).size)
        reject("BF-APP-LIMIT") {
            BifrostApplicationPolicy.parseUiList((sixtyFour + "com.example.ui64").joinToString(","))
        }
        val byteBound = (0 until 64).map { "a$it." + "b".repeat(130) }
        reject("BF-APP-LIMIT") {
            BifrostApplicationPolicy.normalize("per-app", "allow", byteBound, emptyList())
        }
    }

    @Test
    fun installedPackageValidationCoversAllowExcludeAndImageRaces() {
        val catalog = FakePackageCatalog(mutableMapOf("com.example.alpha" to "v1", "com.example.blocked" to "v1"))
        val validator = BifrostApplicationPolicyPackageValidator(catalog, "com.bifrost.client")
        val allow = BifrostApplicationPolicy.normalize("per-app", "allow", listOf("com.example.alpha"), emptyList())
        val firstBinding = validator.validate(allow)
        assertEquals(listOf(BifrostApplicationPackageBinding("com.example.alpha", "v1")), firstBinding)

        catalog.entries.remove("com.example.alpha")
        reject("BF-APP-PACKAGE-INVALID") { validator.validate(allow, firstBinding) }
        catalog.entries["com.example.alpha"] = "v2"
        reject("BF-APP-PACKAGE-INVALID") { validator.validate(allow, firstBinding) }
        assertEquals("v2", validator.validate(allow).single().imageIdentity)

        val exclude = BifrostApplicationPolicy.normalize("per-app", "exclude", emptyList(), listOf("com.example.blocked"))
        assertEquals("com.example.blocked", validator.validate(exclude).single().packageName)
        val self = BifrostApplicationPolicy.normalize("per-app", "allow", listOf("com.bifrost.client"), emptyList())
        reject("BF-APP-PACKAGE-INVALID") { validator.validate(self) }

        val coordinator = BifrostApplicationPolicyConnectionCoordinator(validator)
        val firstBindings = coordinator.validate(allow)
        assertEquals(listOf(BifrostApplicationPackageBinding("com.example.alpha", "v2")), firstBindings)
        catalog.entries.remove("com.example.alpha")
        reject("BF-APP-PACKAGE-INVALID") {
            coordinator.validate(allow, firstBindings)
        }
    }

    @Test
    fun snapshotVerificationAndCompilerBoundaryRejectTampering() {
        val snapshot = BifrostApplicationPolicy.normalize(
            "per-app", "allow", listOf("com.example.one"), emptyList(),
        )
        assertEquals(snapshot, BifrostApplicationPolicy.verify(snapshot))
        reject("BF-APP-POLICY-SNAPSHOT") {
            BifrostConfigCompiler.compile(
                "{}", "A", "default", "per-app", "sing-box",
                includePackages = listOf("com.example.other"),
                appPolicyMode = snapshot.policyMode,
                applicationPolicy = snapshot,
            )
        }
        try {
            @Suppress("UNCHECKED_CAST")
            (snapshot.includePackages as MutableList<String>).add("com.example.tampered")
            fail("immutable package list was mutable")
        } catch (_: UnsupportedOperationException) {
            // expected: the snapshot exposes an unmodifiable defensive copy
        }
    }

    @Test
    fun snapshotHasOnlyValidatedFactoryConstructionAndNoRawCreateApi() {
        val snapshotType = BifrostApplicationPolicySnapshot::class.java
        assertTrue(Modifier.isFinal(snapshotType.modifiers))
        assertTrue(snapshotType.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        assertTrue(snapshotType.interfaces.isEmpty())
        val snapshot = BifrostApplicationPolicy.normalize(
            "per-app", "allow", listOf("com.example.immutable"), emptyList(),
        )
        assertEquals(snapshot, BifrostApplicationPolicy.verify(snapshot))
        try {
            @Suppress("UNCHECKED_CAST")
            (snapshot.excludePackages as MutableList<String>).add("com.example.tampered")
            fail("immutable exclusion list was mutable")
        } catch (_: UnsupportedOperationException) {
            // expected
        }
    }

    @Test
    fun bytecodeImplementationsHavePrivateConstructorsAndNoRawIssueCompanions() {
        val snapshotImplementation = BifrostApplicationPolicySnapshot::class.java
        assertTrue(snapshotImplementation.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        assertTrue(snapshotImplementation.declaredConstructors.none {
            it.parameterTypes.any { parameter -> parameter.name == "kotlin.jvm.internal.DefaultConstructorMarker" }
        })
        assertTrue(snapshotImplementation.declaredMethods.filter { Modifier.isPublic(it.modifiers) }.none { it.name.contains("issue") })

    }

    @Test
    fun snapshotHandoffIsProcessLocalAndNeverParsesTransportJson() {
        val id = "e".repeat(32)
        val snapshot = BifrostApplicationPolicy.normalize("global", "none", emptyList(), emptyList())
        BifrostApplicationPolicySnapshotRegistry.remove(id)
        assertTrue(BifrostApplicationPolicySnapshotRegistry.register(id, snapshot))
        assertEquals(snapshot, BifrostApplicationPolicySnapshotRegistry.lookup(id))
        BifrostApplicationPolicySnapshotRegistry.remove(id)
        assertTrue(BifrostApplicationPolicySnapshotRegistry.lookup(id) == null)
    }

    @Test
    fun signerSetBindingIsOrderIndependentAndBindsEverySignerAndImageMetadata() {
        val first = "a".repeat(64)
        val second = "b".repeat(64)
        val replacement = "c".repeat(64)
        val baseline = BifrostApplicationPackageImageIdentity.compose(7, 11, listOf(first, second))
        assertEquals(baseline, BifrostApplicationPackageImageIdentity.compose(7, 11, listOf(second, first)))
        assertNotEquals(baseline, BifrostApplicationPackageImageIdentity.compose(7, 11, listOf(first)))
        assertNotEquals(baseline, BifrostApplicationPackageImageIdentity.compose(7, 11, listOf(first, second, replacement)))
        assertNotEquals(baseline, BifrostApplicationPackageImageIdentity.compose(7, 11, listOf(first, replacement)))
        assertNotEquals(baseline, BifrostApplicationPackageImageIdentity.compose(8, 11, listOf(first, second)))
        assertNotEquals(baseline, BifrostApplicationPackageImageIdentity.compose(7, 12, listOf(first, second)))
        assertTrue(BifrostApplicationPackageImageIdentity.isCanonical(baseline))
        val binding = BifrostApplicationPackageBinding("com.example.app", baseline)
        assertEquals(listOf(binding), BifrostApplicationPackageBindings.decode(BifrostApplicationPackageBindings.encode(listOf(binding))))
        reject("BF-APP-PACKAGE-INVALID") {
            BifrostApplicationPackageBindings.decode("[{\"package_name\":\"com.example.app\",\"image_identity\":\"forged\"}]")
        }
        reject("BF-APP-PACKAGE-INVALID") {
            BifrostApplicationPackageBindings.decode(
                "[{\"package_name\":\"com.example.app\",\"image_identity\":\"v1|version:01|updated:11|signers:02|64:${first}|64:${second}\"}]",
            )
        }
        reject("BF-APP-PACKAGE-INVALID") {
            BifrostApplicationPackageBindings.encode(listOf(BifrostApplicationPackageBinding("com.example.app", "forged")))
        }
    }

    private fun reject(code: String, block: () -> Unit) {
        try {
            block()
            fail("expected $code")
        } catch (error: Throwable) {
            assertTrue(error.message == code || error.message?.startsWith("$code:") == true)
        }
    }

    private class FakePackageCatalog(val entries: MutableMap<String, String>) : BifrostApplicationPackageCatalog {
        override fun installed(packageName: String): BifrostApplicationPackageBinding? =
            entries[packageName]?.let { BifrostApplicationPackageBinding(packageName, it) }
    }
}
