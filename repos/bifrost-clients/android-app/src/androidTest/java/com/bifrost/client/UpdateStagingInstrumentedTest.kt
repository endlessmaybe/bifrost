package com.bifrost.client

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.nio.file.Files
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UpdateStagingInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun directory(): File {
        assertTrue(BuildConfig.DEBUG && BuildConfig.BIFROST_TEST_VARIANT)
        assertEquals("com.bifrost.client.test", context.packageName)
        return File(context.noBackupFilesDir, "update-path-test-${UUID.randomUUID()}").apply { check(mkdirs()) }
    }

    @Test fun androidPrivateStorageCanDownloadAndReuseAnArtifact() {
        val root = directory()
        val destination = File(root, ".staging-123/android/app.apk")
        val legacyAccepts = destination.absoluteFile.toPath().normalize().startsWith(root.canonicalFile.toPath())
        android.util.Log.i("BifrostUpdatePathTest", "Android private storage: legacy_accepts=$legacyAccepts")
        assertFalse(BifrostUpdateStaging.reuse(root, destination) { fail("No downloaded file yet") })
        check(destination.parentFile!!.mkdirs())
        destination.writeText("signed-byte-fixture")
        assertTrue(BifrostUpdateStaging.reuse(root, destination) { assertEquals("signed-byte-fixture", it.readText()) })
    }

    @Test fun parentDirectoryAliasSupportsDownloadReuseAndCorruptRetry() {
        val base = directory()
        val actual = File(base, "actual-app-data").apply { check(mkdir()) }
        val alias = File(base, "android-app-data-alias")
        Files.createSymbolicLink(alias.toPath(), actual.toPath())
        val root = File(alias, "updates").apply { check(mkdir()) }
        val destination = File(root, ".staging-123/android/app.apk")
        // This is the exact comparison at 2.2.14's mapped failing line 11.
        assertFalse(destination.absoluteFile.toPath().normalize().startsWith(root.canonicalFile.toPath()))
        assertFalse(BifrostUpdateStaging.reuse(root, destination) { fail("No downloaded file yet") })
        check(destination.parentFile!!.mkdirs())
        destination.writeText("partial")
        assertFalse(BifrostUpdateStaging.reuse(root, destination) { error("BF-RELEASE-DIGEST") })
        assertFalse(destination.exists())
        destination.writeText("complete")
        assertTrue(BifrostUpdateStaging.reuse(root, destination) { assertEquals("complete", it.readText()) })
    }

    @Test fun linksAndTraversalCannotReadOrRemoveUnrelatedFiles() {
        val base = directory()
        val root = File(base, "updates").apply { check(mkdir()) }
        val outside = File(base, "outside").apply { check(mkdir()) }
        val preserved = File(outside, "app.apk").apply { writeText("preserve") }
        val insideLink = File(root, "redirect")
        Files.createSymbolicLink(insideLink.toPath(), outside.toPath())
        val rootLink = File(base, "root-link")
        Files.createSymbolicLink(rootLink.toPath(), root.toPath())
        for ((boundary, destination) in listOf(
            root to File(insideLink, "app.apk"),
            root to File(root, "../outside/app.apk"),
            rootLink to File(rootLink, "app.apk"),
            root to root,
        )) {
            val error = runCatching { BifrostUpdateStaging.reuse(boundary, destination) { fail("Must reject before verification") } }.exceptionOrNull()
            assertEquals("BF-RELEASE-PATH", error?.message)
            assertEquals("preserve", preserved.readText())
        }
    }
}
