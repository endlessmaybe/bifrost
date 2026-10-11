package com.bifrost.client

import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class BifrostUpdateStagingTest {
    @get:Rule val temporary = TemporaryFolder()
    @Test fun absentNestedArtifactNeedsDownloadWithoutVerification() {
        val file = java.io.File(temporary.root, ".staging-123/android/app.apk")
        assertFalse(BifrostUpdateStaging.reuse(temporary.root, file) { fail("Absent bytes cannot be verified") })
        assertFalse(file.exists())
    }
    @Test fun completeFileIsVerifiedAndReused() {
        val file = temporary.newFile("complete.apk").apply { writeText("verified bytes") }
        assertTrue(BifrostUpdateStaging.reuse(temporary.root, file) { check(it.readText() == "verified bytes") })
        assertEquals("verified bytes", file.readText())
    }
    @Test fun interruptedOrCorruptFileCanBeDownloadedAgain() {
        for (code in listOf("BF-RELEASE-SIZE", "BF-RELEASE-DIGEST")) {
            val file = temporary.newFile(code).apply { writeText("incomplete") }
            assertFalse(BifrostUpdateStaging.reuse(temporary.root, file) { error(code) })
            assertFalse(file.exists())
            Files.write(file.toPath(), "replacement".toByteArray())
            assertTrue(BifrostUpdateStaging.reuse(temporary.root, file) { check(it.readText() == "replacement") })
        }
    }
    @Test fun cleanupCannotCrossTheUpdateDirectory() {
        val updates = temporary.newFolder("updates")
        val unrelated = temporary.newFile("preserved").apply { writeText("user data") }
        val failure = runCatching { BifrostUpdateStaging.reuse(updates, unrelated) { error("BF-RELEASE-DIGEST") } }.exceptionOrNull()
        assertEquals("BF-RELEASE-PATH", failure?.message)
        assertEquals("user data", unrelated.readText())
    }
}
