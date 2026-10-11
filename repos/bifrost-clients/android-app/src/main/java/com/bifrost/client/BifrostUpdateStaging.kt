package com.bifrost.client

import java.io.File
import java.nio.file.Files

/** Reuse complete signed bytes, or remove only a corrupt owned staging file. */
internal object BifrostUpdateStaging {
    fun reuse(root: File, destination: File, verify: (File) -> Unit): Boolean {
        // Android can expose app storage through /data/user/0 while its real
        // directory is under /data/data. Compare both lexical paths first;
        // mixing a canonical root with an absolute child rejects that alias.
        val boundary = root.absoluteFile.toPath().normalize()
        val target = destination.absoluteFile.toPath().normalize()
        check(target.startsWith(boundary) && target != boundary) { "BF-RELEASE-PATH" }
        check(!Files.isSymbolicLink(boundary)) { "BF-RELEASE-PATH" }
        var current = target
        while (current != boundary) {
            check(!Files.isSymbolicLink(current)) { "BF-RELEASE-PATH" }
            current = current.parent ?: error("BF-RELEASE-PATH")
        }
        // Ancestors supplied by Android may be aliases. Links inside our own
        // staging tree remain forbidden, and the resolved child must stay in it.
        check(destination.canonicalFile.toPath().startsWith(root.canonicalFile.toPath())) { "BF-RELEASE-PATH" }
        if (!destination.exists()) return false
        check(destination.isFile) { "BF-RELEASE-PATH" }
        try {
            verify(destination)
            return true
        } catch (error: IllegalStateException) {
            if (error.message !in setOf("BF-RELEASE-SIZE", "BF-RELEASE-DIGEST")) throw error
            check(destination.delete()) { "BF-RELEASE-CLEANUP" }
            return false
        }
    }
}
