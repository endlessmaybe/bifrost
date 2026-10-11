package com.bifrost.client

import java.net.URI
import java.net.URLEncoder

/** Only public, signed content-addressed artifacts may leave the control origin.
 * Never use this destination for manifests, configuration or device credentials. */
internal object BifrostReleaseMirror {
    fun endpoint(controlOrigin: String, digest: String, relative: String): String? {
        val origin = runCatching { URI(controlOrigin) }.getOrNull() ?: return null
        if (!origin.scheme.equals("https", true) || !origin.host.equals("edge.bifrostlog.com", true) ||
            origin.port !in setOf(-1, 443) || origin.userInfo != null || origin.query != null ||
            origin.fragment != null || origin.rawPath !in setOf("", "/")) return null
        require(digest.matches(Regex("[0-9a-f]{64}"))) { "BF-RELEASE-DIGEST" }
        val leaf = relative.substringAfterLast('/')
        require(leaf.isNotBlank() && leaf != "." && leaf != ".." &&
            leaf.none { it == '\\' || it.isISOControl() }) { "BF-RELEASE-PATH" }
        return "https://bifrostlog.com/v1/releases/blobs/$digest/" + URLEncoder.encode("$leaf.bin", "UTF-8").replace("+", "%20")
    }

    fun validate(endpoint: String) {
        val uri = URI(endpoint)
        check(uri.scheme == "https" && uri.rawAuthority == "bifrostlog.com" &&
            uri.userInfo == null && uri.query == null && uri.fragment == null &&
            uri.rawPath.matches(Regex("/v1/releases/blobs/[0-9a-f]{64}/[^/]+\\.bin"))) { "BF-RELEASE-ORIGIN" }
    }
}
