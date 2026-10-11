package com.bifrost.client

/** Generated exact stable release payload sets; IDs are never inferred from paths. */
internal object ReleaseArtifactPolicy {
    val WINDOWS_X64_STABLE = setOf("app", "service", "installer", "mihomo", "geosite", "geoip", "core-manifest", "install-metadata")
    val ANDROID_STABLE = setOf("android-arm64-v8a-apk", "android-armeabi-v7a-apk", "android-x86_64-apk")
    fun isWindowsX64Stable(ids: Set<String>) = ids == WINDOWS_X64_STABLE
}
