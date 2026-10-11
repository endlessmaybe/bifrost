using System.Collections.Generic;
namespace Bifrost.Release;

internal static class ReleaseArtifactPolicy
{
    internal static readonly HashSet<string> WindowsX64Stable = new(System.StringComparer.Ordinal) { "app", "service", "installer", "mihomo", "geosite", "geoip", "core-manifest", "install-metadata" };
    internal static readonly HashSet<string> AndroidStable = new(System.StringComparer.Ordinal) { "android-arm64-v8a-apk", "android-armeabi-v7a-apk", "android-x86_64-apk" };
    internal static bool IsWindowsX64Stable(IEnumerable<string> ids) => WindowsX64Stable.SetEquals(ids);
}
