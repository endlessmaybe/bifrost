namespace Bifrost.Release;

// Default unsigned-local binding.  A ceremony-enabled build conditionally
// compiles the generated object produced by provision-release-root.mjs.
internal static class ReleaseTrustBinding
{
    internal const string TrustRootKeyId = "bifrost-root-v1";
    internal const string TrustRootPem = null;
    internal const bool TrustRootProvisioned = false;
    internal const string TrustRootFingerprint = null;
    internal const string BuildMarker = "UNPROVISIONED-RELEASE-TRUST-BINDING";
}
