namespace Bifrost.Release;

internal static class ReleaseContract
{
    internal const string ContractId = "bifrost.release";
    internal const string ContractVersion = "1.2.0";
    internal const string TrustRootKeyId = ReleaseTrustBinding.TrustRootKeyId;
    internal const string ReleaseSigningKeyId = "bifrost-release-v1";
    internal const string TrustRootPem = ReleaseTrustBinding.TrustRootPem;
    internal static readonly bool TrustRootProvisioned = ReleaseTrustBinding.TrustRootProvisioned;
    internal const string TrustRootFingerprint = ReleaseTrustBinding.TrustRootFingerprint;
}
