using System.Net;
using System.Text.RegularExpressions;

namespace Bifrost;

/// <summary>
/// The only origin that may be used for first enrollment and subsequent
/// authenticated control-plane calls.  It is supplied by the build through
/// BifrostTrustedControlOrigin and is deliberately immutable at runtime.
/// </summary>
public sealed class TrustedControlOrigin
{
    public const string LocalEvaluationOrigin = "http://127.0.0.1:17880";
    private static readonly Regex DnsName = new(
        "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public string Value { get; }

    private TrustedControlOrigin(string value) => Value = value;

    public static bool TryParse(string? candidate, out TrustedControlOrigin? origin)
    {
        origin = null;
        if (string.IsNullOrEmpty(candidate) || candidate.Any(char.IsWhiteSpace) || candidate.Any(ch => ch > 0x7f)) return false;
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri) ||
            uri.UserInfo.Length != 0 ||
            uri.Query.Length != 0 ||
            uri.Fragment.Length != 0 ||
            (uri.AbsolutePath.Length != 0 && uri.AbsolutePath != "/") ||
            !string.Equals(uri.Host, uri.DnsSafeHost, StringComparison.Ordinal)) return false;

        if (BifrostBuildConstants.LocalEvaluation)
        {
            var expected = BifrostBuildConstants.LocalEvaluationFixture ? candidate : LocalEvaluationOrigin;
            if (!string.Equals(candidate, expected, StringComparison.Ordinal) ||
                uri.Scheme != Uri.UriSchemeHttp || uri.Host != "127.0.0.1" || uri.Port is < 1 or > 65535) return false;
            if (!BifrostBuildConstants.LocalEvaluationFixture && uri.Port != 17880) return false;
            origin = new TrustedControlOrigin(candidate);
            return true;
        }
        if (uri.Scheme != Uri.UriSchemeHttps || uri.Port != 443 || uri.HostNameType != UriHostNameType.Dns) return false;

        var host = uri.Host;
        // The entire special-use localhost namespace is loopback authority,
        // not a deployable control-plane origin. Reject nested names too.
        if (host.Length > 253 || !DnsName.IsMatch(host) ||
            string.Equals(host, "localhost", StringComparison.Ordinal) ||
            host.EndsWith(".localhost", StringComparison.Ordinal) ||
            IPAddress.TryParse(host, out _)) return false;

        var canonical = $"https://{host}";
        if (!string.Equals(candidate, canonical, StringComparison.Ordinal)) return false;
        origin = new TrustedControlOrigin(canonical);
        return true;
    }

    public static TrustedControlOrigin? Compiled
    {
        get => TryParse(BifrostBuildConstants.TrustedControlOrigin, out var origin) ? origin : null;
    }

    public static string CompiledValue => BifrostBuildConstants.TrustedControlOrigin;
    public static bool IsLocalEvaluation => BifrostBuildConstants.LocalEvaluation;

    public static string CompiledStatus => Compiled is null ? "BF-CONTROL-UNCONFIGURED" : "CONFIGURED";
}

public static class BifrostProductConfiguration
{
    public static bool IsControlPlaneConfigured => TrustedControlOrigin.Compiled is not null;
    public static string ControlPlaneStatus => IsControlPlaneConfigured ? "发行版已配置控制面" : "此测试构建未配置控制面";
}
