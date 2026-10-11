namespace Bifrost.ClientService;

/// <summary>Single source of Windows-specific bounds owned by Mihomo.</summary>
internal static class MihomoWindowsContract
{
    internal const string TunInterfaceName = "bifrost1";
    internal const string TunIpv4Address = "198.18.0.1";
    internal const string TunIpv4Cidr = "198.18.0.1/30";
    internal const string TunIpv6Cidr = "fdfe:dcba:9876::1/126";
    internal const string FakeIpv6Cidr = "fdfe:dcba:9876::1/64";
    // The adapter's own .1 is a local host address, not the TUN DNS peer.
    internal const string TunDnsAddress = "198.18.0.2";
    internal const int ControllerPortMin = 19000;
    internal const int ControllerPortMax = 49151;
    // Provider health and URLTest/Fallback must measure the same endpoint.
    // The production graph already routes www.gstatic.com through direct DNS
    // during bootstrap, so this does not depend on the not-yet-selected proxy
    // group.  Real source-A validation showed the literal 1.1.1.1 trace target
    // marks every otherwise reachable VMess candidate dead, while gstatic's
    // canonical 204 probe is reachable through the same candidates.  Keeping
    // both selectors on this proven target prevents the old split-brain health
    // result without introducing a DNS bootstrap cycle.
    internal const string StartupProbeUrl = "https://www.gstatic.com/generate_204";
    internal const int StartupProbeExpectedStatus = 204;
    internal static readonly string[] DataPlaneProbeHosts = ["www.gstatic.com", "cp.cloudflare.com"];

    internal static bool TryParseController(string? value, out int port)
    {
        port = 0;
        if (string.IsNullOrWhiteSpace(value)) return false;
        var separator = value.LastIndexOf(':');
        return separator > 0 && value[..separator] == "127.0.0.1" &&
            int.TryParse(value[(separator + 1)..], out port) &&
            port is >= ControllerPortMin and <= ControllerPortMax;
    }
}
