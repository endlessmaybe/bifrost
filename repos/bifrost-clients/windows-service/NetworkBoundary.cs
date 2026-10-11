using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Bifrost.ClientService;

/// <summary>
/// The network boundary is deliberately separate from core health.  A core
/// process and a loopback health endpoint are not evidence that traffic is
/// captured.  Production remains fail-closed until a native, owned boundary
/// is supplied; tests use the deterministic fake below only.
/// </summary>
public sealed record NetworkBoundaryIntent(
    string Mode,
    string Core,
    string ConfigId,
    string PolicyDigest,
    string Generation);

public sealed record NetworkBoundaryEvidence(
    string Mode,
    string Core,
    string ConfigId,
    string Generation,
    string PolicyDigest,
    bool TunOwned,
    bool BoundaryOwned,
    bool DnsBound,
    bool ProcessBound,
    bool ReadbackVerified);

public sealed record NetworkBoundaryResult(bool Ok, string Code, NetworkBoundaryEvidence? Evidence = null)
{
    public static NetworkBoundaryResult Fail(string code) => new(false, code);
}

public interface INetworkBoundary
{
    NetworkBoundaryResult Prepare(NetworkBoundaryIntent intent);
    NetworkBoundaryResult Activate(NetworkBoundaryIntent intent, int ownerProcessId);
    NetworkBoundaryResult Readback(NetworkBoundaryIntent intent);
    void Retire(string generation);
}

public enum NetworkBoundaryPhase
{
    Idle,
    Prepared,
    Active,
    Failed,
}

public sealed class NetworkBoundaryStateMachine
{
    private readonly object _sync = new();
    private NetworkBoundaryPhase _phase;
    private NetworkBoundaryIntent? _intent;
    private NetworkBoundaryEvidence? _evidence;

    public NetworkBoundaryPhase Phase { get { lock (_sync) return _phase; } }
    public NetworkBoundaryIntent? Intent { get { lock (_sync) return _intent; } }
    public NetworkBoundaryEvidence? Evidence { get { lock (_sync) return _evidence; } }

    public NetworkBoundaryResult Prepare(INetworkBoundary boundary, NetworkBoundaryIntent intent)
    {
        lock (_sync)
        {
            if (_phase is not NetworkBoundaryPhase.Idle and not NetworkBoundaryPhase.Failed)
                return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY-GENERATION");
            var result = boundary.Prepare(intent);
            if (!result.Ok || result.Evidence is null || !MatchesIdentity(result.Evidence, intent) || result.Evidence.ReadbackVerified)
            {
                // Keep the intent so a caller can still attempt deterministic
                // retirement if a native prepare partially installed state.
                _intent = intent;
                _evidence = result.Evidence;
                try
                {
                    // Prepare is allowed to fail after installing part of a
                    // native boundary. Always ask the adapter to retire that
                    // generation before declaring cleanup complete.
                    boundary.Retire(intent.Generation);
                    _phase = NetworkBoundaryPhase.Idle;
                    _intent = null;
                    _evidence = null;
                }
                catch
                {
                    // A failed retire means native state may still survive;
                    // retain the generation and stay fail-closed/retryable.
                    _phase = NetworkBoundaryPhase.Failed;
                }
                return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
            }
            _intent = intent;
            _evidence = result.Evidence;
            _phase = NetworkBoundaryPhase.Prepared;
            return result;
        }
    }

    public NetworkBoundaryResult Activate(INetworkBoundary boundary, int ownerProcessId)
    {
        lock (_sync)
        {
            if (_phase != NetworkBoundaryPhase.Prepared || _intent is null)
                return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY-GENERATION");
            var result = boundary.Activate(_intent, ownerProcessId);
            if (!result.Ok || result.Evidence is null || !IsActiveEvidenceFor(result.Evidence, _intent))
            {
                _phase = NetworkBoundaryPhase.Failed;
                return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
            }
            _evidence = result.Evidence;
            _phase = NetworkBoundaryPhase.Active;
            return result;
        }
    }

    public bool IsHealthy(INetworkBoundary boundary)
    {
        lock (_sync)
        {
            if (_phase != NetworkBoundaryPhase.Active || _intent is null || _evidence is null)
                return false;
            var result = boundary.Readback(_intent);
            if (!result.Ok || result.Evidence is null || !IsActiveEvidenceFor(result.Evidence, _intent) ||
                !result.Evidence.ReadbackVerified || !IsActiveEvidenceFor(_evidence, _intent))
            {
                // A lost or mismatched readback is a boundary failure, not a
                // merely unhealthy core. Keep intent/evidence for explicit
                // retirement and never report Active again.
                _phase = NetworkBoundaryPhase.Failed;
                return false;
            }
            _evidence = result.Evidence;
            return true;
        }
    }

    public void Retire(INetworkBoundary boundary)
    {
        lock (_sync)
        {
            var generation = _intent?.Generation;
            if (generation is not null)
            {
                try
                {
                    boundary.Retire(generation);
                }
                catch
                {
                    // A failed retirement must not be represented as Idle:
                    // native state may still own traffic and needs retry/repair.
                    _phase = NetworkBoundaryPhase.Failed;
                    return;
                }
            }
            _phase = NetworkBoundaryPhase.Idle;
            _intent = null;
            _evidence = null;
        }
    }

    public void FailClosed()
    {
        lock (_sync)
        {
            _phase = NetworkBoundaryPhase.Failed;
        }
    }

    private static bool MatchesIdentity(NetworkBoundaryEvidence evidence, NetworkBoundaryIntent intent) =>
        string.Equals(evidence.Mode, intent.Mode, StringComparison.Ordinal) &&
        string.Equals(evidence.Core, intent.Core, StringComparison.Ordinal) &&
        string.Equals(evidence.ConfigId, intent.ConfigId, StringComparison.Ordinal) &&
        string.Equals(evidence.Generation, intent.Generation, StringComparison.Ordinal) &&
        string.Equals(evidence.PolicyDigest, intent.PolicyDigest, StringComparison.Ordinal);

    private static bool IsActiveEvidenceFor(NetworkBoundaryEvidence evidence, NetworkBoundaryIntent intent) =>
        MatchesIdentity(evidence, intent) && evidence.TunOwned && evidence.BoundaryOwned &&
        evidence.DnsBound && evidence.ProcessBound;
}

/// <summary>Exact readback check shared by the service and pure fixture.</summary>
public static class EnforcementSummaryValidator
{
    public static bool Matches(
        EnforcementSummary summary,
        ApplicationPolicySnapshot policy,
        NetworkBoundaryIntent intent,
        NetworkBoundaryEvidence evidence) =>
        summary.Route == intent.Mode &&
        summary.Policy == policy.PolicyMode &&
        summary.IdentityCount == policy.Identities.Count &&
        summary.Digest == policy.Digest &&
        summary.Generation == policy.Generation &&
        summary.ReadbackVerified &&
        evidence.ReadbackVerified &&
        evidence.Mode == intent.Mode &&
        evidence.Core == intent.Core &&
        evidence.ConfigId == intent.ConfigId &&
        evidence.PolicyDigest == policy.Digest &&
        evidence.Generation == policy.Generation &&
        evidence.TunOwned && evidence.BoundaryOwned && evidence.DnsBound && evidence.ProcessBound;
}

/// <summary>
/// Production readback for the exact TUN owned by packaged Mihomo
/// process. It does not install host-wide WFP rules: the boundary is the
/// service-owned TUN plus the separately schema-validated Mihomo package.
/// </summary>
public sealed class OwnedTunNetworkBoundary : INetworkBoundary
{
    private const string InterfaceName = MihomoWindowsContract.TunInterfaceName;
    private readonly object _sync = new();
    private NetworkBoundaryIntent? _intent;
    private int _ownerProcessId;

    public NetworkBoundaryResult Prepare(NetworkBoundaryIntent intent)
    {
        lock (_sync)
        {
            if (!OperatingSystem.IsWindows()) return NetworkBoundaryResult.Fail("BF-WFP-PLATFORM");
            if (_intent is not null && !Same(_intent, intent)) return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY-GENERATION");
            _intent = intent;
            _ownerProcessId = 0;
            return new NetworkBoundaryResult(true, "OK", Evidence(intent, active: false, readback: false));
        }
    }

    public NetworkBoundaryResult Activate(NetworkBoundaryIntent intent, int ownerProcessId)
    {
        lock (_sync)
        {
            if (_intent is null || !Same(_intent, intent) || ownerProcessId <= 0)
                return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY-GENERATION");
            var deadline = DateTime.UtcNow.AddSeconds(3);
            do
            {
                if (OwnsBifrostCoreProcess(ownerProcessId) && HasExactTun())
                {
                    _ownerProcessId = ownerProcessId;
                    return new NetworkBoundaryResult(true, "OK", Evidence(intent, active: true, readback: false));
                }
                Thread.Sleep(50);
            } while (DateTime.UtcNow < deadline);
            return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
        }
    }

    public NetworkBoundaryResult Readback(NetworkBoundaryIntent intent)
    {
        lock (_sync)
        {
            if (_intent is null || !Same(_intent, intent) || _ownerProcessId <= 0 ||
                !OwnsBifrostCoreProcess(_ownerProcessId) || !HasExactTun())
                return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
            return new NetworkBoundaryResult(true, "OK", Evidence(intent, active: true, readback: true));
        }
    }

    public void Retire(string generation)
    {
        lock (_sync)
        {
            if (_intent?.Generation != generation) return;
            _intent = null;
            _ownerProcessId = 0;
        }
    }

    internal static bool HasExactTun()
    {
        try
        {
            var matches = WindowsInterfaceReadback.Read()
                .Where(item => string.Equals(item.Name, InterfaceName, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (matches.Length != 1 || matches[0].OperationalStatus != OperationalStatus.Up) return false;
            return matches[0].UnicastAddresses
                .Any(address => address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address));
        }
        catch { return false; }
    }

    internal static bool TryGetExactTunInterfaceIndex(out int interfaceIndex)
    {
        interfaceIndex = 0;
        try
        {
            var matches = WindowsInterfaceReadback.Read()
                .Where(item => string.Equals(item.Name, InterfaceName, StringComparison.OrdinalIgnoreCase) &&
                               item.OperationalStatus == OperationalStatus.Up &&
                               item.UnicastAddresses.Any(address =>
                                   address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address)))
                .ToArray();
            if (matches.Length != 1) return false;
            if (matches[0].InterfaceIndex <= 0) return false;
            interfaceIndex = matches[0].InterfaceIndex;
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// A second full-tunnel VPN is not an implicit Bifrost chain.  Detect the
    /// interface Windows would currently use for a public IPv4 destination;
    /// if that best route terminates on another tunnel, fail fast instead of
    /// stacking two auto_route/strict_route owners and producing opaque core
    /// startup failures.
    /// </summary>
    internal static bool HasCompetingDefaultTunnel()
        => TryGetCompetingDefaultTunnel(out _);

    internal static bool TryGetCompetingDefaultTunnel(out string? interfaceName)
    {
        interfaceName = null;
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            // Some transparent proxy stacks (notably sing-box TUN used by
            // v2rayN) install a 0/0 route with the same route metric as the
            // physical uplink. In that tie, GetBestInterface may legally pick
            // the physical adapter even though the transparent TUN is actively
            // intercepting host traffic. Detect the known full-tunnel adapter
            // class first. Deliberately exclude overlay-only virtual networks
            // such as Tailscale/Radmin/ZeroTier so their mere presence does not
            // prevent Bifrost from connecting.
            foreach (var item in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (item.OperationalStatus != OperationalStatus.Up ||
                    string.Equals(item.Name, InterfaceName, StringComparison.OrdinalIgnoreCase)) continue;
                if (!LooksLikeTransparentFullTunnel(item)) continue;
                interfaceName = item.Name;
                return !string.IsNullOrWhiteSpace(interfaceName);
            }

            // Do not infer the winning route from the local address selected
            // for an unbound UDP socket. Transparent Wintun/sing-box routing
            // can keep the physical adapter's source address while the route
            // itself is owned by a tunnel, which made Bifrost miss v2rayN's
            // singbox_tun and then start a second auto_route TUN. Query the
            // Windows IP Helper routing table directly instead.
            if (GetBestInterface(unchecked((uint)IPAddress.NetworkToHostOrder(unchecked((int)0x01010101))), out var bestIndex) == 0 && bestIndex != 0)
            {
                foreach (var item in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (item.OperationalStatus != OperationalStatus.Up ||
                        string.Equals(item.Name, InterfaceName, StringComparison.OrdinalIgnoreCase)) continue;
                    int index;
                    try { index = item.GetIPProperties().GetIPv4Properties()?.Index ?? -1; }
                    catch { continue; }
                    if (index == checked((int)bestIndex) && LooksLikeTunnel(item))
                    {
                        interfaceName = item.Name;
                        return !string.IsNullOrWhiteSpace(interfaceName);
                    }
                }
            }

            // Compatibility fallback for unusual adapters/drivers where the
            // IP Helper lookup is unavailable. This is deliberately secondary
            // because source-address inference alone is not authoritative.
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.Connect(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53));
            if (probe.LocalEndPoint is not IPEndPoint local) return false;
            foreach (var item in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (item.OperationalStatus != OperationalStatus.Up ||
                    string.Equals(item.Name, InterfaceName, StringComparison.OrdinalIgnoreCase)) continue;
                var ownsBestAddress = item.GetIPProperties().UnicastAddresses
                    .Any(address => address.Address.Equals(local.Address));
                if (ownsBestAddress && LooksLikeTunnel(item))
                {
                    interfaceName = item.Name;
                    return !string.IsNullOrWhiteSpace(interfaceName);
                }
            }
            return false;
        }
        catch { interfaceName = null; return false; }
    }

    [System.Runtime.InteropServices.DllImport("iphlpapi.dll", SetLastError = false)]
    private static extern uint GetBestInterface(uint destinationAddress, out uint bestInterfaceIndex);

    internal static string? LoopbackInterfaceName()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(item => item.NetworkInterfaceType == NetworkInterfaceType.Loopback && item.OperationalStatus == OperationalStatus.Up)
                .Select(item => item.Name)
                .FirstOrDefault(name => !string.IsNullOrWhiteSpace(name));
        }
        catch { return null; }
    }

    /// <summary>
    /// Resolve a real host underlay while another full-tunnel interface owns
    /// the default route.  The Bifrost transport must bypass both TUNs rather
    /// than chaining through the competing VPN.  Fail closed when the host has
    /// no unambiguous routed physical adapter (for example two simultaneously
    /// active Ethernet/Wi-Fi uplinks).
    /// </summary>
    internal static bool TryGetPhysicalUnderlay(out string? interfaceName)
    {
        interfaceName = null;
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            // Prefer the physical interface that Windows itself currently
            // selects for a public IPv4 destination.  This keeps a normal
            // single-uplink host deterministic even when another physical
            // adapter is also Up (for example Ethernet plus Wi-Fi).  When a
            // transparent tunnel owns the best route this lookup deliberately
            // falls through to the gateway-backed physical-candidate logic
            // below, which is the coexistence case this helper historically
            // handled.
            if (GetBestInterface(unchecked((uint)IPAddress.NetworkToHostOrder(unchecked((int)0x01010101))), out var bestIndex) == 0 && bestIndex != 0)
            {
                var bestPhysical = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(item => item.OperationalStatus == OperationalStatus.Up &&
                        item.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) &&
                        !LooksLikeTunnel(item))
                    .FirstOrDefault(item =>
                    {
                        int index;
                        try { index = item.GetIPProperties().GetIPv4Properties()?.Index ?? -1; }
                        catch { return false; }
                        if (index != checked((int)bestIndex)) return false;
                        var properties = item.GetIPProperties();
                        return properties.GatewayAddresses.Any(gateway =>
                            gateway.Address.AddressFamily == AddressFamily.InterNetwork &&
                            !gateway.Address.Equals(IPAddress.Any) && !gateway.Address.Equals(IPAddress.None));
                    });
                if (bestPhysical is not null && !string.IsNullOrWhiteSpace(bestPhysical.Name))
                {
                    interfaceName = bestPhysical.Name;
                    return true;
                }
            }

            var candidates = NetworkInterface.GetAllNetworkInterfaces()
                .Where(item => item.OperationalStatus == OperationalStatus.Up &&
                    item.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) &&
                    !LooksLikeTunnel(item))
                .Where(item =>
                {
                    var properties = item.GetIPProperties();
                    return properties.GatewayAddresses.Any(gateway =>
                               gateway.Address.AddressFamily == AddressFamily.InterNetwork &&
                               !gateway.Address.Equals(IPAddress.Any) && !gateway.Address.Equals(IPAddress.None)) &&
                           properties.UnicastAddresses.Any(address =>
                               address.Address.AddressFamily == AddressFamily.InterNetwork &&
                               !IPAddress.IsLoopback(address.Address));
                })
                .Select(item => item.Name)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (candidates.Length != 1) return false;
            interfaceName = candidates[0];
            return !string.IsNullOrWhiteSpace(interfaceName);
        }
        catch { interfaceName = null; return false; }
    }

    internal static bool IsPhysicalUnderlay(string? interfaceName)
    {
        if (string.IsNullOrWhiteSpace(interfaceName) || !OperatingSystem.IsWindows()) return false;
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(item =>
                string.Equals(item.Name, interfaceName, StringComparison.OrdinalIgnoreCase) &&
                item.OperationalStatus == OperationalStatus.Up &&
                item.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) &&
                !LooksLikeTunnel(item) &&
                item.GetIPProperties().GatewayAddresses.Any(gateway => gateway.Address.AddressFamily == AddressFamily.InterNetwork));
        }
        catch { return false; }
    }

    private static bool LooksLikeTunnel(NetworkInterface item)
    {
        if (item.NetworkInterfaceType == NetworkInterfaceType.Tunnel) return true;
        var label = $"{item.Name} {item.Description}".ToLowerInvariant();
        return new[] { " tunnel", "tun", "tap", "wintun", "wireguard", "tailscale", "zerotier", " vpn" }
            .Any(marker => label.Contains(marker, StringComparison.Ordinal));
    }

    private static bool LooksLikeTransparentFullTunnel(NetworkInterface item)
    {
        var label = $"{item.Name} {item.Description}".ToLowerInvariant();
        if (label.Contains("tailscale", StringComparison.Ordinal) ||
            label.Contains("radmin", StringComparison.Ordinal) ||
            label.Contains("zerotier", StringComparison.Ordinal) ||
            label.Contains("teredo", StringComparison.Ordinal))
            return false;
        return label.Contains("singbox_tun", StringComparison.Ordinal) ||
               label.Contains("sing-tun", StringComparison.Ordinal) ||
               label.Contains("wintun", StringComparison.Ordinal) ||
               label.Contains("mihomo", StringComparison.Ordinal) ||
               label.Contains("clash", StringComparison.Ordinal) ||
               label.Contains("tun mode", StringComparison.Ordinal);
    }

    private static bool OwnsBifrostCoreProcess(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            if (process.HasExited) return false;
            var path = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(path)) return false;
            path = Path.GetFullPath(path);
            var root = AppContext.BaseDirectory;
            var allowed = new[]
            {
                Path.GetFullPath(Path.Combine(root, "cores", "mihomo.exe")),
                Path.GetFullPath(Path.Combine(root, "mihomo.exe")),
            };
            return allowed.Any(candidate => string.Equals(candidate, path, StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }

    private static bool Same(NetworkBoundaryIntent left, NetworkBoundaryIntent right) =>
        left.Mode == right.Mode && left.Core == right.Core && left.ConfigId == right.ConfigId &&
        left.PolicyDigest == right.PolicyDigest && left.Generation == right.Generation;

    private static NetworkBoundaryEvidence Evidence(NetworkBoundaryIntent intent, bool active, bool readback) =>
        new(intent.Mode, intent.Core, intent.ConfigId, intent.Generation, intent.PolicyDigest,
            active, active, active, active, readback);
}

/// <summary>Explicit disabled adapter retained for failure-path fixtures.</summary>
public sealed class DisabledNetworkBoundary : INetworkBoundary
{
    public NetworkBoundaryResult Prepare(NetworkBoundaryIntent intent) => NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
    public NetworkBoundaryResult Activate(NetworkBoundaryIntent intent, int ownerProcessId) => NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
    public NetworkBoundaryResult Readback(NetworkBoundaryIntent intent) => NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
    public void Retire(string generation) { }
}

/// <summary>
/// Pure fake used by contract tests. It models ownership and generation
/// checks, but never touches WFP, TUN, sockets or the host network.
/// </summary>
public sealed class FakeNetworkBoundary : INetworkBoundary
{
    private readonly object _sync = new();
    private readonly ConcurrentQueue<string> _events = new();
    private NetworkBoundaryIntent? _intent;
    private NetworkBoundaryEvidence? _evidence;
    private int _ownerPid;

    public bool FailPrepare { get; set; }
    public bool FailActivate { get; set; }
    public bool FailReadback { get; set; }
    public bool FailRetire { get; set; }
    public bool FailPrepareAfterInstall { get; set; }
    public bool ReturnMismatchedReadback { get; set; }
    public IReadOnlyCollection<string> Events => _events.ToArray();

    public NetworkBoundaryResult Prepare(NetworkBoundaryIntent intent)
    {
        lock (_sync)
        {
            _events.Enqueue("prepare:" + intent.Generation);
            if (FailPrepare) return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
            _intent = intent;
            _evidence = Evidence(intent, false);
            if (FailPrepareAfterInstall) return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
            return new NetworkBoundaryResult(true, "OK", _evidence);
        }
    }

    public NetworkBoundaryResult Activate(NetworkBoundaryIntent intent, int ownerProcessId)
    {
        lock (_sync)
        {
            _events.Enqueue("activate:" + intent.Generation);
            if (FailActivate || _intent is null || !Same(_intent, intent)) return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
            _ownerPid = ownerProcessId;
            _evidence = Evidence(intent, true);
            return new NetworkBoundaryResult(true, "OK", _evidence);
        }
    }

    public NetworkBoundaryResult Readback(NetworkBoundaryIntent intent)
    {
        lock (_sync)
        {
            _events.Enqueue("readback:" + intent.Generation);
            if (FailReadback || _ownerPid <= 0 || _intent is null || _evidence is null || !Same(_intent, intent))
                return NetworkBoundaryResult.Fail("BF-NETWORK-BOUNDARY");
            var readback = _evidence with { ReadbackVerified = true };
            if (ReturnMismatchedReadback)
                readback = readback with { PolicyDigest = "mismatched".PadLeft(64, 'm') };
            return new NetworkBoundaryResult(true, "OK", readback);
        }
    }

    public void Retire(string generation)
    {
        lock (_sync)
        {
            _events.Enqueue("retire:" + generation);
            if (FailRetire) throw new InvalidOperationException("test-only retire failure");
            if (_intent?.Generation == generation)
            {
                _intent = null;
                _evidence = null;
                _ownerPid = 0;
            }
        }
    }

    public void SimulateCrash() { lock (_sync) { _ownerPid = 0; _evidence = null; _events.Enqueue("crash"); } }

    private static bool Same(NetworkBoundaryIntent a, NetworkBoundaryIntent b) =>
        a.Mode == b.Mode && a.Core == b.Core && a.ConfigId == b.ConfigId && a.PolicyDigest == b.PolicyDigest && a.Generation == b.Generation;

    private static NetworkBoundaryEvidence Evidence(NetworkBoundaryIntent intent, bool active) =>
        // Prepare/activate establish ownership only.  The active generation is
        // not trusted until a separate readback has verified the live boundary.
        new(intent.Mode, intent.Core, intent.ConfigId, intent.Generation, intent.PolicyDigest, active, active, active, active, false);
}
