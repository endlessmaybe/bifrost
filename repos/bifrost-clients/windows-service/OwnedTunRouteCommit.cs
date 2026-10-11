using System.Diagnostics;
using System.Net;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Bifrost.ClientService;

/// <summary>
/// Owns only the temporary active-store routes used for Bifrost cutover.
/// It never edits a third-party route, never writes the persistent route store,
/// and every add has an exact prefix/interface delete counterpart.
/// </summary>
internal sealed class OwnedTunRouteCommit : IDisposable
{
    private const int RouteMetric = 1;
    private readonly int _interfaceIndex;
    private readonly bool _includeIpv6;
    private readonly Func<string, string, int, bool>? _testRunner;
    private readonly Func<string, int, bool?>? _testRouteExists;
    private IPAddress? _canary;
    private bool _v4LowHalf;
    private bool _v4HighHalf;
    private bool _v6LowHalf;
    private bool _v6HighHalf;
    private bool _disposed;

    internal bool HasFullTunnel => !_disposed && _v4LowHalf && _v4HighHalf &&
        (!_includeIpv6 || _v6LowHalf && _v6HighHalf);

    internal OwnedTunRouteCommit(int interfaceIndex, bool includeIpv6 = false,
        Func<string, string, int, bool>? testRunner = null, Func<string, int, bool?>? testRouteExists = null)
    {
        if (interfaceIndex <= 0) throw new ServiceFailure("BF-TUN-ROUTE");
        _interfaceIndex = interfaceIndex;
        _includeIpv6 = includeIpv6;
        _testRunner = testRunner;
        _testRouteExists = testRouteExists;
    }

    /// <summary>
    /// Crash/startup recovery for the only host-wide prefixes this class can
    /// ever own.  It is intentionally scoped to the exact bifrost1 interface
    /// index supplied by the caller, so a v2rayN/Clash/WireGuard route on any
    /// other interface is unreachable from this cleanup path.  Missing routes
    /// are harmless: cleanup is best-effort because netsh reports a non-zero
    /// exit code when an exact route is already absent.
    /// </summary>
    internal static void RemoveKnownFullTunnelRoutesBestEffort(int interfaceIndex,
        Func<string, string, int, bool>? testRunner = null)
    {
        if (interfaceIndex <= 0) return;
        foreach (var prefix in new[] { "8000::/1", "::/1", "128.0.0.0/1", "0.0.0.0/1" })
            _ = RunNetshCore("delete", prefix, interfaceIndex, testRunner);
    }

    internal void InstallCanary(IPAddress address)
    {
        ThrowIfDisposed();
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new ServiceFailure("BF-TUN-ROUTE");
        RemoveCanary();
        var canonical = IPAddress.Parse(address.ToString());
        Add(canonical + "/32");
        _canary = canonical;
    }

    internal void CommitFullTunnel()
    {
        ThrowIfDisposed();
        try
        {
            if (!_v4LowHalf)
            {
                Add("0.0.0.0/1");
                _v4LowHalf = true;
            }
            if (!_v4HighHalf)
            {
                Add("128.0.0.0/1");
                _v4HighHalf = true;
            }
            if (_includeIpv6 && !_v6LowHalf)
            {
                Add("::/1");
                _v6LowHalf = true;
            }
            if (_includeIpv6 && !_v6HighHalf)
            {
                Add("8000::/1");
                _v6HighHalf = true;
            }
        }
        catch
        {
            // This is one transaction.  A partial route set is more dangerous
            // than no Bifrost route at all because it can make only half of
            // the address space disappear.  Reverse every route that this
            // instance successfully added before propagating the failure.
            _ = RemoveAll();
            throw;
        }
    }

    internal void RemoveCanary()
    {
        if (_canary is null) return;
        if (!Delete(_canary + "/32"))
            throw new ServiceFailure("BF-TUN-ROUTE");
        _canary = null;
    }

    internal bool RemoveAll()
    {
        var ok = true;
        if (_v6HighHalf)
        {
            var removed = Delete("8000::/1");
            ok &= removed;
            if (removed) _v6HighHalf = false;
        }
        if (_v6LowHalf)
        {
            var removed = Delete("::/1");
            ok &= removed;
            if (removed) _v6LowHalf = false;
        }
        if (_v4HighHalf)
        {
            var removed = Delete("128.0.0.0/1");
            ok &= removed;
            if (removed) _v4HighHalf = false;
        }
        if (_v4LowHalf)
        {
            var removed = Delete("0.0.0.0/1");
            ok &= removed;
            if (removed) _v4LowHalf = false;
        }
        if (_canary is not null)
        {
            var removed = Delete(_canary + "/32");
            ok &= removed;
            if (removed) _canary = null;
        }
        return ok;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _ = RemoveAll();
        _disposed = true;
    }

    private void Add(string prefix)
    {
        if (!RunNetsh("add", prefix)) throw new ServiceFailure("BF-TUN-ROUTE");
    }

    private bool Delete(string prefix)
    {
        if (RunNetsh("delete", prefix)) return true;
        // Windows also deletes active-store routes when the TUN disappears.
        // A missing route is already cleaned; an unreadable route is not.
        var exists = _testRouteExists is not null ? _testRouteExists(prefix, _interfaceIndex)
            : _testRunner is null ? ReadRoutePresent(prefix, _interfaceIndex) : null;
        return exists == false;
    }

    internal static bool? ReadRoutePresent(string prefix, int interfaceIndex)
    {
        if (!OperatingSystem.IsWindows() || interfaceIndex <= 0) return null;
        try
        {
            var parts = prefix.Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address) || !byte.TryParse(parts[1], out var length)) return null;
            var ipv4 = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
            if (length > (ipv4 ? 32 : 128)) return null;
            // MIB_IPFORWARD_ROW2: fixed native layout, including two 28-byte
            // SOCKADDR_INET unions. On-link next hop is the zero address.
            var row = new byte[104];
            BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(8), (uint)interfaceIndex);
            var family = (ushort)(ipv4 ? 2 : 23);
            BinaryPrimitives.WriteUInt16LittleEndian(row.AsSpan(12), family);
            address.GetAddressBytes().CopyTo(row, ipv4 ? 16 : 20);
            row[40] = length;
            BinaryPrimitives.WriteUInt16LittleEndian(row.AsSpan(44), family);
            return GetIpForwardEntry2(row) switch { 0 => true, 1168 => false, _ => null };
        }
        catch { return null; }
    }

    [DllImport("iphlpapi.dll", SetLastError = false)]
    private static extern uint GetIpForwardEntry2([In, Out] byte[] row);

    private bool RunNetsh(string operation, string prefix) =>
        RunNetshCore(operation, prefix, _interfaceIndex, _testRunner);

    private static bool RunNetshCore(string operation, string prefix, int interfaceIndex,
        Func<string, string, int, bool>? testRunner)
    {
        if (testRunner is not null) return testRunner(operation, prefix, interfaceIndex);
        if (!OperatingSystem.IsWindows()) return false;
        var netsh = Path.Combine(Environment.SystemDirectory, "netsh.exe");
        if (!File.Exists(netsh)) return false;
        var start = new ProcessStartInfo
        {
            FileName = netsh,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("interface");
        start.ArgumentList.Add(prefix.Contains(':', StringComparison.Ordinal) ? "ipv6" : "ipv4");
        start.ArgumentList.Add(operation);
        start.ArgumentList.Add("route");
        start.ArgumentList.Add("prefix=" + prefix);
        start.ArgumentList.Add("interface=" + interfaceIndex.ToString(System.Globalization.CultureInfo.InvariantCulture));
        start.ArgumentList.Add("store=active");
        if (operation == "add") start.ArgumentList.Add("metric=" + RouteMetric.ToString(System.Globalization.CultureInfo.InvariantCulture));
        using var process = Process.Start(start);
        if (process is null) return false;
        if (!process.WaitForExit(1500))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            return false;
        }
        return process.ExitCode == 0;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(OwnedTunRouteCommit));
    }
}
