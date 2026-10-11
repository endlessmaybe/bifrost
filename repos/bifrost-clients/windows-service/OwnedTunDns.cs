using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Bifrost.ClientService;

internal sealed record OwnedTunDnsState(string InterfaceId, IReadOnlyList<string> Servers);

/// <summary>
/// Binds Windows resolution to the already running, owned TUN. Merely declaring
/// dns-hijack in Mihomo cannot intercept a router DNS address on a more specific
/// physical LAN route. Keep the physical adapter and other VPNs untouched.
/// </summary>
internal sealed class OwnedTunDns : IDisposable
{
    private readonly int _interfaceIndex;
    private readonly Func<int, OwnedTunDnsState?> _read;
    private readonly Func<int, bool, bool> _write;
    private string? _interfaceId;
    private bool _installed;

    internal OwnedTunDns(int interfaceIndex, Func<int, OwnedTunDnsState?>? read = null,
        Func<int, bool, bool>? write = null)
    {
        if (interfaceIndex <= 0) throw new InvalidDataException("BF-TUN-DNS");
        _interfaceIndex = interfaceIndex;
        _read = read ?? ReadOwnedInterface;
        _write = write ?? WriteDns;
    }

    internal bool IsBound
    {
        get
        {
            var current = _read(_interfaceIndex);
            return _installed && current is not null && current.InterfaceId == _interfaceId && IsOurDns(current);
        }
    }

    internal void Install()
    {
        var current = _read(_interfaceIndex) ?? throw new InvalidDataException("BF-TUN-DNS-OWNER");
        if (current.Servers.Count != 0 && !IsOurDns(current))
            throw new InvalidDataException("BF-TUN-DNS-OWNER");
        _interfaceId = current.InterfaceId;
        _installed = true;
        try
        {
            if (!IsOurDns(current) && !_write(_interfaceIndex, true)) throw new InvalidDataException("BF-TUN-DNS");
            if (!IsBound) throw new InvalidDataException("BF-TUN-DNS-READBACK");
        }
        catch
        {
            _ = Restore();
            throw;
        }
    }

    internal bool Restore()
    {
        if (!_installed) return true;
        var current = _read(_interfaceIndex);
        // A removed adapter, or a recycled numeric index, is no longer ours.
        if (current is null || current.InterfaceId != _interfaceId || current.Servers.Count == 0)
        {
            _installed = false;
            return true;
        }
        if (!IsOurDns(current)) return false;
        if (!_write(_interfaceIndex, false)) return false;
        var after = _read(_interfaceIndex);
        var restored = after is null || after.InterfaceId != _interfaceId || after.Servers.Count == 0;
        if (restored) _installed = false;
        return restored;
    }

    internal static bool Recover(int interfaceIndex, Func<int, OwnedTunDnsState?>? read = null,
        Func<int, bool, bool>? write = null)
    {
        using var owned = new OwnedTunDns(interfaceIndex, read, write);
        var current = owned._read(interfaceIndex);
        if (current is null || !IsOurDns(current)) return true;
        owned._interfaceId = current.InterfaceId;
        owned._installed = true;
        return owned.Restore();
    }

    public void Dispose() { try { _ = Restore(); } catch { } }

    private static bool IsOurDns(OwnedTunDnsState state) =>
        state.Servers.Count == 1 && state.Servers[0] == MihomoWindowsContract.TunDnsAddress;

    private static OwnedTunDnsState? ReadOwnedInterface(int index)
    {
        try
        {
            var matches = WindowsInterfaceReadback.Read().Where(item =>
                item.Name.Equals(MihomoWindowsContract.TunInterfaceName, StringComparison.OrdinalIgnoreCase) &&
                item.Description.Equals("Meta Tunnel", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length != 1) return null;
            var current = matches[0];
            if (current.InterfaceIndex != index || !current.UnicastAddresses.Any(item =>
                item.ToString() == MihomoWindowsContract.TunIpv4Address)) return null;
            return new OwnedTunDnsState(current.Id, current.DnsAddresses
                .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
                .Select(address => address.ToString()).ToArray());
        }
        catch { return null; }
    }

    private static bool WriteDns(int index, bool enable)
    {
        if (!OperatingSystem.IsWindows() || ReadOwnedInterface(index) is null) return false;
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "netsh.exe"),
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var argument in new[] { "interface", "ipv4", "set", "dnsservers",
            "name=" + index.ToString(System.Globalization.CultureInfo.InvariantCulture),
            enable ? "source=static" : "source=dhcp" }) start.ArgumentList.Add(argument);
        if (enable)
        {
            start.ArgumentList.Add("address=" + MihomoWindowsContract.TunDnsAddress);
            start.ArgumentList.Add("validate=no");
        }
        try
        {
            using var process = Process.Start(start);
            if (process is null) return false;
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(3000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return false;
            }
            Task.WhenAll(output, error).GetAwaiter().GetResult();
            return process.ExitCode == 0;
        }
        catch { return false; }
    }
}
