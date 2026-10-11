using System.IO;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

namespace Bifrost;

/// <summary>
/// Returns a privacy-preserving, installation-local network bucket.  The
/// profile identifier is obtained from Windows Network List Manager when it is
/// unambiguous; otherwise this instance deliberately falls back to a
/// process-session epoch so a result can never cross an unknown network.
/// Raw profile, adapter, SSID, MAC and IP values never leave this class.
/// </summary>
internal sealed class WindowsNetworkBucket
{
    private const string NetworkListManagerClsid = "DCB00C01-570F-4A9B-8D69-199FDBA5723B";
    private readonly string _saltPath;
    private readonly byte[] _salt;
    private readonly string _sessionEpoch = Guid.NewGuid().ToString("N");
    private readonly Func<string?> _stableMaterialProvider;

    public WindowsNetworkBucket(string root, Func<string?>? stableMaterialProvider = null, bool initialize = true)
    {
        if (!initialize)
        {
            _saltPath = string.Empty;
            _salt = RandomNumberGenerator.GetBytes(32);
            _stableMaterialProvider = stableMaterialProvider ?? (() => null);
            return;
        }
        Directory.CreateDirectory(root);
        _saltPath = Path.Combine(root, "candidate-probe.salt.bin");
        _salt = LoadOrCreateSalt(_saltPath);
        _stableMaterialProvider = stableMaterialProvider ?? TryGetStableProfileMaterial;
    }

    public string GetFingerprint()
    {
        var material = _stableMaterialProvider();
        if (string.IsNullOrWhiteSpace(material)) material = "session:" + _sessionEpoch;
        using var hmac = new HMACSHA256(_salt);
        return "net-" + Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    private static byte[] LoadOrCreateSalt(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var protectedBytes = File.ReadAllBytes(path);
                var salt = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
                if (salt.Length >= 16) return salt;
            }
        }
        catch { /* corrupted or unavailable DPAPI => replace, never reuse plaintext */ }

        var created = RandomNumberGenerator.GetBytes(32);
        try
        {
            var temp = path + "." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllBytes(temp, ProtectedData.Protect(created, null, DataProtectionScope.CurrentUser));
            File.Move(temp, path, true);
        }
        catch { /* the in-memory salt still protects this process' buckets */ }
        return created;
    }

    private static string? TryGetStableProfileMaterial()
    {
        try
        {
            var active = NetworkInterface.GetAllNetworkInterfaces()
                .Where(item => item.OperationalStatus == OperationalStatus.Up && item.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(item => item.Id)
                .Where(item => Guid.TryParse(item, out _))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (active.Count == 0) return null;

            var networkType = Type.GetTypeFromCLSID(Guid.Parse(NetworkListManagerClsid));
            if (networkType is null) return null;
            object? manager = Activator.CreateInstance(networkType);
            try
            {
                // NLM_ENUM_NETWORK_CONNECTED = 1.  Late binding keeps this helper
                // optional on stripped/older Windows images; all failures fail safe.
                dynamic networks = ((dynamic)manager!).GetNetworks(1);
                try
                {
                    var pairs = new List<string>();
                    foreach (var network in networks)
                    {
                        object? connections = null;
                        try
                        {
                            Guid profile = ((dynamic)network).GetNetworkId();
                            connections = ((dynamic)network).GetNetworkConnections();
                            foreach (var connection in (dynamic)connections)
                            {
                                Guid adapter = ((dynamic)connection).GetAdapterId();
                                if (active.Contains(adapter.ToString("B")) || active.Contains(adapter.ToString()))
                                    pairs.Add(profile.ToString("D") + ":" + adapter.ToString("D"));
                                ReleaseCom(connection);
                            }
                        }
                        finally
                        {
                            ReleaseCom(connections);
                            ReleaseCom(network);
                        }
                    }
                    var unique = pairs.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                    return unique.Length == 1 ? unique[0] : null;
                }
                finally { ReleaseCom(networks); }
            }
            finally { ReleaseCom(manager); }
        }
        catch
        {
            return null;
        }
    }

    private static void ReleaseCom(object? value)
    {
        try
        {
            if (value is not null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value);
        }
        catch { /* cleanup is best-effort; identity remains fail-safe */ }
    }
}
