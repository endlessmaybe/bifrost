using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bifrost.ClientService;

internal static class MihomoHealthProbeSession
{
    internal static async Task<IReadOnlyList<MihomoProxyHealth>> MeasureAsync(
        MihomoCompiledPackage package,
        string binary,
        string expectedSha256,
        string generationRoot,
        string runtimeRoot,
        IReadOnlyList<string> candidates,
        CancellationToken cancellationToken,
        Func<MihomoProxyHealth, Task>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(package);
        if (candidates is null || candidates.Count is < 1 or > 600 ||
            candidates.Distinct(StringComparer.OrdinalIgnoreCase).Count() != candidates.Count ||
            candidates.Any(candidate => !package.AllowedCandidates.Contains(candidate)))
            throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        var measurementPackage = PrepareMeasurementPackage(package);
        var (controller, secret) = Controller(measurementPackage.MainConfig);
        using var supervisor = new MihomoRuntimeSupervisor(binary, expectedSha256, runtimeRoot);
        MihomoRuntimeIdentity? identity = null;
        try
        {
            identity = supervisor.Start(measurementPackage, generationRoot);
            using var client = new MihomoControllerClient(controller, secret, TimeSpan.FromSeconds(12));
            await client.WaitReadyAsync(cancellationToken).ConfigureAwait(false);
            return await client.MeasureCandidatesInBatchesAsync(package.ProviderName, candidates,
                progress, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (identity is not null) supervisor.StopConfirmed(identity, TimeSpan.FromSeconds(5));
            CryptographicOperations.ZeroMemory(measurementPackage.MainConfig);
            CryptographicOperations.ZeroMemory(measurementPackage.Provider);
        }
    }

    private static MihomoCompiledPackage PrepareMeasurementPackage(MihomoCompiledPackage package)
    {
        JsonObject main;
        try { main = JsonNode.Parse(package.MainConfig)!.AsObject(); }
        catch { throw new InvalidDataException("BF-MIHOMO-CONFIG"); }
        var tun = main["tun"] as JsonObject ?? throw new InvalidDataException("BF-MIHOMO-TUN");
        tun["enable"] = false;

        // A manual/global package uses a selector that names one proxy from a
        // file provider. Mihomo validates selectors before asynchronous file
        // providers are loaded, so that otherwise-valid runtime exits with
        // "proxy not found" before its controller can start. A latency sweep
        // needs the complete provider rather than the customer's fixed choice.
        // Use a provider-backed selector and disable autonomous health rounds
        // in this transient copy. Only the bounded per-node delay requests may
        // start probes; the signed connection package stays unchanged.
        var groups = main["proxy-groups"] as JsonArray ?? throw new InvalidDataException("BF-MIHOMO-GROUP");
        var activeGroups = groups.OfType<JsonObject>().Where(group =>
            string.Equals(group["name"]?.GetValue<string>(), package.ActiveGroup, StringComparison.Ordinal)).ToArray();
        if (activeGroups.Length != 1) throw new InvalidDataException("BF-MIHOMO-GROUP");
        var activeGroup = activeGroups[0];
        activeGroup.Clear();
        activeGroup["name"] = package.ActiveGroup;
        activeGroup["type"] = "select";
        activeGroup["use"] = new JsonArray(package.ProviderName);
        activeGroup["empty-fallback"] = "REJECT";
        var health = main["proxy-providers"]?[package.ProviderName]?["health-check"] as JsonObject
            ?? throw new InvalidDataException("BF-MIHOMO-CONFIG");
        health["enable"] = false;
        var mainBytes = JsonSerializer.SerializeToUtf8Bytes(main, new JsonSerializerOptions { WriteIndented = false });
        var provider = package.Provider.ToArray();
        var combined = new byte[mainBytes.Length + provider.Length];
        try
        {
            mainBytes.CopyTo(combined, 0); provider.CopyTo(combined, mainBytes.Length);
            return package with
            {
                MainConfig = mainBytes,
                Provider = provider,
                Digest = Convert.ToHexString(SHA256.HashData(combined)).ToLowerInvariant(),
            };
        }
        finally { CryptographicOperations.ZeroMemory(combined); }
    }

    private static (Uri Controller, string Secret) Controller(byte[] mainConfig)
    {
        try
        {
            using var document = JsonDocument.Parse(mainConfig);
            var root = document.RootElement;
            var value = root.GetProperty("external-controller").GetString() ?? string.Empty;
            var secret = root.GetProperty("secret").GetString() ?? string.Empty;
            if (!value.StartsWith("127.0.0.1:", StringComparison.Ordinal) ||
                !int.TryParse(value["127.0.0.1:".Length..], out var port) || port is < 1024 or > 65535 || secret.Length is < 32 or > 256)
                throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
            return (new Uri($"http://127.0.0.1:{port}/"), secret);
        }
        catch (InvalidDataException) { throw; }
        catch { throw new InvalidDataException("BF-MIHOMO-CONTROLLER"); }
    }
}
