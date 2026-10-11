using System.IO;
using System.Text.Json.Nodes;

namespace Bifrost;

public enum CandidateMode
{
    Auto,
    Manual,
}

public sealed record CandidateOption(string Label, string DisplayName);

public sealed record CoreOption(string Code, string DisplayName);

public enum ConnectionType
{
    DirectVmess,
    SmartGate,
}

public enum RouteMode
{
    Smart,
    Global,
    PerApp,
}

public sealed record ConnectionRouteSelection(ConnectionType ConnectionType, RouteMode RouteMode)
{
    public static ConnectionRouteSelection FromPresentation(string mode, bool appPolicyEnabled) =>
        mode switch
        {
            ProtocolCodes.ModeSmartGate => new(ConnectionType.SmartGate, appPolicyEnabled ? RouteMode.PerApp : RouteMode.Smart),
            ProtocolCodes.ModeSmart => new(ConnectionType.DirectVmess, appPolicyEnabled ? RouteMode.PerApp : RouteMode.Smart),
            ProtocolCodes.ModeGlobal => new(ConnectionType.DirectVmess, appPolicyEnabled ? RouteMode.PerApp : RouteMode.Global),
            _ => throw new InvalidDataException("BF-CONNECTION-TYPE")
        };

    public static ConnectionRouteSelection Parse(string? connectionType, string? routeMode) =>
        (connectionType, routeMode) switch
        {
            ("direct-vmess", ProtocolCodes.ModeSmart) => new(ConnectionType.DirectVmess, RouteMode.Smart),
            ("direct-vmess", ProtocolCodes.ModeGlobal) => new(ConnectionType.DirectVmess, RouteMode.Global),
            ("direct-vmess", ProtocolCodes.ModePerApp) => new(ConnectionType.DirectVmess, RouteMode.PerApp),
            ("smartgate", ProtocolCodes.ModeSmart) => new(ConnectionType.SmartGate, RouteMode.Smart),
            ("smartgate", ProtocolCodes.ModePerApp) => new(ConnectionType.SmartGate, RouteMode.PerApp),
            _ => throw new InvalidDataException("BF-CONNECTION-TYPE")
        };

    public string ConnectionTypeCode => ConnectionType == ConnectionType.SmartGate ? "smartgate" : "direct-vmess";
    public string RouteModeCode => RouteMode switch
    {
        RouteMode.Smart => ProtocolCodes.ModeSmart,
        RouteMode.Global => ProtocolCodes.ModeGlobal,
        RouteMode.PerApp => ProtocolCodes.ModePerApp,
        _ => throw new InvalidDataException("BF-ROUTE-MODE")
    };
}

/** Safe, typed node choices shared by the WPF view model and compiler seam. */
public static class CandidateSelectionContract
{
    public static IReadOnlyList<CoreOption> CoreOptions { get; } = new[]
    {
        new CoreOption(ProtocolCodes.CoreAuto, "自动（Mihomo）"),
        new CoreOption(ProtocolCodes.CoreMihomo, "Mihomo 核心"),
    };

    public static IReadOnlyList<CandidateOption> CandidateOptions(JsonObject verifiedConfig, string sourceCode)
    {
        var source = FindSource(verifiedConfig, sourceCode);
        if (source?["candidates"] is not JsonArray candidates) return Array.Empty<CandidateOption>();
        return candidates.OfType<JsonObject>()
            .Select(item =>
            {
                var label = item["label"]?.GetValue<string>()?.Trim();
                var display = item["display_name"]?.GetValue<string>()?.Trim();
                if (string.IsNullOrWhiteSpace(display)) display = item["name"]?.GetValue<string>()?.Trim();
                return string.IsNullOrWhiteSpace(label) || !SafeDisplay(label) ? null : new CandidateOption(label, SafeDisplay(display) ? display! : label);
            })
            .Where(option => option is not null)
            .Cast<CandidateOption>()
            .DistinctBy(option => option.Label, StringComparer.Ordinal)
            .ToArray();
    }

    public static CandidateMode ParseMode(string? value) => string.Equals(value, "manual", StringComparison.OrdinalIgnoreCase) ? CandidateMode.Manual : CandidateMode.Auto;

    public static string? ValidateManual(JsonObject verifiedConfig, string sourceCode, CandidateMode mode, string? label)
    {
        if (mode == CandidateMode.Auto) return null;
        var normalized = label?.Trim();
        if (string.IsNullOrWhiteSpace(normalized)) throw new InvalidDataException("BF-CANDIDATE-MISSING");
        if (!CandidateOptions(verifiedConfig, sourceCode).Any(option => string.Equals(option.Label, normalized, StringComparison.Ordinal)))
            throw new InvalidDataException("BF-CANDIDATE-NOT-READY");
        return normalized;
    }

    private static JsonObject? FindSource(JsonObject config, string sourceCode) =>
        (config["sources"] as JsonArray)?.OfType<JsonObject>()
            .FirstOrDefault(item => item["configured"]?.GetValue<bool>() == true &&
                string.Equals(item["code"]?.GetValue<string>(), sourceCode, StringComparison.OrdinalIgnoreCase));

    private static bool SafeDisplay(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 128 && !value.Any(char.IsControl) &&
        !value.Contains('/', StringComparison.Ordinal) && !value.Contains(':', StringComparison.Ordinal) && !value.Contains('@', StringComparison.Ordinal);
}
