using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bifrost;

internal static class NodeConfigurationNotifications
{
    // Compare verified routing content, never randomized envelope bytes or
    // global revocation counters. Keep transport credentials in the hash so
    // changing a node's UUID/password is still a real node update.
    internal static string? Fingerprint(string? verifiedConfig)
    {
        if (string.IsNullOrWhiteSpace(verifiedConfig)) return null;
        var config = JsonNode.Parse(verifiedConfig) as JsonObject;
        if (config is null) return null;
        var nodes = new JsonObject();
        foreach (var key in new[] { "sources", "countries", "routing", "core_policy" })
        {
            if (config[key] is null) return null;
            nodes[key] = Sort(config[key]);
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(nodes.ToJsonString())));
    }

    private static JsonNode? Sort(JsonNode? value) => value switch
    {
        JsonObject obj => new JsonObject(obj.OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => new KeyValuePair<string, JsonNode?>(pair.Key, Sort(pair.Value)))),
        JsonArray array => new JsonArray(array.Select(Sort).ToArray()),
        _ => value?.DeepClone()
    };

    internal static bool ShouldNotify(long before, long after, long lastNotified,
        string? previousFingerprint, string? currentFingerprint) =>
        before > 0 && after > before && after > lastNotified &&
        previousFingerprint is not null && currentFingerprint is not null &&
        !string.Equals(previousFingerprint, currentFingerprint, StringComparison.Ordinal);
}
