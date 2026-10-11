using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bifrost.ClientService;

// Persists only a throughput-confirmed automatic winner. Every recalled member
// is revalidated through the current signed provider and controller readback.
// A very recent winner may then take the fast reconnect path; older history can
// never bypass current health authority.
internal sealed class MihomoConnectionMemory(string path)
{
    private sealed record Entry(string Key, string Candidate, long At);
    // New writes bind to source identity + physical adapter identity. The
    // recalled candidate is always checked against the current signed provider
    // and fresh health before use, so harmless provider regeneration/reordering
    // must not throw away the previous throughput winner.
    // Keep old winners long enough to survive harmless provider regeneration,
    // but only trust a very recent winner for the zero-download fast path.
    // Residential/edge capacity can change much faster than reachability; a
    // seven-day-old entry must seed history, not skip a fresh qualification.
    internal const long LifetimeMs = 7L * 24 * 60 * 60_000;
    internal const long FastReuseMs = 15L * 60_000;
    private static readonly object Gate = new();
    internal static string StableKey(string providerName, string network) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            "v2|" + providerName.Trim().ToUpperInvariant() + "|" + network)));

    // Legacy key used by <=2.2.38. Retained only for one-time migration.
    internal static string Key(byte[] provider, string network) =>
        Convert.ToHexString(SHA256.HashData(provider.Concat(Encoding.UTF8.GetBytes(network)).ToArray()));

    internal string? Recall(string key, IReadOnlySet<string> allowed, long now)
    {
        lock (Gate)
            return Read().LastOrDefault(entry => entry.Key == key && allowed.Contains(entry.Candidate) &&
                now - entry.At is >= 0 and <= LifetimeMs)?.Candidate;
    }

    internal string? RecallFresh(string key, IReadOnlySet<string> allowed, long now)
    {
        lock (Gate)
            return Read().LastOrDefault(entry => entry.Key == key && allowed.Contains(entry.Candidate) &&
                now - entry.At is >= 0 and <= FastReuseMs)?.Candidate;
    }

    internal string? RecallAny(IReadOnlySet<string> allowed, long now)
    {
        lock (Gate)
            return Read().LastOrDefault(entry => allowed.Contains(entry.Candidate) &&
                now - entry.At is >= 0 and <= LifetimeMs)?.Candidate;
    }

    internal string? RecallAnyFresh(IReadOnlySet<string> allowed, long now)
    {
        lock (Gate)
            return Read().LastOrDefault(entry => allowed.Contains(entry.Candidate) &&
                now - entry.At is >= 0 and <= FastReuseMs)?.Candidate;
    }

    internal void Remember(string key, string candidate, long now)
    {
        lock (Gate)
        {
            try
            {
                if (key.Length != 64 || candidate.Length is < 1 or > 128) return;
                var entries = Read().Where(entry => entry.Key != key && now - entry.At is >= 0 and <= LifetimeMs)
                    .TakeLast(7).Append(new Entry(key, candidate, now)).ToArray();
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                var temporary = path + ".tmp";
                File.WriteAllText(temporary, JsonSerializer.Serialize(entries));
                File.Move(temporary, path, overwrite: true);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        }
    }

    internal void Forget(string key)
    {
        lock (Gate)
        {
            try
            {
                var entries = Read().Where(entry => entry.Key != key).TakeLast(8).ToArray();
                if (entries.Length == 0)
                {
                    if (File.Exists(path)) File.Delete(path);
                    return;
                }
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                var temporary = path + ".tmp";
                File.WriteAllText(temporary, JsonSerializer.Serialize(entries));
                File.Move(temporary, path, overwrite: true);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        }
    }

    private Entry[] Read()
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length > 16 * 1024) return [];
            return (JsonSerializer.Deserialize<Entry?[]>(File.ReadAllBytes(path)) ?? [])
                .Where(entry => entry is { Key.Length: 64, Candidate.Length: >= 1 and <= 128, At: > 0 })
                .Select(entry => entry!).TakeLast(8).ToArray();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException) { return []; }
    }
}
