using System.IO;

namespace Bifrost;

/// <summary>TEST-HARNESS-only state root resolver; production builds never read this seam.</summary>
internal static class LocalEvaluationStateRoot
{
    internal static string Resolve(string leaf)
    {
        if (string.IsNullOrWhiteSpace(leaf) || leaf.Any(char.IsControl) || Path.IsPathRooted(leaf))
            throw new InvalidDataException("BF-TEST-SCOPE");
        var overrideRoot = Environment.GetEnvironmentVariable("BIFROST_TEST_STATE_ROOT");
        if (string.IsNullOrWhiteSpace(overrideRoot)) throw new InvalidDataException("BF-TEST-SCOPE");
        var full = Path.GetFullPath(overrideRoot);
        var temp = Path.GetFullPath(Path.GetTempPath());
        if (!full.StartsWith(temp, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-TEST-SCOPE");
        return Path.Combine(full, leaf);
    }
}
