using System.IO;

namespace Bifrost;

internal static class DesktopGenerationPolicy
{
    internal static bool IsPreviousImage(string image, string currentImage, string installRoot)
    {
        try
        {
            var full = Path.GetFullPath(image);
            if (string.Equals(full, Path.GetFullPath(currentImage), StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(Path.GetFileName(full), "Bifrost.exe", StringComparison.OrdinalIgnoreCase)) return false;
            var generation = Directory.GetParent(full);
            var generations = generation?.Parent;
            return generation?.Name.StartsWith("g-", StringComparison.Ordinal) == true && generations is not null &&
                string.Equals(generations.FullName, Path.Combine(Path.GetFullPath(installRoot), ".bifrost-generations"), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }
}
