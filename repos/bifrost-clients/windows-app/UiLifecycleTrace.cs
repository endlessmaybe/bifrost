using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Bifrost;

/// <summary>Rare lifecycle events only; never includes exception messages, tokens or UI content.</summary>
internal static class UiLifecycleTrace
{
    private static readonly object Sync = new();
    private const int MaxBytes = 128 * 1024;
    internal static string DirectoryPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bifrost", "diagnostics");

    internal static void Write(string eventName, Exception? exception = null, int? exitCode = null)
        => WriteTo(DirectoryPath, eventName, exception, exitCode);

    internal static void WriteTo(string directory, string eventName, Exception? exception = null, int? exitCode = null)
    {
        try
        {
            var frames = exception is null ? Array.Empty<string>() :
                (new StackTrace(exception, false).GetFrames() ?? Array.Empty<StackFrame>()).Take(20)
                .Select(frame => frame.GetMethod()).Where(method => method is not null)
                .Select(method => (method!.DeclaringType?.FullName ?? "unknown") + "." + method.Name).ToArray();
            var record = JsonSerializer.Serialize(new
            {
                utc = DateTimeOffset.UtcNow.ToString("o"), pid = Environment.ProcessId,
                version = typeof(UiLifecycleTrace).Assembly.GetName().Version?.ToString(),
                event_name = eventName, exit_code = exitCode,
                error_type = exception?.GetType().FullName, frames,
            });
            lock (Sync)
            {
                Directory.CreateDirectory(directory);
                var path = Path.Combine(directory, "ui-lifecycle.ndjson");
                if (File.Exists(path) && new FileInfo(path).Length + Encoding.UTF8.GetByteCount(record) > MaxBytes)
                    File.Move(path, path + ".1", true);
                File.AppendAllText(path, record + Environment.NewLine, new UTF8Encoding(false));
            }
        }
        // Diagnostics must not convert a full disk, locked file or denied
        // directory into a second crash while recording the original event.
        catch { }
    }
}
