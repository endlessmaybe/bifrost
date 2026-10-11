using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Bifrost.ClientService;

/// <summary>
/// The one framing/authentication implementation shared by the service,
/// desktop client and installer.  It deliberately contains no WPF, SCM or
/// process-management code so the installer cannot drift into a second wire
/// protocol.  All I/O is bounded and cancellation driven.
/// </summary>
public static class BifrostIpcWire
{
    public const int MaxFrameBytes = 1536 * 1024;
    public const string GenerationsDirectoryName = ".bifrost-generations";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 8,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow
    };

    public static async Task<byte[]> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var prefix = new byte[sizeof(int)];
        await ReadExactAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        CryptographicOperations.ZeroMemory(prefix);
        if (length <= 0 || length > MaxFrameBytes) throw new InvalidDataException("BF-IPC-FRAME");
        var payload = new byte[length];
        try
        {
            await ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false);
            return payload;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(payload);
            throw;
        }
    }

    public static async Task WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (payload.Length <= 0 || payload.Length > MaxFrameBytes) throw new InvalidDataException("BF-IPC-FRAME");
        var prefix = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        try
        {
            await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(prefix); }
    }

    public static async Task<JsonDocument> ReadJsonAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = await ReadFrameAsync(stream, cancellationToken).ConfigureAwait(false);
        try { return ParseStrict(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static Task WriteJsonAsync(Stream stream, object value, CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        return WriteAndClearAsync(stream, bytes, cancellationToken);
    }

    private static async Task WriteAndClearAsync(Stream stream, byte[] bytes, CancellationToken cancellationToken)
    {
        try { await WriteFrameAsync(stream, bytes, cancellationToken).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static JsonDocument ParseStrict(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length <= 0 || bytes.Length > MaxFrameBytes) throw new InvalidDataException("BF-IPC-FRAME");
        var document = JsonDocument.Parse(bytes.ToArray(), new JsonDocumentOptions { MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false });
        try { ValidateNoDuplicateKeys(document.RootElement, 0); return document; }
        catch { document.Dispose(); throw; }
    }

    private static void ValidateNoDuplicateKeys(JsonElement element, int depth)
    {
        if (depth > 8) throw new InvalidDataException("BF-IPC-JSON");
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("BF-IPC-JSON");
                ValidateNoDuplicateKeys(property.Value, depth + 1);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) ValidateNoDuplicateKeys(item, depth + 1);
    }

    private static async Task ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read <= 0) throw new EndOfStreamException();
            offset += read;
        }
    }

    public static string Mac(ReadOnlySpan<byte> secret, string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        try { return Convert.ToHexString(HMACSHA256.HashData(secret, bytes)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static bool FixedMac(ReadOnlySpan<byte> secret, string text, string supplied)
    {
        if (supplied.Length != 64 || supplied.Any(c => !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))) return false;
        var expected = Encoding.ASCII.GetBytes(Mac(secret, text));
        var actual = Encoding.ASCII.GetBytes(supplied.ToLowerInvariant());
        try { return CryptographicOperations.FixedTimeEquals(expected, actual); }
        finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(actual); }
    }

    /// <summary>
    /// Resolve the installation root from the immutable generation layout
    /// that actually contains the running app/service:
    ///   &lt;install-root&gt;\.bifrost-generations\g-&lt;sequence&gt;-&lt;digest&gt;\
    ///
    /// The install root is deliberately not derived from Program Files. The
    /// installer supports a user-selected destination, so update authority
    /// must follow the installed generation instead of silently jumping back
    /// to C:\Program Files\Bifrost.
    /// </summary>
    public static string ResolveInstallRootFromGenerationDirectory(string baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(baseDirectory))
            throw new InvalidDataException("BF-INSTALL-LAYOUT");

        var generationRoot = new DirectoryInfo(Path.GetFullPath(baseDirectory));
        if (!generationRoot.Name.StartsWith("g-", StringComparison.Ordinal) ||
            generationRoot.Parent is null ||
            !string.Equals(generationRoot.Parent.Name, GenerationsDirectoryName, StringComparison.Ordinal) ||
            generationRoot.Parent.Parent is null)
            throw new InvalidDataException("BF-INSTALL-LAYOUT");

        var installRoot = Path.GetFullPath(generationRoot.Parent.Parent.FullName);
        var expectedGenerationRoot = Path.GetFullPath(Path.Combine(installRoot, GenerationsDirectoryName, generationRoot.Name));
        if (!string.Equals(
                expectedGenerationRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                generationRoot.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new InvalidDataException("BF-INSTALL-LAYOUT");

        return installRoot;
    }

    public static byte[] ReadBoundedFile(string path, int maxBytes)
    {
        FileStream stream;
        if (OperatingSystem.IsWindows())
        {
            var handle = OpenNoFollow(path);
            if (!GetFileInformationByHandle(handle, out var info) || info.NumberOfLinks != 1 || (info.FileAttributes & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            {
                handle.Dispose();
                throw new InvalidDataException("BF-IPC-BINDING");
            }
            stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        }
        else
        {
            var attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException("BF-IPC-BINDING");
            stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        }
        using (stream)
        {
        if (stream.Length <= 0 || stream.Length > maxBytes) throw new InvalidDataException("BF-IPC-BINDING");
        var bytes = new byte[checked((int)stream.Length)];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = stream.Read(bytes, offset, bytes.Length - offset);
            if (read <= 0) throw new EndOfStreamException();
            offset += read;
        }
        if (stream.ReadByte() != -1) throw new InvalidDataException("BF-IPC-BINDING");
        return bytes;
        }
    }

    private static SafeFileHandle OpenNoFollow(string path)
    {
        var handle = CreateFileW(path, 0x80000000u, 0x00000001u, IntPtr.Zero, 3u, 0x00200080u, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new IOException("BF-IPC-BINDING"); }
        return handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes, CreationTimeLow, CreationTimeHigh, LastAccessTimeLow, LastAccessTimeHigh, LastWriteTimeLow, LastWriteTimeHigh, VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation info);
}
