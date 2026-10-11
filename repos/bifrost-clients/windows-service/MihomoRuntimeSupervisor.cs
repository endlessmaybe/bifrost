using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bifrost.ClientService;

internal sealed class MihomoRuntimeSupervisor : IDisposable
{
    private const int JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnClose = 0x00002000;
    private readonly object _gate = new();
    private readonly string _binary;
    private readonly string _expectedSha256;
    private readonly string _runtimeRoot;
    private IntPtr _job;
    private Process? _process;
    private MihomoRuntimeIdentity? _identity;
    private bool _disposed;

    internal MihomoRuntimeSupervisor(string binary, string expectedSha256, string runtimeRoot)
    {
        _binary = Path.GetFullPath(binary);
        _runtimeRoot = Path.GetFullPath(runtimeRoot);
        if (!IsDigest(expectedSha256)) throw new InvalidDataException("BF-CORE-HASH");
        _expectedSha256 = expectedSha256;
        if (OperatingSystem.IsWindows()) _job = CreateKillOnCloseJob();
    }

    internal MihomoRuntimeIdentity Start(MihomoCompiledPackage package, string generationRoot)
    {
        ArgumentNullException.ThrowIfNull(package);
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_process is { HasExited: false }) throw new InvalidDataException("BF-MIHOMO-ALREADY-RUNNING");
            _process?.Dispose(); _process = null; _identity = null;
            var generation = Path.GetFullPath(generationRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!_binary.StartsWith(generation, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-INSTALL-LAYOUT");
            ValidateFile(_binary, _expectedSha256);
            PrepareRuntime(package);
            var config = Path.Combine(_runtimeRoot, "config.json");
            var start = new ProcessStartInfo
            {
                FileName = _binary,
                WorkingDirectory = _runtimeRoot,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add("-d"); start.ArgumentList.Add(_runtimeRoot);
            start.ArgumentList.Add("-f"); start.ArgumentList.Add(config);
            var process = new Process { StartInfo = start, EnableRaisingEvents = true };
            try
            {
                if (!process.Start() || process.Id <= 0) throw new InvalidDataException("BF-MIHOMO-START");
                if (_job != IntPtr.Zero && !AssignProcessToJobObject(_job, process.Handle))
                    throw new InvalidDataException("BF-MIHOMO-JOB");
                process.BeginOutputReadLine(); process.BeginErrorReadLine();
                var deadline = DateTime.UtcNow.AddSeconds(2);
                while (DateTime.UtcNow < deadline)
                {
                    if (process.HasExited) throw new InvalidDataException("BF-MIHOMO-START");
                    if (DateTime.UtcNow.AddMilliseconds(100) >= deadline || process.TotalProcessorTime >= TimeSpan.Zero) break;
                    Thread.Sleep(25);
                }
                var identity = new MihomoRuntimeIdentity(process.Id, _binary, package.Digest);
                _process = process; _identity = identity;
                return identity;
            }
            catch
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
                try { process.WaitForExit(2000); } catch { }
                process.Dispose();
                throw;
            }
        }
    }

    internal bool IsExactProcessAlive(MihomoRuntimeIdentity identity)
    {
        lock (_gate)
        {
            if (_disposed || _process is null || _identity != identity) return false;
            try
            {
                return !_process.HasExited && _process.Id == identity.ProcessId &&
                    string.Equals(Path.GetFullPath(_process.MainModule?.FileName ?? string.Empty), identity.ImagePath, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }
    }

    internal void StopConfirmed(MihomoRuntimeIdentity identity, TimeSpan deadline)
    {
        if (deadline < TimeSpan.FromMilliseconds(250) || deadline > TimeSpan.FromSeconds(30))
            throw new InvalidDataException("BF-MIHOMO-TEARDOWN");
        lock (_gate)
        {
            if (_identity != identity || _process is null) return;
            var process = _process;
            try
            {
                if (!process.HasExited)
                {
                    try { process.Kill(entireProcessTree: true); } catch { }
                    if (!process.WaitForExit(Math.Max(1, checked((int)deadline.TotalMilliseconds))))
                    {
                        if (_job != IntPtr.Zero)
                        {
                            _ = CloseHandle(_job); _job = IntPtr.Zero;
                            try { process.WaitForExit(2000); } catch { }
                        }
                        if (!process.HasExited) throw new InvalidDataException("BF-MIHOMO-TEARDOWN");
                    }
                }
            }
            finally
            {
                if (process.HasExited)
                {
                    process.Dispose(); _process = null; _identity = null;
                }
            }
        }
    }

    private void PrepareRuntime(MihomoCompiledPackage package)
    {
        Directory.CreateDirectory(_runtimeRoot);
        RejectReparse(_runtimeRoot, directory: true);
        var config = Path.Combine(_runtimeRoot, "config.json");
        WriteAtomic(config, package.MainConfig);
        var providerRelative = ResolveProviderPath(package);
        if (providerRelative is not null)
        {
            var providerPath = Path.GetFullPath(Path.Combine(_runtimeRoot, providerRelative.Replace('/', Path.DirectorySeparatorChar)));
            if (!IsContained(_runtimeRoot, providerPath)) throw new InvalidDataException("BF-MIHOMO-PROVIDER");
            Directory.CreateDirectory(Path.GetDirectoryName(providerPath)!);
            RejectReparse(Path.GetDirectoryName(providerPath)!, directory: true);
            WriteAtomic(providerPath, package.Provider);
        }
        PrepareGeodata("GeoSite.dat");
        PrepareGeodata("geoip.metadb");
    }

    private void PrepareGeodata(string name)
    {
        var coreRoot = Path.GetDirectoryName(_binary) ?? throw new InvalidDataException("BF-INSTALL-LAYOUT");
        var manifestPath = Path.Combine(coreRoot, "CORE-MANIFEST.json");
        if (!File.Exists(manifestPath) || new FileInfo(manifestPath).Length is < 64 or > 64 * 1024)
            throw new InvalidDataException("BF-CORE-MANIFEST");
        RejectReparse(manifestPath, directory: false);
        // Release tooling may emit a UTF-8 BOM. JsonDocument's byte overload
        // deliberately rejects that marker, even though it is valid text at
        // the start of a JSON file. Read as UTF-8 text so both BOM and
        // BOM-less signed core manifests remain usable at runtime.
        using var manifest = JsonDocument.Parse(File.ReadAllText(manifestPath, new UTF8Encoding(false, true)), new JsonDocumentOptions
        {
            MaxDepth = 8,
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
        });
        if (manifest.RootElement.GetProperty("format").GetString() != "BIFROST-CORE-MANIFEST-2" ||
            !manifest.RootElement.TryGetProperty("artifacts", out var artifacts) || artifacts.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("BF-CORE-MANIFEST");
        var matches = artifacts.EnumerateArray().Where(item =>
            item.TryGetProperty("path", out var path) && string.Equals(path.GetString(), name, StringComparison.Ordinal)).ToArray();
        if (matches.Length != 1 || !matches[0].TryGetProperty("sha256", out var digestElement) ||
            !matches[0].TryGetProperty("bytes", out var bytesElement) || !bytesElement.TryGetInt64(out var expectedBytes) ||
            expectedBytes is < 1 or > 64 * 1024 * 1024)
            throw new InvalidDataException("BF-CORE-MANIFEST");
        var expected = digestElement.GetString() ?? string.Empty;
        if (!IsDigest(expected)) throw new InvalidDataException("BF-CORE-MANIFEST");
        var source = Path.Combine(coreRoot, name);
        if (!File.Exists(source) || new FileInfo(source).Length != expectedBytes) throw new InvalidDataException("BF-CORE-MISSING");
        ValidateFile(source, expected);
        var destination = Path.Combine(_runtimeRoot, name);
        if (File.Exists(destination))
        {
            try
            {
                if (new FileInfo(destination).Length == expectedBytes)
                {
                    ValidateFile(destination, expected);
                    return;
                }
            }
            catch (InvalidDataException) { }
        }
        CopyAtomic(source, destination);
        ValidateFile(destination, expected);
    }

    private static string? ResolveProviderPath(MihomoCompiledPackage package)
    {
        try
        {
            using var document = JsonDocument.Parse(package.MainConfig);
            if (!document.RootElement.TryGetProperty("proxy-providers", out var providers) ||
                !providers.TryGetProperty(package.ProviderName, out var provider) ||
                !provider.TryGetProperty("path", out var path) || path.ValueKind != JsonValueKind.String) return null;
            var value = path.GetString();
            if (string.IsNullOrWhiteSpace(value) || value.Contains("..", StringComparison.Ordinal) || Path.IsPathRooted(value))
                throw new InvalidDataException("BF-MIHOMO-PROVIDER");
            return value;
        }
        catch (JsonException) { throw new InvalidDataException("BF-MIHOMO-CONFIG"); }
    }

    private static void WriteAtomic(string path, byte[] bytes)
    {
        if (bytes.Length is < 2 or > 1024 * 1024) throw new InvalidDataException("BF-MIHOMO-CONFIG");
        var temp = path + "." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 16 * 1024, FileOptions.WriteThrough))
            {
                stream.Write(bytes); stream.Flush(true);
            }
            if (File.Exists(path)) File.Replace(temp, path, null, true);
            else File.Move(temp, path);
        }
        finally { try { if (File.Exists(temp)) File.Delete(temp); } catch { } }
    }

    private static void CopyAtomic(string source, string destination)
    {
        var temp = destination + "." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan))
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.WriteThrough))
            {
                input.CopyTo(output, 1024 * 1024);
                output.Flush(true);
            }
            if (File.Exists(destination)) File.Replace(temp, destination, null, true);
            else File.Move(temp, destination);
        }
        finally { try { if (File.Exists(temp)) File.Delete(temp); } catch { } }
    }

    private static void ValidateFile(string path, string expected)
    {
        if (!File.Exists(path)) throw new InvalidDataException("BF-CORE-MISSING");
        RejectReparse(path, directory: false);
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actual = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(actual), System.Text.Encoding.ASCII.GetBytes(expected)))
            throw new InvalidDataException("BF-CORE-HASH");
    }

    private static bool IsContained(string root, string target)
    {
        var prefix = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(target).StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static void RejectReparse(string path, bool directory)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 || directory != ((attributes & FileAttributes.Directory) != 0))
            throw new InvalidDataException("BF-INSTALL-LAYOUT");
    }

    private static bool IsDigest(string value) => value.Length == 64 && value.All(character =>
        character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(MihomoRuntimeSupervisor));
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            if (_process is { } process && _identity is { } identity)
            {
                try { StopConfirmed(identity, TimeSpan.FromSeconds(5)); } catch { }
            }
            if (_job != IntPtr.Zero) { _ = CloseHandle(_job); _job = IntPtr.Zero; }
            _disposed = true;
        }
    }

    private static IntPtr CreateKillOnCloseJob()
    {
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new InvalidDataException("BF-MIHOMO-JOB");
        var info = new JobObjectExtendedLimitInformation();
        info.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnClose;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, ref info,
                checked((uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>())))
        {
            _ = CloseHandle(job);
            throw new InvalidDataException("BF-MIHOMO-JOB");
        }
        return job;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref JobObjectExtendedLimitInformation information, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount;
        public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation; public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit; public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed;
    }
}
