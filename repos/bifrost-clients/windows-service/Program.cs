using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;
using Bifrost;

namespace Bifrost.ClientService;

public static class Program
{
    private const string PipeName = "BifrostClientService";
    private static readonly int MaxConcurrentIpcClients = Math.Clamp(Environment.ProcessorCount * 2, 8, 32);

    internal static void LiveTrace(string message) => LiveServiceTrace.Write(message);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint clientProcessId);

    private const uint TokenQuery = 0x0008;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr processHandle, uint flags, StringBuilder executablePath, ref uint size);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint sessionHandle, int sessionFlags, string sessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint sessionHandle, uint fileCount,
        [In] string[] fileNames, uint applicationCount, [In] RmUniqueProcess[]? applications,
        uint serviceCount, [In] string[]? serviceNames);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmGetList(uint sessionHandle, out uint processInfoNeeded,
        ref uint processInfoCount, [In, Out] RmProcessInfo[]? processInfo, ref uint rebootReasons);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint sessionHandle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JobObjectExtendedLimitInformation info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    private const int JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int ErrorMoreData = 234;

    [StructLayout(LayoutKind.Sequential)]
    private struct RmUniqueProcess
    {
        public uint ProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RmProcessInfo
    {
        public RmUniqueProcess Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string ApplicationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string ServiceShortName;
        public uint ApplicationType;
        public uint ApplicationStatus;
        public uint TerminalServicesSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool Restartable;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    internal static IntPtr CreateCoreKillOnCloseJob()
    {
        if (!OperatingSystem.IsWindows()) return IntPtr.Zero;
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new ServiceFailure("BF-CORE-JOB");
        var info = new JobObjectExtendedLimitInformation();
        info.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, ref info,
                checked((uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>())))
        {
            _ = CloseHandle(job);
            throw new ServiceFailure("BF-CORE-JOB");
        }
        return job;
    }

    internal static void AssignCoreToJob(IntPtr job, Process process)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (job == IntPtr.Zero || process.HasExited || !AssignProcessToJobObject(job, process.Handle))
            throw new ServiceFailure("BF-CORE-JOB");
    }

    internal static string? TryGetProcessImagePath(int processId)
    {
        if (!OperatingSystem.IsWindows() || processId <= 0) return null;
        var handle = IntPtr.Zero;
        try
        {
            handle = OpenProcess(ProcessQueryLimitedInformation, false, checked((uint)processId));
            if (handle == IntPtr.Zero) return null;
            var buffer = new StringBuilder(32768);
            var length = checked((uint)buffer.Capacity);
            if (!QueryFullProcessImageName(handle, 0, buffer, ref length) || length == 0) return null;
            return Path.GetFullPath(buffer.ToString(0, checked((int)length)));
        }
        catch { return null; }
        finally { if (handle != IntPtr.Zero) _ = CloseHandle(handle); }
    }

    internal static HashSet<int> GetLockingProcessIds(IEnumerable<string> fileNames)
    {
        var result = new HashSet<int>();
        if (!OperatingSystem.IsWindows()) return result;
        var resources = fileNames.Where(fileName => !string.IsNullOrWhiteSpace(fileName) && File.Exists(fileName))
            .Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (resources.Length == 0 || RmStartSession(out var session, 0, Guid.NewGuid().ToString("N")) != 0)
            return result;
        try
        {
            if (RmRegisterResources(session, checked((uint)resources.Length), resources, 0, null, 0, null) != 0)
                return result;
            uint count = 0;
            uint rebootReasons = 0;
            var query = RmGetList(session, out var needed, ref count, null, ref rebootReasons);
            if (query == 0 || query != ErrorMoreData || needed == 0) return result;
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var processes = new RmProcessInfo[needed];
                count = needed;
                query = RmGetList(session, out needed, ref count, processes, ref rebootReasons);
                if (query == ErrorMoreData && needed > count) continue;
                if (query != 0) return result;
                foreach (var process in processes.Take(checked((int)Math.Min(count, (uint)processes.Length))))
                    if (process.Process.ProcessId is > 0 and <= int.MaxValue)
                        result.Add(checked((int)process.Process.ProcessId));
                return result;
            }
            return result;
        }
        catch { return result; }
        finally { _ = RmEndSession(session); }
    }
    public static async Task Main(string[] args)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                WindowsServiceHost.Run(RunAsync);
                return;
            }
            await RunAsync(CancellationToken.None);
        }
        finally { await LiveServiceTrace.CompleteAsync(); }
    }

    private static async Task RunAsync(CancellationToken serviceCancellation)
    {
        using var shutdown = new CancellationTokenSource();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token, serviceCancellation);
        var cancellationToken = linked.Token;
        ConsoleCancelEventHandler cancelHandler = (_, e) =>
        {
            e.Cancel = true;
            try { shutdown.Cancel(); } catch (ObjectDisposedException) { }
        };
        EventHandler processExitHandler = (_, _) =>
        {
            try { shutdown.Cancel(); } catch (ObjectDisposedException) { }
        };
        Console.CancelKeyPress += cancelHandler;
        AppDomain.CurrentDomain.ProcessExit += processExitHandler;
        var runtime = new CoreRuntime(cleanupOrphanedPackagedCores: true);
        await runtime.ConfirmStartupOrphanRecoveryAsync(cancellationToken).ConfigureAwait(false);
        var healthMonitor = Task.Run(() => runtime.MonitorConnectionAsync(cancellationToken), CancellationToken.None);
        using var ipcSlots = new SemaphoreSlim(MaxConcurrentIpcClients, MaxConcurrentIpcClients);
        var activeClients = new List<Task>(MaxConcurrentIpcClients);
        var firstPipeInstance = true;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                LiveTrace("ipc-loop-wait-slot");
                await ipcSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
                LiveTrace("ipc-loop-slot-acquired");
                NamedPipeServerStream? pipe = null;
                try
                {
                    // The service may run as LocalSystem while the WPF process runs
                    // as the interactive user. CreatePipe applies the installer
                    // binding SID ACL; every command is authenticated again below.
                    // Keep one acceptor available while prior authenticated clients
                    // are still running so a long latency batch cannot monopolize
                    // the entire service control surface. CoreRuntime itself remains
                    // the serialization authority for tunnel state mutations.
                    LiveTrace($"ipc-create-start first={firstPipeInstance}");
                    pipe = CreatePipe(firstPipeInstance);
                    LiveTrace("ipc-create-end");
                    firstPipeInstance = false;
                    LiveTrace("ipc-wait-connection");
                    await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                    var connectedPipe = pipe;
                    pipe = null;
                    LiveTrace($"ipc-accepted active={activeClients.Count(task => !task.IsCompleted)}");
                    activeClients.RemoveAll(static task => task.IsCompleted);
                    activeClients.Add(HandleConnectedClientAsync(connectedPipe, runtime, ipcSlots, cancellationToken));
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    pipe?.Dispose();
                    ipcSlots.Release();
                    break;
                }
                catch (Exception error)
                {
                    LiveTrace($"ipc-loop-error type={error.GetType().Name} hresult={error.HResult}");
                    pipe?.Dispose();
                    ipcSlots.Release();
                    // A malformed frame, failed binding read, or a client that
                    // disconnects mid-command must not terminate the service.
                    // The next owned pipe instance is the recovery boundary.
                    if (!cancellationToken.IsCancellationRequested)
                        await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
            AppDomain.CurrentDomain.ProcessExit -= processExitHandler;
            shutdown.Cancel();
            runtime.CancelRecovery();
            try { await healthMonitor.ConfigureAwait(false); } catch (OperationCanceledException) { }
            try { await Task.WhenAll(activeClients).ConfigureAwait(false); }
            catch { /* per-client failures are already contained by HandleClientAsync */ }
            runtime.Disconnect();
        }
    }

    private static async Task HandleConnectedClientAsync(
        NamedPipeServerStream pipe,
        CoreRuntime runtime,
        SemaphoreSlim ipcSlots,
        CancellationToken cancellationToken)
    {
        LiveTrace("ipc-handler-start");
        try
        {
            await using (pipe.ConfigureAwait(false))
                await HandleClientAsync(pipe, runtime, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // HandleClientAsync already translates protocol/service failures to
            // bounded error frames. This final guard only protects the accept loop
            // against disposal or transport failures outside that boundary.
        }
        finally
        {
            LiveTrace("ipc-handler-end");
            ipcSlots.Release();
        }
    }

    private static async Task HandleClientAsync(Stream pipe, CoreRuntime runtime, CancellationToken cancellationToken)
    {
        IpcProtocol.Binding? binding = null;
        byte[]? challengeBytes = null;
        var localSystemClient = false;
        try
        {
            using var authenticationDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            authenticationDeadline.CancelAfter(IpcProtocol.OperationTimeout);
            var authenticationToken = authenticationDeadline.Token;
            binding = IpcProtocol.LoadBinding();
            if (OperatingSystem.IsWindows() && pipe is NamedPipeServerStream serverPipe)
            {
                var clientIdentity = ClassifyPipeClientIdentity(serverPipe, binding.Sid);
                if (clientIdentity == PipeClientIdentity.Rejected)
                    throw new ServiceFailure("BF-IPC-IDENTITY");
                localSystemClient = clientIdentity == PipeClientIdentity.LocalSystem;
            }

            challengeBytes = RandomNumberGenerator.GetBytes(32);
            var challengeText = Convert.ToBase64String(challengeBytes);
            var serverPid = Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var serverMac = IpcProtocol.Mac(binding.Secret, "server|" + challengeText + "|" + binding.Sid + "|" + serverPid);
            await IpcProtocol.WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(new
            {
                kind = "challenge", version = 1, nonce = challengeText, sid = binding.Sid, pid = serverPid, mac = serverMac
            }), authenticationToken);
            using var authDoc = await IpcProtocol.ReadJsonAsync(pipe, authenticationToken);
            if (!IpcProtocol.VerifyAuth(authDoc.RootElement, binding, challengeText, expectedCounter: 1))
                throw new ServiceFailure("BF-IPC-PROOF");
            using var envelope = await IpcProtocol.ReadJsonAsync(pipe, authenticationToken);
            if (!IpcProtocol.VerifyRequest(envelope.RootElement, binding, challengeText, expectedCounter: 2, out var line, out var requestOperationId))
                throw new ServiceFailure("BF-IPC-REPLAY");

            ServiceCommand command;
            try { command = IpcProtocol.ParseCommand(line); }
            catch (JsonException) { throw new ServiceFailure("BF-IPC-COMMAND-JSON"); }
            LiveTrace($"command-start action={command.Action}");
            // The signed installer promotes an update as LocalSystem and must
            // prove the candidate service's immutable release identity before
            // committing state/pointer ownership.  Permit that one authenticated
            // health command only after the ordinary secret/MAC handshake above.
            // LocalSystem never gains desktop control authority through this
            // exception: every other command remains bound to the enrolled
            // interactive SID and the existing executable-identity checks.
            if (localSystemClient && command.Action != "release_health")
                throw new ServiceFailure("BF-IPC-IDENTITY");
            if (command.Action is "stage_config" or "latency_batch" or "apply_update" && OperatingSystem.IsWindows())
            {
                if (pipe is not NamedPipeServerStream stagePipe || !IsTrustedStageClient(stagePipe))
                    throw new ServiceFailure("BF-IPC-IDENTITY");
            }
            using var commandDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            commandDeadline.CancelAfter(command.Action switch
            {
                "connect" => IpcProtocol.ConnectOperationTimeout,
                "latency_batch" => IpcProtocol.LatencyBatchOperationTimeout,
                _ => IpcProtocol.OperationTimeout,
            });
            if (command.Action == "latency_batch")
            {
                LiveTrace("latency-batch-handler-enter");
                var completed = 0;
                var total = command.Candidates?.Count ?? 0;
                using var batchCancellation = CancellationTokenSource.CreateLinkedTokenSource(commandDeadline.Token);
                using var cancelMonitorLifetime = CancellationTokenSource.CreateLinkedTokenSource(commandDeadline.Token);
                var cancelMonitor = MonitorLatencyBatchCancelAsync(
                    pipe, binding, challengeText, requestOperationId, batchCancellation, cancelMonitorLifetime.Token);
                try
                {
                    await runtime.MeasureLatencyBatchAsync(command, async frame =>
                    {
                        completed = Math.Max(completed, frame.Completed);
                        await IpcProtocol.WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(frame, JsonOptions), batchCancellation.Token).ConfigureAwait(false);
                    }, batchCancellation.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (batchCancellation.IsCancellationRequested &&
                    !commandDeadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    // The authenticated desktop explicitly cancelled the
                    // batch (or disconnected). The client already owns the
                    // visible terminal state, so no dead-pipe write is needed.
                    return;
                }
                catch (OperationCanceledException) when (commandDeadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    var frame = LatencyBatchFrame.Blocked("BF-IPC-TIMEOUT", completed, Math.Max(1, total));
                    await IpcProtocol.WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(frame, JsonOptions), cancellationToken).ConfigureAwait(false);
                }
                catch (ServiceFailure failure)
                {
                    var frame = LatencyBatchFrame.Blocked(failure.Code, completed, Math.Max(1, total));
                    await IpcProtocol.WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(frame, JsonOptions), cancellationToken).ConfigureAwait(false);
                }
                catch (Exception error)
                {
                    // A probe runtime can fail with transport, file or malformed
                    // controller data errors that are not ServiceFailure.  The
                    // latency IPC is a streaming protocol, so returning the
                    // ordinary service status envelope here makes the desktop
                    // misread a valid failure as BF-IPC-JSON.  Always finish the
                    // stream with its own terminal frame instead; the normal
                    // connection path remains available and can let Mihomo's
                    // URLTest group select a healthy candidate independently.
                    const string code = "BF-CANDIDATE-PROBE-FAILED";
                    LiveTrace($"latency-batch-failure code={code} type={error.GetType().Name}");
                    var frame = LatencyBatchFrame.Blocked(code, completed, Math.Max(1, total));
                    await IpcProtocol.WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(frame, JsonOptions), cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    cancelMonitorLifetime.Cancel();
                    try { await cancelMonitor.ConfigureAwait(false); }
                    catch (OperationCanceledException) when (cancelMonitorLifetime.IsCancellationRequested) { }
                    LiveTrace("latency-batch-handler-exit");
                }
                return;
            }
            object response = command.Action switch
            {
                "connect" => TraceConnect(runtime, command, commandDeadline.Token),
                "stage_config" => runtime.StageConfig(command),
                "disconnect" => TraceDisconnect(runtime),
                "status" => runtime.StatusForClient(),
                "release_health" => runtime.ReleaseHealth(),
                "apply_update" => SchedulePendingUpdate(),
                _ => throw new ServiceFailure("BF-SERVICE-COMMAND")
            };
            await IpcProtocol.WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions), commandDeadline.Token);
            LiveTrace($"command-end action={command.Action}");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (OperationCanceledException) { await TryWriteErrorAsync(pipe, "BF-IPC-TIMEOUT", cancellationToken); }
        catch (ServiceFailure failure) { await TryWriteErrorAsync(pipe, failure.Code, cancellationToken); }
        catch (JsonException) { await TryWriteErrorAsync(pipe, "BF-IPC-JSON", cancellationToken); }
        catch { await TryWriteErrorAsync(pipe, "BF-SERVICE-ERROR", cancellationToken); }
        finally
        {
            if (challengeBytes is not null) CryptographicOperations.ZeroMemory(challengeBytes);
            binding?.Dispose();
        }
    }

    private static ServiceStatus TraceConnect(CoreRuntime runtime, ServiceCommand command, CancellationToken cancellationToken)
    {
        LiveTrace("connect-dispatch-enter");
        try
        {
            return runtime.ConnectWithRecovery(command, cancellationToken);
        }
        finally { LiveTrace("connect-dispatch-exit"); }
    }

    private static ServiceStatus TraceDisconnect(CoreRuntime runtime)
    {
        LiveTrace("disconnect-dispatch-enter");
        try { return runtime.Disconnect(); }
        finally { LiveTrace("disconnect-dispatch-exit"); }
    }

    private static async Task MonitorLatencyBatchCancelAsync(
        Stream pipe,
        IpcProtocol.Binding binding,
        string challenge,
        string operationId,
        CancellationTokenSource batchCancellation,
        CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using var frame = await IpcProtocol.ReadJsonAsync(pipe, cancellationToken).ConfigureAwait(false);
                if (!IpcProtocol.VerifyCancel(frame.RootElement, binding, challenge, operationId, expectedCounter: 3))
                {
                    // An unexpected post-request frame is never authority to
                    // cancel work. Treat it as a broken control stream and
                    // fail closed rather than accepting an unauthenticated
                    // cancellation signal.
                    batchCancellation.Cancel();
                    return;
                }
                batchCancellation.Cancel();
                return;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch
        {
            // A vanished desktop must not leave six temporary probe cores
            // running until the batch deadline. Pipe failure is cancellation.
            try { batchCancellation.Cancel(); } catch (ObjectDisposedException) { }
        }
    }

    private static bool IsTrustedStageClient(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid) || clientPid == 0)
            return false;
        var processHandle = IntPtr.Zero;
        try
        {
            processHandle = OpenProcess(ProcessQueryLimitedInformation, false, clientPid);
            if (processHandle == IntPtr.Zero) return false;
            var buffer = new StringBuilder(32768);
            var length = checked((uint)buffer.Capacity);
            if (!QueryFullProcessImageName(processHandle, 0, buffer, ref length) || length == 0) return false;
            var actual = buffer.ToString(0, checked((int)length));
            var expected = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Bifrost.exe"));
            actual = Path.GetFullPath(actual);
            if (!IsPlainExecutable(actual) || !IsPlainExecutable(expected)) return false;

            // Installed clients normally execute the immutable companion beside
            // this service.  The separately published Windows payload is also a
            // supported launch surface, though, and is byte-for-byte identical
            // to that installed companion.  Trust the executable identity rather
            // than one physical path so the published client is not rejected by
            // stage_config/latency_batch merely because it was launched from the
            // signed release directory.  Any modified or unrelated process still
            // fails closed even though it runs as the bound interactive user.
            if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)) return true;
            return HaveSameSha256(actual, expected);
        }
        catch { return false; }
        finally { if (processHandle != IntPtr.Zero) _ = CloseHandle(processHandle); }
    }

    private static bool IsPlainExecutable(string path)
    {
        if (!File.Exists(path)) return false;
        var attrs = File.GetAttributes(path);
        return (attrs & (FileAttributes.ReparsePoint | FileAttributes.Directory)) == 0;
    }

    private static bool HaveSameSha256(string actual, string expected)
    {
        byte[]? actualHash = null;
        byte[]? expectedHash = null;
        try
        {
            using (var stream = new FileStream(actual, FileMode.Open, FileAccess.Read, FileShare.Read,
                       128 * 1024, FileOptions.SequentialScan))
                actualHash = SHA256.HashData(stream);
            using (var stream = new FileStream(expected, FileMode.Open, FileAccess.Read, FileShare.Read,
                       128 * 1024, FileOptions.SequentialScan))
                expectedHash = SHA256.HashData(stream);
            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
        finally
        {
            if (actualHash is not null) CryptographicOperations.ZeroMemory(actualHash);
            if (expectedHash is not null) CryptographicOperations.ZeroMemory(expectedHash);
        }
    }

    private enum PipeClientIdentity { Rejected, BoundInteractive, LocalSystem }

    private static PipeClientIdentity ClassifyPipeClientIdentity(NamedPipeServerStream pipe, string expectedSid)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid) || clientPid == 0)
            return PipeClientIdentity.Rejected;
        IntPtr tokenHandle = IntPtr.Zero;
        try
        {
            using var process = Process.GetProcessById(checked((int)clientPid));
            if (process.HasExited || !OpenProcessToken(process.Handle, TokenQuery, out tokenHandle) || tokenHandle == IntPtr.Zero)
                return PipeClientIdentity.Rejected;
            using var identity = new WindowsIdentity(tokenHandle);
            var actualSid = identity.User?.Value;
            if (string.Equals(actualSid, expectedSid, StringComparison.OrdinalIgnoreCase))
                return PipeClientIdentity.BoundInteractive;
            var localSystemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value;
            return string.Equals(actualSid, localSystemSid, StringComparison.OrdinalIgnoreCase)
                ? PipeClientIdentity.LocalSystem
                : PipeClientIdentity.Rejected;
        }
        catch { return PipeClientIdentity.Rejected; }
        finally
        {
            if (tokenHandle != IntPtr.Zero) _ = CloseHandle(tokenHandle);
        }
    }

    private static async Task TryWriteErrorAsync(Stream pipe, string code, CancellationToken cancellationToken)
    {
        try { await IpcProtocol.WriteFrameAsync(pipe, IpcProtocol.Error(code), cancellationToken); }
        catch { /* disconnected clients cannot receive an error */ }
    }

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    private static ServiceStatus SchedulePendingUpdate()
    {
        if (!OperatingSystem.IsWindows()) throw new ServiceFailure("BF-UPDATE-PLATFORM");
        string installRoot;
        try { installRoot = BifrostIpcWire.ResolveInstallRootFromGenerationDirectory(AppContext.BaseDirectory); }
        catch { throw new ServiceFailure("BF-UPDATE-STATE"); }
        var stateRoot = Path.Combine(installRoot, ".bifrost-state");
        var pointerPath = Path.Combine(stateRoot, "current.json");
        var pendingPath = Path.Combine(ServicePaths.ProgramDataRoot, "updates", "update-pending.json");
        try
        {
            ServicePaths.RejectReparse(installRoot, directory: true);
            ServicePaths.RejectReparse(stateRoot, directory: true);
            ServicePaths.RejectReparse(pointerPath, directory: false);
            ServicePaths.RejectReparse(Path.GetDirectoryName(pendingPath)!, directory: true);
            ServicePaths.RejectReparse(pendingPath, directory: false);
        }
        catch { throw new ServiceFailure("BF-UPDATE-STATE"); }

        var pointerBytes = BifrostIpcWire.ReadBoundedFile(pointerPath, 64 * 1024);
        string payloadRoot;
        try
        {
            using var pointer = BifrostIpcWire.ParseStrict(pointerBytes);
            var root = pointer.RootElement;
            if (!root.TryGetProperty("current_payload_root", out var payload) || payload.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(payload.GetString())) throw new ServiceFailure("BF-UPDATE-STATE");
            payloadRoot = Path.GetFullPath(payload.GetString()!);
        }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure("BF-UPDATE-STATE"); }
        finally { CryptographicOperations.ZeroMemory(pointerBytes); }

        if (!ServicePaths.IsContained(installRoot, payloadRoot)) throw new ServiceFailure("BF-UPDATE-STATE");
        try { ServicePaths.RejectReparse(payloadRoot, directory: true); }
        catch { throw new ServiceFailure("BF-UPDATE-STATE"); }
        var servicePath = Path.GetFullPath(Environment.ProcessPath ?? string.Empty);
        var expectedService = Path.GetFullPath(Path.Combine(payloadRoot, "BifrostClientService.exe"));
        if (!string.Equals(servicePath, expectedService, StringComparison.OrdinalIgnoreCase)) throw new ServiceFailure("BF-UPDATE-STATE");
        var installerPath = Path.Combine(payloadRoot, "BifrostSetup.exe");
        try { ServicePaths.RejectReparse(installerPath, directory: false); }
        catch { throw new ServiceFailure("BF-UPDATE-INSTALLER"); }

        var start = new ProcessStartInfo(installerPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = payloadRoot,
        };
        start.ArgumentList.Add("--apply-pending");
        start.ArgumentList.Add("--install-root");
        start.ArgumentList.Add(installRoot);
        // Do not acknowledge "update_scheduled" until Windows has actually
        // accepted the trusted installer process.  The previous delayed
        // fire-and-forget launch swallowed Process.Start failures, so the UI
        // could close and report an update in progress even though no updater
        // process existed.  Process.Start returns after process creation; the
        // installer performs its signed/pending verification before it reaches
        // the service transaction, leaving this IPC handler time to return the
        // authenticated acknowledgement without hiding launch failures.
        try
        {
            using var installer = Process.Start(start) ?? throw new ServiceFailure("BF-UPDATE-INSTALLER");
        }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure("BF-UPDATE-INSTALLER"); }
        return ServiceStatus.UpdateScheduled();
    }

    private static NamedPipeServerStream CreatePipe(bool firstInstance)
    {
        if (!OperatingSystem.IsWindows())
            return new NamedPipeServerStream(PipeName, PipeDirection.InOut, MaxConcurrentIpcClients, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var binding = IpcProtocol.LoadBinding();
        var security = new System.IO.Pipes.PipeSecurity();
        var user = new SecurityIdentifier(binding.Sid);
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        // The first pipe instance establishes the named-pipe object's DACL.
        // Client ReadWrite is intentionally insufficient to create a server
        // instance, while LocalSystem must retain CreateNewInstance authority
        // so the accept loop can keep a second authenticated control channel
        // available during long latency/connect operations. Without this rule
        // Windows accepts instance #1 and rejects every later CreatePipe with
        // ERROR_ACCESS_DENIED, effectively collapsing MaxConcurrentIpcClients
        // to one and making Disconnect impossible to preempt a long request.
        security.SetOwner(localSystem);
        security.AddAccessRule(new System.IO.Pipes.PipeAccessRule(localSystem, System.IO.Pipes.PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
        security.AddAccessRule(new System.IO.Pipes.PipeAccessRule(user, System.IO.Pipes.PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Allow));
        var options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return System.IO.Pipes.NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, MaxConcurrentIpcClients, PipeTransmissionMode.Byte, options, IpcProtocol.MaxFrameBytes, IpcProtocol.MaxFrameBytes, security);
    }
}

internal static class ServicePaths
{
    public static string ProgramDataRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost");
    public static string IpcRoot => Path.Combine(ProgramDataRoot, "ipc");
    public static string ConfigRoot => Path.Combine(ProgramDataRoot, "configs");

    public static bool IsOpaqueId(string? value, string? requiredPrefix = null)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length is < 8 or > 96) return false;
        if (requiredPrefix is not null && !value.StartsWith(requiredPrefix, StringComparison.Ordinal)) return false;
        return value.All(c => (c is >= 'a' and <= 'z') || (c is >= 'A' and <= 'Z') ||
                              (c is >= '0' and <= '9') || c is '_' or '-');
    }

    public static string Child(string root, string id)
    {
        if (!IsOpaqueId(id)) throw new ServiceFailure("BF-CONFIG-PACKAGE");
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var full = Path.GetFullPath(Path.Combine(fullRoot, id));
        if (!full.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new ServiceFailure("BF-CONFIG-PACKAGE");
        return full;
    }

    public static bool IsContained(string root, string path)
    {
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var full = Path.GetFullPath(path);
        return full.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    public static void RejectReparse(string path, bool directory)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
            throw new ServiceFailure("BF-CONFIG-PACKAGE");
        var attrs = File.GetAttributes(path);
        if ((attrs & FileAttributes.ReparsePoint) != 0 ||
            directory && (attrs & FileAttributes.Directory) == 0 ||
            !directory && (attrs & FileAttributes.Directory) != 0)
            throw new ServiceFailure("BF-CONFIG-PACKAGE");
    }
}

internal sealed class ServiceFailure : Exception
{
    public string Code { get; }
    public ServiceFailure(string code) : base(code) => Code = code;
}

internal sealed record ServiceCommand(
    string Action,
    string? Mode = null,
    string? Core = null,
    string? Source = null,
    string? Country = null,
    string? ConfigId = null,
    string? AppPolicy = null,
    string? AppPolicySnapshot = null,
    string? AppPolicyDigest = null,
    string? AppPolicyGeneration = null,
    string? ConnectionType = null,
    long ConfigVersion = 0,
    string? ConfigContentDigest = null,
    string? SignedConfigJson = null,
    string? SignedEnvelopeJson = null,
    string? ConfigKeyStateJson = null,
    string? SelectedCandidate = null,
    string? FrontSource = null,
    string? FrontCandidate = null,
    string? BootstrapProxyType = null,
    int? BootstrapProxyPort = null,
    IReadOnlyList<string>? Candidates = null);

/// <summary>
/// The service boundary is a bounded, authenticated framed protocol. Binding
/// material is provisioned under ProgramData by the installer and is never
/// derived from an environment variable or a client supplied path.
/// </summary>
internal static class IpcProtocol
{
    public const int MaxFrameBytes = 1536 * 1024;
    public const int MaxCommandBytes = 1024 * 1024;
    public static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(10);
    // Startup throughput qualification is capped at 45 seconds. Keep a wider
    // connect boundary for provider startup and the bounded cutover-recovery
    // path; this IPC timeout is a fail-safe, not the node-selection budget.
    public static readonly TimeSpan ConnectOperationTimeout = TimeSpan.FromSeconds(330);
    public static readonly TimeSpan LatencyOperationTimeout = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan LatencyBatchOperationTimeout = TimeSpan.FromSeconds(330);
    private const int SecretBytes = 32;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    internal sealed class Binding : IDisposable
    {
        private int _disposed;
        public Binding(byte[] secret, string sid) { Secret = secret; Sid = sid; }
        public byte[] Secret { get; }
        public string Sid { get; }
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                CryptographicOperations.ZeroMemory(Secret);
        }
    }

    public static Binding LoadBinding()
    {
        var root = ServicePaths.IpcRoot;
        ServicePaths.RejectReparse(root, directory: true);
        var secretPath = Path.Combine(root, "ipc-binding.bin");
        var sidPath = Path.Combine(root, "interactive.sid");
        ServicePaths.RejectReparse(secretPath, directory: false);
        ServicePaths.RejectReparse(sidPath, directory: false);
        var secret = BifrostIpcWire.ReadBoundedFile(secretPath, SecretBytes);
        try
        {
            if (secret.Length != SecretBytes) throw new ServiceFailure("BF-IPC-BINDING");
            var sidBytes = BifrostIpcWire.ReadBoundedFile(sidPath, 256);
            var sid = Encoding.ASCII.GetString(sidBytes).Trim();
            if (sidBytes.Any(b => b > 0x7f || b < 0x20 && b is not (byte)'\r' and not (byte)'\n'))
                throw new ServiceFailure("BF-IPC-BINDING");
            _ = new SecurityIdentifier(sid);
            return new Binding(secret, sid);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(secret);
            throw;
        }
    }

    public static string Mac(byte[] secret, string text)
    {
        if (secret.Length != SecretBytes) throw new ServiceFailure("BF-IPC-BINDING");
        return Convert.ToHexString(HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    }

    public static bool VerifyAuth(JsonElement root, Binding binding, string challenge, int expectedCounter)
    {
        if (!HasOnly(root, "kind", "version", "sid", "nonce", "counter", "mac") ||
            !TryString(root, "kind", 16, out var kind) || kind != "auth" ||
            !TryInt(root, "version", out var version) || version != 1 ||
            !TryString(root, "sid", 256, out var sid) ||
            !TryString(root, "nonce", 128, out var nonce) ||
            !TryInt(root, "counter", out var counter) || counter != expectedCounter ||
            !TryCanonicalMac(root, "mac", out var supplied) ||
            !string.Equals(sid, binding.Sid, StringComparison.Ordinal) ||
            !string.Equals(nonce, challenge, StringComparison.Ordinal))
            return false;
        return FixedMac(binding.Secret, $"auth|{challenge}|{binding.Sid}|{expectedCounter}", supplied);
    }

    public static bool VerifyRequest(JsonElement root, Binding binding, string challenge, int expectedCounter, out string body) =>
        VerifyRequest(root, binding, challenge, expectedCounter, out body, out _);

    public static bool VerifyRequest(JsonElement root, Binding binding, string challenge, int expectedCounter, out string body, out string operationId)
    {
        body = string.Empty;
        operationId = string.Empty;
        if (!HasOnly(root, "kind", "version", "nonce", "counter", "operation_id", "body", "body_sha256", "mac") ||
            !TryString(root, "kind", 16, out var kind) || kind != "request" ||
            !TryInt(root, "version", out var version) || version != 1 ||
            !TryString(root, "nonce", 128, out var nonce) ||
            !TryInt(root, "counter", out var counter) || counter != expectedCounter ||
            !TryString(root, "operation_id", 36, out operationId) ||
            !Guid.TryParseExact(operationId, "D", out var operationGuid) ||
            !string.Equals(operationId, operationGuid.ToString("D"), StringComparison.Ordinal) ||
            !TryString(root, "body", MaxCommandBytes, out body) ||
            !TryCanonicalHash(root, "body_sha256", out var digest) ||
            !TryCanonicalMac(root, "mac", out var supplied) ||
            !string.Equals(nonce, challenge, StringComparison.Ordinal))
            return false;
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        try
        {
            var actualDigest = Convert.ToHexString(SHA256.HashData(bodyBytes)).ToLowerInvariant();
            if (!string.Equals(actualDigest, digest, StringComparison.Ordinal)) return false;
            return FixedMac(binding.Secret, $"request|{challenge}|{operationId}|{expectedCounter}|{digest}", supplied);
        }
        finally { CryptographicOperations.ZeroMemory(bodyBytes); }
    }

    public static bool VerifyCancel(JsonElement root, Binding binding, string challenge, string operationId, int expectedCounter)
    {
        if (!HasOnly(root, "kind", "version", "nonce", "counter", "operation_id", "mac") ||
            !TryString(root, "kind", 16, out var kind) || kind != "cancel" ||
            !TryInt(root, "version", out var version) || version != 1 ||
            !TryString(root, "nonce", 128, out var nonce) || !string.Equals(nonce, challenge, StringComparison.Ordinal) ||
            !TryInt(root, "counter", out var counter) || counter != expectedCounter ||
            !TryString(root, "operation_id", 36, out var suppliedOperationId) || !string.Equals(suppliedOperationId, operationId, StringComparison.Ordinal) ||
            !Guid.TryParseExact(suppliedOperationId, "D", out var operationGuid) ||
            !string.Equals(suppliedOperationId, operationGuid.ToString("D"), StringComparison.Ordinal) ||
            !TryCanonicalMac(root, "mac", out var supplied))
            return false;
        return FixedMac(binding.Secret, $"cancel|{challenge}|{operationId}|{expectedCounter}", supplied);
    }

    public static ServiceCommand ParseCommand(string body)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        try
        {
            if (bytes.Length is <= 0 or > MaxCommandBytes) throw new ServiceFailure("BF-SERVICE-COMMAND");
            using var document = ParseStrict(bytes);
            var root = document.RootElement;
            if (!TryString(root, "action", 32, out var action)) throw new ServiceFailure("BF-SERVICE-COMMAND");
            return action switch
            {
                "connect" => ParseConnect(root),
                "stage_config" => ParseStage(root),
                "latency_batch" => ParseLatencyBatch(root),
                "disconnect" when HasOnly(root, "action") => new ServiceCommand(action),
                "status" when HasOnly(root, "action") => new ServiceCommand(action),
                "release_health" when HasOnly(root, "action") => new ServiceCommand(action),
                "apply_update" when HasOnly(root, "action") => new ServiceCommand(action),
                _ => throw new ServiceFailure("BF-SERVICE-COMMAND")
            };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static ServiceCommand ParseConnect(JsonElement root)
    {
        if (!HasOnly(root, "action", "mode", "connection_type", "core", "source", "country", "config_id", "app_policy", "app_policy_snapshot", "app_policy_digest", "app_policy_generation") ||
            !TryString(root, "mode", 16, out var mode) ||
            !TryString(root, "connection_type", 32, out var connectionType) ||
            !TryString(root, "core", 16, out var core) ||
            !TryToken(root, "source", out var source) ||
            !TryToken(root, "country", out var country) ||
            !TryNullableToken(root, "config_id", out var configId) ||
            !TryString(root, "app_policy", 16, out var appPolicy) ||
            !TryString(root, "app_policy_snapshot", ApplicationPolicySnapshot.MaxJsonBytes, out var appPolicySnapshot) ||
            !TryString(root, "app_policy_digest", 64, out var appPolicyDigest) ||
            !TryString(root, "app_policy_generation", 32, out var appPolicyGeneration) ||
            mode is not ("smart" or "global" or "per-app") ||
            core is not ("auto" or "mihomo") ||
            source == "auto" || appPolicy is not ("none" or "allow" or "exclude") || !ServicePaths.IsOpaqueId(configId, "cfg_") ||
            !IsCanonicalHash(appPolicyDigest, 64) || !IsCanonicalHash(appPolicyGeneration, 32))
        {
            // A null config_id is not a valid connection: the service must
            // never compile or read a path supplied by the UI.
            throw new ServiceFailure("BF-CONFIG-PACKAGE");
        }
        try
        {
            var snapshot = ApplicationPolicySnapshot.Parse(appPolicySnapshot);
            if (snapshot.RouteMode != mode || snapshot.PolicyMode != appPolicy ||
                !string.Equals(snapshot.Digest, appPolicyDigest, StringComparison.Ordinal) ||
                !string.Equals(snapshot.Generation, appPolicyGeneration, StringComparison.Ordinal))
                throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT");
        }
        catch (ApplicationPolicyFailure failure) { throw new ServiceFailure(failure.Code); }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT"); }
        if (!((connectionType == "direct-vmess" && mode is "smart" or "global" or "per-app") ||
              (connectionType == "smartgate" && mode is "smart" or "per-app")))
            throw new ServiceFailure("BF-CONNECTION-TYPE");
        if (connectionType == "direct-vmess" && country != "default" ||
            connectionType == "smartgate" && country == "default")
            throw new ServiceFailure("BF-CONNECTION-TYPE");
        return new ServiceCommand("connect", mode, core, source, country, configId, appPolicy,
            appPolicySnapshot, appPolicyDigest, appPolicyGeneration, ConnectionType: connectionType);
    }

    private static ServiceCommand ParseStage(JsonElement root)
    {
        if (!HasOnly(root, "action", "mode", "connection_type", "core", "source", "country", "app_policy_snapshot", "app_policy_digest", "app_policy_generation", "config_version", "config_content_digest", "signed_config_json", "signed_envelope_json", "config_key_state_json", "selected_candidate", "front_source", "front_candidate", "bootstrap_proxy_type", "bootstrap_proxy_port") ||
            !TryString(root, "mode", 16, out var mode) ||
            !TryString(root, "connection_type", 32, out var connectionType) ||
            !TryString(root, "core", 16, out var core) ||
            !TryToken(root, "source", out var source) || source == "auto" ||
            !TryToken(root, "country", out var country) ||
            !TryString(root, "app_policy_snapshot", ApplicationPolicySnapshot.MaxJsonBytes, out var appPolicySnapshot) ||
            !TryCanonicalHash(root, "app_policy_digest", out var appPolicyDigest) ||
            !TryString(root, "app_policy_generation", 32, out var appPolicyGeneration) || !IsCanonicalHash(appPolicyGeneration, 32) ||
            !TryInt64(root, "config_version", out var configVersion) || configVersion <= 0 ||
            !TryCanonicalHash(root, "config_content_digest", out var configContentDigest) ||
            !TryString(root, "signed_config_json", SignedClientPackageImporter.MaxSignedConfigBytes, out var signedConfigJson) ||
            !TryString(root, "signed_envelope_json", SignedClientPackageImporter.MaxSignedEnvelopeBytes, out var signedEnvelopeJson) ||
            !TryNullableString(root, "config_key_state_json", 64 * 1024, out var configKeyStateJson) ||
            !TryToken(root, "selected_candidate", out var selectedCandidate) ||
            !TryNullableToken(root, "front_source", out var frontSource) ||
            !TryNullableToken(root, "front_candidate", out var frontCandidate) ||
            !TryNullableString(root, "bootstrap_proxy_type", 32, out var bootstrapProxyType) ||
            !TryNullableInt(root, "bootstrap_proxy_port", out var bootstrapProxyPort) ||
            mode is not ("smart" or "global" or "per-app") || core is not ("auto" or "mihomo") ||
            !((connectionType == "direct-vmess" && mode is "smart" or "global" or "per-app") ||
              (connectionType == "smartgate" && mode is "smart" or "per-app")))
            throw new ServiceFailure("BF-CONFIG-PACKAGE");
        if ((bootstrapProxyType is null) != (bootstrapProxyPort is null) ||
            bootstrapProxyType is not null && (bootstrapProxyType is not ("http-connect" or "socks5") || bootstrapProxyPort is < 1 or > 65535 || bootstrapProxyPort is >= 19000 and <= 49151))
            throw new ServiceFailure("BF-TRANSPORT-UPSTREAM");
        if (connectionType == "direct-vmess" && (country != "default" || frontSource is not null || frontCandidate is not null) ||
            connectionType == "smartgate" && country == "default")
            throw new ServiceFailure("BF-CONNECTION-TYPE");
        try
        {
            var snapshot = ApplicationPolicySnapshot.Parse(appPolicySnapshot);
            if (snapshot.RouteMode != mode || !string.Equals(snapshot.Digest, appPolicyDigest, StringComparison.Ordinal) ||
                !string.Equals(snapshot.Generation, appPolicyGeneration, StringComparison.Ordinal))
                throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT");
        }
        catch (ApplicationPolicyFailure failure) { throw new ServiceFailure(failure.Code); }
        return new ServiceCommand("stage_config", mode, core, source, country,
            AppPolicySnapshot: appPolicySnapshot, AppPolicyDigest: appPolicyDigest,
            AppPolicyGeneration: appPolicyGeneration, ConnectionType: connectionType,
            ConfigVersion: configVersion, ConfigContentDigest: configContentDigest,
            SignedConfigJson: signedConfigJson, SignedEnvelopeJson: signedEnvelopeJson,
            ConfigKeyStateJson: configKeyStateJson, SelectedCandidate: selectedCandidate,
            FrontSource: frontSource, FrontCandidate: frontCandidate,
            BootstrapProxyType: bootstrapProxyType, BootstrapProxyPort: bootstrapProxyPort);
    }

    private static ServiceCommand ParseLatencyBatch(JsonElement root)
    {
        if (!HasOnly(root, "action", "mode", "connection_type", "core", "source", "country",
                "app_policy_snapshot", "app_policy_digest", "app_policy_generation", "config_version",
                "config_content_digest", "signed_config_json", "signed_envelope_json", "config_key_state_json", "candidates") ||
            !TryString(root, "mode", 16, out var mode) || mode != "global" ||
            !TryString(root, "connection_type", 32, out var connectionType) || connectionType != "direct-vmess" ||
            !TryString(root, "core", 16, out var core) || core is not ("auto" or "mihomo") ||
            !TryToken(root, "source", out var source) || source == "auto" ||
            !TryToken(root, "country", out var country) || country != "default" ||
            !TryString(root, "app_policy_snapshot", ApplicationPolicySnapshot.MaxJsonBytes, out var snapshotJson) ||
            !TryCanonicalHash(root, "app_policy_digest", out var digest) ||
            !TryString(root, "app_policy_generation", 32, out var generation) || !IsCanonicalHash(generation, 32) ||
            !TryInt64(root, "config_version", out var configVersion) || configVersion <= 0 ||
            !TryCanonicalHash(root, "config_content_digest", out var configContentDigest) ||
            !TryString(root, "signed_config_json", SignedClientPackageImporter.MaxSignedConfigBytes, out var signedConfigJson) ||
            !TryString(root, "signed_envelope_json", SignedClientPackageImporter.MaxSignedEnvelopeBytes, out var signedEnvelopeJson) ||
            !TryNullableString(root, "config_key_state_json", 64 * 1024, out var configKeyStateJson) ||
            !TryTokenArray(root, "candidates", 600, out var candidates))
            throw new ServiceFailure("BF-LATENCY-CONFIG");
        try
        {
            var snapshot = ApplicationPolicySnapshot.Parse(snapshotJson);
            if (snapshot.RouteMode != "global" || snapshot.PolicyMode != "none" || snapshot.Identities.Count != 0 ||
                !string.Equals(snapshot.Digest, digest, StringComparison.Ordinal) ||
                !string.Equals(snapshot.Generation, generation, StringComparison.Ordinal))
                throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT");
        }
        catch (ApplicationPolicyFailure failure) { throw new ServiceFailure(failure.Code); }
        return new ServiceCommand("latency_batch", mode, core, source, country,
            AppPolicySnapshot: snapshotJson, AppPolicyDigest: digest, AppPolicyGeneration: generation,
            ConnectionType: connectionType, ConfigVersion: configVersion, ConfigContentDigest: configContentDigest,
            SignedConfigJson: signedConfigJson, SignedEnvelopeJson: signedEnvelopeJson,
            ConfigKeyStateJson: configKeyStateJson, Candidates: candidates);
    }

    private static bool HasOnly(JsonElement root, params string[] names)
    {
        if (root.ValueKind != JsonValueKind.Object) return false;
        var expected = new HashSet<string>(names, StringComparer.Ordinal);
        return root.EnumerateObject().All(property => expected.Contains(property.Name)) &&
               root.EnumerateObject().Count() == expected.Count;
    }

    private static bool TryString(JsonElement root, string name, int max, out string value)
    {
        value = string.Empty;
        if (!root.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
            return false;
        var candidate = element.GetString();
        if (candidate is null || candidate.Length == 0 || candidate.Length > max || candidate.Any(char.IsControl))
            return false;
        value = candidate;
        return true;
    }

    private static bool TryInt64(JsonElement root, string name, out long value)
    {
        value = 0;
        return root.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out value);
    }

    private static bool IsBase64Url(string value)
    {
        if (value.Length is < 16 or > 512 || value.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '='))) return false;
        try { _ = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '=')); return true; }
        catch (FormatException) { return false; }
    }

    private static bool TryToken(JsonElement root, string name, out string value)
    {
        if (!TryString(root, name, 96, out value)) return false;
        return value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.');
    }

    private static bool TryNullableToken(JsonElement root, string name, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var element)) return false;
        if (element.ValueKind == JsonValueKind.Null) return true;
        if (!TryString(root, name, 96, out var text)) return false;
        value = text;
        return true;
    }

    private static bool TryNullableString(JsonElement root, string name, int max, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var element)) return false;
        if (element.ValueKind == JsonValueKind.Null) return true;
        if (element.ValueKind != JsonValueKind.String) return false;
        var candidate = element.GetString();
        if (candidate is null || candidate.Length == 0 || candidate.Length > max || candidate.Any(char.IsControl)) return false;
        value = candidate;
        return true;
    }

    private static bool TryTokenArray(JsonElement root, string name, int maxCount, out IReadOnlyList<string> values)
    {
        values = Array.Empty<string>();
        if (!root.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.Array ||
            element.GetArrayLength() is < 1 || element.GetArrayLength() > maxCount) return false;
        var result = new List<string>(element.GetArrayLength());
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) return false;
            var value = item.GetString();
            if (string.IsNullOrWhiteSpace(value) || value.Length > 96 ||
                value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.')) ||
                !unique.Add(value)) return false;
            result.Add(value);
        }
        values = result;
        return true;
    }

    private static bool TryInt(JsonElement root, string name, out int value)
    {
        value = 0;
        return root.TryGetProperty(name, out var element) &&
               element.ValueKind == JsonValueKind.Number &&
               element.TryGetInt32(out value);
    }

    private static bool TryNullableInt(JsonElement root, string name, out int? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var element)) return false;
        if (element.ValueKind == JsonValueKind.Null) return true;
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetInt32(out var integer)) return false;
        value = integer;
        return true;
    }

    private static bool TryCanonicalMac(JsonElement root, string name, out string value) =>
        TryCanonicalHex(root, name, 64, out value);

    private static bool TryCanonicalHash(JsonElement root, string name, out string value) =>
        TryCanonicalHex(root, name, 64, out value);

    private static bool TryCanonicalHex(JsonElement root, string name, int length, out string value)
    {
        value = string.Empty;
        if (!TryString(root, name, length, out var candidate) || candidate.Length != length)
            return false;
        if (candidate.Any(c => !((c is >= '0' and <= '9') || (c is >= 'a' and <= 'f'))))
            return false;
        value = candidate;
        return true;
    }

    private static bool IsCanonicalHash(string value, int length) =>
        value.Length == length && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool FixedMac(byte[] secret, string text, string supplied)
    {
        var expected = Encoding.ASCII.GetBytes(Mac(secret, text));
        var actual = Encoding.ASCII.GetBytes(supplied);
        try { return CryptographicOperations.FixedTimeEquals(expected, actual); }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    public static byte[] Error(string code) =>
        // Every error uses the same typed status DTO.  Explicit nulls keep the
        // client parser from mistaking a service failure for malformed JSON.
        JsonSerializer.SerializeToUtf8Bytes(ServiceStatus.Blocked(code), JsonOptions);

    public static async Task<JsonDocument> ReadJsonAsync(Stream stream, CancellationToken cancellationToken)
        => await BifrostIpcWire.ReadJsonAsync(stream, cancellationToken).ConfigureAwait(false);

    public static JsonDocument ParseStrict(byte[] bytes)
    {
        ValidateJson(bytes);
        return JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false
        });
    }

    private static void ValidateJson(ReadOnlySpan<byte> bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions
        {
            MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false
        });
        var containers = new Stack<HashSet<string>?>();
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    containers.Push(new HashSet<string>(StringComparer.Ordinal));
                    break;
                case JsonTokenType.StartArray:
                    containers.Push(null);
                    break;
                case JsonTokenType.PropertyName:
                    if (containers.Count == 0 || containers.Peek() is null ||
                        !containers.Peek()!.Add(reader.GetString() ?? throw new JsonException()))
                        throw new JsonException("duplicate JSON property");
                    break;
                case JsonTokenType.EndObject:
                case JsonTokenType.EndArray:
                    if (containers.Count == 0) throw new JsonException("invalid JSON nesting");
                    containers.Pop();
                    break;
            }
        }
        if (containers.Count != 0 || reader.BytesConsumed != bytes.Length)
            throw new JsonException("invalid JSON");
    }

    public static async Task<byte[]> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
        => await BifrostIpcWire.ReadFrameAsync(stream, cancellationToken).ConfigureAwait(false);

    public static async Task WriteFrameAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
        => await BifrostIpcWire.WriteFrameAsync(stream, payload, cancellationToken).ConfigureAwait(false);

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
    }
}

/// <summary>
/// Minimal native SCM host.  The service is still runnable as a console
/// process for isolated tests, but an installed release enters the Windows
/// service dispatcher and reports real START_PENDING/RUNNING/STOP_PENDING/
/// STOPPED states.  This avoids pretending that a console loop is an SCM
/// service and keeps the updater able to stop and health-check it safely.
internal static class WindowsServiceHost
{
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceAcceptStop = 0x00000001;
    private const uint ServiceAcceptShutdown = 0x00000004;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceControlShutdown = 0x00000005;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceStopped = 0x00000001;
    private const int ErrorFailedServiceControllerConnect = 1063;
    private static readonly string ServiceName = "BifrostClientService";
    private static ServiceMainDelegate? _serviceMain;
    private static HandlerExDelegate? _handler;
    private static IntPtr _statusHandle;
    private static CancellationTokenSource? _stop;
    private static Func<CancellationToken, Task>? _run;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        public string? ServiceName;
        public ServiceMainDelegate? ServiceProc;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainDelegate(uint argc, IntPtr argv);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint HandlerExDelegate(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] table);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, HandlerExDelegate handler, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetServiceStatus(IntPtr serviceStatusHandle, ref ServiceStatus status);

    public static void Run(Func<CancellationToken, Task> run)
    {
        _run = run;
        _stop = new CancellationTokenSource();
        _serviceMain = ServiceMain;
        _handler = ServiceControlHandler;
        var table = new[]
        {
            new ServiceTableEntry { ServiceName = ServiceName, ServiceProc = _serviceMain },
            new ServiceTableEntry()
        };
        if (StartServiceCtrlDispatcher(table)) return;
        var error = Marshal.GetLastWin32Error();
        // A Windows release is an SCM service.  Do not silently become a
        // console pipe server when launched by a user or a fake executable.
        if (error == ErrorFailedServiceControllerConnect) throw new InvalidOperationException("BF-SERVICE-SCM");
        throw new InvalidOperationException($"StartServiceCtrlDispatcher failed: {error}");
    }

    private static void ServiceMain(uint argc, IntPtr argv)
    {
        if (_handler is null || _stop is null || _run is null) return;
        _statusHandle = RegisterServiceCtrlHandlerEx(ServiceName, _handler, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero) return;
        SetStatus(ServiceStartPending, ServiceAcceptStop | ServiceAcceptShutdown, 1, 30_000);
        try
        {
            SetStatus(ServiceRunning, ServiceAcceptStop | ServiceAcceptShutdown, 0, 0);
            _run(_stop.Token).GetAwaiter().GetResult();
            SetStatus(ServiceStopped, 0, 0, 0);
        }
        catch
        {
            SetStatus(ServiceStopped, 0, 1, 0);
        }
    }

    private static uint ServiceControlHandler(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control is ServiceControlStop or ServiceControlShutdown)
        {
            SetStatus(ServiceStopPending, 0, 1, 30_000);
            _stop?.Cancel();
        }
        return 0;
    }

    private static void SetStatus(uint state, uint accepted, uint exitCode, uint waitHint)
    {
        if (_statusHandle == IntPtr.Zero) return;
        var status = new ServiceStatus
        {
            ServiceType = ServiceWin32OwnProcess,
            CurrentState = state,
            ControlsAccepted = accepted,
            Win32ExitCode = exitCode,
            ServiceSpecificExitCode = 0,
            CheckPoint = state is ServiceStartPending or ServiceStopPending ? 1u : 0u,
            WaitHint = waitHint
        };
        SetServiceStatus(_statusHandle, ref status);
    }
}

internal sealed class CoreRuntime
{
    private static readonly TimeSpan DataPlaneProbeTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan SteadyStateDataPlaneProbeTimeout = DataPlaneHealthPolicy.EndpointTimeout;
    // A cold selected VMess/WSS path can complete Mihomo's provider health
    // check yet still need more than three seconds for the first host-originated
    // TLS exchange through the route-neutral TUN.  Use the same bounded startup
    // budget as the loopback data-plane proof so a slow healthy winner is not
    // misclassified as dead during make-before-break cutover.
    private static readonly TimeSpan CutoverDataPlaneProbeTimeout = TimeSpan.FromSeconds(12);
    private const int CutoverDataPlaneProbeAttempts = 2;
    // A complete SmartGate cohort can take slightly more than twenty seconds
    // to publish the first health result (35 chained candidates, each with a
    // real TLS probe).  Cutting the round off at twenty seconds made a healthy
    // provider fail according to scheduler timing.  Keep this at the client
    // controller's bounded maximum rather than treating startup as dead early.
    private static readonly TimeSpan StartupProviderMeasurementTimeout = TimeSpan.FromSeconds(30);
    // A fresh file provider is not populated merely because /version is
    // ready.  Real source-A controller measurements show the official health
    // endpoint completes in about 2.5-2.7 seconds and leaves URLTest with a
    // usable winner before it returns.  Keep only a bounded post-health
    // publication margin instead of polling provider/group state while Mihomo
    // is still committing the health round.
    private static readonly TimeSpan StartupGroupSelectionTimeout = TimeSpan.FromSeconds(5);
    // Windows TUN/PnP creation can be slower than provider selection.  Start
    // observing the exact reserved interface as soon as the controller is
    // ready so PnP initialization overlaps provider health rather than being
    // paid serially after a winner is known.
    private static readonly TimeSpan StartupTunReadyTimeout = TimeSpan.FromSeconds(22);
    private static readonly TimeSpan DataPlaneProbeInterval = TimeSpan.FromSeconds(15);
    // Healthy connections use one small request per fifteen seconds. Once a
    // real 204 probe misses, do not wait another full cadence before deciding
    // whether the path is merely jittery or actually blocked: the protected UI
    // already asks for status every second, so use that opportunity for a
    // bounded confirmation probe.
    private static readonly TimeSpan DataPlaneFailureRetryInterval = TimeSpan.FromSeconds(1);
    // Startup validation runs through the selected proxy graph before the TUN
    // owns host routing.  Real TLS establishment through chained/bootstrap
    // proxies can legitimately take several seconds even after the RTT probe
    // has succeeded, so keep enough budget to distinguish a slow usable path
    // from a dead one without falling back to the 15-second steady-state cap.
    private static readonly TimeSpan StartupDataPlaneProbeTimeout = TimeSpan.FromSeconds(12);
    // Do not hide a blocked foreign path behind the provider's 30-second
    // background health interval. Three independent application-level misses
    // are enough for soft protocol jitter; hard reachability failures (or an
    // independently unhealthy selected candidate) use two. The UI can then
    // run its existing reconnect/failover path instead of showing Connected
    // for tens of seconds while ordinary foreign traffic is already dead.
    private const int DataPlaneFailureThreshold = 3;
    private const int DataPlaneFastFailureThreshold = 2;
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (long Length, long LastWriteTicks)> VerifiedCoreArtifacts = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HttpClient LoopbackHealthClient = new(new SocketsHttpHandler
    {
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromMilliseconds(500),
        PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
        MaxConnectionsPerServer = Math.Clamp(Environment.ProcessorCount, 4, 16),
    })
    {
        Timeout = TimeSpan.FromSeconds(1),
    };
    private readonly object _sync = new();
    private readonly object _latencyBatchSync = new();
    private readonly object _connectCancellationSync = new();
    private readonly INetworkBoundary _networkBoundary;
    private readonly Func<bool> _ensureOwnedTunInactive;
    private readonly NetworkBoundaryStateMachine _boundaryState = new();
    private readonly IntPtr _coreJob;
    private Process? _core;
    private Process? _transport;
    private MihomoRuntimeSupervisor? _mihomoSupervisor;
    private MihomoRuntimeIdentity? _mihomoIdentity;
    private MihomoControllerClient? _mihomoController;
    private MihomoQualityOptimizer? _mihomoQualityOptimizer;
    private readonly MihomoConnectionMemory _connectionMemory = new(Path.Combine(ServicePaths.ConfigRoot, ".last-working-candidates.json"));
    private MihomoGroupState? _mihomoGroup;
    private string? _mihomoChatGptGroupName;
    private string? _mihomoChatGptCandidate;
    private string? _mihomoProviderName;
    private IReadOnlySet<string>? _mihomoAllowedCandidates;
    private string? _mihomoFixedCandidate;
    private int _mihomoTunInterfaceIndex;
    private DateTime _lastMihomoReadbackAt = DateTime.MinValue;
    private WindowsRouteHandover? _mihomoHandover;
    private OwnedTunDns? _mihomoDns;
    private string? _coreName;
    private string? _mode;
    private string? _configId;
    private string? _source;
    private string? _country;
    private string? _appPolicy;
    private string? _appPolicyDigest;
    private string? _appPolicyGeneration;
    private string? _effectiveCore;
    private Uri? _healthEndpoint;
    private DataPlaneProbeTarget? _dataPlaneProbe;
    private DateTime _lastDataPlaneProbeAt = DateTime.MinValue;
    private bool _lastDataPlaneProbeHealthy;
    private string? _lastDataPlaneProbeCode;
    private int _consecutiveDataPlaneProbeFailures;
    private int _preferredDataPlaneTarget;
    private long _dataPlaneFailureStartedAt;
    private bool _selectedCandidateTransientUnhealthy;
    private bool _coexistMode;
    private OwnedTunRouteCommit? _coexistRoutes;
    private IPAddress? _coexistCanaryAddress;
    private DateTime _lastCoreTeardownAt = DateTime.MinValue;
    private NetworkBoundaryIntent? _boundaryIntent;
    private EnforcementSummary? _enforcementSummary;
    private ApplicationPolicySnapshot? _applicationPolicySnapshot;
    private ControlledRuntimeCoordinator? _controlledRuntime;
    private IControlledCoreAdapter? _testControlledCore;
    private IControlledNetworkBoundary? _testControlledBoundary;
    private CancellationTokenSource? _latencyBatchCancellation;
    private CancellationTokenSource? _connectCancellation;
    private readonly RuntimeConnectionRecovery _connectionRecovery = new();
    private readonly RuntimeStatusSnapshot _statusSnapshot = new();
    private string? _lastRuntimeFailure;
    private string? _lastRuntimeDiagnostic;

    internal void CancelRecovery() => _connectionRecovery.Cancel();

    internal async Task MonitorConnectionAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            try { _connectionRecovery.Tick(Status, cancellationToken); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return; }
            catch { Program.LiveTrace("runtime-health-monitor-read-failed"); }
        }
    }

    internal ServiceStatus ConnectWithRecovery(ServiceCommand command, CancellationToken cancellationToken)
    {
        var revision = _connectionRecovery.CancellationRevision;
        lock (_sync)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // A queued request must not revive a session after Disconnect.
            if (revision != _connectionRecovery.CancellationRevision) return ServiceStatus.Disconnected();
            if (_controlledRuntime is not null && _controlledRuntime.State.Phase != ControlledRuntimePhase.Idle)
            {
                // Connect validates exact policy/package identity and permits
                // an idempotent readback. A rejected request owns neither the
                // existing session's recovery intent nor its published state.
                var existing = Connect(command.Mode!, command.Core!, command.Source!, command.Country!, command.ConfigId,
                    command.AppPolicy!, command.AppPolicySnapshot!, command.AppPolicyDigest!, command.AppPolicyGeneration!,
                    command.ConnectionType!, cancellationToken);
                if (existing.Ok && existing.Connected) _statusSnapshot.Publish(existing);
                return existing;
            }
            return ConnectWithRecoveryLocked(command, cancellationToken, revision);
        }
    }

    private ServiceStatus ConnectWithRecoveryLocked(ServiceCommand command, CancellationToken cancellationToken, long revision)
    {
        // Capture only the accepted connection fields; replay always resolves
        // the same signed staged package and revalidates its policy/expiry.
        RuntimeConnectionRecovery.Intent? intent = null;
        intent = _connectionRecovery.TryBegin(revision, token =>
        {
            lock (_sync)
            {
                token.ThrowIfCancellationRequested();
                if (!_connectionRecovery.IsCurrent(intent!)) return ServiceStatus.Disconnected();
                if (!RestoreFailedConnectNetworkLocked()) return PublishStatus(ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN"));
                try
                {
                    var result = Connect(command.Mode!, command.Core!, command.Source!, command.Country!, command.ConfigId,
                        command.AppPolicy!, command.AppPolicySnapshot!, command.AppPolicyDigest!, command.AppPolicyGeneration!,
                        command.ConnectionType!, token);
                    _lastRuntimeFailure = result.Connected ? null : result.Code;
                    if (_connectionRecovery.IsCurrent(intent!)) _statusSnapshot.Publish(result);
                    return result;
                }
                catch (ServiceFailure failure) { PublishStatus(ServiceStatus.Blocked(failure.Code)); throw; }
                catch { PublishStatus(ServiceStatus.Blocked("BF-CORE-START")); throw; }
            }
        });
        if (intent is null) return ServiceStatus.Disconnected();
        using var initial = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, intent.Cancellation.Token);
        _statusSnapshot.Publish(ServiceStatus.Reconnecting());
        try
        {
            var status = Connect(command.Mode!, command.Core!, command.Source!, command.Country!, command.ConfigId,
                command.AppPolicy!, command.AppPolicySnapshot!, command.AppPolicyDigest!, command.AppPolicyGeneration!,
                command.ConnectionType!, initial.Token);
            lock (_sync)
            {
                if (_connectionRecovery.IsCurrent(intent))
                { _connectionRecovery.CompleteInitial(intent, status); _statusSnapshot.Publish(status); }
            }
            return status;
        }
        catch (Exception error)
        {
            lock (_sync)
                if (_connectionRecovery.IsCurrent(intent))
                    PublishStatus(ServiceStatus.Blocked(error is ServiceFailure failure ? failure.Code : "BF-CORE-START"));
            throw;
        }
    }

    internal CoreRuntime(INetworkBoundary? networkBoundary = null, bool cleanupOrphanedPackagedCores = false,
        Func<bool>? ensureOwnedTunInactiveForTest = null)
    {
        // Production proves ownership of the exact Bifrost TUN and its owning
        // Mihomo process. WFP remains disabled because the previous broad
        // ALE design could affect unrelated applications on the host.
        _networkBoundary = networkBoundary ?? new OwnedTunNetworkBoundary();
        if (cleanupOrphanedPackagedCores && ensureOwnedTunInactiveForTest is not null)
            throw new InvalidOperationException("Production recovery requires native TUN readback");
        _ensureOwnedTunInactive = ensureOwnedTunInactiveForTest ?? EnsureOwnedTunInactiveAfterStop;
        _coreJob = cleanupOrphanedPackagedCores ? Program.CreateCoreKillOnCloseJob() : IntPtr.Zero;
        if (cleanupOrphanedPackagedCores)
            RecoverOrphanedPackagedCoresLocked("startup");
    }

    internal async Task ConfirmStartupOrphanRecoveryAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() || _coreJob == IntPtr.Zero) return;
        for (var pass = 1; pass <= 2; pass++)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken).ConfigureAwait(false);
            lock (_sync)
                RecoverOrphanedPackagedCoresLocked($"startup-confirm-{pass}");
        }
    }

    // Narrow fixture seam over the same CoreRuntime-owned coordinator used by
    // the service command path.  It only accepts injected adapters and cannot
    // select a binary, path, port, or native boundary.
    internal ControlledRuntimeResult ConnectControlledForTest(IControlledPackage package, IControlledCoreAdapter core, IControlledNetworkBoundary boundary)
    {
        lock (_sync)
        {
            if (_controlledRuntime is not null)
            {
                if (_controlledRuntime.State.Phase != ControlledRuntimePhase.Idle)
                    throw new InvalidOperationException("BF-CONNECTION-RESET-REQUIRED");
                _controlledRuntime = null;
                _testControlledCore = null;
                _testControlledBoundary = null;
            }
            _controlledRuntime = new ControlledRuntimeCoordinator(core, boundary);
            _testControlledCore = core;
            _testControlledBoundary = boundary;
            return _controlledRuntime.Connect(package);
        }
    }

    internal ControlledRuntimeState RuntimeStateForTest =>
        _controlledRuntime?.State ?? new ControlledRuntimeState(ControlledRuntimePhase.Idle, false);

    internal bool DisconnectControlledForTest()
    {
        lock (_sync)
        {
            if (_controlledRuntime is null) return true;
            if (!_controlledRuntime.Disconnect()) return false;
            _controlledRuntime = null;
            _testControlledCore = null;
            _testControlledBoundary = null;
            return true;
        }
    }

    public ServiceStatus StageConfig(ServiceCommand command)
    {
        Program.LiveTrace("runtime-stage-before-lock");
        lock (_sync)
        {
            Program.LiveTrace("runtime-stage-acquired-lock");
            try
            {
                if (command.Action != "stage_config" || string.IsNullOrWhiteSpace(command.Mode) ||
                    string.IsNullOrWhiteSpace(command.Core) || string.IsNullOrWhiteSpace(command.Source) ||
                    string.IsNullOrWhiteSpace(command.Country) || string.IsNullOrWhiteSpace(command.AppPolicySnapshot) ||
                    string.IsNullOrWhiteSpace(command.AppPolicyDigest) || string.IsNullOrWhiteSpace(command.AppPolicyGeneration) ||
                    command.ConfigVersion <= 0 || string.IsNullOrWhiteSpace(command.ConfigContentDigest) ||
                    string.IsNullOrWhiteSpace(command.SignedConfigJson) || string.IsNullOrWhiteSpace(command.SignedEnvelopeJson) ||
                    string.IsNullOrWhiteSpace(command.ConfigKeyStateJson) || string.IsNullOrWhiteSpace(command.SelectedCandidate) ||
                    string.IsNullOrWhiteSpace(command.ConnectionType))
                    return ServiceStatus.Blocked("BF-CONFIG-PACKAGE");
                var staged = SignedClientPackageImporter.Import(ServicePaths.ConfigRoot, command);
                ClientPackageStager.PruneStaged(ServicePaths.ConfigRoot, new[] { _configId, staged.ConfigId });
                return ServiceStatus.Staged(staged.ConfigId, staged.Core, staged.Mode, staged.Source);
            }
            catch (JsonException)
            {
                return ServiceStatus.Blocked("BF-CONFIG-STAGE-RAW-JSON");
            }
            catch (Exception ex)
            {
                var runtimeState = _controlledRuntime?.State;
                if (runtimeState?.Phase == ControlledRuntimePhase.BlockedFailure &&
                    string.Equals(runtimeState.FailureCode, "BF-CONNECTION-TEARDOWN", StringComparison.Ordinal))
                    return ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN");
                return ServiceStatus.Blocked(MapError(ex));
            }
        }
    }

    private const int MaxConcurrentLatencyProbes = 12;

    public async Task MeasureLatencyBatchAsync(ServiceCommand command, Func<LatencyBatchFrame, Task> publish, CancellationToken cancellationToken)
    {
        Program.LiveTrace("runtime-latency-batch-enter");
        if (command.Action != "latency_batch" || command.Mode != "global" || command.Country != "default" ||
            command.ConnectionType != "direct-vmess" || command.Core is not ("auto" or "mihomo") ||
            string.IsNullOrWhiteSpace(command.Source) || command.Candidates is not { Count: > 0 } candidates ||
            string.IsNullOrWhiteSpace(command.AppPolicySnapshot) || string.IsNullOrWhiteSpace(command.AppPolicyDigest) ||
            string.IsNullOrWhiteSpace(command.AppPolicyGeneration))
            throw new ServiceFailure("BF-LATENCY-CONFIG");

        var policy = ApplicationPolicySnapshot.Parse(command.AppPolicySnapshot);
        if (policy.RouteMode != "global" || policy.PolicyMode != "none" || policy.Identities.Count != 0 ||
            !string.Equals(policy.Digest, command.AppPolicyDigest, StringComparison.Ordinal) ||
            !string.Equals(policy.Generation, command.AppPolicyGeneration, StringComparison.Ordinal))
            throw new ServiceFailure("BF-APP-POLICY-SNAPSHOT");

        // A latency sweep is service-owned transient work.  It must not live
        // past an explicit disconnect/reconnect, and a newer sweep supersedes
        // an older one.  Previously Disconnect() only tore down the main TUN,
        // leaving per-candidate temporary cores running until their long IPC
        // deadline.  Keep one cancellable generation here so the ordinary
        // service control path can stop every probe immediately.
        using var batchLifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        CancellationTokenSource? previousBatch;
        lock (_latencyBatchSync)
        {
            previousBatch = _latencyBatchCancellation;
            _latencyBatchCancellation = batchLifetime;
        }
        if (previousBatch is not null && !ReferenceEquals(previousBatch, batchLifetime))
        {
            try { previousBatch.Cancel(); } catch (ObjectDisposedException) { }
        }
        cancellationToken = batchLifetime.Token;

        ClientPackageStageResult? staged = null;
        string? probeRuntimeRoot = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            Program.LiveTrace("runtime-latency-batch-import-start");
            // One signed source produces one provider containing all
            // candidates.  Health discovery therefore pays for one route-neutral
            // Mihomo process, not one core/TUN per row.
            staged = SignedClientPackageImporter.Import(ServicePaths.ConfigRoot, command with
            {
                Action = "stage_config",
                SelectedCandidate = candidates[0],
            });
            if (staged.Core != "mihomo") throw new ServiceFailure("BF-CONFIG-CORE");
            Program.LiveTrace("runtime-latency-batch-import-end count=1");
            var resolved = ClientPackageStager.Resolve(ServicePaths.ConfigRoot, staged.ConfigId, command.Mode!, "mihomo",
                command.Source!, command.Country!, policy);
            var package = LoadMihomoPackage(resolved);
            var binary = ResolveLockedBinary("mihomo");
            probeRuntimeRoot = Path.Combine(ServicePaths.ConfigRoot, ".mihomo-probe-" + Guid.NewGuid().ToString("N"));
            var completed = 0;
            await MihomoHealthProbeSession.MeasureAsync(package, binary, HashFile(binary), AppContext.BaseDirectory,
                probeRuntimeRoot, candidates, cancellationToken, async candidate =>
                {
                    var result = candidate.Alive && candidate.DelayMs is > 0
                        ? LatencyTestResult.Measured(candidate.DelayMs.Value)
                        : LatencyTestResult.Unavailable();
                    await publish(LatencyBatchFrame.Progress(candidate.Name, result, ++completed, candidates.Count)).ConfigureAwait(false);
                }).ConfigureAwait(false);
            await publish(LatencyBatchFrame.Complete(candidates.Count)).ConfigureAwait(false);
        }
        finally
        {
            Program.LiveTrace("runtime-latency-batch-finally");
            if (staged is not null) try { ClientPackageStager.RemoveStaged(ServicePaths.ConfigRoot, staged.ConfigId); } catch { }
            if (probeRuntimeRoot is not null) TryDeleteOwnedMihomoProbeRuntime(probeRuntimeRoot);
            lock (_latencyBatchSync)
            {
                if (ReferenceEquals(_latencyBatchCancellation, batchLifetime))
                    _latencyBatchCancellation = null;
            }
            Program.LiveTrace("runtime-latency-batch-exit");
        }
    }

    private void CancelLatencyBatch()
    {
        Program.LiveTrace("runtime-cancel-latency-enter");
        CancellationTokenSource? batch;
        lock (_latencyBatchSync) batch = _latencyBatchCancellation;
        if (batch is null)
        {
            Program.LiveTrace("runtime-cancel-latency-none");
            return;
        }
        try { batch.Cancel(); } catch (ObjectDisposedException) { }
        Program.LiveTrace("runtime-cancel-latency-sent");
    }

    private void CancelConnectionStart()
    {
        Program.LiveTrace("runtime-cancel-connect-enter");
        CancellationTokenSource? connect;
        lock (_connectCancellationSync) connect = _connectCancellation;
        if (connect is null)
        {
            Program.LiveTrace("runtime-cancel-connect-none");
            return;
        }
        try { connect.Cancel(); } catch (ObjectDisposedException) { }
        Program.LiveTrace("runtime-cancel-connect-sent");
    }

    private static void TryDeleteOwnedMihomoProbeRuntime(string runtimeRoot)
    {
        try
        {
            var full = Path.GetFullPath(runtimeRoot);
            var name = Path.GetFileName(full);
            if (!ServicePaths.IsContained(ServicePaths.ConfigRoot, full) ||
                !name.StartsWith(".mihomo-probe-", StringComparison.Ordinal) ||
                name.Length != ".mihomo-probe-".Length + 32 ||
                name[".mihomo-probe-".Length..].Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
                !Directory.Exists(full)) return;
            ServicePaths.RejectReparse(full, directory: true);
            foreach (var entry in Directory.EnumerateFileSystemEntries(full, "*", SearchOption.AllDirectories))
                ServicePaths.RejectReparse(entry, Directory.Exists(entry));
            Directory.Delete(full, recursive: true);
        }
        catch { }
    }

    public ServiceStatus Connect(
        string mode,
        string core,
        string source = "auto",
        string country = "default",
        string? configId = null,
        string appPolicy = "none",
        string? appPolicySnapshot = null,
        string? appPolicyDigest = null,
        string? appPolicyGeneration = null,
        string connectionType = "direct-vmess",
        CancellationToken cancellationToken = default)
    {
        CancelLatencyBatch();
        using var connectLifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        CancellationTokenSource? previousConnect;
        lock (_connectCancellationSync)
        {
            previousConnect = _connectCancellation;
            _connectCancellation = connectLifetime;
        }
        if (previousConnect is not null && !ReferenceEquals(previousConnect, connectLifetime))
        {
            try { previousConnect.Cancel(); } catch (ObjectDisposedException) { }
        }
        var connectToken = connectLifetime.Token;
        try
        {
            connectToken.ThrowIfCancellationRequested();
            Program.LiveTrace("runtime-connect-before-lock");
            lock (_sync)
            {
            Program.LiveTrace("runtime-connect-acquired-lock");
            connectToken.ThrowIfCancellationRequested();
            _lastRuntimeFailure = null;
            if (!((connectionType == "direct-vmess" && mode is "smart" or "global" or "per-app") ||
                  (connectionType == "smartgate" && mode is "smart" or "per-app")))
                return ServiceStatus.Blocked("BF-CONNECTION-TYPE");
            ApplicationPolicySnapshot verifiedPolicy;
            try
            {
                if (string.IsNullOrWhiteSpace(appPolicySnapshot) || string.IsNullOrWhiteSpace(appPolicyDigest) || string.IsNullOrWhiteSpace(appPolicyGeneration))
                    return ServiceStatus.Blocked("BF-APP-POLICY-MISSING");
                verifiedPolicy = ApplicationPolicySnapshot.Parse(appPolicySnapshot);
                if (verifiedPolicy.RouteMode != mode || verifiedPolicy.PolicyMode != appPolicy ||
                    !string.Equals(verifiedPolicy.Digest, appPolicyDigest, StringComparison.Ordinal) ||
                    !string.Equals(verifiedPolicy.Generation, appPolicyGeneration, StringComparison.Ordinal))
                    return ServiceStatus.Blocked("BF-APP-POLICY-SNAPSHOT");
            }
            catch (ApplicationPolicyFailure failure)
            {
                return ServiceStatus.Blocked(failure.Code);
            }
            catch (ServiceFailure failure)
            {
                return ServiceStatus.Blocked(failure.Code);
            }
            catch
            {
                return ServiceStatus.Blocked("BF-APP-POLICY-SNAPSHOT");
            }
            // StageConfig is the single authority that resolves "auto" from
            // the signed core policy. Connect must consume the concrete core
            // returned by staging instead of resolving policy a second time.
            if (core != "mihomo")
                return ServiceStatus.Blocked("BF-CONFIG-CORE");
            var effectiveCore = core;
            var healthy = _core is { HasExited: false } && (_transport is null || !_transport.HasExited) && _boundaryState.IsHealthy(_networkBoundary);
            if (healthy && string.Equals(_mode, mode, StringComparison.Ordinal) && string.Equals(_effectiveCore, effectiveCore, StringComparison.Ordinal) && string.Equals(_source, source, StringComparison.Ordinal) && string.Equals(_country, country, StringComparison.Ordinal) && string.Equals(_appPolicy, appPolicy, StringComparison.Ordinal) && string.Equals(_appPolicyDigest, verifiedPolicy.Digest, StringComparison.Ordinal) && string.Equals(_appPolicyGeneration, verifiedPolicy.Generation, StringComparison.Ordinal) && string.Equals(_configId, configId, StringComparison.Ordinal) && IsSummaryCurrent(verifiedPolicy, mode, effectiveCore, configId))
                return ConnectedStatusLocked(_coreName ?? effectiveCore, _mode ?? mode, _configId, _source!, _enforcementSummary!);
            if (_controlledRuntime is not null && _controlledRuntime.State.Phase != ControlledRuntimePhase.Idle)
            {
                var runtimeState = _controlledRuntime.State;
                return ServiceStatus.Blocked(runtimeState.FailureCode ?? "BF-CONNECTION-RESET-REQUIRED", "runtime requires explicit teardown before reconnect");
            }
            if (_core is not null || _transport is not null)
            {
                if (_controlledRuntime is not null)
                {
                    if (!_controlledRuntime.Disconnect())
                        return ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN");
                    _controlledRuntime = null;
                }
                else
                {
                    if (!StopCoreLocked() || !RemoveBoundaryLocked())
                        return ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN");
                }
            }
            if (mode is not ("smart" or "global" or "per-app"))
                return ServiceStatus.Blocked("BF-CONFIG-MODE");
            if (source == "auto" || !ServiceSelectionCodes.IsSource(source) || !ServiceSelectionCodes.IsCountry(country) ||
                appPolicy is not ("none" or "allow" or "exclude") ||
                mode == "per-app" && appPolicy is not ("allow" or "exclude") ||
                mode != "per-app" && appPolicy != "none" ||
                !ServicePaths.IsOpaqueId(configId, "cfg_"))
                return ServiceStatus.Blocked("BF-CONFIG-PACKAGE");
            try
            {
                var resolved = ClientPackageStager.Resolve(ServicePaths.ConfigRoot, configId!, mode, effectiveCore, source, country, verifiedPolicy);
                var config = resolved.MainConfigPath;
                var healthEndpoint = ResolveMihomoHealthEndpoint(config);
                var dataPlaneProbe = ResolveMihomoDataPlaneProbeTarget(config);
                if (healthEndpoint is null || dataPlaneProbe is null) return ServiceStatus.Blocked("BF-MIHOMO-CONFIG");
                // Keep the plan for diagnostics; WFP installation is disabled
                // in this release so no host-wide rule can affect other apps.
                _ = WfpBoundary.BuildPlan(mode, effectiveCore, true);
                if (healthEndpoint is null) return ServiceStatus.Blocked("BF-CORE-HEALTH-CONFIG");
                if (dataPlaneProbe is null) return ServiceStatus.Blocked("BF-CORE-HEALTH-CONFIG");
                _boundaryIntent = new NetworkBoundaryIntent(mode, effectiveCore, configId!, resolved.ApplicationPolicyDigest, resolved.ApplicationPolicyGeneration);
                var controlledPackage = new ServiceControlledPackage(connectionType, effectiveCore);
                var controlled = new ControlledRuntimeCoordinator(
                    new ServiceCoreAdapter(this, resolved, mode, effectiveCore, configId!, source, country, appPolicy, verifiedPolicy, healthEndpoint, dataPlaneProbe, connectToken),
                    new ServiceBoundaryAdapter(this, connectToken));
                _controlledRuntime = controlled;
                _ = controlled.Connect(controlledPackage);
                if (connectToken.IsCancellationRequested)
                {
                    if (!controlled.Disconnect()) return ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN");
                    _controlledRuntime = null;
                    return ServiceStatus.Disconnected();
                }
                var evidence = _boundaryState.Evidence ?? throw new ServiceFailure("BF-APP-POLICY-READBACK");
                var summary = new EnforcementSummary(
                    mode,
                    verifiedPolicy.PolicyMode,
                    verifiedPolicy.Identities.Count,
                    resolved.ApplicationPolicyDigest,
                    resolved.ApplicationPolicyGeneration,
                    true);
                if (!EnforcementSummaryValidator.Matches(summary, verifiedPolicy, _boundaryIntent!, evidence))
                    throw new ServiceFailure("BF-APP-POLICY-READBACK");
                _enforcementSummary = summary;
                return ConnectedStatusLocked(_coreName ?? effectiveCore, mode, _configId, _source!, summary);
            }
            catch (Exception ex)
            {
                var code = MapError(ex);
                Program.LiveTrace($"runtime-connect-failed code={code} exception={ex.GetType().Name}");
                if (!RestoreFailedConnectNetworkLocked())
                    return ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN");
                return ServiceStatus.Blocked(code);
            }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            lock (_sync)
            {
                return RestoreFailedConnectNetworkLocked()
                    ? ServiceStatus.Disconnected()
                    : ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN");
            }
        }
        finally
        {
            Program.LiveTrace("runtime-connect-finally");
            lock (_connectCancellationSync)
            {
                if (ReferenceEquals(_connectCancellation, connectLifetime))
                    _connectCancellation = null;
            }
        }
    }

    public ServiceStatus Status()
    {
        lock (_sync) return PublishStatus(ObserveStatus());
    }

    private ServiceStatus PublishStatus(ServiceStatus status) { _statusSnapshot.Publish(status); return status; }

    public ServiceStatus StatusForClient() => _statusSnapshot.Read(_connectionRecovery.IsReconnecting);

    private ServiceStatus ObserveStatus()
    {
        Program.LiveTrace("runtime-status-before-lock");
        lock (_sync)
        {
            Program.LiveTrace("runtime-status-acquired-lock");
            RefreshMihomoReadbackLocked(force: false);
            if (_controlledRuntime?.State.Phase == ControlledRuntimePhase.Connected &&
                _testControlledCore is not null && _testControlledBoundary is not null &&
                (!_testControlledCore.IsHealthy || !_testControlledBoundary.IsBound))
                _controlledRuntime.MarkFailure("BF-RUNTIME-HEALTH");
            if (_controlledRuntime?.State.Phase is ControlledRuntimePhase.FencedStarting or ControlledRuntimePhase.BlockedFailure or ControlledRuntimePhase.Disconnecting)
                return ServiceStatus.Blocked(_controlledRuntime.State.FailureCode ?? "BF-RUNTIME-BLOCKED", "runtime remains fail-closed until explicit teardown");
            var coreAlive = _core is { HasExited: false } && (_transport is null || !_transport.HasExited);
            bool coreHealthy, boundaryHealthy;
            using (WindowsInterfaceReadback.Begin())
            {
                coreHealthy = coreAlive && IsCoreHealthyLocked();
                boundaryHealthy = coreAlive && _boundaryState.IsHealthy(_networkBoundary);
            }
            var runtimeHealthy = coreHealthy && boundaryHealthy;
            if (runtimeHealthy)
            {
                // Core/TUN/readback evidence alone can still produce a false
                // "Connected" state when a coexist cutover broke real host
                // traffic. Probe the actual proxy data plane on a short
                // cadence and immediately tear Bifrost back down on failure so
                // the pre-existing network is restored instead of remaining
                // trapped behind a dead TUN.
                if (!IsDataPlaneHealthyLocked(force: false))
                {
                    var diagnostic = _lastDataPlaneProbeCode ?? "BF-TRANSPORT-PROBE";
                    Program.LiveTrace($"runtime-live-dataplane-failed code={diagnostic} coexist={_coexistMode}");
                    // A bad selected proxy is not the same thing as a bad
                    // TUN/core. Give Mihomo's native automatic group one
                    // bounded in-place reselection first. This keeps the
                    // owned routes and established TUN alive, matching mature
                    // Clash/v2ray-style failure handling. Only a failed
                    // same-core recovery escalates to full teardown/restart.
                    if (!TryRecoverAutomaticMihomoPathLocked(diagnostic))
                    {
                        if (!RestoreFailedConnectNetworkLocked())
                            return ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN");
                        _lastRuntimeFailure = "BF-RUNTIME-HEALTH";
                        _lastRuntimeDiagnostic = diagnostic;
                        return ServiceStatus.Blocked("BF-RUNTIME-HEALTH", diagnostic);
                    }
                }
                if (_applicationPolicySnapshot is not null && IsSummaryCurrent(_applicationPolicySnapshot, _mode ?? "", _effectiveCore ?? "", _configId))
                    return ConnectedStatusLocked(_coreName ?? "unknown", _mode ?? "unknown", _configId, _source!, _enforcementSummary!);
            }
            if (coreAlive && !boundaryHealthy)
            {
                _controlledRuntime?.MarkFailure("BF-NETWORK-BOUNDARY");
                return ServiceStatus.Blocked("BF-NETWORK-BOUNDARY", "network boundary evidence disappeared");
            }
            if (_core is { HasExited: false })
            {
                _controlledRuntime?.MarkFailure("BF-CORE-NOT-READY");
                return ServiceStatus.Blocked("BF-CORE-NOT-READY", "core health evidence disappeared");
            }
            if (_core is not null)
            {
                _controlledRuntime?.MarkFailure("BF-CORE-EXITED");
                return ServiceStatus.Blocked("BF-CORE-EXITED", "core exited; owned network rules were removed");
            }
            return _lastRuntimeFailure is { } failure ? ServiceStatus.Blocked(failure,
                failure == "BF-RUNTIME-HEALTH" ? _lastRuntimeDiagnostic : null) : ServiceStatus.Disconnected();
        }
    }

    public ServiceStatus Disconnect()
    {
        _connectionRecovery.Cancel();
        Program.LiveTrace("runtime-disconnect-enter");
        CancelLatencyBatch();
        Program.LiveTrace("runtime-disconnect-after-latency-cancel");
        // Cancellation must happen before waiting for _sync. Connect holds the
        // mutation lock while it starts Wintun/core health checks; signalling
        // first makes those bounded waits abort so Disconnect can acquire the
        // lock and complete teardown instead of timing out behind startup.
        CancelConnectionStart();
        Program.LiveTrace("runtime-disconnect-after-connect-cancel");
        Program.LiveTrace("runtime-disconnect-before-lock");
        lock (_sync)
        {
            Program.LiveTrace("runtime-disconnect-acquired-lock");
            _lastRuntimeFailure = null;
            if (_controlledRuntime is not null)
            {
                if (!_controlledRuntime.Disconnect())
                {
                    if (!RestoreFailedConnectNetworkLocked())
                        return PublishStatus(ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN"));
                }
                _controlledRuntime = null;
                _testControlledCore = null;
                _testControlledBoundary = null;
            }
            else
            {
                if (!StopCoreLocked() || !RemoveBoundaryLocked())
                    return PublishStatus(ServiceStatus.Blocked("BF-CONNECTION-TEARDOWN"));
            }
            Program.LiveTrace("runtime-disconnect-done");
            return PublishStatus(ServiceStatus.Disconnected());
        }
    }

    private bool RestoreFailedConnectNetworkLocked()
    {
        Program.LiveTrace("runtime-failed-connect-restore-enter");
        if (_controlledRuntime is not null)
        {
            try { _ = _controlledRuntime.Disconnect(); } catch { }
        }
        var coreStopped = StopCoreLocked();
        var boundaryRemoved = RemoveBoundaryLocked();
        var tunInactive = _ensureOwnedTunInactive();
        if (coreStopped && boundaryRemoved && tunInactive)
        {
            _controlledRuntime = null;
            _testControlledCore = null;
            _testControlledBoundary = null;
            Program.LiveTrace("runtime-failed-connect-restore-done");
            return true;
        }
        Program.LiveTrace($"runtime-failed-connect-restore-failed core={coreStopped} boundary={boundaryRemoved} tun={tunInactive}");
        return false;
    }

    /// <summary>Returns the service-owned release identity over the pipe.</summary>
    public ServiceReleaseHealth ReleaseHealth()
    {
        var path = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            throw new ServiceFailure("BF-SERVICE-HEALTH");
        path = Path.GetFullPath(path);
        var generation = Path.GetFileName(Path.GetDirectoryName(path) ?? string.Empty);
        if (string.IsNullOrWhiteSpace(generation)) throw new ServiceFailure("BF-SERVICE-HEALTH");
        var generationParent = Path.GetDirectoryName(Path.GetDirectoryName(path) ?? string.Empty) ?? string.Empty;
        var installRoot = string.Equals(Path.GetFileName(generationParent), ".bifrost-generations", StringComparison.OrdinalIgnoreCase)
            ? Path.GetFileName(Path.GetDirectoryName(generationParent) ?? string.Empty)
            : Path.GetFileName(generationParent);
        var installRootPath = string.Equals(Path.GetFileName(generationParent), ".bifrost-generations", StringComparison.OrdinalIgnoreCase)
            ? Path.GetDirectoryName(generationParent) ?? string.Empty
            : generationParent;
        if (string.IsNullOrWhiteSpace(installRoot) || string.IsNullOrWhiteSpace(installRootPath)) throw new ServiceFailure("BF-SERVICE-HEALTH");
        var sequenceToken = generation.StartsWith("g-", StringComparison.OrdinalIgnoreCase)
            ? generation[2..].Split('-', 2, StringSplitOptions.RemoveEmptyEntries)[0]
            : generation.Split('-', 2, StringSplitOptions.RemoveEmptyEntries)[0];
        if (!long.TryParse(sequenceToken, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var sequence) || sequence <= 0)
            throw new ServiceFailure("BF-SERVICE-HEALTH");
        string identity;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
            identity = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch { throw new ServiceFailure("BF-SERVICE-HEALTH"); }
        using var binding = IpcProtocol.LoadBinding();
        var installId = Convert.ToHexString(HMACSHA256.HashData(binding.Secret, Encoding.UTF8.GetBytes("install|" + Path.GetFullPath(installRootPath)))).ToLowerInvariant();
        return new ServiceReleaseHealth("bifrost-client-service", installId, sequence, generation, Environment.ProcessId, identity);
    }

    private bool EnterFailClosedLocked()
    {
        if (_boundaryIntent is null) return false;
        if (_boundaryState.Phase is NetworkBoundaryPhase.Active or NetworkBoundaryPhase.Prepared or NetworkBoundaryPhase.Failed)
        {
            _boundaryState.FailClosed();
            Program.LiveTrace($"runtime-boundary-prepare reused-phase={_boundaryState.Phase}");
            return true;
        }
        var prepared = _boundaryState.Prepare(_networkBoundary, _boundaryIntent);
        Program.LiveTrace($"runtime-boundary-prepare ok={prepared.Ok} code={prepared.Code} phase={_boundaryState.Phase}");
        return prepared.Ok;
    }

    private bool ActivateBoundaryLocked(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var process = _core;
        if (process is null || process.HasExited)
        {
            Program.LiveTrace("runtime-boundary-activate core-alive=False");
            return false;
        }
        var activated = _boundaryState.Activate(_networkBoundary, process.Id);
        Program.LiveTrace($"runtime-boundary-activate core-alive=True ok={activated.Ok} code={activated.Code} phase={_boundaryState.Phase}");
        if (!activated.Ok) return false;
        var boundaryHealthy = _boundaryState.IsHealthy(_networkBoundary);
        Program.LiveTrace($"runtime-boundary-readback healthy={boundaryHealthy} phase={_boundaryState.Phase}");
        if (!boundaryHealthy) return false;
        if (_coexistRoutes is not null)
        {
            var routes = _coexistRoutes;
            var canary = _coexistCanaryAddress;
            var probe = _dataPlaneProbe;
            if (routes is null || canary is null || probe is null) return false;
            try
            {
                // The core/TUN is healthy while host routing is still untouched.
                // Only now commit the service-owned active-store /1 routes.
                // The same
                // canary address that already passed through a /32 route must
                // continue to pass after the /32 is gone, proving the /1
                // cutover itself before Connected can be reported.
                routes.CommitFullTunnel();
                var cutoverProbe = ProbeHostDataPlane(canary, probe, cancellationToken, CutoverDataPlaneProbeTimeout);
                Program.LiveTrace($"runtime-owned-full-cutover healthy={cutoverProbe.Healthy} code={cutoverProbe.Code}");
                if (!cutoverProbe.Healthy)
                {
                    _ = routes.RemoveAll();
                    return false;
                }
            }
            catch
            {
                _ = routes.RemoveAll();
                return false;
            }
        }
        cancellationToken.ThrowIfCancellationRequested();
        return true;
    }

    private bool IsBoundaryBoundLocked() =>
        _boundaryState.Phase == NetworkBoundaryPhase.Active && _boundaryState.IsHealthy(_networkBoundary);

    private void StartCoreProcessesLocked(ClientPackageResolved resolved, string mode, string effectiveCore,
        string connectionType,
        string configId, string source, string country, string appPolicy,
        ApplicationPolicySnapshot verifiedPolicy, Uri healthEndpoint, DataPlaneProbeTarget dataPlaneProbe,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (effectiveCore != "mihomo") throw new ServiceFailure("BF-CONFIG-CORE");
        StartMihomoProcessesLocked(resolved, mode, connectionType, configId, source, country, appPolicy,
            verifiedPolicy, dataPlaneProbe, cancellationToken);
    }

    private void StartMihomoProcessesLocked(
        ClientPackageResolved resolved,
        string mode,
        string connectionType,
        string configId,
        string source,
        string country,
        string appPolicy,
        ApplicationPolicySnapshot verifiedPolicy,
        DataPlaneProbeTarget dataPlaneProbe,
        CancellationToken cancellationToken)
    {
        if (_core is not null || _transport is not null || _mihomoSupervisor is not null)
            throw new ServiceFailure("BF-MIHOMO-ALREADY-RUNNING");
        // SCM can report the prior service stopped before a detached core has
        // finished exiting.  Startup recovery can therefore legitimately see
        // no orphan, only for the old Mihomo process to become observable a
        // moment later.  Repeat the exact immutable-generation ownership check
        // at the last safe point before starting a new core.  This keeps an
        // upgrade race from turning into a controller/TUN port collision while
        // still excluding independently installed Clash/v2rayN processes.
        RecoverOrphanedPackagedCoresLocked("pre-connect");
        var qualityRuntime = MihomoQualityOptimizer.Prepare(LoadMihomoPackage(resolved));
        var package = qualityRuntime.Package;
        var fixedCandidate = MihomoPolicyCompiler.FixedCandidate(package);
        var underlayName = JsonNode.Parse(package.MainConfig)?["interface-name"]?.GetValue<string>() ?? "";
        var underlay = WindowsInterfaceReadback.Read().FirstOrDefault(item => item.Name == underlayName || item.Id == underlayName);
        // Fast reconnect survives ordinary signed-provider regeneration and
        // candidate reordering. The key uses source identity + physical
        // adapter; the candidate itself is still current-provider scoped and
        // fresh-health-checked before any host route moves.
        var memoryKey = underlay is null ? null : MihomoConnectionMemory.StableKey(package.ProviderName, underlay.Id);
        // Migrate both historical key shapes when possible. If provider bytes
        // changed since the old winner was saved, RecallAny is a final one-time
        // bridge: allowed-label + fresh signed-provider health validation keeps
        // it safe, then the stable key takes over for subsequent launches.
        var legacyMemoryKey = underlay is null ? null : MihomoConnectionMemory.Key(package.Provider, underlay.Id);
        var oldestLegacyMemoryKey = underlay is null ? null : MihomoConnectionMemory.Key(package.Provider,
            underlay.Id + ":" + string.Join(",", underlay.UnicastAddresses.Select(address => address.ToString()).Order()));
        var memoryNow = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        string? rememberedMemoryKey = memoryKey;
        var rememberedCandidate = fixedCandidate is null && memoryKey is not null
            ? _connectionMemory.RecallFresh(memoryKey, package.AllowedCandidates, memoryNow)
            : null;
        if (rememberedCandidate is null && fixedCandidate is null && legacyMemoryKey is not null &&
            !string.Equals(legacyMemoryKey, memoryKey, StringComparison.Ordinal))
        {
            rememberedCandidate = _connectionMemory.RecallFresh(legacyMemoryKey, package.AllowedCandidates, memoryNow);
            if (rememberedCandidate is not null) rememberedMemoryKey = legacyMemoryKey;
        }
        if (rememberedCandidate is null && fixedCandidate is null && oldestLegacyMemoryKey is not null &&
            !string.Equals(oldestLegacyMemoryKey, memoryKey, StringComparison.Ordinal) &&
            !string.Equals(oldestLegacyMemoryKey, legacyMemoryKey, StringComparison.Ordinal))
        {
            rememberedCandidate = _connectionMemory.RecallFresh(oldestLegacyMemoryKey, package.AllowedCandidates, memoryNow);
            if (rememberedCandidate is not null) rememberedMemoryKey = oldestLegacyMemoryKey;
        }
        if (rememberedCandidate is null && fixedCandidate is null && memoryKey is not null)
        {
            rememberedCandidate = _connectionMemory.RecallAnyFresh(package.AllowedCandidates, memoryNow);
            if (rememberedCandidate is not null) rememberedMemoryKey = null;
        }
        var (controllerUri, controllerSecret, _) = ReadMihomoControllerConfig(package.MainConfig);
        var binary = ResolveLockedBinary("mihomo");
        var runtimeRoot = Path.Combine(ServicePaths.ConfigRoot, ".mihomo-runtime");
        var supervisor = new MihomoRuntimeSupervisor(binary, HashFile(binary), runtimeRoot);
        MihomoRuntimeIdentity? identity = null;
        MihomoControllerClient? controller = null;
        WindowsRouteHandover? handover = null;
        OwnedTunDns? tunDns = null;
        MihomoQualityOptimizer? qualityOptimizer = null;
        Process? process = null;
        CancellationTokenSource? startupParallel = null;
        Task<int>? tunReady = null;
        Task<IPAddress>? canaryReady = null;
        try
        {
            identity = supervisor.Start(package, AppContext.BaseDirectory);
            process = Process.GetProcessById(identity.ProcessId);
            controller = new MihomoControllerClient(controllerUri, controllerSecret, TimeSpan.FromSeconds(15));
            controller.WaitReadyAsync(cancellationToken).GetAwaiter().GetResult();
            Program.LiveTrace("runtime-mihomo-controller-ready");
            startupParallel = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            tunReady = WaitForOwnedTunInterfaceAsync(supervisor, identity, StartupTunReadyTimeout, startupParallel.Token);
            canaryReady = Task.Run(() => ResolveHostProbeAddress(dataPlaneProbe, startupParallel.Token), startupParallel.Token);
            // The native provider tests bounded cohorts in the background. Admit
            // the first verified usable member; selection keeps improving while
            // the committed TUN and established connections remain in place.
            controller.RefreshProviderAsync(package.ProviderName, cancellationToken).GetAwaiter().GetResult();
            Program.LiveTrace("runtime-mihomo-provider-refreshed");
            MihomoGroupState? recalledGroup = null;
            if (!string.IsNullOrWhiteSpace(rememberedCandidate))
            {
                try
                {
                    var recalledHealth = controller.MeasureVerifiedCandidatesAsync(package.ProviderName,
                        new[] { rememberedCandidate }, package.AllowedCandidates, cancellationToken).GetAwaiter().GetResult();
                    if (recalledHealth.Count == 1 && recalledHealth[0].Alive &&
                        NodeQualityPolicy.IsUsableDelay(recalledHealth[0].DelayMs))
                    {
                        controller.SelectAsync(package.ActiveGroup, rememberedCandidate, cancellationToken).GetAwaiter().GetResult();
                        var readback = controller.ReadGroupAsync(package.ActiveGroup, package.ProviderName, cancellationToken,
                            package.AllowedCandidates).GetAwaiter().GetResult();
                        if (string.Equals(readback.Now, rememberedCandidate, StringComparison.OrdinalIgnoreCase) &&
                            readback.Candidates.Any(candidate => candidate.Alive &&
                                string.Equals(candidate.Name, rememberedCandidate, StringComparison.OrdinalIgnoreCase)))
                        {
                            recalledGroup = readback;
                            if (memoryKey is not null && !string.Equals(memoryKey, rememberedMemoryKey, StringComparison.Ordinal))
                            {
                                _connectionMemory.Remember(memoryKey, rememberedCandidate, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                                if (rememberedMemoryKey is not null) _connectionMemory.Forget(rememberedMemoryKey);
                                Program.LiveTrace($"runtime-mihomo-optimized-memory-migrated candidate={rememberedCandidate}");
                            }
                            Program.LiveTrace($"runtime-mihomo-optimized-memory-recalled candidate={rememberedCandidate}");
                        }
                    }
                    if (recalledGroup is null)
                    {
                        if (rememberedMemoryKey is not null) _connectionMemory.Forget(rememberedMemoryKey);
                        Program.LiveTrace($"runtime-mihomo-optimized-memory-rejected candidate={rememberedCandidate}");
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch
                {
                    if (rememberedMemoryKey is not null) _connectionMemory.Forget(rememberedMemoryKey);
                    Program.LiveTrace($"runtime-mihomo-optimized-memory-rejected candidate={rememberedCandidate}");
                }
            }
            // URLTest discovers the first usable node. Throughput qualification
            // then chooses the startup incumbent, and a later confirmed body
            // transfer may replace it. Runtime recovery clears the selection
            // cache if the incumbent actually fails.
            var group = recalledGroup ?? (fixedCandidate is null
                ? controller.WaitForFirstUsableAutomaticGroupAsync(package.ActiveGroup, package.ProviderName, package.AllowedCandidates,
                    TimeSpan.FromSeconds(20), cancellationToken).GetAwaiter().GetResult()
                : controller.WaitForHealthyGroupAsync(package.ActiveGroup, package.ProviderName, package.AllowedCandidates,
                    TimeSpan.FromSeconds(20), cancellationToken, fixedCandidate).GetAwaiter().GetResult());
            Program.LiveTrace("runtime-mihomo-first-usable-ready");
            Program.LiveTrace($"runtime-mihomo-group-ready candidate={group.Now}");
            if (!package.AllowedCandidates.Contains(group.Now)) throw new ServiceFailure("BF-CANDIDATE-SOURCE-MISMATCH");

            // URLTest is excellent reachability/latency authority but a
            // single 204 request says nothing about sustained capacity.  Do
            // the bounded multi-stream qualification while the core is alive
            // but before Bifrost commits host routes/DNS.  This means the
            // user's first real download starts on the throughput-qualified
            // winner instead of racing the old background worker and causing
            // that worker to yield to foreground traffic.
            var startupCapacityConfirmed = false;
            if (fixedCandidate is null && qualityRuntime.Port > 0)
            {
                void ConfirmCapacity(string candidate)
                {
                    startupCapacityConfirmed = true;
                    RememberOptimizedCandidate(memoryKey, candidate);
                }
                if (recalledGroup is not null)
                {
                    // Reachability is not proof that yesterday's/earlier
                    // capacity still exists. Reuse the remembered candidate
                    // as the incumbent for a compact qualification, so a
                    // congested 40-50 Mbps path cannot remain sticky while a
                    // 200+ Mbps peer is still present in the signed ranking.
                    group = MihomoQualityOptimizer.QualifyStartupAsync(qualityRuntime, controller, group,
                        Program.LiveTrace, cancellationToken, ConfirmCapacity,
                        compactReconnect: true).GetAwaiter().GetResult();
                    Program.LiveTrace($"runtime-mihomo-throughput-reuse-requalified candidate={group.Now} confirmed={startupCapacityConfirmed}");
                }
                else
                {
                    group = MihomoQualityOptimizer.QualifyStartupAsync(qualityRuntime, controller, group,
                        Program.LiveTrace, cancellationToken, ConfirmCapacity).GetAwaiter().GetResult();
                    Program.LiveTrace($"runtime-mihomo-throughput-qualification candidate={group.Now} confirmed={startupCapacityConfirmed}");
                }
            }

            if (fixedCandidate is null && startupCapacityConfirmed)
            {
                // PUT pins the measured startup node even when it already
                // happened to be URLTest's latency winner. Otherwise later
                // URLTest health rounds silently move new X/media flows to a
                // lower-bandwidth node without a throughput comparison.
                controller.SelectAsync(package.ActiveGroup, group.Now, cancellationToken).GetAwaiter().GetResult();
                var pinned = controller.ReadGroupAsync(package.ActiveGroup, package.ProviderName, cancellationToken,
                    package.AllowedCandidates).GetAwaiter().GetResult();
                if (!string.Equals(pinned.Now, group.Now, StringComparison.OrdinalIgnoreCase) ||
                    !pinned.Candidates.Any(candidate => candidate.Alive &&
                        string.Equals(candidate.Name, pinned.Now, StringComparison.OrdinalIgnoreCase) &&
                        NodeQualityPolicy.IsUsableDelay(candidate.DelayMs)))
                    throw new ServiceFailure("BF-MIHOMO-GROUP");
                group = pinned;
                Program.LiveTrace($"runtime-mihomo-startup-pinned candidate={group.Now}");
            }
            else if (fixedCandidate is null)
            {
                // A failed short download is only a reachability result. Do
                // not freeze URLTest on the incumbent without body evidence.
                if (rememberedMemoryKey is not null) _connectionMemory.Forget(rememberedMemoryKey);
                group = controller.WaitForFirstUsableAutomaticGroupAsync(package.ActiveGroup,
                    package.ProviderName, package.AllowedCandidates, TimeSpan.FromSeconds(5),
                    cancellationToken).GetAwaiter().GetResult();
                Program.LiveTrace($"runtime-mihomo-startup-unqualified-auto candidate={group.Now}");
            }

            string? chatGptCandidate = null;
            if (!string.IsNullOrWhiteSpace(package.ChatGptGroupName))
            {
                // ChatGPT keeps long-lived page/auth connections while file
                // uploads and assets open separate HTTPS connections. Pin the
                // entire OpenAI service boundary to the same measured startup
                // egress so a later URLTest winner cannot split one browser
                // session across public IPs. The dedicated Fallback group
                // continues tracking health; readback performs a controlled
                // repin only after the affinity member is actually unhealthy.
                controller.SelectAsync(package.ChatGptGroupName, group.Now, cancellationToken).GetAwaiter().GetResult();
                var chatGptGroup = controller.ReadGroupAsync(package.ChatGptGroupName, package.ProviderName, cancellationToken)
                    .GetAwaiter().GetResult();
                if (!string.Equals(chatGptGroup.Now, group.Now, StringComparison.OrdinalIgnoreCase) ||
                    !chatGptGroup.Candidates.Any(candidate => candidate.Alive &&
                        string.Equals(candidate.Name, chatGptGroup.Now, StringComparison.OrdinalIgnoreCase)))
                    throw new ServiceFailure("BF-MIHOMO-GROUP");
                chatGptCandidate = chatGptGroup.Now;
                Program.LiveTrace($"runtime-mihomo-openai-pinned candidate={chatGptCandidate}");
            }

            var interfaceIndex = tunReady.GetAwaiter().GetResult();
            Program.LiveTrace($"runtime-mihomo-tun-ready index={interfaceIndex}");
            var canary = canaryReady.GetAwaiter().GetResult();
            Program.LiveTrace($"runtime-mihomo-canary-resolved address={canary}");
            startupParallel.Dispose();
            startupParallel = null;
            tunReady = null;
            canaryReady = null;
            var includeIpv6 = System.Text.Json.Nodes.JsonNode.Parse(package.MainConfig)?["ipv6"]?.GetValue<bool>() == true;
            handover = new WindowsRouteHandover(interfaceIndex, includeIpv6);
            _ = handover.PrepareAndCommit(identity, group, package.AllowedCandidates, canary,
                (address, token) =>
                {
                    for (var attempt = 1; attempt <= CutoverDataPlaneProbeAttempts; attempt++)
                    {
                        var cutoverProbe = ProbeHostDataPlane(address, dataPlaneProbe, token, CutoverDataPlaneProbeTimeout);
                        Program.LiveTrace($"runtime-mihomo-cutover-probe attempt={attempt} candidate={group.Now} healthy={cutoverProbe.Healthy} code={cutoverProbe.Code}");
                        if (cutoverProbe.Healthy) return true;
                        if (attempt == CutoverDataPlaneProbeAttempts) return false;

                        // A provider winner can degrade between startup health
                        // measurement and the first host-originated TUN request.
                        // Refresh the complete signed cohort in stable provider
                        // order so every member gets fresh evidence, then hand
                        // automatic selection back to native URLTest. The old
                        // host route remains in place apart from this single
                        // /32 canary, so a failed refresh cannot strand the
                        // user's existing network.
                        var recoveryOrder = (package.PreferredCandidates ?? package.AllowedCandidates.Order(StringComparer.Ordinal).ToArray())
                            .Where(package.AllowedCandidates.Contains).Distinct(StringComparer.Ordinal).ToArray();
                        var measured = controller.MeasureGroupUntilUsableAsync(package.ActiveGroup, package.ProviderName,
                            recoveryOrder, StartupProviderMeasurementTimeout, token)
                            .GetAwaiter().GetResult();
                        var aliveCount = measured.Count(candidate => candidate.Alive && candidate.DelayMs is > 0);
                        Program.LiveTrace($"runtime-mihomo-cutover-remeasured alive={aliveCount} total={measured.Count}");
                        if (aliveCount == 0) throw new ServiceFailure("BF-SOURCE-ALL-CANDIDATES-DEAD");
                        group = fixedCandidate is null
                            ? controller.WaitForFirstUsableAutomaticGroupAsync(package.ActiveGroup, package.ProviderName,
                                package.AllowedCandidates, StartupGroupSelectionTimeout, token).GetAwaiter().GetResult()
                            : controller.WaitForHealthyGroupAsync(package.ActiveGroup, package.ProviderName,
                                package.AllowedCandidates, StartupGroupSelectionTimeout, token, fixedCandidate).GetAwaiter().GetResult();
                        group = MergeMeasuredCandidateHealth(group, measured);
                        Program.LiveTrace($"runtime-mihomo-cutover-reselected candidate={group.Now}");
                    }
                    return false;
                },
                cancellationToken);
            Program.LiveTrace("runtime-mihomo-handover-committed");

            // Commit DNS only after the core and host route path work. The
            // owned adapter has a lower metric than the physical LAN; Windows
            // then uses Mihomo's signed DNS policy instead of leaking queries
            // and unusable AAAA answers through a more specific router route.
            tunDns = new OwnedTunDns(interfaceIndex);
            tunDns.Install();
            Program.LiveTrace("runtime-mihomo-dns-committed");

            if (qualityRuntime.Port > 0)
            {
                qualityOptimizer = new MihomoQualityOptimizer(qualityRuntime, controllerUri, controllerSecret, Program.LiveTrace,
                    candidate => RememberOptimizedCandidate(memoryKey, candidate));
                Program.LiveTrace("runtime-mihomo-quality-observer-active");
            }

            _mihomoSupervisor = supervisor;
            _mihomoIdentity = identity;
            _mihomoController = controller;
            _mihomoQualityOptimizer = qualityOptimizer;
            qualityOptimizer = null;
            _mihomoGroup = group;
            _mihomoChatGptGroupName = package.ChatGptGroupName;
            _mihomoChatGptCandidate = chatGptCandidate;
            _mihomoProviderName = package.ProviderName;
            _mihomoAllowedCandidates = package.AllowedCandidates.ToHashSet(StringComparer.OrdinalIgnoreCase);
            _mihomoFixedCandidate = fixedCandidate;
            _mihomoTunInterfaceIndex = interfaceIndex;
            _lastMihomoReadbackAt = DateTime.UtcNow;
            _mihomoHandover = handover;
            _mihomoDns = tunDns;
            _core = process;
            _coreName = "mihomo";
            _mode = mode; _configId = configId; _source = source; _country = country; _appPolicy = appPolicy;
            _appPolicyDigest = resolved.ApplicationPolicyDigest; _appPolicyGeneration = resolved.ApplicationPolicyGeneration;
            _effectiveCore = "mihomo"; _applicationPolicySnapshot = verifiedPolicy;
            _healthEndpoint = new Uri($"tcp://127.0.0.1:{dataPlaneProbe.ProxyPort}");
            _dataPlaneProbe = dataPlaneProbe; _lastDataPlaneProbeAt = DateTime.MinValue;
            _lastDataPlaneProbeHealthy = false; _lastDataPlaneProbeCode = null; _consecutiveDataPlaneProbeFailures = 0;
            _selectedCandidateTransientUnhealthy = false;
            _coexistMode = OwnedTunNetworkBoundary.HasCompetingDefaultTunnel();
            supervisor = null!; controller = null; handover = null; tunDns = null; process = null;
        }
        catch (InvalidDataException failure) { throw new ServiceFailure(failure.Message); }
        finally
        {
            if (startupParallel is not null)
            {
                try { startupParallel.Cancel(); } catch { }
                if (tunReady is not null) { try { tunReady.GetAwaiter().GetResult(); } catch { } }
                if (canaryReady is not null) { try { canaryReady.GetAwaiter().GetResult(); } catch { } }
                startupParallel.Dispose();
            }
            tunDns?.Dispose();
            qualityOptimizer?.Dispose();
            if (handover is not null) { try { handover.RollbackAndVerify(); } catch { } handover.Dispose(); }
            controller?.Dispose();
            if (identity is not null && supervisor is not null) { try { supervisor.StopConfirmed(identity, TimeSpan.FromSeconds(5)); } catch { } }
            supervisor?.Dispose();
            process?.Dispose();
        }
    }

    private bool IsCoreHealthyLocked()
    {
        if (_effectiveCore != "mihomo" || _mihomoSupervisor is null || _mihomoIdentity is null || _mihomoGroup is null ||
            !_mihomoSupervisor.IsExactProcessAlive(_mihomoIdentity) || !OwnedTunNetworkBoundary.HasExactTun() ||
            _mihomoDns is null || !_mihomoDns.IsBound || _healthEndpoint is null ||
            (DateTime.UtcNow - _lastMihomoReadbackAt >= TimeSpan.FromMilliseconds(750) && !IsReady(_healthEndpoint))) return false;
        return _mihomoGroup.Candidates.Any(candidate =>
            candidate.Alive && string.Equals(candidate.Name, _mihomoGroup.Now, StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<int> WaitForOwnedTunInterfaceAsync(
        MihomoRuntimeSupervisor supervisor,
        MihomoRuntimeIdentity identity,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (timeout < TimeSpan.FromSeconds(1) || timeout > TimeSpan.FromSeconds(30))
            throw new ServiceFailure("BF-MIHOMO-TUN");
        using var timeoutCancellation = new CancellationTokenSource(timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCancellation.Token);
        try
        {
            while (true)
            {
                linked.Token.ThrowIfCancellationRequested();
                if (OwnedTunNetworkBoundary.TryGetExactTunInterfaceIndex(out var interfaceIndex)) return interfaceIndex;
                if (!supervisor.IsExactProcessAlive(identity)) throw new ServiceFailure("BF-MIHOMO-START");
                await Task.Delay(TimeSpan.FromMilliseconds(50), linked.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && timeoutCancellation.IsCancellationRequested)
        {
            throw new ServiceFailure("BF-MIHOMO-TUN");
        }
    }

    private static MihomoGroupState MergeMeasuredCandidateHealth(
        MihomoGroupState group,
        IReadOnlyList<MihomoProxyHealth> measured)
    {
        var measurements = measured.ToDictionary(candidate => candidate.Name, StringComparer.OrdinalIgnoreCase);
        var candidates = group.Candidates.Select(candidate =>
        {
            if (candidate.Alive && candidate.DelayMs is > 0) return candidate;
            return measurements.TryGetValue(candidate.Name, out var measurement) &&
                   measurement.Alive && measurement.DelayMs is > 0
                ? new MihomoProxyHealth(candidate.Name, true, measurement.DelayMs)
                : candidate;
        }).ToArray();
        return group with { Candidates = candidates };
    }

    private void RefreshMihomoReadbackLocked(bool force)
    {
        if (_effectiveCore != "mihomo" || _mihomoController is null || _mihomoGroup is null ||
            string.IsNullOrWhiteSpace(_mihomoProviderName) || _mihomoAllowedCandidates is null) return;
        var now = DateTime.UtcNow;
        if (!force && now - _lastMihomoReadbackAt < TimeSpan.FromMilliseconds(750)) return;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(700));
            var readback = _mihomoController.ReadMonitoredGroupAsync(_mihomoGroup.Name, _mihomoProviderName,
                    _mihomoAllowedCandidates, deadline.Token, force, fixedCandidate: _mihomoFixedCandidate)
                .GetAwaiter().GetResult();
            if (!_mihomoAllowedCandidates.Contains(readback.Now) ||
                !readback.Candidates.Select(candidate => candidate.Name).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(_mihomoAllowedCandidates))
                throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
            var selectedCandidateHealthy = readback.Candidates.Any(candidate => candidate.Alive &&
                string.Equals(candidate.Name, readback.Now, StringComparison.OrdinalIgnoreCase));
            if (!selectedCandidateHealthy)
            {
                // URLTest can expose its previous `now` as unhealthy for a
                // short interval while it promotes another already measured
                // member. Keep the last strictly healthy source-scoped
                // readback during that handoff instead of turning a same-core
                // member switch into BF-CORE-NOT-READY and a TUN restart.
                // The independently probed host data plane remains
                // authoritative and tears down after its bounded consecutive
                // failure threshold (or immediately if owned routes vanish).
                _lastMihomoReadbackAt = now;
                _selectedCandidateTransientUnhealthy = true;
                Program.LiveTrace($"runtime-mihomo-readback-transient-unhealthy candidate={readback.Now}");
                return;
            }
            _selectedCandidateTransientUnhealthy = false;
            _mihomoGroup = readback;
            RefreshChatGptAffinityLocked(readback, deadline.Token);
            _lastMihomoReadbackAt = now;
        }
        catch (OperationCanceledException) { }
        catch (InvalidDataException failure)
        {
            Program.LiveTrace($"runtime-mihomo-readback-failed code={failure.Message}");
        }
    }

    private void RefreshChatGptAffinityLocked(MihomoGroupState smartReadback, CancellationToken cancellationToken)
    {
        if (_mihomoController is null || string.IsNullOrWhiteSpace(_mihomoChatGptGroupName) ||
            string.IsNullOrWhiteSpace(_mihomoProviderName) || _mihomoAllowedCandidates is null) return;

        var affinity = _mihomoController.ReadMonitoredGroupAsync(_mihomoChatGptGroupName, _mihomoProviderName,
                _mihomoAllowedCandidates, cancellationToken, pinnedCandidate: _mihomoChatGptCandidate)
            .GetAwaiter().GetResult();
        var names = affinity.Candidates.Select(candidate => candidate.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!names.SetEquals(_mihomoAllowedCandidates)) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");

        static bool Healthy(MihomoGroupState state, string? candidate) =>
            !string.IsNullOrWhiteSpace(candidate) && state.Candidates.Any(item => item.Alive && item.DelayMs is > 0 &&
                string.Equals(item.Name, candidate, StringComparison.OrdinalIgnoreCase));

        var expected = _mihomoChatGptCandidate;
        if (Healthy(affinity, expected))
        {
            if (!string.Equals(affinity.Now, expected, StringComparison.OrdinalIgnoreCase))
            {
                // Reassert a still-healthy pin if another controller action
                // cleared the non-selector group's fixed field. This keeps
                // latency probes from silently changing the authenticated
                // OpenAI service egress.
                _mihomoController.SelectAsync(_mihomoChatGptGroupName, expected!, cancellationToken).GetAwaiter().GetResult();
                affinity = _mihomoController.ReadMonitoredGroupAsync(_mihomoChatGptGroupName, _mihomoProviderName,
                        _mihomoAllowedCandidates, cancellationToken)
                    .GetAwaiter().GetResult();
                if (!string.Equals(affinity.Now, expected, StringComparison.OrdinalIgnoreCase) || !Healthy(affinity, expected))
                    throw new InvalidDataException("BF-MIHOMO-GROUP");
                Program.LiveTrace($"runtime-mihomo-openai-affinity-restored candidate={expected}");
            }
            return;
        }

        // If Fallback has already promoted a healthy member after the pinned
        // one failed, accept that single failure-driven transition and pin the
        // promoted member. Otherwise choose from the same signed provider
        // cohort, preferring the ordinary smart group's healthy winner.
        string? replacement = Healthy(affinity, affinity.Now) ? affinity.Now : null;
        if (replacement is null && Healthy(affinity, smartReadback.Now)) replacement = smartReadback.Now;
        if (replacement is null)
            replacement = affinity.Candidates.Where(candidate => candidate.Alive && candidate.DelayMs is > 0)
                .Select(candidate => candidate.Name).FirstOrDefault();
        if (string.IsNullOrWhiteSpace(replacement)) throw new InvalidDataException("BF-SOURCE-ALL-CANDIDATES-DEAD");

        _mihomoController.SelectAsync(_mihomoChatGptGroupName, replacement, cancellationToken).GetAwaiter().GetResult();
        affinity = _mihomoController.ReadMonitoredGroupAsync(_mihomoChatGptGroupName, _mihomoProviderName,
                _mihomoAllowedCandidates, cancellationToken)
            .GetAwaiter().GetResult();
        if (!string.Equals(affinity.Now, replacement, StringComparison.OrdinalIgnoreCase) || !Healthy(affinity, replacement))
            throw new InvalidDataException("BF-MIHOMO-GROUP");
        _mihomoChatGptCandidate = replacement;
        Program.LiveTrace($"runtime-mihomo-openai-failover candidate={replacement}");
    }

    private ServiceStatus ConnectedStatusLocked(string core, string mode, string? configId, string source, EnforcementSummary summary)
    {
        MihomoRuntimeReadback? mihomo = null;
        if (core == "mihomo")
        {
            if (_mihomoGroup is null || _mihomoIdentity is null || _mihomoAllowedCandidates is null ||
                _mihomoTunInterfaceIndex <= 0 || !_mihomoAllowedCandidates.Contains(_mihomoGroup.Now))
            {
                Program.LiveTrace("runtime-connected-readback-invalid identity-or-group");
                return ServiceStatus.Blocked("BF-MIHOMO-READBACK");
            }
            var candidates = _mihomoGroup.Candidates
                .OrderBy(candidate => candidate.Name, StringComparer.Ordinal)
                .Select(candidate =>
                {
                    // Mihomo may mark a proxy alive just before its first
                    // health history sample is committed. Do not emit the
                    // contradictory alive=true/delay=null IPC shape; it is a
                    // startup snapshot, not a usable measured candidate yet.
                    var measuredAlive = candidate.Alive && candidate.DelayMs is > 0;
                    return new MihomoCandidateReadback(candidate.Name, measuredAlive,
                        measuredAlive ? candidate.DelayMs : null);
                })
                .ToArray();
            if (!candidates.Select(candidate => candidate.Name).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(_mihomoAllowedCandidates) ||
                !candidates.Any(candidate => candidate.Alive && string.Equals(candidate.Name, _mihomoGroup.Now, StringComparison.OrdinalIgnoreCase)))
            {
                Program.LiveTrace($"runtime-connected-readback-invalid candidate={_mihomoGroup.Now} measured-alive={candidates.Count(candidate => candidate.Alive)}");
                return ServiceStatus.Blocked("BF-MIHOMO-READBACK");
            }
            mihomo = new MihomoRuntimeReadback(_mihomoGroup.Name, _mihomoGroup.Now, candidates,
                _mihomoIdentity.ProcessId, _mihomoTunInterfaceIndex);
        }
        return ServiceStatus.ConnectedState(core, mode, configId, source, summary, mihomo);
    }

    private sealed record ServiceControlledPackage(string ConnectionType, string Core) : IControlledPackage;

    private sealed class ServiceCoreAdapter : IControlledCoreAdapter
    {
        private readonly CoreRuntime _owner; private readonly ClientPackageResolved _resolved; private readonly string _mode, _core, _configId, _source, _country, _appPolicy; private readonly ApplicationPolicySnapshot _policy; private readonly Uri _health; private readonly DataPlaneProbeTarget _probe; private readonly CancellationToken _cancellationToken;
        public ServiceCoreAdapter(CoreRuntime owner, ClientPackageResolved resolved, string mode, string core, string configId, string source, string country, string appPolicy, ApplicationPolicySnapshot policy, Uri health, DataPlaneProbeTarget probe, CancellationToken cancellationToken) { _owner = owner; _resolved = resolved; _mode = mode; _core = core; _configId = configId; _source = source; _country = country; _appPolicy = appPolicy; _policy = policy; _health = health; _probe = probe; _cancellationToken = cancellationToken; }
        public bool Start(IControlledPackage package)
        {
            if (package is not ServiceControlledPackage controlled)
                throw new ServiceFailure("BF-CONNECTION-TYPE");
            _owner.StartCoreProcessesLocked(_resolved, _mode, _core, controlled.ConnectionType, _configId, _source,
                _country, _appPolicy, _policy, _health, _probe, _cancellationToken);
            return true;
        }
        public bool IsHealthy
        {
            get
            {
                var healthy = _owner.IsCoreHealthyLocked();
                Program.LiveTrace($"runtime-core-startup-health healthy={healthy}");
                return healthy;
            }
        }
        public bool Stop() => _owner.StopCoreLocked();
    }

    private sealed class ServiceBoundaryAdapter : IControlledNetworkBoundary
    {
        private readonly CoreRuntime _owner;
        private readonly CancellationToken _cancellationToken;
        public ServiceBoundaryAdapter(CoreRuntime owner, CancellationToken cancellationToken) { _owner = owner; _cancellationToken = cancellationToken; }
        public bool EnterFailClosed() => _owner.EnterFailClosedLocked();
        public bool Activate() => _owner.ActivateBoundaryLocked(_cancellationToken);
        public bool IsBound => _owner.IsBoundaryBoundLocked();
        public bool Release() => _owner.RemoveBoundaryLocked();
    }

    private static string ResolveLockedBinary(string requestedCore)
    {
        if (!string.Equals(requestedCore, "mihomo", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("unsupported core binary");
        const string normalized = "mihomo.exe";
        var packageRoot = AppContext.BaseDirectory;
        var packaged = new[] { Path.Combine(packageRoot, "cores", normalized), Path.Combine(packageRoot, normalized) };
        foreach (var candidate in packaged)
            if (File.Exists(candidate)) return VerifyPackagedCore(candidate);
        throw new FileNotFoundException($"packaged {requestedCore} core binary is missing");
    }

    private static string VerifyPackagedCore(string path)
    {
        if (!OperatingSystem.IsWindows() || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("core binary must be a Windows executable");
        var manifest = Path.Combine(Path.GetDirectoryName(path)!, "CORE-MANIFEST.json");
        if (File.Exists(manifest))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
            var name = Path.GetFileName(path);
            var entry = doc.RootElement.TryGetProperty("artifacts", out var artifacts) && artifacts.ValueKind == JsonValueKind.Array
                ? artifacts.EnumerateArray().FirstOrDefault(x => string.Equals(x.TryGetProperty("path", out var p) ? p.GetString() : null, name, StringComparison.OrdinalIgnoreCase))
                : default;
            var expected = entry.ValueKind != JsonValueKind.Undefined && entry.TryGetProperty("sha256", out var hash) ? hash.GetString() : null;
            if (string.IsNullOrWhiteSpace(expected)) throw new InvalidOperationException($"core manifest has no digest for {name}");
            var fileInfo = new FileInfo(path);
            var cacheKey = Path.GetFullPath(path) + "|" + expected.ToLowerInvariant();
            if (VerifiedCoreArtifacts.TryGetValue(cacheKey, out var cached) &&
                cached.Length == fileInfo.Length && cached.LastWriteTicks == fileInfo.LastWriteTimeUtc.Ticks)
                return path;
            using var stream = File.OpenRead(path);
            var actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
            if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException($"core digest mismatch: {name}");
            fileInfo.Refresh();
            VerifiedCoreArtifacts[cacheKey] = (fileInfo.Length, fileInfo.LastWriteTimeUtc.Ticks);
        }
        else throw new InvalidOperationException("signed core manifest is missing");
        return path;
    }

    private static MihomoCompiledPackage LoadMihomoPackage(ClientPackageResolved resolved)
    {
        var main = BifrostIpcWire.ReadBoundedFile(resolved.MainConfigPath, 1024 * 1024);
        var provider = BifrostIpcWire.ReadBoundedFile(resolved.ProviderConfigPath, 1024 * 1024);
        try
        {
            using var mainDocument = JsonDocument.Parse(main);
            using var providerDocument = JsonDocument.Parse(provider);
            var providers = mainDocument.RootElement.GetProperty("proxy-providers");
            var providerEntries = providers.EnumerateObject().ToArray();
            if (providerEntries.Length != 1) throw new ServiceFailure("BF-MIHOMO-PROVIDER");
            var groups = mainDocument.RootElement.GetProperty("proxy-groups");
            if (groups.ValueKind != JsonValueKind.Array || groups.GetArrayLength() is < 1 or > 2)
                throw new ServiceFailure("BF-MIHOMO-GROUP");
            var activeGroup = groups[0].GetProperty("name").GetString() ?? throw new ServiceFailure("BF-MIHOMO-GROUP");
            var chatGptGroupName = groups.GetArrayLength() == 2
                ? groups[1].GetProperty("name").GetString() ?? throw new ServiceFailure("BF-MIHOMO-GROUP")
                : null;
            var proxies = providerDocument.RootElement.GetProperty("proxies");
            // Provider array order is part of the signed/configured candidate
            // quality ranking.  Preserve it across staging -> LocalSystem
            // reload; converting straight to a HashSet used to discard that
            // order, forcing the throughput optimizer to fall back to stable
            // identifier/alphabetical exploration after every real install.
            var preferredCandidates = proxies.EnumerateArray()
                .Select(item => item.GetProperty("name").GetString() ?? string.Empty)
                .ToArray();
            var candidates = preferredCandidates.ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (candidates.Count is < 1 or > 600 || candidates.Any(string.IsNullOrWhiteSpace))
                throw new ServiceFailure("BF-MIHOMO-PROVIDER");
            try { MihomoConfigValidator.ValidateStaged(main, provider, resolved.Source, resolved.Mode, resolved.ApplicationPolicySnapshot); }
            catch (InvalidDataException failure) { throw new ServiceFailure(failure.Message); }
            var combined = new byte[main.Length + provider.Length];
            try
            {
                main.CopyTo(combined, 0); provider.CopyTo(combined, main.Length);
                return new MihomoCompiledPackage(main.ToArray(), provider.ToArray(), providerEntries[0].Name, activeGroup,
                    candidates, Convert.ToHexString(SHA256.HashData(combined)).ToLowerInvariant(), chatGptGroupName,
                    preferredCandidates);
            }
            finally { CryptographicOperations.ZeroMemory(combined); }
        }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure("BF-MIHOMO-CONFIG"); }
        finally { CryptographicOperations.ZeroMemory(main); CryptographicOperations.ZeroMemory(provider); }
    }

    private static (Uri Controller, string Secret, int MixedPort) ReadMihomoControllerConfig(byte[] mainConfig)
    {
        try
        {
            using var document = JsonDocument.Parse(mainConfig);
            var root = document.RootElement;
            var controller = root.GetProperty("external-controller").GetString() ?? string.Empty;
            var secret = root.GetProperty("secret").GetString() ?? string.Empty;
            var mixedPort = root.GetProperty("mixed-port").GetInt32();
            if (!controller.StartsWith("127.0.0.1:", StringComparison.Ordinal) ||
                !int.TryParse(controller["127.0.0.1:".Length..], out var controllerPort) || controllerPort is < 1024 or > 65535 ||
                mixedPort is < 1024 or > 65535 || mixedPort == controllerPort || secret.Length is < 32 or > 256)
                throw new ServiceFailure("BF-MIHOMO-CONTROLLER");
            return (new Uri($"http://127.0.0.1:{controllerPort}/"), secret, mixedPort);
        }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure("BF-MIHOMO-CONTROLLER"); }
    }

    private static Uri? ResolveMihomoHealthEndpoint(string config)
    {
        try
        {
            var bytes = File.ReadAllBytes(config);
            try { return new Uri($"tcp://127.0.0.1:{ReadMihomoControllerConfig(bytes).MixedPort}"); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        catch { return null; }
    }

    private static DataPlaneProbeTarget? ResolveMihomoDataPlaneProbeTarget(string config)
    {
        try
        {
            var bytes = File.ReadAllBytes(config);
            try { return new DataPlaneProbeTarget("www.gstatic.com", 443, "/generate_204", ReadMihomoControllerConfig(bytes).MixedPort); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        catch { return null; }
    }

    private static string HashFile(string path)
    {
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private sealed record DataPlaneProbeTarget(string ServerName, int Port, string Path, int ProxyPort);

    private bool TryRecoverAutomaticMihomoPathLocked(string diagnostic, CancellationToken cancellationToken = default)
    {
        if (string.Equals(diagnostic, "BF-TUN-ROUTE", StringComparison.Ordinal))
            return false;
        if (_effectiveCore != "mihomo" || _mihomoController is null || _mihomoGroup is null ||
            string.IsNullOrWhiteSpace(_mihomoProviderName) || _mihomoAllowedCandidates is null ||
            _mihomoFixedCandidate is not null || _dataPlaneProbe is null)
            return false;

        var previous = _mihomoGroup.Now;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(18));
        try
        {
            // DELETE on a URLTest group clears only its short-lived manual/
            // cached selection and lets Mihomo immediately choose from its
            // already measured provider members. It does not restart the core,
            // recreate Wintun, alter host routes, or touch another VPN.
            var recovered = _mihomoController.WaitForFirstUsableAutomaticGroupAsync(
                    _mihomoGroup.Name, _mihomoProviderName, _mihomoAllowedCandidates,
                    TimeSpan.FromSeconds(5), deadline.Token)
                .GetAwaiter().GetResult();
            _mihomoGroup = recovered;
            _lastMihomoReadbackAt = DateTime.UtcNow;
            _selectedCandidateTransientUnhealthy = false;
            Program.LiveTrace($"runtime-mihomo-inplace-reselected from={previous} to={recovered.Now} cause={diagnostic}");

            // A controller readback alone is not recovery evidence. Prove the
            // new path with the same real proxy data-plane probe that detected
            // the failure before preserving the existing TUN transaction.
            if (!IsDataPlaneHealthyLocked(force: true, deadline.Token))
            {
                Program.LiveTrace($"runtime-mihomo-inplace-recovery-failed candidate={recovered.Now} code={_lastDataPlaneProbeCode}");
                return false;
            }
            _lastRuntimeFailure = null;
            _lastRuntimeDiagnostic = null;
            Program.LiveTrace($"runtime-mihomo-inplace-recovery-succeeded candidate={recovered.Now}");
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Program.LiveTrace("runtime-mihomo-inplace-recovery-timeout");
            return false;
        }
        catch (Exception error)
        {
            Program.LiveTrace($"runtime-mihomo-inplace-recovery-error type={error.GetType().Name}");
            return false;
        }
    }

    private bool IsDataPlaneHealthyLocked(bool force, CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var probeInterval = _consecutiveDataPlaneProbeFailures > 0
            ? DataPlaneFailureRetryInterval
            : DataPlaneProbeInterval;
        if (!force && now - _lastDataPlaneProbeAt < probeInterval) return _lastDataPlaneProbeHealthy;
        DataPlaneProbeResult result;
        if (_dataPlaneProbe is not null && !force)
        {
            var observation = DataPlaneHealthPolicy.ProbeWithFallback(_preferredDataPlaneTarget,
                (index, budget, token) =>
                {
                    var target = _dataPlaneProbe with { ServerName = MihomoWindowsContract.DataPlaneProbeHosts[index] };
                    DataPlaneProbeResult checkedResult;
                    if (_coexistRoutes is null) checkedResult = ProbeDataPlane(target, token, budget);
                    else
                    {
                        if (!_coexistRoutes.HasFullTunnel || _coexistCanaryAddress is null)
                            return (false, "BF-TUN-ROUTE");
                        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                        deadline.CancelAfter(budget);
                        try
                        {
                            var address = index == 0 ? _coexistCanaryAddress : ResolveHostProbeAddress(target, deadline.Token);
                            checkedResult = ProbeHostDataPlane(address, target, deadline.Token, budget);
                        }
                        catch (OperationCanceledException) when (!token.IsCancellationRequested)
                        { return (false, "BF-TRANSPORT-PROBE-TIMEOUT"); }
                        catch (ServiceFailure failure) { return (false, failure.Code); }
                    }
                    return (checkedResult.Healthy, checkedResult.Code);
                }, cancellationToken);
            _preferredDataPlaneTarget = observation.Preferred;
            result = new DataPlaneProbeResult(observation.Healthy, observation.Code);
        }
        else if (_dataPlaneProbe is null)
        {
            result = new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-UNAVAILABLE");
        }
        else if (_coexistRoutes is not null)
        {
            // The loopback health proxy can remain healthy even if the
            // service-owned /1 routes disappeared and ordinary host traffic
            // silently fell back to the pre-Bifrost path. Connected status
            // therefore requires both route-transaction ownership and a probe
            // that originates as normal host traffic through those /1 routes.
            result = _coexistRoutes?.HasFullTunnel == true && _coexistCanaryAddress is not null
                ? ProbeHostDataPlane(_coexistCanaryAddress, _dataPlaneProbe, cancellationToken,
                    force ? CutoverDataPlaneProbeTimeout : SteadyStateDataPlaneProbeTimeout)
                : new DataPlaneProbeResult(false, "BF-TUN-ROUTE");
        }
        else
        {
            result = ProbeDataPlane(_dataPlaneProbe, cancellationToken,
                force ? StartupDataPlaneProbeTimeout : SteadyStateDataPlaneProbeTimeout);
        }
        _lastDataPlaneProbeAt = DateTime.UtcNow;
        if (result.Healthy)
        {
            _consecutiveDataPlaneProbeFailures = 0;
            _lastDataPlaneProbeHealthy = true;
            _lastDataPlaneProbeCode = null;
            return true;
        }
        _lastDataPlaneProbeCode = result.Code;
        _consecutiveDataPlaneProbeFailures++;
        if (_consecutiveDataPlaneProbeFailures == 1) _dataPlaneFailureStartedAt = Stopwatch.GetTimestamp();
        // Losing our exact /1 route transaction is authoritative and must
        // fail closed immediately. For the data plane itself, distinguish an
        // obvious reachability failure from softer protocol jitter. A second
        // additional signal from Mihomo that the selected candidate is
        // unhealthy also promotes the decision to the fast two-sample path.
        var routeOwnershipLost = string.Equals(result.Code, "BF-TUN-ROUTE", StringComparison.Ordinal);
        var fastFailure = _selectedCandidateTransientUnhealthy || IsFastDataPlaneFailure(result.Code);
        var failureThreshold = fastFailure ? DataPlaneFastFailureThreshold : DataPlaneFailureThreshold;
        Program.LiveTrace($"runtime-dataplane-miss code={result.Code} count={_consecutiveDataPlaneProbeFailures} threshold={failureThreshold} candidate-unhealthy={_selectedCandidateTransientUnhealthy}");
        if (DataPlaneHealthPolicy.ShouldDisconnect(_consecutiveDataPlaneProbeFailures,
            Stopwatch.GetElapsedTime(_dataPlaneFailureStartedAt), force, routeOwnershipLost, fastFailure, failureThreshold))
        {
            _lastDataPlaneProbeHealthy = false;
            return false;
        }
        // Startup never reaches this path without a strict success. During an
        // established connection keep the previous Connected state only long
        // enough for the one-second confirmation cadence above. Any successful
        // probe resets the counter and returns to the normal fifteen-second pace.
        _lastDataPlaneProbeHealthy = true;
        return true;
    }

    private sealed record DataPlaneProbeResult(bool Healthy, string Code);

    private static bool IsFastDataPlaneFailure(string code) => DataPlaneHealthPolicy.IsFastFailure(code);

    private static DataPlaneProbeResult ProbeDataPlane(DataPlaneProbeTarget target, CancellationToken cancellationToken = default, TimeSpan? timeout = null)
    {
        var stage = "TCP";
        var tlsPolicyErrors = SslPolicyErrors.None;
        var tlsChainFlags = System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.NoError;
        try
        {
            var probeBudget = timeout ?? DataPlaneProbeTimeout;
            if (probeBudget < TimeSpan.FromSeconds(1) || probeBudget > DataPlaneProbeTimeout) probeBudget = DataPlaneProbeTimeout;
            using var timeoutCancellation = new CancellationTokenSource(probeBudget);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(timeoutCancellation.Token, cancellationToken);
            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            tcp.ConnectAsync(IPAddress.Loopback, target.ProxyPort, cancellation.Token).AsTask().GetAwaiter().GetResult();

            stage = "PROXY";
            var stream = tcp.GetStream();
            var connectRequest = Encoding.ASCII.GetBytes($"CONNECT {target.ServerName}:{target.Port} HTTP/1.1\r\nHost: {target.ServerName}:{target.Port}\r\nProxy-Connection: keep-alive\r\n\r\n");
            stream.WriteAsync(connectRequest, cancellation.Token).AsTask().GetAwaiter().GetResult();
            stream.FlushAsync(cancellation.Token).GetAwaiter().GetResult();
            var header = new byte[4096];
            var headerLength = 0;
            while (headerLength < header.Length)
            {
                var proxyRead = stream.ReadAsync(header.AsMemory(headerLength, 1), cancellation.Token).AsTask().GetAwaiter().GetResult();
                if (proxyRead <= 0) break;
                headerLength += proxyRead;
                if (headerLength >= 4 && header[headerLength - 4] == '\r' && header[headerLength - 3] == '\n' &&
                    header[headerLength - 2] == '\r' && header[headerLength - 1] == '\n') break;
            }
            if (headerLength < 12) return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-PROXY");
            var connectPrefix = Encoding.ASCII.GetString(header, 0, Math.Min(headerLength, 32));
            if (!connectPrefix.StartsWith("HTTP/1.1 200", StringComparison.Ordinal) &&
                !connectPrefix.StartsWith("HTTP/1.0 200", StringComparison.Ordinal))
                return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-PROXY");

            stage = "TLS";
            using var tls = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, chain, errors) =>
            {
                tlsPolicyErrors = errors;
                if (chain is not null)
                    foreach (var status in chain.ChainStatus) tlsChainFlags |= status.Status;
                // Preserve strict platform validation. The callback exists only
                // to retain a bounded, non-sensitive failure category.
                return errors == SslPolicyErrors.None;
            });
            tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = target.ServerName,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                // This is a connectivity probe, not the trust boundary for
                // application traffic.  Online CRL/OCSP retrieval is performed
                // by the LocalSystem process outside this already-established
                // CONNECT stream and can be unreachable even when the selected
                // proxy path is fully usable (observed as a TLS timeout).  Keep
                // strict hostname + chain validation for the probe while leaving
                // revocation policy to the real application TLS stack.
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            }, cancellation.Token).GetAwaiter().GetResult();
            if (!tls.IsAuthenticated || !tls.IsEncrypted) return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-TLS");

            // A TLS handshake alone can still produce a false-positive when
            // certificate infrastructure or the proxied application stream is
            // unusable. Require a complete browser-style 204 exchange before
            // reporting Connected.
            stage = "HTTP";
            var request = Encoding.ASCII.GetBytes($"GET {target.Path} HTTP/1.1\r\nHost: {target.ServerName}\r\nConnection: close\r\nAccept: */*\r\n\r\n");
            tls.WriteAsync(request, cancellation.Token).AsTask().GetAwaiter().GetResult();
            tls.FlushAsync(cancellation.Token).GetAwaiter().GetResult();
            var healthy = DataPlaneHealthPolicy.Read204ResponseAsync(tls, cancellation.Token).GetAwaiter().GetResult();
            return healthy
                ? new DataPlaneProbeResult(true, "BF-OK")
                : new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-HTTP");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (stage == "TLS")
        {
            return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-TLS-TIMEOUT");
        }
        catch (System.Security.Authentication.AuthenticationException) when (stage == "TLS")
        {
            if ((tlsPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-TLS-NAME");
            if ((tlsPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
                return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-TLS-CERT");
            if ((tlsPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            {
                const System.Security.Cryptography.X509Certificates.X509ChainStatusFlags revocation =
                    System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.Revoked |
                    System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.RevocationStatusUnknown |
                    System.Security.Cryptography.X509Certificates.X509ChainStatusFlags.OfflineRevocation;
                return new DataPlaneProbeResult(false,
                    (tlsChainFlags & revocation) != 0
                        ? "BF-TRANSPORT-PROBE-TLS-REVOCATION"
                        : "BF-TRANSPORT-PROBE-TLS-CHAIN");
            }
            return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-TLS-HANDSHAKE");
        }
        catch when (stage == "TLS")
        {
            return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-TLS-HANDSHAKE");
        }
        catch
        {
            return new DataPlaneProbeResult(false, $"BF-TRANSPORT-PROBE-{stage}");
        }
    }

    private static IPAddress ResolveHostProbeAddress(DataPlaneProbeTarget target, CancellationToken cancellationToken)
    {
        try
        {
            var addresses = Dns.GetHostAddressesAsync(target.ServerName, cancellationToken).GetAwaiter().GetResult();
            return addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork)
                ?? throw new ServiceFailure("BF-TRANSPORT-PROBE-DNS");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (ServiceFailure) { throw; }
        catch { throw new ServiceFailure("BF-TRANSPORT-PROBE-DNS"); }
    }

    private static DataPlaneProbeResult ProbeHostDataPlane(IPAddress address, DataPlaneProbeTarget target,
        CancellationToken cancellationToken, TimeSpan timeout)
    {
        var stage = "TCP";
        try
        {
            using var timeoutCancellation = new CancellationTokenSource(timeout);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(timeoutCancellation.Token, cancellationToken);
            using var tcp = new TcpClient(AddressFamily.InterNetwork);
            tcp.ConnectAsync(address, target.Port, cancellation.Token).AsTask().GetAwaiter().GetResult();
            stage = "TLS";
            using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false,
                (_, _, _, errors) => errors == SslPolicyErrors.None);
            tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = target.ServerName,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
            }, cancellation.Token).GetAwaiter().GetResult();
            if (!tls.IsAuthenticated || !tls.IsEncrypted)
                return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-TLS");
            stage = "HTTP";
            var request = Encoding.ASCII.GetBytes($"GET {target.Path} HTTP/1.1\r\nHost: {target.ServerName}\r\nConnection: close\r\nAccept: */*\r\n\r\n");
            tls.WriteAsync(request, cancellation.Token).AsTask().GetAwaiter().GetResult();
            tls.FlushAsync(cancellation.Token).GetAwaiter().GetResult();
            return DataPlaneHealthPolicy.Read204ResponseAsync(tls, cancellation.Token).GetAwaiter().GetResult()
                ? new DataPlaneProbeResult(true, "BF-OK")
                : new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-HTTP");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return new DataPlaneProbeResult(false, $"BF-TRANSPORT-PROBE-{stage}-TIMEOUT"); }
        catch (System.Security.Authentication.AuthenticationException) { return new DataPlaneProbeResult(false, "BF-TRANSPORT-PROBE-TLS-HANDSHAKE"); }
        catch { return new DataPlaneProbeResult(false, $"BF-TRANSPORT-PROBE-{stage}"); }
    }

    private static bool IsReady(Uri endpoint, CancellationToken cancellationToken = default)
    {
        try
        {
            if (endpoint.Scheme.Equals("tcp", StringComparison.OrdinalIgnoreCase))
            {
                using var tcp = new TcpClient();
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(1));
                tcp.ConnectAsync(endpoint.Host, endpoint.Port, timeout.Token).AsTask().GetAwaiter().GetResult();
                return true;
            }
            using var response = LoopbackHealthClient.GetAsync(endpoint, HttpCompletionOption.ResponseHeadersRead, cancellationToken).GetAwaiter().GetResult();
            return (int)response.StatusCode is >= 200 and < 300;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return false; }
    }

    private static bool TryResolveLegacyInstallTombstoneCore(string processImage, out string tombstoneImage)
    {
        tombstoneImage = string.Empty;
        try
        {
            var fullImage = Path.GetFullPath(processImage);
            var coreName = Path.GetFileName(fullImage);
            if (coreName is not ("mihomo.exe" or "sing-box.exe")) return false;
            var coresRoot = Directory.GetParent(fullImage);
            var generationRoot = coresRoot?.Parent;
            var generationsRoot = generationRoot?.Parent;
            var legacyInstallRoot = generationsRoot?.Parent;
            if (coresRoot is null || generationRoot is null || generationsRoot is null || legacyInstallRoot is null ||
                !string.Equals(coresRoot.Name, "cores", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(generationsRoot.Name, ".bifrost-generations", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(legacyInstallRoot.Name, "Bifrost", StringComparison.OrdinalIgnoreCase)) return false;
            var generationName = generationRoot.Name;
            if (!generationName.StartsWith("g-", StringComparison.Ordinal) || generationName.Length is < 3 or > 128 ||
                generationName.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch is not '-' and not '_')) return false;

            // The original path must already have been renamed away. If a live
            // installation exists at that path, never infer ownership from its
            // shape; the normal immutable-generation ownership path handles it.
            if (Directory.Exists(legacyInstallRoot.FullName) || File.Exists(legacyInstallRoot.FullName)) return false;
            var volumeRoot = legacyInstallRoot.Parent;
            if (volumeRoot is null || !Directory.Exists(volumeRoot.FullName) ||
                (File.GetAttributes(volumeRoot.FullName) & FileAttributes.ReparsePoint) != 0) return false;

            string? matched = null;
            foreach (var staleRoot in Directory.EnumerateDirectories(volumeRoot.FullName, "Bifrost.uninstalling-*", SearchOption.TopDirectoryOnly))
            {
                var staleName = Path.GetFileName(staleRoot);
                var suffix = staleName["Bifrost.uninstalling-".Length..];
                if (!Guid.TryParseExact(suffix, "N", out _) ||
                    (File.GetAttributes(staleRoot) & FileAttributes.ReparsePoint) != 0) continue;
                var staleGenerations = Path.Combine(staleRoot, ".bifrost-generations");
                var staleGeneration = Path.Combine(staleGenerations, generationName);
                var staleCores = Path.Combine(staleGeneration, "cores");
                var candidate = Path.Combine(staleCores, coreName);
                if (!Directory.Exists(staleGenerations) || !Directory.Exists(staleGeneration) || !Directory.Exists(staleCores) || !File.Exists(candidate) ||
                    (File.GetAttributes(staleGenerations) & FileAttributes.ReparsePoint) != 0 ||
                    (File.GetAttributes(staleGeneration) & FileAttributes.ReparsePoint) != 0 ||
                    (File.GetAttributes(staleCores) & FileAttributes.ReparsePoint) != 0 ||
                    (File.GetAttributes(candidate) & FileAttributes.ReparsePoint) != 0) continue;
                if (matched is not null) return false;
                matched = Path.GetFullPath(candidate);
            }
            if (matched is null) return false;
            tombstoneImage = matched;
            return true;
        }
        catch { return false; }
    }

    private static bool CleanupOrphanedPackagedCores(out bool stoppedAny)
    {
        stoppedAny = false;
        if (!OperatingSystem.IsWindows()) return true;
        var packageRoot = Path.GetFullPath(AppContext.BaseDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var ownedImages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var historicalOwnedImages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in new[] { "mihomo.exe", "sing-box.exe" })
        {
            foreach (var candidate in new[] { Path.Combine(packageRoot, "cores", file), Path.Combine(packageRoot, file) })
            {
                try
                {
                    if (File.Exists(candidate)) ownedImages.Add(Path.GetFullPath(candidate));
                }
                catch { }
            }
        }

        // A crashed/force-stopped updater or validation generation can leave
        // its packaged core alive after the service binary has moved to a new
        // generation.  Restrict cross-generation ownership to the immutable
        // install generations tree and the exact packaged core locations;
        // never infer ownership from process name alone.  This deliberately
        // excludes independently installed v2rayN/Clash cores such as
        // H:\v2rayN\bin\sing_box\sing-box.exe.
        string? generationsRoot = null;
        try
        {
            var currentGeneration = new DirectoryInfo(packageRoot);
            var parent = currentGeneration.Parent;
            if (parent is not null && string.Equals(parent.Name, ".bifrost-generations", StringComparison.OrdinalIgnoreCase))
                generationsRoot = Path.GetFullPath(parent.FullName).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch { }

        if (generationsRoot is not null)
        {
            try
            {
                foreach (var generation in Directory.EnumerateDirectories(generationsRoot, "g-*", SearchOption.TopDirectoryOnly))
                {
                    var name = Path.GetFileName(generation);
                    if (name.Length is < 3 or > 128 || name.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch is not '-' and not '_'))
                        continue;
                    foreach (var coreName in new[] { "mihomo.exe", "sing-box.exe" })
                    {
                        var candidate = Path.Combine(generation, "cores", coreName);
                        if (File.Exists(candidate)) ownedImages.Add(Path.GetFullPath(candidate));
                    }
                }
            }
            catch { }
        }

        // The installer renames an old installation to
        // Bifrost.uninstalling-<guid> before deleting it. A core that survived
        // service teardown keeps its original image path in the process
        // table, while Restart Manager can still prove the lock against the
        // renamed file. Include only exact core files beneath that narrowly
        // named sibling tree so the new service can reap them safely.
        try
        {
            var installRoot = generationsRoot is null ? null : Directory.GetParent(generationsRoot)?.FullName;
            var volumeRoot = string.IsNullOrWhiteSpace(installRoot) ? null : Directory.GetParent(installRoot)?.FullName;
            if (!string.IsNullOrWhiteSpace(volumeRoot))
            {
                // A renamed uninstall tombstone can leave Windows reporting the pre-rename image path.
                // Treat that historical path as owned only while the original Bifrost root is absent.
                // If a new installation already occupies the original root, never infer ownership from shape alone.
                var preRenameRoot = Path.GetFullPath(Path.Combine(volumeRoot, "Bifrost"));
                var preRenameRootAbsent = false;
                try { _ = File.GetAttributes(preRenameRoot); }
                catch (FileNotFoundException) { preRenameRootAbsent = true; }
                catch (DirectoryNotFoundException) { preRenameRootAbsent = true; }
                catch { preRenameRootAbsent = false; }

                foreach (var staleRoot in Directory.EnumerateDirectories(volumeRoot, "Bifrost.uninstalling-*", SearchOption.TopDirectoryOnly))
                {
                    var staleName = Path.GetFileName(staleRoot);
                    var suffix = staleName["Bifrost.uninstalling-".Length..];
                    if (!Guid.TryParseExact(suffix, "N", out _) ||
                        (File.GetAttributes(staleRoot) & FileAttributes.ReparsePoint) != 0) continue;
                    var staleGenerations = Path.Combine(staleRoot, ".bifrost-generations");
                    if (!Directory.Exists(staleGenerations) ||
                        (File.GetAttributes(staleGenerations) & FileAttributes.ReparsePoint) != 0) continue;
                    foreach (var generation in Directory.EnumerateDirectories(staleGenerations, "g-*", SearchOption.TopDirectoryOnly))
                    {
                        var name = Path.GetFileName(generation);
                        if (name.Length is < 3 or > 128 || name.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch is not '-' and not '_')) continue;
                        foreach (var coreName in new[] { "mihomo.exe", "sing-box.exe" })
                        {
                            var candidate = Path.Combine(generation, "cores", coreName);
                            if (!File.Exists(candidate)) continue;
                            ownedImages.Add(Path.GetFullPath(candidate));
                            if (preRenameRootAbsent)
                            {
                                historicalOwnedImages.Add(Path.GetFullPath(Path.Combine(
                                    preRenameRoot, ".bifrost-generations", name, "cores", coreName)));
                            }
                        }
                    }
                }
            }
        }
        catch { }

        // A custom-drive installation can later be migrated to Program Files.
        // In that case the old process table still reports the pre-rename image
        // (for example E:\Bifrost\.bifrost-generations\g-*\cores\mihomo.exe),
        // while the actual locked file lives in E:\Bifrost.uninstalling-<guid>.
        // Resolve that one exact legacy path from each running core image and
         // register the corresponding tombstone file with Restart Manager. The
        // image shape alone is never sufficient: the original Bifrost root must
        // be absent and exactly one GUID tombstone must contain the same
        // generation/core path.
        foreach (var name in new[] { "mihomo", "sing-box" })
        {
            Process[] processes;
            try { processes = Process.GetProcessesByName(name); }
            catch { continue; }
            foreach (var process in processes)
            {
                try
                {
                    var image = Program.TryGetProcessImagePath(process.Id);
                    if (string.IsNullOrWhiteSpace(image) ||
                        !TryResolveLegacyInstallTombstoneCore(image, out var tombstoneImage)) continue;
                    historicalOwnedImages.Add(Path.GetFullPath(image));
                    ownedImages.Add(tombstoneImage);
                }
                finally { try { process.Dispose(); } catch { } }
            }
        }

        bool IsOwnedGenerationCore(string fullImage)
        {
            if (ownedImages.Contains(fullImage) || historicalOwnedImages.Contains(fullImage)) return true;
            if (string.IsNullOrWhiteSpace(generationsRoot)) return false;
            try
            {
                var full = Path.GetFullPath(fullImage);
                var rootPrefix = generationsRoot + Path.DirectorySeparatorChar;
                if (!full.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase)) return false;
                var relative = Path.GetRelativePath(generationsRoot, full);
                var parts = relative.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 3 || !parts[0].StartsWith("g-", StringComparison.Ordinal) ||
                    parts[0].Length is < 3 or > 128 || parts[0].Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch is not '-' and not '_') ||
                    !string.Equals(parts[1], "cores", StringComparison.OrdinalIgnoreCase) ||
                    parts[2] is not ("mihomo.exe" or "sing-box.exe"))
                    return false;
                return true;
            }
            catch { return false; }
        }

        if (ownedImages.Count == 0 && generationsRoot is null) return true;

        var stoppedAll = true;
        // Query Restart Manager for processes holding the exact immutable core
        // files. Windows can deny QueryFullProcessImageName even to the
        // LocalSystem service for detached historical processes; a registered
        // file lock remains an exact ownership proof and avoids ever killing a
        // same-named core from v2rayN/Clash outside Bifrost's generations.
        var lockingProcessIds = Program.GetLockingProcessIds(ownedImages);
        foreach (var name in new[] { "mihomo", "sing-box" })
        {
            Process[] processes;
            try { processes = Process.GetProcessesByName(name); }
            catch { continue; }
            foreach (var process in processes)
            {
                var image = Program.TryGetProcessImagePath(process.Id);
                var exactLockOwner = lockingProcessIds.Contains(process.Id);
                string? fullImage = null;
                if (!string.IsNullOrWhiteSpace(image))
                {
                    try { fullImage = Path.GetFullPath(image); }
                    catch { }
                }
                if (!exactLockOwner && (fullImage is null || !IsOwnedGenerationCore(fullImage)))
                {
                    // In particular, v2rayN's independently installed
                    // sing-box/xray binaries are never considered ours.
                    try { process.Dispose(); } catch { }
                    continue;
                }
                stoppedAny = true;
                if (!StopProcess(process)) stoppedAll = false;
            }
        }
        return stoppedAll;
    }

    private void RecoverOrphanedPackagedCoresLocked(string phase)
    {
        // If a prior service died after committing its active-store /1 routes,
        // remove only Bifrost's exact reserved-interface routes before touching
        // the packaged core.  Third-party VPN/TUN interfaces are never selected.
        if (OwnedTunNetworkBoundary.TryGetExactTunInterfaceIndex(out var staleTunIndex))
        {
            Program.LiveTrace($"runtime-{phase}-stale-tun index={staleTunIndex}");
            if (!OwnedTunDns.Recover(staleTunIndex)) throw new ServiceFailure("BF-TUN-DNS-RESTORE");
            OwnedTunRouteCommit.RemoveKnownFullTunnelRoutesBestEffort(staleTunIndex);
        }
        if (!CleanupOrphanedPackagedCores(out var stoppedAny))
            throw new ServiceFailure("BF-CORE-BLOCKED-STOP-UNCONFIRMED");
        if (stoppedAny)
        {
            _lastCoreTeardownAt = DateTime.UtcNow;
            Program.LiveTrace($"runtime-{phase}-orphaned-core-stopped");
        }
        if (OwnedTunNetworkBoundary.HasExactTun() && !_ensureOwnedTunInactive())
            throw new ServiceFailure("BF-CONNECTION-TEARDOWN");
        RemoveStaleOwnedWintunDeviceBestEffort(phase);
    }

    private bool StopCoreLocked()
    {
        var process = _core;
        var transport = _transport;
        var hadRuntime = process is not null || transport is not null || _mihomoSupervisor is not null;
        // Stop the background throughput selector before routes, DNS or the
        // core are torn down so it cannot race teardown with a late switch.
        _mihomoQualityOptimizer?.Dispose();
        _mihomoQualityOptimizer = null;
        // Release the resolver while its TUN peer is still alive, before
        // removing routes or stopping the core. Recovery also handles a prior
        // service exit after DNS commit, using only the exact reserved adapter.
        var dnsRestored = _mihomoDns?.Restore() ?? true;
        if (dnsRestored) { _mihomoDns?.Dispose(); _mihomoDns = null; }
        // Restore the host route table before touching the core process. This
        // makes disconnect/failure return traffic to the pre-existing VPN as
        // the first teardown action instead of waiting for Wintun/PnP cleanup.
        var routesRemoved = _coexistRoutes?.RemoveAll() ?? true;
        if (routesRemoved)
        {
            _coexistRoutes?.Dispose(); _coexistRoutes = null;
            _coexistCanaryAddress = null;
        }
        if (_mihomoHandover is not null)
        {
            try
            {
                _mihomoHandover.RollbackAndVerify();
                _mihomoHandover.Dispose(); _mihomoHandover = null;
            }
            catch { routesRemoved = false; }
        }
        var mihomoStopped = true;
        if (_mihomoSupervisor is not null && _mihomoIdentity is not null)
        {
            try { _mihomoSupervisor.StopConfirmed(_mihomoIdentity, TimeSpan.FromSeconds(5)); }
            catch { mihomoStopped = false; }
        }
        _mihomoController?.Dispose(); _mihomoController = null;
        if (mihomoStopped)
        {
            _mihomoSupervisor?.Dispose(); _mihomoSupervisor = null;
            _mihomoIdentity = null;
        }
        _mihomoGroup = null;
        _mihomoProviderName = null; _mihomoAllowedCandidates = null; _mihomoTunInterfaceIndex = 0;
        _mihomoFixedCandidate = null;
        _lastMihomoReadbackAt = DateTime.MinValue;
        var coreStopped = StopProcess(process);
        var transportStopped = StopProcess(transport);
        // Keep failed DNS/route leases for a later retry, but never keep a
        // disposed Process as if it were still running. TUN removal can lag
        // behind process exit; retrying that handle otherwise fails forever.
        if (coreStopped) _core = null;
        if (transportStopped) _transport = null;
        if (!dnsRestored || !routesRemoved || !mihomoStopped || !coreStopped || !transportStopped)
        {
            _ = _ensureOwnedTunInactive();
            return false;
        }
        if (hadRuntime) _lastCoreTeardownAt = DateTime.UtcNow;
        if (!_ensureOwnedTunInactive()) return false;
        _core = null;
        _transport = null;
        _coreName = null;
        _mode = null;
        _configId = null;
        _source = null;
        _country = null;
        _appPolicy = null;
        _appPolicyDigest = null;
        _appPolicyGeneration = null;
        _effectiveCore = null;
        _healthEndpoint = null;
        _dataPlaneProbe = null;
        _lastDataPlaneProbeAt = DateTime.MinValue;
        _lastDataPlaneProbeHealthy = false;
        _lastDataPlaneProbeCode = null;
        _consecutiveDataPlaneProbeFailures = 0;
        _selectedCandidateTransientUnhealthy = false;
        _mihomoChatGptGroupName = null;
        _mihomoChatGptCandidate = null;
        _coexistMode = false;
        _applicationPolicySnapshot = null;
        _enforcementSummary = null;
        return routesRemoved;
    }

    private void RememberOptimizedCandidate(string? key, string candidate)
    {
        if (key is null) return;
        _connectionMemory.Remember(key, candidate, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        Program.LiveTrace($"runtime-mihomo-optimized-memory-saved candidate={candidate}");
    }

    private static bool StopProcess(Process? process)
    {
        if (process is null) return true;
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(2000);
                if (!process.HasExited) return false;
            }
            process.Dispose();
            return true;
        }
        catch { return false; }
    }

    private static bool EnsureOwnedTunInactiveAfterStop()
    {
        if (!OwnedTunNetworkBoundary.HasExactTun()) return true;
        var deadline = DateTime.UtcNow.AddMilliseconds(600);
        while (DateTime.UtcNow < deadline)
        {
            if (!OwnedTunNetworkBoundary.HasExactTun()) return true;
            Thread.Sleep(50);
        }

        // The process is already stopped at this point.  If Wintun/PnP still
        // leaves Bifrost's reserved adapter active, disable only that adapter
        // so its routes stop affecting the host immediately.  Never touch an
        // existing third-party TUN such as v2rayN's singbox_tun.
        if (!TryDisableOwnedTunInterface()) return false;
        deadline = DateTime.UtcNow.AddSeconds(2);
        while (DateTime.UtcNow < deadline)
        {
            if (!OwnedTunNetworkBoundary.HasExactTun()) return true;
            Thread.Sleep(50);
        }
        return !OwnedTunNetworkBoundary.HasExactTun();
    }

    private static bool TryDisableOwnedTunInterface()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            var netsh = Path.Combine(Environment.SystemDirectory, "netsh.exe");
            if (!File.Exists(netsh)) return false;
            var start = new ProcessStartInfo
            {
                FileName = netsh,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            start.ArgumentList.Add("interface");
            start.ArgumentList.Add("set");
            start.ArgumentList.Add("interface");
            start.ArgumentList.Add("name=" + MihomoWindowsContract.TunInterfaceName);
            start.ArgumentList.Add("admin=DISABLED");
            using var helper = Process.Start(start);
            if (helper is null) return false;
            if (!helper.WaitForExit(1500))
            {
                try { helper.Kill(entireProcessTree: true); } catch { }
                return false;
            }
            return helper.ExitCode == 0;
        }
        catch { return false; }
    }

    private static void RemoveStaleOwnedWintunDeviceBestEffort(string phase)
    {
        if (!OperatingSystem.IsWindows() || OwnedTunNetworkBoundary.HasExactTun()) return;
        try
        {
            const string networkClass = @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";
            using var root = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(networkClass, writable: false);
            if (root is null) return;
            var owned = new List<string>();
            foreach (var subKeyName in root.GetSubKeyNames())
            {
                using var connection = root.OpenSubKey(subKeyName + @"\Connection", writable: false);
                if (connection?.GetValue("Name") is not string name ||
                    !string.Equals(name, MihomoWindowsContract.TunInterfaceName, StringComparison.OrdinalIgnoreCase) ||
                    connection.GetValue("PnpInstanceID") is not string instanceId)
                    continue;
                const string wintunPrefix = @"SWD\Wintun\{";
                if (!instanceId.StartsWith(wintunPrefix, StringComparison.OrdinalIgnoreCase) ||
                    !instanceId.EndsWith('}') ||
                    !Guid.TryParse(instanceId[wintunPrefix.Length..^1], out _))
                    continue;
                owned.Add(instanceId);
            }
            if (owned.Count != 1)
            {
                if (owned.Count > 1) Program.LiveTrace($"runtime-{phase}-stale-wintun-ambiguous count={owned.Count}");
                return;
            }

            // Wintun can leave a non-present SWD device whose connection name
            // is still bifrost1.  Mihomo then spends roughly one full adapter
            // creation timeout on "file already exists / element not found"
            // before its retry succeeds.  At this point the exact bifrost1
            // interface is absent and all packaged cores have been stopped, so
            // removing only that registry-bound Wintun instance cannot touch
            // singbox_tun, Tailscale, or another active adapter.
            var pnputil = Path.Combine(Environment.SystemDirectory, "pnputil.exe");
            if (!File.Exists(pnputil)) return;
            var start = new ProcessStartInfo
            {
                FileName = pnputil,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            start.ArgumentList.Add("/remove-device");
            start.ArgumentList.Add(owned[0]);
            using var helper = Process.Start(start);
            if (helper is null) return;
            if (!helper.WaitForExit(5000))
            {
                try { helper.Kill(entireProcessTree: true); } catch { }
                Program.LiveTrace($"runtime-{phase}-stale-wintun-cleanup timeout=True");
                return;
            }
            Program.LiveTrace($"runtime-{phase}-stale-wintun-cleanup exit={helper.ExitCode}");
        }
        catch
        {
            Program.LiveTrace($"runtime-{phase}-stale-wintun-cleanup failed=True");
        }
    }

    private bool RemoveBoundaryLocked()
    {
        _boundaryState.Retire(_networkBoundary);
        if (_boundaryState.Phase != NetworkBoundaryPhase.Idle) return false;
        _boundaryIntent = null;
        return true;
    }

    private bool IsSummaryCurrent(ApplicationPolicySnapshot policy, string mode, string core, string? configId)
    {
        var intent = _boundaryIntent;
        var evidence = _boundaryState.Evidence;
        var summary = _enforcementSummary;
        return summary is not null && intent is not null && evidence is not null &&
            summary.Route == mode && intent.Core == core && intent.ConfigId == configId &&
            EnforcementSummaryValidator.Matches(summary, policy, intent, evidence);
    }

    private static string MapError(Exception ex) => ex switch
    {
        ServiceFailure failure => failure.Code,
        ApplicationPolicyFailure failure => failure.Code,
        PlatformNotSupportedException => "BF-WFP-PLATFORM",
        FileNotFoundException => "BF-CORE-BINARY-MISSING",
        UnauthorizedAccessException => "BF-WFP-ACCESS",
        JsonException => "BF-IPC-JSON",
        IOException => "BF-SERVICE-IO",
        InvalidOperationException invalid when invalid.Message.StartsWith("BF-WFP-DRY-RUN", StringComparison.Ordinal) => "BF-WFP-DRY-RUN",
        _ => "BF-SERVICE-CONNECT"
    };
}
