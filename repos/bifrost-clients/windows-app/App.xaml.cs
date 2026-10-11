using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Bifrost.ClientService;
using Microsoft.Win32;

namespace Bifrost;

public partial class App : Application
{
    private DesktopInstanceLease? _desktopLease;
    public App()
    {
        UiLifecycleTrace.Write("process-start");
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            UiLifecycleTrace.Write("unhandled-fatal", args.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, args) =>
            UiLifecycleTrace.Write("unobserved-background-task", args.Exception);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _desktopLease?.Dispose(); _desktopLease = null;
        UiLifecycleTrace.Write("application-exit", exitCode: e.ApplicationExitCode);
        base.OnExit(e);
    }

    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        UiLifecycleTrace.Write("windows-session-ending");
        base.OnSessionEnding(e);
    }

#if !BIFROST_INTERNAL_LIVE_VALIDATION
    protected override void OnStartup(StartupEventArgs e)
    {
        if (!BifrostBuildConstants.LocalEvaluation)
        {
            try
            {
                var root = BifrostIpcWire.ResolveInstallRootFromGenerationDirectory(AppContext.BaseDirectory);
                RetirePreviousDesktopGeneration(root);
                _desktopLease = DesktopInstanceLease.Acquire(root);
                if (!_desktopLease.IsOwner)
                {
                    DesktopInstanceLease.RaiseExisting(Environment.ProcessPath!);
                    Shutdown(0);
                    return;
                }
            }
            catch (InvalidDataException error) when (string.Equals(error.Message, "BF-INSTALL-LAYOUT", StringComparison.Ordinal))
            {
                var launcher = TryGetRegisteredLauncher();
                if (launcher is not null)
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = launcher,
                        WorkingDirectory = Path.GetDirectoryName(launcher)!,
                        UseShellExecute = true,
                    });
                    Shutdown(0);
                    return;
                }
                MessageBox.Show(
                    "当前文件只是 Bifrost 发布包内部组件，不能作为独立软件更新。请运行唯一的 Bifrost Offline Setup 安装包；安装后从桌面 Bifrost 快捷方式启动。",
                    "Bifrost", MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown(2);
                return;
            }
        }
        base.OnStartup(e);
    }

    private static string? TryGetRegisteredLauncher()
    {
        try
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Bifrost", false);
            var registered = key?.GetValue("InstallLocation") as string;
            if (string.IsNullOrWhiteSpace(registered)) return null;
            var root = Path.GetFullPath(registered).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var pointerPath = Path.Combine(root, ".bifrost-state", "current.json");
            var launcher = Path.Combine(root, "Bifrost.exe");
            if (!Directory.Exists(root) || !File.Exists(pointerPath) || !File.Exists(launcher)) return null;
            if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0 ||
                (File.GetAttributes(pointerPath) & FileAttributes.ReparsePoint) != 0 ||
                (File.GetAttributes(launcher) & FileAttributes.ReparsePoint) != 0) return null;
            var info = new FileInfo(pointerPath);
            if (info.Length is <= 0 or > 64 * 1024) return null;
            using var pointer = JsonDocument.Parse(File.ReadAllBytes(pointerPath));
            var value = pointer.RootElement;
            if (!value.TryGetProperty("schema", out var schema) || schema.GetString() != "bifrost-current-v2" ||
                !value.TryGetProperty("current_root", out var currentRoot) || currentRoot.ValueKind != JsonValueKind.String ||
                !string.Equals(Path.GetFullPath(currentRoot.GetString()!).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase) ||
                !value.TryGetProperty("current_payload_root", out var currentPayload) || currentPayload.ValueKind != JsonValueKind.String)
                return null;
            var payload = Path.GetFullPath(currentPayload.GetString()!);
            if (!payload.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || !Directory.Exists(payload)) return null;
            return launcher;
        }
        catch
        {
            return null;
        }
    }

    private static void RetirePreviousDesktopGeneration(string root)
    {
        // The offline installer starts a new immutable generation. Closing an
        // old WPF window merely hides it in the tray, leaving two controllers
        // that can retain contradictory connection intent. Retire only older
        // desktop images belonging to this exact committed installation.
        try
        {
            var pointerPath = Path.Combine(root, ".bifrost-state", "current.json");
            if (!File.Exists(pointerPath) || new FileInfo(pointerPath).Length > 128 * 1024) return;
            using var pointer = JsonDocument.Parse(File.ReadAllBytes(pointerPath));
            var currentRoot = pointer.RootElement.GetProperty("current_payload_root").GetString();
            if (!string.Equals(Path.GetFullPath(currentRoot!).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)) return;
            foreach (var process in Process.GetProcessesByName("Bifrost"))
            {
                using (process)
                {
                    if (process.Id == Environment.ProcessId) continue;
                    try
                    {
                        var image = process.MainModule?.FileName;
                        if (image is null || !DesktopGenerationPolicy.IsPreviousImage(image, Environment.ProcessPath!, root)) continue;
                        process.Kill(entireProcessTree: false);
                        process.WaitForExit(2000);
                    }
                    catch (Exception error) { UiLifecycleTrace.Write("previous-generation-exit-unavailable", error); }
                }
            }
        }
        catch (Exception error) { UiLifecycleTrace.Write("previous-generation-readback-unavailable", error); }
    }
#endif

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs args)
    {
        UiLifecycleTrace.Write("dispatcher-unhandled", args.Exception);
        if (BifrostBuildConstants.LocalEvaluation || !ContainsInstallLayoutFailure(args.Exception)) return;

        // Shipping Bifrost.exe is an immutable generation payload. A
        // byte-identical published client may use the installed LocalSystem
        // service, but installation and update ownership still require the
        // managed install layout. Treat a missing layout as a guided launch
        // error rather than a process crash/Windows Error Reporting event.
        args.Handled = true;
        MessageBox.Show(
            "当前启动位置不具备安装或更新布局。\n\n连接可由已安装服务提供；如需安装、修复或更新，请运行 BifrostSetup.exe。日常使用建议从桌面快捷方式启动 Bifrost。",
            "Bifrost",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
        Shutdown(2);
    }

#if BIFROST_INTERNAL_LIVE_VALIDATION
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var validateGlobal = e.Args.Contains("--live-validate-connect", StringComparer.Ordinal);
        var validateSmart = e.Args.Contains("--live-validate-smart", StringComparer.Ordinal);
        var validateLatency = e.Args.Contains("--live-validate-latency", StringComparer.Ordinal);
        var validateDisconnect = e.Args.Contains("--live-validate-disconnect", StringComparer.Ordinal);
        if (!validateGlobal && !validateSmart && !validateLatency && !validateDisconnect) return;
        Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(async () =>
        {
            var resultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bifrost", "live-validation-result.json");
            var validationPhase = "startup";
            try
            {
                var window = Current.Windows.OfType<MainWindow>().Single();
                if (validateDisconnect)
                {
                    validationPhase = "direct-disconnect";
                    var disconnected = await new ClientServiceContract().DisconnectAsync();
                    WriteLiveValidationResult(resultPath, new
                    {
                        schema = "BIFROST-LIVE-VALIDATION-1",
                        requested_mode = "disconnect",
                        disconnected.Ok,
                        disconnected.Connected,
                        disconnected.State,
                        disconnected.Code,
                        timestamp = DateTimeOffset.UtcNow.ToString("O")
                    });
                    _ = Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() =>
                    {
                        try { window.Close(); } catch { }
                        try { Shutdown(disconnected.Ok && !disconnected.Connected ? 0 : 5); } catch { }
                    }));
                    return;
                }
                validationPhase = "view-model-start";
                await window.ViewModel.StartAsync();
                // StartAsync intentionally returns after scheduling the normal
                // warm-start work so first paint is never blocked on Control.
                // The live validator is different: it must not start a real
                // latency round until the current signed configuration has
                // been fetched and applied to the view model, otherwise an
                // empty cached option set makes the run look like a successful
                // zero-candidate measurement and never reaches LocalSystem.
                validationPhase = "configuration-refresh";
                if (!await window.ViewModel.RefreshAsync())
                    throw new InvalidOperationException("BF-LIVE-VALIDATION-CONFIG");
                window.ViewModel.Source = "A";
                if (validateLatency)
                {
                    validationPhase = "latency-measure";
                    var latencyMeasured = await window.ViewModel.RunLiveLatencyValidationAsync("A");
                    validationPhase = "status-readback";
                    var latencyStatus = await new ClientServiceContract().GetStatusAsync();
                    validationPhase = "result-write";
                    WriteLiveValidationResult(resultPath, new
                    {
                        schema = "BIFROST-LIVE-VALIDATION-1",
                        requested_mode = "latency-only",
                        source = latencyMeasured.Source,
                        measured_best_candidate = latencyMeasured.SelectedCandidateLabel,
                        measured_candidates = latencyMeasured.Candidates.Select(candidate => new
                        {
                            code = candidate.Code,
                            success = candidate.Success,
                            rtt_ms = candidate.RttMs,
                            error_code = candidate.ErrorCode
                        }).ToArray(),
                        service_ok = latencyStatus.Ok,
                        connected = latencyStatus.Connected,
                        state = latencyStatus.State,
                        service_code = latencyStatus.Code,
                        service_core = latencyStatus.Core,
                        service_mode = latencyStatus.Mode,
                        service_config_id = latencyStatus.ConfigId,
                        service_source = latencyStatus.Source,
                        timestamp = DateTimeOffset.UtcNow.ToString("O")
                    });
                    validationPhase = "result-written";
                    var exitCode = latencyStatus.Connected ? 3 : 0;
                    _ = Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() =>
                    {
                        try { window.Close(); } catch { }
                        try { Shutdown(exitCode); } catch { }
                    }));
                    return;
                }
                if (validateSmart)
                {
                    // stage_config deliberately requires the exact shipping Bifrost.exe hash.
                    // An internal validator therefore cannot restage a package without weakening
                    // the production identity boundary. Reuse the newest package that the real
                    // installed client already staged and let this bound interactive process test
                    // only the runtime connect path. The service revalidates the package on load.
                    validationPhase = "existing-staged-config";
                    var configsRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost", "configs");
                    var stagedPackage = Directory.GetDirectories(configsRoot, "cfg_*", SearchOption.TopDirectoryOnly)
                        .Select(path => new { Path = path, Package = Path.Combine(path, "package.json"), At = Directory.GetLastWriteTimeUtc(path) })
                        .Where(item => File.Exists(item.Package))
                        .OrderByDescending(item => item.At)
                        .Select(item =>
                        {
                            try
                            {
                                using var doc = JsonDocument.Parse(File.ReadAllBytes(item.Package));
                                var root = doc.RootElement;
                                return root.TryGetProperty("source", out var source) && source.GetString() == "A" &&
                                    root.TryGetProperty("mode", out var mode) && mode.GetString() == ProtocolCodes.ModeSmart &&
                                    root.TryGetProperty("core", out var core) && core.GetString() == ProtocolCodes.CoreMihomo
                                    ? new
                                    {
                                        ConfigId = root.GetProperty("config_id").GetString(),
                                        Snapshot = root.GetProperty("app_policy_snapshot").GetString(),
                                        Policy = root.GetProperty("app_policy").GetString()
                                    }
                                    : null;
                            }
                            catch { return null; }
                        })
                        .FirstOrDefault(item => item is not null)
                        ?? throw new InvalidOperationException("BF-CONFIG-PACKAGE");
                    if (string.IsNullOrWhiteSpace(stagedPackage.ConfigId) || string.IsNullOrWhiteSpace(stagedPackage.Snapshot))
                        throw new InvalidOperationException("BF-CONFIG-PACKAGE");
                    var snapshot = ApplicationPolicySnapshot.Parse(stagedPackage.Snapshot);
                    validationPhase = "direct-connect-runtime";
                    var service = new ClientServiceContract();
                    var connected = await service.ConnectAsync(ProtocolCodes.ModeSmart, ProtocolCodes.CoreMihomo,
                        "A", "default", stagedPackage.ConfigId, stagedPackage.Policy ?? "none",
                        CancellationToken.None, snapshot, "direct-vmess");
                    validationPhase = "direct-status-readback";
                    var directStatus = await service.GetStatusAsync(CancellationToken.None);
                    WriteLiveValidationResult(resultPath, new
                    {
                        schema = "BIFROST-LIVE-VALIDATION-1",
                        requested_mode = "smart-direct",
                        staged_config_id = stagedPackage.ConfigId,
                        connected_result = connected.Connected,
                        directStatus.Ok,
                        directStatus.Connected,
                        directStatus.State,
                        directStatus.Code,
                        directStatus.Core,
                        directStatus.Mode,
                        directStatus.ConfigId,
                        directStatus.Source,
                        mihomo = directStatus.Mihomo is null ? null : new
                        {
                            group = directStatus.Mihomo.Group,
                            active_candidate = directStatus.Mihomo.ActiveCandidate,
                            process_id = directStatus.Mihomo.ProcessId,
                            tun_interface_index = directStatus.Mihomo.TunInterfaceIndex,
                            candidates = directStatus.Mihomo.Candidates.Select(candidate => new
                            {
                                name = candidate.Name,
                                alive = candidate.Alive,
                                delay_ms = candidate.DelayMs
                            }).ToArray()
                        },
                        timestamp = DateTimeOffset.UtcNow.ToString("O")
                    });
                    validationPhase = "result-written";
                    var exitCode = directStatus.Ok && directStatus.Connected ? 0 : 4;
                    _ = Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() =>
                    {
                        try { window.Close(); } catch { }
                        try { Shutdown(exitCode); } catch { }
                    }));
                    return;
                }
                window.ViewModel.Mode = validateSmart ? ProtocolCodes.ModeSmart : ProtocolCodes.ModeGlobal;
                if (validateSmart)
                {
                    window.ViewModel.CandidateMode = "auto";
                }
                else
                {
                    window.ViewModel.CandidateMode = "manual";
                    window.ViewModel.CandidateLabel = "A-10";
                }
                await window.ViewModel.ConnectAsync();
                var status = await new ClientServiceContract().GetStatusAsync();
                var measured = window.ViewModel.LastAutomaticMeasurement;
                WriteLiveValidationResult(resultPath, new
                {
                    schema = "BIFROST-LIVE-VALIDATION-1",
                    requested_mode = validateSmart ? "smart" : "global",
                    selected_candidate = window.ViewModel.EffectiveCandidateLabel,
                    measured_best_candidate = measured?.SelectedCandidateLabel,
                    measured_candidates = measured?.Candidates.Select(candidate => new
                    {
                        code = candidate.Code,
                        success = candidate.Success,
                        rtt_ms = candidate.RttMs,
                        error_code = candidate.ErrorCode
                    }).ToArray(),
                    candidate_attempts = window.ViewModel.LastAutomaticCandidateAttempts,
                    status.Ok,
                    status.Connected,
                    status.State,
                    status.Code,
                    status.Core,
                    status.Mode,
                    status.ConfigId,
                    status.Source,
                    mihomo = status.Mihomo is null ? null : new
                    {
                        group = status.Mihomo.Group,
                        active_candidate = status.Mihomo.ActiveCandidate,
                        process_id = status.Mihomo.ProcessId,
                        tun_interface_index = status.Mihomo.TunInterfaceIndex,
                        candidates = status.Mihomo.Candidates.Select(candidate => new
                        {
                            name = candidate.Name,
                            alive = candidate.Alive,
                            delay_ms = candidate.DelayMs
                        }).ToArray()
                    },
                    timestamp = DateTimeOffset.UtcNow.ToString("O")
                });
            }
            catch (Exception error)
            {
                var code = error is ServiceException serviceError ? serviceError.Code : error.Message.StartsWith("BF-", StringComparison.Ordinal) ? error.Message : "BF-LIVE-VALIDATION";
                WriteLiveValidationResult(resultPath, new
                {
                    schema = "BIFROST-LIVE-VALIDATION-1",
                    ok = false,
                    connected = false,
                    state = "failed",
                    code,
                    validation_phase = validationPhase,
                    error_type = error.GetType().FullName,
                    error_message = error.Message,
                    timestamp = DateTimeOffset.UtcNow.ToString("O")
                });
            }
        }));
    }

    private static void WriteLiveValidationResult(string path, object value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(value) + Environment.NewLine, new UTF8Encoding(false));
    }
#endif

    private static bool ContainsInstallLayoutFailure(Exception error)
    {
        for (var current = error; current is not null; current = current.InnerException)
        {
            if (current is InvalidDataException &&
                string.Equals(current.Message, "BF-INSTALL-LAYOUT", StringComparison.Ordinal))
                return true;
        }
        return false;
    }
}
