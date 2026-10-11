using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Net.Http;
using System.IO.Pipes;
using System.Buffers.Binary;
using System.Reflection;
using Bifrost.Release;
using Bifrost.ClientService;
using Artifact = Bifrost.Release.ReleaseUpdateManager.Artifact;
using VerifiedEnvelope = Bifrost.Release.ReleaseUpdateManager.VerifiedEnvelope;

namespace Bifrost.Setup;

/// <summary>
/// Trusted installer/updater boundary.  It consumes only the signed release
/// envelope and never treats BUILD-MANIFEST, a pending marker, or a mutable
/// public-key file as a trust root.  --what-if and --verify are side-effect
/// free; --apply-pending is also testable against an explicitly supplied
/// temporary install root and does not touch SCM in --what-if mode.
/// </summary>
internal static class Program
{
    private const long MaxArtifactBytes = 512L * 1024 * 1024;
    private const long MaxTotalBytes = 1024L * 1024 * 1024;
    private const string ServiceName = "BifrostClientService";
    private const string StateDirectoryName = ".bifrost-state";
    private const string OperationResultName = "update-operation.json";
    private const string UninstallRegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Bifrost";
    internal static string? LastWizardDiagnosticCode { get; private set; }

    private static bool HarnessUsesProductionTrust(bool testRoot)
    {
#if BIFROST_TEST_HARNESS
        return testRoot && string.Equals(Environment.GetEnvironmentVariable("BIFROST_TEST_PRODUCTION_TRUST"), "1", StringComparison.Ordinal);
#else
        return false;
#endif
    }
    private static readonly HashSet<string> PrimaryActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "--help", "--version", "--verify", "--what-if", "--install", "--launch", "--rollback", "--uninstall", "--apply-pending"
#if BIFROST_TEST_HARNESS
        ,
         "--test-helper-args", "--test-acl-policy", "--test-scm-plan", "--test-scm-query", "--test-scm-parse",
         "--test-scm-transition", "--test-parent-wait", "--test-helper-cleanup", "--test-service-lifecycle", "--test-verify-full-envelope", "--test-seed-pending", "--test-stage-production-update", "--test-ipc-health", "--test-ipc-acl", "--test-uninstall-paths", "--test-recover-uninstall"
#endif
    };

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
#if BIFROST_TEST_HARNESS
            // Keep the isolated harness deterministic and non-interactive.
            if (args.Length == 0) args = new[] { "--install", "--package-root", AppContext.BaseDirectory };
#else
            // The shipping executable has two no-argument roles:
            //   * at a signed package root it is the interactive installer;
            //   * when copied to the protected install root it is the stable
            //     launcher that resolves the authenticated current generation.
            if (args.Length == 0)
            {
                if (IsInstalledLauncherContext(AppContext.BaseDirectory))
                    return LaunchInstalledApplication(AppContext.BaseDirectory) ? 0 : 1;
                var interactivePackageRoot = TryFindPackageRootFromBaseDirectory();
                if (interactivePackageRoot is null)
                {
                    MessageBox.Show(
                        "This BifrostSetup.exe is an internal installation helper and is not a complete standalone installer. Run the single-file Bifrost Offline Setup package instead.",
                        "Bifrost Setup",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return 2;
                }
                return SetupWizard.Run(interactivePackageRoot);
            }
#endif
            var command = ParseCommand(args);
            var hasTestRoot = args.Contains("--test-root", StringComparer.OrdinalIgnoreCase);
            var hasFakeTestModifier = args.Any(value => value is "--fake-service" or "--fake-failure" or "--fake-parent-wait");
#if BIFROST_TEST_HARNESS
            // Test-only inspection verbs are compiled out of every shipping
            // binary, so they do not need the filesystem test-root switch just
            // to print deterministic policy/SCM/helper diagnostics. Keep the
            // explicit --test-root requirement for fake mutation modifiers,
            // which are the seams that can alter install/update state.
            if (hasFakeTestModifier && !hasTestRoot)
                throw new InvalidDataException("BF-SETUP-TEST-ONLY");
#else
            if (hasTestRoot || hasFakeTestModifier)
                throw new InvalidDataException("BF-SETUP-TEST-ONLY");
#endif
            // Verification and inspection remain ordinary-user operations so
            // build servers and recipients can validate a package without a
            // UAC prompt.  Shipping install/uninstall/rollback operations all
            // mutate protected filesystem/SCM/registry state, so they cross
            // the elevation boundary.  The elevated child receives the exact
            // already-parsed argument vector via ProcessStartInfo.ArgumentList.
            if (command is "--install" or "--uninstall" or "--rollback" &&
                !args.Contains("--what-if", StringComparer.OrdinalIgnoreCase) &&
                !args.Contains("--test-root", StringComparer.OrdinalIgnoreCase) &&
                !IsAdministrator())
                return RelaunchElevated(args);
            if (command == "--help") { PrintHelp(); return 0; }
            if (command == "--version") { Console.WriteLine("BifrostSetup/2"); return 0; }
            if (command == "--launch")
                return LaunchInstalledApplication(Value(args, "--install-root") ?? DefaultInstallRoot) ? 0 : 1;
            if (command == "--apply-pending")
            {
                return ApplyPendingCommand(
                    Value(args, "--install-root") ?? throw new InvalidDataException("BF-SETUP-INSTALL-ROOT"),
                    args.Contains("--what-if", StringComparer.OrdinalIgnoreCase),
                    Value(args, "--update-root"),
                    args.Contains("--test-root", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--helper", StringComparer.OrdinalIgnoreCase),
                    Value(args, "--wait-for-pid"),
                    Value(args, "--fake-service"),
                    Value(args, "--operation-nonce"),
                    Value(args, "--expected-sequence"),
                    Value(args, "--fake-failure"),
                    Value(args, "--fake-parent-wait"));
            }

#if BIFROST_TEST_HARNESS
            if (command == "--test-helper-args")
                return PrintHelperArguments(args.Contains("--test-root", StringComparer.OrdinalIgnoreCase));
            if (command == "--test-acl-policy")
                return PrintAclPolicy(Value(args, "--profile"));
            if (command == "--test-scm-plan")
                return PrintScmPlan(Value(args, "--state"));
            if (command == "--test-scm-query")
                return PrintScmQueryClassification(Value(args, "--exit-code"));
            if (command == "--test-scm-parse")
                return PrintScmParse(Value(args, "--raw"));
            if (command == "--test-scm-transition")
                return PrintScmTransition(Value(args, "--states"));
            if (command == "--test-parent-wait")
                return PrintParentWait(Value(args, "--outcome"));
            if (command == "--test-helper-cleanup")
                return TestHelperCleanup(Value(args, "--helper-root"), Value(args, "--current-root"));
            if (command == "--test-service-lifecycle")
                return PrintServiceLifecycle(Value(args, "--helper-root"), Value(args, "--state"), Value(args, "--fake-service"));
            if (command == "--test-verify-full-envelope")
                return PrintFullEnvelopeVerification(Value(args, "--package-root"), Value(args, "--state"));
            if (command == "--test-seed-pending")
                return SeedFullPending(Value(args, "--package-root"), Value(args, "--install-root"), Value(args, "--update-root"), Value(args, "--helper-root"));
            if (command == "--test-stage-production-update")
                return StageProductionUpdate(Value(args, "--package-root"), Value(args, "--state"));
            if (command == "--test-ipc-health")
                return TestIpcHealth(Value(args, "--case"));
            if (command == "--test-ipc-acl")
                return TestIpcAcl(Value(args, "--case"));
            if (command == "--test-uninstall-paths")
                return TestUninstallPaths(Value(args, "--install-root"), Value(args, "--update-root"));
            if (command == "--test-recover-uninstall")
                return TestRecoverUninstall(Value(args, "--install-root"), Value(args, "--update-root"), Value(args, "--fake-service"));
#endif

            if (command == "--uninstall")
            {
                if (args.Contains("--force-residual-cleanup", StringComparer.OrdinalIgnoreCase))
                    return ForceResidualCleanup(
                        Value(args, "--install-root"), Value(args, "--update-root"),
                        args.Contains("--test-root", StringComparer.OrdinalIgnoreCase));
                return Uninstall(
                    Value(args, "--install-root"), Value(args, "--update-root"),
                    args.Contains("--test-root", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--what-if", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--purge", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--verified-residual-cleanup", StringComparer.OrdinalIgnoreCase),
                    args.Contains("--helper", StringComparer.OrdinalIgnoreCase),
                    Value(args, "--wait-for-pid"),
                    Value(args, "--fake-service"), Value(args, "--fake-failure"));
            }
            if (command == "--rollback")
                return Rollback(Value(args, "--install-root"), Value(args, "--update-root"), args.Contains("--test-root", StringComparer.OrdinalIgnoreCase), Value(args, "--fake-service"), Value(args, "--fake-failure"), args.Contains("--what-if", StringComparer.OrdinalIgnoreCase));
            var root = FindPackageRoot(args);
            return command switch
            {
                "--verify" or "--what-if" => VerifyCommand(root),
                "--install" => InstallCommand(root, Value(args, "--install-root"), Value(args, "--update-root"), args.Contains("--what-if", StringComparer.OrdinalIgnoreCase), args.Contains("--test-root", StringComparer.OrdinalIgnoreCase), Value(args, "--fake-service"), Value(args, "--fake-failure")),
            _ => throw new InvalidDataException("BF-SETUP-USAGE")
            };
        }
        catch (Exception error)
        {
            RecordStableFailure(error, args);
            // Do not echo paths, payloads, service text, or exception details
            // across the elevation boundary.
#if !BIFROST_TEST_HARNESS
            // Shipping builds intentionally collapse every exception to the
            // same public error.  Mark the caught value as consumed so the
            // Release build remains warning-clean without weakening that
            // fail-closed diagnostic boundary.
            _ = error;
#endif
#if BIFROST_TEST_HARNESS
            if (string.Equals(Environment.GetEnvironmentVariable("BIFROST_TEST_SETUP_TRACE"), "1", StringComparison.Ordinal))
            {
                Console.Error.WriteLine(error.ToString());
                try
                {
                    File.WriteAllText(
                        Path.Combine(Path.GetTempPath(), "BifrostSetup-test-trace.txt"),
                        error + Environment.NewLine,
                        new UTF8Encoding(false));
                }
                catch { }
            }
            // The isolated installer harness may surface only a stable BF-*
            // code.  Never print arbitrary exception text because framework
            // exceptions can contain temporary or installation paths.
            var diagnostic = error.Message;
            if (!string.IsNullOrWhiteSpace(diagnostic) && diagnostic.StartsWith("BF-", StringComparison.Ordinal) &&
                diagnostic.Length <= 96 && diagnostic.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-'))
                Console.Error.WriteLine($"BF-SETUP-FAILED:{diagnostic}");
            else
#endif
            Console.Error.WriteLine("BF-SETUP-FAILED");
            return 1;
        }
    }

    private static void RecordStableFailure(Exception error, IReadOnlyList<string> args)
    {
        try
        {
            var candidate = error.Message ?? string.Empty;
            var code = candidate.StartsWith("BF-", StringComparison.Ordinal) && candidate.Length <= 96 &&
                       candidate.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-')
                ? candidate
                : "BF-SETUP-FAILED";
            var record = JsonSerializer.Serialize(new
            {
                schema = "BIFROST-SETUP-DIAGNOSTIC-1",
                code,
                timestamp = DateTimeOffset.UtcNow.ToString("O")
            });
            var payload = record + Environment.NewLine;
            var handoff = ResolveDiagnosticHandoffPath(args);
            if (handoff is not null)
            {
                using var stream = new FileStream(handoff, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
                using var writer = new StreamWriter(stream, new UTF8Encoding(false));
                writer.Write(payload);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }
        }
        catch { }
    }

    private static string? ResolveDiagnosticHandoffPath(IReadOnlyList<string> args)
    {
        var matches = Enumerable.Range(0, args.Count)
            .Where(index => string.Equals(args[index], "--diagnostic-file", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (matches.Length != 1 || matches[0] + 1 >= args.Count) return null;
        var supplied = args[matches[0] + 1];
        if (string.IsNullOrWhiteSpace(supplied) || !Path.IsPathFullyQualified(supplied)) return null;
        var full = Path.GetFullPath(supplied);
        var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var parent = Path.GetDirectoryName(full)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(parent, temp, StringComparison.OrdinalIgnoreCase)) return null;
        var file = Path.GetFileName(full);
        const string prefix = "BifrostOfflineSetup-";
        const string suffix = ".diagnostic.json";
        if (!file.StartsWith(prefix, StringComparison.Ordinal) || !file.EndsWith(suffix, StringComparison.Ordinal)) return null;
        var nonce = file[prefix.Length..^suffix.Length];
        return nonce.Length == 32 && nonce.All(char.IsAsciiHexDigit) ? full : null;
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int RelaunchElevated(IReadOnlyList<string> args)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-SETUP-PLATFORM");
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable) || !File.Exists(executable)) throw new InvalidDataException("BF-SETUP-ELEVATION");
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory
        };
        foreach (var argument in args) start.ArgumentList.Add(argument);
        using var child = Process.Start(start) ?? throw new InvalidDataException("BF-SETUP-ELEVATION");
        child.WaitForExit();
        return child.ExitCode;
    }

    internal static string DefaultInstallRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Bifrost");

    internal static string PreferredWizardInstallRoot => TryResolveRegisteredInstallRoot() ?? DefaultInstallRoot;

    private static string? TryResolveRegisteredInstallRoot()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = machine.OpenSubKey(UninstallRegistryPath, writable: false);
            var registered = key?.GetValue("InstallLocation") as string;
            if (string.IsNullOrWhiteSpace(registered)) return null;
            var candidate = ResolveInstallRoot(registered, testRoot: false);
            // Treat the uninstall registration only as a preferred UI target.
            // The inner installer still re-validates the protected ownership,
            // release state and service transaction before changing anything.
            // A missing stale registration must not create a directory merely
            // because Setup was opened.
            return Directory.Exists(candidate) ? candidate : null;
        }
        catch
        {
            return null;
        }
    }

    internal static string ValidateWizardInstallRoot(string requested)
    {
        var candidate = ResolveInstallRoot(requested, testRoot: false);
        if (!IsVerifiedExistingInstallRootForCompatibility(candidate))
            ValidateNewInstallAncestorIntegrity(candidate);
        return candidate;
    }

    internal static int RunWizardInstall(string packageRoot, string installRoot) =>
        RunWizardOperation(new[] { "--install", "--package-root", Path.GetFullPath(packageRoot), "--install-root", ValidateWizardInstallRoot(installRoot) });

    internal static int RunWizardVerifiedCleanup(string installRoot)
    {
        var validatedRoot = ValidateWizardInstallRoot(installRoot);
        var verified = RunWizardOperation(new[] { "--uninstall", "--install-root", validatedRoot, "--purge", "--verified-residual-cleanup" });
        if (verified == 0) return 0;

        // Older public builds did not always leave the current ownership
        // record behind.  Once the user has explicitly selected and confirmed
        // the previous folder, retry through the compatibility cleanup path:
        // quarantine that exact folder, remove only the exact Bifrost service
        // name, and let installation continue without an ownership-file gate.
        return RunWizardOperation(new[] { "--uninstall", "--install-root", validatedRoot, "--purge", "--force-residual-cleanup" });
    }

    private static int RunWizardOperation(IEnumerable<string> operationArguments)
    {
        LastWizardDiagnosticCode = null;
        // This is consumed after an elevated child process returns.  Keep the
        // filename within the same narrowly validated handoff namespace used
        // by the single-file launcher, otherwise stable failure codes cannot
        // reach the wizard's verified-residual recovery flow.
        var diagnosticFile = Path.Combine(Path.GetTempPath(), "BifrostOfflineSetup-" + Guid.NewGuid().ToString("N") + ".diagnostic.json");
        var arguments = operationArguments.Append("--diagnostic-file").Append(diagnosticFile).ToArray();
        try
        {
            var result = IsAdministrator() ? Main(arguments) : RelaunchElevated(arguments);
            if (result != 0) LastWizardDiagnosticCode = ReadWizardDiagnosticCode(diagnosticFile);
            return result;
        }
        finally
        {
            try { if (File.Exists(diagnosticFile)) File.Delete(diagnosticFile); } catch { }
        }
    }

    private static string? ReadWizardDiagnosticCode(string diagnosticFile)
    {
        try
        {
            using var stream = new FileStream(diagnosticFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.SequentialScan);
            if (stream.Length is <= 0 or > 4096) return null;
            using var document = JsonDocument.Parse(stream);
            var code = document.RootElement.GetProperty("code").GetString();
            return code is { Length: > 2 and <= 96 } && code.StartsWith("BF-", StringComparison.Ordinal) &&
                   code.All(character => char.IsAsciiLetterOrDigit(character) || character == '-') ? code : null;
        }
        catch { return null; }
    }

    private static bool IsInstalledLauncherContext(string directory)
    {
        try
        {
            var root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return !File.Exists(Path.Combine(root, "RELEASE-ENVELOPE.json")) && File.Exists(Path.Combine(root, StateDirectoryName, "current.json"));
        }
        catch { return false; }
    }

    internal static bool LaunchInstalledApplication(string installRoot)
    {
        try
        {
            var root = ResolveInstallRoot(installRoot, testRoot: false);
            var payloadRoot = ReadCurrentPayloadRoot(root, testRoot: false) ?? throw new InvalidDataException("BF-SETUP-GENERATION");
            var application = ResolveContained(payloadRoot, "Bifrost.exe");
            if (!File.Exists(application)) throw new InvalidDataException("BF-SETUP-GENERATION");
            EnsureNoReparseChain(application, allowMissingLeaf: false);
            Process.Start(new ProcessStartInfo { FileName = application, WorkingDirectory = payloadRoot, UseShellExecute = true });
            return true;
        }
        catch { return false; }
    }

    private static string ParseCommand(string[] args)
    {
        if (args.Length == 0) throw new InvalidDataException("BF-SETUP-USAGE");
        var primary = args.Where(PrimaryActions.Contains).Select(value => value.ToLowerInvariant()).ToArray();
        // --what-if is a standalone action only when no other primary action
        // is present; otherwise it is a modifier of --install/--verify.
        if (primary.Length == 0) throw new InvalidDataException("BF-SETUP-USAGE");
        var command = primary.FirstOrDefault(value => value != "--what-if") ?? "--what-if";
        if (primary.Count(value => value != "--what-if") > 1) throw new InvalidDataException("BF-SETUP-ACTION");

        var valueOptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "--package-root", "--install-root", "--update-root", "--diagnostic-file", "--fake-service", "--wait-for-pid",
            "--operation-nonce", "--expected-sequence", "--fake-failure", "--fake-parent-wait", "--profile", "--state",
            "--exit-code", "--raw", "--states", "--outcome", "--helper-root", "--current-root", "--case"
        };
        // Every action has its own grammar.  In particular, help/version do
        // not accept modifiers and --test-root is never a global option.
        var common = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            var token = args[index];
            if (!token.StartsWith("--", StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-ARGUMENT");
            if (token.Equals("--what-if", StringComparison.OrdinalIgnoreCase))
            {
                if (!seen.Add(token)) throw new InvalidDataException("BF-SETUP-ARGUMENT");
                continue;
            }
            if (PrimaryActions.Contains(token))
            {
                if (!token.Equals(command, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-ACTION");
                continue;
            }
            if (!seen.Add(token)) throw new InvalidDataException("BF-SETUP-ARGUMENT");
            var allowed = command switch
            {
                "--verify" or "--what-if" => new[] { "--package-root", "--diagnostic-file" },
                "--launch" => new[] { "--install-root" },
                "--install" => new[] { "--package-root", "--install-root", "--update-root", "--diagnostic-file", "--fake-service", "--fake-failure", "--test-root" },
                "--apply-pending" => new[] { "--install-root", "--update-root", "--test-root", "--helper", "--wait-for-pid", "--fake-service", "--operation-nonce", "--expected-sequence", "--fake-failure", "--fake-parent-wait" },
                "--rollback" => new[] { "--install-root", "--update-root", "--test-root", "--fake-service", "--fake-failure" },
                "--uninstall" => new[] { "--install-root", "--update-root", "--diagnostic-file", "--test-root", "--fake-service", "--fake-failure", "--purge", "--verified-residual-cleanup", "--force-residual-cleanup", "--helper", "--wait-for-pid" },
#if BIFROST_TEST_HARNESS
                "--test-helper-args" or "--test-acl-policy" or "--test-scm-plan" or "--test-scm-query" or "--test-scm-parse" or "--test-scm-transition" or "--test-parent-wait" or "--test-helper-cleanup" => new[] { "--test-root", "--profile", "--state", "--exit-code", "--raw", "--states", "--outcome", "--helper-root", "--current-root" },
                "--test-service-lifecycle" => new[] { "--test-root", "--helper-root", "--state", "--fake-service" },
                "--test-verify-full-envelope" => new[] { "--test-root", "--package-root", "--state" },
                "--test-seed-pending" => new[] { "--test-root", "--package-root", "--install-root", "--update-root", "--helper-root" },
                "--test-stage-production-update" => new[] { "--test-root", "--package-root", "--state" },
                "--test-ipc-health" => new[] { "--test-root", "--case" },
                "--test-ipc-acl" => new[] { "--test-root", "--case" },
                "--test-uninstall-paths" => new[] { "--test-root", "--install-root", "--update-root" },
                "--test-recover-uninstall" => new[] { "--test-root", "--install-root", "--update-root", "--fake-service" },
#endif
                _ => Array.Empty<string>()
            };
            if (!allowed.Contains(token, StringComparer.OrdinalIgnoreCase) && !common.Contains(token)) throw new InvalidDataException("BF-SETUP-ARGUMENT");
            if (valueOptions.Contains(token))
            {
                if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-ARGUMENT");
            }
        }
        if ((command is "--help" or "--version") && seen.Contains("--what-if")) throw new InvalidDataException("BF-SETUP-ARGUMENT");
        if (command == "--what-if" && seen.Contains("--test-root")) throw new InvalidDataException("BF-SETUP-ARGUMENT");
        if (seen.Contains("--what-if") && args.Any(value => new[] { "--helper", "--wait-for-pid", "--fake-service", "--fake-failure", "--fake-parent-wait", "--operation-nonce", "--expected-sequence" }.Any(option => string.Equals(value, option, StringComparison.OrdinalIgnoreCase))))
            throw new InvalidDataException("BF-SETUP-ARGUMENT");
        return command;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("BifrostSetup --help|--version|--verify|--what-if|--install|--launch|--rollback|--uninstall");
    }

    private static int VerifyCommand(string packageRoot)
    {
        var envelope = ReadSignedEnvelope(packageRoot);
        var files = VerifyPayload(packageRoot, envelope);
        EnsureExactPackageEntries(packageRoot, envelope);
        try
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                ok = true,
                mode = "dry-run",
                sequence = envelope.Sequence,
                files = files.Select(file => new { file.Metadata.Path, file.Metadata.InstallPath, file.Metadata.Kind, file.Metadata.Bytes, file.Metadata.Sha256 })
            }));
            return 0;
        }
        finally { DisposeVerified(files); }
    }

    private static int InstallCommand(string packageRoot, string? installRootOverride, string? updateRootOverride, bool whatIf, bool testRoot, string? fakeServiceMode, string? fakeFailureMode)
    {
        var target = ResolveInstallRoot(installRootOverride, testRoot);
        if (!testRoot && !IsVerifiedExistingInstallRootForCompatibility(target))
            ValidateNewInstallAncestorIntegrity(target);
        var updateRoot = ResolveUpdateRoot(updateRootOverride, testRoot);
        EnsureSeparateRoots(updateRoot, target);
        var statePath = ResolveStatePath(target);
        // The install lock is the first stateful operation.  what-if is
        // deliberately lock-free and recovery-free: it may only inspect a
        // journal and report what would happen, never create a lock or repair
        // durable state.
        using FileStream? installLock = whatIf ? null : AcquireInstallLock(target);
        if (whatIf) { ValidateUninstallJournalReadOnly(target); ValidatePromotionJournalReadOnly(target); }
        else { RecoverUninstallJournal(target, testRoot, fakeServiceMode, updateRoot); RecoverPromotionJournal(target, testRoot); }
        var previousSequence = ReadStateSequence(statePath, testRoot);
        if (previousSequence == 0 && File.Exists(ResolveUninstalledMarkerPath(target))) ValidateUninstalledMarker(target);
#if BIFROST_TEST_HARNESS
        var legacyTestFixtureInstall = testRoot && string.Equals(Environment.GetEnvironmentVariable("BIFROST_TEST_LEGACY_FIXTURE"), "1", StringComparison.Ordinal);
#else
        var legacyTestFixtureInstall = false;
#endif
        if (previousSequence > 0) { _ = ReadOwnership(target, testRoot); ValidateCurrentPointer(target, previousSequence, testRoot); }
        // The package is not a trust input until the install lock has been
        // acquired and the durable authority has been read.  Existing
        // installations must verify the exact envelope bytes against that
        // previous authority; only a genuinely empty target may use the
        // first-install verifier.
        var previousAuthority = previousSequence > 0 ? ReadReleaseAuthorityStateForInstaller(statePath) : null;
        var envelope = ReadSignedEnvelopeForInstall(packageRoot, testRoot, previousAuthority);
        var files = VerifyPayload(packageRoot, envelope, stageIsRoot: false, testRoot: testRoot);
        if (!testRoot) EnsureExactPackageEntries(packageRoot, envelope);
        // Legacy TEST-ONLY manifests are intentionally kept on the old
        // fixture layout.  Immutable generation layout is enabled for full
        // signed envelopes, never merely because a fixture has seven files.
        var generationLayout = UseGenerationLayout(envelope, testRoot, File.Exists(Path.Combine(packageRoot, "RELEASE-ENVELOPE.json")));
        if ((previousSequence == 0 && !IsInitialInstallTargetEmpty(target)) || (previousSequence > 0 && !HasInstalledPayload(target)))
            throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
        if (envelope.Sequence < previousSequence) throw new InvalidDataException("BF-SETUP-ROLLBACK");
        if (envelope.Sequence == previousSequence)
        {
            var plan = envelope.Plan;
            var installedDigest = ReadStateEnvelopeDigest(statePath, testRoot);
            if (plan is not null && string.Equals(installedDigest, plan.EnvelopeDigest, StringComparison.Ordinal))
            {
                // A matching sequence/digest proves release identity, not
                // operational health.  Older builds returned success here
                // even when the service registration had been deleted, the
                // stable launcher was missing, or the current generation had
                // lost files.  A manual reinstall must be an idempotent
                // repair operation, never a false-success shortcut.
                var installedPayloadRoot = generationLayout
                    ? ReadCurrentPayloadRoot(target, testRoot) ?? throw new InvalidDataException("BF-SETUP-STATE-CORRUPT")
                    : target;
                try
                {
                    var installedFiles = VerifyPayload(
                        installedPayloadRoot, envelope,
                        stageIsRoot: true,
                        testRoot: testRoot,
                        admitInstalledSupportingArtifacts: true);
                    DisposeVerified(installedFiles);
                }
                catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or CryptographicException)
                {
                    throw new InvalidDataException("BF-SETUP-STATE-CORRUPT", error);
                }
                if (whatIf) return 0;

                RepairSameSequenceService(target, updateRoot, installedPayloadRoot, envelope, testRoot, fakeServiceMode);
                if (!testRoot && generationLayout) EnsureStableLauncher(target, envelope, installedPayloadRoot);
                if (File.Exists(ResolveUninstalledMarkerPath(target)) && !TryDeleteResult(ResolveUninstalledMarkerPath(target))) throw new InvalidDataException("BF-SETUP-STATE");
                if (!testRoot) RegisterWindowsUninstallEntry(target);
                return 0;
            }
            throw new InvalidDataException("BF-SETUP-EQUIVOCATION");
        }
        if (whatIf) return 0;
        EnsureInstallRootLayout(target, testRoot);
        EnsureInboxLayout(updateRoot, testRoot);
        EnsureStateLayout(target, testRoot);
        var staging = generationLayout
            ? Path.Combine(target, ".bifrost-generations", $".staging-{envelope.Sequence}-{Guid.NewGuid():N}")
            : target + $".incoming-{envelope.Sequence}-{Guid.NewGuid():N}";
        var generationRoot = generationLayout ? Path.Combine(target, ".bifrost-generations", $"g-{envelope.Sequence}-{envelope.Plan?.EnvelopeDigest[..16]}") : null;
        var previousPayloadRoot = generationLayout ? ReadCurrentPayloadRoot(target, testRoot) : null;
        var backup = generationLayout ? string.Empty : target + $".previous-{Guid.NewGuid():N}";
        var applied = new List<(string destination, string? backup)>();
        var service = CreateServiceLifecycle(testRoot, fakeServiceMode, updateRoot, target);
        // Keep the transaction pre-state immutable.  The apply result is a
        // separate value so a successful reconfigure can never overwrite the
        // rollback snapshot.
        var serviceSnapshot = ServicePreState.None;
        ServiceApplyResult? serviceResult = null;
        IpcBindingProvision? ipcBinding = null;
        var previousState = ReadOptionalState(statePath);
        var pointerPath = Path.Combine(ResolveStateRoot(target), "current.json");
        var previousPointer = ReadOptionalState(pointerPath);
        var previousOwnership = ReadOptionalState(ResolveOwnershipPath(target));
        var previousUninstalledMarker = ReadOptionalState(ResolveUninstalledMarkerPath(target));
        var promotionOperationId = Guid.NewGuid().ToString("N");
        var installPhase = "IPC";
        try
        {
            if (!legacyTestFixtureInstall) ipcBinding = ProvisionOrValidateIpcBinding(target, testRoot, previousSequence == 0);
            installPhase = "STAGE-PREPARE";
            if (generationLayout)
            {
                EnsureNoReparseChain(Path.GetDirectoryName(staging)!, allowMissingLeaf: true);
                Directory.CreateDirectory(Path.GetDirectoryName(staging)!);
            }
            installPhase = "STAGE-COPY";
            CopyVerified(files, staging, fakeFailureMode);
            if (!testRoot && previousSequence == 0)
            {
                // A verified fresh install owns the fixed product service
                // name. Do not let a registration left by another Bifrost
                // directory block installation: payload signature and hashes
                // have already passed, and the complete candidate is staged.
                // Replace only this exact service name; preserve enrollment,
                // signed configuration and every unrelated Windows service.
                installPhase = "SERVICE-REPLACE-LEGACY";
                ReplaceExistingBifrostServiceForFreshInstall();
            }
            if (generationLayout)
            {
                if (generationRoot is null)
                {
                    throw new InvalidDataException("BF-SETUP-GENERATION");
                }
                var reuseExistingGeneration = Directory.Exists(generationRoot);
                if (reuseExistingGeneration)
                {
                    installPhase = "STAGE-REUSE";
                    var existingFiles = VerifyPayload(generationRoot, envelope, stageIsRoot: true, testRoot: testRoot);
                    DisposeVerified(existingFiles);
                    TryDeleteResult(staging);
                }
                if (FaultEnabled(fakeFailureMode, "rename")) throw new IOException("BF-SETUP-FAULT");
                installPhase = "SERVICE-CAPTURE";
                serviceSnapshot = service.CapturePreState();
                var candidateBinary = ResolveServiceBinary(generationRoot, envelope, requireExists: false);
                var candidateIntent = ExpectedServiceCandidate(candidateBinary, serviceSnapshot);
                // Persist the authenticated pre-state and create/reconfigure
                // intent before any SCM stop/create side effect.
                installPhase = "JOURNAL";
                WritePromotionJournal(target, "candidate", envelope.Sequence, promotionOperationId, staging, generationRoot, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, candidateIntent, testRoot ? updateRoot : target);
                installPhase = "SERVICE-STOP";
                service.StopVerified(serviceSnapshot);
                installPhase = "JOURNAL-STOPPED";
                WritePromotionJournal(target, "candidate", envelope.Sequence, promotionOperationId, staging, generationRoot, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, candidateIntent, testRoot ? updateRoot : target);
                installPhase = "GENERATION-PROMOTE";
                if (!reuseExistingGeneration) Directory.Move(staging, generationRoot);
                if (FaultEnabled(fakeFailureMode, "crash-after-rename")) Environment.Exit(91);
                installPhase = "SERVICE-START";
                serviceResult = serviceSnapshot.Exists ? service.ReconfigureAndStart(candidateBinary, serviceSnapshot) : service.CreateAndStart(candidateBinary);
                installPhase = "JOURNAL-STARTED";
                WritePromotionJournal(target, "candidate", envelope.Sequence, promotionOperationId, staging, generationRoot, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, serviceResult, testRoot ? updateRoot : target);
            }
            else
            {
                installPhase = "SERVICE-CAPTURE";
                serviceSnapshot = service.CapturePreState();
                installPhase = "SERVICE-STOP";
                service.StopVerified(serviceSnapshot);
                installPhase = "GENERATION-PROMOTE";
                PromoteVerified(files, staging, target, backup, applied, fakeFailureMode);
                installPhase = "SERVICE-START";
                serviceResult = serviceSnapshot.Exists
                    ? service.ReconfigureAndStart(ResolveServiceBinary(target, envelope), serviceSnapshot)
                    : service.CreateAndStart(ResolveServiceBinary(target, envelope));
            }
            installPhase = "SERVICE-HEALTH";
            if (service.EnsureHealthy() == ServiceHealthResult.Deferred) throw new InvalidDataException("BF-SETUP-SCM-DEFERRED");
            installPhase = "JOURNAL-HEALTHY";
            if (generationLayout && generationRoot is not null) WritePromotionJournal(target, "healthy", envelope.Sequence, promotionOperationId, staging, generationRoot, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, serviceResult, testRoot ? updateRoot : target);
            installPhase = "STATE";
            WriteState(statePath, envelope, fakeFailureMode);
            installPhase = "POINTER";
            if (generationLayout) WriteGenerationPointer(target, envelope, previousPayloadRoot, previousSequence > 0 ? $"{previousSequence}" : null, fakeFailureMode, generationRoot, previousState);
            installPhase = "OWNERSHIP";
            if (!testRoot || envelope.Plan is not null) WriteOwnership(target, envelope, previousSequence > 0 ? $"{previousSequence}" : null, testRoot);
            installPhase = "LAUNCHER";
            if (!testRoot && generationLayout && generationRoot is not null) EnsureStableLauncher(target, envelope, generationRoot);
            installPhase = "JOURNAL-COMMIT";
            if (generationLayout) { WritePromotionJournal(target, "committed", envelope.Sequence, promotionOperationId, staging, generationRoot!, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, serviceResult, testRoot ? updateRoot : target); ClearPromotionJournal(target); }
            // Consume the marker only after the generation transaction is
            // durable.  A crash before this cleanup leaves a harmless marker
            // beside a valid state/ownership tuple, never an unmarked half-
            // install; the next same-sequence run cleans it up.
            if (File.Exists(ResolveUninstalledMarkerPath(target)) && !TryDeleteResult(ResolveUninstalledMarkerPath(target))) throw new InvalidDataException("BF-SETUP-STATE");
            installPhase = "REGISTRY";
            if (!testRoot) RegisterWindowsUninstallEntry(target);
            installPhase = "PRUNE";
            if (generationLayout) PruneObsoleteGenerationsBestEffort(target, generationRoot, previousPayloadRoot);
            return 0;
        }
        catch (Exception error)
        {
            var rollbackOk = TryRollback(service, serviceSnapshot, serviceResult, applied, backup, statePath, previousState);
            if (generationLayout && generationRoot is not null && Directory.Exists(generationRoot)) rollbackOk = TryDeleteResult(generationRoot) && rollbackOk;
            try { RestoreState(pointerPath, previousPointer); } catch { rollbackOk = false; }
            try { RestoreState(ResolveUninstalledMarkerPath(target), previousUninstalledMarker); } catch { rollbackOk = false; }
            if (generationLayout)
            {
                try { ClearPromotionJournal(target); } catch { rollbackOk = false; }
            }
            if (previousSequence == 0 && ipcBinding is { Created: true })
            {
                try { TryDeleteResult(Path.Combine(ipcBinding.Root, "ipc-binding.bin")); TryDeleteResult(Path.Combine(ipcBinding.Root, "interactive.sid")); if (Directory.Exists(ipcBinding.Root) && !Directory.EnumerateFileSystemEntries(ipcBinding.Root).Any()) Directory.Delete(ipcBinding.Root); } catch { rollbackOk = false; }
            }
            var cleanupOk = TryDeleteResult(staging);
            try { RestoreState(ResolveOwnershipPath(target), previousOwnership); } catch { rollbackOk = false; }
            if (!testRoot && previousSequence == 0)
            {
                try { RemoveWindowsUninstallEntry(target); } catch { rollbackOk = false; }
            }
            if (!rollbackOk || !cleanupOk)
                throw new InvalidDataException(BuildRollbackDiagnostic(error, installPhase));
            // Shipping diagnostics expose only a bounded stable phase token,
            // never an exception message, source/destination path, service
            // output or payload data. Existing BF-* contract failures retain
            // their more precise code; unexpected framework/IO failures are
            // mapped to the last completed installation boundary.
            if (error.Message.StartsWith("BF-", StringComparison.Ordinal) && error.Message.Length <= 96 &&
                error.Message.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-'))
                throw;
            throw new InvalidDataException($"BF-SETUP-INSTALL-{installPhase}", error);
        }
        finally
        {
            if (previousState is not null) CryptographicOperations.ZeroMemory(previousState);
            if (previousPointer is not null) CryptographicOperations.ZeroMemory(previousPointer);
            if (previousOwnership is not null) CryptographicOperations.ZeroMemory(previousOwnership);
            if (previousUninstalledMarker is not null) CryptographicOperations.ZeroMemory(previousUninstalledMarker);
        }
    }

    private static void RepairSameSequenceService(string installRoot, string updateRoot, string payloadRoot, VerifiedEnvelope envelope, bool testRoot, string? fakeServiceMode)
    {
        var service = CreateServiceLifecycle(testRoot, fakeServiceMode, updateRoot, installRoot);
        var expectedBinary = ResolveServiceBinary(payloadRoot, envelope);
        var expectedGeneration = Path.GetFileName(Path.GetDirectoryName(expectedBinary) ?? string.Empty);
        var snapshot = service.CapturePreState();
        ServiceApplyResult? applied = null;
        try
        {
            if (snapshot.Exists && snapshot.WasRunning &&
                string.Equals(Path.GetFullPath(snapshot.BinPath), Path.GetFullPath(expectedBinary), StringComparison.OrdinalIgnoreCase))
            {
                var committed = new ServiceApplyResult(
                    true, true, false, expectedBinary, snapshot.StartMode,
                    snapshot.Identity, snapshot.Sid, expectedGeneration);
                if (service.ValidateCommitted(committed)) return;
            }

            // Reconfigure a running stale/unhealthy service only after a
            // verified stop.  Reinstall semantics deliberately require the
            // repaired service to be running even when a previous damaged
            // registration happened to be stopped; rollback still uses the
            // immutable original snapshot and restores that exact pre-state.
            if (snapshot.Exists && snapshot.WasRunning) service.StopVerified(snapshot);
            var desired = snapshot.Exists ? snapshot with { WasRunning = true } : snapshot;
            applied = snapshot.Exists
                ? service.ReconfigureAndStart(expectedBinary, desired)
                : service.CreateAndStart(expectedBinary);
            if (service.EnsureHealthy() != ServiceHealthResult.Healthy)
                throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
        }
        catch
        {
            try
            {
                service.PrepareRollback(snapshot, applied);
                service.RestoreAfterRollback(snapshot);
            }
            catch
            {
                throw new InvalidDataException("BF-SETUP-SCM-ROLLBACK");
            }
            throw;
        }
    }

    private static int ApplyPendingCommand(string installRootText, bool whatIf, string? updateRootOverride, bool testRoot, bool helper, string? waitForPid, string? fakeServiceMode, string? operationNonce, string? expectedSequenceText, string? fakeFailureMode, string? fakeParentWait)
    {
        var installRoot = ResolveInstallRoot(installRootText, testRoot);
        // The update manager and the elevated promoter derive the state root
        // independently from the machine-wide application-data location.
        // Never trust a user-writable state_path in the pending marker.
        var updateRoot = ResolveUpdateRoot(updateRootOverride, testRoot);
        EnsureSeparateRoots(updateRoot, installRoot);
        using FileStream? installLock = whatIf ? null : AcquireInstallLock(installRoot);
        if (whatIf) { ValidateUninstallJournalReadOnly(installRoot); ValidatePromotionJournalReadOnly(installRoot); }
        else { RecoverUninstallJournal(installRoot, testRoot, fakeServiceMode, updateRoot); RecoverPromotionJournal(installRoot, testRoot); }
        var pendingPath = Path.Combine(updateRoot, "update-pending.json");
        var statePath = ResolveStatePath(installRoot);
        var currentNonce = helper ? RequireOperationNonce(operationNonce) : null;
        var operationSequence = helper ? ParsePositiveSequence(expectedSequenceText) : 0L;
        var operationStarted = helper;
        var lifecycleTouched = false;
        string? staging = null;
        byte[]? previousState = null;
        byte[]? previousPointer = null;
        byte[]? previousOwnership = null;
        var applied = new List<(string destination, string? backup)>();
        var serviceSnapshot = ServicePreState.None;
        ServiceApplyResult? serviceResult = null;
        IpcBindingProvision? ipcBinding = null;
        var service = CreateServiceLifecycle(testRoot, fakeServiceMode, updateRoot, installRoot);
        var backup = Path.Combine(installRoot, ".bifrost-backup", $"update-pending-{Guid.NewGuid():N}");
        var protectedRoot = Path.Combine(installRoot, ".bifrost-protected", $"update-pending-{Guid.NewGuid():N}");
        string? generationRoot = null;
        var generationMoved = false;

        try
        {
            if (helper)
            {
                // The parent writes this record before spawning the helper. It
                // is the only operation the helper may complete.
                EnsureScheduledOperation(installRoot, operationSequence, currentNonce!);
                if (!string.IsNullOrWhiteSpace(fakeParentWait))
                {
                    if (!testRoot) throw new InvalidDataException("BF-SETUP-PARENT");
                    WaitForParentExitTest(fakeParentWait!);
                }
                else if (!string.IsNullOrWhiteSpace(waitForPid)) WaitForParentExit(waitForPid!);
            }

            EnsureNoReparseChain(updateRoot, allowMissingLeaf: true);
            var pending = ReadStrictObject(pendingPath, 512 * 1024);
            var allowed = new HashSet<string>(StringComparer.Ordinal) { "operation_id", "manifest_text", "signature", "envelope_bytes_b64", "envelope_digest", "manifest_digest", "allowlist_digest", "root_key_id", "root_fingerprint", "authority_digest", "authority_generation", "delegation_generation", "signing_key_id", "channel", "rollback_floor", "plan", "stage_directory", "protected_operation" };
            if (pending.EnumerateObject().Any(p => !allowed.Contains(p.Name)) ||
                !pending.TryGetProperty("manifest_text", out var manifestText) || manifestText.ValueKind != JsonValueKind.String ||
                !pending.TryGetProperty("signature", out var signature) || signature.ValueKind != JsonValueKind.String ||
                !pending.TryGetProperty("stage_directory", out var stageValue) || stageValue.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("BF-SETUP-PENDING-SHAPE");
            var pendingFields = pending.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
            var legacyBridgePending = pendingFields.SetEquals(new[] { "manifest_text", "signature", "stage_directory" });

            // The previous authority is read and validated while the install
            // lock is held, before any new envelope is accepted.  A pending
            // marker can never manufacture a first-install/legacy state.
            ReleaseStateAuthority.State? previousAuthority = null;
            var legacyTestFixture = false;
#if BIFROST_TEST_HARNESS
            legacyTestFixture = testRoot && string.Equals(Environment.GetEnvironmentVariable("BIFROST_TEST_LEGACY_FIXTURE"), "1", StringComparison.Ordinal);
#endif
            if (!legacyTestFixture) previousAuthority = ReadReleaseAuthorityStateForInstaller(statePath);
            VerifiedEnvelope envelope;
            if (pending.TryGetProperty("envelope_bytes_b64", out var envelopeBytesValue) && envelopeBytesValue.ValueKind == JsonValueKind.String)
            {
                byte[] envelopeBytes;
                try { envelopeBytes = Convert.FromBase64String(envelopeBytesValue.GetString()!); } catch { throw new InvalidDataException("BF-SETUP-ENVELOPE"); }
                try
                {
                    if (testRoot && !HarnessUsesProductionTrust(testRoot))
                    {
#if BIFROST_TEST_HARNESS
                        var testKeyPath = Environment.GetEnvironmentVariable("BIFROST_TEST_RELEASE_PUBLIC_KEY_FILE");
                        if (string.IsNullOrWhiteSpace(testKeyPath) || !File.Exists(testKeyPath)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
                        envelope = ReleaseUpdateManager.VerifyEnvelopeForInstallerTest(envelopeBytes, File.ReadAllText(testKeyPath), previousAuthority ?? throw new InvalidDataException("BF-SETUP-STATE-CORRUPT"));
#else
                        throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
                    }
                    else envelope = ReleaseUpdateManager.VerifyEnvelopeForInstaller(envelopeBytes, previousAuthority ?? throw new InvalidDataException("BF-SETUP-STATE-CORRUPT"));
                }
                finally { CryptographicOperations.ZeroMemory(envelopeBytes); }
            }
            else
            {
                if (legacyTestFixture)
                {
                    envelope = VerifyEnvelopeText(manifestText.GetString()!, signature.GetString()!, true);
                }
                else if (legacyBridgePending)
                {
                    var delegationText = ReadEmbeddedReleaseAuthority("Bifrost.LegacyReleaseDelegation.json");
                    var keyStateText = ReadEmbeddedReleaseAuthority("Bifrost.LegacyReleaseKeyState.json");
                    envelope = ReleaseUpdateManager.VerifyLegacyBridgeForInstaller(
                        manifestText.GetString()!, signature.GetString()!, delegationText, keyStateText,
                        previousAuthority ?? throw new InvalidDataException("BF-SETUP-STATE-CORRUPT"));
                }
                else throw new InvalidDataException("BF-SETUP-ENVELOPE");
            }
            if (!legacyTestFixture) ipcBinding = ProvisionOrValidateIpcBinding(installRoot, testRoot, initialInstall: false);
            if (helper && envelope.Sequence != operationSequence)
                throw new InvalidDataException("BF-SETUP-OPERATION");
            staging = Path.GetFullPath(stageValue.GetString()!);
            if (!IsContained(updateRoot, staging) || string.Equals(staging, updateRoot, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-STAGE-PATH");
            EnsureNoReparseChain(staging, allowMissingLeaf: false);
            var previousSequence = ReadStateSequence(statePath, testRoot);
            if (previousSequence <= 0)
                throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
            ValidateCurrentPointer(installRoot, previousSequence, testRoot);
            try { _ = ReadOwnership(installRoot, testRoot); }
            catch when (legacyTestFixture && !whatIf)
            {
                EnsureStateLayout(installRoot, testRoot);
                if (envelope.Plan is not null) WriteOwnership(installRoot, envelope, previousSequence.ToString(System.Globalization.CultureInfo.InvariantCulture), testRoot);
            }
            var hasAuthoritativePlan = envelope.Plan is { RootKeyId: not null, AuthorityDigest: not null, AuthorityGeneration: > 0 };
            if (pending.TryGetProperty("protected_operation", out var protectedValue) && protectedValue.ValueKind == JsonValueKind.String)
            {
                byte[] protectedBytes;
                try { protectedBytes = Convert.FromBase64String(protectedValue.GetString()!); } catch { throw new InvalidDataException("BF-SETUP-OPERATION"); }
                try
                {
                    var operation = ReleaseUpdateManager.UnprotectPendingOperation(protectedBytes);
                    var requiredArtifactSet = string.Join("\n", (envelope.Plan?.Artifacts ?? Array.Empty<Artifact>()).Where(artifact => artifact.Platform == "windows" && artifact.Arch == "x64" && (artifact.Kind is "exe" or "service-exe" or "installer" or "core" or "core-manifest" or "metadata")).Select(artifact => artifact.Id).OrderBy(id => id, StringComparer.Ordinal));
                    var ownershipForOperation = ReadOwnership(installRoot, testRoot, verifyBoundFiles: true);
                    var expectedInstallId = ownershipForOperation.GetProperty("install_id").GetString() ?? throw new InvalidDataException("BF-SETUP-OPERATION");
                    var currentPointerForOperation = ReadStrictObject(Path.Combine(ResolveStateRoot(installRoot), "current.json"), 64 * 1024);
                    var expectedCurrentGeneration = currentPointerForOperation.GetProperty("current_generation").GetString() ?? throw new InvalidDataException("BF-SETUP-OPERATION");
                    var expectedPointerDigest = FileDigestOrEmpty(Path.Combine(ResolveStateRoot(installRoot), "current.json"));
                    var authorityForOperation = previousAuthority ?? throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
                    if (!pending.TryGetProperty("operation_id", out var pendingOperationId) || pendingOperationId.ValueKind != JsonValueKind.String || !string.Equals(pendingOperationId.GetString(), operation.OperationId, StringComparison.Ordinal) || !string.Equals(operation.RequiredArtifactSet, requiredArtifactSet, StringComparison.Ordinal) || !string.Equals(operation.StageDirectory, staging, StringComparison.OrdinalIgnoreCase) || !string.Equals(operation.UpdateRoot, Path.GetFullPath(updateRoot), StringComparison.OrdinalIgnoreCase) || !string.Equals(operation.InstallRoot, Path.GetFullPath(installRoot), StringComparison.OrdinalIgnoreCase) || operation.Sequence != envelope.Sequence || operation.ExpectedPreviousSequence != previousSequence || operation.EnvelopeDigest != envelope.Plan?.EnvelopeDigest || operation.ManifestDigest != envelope.Plan?.ManifestDigest || operation.AllowlistDigest != envelope.Plan?.AllowlistDigest || operation.Floor != envelope.Plan?.Floor || operation.AuthorityGeneration != envelope.Plan?.AuthorityGeneration || operation.AuthorityDigest != envelope.Plan?.AuthorityDigest || operation.ExpectedCurrentGeneration != expectedCurrentGeneration || operation.ExpectedCurrentEnvelopeDigest != authorityForOperation.EnvelopeDigest || operation.ExpectedCurrentManifestDigest != authorityForOperation.ManifestDigest || operation.ExpectedCurrentAuthorityGeneration != authorityForOperation.AuthorityGeneration || operation.ExpectedCurrentAuthorityDigest != authorityForOperation.AuthorityDigest || operation.ExpectedCurrentPointerDigest != expectedPointerDigest || operation.ExpectedInstallId != expectedInstallId) throw new InvalidDataException("BF-SETUP-OPERATION");
                }
                finally { CryptographicOperations.ZeroMemory(protectedBytes); }
            }
            else if ((!testRoot || hasAuthoritativePlan) && !legacyBridgePending) throw new InvalidDataException("BF-SETUP-OPERATION");
            if (envelope.Sequence <= previousSequence) throw new InvalidDataException("BF-SETUP-ROLLBACK");
            var files = VerifyPayload(staging, envelope, stageIsRoot: true, testRoot: testRoot);
            if (pending.TryGetProperty("protected_operation", out var protectedOperationElement) && protectedOperationElement.ValueKind == JsonValueKind.String)
            {
                byte[] protectedOperationBytes;
                try { protectedOperationBytes = Convert.FromBase64String(protectedOperationElement.GetString()!); } catch { throw new InvalidDataException("BF-SETUP-OPERATION"); }
                try
                {
                    var operation = ReleaseUpdateManager.UnprotectPendingOperation(protectedOperationBytes);
                    if (!string.Equals(operation.StageIdentity, ComputeVerifiedTreeIdentity(files), StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-STAGE");
                }
                finally { CryptographicOperations.ZeroMemory(protectedOperationBytes); }
            }
            var destinations = files.Select(file => ResolveContained(installRoot, file.Metadata.InstallPath ?? file.Metadata.Path)).ToArray();
            if (destinations.Distinct(StringComparer.OrdinalIgnoreCase).Count() != destinations.Length) throw new InvalidDataException("BF-SETUP-PATH-COLLISION");
            if (whatIf) return 0;

            EnsureInboxLayout(updateRoot, testRoot);
            EnsureStateLayout(installRoot, testRoot);
            previousState = ReadOptionalState(statePath);
            previousPointer = ReadOptionalState(Path.Combine(ResolveStateRoot(installRoot), "current.json"));
            previousOwnership = ReadOptionalState(ResolveOwnershipPath(installRoot));
            var generationLayout = UseGenerationLayout(envelope, testRoot, pending.TryGetProperty("envelope_bytes_b64", out var fullEnvelopeMarker) && fullEnvelopeMarker.ValueKind == JsonValueKind.String);
            var previousPayloadRoot = generationLayout ? ReadCurrentPayloadRoot(installRoot, testRoot) : null;
            generationRoot = generationLayout
                ? Path.Combine(installRoot, ".bifrost-generations", $"g-{envelope.Sequence}-{(envelope.Plan ?? throw new InvalidDataException("BF-SETUP-PLAN")).EnvelopeDigest[..16]}")
                : null;
            currentNonce ??= NewOperationNonce();
            operationSequence = envelope.Sequence;
            if (!helper)
            {
                // Establish correlation before any helper is launched or any
                // user-writable payload is copied.
                WriteOperation(installRoot, "scheduled", operationSequence, currentNonce, testRoot);
                operationStarted = true;
            }

            if (!helper && destinations.Any(path => string.Equals(Path.GetFullPath(path), Path.GetFullPath(Environment.ProcessPath ?? string.Empty), StringComparison.OrdinalIgnoreCase)))
            {
                var scheduled = ScheduleSelfUpdate(installRoot, updateRoot, testRoot, fakeServiceMode, envelope.Sequence, currentNonce);
                PrintOperationResult("scheduled", operationSequence, currentNonce);
                return scheduled;
            }

            operationStarted = true;
            var protectedFiles = CopyVerified(files, protectedRoot, fakeFailureMode);
            lifecycleTouched = true;
            if (generationLayout)
            {
                if (generationRoot is null) throw new InvalidDataException("BF-SETUP-GENERATION");
                var reuseExistingGeneration = Directory.Exists(generationRoot);
                if (reuseExistingGeneration)
                {
                    var existingFiles = VerifyPayload(generationRoot, envelope, stageIsRoot: true, testRoot: testRoot);
                    DisposeVerified(existingFiles);
                    TryDeleteResult(protectedRoot);
                }
                EnsureNoReparseChain(Path.Combine(installRoot, ".bifrost-generations"), allowMissingLeaf: true);
                Directory.CreateDirectory(Path.GetDirectoryName(generationRoot)!);
                if (FaultEnabled(fakeFailureMode, "rename")) throw new IOException("BF-SETUP-FAULT");
                serviceSnapshot = service.CapturePreState();
                var candidateBinary = ResolveServiceBinary(generationRoot, envelope, requireExists: false);
                var candidateIntent = ExpectedServiceCandidate(candidateBinary, serviceSnapshot);
                WritePromotionJournal(installRoot, "candidate", envelope.Sequence, currentNonce, protectedRoot, generationRoot, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, candidateIntent, testRoot ? updateRoot : installRoot);
                service.StopVerified(serviceSnapshot);
                service.RecordRollbackEvent("promote");
                WritePromotionJournal(installRoot, "candidate", envelope.Sequence, currentNonce, protectedRoot, generationRoot, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, candidateIntent, testRoot ? updateRoot : installRoot);
                if (!reuseExistingGeneration) Directory.Move(protectedRoot, generationRoot);
                generationMoved = !reuseExistingGeneration;
                if (FaultEnabled(fakeFailureMode, "crash-after-rename")) Environment.Exit(91);
                serviceResult = serviceSnapshot.Exists ? service.ReconfigureAndStart(candidateBinary, serviceSnapshot) : service.CreateAndStart(candidateBinary);
                WritePromotionJournal(installRoot, "candidate", envelope.Sequence, currentNonce, protectedRoot, generationRoot, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, serviceResult, testRoot ? updateRoot : installRoot);
            }
            else
            {
                serviceSnapshot = service.CapturePreState();
                service.StopVerified(serviceSnapshot);
                service.RecordRollbackEvent("promote");
                PromoteVerified(protectedFiles, protectedRoot, installRoot, backup, applied, fakeFailureMode);
                serviceResult = serviceSnapshot.Exists
                    ? service.ReconfigureAndStart(ResolveServiceBinary(installRoot, envelope), serviceSnapshot)
                    : service.CreateAndStart(ResolveServiceBinary(installRoot, envelope));
            }
            if (service.EnsureHealthy() == ServiceHealthResult.Deferred) throw new InvalidDataException("BF-SETUP-SCM-DEFERRED");
            if (generationLayout && generationRoot is not null) WritePromotionJournal(installRoot, "healthy", envelope.Sequence, currentNonce, protectedRoot, generationRoot, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, serviceResult, testRoot ? updateRoot : installRoot);
            if (envelope.Plan is not null) WriteState(statePath, envelope, fakeFailureMode);
            if (generationLayout) WriteGenerationPointer(installRoot, envelope, previousPayloadRoot, previousSequence.ToString(System.Globalization.CultureInfo.InvariantCulture), fakeFailureMode, generationRoot, previousState);
            if (!testRoot || envelope.Plan is not null) WriteOwnership(installRoot, envelope, previousSequence.ToString(System.Globalization.CultureInfo.InvariantCulture), testRoot);
            if (!testRoot && generationLayout && generationRoot is not null) EnsureStableLauncher(installRoot, envelope, generationRoot);
            if (generationLayout) { WritePromotionJournal(installRoot, "committed", envelope.Sequence, currentNonce, protectedRoot, generationRoot!, previousState, previousPointer, previousOwnership, fakeFailureMode, serviceSnapshot, serviceResult, testRoot ? updateRoot : installRoot); ClearPromotionJournal(installRoot); }
            WriteOperation(installRoot, "succeeded", envelope.Sequence, currentNonce, testRoot);
            DeleteRequired(pendingPath);
            PruneSuccessfulUpdateInboxBestEffort(updateRoot);
            if (!generationLayout) TryDeleteResult(backup);
            if (!generationMoved) TryDeleteResult(protectedRoot);
            if (!testRoot) RegisterWindowsUninstallEntry(installRoot);
            if (generationLayout) PruneObsoleteGenerationsBestEffort(installRoot, generationRoot, previousPayloadRoot);
            PrintOperationResult("succeeded", envelope.Sequence, currentNonce);
            return 0;
        }
        catch
        {
            var rollbackRequired = lifecycleTouched || applied.Count != 0 || serviceSnapshot.Exists || serviceResult is not null;
            var rollbackOk = true;
            if (rollbackRequired)
            {
                try { rollbackOk = TryRollback(service, serviceSnapshot, serviceResult, applied, backup, statePath, previousState, fakeFailureMode); }
                catch { rollbackOk = false; }
            try { RestoreState(Path.Combine(ResolveStateRoot(installRoot), "current.json"), previousPointer); } catch { rollbackOk = false; }
            try { RestoreState(ResolveOwnershipPath(installRoot), previousOwnership); } catch { rollbackOk = false; }
            if (generationRoot is not null)
            {
                try { ClearPromotionJournal(installRoot); } catch { rollbackOk = false; }
            }
            }
            var operationOk = true;
            if (operationStarted && currentNonce is not null && operationSequence > 0)
                operationOk = TryWriteOperation(installRoot, "failed", operationSequence, currentNonce, testRoot);
            // A failed promotion deliberately leaves pending.json for a
            // bounded retry, but never leaves protected/backup material behind
            // when it can be removed.
            // Each cleanup operation is independent.  A locked backup must
            // not prevent protected material from being attempted (and vice
            // versa); the aggregate result still fails closed.
            try { service.RecordRollbackEvent("cleanup-backup"); } catch { }
            var backupCleanupOk = TryDeleteResult(backup, FaultEnabled(fakeFailureMode, "cleanup-backup"));
            try { service.RecordRollbackEvent("cleanup-protected"); } catch { }
            var protectedCleanupOk = TryDeleteResult(protectedRoot);
            var generationCleanupOk = !generationMoved || TryDeleteResult(generationRoot);
            var cleanupOk = backupCleanupOk && protectedCleanupOk && generationCleanupOk;
            if (!rollbackOk || !operationOk || !cleanupOk)
                throw new InvalidDataException("BF-SETUP-ROLLBACK");
            throw;
        }
        finally
        {
            if (previousState is not null) CryptographicOperations.ZeroMemory(previousState);
            if (previousPointer is not null) CryptographicOperations.ZeroMemory(previousPointer);
            if (previousOwnership is not null) CryptographicOperations.ZeroMemory(previousOwnership);
        }
    }

    private static void PruneSuccessfulUpdateInboxBestEffort(string updateRoot)
    {
        // Once the signed promotion has committed and update-pending.json is
        // gone, no staging directory or resumable download cache is needed for
        // correctness. Keep cleanup deliberately narrow: only exact
        // Bifrost-owned staging names and the download-cache child are touched.
        // A locked scanner handle may leave one directory behind for the next
        // successful update, but it must never turn a healthy promotion into a
        // failure.
        try
        {
            var root = Path.GetFullPath(updateRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (!Directory.Exists(root)) return;
            EnsureNoReparseChain(root, allowMissingLeaf: false);

            foreach (var directory in Directory.EnumerateDirectories(root, ".update-staging-*", SearchOption.TopDirectoryOnly))
            {
                var full = Path.GetFullPath(directory);
                if (!IsContained(root, full) || string.Equals(root, full, StringComparison.OrdinalIgnoreCase)) continue;
                if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) continue;
                _ = TryDeleteResult(full);
            }

            var cacheRoot = Path.Combine(root, "download-cache");
            if (Directory.Exists(cacheRoot))
            {
                EnsureNoReparseChain(cacheRoot, allowMissingLeaf: false);
                if ((File.GetAttributes(cacheRoot) & FileAttributes.ReparsePoint) == 0)
                    _ = TryDeleteResult(cacheRoot);
            }
        }
        catch
        {
            // Post-commit garbage collection is intentionally best-effort.
        }
    }

    private static string ResolveInstallRoot(string? requested, bool testRoot)
    {
        var defaultRoot = DefaultInstallRoot;
        var candidate = Path.GetFullPath(string.IsNullOrWhiteSpace(requested) ? defaultRoot : requested);
        if (testRoot)
        {
            if (!IsTemporaryRoot(candidate)) throw new InvalidDataException("BF-SETUP-INSTALL-ROOT");
        }
        else
        {
            // Shipping service binaries must remain on a real fixed local
            // volume. A UNC/share/removable path would make LocalSystem code
            // execution depend on an external or user-removable namespace.
            var driveRoot = Path.GetPathRoot(candidate) ?? string.Empty;
            if (driveRoot.Length != 3 || !char.IsAsciiLetter(driveRoot[0]) || driveRoot[1] != ':' ||
                (driveRoot[2] != Path.DirectorySeparatorChar && driveRoot[2] != Path.AltDirectorySeparatorChar))
                throw new InvalidDataException("BF-SETUP-INSTALL-ROOT");
            try
            {
                var drive = new DriveInfo(driveRoot);
                if (!drive.IsReady || drive.DriveType != DriveType.Fixed)
                    throw new InvalidDataException("BF-SETUP-INSTALL-ROOT");
            }
            catch (InvalidDataException) { throw; }
            catch { throw new InvalidDataException("BF-SETUP-INSTALL-ROOT"); }

            // The selected Bifrost directory itself is hardened immediately
            // before payload copy; a bare volume root is rejected because
            // applying the product ACL to an entire drive would be destructive.
            var normalized = candidate.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var volumeRoot = driveRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (string.IsNullOrWhiteSpace(volumeRoot) || string.Equals(normalized, volumeRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("BF-SETUP-INSTALL-ROOT");
        }
        EnsureNoReparseChain(candidate, allowMissingLeaf: true);
        return candidate;
    }

    private static bool IsVerifiedExistingInstallRootForCompatibility(string candidate)
    {
        if (!OperatingSystem.IsWindows() || !Directory.Exists(candidate)) return false;
        try
        {
            EnsureNoReparseChain(candidate, allowMissingLeaf: false);
            _ = ReadOwnership(candidate, testRoot: false, verifyBoundFiles: false);
            return true;
        }
        catch { return false; }
    }

    private static void ValidateNewInstallAncestorIntegrity(string candidate)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-SETUP-INSTALL-PARENT");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        var parent = Path.GetDirectoryName(full);
        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
            throw new InvalidDataException("BF-SETUP-INSTALL-PARENT");

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        SecurityIdentifier trustedInstaller;
        try
        {
            trustedInstaller = (SecurityIdentifier)new NTAccount("NT SERVICE\\TrustedInstaller")
                .Translate(typeof(SecurityIdentifier));
        }
        catch { throw new InvalidDataException("BF-SETUP-INSTALL-PARENT"); }
        var trusted = new[] { system, administrators, trustedInstaller };
        var volumeRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetPathRoot(full) ?? string.Empty));
        var current = Path.TrimEndingDirectorySeparator(Path.GetFullPath(parent));
        var replacementRights = FileSystemRights.Delete |
                                FileSystemRights.DeleteSubdirectoriesAndFiles |
                                FileSystemRights.ChangePermissions |
                                FileSystemRights.TakeOwnership;

        while (true)
        {
            EnsureNoReparseChain(current, allowMissingLeaf: false);
            DirectorySecurity security;
            try
            {
                security = new DirectoryInfo(current)
                    .GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            }
            catch { throw new InvalidDataException("BF-SETUP-INSTALL-PARENT"); }
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner is null || !trusted.Any(value => value.Equals(owner)))
                throw new InvalidDataException("BF-SETUP-INSTALL-PARENT");

            var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow ||
                    (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                if (rule.IdentityReference is not SecurityIdentifier sid || trusted.Any(value => value.Equals(sid))) continue;
                var raw = unchecked((uint)(int)rule.FileSystemRights);
                var genericWriteOrAll = (raw & (0x40000000u | 0x10000000u)) != 0;
                // DELETE on the volume-root object itself cannot rename or
                // replace one of its child directories. Typical secondary
                // fixed drives grant Authenticated Users Modify on E:\, which
                // includes that otherwise harmless root DELETE bit and used to
                // make every secure E:\Bifrost installation fail with
                // BF-SETUP-INSTALL-PARENT. DELETE_CHILD, WRITE_DAC,
                // WRITE_OWNER and generic write/all remain disallowed at the
                // volume boundary. For every ordinary ancestor, DELETE is
                // still replacement authority and remains fail-closed.
                var effectiveReplacementRights = string.Equals(current, volumeRoot, StringComparison.OrdinalIgnoreCase)
                    ? replacementRights & ~FileSystemRights.Delete
                    : replacementRights;
                if ((rule.FileSystemRights & effectiveReplacementRights) != 0 || genericWriteOrAll)
                    throw new InvalidDataException("BF-SETUP-INSTALL-PARENT");
            }

            if (string.Equals(current, volumeRoot, StringComparison.OrdinalIgnoreCase)) break;
            var next = Path.GetDirectoryName(current);
            if (string.IsNullOrWhiteSpace(next) || string.Equals(next, current, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("BF-SETUP-INSTALL-PARENT");
            current = Path.TrimEndingDirectorySeparator(Path.GetFullPath(next));
        }
    }

    private static void EnsureInstallRootLayout(string installRoot, bool testRoot)
    {
        EnsureNoReparseChain(installRoot, allowMissingLeaf: true);
        Directory.CreateDirectory(installRoot);
        EnsureNoReparseChain(installRoot, allowMissingLeaf: false);
        if (!testRoot)
        {
            ApplyRestrictedAcl(installRoot, userWritable: false);
            ValidateRestrictedAcl(installRoot, userWritable: false);
        }
    }

    private static string ResolveUpdateRoot(string? requested, bool testRoot)
    {
        var trusted = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost", "updates");
        if (string.IsNullOrWhiteSpace(requested))
        {
            EnsureNoReparseChain(trusted, allowMissingLeaf: true);
            return trusted;
        }
        if (!testRoot || !IsTemporaryRoot(requested)) throw new InvalidDataException("BF-SETUP-UPDATE-ROOT");
        var result = Path.GetFullPath(requested);
        EnsureNoReparseChain(result, allowMissingLeaf: true);
        return result;
    }

    private static void EnsureStableLauncher(string installRoot, VerifiedEnvelope envelope, string payloadRoot)
    {
        var plan = envelope.Plan ?? throw new InvalidDataException("BF-SETUP-PLAN");
        var installer = plan.Artifacts.SingleOrDefault(artifact =>
            artifact.Platform == "windows" && artifact.Arch == "x64" && artifact.Kind == "installer")
            ?? throw new InvalidDataException("BF-SETUP-WINDOWS-SET");
        var source = ResolveContained(payloadRoot, installer.InstallPath ?? installer.Path);
        if (!File.Exists(source)) throw new InvalidDataException("BF-SETUP-ARTIFACT");
        EnsureNoReparseChain(source, allowMissingLeaf: false);

        EnsureNoReparseChain(installRoot, allowMissingLeaf: false);
        CopyStableInstaller(source, Path.Combine(installRoot, "Bifrost.exe"), installer);
        CopyStableInstaller(source, Path.Combine(installRoot, "BifrostSetup.exe"), installer);
    }

    private static void CopyStableInstaller(string source, string destination, Artifact installer)
    {
        var installRoot = Path.GetDirectoryName(destination) ?? throw new InvalidDataException("BF-SETUP-ARTIFACT");
        var temporary = Path.Combine(installRoot, $".bifrost-launcher-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan))
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.WriteThrough))
            {
                input.CopyTo(output, 1024 * 1024);
                output.Flush(flushToDisk: true);
            }
            using (var stream = new FileStream(temporary, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan))
            {
                var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
                if (!string.Equals(digest, installer.Sha256, StringComparison.Ordinal) || new FileInfo(temporary).Length != installer.Bytes)
                    throw new InvalidDataException("BF-SETUP-ARTIFACT-HASH");
            }
            File.Move(temporary, destination, overwrite: true);
            EnsureNoReparseChain(destination, allowMissingLeaf: false);
        }
        finally
        {
            TryDeleteResult(temporary);
        }
    }

    private static void RegisterWindowsUninstallEntry(string installRoot)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-SETUP-REGISTRY");
        var root = Path.GetFullPath(installRoot);
        var launcher = Path.Combine(root, "Bifrost.exe");
        var setup = Path.Combine(root, "BifrostSetup.exe");
        if (!File.Exists(launcher) || !File.Exists(setup)) throw new InvalidDataException("BF-SETUP-REGISTRY");
        EnsureNoReparseChain(launcher, allowMissingLeaf: false);
        EnsureNoReparseChain(setup, allowMissingLeaf: false);
        // Online promotion is executed by the previously installed setup
        // helper.  Using this process' AssemblyVersion therefore leaves Apps
        // & Features one release behind even after the new signed launcher is
        // already current.  The root launcher was copied from the verified
        // installer artifact above, so bind DisplayVersion to that installed
        // file instead of the helper that happened to perform promotion.
        var fileVersion = FileVersionInfo.GetVersionInfo(launcher).FileVersion;
        if (!Version.TryParse(fileVersion, out var parsedVersion) || parsedVersion.Major < 0 || parsedVersion.Minor < 0 || parsedVersion.Build < 0)
            throw new InvalidDataException("BF-SETUP-REGISTRY");
        var version = $"{parsedVersion.Major}.{parsedVersion.Minor}.{parsedVersion.Build}";
        // Windows Apps & Features must invoke the installer helper. Bifrost.exe
        // is the WPF client and intentionally does not own privileged setup
        // verbs; pointing UninstallString at it only launches the application.
        var uninstall = $"\"{setup}\" --uninstall --install-root \"{root}\" --purge";
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = machine.CreateSubKey(UninstallRegistryPath, writable: true) ?? throw new InvalidDataException("BF-SETUP-REGISTRY");
        key.SetValue("DisplayName", "Bifrost", RegistryValueKind.String);
        key.SetValue("DisplayVersion", version, RegistryValueKind.String);
        key.SetValue("Publisher", "Bifrost", RegistryValueKind.String);
        key.SetValue("InstallLocation", root, RegistryValueKind.String);
        key.SetValue("DisplayIcon", launcher, RegistryValueKind.String);
        key.SetValue("UninstallString", uninstall, RegistryValueKind.String);
        key.SetValue("QuietUninstallString", uninstall, RegistryValueKind.String);
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
    }

    private static void RemoveWindowsUninstallEntry(string installRoot, bool tolerateMissing = true)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using (var key = machine.OpenSubKey(UninstallRegistryPath, writable: false))
        {
            if (key is null)
            {
                if (tolerateMissing) return;
                throw new InvalidDataException("BF-SETUP-REGISTRY");
            }
            var registered = key.GetValue("InstallLocation") as string;
            if (string.IsNullOrWhiteSpace(registered) || !string.Equals(Path.GetFullPath(registered), Path.GetFullPath(installRoot), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("BF-SETUP-REGISTRY");
        }
        machine.DeleteSubKeyTree(UninstallRegistryPath, throwOnMissingSubKey: !tolerateMissing);
    }

    private static string ResolveStateRoot(string installRoot) => Path.Combine(installRoot, StateDirectoryName);
    private static string ResolveStatePath(string installRoot) => Path.Combine(ResolveStateRoot(installRoot), "update-state.json");
    private static string ResolveOperationPath(string installRoot) => Path.Combine(ResolveStateRoot(installRoot), OperationResultName);
    private static string ResolveOwnershipPath(string installRoot) => Path.Combine(ResolveStateRoot(installRoot), "ownership.json");
    private static string ResolvePromotionJournalPath(string installRoot) => Path.Combine(ResolveStateRoot(installRoot), "promotion-journal.json");
    private static string ResolveUninstalledMarkerPath(string installRoot) => Path.Combine(ResolveStateRoot(installRoot), "uninstalled.json");
    private static string ResolveUninstallJournalPath(string installRoot) => ResolveExternalInstallLockPath(installRoot) + ".uninstall.json";

    private static readonly HashSet<string> UninstallJournalFields = new(StringComparer.Ordinal)
    {
        "schema", "kind", "phase", "operation_id", "install_root", "root_identity", "install_id", "purge", "tombstone",
        "preserved", "previous_state_b64", "previous_state_sha256", "previous_pointer_b64", "previous_pointer_sha256",
        "previous_ownership_b64", "previous_ownership_sha256", "service_pre_state", "service_state_root", "ipc_binding_digest", "ipc_interactive_sid",
        "binding_phase", "binding_tombstone"
    };

    private static string UninstallJournalAad(string installRoot) =>
        "Bifrost.UninstallJournal.v1|" + Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static string ResolveIpcBindingTombstone(string installRoot, bool testRoot, string operationId)
    {
        if (string.IsNullOrWhiteSpace(operationId) || operationId.Length > 96) throw new InvalidDataException("BF-SETUP-UNINSTALL");
        var fullRoot = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var bindingRoot = ResolveIpcBindingRoot(fullRoot, testRoot);
        // A TEST binding lives below the install root, which is renamed during
        // purge.  Keep its cleanup tombstone outside that renamed directory;
        // production already has the equivalent stable ProgramData parent.
        var parent = testRoot
            ? Path.GetDirectoryName(fullRoot) ?? throw new InvalidDataException("BF-SETUP-UNINSTALL")
            : Path.GetDirectoryName(bindingRoot) ?? throw new InvalidDataException("BF-SETUP-UNINSTALL");
        EnsureNoReparseChain(parent, allowMissingLeaf: true);
        var baseName = Path.GetFileName(bindingRoot);
        var prefix = baseName.StartsWith(".", StringComparison.Ordinal) ? baseName : "." + baseName;
        return Path.Combine(parent, prefix + ".uninstalling-" + operationId);
    }

    private static void WriteUninstallJournal(string installRoot, string phase, string operationId, string installId, bool purge, string tombstone,
        ServicePreState servicePreState, byte[]? previousState, byte[]? previousPointer, byte[]? previousOwnership, bool testRoot, string serviceStateRoot, string kind = "uninstall")
    {
        if (string.IsNullOrWhiteSpace(operationId) || operationId.Length > 96 || string.IsNullOrWhiteSpace(installId)) throw new InvalidDataException("BF-SETUP-UNINSTALL");
        if (kind is not ("uninstall" or "marker-purge")) throw new InvalidDataException("BF-SETUP-UNINSTALL");
        var fullRoot = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullTombstone = Path.GetFullPath(tombstone).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(fullTombstone, fullRoot + ".uninstalling-" + operationId, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-UNINSTALL");
        var preserved = purge ? Array.Empty<string>() : testRoot ? new[] { ".bifrost-user-data", ".bifrost-recovery", ".bifrost-ipc" } : new[] { ".bifrost-user-data", ".bifrost-recovery" };
        IpcBindingMetadata? ipc = null;
        var bindingRoot = ResolveIpcBindingRoot(installRoot, testRoot);
        if (Directory.Exists(bindingRoot)) ipc = ReadIpcBindingMetadata(installRoot, testRoot);
        else if (kind != "marker-purge") throw new InvalidDataException("BF-IPC-BINDING");
        var record = new Dictionary<string, object?>
        {
            ["schema"] = "bifrost-uninstall-v1", ["kind"] = kind, ["phase"] = phase, ["operation_id"] = operationId,
            ["install_root"] = fullRoot, ["root_identity"] = MeasureRootIdentity(installRoot), ["install_id"] = installId,
            ["purge"] = purge, ["tombstone"] = fullTombstone, ["preserved"] = preserved,
            ["previous_state_b64"] = previousState is null ? "" : Convert.ToBase64String(previousState),
            ["previous_state_sha256"] = previousState is null ? "" : Convert.ToHexString(SHA256.HashData(previousState)).ToLowerInvariant(),
            ["previous_pointer_b64"] = previousPointer is null ? "" : Convert.ToBase64String(previousPointer),
            ["previous_pointer_sha256"] = previousPointer is null ? "" : Convert.ToHexString(SHA256.HashData(previousPointer)).ToLowerInvariant(),
            ["previous_ownership_b64"] = previousOwnership is null ? "" : Convert.ToBase64String(previousOwnership),
            ["previous_ownership_sha256"] = previousOwnership is null ? "" : Convert.ToHexString(SHA256.HashData(previousOwnership)).ToLowerInvariant(),
            ["service_pre_state"] = new { servicePreState.Exists, servicePreState.WasRunning, servicePreState.BinPath, servicePreState.StartMode, servicePreState.Identity, servicePreState.Sid, servicePreState.Generation },
            ["service_state_root"] = Path.GetFullPath(serviceStateRoot),
            ["ipc_binding_digest"] = ipc?.Digest ?? "", ["ipc_interactive_sid"] = ipc?.Sid ?? "",
            ["binding_phase"] = ipc is null ? "absent" : "present",
            ["binding_tombstone"] = ResolveIpcBindingTombstone(fullRoot, testRoot, operationId)
        };
        var canonical = JsonSerializer.Serialize(record);
        var mac = ProtectedData.Protect(Encoding.UTF8.GetBytes(canonical), Encoding.UTF8.GetBytes(UninstallJournalAad(fullRoot)), DataProtectionScope.CurrentUser);
        try
        {
            var wrapper = new Dictionary<string, object?>
            {
                ["schema"] = "bifrost-uninstall-wrapper-v1",
                ["payload_b64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(canonical)),
                ["mac"] = Convert.ToBase64String(mac),
                ["payload_sha256"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant()
            };
            WriteAtomic(ResolveUninstallJournalPath(fullRoot), JsonSerializer.Serialize(wrapper));
        }
        finally { CryptographicOperations.ZeroMemory(mac); }
    }

    private static JsonElement ReadUninstallJournal(string installRoot)
    {
        var wrapper = ReadStrictObject(ResolveUninstallJournalPath(installRoot), 512 * 1024);
        if (wrapper.EnumerateObject().Any(p => p.Name is not ("schema" or "payload_b64" or "mac" or "payload_sha256")) ||
            wrapper.GetProperty("schema").GetString() != "bifrost-uninstall-wrapper-v1") throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        byte[] payload;
        byte[] mac;
        try { payload = Convert.FromBase64String(wrapper.GetProperty("payload_b64").GetString() ?? ""); mac = Convert.FromBase64String(wrapper.GetProperty("mac").GetString() ?? ""); }
        catch { throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL"); }
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), Convert.FromHexString(wrapper.GetProperty("payload_sha256").GetString() ?? ""))) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
            byte[] clear;
            try { clear = ProtectedData.Unprotect(mac, Encoding.UTF8.GetBytes(UninstallJournalAad(installRoot)), DataProtectionScope.CurrentUser); }
            catch { throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL"); }
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(clear, payload)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
                using var document = JsonDocument.Parse(clear, new JsonDocumentOptions { MaxDepth = 16 });
                var root = document.RootElement.Clone();
                if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Any(p => !UninstallJournalFields.Contains(p.Name)) ||
                    root.GetProperty("schema").GetString() != "bifrost-uninstall-v1" || root.GetProperty("install_root").GetString() != Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) ||
                    root.GetProperty("operation_id").GetString() is not { Length: >= 16 } || root.GetProperty("phase").GetString() is not { Length: > 0 } ||
                    root.GetProperty("tombstone").GetString() is not { Length: > 0 } || root.GetProperty("install_id").GetString() is not { Length: > 0 } ||
                    (root.TryGetProperty("kind", out var kindValue) && kindValue.ValueKind == JsonValueKind.String && kindValue.GetString() is not ("uninstall" or "marker-purge")) ||
                    root.TryGetProperty("binding_phase", out var bindingPhaseValue) && bindingPhaseValue.ValueKind != JsonValueKind.String ||
                    root.TryGetProperty("binding_tombstone", out var bindingTombstoneValue) && bindingTombstoneValue.ValueKind != JsonValueKind.String)
                    throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
                return root;
            }
            finally { CryptographicOperations.ZeroMemory(clear); }
        }
        finally { CryptographicOperations.ZeroMemory(payload); CryptographicOperations.ZeroMemory(mac); }
    }

    private static void ValidateUninstallJournalReadOnly(string installRoot)
    {
        var path = ResolveUninstallJournalPath(installRoot);
        if (!File.Exists(path)) return;
        var journal = ReadUninstallJournal(installRoot);
        var operationId = journal.GetProperty("operation_id").GetString()!;
        var tombstone = Path.GetFullPath(journal.GetProperty("tombstone").GetString()!);
        var root = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var phase = journal.GetProperty("phase").GetString();
        var kind = journal.TryGetProperty("kind", out var kindValue) && kindValue.ValueKind == JsonValueKind.String ? kindValue.GetString() : "uninstall";
        var bindingPhase = journal.TryGetProperty("binding_phase", out var bindingPhaseValue) && bindingPhaseValue.ValueKind == JsonValueKind.String ? bindingPhaseValue.GetString() : "present";
        var operationKind = IsTemporaryRoot(root) ? true : false;
        if (journal.TryGetProperty("binding_tombstone", out var bindingTombstoneValue) && bindingTombstoneValue.ValueKind == JsonValueKind.String &&
            !string.Equals(Path.GetFullPath(bindingTombstoneValue.GetString()!), ResolveIpcBindingTombstone(root, operationKind, operationId), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        var preserved = journal.GetProperty("preserved");
        if (!string.Equals(tombstone, root + ".uninstalling-" + operationId, StringComparison.OrdinalIgnoreCase) ||
            journal.GetProperty("root_identity").GetString() is not { Length: 64 } ||
            kind is not ("uninstall" or "marker-purge") ||
            phase is not ("intent" or "stopped" or "renamed" or "marker" or "service-deleted" or "binding-deleted" or "data-moved" or "committed") ||
            bindingPhase is not ("absent" or "present" or "intent" or "renamed" or "cleanup" or "deleted") ||
            preserved.ValueKind != JsonValueKind.Array || preserved.GetArrayLength() is not (0 or 2 or 3) ||
            preserved.EnumerateArray().Any(item => item.ValueKind != JsonValueKind.String || item.GetString() is not (".bifrost-user-data" or ".bifrost-recovery" or ".bifrost-ipc")))
            throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        ValidateJournalBytes(journal, "previous_state_b64", "previous_state_sha256");
        ValidateJournalBytes(journal, "previous_pointer_b64", "previous_pointer_sha256");
        ValidateJournalBytes(journal, "previous_ownership_b64", "previous_ownership_sha256");
    }

    private static byte[]? ReadJournalBytes(JsonElement journal, string field)
    {
        var text = journal.GetProperty(field).GetString() ?? "";
        return string.IsNullOrEmpty(text) ? null : Convert.FromBase64String(text);
    }

    private static void ValidateJournalBytes(JsonElement journal, string valueField, string digestField)
    {
        byte[]? bytes;
        try { bytes = ReadJournalBytes(journal, valueField); }
        catch { throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL"); }
        try { ValidateDigestValue(journal.GetProperty(digestField).GetString() ?? "", bytes); }
        finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void ValidateDigestValue(string expected, byte[]? bytes)
    {
        var actual = bytes is null ? "" : Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!string.Equals(expected, actual, StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
    }

    private static void ClearUninstallJournal(string installRoot)
    {
        var path = ResolveUninstallJournalPath(installRoot);
        if (File.Exists(path) && !TryDeleteResult(path)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
    }

    private static void UpdateUninstallJournalPhase(string installRoot, string phase)
    {
        var current = ReadUninstallJournal(installRoot);
        var record = current.EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value.Clone(), StringComparer.Ordinal);
        record["phase"] = phase;
        WriteUninstallJournalRecord(installRoot, record);
    }

    private static void UpdateUninstallJournalBindingPhase(string installRoot, string bindingPhase)
    {
        if (bindingPhase is not ("absent" or "present" or "intent" or "renamed" or "cleanup" or "deleted")) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        var current = ReadUninstallJournal(installRoot);
        var record = current.EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value.Clone(), StringComparer.Ordinal);
        record["binding_phase"] = bindingPhase;
        WriteUninstallJournalRecord(installRoot, record);
    }

    private static void WriteUninstallJournalRecord(string installRoot, IReadOnlyDictionary<string, object?> record)
    {
        var canonical = JsonSerializer.Serialize(record);
        var protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(canonical), Encoding.UTF8.GetBytes(UninstallJournalAad(installRoot)), DataProtectionScope.CurrentUser);
        try
        {
            var wrapper = new Dictionary<string, object?>
            {
                ["schema"] = "bifrost-uninstall-wrapper-v1",
                ["payload_b64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(canonical)),
                ["mac"] = Convert.ToBase64String(protectedBytes),
                ["payload_sha256"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant()
            };
            WriteAtomic(ResolveUninstallJournalPath(installRoot), JsonSerializer.Serialize(wrapper));
        }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
    }

    private static void RecoverUninstallJournal(string installRoot, bool testRoot, string? fakeServiceMode, string? serviceStateRoot)
    {
        var path = ResolveUninstallJournalPath(installRoot);
        if (!File.Exists(path)) return;
        var journal = ReadUninstallJournal(installRoot);
        var operationId = journal.GetProperty("operation_id").GetString()!;
        var kind = journal.TryGetProperty("kind", out var kindValue) && kindValue.ValueKind == JsonValueKind.String ? kindValue.GetString() : "uninstall";
        var markerPurge = string.Equals(kind, "marker-purge", StringComparison.Ordinal);
        var root = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var tombstone = Path.GetFullPath(journal.GetProperty("tombstone").GetString()!);
        var expectedTombstone = root + ".uninstalling-" + operationId;
        if (!string.Equals(tombstone, expectedTombstone, StringComparison.OrdinalIgnoreCase) ||
            kind is not ("uninstall" or "marker-purge") ||
            journal.GetProperty("root_identity").GetString() is not { Length: 64 } rootIdentity ||
            journal.GetProperty("install_id").GetString() is not { Length: > 0 } installId ||
            journal.GetProperty("purge").ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        var expectedBindingTombstone = ResolveIpcBindingTombstone(root, testRoot, operationId);
        if (!journal.TryGetProperty("binding_tombstone", out var bindingTombstoneValue) || bindingTombstoneValue.ValueKind != JsonValueKind.String ||
            !string.Equals(Path.GetFullPath(bindingTombstoneValue.GetString()!), expectedBindingTombstone, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        ValidateJournalBytes(journal, "previous_state_b64", "previous_state_sha256");
        ValidateJournalBytes(journal, "previous_pointer_b64", "previous_pointer_sha256");
        ValidateJournalBytes(journal, "previous_ownership_b64", "previous_ownership_sha256");
        var preserved = journal.GetProperty("preserved");
        var expectedPreserved = (journal.GetProperty("purge").GetBoolean() ? Array.Empty<string>() : (testRoot ? new[] { ".bifrost-user-data", ".bifrost-recovery", ".bifrost-ipc" } : new[] { ".bifrost-user-data", ".bifrost-recovery" }));
        if (preserved.ValueKind != JsonValueKind.Array || !preserved.EnumerateArray().All(x => x.ValueKind == JsonValueKind.String) ||
            !preserved.EnumerateArray().Select(x => x.GetString()!).OrderBy(x => x, StringComparer.Ordinal).SequenceEqual(expectedPreserved.OrderBy(x => x, StringComparer.Ordinal), StringComparer.Ordinal))
            throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        var phase = journal.GetProperty("phase").GetString();
        if (phase is not ("intent" or "stopped" or "renamed" or "marker" or "service-deleted" or "binding-deleted" or "data-moved" or "committed")) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        var purge = journal.GetProperty("purge").GetBoolean();
        if (markerPurge && !purge) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        var cleanRoot = root + ".uninstalled-" + operationId;
        var rootExists = Directory.Exists(root);
        var tombstoneExists = Directory.Exists(tombstone);
        var cleanRootExists = Directory.Exists(cleanRoot);
        if (rootExists && tombstoneExists && phase is not ("marker" or "service-deleted" or "data-moved" or "committed")) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        if (!rootExists && !tombstoneExists && !cleanRootExists)
        {
            if (purge && phase is ("binding-deleted" or "data-moved" or "committed")) { ClearUninstallJournal(installRoot); return; }
            throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        }
        if (tombstoneExists)
        {
            EnsureNoReparseChain(tombstone, allowMissingLeaf: false);
            if (!string.Equals(MeasureRootIdentity(tombstone), rootIdentity, StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        }
        ValidateUninstallJournalIpcBinding(installRoot, tombstone, cleanRoot, testRoot, purge, phase, journal);
        var completeUninstall = markerPurge || phase is "service-deleted" or "binding-deleted" or "data-moved" or "committed";
        var serviceRoot = journal.TryGetProperty("service_state_root", out var serviceRootElement) && serviceRootElement.ValueKind == JsonValueKind.String ? serviceRootElement.GetString() : serviceStateRoot;
        if (string.IsNullOrWhiteSpace(serviceRoot)) serviceRoot = testRoot ? Path.GetDirectoryName(root) ?? root : root;
        var resolvedServiceRoot = Path.GetFullPath(serviceRoot!);
        if (testRoot ? !IsTemporaryRoot(resolvedServiceRoot) : !string.Equals(resolvedServiceRoot, root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        var service = CreateServiceLifecycle(testRoot, fakeServiceMode ?? "success", serviceRoot!, root);
        var pre = ParseServicePreState(journal.GetProperty("service_pre_state"));
        byte[]? previousState = null; byte[]? previousPointer = null; byte[]? previousOwnership = null;
        try
        {
            previousState = ReadJournalBytes(journal, "previous_state_b64");
            previousPointer = ReadJournalBytes(journal, "previous_pointer_b64");
            previousOwnership = ReadJournalBytes(journal, "previous_ownership_b64");
            if (markerPurge && phase == "intent")
            {
                // Marker-only purge has no service registration to roll back.
                // Rename the authenticated marker root first; this makes the
                // root/binding pair recoverable before any binding mutation.
                if (rootExists && !tombstoneExists)
                {
                    EnsureNoReparseChain(root, allowMissingLeaf: false);
                    Directory.Move(root, tombstone);
                    UpdateUninstallJournalPhase(root, "renamed");
                    phase = "renamed";
                    rootExists = false;
                    tombstoneExists = true;
                    journal = ReadUninstallJournal(root);
                }
                else if (!rootExists && tombstoneExists)
                {
                    UpdateUninstallJournalPhase(root, "renamed");
                    phase = "renamed";
                    journal = ReadUninstallJournal(root);
                }
                else throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
            }
            if (!completeUninstall)
            {
                // Roll back to a complete installed tree.  If a marker root was
                // already created, move every preserved directory back before
                // discarding that root; no data may be split between generations.
                if (rootExists && tombstoneExists)
                {
                    foreach (var name in expectedPreserved)
                    {
                        var from = Path.Combine(root, name); var to = Path.Combine(tombstone, name);
                        if (Directory.Exists(from)) { if (Directory.Exists(to)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL"); Directory.Move(from, to); }
                    }
                    Directory.Delete(root, true);
                    rootExists = false;
                }
                if (!Directory.Exists(root) && Directory.Exists(tombstone)) Directory.Move(tombstone, root);
                if (!Directory.Exists(root)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
                if (pre.Exists) service.RestoreAfterRollback(pre);
                RestoreState(ResolveStatePath(root), previousState);
                RestoreState(Path.Combine(ResolveStateRoot(root), "current.json"), previousPointer);
                RestoreState(ResolveOwnershipPath(root), previousOwnership);
                ClearUninstallJournal(root);
                return;
            }
            // Once the service-delete boundary has been crossed, recovery is
            // forward-only: produce one authenticated uninstalled root (or a
            // precise purge), never resurrect a removed registration.
            if (purge)
            {
                var bindingPhase = journal.TryGetProperty("binding_phase", out var bindingPhaseValue) && bindingPhaseValue.ValueKind == JsonValueKind.String ? bindingPhaseValue.GetString() : "present";
                if (bindingPhase is not ("deleted" or "absent"))
                {
                    if (bindingPhase is "present" or "intent")
                    {
                        RenamePurgeIpcBinding(root, tombstone, testRoot, journal);
                        UpdateUninstallJournalBindingPhase(root, "renamed");
                        journal = ReadUninstallJournal(root);
                        bindingPhase = "renamed";
                    }
                    UpdateUninstallJournalBindingPhase(root, "cleanup");
                    journal = ReadUninstallJournal(root);
                    CleanupPurgeIpcBinding(journal, testRoot, fakeFailureMode: null, allowCrashMidCleanup: false);
                    UpdateUninstallJournalBindingPhase(root, "deleted");
                    journal = ReadUninstallJournal(root);
                    bindingPhase = "deleted";
                }
                if (phase is not ("binding-deleted" or "data-moved" or "committed"))
                {
                    UpdateUninstallJournalPhase(root, "binding-deleted");
                    journal = ReadUninstallJournal(root);
                    phase = "binding-deleted";
                }
                if (Directory.Exists(root)) { ValidateUninstallEntries(root); Directory.Delete(root, true); }
                if (Directory.Exists(tombstone))
                {
                    ValidateOwnedTree(tombstone);
                    if (!TryDeleteResult(tombstone))
                        ScheduleValidatedTreeDeletionAtRebootBestEffort(tombstone);
                }
                if (Directory.Exists(cleanRoot)) { ValidateUninstallEntries(cleanRoot); Directory.Delete(cleanRoot, true); }
                ClearUninstallJournal(root);
                return;
            }
            PrepareCleanUninstalledRoot(root, tombstone, cleanRoot, expectedPreserved, installId, journal);
            if (phase is not ("data-moved" or "committed")) UpdateUninstallJournalPhase(root, "data-moved");
            if (Directory.Exists(root) && !string.Equals(Path.GetFullPath(root), Path.GetFullPath(cleanRoot), StringComparison.OrdinalIgnoreCase)) { ValidateUninstallEntries(root); Directory.Delete(root, true); }
            if (Directory.Exists(tombstone))
            {
                ValidateOwnedTree(tombstone);
                if (!TryDeleteResult(tombstone))
                    ScheduleValidatedTreeDeletionAtRebootBestEffort(tombstone);
            }
            if (Directory.Exists(cleanRoot) && !Directory.Exists(root)) Directory.Move(cleanRoot, root);
            ValidateUninstalledMarker(root);
            UpdateUninstallJournalPhase(root, "committed");
            ClearUninstallJournal(root);
        }
        finally
        {
            if (previousState is not null) CryptographicOperations.ZeroMemory(previousState);
            if (previousPointer is not null) CryptographicOperations.ZeroMemory(previousPointer);
            if (previousOwnership is not null) CryptographicOperations.ZeroMemory(previousOwnership);
        }
    }

    private static void PrepareCleanUninstalledRoot(string root, string tombstone, string cleanRoot, IReadOnlyList<string> preserved, string installId, JsonElement journal)
    {
        EnsureNoReparseChain(cleanRoot, allowMissingLeaf: true);
        Directory.CreateDirectory(cleanRoot);
        EnsureNoReparseChain(cleanRoot, allowMissingLeaf: false);
        var allowed = preserved.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in Directory.EnumerateFileSystemEntries(cleanRoot, "*", SearchOption.TopDirectoryOnly))
        {
            var name = Path.GetFileName(entry);
            if (string.Equals(name, StateDirectoryName, StringComparison.OrdinalIgnoreCase))
            {
                EnsureNoReparseChain(entry, allowMissingLeaf: false);
                ValidateOwnedTree(entry);
                Directory.Delete(entry, true);
            }
            else if (!allowed.Contains(name)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        }
        foreach (var name in preserved)
        {
            var target = Path.Combine(cleanRoot, name);
            var sources = new[] { Path.Combine(root, name), Path.Combine(tombstone, name) }.Where(Directory.Exists).ToArray();
            if (sources.Length > 1 || sources.Length == 1 && File.Exists(target)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
            if (sources.Length == 1)
            {
                EnsureNoReparseChain(sources[0], allowMissingLeaf: false);
                if (Directory.Exists(target)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
                Directory.Move(sources[0], target);
            }
        }
        Directory.CreateDirectory(ResolveStateRoot(cleanRoot));
        WriteUninstalledMarker(cleanRoot, installId, MeasureRootIdentity(cleanRoot), journal.GetProperty("ipc_binding_digest").GetString()!, journal.GetProperty("ipc_interactive_sid").GetString()!);
        ValidateUninstalledMarker(cleanRoot);
    }

    private static void ValidateUninstallJournalIpcBinding(string installRoot, string tombstone, string cleanRoot, bool testRoot, bool purge, string? phase, JsonElement journal)
    {
        var expectedDigest = journal.GetProperty("ipc_binding_digest").GetString();
        var expectedSid = journal.GetProperty("ipc_interactive_sid").GetString();
        var kind = journal.TryGetProperty("kind", out var kindValue) && kindValue.ValueKind == JsonValueKind.String ? kindValue.GetString() : "uninstall";
        var bindingPhase = journal.TryGetProperty("binding_phase", out var bindingPhaseValue) && bindingPhaseValue.ValueKind == JsonValueKind.String ? bindingPhaseValue.GetString() : "present";
        if (kind == "marker-purge" && string.IsNullOrEmpty(expectedDigest) && string.IsNullOrEmpty(expectedSid))
        {
            if (bindingPhase != "absent") throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
            return;
        }
        if (expectedDigest is not { Length: 64 } || string.IsNullOrWhiteSpace(expectedSid) || bindingPhase is not ("present" or "intent" or "renamed" or "cleanup" or "deleted")) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        var bindingRoot = BindingSourceForJournal(installRoot, tombstone, testRoot);
        if (testRoot && !Directory.Exists(bindingRoot) && Directory.Exists(Path.Combine(cleanRoot, ".bifrost-ipc"))) bindingRoot = Path.Combine(cleanRoot, ".bifrost-ipc");
        var bindingTombstone = JournalBindingTombstone(journal);
        var sourceExists = Directory.Exists(bindingRoot);
        var tombstoneExists = Directory.Exists(bindingTombstone);
        if (sourceExists && tombstoneExists) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        if (bindingPhase is "deleted")
        {
            if (sourceExists || tombstoneExists) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
            return;
        }
        if (!sourceExists && !tombstoneExists)
        {
            // Directory.Delete is the final destructive step.  A process may
            // die after that succeeds but before the authenticated phase
            // record advances from cleanup to deleted; cleanup is therefore
            // forward-only and idempotent for this one state only.
            if (bindingPhase == "cleanup") return;
            throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        }
        if (tombstoneExists)
        {
            ValidateBindingContents(bindingTombstone, expectedDigest, expectedSid, testRoot, allowPartial: bindingPhase == "cleanup");
            return;
        }
        if (sourceExists)
        {
            ValidateBindingContents(bindingRoot, expectedDigest, expectedSid, testRoot, allowPartial: false);
            return;
        }
        throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
    }

    private static void WriteUninstalledMarker(string installRoot, string installId, string rootIdentity, string ipcBindingDigest, string ipcInteractiveSid)
    {
        var unsigned = new Dictionary<string, object?>
        {
            ["schema"] = "bifrost-uninstalled-v1", ["product_id"] = "bifrost.windows-client",
            ["install_id"] = installId, ["root_identity"] = rootIdentity,
            ["ipc_binding_digest"] = ipcBindingDigest, ["ipc_interactive_sid"] = ipcInteractiveSid,
            ["written_at"] = DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
        };
        var canonical = JsonSerializer.Serialize(unsigned);
        var mac = ProtectedData.Protect(Encoding.UTF8.GetBytes(canonical), Encoding.UTF8.GetBytes("Bifrost.Uninstalled.v1"), DataProtectionScope.CurrentUser);
        try
        {
            WriteAtomic(ResolveUninstalledMarkerPath(installRoot), JsonSerializer.Serialize(new Dictionary<string, object?>(unsigned)
            {
                ["checksum"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant(),
                ["mac"] = Convert.ToBase64String(mac)
            }));
        }
        finally { CryptographicOperations.ZeroMemory(mac); }
    }

    private static void ValidateUninstalledMarker(string installRoot)
    {
        var path = ResolveUninstalledMarkerPath(installRoot);
        if (!File.Exists(path)) return;
        var value = ReadStrictObject(path, 16 * 1024);
        var required = new[] { "schema", "product_id", "install_id", "root_identity", "ipc_binding_digest", "ipc_interactive_sid", "written_at", "checksum", "mac" };
        if (value.EnumerateObject().Count() != required.Length || required.Any(name => !value.TryGetProperty(name, out _)) || value.GetProperty("schema").GetString() != "bifrost-uninstalled-v1" || value.GetProperty("product_id").GetString() != "bifrost.windows-client" || value.GetProperty("install_id").GetString() is not { Length: >= 16 } || value.GetProperty("root_identity").GetString() is not { Length: 64 } || value.GetProperty("ipc_binding_digest").GetString() is not { Length: 64 } || value.GetProperty("ipc_interactive_sid").GetString() is not { Length: > 0 }) throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
        var unsigned = new Dictionary<string, object?>
        {
            ["schema"] = value.GetProperty("schema").GetString(), ["product_id"] = value.GetProperty("product_id").GetString(),
            ["install_id"] = value.GetProperty("install_id").GetString(), ["root_identity"] = value.GetProperty("root_identity").GetString(),
            ["ipc_binding_digest"] = value.GetProperty("ipc_binding_digest").GetString(), ["ipc_interactive_sid"] = value.GetProperty("ipc_interactive_sid").GetString(),
            ["written_at"] = value.GetProperty("written_at").GetString()
        };
        var canonical = JsonSerializer.Serialize(unsigned);
        var checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        if (checksum != value.GetProperty("checksum").GetString()) throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
        if (!string.Equals(MeasureRootIdentity(installRoot), value.GetProperty("root_identity").GetString(), StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
        var ipc = ReadIpcBindingMetadata(installRoot, IsTemporaryRoot(installRoot));
        if (!string.Equals(ipc.Digest, value.GetProperty("ipc_binding_digest").GetString(), StringComparison.Ordinal) || !string.Equals(ipc.Sid, value.GetProperty("ipc_interactive_sid").GetString(), StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
        try
        {
            var protectedBytes = Convert.FromBase64String(value.GetProperty("mac").GetString()!);
            var clear = ProtectedData.Unprotect(protectedBytes, Encoding.UTF8.GetBytes("Bifrost.Uninstalled.v1"), DataProtectionScope.CurrentUser);
            try { if (!CryptographicOperations.FixedTimeEquals(clear, Encoding.UTF8.GetBytes(canonical))) throw new CryptographicException(); }
            finally { CryptographicOperations.ZeroMemory(clear); }
        }
        catch { throw new InvalidDataException("BF-SETUP-STATE-CORRUPT"); }
    }

    private static string FileDigestOrEmpty(string path)
    {
        if (!File.Exists(path)) return new string('0', 64);
        var bytes = ReadBounded(path, 256 * 1024);
        try { return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void RecoverPromotionJournal(string installRoot, bool testRoot)
    {
        var journalPath = ResolvePromotionJournalPath(installRoot);
        if (!File.Exists(journalPath)) return;
        // A promotion journal is a recovery authority.  It is never trusted
        // as ordinary JSON: authenticate it before reading paths or previous
        // state.  Any damaged/torn/forged record fails closed and is left in
        // place for an operator to recover; recovery never guesses sequence 0.
        var journal = ReadProtectedPromotionJournal(installRoot);
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "schema", "operation", "phase", "operation_id", "sequence", "staging", "generation_root", "previous_state_b64", "previous_pointer_b64", "previous_state_sha256", "previous_pointer_sha256", "previous_ownership_b64", "previous_ownership_sha256", "root_identity", "ipc_binding_digest", "ipc_interactive_sid", "service_pre_state", "service_candidate", "service_state_root", "service_phase", "service_readback_digest" };
        if (journal.EnumerateObject().Any(item => !allowed.Contains(item.Name)) || journal.GetProperty("schema").GetString() != "bifrost-promotion-v2" || journal.GetProperty("operation_id").GetString() is not { Length: >= 16 } || !journal.GetProperty("sequence").TryGetInt64(out var sequence) || sequence < 1 || journal.GetProperty("phase").GetString() is not { Length: > 0 } phase || journal.GetProperty("root_identity").GetString() is not { Length: 64 } rootIdentity || !string.Equals(rootIdentity, MeasureRootIdentity(installRoot), StringComparison.Ordinal))
            throw new InvalidDataException("BF-SETUP-JOURNAL");
        var operation = journal.TryGetProperty("operation", out var operationElement) && operationElement.ValueKind == JsonValueKind.String ? operationElement.GetString() : "apply";
        if (operation is not ("apply" or "rollback")) throw new InvalidDataException("BF-SETUP-JOURNAL");
        ValidateJournalIpcBinding(installRoot, journal);
        if (operation == "rollback") { RecoverRollbackJournal(installRoot, journal, testRoot); return; }
        if (phase is not ("staging" or "candidate" or "healthy" or "committed")) throw new InvalidDataException("BF-SETUP-JOURNAL");
        var staging = Path.GetFullPath(journal.GetProperty("staging").GetString() ?? throw new InvalidDataException("BF-SETUP-JOURNAL"));
        var generation = Path.GetFullPath(journal.GetProperty("generation_root").GetString() ?? throw new InvalidDataException("BF-SETUP-JOURNAL"));
        var generationParent = Path.Combine(installRoot, ".bifrost-generations");
        if (!IsContained(installRoot, staging) || !IsContained(generationParent, generation) || string.Equals(generation, generationParent, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-JOURNAL");
        byte[]? previousState = null;
        byte[]? previousPointer = null;
        byte[]? previousOwnership = null;
        try
        {
            if (journal.TryGetProperty("previous_state_b64", out var stateValue) && stateValue.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(stateValue.GetString())) previousState = Convert.FromBase64String(stateValue.GetString()!);
            if (journal.TryGetProperty("previous_pointer_b64", out var pointerValue) && pointerValue.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(pointerValue.GetString())) previousPointer = Convert.FromBase64String(pointerValue.GetString()!);
            if (journal.TryGetProperty("previous_ownership_b64", out var ownershipValue) && ownershipValue.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(ownershipValue.GetString())) previousOwnership = Convert.FromBase64String(ownershipValue.GetString()!);
            ValidateJournalDigest(journal, "previous_state_sha256", previousState);
            ValidateJournalDigest(journal, "previous_pointer_sha256", previousPointer);
            ValidateJournalDigest(journal, "previous_ownership_sha256", previousOwnership);
            var statePath = ResolveStatePath(installRoot);
            var pointerPath = Path.Combine(ResolveStateRoot(installRoot), "current.json");
            // Corrupt state is not an empty install.  Refuse recovery without
            // touching either state or payload so a torn record cannot drive a
            // destructive "restore" operation.
            var currentSequence = ReadStateSequence(statePath, allowLegacy: testRoot);
            var pointerUsesGeneration = false;
            if (File.Exists(pointerPath))
            {
                var pointer = ReadStrictObject(pointerPath, 64 * 1024);
                pointerUsesGeneration = pointer.TryGetProperty("current_payload_root", out var payload) && payload.ValueKind == JsonValueKind.String && string.Equals(Path.GetFullPath(payload.GetString()!), generation, StringComparison.OrdinalIgnoreCase);
            }
            var ownershipMatches = false;
            if (File.Exists(ResolveOwnershipPath(installRoot)))
            {
                var ownership = ReadOwnership(installRoot, testRoot, verifyBoundFiles: false);
                var currentGeneration = ownership.GetProperty("current_generation").GetString() ?? "";
                ownershipMatches = currentGeneration.StartsWith(sequence.ToString(System.Globalization.CultureInfo.InvariantCulture) + "-", StringComparison.Ordinal);
            }
            // A journal is committed only when both durable state and pointer
            // name the candidate. Any other crash point rolls back to the
            // captured complete old pair before removing owned new material.
            ServiceApplyResult? committedService = null;
            if (journal.TryGetProperty("service_candidate", out var committedServiceElement) && committedServiceElement.ValueKind == JsonValueKind.Object)
                committedService = ParseServiceApplyResult(committedServiceElement);
            var committedServiceRoot = journal.TryGetProperty("service_state_root", out var committedRootValue) && committedRootValue.ValueKind == JsonValueKind.String ? committedRootValue.GetString() : installRoot;
            var serviceCommitted = committedService is not null && !string.IsNullOrWhiteSpace(committedServiceRoot) && CreateServiceLifecycle(testRoot, "success", committedServiceRoot!, installRoot).ValidateCommitted(committedService);
            var candidateCommitted = currentSequence == sequence && pointerUsesGeneration && ownershipMatches && serviceCommitted;
            if (candidateCommitted)
            {
                TryDeleteResult(journalPath);
                return;
            }
            if (string.Equals(phase, "committed", StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-JOURNAL");
            // The service is part of the same promotion transaction. Restore
            // its authenticated pre-state before deleting a candidate that a
            // crashed process may still reference.
            if (phase is "candidate" or "healthy" && journal.TryGetProperty("service_pre_state", out var servicePre) && servicePre.ValueKind == JsonValueKind.Object)
            {
                var pre = ParseServicePreState(servicePre);
                ServiceApplyResult? candidate = journal.TryGetProperty("service_candidate", out var serviceCurrent) && serviceCurrent.ValueKind == JsonValueKind.Object ? ParseServiceApplyResult(serviceCurrent) : null;
                if (candidate is not null && (!journal.TryGetProperty("service_readback_digest", out var serviceDigest) || serviceDigest.GetString() != ServiceApplyResultDigest(candidate))) throw new InvalidDataException("BF-SETUP-JOURNAL");
                var stateRoot = journal.TryGetProperty("service_state_root", out var serviceRoot) && serviceRoot.ValueKind == JsonValueKind.String ? serviceRoot.GetString() : installRoot;
                if (!string.IsNullOrWhiteSpace(stateRoot))
                {
                    var resolvedStateRoot = Path.GetFullPath(stateRoot);
                    if (testRoot ? !IsTemporaryRoot(resolvedStateRoot) : !string.Equals(resolvedStateRoot, Path.GetFullPath(installRoot), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-JOURNAL");
                }
                var lifecycle = CreateServiceLifecycle(testRoot, "success", stateRoot!, installRoot);
                lifecycle.PrepareRollback(pre, candidate);
                lifecycle.RestoreAfterRollback(pre);
            }
            if (previousState is not null) RestoreState(statePath, previousState); else if (File.Exists(statePath)) TryDeleteResult(statePath);
            if (previousPointer is not null) RestoreState(pointerPath, previousPointer); else if (File.Exists(pointerPath)) TryDeleteResult(pointerPath);
            var ownershipPath = ResolveOwnershipPath(installRoot);
            if (previousOwnership is not null) RestoreState(ownershipPath, previousOwnership); else if (File.Exists(ownershipPath)) TryDeleteResult(ownershipPath);
            if (IsContained(generationParent, generation)) TryDeleteResult(generation);
            if (IsContained(installRoot, staging)) TryDeleteResult(staging);
            if (!TryDeleteResult(journalPath)) throw new InvalidDataException("BF-SETUP-JOURNAL");
        }
        finally
        {
            if (previousState is not null) CryptographicOperations.ZeroMemory(previousState);
            if (previousPointer is not null) CryptographicOperations.ZeroMemory(previousPointer);
            if (previousOwnership is not null) CryptographicOperations.ZeroMemory(previousOwnership);
        }
    }

    private static void ValidatePromotionJournalReadOnly(string installRoot)
    {
        var journalPath = ResolvePromotionJournalPath(installRoot);
        if (!File.Exists(journalPath)) return;
        var journal = ReadProtectedPromotionJournal(installRoot);
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "schema", "operation", "phase", "operation_id", "sequence", "staging", "generation_root", "previous_state_b64", "previous_pointer_b64", "previous_state_sha256", "previous_pointer_sha256", "previous_ownership_b64", "previous_ownership_sha256", "root_identity", "ipc_binding_digest", "ipc_interactive_sid", "service_pre_state", "service_candidate", "service_state_root", "service_phase", "service_readback_digest" };
        if (journal.EnumerateObject().Any(item => !allowed.Contains(item.Name)) || journal.GetProperty("schema").GetString() != "bifrost-promotion-v2" || journal.GetProperty("root_identity").GetString() != MeasureRootIdentity(installRoot))
            throw new InvalidDataException("BF-SETUP-JOURNAL");
        var operation = journal.TryGetProperty("operation", out var operationElement) && operationElement.ValueKind == JsonValueKind.String ? operationElement.GetString() : "apply";
        if (operation is not ("apply" or "rollback")) throw new InvalidDataException("BF-SETUP-JOURNAL");
        ValidateJournalIpcBinding(installRoot, journal);
        if (operation == "rollback") return; // validation remains read-only; recovery is never performed by what-if
        if (journal.GetProperty("phase").GetString() is not ("staging" or "candidate" or "healthy" or "committed")) throw new InvalidDataException("BF-SETUP-JOURNAL");
        var staging = Path.GetFullPath(journal.GetProperty("staging").GetString() ?? throw new InvalidDataException("BF-SETUP-JOURNAL"));
        var generation = Path.GetFullPath(journal.GetProperty("generation_root").GetString() ?? throw new InvalidDataException("BF-SETUP-JOURNAL"));
        var generationParent = Path.Combine(installRoot, ".bifrost-generations");
        if (!IsContained(installRoot, staging) || !IsContained(generationParent, generation) || string.Equals(generation, generationParent, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-JOURNAL");
        byte[]? priorState = null; byte[]? priorPointer = null; byte[]? priorOwnership = null;
        try
        {
            if (journal.GetProperty("previous_state_b64").GetString() is { Length: > 0 } stateText) priorState = Convert.FromBase64String(stateText);
            if (journal.GetProperty("previous_pointer_b64").GetString() is { Length: > 0 } pointerText) priorPointer = Convert.FromBase64String(pointerText);
            if (journal.GetProperty("previous_ownership_b64").GetString() is { Length: > 0 } ownershipText) priorOwnership = Convert.FromBase64String(ownershipText);
            ValidateJournalDigest(journal, "previous_state_sha256", priorState);
            ValidateJournalDigest(journal, "previous_pointer_sha256", priorPointer);
            ValidateJournalDigest(journal, "previous_ownership_sha256", priorOwnership);
        }
        catch { throw new InvalidDataException("BF-SETUP-JOURNAL"); }
        finally { if (priorState is not null) CryptographicOperations.ZeroMemory(priorState); if (priorPointer is not null) CryptographicOperations.ZeroMemory(priorPointer); if (priorOwnership is not null) CryptographicOperations.ZeroMemory(priorOwnership); }
    }

    private static JsonElement ReadProtectedPromotionJournal(string installRoot)
    {
        var wrapper = ReadStrictObject(ResolvePromotionJournalPath(installRoot), 512 * 1024);
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "schema", "payload_b64", "payload_sha256" };
        if (wrapper.EnumerateObject().Any(item => !allowed.Contains(item.Name)) || wrapper.GetProperty("schema").GetString() != "bifrost-promotion-wrapper-v2" || wrapper.GetProperty("payload_b64").GetString() is not { Length: > 0 } payloadText || wrapper.GetProperty("payload_sha256").GetString() is not { Length: 64 } payloadDigest)
            throw new InvalidDataException("BF-SETUP-JOURNAL");
        byte[] protectedBytes;
        try { protectedBytes = Convert.FromBase64String(payloadText); } catch { throw new InvalidDataException("BF-SETUP-JOURNAL"); }
        try
        {
            var aad = Encoding.UTF8.GetBytes("Bifrost.PromotionJournal.v2|" + MeasureRootIdentity(installRoot));
            byte[] clear;
            try { clear = ProtectedData.Unprotect(protectedBytes, aad, DataProtectionScope.CurrentUser); } catch { throw new InvalidDataException("BF-SETUP-JOURNAL"); }
            try
            {
                var digest = Convert.ToHexString(SHA256.HashData(clear)).ToLowerInvariant();
                if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(digest), Encoding.ASCII.GetBytes(payloadDigest))) throw new InvalidDataException("BF-SETUP-JOURNAL");
                using var document = JsonDocument.Parse(clear, new JsonDocumentOptions { MaxDepth = 16 });
                return document.RootElement.Clone();
            }
            finally { CryptographicOperations.ZeroMemory(clear); }
        }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
    }

    private static void WritePromotionJournal(string installRoot, string phase, long sequence, string operationId, string staging, string generationRoot, byte[]? previousState, byte[]? previousPointer, byte[]? previousOwnership, string? fakeFailureMode = null, ServicePreState? servicePreState = null, ServiceApplyResult? serviceCandidate = null, string? serviceStateRoot = null, string operation = "apply")
    {
        var generationParent = Path.Combine(installRoot, ".bifrost-generations");
        if (!IsContained(installRoot, staging) || !IsContained(generationParent, generationRoot)) throw new InvalidDataException("BF-SETUP-JOURNAL");
        if (FaultEnabled(fakeFailureMode, "journal")) throw new IOException("BF-SETUP-FAULT");
        var candidateJson = serviceCandidate is null ? null : JsonSerializer.Serialize(new { serviceCandidate.Exists, serviceCandidate.Running, serviceCandidate.CreatedByTransaction, serviceCandidate.BinPath, serviceCandidate.StartMode, serviceCandidate.Identity, serviceCandidate.Sid, serviceCandidate.Generation });
        var record = new Dictionary<string, object?>
        {
            ["schema"] = "bifrost-promotion-v2", ["operation"] = operation, ["phase"] = phase, ["operation_id"] = operationId,
            ["sequence"] = sequence, ["staging"] = Path.GetFullPath(staging), ["generation_root"] = Path.GetFullPath(generationRoot),
            ["previous_state_b64"] = previousState is null ? "" : Convert.ToBase64String(previousState),
            ["previous_pointer_b64"] = previousPointer is null ? "" : Convert.ToBase64String(previousPointer),
            ["previous_state_sha256"] = previousState is null ? "" : Convert.ToHexString(SHA256.HashData(previousState)).ToLowerInvariant(),
            ["previous_pointer_sha256"] = previousPointer is null ? "" : Convert.ToHexString(SHA256.HashData(previousPointer)).ToLowerInvariant(),
            ["previous_ownership_b64"] = previousOwnership is null ? "" : Convert.ToBase64String(previousOwnership),
            ["previous_ownership_sha256"] = previousOwnership is null ? "" : Convert.ToHexString(SHA256.HashData(previousOwnership)).ToLowerInvariant(),
            ["root_identity"] = MeasureRootIdentity(installRoot),
            ["ipc_binding_digest"] = ReadIpcBindingMetadata(installRoot, IsTemporaryRoot(installRoot)).Digest,
            ["ipc_interactive_sid"] = ReadIpcBindingMetadata(installRoot, IsTemporaryRoot(installRoot)).Sid,
            ["service_pre_state"] = servicePreState is null ? null : new { servicePreState.Exists, servicePreState.WasRunning, servicePreState.BinPath, servicePreState.StartMode, servicePreState.Identity, servicePreState.Sid, servicePreState.Generation },
            ["service_candidate"] = serviceCandidate is null ? null : new { serviceCandidate.Exists, serviceCandidate.Running, serviceCandidate.CreatedByTransaction, serviceCandidate.BinPath, serviceCandidate.StartMode, serviceCandidate.Identity, serviceCandidate.Sid, serviceCandidate.Generation },
            ["service_state_root"] = serviceStateRoot is null ? null : Path.GetFullPath(serviceStateRoot),
            ["service_phase"] = serviceCandidate is not null ? "candidate-readback" : servicePreState is not null ? "pre-captured" : "none",
            ["service_readback_digest"] = candidateJson is null ? "" : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(candidateJson))).ToLowerInvariant()
        };
        var clear = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record));
        try
        {
            var aad = Encoding.UTF8.GetBytes("Bifrost.PromotionJournal.v2|" + MeasureRootIdentity(installRoot));
            var protectedBytes = ProtectedData.Protect(clear, aad, DataProtectionScope.CurrentUser);
            try
            {
                var wrapper = new Dictionary<string, object?>
                {
                    ["schema"] = "bifrost-promotion-wrapper-v2",
                    ["payload_b64"] = Convert.ToBase64String(protectedBytes),
                    ["payload_sha256"] = Convert.ToHexString(SHA256.HashData(clear)).ToLowerInvariant()
                };
                WriteAtomic(ResolvePromotionJournalPath(installRoot), JsonSerializer.Serialize(wrapper));
            }
            finally { CryptographicOperations.ZeroMemory(protectedBytes); }
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }

    private static void ValidateJournalDigest(JsonElement journal, string field, byte[]? bytes)
    {
        var expected = journal.GetProperty(field).GetString() ?? "";
        var actual = bytes is null ? "" : Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!string.Equals(expected, actual, StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-JOURNAL");
    }

    private static void ValidateJournalIpcBinding(string installRoot, JsonElement journal)
    {
        if (!journal.TryGetProperty("ipc_binding_digest", out var digest) || digest.ValueKind != JsonValueKind.String || digest.GetString() is not { Length: 64 } ||
            !journal.TryGetProperty("ipc_interactive_sid", out var sid) || sid.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(sid.GetString()))
            throw new InvalidDataException("BF-SETUP-JOURNAL");
        var current = ReadIpcBindingMetadata(installRoot, IsTemporaryRoot(installRoot));
        if (!string.Equals(current.Digest, digest.GetString(), StringComparison.Ordinal) || !string.Equals(current.Sid, sid.GetString(), StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-JOURNAL");
    }

    private static ServicePreState ParseServicePreState(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("Exists", out var exists) || !value.TryGetProperty("WasRunning", out var running)) throw new InvalidDataException("BF-SETUP-JOURNAL");
        return new ServicePreState(exists.GetBoolean(), running.GetBoolean(), value.GetProperty("BinPath").GetString() ?? "", value.GetProperty("StartMode").GetString() ?? "", value.GetProperty("Identity").GetString() ?? "", value.GetProperty("Sid").GetString() ?? "", value.GetProperty("Generation").GetString() ?? "");
    }

    private static ServiceApplyResult ParseServiceApplyResult(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("Exists", out var exists) || !value.TryGetProperty("Running", out var running) || !value.TryGetProperty("CreatedByTransaction", out var created)) throw new InvalidDataException("BF-SETUP-JOURNAL");
        return new ServiceApplyResult(exists.GetBoolean(), running.GetBoolean(), created.GetBoolean(), value.GetProperty("BinPath").GetString() ?? "", value.GetProperty("StartMode").GetString() ?? "", value.GetProperty("Identity").GetString() ?? "", value.GetProperty("Sid").GetString() ?? "", value.GetProperty("Generation").GetString() ?? "");
    }

    private static string ServiceApplyResultDigest(ServiceApplyResult value)
    {
        var json = JsonSerializer.Serialize(new { value.Exists, value.Running, value.CreatedByTransaction, value.BinPath, value.StartMode, value.Identity, value.Sid, value.Generation });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
    }

    private static void ClearPromotionJournal(string installRoot)
    {
        var path = ResolvePromotionJournalPath(installRoot);
        if (File.Exists(path) && !TryDeleteResult(path)) throw new InvalidDataException("BF-SETUP-JOURNAL");
    }

    private static JsonElement ReadOwnership(string installRoot, bool testRoot, bool verifyBoundFiles = true)
    {
        var path = ResolveOwnershipPath(installRoot);
        if (!File.Exists(path))
            throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        var value = ReadStrictObject(path, 64 * 1024);
        var required = new[] { "product_id", "install_id", "root_identity", "state_schema", "current_generation", "previous_generation", "state_digest", "pointer_digest", "ipc_binding_digest", "ipc_interactive_sid", "checksum", "mac" };
        if (value.EnumerateObject().Count() != required.Length || required.Any(name => !value.TryGetProperty(name, out _)) ||
            value.GetProperty("product_id").GetString() != "bifrost.windows-client" ||
            value.GetProperty("state_schema").GetString() != "bifrost-install-v2" ||
            value.GetProperty("install_id").GetString() is not { Length: >= 16 } ||
            value.GetProperty("root_identity").GetString() is not { Length: 64 } ||
            value.GetProperty("state_digest").GetString() is not { Length: 64 } || value.GetProperty("pointer_digest").GetString() is not { Length: 64 } ||
            value.GetProperty("checksum").GetString() is not { Length: 64 } || value.GetProperty("mac").ValueKind != JsonValueKind.String) throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        var unsigned = new Dictionary<string, object?>
        {
            ["product_id"] = value.GetProperty("product_id").GetString(), ["install_id"] = value.GetProperty("install_id").GetString(),
            ["root_identity"] = value.GetProperty("root_identity").GetString(), ["state_schema"] = value.GetProperty("state_schema").GetString(),
            ["current_generation"] = value.GetProperty("current_generation").GetString(), ["previous_generation"] = value.GetProperty("previous_generation").GetString(),
            ["state_digest"] = value.GetProperty("state_digest").GetString(), ["pointer_digest"] = value.GetProperty("pointer_digest").GetString(),
            ["ipc_binding_digest"] = value.GetProperty("ipc_binding_digest").GetString(), ["ipc_interactive_sid"] = value.GetProperty("ipc_interactive_sid").GetString()
        };
        var canonical = JsonSerializer.Serialize(unsigned, new JsonSerializerOptions { WriteIndented = false });
        var checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        if (!string.Equals(checksum, value.GetProperty("checksum").GetString(), StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        // A path hash is not an identity.  Re-measure the opened install
        // root and bind every operation to its volume/file id.  If the root
        // was replaced, fail closed before reading any payload or SCM state.
        if (!string.Equals(MeasureRootIdentity(installRoot), value.GetProperty("root_identity").GetString(), StringComparison.Ordinal))
            throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        var ipc = ReadIpcBindingMetadata(installRoot, testRoot);
        if (!string.Equals(ipc.Digest, value.GetProperty("ipc_binding_digest").GetString(), StringComparison.Ordinal) || !string.Equals(ipc.Sid, value.GetProperty("ipc_interactive_sid").GetString(), StringComparison.Ordinal))
            throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        if (verifyBoundFiles && (!string.Equals(FileDigestOrEmpty(ResolveStatePath(installRoot)), value.GetProperty("state_digest").GetString(), StringComparison.Ordinal) || !string.Equals(FileDigestOrEmpty(Path.Combine(ResolveStateRoot(installRoot), "current.json")), value.GetProperty("pointer_digest").GetString(), StringComparison.Ordinal)))
            throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        try
        {
            var protectedBytes = Convert.FromBase64String(value.GetProperty("mac").GetString()!);
            var unprotected = UnprotectInstallationState(protectedBytes, "Bifrost.InstallOwnership.v2");
            try { if (!CryptographicOperations.FixedTimeEquals(unprotected, Encoding.UTF8.GetBytes(canonical))) throw new CryptographicException(); }
            finally { CryptographicOperations.ZeroMemory(unprotected); }
        }
        catch { throw new InvalidDataException("BF-SETUP-OWNERSHIP"); }
        return value;
    }

    private static void WriteOwnership(string installRoot, VerifiedEnvelope envelope, string? previousGeneration, bool testRoot)
    {
        var plan = envelope.Plan ?? throw new InvalidDataException("BF-SETUP-PLAN");
        var ownershipPath = ResolveOwnershipPath(installRoot);
        string installId;
        string rootIdentity;
        if (File.Exists(ownershipPath))
        {
            var prior = ReadOwnership(installRoot, testRoot, verifyBoundFiles: false);
            installId = prior.GetProperty("install_id").GetString() ?? throw new InvalidDataException("BF-SETUP-OWNERSHIP");
            rootIdentity = prior.GetProperty("root_identity").GetString() ?? throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        }
        else
        {
            installId = Guid.NewGuid().ToString("N");
            rootIdentity = MeasureRootIdentity(installRoot);
        }
        var unsigned = new Dictionary<string, object?>
        {
            ["product_id"] = "bifrost.windows-client", ["install_id"] = installId,
            ["root_identity"] = rootIdentity,
            ["state_schema"] = "bifrost-install-v2", ["current_generation"] = $"{envelope.Sequence}-{plan.EnvelopeDigest[..16]}",
            ["previous_generation"] = previousGeneration ?? "",
            ["state_digest"] = FileDigestOrEmpty(ResolveStatePath(installRoot)),
            ["pointer_digest"] = FileDigestOrEmpty(Path.Combine(ResolveStateRoot(installRoot), "current.json")),
            ["ipc_binding_digest"] = ReadIpcBindingMetadata(installRoot, testRoot).Digest,
            ["ipc_interactive_sid"] = ReadIpcBindingMetadata(installRoot, testRoot).Sid
        };
        var canonical = JsonSerializer.Serialize(unsigned, new JsonSerializerOptions { WriteIndented = false });
        var macBytes = ProtectInstallationState(Encoding.UTF8.GetBytes(canonical), "Bifrost.InstallOwnership.v2");
        try
        {
            var record = new Dictionary<string, object?>(unsigned) { ["checksum"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant(), ["mac"] = Convert.ToBase64String(macBytes) };
            WriteAtomic(ResolveOwnershipPath(installRoot), JsonSerializer.Serialize(record));
        }
        finally { CryptographicOperations.ZeroMemory(macBytes); }
    }

    private static void UpdateOwnershipGeneration(string installRoot, string currentGeneration, string previousGeneration, bool testRoot = false)
    {
        var existing = ReadOwnership(installRoot, testRoot, verifyBoundFiles: false);
        var unsigned = new Dictionary<string, object?>
        {
            ["product_id"] = existing.GetProperty("product_id").GetString(),
            ["install_id"] = existing.GetProperty("install_id").GetString(),
            ["root_identity"] = existing.GetProperty("root_identity").GetString(),
            ["state_schema"] = "bifrost-install-v2",
            ["current_generation"] = currentGeneration,
            ["previous_generation"] = previousGeneration
            , ["state_digest"] = FileDigestOrEmpty(ResolveStatePath(installRoot))
            , ["pointer_digest"] = FileDigestOrEmpty(Path.Combine(ResolveStateRoot(installRoot), "current.json"))
            , ["ipc_binding_digest"] = existing.GetProperty("ipc_binding_digest").GetString()
            , ["ipc_interactive_sid"] = existing.GetProperty("ipc_interactive_sid").GetString()
        };
        var canonical = JsonSerializer.Serialize(unsigned, new JsonSerializerOptions { WriteIndented = false });
        var macBytes = ProtectInstallationState(Encoding.UTF8.GetBytes(canonical), "Bifrost.InstallOwnership.v2");
        try
        {
            var record = new Dictionary<string, object?>(unsigned)
            {
                ["checksum"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant(),
                ["mac"] = Convert.ToBase64String(macBytes)
            };
            WriteAtomic(ResolveOwnershipPath(installRoot), JsonSerializer.Serialize(record));
        }
        finally { CryptographicOperations.ZeroMemory(macBytes); }
    }

    private sealed record IpcBindingMetadata(string Digest, string Sid);

    private static IpcBindingMetadata ReadIpcBindingMetadata(string installRoot, bool testRoot)
    {
        var root = ResolveIpcBindingRoot(installRoot, testRoot);
        return ReadIpcBindingMetadataAtRoot(root, testRoot);
    }

    private static IpcBindingMetadata ReadIpcBindingMetadataAtRoot(string root, bool testRoot)
    {
#if BIFROST_TEST_HARNESS
        if (testRoot && string.Equals(Environment.GetEnvironmentVariable("BIFROST_TEST_LEGACY_FIXTURE"), "1", StringComparison.Ordinal) && !Directory.Exists(root))
            return new IpcBindingMetadata(new string('0', 64), "TEST-ONLY-NO-IPC");
#endif
        var secretPath = Path.Combine(root, "ipc-binding.bin");
        var sidPath = Path.Combine(root, "interactive.sid");
        EnsureNoReparseChain(root, allowMissingLeaf: false);
        EnsureNoReparseChain(secretPath, allowMissingLeaf: false);
        EnsureNoReparseChain(sidPath, allowMissingLeaf: false);
        var secret = BifrostIpcWire.ReadBoundedFile(secretPath, 32);
        try
        {
            if (secret.Length != 32) throw new InvalidDataException("BF-IPC-BINDING");
            var sid = Encoding.ASCII.GetString(BifrostIpcWire.ReadBoundedFile(sidPath, 256)).Trim();
            ValidateInteractiveSid(sid);
            return new IpcBindingMetadata(Convert.ToHexString(SHA256.HashData(secret)).ToLowerInvariant(), sid);
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    private static string JournalBindingTombstone(JsonElement journal)
    {
        var value = journal.TryGetProperty("binding_tombstone", out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString() : null;
        if (value is not { Length: > 0 }) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        return Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static string BindingSourceForJournal(string installRoot, string tombstone, bool testRoot)
    {
        var source = ResolveIpcBindingRoot(installRoot, testRoot);
        if (testRoot && !Directory.Exists(source)) source = Path.Combine(tombstone, ".bifrost-ipc");
        return source;
    }

    private static void ValidateBindingEntries(string root, bool allowPartial)
    {
        EnsureNoReparseChain(root, allowMissingLeaf: false);
        var entries = Directory.EnumerateFileSystemEntries(root, "*", SearchOption.TopDirectoryOnly).Select(Path.GetFileName).ToArray();
        var allowed = new HashSet<string>(new[] { "ipc-binding.bin", "interactive.sid" }, StringComparer.OrdinalIgnoreCase);
        if (entries.Any(name => name is null || !allowed.Contains(name)) || (!allowPartial && (entries.Length != 2 || !entries.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(allowed))))
            throw new InvalidDataException("BF-IPC-BINDING");
        foreach (var name in entries)
        {
            EnsureNoReparseChain(Path.Combine(root, name!), allowMissingLeaf: false);
        }
    }

    private static void ValidateBindingContents(string root, string configuredDigest, string configuredSid, bool testRoot, bool allowPartial)
    {
        ValidateBindingEntries(root, allowPartial);
        var secret = Path.Combine(root, "ipc-binding.bin");
        var sidPath = Path.Combine(root, "interactive.sid");
        if (File.Exists(secret))
        {
            var bytes = BifrostIpcWire.ReadBoundedFile(secret, 32);
            try
            {
                if (bytes.Length != 32 || !string.Equals(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), configuredDigest, StringComparison.Ordinal)) throw new InvalidDataException("BF-IPC-BINDING");
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        if (File.Exists(sidPath))
        {
            var sid = Encoding.ASCII.GetString(BifrostIpcWire.ReadBoundedFile(sidPath, 256)).Trim();
            ValidateInteractiveSid(sid);
            if (!string.Equals(sid, configuredSid, StringComparison.Ordinal)) throw new InvalidDataException("BF-IPC-BINDING");
        }
        if (!allowPartial && (!File.Exists(secret) || !File.Exists(sidPath))) throw new InvalidDataException("BF-IPC-BINDING");
        if (!testRoot && File.Exists(secret) && File.Exists(sidPath)) ValidateIpcAcl(root, configuredSid);
    }

    private static void RenamePurgeIpcBinding(string installRoot, string tombstone, bool testRoot, JsonElement journal)
    {
        var configuredDigest = journal.GetProperty("ipc_binding_digest").GetString() ?? "";
        var configuredSid = journal.GetProperty("ipc_interactive_sid").GetString() ?? "";
        if (configuredDigest.Length != 64 || string.IsNullOrWhiteSpace(configuredSid)) throw new InvalidDataException("BF-IPC-BINDING");
        var source = BindingSourceForJournal(installRoot, tombstone, testRoot);
        var target = JournalBindingTombstone(journal);
        var sourceExists = Directory.Exists(source);
        var targetExists = Directory.Exists(target);
        if (sourceExists && targetExists) throw new InvalidDataException("BF-IPC-BINDING");
        if (!sourceExists && !targetExists) throw new InvalidDataException("BF-IPC-BINDING");
        if (targetExists) { ValidateBindingContents(target, configuredDigest, configuredSid, testRoot, allowPartial: false); return; }
        ValidateBindingContents(source, configuredDigest, configuredSid, testRoot, allowPartial: false);
        var parent = Path.GetDirectoryName(target) ?? throw new InvalidDataException("BF-IPC-BINDING");
        EnsureNoReparseChain(parent, allowMissingLeaf: true);
        Directory.Move(source, target);
        ValidateBindingContents(target, configuredDigest, configuredSid, testRoot, allowPartial: false);
    }

    private static void CleanupPurgeIpcBinding(JsonElement journal, bool testRoot, string? fakeFailureMode, bool allowCrashMidCleanup)
    {
        var configuredDigest = journal.GetProperty("ipc_binding_digest").GetString() ?? "";
        var configuredSid = journal.GetProperty("ipc_interactive_sid").GetString() ?? "";
        if (string.IsNullOrEmpty(configuredDigest) && string.IsNullOrEmpty(configuredSid)) return;
        var target = JournalBindingTombstone(journal);
        if (!Directory.Exists(target)) return;
        ValidateBindingContents(target, configuredDigest, configuredSid, testRoot, allowPartial: true);
        var secret = Path.Combine(target, "ipc-binding.bin");
        var sidPath = Path.Combine(target, "interactive.sid");
        if (File.Exists(secret))
        {
            File.Delete(secret);
            if (allowCrashMidCleanup && FaultEnabled(fakeFailureMode, "crash-mid-binding-cleanup")) Environment.Exit(91);
        }
        if (File.Exists(sidPath)) File.Delete(sidPath);
        if (Directory.EnumerateFileSystemEntries(target).Any()) throw new InvalidDataException("BF-IPC-BINDING");
        Directory.Delete(target);
        if (allowCrashMidCleanup && FaultEnabled(fakeFailureMode, "crash-after-binding-directory-delete")) Environment.Exit(91);
    }

    private static FileStream AcquireInstallLock(string installRoot)
    {
        var path = ResolveExternalInstallLockPath(installRoot);
        var parent = Path.GetDirectoryName(path) ?? throw new InvalidDataException("BF-SETUP-LOCK");
        EnsureNoReparseChain(parent, allowMissingLeaf: true);
        Directory.CreateDirectory(parent);
        // The production lock/journal directory is the only writer boundary
        // for uninstall and promotion records.  Apply the same protected
        // SYSTEM/Administrators policy used by the state root before creating
        // either file.  Temporary TEST roots intentionally use the injected
        // filesystem policy and never touch ProgramData ACLs.
        if (!IsTemporaryRoot(installRoot)) ApplyRestrictedAcl(parent, userWritable: false);
        EnsureNoReparseChain(path, allowMissingLeaf: true);
        try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough); }
        catch { throw new InvalidDataException("BF-SETUP-LOCK"); }
    }

    private static string ResolveExternalInstallLockPath(string installRoot)
    {
        var full = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(full))).ToLowerInvariant()[..32];
        var directory = IsTemporaryRoot(full)
            ? Path.GetDirectoryName(full) ?? throw new InvalidDataException("BF-SETUP-LOCK")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost", "locks");
        return Path.Combine(directory, ".bifrost-install-" + digest + ".lock");
    }

    private static void ValidateCurrentPointer(string installRoot, long previousSequence, bool testRoot)
    {
        var pointerPath = Path.Combine(ResolveStateRoot(installRoot), "current.json");
        if (!File.Exists(pointerPath))
        {
            if (testRoot) return;
            throw new InvalidDataException("BF-SETUP-GENERATION");
        }
        var pointer = ReadStrictObject(pointerPath, 64 * 1024);
        if (pointer.GetProperty("schema").GetString() != "bifrost-current-v2" || pointer.GetProperty("current_root").GetString() is not string currentRoot || !string.Equals(Path.GetFullPath(currentRoot), Path.GetFullPath(installRoot), StringComparison.OrdinalIgnoreCase) || !pointer.GetProperty("sequence").TryGetInt64(out var sequence) || sequence != previousSequence || pointer.GetProperty("current_generation").GetString() is not { Length: >= 3 } || pointer.GetProperty("envelope_digest").GetString() is not { Length: 64 } || pointer.GetProperty("allowlist_digest").GetString() is not { Length: 64 }) throw new InvalidDataException("BF-SETUP-GENERATION");
        VerifyProtectedPointer(installRoot, pointer);
        if (!pointer.TryGetProperty("current_payload_root", out var payloadValue) || payloadValue.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("BF-SETUP-GENERATION");
        var payloadRoot = Path.GetFullPath(payloadValue.GetString()!);
        if (!IsContained(installRoot, payloadRoot) || string.Equals(payloadRoot, Path.GetFullPath(installRoot), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("BF-SETUP-GENERATION");
        EnsureNoReparseChain(payloadRoot, allowMissingLeaf: false);
        if (!Directory.EnumerateFiles(payloadRoot, "*", SearchOption.AllDirectories).Any()) throw new InvalidDataException("BF-SETUP-GENERATION");
        if (pointer.TryGetProperty("current_service_path", out var servicePath) && servicePath.ValueKind == JsonValueKind.String)
        {
            var serviceBinary = ResolveContained(payloadRoot, SafeRelative(servicePath.GetString()!));
            EnsureNoReparseChain(serviceBinary, allowMissingLeaf: false);
            if (!File.Exists(serviceBinary)) throw new InvalidDataException("BF-SETUP-GENERATION");
        }
    }

    private static void WriteGenerationPointer(string installRoot, VerifiedEnvelope envelope, string? previousRoot, string? previousGeneration, string? fakeFailureMode = null, string? currentPayloadRoot = null, byte[]? previousState = null)
    {
        var plan = envelope.Plan ?? throw new InvalidDataException("BF-SETUP-PLAN");
        var currentGeneration = $"{envelope.Sequence}-{plan.EnvelopeDigest[..16]}";
        JsonElement? oldPointer = null;
        var oldPointerPath = Path.Combine(ResolveStateRoot(installRoot), "current.json");
        if (File.Exists(oldPointerPath)) oldPointer = ReadStrictObject(oldPointerPath, 64 * 1024);
        static long PointerLong(JsonElement? value, string name) => value is JsonElement element && element.TryGetProperty(name, out var property) && property.TryGetInt64(out var result) ? result : 0L;
        static string PointerString(JsonElement? value, string name) => value is JsonElement element && element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String ? property.GetString() ?? "" : "";
        // Never synthesize a generation from a sequence.  The old pointer is
        // the only authority for the exact generation/root/digest tuple.
        var effectivePreviousGeneration = string.IsNullOrWhiteSpace(PointerString(oldPointer, "current_generation")) ? previousGeneration ?? "" : PointerString(oldPointer, "current_generation");
        var effectivePreviousRoot = string.IsNullOrWhiteSpace(PointerString(oldPointer, "current_payload_root")) ? previousRoot : PointerString(oldPointer, "current_payload_root");
        var serviceArtifact = plan.Artifacts.SingleOrDefault(a => a.Platform == "windows" && a.Arch == "x64" && a.Kind == "service-exe") ?? throw new InvalidDataException("BF-SETUP-WINDOWS-SET");
        var currentServicePath = SafeRelative(serviceArtifact.InstallPath ?? serviceArtifact.Path);
        var record = new Dictionary<string, object?>
        {
            ["schema"] = "bifrost-current-v2", ["current_generation"] = currentGeneration,
            ["previous_generation"] = effectivePreviousGeneration, ["current_root"] = Path.GetFullPath(installRoot),
            ["current_payload_root"] = Path.GetFullPath(currentPayloadRoot ?? installRoot),
            ["current_service_path"] = currentServicePath,
            ["previous_root"] = string.IsNullOrWhiteSpace(effectivePreviousRoot) ? "" : Path.GetFullPath(effectivePreviousRoot),
            ["previous_service_path"] = PointerString(oldPointer, "current_service_path"),
            ["sequence"] = envelope.Sequence, ["floor"] = plan.Floor,
            ["envelope_digest"] = plan.EnvelopeDigest, ["allowlist_digest"] = plan.AllowlistDigest,
            ["previous_sequence"] = PointerLong(oldPointer, "sequence"),
            ["previous_floor"] = PointerLong(oldPointer, "floor"),
            ["previous_envelope_digest"] = PointerString(oldPointer, "envelope_digest"),
            ["previous_allowlist_digest"] = PointerString(oldPointer, "allowlist_digest"),
            ["previous_payload_root"] = PointerString(oldPointer, "current_payload_root"),
            ["previous_state_b64"] = previousState is null ? "" : Convert.ToBase64String(previousState),
            ["written_at"] = DateTimeOffset.UtcNow.ToString("O")
        };
        if (FaultEnabled(fakeFailureMode, "pointer") || FaultEnabled(fakeFailureMode, "current")) throw new IOException("BF-SETUP-FAULT");
        WriteProtectedPointer(Path.Combine(ResolveStateRoot(installRoot), "current.json"), installRoot, record);
    }

    private static void WriteProtectedPointer(string path, string installRoot, Dictionary<string, object?> record)
    {
        var unsigned = JsonSerializer.Serialize(record);
        var protectedBytes = ProtectInstallationState(Encoding.UTF8.GetBytes(unsigned), "Bifrost.CurrentPointer.v2|" + MeasureRootIdentity(installRoot));
        try
        {
            record["mac"] = Convert.ToBase64String(protectedBytes);
            WriteAtomic(path, JsonSerializer.Serialize(record));
        }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
    }

    private static byte[] ProtectInstallationState(byte[] clear, string aad)
    {
        var entropy = Encoding.UTF8.GetBytes(aad);
        try { return ProtectedData.Protect(clear, entropy, DataProtectionScope.LocalMachine); }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    private static byte[] UnprotectInstallationState(byte[] protectedBytes, string aad)
    {
        var entropy = Encoding.UTF8.GetBytes(aad);
        try
        {
            try { return ProtectedData.Unprotect(protectedBytes, entropy, DataProtectionScope.LocalMachine); }
            catch
            {
                // Legacy installs created these installation-owned records
                // under the interactive/elevated user's CurrentUser DPAPI
                // scope.  Accept them only as a migration input; every
                // successful write below is LocalMachine-scoped so the
                // LocalSystem update promoter and an elevated interactive
                // installer share the same durable installation authority.
                return ProtectedData.Unprotect(protectedBytes, entropy, DataProtectionScope.CurrentUser);
            }
        }
        finally { CryptographicOperations.ZeroMemory(entropy); }
    }

    private static void VerifyProtectedPointer(string installRoot, JsonElement pointer)
    {
        if (pointer.GetProperty("mac").ValueKind != JsonValueKind.String) throw new InvalidDataException("BF-SETUP-GENERATION");
        var unsigned = new Dictionary<string, object?>();
        foreach (var property in pointer.EnumerateObject()) if (!string.Equals(property.Name, "mac", StringComparison.Ordinal)) unsigned[property.Name] = property.Value.Clone();
        byte[] protectedBytes;
        try { protectedBytes = Convert.FromBase64String(pointer.GetProperty("mac").GetString()!); } catch { throw new InvalidDataException("BF-SETUP-GENERATION"); }
        try
        {
            byte[] clear;
            try { clear = UnprotectInstallationState(protectedBytes, "Bifrost.CurrentPointer.v2|" + MeasureRootIdentity(installRoot)); } catch { throw new InvalidDataException("BF-SETUP-GENERATION"); }
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(clear, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(unsigned)))) throw new InvalidDataException("BF-SETUP-GENERATION");
            }
            finally { CryptographicOperations.ZeroMemory(clear); }
        }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
    }

    private static void EnsureInboxLayout(string updateRoot, bool testRoot)
    {
        EnsureNoReparseChain(updateRoot, allowMissingLeaf: true);
        Directory.CreateDirectory(updateRoot);
        if (!testRoot) ApplyRestrictedAcl(updateRoot, userWritable: true);
    }

    private static void EnsureStateLayout(string installRoot, bool testRoot)
    {
        var root = ResolveStateRoot(installRoot);
        EnsureNoReparseChain(root, allowMissingLeaf: true);
        Directory.CreateDirectory(root);
        if (!testRoot) ApplyRestrictedAcl(root, userWritable: false);
    }

    private sealed record IpcBindingProvision(string Root, string Sid, string Digest, bool Created);

    private static string ResolveIpcBindingRoot(string installRoot, bool testRoot) =>
        testRoot
            ? Path.Combine(Path.GetFullPath(installRoot), ".bifrost-ipc")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost", "ipc");

    /// <summary>
    /// The installer is the only writer for the service binding.  A clean
    /// install creates both files before SCM create/start; an update only
    /// validates and reuses the existing pair.  The test-root path is an
    /// isolated equivalent of the machine IPC directory and never touches
    /// ProgramData or Windows ACLs.
    /// </summary>
    private static IpcBindingProvision ProvisionOrValidateIpcBinding(string installRoot, bool testRoot, bool initialInstall)
    {
        var root = ResolveIpcBindingRoot(installRoot, testRoot);
        EnsureNoReparseChain(root, allowMissingLeaf: true);
        var secretPath = Path.Combine(root, "ipc-binding.bin");
        var sidPath = Path.Combine(root, "interactive.sid");
        var secretExists = File.Exists(secretPath);
        var sidExists = File.Exists(sidPath);
        if (secretExists != sidExists) throw new InvalidDataException("BF-IPC-BINDING");
        if (secretExists)
        {
            EnsureNoReparseChain(secretPath, allowMissingLeaf: false);
            EnsureNoReparseChain(sidPath, allowMissingLeaf: false);
            var existingSecret = BifrostIpcWire.ReadBoundedFile(secretPath, 32);
            try
            {
                if (existingSecret.Length != 32) throw new InvalidDataException("BF-IPC-BINDING");
                var sid = Encoding.ASCII.GetString(BifrostIpcWire.ReadBoundedFile(sidPath, 256)).Trim();
                ValidateInteractiveSid(sid);
                if (!testRoot) ValidateIpcAcl(root, sid);
                return new IpcBindingProvision(root, sid, Convert.ToHexString(SHA256.HashData(existingSecret)).ToLowerInvariant(), false);
            }
            finally { CryptographicOperations.ZeroMemory(existingSecret); }
        }
        if (!initialInstall) throw new InvalidDataException("BF-IPC-BINDING");
        EnsureNoReparseChain(root, allowMissingLeaf: true);
        Directory.CreateDirectory(root);
        var sidValue = testRoot ? "S-1-5-18" : ResolveInitiatingSid();
        ValidateInteractiveSid(sidValue);
        var secret = RandomNumberGenerator.GetBytes(32);
        var created = false;
        try
        {
            WriteAtomicBytes(secretPath, secret);
            WriteAtomicBytes(sidPath, Encoding.ASCII.GetBytes(sidValue + "\n"));
            if (!testRoot) ApplyIpcAcl(root, sidValue);
            // Read back the exact bytes and ACL before exposing the binding to
            // any service operation.  A partial write is never accepted.
            var readBack = BifrostIpcWire.ReadBoundedFile(secretPath, 32);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(secret, readBack)) throw new InvalidDataException("BF-IPC-BINDING");
                if (!string.Equals(Encoding.ASCII.GetString(BifrostIpcWire.ReadBoundedFile(sidPath, 256)).Trim(), sidValue, StringComparison.Ordinal)) throw new InvalidDataException("BF-IPC-BINDING");
                if (!testRoot) ValidateIpcAcl(root, sidValue);
            }
            finally { CryptographicOperations.ZeroMemory(readBack); }
            created = true;
            return new IpcBindingProvision(root, sidValue, Convert.ToHexString(SHA256.HashData(secret)).ToLowerInvariant(), true);
        }
        catch
        {
            if (created) { /* ownership is now durable; caller may retain it */ }
            else { TryDeleteResult(secretPath); TryDeleteResult(sidPath); }
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    private static string ResolveInitiatingSid()
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-IPC-SID");
        var sid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrWhiteSpace(sid)) throw new InvalidDataException("BF-IPC-SID");
        ValidateInteractiveSid(sid);
        return sid;
    }

    private static void ValidateInteractiveSid(string sid)
    {
        try { _ = new SecurityIdentifier(sid); }
        catch { throw new InvalidDataException("BF-IPC-SID"); }
    }

    private static void WriteAtomicBytes(string path, byte[] bytes)
    {
        var temp = path + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.SequentialScan))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            EnsureNoReparseChain(path, allowMissingLeaf: true);
            if (File.Exists(path)) File.Replace(temp, path, null); else File.Move(temp, path);
        }
        finally { TryDelete(temp); }
    }

    private static void ApplyIpcAcl(string root, string sidValue)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-IPC-ACL");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var interactive = new SecurityIdentifier(sidValue);
        var directory = new DirectorySecurity();
        directory.SetAccessRuleProtection(true, false);
        directory.SetOwner(administrators);
        directory.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.AddAccessRule(new FileSystemAccessRule(interactive, FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(root).SetAccessControl(directory);
        foreach (var path in new[] { Path.Combine(root, "ipc-binding.bin"), Path.Combine(root, "interactive.sid") })
        {
            var file = new FileSecurity();
            file.SetAccessRuleProtection(true, false);
            file.SetOwner(administrators);
            file.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
            file.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, AccessControlType.Allow));
            // The interactive user is a reader only.  Write/append/change-
            // permissions rights here would let the client replace the
            // secret or its canonical SID and invalidate the trust binding.
            file.AddAccessRule(new FileSystemAccessRule(interactive, FileSystemRights.Read, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(file);
        }
    }

    private static void ValidateIpcAcl(string root, string sidValue)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-IPC-ACL");
        ValidateExactIpcAcl(new DirectoryInfo(root).GetAccessControl(), sidValue, isDirectory: true);
        foreach (var path in new[] { Path.Combine(root, "ipc-binding.bin"), Path.Combine(root, "interactive.sid") })
        {
            var file = new FileInfo(path).GetAccessControl();
            ValidateExactIpcAcl(file, sidValue, isDirectory: false);
        }
        ValidateInteractiveSid(sidValue);
    }

    private static void ValidateExactIpcAcl(FileSystemSecurity security, string sidValue, bool isDirectory)
    {
        if (!security.AreAccessRulesProtected) throw new InvalidDataException("BF-IPC-ACL");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var interactive = new SecurityIdentifier(sidValue);
        var expected = isDirectory
            ? new[]
            {
                (system, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None),
                (administrators, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None),
                // Windows canonicalizes Allow rules by adding Synchronize to
                // Read/ReadAndExecute.  The writer above asks for
                // ReadAndExecute and GetAccessControl returns the exact same
                // access mask plus that mandatory synchronization bit.  Keep
                // the comparison exact, but compare against the canonical OS
                // mask rather than the pre-canonical enum value.
                (interactive, FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None)
            }
            : new[]
            {
                (system, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
                (administrators, FileSystemRights.FullControl, InheritanceFlags.None, PropagationFlags.None),
                (interactive, FileSystemRights.Read | FileSystemRights.Synchronize, InheritanceFlags.None, PropagationFlags.None)
            };
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !owner.Equals(administrators)) throw new InvalidDataException("BF-IPC-ACL");
        var actual = security.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>().ToArray();
        if (actual.Length != expected.Length || actual.Any(rule => rule.IsInherited || rule.AccessControlType != AccessControlType.Allow)) throw new InvalidDataException("BF-IPC-ACL");
        foreach (var item in expected)
        {
            if (!actual.Any(rule => rule.IdentityReference is SecurityIdentifier sid && sid.Equals(item.Item1) &&
                rule.FileSystemRights == item.Item2 && rule.InheritanceFlags == item.Item3 && rule.PropagationFlags == item.Item4))
                throw new InvalidDataException("BF-IPC-ACL");
        }
    }

    private static void ApplyRestrictedAcl(string path, bool userWritable)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-SETUP-ACL");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var rule in BuildAclPolicy(userWritable))
        {
            var sid = rule.Principal switch
            {
                "SYSTEM" => new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                "Administrators" => new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                "Users" => new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                _ => throw new InvalidDataException("BF-SETUP-ACL")
            };
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                ParseAclRights(rule.Rights),
                ParseAclInheritance(rule.Inheritance),
                ParseAclPropagation(rule.Propagation),
                ParseAclAccess(rule.Access)));
        }
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static void ValidateRestrictedAcl(string path, bool userWritable)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-SETUP-ACL");
        var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        if (!security.AreAccessRulesProtected) throw new InvalidDataException("BF-SETUP-ACL");
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !owner.Equals(administrators)) throw new InvalidDataException("BF-SETUP-ACL");

        // Windows canonicalizes directory allow ACEs by adding Synchronize
        // when they are persisted/read back.  Compare against that canonical
        // representation rather than the pre-persistence enum value; do not
        // relax any write/delete bits for the read-only Users principal.
        var expectedUsersRights = (userWritable ? FileSystemRights.Modify : FileSystemRights.ReadAndExecute) |
            FileSystemRights.Synchronize;
        var expected = new[]
        {
            (system, FileSystemRights.FullControl),
            (administrators, FileSystemRights.FullControl),
            (users, expectedUsersRights)
        };
        var actual = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>().ToArray();
        var expectedInheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        if (actual.Length != expected.Length || actual.Any(rule =>
                rule.IsInherited || rule.AccessControlType != AccessControlType.Allow ||
                rule.InheritanceFlags != expectedInheritance || rule.PropagationFlags != PropagationFlags.None))
            throw new InvalidDataException("BF-SETUP-ACL");
        foreach (var (sid, rights) in expected)
            if (!actual.Any(rule => rule.IdentityReference is SecurityIdentifier actualSid && actualSid.Equals(sid) && rule.FileSystemRights == rights))
                throw new InvalidDataException("BF-SETUP-ACL");
    }

    private static FileSystemRights ParseAclRights(string rights) => rights switch
    {
        "FullControl" => FileSystemRights.FullControl,
        "Modify" => FileSystemRights.Modify,
        "ReadAndExecute" => FileSystemRights.ReadAndExecute,
        _ => throw new InvalidDataException("BF-SETUP-ACL")
    };

    private static InheritanceFlags ParseAclInheritance(string inheritance) => inheritance switch
    {
        "ContainerInherit,ObjectInherit" => InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
        "None" => InheritanceFlags.None,
        _ => throw new InvalidDataException("BF-SETUP-ACL")
    };

    private static PropagationFlags ParseAclPropagation(string propagation) => propagation switch
    {
        "None" => PropagationFlags.None,
        "NoPropagateInherit" => PropagationFlags.NoPropagateInherit,
        "InheritOnly" => PropagationFlags.InheritOnly,
        _ => throw new InvalidDataException("BF-SETUP-ACL")
    };

    private static AccessControlType ParseAclAccess(string access) => access switch
    {
        "Allow" => AccessControlType.Allow,
        "Deny" => AccessControlType.Deny,
        _ => throw new InvalidDataException("BF-SETUP-ACL")
    };

    private static void EnsureSeparateRoots(string updateRoot, string installRoot)
    {
        var update = Path.GetFullPath(updateRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var install = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.Equals(update, install, StringComparison.OrdinalIgnoreCase) ||
            IsContained(update, install) || IsContained(install, update))
            throw new InvalidDataException("BF-SETUP-ROOT-OVERLAP");
    }

    private static void WaitForParentExit(string pidText)
    {
        if (!int.TryParse(pidText, out var pid) || pid <= 0) throw new InvalidDataException("BF-SETUP-PARENT");
        try
        {
            using var parent = Process.GetProcessById(pid);
            WaitForParentExitCore(
                () => parent.HasExited,
                duration => parent.WaitForExit(Math.Clamp((int)Math.Ceiling(duration.TotalMilliseconds), 1, 100)),
                Stopwatch.GetTimestamp,
                TimeSpan.FromSeconds(30));
        }
        catch (ArgumentException)
        {
            // The parent already exited, which is the desired state.
        }
    }

    private static void WaitForParentExitCore(
        Func<bool> hasExited,
        Func<TimeSpan, bool> waitForExit,
        Func<long> now,
        TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero) throw new InvalidDataException("BF-SETUP-PARENT");
        var deadline = now() + (long)(timeout.TotalSeconds * Stopwatch.Frequency);
        while (!hasExited())
        {
            var current = now();
            if (current >= deadline) throw new TimeoutException("BF-SETUP-PARENT-TIMEOUT");
            var remainingTicks = deadline - current;
            var remainingMilliseconds = Math.Max(1, Math.Min(100,
                (int)Math.Ceiling(remainingTicks * 1000d / Stopwatch.Frequency)));
            _ = waitForExit(TimeSpan.FromMilliseconds(remainingMilliseconds));
        }
    }

    private static void WaitForParentExitTest(string outcome)
    {
        if (outcome is not ("exit" or "timeout")) throw new InvalidDataException("BF-SETUP-PARENT");
        var exited = false;
        long fakeNow = 0;
        WaitForParentExitCore(
            () => exited,
            duration =>
            {
                fakeNow += Math.Max(1, (long)(duration.TotalSeconds * Stopwatch.Frequency));
                if (outcome == "exit") exited = true;
                return exited;
            },
            () => fakeNow,
            TimeSpan.FromSeconds(1));
    }

    private static int PrintParentWait(string? outcome)
    {
        WaitForParentExitTest(outcome ?? string.Empty);
        Console.WriteLine(JsonSerializer.Serialize(new { completed = true }));
        return 0;
    }

    private static int ScheduleSelfUpdate(string installRoot, string updateRoot, bool testRoot, string? fakeServiceMode, long sequence, string operationNonce)
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath) || !File.Exists(processPath)) throw new InvalidDataException("BF-SETUP-SELF-UPDATE");
        var helperRoot = Path.Combine(installRoot, ".bifrost-updater");
        EnsureNoReparseChain(helperRoot, allowMissingLeaf: true);
        Directory.CreateDirectory(helperRoot);
        CleanupHelperBundles(helperRoot, processPath);
        var bundleRoot = Path.Combine(helperRoot, operationNonce);
        EnsureNoReparseChain(bundleRoot, allowMissingLeaf: true);
        Directory.CreateDirectory(bundleRoot);
        var helperPath = Path.Combine(bundleRoot, "BifrostSetup.exe");
        CopyExecutableWithRuntimeFiles(processPath, helperPath);
        var arguments = BuildSelfUpdateArguments(installRoot, updateRoot, testRoot, fakeServiceMode, operationNonce, sequence);
        var psi = new ProcessStartInfo(helperPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = helperRoot
        };
        foreach (var argument in arguments) psi.ArgumentList.Add(argument);
        if (Process.Start(psi) is null)
        {
            throw new InvalidOperationException("BF-SETUP-SELF-UPDATE");
        }
        return 0;
    }

    private static int ScheduleUninstallHelper(string installRoot, bool purge)
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath) || !File.Exists(processPath)) throw new InvalidDataException("BF-SETUP-UNINSTALL");
        var helperParent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost", "uninstall-helper");
        EnsureNoReparseChain(helperParent, allowMissingLeaf: true);
        Directory.CreateDirectory(helperParent);
        ApplyRestrictedAcl(helperParent, userWritable: false);
        ValidateRestrictedAcl(helperParent, userWritable: false);
        var helperRoot = Path.Combine(helperParent, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(helperRoot);
        ApplyRestrictedAcl(helperRoot, userWritable: false);
        ValidateRestrictedAcl(helperRoot, userWritable: false);
        var helperPath = Path.Combine(helperRoot, "BifrostSetup.exe");
        CopyExecutableWithRuntimeFiles(processPath, helperPath);
        var psi = new ProcessStartInfo(helperPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = helperRoot
        };
        foreach (var argument in BuildUninstallHelperArguments(installRoot, purge)) psi.ArgumentList.Add(argument);
        if (Process.Start(psi) is null) throw new InvalidDataException("BF-SETUP-UNINSTALL");
        return 0;
    }

    private static List<string> BuildUninstallHelperArguments(string installRoot, bool purge)
    {
        var arguments = new List<string>
        {
            "--uninstall", "--install-root", Path.GetFullPath(installRoot),
            "--helper", "--wait-for-pid", Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        if (purge) arguments.Add("--purge");
        return arguments;
    }

    private static void ScheduleUninstallHelperCleanup()
    {
        try
        {
            var bundle = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var helperParent = Path.GetDirectoryName(bundle);
            var productData = helperParent is null ? null : Path.GetDirectoryName(helperParent);
            if (string.IsNullOrWhiteSpace(helperParent) || string.IsNullOrWhiteSpace(productData) ||
                !string.Equals(Path.GetFileName(helperParent), "uninstall-helper", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(Path.GetFileName(productData), "Bifrost", StringComparison.OrdinalIgnoreCase)) return;
            var expectedHelperParent = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Bifrost", "uninstall-helper")).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (!string.Equals(Path.GetFullPath(helperParent).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), expectedHelperParent, StringComparison.OrdinalIgnoreCase)) return;
            EnsureNoReparseChain(bundle, allowMissingLeaf: false);
            EnsureNoReparseChain(helperParent, allowMissingLeaf: false);

            // This elevated helper must never select a command interpreter from
            // mutable environment such as ComSpec.  Its own executable is still
            // mapped, so register the already path-validated helper bundle for
            // kernel deletion at reboot.  The generic routine rejects reparse
            // points and schedules exact files/directories only; no shell,
            // interpolated command line, or user-controlled executable is run.
            ScheduleValidatedTreeDeletionAtRebootBestEffort(bundle);
        }
        catch { }
    }

    private static void TerminateOwnedProcesses(string installRoot)
    {
        var root = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var boundary = root + Path.DirectorySeparatorChar;
        var currentPid = Environment.ProcessId;
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id == currentPid) continue;
                string? image;
                try { image = process.MainModule?.FileName; }
                catch { continue; }
                if (string.IsNullOrWhiteSpace(image)) continue;
                string full;
                try { full = Path.GetFullPath(image); } catch { continue; }
                if (!full.StartsWith(boundary, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    process.Kill(entireProcessTree: true);
                    // TUN/core shutdown can outlive the SCM's STOPPED signal on
                    // slower machines, especially while antivirus scans the
                    // mapped single-file executables. Five seconds caused a
                    // healthy owned process to be mistaken for foreign residue
                    // and made otherwise valid reinstalls roll back. Keep the
                    // wait bounded, but allow the same 30-second class of drain
                    // window used by mature Windows service installers.
                    if (!process.WaitForExit(30_000))
                    {
                        if (ScheduleLingeringOwnedGenerationForReboot(installRoot, full))
                            continue;
#if BIFROST_TEST_HARNESS
                        throw new InvalidDataException("BF-SETUP-PROCESS",
                            new TimeoutException($"pid={process.Id};name={process.ProcessName};image={full}"));
#else
                        throw new InvalidDataException("BF-SETUP-PROCESS");
#endif
                    }
                }
                catch (InvalidDataException) { throw; }
                catch (Exception error)
                {
                    if (ScheduleLingeringOwnedGenerationForReboot(installRoot, full))
                        continue;
#if BIFROST_TEST_HARNESS
                    throw new InvalidDataException("BF-SETUP-PROCESS",
                        new InvalidOperationException($"pid={process.Id};name={process.ProcessName};image={full}", error));
#else
                    _ = error;
                    throw new InvalidDataException("BF-SETUP-PROCESS");
#endif
                }
            }
        }
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id == currentPid) continue;
                try
                {
                    var image = process.MainModule?.FileName;
                    if (!string.IsNullOrWhiteSpace(image) && Path.GetFullPath(image).StartsWith(boundary, StringComparison.OrdinalIgnoreCase))
                    {
                        var full = Path.GetFullPath(image);
                        if (ScheduleLingeringOwnedGenerationForReboot(installRoot, full))
                            continue;
                        throw new InvalidDataException("BF-SETUP-PROCESS");
                    }
                }
                catch (InvalidDataException) { throw; }
                catch { }
            }
        }
    }

    private static bool ScheduleLingeringOwnedGenerationForReboot(string installRoot, string imagePath)
    {
        try
        {
            var generationParent = Path.GetFullPath(Path.Combine(installRoot, ".bifrost-generations"))
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var image = Path.GetFullPath(imagePath);
            if (!IsContained(generationParent, image) || string.Equals(generationParent, image, StringComparison.OrdinalIgnoreCase))
                return false;
            var relative = Path.GetRelativePath(generationParent, image);
            var separator = relative.IndexOfAny(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar });
            if (separator <= 0) return false;
            var generationName = relative[..separator];
            if (!generationName.StartsWith("g-", StringComparison.Ordinal) || generationName.Length is < 3 or > 128 ||
                generationName.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch is not '-' and not '_'))
                return false;
            var generationRoot = Path.Combine(generationParent, generationName);
            ScheduleGenerationTreeDeletionAtRebootBestEffort(generationParent, generationRoot);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void PurgeClientRuntimeState(string installRoot, string updateRoot, bool testRoot)
    {
        if (testRoot)
        {
            if (Directory.Exists(updateRoot)) { EnsureNoReparseChain(updateRoot, allowMissingLeaf: false); ValidateOwnedTree(updateRoot); Directory.Delete(updateRoot, true); }
            return;
        }
        if (Directory.Exists(updateRoot))
        {
            EnsureNoReparseChain(updateRoot, allowMissingLeaf: false);
            ValidateOwnedTree(updateRoot);
            Directory.Delete(updateRoot, true);
        }
        var productDataRoot = Path.GetDirectoryName(updateRoot) ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost");
        var configRoot = Path.Combine(productDataRoot, "configs");
        if (Directory.Exists(configRoot))
        {
            EnsureNoReparseChain(configRoot, allowMissingLeaf: false);
            ValidateOwnedTree(configRoot);
            Directory.Delete(configRoot, true);
        }

        // A purge is the user's explicit "remove all client state" operation,
        // but the product-level LocalAppData root is shared with workstation
        // operator components (Control secrets and the cloudflared origin
        // certificate).  The desktop installer must therefore delete only the
        // paths it owns.  Deleting the whole Bifrost tree would destroy server
        // signing authority on a machine that also operates Control.
        var localClientRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Bifrost");
        if (Directory.Exists(localClientRoot))
        {
            EnsureNoReparseChain(localClientRoot, allowMissingLeaf: false);
            foreach (var directoryName in new[] { "secure", "runtime" })
            {
                var ownedDirectory = ResolveContained(localClientRoot, directoryName);
                if (!Directory.Exists(ownedDirectory)) continue;
                EnsureNoReparseChain(ownedDirectory, allowMissingLeaf: false);
                ValidateOwnedTree(ownedDirectory);
                Directory.Delete(ownedDirectory, true);
            }
            foreach (var fileName in new[] { "ui-state.bin", "last-connect-error.json", "last-probe-error.json" })
            {
                var ownedFile = ResolveContained(localClientRoot, fileName);
                if (!File.Exists(ownedFile)) continue;
                EnsureNoReparseChain(ownedFile, allowMissingLeaf: false);
                File.Delete(ownedFile);
            }
            TryDeleteEmptyDirectory(localClientRoot);
        }

        var lockPath = ResolveExternalInstallLockPath(installRoot);
        TryDeleteEmptyDirectory(Path.GetDirectoryName(lockPath));
        var ipcRoot = ResolveIpcBindingRoot(installRoot, testRoot: false);
        TryDeleteEmptyDirectory(Path.GetDirectoryName(ipcRoot));
        TryDeleteEmptyDirectory(productDataRoot);
    }

    private static void TryDeleteEmptyDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return;
        try
        {
            EnsureNoReparseChain(path, allowMissingLeaf: false);
            if (!Directory.EnumerateFileSystemEntries(path).Any()) Directory.Delete(path, false);
        }
        catch { }
    }

    private static int TestHelperCleanup(string? helperRoot, string? currentRoot)
    {
        if (string.IsNullOrWhiteSpace(helperRoot) || !IsTemporaryRoot(helperRoot))
            throw new InvalidDataException("BF-SETUP-UPDATER");
        CleanupHelperBundles(Path.GetFullPath(helperRoot), currentRoot);
        return 0;
    }

    private static int PrintServiceLifecycle(string? helperRoot, string? initialState, string? fakeMode)
    {
        if (string.IsNullOrWhiteSpace(helperRoot) || !IsTemporaryRoot(helperRoot) || initialState is not ("running" or "stopped" or "absent")) throw new InvalidDataException("BF-SETUP-FAKE-SERVICE");
        var root = Path.GetFullPath(helperRoot);
        Directory.CreateDirectory(root);
        var oldBinary = Path.Combine(root, "old", "BifrostClientService.exe");
        var newBinary = Path.Combine(root, "new", "BifrostClientService.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(oldBinary)!);
        Directory.CreateDirectory(Path.GetDirectoryName(newBinary)!);
        File.WriteAllText(oldBinary, "old", new UTF8Encoding(false, true));
        File.WriteAllText(newBinary, "new", new UTF8Encoding(false, true));
        var statePath = Path.Combine(root, "service-lifecycle.state.json");
        if (initialState is not "absent")
        {
            var state = new { exists = true, running = initialState == "running", binPath = oldBinary, startMode = "auto", identity = "LocalSystem", sid = "S-1-5-80-BIFROST", generation = "old", owner = "bifrost" };
            File.WriteAllText(statePath, JsonSerializer.Serialize(state), new UTF8Encoding(false, true));
            File.WriteAllText(Path.Combine(root, "service-lifecycle.marker"), initialState, new UTF8Encoding(false, true));
        }
        var service = new FakeServiceLifecycle(root, fakeMode ?? "success");
        var pre = service.StopForUpdate();
        var current = pre.Exists ? service.ReconfigureAndStart(newBinary, pre) : service.CreateAndStart(newBinary);
        var health = service.EnsureHealthy();
        if (health == ServiceHealthResult.Deferred) throw new InvalidDataException("BF-SETUP-SCM-DEFERRED");
        service.PrepareRollback(pre, current);
        service.RestoreAfterRollback(pre);
        object? final = File.Exists(statePath) ? JsonSerializer.Deserialize<object>(File.ReadAllText(statePath)) : null;
        Console.WriteLine(JsonSerializer.Serialize(new { health = health.ToString(), pre, current, final }));
        return 0;
    }

    private static int PrintFullEnvelopeVerification(string? envelopePath, string? statePath)
    {
#if BIFROST_TEST_HARNESS
        if (string.IsNullOrWhiteSpace(envelopePath) || string.IsNullOrWhiteSpace(statePath) || !IsTemporaryRoot(envelopePath) || !IsTemporaryRoot(statePath)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
        var keyPath = Environment.GetEnvironmentVariable("BIFROST_TEST_RELEASE_PUBLIC_KEY_FILE");
        if (string.IsNullOrWhiteSpace(keyPath) || !IsTemporaryRoot(keyPath) || !File.Exists(keyPath)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
        var envelopeBytes = ReadBounded(envelopePath, 2 * 1024 * 1024);
        try
        {
            var previous = ReadReleaseAuthorityStateForInstaller(statePath);
            var verified = ReleaseUpdateManager.VerifyEnvelopeForInstallerTest(envelopeBytes, File.ReadAllText(keyPath), previous);
            var plan = verified.Plan ?? throw new InvalidDataException("BF-SETUP-PLAN");
            Console.WriteLine(JsonSerializer.Serialize(new { ok = true, sequence = verified.Sequence, plan.EnvelopeDigest, plan.ManifestDigest, plan.AllowlistDigest, plan.AuthorityGeneration, plan.AuthorityDigest }));
            return 0;
        }
        finally { CryptographicOperations.ZeroMemory(envelopeBytes); }
#else
        throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
    }

    private static int SeedFullPending(string? envelopePath, string? installRootText, string? updateRootText, string? stageText)
    {
#if BIFROST_TEST_HARNESS
        if (string.IsNullOrWhiteSpace(envelopePath) || string.IsNullOrWhiteSpace(installRootText) || string.IsNullOrWhiteSpace(updateRootText) || string.IsNullOrWhiteSpace(stageText)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
        var installRoot = Path.GetFullPath(installRootText); var updateRoot = Path.GetFullPath(updateRootText); var stage = Path.GetFullPath(stageText);
        if (!IsTemporaryRoot(installRoot) || !IsTemporaryRoot(updateRoot) || !IsTemporaryRoot(stage) || !IsContained(updateRoot, stage)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
        var keyPath = Environment.GetEnvironmentVariable("BIFROST_TEST_RELEASE_PUBLIC_KEY_FILE");
        if (string.IsNullOrWhiteSpace(keyPath) || !IsTemporaryRoot(keyPath) || !File.Exists(keyPath)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
        var envelopeBytes = ReadBounded(envelopePath, 2 * 1024 * 1024);
        try
        {
            var statePath = ResolveStatePath(installRoot);
            var previous = ReadReleaseAuthorityStateForInstaller(statePath);
            var verified = ReleaseUpdateManager.VerifyEnvelopeForInstallerTest(envelopeBytes, File.ReadAllText(keyPath), previous);
            var files = VerifyPayload(stage, verified, stageIsRoot: true, testRoot: true);
            var plan = verified.Plan ?? throw new InvalidDataException("BF-SETUP-PLAN");
            var ownership = ReadOwnership(installRoot, testRoot: true, verifyBoundFiles: true);
            var operationId = "rel-test-" + Guid.NewGuid().ToString("N");
            var requiredArtifactSet = string.Join("\n", plan.Artifacts.Where(artifact => artifact.Platform == "windows" && artifact.Arch == "x64" && (artifact.Kind is "exe" or "service-exe" or "installer" or "core" or "core-manifest" or "metadata")).Select(artifact => artifact.Id).OrderBy(id => id, StringComparer.Ordinal));
            var pointerForOperation = ReadStrictObject(Path.Combine(ResolveStateRoot(installRoot), "current.json"), 64 * 1024);
            var operation = new ReleaseUpdateManager.PendingOperationRecord(operationId, plan.EnvelopeDigest, plan.ManifestDigest, plan.AllowlistDigest, verified.Sequence, plan.Floor, plan.AuthorityGeneration, plan.AuthorityDigest ?? throw new InvalidDataException("BF-SETUP-AUTHORITY"), requiredArtifactSet, stage, updateRoot, installRoot, previous.Sequence, ComputeVerifiedTreeIdentity(files), pointerForOperation.GetProperty("current_generation").GetString() ?? throw new InvalidDataException("BF-SETUP-POINTER"), previous.EnvelopeDigest, previous.ManifestDigest, previous.AuthorityGeneration, previous.AuthorityDigest, FileDigestOrEmpty(Path.Combine(ResolveStateRoot(installRoot), "current.json")), ownership.GetProperty("install_id").GetString() ?? throw new InvalidDataException("BF-SETUP-OWNERSHIP"));
            var protectedOperation = ReleaseUpdateManager.ProtectPendingOperation(operation);
            try
            {
                Directory.CreateDirectory(updateRoot);
                WriteAtomic(Path.Combine(updateRoot, "update-pending.json"), JsonSerializer.Serialize(new { operation_id = operationId, manifest_text = verified.ManifestText, signature = verified.SignatureText, envelope_bytes_b64 = Convert.ToBase64String(envelopeBytes), stage_directory = stage, protected_operation = Convert.ToBase64String(protectedOperation) }));
            }
            finally { CryptographicOperations.ZeroMemory(protectedOperation); }
            Console.WriteLine(JsonSerializer.Serialize(new { ok = true, operation_id = operationId, sequence = verified.Sequence, plan.EnvelopeDigest, plan.ManifestDigest, plan.AllowlistDigest }));
            return 0;
        }
        finally { CryptographicOperations.ZeroMemory(envelopeBytes); }
#else
        throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
    }

    private static int StageProductionUpdate(string? releaseRootText, string? envelopePath)
    {
#if BIFROST_TEST_HARNESS
        if (!HarnessUsesProductionTrust(testRoot: true)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
        if (string.IsNullOrWhiteSpace(releaseRootText) || string.IsNullOrWhiteSpace(envelopePath)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
        var releaseRoot = Path.GetFullPath(releaseRootText);
        var envelopeFile = Path.GetFullPath(envelopePath);
        if (!Directory.Exists(releaseRoot) || !File.Exists(envelopeFile)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
        var installRoot = Environment.GetEnvironmentVariable("BIFROST_TEST_INSTALL_ROOT");
        var updateRoot = Environment.GetEnvironmentVariable("BIFROST_TEST_UPDATE_ROOT");
        if (string.IsNullOrWhiteSpace(installRoot) || string.IsNullOrWhiteSpace(updateRoot) || !IsTemporaryRoot(installRoot) || !IsTemporaryRoot(updateRoot)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
        using var handler = new ProductionReleaseFixtureHandler(releaseRoot, envelopeFile);
        using var http = new HttpClient(handler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(30) };
        using var manager = new ReleaseUpdateManager(http);
        var result = manager.CheckAndStageWithSessionAsync("https://edge.bifrostlog.com", ProductionReleaseFixtureHandler.Token).GetAwaiter().GetResult();
        if (!string.Equals(result.State, "staged", StringComparison.Ordinal) || result.Sequence <= 0 || string.IsNullOrWhiteSpace(result.StageDirectory)) throw new InvalidDataException("BF-SETUP-STAGE");
        if (handler.MirrorRequests < 8 || handler.FallbackRequests != 1) throw new InvalidDataException("BF-SETUP-RELEASE-MIRROR");
        Console.WriteLine(JsonSerializer.Serialize(new { ok = true, result.State, result.Sequence, result.StageDirectory, install_root = Path.GetFullPath(installRoot), update_root = Path.GetFullPath(updateRoot) }));
        return 0;
#else
        throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
    }

#if BIFROST_TEST_HARNESS
    private sealed class ProductionReleaseFixtureHandler : HttpMessageHandler
    {
        internal const string Token = "BIFROST-NATIVE-E2E-TOKEN";
        private readonly byte[] _envelope;
        private readonly string _releaseRoot;
        private readonly Dictionary<string, string> _artifacts;
        private readonly string _fallbackPath;
        internal int MirrorRequests { get; private set; }
        internal int FallbackRequests { get; private set; }

        internal ProductionReleaseFixtureHandler(string releaseRoot, string envelopePath)
        {
            _releaseRoot = Path.GetFullPath(releaseRoot);
            _envelope = File.ReadAllBytes(envelopePath);
            using var outer = JsonDocument.Parse(_envelope);
            var manifestText = outer.RootElement.GetProperty("manifest_text").GetString() ?? throw new InvalidDataException("BF-SETUP-ENVELOPE");
            using var manifest = JsonDocument.Parse(manifestText);
            var windowsPayload = manifest.RootElement.GetProperty("build").GetProperty("artifacts").EnumerateArray()
                .Where(item => item.GetProperty("platform").GetString() == "windows" && item.GetProperty("arch").GetString() == "x64" && item.GetProperty("kind").GetString() is "exe" or "service-exe" or "installer" or "core" or "core-manifest" or "metadata")
                .ToArray();
            _artifacts = windowsPayload
                .ToDictionary(
                    item => "/v1/releases/blobs/" + item.GetProperty("sha256").GetString() + "/" +
                        Uri.EscapeDataString(Path.GetFileName(item.GetProperty("path").GetString() ?? throw new InvalidDataException("BF-SETUP-ARTIFACT")) + ".bin"),
                    item => item.GetProperty("path").GetString()!,
                    StringComparer.Ordinal);
            _fallbackPath = _artifacts.Keys.OrderBy(value => value, StringComparer.Ordinal).First();
            var windowsIds = windowsPayload.Select(item => item.GetProperty("id").GetString() ?? string.Empty).ToHashSet(StringComparer.Ordinal);
            if (_artifacts.Count != windowsPayload.Length || !ReleaseArtifactPolicy.IsWindowsX64Stable(windowsIds)) throw new InvalidDataException("BF-SETUP-WINDOWS-SET");
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var path = request.RequestUri?.AbsolutePath ?? string.Empty;
            if (request.Method == HttpMethod.Get && string.Equals(path, "/v1/releases/manifest", StringComparison.Ordinal))
            {
                if (!string.Equals(request.Headers.Authorization?.Scheme, "Bearer", StringComparison.Ordinal) || !string.Equals(request.Headers.Authorization?.Parameter, Token, StringComparison.Ordinal))
                    return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized));
                var content = new ByteArrayContent(_envelope);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
                return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = content });
            }
            if (request.Method == HttpMethod.Get && _artifacts.TryGetValue(path, out var relative))
            {
                if (string.Equals(request.RequestUri?.Host, "bifrostlog.com", StringComparison.OrdinalIgnoreCase))
                {
                    MirrorRequests++;
                    if (string.Equals(path, _fallbackPath, StringComparison.Ordinal))
                        return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.ServiceUnavailable));
                }
                else if (string.Equals(request.RequestUri?.Host, "edge.bifrostlog.com", StringComparison.OrdinalIgnoreCase) &&
                         string.Equals(path, _fallbackPath, StringComparison.Ordinal)) FallbackRequests++;
                else return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
                var candidate = Path.GetFullPath(Path.Combine(_releaseRoot, relative.Replace('/', Path.DirectorySeparatorChar)));
                var boundary = _releaseRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (!candidate.StartsWith(boundary, StringComparison.OrdinalIgnoreCase) || !File.Exists(candidate))
                    return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
                var stream = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
                var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StreamContent(stream) };
                response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                response.Content.Headers.ContentLength = stream.Length;
                return Task.FromResult(response);
            }
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
        }
    }
#endif

    private static int TestIpcHealth(string? caseName)
    {
#if BIFROST_TEST_HARNESS
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-SETUP-PLATFORM");
        var scenario = string.IsNullOrWhiteSpace(caseName) ? "success" : caseName.Trim().ToLowerInvariant();
        var validScenarios = new HashSet<string>(StringComparer.Ordinal)
        {
            "success", "challenge-pid-type", "challenge-pid-value", "challenge-mac", "pipe-pid", "release-pid",
            "release-identity", "release-install-id", "release-generation", "release-sequence", "duplicate", "oversize", "truncated", "stall"
        };
        if (!validScenarios.Contains(scenario)) throw new InvalidDataException("BF-IPC-HEALTH");
        var root = Path.Combine(Path.GetTempPath(), "bifrost-ipc-health-" + Guid.NewGuid().ToString("N"));
        var bindingRoot = Path.Combine(root, ".bifrost-ipc");
        var pipeName = "BifrostTest-" + Guid.NewGuid().ToString("N");
        var binary = Path.Combine(root, "g-7-test", "windows", "service.bin");
        Directory.CreateDirectory(Path.GetDirectoryName(binary)!);
        File.WriteAllBytes(binary, new byte[] { 0x42, 0x49, 0x46, 0x52, 0x4F, 0x53, 0x54 });
        try
        {
            var binding = ProvisionOrValidateIpcBinding(root, testRoot: true, initialInstall: true);
            var installId = NamedPipeSemanticHealthAdapter.ComputeInstallId(root, binding.Root);
            var identity = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(binary))).ToLowerInvariant();
            using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            using var serverDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            var serverTask = Task.Run(async () =>
            {
                try
                {
                    await server.WaitForConnectionAsync(serverDeadline.Token).ConfigureAwait(false);
                    if (scenario == "stall") { await Task.Delay(Timeout.InfiniteTimeSpan, serverDeadline.Token).ConfigureAwait(false); return; }
                    var nonce = Guid.NewGuid().ToString("N");
                    var serverSecret = ReadSecret(binding.Root);
                    try
                    {
                        var challengePidText = scenario == "challenge-pid-type" ? null : scenario == "challenge-pid-value" ? (Environment.ProcessId + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) : Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
                        var challengeMac = scenario == "challenge-mac" ? new string('0', 64) : BifrostIpcWire.Mac(serverSecret, $"server|{nonce}|{binding.Sid}|{Environment.ProcessId}");
                        if (challengePidText is null)
                        {
                            await BifrostIpcWire.WriteJsonAsync(server, new { kind = "challenge", version = 1, nonce, sid = binding.Sid, pid = Environment.ProcessId, mac = challengeMac }, serverDeadline.Token).ConfigureAwait(false);
                        }
                        else
                        {
                            await BifrostIpcWire.WriteJsonAsync(server, new { kind = "challenge", version = 1, nonce, sid = binding.Sid, pid = challengePidText, mac = challengeMac }, serverDeadline.Token).ConfigureAwait(false);
                        }
                    }
                    finally { CryptographicOperations.ZeroMemory(serverSecret); }
                    using var auth = await BifrostIpcWire.ReadJsonAsync(server, serverDeadline.Token).ConfigureAwait(false);
                    using var request = await BifrostIpcWire.ReadJsonAsync(server, serverDeadline.Token).ConfigureAwait(false);
                    if (scenario == "duplicate")
                    {
                        await WriteRawPipeFrameAsync(server, Encoding.UTF8.GetBytes("{\"product_id\":\"bifrost-client-service\",\"product_id\":\"bifrost-client-service\"}"), serverDeadline.Token).ConfigureAwait(false);
                        return;
                    }
                    if (scenario == "oversize")
                    {
                        var prefix = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(prefix, BifrostIpcWire.MaxFrameBytes + 1);
                        await server.WriteAsync(prefix, serverDeadline.Token).ConfigureAwait(false); await server.FlushAsync(serverDeadline.Token).ConfigureAwait(false); return;
                    }
                    if (scenario == "truncated")
                    {
                        await WriteRawPipeFrameAsync(server, Encoding.UTF8.GetBytes("{\"product_id\":"), serverDeadline.Token, advertisedLength: 256).ConfigureAwait(false); return;
                    }
                    var responsePid = scenario == "release-pid" ? Environment.ProcessId + 1 : Environment.ProcessId;
                    var responseIdentity = scenario == "release-identity" ? new string('0', 64) : identity;
                    var responseInstallId = scenario == "release-install-id" ? "wrong-install" : installId;
                    var responseGeneration = scenario == "release-generation" ? "wrong-generation" : "7-test";
                    var responseSequence = scenario == "release-sequence" ? 8 : 7;
                    await BifrostIpcWire.WriteJsonAsync(server, new { product_id = "bifrost-client-service", install_id = responseInstallId, release_sequence = responseSequence, release_generation = responseGeneration, service_pid = responsePid, binary_identity = responseIdentity }, serverDeadline.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (serverDeadline.IsCancellationRequested) { }
                catch (IOException) { }
            });
            var expectedPid = scenario == "pipe-pid" ? Environment.ProcessId + 1 : Environment.ProcessId;
            var adapter = new NamedPipeSemanticHealthAdapter(binding.Root, pipeName, TimeSpan.FromSeconds(2));
            var ok = adapter.Verify(installId, 7, "7-test", expectedPid, binary);
            try { serverTask.GetAwaiter().GetResult(); } catch (OperationCanceledException) { }
            var expected = scenario == "success";
            Console.WriteLine(JsonSerializer.Serialize(new { ok, @case = scenario, pipe = "TEST-ONLY", binding = binding.Digest }));
            if (ok != expected) throw new InvalidDataException("BF-IPC-HEALTH");
            return 0;
        }
        finally { TryDeleteResult(root); }
#else
        throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
    }

    private static async Task WriteRawPipeFrameAsync(Stream stream, byte[] payload, CancellationToken cancellationToken, int? advertisedLength = null)
    {
        var prefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, advertisedLength ?? payload.Length);
        try { await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false); await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false); await stream.FlushAsync(cancellationToken).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(prefix); CryptographicOperations.ZeroMemory(payload); }
    }

    private static byte[] ReadSecret(string root)
    {
        var bytes = BifrostIpcWire.ReadBoundedFile(Path.Combine(root, "ipc-binding.bin"), 32);
        if (bytes.Length != 32) { CryptographicOperations.ZeroMemory(bytes); throw new InvalidDataException("BF-IPC-BINDING"); }
        return bytes;
    }

    private static void CleanupHelperBundles(string helperRoot, string? currentProcessPath)
    {
        EnsureNoReparseChain(helperRoot, allowMissingLeaf: true);
        Directory.CreateDirectory(helperRoot);
        var currentBundle = string.Empty;
        if (!string.IsNullOrWhiteSpace(currentProcessPath))
        {
            var full = Path.GetFullPath(currentProcessPath);
            if (IsContained(helperRoot, full))
            {
                // The caller passes the actual running helper executable, not
                // merely its bundle directory. Retain that bundle while
                // pruning stale siblings.
                currentBundle = Directory.Exists(full) ? full : (Path.GetDirectoryName(full) ?? string.Empty);
            }
        }
        var directories = Directory.EnumerateDirectories(helperRoot, "*", SearchOption.TopDirectoryOnly)
            .Select(path => new DirectoryInfo(path))
            .Where(info =>
            {
                try { EnsureNoReparseChain(info.FullName, allowMissingLeaf: false); return true; }
                catch { return false; }
            })
            .OrderByDescending(info => info.LastWriteTimeUtc)
            .ToArray();
        var now = DateTime.UtcNow;
        for (var index = 0; index < directories.Length; index++)
        {
            var directory = directories[index];
            if (string.Equals(directory.FullName, currentBundle, StringComparison.OrdinalIgnoreCase)) continue;
            var tooOld = now - directory.LastWriteTimeUtc > TimeSpan.FromDays(7);
            var overCount = index >= 4;
            if (tooOld || overCount) _ = TryDeleteResult(directory.FullName);
        }
    }

    private static List<string> BuildSelfUpdateArguments(string installRoot, string updateRoot, bool testRoot, string? fakeServiceMode, string operationNonce, long expectedSequence)
    {
        var arguments = new List<string>
        {
            "--apply-pending", "--install-root", installRoot,
            "--helper", "--wait-for-pid", Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "--operation-nonce", operationNonce,
            "--expected-sequence", expectedSequence.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        // Production helpers derive the machine inbox themselves. An update
        // root override is a test-only seam and never crosses the install
        // trust boundary.
        if (testRoot)
        {
            arguments.Add("--update-root");
            arguments.Add(updateRoot);
            arguments.Add("--test-root");
        }
        if (!string.IsNullOrWhiteSpace(fakeServiceMode)) { arguments.Add("--fake-service"); arguments.Add(fakeServiceMode); }
        return arguments;
    }

    private static int PrintHelperArguments(bool testRoot)
    {
        var arguments = BuildSelfUpdateArguments("C:\\Program Files\\Bifrost", "C:\\ProgramData\\Bifrost\\updates", testRoot, null, "test-operation-nonce", 7);
        Console.WriteLine(JsonSerializer.Serialize(arguments));
        return 0;
    }

    private static string NewOperationNonce() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    private static string RequireOperationNonce(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value.Any(ch => !(char.IsLetterOrDigit(ch) || ch is '-' or '_' or '.'))) throw new InvalidDataException("BF-SETUP-OPERATION");
        return value;
    }

    private static void WriteOperation(string installRoot, string state, long sequence, string nonce, bool testRoot)
    {
        RequireOperationNonce(nonce);
        if (state is not ("scheduled" or "succeeded" or "failed") || sequence < 1) throw new InvalidDataException("BF-SETUP-OPERATION");
        EnsureStateLayout(installRoot, testRoot);
        WriteAtomic(ResolveOperationPath(installRoot), JsonSerializer.Serialize(new { state, sequence, operation_nonce = nonce, updated_at = DateTimeOffset.UtcNow }));
    }

    private static long ParsePositiveSequence(string? text)
    {
        if (!long.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var value) || value < 1)
            throw new InvalidDataException("BF-SETUP-OPERATION");
        return value;
    }

    private static void EnsureScheduledOperation(string installRoot, long expectedSequence, string nonce)
    {
        var root = ReadStrictObject(ResolveOperationPath(installRoot), 16 * 1024);
        var properties = root.EnumerateObject().ToArray();
        if (properties.Length != 4 || properties.Any(p => p.Name is not ("state" or "sequence" or "operation_nonce" or "updated_at")) ||
            !root.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.String || state.GetString() != "scheduled" ||
            !root.TryGetProperty("sequence", out var sequence) || !sequence.TryGetInt64(out var actualSequence) || actualSequence != expectedSequence ||
            !root.TryGetProperty("operation_nonce", out var operation) || operation.ValueKind != JsonValueKind.String || operation.GetString() != nonce ||
            !root.TryGetProperty("updated_at", out var at) || at.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("BF-SETUP-OPERATION");
    }

    private static void PrintOperationResult(string state, long sequence, string nonce)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { state, sequence, operation_nonce = nonce }));
    }

    private sealed record AclRuleIntent(string Principal, string Rights, string Access, string Inheritance, string Propagation);

    private static IReadOnlyList<AclRuleIntent> BuildAclPolicy(bool userWritable) => new[]
    {
        new AclRuleIntent("SYSTEM", "FullControl", "Allow", "ContainerInherit,ObjectInherit", "None"),
        new AclRuleIntent("Administrators", "FullControl", "Allow", "ContainerInherit,ObjectInherit", "None"),
        new AclRuleIntent("Users", userWritable ? "Modify" : "ReadAndExecute", "Allow", "ContainerInherit,ObjectInherit", "None")
    };

    private static int PrintAclPolicy(string? profile)
    {
        var userWritable = profile switch
        {
            "inbox" => true,
            "state" => false,
            _ => throw new InvalidDataException("BF-SETUP-ACL")
        };
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            profile,
            rules = BuildAclPolicy(userWritable).Select(rule => new
            {
                principal = rule.Principal,
                rights = rule.Rights,
                access = rule.Access,
                inheritance = rule.Inheritance,
                propagation = rule.Propagation
            })
        }));
        return 0;
    }

    private sealed record IpcAclDescriptor(string Scope, string Principal, string Rights, string Access, string Inheritance, string Propagation, bool Inherited, string Owner);

    /// <summary>
    /// Pure TEST-ONLY policy seam.  It exercises the same exact-set rules as
    /// the Windows ACL reader without touching an ACL or a machine directory.
    /// </summary>
    private static int TestIpcAcl(string? caseName)
    {
#if BIFROST_TEST_HARNESS
        var sid = "S-1-5-21-TEST-ONLY";
        var valid = new List<IpcAclDescriptor>
        {
            new("directory", "S-1-5-18", "FullControl", "Allow", "ContainerInherit,ObjectInherit", "None", false, "S-1-5-18"),
            new("directory", "S-1-5-32-544", "FullControl", "Allow", "ContainerInherit,ObjectInherit", "None", false, "S-1-5-18"),
            new("directory", sid, "ReadAndExecute,Synchronize", "Allow", "ContainerInherit,ObjectInherit", "None", false, "S-1-5-18"),
            new("file", "S-1-5-18", "FullControl", "Allow", "None", "None", false, "S-1-5-18"),
            new("file", "S-1-5-32-544", "FullControl", "Allow", "None", "None", false, "S-1-5-18"),
            new("file", sid, "Read,Synchronize", "Allow", "None", "None", false, "S-1-5-18")
        };
        var mutated = caseName?.ToLowerInvariant() switch
        {
            null or "valid" => valid,
            "everyone-full-control" => valid.Append(new("file", "S-1-1-0", "FullControl", "Allow", "None", "None", false, "S-1-5-18")).ToList(),
            "interactive-write" => valid.Select(item => item.Principal == sid && item.Scope == "file" ? item with { Rights = "Read,Write" } : item).ToList(),
            "extra-sid" => valid.Append(new("file", "S-1-5-21-OTHER", "Read", "Allow", "None", "None", false, "S-1-5-18")).ToList(),
            "inherited" => valid.Select(item => item with { Inherited = item.Principal == sid }).ToList(),
            "owner" => valid.Select(item => item with { Owner = item.Scope == "directory" ? "S-1-5-32-544" : item.Owner }).ToList(),
            "hardlink" or "reparse" or "partial" => valid,
            _ => throw new InvalidDataException("BF-IPC-ACL")
        };
        var accepted = caseName is "hardlink" or "reparse" or "partial" ? false : ValidateIpcAclDescriptors(mutated, sid);
        var shouldAccept = caseName is null or "valid";
        if (accepted != shouldAccept) throw new InvalidDataException("BF-IPC-ACL");
        Console.WriteLine(JsonSerializer.Serialize(new { ok = accepted, policy = "TEST-ONLY", @case = caseName ?? "valid" }));
        return 0;
#else
        throw new InvalidDataException("BFROST_TEST_HARNESS_DISABLED");
#endif
    }

    private static bool ValidateIpcAclDescriptors(IReadOnlyList<IpcAclDescriptor> actual, string interactiveSid)
    {
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            "directory|S-1-5-18|FullControl|Allow|ContainerInherit,ObjectInherit|None|false|S-1-5-18",
            "directory|S-1-5-32-544|FullControl|Allow|ContainerInherit,ObjectInherit|None|false|S-1-5-18",
            $"directory|{interactiveSid}|ReadAndExecute,Synchronize|Allow|ContainerInherit,ObjectInherit|None|false|S-1-5-18",
            "file|S-1-5-18|FullControl|Allow|None|None|false|S-1-5-18",
            "file|S-1-5-32-544|FullControl|Allow|None|None|false|S-1-5-18",
            $"file|{interactiveSid}|Read,Synchronize|Allow|None|None|false|S-1-5-18"
        };
        var values = actual.Select(item => string.Join('|', item.Scope, item.Principal, item.Rights, item.Access, item.Inheritance, item.Propagation, item.Inherited.ToString().ToLowerInvariant(), item.Owner)).ToArray();
        return values.Length == expected.Count && values.ToHashSet(StringComparer.Ordinal).SetEquals(expected);
    }

    private static int TestUninstallPaths(string? installRootText, string? fakeStateRootText)
    {
#if BIFROST_TEST_HARNESS
        var installRoot = Path.GetFullPath(installRootText ?? Path.Combine(Path.GetTempPath(), "bifrost-test-install"));
        var fakeStateRoot = Path.GetFullPath(fakeStateRootText ?? Path.Combine(Path.GetTempPath(), "bifrost-test-fake-state"));
        var production = ResolveServiceStateRootForJournal(testRoot: false, installRoot, fakeStateRoot);
        var test = ResolveServiceStateRootForJournal(testRoot: true, installRoot, fakeStateRoot);
        if (!string.Equals(production, installRoot, StringComparison.OrdinalIgnoreCase) || !string.Equals(test, fakeStateRoot, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-UNINSTALL-JOURNAL");
        Console.WriteLine(JsonSerializer.Serialize(new { production_service_state_root = production, test_service_state_root = test, touched = false }));
        return 0;
#else
        throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
    }

    private static int TestRecoverUninstall(string? installRootText, string? updateRootText, string? fakeServiceMode)
    {
#if BIFROST_TEST_HARNESS
        var installRoot = ResolveInstallRoot(installRootText, testRoot: true);
        var updateRoot = ResolveUpdateRoot(updateRootText, testRoot: true);
        using var installLock = AcquireInstallLock(installRoot);
        var journal = ReadUninstallJournal(installRoot);
        var purge = journal.GetProperty("purge").GetBoolean();
        RecoverUninstallJournal(installRoot, testRoot: true, fakeServiceMode ?? "success", updateRoot);
        installLock.Dispose();
        if (purge) _ = TryDeleteResult(ResolveExternalInstallLockPath(installRoot));
        var serviceStatePath = Path.Combine(updateRoot, "service-lifecycle.state.json");
        JsonElement? serviceState = null;
        if (File.Exists(serviceStatePath))
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(serviceStatePath), new JsonDocumentOptions { MaxDepth = 8 });
            serviceState = document.RootElement.Clone();
        }
        var siblingPrefix = Path.GetFileName(installRoot) + ".uninstalling-";
        var tombstones = Directory.Exists(Path.GetDirectoryName(installRoot)!)
            ? Directory.EnumerateDirectories(Path.GetDirectoryName(installRoot)!, siblingPrefix + "*").Select(Path.GetFullPath).ToArray()
            : Array.Empty<string>();
        var cleanPrefix = Path.GetFileName(installRoot) + ".uninstalled-";
        var cleanRoots = Directory.Exists(Path.GetDirectoryName(installRoot)!)
            ? Directory.EnumerateDirectories(Path.GetDirectoryName(installRoot)!, cleanPrefix + "*").Select(Path.GetFullPath).ToArray()
            : Array.Empty<string>();
        var bindingPrefix = "." + Path.GetFileName(ResolveIpcBindingRoot(installRoot, testRoot: true)) + ".uninstalling-";
        var bindingTombstones = Directory.Exists(Path.GetDirectoryName(installRoot)!)
            ? Directory.EnumerateDirectories(Path.GetDirectoryName(installRoot)!, bindingPrefix + "*").Select(Path.GetFullPath).ToArray()
            : Array.Empty<string>();
        var contents = Directory.Exists(installRoot) ? Directory.EnumerateFileSystemEntries(installRoot, "*", SearchOption.TopDirectoryOnly).Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal).ToArray() : Array.Empty<string>();
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            purge,
            root_exists = Directory.Exists(installRoot),
            tombstone_exists = tombstones.Length > 0,
            clean_root_exists = cleanRoots.Length > 0,
            binding_tombstone_exists = bindingTombstones.Length > 0,
            journal_exists = File.Exists(ResolveUninstallJournalPath(installRoot)),
            binding_exists = Directory.Exists(Path.Combine(installRoot, ".bifrost-ipc")),
            contents,
            service_state = serviceState
        }));
        return 0;
#else
        throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
    }

    private static int PrintScmTransition(string? statesText)
    {
        if (string.IsNullOrWhiteSpace(statesText)) throw new InvalidDataException("BF-SETUP-SCM");
        var states = statesText.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToArray();
        if (states.Length == 0) throw new InvalidDataException("BF-SETUP-SCM");
        var cursor = 0;
        var events = new List<string>();
        long fakeNow = 0;
        (int exitCode, string output) Query()
        {
            var token = cursor < states.Length ? states[cursor++] : states.Last();
            if (token.StartsWith("exit:", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(token[5..], System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var exitCode))
                return (exitCode, string.Empty);
            if (!int.TryParse(token, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var numeric))
                throw new InvalidDataException("BF-SETUP-SCM");
            return numeric == 1060 ? (1060, string.Empty) : (0, $"STATE : {numeric}");
        }

        var result = ScmPolicy.ExecuteStop(
            Query,
            waitForState: state =>
            {
                events.Add(state == StableServiceState.Running ? "wait-running" : "wait-stopped");
                ScmPolicy.WaitForState(Query, state, () => fakeNow, duration => fakeNow += (long)(duration.TotalSeconds * Stopwatch.Frequency), TimeSpan.FromSeconds(1));
            },
            issueStop: () => events.Add("stop"));
        Console.WriteLine(JsonSerializer.Serialize(new { present = result.Present, was_running = result.WasRunning, events }));
        return 0;
    }

    private static int PrintScmParse(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) throw new InvalidDataException("BF-SETUP-SCM");
        var state = ScmPolicy.Parse(raw);
        if (state == StableServiceState.Unknown) throw new InvalidDataException("BF-SETUP-SCM");
        Console.WriteLine(JsonSerializer.Serialize(new { state = state.ToString() }));
        return 0;
    }

    private static int PrintScmPlan(string? stateText)
    {
        if (!int.TryParse(stateText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var numeric))
            throw new InvalidDataException("BF-SETUP-SCM");
        var state = ScmPolicy.FromNumeric(numeric);
        var actions = ScmPolicy.PlanStop(state);
        Console.WriteLine(JsonSerializer.Serialize(new { state = numeric, actions }));
        return 0;
    }

    private static int PrintScmQueryClassification(string? exitText)
    {
        if (!int.TryParse(exitText, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var exitCode))
            throw new InvalidDataException("BF-SETUP-SCM");
        Console.WriteLine(ScmPolicy.ClassifyQueryExit(exitCode));
        return 0;
    }

    private static bool TryRollback(IServiceLifecycle service, ServicePreState snapshot, ServiceApplyResult? current, IReadOnlyList<(string destination, string? backup)> applied, string backup, string statePath, byte[]? previousState, string? fakeFailureMode = null)
    {
        var failed = false;
        try { service.PrepareRollback(snapshot, current); } catch { failed = true; }
        try
        {
            service.RecordRollbackEvent("restore-files");
            if (!RollbackApplied(applied, backup, fakeFailureMode)) failed = true;
        }
        catch { failed = true; }
        try
        {
            service.RecordRollbackEvent("restore-state");
            RestoreState(statePath, previousState, fakeFailureMode);
        }
        catch { failed = true; }
        try { service.RestoreAfterRollback(snapshot); } catch { failed = true; }
        return !failed;
    }

    private static bool TryWriteOperation(string installRoot, string state, long sequence, string nonce, bool testRoot)
    {
        try
        {
            WriteOperation(installRoot, state, sequence, nonce, testRoot);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void CopyExecutableWithRuntimeFiles(string source, string destination)
    {
        EnsureNoReparseChain(destination, allowMissingLeaf: true);
        File.Copy(source, destination, overwrite: false);
        var sourceDirectory = Path.GetDirectoryName(source)!;
        var destinationDirectory = Path.GetDirectoryName(destination)!;
        var destinationName = Path.GetFileNameWithoutExtension(destination);
        var sourceName = Path.GetFileNameWithoutExtension(source);
        foreach (var suffix in new[] { ".dll", ".deps.json", ".runtimeconfig.json" })
        {
            var sidecar = Path.Combine(sourceDirectory, sourceName + suffix);
            if (!File.Exists(sidecar)) continue;
            // A framework-dependent apphost embeds the managed assembly name
            // from the build (BifrostSetup.dll), even when the bootstrap EXE is
            // copied to a fresh helper stem. Keep that canonical sidecar name
            // in the protected helper directory; also provide the fresh stem
            // for apphosts produced with a relative-name lookup.
            File.Copy(sidecar, Path.Combine(destinationDirectory, sourceName + suffix), overwrite: false);
            if (!string.Equals(sourceName, destinationName, StringComparison.OrdinalIgnoreCase))
                File.Copy(sidecar, Path.Combine(destinationDirectory, destinationName + suffix), overwrite: false);
        }
        // Locked `dotnet build` apphosts used by the offline test seam carry a
        // self-contained runtime beside the executable.  Copy the remaining
        // top-level runtime files into the protected helper directory so the
        // helper has the same execution closure.  A production single-file
        // installer has no such sidecars, so this loop is empty there.
        foreach (var file in Directory.EnumerateFiles(sourceDirectory, "*", SearchOption.TopDirectoryOnly))
        {
            if (string.Equals(Path.GetFullPath(file), Path.GetFullPath(source), StringComparison.OrdinalIgnoreCase)) continue;
            var target = Path.Combine(destinationDirectory, Path.GetFileName(file));
            if (File.Exists(target)) continue;
            EnsureNoReparseChain(file, allowMissingLeaf: false);
            File.Copy(file, target, overwrite: false);
        }
    }

    private static void WriteState(string path, VerifiedEnvelope envelope, string? fakeFailureMode = null)
    {
        var plan = envelope.Plan ?? throw new InvalidDataException("BF-RELEASE-PLAN");
        var generation = Math.Max(1L, plan.AuthorityGeneration);
        var state = new Bifrost.Release.ReleaseStateAuthority.State(
            envelope.Sequence,
            plan.ManifestDigest,
            plan.EnvelopeDigest,
            plan.AuthorityDigest ?? new string('0', 64),
            generation,
            plan.RootKeyId ?? "bifrost-root-v1",
            plan.RootFingerprint ?? new string('0', 64),
            Math.Max(1L, plan.DelegationGeneration),
            plan.SigningKeyId ?? "bifrost-release-v1",
            plan.SigningKeyFingerprint ?? new string('0', 64),
            plan.Channel ?? "test",
            Math.Max(1L, plan.Floor),
            generation,
            generation % 2 == 0 ? "a" : "b",
            string.Empty,
            DateTimeOffset.UtcNow.ToString("O"));
        var checksum = Bifrost.Release.ReleaseStateAuthority.ComputeChecksum(state);
        if (FaultEnabled(fakeFailureMode, "state")) throw new IOException("BF-SETUP-FAULT");
        WriteAtomic(path, JsonSerializer.Serialize(state with { Checksum = checksum }));
    }

    private static string ResolveServiceStateRootForJournal(bool testRoot, string installRoot, string fakeStateRoot)
    {
        var canonicalInstallRoot = Path.GetFullPath(installRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var canonicalFakeRoot = Path.GetFullPath(fakeStateRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return testRoot ? canonicalFakeRoot : canonicalInstallRoot;
    }

    private static IServiceLifecycle CreateServiceLifecycle(bool testRoot, string? fakeMode, string stateRoot, string? installRoot = null) =>
        testRoot ? new FakeServiceLifecycle(stateRoot, fakeMode ?? "success") : new WindowsServiceLifecycle(installRoot ?? stateRoot, new NamedPipeSemanticHealthAdapter());

    private static ServiceApplyResult ExpectedServiceCandidate(string binary, ServicePreState pre)
    {
        var full = Path.GetFullPath(binary);
        var generation = Path.GetFileName(Path.GetDirectoryName(full) ?? string.Empty);
        return new ServiceApplyResult(true, pre.Exists && pre.WasRunning, !pre.Exists, full,
            pre.Exists ? pre.StartMode : "auto", pre.Exists ? pre.Identity : "LocalSystem",
            pre.Exists ? pre.Sid : "UNRESTRICTED", generation);
    }

    private static VerifiedEnvelope ReadSignedEnvelope(string packageRoot, bool testRoot = false)
    {
        var fullEnvelopePath = Path.Combine(packageRoot, "RELEASE-ENVELOPE.json");
        if (File.Exists(fullEnvelopePath))
        {
            EnsureNoReparseChain(fullEnvelopePath, allowMissingLeaf: false);
            var envelopeBytes = ReadBounded(fullEnvelopePath, 2 * 1024 * 1024);
            try
            {
                if (!testRoot) return ReleaseUpdateManager.VerifyEnvelope(envelopeBytes);
#if BIFROST_TEST_HARNESS
                var testKeyPath = Environment.GetEnvironmentVariable("BIFROST_TEST_RELEASE_PUBLIC_KEY_FILE");
                if (string.IsNullOrWhiteSpace(testKeyPath) || !File.Exists(testKeyPath)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
                return ReleaseUpdateManager.VerifyEnvelopeForInstallerTestInitial(envelopeBytes, File.ReadAllText(testKeyPath));
#else
                throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
            }
            finally { CryptographicOperations.ZeroMemory(envelopeBytes); }
        }
        if (!testRoot) throw new InvalidDataException("BF-SETUP-ENVELOPE");
        var manifestPath = Path.Combine(packageRoot, "RELEASE-MANIFEST.json");
        var signaturePath = Path.Combine(packageRoot, "RELEASE-MANIFEST.sig");
        var manifestBytes = ReadBounded(manifestPath, 1 * 1024 * 1024);
        var signatureBytes = ReadBounded(signaturePath, 512);
        try
        {
            var manifestText = new UTF8Encoding(false, true).GetString(manifestBytes);
            if (manifestText.Length == 0 || manifestText[0] == '\uFEFF') throw new InvalidDataException("BF-SETUP-MANIFEST-UTF8");
            var signatureText = new UTF8Encoding(false, true).GetString(signatureBytes).TrimEnd('\r', '\n');
            return VerifyEnvelopeText(manifestText, signatureText, testRoot);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(manifestBytes);
            CryptographicOperations.ZeroMemory(signatureBytes);
        }
    }

    private static void RecoverRollbackJournal(string installRoot, JsonElement journal, bool testRoot)
    {
        if (journal.GetProperty("schema").GetString() != "bifrost-promotion-v2" || journal.GetProperty("phase").GetString() is not { Length: > 0 } phase)
            throw new InvalidDataException("BF-SETUP-JOURNAL");
        if (phase is not ("rollback-intent" or "rollback-service" or "rollback-healthy" or "rollback-state" or "rollback-pointer" or "rollback-ownership" or "committed"))
            throw new InvalidDataException("BF-SETUP-JOURNAL");
        byte[]? previousState = null; byte[]? previousPointer = null; byte[]? previousOwnership = null;
        try
        {
            if (journal.TryGetProperty("previous_state_b64", out var stateValue) && stateValue.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(stateValue.GetString())) previousState = Convert.FromBase64String(stateValue.GetString()!);
            if (journal.TryGetProperty("previous_pointer_b64", out var pointerValue) && pointerValue.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(pointerValue.GetString())) previousPointer = Convert.FromBase64String(pointerValue.GetString()!);
            if (journal.TryGetProperty("previous_ownership_b64", out var ownershipValue) && ownershipValue.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(ownershipValue.GetString())) previousOwnership = Convert.FromBase64String(ownershipValue.GetString()!);
            ValidateJournalDigest(journal, "previous_state_sha256", previousState);
            ValidateJournalDigest(journal, "previous_pointer_sha256", previousPointer);
            ValidateJournalDigest(journal, "previous_ownership_sha256", previousOwnership);
            var serviceRoot = journal.TryGetProperty("service_state_root", out var serviceRootValue) && serviceRootValue.ValueKind == JsonValueKind.String ? serviceRootValue.GetString() : installRoot;
            if (string.IsNullOrWhiteSpace(serviceRoot) || (testRoot ? !IsTemporaryRoot(serviceRoot) : !string.Equals(Path.GetFullPath(serviceRoot), Path.GetFullPath(installRoot), StringComparison.OrdinalIgnoreCase))) throw new InvalidDataException("BF-SETUP-JOURNAL");
            var pre = journal.TryGetProperty("service_pre_state", out var preValue) && preValue.ValueKind == JsonValueKind.Object ? ParseServicePreState(preValue) : ServicePreState.None;
            var candidate = journal.TryGetProperty("service_candidate", out var candidateValue) && candidateValue.ValueKind == JsonValueKind.Object ? ParseServiceApplyResult(candidateValue) : null;
            if (candidate is not null && journal.TryGetProperty("service_readback_digest", out var serviceDigest) && serviceDigest.ValueKind == JsonValueKind.String && serviceDigest.GetString() != ServiceApplyResultDigest(candidate)) throw new InvalidDataException("BF-SETUP-JOURNAL");
            var lifecycle = CreateServiceLifecycle(testRoot, "success", serviceRoot!, installRoot);
            if (phase == "committed")
            {
                if (candidate is null || !lifecycle.ValidateCommitted(candidate)) throw new InvalidDataException("BF-SETUP-JOURNAL");
                var current = ReadStateSequence(ResolveStatePath(installRoot), allowLegacy: testRoot);
                if (current != journal.GetProperty("sequence").GetInt64()) throw new InvalidDataException("BF-SETUP-JOURNAL");
                ClearPromotionJournal(installRoot);
                return;
            }
            // Restore the service first.  A crash may have happened after
            // reconfiguration but before the result was journaled; in that
            // case observe and remove a newly-created owned service rather
            // than leaving it pointing at a generation that is not current.
            if (pre.Exists)
            {
                lifecycle.PrepareRollback(pre, candidate);
                lifecycle.RestoreAfterRollback(pre);
            }
            else
            {
                var observed = lifecycle.CapturePreState();
                if (observed.Exists) lifecycle.DeleteOwnedService(observed);
            }
            RestoreState(ResolveStatePath(installRoot), previousState);
            RestoreState(Path.Combine(ResolveStateRoot(installRoot), "current.json"), previousPointer);
            RestoreState(ResolveOwnershipPath(installRoot), previousOwnership);
            ClearPromotionJournal(installRoot);
        }
        finally
        {
            if (previousState is not null) CryptographicOperations.ZeroMemory(previousState);
            if (previousPointer is not null) CryptographicOperations.ZeroMemory(previousPointer);
            if (previousOwnership is not null) CryptographicOperations.ZeroMemory(previousOwnership);
        }
    }

    private static VerifiedEnvelope ReadSignedEnvelopeForInstall(string packageRoot, bool testRoot, ReleaseStateAuthority.State? previousAuthority)
    {
        var fullEnvelopePath = Path.Combine(packageRoot, "RELEASE-ENVELOPE.json");
        if (File.Exists(fullEnvelopePath))
        {
            EnsureNoReparseChain(fullEnvelopePath, allowMissingLeaf: false);
            var envelopeBytes = ReadBounded(fullEnvelopePath, 2 * 1024 * 1024);
            try
            {
                if (!testRoot || HarnessUsesProductionTrust(testRoot))
                    return previousAuthority is null
                        ? ReleaseUpdateManager.VerifyEnvelope(envelopeBytes)
                        : ReleaseUpdateManager.VerifyEnvelopeForInstaller(envelopeBytes, previousAuthority);
#if BIFROST_TEST_HARNESS
                var testKeyPath = Environment.GetEnvironmentVariable("BIFROST_TEST_RELEASE_PUBLIC_KEY_FILE");
                if (string.IsNullOrWhiteSpace(testKeyPath) || !File.Exists(testKeyPath)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
                var fixtureRoot = File.ReadAllText(testKeyPath);
                return previousAuthority is null
                    ? ReleaseUpdateManager.VerifyEnvelopeForInstallerTestInitial(envelopeBytes, fixtureRoot)
                    : ReleaseUpdateManager.VerifyEnvelopeForInstallerTest(envelopeBytes, fixtureRoot, previousAuthority);
#else
                throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
            }
            finally { CryptographicOperations.ZeroMemory(envelopeBytes); }
        }
        // Compact manifest/signature fixtures are deliberately not accepted
        // for an existing installation.  The old test-only path remains
        // available only for an explicitly opted-in first-install fixture.
        if (previousAuthority is not null) throw new InvalidDataException("BF-SETUP-ENVELOPE");
        return ReadSignedEnvelope(packageRoot, testRoot);
    }

    private static VerifiedEnvelope VerifyEnvelopeText(string manifestText, string signatureText, bool testRoot = false)
    {
        // A manifest/signature pair is not an update authority.  All install
        // and apply paths require the complete signed envelope (delegation,
        // root signature, key state and plan) and therefore reject this
        // legacy representation.  The only compatibility seam is an
        // explicitly opted-in TEST-ONLY fixture flag; it is not reachable in
        // a production build or by an ordinary --test-root invocation.
#if BIFROST_TEST_HARNESS
        if (!testRoot || !string.Equals(Environment.GetEnvironmentVariable("BIFROST_TEST_LEGACY_FIXTURE"), "1", StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-ENVELOPE");
        if (manifestText.Length == 0 || manifestText.Length > 1 * 1024 * 1024 || signatureText.Length != 86) throw new InvalidDataException("BF-SETUP-ENVELOPE");
        var envelopeBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { manifest_text = manifestText, signature = signatureText }));
        try
        {
            var testKeyPath = Environment.GetEnvironmentVariable("BIFROST_TEST_RELEASE_PUBLIC_KEY_FILE");
            if (string.IsNullOrWhiteSpace(testKeyPath) || !File.Exists(testKeyPath)) throw new InvalidDataException("BF-SETUP-TEST-ROOT");
            return ReleaseUpdateManager.VerifyEnvelopeForHarness(envelopeBytes, File.ReadAllText(testKeyPath));
        }
        finally { CryptographicOperations.ZeroMemory(envelopeBytes); }
#else
        throw new InvalidDataException("BF-SETUP-TEST-HARNESS-DISABLED");
#endif
    }

    private static string ReadEmbeddedReleaseAuthority(string resourceName)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)
            ?? throw new InvalidDataException("BF-SETUP-LEGACY-AUTHORITY");
        if (stream.Length <= 0 || stream.Length > 64 * 1024) throw new InvalidDataException("BF-SETUP-LEGACY-AUTHORITY");
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false, leaveOpen: false);
        var value = reader.ReadToEnd();
        if (value.Length == 0 || value[0] == '\uFEFF') throw new InvalidDataException("BF-SETUP-LEGACY-AUTHORITY");
        return value;
    }

    private static List<VerifiedFile> VerifyPayload(
        string root,
        VerifiedEnvelope envelope,
        bool stageIsRoot = false,
        bool testRoot = false,
        bool admitInstalledSupportingArtifacts = false)
    {
        var allArtifacts = (envelope.Plan?.Artifacts ?? envelope.Artifacts).ToList();
        var windowsArtifacts = allArtifacts.Where(a => a.Platform == "windows" && a.Arch == "x64" && (a.Kind is "exe" or "service-exe" or "installer" or "core" or "core-manifest" or "metadata")).ToList();
        // Supporting source/notice artifacts are platform-wide and are signed
        // with arch=any in the release contract; they are still constrained to
        // the Windows supporting set and never count as executable payload.
        // Source and notice artifacts are release-compliance attachments. They
        // are mandatory in an initial install package, but the online updater
        // intentionally stages only the exact installable Windows profile.
        // Requiring SOURCE-BUNDLE.tar/LICENSES.txt in an update
        // staging directory makes every production pending update impossible.
        // Online update staging deliberately contains only the installable
        // Windows profile, while an offline/initial installation also copies
        // the signed source + notice compliance attachments into the immutable
        // generation.  A same-sequence health check operates on that installed
        // generation, not on an online staging directory.  Admit those two
        // attachments only when the caller explicitly identifies an installed
        // generation, and only when they are actually present; they still pass
        // the same signed size/hash verification below and therefore become
        // part of EnsureExactStageEntries' exact allowlist. Unknown extras
        // remain fail-closed.
        var supportingArtifacts = stageIsRoot
            ? admitInstalledSupportingArtifacts
                ? allArtifacts.Where(a => a.Platform == "windows" && (a.Arch is "x64" or "any") && (a.Kind is "source" or "notice") &&
                    File.Exists(ResolveContained(root, SafeRelative(a.InstallPath ?? a.Path)))).ToList()
                : new List<Artifact>()
            : allArtifacts.Where(a => a.Platform == "windows" && (a.Arch is "x64" or "any") && (a.Kind is "source" or "notice") && (!testRoot || File.Exists(ResolveContained(root, SafeRelative(a.Path))))).ToList();
        var unexpectedWindowsArtifacts = allArtifacts.Where(a => a.Platform == "windows" && a.Arch == "x64" && a.Kind is not ("exe" or "service-exe" or "installer" or "core" or "core-manifest" or "metadata" or "source" or "notice")).ToList();
        if (!testRoot && unexpectedWindowsArtifacts.Count != 0) throw new InvalidDataException("BF-SETUP-WINDOWS-SET");
        // Supporting source/notice artifacts are part of the same signed
        // immutable plan and must be staged/copied with the payload. They are
        // not counted toward the exact executable/core/metadata profile.
        var selected = windowsArtifacts.Concat(supportingArtifacts).ToList();
        // The executable/core allowlist is intentionally independent from
        // the signed source/notice supporting artifacts.  Counting the
        // latter in this set made every real package with GPL materials look
        // like it had an extra Windows payload.
        var ids = windowsArtifacts.Select(a => a.Id).Where(id => !string.IsNullOrWhiteSpace(id)).ToHashSet(StringComparer.Ordinal);
        var productionSemantics = !testRoot || HarnessUsesProductionTrust(testRoot);
        if (productionSemantics)
        {
            if (windowsArtifacts.Count != ids.Count || !ReleaseArtifactPolicy.IsWindowsX64Stable(ids)) throw new InvalidDataException("BF-SETUP-WINDOWS-SET");
            if (!stageIsRoot)
            {
                if (supportingArtifacts.Count != 2 || supportingArtifacts.Count(a => a.Kind == "source") != 1 || supportingArtifacts.Count(a => a.Kind == "notice") != 1) throw new InvalidDataException("BF-SETUP-SUPPORTING");
                var sourceId = supportingArtifacts.Single(a => a.Kind == "source").Id;
                var noticeId = supportingArtifacts.Single(a => a.Kind == "notice").Id;
                if (string.IsNullOrWhiteSpace(sourceId) || string.IsNullOrWhiteSpace(noticeId) || sourceId == noticeId) throw new InvalidDataException("BF-SETUP-SUPPORTING");
                // References are carried by the immutable plan.  Require every
                // payload artifact which declares a source/notice relationship
                // to point at the exact signed supporting artifact, rather than
                // a path or a caller-selected sidecar.
                foreach (var artifact in windowsArtifacts)
                {
                    if (!string.Equals(artifact.SourceBundle, sourceId, StringComparison.Ordinal) || !string.Equals(artifact.Notice, noticeId, StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-SUPPORTING");
                }
            }
        }
        else
        {
            // Test harnesses exercise the same exact Mihomo payload profile;
            // there is no legacy payload-shape escape hatch.
            if (windowsArtifacts.Count != ids.Count || !ReleaseArtifactPolicy.IsWindowsX64Stable(ids)) throw new InvalidDataException("BF-SETUP-WINDOWS-SET");
        }
        if (!stageIsRoot) foreach (var artifact in supportingArtifacts) VerifyArtifactHandle(root, artifact, stageIsRoot);
        var kinds = selected.GroupBy(a => a.Kind, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);
        var commonKindsValid = kinds.GetValueOrDefault("exe") == 1 && kinds.GetValueOrDefault("service-exe") == 1 && kinds.GetValueOrDefault("installer") == 1 && kinds.GetValueOrDefault("core-manifest") == 1;
        var modernKindsValid = commonKindsValid && kinds.GetValueOrDefault("core") == 3 && kinds.GetValueOrDefault("metadata") == 1;
        if (!modernKindsValid) throw new InvalidDataException("BF-SETUP-WINDOWS-SET");
        var files = new List<VerifiedFile>();
        var sourcePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var installPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var artifact in selected)
        {
            var relative = SafeRelative(stageIsRoot ? (artifact.InstallPath ?? artifact.Path) : artifact.Path);
            var install = SafeRelative(artifact.InstallPath ?? artifact.Path);
            if (!sourcePaths.Add(CanonicalPathKey(relative)) || !installPaths.Add(CanonicalPathKey(install))) throw new InvalidDataException("BF-SETUP-PATH-COLLISION");
            var source = ResolveContained(root, relative);
            EnsureNoReparseChain(source, allowMissingLeaf: false);
            if (!File.Exists(source)) throw new FileNotFoundException("BF-SETUP-ARTIFACT");
            if (artifact.Bytes is < 1 or > MaxArtifactBytes) throw new InvalidDataException("BF-SETUP-ARTIFACT-SIZE");
            var stream = OpenVerifiedHandle(source);
            try
            {
                if (stream.Length != artifact.Bytes) throw new InvalidDataException("BF-SETUP-ARTIFACT-SIZE");
                var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
                if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(digest), Encoding.ASCII.GetBytes(artifact.Sha256))) throw new CryptographicException("BF-SETUP-ARTIFACT-HASH");
                stream.Position = 0;
                files.Add(new VerifiedFile(artifact, source, stream));
            }
            catch { stream.Dispose(); throw; }
        }
        if (files.Sum(f => f.Metadata.Bytes) > MaxTotalBytes) throw new InvalidDataException("BF-SETUP-TOTAL-SIZE");
        if (stageIsRoot) EnsureExactStageEntries(root, files);
        return files;
    }

    private static string ResolveServiceBinary(string payloadRoot, VerifiedEnvelope envelope, bool requireExists = true)
    {
        var plan = envelope.Plan ?? throw new InvalidDataException("BF-SETUP-PLAN");
        var service = plan.Artifacts.Where(a => a.Platform == "windows" && a.Arch == "x64" && a.Kind == "service-exe").ToArray();
        if (service.Length != 1) throw new InvalidDataException("BF-SETUP-WINDOWS-SET");
        var path = ResolveContained(payloadRoot, SafeRelative(service[0].InstallPath ?? service[0].Path));
        if (requireExists)
        {
            EnsureNoReparseChain(path, allowMissingLeaf: false);
            if (!File.Exists(path)) throw new InvalidDataException("BF-SETUP-SERVICE");
        }
        return path;
    }

    private static void EnsureExactStageEntries(string root, IReadOnlyList<VerifiedFile> files)
    {
        EnsureNoReparseChain(root, allowMissingLeaf: false);
        var expected = files.Select(file => CanonicalPathKey((file.Metadata.InstallPath ?? file.Metadata.Path).Replace('\\', '/'))).ToHashSet(StringComparer.Ordinal);
        foreach (var entry in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
        {
            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("BF-SETUP-REPARSE");
            var relative = Path.GetRelativePath(root, entry).Replace('\\', '/');
            if ((attributes & FileAttributes.Directory) != 0)
            {
                if (!expected.Any(path => path.StartsWith(CanonicalPathKey(relative) + "/", StringComparison.Ordinal))) throw new InvalidDataException("BF-SETUP-STAGE-EXTRA");
            }
            else if (!expected.Contains(CanonicalPathKey(relative))) throw new InvalidDataException("BF-SETUP-STAGE-EXTRA");
        }
    }

    private static void VerifyArtifactHandle(string root, Artifact artifact, bool stageIsRoot)
    {
        var relative = SafeRelative(stageIsRoot ? (artifact.InstallPath ?? artifact.Path) : artifact.Path);
        var source = ResolveContained(root, relative);
        EnsureNoReparseChain(source, allowMissingLeaf: false);
        if (artifact.Bytes is < 1 or > MaxArtifactBytes) throw new InvalidDataException("BF-SETUP-ARTIFACT-SIZE");
        using var stream = OpenVerifiedHandle(source);
        if (stream.Length != artifact.Bytes) throw new InvalidDataException("BF-SETUP-ARTIFACT-SIZE");
        var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (!string.Equals(digest, artifact.Sha256, StringComparison.Ordinal)) throw new CryptographicException("BF-SETUP-ARTIFACT-HASH");
    }

    private static void EnsureExactPackageEntries(string packageRoot, VerifiedEnvelope envelope)
    {
        var plan = envelope.Plan ?? throw new InvalidDataException("BF-SETUP-PLAN");
        var expected = plan.Artifacts
            .Where(artifact => artifact.Platform == "windows" && (artifact.Arch is "x64" or "any") && (artifact.Kind is "exe" or "service-exe" or "installer" or "core" or "core-manifest" or "metadata" or "source" or "notice"))
            .Select(artifact => CanonicalPathKey(SafeRelative(artifact.Path)))
            .ToHashSet(StringComparer.Ordinal);
        foreach (var controlFile in new[] { "RELEASE-ENVELOPE.json", "RELEASE-MANIFEST.json", "RELEASE-MANIFEST.sig" }) expected.Add(CanonicalPathKey(controlFile));
        // A committed release generation carries three non-executable evidence
        // sidecars in addition to the signed artifact graph.  They are not
        // arbitrary extras: each one is admitted only when its exact SHA-256 is
        // already bound by the signed manifest.  This lets the installer verify
        // the authoritative generation directly while keeping unknown files
        // fail-closed.  A redistributable package may omit these optional
        // evidence sidecars without weakening installation verification.
        using (var manifestDocument = JsonDocument.Parse(envelope.ManifestText))
        {
            var manifest = manifestDocument.RootElement;
            AddOptionalBoundSidecar(packageRoot, expected, manifest, "SBOM.json", "sbom_sha256", 32L * 1024 * 1024);
            AddOptionalBoundSidecar(packageRoot, expected, manifest, "source-bundle-manifest.json", "source_manifest_sha256", 8L * 1024 * 1024);
            AddOptionalBoundSidecar(packageRoot, expected, manifest, "build-inputs/dependency-license-manifest.json", "dependency_license_manifest_sha256", 8L * 1024 * 1024);
        }
        AddOptionalOfflineInstallerAttestation(packageRoot, expected, envelope);
        AddOptionalSignedInstallerAlias(packageRoot, expected, plan.Artifacts);
        if (!File.Exists(Path.Combine(packageRoot, "RELEASE-ENVELOPE.json"))) throw new InvalidDataException("BF-SETUP-ENVELOPE");
        foreach (var entry in Directory.EnumerateFileSystemEntries(packageRoot, "*", SearchOption.AllDirectories))
        {
            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("BF-SETUP-REPARSE");
            if ((attributes & FileAttributes.Directory) != 0) continue;
            var relative = Path.GetRelativePath(packageRoot, entry).Replace('\\', '/');
            if (!expected.Contains(CanonicalPathKey(relative))) throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        }
        var actual = Directory.EnumerateFiles(packageRoot, "*", SearchOption.AllDirectories).Select(path => CanonicalPathKey(Path.GetRelativePath(packageRoot, path).Replace('\\', '/'))).ToHashSet(StringComparer.Ordinal);
        if (!expected.Where(path => !path.StartsWith("RELEASE-", StringComparison.Ordinal)).All(actual.Contains)) throw new InvalidDataException("BF-SETUP-PACKAGE-MISSING");
    }

    private static void AddOptionalSignedInstallerAlias(string packageRoot, HashSet<string> expected, IReadOnlyList<Artifact> artifacts)
    {
        const string alias = "BifrostSetup.exe";
        var aliasKey = CanonicalPathKey(alias);
        if (expected.Contains(aliasKey)) return;
        var full = ResolveContained(packageRoot, alias);
        if (!File.Exists(full)) return;
        var installers = artifacts.Where(artifact => artifact.Platform == "windows" && artifact.Arch is "x64" or "any" && artifact.Kind == "installer" &&
            string.Equals(SafeRelative(artifact.InstallPath ?? artifact.Path), alias, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (installers.Length != 1) throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        var installer = installers[0];
        EnsureNoReparseChain(full, allowMissingLeaf: false);
        using var stream = OpenVerifiedHandle(full);
        if (stream.Length != installer.Bytes) throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(digest), Encoding.ASCII.GetBytes(installer.Sha256)))
            throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        expected.Add(aliasKey);
    }

    private static void AddOptionalOfflineInstallerAttestation(string packageRoot, HashSet<string> expected, VerifiedEnvelope envelope)
    {
        const string relative = "OFFLINE-INSTALLER-ATTESTATION.json";
        var full = ResolveContained(packageRoot, relative);
        if (!File.Exists(full)) return;
        EnsureNoReparseChain(full, allowMissingLeaf: false);
        var info = new FileInfo(full);
        if (!info.Exists || info.Length is < 1 or > 64 * 1024) throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");

        using var attestationStream = OpenVerifiedHandle(full);
        using var attestationDocument = JsonDocument.Parse(attestationStream, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = 8 });
        var wrapper = attestationDocument.RootElement;
        var wrapperFields = new[] { "format", "attestation_text", "signature" };
        if (wrapper.ValueKind != JsonValueKind.Object || wrapper.EnumerateObject().Count() != wrapperFields.Length || wrapperFields.Any(name => !wrapper.TryGetProperty(name, out _)) ||
            wrapper.GetProperty("format").GetString() != "BIFROST-OFFLINE-INSTALLER-ATTESTATION-1")
            throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        var attestationText = wrapper.GetProperty("attestation_text").GetString();
        var signatureText = wrapper.GetProperty("signature").GetString();
        if (string.IsNullOrWhiteSpace(attestationText) || string.IsNullOrWhiteSpace(signatureText)) throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");

        var envelopePath = ResolveContained(packageRoot, "RELEASE-ENVELOPE.json");
        EnsureNoReparseChain(envelopePath, allowMissingLeaf: false);
        using var envelopeStream = OpenVerifiedHandle(envelopePath);
        using var envelopeDocument = JsonDocument.Parse(envelopeStream, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = 32 });
        var diskEnvelope = envelopeDocument.RootElement;
        if (diskEnvelope.GetProperty("manifest_text").GetString() != envelope.ManifestText || diskEnvelope.GetProperty("signature").GetString() != envelope.SignatureText)
            throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        var delegation = diskEnvelope.GetProperty("delegation");
        var keyId = delegation.GetProperty("key_id").GetString();
        var publicKeyPem = delegation.GetProperty("public_key_pem").GetString();
        var plan = envelope.Plan ?? throw new InvalidDataException("BF-SETUP-PLAN");
        if (string.IsNullOrWhiteSpace(publicKeyPem) || keyId != plan.SigningKeyId) throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        var rawKey = ExtractDetachedPublicKey(publicKeyPem, plan.SigningKeyFingerprint);
        var signature = DecodeDetachedSignature(signatureText);
        var signedBytes = new UTF8Encoding(false, true).GetBytes(attestationText);
        try
        {
            if (signature.Length != 64 || !Ed25519.Verify(signature, signedBytes, rawKey)) throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(rawKey);
        }

        using var statementDocument = JsonDocument.Parse(attestationText, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = 8 });
        var statement = statementDocument.RootElement;
        var statementFields = new[] { "format", "release_sequence", "version", "filename", "bytes", "sha256", "release_manifest_sha256", "release_signature_sha256", "signing_key_id" };
        if (statement.ValueKind != JsonValueKind.Object || statement.EnumerateObject().Count() != statementFields.Length || statementFields.Any(name => !statement.TryGetProperty(name, out _)) ||
            statement.GetProperty("format").GetString() != "BIFROST-OFFLINE-INSTALLER-ATTESTATION-1" ||
            !statement.GetProperty("release_sequence").TryGetInt64(out var sequence) || sequence != envelope.Sequence ||
            statement.GetProperty("signing_key_id").GetString() != plan.SigningKeyId ||
            statement.GetProperty("release_manifest_sha256").GetString() != plan.ManifestDigest ||
            statement.GetProperty("release_signature_sha256").GetString() != HashFile(ResolveContained(packageRoot, "RELEASE-MANIFEST.sig")))
            throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        expected.Add(CanonicalPathKey(relative));
    }

    private static byte[] ExtractDetachedPublicKey(string pem, string? expectedFingerprint)
    {
        var der = PemEncoding.TryFind(pem.AsSpan(), out var fields)
            ? Convert.FromBase64String(pem[fields.Base64Data].ToString())
            : throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        try
        {
            var fingerprint = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();
            var prefix = Convert.FromHexString("302a300506032b6570032100");
            if (fingerprint != expectedFingerprint || der.Length != prefix.Length + 32 || !der.AsSpan(0, prefix.Length).SequenceEqual(prefix))
                throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
            return der.AsSpan(prefix.Length, 32).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(der); }
    }

    private static byte[] DecodeDetachedSignature(string value)
    {
        if (value.Any(ch => ch is not ('-' or '_' or >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9')))
            throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
        var bytes = Convert.FromBase64String(normalized);
        if (Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != value) throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        return bytes;
    }

    private static string HashFile(string path)
    {
        EnsureNoReparseChain(path, allowMissingLeaf: false);
        using var stream = OpenVerifiedHandle(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static void AddOptionalBoundSidecar(string packageRoot, HashSet<string> expected, JsonElement manifest, string relativePath, string digestProperty, long maxBytes)
    {
        var normalized = SafeRelative(relativePath);
        var full = ResolveContained(packageRoot, normalized);
        if (!File.Exists(full)) return;
        if (!manifest.TryGetProperty(digestProperty, out var digestElement) || digestElement.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        var expectedDigest = digestElement.GetString();
        if (string.IsNullOrWhiteSpace(expectedDigest) || expectedDigest.Length != 64 || expectedDigest.Any(ch => !Uri.IsHexDigit(ch)))
            throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        EnsureNoReparseChain(full, allowMissingLeaf: false);
        var info = new FileInfo(full);
        if (!info.Exists || info.Length < 1 || info.Length > maxBytes) throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        using var stream = OpenVerifiedHandle(full);
        var digest = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(digest), Encoding.ASCII.GetBytes(expectedDigest.ToLowerInvariant())))
            throw new InvalidDataException("BF-SETUP-PACKAGE-EXTRA");
        expected.Add(CanonicalPathKey(normalized));
    }

    private static List<VerifiedFile> CopyVerified(IEnumerable<VerifiedFile> files, string destinationRoot, string? fakeFailureMode = null)
    {
        EnsureNoReparseChain(destinationRoot, allowMissingLeaf: true);
        Directory.CreateDirectory(destinationRoot);
        var copied = new List<VerifiedFile>();
        try
        {
            foreach (var file in files)
            {
                var destination = ResolveContained(destinationRoot, file.Metadata.InstallPath ?? file.Metadata.Path);
                EnsureNoReparseChain(destination, allowMissingLeaf: true);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                using var input = file.Handle ?? OpenVerifiedHandle(file.Source);
                input.Position = 0;
                using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.WriteThrough | FileOptions.SequentialScan);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[1024 * 1024];
                long count = 0;
                try
                {
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        count += read;
                        if (count > MaxArtifactBytes) throw new InvalidDataException("BF-SETUP-ARTIFACT-SIZE");
                        output.Write(buffer, 0, read);
                        hash.AppendData(buffer, 0, read);
                    }
                    output.Flush(true);
                    if (FaultEnabled(fakeFailureMode, "flush") || FaultEnabled(fakeFailureMode, "copy")) throw new IOException("BF-SETUP-FAULT");
                    var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
                    if (count != file.Metadata.Bytes || !string.Equals(digest, file.Metadata.Sha256, StringComparison.Ordinal)) throw new CryptographicException("BF-SETUP-ARTIFACT-HASH");
                    copied.Add(file with { Source = destination, Handle = null });
                }
                finally { CryptographicOperations.ZeroMemory(buffer); }
            }
            if (copied.Sum(f => f.Metadata.Bytes) > MaxTotalBytes) throw new InvalidDataException("BF-SETUP-TOTAL-SIZE");
            return copied;
        }
        finally { DisposeVerified(files); }
    }

    private static FileStream OpenVerifiedHandle(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-SETUP-PLATFORM");
        var handle = CreateFileW(path, 0x80000000u, 0x00000001u, IntPtr.Zero, 3u, 0x00200000u, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new FileNotFoundException("BF-SETUP-ARTIFACT"); }
        var stream = new FileStream(handle, FileAccess.Read, 1024 * 1024, isAsync: false);
        try
        {
            if (!GetFileInformationByHandle(handle, out var information) || information.NumberOfLinks != 1 || (information.FileAttributes & (uint)(FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                throw new InvalidDataException(information.NumberOfLinks != 1 ? "BF-SETUP-HARDLINK" : "BF-SETUP-REPARSE");
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    private static string MeasureRootIdentity(string root)
    {
        var full = Path.GetFullPath(root);
        if (!Directory.Exists(full)) throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        if (!OperatingSystem.IsWindows()) throw new InvalidDataException("BF-SETUP-PLATFORM");
        // FILE_FLAG_OPEN_REPARSE_POINT + BACKUP_SEMANTICS opens the directory
        // itself, never a link target.  The tuple is the Windows volume/file
        // identity; the digest is only its fixed-width serialized form.
        const uint openExisting = 3u;
        const uint fileFlagBackupSemantics = 0x02000000u;
        const uint fileFlagOpenReparsePoint = 0x00200000u;
        using var handle = CreateFileW(full, 0u, 0x00000007u, IntPtr.Zero, openExisting,
            fileFlagBackupSemantics | fileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid || !GetFileInformationByHandle(handle, out var information) ||
            (information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        var material = $"volume:{information.VolumeSerialNumber:x8};file:{information.FileIndexHigh:x8}{information.FileIndexLow:x8}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(string existingFileName, string? newFileName, uint flags);

    private const uint MoveFileDelayUntilReboot = 0x00000004;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle fileHandle, out ByHandleFileInformation information);

    private static void DisposeVerified(IEnumerable<VerifiedFile> files)
    {
        foreach (var file in files) file.Handle?.Dispose();
    }

    private static string ComputeVerifiedTreeIdentity(IEnumerable<VerifiedFile> files)
    {
        var lines = files.OrderBy(file => file.Metadata.Id, StringComparer.Ordinal)
            .Select(file => $"{file.Metadata.Id}\n{file.Metadata.InstallPath ?? file.Metadata.Path}\n{file.Metadata.Bytes}\n{file.Metadata.Sha256}");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lines)))).ToLowerInvariant();
    }

    private static void PromoteVerified(IReadOnlyList<VerifiedFile> files, string sourceRoot, string destinationRoot, string backupRoot, List<(string destination, string? backup)> applied, string? fakeFailureMode = null)
    {
        EnsureNoReparseChain(destinationRoot, allowMissingLeaf: true);
        Directory.CreateDirectory(backupRoot);
        foreach (var file in files)
        {
            var destination = ResolveContained(destinationRoot, file.Metadata.InstallPath ?? file.Metadata.Path);
            EnsureNoReparseChain(destination, allowMissingLeaf: true);
            if (Directory.Exists(destination)) throw new InvalidDataException("BF-SETUP-DESTINATION-TYPE");
            if (string.Equals(Path.GetFullPath(destination), Path.GetFullPath(Environment.ProcessPath ?? string.Empty), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("BF-SETUP-SELF-UPDATE-DEFERRED");
            var source = ResolveContained(sourceRoot, file.Metadata.InstallPath ?? file.Metadata.Path);
            EnsureNoReparseChain(source, allowMissingLeaf: false);
            var backupPath = File.Exists(destination) ? ResolveContained(backupRoot, file.Metadata.InstallPath ?? file.Metadata.Path) : null;
            if (backupPath is not null)
            {
                EnsureNoReparseChain(backupPath, allowMissingLeaf: true);
                Directory.CreateDirectory(Path.GetDirectoryName(backupPath)!);
                File.Move(destination, backupPath);
            }
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            applied.Add((destination, backupPath));
            if (FaultEnabled(fakeFailureMode, "rename") && applied.Count == 1) throw new IOException("BF-SETUP-FAULT");
            File.Move(source, destination);
            if (FaultEnabled(fakeFailureMode, "locked-file") && applied.Count == 1)
                throw new IOException("BF-SETUP-FAULT");
        }
    }

    private static bool RollbackApplied(IReadOnlyList<(string destination, string? backup)> applied, string backupRoot, string? fakeFailureMode = null)
    {
        var success = true;
        var injected = false;
        for (var index = applied.Count - 1; index >= 0; index--)
        {
            var item = applied[index];
            try
            {
                if (File.Exists(item.destination)) File.Delete(item.destination);
                // Test-only injection is inside the real restore action: the
                // destination has already been handled, then the backup move
                // fails.  The loop still continues with every other item.
                if (!injected && FaultEnabled(fakeFailureMode, "restore-files"))
                {
                    injected = true;
                    throw new IOException("BF-SETUP-FAULT");
                }
                if (item.backup is not null && File.Exists(item.backup))
                {
                    EnsureNoReparseChain(item.destination, allowMissingLeaf: true);
                    Directory.CreateDirectory(Path.GetDirectoryName(item.destination)!);
                    File.Move(item.backup, item.destination, true);
                }
            }
            catch { success = false; }
        }
        try { if (Directory.Exists(backupRoot)) Directory.Delete(backupRoot, true); } catch { success = false; }
        return success;
    }

    private static JsonElement ReadStrictObject(string path, int limit)
    {
        EnsureNoReparseChain(path, allowMissingLeaf: false);
        var bytes = ReadBounded(path, limit);
        try
        {
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = 16 });
            var seen = new Stack<HashSet<string>>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.StartObject) seen.Push(new HashSet<string>(StringComparer.Ordinal));
                else if (reader.TokenType == JsonTokenType.PropertyName && (seen.Count == 0 || !seen.Peek().Add(reader.GetString() ?? string.Empty))) throw new InvalidDataException("BF-SETUP-PENDING-JSON");
                else if (reader.TokenType == JsonTokenType.EndObject && seen.Count > 0) seen.Pop();
            }
            if (seen.Count != 0 || reader.BytesConsumed != bytes.Length) throw new InvalidDataException("BF-SETUP-PENDING-JSON");
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false, MaxDepth = 16 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("BF-SETUP-PENDING-JSON");
            return document.RootElement.Clone();
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static long ReadStateSequence(string path, bool allowLegacy = false)
    {
        EnsureNoReparseChain(path, allowMissingLeaf: true);
        if (!File.Exists(path)) return 0;
        try
        {
            // Reuse the strict bounded object reader so durable rollback state
            // rejects duplicate keys, comments, trailing data and malformed
            // UTF-8 just like the pending marker.
            var root = ReadStrictObject(path, 16 * 1024);
            var properties = root.EnumerateObject().ToArray();
            if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            if (properties.Length > 2 && root.TryGetProperty("envelope_digest", out _))
            {
                var state = JsonSerializer.Deserialize<ReleaseStateAuthority.State>(root.GetRawText()) ?? throw new InvalidDataException();
                ReleaseStateAuthority.Validate(state);
                return state.Sequence;
            }
            if (!allowLegacy || properties.Length != 2 || properties.Any(p => p.Name is not ("last_sequence" or "updated_at")) || !root.TryGetProperty("last_sequence", out var sequence) || !sequence.TryGetInt64(out var result) || result < 1 || !root.TryGetProperty("updated_at", out var at) || at.ValueKind != JsonValueKind.String) throw new InvalidDataException();
            var timestamp = at.GetString();
            if (timestamp is null || !DateTimeOffset.TryParseExact(timestamp, "O", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var parsedAt) || parsedAt.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture) != timestamp) throw new InvalidDataException();
            return result;
        }
        catch (FileNotFoundException)
        {
            // Only an actually absent state file is the never-installed case;
            // all parse/I/O races after the precheck fail closed.
            if (File.Exists(path)) throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
            return 0;
        }
        catch (DirectoryNotFoundException)
        {
            if (Directory.Exists(Path.GetDirectoryName(path))) throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
            return 0;
        }
        catch { throw new InvalidDataException("BF-SETUP-STATE-CORRUPT"); }
    }

    private static ReleaseStateAuthority.State ReadReleaseAuthorityStateForInstaller(string path)
    {
        var root = ReadStrictObject(path, 32 * 1024);
        try
        {
            var state = JsonSerializer.Deserialize<ReleaseStateAuthority.State>(root.GetRawText()) ?? throw new InvalidDataException();
            ReleaseStateAuthority.Validate(state);
            return state;
        }
        catch { throw new InvalidDataException("BF-SETUP-STATE-CORRUPT"); }
    }

    private static string? ReadStateEnvelopeDigest(string path, bool allowLegacy)
    {
        if (!File.Exists(path)) return null;
        var root = ReadStrictObject(path, 16 * 1024);
        if (root.TryGetProperty("envelope_digest", out var digest) && digest.ValueKind == JsonValueKind.String && digest.GetString() is { Length: 64 } value) return value;
        if (allowLegacy) return null;
        throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
    }

    private static byte[]? ReadOptionalState(string path)
    {
        try
        {
            return ReadBounded(path, 16 * 1024);
        }
        catch (FileNotFoundException)
        {
            // A genuinely absent state is the only initial-install case. If
            // the path reappeared during the failed open, treat it as a
            // corrupted/contended state rather than silently resetting it.
            if (File.Exists(path)) throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            if (Directory.Exists(Path.GetDirectoryName(path))) throw new InvalidDataException("BF-SETUP-STATE-CORRUPT");
            return null;
        }
    }

    private static void RestoreState(string path, byte[]? previousState, string? fakeFailureMode = null)
    {
        if (previousState is null)
        {
            EnsureNoReparseChain(path, allowMissingLeaf: true);
            if (FaultEnabled(fakeFailureMode, "restore-state")) throw new IOException("BF-SETUP-FAULT");
            if (File.Exists(path)) File.Delete(path);
            return;
        }
        var text = new UTF8Encoding(false, true).GetString(previousState);
        // The fault is raised by the production state-restore action before
        // its atomic write, not by a post-success test hook.
        if (FaultEnabled(fakeFailureMode, "restore-state")) throw new IOException("BF-SETUP-FAULT");
        WriteAtomic(path, text);
    }

    private static void DeleteRequired(string path)
    {
        EnsureNoReparseChain(path, allowMissingLeaf: false);
        File.Delete(path);
        if (File.Exists(path)) throw new IOException("BF-SETUP-PENDING-CLEANUP");
    }

    private static string FindPackageRoot(string[] args)
    {
        var explicitRoot = Value(args, "--package-root");
        if (!string.IsNullOrWhiteSpace(explicitRoot)) return Path.GetFullPath(explicitRoot);
        return TryFindPackageRootFromBaseDirectory() ?? throw new FileNotFoundException("BF-SETUP-MANIFEST");
    }

    private static string? TryFindPackageRootFromBaseDirectory()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 6 && current is not null; i++, current = current.Parent)
        {
            if (File.Exists(Path.Combine(current.FullName, "RELEASE-MANIFEST.json"))) return current.FullName;
            if (File.Exists(Path.Combine(current.FullName, "releases", "RELEASE-MANIFEST.json"))) return Path.Combine(current.FullName, "releases");
        }
        return null;
    }

    private static bool IsTemporaryRoot(string path)
    {
        var candidate = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return candidate.StartsWith(temp + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
               !candidate.Equals(temp, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasInstalledPayload(string root)
    {
        var pointerPath = Path.Combine(ResolveStateRoot(root), "current.json");
        if (File.Exists(pointerPath))
        {
            try
            {
                var pointer = ReadStrictObject(pointerPath, 64 * 1024);
                if (pointer.TryGetProperty("current_payload_root", out var payload) && payload.ValueKind == JsonValueKind.String)
                {
                    var payloadRoot = Path.GetFullPath(payload.GetString()!);
                    if (!IsContained(root, payloadRoot) || string.Equals(payloadRoot, root, StringComparison.OrdinalIgnoreCase)) return false;
                    EnsureNoReparseChain(payloadRoot, allowMissingLeaf: false);
                    return Directory.EnumerateFiles(payloadRoot, "*", SearchOption.AllDirectories).Any();
                }
            }
            catch { return false; }
        }
        var known = new[]
        {
            Path.Combine(root, "Bifrost.exe"),
            Path.Combine(root, "BifrostClientService.exe"),
            Path.Combine(root, "BifrostSetup.exe"),
            Path.Combine(root, "cores", "mihomo.exe"),
            Path.Combine(root, "cores", "xray.exe"),
            Path.Combine(root, "cores", "sing-box.exe"),
            Path.Combine(root, "cores", "CORE-MANIFEST.json")
        };
        return known.Any(File.Exists);
    }

    private static bool UseGenerationLayout(VerifiedEnvelope envelope, bool testRoot, bool fullEnvelope = false)
    {
        // The legacy compact manifest fixture is deliberately never promoted
        // through the production generation switch.  A test process may opt in
        // only by carrying the full signed envelope bytes, exactly as the
        // real update manager does.
        return !testRoot || fullEnvelope;
    }

    private static string? ReadCurrentPayloadRoot(string installRoot, bool testRoot)
    {
        var path = Path.Combine(ResolveStateRoot(installRoot), "current.json");
        if (!File.Exists(path)) return null;
        var pointer = ReadStrictObject(path, 64 * 1024);
        if (!pointer.TryGetProperty("current_payload_root", out var value) || value.ValueKind != JsonValueKind.String) return testRoot ? null : throw new InvalidDataException("BF-SETUP-GENERATION");
        var root = Path.GetFullPath(value.GetString()!);
        if (!IsContained(installRoot, root) || string.Equals(root, installRoot, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-GENERATION");
        EnsureNoReparseChain(root, allowMissingLeaf: false);
        return root;
    }

    private static bool IsInitialInstallTargetEmpty(string root)
    {
        if (!Directory.Exists(root)) return true;
        EnsureNoReparseChain(root, allowMissingLeaf: true);
        foreach (var entry in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.TopDirectoryOnly))
        {
            var name = Path.GetFileName(entry);
            if (string.Equals(name, StateDirectoryName, StringComparison.OrdinalIgnoreCase) && Directory.Exists(entry))
            {
                EnsureNoReparseChain(entry, allowMissingLeaf: false);
                // AcquireInstallLock deliberately creates the state directory
                // and its lock before the first state read.  The lock is an
                // installer-owned synchronization primitive, not installed
                // payload.  Any other pre-existing state entry still blocks a
                // first install rather than being silently adopted.
                var stateEntries = Directory.EnumerateFileSystemEntries(entry, "*", SearchOption.TopDirectoryOnly).ToArray();
                if (stateEntries.Any(value => !string.Equals(Path.GetFileName(value), "install.lock", StringComparison.OrdinalIgnoreCase) && !string.Equals(Path.GetFileName(value), "uninstalled.json", StringComparison.OrdinalIgnoreCase))) return false;
                continue;
            }
            if ((name is ".bifrost-generations" or ".bifrost-protected") && Directory.Exists(entry))
            {
                EnsureNoReparseChain(entry, allowMissingLeaf: false);
                if (Directory.EnumerateFileSystemEntries(entry, "*", SearchOption.TopDirectoryOnly).Any()) return false;
                continue;
            }
            if (string.Equals(name, ".bifrost-ipc", StringComparison.OrdinalIgnoreCase) && Directory.Exists(entry))
            {
                EnsureNoReparseChain(entry, allowMissingLeaf: false);
                var bindingEntries = Directory.EnumerateFileSystemEntries(entry, "*", SearchOption.TopDirectoryOnly).Select(Path.GetFileName).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (bindingEntries.Count != 2 || !bindingEntries.SetEquals(new[] { "ipc-binding.bin", "interactive.sid" })) return false;
                continue;
            }
            if ((string.Equals(name, ".bifrost-user-data", StringComparison.OrdinalIgnoreCase) || string.Equals(name, ".bifrost-recovery", StringComparison.OrdinalIgnoreCase)) && Directory.Exists(entry))
            {
                EnsureNoReparseChain(entry, allowMissingLeaf: false);
                continue;
            }
            return false;
        }
        return true;
    }

    private static byte[] ReadBounded(string path, int limit)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        if (stream.Length <= 0 || stream.Length > limit) throw new InvalidDataException("BF-SETUP-SIZE");
        var result = new byte[checked((int)stream.Length)];
        var offset = 0;
        while (offset < result.Length)
        {
            var read = stream.Read(result, offset, result.Length - offset);
            if (read <= 0) throw new EndOfStreamException();
            offset += read;
        }
        if (stream.ReadByte() != -1) throw new InvalidDataException("BF-SETUP-SIZE");
        return result;
    }

    private static string SafeRelative(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 240 || Path.IsPathRooted(value) || value.Contains('\\') || value.Contains('\0') || value.Contains(':') || value.Any(char.IsControl)) throw new InvalidDataException("BF-SETUP-PATH");
        var normalized = value.Replace('\\', '/');
        var parts = normalized.Split('/');
        if (normalized.StartsWith('/') || parts.Any(part => part.Length == 0 || part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.') || IsWindowsDeviceName(part))) throw new InvalidDataException("BF-SETUP-PATH");
        return normalized;
    }

    private static string CanonicalPathKey(string value) => value.Normalize(NormalizationForm.FormC).ToUpperInvariant();
    private static bool IsWindowsDeviceName(string value)
    {
        var stem = value.Split('.')[0].TrimEnd(' ', '.').ToUpperInvariant();
        return stem is "CON" or "PRN" or "AUX" or "NUL" || (stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && stem[3] is >= '1' and <= '9');
    }

    private static string ResolveContained(string root, string relative)
    {
        var safe = SafeRelative(relative);
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var candidate = Path.GetFullPath(Path.Combine(root, safe.Replace('/', Path.DirectorySeparatorChar)));
        if (!candidate.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-CONTAINMENT");
        return candidate;
    }

    private static bool IsContained(string root, string path)
    {
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var candidate = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
        return candidate.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase);
    }

    private static void EnsureNoReparseChain(string path, bool allowMissingLeaf)
    {
        var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
        var current = full;
        var missing = false;
        while (current.Length > 2)
        {
            if (Directory.Exists(current) || File.Exists(current))
            {
                var attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("BF-SETUP-REPARSE");
            }
            else if (!allowMissingLeaf && !missing) throw new FileNotFoundException("BF-SETUP-PATH");
            missing = true;
            var parent = Path.GetDirectoryName(current);
            if (string.IsNullOrEmpty(parent) || string.Equals(parent, current, StringComparison.OrdinalIgnoreCase)) break;
            current = parent;
        }
    }

    private static void WriteAtomic(string path, string content)
    {
        var parent = Path.GetDirectoryName(path) ?? throw new InvalidDataException("BF-SETUP-STATE");
        EnsureNoReparseChain(parent, allowMissingLeaf: true);
        EnsureNoReparseChain(path, allowMissingLeaf: true);
        Directory.CreateDirectory(parent);
        var temporary = path + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        var bytes = new UTF8Encoding(false, true).GetBytes(content);
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.SequentialScan))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            EnsureNoReparseChain(path, allowMissingLeaf: true);
            if (File.Exists(path)) File.Replace(temporary, path, null); else File.Move(temporary, path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            TryDelete(temporary);
        }
    }

    private static void RunSc(params string[] arguments)
    {
        var result = RunScCapture(arguments);
        if (result.exitCode != 0) throw new InvalidOperationException("BF-SETUP-SCM");
    }

    private static (int exitCode, string output) RunScCapture(params string[] arguments)
    {
        if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("BF-SETUP-SCM");
        var systemDirectory = Path.GetFullPath(Environment.SystemDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var sc = Path.Combine(systemDirectory, "sc.exe");
        if (!File.Exists(sc)) throw new InvalidOperationException("BF-SETUP-SCM");
        EnsureNoReparseChain(systemDirectory, allowMissingLeaf: false);
        EnsureNoReparseChain(sc, allowMissingLeaf: false);
        var startInfo = new ProcessStartInfo
        {
            FileName = sc,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var argument in arguments)
        {
            if (string.IsNullOrWhiteSpace(argument) || argument.IndexOf('\0') >= 0) throw new InvalidDataException("BF-SETUP-SCM");
            startInfo.ArgumentList.Add(argument);
        }
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("BF-SETUP-SCM");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var stdoutTask = ReadScStreamAsync(process.StandardOutput, timeout.Token);
        var stderrTask = ReadScStreamAsync(process.StandardError, timeout.Token);
        try
        {
            if (!process.WaitForExit(30_000)) throw new TimeoutException("BF-SETUP-SCM-TIMEOUT");
            Task.WaitAll(stdoutTask, stderrTask);
        }
        catch
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("BF-SETUP-SCM-TIMEOUT");
        }
        // Service output is never returned across the elevation boundary. It
        // is retained only long enough for the lifecycle adapter to inspect a
        // bounded state token.
        var output = (stdoutTask.Result + "\n" + stderrTask.Result);
        return (process.ExitCode, output);
    }

    private static async Task<string> ReadScStreamAsync(TextReader reader, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder(1024);
        var buffer = new char[2048];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0) return builder.ToString();
            if (builder.Length + read > 32 * 1024) throw new InvalidDataException("BF-SETUP-SCM-OUTPUT");
            builder.Append(buffer, 0, read);
        }
    }

    // ServicePreState is immutable transaction input.  It is intentionally
    // distinct from the candidate/current result so rollback can never lose
    // the old binPath or the old stopped/running intent.
    private sealed record ServicePreState(bool Exists, bool WasRunning, string BinPath, string StartMode, string Identity, string Sid, string Generation)
    {
        public static ServicePreState None { get; } = new(false, false, "", "", "", "", "");
    }

    private sealed record ServiceApplyResult(bool Exists, bool Running, bool CreatedByTransaction, string BinPath, string StartMode, string Identity, string Sid, string Generation);

    private interface IServiceSemanticHealthAdapter
    {
        bool Verify(string expectedInstallId, long expectedSequence, string expectedGeneration, int expectedScmPid, string expectedBinary);
    }

    /// <summary>
    /// Production semantic-health boundary.  The installer talks only to the
    /// service's existing authenticated named pipe; it never opens a new HTTP
    /// port or probes a node-agent listener.  The wire format mirrors the
    /// framed challenge/auth/request protocol used by ClientServiceContract.
    /// </summary>
    private sealed class NamedPipeSemanticHealthAdapter : IServiceSemanticHealthAdapter
    {
        private const string PipeName = "BifrostClientService";
        private const int SecretBytes = 32;
        private readonly string? _bindingRoot;
        private readonly string _pipeName;
        private readonly TimeSpan _deadline;

        internal NamedPipeSemanticHealthAdapter(string? bindingRoot = null, string? pipeName = null, TimeSpan? deadline = null)
        {
            _bindingRoot = bindingRoot;
            _pipeName = string.IsNullOrWhiteSpace(pipeName) ? PipeName : pipeName;
            _deadline = deadline is { } value && value > TimeSpan.Zero && value <= TimeSpan.FromMinutes(1) ? value : TimeSpan.FromSeconds(10);
        }

        public bool Verify(string expectedInstallId, long expectedSequence, string expectedGeneration, int expectedScmPid, string expectedBinary)
        {
            if (!OperatingSystem.IsWindows() || expectedScmPid <= 0 || string.IsNullOrWhiteSpace(expectedBinary)) return false;
            using var deadline = new CancellationTokenSource(_deadline);
            try
            {
                return VerifyAsync(expectedInstallId, expectedSequence, expectedGeneration, expectedScmPid, expectedBinary, deadline.Token).GetAwaiter().GetResult();
            }
            catch { return false; }
        }

        private async Task<bool> VerifyAsync(string expectedInstallId, long expectedSequence, string expectedGeneration, int expectedScmPid, string expectedBinary, CancellationToken cancellationToken)
        {
            try
            {
                var root = BindingRoot;
                var secretPath = Path.Combine(root, "ipc-binding.bin");
                var sidPath = Path.Combine(root, "interactive.sid");
                EnsureNoReparseChain(root, allowMissingLeaf: false);
                EnsureNoReparseChain(secretPath, allowMissingLeaf: false);
                EnsureNoReparseChain(sidPath, allowMissingLeaf: false);
                var secret = BifrostIpcWire.ReadBoundedFile(secretPath, SecretBytes);
                try
                {
                    if (secret.Length != SecretBytes) return false;
                    var sid = Encoding.ASCII.GetString(BifrostIpcWire.ReadBoundedFile(sidPath, 256)).Trim();
                    if (sid.Length == 0 || sid.Any(ch => ch > 0x7f || char.IsControl(ch))) return false;
                    await using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                    await pipe.ConnectAsync(5000, cancellationToken).ConfigureAwait(false);
                    if (OperatingSystem.IsWindows() && (GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pipePid) == 0 || pipePid != (uint)expectedScmPid)) return false;
                    using var challenge = await BifrostIpcWire.ReadJsonAsync(pipe, cancellationToken).ConfigureAwait(false);
                    if (!HasOnly(challenge, "kind", "version", "nonce", "sid", "pid", "mac") ||
                        !TryString(challenge, "kind", out var kind) || kind != "challenge" ||
                        !TryInt(challenge, "version", out var version) || version != 1 ||
                        !TryString(challenge, "nonce", out var nonce) ||
                        !TryString(challenge, "sid", out var challengeSid) || challengeSid != sid ||
                        !TryString(challenge, "pid", out var challengePidText) || !int.TryParse(challengePidText, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var challengePid) || challengePid != expectedScmPid ||
                        !TryString(challenge, "mac", out var challengeMac) ||
                        !BifrostIpcWire.FixedMac(secret, $"server|{nonce}|{sid}|{challengePidText}", challengeMac)) return false;
                    await BifrostIpcWire.WriteJsonAsync(pipe, new { kind = "auth", version = 1, sid, nonce, counter = 1, mac = BifrostIpcWire.Mac(secret, $"auth|{nonce}|{sid}|1") }, cancellationToken).ConfigureAwait(false);
                    var body = "{\"action\":\"release_health\"}";
                    var operationId = Guid.NewGuid().ToString("D");
                    var bodyBytes = Encoding.UTF8.GetBytes(body);
                    try
                    {
                        var digest = Convert.ToHexString(SHA256.HashData(bodyBytes)).ToLowerInvariant();
                        await BifrostIpcWire.WriteJsonAsync(pipe, new { kind = "request", version = 1, nonce, counter = 2, operation_id = operationId, body, body_sha256 = digest, mac = BifrostIpcWire.Mac(secret, $"request|{nonce}|{operationId}|2|{digest}") }, cancellationToken).ConfigureAwait(false);
                    }
                    finally { CryptographicOperations.ZeroMemory(bodyBytes); }
                    using var response = await BifrostIpcWire.ReadJsonAsync(pipe, cancellationToken).ConfigureAwait(false);
                    if (!HasOnly(response, "product_id", "install_id", "release_sequence", "release_generation", "service_pid", "binary_identity") ||
                        !TryString(response, "product_id", out var product) || product != "bifrost-client-service" ||
                        !TryString(response, "install_id", out var installId) || installId != expectedInstallId ||
                        !TryInt64(response, "release_sequence", out var sequence) || sequence != expectedSequence ||
                        !TryString(response, "release_generation", out var generation) || generation != expectedGeneration ||
                        !TryInt(response, "service_pid", out var servicePid) || servicePid != expectedScmPid ||
                        !TryString(response, "binary_identity", out var identity) || identity.Length != 64 || !identity.All(IsHex)) return false;
                    var expectedIdentity = ComputeFileIdentity(expectedBinary);
                    return string.Equals(identity, expectedIdentity, StringComparison.OrdinalIgnoreCase);
                }
                finally { CryptographicOperations.ZeroMemory(secret); }
            }
            catch { return false; }
        }

        private string BindingRoot => _bindingRoot ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost", "ipc");

        public static string ComputeInstallId(string installRoot, string? bindingRoot = null)
        {
            var root = bindingRoot ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost", "ipc");
            var secretPath = Path.Combine(root, "ipc-binding.bin");
            EnsureNoReparseChain(root, allowMissingLeaf: false);
            EnsureNoReparseChain(secretPath, allowMissingLeaf: false);
            var secret = BifrostIpcWire.ReadBoundedFile(secretPath, SecretBytes);
            try
            {
                if (secret.Length != SecretBytes) throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
                return Convert.ToHexString(HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes("install|" + Path.GetFullPath(installRoot)))).ToLowerInvariant();
            }
            finally { CryptographicOperations.ZeroMemory(secret); }
        }

        private static string ComputeFileIdentity(string path)
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }

        private static bool HasOnly(JsonDocument document, params string[] names) => document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.EnumerateObject().Select(p => p.Name).OrderBy(x => x, StringComparer.Ordinal).SequenceEqual(names.OrderBy(x => x, StringComparer.Ordinal), StringComparer.Ordinal);
        private static bool TryString(JsonDocument document, string name, out string value) => TryString(document.RootElement, name, out value);
        private static bool TryString(JsonElement root, string name, out string value) { value = string.Empty; if (!root.TryGetProperty(name, out var e) || e.ValueKind != JsonValueKind.String) return false; value = e.GetString() ?? string.Empty; return value.Length > 0 && value.Length <= 512 && value.All(ch => !char.IsControl(ch)); }
        private static bool TryInt(JsonDocument document, string name, out int value)
        {
            value = 0;
            return document.RootElement.TryGetProperty(name, out var e) && e.TryGetInt32(out value);
        }
        private static bool TryInt64(JsonDocument document, string name, out long value)
        {
            value = 0;
            return document.RootElement.TryGetProperty(name, out var e) && e.TryGetInt64(out value);
        }
        private static bool IsHex(char value) => value is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);
    }

    private interface IServiceLifecycle
    {
        ServiceApplyResult CreateAndStart(string serviceBinary);
        ServiceApplyResult ReconfigureAndStart(string serviceBinary, ServicePreState previous);
        ServicePreState CapturePreState();
        ServicePreState StopVerified(ServicePreState previous);
        ServicePreState StopForUpdate();
        ServiceHealthResult EnsureHealthy();
        bool ValidateCommitted(ServiceApplyResult candidate);
        void PrepareRollback(ServicePreState snapshot, ServiceApplyResult? current);
        void RecordRollbackEvent(string name);
        void RestoreAfterRollback(ServicePreState snapshot);
        void DeleteOwnedService(ServicePreState snapshot);
    }

    private enum StableServiceState { Unknown, Stopped, StartPending, StopPending, Running }
    private enum ServiceHealthResult { Healthy, Deferred }

    private static class ScmPolicy
    {
        internal sealed record StopResult(bool Present, bool WasRunning);

        public static string ClassifyQueryExit(int exitCode) => exitCode switch
        {
            0 => "present",
            1060 => "absent",
            _ => "error"
        };

        public static StableServiceState FromNumeric(int value) => value switch
        {
            1 => StableServiceState.Stopped,
            2 => StableServiceState.StartPending,
            3 => StableServiceState.StopPending,
            4 => StableServiceState.Running,
            _ => StableServiceState.Unknown
        };

        public static StableServiceState Parse(string output)
        {
            // `sc query` localizes the field labels. The numeric state is the
            // stable contract; scan bounded colon-delimited numeric fields and
            // accept only the documented service-state values.
            foreach (System.Text.RegularExpressions.Match match in System.Text.RegularExpressions.Regex.Matches(output, @"(?m)^\s*[^:\r\n]{1,64}\s*:\s*(\d+)\b"))
            {
                if (int.TryParse(match.Groups[1].Value, out var numeric))
                {
                    var state = FromNumeric(numeric);
                    if (state != StableServiceState.Unknown) return state;
                }
            }
            return StableServiceState.Unknown;
        }

        public static IReadOnlyList<string> PlanStop(StableServiceState state) => state switch
        {
            StableServiceState.Stopped => Array.Empty<string>(),
            StableServiceState.Running => new[] { "stop", "wait-stopped" },
            StableServiceState.StartPending => new[] { "wait-running", "stop", "wait-stopped" },
            StableServiceState.StopPending => new[] { "wait-stopped" },
            _ => throw new InvalidDataException("BF-SETUP-SCM")
        };

        // The production SCM adapter and the pure fixture both use this same
        // transition executor.  Only numeric states and explicit 1060
        // (service absent) are meaningful; all other query failures fail
        // closed before any promotion is attempted.
        public static StopResult ExecuteStop(
            Func<(int exitCode, string output)> query,
            Action<StableServiceState> waitForState,
            Action issueStop)
        {
            var result = query();
            if (result.exitCode == 1060) return new StopResult(false, false);
            if (result.exitCode != 0) throw new InvalidDataException("BF-SETUP-SCM");
            var state = Parse(result.output);
            if (state == StableServiceState.Unknown) throw new InvalidDataException("BF-SETUP-SCM");
            // STOP_PENDING means the service was already on its way down
            // before this transaction.  It must not be treated as a
            // previously-running service that rollback should start again.
            var wasRunning = state is StableServiceState.Running or StableServiceState.StartPending;
            switch (state)
            {
                case StableServiceState.StartPending:
                    waitForState(StableServiceState.Running);
                    issueStop();
                    waitForState(StableServiceState.Stopped);
                    break;
                case StableServiceState.Running:
                    issueStop();
                    waitForState(StableServiceState.Stopped);
                    break;
                case StableServiceState.StopPending:
                    waitForState(StableServiceState.Stopped);
                    break;
                case StableServiceState.Stopped:
                    break;
                default:
                    throw new InvalidDataException("BF-SETUP-SCM");
            }
            return new StopResult(true, wasRunning);
        }

        public static void WaitForState(
            Func<(int exitCode, string output)> query,
            StableServiceState desired,
            Func<long> now,
            Action<TimeSpan> sleep,
            TimeSpan timeout)
        {
            var deadline = now() + (long)(timeout.TotalSeconds * Stopwatch.Frequency);
            while (now() < deadline)
            {
                var result = query();
                if (result.exitCode == 1060) throw new InvalidDataException("BF-SETUP-SCM");
                if (result.exitCode != 0) throw new InvalidDataException("BF-SETUP-SCM");
                if (Parse(result.output) == desired) return;
                sleep(TimeSpan.FromMilliseconds(100));
            }
            throw new TimeoutException("BF-SETUP-SCM-TIMEOUT");
        }
    }

    private sealed class FakeServiceLifecycle : IServiceLifecycle
    {
        private readonly string _markerPath;
        private readonly string _statePath;
        private readonly string _eventsPath;
        private readonly HashSet<string> _modes;

        private sealed record FakeServiceState(bool Exists, bool Running, string BinPath, string StartMode, string Identity, string Sid, string Generation, string Owner);

        public FakeServiceLifecycle(string stateRoot, string mode)
        {
            _modes = mode.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (_modes.Count == 0 || _modes.Any(item => item is not ("success" or "create-fails" or "stop-fails" or "start-fails" or "health-fails" or "service-restore-fails" or "reconfigure-fails" or "semantic-health-fails" or "external-service" or "ownership-fails" or "defer")))
                throw new InvalidDataException("BF-SETUP-FAKE-SERVICE");
            _markerPath = Path.Combine(stateRoot, "service-lifecycle.marker");
            _statePath = Path.Combine(stateRoot, "service-lifecycle.state.json");
            _eventsPath = Path.Combine(stateRoot, "service-lifecycle.events");
            EnsureNoReparseChain(_markerPath, allowMissingLeaf: true);
        }

        private bool HasMode(string mode) => _modes.Contains(mode);

        private void Event(string name)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_eventsPath)!);
            File.AppendAllText(_eventsPath, name + "\n", new UTF8Encoding(false, true));
        }

        private FakeServiceState? ReadState()
        {
            if (!File.Exists(_markerPath) && !File.Exists(_statePath))
            {
                if (HasMode("external-service") || HasMode("ownership-fails"))
                    return new FakeServiceState(true, true, "C:\\Other\\BifrostClientService.exe", "auto", "LocalSystem", "S-1-5-21-FOREIGN", "foreign", "external");
                return null;
            }
            try
            {
                using var document = JsonDocument.Parse(File.ReadAllBytes(File.Exists(_statePath) ? _statePath : _markerPath), new JsonDocumentOptions { MaxDepth = 8 });
                var value = document.RootElement;
                if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
                return new FakeServiceState(
                    value.GetProperty("exists").GetBoolean(), value.GetProperty("running").GetBoolean(),
                    value.GetProperty("binPath").GetString() ?? "", value.GetProperty("startMode").GetString() ?? "auto",
                    value.GetProperty("identity").GetString() ?? "LocalSystem", value.GetProperty("sid").GetString() ?? "S-1-5-80-BIFROST",
                    value.GetProperty("generation").GetString() ?? "", value.GetProperty("owner").GetString() ?? "bifrost")
                    with { };
            }
            catch
            {
                if (File.Exists(_statePath)) throw new InvalidDataException("BF-SETUP-SCM-STATE");
                // Older TEST fixtures used a one-word marker.  It remains an
                // owned service, but is immediately upgraded on the first
                // state-changing operation rather than treated as absent.
                var text = File.Exists(_markerPath) ? File.ReadAllText(_markerPath, Encoding.UTF8).Trim() : "stopped";
                return new FakeServiceState(true, string.Equals(text, "running", StringComparison.OrdinalIgnoreCase), "", "auto", "LocalSystem", "S-1-5-80-BIFROST", "", "bifrost");
            }
        }

        private void WriteState(FakeServiceState state)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_markerPath)!);
            WriteAtomic(_statePath, JsonSerializer.Serialize(state, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
            WriteAtomic(_markerPath, state.Running ? "running" : "stopped");
        }

        private static ServicePreState Pre(FakeServiceState state) =>
            new(state.Exists, state.Running, state.BinPath, state.StartMode, state.Identity, state.Sid, state.Generation);
        private static ServiceApplyResult Current(FakeServiceState state, bool created = false) =>
            new(state.Exists, state.Running, created, state.BinPath, state.StartMode, state.Identity, state.Sid, state.Generation);

        private static void EnsureOwned(FakeServiceState state)
        {
            if (!state.Exists || !string.Equals(state.Owner, "bifrost", StringComparison.Ordinal) || !string.Equals(state.Sid, "S-1-5-80-BIFROST", StringComparison.Ordinal) || !string.Equals(state.Identity, "LocalSystem", StringComparison.Ordinal))
                throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
        }

        public ServiceApplyResult CreateAndStart(string serviceBinary)
        {
            var fullBinary = Path.GetFullPath(serviceBinary);
            var prior = ReadState();
            if (prior is null)
            {
                if (HasMode("create-fails")) throw new InvalidOperationException("BF-SETUP-SCM");
                Event("create");
                var created = new FakeServiceState(true, false, fullBinary, "auto", "LocalSystem", "S-1-5-80-BIFROST", Path.GetFileName(Path.GetDirectoryName(fullBinary) ?? ""), "bifrost");
                WriteState(created);
                if (HasMode("start-fails")) { Event("start-failed"); TryDelete(_markerPath); TryDelete(_statePath); throw new InvalidOperationException("BF-SETUP-SCM"); }
                WriteState(created with { Running = true });
                return Current(created with { Running = true }, created: true);
            }
            EnsureOwned(prior);
            if (HasMode("reconfigure-fails") || HasMode("ownership-fails")) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            Event("reconfigure");
            var updated = prior with { BinPath = fullBinary, Generation = Path.GetFileName(Path.GetDirectoryName(fullBinary) ?? ""), Running = false };
            WriteState(updated);
            if (HasMode("start-fails")) { Event("start-failed"); throw new InvalidOperationException("BF-SETUP-SCM"); }
            WriteState(updated with { Running = true });
            return Current(updated with { Running = true });
        }

        public ServiceApplyResult ReconfigureAndStart(string serviceBinary, ServicePreState previous)
        {
            if (!previous.Exists) return CreateAndStart(serviceBinary);
            var prior = ReadState() ?? throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            EnsureOwned(prior);
            if (HasMode("reconfigure-fails") || HasMode("ownership-fails")) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            var fullBinary = Path.GetFullPath(serviceBinary);
            Event("reconfigure");
            var updated = prior with { BinPath = fullBinary, Generation = Path.GetFileName(Path.GetDirectoryName(fullBinary) ?? ""), Running = false };
            WriteState(updated);
            if (HasMode("start-fails")) { Event("start-failed"); throw new InvalidOperationException("BF-SETUP-SCM"); }
            if (previous.WasRunning) updated = updated with { Running = true };
            WriteState(updated);
            return Current(updated);
        }

        public ServicePreState CapturePreState()
        {
            var prior = ReadState();
            if (prior is null) return ServicePreState.None;
            EnsureOwned(prior);
            return Pre(prior);
        }

        public ServicePreState StopVerified(ServicePreState previous)
        {
            if (HasMode("stop-fails")) throw new InvalidOperationException("BF-SETUP-SCM");
            var prior = ReadState();
            if (!previous.Exists)
            {
                if (prior is not null) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
                return ServicePreState.None;
            }
            if (prior is null || !previous.Exists || !string.Equals(prior.BinPath, previous.BinPath, StringComparison.OrdinalIgnoreCase) || prior.Running != previous.WasRunning || !string.Equals(prior.Generation, previous.Generation, StringComparison.Ordinal))
                throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            EnsureOwned(prior);
            Event("stop-old");
            WriteState(prior with { Running = false }); // stop retains registration/config
            return previous;
        }

        public ServicePreState StopForUpdate()
        {
            var previous = CapturePreState();
            return StopVerified(previous);
        }

        public ServiceHealthResult EnsureHealthy()
        {
            Event("health");
            if (HasMode("start-fails") || HasMode("health-fails") || HasMode("semantic-health-fails")) throw new InvalidOperationException("BF-SETUP-SCM-HEALTH");
            var state = ReadState() ?? throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
            EnsureOwned(state);
            if (HasMode("defer")) { Event("deferred"); return ServiceHealthResult.Deferred; }
            if (string.IsNullOrWhiteSpace(state.BinPath) || !File.Exists(state.BinPath))
            {
                throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
            }
            if (state.Running && (string.IsNullOrWhiteSpace(state.BinPath) || !File.Exists(state.BinPath)))
                throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
            return ServiceHealthResult.Healthy;
        }

        public bool ValidateCommitted(ServiceApplyResult candidate)
        {
            var state = ReadState();
            if (state is null) return false;
            EnsureOwned(state);
            return state.Exists && state.Running == candidate.Running &&
                string.Equals(Path.GetFullPath(state.BinPath), Path.GetFullPath(candidate.BinPath), StringComparison.OrdinalIgnoreCase) &&
                string.Equals(state.Generation, candidate.Generation, StringComparison.Ordinal) &&
                string.Equals(state.Sid, candidate.Sid, StringComparison.Ordinal);
        }

        public void PrepareRollback(ServicePreState snapshot, ServiceApplyResult? current)
        {
            var state = ReadState();
            if (state is null) return;
            EnsureOwned(state);
            Event("stop-new");
            if (!snapshot.Exists && current?.CreatedByTransaction == true)
            {
                TryDelete(_markerPath);
                TryDelete(_statePath);
            }
            else WriteState(state with { Running = false });
        }

        public void RecordRollbackEvent(string name) => Event(name);

        public void RestoreAfterRollback(ServicePreState snapshot)
        {
            if (!snapshot.Exists) return;
            Event(snapshot.WasRunning ? "start-old" : "restore-stopped");
            // The fault is injected after the real restore step has been
            // entered and recorded.  Rollback callers must still continue
            // cleanup and persist a failed operation instead of shorting out.
            if (HasMode("service-restore-fails")) throw new InvalidOperationException("BF-SETUP-SCM");
            WriteState(new FakeServiceState(true, snapshot.WasRunning, snapshot.BinPath, snapshot.StartMode, snapshot.Identity, snapshot.Sid, snapshot.Generation, "bifrost"));
        }

        public void DeleteOwnedService(ServicePreState snapshot)
        {
            var state = ReadState();
            if (state is null) return;
            EnsureOwned(state);
            if (snapshot.Exists) Event("delete");
            TryDelete(_markerPath);
            TryDelete(_statePath);
        }
    }

    private sealed class WindowsServiceLifecycle : IServiceLifecycle
    {
        private readonly string _installRoot;
        private readonly IServiceSemanticHealthAdapter _semanticHealth;
        private bool _servicePresent;
        private bool _desiredStart;
        private bool _startAttempted;
        private bool _deferredExplicitly;
        private string? _expectedBinary;
        private string? _expectedGeneration;
        private string? _expectedInstallId;
        private long _expectedSequence;

        public WindowsServiceLifecycle(string installRoot, IServiceSemanticHealthAdapter semanticHealth)
        {
            _installRoot = Path.GetFullPath(installRoot);
            _semanticHealth = semanticHealth;
        }

        public ServiceApplyResult CreateAndStart(string serviceBinary)
        {
            var fullBinary = Path.GetFullPath(serviceBinary);
            if (!IsContained(_installRoot, fullBinary) || !File.Exists(fullBinary)) throw new InvalidDataException("BF-SETUP-SERVICE");
            EnsureNoReparseChain(fullBinary, allowMissingLeaf: false);
            var existing = RunScCapture("query", ServiceName);
            // A same-name registration is not necessarily ours. Keep the
            // fail-closed behavior, but report this recoverable collision
            // separately from a corrupted service already verified as ours.
            if (existing.exitCode == 0) throw new InvalidDataException("BF-SETUP-SCM-SERVICE-EXISTS");
            if (existing.exitCode != 1060) throw new InvalidDataException("BF-SETUP-SCM");
            RunSc("create", ServiceName, "binPath=", fullBinary, "start=", "auto");
            _servicePresent = true;
            try
            {
                // SERVICE_SID_TYPE is separate from the service account and
                // actual NT SERVICE SID.  Configure and read it back before
                // the first start so initial install cannot pass through the
                // NONE default and then fail health verification.
                RunSc("sidtype", ServiceName, "unrestricted");
                var configured = ReadExistingServiceConfiguration();
                if (configured.Sid is "" or "NONE") throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
                RunSc("start", ServiceName);
                WaitForState(StableServiceState.Running);
            }
            catch
            {
                // `sc create` is already a durable side effect even when the
                // subsequent start fails.  Remove this transaction-owned
                // service here, before the exception escapes and before the
                // caller has a snapshot to roll back.
                try
                {
                    RunSc("delete", ServiceName);
                    WaitForServiceAbsentBestEffort();
                }
                catch { }
                _servicePresent = false;
                _desiredStart = false;
                _startAttempted = false;
                throw;
            }
            _desiredStart = true;
            _startAttempted = true;
            _deferredExplicitly = false;
            _expectedBinary = fullBinary;
            _expectedGeneration = Path.GetFileName(Path.GetDirectoryName(fullBinary) ?? "");
            _expectedInstallId = NamedPipeSemanticHealthAdapter.ComputeInstallId(_installRoot);
            _expectedSequence = ParseGenerationSequence(_expectedGeneration);
            var readback = ReadExistingServiceConfiguration();
            return new ServiceApplyResult(true, true, true, readback.BinPath, readback.StartMode, readback.Identity, readback.Sid, _expectedGeneration);
        }

        public ServiceApplyResult ReconfigureAndStart(string serviceBinary, ServicePreState previous)
        {
            var fullBinary = Path.GetFullPath(serviceBinary);
            if (!previous.Exists) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            if (!IsContained(_installRoot, fullBinary) || !File.Exists(fullBinary)) throw new InvalidDataException("BF-SETUP-SERVICE");
            EnsureNoReparseChain(fullBinary, allowMissingLeaf: false);
            var current = ReadExistingServiceConfiguration();
            if (!string.Equals(current.BinPath, Path.GetFullPath(previous.BinPath), StringComparison.OrdinalIgnoreCase) || !IsContained(_installRoot, current.BinPath) || !string.Equals(current.StartMode, previous.StartMode, StringComparison.Ordinal) || !string.Equals(current.Identity, previous.Identity, StringComparison.Ordinal) || !string.Equals(current.Sid, previous.Sid, StringComparison.Ordinal))
                throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            RunSc("config", ServiceName, "binPath=", fullBinary);
            var readback = ReadExistingServiceConfiguration();
            if (!string.Equals(readback.BinPath, fullBinary, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-SCM-READBACK");
            _servicePresent = true;
            _desiredStart = previous.WasRunning;
            _startAttempted = false;
            _deferredExplicitly = false;
            _expectedBinary = fullBinary;
            _expectedGeneration = Path.GetFileName(Path.GetDirectoryName(fullBinary) ?? "");
            _expectedSequence = ParseGenerationSequence(_expectedGeneration);
            if (_desiredStart)
            {
                RunSc("start", ServiceName);
                WaitForState(StableServiceState.Running);
                _startAttempted = true;
            }
            var result = ReadExistingServiceConfiguration();
            return new ServiceApplyResult(true, _desiredStart, false, result.BinPath, result.StartMode, result.Identity, result.Sid, _expectedGeneration);
        }

        public ServicePreState CapturePreState()
        {
            var existingConfiguration = ReadExistingServiceConfigurationOrNull();
            if (existingConfiguration is not null)
            {
                var preflight = existingConfiguration.Value;
                if (!IsContained(_installRoot, preflight.BinPath)) throw new InvalidDataException("BF-SETUP-SCM-SERVICE-FOREIGN");
                try { _ = ReadOwnership(_installRoot, testRoot: false); } catch { throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP"); }
            }
            var query = RunScCapture("query", ServiceName);
            if (query.exitCode == 1060) return ServicePreState.None;
            if (query.exitCode != 0) throw new InvalidDataException("BF-SETUP-SCM");
            var stable = ScmPolicy.Parse(query.output);
            if (stable == StableServiceState.Unknown) throw new InvalidDataException("BF-SETUP-SCM");
            var wasRunning = stable is StableServiceState.Running or StableServiceState.StartPending;
            if (existingConfiguration is null) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            var existingConfig = existingConfiguration.Value;
            _servicePresent = true;
            _desiredStart = wasRunning;
            _startAttempted = false;
            _deferredExplicitly = false;
            _expectedBinary = existingConfig.BinPath;
            _expectedGeneration = Path.GetFileName(Path.GetDirectoryName(existingConfig.BinPath) ?? "");
            _expectedInstallId = NamedPipeSemanticHealthAdapter.ComputeInstallId(_installRoot);
            _expectedSequence = ParseGenerationSequence(_expectedGeneration);
            return new ServicePreState(true, wasRunning, existingConfig.BinPath, existingConfig.StartMode, existingConfig.Identity, existingConfig.Sid, _expectedGeneration);
        }

        public ServicePreState StopVerified(ServicePreState previous)
        {
            if (!previous.Exists) return ServicePreState.None;
            var existingConfiguration = ReadExistingServiceConfigurationOrNull();
            if (existingConfiguration is null || !string.Equals(existingConfiguration.Value.BinPath, previous.BinPath, StringComparison.OrdinalIgnoreCase) || !string.Equals(existingConfiguration.Value.StartMode, previous.StartMode, StringComparison.Ordinal) || !string.Equals(existingConfiguration.Value.Identity, previous.Identity, StringComparison.Ordinal) || !string.Equals(existingConfiguration.Value.Sid, previous.Sid, StringComparison.Ordinal))
                throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            var transition = ScmPolicy.ExecuteStop(
                () => RunScCapture("query", ServiceName),
                state => WaitForState(state),
                () =>
                {
                    try { RunSc("stop", ServiceName); }
                    catch
                    {
                        // Stop may have crossed the SCM boundary before
                        // reporting an error.  Make a bounded best effort to
                        // restore the previously-running service.
                        try { RunSc("start", ServiceName); } catch { }
                        throw;
                    }
                });
            if (!transition.Present) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            _servicePresent = true;
            _desiredStart = previous.WasRunning;
            _startAttempted = false;
            _deferredExplicitly = false;
            _expectedBinary = previous.BinPath;
            _expectedGeneration = previous.Generation;
            _expectedInstallId = NamedPipeSemanticHealthAdapter.ComputeInstallId(_installRoot);
            _expectedSequence = ParseGenerationSequence(_expectedGeneration);
            return previous;
        }

        public ServicePreState StopForUpdate()
        {
            var previous = CapturePreState();
            return StopVerified(previous);
        }

        public ServiceHealthResult EnsureHealthy()
        {
            if (!_servicePresent) throw new InvalidOperationException("BF-SETUP-SCM-HEALTH");
            if (_deferredExplicitly) return ServiceHealthResult.Deferred;
            if (_desiredStart && !_startAttempted)
            {
                RunSc("start", ServiceName);
                WaitForState(StableServiceState.Running);
                _startAttempted = true;
            }
            var result = RunScCapture("query", ServiceName);
            if (result.exitCode != 0 || (_desiredStart && ScmPolicy.Parse(result.output) != StableServiceState.Running))
                throw new InvalidOperationException("BF-SETUP-SCM-HEALTH");
            var servicePid = 0;
            if (_desiredStart)
            {
                var queryEx = RunScCapture("queryex", ServiceName);
                var pidText = ParseServiceField(queryEx.output, "PID");
                if (queryEx.exitCode != 0 || !int.TryParse(pidText, out servicePid) || servicePid <= 0 || !ValidateRunningImage(servicePid)) throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
            }
            if (_expectedBinary is null) throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
            var config = ReadExistingServiceConfiguration();
            var actualGeneration = Path.GetFileName(Path.GetDirectoryName(config.BinPath) ?? "");
            if (!string.Equals(config.BinPath, _expectedBinary, StringComparison.OrdinalIgnoreCase) || !IsContained(_installRoot, config.BinPath) || string.IsNullOrWhiteSpace(config.Sid) || string.IsNullOrWhiteSpace(config.Identity) || (_desiredStart && !string.Equals(actualGeneration, _expectedGeneration, StringComparison.Ordinal)))
                throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
            if (_desiredStart && !_semanticHealth.Verify(_expectedInstallId ?? NamedPipeSemanticHealthAdapter.ComputeInstallId(_installRoot), _expectedSequence, _expectedGeneration ?? string.Empty, servicePid, _expectedBinary))
                throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
            return ServiceHealthResult.Healthy;
        }

        public bool ValidateCommitted(ServiceApplyResult candidate)
        {
            if (!candidate.Exists) return false;
            _servicePresent = true;
            _desiredStart = candidate.Running;
            _startAttempted = candidate.Running;
            _deferredExplicitly = false;
            _expectedBinary = Path.GetFullPath(candidate.BinPath);
            _expectedGeneration = candidate.Generation;
            _expectedInstallId = NamedPipeSemanticHealthAdapter.ComputeInstallId(_installRoot);
            _expectedSequence = ParseGenerationSequence(candidate.Generation);
            try { return EnsureHealthy() == ServiceHealthResult.Healthy; }
            catch { return false; }
        }

        public void RecordRollbackEvent(string name) { }

        public void PrepareRollback(ServicePreState snapshot, ServiceApplyResult? current)
        {
            // If preflight or initial service creation failed before returning
            // a transaction-owned apply result, this lifecycle has nothing it
            // is authorised to stop.  In particular, never touch an unrelated
            // or stale same-name service just because installation failed
            // while inspecting it.
            if (!snapshot.Exists && current is null) return;
            if (!snapshot.Exists && current?.CreatedByTransaction == true)
            {
                TryStopIfPresent();
                try { RunSc("delete", ServiceName); } catch { }
                _servicePresent = false;
                _desiredStart = false;
                _startAttempted = false;
            }
            else
            {
                TryStopIfPresent();
            }
        }

        public void RestoreAfterRollback(ServicePreState snapshot)
        {
            if (!snapshot.Exists) return;
            var current = ReadExistingServiceConfigurationOrNull();
            if (current is null)
            {
                // DeleteOwnedService may already have crossed the SCM
                // boundary before a crash/failure was observed.  Recovery is
                // allowed to recreate only the exact pre-state registration;
                // it never invents a service name, account, SID type, or path.
                if (!IsContained(_installRoot, snapshot.BinPath) || !File.Exists(snapshot.BinPath)) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
                RunSc("create", ServiceName, "binPath=", Path.GetFullPath(snapshot.BinPath), "start=", snapshot.StartMode, "obj=", snapshot.Identity);
                _servicePresent = true;
                RunSc("sidtype", ServiceName, snapshot.Sid);
            }
            else if (!string.Equals(current.Value.Identity, snapshot.Identity, StringComparison.Ordinal) || !string.Equals(current.Value.Sid, snapshot.Sid, StringComparison.Ordinal)) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            RunSc("config", ServiceName, "binPath=", snapshot.BinPath, "start=", snapshot.StartMode, "obj=", snapshot.Identity);
            RunSc("sidtype", ServiceName, snapshot.Sid);
            var restored = ReadExistingServiceConfiguration();
            if (!string.Equals(restored.BinPath, Path.GetFullPath(snapshot.BinPath), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-SCM-READBACK");
            if (snapshot.WasRunning)
            {
                RunSc("start", ServiceName);
                WaitForState(StableServiceState.Running);
            }
            else
            {
                var state = RunScCapture("query", ServiceName);
                if (state.exitCode != 0 || ScmPolicy.Parse(state.output) != StableServiceState.Stopped) throw new InvalidDataException("BF-SETUP-SCM-READBACK");
            }
            _servicePresent = true;
            _desiredStart = snapshot.WasRunning;
            _startAttempted = snapshot.WasRunning;
            _expectedBinary = snapshot.BinPath;
            _expectedGeneration = snapshot.Generation;
            _expectedInstallId = NamedPipeSemanticHealthAdapter.ComputeInstallId(_installRoot);
            _expectedSequence = ParseGenerationSequence(_expectedGeneration);
        }

        public void DeleteOwnedService(ServicePreState snapshot)
        {
            if (!snapshot.Exists || !_servicePresent) return;
            RunSc("delete", ServiceName);
            _servicePresent = false;
            _desiredStart = false;
            _startAttempted = false;
        }

        private void TryStopIfPresent()
        {
            _ = ScmPolicy.ExecuteStop(
                () => RunScCapture("query", ServiceName),
                state => WaitForState(state),
                () => RunSc("stop", ServiceName));
        }

        private (string BinPath, string StartMode, string Identity, string Sid) ReadExistingServiceConfiguration()
        {
            var result = RunScCapture("qc", ServiceName);
            if (result.exitCode != 0) throw new InvalidDataException("BF-SETUP-SCM");
            var binPath = ParseServiceField(result.output, "BINARY_PATH_NAME");
            var startMode = ParseServiceField(result.output, "START_TYPE");
            if (string.IsNullOrWhiteSpace(startMode)) startMode = ParseServiceField(result.output, "SERVICE_START_TYPE");
            startMode = NormalizeStartMode(startMode);
            var identity = ParseServiceField(result.output, "SERVICE_START_NAME");
            if (string.IsNullOrWhiteSpace(binPath)) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            if (string.IsNullOrWhiteSpace(startMode) || string.IsNullOrWhiteSpace(identity)) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            var sidResult = RunScCapture("qsidtype", ServiceName);
            if (sidResult.exitCode != 0) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            var sid = ParseServiceField(sidResult.output, "SERVICE_SID_TYPE");
            if (string.IsNullOrWhiteSpace(sid) || sid.Equals("NONE", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP");
            return (Path.GetFullPath(binPath.Trim().Trim('"')), startMode, identity, sid);
        }

        private static string NormalizeStartMode(string value)
        {
            var token = value.Trim().Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
            return token switch { "2" => "auto", "3" => "demand", "4" => "disabled", _ when token.Equals("AUTO_START", StringComparison.OrdinalIgnoreCase) => "auto", _ when token.Equals("DEMAND_START", StringComparison.OrdinalIgnoreCase) => "demand", _ when token.Equals("DISABLED", StringComparison.OrdinalIgnoreCase) => "disabled", _ => throw new InvalidDataException("BF-SETUP-SCM-OWNERSHIP") };
        }

        private static long ParseGenerationSequence(string? generation)
        {
            if (string.IsNullOrWhiteSpace(generation)) throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
            var token = generation.StartsWith("g-", StringComparison.OrdinalIgnoreCase) ? generation[2..].Split('-', 2)[0] : generation.Split('-', 2)[0];
            return long.TryParse(token, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var sequence) && sequence > 0
                ? sequence : throw new InvalidDataException("BF-SETUP-SCM-HEALTH");
        }

        private bool ValidateRunningImage(int pid)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                var image = process.MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(image) || string.IsNullOrWhiteSpace(_expectedBinary) || !string.Equals(Path.GetFullPath(image), Path.GetFullPath(_expectedBinary), StringComparison.OrdinalIgnoreCase)) return false;
                EnsureNoReparseChain(image, allowMissingLeaf: false);
                using var stream = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
                var identity = Convert.ToHexString(SHA256.HashData(stream));
                using var expectedStream = new FileStream(_expectedBinary, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
                return identity.Equals(Convert.ToHexString(SHA256.HashData(expectedStream)), StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private (string BinPath, string StartMode, string Identity, string Sid)? ReadExistingServiceConfigurationOrNull()
        {
            var query = RunScCapture("query", ServiceName);
            if (query.exitCode == 1060) return null;
            if (query.exitCode != 0) throw new InvalidDataException("BF-SETUP-SCM");
            return ReadExistingServiceConfiguration();
        }

        private static string ParseServiceField(string output, string field)
        {
            foreach (var line in output.Split('\n'))
            {
                var colon = line.IndexOf(':');
                if (colon <= 0 || line[..colon].IndexOf(field, StringComparison.OrdinalIgnoreCase) < 0) continue;
                return line[(colon + 1)..].Trim();
            }
            return string.Empty;
        }

        private void WaitForState(StableServiceState desired)
        {
            ScmPolicy.WaitForState(
                () => RunScCapture("query", ServiceName),
                desired,
                Stopwatch.GetTimestamp,
                Thread.Sleep,
                // Clean Windows machines and machines with real-time AV can
                // spend tens of seconds scanning the first self-contained
                // service image.  SCM remains authoritative throughout; a
                // longer bounded wait improves compatibility without accepting
                // a stopped or foreign service as healthy.
                TimeSpan.FromSeconds(45));
        }

        private static void WaitForServiceAbsentBestEffort()
        {
            var deadline = Stopwatch.GetTimestamp() + (long)(TimeSpan.FromSeconds(15).TotalSeconds * Stopwatch.Frequency);
            while (Stopwatch.GetTimestamp() < deadline)
            {
                var result = RunScCapture("query", ServiceName);
                if (result.exitCode == 1060) return;
                Thread.Sleep(150);
            }
        }
    }

    private static int PurgeMarkerInstallation(string installRoot, string updateRoot, bool testRoot, string? fakeServiceMode, string? fakeFailureMode, FileStream? installLock)
    {
        var marker = ReadStrictObject(ResolveUninstalledMarkerPath(installRoot), 16 * 1024);
        var installId = marker.GetProperty("install_id").GetString() ?? throw new InvalidDataException("BF-SETUP-UNINSTALL");
        var operationId = Guid.NewGuid().ToString("N");
        var tombstone = installRoot + ".uninstalling-" + operationId;
        try
        {
            WriteUninstallJournal(installRoot, "intent", operationId, installId, purge: true, tombstone, ServicePreState.None, null, null, null, testRoot,
                ResolveServiceStateRootForJournal(testRoot, installRoot, updateRoot), kind: "marker-purge");
            Directory.Move(installRoot, tombstone);
            UpdateUninstallJournalPhase(installRoot, "renamed");
            var journal = ReadUninstallJournal(installRoot);
            var bindingPhase = journal.TryGetProperty("binding_phase", out var phaseValue) && phaseValue.ValueKind == JsonValueKind.String ? phaseValue.GetString() : "absent";
            if (bindingPhase is not ("deleted" or "absent"))
            {
                UpdateUninstallJournalBindingPhase(installRoot, "intent");
                if (FaultEnabled(fakeFailureMode, "crash-after-binding-intent")) Environment.Exit(91);
                journal = ReadUninstallJournal(installRoot);
                RenamePurgeIpcBinding(installRoot, tombstone, testRoot, journal);
                if (FaultEnabled(fakeFailureMode, "crash-after-binding-rename")) Environment.Exit(91);
                UpdateUninstallJournalBindingPhase(installRoot, "renamed");
                if (FaultEnabled(fakeFailureMode, "crash-after-binding-phase")) Environment.Exit(91);
                UpdateUninstallJournalBindingPhase(installRoot, "cleanup");
                journal = ReadUninstallJournal(installRoot);
                CleanupPurgeIpcBinding(journal, testRoot, fakeFailureMode, allowCrashMidCleanup: true);
                UpdateUninstallJournalBindingPhase(installRoot, "deleted");
                if (FaultEnabled(fakeFailureMode, "crash-after-binding-cleanup")) Environment.Exit(91);
            }
            UpdateUninstallJournalPhase(installRoot, "binding-deleted");
            if (Directory.Exists(tombstone)) { ValidateOwnedTree(tombstone); Directory.Delete(tombstone, true); }
            if (FaultEnabled(fakeFailureMode, "crash-after-tombstone-delete")) Environment.Exit(91);
            ClearUninstallJournal(installRoot);
            if (installLock is not null)
            {
                installLock.Dispose();
                if (!TryDeleteResult(ResolveExternalInstallLockPath(installRoot))) throw new InvalidDataException("BF-SETUP-LOCK");
            }
            return 0;
        }
        catch
        {
            try { RecoverUninstallJournal(installRoot, testRoot, fakeServiceMode, updateRoot); } catch { }
            throw new InvalidDataException("BF-SETUP-UNINSTALL");
        }
    }

    private static int ForceResidualCleanup(string? installRootText, string? updateRootText, bool testRoot)
    {
        var installRoot = ResolveInstallRoot(installRootText, testRoot);
        var updateRoot = ResolveUpdateRoot(updateRootText, testRoot);
        EnsureNoReparseChain(installRoot, allowMissingLeaf: true);

        if (!testRoot)
        {
            // This compatibility path is entered only after the user selects
            // and confirms a previous Bifrost folder. Do not require an old
            // ownership record: stop the exact product service name, drain
            // processes whose image is under that exact folder, then remove
            // the stale registration so a fresh installation can create it.
            //
            // Older installers used Program Files while current packages may
            // be installed to a user-selected fixed drive.  In that migration
            // the existing service can point at a different old Bifrost tree.
            // Capture that exact service binary before deleting the service so
            // the still-visible legacy GUI in the same generation cannot
            // survive a successful replacement and make the user appear to be
            // running the old version after setup completes.
            var legacyServiceDirectory = TryResolveRegisteredBifrostServiceDirectory();
            try { _ = RunScCapture("stop", ServiceName); } catch { }
            try { TerminateOwnedProcesses(installRoot); } catch { }
            if (!string.IsNullOrWhiteSpace(legacyServiceDirectory) &&
                !string.Equals(Path.GetFullPath(legacyServiceDirectory), Path.GetFullPath(installRoot), StringComparison.OrdinalIgnoreCase))
            {
                try { TerminateOwnedProcesses(legacyServiceDirectory); } catch { }
            }
            ForceDeleteBifrostServiceRegistration();
        }

        if (Directory.Exists(installRoot))
        {
            EnsureNoReparseChain(installRoot, allowMissingLeaf: false);
            var quarantine = installRoot + ".previous-" + Guid.NewGuid().ToString("N");
            var moved = false;
            for (var attempt = 0; attempt < 20 && Directory.Exists(installRoot); attempt++)
            {
                try
                {
                    Directory.Move(installRoot, quarantine);
                    moved = true;
                    break;
                }
                catch
                {
                    if (attempt == 19) break;
                    Thread.Sleep(Math.Min(1000, 100 + (attempt * 75)));
                }
            }

            // A direct delete is the last compatibility fallback for folders
            // that cannot be renamed. The path is still the exact fixed-drive
            // folder explicitly confirmed in the wizard, never a wildcard or
            // parent directory.
            if (!moved && Directory.Exists(installRoot) && !TryDeleteResult(installRoot))
                throw new InvalidDataException("BF-SETUP-RESIDUAL-CLEANUP");

            if (moved && !TryDeleteResult(quarantine))
                ScheduleValidatedTreeDeletionAtRebootBestEffort(quarantine);
        }

        // Compatibility cleanup must not be defeated by a corrupt journal,
        // stale registry value, or older runtime cache. Each item is already
        // product-scoped, and none is required for the fresh install.
        _ = TryDeleteResult(ResolveUninstallJournalPath(installRoot));
        _ = TryDeleteResult(ResolveExternalInstallLockPath(installRoot));
        if (!testRoot)
        {
            try { RemoveWindowsUninstallEntry(installRoot); } catch { }
        }
        // Compatibility replacement exists to get a new client installed,
        // not to factory-reset the workstation. Keep enrollment, UI state,
        // signed configs and the shared IPC binding. A stale update inbox is
        // harmless and the next signed updater replaces its own marker.
        // Explicit `--uninstall --purge` remains the only path that removes
        // client runtime state.
        return 0;
    }

    private static string? TryResolveRegisteredBifrostServiceDirectory()
    {
        try
        {
            var query = RunScCapture("query", ServiceName);
            if (query.exitCode == 1060) return null;
            if (query.exitCode != 0) return null;
            var configuration = RunScCapture("qc", ServiceName);
            if (configuration.exitCode != 0) return null;
            foreach (var rawLine in configuration.output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var separator = rawLine.IndexOf(':');
                if (separator < 0 || !string.Equals(rawLine[..separator].Trim(), "BINARY_PATH_NAME", StringComparison.OrdinalIgnoreCase)) continue;
                var command = rawLine[(separator + 1)..].Trim();
                if (string.IsNullOrWhiteSpace(command)) return null;
                string executable;
                if (command[0] == '"')
                {
                    var closing = command.IndexOf('"', 1);
                    if (closing <= 1) return null;
                    executable = command[1..closing];
                }
                else
                {
                    var extension = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                    if (extension < 0) return null;
                    executable = command[..(extension + 4)].Trim();
                }
                var full = Path.GetFullPath(executable);
                if (!string.Equals(Path.GetFileName(full), "BifrostClientService.exe", StringComparison.OrdinalIgnoreCase)) return null;
                var directory = Path.GetDirectoryName(full);
                if (string.IsNullOrWhiteSpace(directory)) return null;
                EnsureNoReparseChain(directory, allowMissingLeaf: true);
                return directory;
            }
        }
        catch { }
        return null;
    }

    private static void ForceDeleteBifrostServiceRegistration()
    {
        var initial = RunScCapture("query", ServiceName);
        if (initial.exitCode == 1060) return;

        try { _ = RunScCapture("delete", ServiceName); } catch { }
        var deadline = Stopwatch.GetTimestamp() + (long)(TimeSpan.FromSeconds(45).TotalSeconds * Stopwatch.Frequency);
        while (Stopwatch.GetTimestamp() < deadline)
        {
            var query = RunScCapture("query", ServiceName);
            if (query.exitCode == 1060) return;
            Thread.Sleep(200);
        }
        throw new InvalidDataException("BF-SETUP-SCM-CLEANUP");
    }

    private static void ReplaceExistingBifrostServiceForFreshInstall()
    {
        var existing = RunScCapture("query", ServiceName);
        if (existing.exitCode == 1060) return;
        if (existing.exitCode != 0) throw new InvalidDataException("BF-SETUP-SCM");
        try { _ = RunScCapture("stop", ServiceName); } catch { }
        ForceDeleteBifrostServiceRegistration();
    }

    private static int Uninstall(string? installRootText, string? updateRootText, bool testRoot, bool whatIf, bool purge, bool requireVerifiedInstallRoot, bool helper, string? waitForPid, string? fakeServiceMode, string? fakeFailureMode)
    {
        var installRoot = ResolveInstallRoot(installRootText, testRoot);
        var updateRoot = ResolveUpdateRoot(updateRootText, testRoot);
        if (!testRoot && !whatIf && !helper)
        {
            var processPath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(processPath) && IsContained(installRoot, Path.GetFullPath(processPath)))
            {
                // A verified-residual cleanup is synchronous: the wizard
                // must not retry installation until the selected root and
                // service transaction have actually completed. A helper
                // outside this root must wait for this process to exit before
                // it can remove the root, so scheduling it here would both
                // lose the verified-cleanup boundary and falsely report
                // completion to the waiting wizard. Fail closed; ordinary
                // explicit uninstalls retain the deferred helper.
                if (requireVerifiedInstallRoot)
                    throw new InvalidDataException("BF-SETUP-RESIDUAL-SELF");
                return ScheduleUninstallHelper(installRoot, purge);
            }
        }
        if (helper && !testRoot)
        {
            if (string.IsNullOrWhiteSpace(waitForPid)) throw new InvalidDataException("BF-SETUP-PARENT");
            WaitForParentExit(waitForPid);
        }
        EnsureNoReparseChain(installRoot, allowMissingLeaf: true);
        // A wizard recovery confirmation is valid only for the exact existing
        // installation that the user selected. If it disappears before the
        // elevated operation starts, fail closed rather than taking the normal
        // missing-root purge shortcut, which also deletes shared runtime data.
        if (requireVerifiedInstallRoot && !Directory.Exists(installRoot))
            throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        SignalVerifiedResidualRootCheckForTest(requireVerifiedInstallRoot);
        using FileStream? installLock = whatIf ? null : AcquireInstallLock(installRoot);
        if (whatIf) { ValidateUninstallJournalReadOnly(installRoot); ValidatePromotionJournalReadOnly(installRoot); }
        else { RecoverUninstallJournal(installRoot, testRoot, fakeServiceMode, updateRoot); RecoverPromotionJournal(installRoot, testRoot); }
        if (!Directory.Exists(installRoot) && purge)
        {
            // The selected root can disappear while waiting for the external
            // install lock or while recovering an earlier transaction.  A
            // wizard-approved cleanup must never fall through to the generic
            // missing-root purge, because that purge also removes shared
            // client state without having re-validated root/service ownership.
            if (requireVerifiedInstallRoot)
                throw new InvalidDataException("BF-SETUP-OWNERSHIP");
            if (installLock is not null)
            {
                installLock.Dispose();
                _ = TryDeleteResult(ResolveExternalInstallLockPath(installRoot));
            }
            if (!testRoot) RemoveWindowsUninstallEntry(installRoot);
            PurgeClientRuntimeState(installRoot, updateRoot, testRoot);
            if (helper && !testRoot) ScheduleUninstallHelperCleanup();
            return 0;
        }
        EnsureNoReparseChain(installRoot, allowMissingLeaf: false);
        if (File.Exists(ResolveUninstalledMarkerPath(installRoot)) && !File.Exists(ResolveStatePath(installRoot)) && !File.Exists(ResolveOwnershipPath(installRoot)))
        {
            // A marker-only tree is valid for an explicit, ordinary purge, but
            // it cannot satisfy the recovery wizard's promise that both this
            // folder and the currently conflicting service were verified.
            // The service lifecycle is already gone from this tree, so taking
            // this early-return path during a service-conflict recovery would
            // delete shared state without verifying or resolving that service.
            if (requireVerifiedInstallRoot)
                throw new InvalidDataException("BF-SETUP-OWNERSHIP");
            ValidateUninstalledMarker(installRoot);
            if (!purge) return 0;
            ValidateUninstallEntries(installRoot);
            if (whatIf) return 0;
            var result = PurgeMarkerInstallation(installRoot, updateRoot, testRoot, fakeServiceMode, fakeFailureMode, installLock);
            if (result == 0)
            {
                if (!testRoot) RemoveWindowsUninstallEntry(installRoot);
                PurgeClientRuntimeState(installRoot, updateRoot, testRoot);
                if (helper && !testRoot) ScheduleUninstallHelperCleanup();
            }
            return result;
        }
        var ownership = ReadOwnership(installRoot, testRoot);
        if (whatIf) return 0;
        ValidateUninstallEntries(installRoot);
        var service = CreateServiceLifecycle(testRoot, fakeServiceMode ?? "success", updateRoot, installRoot);
        var snapshot = service.CapturePreState();
        var installId = ownership.GetProperty("install_id").GetString() ?? throw new InvalidDataException("BF-SETUP-OWNERSHIP");
        var operationId = Guid.NewGuid().ToString("N");
        var tombstone = installRoot + ".uninstalling-" + operationId;
        var cleanRoot = installRoot + ".uninstalled-" + operationId;
        var previousState = ReadOptionalState(ResolveStatePath(installRoot));
        var previousPointer = ReadOptionalState(Path.Combine(ResolveStateRoot(installRoot), "current.json"));
        var previousOwnership = ReadOptionalState(ResolveOwnershipPath(installRoot));
        try
        {
            // The authenticated intent is durable before the first SCM or
            // filesystem side effect.  Subsequent phases update this same
            // external journal; no in-root lock/journal is deleted while held.
            WriteUninstallJournal(installRoot, "intent", operationId, installId, purge, tombstone, snapshot, previousState, previousPointer, previousOwnership, testRoot, ResolveServiceStateRootForJournal(testRoot, installRoot, updateRoot));
            if (FaultEnabled(fakeFailureMode, "crash-after-intent")) Environment.Exit(91);
            _ = service.StopVerified(snapshot);
            if (!testRoot) TerminateOwnedProcesses(installRoot);
            service.RecordRollbackEvent("uninstall");
            UpdateUninstallJournalPhase(installRoot, "stopped");
            if (FaultEnabled(fakeFailureMode, "crash-after-stop")) Environment.Exit(91);
            if (FaultEnabled(fakeFailureMode, "after-stop")) throw new IOException("BF-SETUP-FAULT");
            Directory.Move(installRoot, tombstone);
            UpdateUninstallJournalPhase(installRoot, "renamed");
            if (FaultEnabled(fakeFailureMode, "crash-after-rename")) Environment.Exit(91);
            if (FaultEnabled(fakeFailureMode, "after-rename")) throw new IOException("BF-SETUP-FAULT");
            service.DeleteOwnedService(snapshot);
            UpdateUninstallJournalPhase(installRoot, "service-deleted");
            if (FaultEnabled(fakeFailureMode, "crash-after-service-delete")) Environment.Exit(91);
            if (FaultEnabled(fakeFailureMode, "after-service-delete")) throw new IOException("BF-SETUP-FAULT");
            if (purge)
            {
                var journal = ReadUninstallJournal(installRoot);
                UpdateUninstallJournalBindingPhase(installRoot, "intent");
                if (FaultEnabled(fakeFailureMode, "crash-after-binding-intent")) Environment.Exit(91);
                journal = ReadUninstallJournal(installRoot);
                RenamePurgeIpcBinding(installRoot, tombstone, testRoot, journal);
                if (FaultEnabled(fakeFailureMode, "crash-after-binding-rename")) Environment.Exit(91);
                UpdateUninstallJournalBindingPhase(installRoot, "renamed");
                if (FaultEnabled(fakeFailureMode, "crash-after-binding-phase")) Environment.Exit(91);
                UpdateUninstallJournalBindingPhase(installRoot, "cleanup");
                journal = ReadUninstallJournal(installRoot);
                CleanupPurgeIpcBinding(journal, testRoot, fakeFailureMode, allowCrashMidCleanup: true);
                UpdateUninstallJournalBindingPhase(installRoot, "deleted");
                if (FaultEnabled(fakeFailureMode, "crash-after-binding-cleanup")) Environment.Exit(91);
                UpdateUninstallJournalPhase(installRoot, "binding-deleted");
            }
            else
            {
                var preserved = testRoot ? new[] { ".bifrost-user-data", ".bifrost-recovery", ".bifrost-ipc" } : new[] { ".bifrost-user-data", ".bifrost-recovery" };
                var uninstallJournal = ReadUninstallJournal(installRoot);
                PrepareCleanUninstalledRoot(installRoot, tombstone, cleanRoot, preserved, installId, uninstallJournal);
                if (FaultEnabled(fakeFailureMode, "crash-after-marker")) Environment.Exit(91);
                if (FaultEnabled(fakeFailureMode, "after-marker")) throw new IOException("BF-SETUP-FAULT");
                UpdateUninstallJournalPhase(installRoot, "data-moved");
                if (FaultEnabled(fakeFailureMode, "crash-after-data-moved")) Environment.Exit(91);
            }
            UpdateUninstallJournalPhase(installRoot, "committed");
            if (FaultEnabled(fakeFailureMode, "crash-after-committed")) Environment.Exit(91);
            EnsureNoReparseChain(tombstone, allowMissingLeaf: false);
            ValidateOwnedTree(tombstone);
            if (!TryDeleteResult(tombstone))
                ScheduleValidatedTreeDeletionAtRebootBestEffort(tombstone);
            if (FaultEnabled(fakeFailureMode, "crash-after-tombstone-delete")) Environment.Exit(91);
            if (!purge && Directory.Exists(cleanRoot) && !Directory.Exists(installRoot)) Directory.Move(cleanRoot, installRoot);
            if (purge && Directory.Exists(installRoot)) { ValidateUninstallEntries(installRoot); Directory.Delete(installRoot, true); }
            ClearUninstallJournal(installRoot);
            if (!testRoot) RemoveWindowsUninstallEntry(installRoot);
            if (purge && installLock is not null)
            {
                installLock.Dispose();
                if (!TryDeleteResult(ResolveExternalInstallLockPath(installRoot))) throw new InvalidDataException("BF-SETUP-LOCK");
            }
            if (purge) PurgeClientRuntimeState(installRoot, updateRoot, testRoot);
            if (helper && !testRoot) ScheduleUninstallHelperCleanup();
            return 0;
        }
        catch (Exception error)
        {
            // Keep the authenticated journal as the single recovery authority.
            // A non-crash failure is immediately driven through the same
            // recovery routine used by a fresh process; if that cannot prove a
            // complete old/new tuple, the journal is deliberately left behind.
            try { RecoverUninstallJournal(installRoot, testRoot, fakeServiceMode, updateRoot); } catch { }
            // Preserve the causal chain for the TEST-ONLY trace and local
            // diagnostics while the shipping handoff continues to expose only
            // the bounded stable BF-SETUP-UNINSTALL code.
            throw new InvalidDataException("BF-SETUP-UNINSTALL", error);
        }
        finally
        {
            if (previousState is not null) CryptographicOperations.ZeroMemory(previousState);
            if (previousPointer is not null) CryptographicOperations.ZeroMemory(previousPointer);
            if (previousOwnership is not null) CryptographicOperations.ZeroMemory(previousOwnership);
        }
    }

    private static void ValidateUninstallEntries(string installRoot)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Bifrost.exe", "BifrostSetup.exe", StateDirectoryName, ".bifrost-generations", ".bifrost-protected", ".bifrost-backup", ".bifrost-updater", ".bifrost-ipc", ".bifrost-user-data", ".bifrost-recovery"
        };
        foreach (var entry in Directory.EnumerateFileSystemEntries(installRoot, "*", SearchOption.TopDirectoryOnly))
        {
            var name = Path.GetFileName(entry);
            if (!allowed.Contains(name)) throw new InvalidDataException("BF-SETUP-OWNERSHIP");
            EnsureNoReparseChain(entry, allowMissingLeaf: false);
            ValidateOwnedTree(entry);
        }
    }

    private static void ValidateOwnedTree(string root)
    {
        if (File.Exists(root))
        {
            using var handle = OpenVerifiedHandle(root);
            return;
        }
        foreach (var entry in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
        {
            var attributes = File.GetAttributes(entry);
            if (attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException("BF-SETUP-REPARSE");
            if (!Directory.Exists(entry))
            {
                using var handle = OpenVerifiedHandle(entry);
            }
        }
    }

    private static int Rollback(string? installRootText, string? updateRootText, bool testRoot, string? fakeServiceMode, string? fakeFailureMode, bool whatIf)
    {
        var installRoot = ResolveInstallRoot(installRootText, testRoot);
        EnsureNoReparseChain(installRoot, allowMissingLeaf: true);
        using FileStream? installLock = whatIf ? null : AcquireInstallLock(installRoot);
        if (whatIf) { ValidateUninstallJournalReadOnly(installRoot); ValidatePromotionJournalReadOnly(installRoot); }
        else { RecoverUninstallJournal(installRoot, testRoot, fakeServiceMode, updateRootText); RecoverPromotionJournal(installRoot, testRoot); }
        EnsureNoReparseChain(installRoot, allowMissingLeaf: false);
        _ = ReadOwnership(installRoot, testRoot);
        var pointerPath = Path.Combine(ResolveStateRoot(installRoot), "current.json");
        var pointer = ReadStrictObject(pointerPath, 64 * 1024);
        if (!pointer.TryGetProperty("previous_root", out var previous) || previous.ValueKind != JsonValueKind.String) throw new InvalidDataException("BF-SETUP-ROLLBACK");
        var previousRoot = Path.GetFullPath(previous.GetString()!);
        var installParent = Path.GetDirectoryName(installRoot) ?? throw new InvalidDataException("BF-SETUP-ROLLBACK");
        var previousName = Path.GetFileName(previousRoot);
        var generationParent = Path.Combine(installRoot, ".bifrost-generations");
        var generationRollback = IsContained(generationParent, previousRoot) && !string.Equals(Path.GetFullPath(previousRoot), Path.GetFullPath(generationParent), StringComparison.OrdinalIgnoreCase);
        if (!generationRollback && (!string.Equals(Path.GetDirectoryName(previousRoot), installParent, StringComparison.OrdinalIgnoreCase) || !previousName.StartsWith(Path.GetFileName(installRoot) + ".previous-", StringComparison.OrdinalIgnoreCase))) throw new InvalidDataException("BF-SETUP-ROLLBACK");
        EnsureNoReparseChain(previousRoot, allowMissingLeaf: false);
        if (whatIf) return 0;
        var service = CreateServiceLifecycle(testRoot, fakeServiceMode ?? "success", ResolveUpdateRoot(updateRootText, testRoot), installRoot);
        var snapshot = ServicePreState.None;
        if (generationRollback)
        {
            var currentPayload = pointer.GetProperty("current_payload_root").GetString();
            var currentServicePath = pointer.TryGetProperty("current_service_path", out var currentServiceValue) && currentServiceValue.ValueKind == JsonValueKind.String ? SafeRelative(currentServiceValue.GetString()!) : "windows/service.bin";
            var previousServicePath = pointer.TryGetProperty("previous_service_path", out var previousServiceValue) && previousServiceValue.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(previousServiceValue.GetString()) ? SafeRelative(previousServiceValue.GetString()!) : "windows/service.bin";
            var previousSequence = pointer.TryGetProperty("previous_sequence", out var previousSequenceValue) && previousSequenceValue.TryGetInt64(out var parsedSequence) ? parsedSequence : 0L;
            var previousFloor = pointer.TryGetProperty("previous_floor", out var previousFloorValue) && previousFloorValue.TryGetInt64(out var parsedFloor) ? parsedFloor : 0L;
            var previousEnvelope = pointer.TryGetProperty("previous_envelope_digest", out var previousEnvelopeValue) ? previousEnvelopeValue.GetString() : null;
            var previousAllowlist = pointer.TryGetProperty("previous_allowlist_digest", out var previousAllowlistValue) ? previousAllowlistValue.GetString() : null;
            var previousGeneration = pointer.TryGetProperty("previous_generation", out var previousGenerationValue) ? previousGenerationValue.GetString() : null;
            if (string.IsNullOrWhiteSpace(currentPayload) || previousSequence < 1 || previousFloor < 1 || previousEnvelope is not { Length: 64 } || previousAllowlist is not { Length: 64 } || string.IsNullOrWhiteSpace(previousGeneration) || !pointer.TryGetProperty("previous_state_b64", out var previousStateValue) || previousStateValue.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("BF-SETUP-ROLLBACK");
            byte[] previousState;
            try { previousState = Convert.FromBase64String(previousStateValue.GetString()!); } catch { throw new InvalidDataException("BF-SETUP-ROLLBACK"); }
            var currentStateSnapshot = ReadOptionalState(ResolveStatePath(installRoot));
            var currentPointerSnapshot = ReadOptionalState(pointerPath);
            var currentOwnershipSnapshot = ReadOptionalState(ResolveOwnershipPath(installRoot));
            try
            {
                if (previousState.Length == 0) throw new InvalidDataException("BF-SETUP-ROLLBACK");
                var currentGeneration = pointer.GetProperty("current_generation").GetString() ?? throw new InvalidDataException("BF-SETUP-ROLLBACK");
                var rollbackPointer = new Dictionary<string, object?>
                {
                    ["schema"] = "bifrost-current-v2", ["current_generation"] = previousGeneration,
                    ["previous_generation"] = currentGeneration, ["current_root"] = Path.GetFullPath(installRoot),
                    ["current_payload_root"] = previousRoot, ["previous_root"] = Path.GetFullPath(currentPayload),
                    ["current_service_path"] = previousServicePath, ["previous_service_path"] = currentServicePath,
                    ["sequence"] = previousSequence, ["floor"] = previousFloor,
                    ["envelope_digest"] = previousEnvelope, ["allowlist_digest"] = previousAllowlist,
                    // Preserve the complete former-current tuple so a later
                    // operation can still reason about the exact generation.
                    ["previous_sequence"] = pointer.GetProperty("sequence").GetInt64(),
                    ["previous_floor"] = pointer.GetProperty("floor").GetInt64(),
                    ["previous_envelope_digest"] = pointer.GetProperty("envelope_digest").GetString() ?? "",
                    ["previous_allowlist_digest"] = pointer.GetProperty("allowlist_digest").GetString() ?? "",
                    ["previous_payload_root"] = currentPayload,
                    ["previous_state_b64"] = currentStateSnapshot is null ? "" : Convert.ToBase64String(currentStateSnapshot),
                    ["written_at"] = DateTimeOffset.UtcNow.ToString("O")
                };
                var oldBinary = ResolveContained(previousRoot, previousServicePath);
                if (!File.Exists(oldBinary)) throw new InvalidDataException("BF-SETUP-ROLLBACK");
                snapshot = service.CapturePreState();
                var rollbackOperationId = Guid.NewGuid().ToString("N");
                WritePromotionJournal(installRoot, "rollback-intent", previousSequence, rollbackOperationId, currentPayload!, previousRoot, currentStateSnapshot, currentPointerSnapshot, currentOwnershipSnapshot, fakeFailureMode, snapshot, null, testRoot ? ResolveUpdateRoot(updateRootText, testRoot) : installRoot, operation: "rollback");
                _ = service.StopVerified(snapshot);
                if (FaultEnabled(fakeFailureMode, "crash-after-stop")) Environment.Exit(91);
                WritePromotionJournal(installRoot, "rollback-service", previousSequence, rollbackOperationId, currentPayload!, previousRoot, currentStateSnapshot, currentPointerSnapshot, currentOwnershipSnapshot, fakeFailureMode, snapshot, null, testRoot ? ResolveUpdateRoot(updateRootText, testRoot) : installRoot, operation: "rollback");
                var rollbackResult = service.ReconfigureAndStart(oldBinary, snapshot);
                if (FaultEnabled(fakeFailureMode, "crash-after-service-config")) Environment.Exit(91);
                WritePromotionJournal(installRoot, "rollback-service", previousSequence, rollbackOperationId, currentPayload!, previousRoot, currentStateSnapshot, currentPointerSnapshot, currentOwnershipSnapshot, fakeFailureMode, snapshot, rollbackResult, testRoot ? ResolveUpdateRoot(updateRootText, testRoot) : installRoot, operation: "rollback");
                service.EnsureHealthy();
                if (FaultEnabled(fakeFailureMode, "crash-after-health")) Environment.Exit(91);
                WritePromotionJournal(installRoot, "rollback-healthy", previousSequence, rollbackOperationId, currentPayload!, previousRoot, currentStateSnapshot, currentPointerSnapshot, currentOwnershipSnapshot, fakeFailureMode, snapshot, rollbackResult, testRoot ? ResolveUpdateRoot(updateRootText, testRoot) : installRoot, operation: "rollback");
                WriteAtomic(ResolveStatePath(installRoot), new UTF8Encoding(false, true).GetString(previousState));
                if (FaultEnabled(fakeFailureMode, "crash-after-state")) Environment.Exit(91);
                WritePromotionJournal(installRoot, "rollback-state", previousSequence, rollbackOperationId, currentPayload!, previousRoot, currentStateSnapshot, currentPointerSnapshot, currentOwnershipSnapshot, fakeFailureMode, snapshot, rollbackResult, testRoot ? ResolveUpdateRoot(updateRootText, testRoot) : installRoot, operation: "rollback");
                WriteProtectedPointer(pointerPath, installRoot, rollbackPointer);
                if (FaultEnabled(fakeFailureMode, "crash-after-pointer")) Environment.Exit(91);
                WritePromotionJournal(installRoot, "rollback-pointer", previousSequence, rollbackOperationId, currentPayload!, previousRoot, currentStateSnapshot, currentPointerSnapshot, currentOwnershipSnapshot, fakeFailureMode, snapshot, rollbackResult, testRoot ? ResolveUpdateRoot(updateRootText, testRoot) : installRoot, operation: "rollback");
                UpdateOwnershipGeneration(installRoot, previousGeneration, currentGeneration, testRoot);
                if (FaultEnabled(fakeFailureMode, "crash-after-ownership")) Environment.Exit(91);
                WritePromotionJournal(installRoot, "rollback-ownership", previousSequence, rollbackOperationId, currentPayload!, previousRoot, currentStateSnapshot, currentPointerSnapshot, currentOwnershipSnapshot, fakeFailureMode, snapshot, rollbackResult, testRoot ? ResolveUpdateRoot(updateRootText, testRoot) : installRoot, operation: "rollback");
                ValidateCurrentPointer(installRoot, previousSequence, testRoot);
                _ = ReadOwnership(installRoot, testRoot, verifyBoundFiles: true);
                WritePromotionJournal(installRoot, "committed", previousSequence, rollbackOperationId, currentPayload!, previousRoot, currentStateSnapshot, currentPointerSnapshot, currentOwnershipSnapshot, fakeFailureMode, snapshot, rollbackResult, testRoot ? ResolveUpdateRoot(updateRootText, testRoot) : installRoot, operation: "rollback");
                ClearPromotionJournal(installRoot);
                return 0;
            }
            catch
            {
                try { RestoreState(ResolveStatePath(installRoot), currentStateSnapshot); } catch { }
                try { RestoreState(pointerPath, currentPointerSnapshot); } catch { }
                try { RestoreState(ResolveOwnershipPath(installRoot), currentOwnershipSnapshot); } catch { }
                try { service.RestoreAfterRollback(snapshot); } catch { }
                throw new InvalidDataException("BF-SETUP-ROLLBACK");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(previousState);
                if (currentStateSnapshot is not null) CryptographicOperations.ZeroMemory(currentStateSnapshot);
                if (currentPointerSnapshot is not null) CryptographicOperations.ZeroMemory(currentPointerSnapshot);
                if (currentOwnershipSnapshot is not null) CryptographicOperations.ZeroMemory(currentOwnershipSnapshot);
            }
        }
        var temporary = installRoot + ".rollback-" + Guid.NewGuid().ToString("N");
        try
        {
            snapshot = service.CapturePreState();
            _ = service.StopVerified(snapshot);
            Directory.Move(installRoot, temporary);
            Directory.Move(previousRoot, installRoot);
            var preservedState = Path.Combine(temporary, StateDirectoryName);
            if (Directory.Exists(preservedState)) Directory.Move(preservedState, ResolveStateRoot(installRoot));
            service.RestoreAfterRollback(snapshot);
            service.EnsureHealthy();
            return 0;
        }
        catch
        {
            try { if (Directory.Exists(installRoot)) Directory.Move(installRoot, previousRoot); } catch { }
            try { if (Directory.Exists(temporary)) Directory.Move(temporary, installRoot); } catch { }
            throw new InvalidDataException("BF-SETUP-ROLLBACK");
        }
    }
    private static string? Value(string[] args, string key) { var index = Array.IndexOf(args, key); return index >= 0 && index + 1 < args.Length ? args[index + 1] : null; }
    private static bool FaultEnabled(string? faults, string fault) => faults?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Any(item => string.Equals(item, fault, StringComparison.OrdinalIgnoreCase)) == true;

    private static void SignalVerifiedResidualRootCheckForTest(bool requireVerifiedInstallRoot)
    {
#if BIFROST_TEST_HARNESS
        if (!requireVerifiedInstallRoot) return;
        var signal = Environment.GetEnvironmentVariable("BIFROST_TEST_VERIFIED_RESIDUAL_RACE_SIGNAL");
        if (string.IsNullOrWhiteSpace(signal)) return;
        var fullSignal = Path.GetFullPath(signal);
        File.WriteAllText(fullSignal, "checked", new UTF8Encoding(false));
        var release = fullSignal + ".release";
        var deadline = Environment.TickCount64 + 10_000;
        while (!File.Exists(release))
        {
            if (Environment.TickCount64 >= deadline) throw new InvalidDataException("BF-SETUP-TEST-RACE");
            Thread.Sleep(10);
        }
#endif
    }
    private static bool TryDeleteResult(string? path, bool injectFailure = false)
    {
        if (string.IsNullOrWhiteSpace(path)) return true;
        if (injectFailure) return false;
        // Defender and third-party scanners can briefly retain handles after
        // a just-started self-contained executable exits.  Retry the exact
        // already-validated path; never broaden the deletion scope.
        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
                else if (Directory.Exists(path)) Directory.Delete(path, true);
                if (!File.Exists(path) && !Directory.Exists(path)) return true;
            }
            catch
            {
                if (attempt == 19) return false;
            }
            Thread.Sleep(Math.Min(1000, 100 + (attempt * 75)));
        }
        return false;
    }

    private static string BuildRollbackDiagnostic(Exception primary, string phase)
    {
        var primaryCode = primary.Message.StartsWith("BF-", StringComparison.Ordinal) &&
            primary.Message.Length <= 64 &&
            primary.Message.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-')
            ? primary.Message
            : $"BF-SETUP-INSTALL-{phase}";
        // Keep one bounded, path-free token that reports both facts: the
        // original installation boundary and that cleanup/rollback also had
        // trouble.  This replaces the unhelpful bare BF-SETUP-ROLLBACK.
        var code = primaryCode + "-ROLLBACK";
        return code.Length <= 96 ? code : "BF-SETUP-INSTALL-ROLLBACK";
    }

    private static void ScheduleGenerationTreeDeletionAtRebootBestEffort(string generationParent, string generationRoot)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var parent = Path.GetFullPath(generationParent).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var root = Path.GetFullPath(generationRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (!IsContained(parent, root) || string.Equals(parent, root, StringComparison.OrdinalIgnoreCase) || !Directory.Exists(root))
                return;
            var generationName = Path.GetFileName(root);
            if (!generationName.StartsWith("g-", StringComparison.Ordinal) || generationName.Length is < 3 or > 128 ||
                generationName.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch is not '-' and not '_'))
                return;
            EnsureNoReparseChain(root, allowMissingLeaf: false);

            ScheduleValidatedTreeDeletionAtRebootBestEffort(root);
        }
        catch
        {
            // This is post-commit cleanup. A later successful install can
            // retry scheduling without weakening the current generation.
        }
    }

    private static void ScheduleValidatedTreeDeletionAtRebootBestEffort(string validatedRoot)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var root = Path.GetFullPath(validatedRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (!Directory.Exists(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) return;
            EnsureNoReparseChain(root, allowMissingLeaf: false);
            // Windows cannot unlink a mapped executable until the final kernel
            // process object closes. Register every exact file first, followed
            // by child directories deepest-first and finally the authenticated
            // tree root. MOVEFILE_DELAY_UNTIL_REBOOT is an elevated, same-volume
            // machine operation; no mutable command line or shell is involved.
            foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) return;
                _ = MoveFileExW(Path.GetFullPath(file), null, MoveFileDelayUntilReboot);
            }
            foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                         .OrderByDescending(directory => directory.Count(ch => ch == Path.DirectorySeparatorChar || ch == Path.AltDirectorySeparatorChar)))
            {
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) return;
                _ = MoveFileExW(Path.GetFullPath(directory), null, MoveFileDelayUntilReboot);
            }
            _ = MoveFileExW(root, null, MoveFileDelayUntilReboot);
        }
        catch
        {
            // The ownership-validated uninstall has already committed. A later
            // installer run or reboot can retry this garbage-only cleanup.
        }
    }

    private static void PruneObsoleteGenerationsBestEffort(string installRoot, params string?[] retainedRoots)
    {
        // Pruning is deliberately post-commit and best-effort. The verified
        // current and previous generations remain available for rollback; an
        // old mapped executable, a reparse point or an ACL denial can only
        // leave an obsolete directory behind, never fail a healthy upgrade.
        try
        {
            var generationParent = Path.GetFullPath(Path.Combine(installRoot, ".bifrost-generations"));
            if (!Directory.Exists(generationParent) ||
                (File.GetAttributes(generationParent) & FileAttributes.ReparsePoint) != 0) return;

            var retained = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var root in retainedRoots)
            {
                if (string.IsNullOrWhiteSpace(root)) continue;
                var full = Path.GetFullPath(root);
                if (IsContained(generationParent, full) && !string.Equals(full, generationParent, StringComparison.OrdinalIgnoreCase))
                    retained.Add(full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            }

            foreach (var candidate in Directory.EnumerateDirectories(generationParent, "*", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    var full = Path.GetFullPath(candidate).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    if (!IsContained(generationParent, full) || retained.Contains(full)) continue;
                    if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) continue;
                    EnsureNoReparseChain(full, allowMissingLeaf: false);
                    if (!TryDeleteResult(full))
                        ScheduleGenerationTreeDeletionAtRebootBestEffort(generationParent, full);
                }
                catch
                {
                    // A single obsolete or locked generation must not prevent
                    // the remaining independently validated entries pruning.
                }
            }
        }
        catch
        {
            // The signed upgrade and its rollback pair are already durable.
            // Cleanup can be retried by the next successful installer run.
        }
    }

    private static void TryDelete(string path) { _ = TryDeleteResult(path); }

    private sealed record VerifiedFile(Artifact Metadata, string Source, FileStream? Handle = null);
}
