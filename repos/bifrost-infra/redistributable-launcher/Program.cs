using System.Diagnostics;
using System.Drawing;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Bifrost.OfflineSetup;

internal static class Program
{
    internal static string ReleaseSequence => Assembly.GetExecutingAssembly()
        .GetCustomAttributes<AssemblyMetadataAttribute>()
        .Single(attribute => attribute.Key == "BifrostReleaseSequence").Value ?? "unknown";

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 1 && string.Equals(args[0], "--verify", StringComparison.OrdinalIgnoreCase))
            return PayloadRunner.Verify(identityFile: null);
        if (args.Length == 3 && string.Equals(args[0], "--verify", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(args[1], "--identity-file", StringComparison.OrdinalIgnoreCase))
            return PayloadRunner.Verify(args[2]);
        if (args.Length == 3 && string.Equals(args[0], "--install", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(args[1], "--install-root", StringComparison.OrdinalIgnoreCase))
        {
            try { return PayloadRunner.Install(InstallPathPolicy.Validate(args[2])); }
            catch { return 1; }
        }
        if (args.Length == 3 && string.Equals(args[0], "--what-if", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(args[1], "--install-root", StringComparison.OrdinalIgnoreCase))
        {
            try { return PayloadRunner.WhatIfInstall(InstallPathPolicy.Validate(args[2])); }
            catch { return 1; }
        }
        if (args.Length == 1 && string.Equals(args[0], "--version", StringComparison.OrdinalIgnoreCase))
            return 0;
        if (args.Length != 0) return 2;

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        using var form = new OfflineSetupForm();
        Application.Run(form);
        return form.ExitCode;
    }
}

internal sealed class OfflineSetupForm : Form
{
    private readonly TextBox _installPath = new();
    private readonly Button _browse = new();
    private readonly Button _install = new();
    private readonly Button _cancel = new();
    private readonly Label _status = new();
    private readonly ProgressBar _progress = new();
    private bool _busy;

    internal int ExitCode { get; private set; } = 1;

    internal OfflineSetupForm()
    {
        Text = $"Bifrost Offline Setup · r{Program.ReleaseSequence}";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        ClientSize = new Size(720, 470);
        BackColor = Color.FromArgb(7, 18, 22);
        ForeColor = Color.FromArgb(229, 237, 235);
        Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Regular, GraphicsUnit.Point);

        var accent = Color.FromArgb(30, 218, 212);
        var muted = Color.FromArgb(154, 174, 174);
        Controls.Add(new Label
        {
            Text = "BIFROST",
            ForeColor = accent,
            Font = new Font("Segoe UI", 19F, FontStyle.Bold, GraphicsUnit.Point),
            AutoSize = true,
            Location = new Point(40, 30)
        });
        Controls.Add(new Label
        {
            Text = "Choose installation location",
            Font = new Font("Microsoft YaHei UI", 20F, FontStyle.Bold, GraphicsUnit.Point),
            AutoSize = true,
            Location = new Point(40, 90)
        });
        Controls.Add(new Label
        {
            Text = "Install Bifrost in any folder on a fixed local drive. Administrator permission is required to protect the selected folder and register the Windows service.",
            ForeColor = muted,
            AutoSize = false,
            Size = new Size(635, 58),
            Location = new Point(42, 142)
        });

        // Re-running the offline installer should target the installation
        // Windows currently knows about, not blindly collide with an older
        // stale Program Files directory.  The signed inner installer remains
        // the authority for ownership and integrity; this is only a UI hint.
        _installPath.Text = InstallPathPolicy.PreferredInstallRoot();
        _installPath.Location = new Point(42, 216);
        _installPath.Size = new Size(510, 30);
        _installPath.BackColor = Color.FromArgb(13, 30, 35);
        _installPath.ForeColor = ForeColor;
        _installPath.BorderStyle = BorderStyle.FixedSingle;
        Controls.Add(_installPath);

        _browse.Text = "Browse...";
        _browse.Location = new Point(570, 213);
        _browse.Size = new Size(105, 35);
        _browse.FlatStyle = FlatStyle.Flat;
        _browse.FlatAppearance.BorderColor = accent;
        _browse.ForeColor = accent;
        _browse.Click += (_, _) => Browse();
        Controls.Add(_browse);

        Controls.Add(new Label
        {
            Text = "Choose an empty folder or an existing Bifrost installation folder. Do not select a drive root. Files outside the selected folder are not modified.",
            ForeColor = muted,
            AutoSize = false,
            Size = new Size(635, 48),
            Location = new Point(42, 266)
        });

        _status.Text = $"The embedded r{Program.ReleaseSequence} release will be verified before any system changes are made.";
        _status.ForeColor = muted;
        _status.AutoSize = false;
        _status.Size = new Size(635, 48);
        _status.Location = new Point(42, 320);
        Controls.Add(_status);

        _progress.Location = new Point(42, 373);
        _progress.Size = new Size(633, 7);
        _progress.Style = ProgressBarStyle.Marquee;
        _progress.MarqueeAnimationSpeed = 24;
        _progress.Visible = false;
        Controls.Add(_progress);

        _cancel.Text = "Cancel";
        _cancel.Location = new Point(440, 405);
        _cancel.Size = new Size(105, 38);
        _cancel.FlatStyle = FlatStyle.Flat;
        _cancel.Click += (_, _) => Close();
        Controls.Add(_cancel);

        _install.Text = "Install";
        _install.Location = new Point(560, 405);
        _install.Size = new Size(115, 38);
        _install.FlatStyle = FlatStyle.Flat;
        _install.FlatAppearance.BorderColor = accent;
        _install.ForeColor = accent;
        _install.Click += InstallClicked;
        Controls.Add(_install);

        FormClosing += (_, eventArgs) => { if (_busy) eventArgs.Cancel = true; };
    }

    private void Browse()
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Choose the Bifrost installation folder on a fixed local drive.",
            ShowNewFolderButton = true,
            SelectedPath = Directory.Exists(_installPath.Text)
                ? _installPath.Text
                : Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        var selected = Path.GetFullPath(dialog.SelectedPath);
        var root = Path.GetPathRoot(selected);
        _installPath.Text = string.Equals(
            selected.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            root?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase)
            ? Path.Combine(selected, "Bifrost")
            : selected;
    }

    private async void InstallClicked(object? sender, EventArgs eventArgs)
    {
        if (_busy) return;
        string installRoot;
        try { installRoot = InstallPathPolicy.Validate(_installPath.Text); }
        catch
        {
            MessageBox.Show(this, "Choose an absolute folder on a fixed local drive, for example D:\\Apps\\Bifrost. Drive roots, network shares, and relative paths are not supported.", "Invalid installation location", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _installPath.Text = installRoot;
        SetBusy(true, "Extracting and verifying the signed release package...");
        int result;
        try { result = await Task.Run(() => PayloadRunner.Install(installRoot)); }
        catch { result = 1; }
        SetBusy(false, result == 0 ? "Installation completed." : "Installation did not complete. No partial installation was marked as successful.");
        if (result != 0)
        {
            var code = PayloadRunner.LastDiagnosticCode;
            if (IsRecoverableResidual(code) && await TryCleanVerifiedResidualAndRetryAsync(installRoot))
                return;
            var suffix = string.IsNullOrWhiteSpace(code) ? string.Empty : $"\r\n\r\nError code: {code}";
            MessageBox.Show(this, FailureMessage(code) + suffix, "Bifrost", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        CompleteInstallation(installRoot);
    }

    private static bool IsRecoverableResidual(string? code)
    {
        // Preserve the precise rollback diagnostic for display, but make the
        // retry decision from its primary cause. BuildRollbackDiagnostic adds
        // exactly this suffix when both installation and rollback have failed.
        var primary = PrimaryDiagnosticCode(code);
        return primary is
            "BF-SETUP-SCM-SERVICE-EXISTS" or "BF-SETUP-SCM-SERVICE-FOREIGN" or "BF-SETUP-SCM-OWNERSHIP" or
            "BF-SETUP-STATE-CORRUPT" or "BF-SETUP-STATE" or "BF-SETUP-GENERATION" or "BF-SETUP-POINTER" or
            "BF-SETUP-OWNERSHIP" or "BF-SETUP-UNINSTALL" or "BF-SETUP-LOCK";
    }

    private static string? PrimaryDiagnosticCode(string? code) =>
        code is { Length: > 9 } && code.EndsWith("-ROLLBACK", StringComparison.Ordinal)
            ? code[..^9]
            : code;

    private async Task<bool> TryCleanVerifiedResidualAndRetryAsync(string installRoot)
    {
        // Clicking Install identifies the one authoritative target. Resolve
        // verified residue there, but never create Bifrost-Current-N siblings:
        // multiple install roots split service, uninstall and shortcut state.
        var previousRoot = installRoot;
        SetBusy(true, "Cleaning the previous Bifrost installation...");
        int cleanupResult;
        try { cleanupResult = await Task.Run(() => PayloadRunner.CleanupVerifiedInstall(previousRoot)); }
        catch { cleanupResult = 1; }
        if (cleanupResult != 0)
        {
            SetBusy(false, "The existing Bifrost installation could not be cleaned safely.");
            var cleanupCode = PayloadRunner.LastDiagnosticCode;
            var cleanupSuffix = string.IsNullOrWhiteSpace(cleanupCode) ? string.Empty : $"\r\n\r\nError code: {cleanupCode}";
            MessageBox.Show(this, "The existing Bifrost installation could not be cleaned safely. Setup will not create a second Bifrost folder. Close running Bifrost processes or repair the selected folder permissions, then retry the same installation location." + cleanupSuffix, "Bifrost", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return true;
        }

        _installPath.Text = installRoot;
        SetBusy(true, "Previous Bifrost installation was removed. Retrying installation...");
        int installResult;
        try { installResult = await Task.Run(() => PayloadRunner.Install(installRoot)); }
        catch { installResult = 1; }
        SetBusy(false, installResult == 0 ? "Installation completed." : "Installation did not complete after cleanup.");
        if (installResult == 0)
        {
            CompleteInstallation(installRoot);
            return true;
        }

        var retryCode = PayloadRunner.LastDiagnosticCode;
        var retrySuffix = string.IsNullOrWhiteSpace(retryCode) ? string.Empty : $"\r\n\r\nError code: {retryCode}";
        MessageBox.Show(this, FailureMessage(retryCode) + retrySuffix, "Bifrost", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return true;
    }

    private void CompleteInstallation(string installRoot)
    {

        ExitCode = 0;
        var launch = MessageBox.Show(this, "Bifrost was installed successfully. Launch it now?", "Bifrost", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
        if (launch == DialogResult.Yes)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = Path.Combine(installRoot, "Bifrost.exe"),
                    WorkingDirectory = installRoot,
                    UseShellExecute = true
                });
            }
            catch
            {
                MessageBox.Show(this, "Installation completed, but Bifrost could not be launched automatically. Run Bifrost.exe from the selected installation folder.", "Bifrost", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        Close();
    }

    private static string FailureMessage(string? code) => PrimaryDiagnosticCode(code) switch
    {
        "BF-SETUP-SCM-SERVICE-EXISTS" or "BF-SETUP-SCM-SERVICE-FOREIGN" =>
            "Bifrost installation stopped because Windows already has a BifrostClientService service that is not verified as belonging to the selected folder. To protect that service, setup did not replace or delete it. If this is a previous Bifrost installation, uninstall it from its original folder, then run this setup again. Otherwise, ask a Windows administrator to identify the service owner before removing it.",
        "BF-SETUP-SCM-OWNERSHIP" =>
            "Bifrost installation stopped because the existing Bifrost service or its protected installation records did not pass the ownership check. Re-run setup for the original Bifrost folder, or uninstall that previous installation before installing again. Setup did not modify the unverified service.",
        "BF-SETUP-RESIDUAL-SELF" =>
            "Setup is running from the selected previous Bifrost folder, so it cannot remove that folder safely. Move the setup outside that folder and run it again. No Windows service was changed.",
        _ => "Bifrost installation failed. The signature, file integrity, folder security, or Windows service check did not pass."
    };

    private void SetBusy(bool busy, string status)
    {
        _busy = busy;
        _status.Text = status;
        _progress.Visible = busy;
        _install.Enabled = !busy;
        _browse.Enabled = !busy;
        _installPath.Enabled = !busy;
        _cancel.Enabled = !busy;
    }
}

internal static class InstallPathPolicy
{
    private const string UninstallRegistryPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Bifrost";

    internal static string PreferredInstallRoot()
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = machine.OpenSubKey(UninstallRegistryPath, writable: false);
                var registered = key?.GetValue("InstallLocation") as string;
                if (!string.IsNullOrWhiteSpace(registered))
                {
                    var candidate = Validate(registered);
                    if (Directory.Exists(candidate)) return candidate;
                }
            }
            catch
            {
                // A stale, malformed or inaccessible registration is only a
                // failed hint.  Fall back to the ordinary first-install path.
            }
        }
        return Validate(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Bifrost"));
    }

    internal static string Validate(string requested)
    {
        if (string.IsNullOrWhiteSpace(requested) || !Path.IsPathFullyQualified(requested))
            throw new InvalidDataException("BF-OFFLINE-INSTALL-ROOT");
        var candidate = Path.GetFullPath(requested).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var root = Path.GetPathRoot(candidate)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.IsNullOrWhiteSpace(root) || string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("BF-OFFLINE-INSTALL-ROOT");
        if (candidate.StartsWith("\\\\", StringComparison.Ordinal))
            throw new InvalidDataException("BF-OFFLINE-INSTALL-ROOT");
        var drive = new DriveInfo(Path.GetPathRoot(candidate)!);
        if (!drive.IsReady || drive.DriveType != DriveType.Fixed)
            throw new InvalidDataException("BF-OFFLINE-INSTALL-ROOT");
        return candidate;
    }


}

internal static class PayloadRunner
{
    private const string PayloadResource = "Bifrost.Payload.zip";
    internal static string? LastDiagnosticCode { get; private set; }

    internal static int Verify(string? identityFile)
    {
        using var package = ExtractedPackage.Create();
        var diagnosticFile = NewDiagnosticFile();
        try
        {
            var result = RunInner(package.Root, "--verify", "--package-root", package.Root, "--diagnostic-file", diagnosticFile);
            LastDiagnosticCode = result == 0 ? null : ReadDiagnosticCode(diagnosticFile);
            if (result == 0 && identityFile is not null)
                WriteVerifiedIdentity(package.Root, identityFile);
            return result;
        }
        finally { TryDeleteDiagnostic(diagnosticFile); }
    }

    private static void WriteVerifiedIdentity(string packageRoot, string identityFile)
    {
        // Identity is emitted only after the signed inner installer has
        // verified this exact extracted package. Cleanup callers can therefore
        // bind the wrapper to an external current pointer without trusting its
        // filename or mutable assembly metadata.
        if (!Path.IsPathFullyQualified(identityFile))
            throw new InvalidDataException("BF-OFFLINE-IDENTITY-PATH");
        var destination = Path.GetFullPath(identityFile);
        var parent = Path.GetDirectoryName(destination);
        if (string.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent) || File.Exists(destination))
            throw new InvalidDataException("BF-OFFLINE-IDENTITY-PATH");

        var manifestPath = Path.Combine(packageRoot, "RELEASE-MANIFEST.json");
        var signaturePath = Path.Combine(packageRoot, "RELEASE-MANIFEST.sig");
        var manifestBytes = File.ReadAllBytes(manifestPath);
        var signatureBytes = File.ReadAllBytes(signaturePath);
        using var document = JsonDocument.Parse(manifestBytes);
        var sequence = document.RootElement.GetProperty("release_sequence").GetInt64();
        if (sequence <= 0) throw new InvalidDataException("BF-OFFLINE-IDENTITY");
        var metadataArtifact = document.RootElement.GetProperty("build").GetProperty("artifacts").EnumerateArray()
            .Single(artifact => artifact.GetProperty("id").GetString() == "install-metadata");
        var metadataRelative = metadataArtifact.GetProperty("path").GetString();
        if (string.IsNullOrWhiteSpace(metadataRelative) || Path.IsPathFullyQualified(metadataRelative))
            throw new InvalidDataException("BF-OFFLINE-IDENTITY");
        var metadataPath = Path.GetFullPath(Path.Combine(packageRoot, metadataRelative.Replace('/', Path.DirectorySeparatorChar)));
        var packagePrefix = packageRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!metadataPath.StartsWith(packagePrefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("BF-OFFLINE-IDENTITY");
        using var metadata = JsonDocument.Parse(File.ReadAllText(metadataPath, Encoding.UTF8));
        var version = metadata.RootElement.GetProperty("version").GetString();
        if (string.IsNullOrWhiteSpace(version)) throw new InvalidDataException("BF-OFFLINE-IDENTITY");
        var identity = JsonSerializer.Serialize(new
        {
            format = "BIFROST-OFFLINE-IDENTITY-1",
            release_sequence = sequence,
            version,
            manifest_sha256 = Convert.ToHexString(SHA256.HashData(manifestBytes)).ToLowerInvariant(),
            signature_sha256 = Convert.ToHexString(SHA256.HashData(signatureBytes)).ToLowerInvariant()
        });
        using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        output.Write(Encoding.UTF8.GetBytes(identity + Environment.NewLine));
        output.Flush(flushToDisk: true);
    }

    internal static int Install(string installRoot)
    {
        LastDiagnosticCode = null;
        using var package = ExtractedPackage.Create();
        var diagnosticFile = NewDiagnosticFile();
        try
        {
            var verified = RunInner(package.Root, "--verify", "--package-root", package.Root, "--diagnostic-file", diagnosticFile);
            if (verified != 0)
            {
                LastDiagnosticCode = ReadDiagnosticCode(diagnosticFile);
                return verified;
            }
            var installed = RunInner(package.Root, "--install", "--package-root", package.Root, "--install-root", installRoot, "--diagnostic-file", diagnosticFile);
            LastDiagnosticCode = installed == 0 ? null : ReadDiagnosticCode(diagnosticFile);
            return installed;
        }
        finally { TryDeleteDiagnostic(diagnosticFile); }
    }

    internal static int WhatIfInstall(string installRoot)
    {
        LastDiagnosticCode = null;
        using var package = ExtractedPackage.Create();
        var diagnosticFile = NewDiagnosticFile();
        try
        {
            var verified = RunInner(package.Root, "--verify", "--package-root", package.Root, "--diagnostic-file", diagnosticFile);
            if (verified != 0)
            {
                LastDiagnosticCode = ReadDiagnosticCode(diagnosticFile);
                return verified;
            }
            TryDeleteDiagnostic(diagnosticFile);
            var inspected = RunInner(package.Root, "--install", "--what-if", "--package-root", package.Root, "--install-root", installRoot, "--diagnostic-file", diagnosticFile);
            LastDiagnosticCode = inspected == 0 ? null : ReadDiagnosticCode(diagnosticFile);
            return inspected;
        }
        finally { TryDeleteDiagnostic(diagnosticFile); }
    }    // Cleanup intentionally reuses the signed inner installer. It first uses
    // the normal authenticated uninstall path, then falls back to the explicit
    // user-confirmed compatibility cleanup for legacy or incomplete installs.
    internal static int CleanupVerifiedInstall(string installRoot)
    {
        LastDiagnosticCode = null;
        using var package = ExtractedPackage.Create();
        var diagnosticFile = NewDiagnosticFile();
        try
        {
            var verified = RunInner(package.Root, "--verify", "--package-root", package.Root, "--diagnostic-file", diagnosticFile);
            if (verified != 0)
            {
                LastDiagnosticCode = ReadDiagnosticCode(diagnosticFile);
                return verified;
            }
            var cleaned = RunInner(package.Root, "--uninstall", "--install-root", installRoot, "--purge", "--verified-residual-cleanup", "--diagnostic-file", diagnosticFile);
            if (cleaned != 0)
            {
                TryDeleteDiagnostic(diagnosticFile);
                cleaned = RunInner(package.Root, "--uninstall", "--install-root", installRoot, "--purge", "--force-residual-cleanup", "--diagnostic-file", diagnosticFile);
            }
            LastDiagnosticCode = cleaned == 0 ? null : ReadDiagnosticCode(diagnosticFile);
            return cleaned;
        }
        finally { TryDeleteDiagnostic(diagnosticFile); }
    }

    private static string NewDiagnosticFile() =>
        Path.Combine(Path.GetTempPath(), "BifrostOfflineSetup-" + Guid.NewGuid().ToString("N") + ".diagnostic.json");

    private static string? ReadDiagnosticCode(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.SequentialScan);
            if (stream.Length is <= 0 or > 4096) return null;
            using var document = JsonDocument.Parse(stream);
            var code = document.RootElement.GetProperty("code").GetString();
            return code is { Length: > 2 and <= 96 } && code.StartsWith("BF-", StringComparison.Ordinal) &&
                   code.All(character => char.IsAsciiLetterOrDigit(character) || character == '-')
                ? code
                : null;
        }
        catch { return null; }
    }

    private static void TryDeleteDiagnostic(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static int RunInner(string packageRoot, params string[] arguments)
    {
        var installer = FindSignedInnerInstaller(packageRoot);
        if (installer is null) return 1;
        var start = new ProcessStartInfo
        {
            FileName = installer,
            WorkingDirectory = packageRoot,
            UseShellExecute = true
        };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start);
        if (process is null) return 1;
        process.WaitForExit();
        return process.ExitCode;
    }

    private static string? FindSignedInnerInstaller(string packageRoot)
    {
        var rootAlias = Path.Combine(packageRoot, "BifrostSetup.exe");
        if (File.Exists(rootAlias)) return rootAlias;
        var installerRoot = Path.Combine(packageRoot, "windows-installer");
        if (!Directory.Exists(installerRoot)) return null;
        var candidates = Directory.EnumerateFiles(installerRoot, "BifrostSetup.exe", SearchOption.AllDirectories)
            .Where(path => Path.GetRelativePath(installerRoot, path).Split(Path.DirectorySeparatorChar).Length == 2)
            .Take(2)
            .ToArray();
        return candidates.Length == 1 ? candidates[0] : null;
    }

    private sealed class ExtractedPackage : IDisposable
    {
        internal string Root { get; }

        private ExtractedPackage(string root) => Root = root;

        internal static ExtractedPackage Create()
        {
            var root = Path.Combine(Path.GetTempPath(), "BifrostOfflineSetup-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            try
            {
                using var payload = Assembly.GetExecutingAssembly().GetManifestResourceStream(PayloadResource)
                    ?? throw new InvalidDataException("BF-OFFLINE-PAYLOAD");
                using var archive = new ZipArchive(payload, ZipArchiveMode.Read, leaveOpen: false);
                foreach (var entry in archive.Entries)
                {
                    ExtractEntry(root, entry);
                }
                if (FindSignedInnerInstaller(root) is null)
                    throw new InvalidDataException("BF-OFFLINE-PAYLOAD");
                return new ExtractedPackage(root);
            }
            catch
            {
                TryDelete(root);
                throw;
            }
        }

        private static void ExtractEntry(string root, ZipArchiveEntry entry)
        {
            var parts = entry.FullName.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0 || parts.Any(part => part is "." or ".." || part.Contains(':')))
                throw new InvalidDataException("BF-OFFLINE-PAYLOAD-PATH");
            var destination = Path.GetFullPath(Path.Combine(root, Path.Combine(parts)));
            var prefix = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!destination.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("BF-OFFLINE-PAYLOAD-PATH");
            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(destination);
                return;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            using var input = entry.Open();
            using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.SequentialScan);
            input.CopyTo(output, 1024 * 1024);
            output.Flush(flushToDisk: true);
        }

        public void Dispose() => TryDelete(Root);

        private static void TryDelete(string path)
        {
            for (var attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
                    return;
                }
                catch
                {
                    if (attempt == 4) return;
                    Thread.Sleep(150);
                }
            }
        }
    }
}
