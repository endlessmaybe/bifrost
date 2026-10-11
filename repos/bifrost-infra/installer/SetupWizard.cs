using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace Bifrost.Setup;

internal static class SetupWizard
{
    internal static int Run(string packageRoot)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        using var form = new SetupWizardForm(Path.GetFullPath(packageRoot));
        Application.Run(form);
        return form.ExitCode;
    }
}

internal sealed class SetupWizardForm : Form
{
    private readonly string _packageRoot;
    private readonly TextBox _installPath = new();
    private readonly Label _heading = new();
    private readonly Label _description = new();
    private readonly Label _detail = new();
    private readonly Button _browse = new();
    private readonly Button _back = new();
    private readonly Button _next = new();
    private readonly ProgressBar _progress = new();
    private readonly CheckBox _launch = new();
    private int _page;
    private bool _installing;
    internal int ExitCode { get; private set; } = 1;

    internal SetupWizardForm(string packageRoot)
    {
        _packageRoot = packageRoot;
        Text = "Bifrost Setup";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = true;
        ClientSize = new Size(700, 450);
        BackColor = Color.FromArgb(7, 18, 22);
        ForeColor = Color.FromArgb(229, 237, 235);
        Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Regular, GraphicsUnit.Point);

        var accent = Color.FromArgb(30, 218, 212);
        var muted = Color.FromArgb(154, 174, 174);

        var brand = new Label
        {
            Text = "BIFROST",
            ForeColor = accent,
            Font = new Font("Segoe UI", 19F, FontStyle.Bold, GraphicsUnit.Point),
            AutoSize = true,
            Location = new Point(38, 30)
        };
        Controls.Add(brand);

        _heading.AutoSize = true;
        _heading.Font = new Font("Microsoft YaHei UI", 20F, FontStyle.Bold, GraphicsUnit.Point);
        _heading.Location = new Point(38, 92);
        Controls.Add(_heading);

        _description.AutoSize = false;
        _description.Size = new Size(615, 52);
        _description.Location = new Point(40, 140);
        _description.ForeColor = muted;
        Controls.Add(_description);

        _detail.AutoSize = false;
        _detail.Size = new Size(615, 72);
        _detail.Location = new Point(40, 245);
        _detail.ForeColor = muted;
        Controls.Add(_detail);

        _installPath.Location = new Point(40, 210);
        _installPath.Size = new Size(500, 30);
        // Prefer the machine's currently registered Bifrost root.  This is
        // important when an older installer left a stale Program Files tree
        // while the live signed installation was later moved to another
        // fixed drive.  The installer validates ownership again before any
        // mutation; this value is only the initial UI target.
        _installPath.Text = Program.PreferredWizardInstallRoot;
        _installPath.BackColor = Color.FromArgb(13, 30, 35);
        _installPath.ForeColor = ForeColor;
        _installPath.BorderStyle = BorderStyle.FixedSingle;
        Controls.Add(_installPath);

        _browse.Text = "Browse...";
        _browse.Location = new Point(555, 207);
        _browse.Size = new Size(100, 34);
        _browse.FlatStyle = FlatStyle.Flat;
        _browse.FlatAppearance.BorderColor = accent;
        _browse.ForeColor = accent;
        _browse.Click += (_, _) => BrowseInstallPath();
        Controls.Add(_browse);

        _progress.Location = new Point(40, 220);
        _progress.Size = new Size(615, 8);
        _progress.Style = ProgressBarStyle.Marquee;
        _progress.MarqueeAnimationSpeed = 25;
        Controls.Add(_progress);

        _launch.Text = "Launch Bifrost after installation";
        _launch.AutoSize = true;
        _launch.Checked = true;
        _launch.Location = new Point(40, 275);
        Controls.Add(_launch);

        _back.Text = "Back";
        _back.Size = new Size(105, 38);
        _back.Location = new Point(430, 382);
        _back.FlatStyle = FlatStyle.Flat;
        _back.Click += (_, _) => { if (!_installing && _page > 0) { _page--; RenderPage(); } };
        Controls.Add(_back);

        _next.Text = "Next";
        _next.Size = new Size(120, 38);
        _next.Location = new Point(545, 382);
        _next.FlatStyle = FlatStyle.Flat;
        _next.FlatAppearance.BorderColor = accent;
        _next.ForeColor = accent;
        _next.Click += NextClicked;
        Controls.Add(_next);

        FormClosing += (_, e) => { if (_installing) e.Cancel = true; };
        RenderPage();
    }

    private void BrowseInstallPath()
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Choose a protected Bifrost installation folder on any fixed local drive. Do not select a drive root or a parent folder writable by ordinary users.",
            ShowNewFolderButton = true,
            SelectedPath = Directory.Exists(_installPath.Text) ? _installPath.Text : Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        var selected = dialog.SelectedPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var volumeRoot = (Path.GetPathRoot(selected) ?? string.Empty).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        _installPath.Text = string.Equals(selected, volumeRoot, StringComparison.OrdinalIgnoreCase) ? Path.Combine(selected, "Bifrost") : selected;
    }

    private async void NextClicked(object? sender, EventArgs e)
    {
        if (_installing) return;
        if (_page == 0)
        {
            try { _installPath.Text = Program.ValidateWizardInstallRoot(_installPath.Text); }
            catch
            {
                MessageBox.Show(this, "Choose a protected folder on any fixed local drive. New installations cannot use drive roots, network/removable locations, symbolic links, user-profile folders, or any parent directory that ordinary users can rename or replace. Program Files is the recommended location.", "Invalid installation location", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            _page = 1;
            RenderPage();
            return;
        }
        if (_page == 1)
        {
            _page = 2;
            _installing = true;
            RenderPage();
            int result;
            try { result = await Task.Run(() => Program.RunWizardInstall(_packageRoot, _installPath.Text)); }
            catch { result = 1; }
            _installing = false;
            if (result == 0)
            {
                ExitCode = 0;
                _page = 3;
                RenderPage();
            }
            else
            {
                _page = 1;
                RenderPage();
                if (IsRecoverableResidual(Program.LastWizardDiagnosticCode) && await TryCleanVerifiedResidualAndRetryAsync()) return;
                var suffix = string.IsNullOrWhiteSpace(Program.LastWizardDiagnosticCode) ? string.Empty : $"\r\n\r\nError code: {Program.LastWizardDiagnosticCode}";
                MessageBox.Show(this, "Installation did not complete. No partial state was marked as a successful installation. Check the selected folder and try again." + suffix, "Bifrost installation failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            return;
        }
        if (_page == 3)
        {
            if (_launch.Checked && !Program.LaunchInstalledApplication(_installPath.Text))
                MessageBox.Show(this, "Bifrost was installed, but it could not be launched automatically. Run Bifrost.exe from the installation folder.", "Bifrost", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Close();
        }
    }

    private static bool IsRecoverableResidual(string? code)
    {
        // A failed installation can preserve its primary diagnostic and add
        // "-ROLLBACK" when rollback cleanup also encountered resistance.
        // Recovery must key off that primary cause as well; otherwise an
        // existing service is recoverable before rollback but becomes an
        // unexplained terminal error after rollback.
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

    private async Task<bool> TryCleanVerifiedResidualAndRetryAsync()
    {
        // The selected installation target is authoritative. A failed cleanup
        // must never manufacture a second Bifrost root beside it; that splits
        // Windows service, uninstall and shortcut state across installations.
        var previousRoot = _installPath.Text;
        _page = 2; _installing = true; RenderPage();
        int cleanup;
        try { cleanup = await Task.Run(() => Program.RunWizardVerifiedCleanup(previousRoot)); } catch { cleanup = 1; }
        if (cleanup != 0)
        {
            _installing = false;
            _page = 1; RenderPage();
            var cleanupSuffix = string.IsNullOrWhiteSpace(Program.LastWizardDiagnosticCode) ? string.Empty : $"\r\n\r\nError code: {Program.LastWizardDiagnosticCode}";
            MessageBox.Show(this, "The existing Bifrost installation could not be cleaned safely. Setup will not create a second Bifrost folder. Close running Bifrost processes or repair the selected folder permissions, then retry the same installation location." + cleanupSuffix, "Bifrost installation failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return true;
        }

        int installed;
        try { installed = await Task.Run(() => Program.RunWizardInstall(_packageRoot, _installPath.Text)); } catch { installed = 1; }
        _installing = false;
        if (installed == 0) { ExitCode = 0; _page = 3; RenderPage(); return true; }
        _page = 1; RenderPage();
        var retrySuffix = string.IsNullOrWhiteSpace(Program.LastWizardDiagnosticCode) ? string.Empty : $"\r\n\r\nError code: {Program.LastWizardDiagnosticCode}";
        MessageBox.Show(this, "Installation did not complete after verified cleanup. Setup kept the same installation location and did not create another Bifrost folder." + retrySuffix, "Bifrost installation failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return true;
    }

    private void RenderPage()
    {
        _installPath.Visible = _page == 0;
        _browse.Visible = _page == 0;
        _progress.Visible = _page == 2;
        _launch.Visible = _page == 3;
        _back.Visible = _page is 1;
        _next.Enabled = !_installing;

        switch (_page)
        {
            case 0:
                _heading.Text = "Choose installation location";
                _description.Text = "Choose a protected Bifrost installation folder on any fixed local drive, for example D:\\Apps\\Bifrost. The default and recommended location is Program Files.";
                _detail.Text = "Because the Bifrost service runs as LocalSystem, Setup also verifies the parent-directory integrity boundary so ordinary users cannot replace the service tree. Existing verified legacy installations remain repairable for migration compatibility.";
                _next.Text = "Next";
                break;
            case 1:
                _heading.Text = "Ready to install";
                _description.Text = "Windows will request administrator permission to write the protected folder and register the system service.";
                _detail.Text = $"Installation location: {_installPath.Text}\r\n\r\nServices and network software outside Bifrost are not modified.";
                _next.Text = "Install";
                break;
            case 2:
                _heading.Text = "Installing Bifrost";
                _description.Text = "Verifying the release, deploying the current generation, and starting BifrostClientService. Do not close this window.";
                _detail.Text = "A partial installation is never marked as successful.";
                _next.Text = "Installing...";
                break;
            default:
                _heading.Text = "Installation completed";
                _description.Text = "Bifrost is installed with a stable launcher. Future updates switch to a verified generation without reinstalling the offline package.";
                _detail.Text = $"Installation location: {_installPath.Text}";
                _next.Text = "Finish";
                break;
        }
    }
}
