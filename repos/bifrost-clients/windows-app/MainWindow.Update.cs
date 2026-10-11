using System.IO;
using System.Text.Json;
using System.Windows;
using Bifrost.ClientService;

namespace Bifrost;

public partial class MainWindow
{
    private bool _updateReconnectIntent;
    private long _updateIntentSequence;

    private void ViewModel_ProgramUpdatePreparing(long sequence, bool reconnect)
    {
        _updateIntentSequence = sequence;
        _updateReconnectIntent = reconnect;
    }

    private async void ViewModel_ProgramUpdateAvailable(long sequence)
    {
        if (!IsLoaded || _screenshotMode) return;
        RestoreFromTray();
        var accepted = MessageBox.Show(this,
            "发现已验证的新版本，现在更新吗？\n\n下载期间保持连接。安装需要短暂切换后台服务，完成后会自动恢复此前的连接、线路和设置。",
            "Bifrost · 发现新版本", MessageBoxButton.YesNo, MessageBoxImage.Information, MessageBoxResult.No);
        if (accepted == MessageBoxResult.Yes) await ViewModel.CheckProgramUpdateAsync();
    }

    private async Task StartAndResumeAfterUpdateAsync()
    {
        await ViewModel.StartAsync();
        try
        {
            var root = BifrostIpcWire.ResolveInstallRootFromGenerationDirectory(AppContext.BaseDirectory);
            var path = Path.Combine(root, ".bifrost-state", "current.json");
            if (!File.Exists(path) || new FileInfo(path).Length > 128 * 1024) return;
            using var state = JsonDocument.Parse(File.ReadAllBytes(path));
            var payload = state.RootElement.GetProperty("current_payload_root").GetString();
            if (!string.Equals(Path.GetFullPath(payload!).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)) return;
            if (new UpdateRestartIntentStore().TryConsume(state.RootElement.GetProperty("sequence").GetInt64()))
                await ViewModel.ResumeAfterUpdateAsync();
        }
        catch (Exception error) { UiLifecycleTrace.Write("update-resume-unavailable", error); }
    }
}
