using System.Windows.Input;
using Bifrost.ClientService;
using Forms = System.Windows.Forms;

namespace Bifrost;

public partial class MainWindow
{
    private void PopulateTrayMenu()
    {
        if (_trayMenu is not BifrostTrayMenu menu) return;
        menu.ClearEntries();
        menu.Items.Add(new Forms.ToolStripLabel($"Bifrost · {ViewModel.DashboardStatusTitle}\n{ViewModel.SelectedSourceDisplay}  {ViewModel.EffectiveCandidateLabel}")
        {
            Name = "trayStatus", AutoSize = false, Size = new System.Drawing.Size(256, 50),
            TextAlign = System.Drawing.ContentAlignment.MiddleLeft, Padding = new Forms.Padding(12, 3, 0, 6),
        });
        menu.Items.Add(TrayAction(ViewModel.IsProtected ? "断开连接" : ViewModel.PrimaryActionLabel, "\uE7E8",
            ViewModel.ConnectCommand, null));
        menu.Items.Add(BifrostTrayMenu.Action("打开 Bifrost", "\uE8A7", RestoreFromTray));
        menu.Items.Add(new Forms.ToolStripSeparator());
        var modes = new Forms.ToolStripMenuItem("代理模式") { Tag = "\uE774", ShortcutKeyDisplayString = ViewModel.DashboardModeName.Trim() };
        foreach (var (code, name) in new[] { (ProtocolCodes.ModeSmart, "智能选线"), (ProtocolCodes.ModeGlobal, "全局代理"), (ProtocolCodes.ModeSmartGate, "SmartGate") })
        {
            var mode = code;
            var item = BifrostTrayMenu.Action(name, "", () =>
            {
                if (!ViewModel.CanEditConnectionSettings) return;
                ViewModel.Mode = mode;
                if (mode == ProtocolCodes.ModeSmartGate) OpenTrayPage("home");
            }, ViewModel.CanEditConnectionSettings);
            item.Tag = null;
            item.Checked = ViewModel.Mode == code;
            modes.DropDownItems.Add(item);
        }
        if (!ViewModel.CanEditConnectionSettings)
            modes.DropDownItems.Add(new Forms.ToolStripLabel("断开连接后可调整模式") { Enabled = false });
        menu.Items.Add(modes);
        var routes = new Forms.ToolStripMenuItem("线路与节点") { Tag = "\uE8FD" };
        foreach (var route in ViewModel.CandidateRoutes.Take(32))
        {
            var item = TrayAction($"{route.Name}   {route.LatencyText}", "", ViewModel.UseCandidateCommand, route.Code);
            item.Tag = null;
            item.Checked = route.IsSelected;
            item.Enabled = route.CanUse && item.Enabled;
            routes.DropDownItems.Add(item);
        }
        if (routes.HasDropDownItems) routes.DropDownItems.Add(new Forms.ToolStripSeparator());
        routes.DropDownItems.Add(BifrostTrayMenu.Action("管理线路…", "\uE8FD", () => OpenTrayPage("nodes")));
        menu.Items.Add(routes);
        menu.Items.Add(BifrostTrayMenu.Action("活动与诊断", "\uE9D9", () => OpenTrayPage("activity")));
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(BifrostTrayMenu.Action(ViewModel.UpdateActionLabel, "\uE777", () =>
        {
            OpenTrayPage("settings");
            SettingsUpdateCard.BringIntoView();
            if (ViewModel.CheckUpdateCommand.CanExecute(null)) ViewModel.CheckUpdateCommand.Execute(null);
        }, ViewModel.CheckUpdateCommand.CanExecute(null)));
        menu.Items.Add(TrayAction("更新节点", "\uE895", ViewModel.RefreshCommand, null));
        menu.Items.Add(BifrostTrayMenu.Action("设置", "\uE713", () => OpenTrayPage("settings")));
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(BifrostTrayMenu.Action("退出 Bifrost", "\uE8BB", CloseForExit));
        menu.ApplyTheme();
    }

    private Forms.ToolStripMenuItem TrayAction(string label, string glyph, ICommand command, object? parameter)
        => BifrostTrayMenu.Action(label, glyph, () =>
        {
            if (command.CanExecute(parameter)) command.Execute(parameter);
        }, command.CanExecute(parameter));

    private void OpenTrayPage(string page)
    {
        ViewModel.SetPage(page);
        RestoreFromTray();
    }
}
