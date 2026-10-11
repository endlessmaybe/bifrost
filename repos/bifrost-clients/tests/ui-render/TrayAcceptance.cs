using System.Reflection;
using System.IO;
using System.Windows;
using Bifrost;
using Forms = System.Windows.Forms;

internal static class TrayAcceptance
{
    internal static int Run(string output)
    {
        Directory.CreateDirectory(output);
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        foreach (var dictionary in new[] { "SemanticTokens", "Components", "LightTheme" })
            app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri($"/Bifrost;component/Themes/{dictionary}.xaml", UriKind.Relative) });
        foreach (var protectedState in new[] { false, true })
        {
            UiCaptureContext.Active = true;
            var window = new MainWindow(protectedState ? UiPresentationState.TestProtected() : UiPresentationState.Idle());
            UiCaptureContext.Active = false;
            window.ViewModel.StartAsync().GetAwaiter().GetResult();
            using var menu = new BifrostTrayMenu();
            typeof(MainWindow).GetField("_trayMenu", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window, menu);
            typeof(MainWindow).GetMethod("PopulateTrayMenu", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, null);
            var primary = (Forms.ToolStripMenuItem)menu.Items[1];
            Require(primary.Enabled == window.ViewModel.ConnectCommand.CanExecute(null), "primary action must use the command fence");
            var modes = (Forms.ToolStripMenuItem)menu.Items[4];
            Require(modes.DropDownItems.Count >= 3, "all three proxy modes must be reachable");
            Require(modes.DropDownItems[1].Enabled == window.ViewModel.CanEditConnectionSettings, "mode changes must respect active tunnel ownership");
            if (!protectedState)
            {
                modes.DropDownItems[1].PerformClick();
                Require(window.ViewModel.Mode == "global", "tray mode action must update the production view model");
            }
            else Require(primary.Text == "断开连接", "connected tray must offer direct disconnect");
            foreach (var dark in new[] { false, true })
            {
                menu.ApplyTheme(dark);
                menu.CreateControl();
                menu.Size = menu.GetPreferredSize(System.Drawing.Size.Empty);
                menu.PerformLayout();
                using var bitmap = new System.Drawing.Bitmap(menu.Width, menu.Height);
                menu.DrawToBitmap(bitmap, new System.Drawing.Rectangle(System.Drawing.Point.Empty, menu.Size));
                bitmap.Save(Path.Combine(output, $"tray-{(dark ? "dark" : "light")}-{(protectedState ? "connected" : "idle")}.png"));
            }
            typeof(MainWindow).GetField("_trayMenu", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window, null);
            window.Close();
        }
        app.Shutdown();
        Console.WriteLine("TRAY PASS production menu render, direct connection command fence, three modes and mode action");
        return 0;
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
