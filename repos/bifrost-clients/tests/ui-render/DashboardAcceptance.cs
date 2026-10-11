using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Bifrost;

/// <summary>Render and exercise the actual WPF shell with a zero-I/O coordinator.</summary>
internal static class DashboardAcceptance
{
    private static readonly List<object> Results = new();
    private static readonly List<string> BindingErrors = new();

    internal static int Run(string output)
    {
        Directory.CreateDirectory(output);
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        foreach (var resource in new[] { "SemanticTokens.xaml", "Components.xaml", "DarkTheme.xaml" })
            app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri($"/Bifrost;component/Themes/{resource}", UriKind.Relative) });
        PresentationTraceSources.DataBindingSource.Listeners.Add(new BindingListener());
        PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Error;
        try
        {
            var originalAxe = BitmapFrame.Create(new Uri("pack://application:,,,/Bifrost;component/Assets/bifrost-teal-rune-symbol-v1.png"));
            var originalAxePixels = Pixels(originalAxe);
            foreach (var (width, height, scale) in new[] { (1440, 900, 100), (1280, 860, 100), (1280, 810, 100), (960, 640, 100), (760, 620, 100), (760, 620, 140), (1280, 860, 140), (960, 640, 80) })
            {
                UiCaptureContext.Active = true;
                var window = new MainWindow(UiPresentationState.Idle());
                UiCaptureContext.Active = false;
                window.ShowInTaskbar = false;
                window.Width = width; window.Height = height;
                window.ViewModel.CandidateMode = "manual";
                window.ViewModel.CandidateLabel = "A-03";
                ((Slider)Element(window, "UiScaleSlider")).Value = scale;
                Check(window.FindName("CompactHomePage") is null, "a second home tree exists");
                var primary = (Button)Element(window, "ConnectButton");
                var mode = (ListBox)Element(window, "ModeBox");
                if (width == 1440 && scale == 100)
                {
                    window.ViewModel.SetPresentation(Connected());
                    window.ViewModel.SetPage("nodes");
                    var routes = (ListBox)Element(window, "CandidateRoutesList");
                    var sourceBinding = System.Windows.Data.BindingOperations.GetBindingBase(routes, ItemsControl.ItemsSourceProperty);
                    routes.ItemsSource = Enumerable.Range(1, 300).Select(i => new UiCandidateRoute($"A-{i:00}", $"A-{i:00}", "205 ms", "可用", "available", true, false)).ToArray();
                    Arrange(window, width, height);
                    var scroller = Descendants<ScrollViewer>(routes).Single();
                    Check(routes.IsEnabled && scroller.IsEnabled, "Connected routes list disables scrolling");
                    Check(scroller.ScrollableHeight > 1000 && scroller.ViewportHeight > 0, "Large routes list has no bounded scroll viewport");
                    scroller.ScrollToBottom();
                    Arrange(window, width, height);
                    Check(scroller.VerticalOffset > 1000, "Cannot scroll to the last routes while connected");
                    Check(routes.ItemContainerGenerator.ContainerFromIndex(299) is ListBoxItem, "Last route cannot be reached");
                    Check(Descendants<ListBoxItem>(routes).Count() < 40, "Routes list stopped virtualizing");
                    Check(Descendants<Button>(routes).All(button => !button.IsEnabled), "Connected route edit fence was removed");
                    Save(window, output, "connected-300-routes-bottom.png", width, height);
                    System.Windows.Data.BindingOperations.SetBinding(routes, ItemsControl.ItemsSourceProperty, sourceBinding!);
                    window.ViewModel.SetPage("home");
                    for (var tick = 0; tick < 120; tick++)
                    {
                        window.ViewModel.SetPresentation(Connected());
                        Arrange(window, width, height);
                        Check(Element(window, "ChartCanvas").ActualHeight <= 200.1, "Home chart grows during telemetry updates");
                    }
                    Results.Add(new { state = "connected-300-routes-scroll-and-120-chart-updates", status = "PASS" });
                }
                foreach (var state in new[] { UiPresentationState.Idle(), Connected(), UiPresentationState.Preparing("正在验证线路…"), UiPresentationState.Reconnecting(), UiPresentationState.Error("连接失败：线路暂不可用，请更换线路后重试。"), Blocked() })
                {
                    window.ViewModel.SetPresentation(state);
                    window.ViewModel.SetPage("home");
                    Arrange(window, width, height);
                    var brandIcon = (Image)Element(window, "SidebarBrandIcon");
                    Check(brandIcon.Source is BitmapSource { PixelWidth: > 0, PixelHeight: > 0 },
                        "Sidebar brand image failed to load from the application resources");
                    if (state.State == UiConnectionState.Idle)
                        Check(Pixels((BitmapSource)brandIcon.Source).SequenceEqual(originalAxePixels),
                            "The original teal axe sidebar emblem was replaced by another icon");
                    if (width >= 1280 && scale == 100)
                        Check(((ScrollViewer)Element(window, "HomePage")).ScrollableHeight < 0.1,
                            $"Default desktop home unexpectedly overflows at {width}x{height}, state={state.State}, scroll={((ScrollViewer)Element(window, "HomePage")).ScrollableHeight}, cards={string.Join(",", new[] { "HomeCommandSurface", "HomeMetricsCard", "HomeActivityCard", "HomeStatusCard" }.Select(name => name + ":" + Element(window, name).ActualHeight))}");
                    Check(primary.Command == window.ViewModel.ConnectCommand, "primary command disconnected");
                    Check(primary.IsEnabled == window.ViewModel.CanUsePrimaryAction, "primary action fence drifted");
                    Check(mode.IsEnabled == window.ViewModel.CanEditConnectionSettings, "mode edits bypass the connection fence");
                    Check(primary.ActualWidth >= 200 && primary.ActualHeight >= 48, "primary target too small");
                    Reach(window, primary, width, height);
                    Reach(window, mode, width, height);
                    if (state.IsProtected)
                    {
                        Check(!window.ViewModel.DashboardStatusDetail.Contains("建立连接"), "connected copy asks to connect again");
                        var points = ((System.Windows.Shapes.Polyline)Element(window, "ChartLine")).Points;
                        Check(points.Count == 60, "full download history is missing");
                        Check(((TextBlock)Element(window, "ChartMaximumLabel")).Text.Contains("MB/s"), "chart rate unit is wrong");
                        ((ScrollViewer)Element(window, "HomePage")).ScrollToTop();
                        Arrange(window, width, height);
                        Save(window, output, $"home-{width}x{height}-{scale}.png", width, height);
                    }
                    Results.Add(new { width, height, scale, state = state.State.ToString(), status = "PASS" });
                }
                window.ViewModel.SetPresentation(UiPresentationState.Idle());
                mode.SelectedValue = ProtocolCodes.ModeSmartGate;
                Arrange(window, width, height);
                Check(window.ViewModel.IsSmartGateMode, "mode binding did not select SmartGate");
                var countries = (ComboBox)Element(window, "HomeSmartGateNodeBox");
                Check(countries.Items.Count > 0, "SmartGate selector lost its options");
                countries.SelectedIndex = 0;
                Arrange(window, width, height);
                Check(window.ViewModel.Country == countries.SelectedValue?.ToString(), "SmartGate selection binding failed");
                Reach(window, countries, width, height);
                if (width == 1280 && scale == 100)
                {
                    ((ScrollViewer)Element(window, "HomePage")).ScrollToTop();
                    Arrange(window, width, height);
                    Save(window, output, "smartgate.png", width, height);
                }
                mode.SelectedValue = ProtocolCodes.ModeGlobal;
                Arrange(window, width, height);
                Check(window.ViewModel.IsGlobalMode, "global mode binding failed");
                mode.SelectedValue = ProtocolCodes.ModeSmart;
                Arrange(window, width, height);
                foreach (var nav in ((Panel)Element(window, "NavStack")).Children.OfType<Button>())
                {
                    nav.Command!.Execute(nav.CommandParameter);
                    Arrange(window, width, height);
                    Check(window.ViewModel.Page == nav.Tag?.ToString(), "navigation binding failed");
                    if (width == 1280 && scale == 100) Save(window, output, $"page-{nav.Tag}.png", width, height);
                    switch (nav.Tag?.ToString())
                    {
                        case "nodes":
                            Reach(window, Element(window, "NodesSummaryCard"), width, height);
                            break;
                        case "routing":
                            foreach (var routingMode in new[] { "smart", "global", "smartgate" })
                            {
                                ((ListBox)Element(window, "ModeWorkspaceBox")).SelectedValue = routingMode;
                                Arrange(window, width, height);
                                var panel = (Panel)Element(window, routingMode == "smart" ? "SmartModePanel" : routingMode == "global" ? "GlobalModePanel" : "SmartGateModePanel");
                                foreach (var card in panel.Children.OfType<Border>()) Reach(window, card, width, height);
                            }
                            ((ListBox)Element(window, "ModeWorkspaceBox")).SelectedValue = "smart";
                            break;
                        case "activity":
                            Reach(window, Element(window, "ActivityChartCanvas"), width, height);
                            break;
                        case "settings":
                            Reach(window, Element(window, "UiScaleSlider"), width, height);
                            break;
                    }
                    if (width == 760 && scale == 140) Save(window, output, $"narrow-{nav.Tag}.png", width, height);
                }
                var updateTitleBefore = window.ViewModel.UpdateStatusTitle;
                ((Button)Element(window, "SidebarUpdateButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Arrange(window, width, height);
                Check(window.ViewModel.IsSettingsPage, "update entry did not navigate to settings");
                Check(window.ViewModel.UpdateStatusTitle != updateTitleBefore, "update entry did not execute the update coordinator");
                Reach(window, Element(window, "CheckUpdateButton"), width, height);
                Check(((Button)Element(window, "CheckUpdateButton")).Command == window.ViewModel.CheckUpdateCommand, "update command was replaced");
                Results.Add(new { width, height, scale, state = "navigation-modes-update", status = "PASS" });
                window.Close();
            }
            Check(BindingErrors.Count == 0, string.Join("\n", BindingErrors.Distinct()));
            File.WriteAllText(Path.Combine(output, "dashboard-validation.json"), JsonSerializer.Serialize(new { status = "PASS", provenance = "Production WPF MainWindow; fixture coordinator and synthetic traffic; no system network changes", scenarios = Results, bindingErrors = BindingErrors }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"PASS unified WPF dashboard: {Results.Count} scenarios; no binding errors");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        finally { app.Shutdown(); }
    }

    private static UiPresentationState Connected()
    {
        var down = Enumerable.Range(0, 60).Select(i => (5.2 + Math.Sin(i * 0.4) * 0.8 + (i > 28 && i < 35 ? 2 : 0)) * 1024 * 1024).ToImmutableArray();
        var up = Enumerable.Range(0, 60).Select(i => (230 + Math.Sin(i * 0.8) * 50) * 1024).ToImmutableArray();
        return new(UiConnectionState.Protected, "已连接", "A", "A-03", "自动", "自动（Mihomo）", MainWindow.FormatChartRate(down[^1]), MainWindow.FormatChartRate(up[^1]), "1.28 GB", "00:42:18", down, true, up);
    }

    private static UiPresentationState Blocked() => new(UiConnectionState.Blocked, "已阻断", "—", "—", "—", "自动", "—", "—", "—", "—", ImmutableArray<double>.Empty);
    private static FrameworkElement Element(MainWindow window, string name) => window.FindName(name) as FrameworkElement ?? throw new Exception($"Missing control {name}");
    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) yield return match;
            foreach (var nested in Descendants<T>(child)) yield return nested;
        }
    }
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static byte[] Pixels(BitmapSource bitmap)
    {
        var normalized = new FormatConvertedBitmap(bitmap, PixelFormats.Bgra32, null, 0);
        var stride = normalized.PixelWidth * 4;
        var pixels = new byte[stride * normalized.PixelHeight];
        normalized.CopyPixels(pixels, stride, 0);
        return pixels;
    }
    private static void Arrange(MainWindow window, int width, int height)
    {
        window.ApplyViewportLayout(width, height);
        var root = (FrameworkElement)window.Content;
        root.Measure(new Size(width, height)); root.Arrange(new Rect(0, 0, width, height)); root.UpdateLayout();
        window.Dispatcher.Invoke(DispatcherPriority.ContextIdle, new Action(root.UpdateLayout));
    }
    private static void Reach(MainWindow window, FrameworkElement control, int width, int height)
    {
        control.BringIntoView(); Arrange(window, width, height);
        var point = control.TransformToAncestor((Visual)window.Content).Transform(new Point());
        Check(control.Visibility == Visibility.Visible && control.ActualWidth > 0 && point.X >= -1 && point.X + control.ActualWidth <= width + 1 && point.Y >= 61 && point.Y + control.ActualHeight <= height + 1,
            $"Unreachable {control.Name} at {width}x{height}: {point} {control.ActualWidth}x{control.ActualHeight}");
    }
    private static void Save(MainWindow window, string output, string name, int width, int height)
    {
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render((Visual)window.Content);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(Path.Combine(output, name)); encoder.Save(stream);
    }
    private sealed class BindingListener : TraceListener
    {
        public override void Write(string? message) { if (!string.IsNullOrEmpty(message)) BindingErrors.Add(message); }
        public override void WriteLine(string? message) => Write(message);
    }
}
