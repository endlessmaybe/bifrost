using System.Collections.Immutable;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Automation;
using Microsoft.Win32;
using Bifrost.ClientService;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows.Interop;

namespace Bifrost;

/// WPF-only shell bridge. Service/control/update orchestration, immutable
/// choices, commands, persistence and typed presentation state live in
/// UiShellViewModel; this class only binds controls, renders state and owns
/// window mechanics/sensitive-dialog bridges.
public partial class MainWindow : Window
{
    private static readonly Lazy<ImageSource> AuroraBackgroundSource = new(LoadAuroraBackground);

    public static readonly DependencyProperty IsLightMaterialProperty =
        DependencyProperty.Register(nameof(IsLightMaterial), typeof(bool), typeof(MainWindow), new PropertyMetadata(false));

    /// <summary>Resolved theme material used by the dial, including system theme resolution.</summary>
    public bool IsLightMaterial { get => (bool)GetValue(IsLightMaterialProperty); private set => SetValue(IsLightMaterialProperty, value); }

    // The settings/about surface and package verifier use the same packaged
    // license constants; keeping this property on the shipping window makes
    // the entry operational rather than an unused resource file.
    public string LicenseTitle => LicenseNotice.TitleZh;

    #if false
    private void LegacyLicense_Click(object sender, RoutedEventArgs e)
    {
        // Read only the signed/package-owned, relative license files.  No
        // caller supplied path or shell is involved in the about surface.
        var root = AppContext.BaseDirectory;
        var candidates = new[] { Path.Combine(root, "licenses", "COPYING"), Path.Combine(root, "licenses", "THIRD_PARTY_NOTICES.md"), Path.Combine(root, "licenses", "INSTALLATION_INFORMATION.md"), Path.Combine(root, "licenses", "LICENSES.txt") };
        var available = candidates.Where(File.Exists).Select(path => $"{Path.GetFileName(path)}\n{ReadPackagedText(path)}").ToArray();
        var text = $"{LicenseNotice.TitleZh}\n\n{LicenseNotice.RedistributionTextZh}\n\n已随安装包提供：{string.Join("、", available)}\n来源包：{LicenseNotice.SourceBundlePath}";
        // Kept only for binary compatibility with older XAML snapshots; the
        // shipping button is wired to LicensePaged_Click above.
        _ = text;
    }
    #endif
    private static string ReadPackagedText(string path)
    {
        const int maxBytes = 8 * 1024 * 1024;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        if (stream.Length > maxBytes) throw new InvalidDataException("Packaged license text exceeds the bounded UI limit.");
        using var reader = new StreamReader(stream, new System.Text.UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: true, bufferSize: 64 * 1024, leaveOpen: false);
        return reader.ReadToEnd();
    }

    private void LicensePaged_Click(object sender, RoutedEventArgs e)
    {
        var root = AppContext.BaseDirectory;
        var documents = new[]
        {
            ("COPYING", Path.Combine(root, "licenses", "COPYING")),
            ("THIRD_PARTY_NOTICES.md", Path.Combine(root, "licenses", "THIRD_PARTY_NOTICES.md")),
            ("INSTALLATION_INFORMATION.md", Path.Combine(root, "licenses", "INSTALLATION_INFORMATION.md")),
            ("LICENSES.txt", Path.Combine(root, "licenses", "LICENSES.txt")),
            ("RELEASE-MANIFEST.json", Path.Combine(root, "licenses", "RELEASE-MANIFEST.json"))
        }.Where(item => File.Exists(item.Item2))
         .Select(item => (item.Item1, Text: ReadPackagedText(item.Item2)))
         .ToList();
        var viewer = new LicenseViewerWindow(LicenseNotice.TitleZh, LicenseNotice.RedistributionTextZh, documents) { Owner = this };
        viewer.ShowDialog();
    }

    private sealed class LicenseViewerWindow : Window
    {
        private readonly IReadOnlyList<(string Name, string Text)> _documents;
        private readonly TextBlock _title;
        private readonly TextBlock _body;
        private readonly TextBlock _page;
        private readonly Button _previous;
        private readonly Button _next;
        private int _index;

        internal LicenseViewerWindow(string title, string redistribution, IReadOnlyList<(string Name, string Text)> documents)
        {
            _documents = documents;
            Title = title;
            Width = 860;
            Height = 640;
            MinWidth = 520;
            MinHeight = 360;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ShowInTaskbar = false;
            WindowStyle = WindowStyle.None;
            Background = Brushes.Transparent;
            SetResourceReference(FontFamilyProperty, "UiFont");

            var frame = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(14), Padding = new Thickness(20) };
            frame.SetResourceReference(Border.BackgroundProperty, "SurfaceElevatedBrush");
            frame.SetResourceReference(Border.BorderBrushProperty, "StrokeBrush");
            var root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            root.RowDefinitions.Add(new RowDefinition());
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            var header = new Grid { Margin = new Thickness(0, 0, 0, 12) };
            header.ColumnDefinitions.Add(new ColumnDefinition());
            header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var titleStack = new StackPanel();
            var eyebrow = new TextBlock { Text = "许可证与再分发材料", FontSize = 11, FontWeight = FontWeights.SemiBold };
            eyebrow.SetResourceReference(TextBlock.ForegroundProperty, "AccentBrush");
            _title = new TextBlock { Text = title, FontSize = 21, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 3, 0, 0) };
            _title.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
            titleStack.Children.Add(eyebrow); titleStack.Children.Add(_title);
            header.Children.Add(titleStack);
            var chromeClose = new Button { Content = "×", Width = 38, Height = 38, MinWidth = 38, MinHeight = 38, Padding = new Thickness(0), Margin = new Thickness(8, 0, 0, 0), ToolTip = "关闭" };
            if (Application.Current.TryFindResource("QuietButton") is Style quietStyle) chromeClose.Style = quietStyle;
            chromeClose.Click += (_, _) => Close();
            Grid.SetColumn(chromeClose, 1); header.Children.Add(chromeClose);
            header.MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) DragMove(); };
            Grid.SetRow(header, 0); root.Children.Add(header);

            var notice = new TextBlock { Text = redistribution, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) };
            notice.SetResourceReference(TextBlock.ForegroundProperty, "MutedTextBrush");
            Grid.SetRow(notice, 1); root.Children.Add(notice);

            _body = new TextBlock { TextWrapping = TextWrapping.Wrap, Padding = new Thickness(12), FontSize = 12 };
            _body.SetResourceReference(TextBlock.FontFamilyProperty, "UiFont");
            _body.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
            var bodyFrame = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(9), ClipToBounds = true };
            bodyFrame.SetResourceReference(Border.BackgroundProperty, "InputBrush");
            bodyFrame.SetResourceReference(Border.BorderBrushProperty, "HairlineBrush");
            bodyFrame.Child = new ScrollViewer { Content = _body, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto };
            Grid.SetRow(bodyFrame, 2); root.Children.Add(bodyFrame);

            var controls = new Grid { Margin = new Thickness(0, 12, 0, 0) };
            controls.ColumnDefinitions.Add(new ColumnDefinition());
            controls.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            _page = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
            _page.SetResourceReference(TextBlock.ForegroundProperty, "MutedTextBrush");
            controls.Children.Add(_page);
            var actions = new StackPanel { Orientation = Orientation.Horizontal };
            _previous = new Button { Content = "上一页", MinWidth = 76, Margin = new Thickness(0, 0, 6, 0) };
            _next = new Button { Content = "下一页", MinWidth = 76, Margin = new Thickness(0, 0, 6, 0) };
            var close = new Button { Content = "完成", MinWidth = 76 };
            if (Application.Current.TryFindResource("PrimaryButton") is Style primaryStyle) close.Style = primaryStyle;
            _previous.Click += (_, _) => ShowDocument(_index - 1);
            _next.Click += (_, _) => ShowDocument(_index + 1);
            close.Click += (_, _) => Close();
            actions.Children.Add(_previous); actions.Children.Add(_next); actions.Children.Add(close);
            Grid.SetColumn(actions, 1); controls.Children.Add(actions);
            Grid.SetRow(controls, 3); root.Children.Add(controls);
            frame.Child = root;
            Content = frame;
            Loaded += (_, _) => ShowDocument(0);
        }

        private void ShowDocument(int index)
        {
            if (_documents.Count == 0)
            {
                _title.Text = "GPLv3";
                _body.Text = "当前安装包未包含可读许可证材料。";
                _page.Text = "0/0";
                _previous.IsEnabled = false;
                _next.IsEnabled = false;
                return;
            }
            _index = Math.Clamp(index, 0, _documents.Count - 1);
            var document = _documents[_index];
            _title.Text = document.Name;
            _body.Text = document.Text;
            _page.Text = $"{_index + 1}/{_documents.Count}";
            _previous.IsEnabled = _index > 0;
            _next.IsEnabled = _index < _documents.Count - 1;
        }
    }

    public UiShellViewModel ViewModel { get; }
    private readonly bool _screenshotMode;
    private SensitiveCodeDialog? _sensitiveCodeDialog;
    private bool _smartGateAdvanced;
    private bool _isNarrowViewport;
    private string? _lastRenderedPage;
    private UiConnectionState? _lastRenderedConnectionState;
    private System.Windows.Forms.NotifyIcon? _trayIcon;
    private System.Windows.Forms.ContextMenuStrip? _trayMenu;
    private System.Drawing.Icon? _trayOwnedIcon;
    private const string UiPreferencesRegistryPath = @"Software\Bifrost\DesktopUi";
    private const string StartupRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string StartupRegistryValue = "Bifrost";
    private bool _uiPreferencesLoaded;
    private bool _closeToTrayEnabled = true;
    private bool _forceWindowExit;
    private bool _notificationsEnabled = true;
    private double _uiScalePercent = 100d;
    private readonly SensitiveCodeController _recoveryCodeController = new(new WpfSensitiveClipboard());
    private readonly SensitiveCodeController _pairingCodeController = new(new WpfSensitiveClipboard());

    /// WPF exposes the same client-area animation switch used by Narrator and
    /// high-contrast users.  The dial consumes it to keep the connecting arc
    /// static when motion is disabled; press feedback remains a short opacity
    /// change with a static visual equivalent.
    public bool ReduceMotion => SystemParameters.HighContrast || !SystemParameters.ClientAreaAnimation;

    public MainWindow() : this(null) { }

    internal MainWindow(UiPresentationState? screenshotState)
    {
        _screenshotMode = screenshotState is not null;
        var fixtureState = screenshotState is null ? null : new UiShellState(Presentation: screenshotState, StatusText: screenshotState.StatusText, IsEnrolled: true);
        ViewModel = screenshotState is null
            ? new UiShellViewModel(new ProductionUiShellCoordinator(), new ProtectedUiShellPersistence())
            : new UiShellViewModel(new FixtureUiShellCoordinator(screenshotState), new InMemoryUiShellPersistence(fixtureState!), fixtureState);
        InitializeComponent();
        AuroraBackgroundImage.Source = AuroraBackgroundSource.Value;
        IsVisibleChanged += (_, _) => ApplyPresentationState(ViewModel.Presentation);
        StateChanged += (_, _) => ApplyPresentationState(ViewModel.Presentation);
        DataContext = ViewModel;
        if (!_screenshotMode && !BifrostBuildConstants.LocalEvaluationFixture)
            LoadUiPreferences();
        if (!_screenshotMode && !BifrostBuildConstants.LocalEvaluationFixture)
            InitializeTrayIcon();
        // Size the activity header from both title lines instead of clipping
        // the live timestamp inside a fixed-height row at larger UI scales.
        if (ActivityChartCanvas.Parent is Grid activityChartHost && activityChartHost.RowDefinitions.Count > 0)
            activityChartHost.RowDefinitions[0].Height = GridLength.Auto;
        SourceInitialized += (_, _) =>
        {
            if (PresentationSource.FromVisual(this) is HwndSource source) source.AddHook(WindowMessageHook);
        };
        ViewModel.PropertyChanged += ViewModel_PropertyChanged;
        ViewModel.ProgramUpdateScheduled += ViewModel_ProgramUpdateScheduled;
        ViewModel.ProgramUpdateAvailable += ViewModel_ProgramUpdateAvailable;
        ViewModel.NodeConfigurationUpdated += ViewModel_NodeConfigurationUpdated;
        ViewModel.ProgramUpdatePreparing += ViewModel_ProgramUpdatePreparing;
        ApplyThemeResources(ViewModel.Theme);
        ApplyDesignDirectionResources(ViewModel.DesignDirection);
        ApplyViewportLayout(Width, Height);
        if (BifrostBuildConstants.LocalEvaluationFixture)
        {
            // PasswordBox intentionally exposes no value automation pattern.
            // The isolated fixture uses a TEST-ONLY plain input while keeping
            // the same production EnrollCommand path; ordinary builds never
            // make this control visible.
            InviteBox.Visibility = Visibility.Collapsed;
            TestInviteBox.Visibility = Visibility.Visible;
            if (string.Equals(Environment.GetEnvironmentVariable("BIFROST_TEST_HEADLESS_UI"), "1", StringComparison.Ordinal))
            {
                // The fixture is exercised through UI Automation without
                // presenting a window on the operator desktop.  This branch
                // is compiled into TEST-HARNESS builds only and is not a
                // production visibility policy.
                ShowInTaskbar = false;
                ShowActivated = false;
                WindowStartupLocation = WindowStartupLocation.Manual;
                Left = -10000;
                Top = -10000;
                WindowState = WindowState.Normal;
                SourceInitialized += (_, _) =>
                {
                    var handle = new WindowInteropHelper(this).Handle;
                    if (handle != IntPtr.Zero) HeadlessNative.ShowWindow(handle, HeadlessNative.SW_HIDE);
                };
            }
        }
        RenderState();
        Deactivated += (_, _) =>
        {
            // ShowDialog deactivates its owner before IsVisible becomes true.
            // The assigned dialog owns the sensitive lifecycle throughout that transition.
            if (_sensitiveCodeDialog is not null) return;
            // A hidden TEST-ONLY automation window is intentionally not the
            // active desktop window; do not erase its injected invite between
            // the ValuePattern write and the real EnrollCommand invocation.
            if (!BifrostBuildConstants.LocalEvaluationFixture) ClearAccountSensitiveInputs();
            _recoveryCodeController.HideValue();
            _pairingCodeController.HideValue();
        };
        if (!_screenshotMode)
        {
            ContentRendered += (_, _) =>
            {
                // Let the first usable frame win over control refresh and
                // real-delay work.  Startup owners are intentionally queued
                // at ContextIdle after the shell is already visible.
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.ContextIdle,
                    new Action(() => _ = StartAndResumeAfterUpdateAsync()));
            };
        }
    }

    private static ImageSource LoadAuroraBackground()
    {
        var resourceUri = new Uri("pack://application:,,,/Bifrost;component/Assets/aurora-bg.b64", UriKind.Absolute);
        var resource = Application.GetResourceStream(resourceUri) ?? throw new InvalidDataException("BF-AURORA-RESOURCE");
        using var resourceStream = resource.Stream;
        using var reader = new StreamReader(resourceStream, System.Text.Encoding.ASCII, detectEncodingFromByteOrderMarks: false);
        var encoded = reader.ReadToEnd();
        byte[] bytes;
        try { bytes = Convert.FromBase64String(encoded); }
        catch (FormatException error) { throw new InvalidDataException("BF-AURORA-RESOURCE", error); }
        using var imageStream = new MemoryStream(bytes, writable: false);
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = imageStream;
        image.EndInit();
        image.Freeze();
        return image;
    }

    private void ViewModel_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(UiShellViewModel.Theme) or null) ApplyThemeResources(ViewModel.Theme);
        if (e.PropertyName is nameof(UiShellViewModel.DesignDirection) or null)
        {
            ApplyDesignDirectionResources(ViewModel.DesignDirection);
            ApplyViewportLayout(ActualWidth > 0 ? ActualWidth : Width, ActualHeight > 0 ? ActualHeight : Height);
        }
        if (e.PropertyName is null or nameof(UiShellViewModel.State) or nameof(UiShellViewModel.HasCountryOptions))
            RenderState();
        else if (e.PropertyName == nameof(UiShellViewModel.LiveDownloadSamples))
            ApplyPresentationState(ViewModel.Presentation);
    }

    private void RenderState()
    {
        var state = ViewModel.State;
        AutomationProperties.SetHelpText(this, $"当前页面：{state.Page}；主题：{state.Theme}");
        // Keep navigation deterministic for both WPF bindings and UI
        // Automation: a null PropertyChanged refresh must never leave a
        // collapsed page in the accessibility tree.
        HomePage.Visibility = state.Page == "home" ? Visibility.Visible : Visibility.Collapsed;
        NodesPage.Visibility = state.Page == "nodes" ? Visibility.Visible : Visibility.Collapsed;
        RoutingPage.Visibility = Visibility.Collapsed;
        RoutingModeWorkspace.Visibility = state.Page == "routing" ? Visibility.Visible : Visibility.Collapsed;
        ActivityPage.Visibility = state.Page == "activity" ? Visibility.Visible : Visibility.Collapsed;
        SettingsPage.Visibility = state.Page == "settings" ? Visibility.Visible : Visibility.Collapsed;
        PageTitleText.Text = state.Page switch
        {
            "nodes" => "线路",
            "routing" => "分流",
            "activity" => "活动",
            "settings" => "设置",
            _ => "连接",
        };
        foreach (var nav in NavStack.Children.OfType<Button>())
        {
            var selected = string.Equals(nav.Tag?.ToString(), state.Page, StringComparison.Ordinal);
            nav.IsDefault = selected;
            nav.Background = selected ? (Brush)FindResource("SelectedBrush") : Brushes.Transparent;
        }
        AutomationProperties.SetName(ThemeQuickButton, "设置");
        var smartGate = string.Equals(state.Mode, ProtocolCodes.ModeSmartGate, StringComparison.Ordinal);
        if (!smartGate) _smartGateAdvanced = false;
        SmartGateAdvancedButton.Visibility = Visibility.Collapsed;
        // Source selection is presented as a drill-down list with a signed
        // route count.  Keep the legacy ComboBox only as a non-visual binding
        // bridge for older state fixtures; showing both controls would make
        // the manual workflow ambiguous.
        SourceBox.Visibility = Visibility.Collapsed;
        CountrySelectionCard.Visibility = smartGate ? Visibility.Visible : Visibility.Collapsed;
        FrontSourceBox.Visibility = smartGate && ViewModel.HasCountryOptions ? Visibility.Visible : Visibility.Collapsed;
        foreach (var label in FindNodeLabels())
        {
            if (label.Text is "真实源站") label.Visibility = Visibility.Visible;
            if (label.Text is "国家 / 地区") label.Visibility = smartGate ? Visibility.Visible : Visibility.Collapsed;
        }
        IncludeAppsPanel.Visibility = state.AppPolicyEnabled && state.AppPolicy == "allow" ? Visibility.Visible : Visibility.Collapsed;
        ExcludeAppsPanel.Visibility = state.AppPolicyEnabled && state.AppPolicy == "exclude" ? Visibility.Visible : Visibility.Collapsed;
        IncludeAppsPanel.IsEnabled = state.AppPolicyEnabled && ViewModel.CanEditConnectionSettings;
        ExcludeAppsPanel.IsEnabled = state.AppPolicyEnabled && ViewModel.CanEditConnectionSettings;
        ModeIncludeAppsPanel.Visibility = state.AppPolicyEnabled && state.AppPolicy == "allow" ? Visibility.Visible : Visibility.Collapsed;
        ModeExcludeAppsPanel.Visibility = state.AppPolicyEnabled && state.AppPolicy == "exclude" ? Visibility.Visible : Visibility.Collapsed;
        ModeIncludeAppsPanel.IsEnabled = state.AppPolicyEnabled && ViewModel.CanEditConnectionSettings;
        ModeExcludeAppsPanel.IsEnabled = state.AppPolicyEnabled && ViewModel.CanEditConnectionSettings;
        ApplyPresentationState(state.Presentation);

        if (!string.Equals(_lastRenderedPage, state.Page, StringComparison.Ordinal))
        {
            _lastRenderedPage = state.Page;
            AnimatePageIn(CurrentPageElement(state.Page));
        }
        if (_lastRenderedConnectionState != state.Presentation.State)
        {
            _lastRenderedConnectionState = state.Presentation.State;
            AnimateStateFeedback();
        }
    }

    private FrameworkElement CurrentPageElement(string page) => page switch
    {
        "nodes" => NodesPage,
        "routing" => RoutingModeWorkspace,
        "activity" => ActivityPage,
        "settings" => SettingsPage,
        _ => HomePage,
    };

    /// <summary>
    /// Short page motion explains navigation without delaying repeat actions.
    /// SnapshotAndReplace makes a second navigation interrupt the first one;
    /// Windows' client-animation/high-contrast setting disables the motion.
    /// </summary>
    private void AnimatePageIn(FrameworkElement page)
    {
        if (_screenshotMode || ReduceMotion)
        {
            page.Opacity = 1;
            page.RenderTransform = Transform.Identity;
            return;
        }
        var translate = new TranslateTransform(0, 8);
        page.RenderTransform = translate;
        page.Opacity = 0.55;
        var duration = TimeSpan.FromMilliseconds(180);
        page.BeginAnimation(OpacityProperty, new DoubleAnimation(0.55, 1, duration) { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } }, HandoffBehavior.SnapshotAndReplace);
        translate.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(8, 0, duration) { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } }, HandoffBehavior.SnapshotAndReplace);
    }

    private void AnimateStateFeedback()
    {
        if (_screenshotMode || ReduceMotion) return;
        var duration = TimeSpan.FromMilliseconds(140);
        StatusLamp.BeginAnimation(OpacityProperty, new DoubleAnimation(0.35, 1, duration), HandoffBehavior.SnapshotAndReplace);
        HomeStatusLamp.BeginAnimation(OpacityProperty, new DoubleAnimation(0.62, 1, duration), HandoffBehavior.SnapshotAndReplace);
    }

    private void SmartGateAdvanced_Click(object sender, RoutedEventArgs e)
    {
        _smartGateAdvanced = !_smartGateAdvanced;
        FrontSourceBox.Visibility = _smartGateAdvanced ? Visibility.Visible : Visibility.Collapsed;
        foreach (var label in FindNodeLabels())
            if (label.Text is "高级前置源站") label.Visibility = _smartGateAdvanced ? Visibility.Visible : Visibility.Collapsed;
        SmartGateAdvancedButton.Content = _smartGateAdvanced ? "收起高级设置" : "高级设置（SmartGate）";
    }

    private void OpenSmartGateAdvanced_Click(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.CanEditConnectionSettings) return;
        ViewModel.Mode = ProtocolCodes.ModeSmartGate;
        _smartGateAdvanced = false;
        ViewModel.SetPage("nodes");
        RenderState();
    }

    private void AddApplication_Click(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.CanEditConnectionSettings) return;
        var dialog = new OpenFileDialog
        {
            Title = "选择要加入 Bifrost 应用规则的程序",
            Filter = "Windows 程序 (*.exe)|*.exe",
            Multiselect = true,
            CheckFileExists = true,
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            ViewModel.AddApplicationIdentities(dialog.FileNames.Select(file => Path.GetFileName(file) ?? throw new InvalidDataException("BF-APP-ID")));
            ViewModel.SetPage("routing");
            RenderState();
        }
        catch
        {
            MessageBox.Show(this, "所选文件不能作为应用规则。请选择本机已安装的 .exe 程序。", "Bifrost", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void ViewModel_ProgramUpdateScheduled(long expectedSequence)
    {
        UiLifecycleTrace.Write("update-restart-scheduled");
        if (!Dispatcher.CheckAccess())
        {
            _ = Dispatcher.BeginInvoke(new Action(() => ViewModel_ProgramUpdateScheduled(expectedSequence)));
            return;
        }

        try
        {
            var installRoot = BifrostIpcWire.ResolveInstallRootFromGenerationDirectory(AppContext.BaseDirectory);
            var operationPath = Path.Combine(installRoot, ".bifrost-state", "update-operation.json");
            var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
            while (!_forceWindowExit)
            {
                var state = TryReadUpdateOperationState(operationPath, expectedSequence);
                if (string.Equals(state, "succeeded", StringComparison.Ordinal))
                {
                    ViewModel.SetProgramUpdateCompletionFeedback(true, "更新成功，正在重启", "新版本已安装成功，正在自动重启 Bifrost…");
                    var launcher = Path.Combine(installRoot, "Bifrost.exe");
                    if (!File.Exists(launcher) || (File.GetAttributes(launcher) & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidDataException("BF-UPDATE-RESTART");
                    new UpdateRestartIntentStore().Save(expectedSequence,
                        _updateIntentSequence == expectedSequence && _updateReconnectIntent);
                    _ = Process.Start(new ProcessStartInfo
                    {
                        FileName = launcher,
                        WorkingDirectory = installRoot,
                        UseShellExecute = true,
                    }) ?? throw new InvalidOperationException("BF-UPDATE-RESTART");
                    UiLifecycleTrace.Write("update-launcher-started");
                    CloseForExit();
                    return;
                }
                if (string.Equals(state, "failed", StringComparison.Ordinal))
                {
                    ViewModel.SetProgramUpdateCompletionFeedback(false, "更新安装失败", "新版本安装没有成功，当前版本仍可继续使用；请再次点击“检查更新”重试。");
                    return;
                }
                if (DateTimeOffset.UtcNow >= deadline)
                {
                    ViewModel.SetUpdateMessage("更新仍在后台安装，正在等待安装结果；完成后会自动重启。");
                    deadline = DateTimeOffset.UtcNow.AddMinutes(5);
                }
                await Task.Delay(TimeSpan.FromMilliseconds(250));
            }

        }
        catch
        {
            ViewModel.SetProgramUpdateCompletionFeedback(false, "更新完成但自动重启失败", "新版本切换结果无法自动确认或重启；当前窗口保持打开，请从桌面 Bifrost 快捷方式重新打开。");
        }
    }

    private static string? TryReadUpdateOperationState(string operationPath, long expectedSequence)
    {
        try
        {
            using var stream = new FileStream(operationPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
            if (stream.Length is <= 0 or > 16 * 1024) return null;
            using var document = JsonDocument.Parse(stream);
            var root = document.RootElement;
            if (!root.TryGetProperty("sequence", out var sequence) || !sequence.TryGetInt64(out var actualSequence) || actualSequence != expectedSequence ||
                !root.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.String)
                return null;
            return state.GetString() is "scheduled" or "succeeded" or "failed" ? state.GetString() : null;
        }
        catch
        {
            return null;
        }
    }

    private static class HeadlessNative
    {
        internal const int SW_HIDE = 0;
        [DllImport("user32.dll")] internal static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }

    private const int WmGetMinMaxInfo = 0x0024;
    private const uint MonitorDefaultToNearest = 0x00000002;

    private IntPtr WindowMessageHook(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (message != WmGetMinMaxInfo || lParam == IntPtr.Zero) return IntPtr.Zero;
        var monitor = MonitorFromWindow(hwnd, MonitorDefaultToNearest);
        if (monitor == IntPtr.Zero) return IntPtr.Zero;
        var monitorInfo = new MonitorInfo { Size = Marshal.SizeOf<MonitorInfo>() };
        if (!GetMonitorInfo(monitor, ref monitorInfo)) return IntPtr.Zero;
        var minMax = Marshal.PtrToStructure<MinMaxInfo>(lParam);
        minMax.MaxPosition.X = Math.Abs(monitorInfo.WorkArea.Left - monitorInfo.Monitor.Left);
        minMax.MaxPosition.Y = Math.Abs(monitorInfo.WorkArea.Top - monitorInfo.Monitor.Top);
        minMax.MaxSize.X = Math.Abs(monitorInfo.WorkArea.Right - monitorInfo.WorkArea.Left);
        minMax.MaxSize.Y = Math.Abs(monitorInfo.WorkArea.Bottom - monitorInfo.WorkArea.Top);
        minMax.MaxTrackSize = minMax.MaxSize;
        Marshal.StructureToPtr(minMax, lParam, false);
        handled = true;
        return IntPtr.Zero;
    }

    [StructLayout(LayoutKind.Sequential)] private struct NativePoint { public int X; public int Y; }
    [StructLayout(LayoutKind.Sequential)] private struct MinMaxInfo
    {
        public NativePoint Reserved;
        public NativePoint MaxSize;
        public NativePoint MaxPosition;
        public NativePoint MinTrackSize;
        public NativePoint MaxTrackSize;
    }
    [StructLayout(LayoutKind.Sequential)] private struct NativeRect { public int Left; public int Top; public int Right; public int Bottom; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)] private struct MonitorInfo
    {
        public int Size;
        public NativeRect Monitor;
        public NativeRect WorkArea;
        public uint Flags;
    }
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
    [DllImport("user32.dll", CharSet = CharSet.Auto)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo monitorInfo);

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject root) where T : DependencyObject
    {
        if (root is null) yield break;
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
        {
            var child = VisualTreeHelper.GetChild(root, index);
            if (child is T match) yield return match;
            foreach (var descendant in FindVisualChildren<T>(child)) yield return descendant;
        }
    }

    private IEnumerable<TextBlock> FindNodeLabels()
    {
        // Logical children are available during the offscreen Measure/Arrange
        // capture before WPF has materialised the visual template tree.
        foreach (var label in FindLogicalChildren<TextBlock>(NodesPage)) yield return label;
        foreach (var label in FindVisualChildren<TextBlock>(NodesPage)) yield return label;
    }

    private static IEnumerable<T> FindLogicalChildren<T>(DependencyObject root) where T : DependencyObject
    {
        if (root is null) yield break;
        foreach (var child in LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>())
        {
            if (child is T match) yield return match;
            foreach (var descendant in FindLogicalChildren<T>(child)) yield return descendant;
        }
    }

    private async void Enroll_Click(object sender, RoutedEventArgs e)
    {
        var invite = BifrostBuildConstants.LocalEvaluationFixture ? TestInviteBox.Text : InviteBox.Password;
        if (string.IsNullOrWhiteSpace(invite)) { ViewModel.SetUpdateMessage("激活失败：请输入邀请码或账号恢复码。"); return; }
        var result = await ViewModel.EnrollCommand.ExecuteAsync(new UiShellViewModel.EnrollRequest(invite));
        if (result?.RecoveryCode is { Length: > 0 } recovery)
        {
            if (BifrostBuildConstants.LocalEvaluationFixture)
                ViewModel.SetUpdateMessage("TEST-ONLY 激活成功，恢复码已安全清除");
            else if (!ShowSensitiveCode(_recoveryCodeController, recovery, "Bifrost 恢复码", "完整恢复码已经加密保存在设置中，换设备时可以随时回来查看。你也可以现在复制一份。"))
                ViewModel.SetUpdateMessage("激活成功，但恢复码未能安全显示");
        }
        if (BifrostBuildConstants.LocalEvaluationFixture) TestInviteBox.Clear();
        ClearAccountSensitiveInputs(clearInvite: ViewModel.ShouldClearEnrollmentInvite);
    }

    private async void Recover_Click(object sender, RoutedEventArgs e)
    {
        var code = RecoveryCodeBox.Password.Trim();
        if (string.IsNullOrWhiteSpace(code)) { ViewModel.SetUpdateMessage("请输入另一端的账号恢复码。"); return; }
        // Cross-platform activation fills this platform's vacant account slot.
        // It must not submit the legacy device-replacement approval request.
        await ViewModel.EnrollCommand.ExecuteAsync(new UiShellViewModel.EnrollRequest(code));
        ClearAccountSensitiveInputs();
    }

    private async void RotateRecoveryCode_Click(object sender, RoutedEventArgs e)
    {
        var result = await ViewModel.RotateRecoveryCodeAsync();
        if (result?.RecoveryCode is { Length: > 0 } recovery &&
            !ShowSensitiveCode(_recoveryCodeController, recovery, "Bifrost 恢复码", "新恢复码已经常驻保存在设置中。你也可以现在复制一份到其他安全位置。"))
            ViewModel.SetUpdateMessage("新恢复码已保存，但弹窗未能显示；可直接在设置页复制。");
    }

    private async void CreatePairing_Click(object sender, RoutedEventArgs e)
    {
        var result = await ViewModel.PairCommand.ExecuteAsync(new UiShellViewModel.PairingRequest(""));
        if (result?.PairingCode is { Length: > 0 } pairing && !ShowSensitiveCode(_pairingCodeController, pairing, "Bifrost 配对码", "配对码只显示一次。默认已遮蔽，请明确点击显示或复制。"))
            ViewModel.SetUpdateMessage("配对码未能安全显示");
    }

    private async void RedeemPairing_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.PairCommand.ExecuteAsync(new UiShellViewModel.PairingRequest(PairingCodeInput.Password.Trim()));
        ClearAccountSensitiveInputs();
    }

    private bool ShowSensitiveCode(SensitiveCodeController controller, string value, string title, string instructions)
    {
        if (!controller.Publish(value, DateTimeOffset.UtcNow)) return false;
        var dialog = new SensitiveCodeDialog(this, controller, title, instructions);
        _sensitiveCodeDialog = dialog;
        dialog.Closed += (_, _) => { if (ReferenceEquals(_sensitiveCodeDialog, dialog)) _sensitiveCodeDialog = null; };
        try { dialog.ShowDialog(); }
        finally { if (ReferenceEquals(_sensitiveCodeDialog, dialog)) _sensitiveCodeDialog = null; }
        return true;
    }

    private void CloseSensitiveCodeDialog()
    {
        var dialog = _sensitiveCodeDialog;
        _sensitiveCodeDialog = null;
        if (dialog is not null) { try { dialog.Close(); } catch { } }
        _recoveryCodeController.OnBackground();
        _pairingCodeController.OnBackground();
    }

    private void ClearAccountSensitiveInputs(bool clearInvite = true)
    {
        if (clearInvite)
        {
            InviteBox.Clear();
            if (BifrostBuildConstants.LocalEvaluationFixture) TestInviteBox.Clear();
        }
        RecoveryCodeBox.Clear(); PairingCodeInput.Clear(); RecoveryPublicIdBox.Clear();
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) { WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized; return; }
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }

    private void InitializeTrayIcon()
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath)) return;
        try
        {
            _trayOwnedIcon = System.Drawing.Icon.ExtractAssociatedIcon(processPath);
            if (_trayOwnedIcon is null) return;
            _trayMenu = new BifrostTrayMenu();
            _trayMenu.Opening += (_, _) => PopulateTrayMenu();
            _trayIcon = new System.Windows.Forms.NotifyIcon
            {
                Icon = _trayOwnedIcon,
                Text = "Bifrost",
                Visible = true,
                ContextMenuStrip = _trayMenu,
            };
            _trayIcon.DoubleClick += (_, _) => Dispatcher.BeginInvoke(new Action(RestoreFromTray));
            Closing += Window_Closing;
            Closed += (_, _) => DisposeTrayIcon();
        }
        catch
        {
            DisposeTrayIcon();
        }
    }

    private void MinimizeToTray()
    {
        if (_trayIcon is null) return;
        UiLifecycleTrace.Write("hide-to-tray");
        ShowInTaskbar = false;
        Hide();
    }

    private void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        UiLifecycleTrace.Write(_forceWindowExit ? "explicit-window-exit" : "window-close-request");
        if (_forceWindowExit || !_closeToTrayEnabled || _trayIcon is null) return;
        e.Cancel = true;
        MinimizeToTray();
    }

    private void CloseForExit()
    {
        _forceWindowExit = true;
        Close();
    }

    private void RestoreFromTray()
    {
        if (_trayIcon is null) return;
        UiLifecycleTrace.Write("restore-from-tray");
        ShowInTaskbar = true;
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void DisposeTrayIcon()
    {
        if (_trayIcon is not null)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            _trayIcon = null;
        }
        _trayMenu?.Dispose();
        _trayMenu = null;
        _trayOwnedIcon?.Dispose();
        _trayOwnedIcon = null;
    }

    private void MinimizeWindow_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void MaximizeWindow_Click(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void CloseWindow_Click(object sender, RoutedEventArgs e) => Close();

    private void LoadUiPreferences()
    {
        _uiPreferencesLoaded = false;
        try
        {
            using var preferences = Registry.CurrentUser.CreateSubKey(UiPreferencesRegistryPath, writable: true);
            // CloseToTray is the canonical preference.  Read the historical
            // MinimizeToTray value once as a compatibility fallback so an
            // existing user's choice survives the corrected window semantics.
            _closeToTrayEnabled = ReadRegistryBoolean(preferences, "CloseToTray",
                ReadRegistryBoolean(preferences, "MinimizeToTray", defaultValue: true));
            _notificationsEnabled = ReadRegistryBoolean(preferences, "Notifications", defaultValue: true);
            var scale = Convert.ToDouble(preferences?.GetValue("ScalePercent", 100) ?? 100, System.Globalization.CultureInfo.InvariantCulture);
            _uiScalePercent = Math.Clamp(scale, 80d, 140d);
        }
        catch
        {
            _closeToTrayEnabled = true;
            _notificationsEnabled = true;
            _uiScalePercent = 100d;
        }

        StartupCheckBox.IsChecked = IsStartupEnabled();
        MinimizeToTrayCheckBox.IsChecked = _closeToTrayEnabled;
        NotificationsCheckBox.IsChecked = _notificationsEnabled;
        UiScaleSlider.Value = _uiScalePercent;
        UiScaleValueText.Text = $"{Math.Round(_uiScalePercent):0}%";
        _uiPreferencesLoaded = true;
    }

    private static bool ReadRegistryBoolean(RegistryKey? key, string valueName, bool defaultValue)
    {
        var value = key?.GetValue(valueName);
        return value is int number ? number != 0 : defaultValue;
    }

    private void PersistUiPreference(string valueName, object value)
    {
        if (!_uiPreferencesLoaded) return;
        try
        {
            using var preferences = Registry.CurrentUser.CreateSubKey(UiPreferencesRegistryPath, writable: true);
            preferences?.SetValue(valueName, value, value is int ? RegistryValueKind.DWord : RegistryValueKind.String);
        }
        catch
        {
            // UI preferences are best-effort; a locked-down profile must not
            // prevent the client from connecting or updating.
        }
    }

    private static bool IsStartupEnabled()
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath)) return false;
        try
        {
            using var run = Registry.CurrentUser.OpenSubKey(StartupRegistryPath, writable: false);
            var configured = run?.GetValue(StartupRegistryValue)?.ToString()?.Trim();
            if (string.IsNullOrWhiteSpace(configured)) return false;
            var expected = $"\"{processPath}\"";
            return string.Equals(configured, expected, StringComparison.OrdinalIgnoreCase)
                   || string.Equals(configured.Trim('"'), processPath, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private void StartupCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        if (!_uiPreferencesLoaded || sender is not CheckBox checkBox) return;
        var enabled = checkBox.IsChecked == true;
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath)) { checkBox.IsChecked = false; return; }
        try
        {
            using var run = Registry.CurrentUser.OpenSubKey(StartupRegistryPath, writable: true);
            if (run is null) throw new InvalidOperationException("Windows startup registry key is unavailable.");
            if (enabled) run.SetValue(StartupRegistryValue, $"\"{processPath}\"", RegistryValueKind.String);
            else run.DeleteValue(StartupRegistryValue, throwOnMissingValue: false);
        }
        catch
        {
            _uiPreferencesLoaded = false;
            checkBox.IsChecked = IsStartupEnabled();
            _uiPreferencesLoaded = true;
        }
    }

    private void MinimizeToTrayCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        if (!_uiPreferencesLoaded || sender is not CheckBox checkBox) return;
        _closeToTrayEnabled = checkBox.IsChecked == true;
        PersistUiPreference("CloseToTray", _closeToTrayEnabled ? 1 : 0);
    }

    private void NotificationsCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        if (!_uiPreferencesLoaded || sender is not CheckBox checkBox) return;
        _notificationsEnabled = checkBox.IsChecked == true;
        PersistUiPreference("Notifications", _notificationsEnabled ? 1 : 0);
    }

    private void UiScaleSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (UiScaleValueText is null) return;
        _uiScalePercent = Math.Clamp(e.NewValue, 80d, 140d);
        UiScaleValueText.Text = $"{Math.Round(_uiScalePercent):0}%";
        if (_uiPreferencesLoaded) PersistUiPreference("ScalePercent", (int)Math.Round(_uiScalePercent));
        if (IsInitialized)
            ApplyViewportLayout(ActualWidth > 0 ? ActualWidth : Width, ActualHeight > 0 ? ActualHeight : Height);
    }

    private void Window_SizeChanged(object sender, SizeChangedEventArgs e) => ApplyViewportLayout(e.NewSize.Width, e.NewSize.Height);

    /// <summary>
    /// One shell and one connection page. Cards reflow using available space
    /// and the saved text scale; Windows remains responsible for monitor DPI.
    /// </summary>
    internal void ApplyViewportLayout(double width, double height)
    {
        if (width <= 0 || height <= 0 || SidebarColumn is null) return;
        var shellWidth = Math.Max(1d, width);
        _isNarrowViewport = shellWidth / (_uiScalePercent / 100d) < 900;
        var shellInset = _isNarrowViewport ? 0d : ResourceDouble("ShellInset", 0d);

        // Windows handles monitor DPI. Text follows the explicit saved UI
        // preference, not the window dimensions, so resizing cannot shrink it.
        var fontScale = Math.Clamp(_uiScalePercent / 100d, 0.8d, 1.4d);
        FontSize = 14d * fontScale;
        Resources["TypeDisplay"] = 28d * fontScale;
        Resources["TypeTitle"] = 22d * fontScale;
        Resources["TypeSection"] = 16d * fontScale;
        Resources["TypeBody"] = 14d * fontScale;
        Resources["TypeCaption"] = 12d * fontScale;
        Resources["TypeMicro"] = 11d * fontScale;
        Resources["TypeMetric"] = 18d * fontScale;
        Resources["DashboardMetricSize"] = 29d * fontScale;
        Resources["DashboardTitleSize"] = 30d * fontScale;

        ShellFrame.Margin = new Thickness(shellInset);
        ToolbarRow.Height = new GridLength(62d);
        var desktopSidebarWidth = _isNarrowViewport ? Math.Max(144d, 144d * fontScale) : ResourceDouble("SidebarWidth", 200d);
        SidebarColumn.Width = new GridLength(desktopSidebarWidth);
        FooterSidebarColumn.Width = new GridLength(desktopSidebarWidth);
        InspectorColumn.Width = new GridLength(0d);
        InspectorBorder.Visibility = Visibility.Collapsed;
        ApplyDashboardLayout(shellWidth - desktopSidebarWidth, height - 62d, fontScale);
        ApplyDirectionComposition();
        var stackCards = (shellWidth - desktopSidebarWidth) / fontScale < 1000d;
        ApplyResponsivePageLayouts(stackCards);
        ApplyWorkspaceLayout(stackCards, shellWidth - desktopSidebarWidth, height - 62d, fontScale);
        // A resize preserves the current logical page and its control tree.
        if (ViewModel is not null)
        {
            HomePage.Visibility = ViewModel.Page == "home" ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private void ApplyResponsivePageLayouts(bool narrow)
    {
        // This method can run during construction and again after a resize.
        // XAML must have created the workspace before its named grids can be
        // rearranged; once it has, responsive layout must remain enabled.
        if (CenterWorkspace is null) return;
        if (SettingsLayout is null || ActivityMetricsGrid is null) return;
        static void StackPair(Grid grid, FrameworkElement first, FrameworkElement second, ColumnDefinition firstColumn, ColumnDefinition gapColumn, ColumnDefinition secondColumn, RowDefinition rowGap, bool stack)
        {
            if (stack)
            {
                firstColumn.Width = new GridLength(1, GridUnitType.Star);
                gapColumn.Width = new GridLength(0);
                secondColumn.Width = new GridLength(0);
                rowGap.Height = new GridLength(14);
                Grid.SetColumn(first, 0); Grid.SetRow(first, 0);
                Grid.SetColumn(second, 0); Grid.SetRow(second, 2);
            }
            else
            {
                gapColumn.Width = new GridLength(16);
                secondColumn.Width = new GridLength(1, GridUnitType.Star);
                rowGap.Height = new GridLength(0);
                Grid.SetColumn(first, 0); Grid.SetRow(first, 0);
                Grid.SetColumn(second, 2); Grid.SetRow(second, 0);
            }
        }

        if (narrow)
        {
            NodesFilterColumn.Width = new GridLength(1, GridUnitType.Star);
            StackPair(NodesLayout, NodesFilterCard, NodesCandidatesCard, NodesFilterColumn, NodesGapColumn, NodesCandidatesColumn, NodesRowGap, true);
            StackPair(RoutingLayout, RoutingModeCard, RoutingAppsCard, RoutingModeColumn, RoutingGapColumn, RoutingAppsColumn, RoutingRowGap, true);
            // Settings cards are Borders. Stack all four cards—not just the
            // first desktop pair—so the account/recovery card keeps its
            // auto-sized inputs instead of being clipped beside the update card.
            var settingsCards = new FrameworkElement[] { SettingsGeneralCard, SettingsAppearanceCard, SettingsAccountCard, SettingsUpdateCard };
            SettingsLeftColumn.Width = new GridLength(1, GridUnitType.Star);
            SettingsGapColumn.Width = new GridLength(0);
            SettingsRightColumn.Width = new GridLength(0);
            SettingsTopRow.Height = GridLength.Auto;
            SettingsRowGap.Height = new GridLength(18);
            SettingsBottomRow.Height = GridLength.Auto;
            SettingsNarrowGapOne.Height = new GridLength(18);
            SettingsNarrowThirdRow.Height = GridLength.Auto;
            SettingsNarrowGapTwo.Height = new GridLength(18);
            SettingsNarrowFourthRow.Height = GridLength.Auto;
            for (var index = 0; index < settingsCards.Length; index++)
            {
                Grid.SetColumn(settingsCards[index], 0);
                Grid.SetRow(settingsCards[index], index * 2);
            }

            ActivityMetricsGrid.ColumnDefinitions[0].Width = new GridLength(1, GridUnitType.Star);
            ActivityMetricsGrid.ColumnDefinitions[1].Width = new GridLength(1, GridUnitType.Star);
            ActivityMetricsGrid.ColumnDefinitions[2].Width = new GridLength(0);
            ActivityMetricsGrid.ColumnDefinitions[3].Width = new GridLength(0);
            ActivityMetricRowGap.Height = new GridLength(8);
            Grid.SetColumn(ActivityDownloadMetric, 0); Grid.SetRow(ActivityDownloadMetric, 0); ActivityDownloadMetric.Margin = new Thickness(0, 0, 4, 0);
            Grid.SetColumn(ActivityUploadMetric, 1); Grid.SetRow(ActivityUploadMetric, 0); ActivityUploadMetric.Margin = new Thickness(4, 0, 0, 0);
            Grid.SetColumn(ActivitySessionMetric, 0); Grid.SetRow(ActivitySessionMetric, 2); ActivitySessionMetric.Margin = new Thickness(0, 0, 4, 0);
            Grid.SetColumn(ActivityDurationMetric, 1); Grid.SetRow(ActivityDurationMetric, 2); ActivityDurationMetric.Margin = new Thickness(4, 0, 0, 0);
        }
        else
        {
            NodesFilterColumn.Width = new GridLength(280);
            StackPair(NodesLayout, NodesFilterCard, NodesCandidatesCard, NodesFilterColumn, NodesGapColumn, NodesCandidatesColumn, NodesRowGap, false);
            RoutingModeColumn.Width = new GridLength(1, GridUnitType.Star);
            StackPair(RoutingLayout, RoutingModeCard, RoutingAppsCard, RoutingModeColumn, RoutingGapColumn, RoutingAppsColumn, RoutingRowGap, false);
            var settingsCards = new FrameworkElement[] { SettingsGeneralCard, SettingsAppearanceCard, SettingsAccountCard, SettingsUpdateCard };
            SettingsLeftColumn.Width = new GridLength(1, GridUnitType.Star);
            SettingsGapColumn.Width = new GridLength(20);
            SettingsRightColumn.Width = new GridLength(1, GridUnitType.Star);
            SettingsTopRow.Height = GridLength.Auto;
            SettingsRowGap.Height = new GridLength(20);
            SettingsBottomRow.Height = GridLength.Auto;
            SettingsNarrowGapOne.Height = new GridLength(0);
            SettingsNarrowThirdRow.Height = new GridLength(0);
            SettingsNarrowGapTwo.Height = new GridLength(0);
            SettingsNarrowFourthRow.Height = new GridLength(0);
            Grid.SetColumn(settingsCards[0], 0); Grid.SetRow(settingsCards[0], 0);
            Grid.SetColumn(settingsCards[1], 2); Grid.SetRow(settingsCards[1], 0);
            Grid.SetColumn(settingsCards[2], 0); Grid.SetRow(settingsCards[2], 2);
            Grid.SetColumn(settingsCards[3], 2); Grid.SetRow(settingsCards[3], 2);

            for (var i = 0; i < 4; i++) ActivityMetricsGrid.ColumnDefinitions[i].Width = new GridLength(1, GridUnitType.Star);
            ActivityMetricRowGap.Height = new GridLength(0);
            Grid.SetColumn(ActivityDownloadMetric, 0); Grid.SetRow(ActivityDownloadMetric, 0); ActivityDownloadMetric.Margin = new Thickness(0, 0, 8, 0);
            Grid.SetColumn(ActivityUploadMetric, 1); Grid.SetRow(ActivityUploadMetric, 0); ActivityUploadMetric.Margin = new Thickness(0, 0, 8, 0);
            Grid.SetColumn(ActivitySessionMetric, 2); Grid.SetRow(ActivitySessionMetric, 0); ActivitySessionMetric.Margin = new Thickness(0, 0, 8, 0);
            Grid.SetColumn(ActivityDurationMetric, 3); Grid.SetRow(ActivityDurationMetric, 0); ActivityDurationMetric.Margin = new Thickness(0);
        }
    }

    private double ResourceDouble(string key, double fallback)
    {
        try { return FindResource(key) is double value ? value : fallback; }
        catch { return fallback; }
    }

    private void ApplyDirectionComposition()
    {
        ShellFrame.Effect = null;
    }

    private void ApplyDesignDirectionResources(string? direction)
    {
        var resources = Application.Current?.Resources;
        if (resources is null) return;
        const string file = "DirectionA.xaml";
        var old = resources.MergedDictionaries.FirstOrDefault(dictionary =>
            dictionary.Source?.OriginalString.Contains("Themes/Direction", StringComparison.OrdinalIgnoreCase) == true);
        // Map legacy presentation choices onto the single approved master.
        if (old?.Source?.OriginalString.EndsWith($"Themes/{file}", StringComparison.OrdinalIgnoreCase) == true) return;
        // Add the replacement before removing the previous dictionary. This
        // keeps every DynamicResource resolvable for the whole dispatcher
        // turn and prevents controls from briefly falling back to system UI.
        var replacement = new ResourceDictionary { Source = new Uri($"/Bifrost;component/Themes/{file}", UriKind.Relative) };
        resources.MergedDictionaries.Add(replacement);
        if (old is not null) resources.MergedDictionaries.Remove(old);
    }

    private void ApplyThemeResources(string? theme)
    {
        const string resolved = "DarkTheme.xaml";
        var resources = Application.Current?.Resources;
        if (resources is null) return;
        var old = resources.MergedDictionaries.FirstOrDefault(dictionary => dictionary.Source?.OriginalString.EndsWith("Theme.xaml", StringComparison.OrdinalIgnoreCase) == true);
        IsLightMaterial = false;
        // Null PropertyChanged notifications refresh the whole shell after
        // every click. Reusing the already loaded dark dictionary avoids a
        // remove/add gap in which WPF's default white ListBox brush can flash.
        if (old?.Source?.OriginalString.EndsWith($"Themes/{resolved}", StringComparison.OrdinalIgnoreCase) == true) return;
        var replacement = new ResourceDictionary { Source = new Uri($"/Bifrost;component/Themes/{resolved}", UriKind.Relative) };
        resources.MergedDictionaries.Add(replacement);
        if (old is not null) resources.MergedDictionaries.Remove(old);
    }

    private static bool SystemThemeIsDark()
    {
        if (SystemParameters.HighContrast) return false;
        try { return Convert.ToInt32(Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1)) == 0; }
        catch { return false; }
    }

    private static SolidColorBrush NewBrush(string value) => new((Color)ColorConverter.ConvertFromString(value));

    protected override void OnClosed(EventArgs e)
    {
        ClearAccountSensitiveInputs(); CloseSensitiveCodeDialog();
        ViewModel.PropertyChanged -= ViewModel_PropertyChanged;
        ViewModel.ProgramUpdateScheduled -= ViewModel_ProgramUpdateScheduled;
        ViewModel.ProgramUpdateAvailable -= ViewModel_ProgramUpdateAvailable;
        ViewModel.NodeConfigurationUpdated -= ViewModel_NodeConfigurationUpdated;
        ViewModel.ProgramUpdatePreparing -= ViewModel_ProgramUpdatePreparing;
        ViewModel.Dispose();
        base.OnClosed(e);
    }

    private void ViewModel_NodeConfigurationUpdated(long version)
    {
        if (_screenshotMode) return;
        _trayIcon?.ShowBalloonTip(5000, "节点已更新",
            ViewModel.IsProtected ? "新节点已同步，下次连接即可使用，无需更新软件" : "新节点已同步，可在线路页选择，无需更新软件",
            System.Windows.Forms.ToolTipIcon.Info);
    }
}
