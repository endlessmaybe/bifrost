using System;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace Bifrost;

/// <summary>Visible only after an explicit action; the value is never exposed through UI Automation.</summary>
internal sealed class SensitiveRevealTextBlock : TextBlock
{
    protected override AutomationPeer OnCreateAutomationPeer() => new SensitiveRevealAutomationPeer(this);
}

internal sealed class SensitiveRevealAutomationPeer : FrameworkElementAutomationPeer
{
    public SensitiveRevealAutomationPeer(FrameworkElement owner) : base(owner) { }

    protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Custom;
    protected override string GetClassNameCore() => nameof(SensitiveRevealTextBlock);
    protected override string GetNameCore() => "敏感码，默认遮蔽，临时显示内容不提供自动化读取";
    protected override bool IsContentElementCore() => false;
    protected override bool IsControlElementCore() => true;
}

internal sealed class SensitiveCodeDialog : Window
{
    private static readonly TimeSpan RemaskAfter = TimeSpan.FromSeconds(30);
    private readonly SensitiveCodeController _controller;
    private readonly SensitiveRevealState _revealState = new(RemaskAfter);
    private readonly SensitiveClipboardLease _clipboardLease;
    private readonly DispatcherTimer _remaskTimer;
    private readonly DispatcherTimer _clipboardTimer;
    private readonly SensitiveRevealTextBlock _valueText;
    private readonly TextBlock _status;
    // A fixed number of bullets looked like a truncated recovery code.  Do
    // not imply a length while the actual one-time value is deliberately
    // hidden; the user must explicitly reveal it to see the complete code.
    private const string MaskedGlyphs = "已隐藏（点击“显示一次”查看完整代码）";

    public SensitiveCodeDialog(Window owner, SensitiveCodeController controller, string title, string instructions)
    {
        Owner = owner;
        _controller = controller ?? throw new ArgumentNullException(nameof(controller));
        _clipboardLease = new SensitiveClipboardLease(_controller, RemaskAfter);
        Title = title;
        Width = 520;
        Height = 330;
        MinWidth = 420;
        MinHeight = 300;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        WindowStyle = WindowStyle.None;
        Background = Brushes.Transparent;
        SetResourceReference(FontFamilyProperty, "UiFont");

        var frame = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(14), Padding = new Thickness(22) };
        frame.SetResourceReference(Border.BackgroundProperty, "SurfaceElevatedBrush");
        frame.SetResourceReference(Border.BorderBrushProperty, "StrokeBrush");
        var panel = new Grid();
        panel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        panel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        panel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        panel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        panel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var header = new Grid { Margin = new Thickness(0, 0, 0, 14) };
        header.ColumnDefinitions.Add(new ColumnDefinition());
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var heading = new StackPanel();
        var eyebrow = new TextBlock { Text = "一次性敏感信息", FontSize = 11, FontWeight = FontWeights.SemiBold };
        eyebrow.SetResourceReference(TextBlock.ForegroundProperty, "AccentBrush");
        var headingText = new TextBlock { Text = title, FontSize = 21, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 3, 0, 0) };
        headingText.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
        heading.Children.Add(eyebrow); heading.Children.Add(headingText);
        header.Children.Add(heading);
        var close = new Button { Content = "×", Width = 38, Height = 38, MinWidth = 38, MinHeight = 38, Padding = new Thickness(0), Margin = new Thickness(8, 0, 0, 0), ToolTip = "关闭" };
        if (Application.Current.TryFindResource("QuietButton") is Style quietStyle) close.Style = quietStyle;
        close.Click += (_, _) => Close();
        Grid.SetColumn(close, 1); header.Children.Add(close);
        Grid.SetRow(header, 0); panel.Children.Add(header);

        var instructionsText = new TextBlock { Text = instructions, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 14) };
        instructionsText.SetResourceReference(TextBlock.ForegroundProperty, "MutedTextBrush");
        Grid.SetRow(instructionsText, 1); panel.Children.Add(instructionsText);

        _valueText = new SensitiveRevealTextBlock
        {
            Text = MaskedGlyphs,
            FontSize = 17,
            VerticalAlignment = VerticalAlignment.Center,
            Padding = new Thickness(12, 10, 12, 10),
            ToolTip = "默认已遮蔽；点击“显示一次”后仅短暂可见"
        };
        _valueText.SetResourceReference(TextBlock.FontFamilyProperty, "UiFont");
        _valueText.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
        AutomationProperties.SetName(_valueText, "敏感码，默认已遮蔽");
        AutomationProperties.SetHelpText(_valueText, "敏感内容不提供自动化读取");
        var valueFrame = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(9), Child = _valueText };
        valueFrame.SetResourceReference(Border.BackgroundProperty, "InputBrush");
        valueFrame.SetResourceReference(Border.BorderBrushProperty, "HairlineBrush");
        Grid.SetRow(valueFrame, 2); panel.Children.Add(valueFrame);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        var reveal = new Button { Content = "显示一次", MinWidth = 90, Margin = new Thickness(0, 0, 8, 0) };
        reveal.Click += (_, _) => Reveal();
        var copy = new Button { Content = "复制（30 秒）", MinWidth = 110, Margin = new Thickness(0, 0, 8, 0) };
        copy.Click += (_, _) => Copy();
        var acknowledge = new Button { Content = "我已安全保存", MinWidth = 120 };
        if (Application.Current.TryFindResource("PrimaryButton") is Style primaryStyle) acknowledge.Style = primaryStyle;
        acknowledge.Click += (_, _) => Acknowledge();
        buttons.Children.Add(reveal);
        buttons.Children.Add(copy);
        buttons.Children.Add(acknowledge);
        Grid.SetRow(buttons, 3); panel.Children.Add(buttons);

        _status = new TextBlock
        {
            Text = "当前已遮蔽；恢复码/配对码只在本窗口临时显示",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 14, 0, 0)
        };
        _status.SetResourceReference(TextBlock.ForegroundProperty, "MutedTextBrush");
        AutomationProperties.SetName(_status, "敏感码状态");
        Grid.SetRow(_status, 4); panel.Children.Add(_status);
        frame.Child = panel;
        Content = frame;

        _remaskTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = RemaskAfter };
        _remaskTimer.Tick += (_, _) =>
        {
            _remaskTimer.Stop();
            _revealState.Mask();
            RenderMasked("已重新遮蔽；如需查看请再次明确点击显示");
        };
        _clipboardTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = RemaskAfter };
        _clipboardTimer.Tick += (_, _) =>
        {
            var cleared = _clipboardLease.Expire(DateTimeOffset.UtcNow);
            if (cleared && !_clipboardLease.IsArmed)
            {
                _clipboardTimer.Stop();
                _status.Text = "剪贴板已按条件清理；如需使用请再次明确复制";
            }
            else if (!cleared)
            {
                _status.Text = "剪贴板清理失败，仍保留所有权并将重试";
            }
        };
        Deactivated += (_, _) => CloseForBackground();
        Closed += (_, _) =>
        {
            _remaskTimer.Stop();
            if (!_clipboardLease.IsArmed) _clipboardTimer.Stop();
            _revealState.Clear();
            RenderMasked("敏感码已清理");
            _controller.HideValue();
        };
    }

    private void Reveal()
    {
        var now = DateTimeOffset.UtcNow;
        var value = _controller.Reveal(now);
        if (value is null || !_revealState.Reveal(value, now))
        {
            RenderMasked("此敏感码已过期或不可用，请重新生成");
            return;
        }
        _valueText.Text = value;
        _remaskTimer.Stop();
        _remaskTimer.Start();
        _status.Text = "已临时显示，30 秒后自动遮蔽；窗口失焦也会立即遮蔽";
    }

    private void Copy()
    {
        if (_controller.Copy(DateTimeOffset.UtcNow))
        {
            _clipboardLease.Arm(DateTimeOffset.UtcNow);
            _clipboardTimer.Stop();
            _clipboardTimer.Start();
            _status.Text = "已复制；仅当剪贴板仍为本次值时自动清理，30 秒后可重试";
        }
        else
        {
            _status.Text = "复制失败或敏感码已过期；未清理其他剪贴板内容";
        }
    }

    private void Acknowledge()
    {
        if (!_controller.Acknowledge(DateTimeOffset.UtcNow))
        {
            RenderMasked("敏感码已过期或清理失败，请重试");
            return;
        }
        Close();
    }

    private void CloseForBackground()
    {
        _remaskTimer.Stop();
        _revealState.Clear();
        RenderMasked("窗口离开前已遮蔽；已复制内容仍按 30 秒期限清理");
    }

    private void RenderMasked(string status)
    {
        _valueText.Text = MaskedGlyphs;
        _status.Text = status;
    }
}
