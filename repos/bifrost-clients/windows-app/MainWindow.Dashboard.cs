using System.Collections.Immutable;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Bifrost;

public partial class MainWindow
{
    private void ApplyWorkspaceLayout(bool stack, double width, double height, double fontScale)
    {
        if (NodesLayout is null || ActivityContent is null || SmartSummaryGrid is null) return;
        // Reflow the existing cards; commands, inputs and selection owners
        // stay attached to the same controls at every width.
        NodesFilterColumn.Width = stack ? new GridLength(1, GridUnitType.Star) : new GridLength(220);
        NodesGapColumn.Width = new GridLength(stack ? 0 : 16);
        NodesCandidatesColumn.Width = stack ? new GridLength(0) : new GridLength(1, GridUnitType.Star);
        NodesLayout.ColumnDefinitions[3].Width = new GridLength(stack ? 0 : 16);
        NodesLayout.ColumnDefinitions[4].Width = stack ? new GridLength(0) : new GridLength(230);
        while (NodesLayout.RowDefinitions.Count < 5) NodesLayout.RowDefinitions.Add(new RowDefinition());
        for (var i = 0; i < 5; i++) NodesLayout.RowDefinitions[i].Height = stack
            ? (i % 2 == 0 ? GridLength.Auto : new GridLength(16))
            : (i == 0 ? GridLength.Auto : new GridLength(0));
        Grid.SetRow(NodesFilterCard, 0); Grid.SetColumn(NodesFilterCard, 0);
        Grid.SetRow(NodesCandidatesCard, stack ? 2 : 0); Grid.SetColumn(NodesCandidatesCard, stack ? 0 : 2);
        Grid.SetRow(NodesSummaryCard, stack ? 4 : 0); Grid.SetColumn(NodesSummaryCard, stack ? 0 : 4);
        NodesCandidatesCard.Height = Math.Max(360d, height - 52d);
        NodesCandidatesCard.MaxHeight = NodesCandidatesCard.Height;
        foreach (var panel in new[] { SmartModePanel, GlobalModePanel, SmartGateModePanel })
        {
            while (panel.RowDefinitions.Count < 7) panel.RowDefinitions.Add(new RowDefinition());
            for (var i = 0; i < panel.ColumnDefinitions.Count; i++)
                panel.ColumnDefinitions[i].Width = stack
                    ? (i == 0 ? new GridLength(1, GridUnitType.Star) : new GridLength(0))
                    : (i % 2 == 0 ? new GridLength(1, GridUnitType.Star) : new GridLength(16));
            for (var i = 0; i < panel.RowDefinitions.Count; i++)
                panel.RowDefinitions[i].Height = stack
                    ? (i % 2 == 0 ? GridLength.Auto : new GridLength(16))
                    : (i == 0 || i == 2 ? GridLength.Auto : new GridLength(i == 1 ? 16 : 0));
            var cards = panel.Children.OfType<Border>().ToArray();
            for (var i = 0; i < cards.Length; i++)
            {
                Grid.SetColumn(cards[i], stack || i == 3 ? 0 : i * 2);
                Grid.SetRow(cards[i], stack ? i * 2 : i == 3 ? 2 : 0);
                Grid.SetColumnSpan(cards[i], !stack && i == 3 ? 5 : 1);
            }
        }
        SmartSummaryGrid.RowDefinitions.Clear();
        var summaries = SmartSummaryGrid.Children.OfType<StackPanel>().ToArray();
        for (var i = 0; i < summaries.Length; i++)
        {
            SmartSummaryGrid.ColumnDefinitions[i].Width = !stack || i == 0 ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            if (stack) SmartSummaryGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(summaries[i], stack ? i : 0); Grid.SetColumn(summaries[i], stack ? 0 : i);
            summaries[i].Margin = new Thickness(0, 0, stack ? 0 : 12, stack ? 16 : 0);
        }
        RoutingWorkspaceContent.RowDefinitions[0].Height = GridLength.Auto;
        ModeWorkspaceBox.Margin = new Thickness(0, 0, 0, 16);
        ModeWorkspaceBox.Width = Math.Min(520d * fontScale, Math.Max(1d, width - 82d));
        ActivityContent.MinHeight = Math.Max(0d, height - 48d);
        ActivityContent.RowDefinitions[0].Height = GridLength.Auto;
        ActivityChartCanvas.Height = Math.Clamp(height * 0.38d, 190d, 300d);
    }

    private void ApplyDashboardLayout(double width, double height, double fontScale)
    {
        if (HomeContent is null) return;
        var inset = width < 800 ? 20d : 30d;
        HomePage.Padding = new Thickness(inset, 14, inset, 24);
        // Leave room for the shell stroke and layout rounding at 125% DPI,
        // otherwise a subpixel overflow shows a full-height scrollbar.
        HomeContent.MinHeight = Math.Max(0d, height - 44d);
        // Geometry uses ActualHeight; constrain the viewport so updated
        // polyline bounds cannot expand their own next measure pass.
        ChartCanvas.Height = Math.Clamp(height - 650d * fontScale, 100d, 200d);
        HomeContent.RowDefinitions[2].Height = GridLength.Auto;
        var innerWidth = Math.Max(1d, Math.Min(1200d, width - inset * 2d) - 58d);
        var stackAction = innerWidth / fontScale < 560d;
        HomeActionColumn.Width = stackAction ? new GridLength(0) : GridLength.Auto;
        Grid.SetRow(ConnectButton, stackAction ? 1 : 0);
        Grid.SetColumn(ConnectButton, stackAction ? 0 : 1);
        ConnectButton.HorizontalAlignment = stackAction ? HorizontalAlignment.Left : HorizontalAlignment.Right;
        ConnectButton.Margin = stackAction ? new Thickness(0, 16, 0, 0) : new Thickness(0);
        HomeStatusSummary.Margin = stackAction ? new Thickness(0) : new Thickness(0, 0, 20, 0);
        var stackMode = innerWidth / fontScale < 700d;
        HomeModeLabelColumn.Width = stackMode ? new GridLength(0) : new GridLength(100d * fontScale);
        Grid.SetColumnSpan((UIElement)HomeModeRow.Children[0], stackMode ? 2 : 1);
        Grid.SetRow(ModeBox, stackMode ? 1 : 0);
        Grid.SetColumn(ModeBox, stackMode ? 0 : 1);
        Grid.SetColumnSpan(ModeBox, stackMode ? 2 : 1);
        ModeBox.Width = Math.Max(1d, Math.Min(520d * fontScale, innerWidth - (stackMode ? 0d : 100d * fontScale)));
        HomeMetricsGrid.Columns = innerWidth / fontScale < 760d ? 2 : 4;
    }

    private void SidebarUpdate_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.SetPage("settings");
        SettingsUpdateCard.BringIntoView();
        if (ViewModel.CheckUpdateCommand.CanExecute(null)) ViewModel.CheckUpdateCommand.Execute(null);
    }

    private void TrafficChart_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (ChartLine is not null && ActivityChartLine is not null)
            ApplyPresentationState(ViewModel.Presentation);
    }

    private void ApplyPresentationState(UiPresentationState state)
    {
        // Keep authoritative counters, but avoid geometry allocations while
        // the window is hidden/minimized or neither chart page is being viewed.
        if (!_screenshotMode && (!IsVisible || WindowState == WindowState.Minimized)) return;
        var home = ViewModel.IsHomePage;
        var activity = ViewModel.IsActivityPage;
        if (!home && !activity) return;
        var download = ViewModel.LiveDownloadSamples.IsDefault ? ImmutableArray<double>.Empty : ViewModel.LiveDownloadSamples;
        var upload = ViewModel.LiveUploadSamples.IsDefault ? ImmutableArray<double>.Empty : ViewModel.LiveUploadSamples;
        var maximum = ChartAxisMaximum(download.Concat(upload));
        if (home)
        {
            ChartMaximumLabel.Text = download.IsEmpty && upload.IsEmpty ? "—" : FormatChartRate(maximum);
            ChartMiddleLabel.Text = download.IsEmpty && upload.IsEmpty ? "—" : FormatChartRate(maximum / 2d);
            var width = Math.Max(1d, ChartCanvas.ActualWidth);
            var height = Math.Max(1d, ChartCanvas.ActualHeight);
            ChartLine.Points = ScaleSamples(download, width, height, maximum);
            ChartLineSecondary.Points = ScaleSamples(upload, width, height, maximum);
            UpdateChartEndpoint(ChartCanvas, "download-end", ChartLine.Points, ChartLine.Stroke, false);
            UpdateChartEndpoint(ChartCanvas, "upload-end", ChartLineSecondary.Points, ChartLineSecondary.Stroke, true);
            var area = new PointCollection(ChartLine.Points);
            if (area.Count > 0)
            {
                area.Insert(0, new Point(area[0].X, height));
                area.Add(new Point(area[^1].X, height));
            }
            area.Freeze();
            ChartArea.Points = area;
        }
        if (activity)
        {
            var width = Math.Max(1d, ActivityChartCanvas.ActualWidth - 4d);
            var height = Math.Max(1d, ActivityChartCanvas.ActualHeight - 12d);
            foreach (var line in ActivityChartCanvas.Children.OfType<System.Windows.Shapes.Line>()) line.X2 = width;
            ActivityChartLine.Points = ScaleSamples(download, width, height, maximum);
            ActivityChartLineSecondary.Points = ScaleSamples(upload, width, height, maximum);
            ActivityChartLineSecondary.StrokeDashArray = new DoubleCollection { 4, 3 };
            UpdateChartEndpoint(ActivityChartCanvas, "download-end", ActivityChartLine.Points, ActivityChartLine.Stroke, false);
            UpdateChartEndpoint(ActivityChartCanvas, "upload-end", ActivityChartLineSecondary.Points, ActivityChartLineSecondary.Stroke, true);
            ActivityEmptyText.Visibility = download.IsEmpty && upload.IsEmpty ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    internal static double ChartAxisMaximum(IEnumerable<double> values)
    {
        var peak = Math.Max(1024d, values.Where(double.IsFinite).DefaultIfEmpty(0d).Max());
        var unit = peak >= 1024d * 1024d ? 1024d * 1024d : 1024d;
        var magnitude = Math.Pow(10d, Math.Floor(Math.Log10(peak / unit)));
        return Math.Ceiling(peak / unit / magnitude) * magnitude * unit;
    }

    private static void UpdateChartEndpoint(Panel canvas, string tag, PointCollection points, Brush brush, bool square)
    {
        var marker = canvas.Children.OfType<System.Windows.Shapes.Shape>().FirstOrDefault(shape => Equals(shape.Tag, tag));
        if (marker is null)
        {
            marker = square ? new System.Windows.Shapes.Rectangle() : new System.Windows.Shapes.Ellipse();
            marker.Tag = tag; marker.IsHitTestVisible = false;
            marker.Width = marker.Height = square ? 4 : 9;
            marker.StrokeThickness = square ? 0 : 2;
            canvas.Children.Add(marker);
        }
        marker.Fill = square ? brush : Brushes.Transparent;
        marker.Stroke = brush;
        marker.Visibility = points.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        if (points.Count == 0) return;
        var left = points[^1].X - marker.Width / 2;
        var top = points[^1].Y - marker.Height / 2;
        if (canvas is Canvas)
        {
            Canvas.SetLeft(marker, left);
            Canvas.SetTop(marker, top);
        }
        else
        {
            marker.HorizontalAlignment = HorizontalAlignment.Left;
            marker.VerticalAlignment = VerticalAlignment.Top;
            marker.RenderTransform = new TranslateTransform(left, top);
        }
    }

    internal static string FormatChartRate(double bytesPerSecond)
    {
        var value = Math.Max(0d, bytesPerSecond);
        var units = new[] { "B/s", "KB/s", "MB/s", "GB/s" };
        var index = 0;
        while (value >= 1024d && index < units.Length - 1) { value /= 1024d; index++; }
        return $"{value:0.#} {units[index]}";
    }

    private static PointCollection ScaleSamples(IEnumerable<double> values, double width, double height, double maximum)
    {
        var samples = values.ToArray();
        var points = new PointCollection(samples.Length);
        // A partial history is right aligned instead of stretching a few
        // startup samples across the entire history axis.
        var slots = Math.Max(60, samples.Length);
        var step = Math.Max(0d, width - 2d) / (slots - 1);
        for (var index = 0; index < samples.Length; index++)
        {
            var value = double.IsFinite(samples[index]) ? Math.Max(0d, samples[index]) : 0d;
            points.Add(new Point(1d + (slots - samples.Length + index) * step,
                2d + Math.Max(0d, height - 4d) * (1d - Math.Clamp(value / maximum, 0d, 1d))));
        }
        points.Freeze();
        return points;
    }
}
