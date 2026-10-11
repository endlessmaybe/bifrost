using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;

namespace Bifrost;

/// <summary>
/// Bifrost's compact Nordic connection medallion. The owner-approved artwork
/// carries the rune ring, forest and Valknut identity; this control adds only
/// restrained, non-destructive connection-state feedback around that artwork.
/// </summary>
public sealed class ObsidianMechanicalDial : FrameworkElement
{
    public static readonly DependencyProperty ConnectionStateProperty =
        DependencyProperty.Register(nameof(ConnectionState), typeof(UiConnectionState), typeof(ObsidianMechanicalDial),
            new FrameworkPropertyMetadata(UiConnectionState.Idle, FrameworkPropertyMetadataOptions.AffectsRender, OnStateChanged));
    public static readonly DependencyProperty IsProtectedProperty =
        DependencyProperty.Register(nameof(IsProtected), typeof(bool), typeof(ObsidianMechanicalDial),
            new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender, OnStateChanged));
    public static readonly DependencyProperty ReduceMotionProperty =
        DependencyProperty.Register(nameof(ReduceMotion), typeof(bool), typeof(ObsidianMechanicalDial),
            new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender, OnStateChanged));
    public static readonly DependencyProperty IsPressedProperty =
        DependencyProperty.Register(nameof(IsPressed), typeof(bool), typeof(ObsidianMechanicalDial),
            new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty UseLightAssetProperty =
        DependencyProperty.Register(nameof(UseLightAsset), typeof(bool), typeof(ObsidianMechanicalDial),
            new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender, OnAssetChanged));

    private EventHandler? _renderingHandler;
    private long _lastRenderingTimestamp;
    private double _stateAngle;
    private bool _renderingSubscribed;
    private Window? _ownerWindow;
    private Pen? _statePen;
    private string? _statePenKey;
    private static readonly Lazy<ImageSource> DarkRuneMedallionAsset = new(() => LoadDialAsset("bifrost-rune-medallion-v2.png"));
    private static readonly Lazy<ImageSource> LightRuneMedallionAsset = new(() => LoadDialAsset("bifrost-rune-medallion-light-v1.png"));

    public ObsidianMechanicalDial()
    {
        SnapsToDevicePixels = true;
        IsHitTestVisible = false;
        Loaded += (_, _) =>
        {
            _ownerWindow = Window.GetWindow(this);
            if (_ownerWindow is not null) _ownerWindow.StateChanged += OnWindowStateChanged;
            UpdateAnimation();
        };
        Unloaded += (_, _) =>
        {
            if (_ownerWindow is not null) _ownerWindow.StateChanged -= OnWindowStateChanged;
            _ownerWindow = null;
            StopAnimation();
        };
        IsVisibleChanged += (_, _) => UpdateAnimation();
    }

    public UiConnectionState ConnectionState { get => (UiConnectionState)GetValue(ConnectionStateProperty); set => SetValue(ConnectionStateProperty, value); }
    public bool IsProtected { get => (bool)GetValue(IsProtectedProperty); set => SetValue(IsProtectedProperty, value); }
    public bool ReduceMotion { get => (bool)GetValue(ReduceMotionProperty); set => SetValue(ReduceMotionProperty, value); }
    public bool IsPressed { get => (bool)GetValue(IsPressedProperty); set => SetValue(IsPressedProperty, value); }
    public bool UseLightAsset { get => (bool)GetValue(UseLightAssetProperty); set => SetValue(UseLightAssetProperty, value); }

    private static void OnStateChanged(DependencyObject sender, DependencyPropertyChangedEventArgs _)
    {
        var dial = (ObsidianMechanicalDial)sender;
        dial.UpdateAnimation();
        dial._statePenKey = null;
        dial._statePen = null;
        dial.InvalidateVisual();
    }

    private static void OnAssetChanged(DependencyObject sender, DependencyPropertyChangedEventArgs _)
    {
        var dial = (ObsidianMechanicalDial)sender;
        // Theme changes are a short opacity-only cross-fade at runtime.  The
        // deterministic renderer uses a static swap so it never captures an
        // intermediate transparent frame; reduced-motion users also receive a
        // static replacement.
        if (!dial.ReduceMotion && dial.IsLoaded && !UiCaptureContext.Active)
        {
            dial.BeginAnimation(OpacityProperty, null);
            dial.Opacity = 0d;
            dial.BeginAnimation(
                OpacityProperty,
                new DoubleAnimation(0d, 1d, new Duration(TimeSpan.FromMilliseconds(160))) { EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut } },
                HandoffBehavior.SnapshotAndReplace);
        }
        dial.InvalidateVisual();
    }

    private bool ShouldAnimate => !ReduceMotion && IsVisible && _ownerWindow?.WindowState != WindowState.Minimized &&
        ConnectionState is UiConnectionState.Preparing or UiConnectionState.Reconnecting;
    private void OnWindowStateChanged(object? sender, EventArgs e) => UpdateAnimation();
    private void UpdateAnimation() { if (IsLoaded && ShouldAnimate) StartAnimation(); else StopAnimation(); }
    private void StartAnimation()
    {
        if (_renderingSubscribed) return;
        _renderingHandler ??= OnRendering;
        _lastRenderingTimestamp = Stopwatch.GetTimestamp();
        CompositionTarget.Rendering += _renderingHandler;
        _renderingSubscribed = true;
    }
    private void StopAnimation()
    {
        if (!_renderingSubscribed) return;
        if (_renderingHandler is not null) CompositionTarget.Rendering -= _renderingHandler;
        _renderingSubscribed = false;
        _lastRenderingTimestamp = 0;
    }
    private void OnRendering(object? sender, EventArgs e)
    {
        if (!ShouldAnimate) { StopAnimation(); return; }
        var now = Stopwatch.GetTimestamp();
        var elapsed = (now - _lastRenderingTimestamp) / (double)Stopwatch.Frequency;
        if (elapsed < 1d / 60d) return;
        _lastRenderingTimestamp = now;
        _stateAngle = (_stateAngle + Math.Clamp(elapsed, 0d, .12d) * 180d) % 360d;
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext drawingContext)
    {
        base.OnRender(drawingContext);
        var diameter = Math.Max(1d, Math.Min(ActualWidth, ActualHeight));
        var center = new Point(ActualWidth / 2d, ActualHeight / 2d);
        DrawDialAsset(drawingContext, center, diameter);
        if (IsPressed)
        {
            var pressedBrush = ResolveBrush("DialPressedOverlay", new SolidColorBrush(Color.FromArgb(30, 0, 0, 0)));
            drawingContext.DrawEllipse(pressedBrush, null, center, diameter * .445d, diameter * .445d);
        }
        if (IsKeyboardFocusWithin)
        {
            var focusPen = MakePen(ResolveBrush("AccentBrush", Brushes.SteelBlue), 2d);
            drawingContext.DrawEllipse(null, focusPen, center, diameter * .465d, diameter * .465d);
        }
        DrawStateArc(drawingContext, center, diameter * .455d);
        if (ConnectionState is UiConnectionState.Preparing or UiConnectionState.Reconnecting)
        {
            var pointBrush = ResolveBrush(ConnectionState == UiConnectionState.Reconnecting ? "DialSwitchingBrush" : "DialStatusBrush", Brushes.Gray);
            drawingContext.DrawEllipse(pointBrush, null, PointOnCircle(center, diameter * .455d, -90d), 2.8d, 2.8d);
        }
    }

    private static ImageSource LoadDialAsset(string fileName)
    {
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.UriSource = new Uri($"pack://application:,,,/Bifrost;component/Assets/{fileName}", UriKind.Absolute);
        image.EndInit();
        image.Freeze();
        return image;
    }

    private void DrawDialAsset(DrawingContext dc, Point center, double diameter)
    {
        // Use the owner-selected 1254 px production artwork directly.  The
        // WPF layer only adds trusted connection-state feedback around it; it
        // must not substitute a simplified procedural approximation.
        // Both assets preserve the same medallion geometry and identity.  The
        // light variant replaces only the material palette so a black plate is
        // never stranded on the warm ivory theme.  The production PNGs include
        // a narrow square safety margin, so clip at the real outer-rim radius.
        var image = UseLightAsset ? LightRuneMedallionAsset.Value : DarkRuneMedallionAsset.Value;
        var side = diameter;
        var clipRadius = diameter * .473d;
        dc.PushClip(new EllipseGeometry(center, clipRadius, clipRadius));
        dc.DrawImage(image, new Rect(center.X - side / 2d, center.Y - side / 2d, side, side));
        dc.Pop();
    }

    private void DrawMedallion(DrawingContext dc, Point center, double diameter)
    {
        var light = UseLightAsset;
        var bronze = ResolveBrush("AccentBrush", new SolidColorBrush(Color.FromRgb(198, 151, 85)));
        var hairline = ResolveBrush("HairlineBrush", new SolidColorBrush(Color.FromRgb(45, 41, 33)));
        var surface = ResolveBrush("SurfaceBrush", new SolidColorBrush(Color.FromRgb(14, 18, 21)));
        var muted = ResolveBrush("MutedTextBrush", Brushes.Gray);
        var outerRadius = diameter * .455d;
        var runeRadius = diameter * .402d;
        var innerRadius = diameter * .325d;

        dc.DrawEllipse(surface, MakePen(hairline, 1d), center, outerRadius, outerRadius);
        dc.DrawEllipse(null, MakePen(bronze, 1.15d), center, outerRadius * .94d, outerRadius * .94d);
        dc.DrawEllipse(null, MakePen(hairline, 1d), center, innerRadius, innerRadius);

        // Sparse deterministic star points keep the centre from reading as a
        // flat black disk while preserving the restrained line-art brief.
        // They are deliberately fixed vectors, never random animation.
        foreach (var (x, y, size, opacity) in new[]
        {
            (-.18d,-.22d,1.1d,.55d), (.08d,-.24d,.8d,.38d), (.22d,-.15d,1d,.45d),
            (-.27d,-.08d,.7d,.30d), (.28d,.00d,.8d,.36d), (-.10d,.02d,.6d,.25d),
            (.16d,.08d,.7d,.30d), (-.24d,.12d,.8d,.34d), (.02d,.16d,.6d,.26d),
            (.27d,.18d,.7d,.28d), (-.05d,-.13d,.6d,.24d), (.13d,-.04d,.6d,.24d),
        })
        {
            var star = bronze.Clone();
            star.Opacity = opacity;
            if (star.CanFreeze) star.Freeze();
            dc.DrawEllipse(star, null, new Point(center.X + diameter * x, center.Y + diameter * y), size, size);
        }

        // Twenty-four small angular rune marks form the ring without turning
        // it into ornamental jewellery.  The approved master uses the Elder
        // Futhark sequence itself rather than generic mechanical ticks, so the
        // production vector draws those glyphs tangentially around the ring.
        const string elderFuthark = "ᚠᚢᚦᚨᚱᚲᚷᚹᚺᚾᛁᛃᛇᛈᛉᛋᛏᛒᛖᛗᛚᛜᛞᛟ";
        var runeTypeface = new Typeface(new FontFamily("Segoe UI Historic"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
        var pixelsPerDip = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        for (var i = 0; i < 24; i++)
        {
            var angle = -90d + i * 15d;
            var longMark = i % 3 == 0;
            var p1 = PointOnCircle(center, runeRadius - (longMark ? diameter * .022d : diameter * .014d), angle);
            var p2 = PointOnCircle(center, runeRadius, angle + (i % 2 == 0 ? 2.2d : -2.2d));
            dc.DrawLine(MakePen(i % 3 == 0 ? bronze : muted, longMark ? .9d : .65d, PenLineCap.Round), p1, p2);

            var rune = new FormattedText(
                elderFuthark[i].ToString(),
                CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight,
                runeTypeface,
                diameter * .034d,
                bronze,
                pixelsPerDip);
            dc.PushTransform(new RotateTransform(angle + 90d, center.X, center.Y));
            dc.DrawText(rune, new Point(center.X - rune.Width / 2d, center.Y - runeRadius + diameter * .018d - rune.Height / 2d));
            dc.Pop();
        }

        // Subtle mountain silhouette grounds the mark without adding another
        // pictorial illustration to the control.
        var mountain = new StreamGeometry();
        using (var g = mountain.Open())
        {
            g.BeginFigure(new Point(center.X - diameter * .24d, center.Y + diameter * .18d), true, true);
            g.LineTo(new Point(center.X - diameter * .12d, center.Y + diameter * .06d), true, false);
            g.LineTo(new Point(center.X - diameter * .04d, center.Y + diameter * .14d), true, false);
            g.LineTo(new Point(center.X + diameter * .08d, center.Y + diameter * .03d), true, false);
            g.LineTo(new Point(center.X + diameter * .23d, center.Y + diameter * .18d), true, false);
        }
        mountain.Freeze();
        var mountainBrush = new SolidColorBrush(light ? Color.FromArgb(28, 65, 60, 52) : Color.FromArgb(145, 4, 7, 9));
        mountainBrush.Freeze();
        dc.DrawGeometry(mountainBrush, null, mountain);
        dc.DrawGeometry(null, MakePen(ResolveBrush("AccentSoftBrush", new SolidColorBrush(Color.FromRgb(90, 68, 42))), .7d), mountain);

        DrawValknut(dc, center, diameter * .235d, bronze);
    }

    private static void DrawValknut(DrawingContext dc, Point center, double radius, Brush bronze)
    {
        var shadow = new SolidColorBrush(Color.FromArgb(150, 4, 5, 5));
        shadow.Freeze();

        // A centred equilateral triangle is invariant under a 120° rotation,
        // which made the old implementation collapse visually to one shape.
        // The approved Heimdall/Valknut mark is three *offset* upward knots.
        // Each knot is now a filled triangular band (outer geometry minus its
        // inset) instead of two independent strokes.  That prevents the six
        // outlines from turning the centre into a wireframe web at crossings.
        var knots = new[]
        {
            new Point(center.X - radius * .31d, center.Y - radius * .12d),
            new Point(center.X + radius * .31d, center.Y - radius * .12d),
            new Point(center.X, center.Y + radius * .27d),
        };
        foreach (var knotCenter in knots)
        {
            var outer = Triangle(knotCenter, radius * .86d);
            var inner = Triangle(knotCenter, radius * .68d);
            var band = new CombinedGeometry(GeometryCombineMode.Exclude, outer, inner);
            band.Freeze();
            dc.PushTransform(new TranslateTransform(0d, Math.Max(1d, radius * .025d)));
            dc.DrawGeometry(shadow, null, band);
            dc.Pop();
            dc.DrawGeometry(bronze, null, band);
        }
    }

    private static StreamGeometry Triangle(Point center, double radius)
    {
        var triangle = new StreamGeometry();
        using (var g = triangle.Open())
        {
            var a = Polar(center, radius, -90d);
            var b = Polar(center, radius, 30d);
            var c = Polar(center, radius, 150d);
            g.BeginFigure(a, false, true);
            g.LineTo(b, true, false);
            g.LineTo(c, true, false);
        }
        triangle.Freeze();
        return triangle;
    }

    private static Point Polar(Point center, double radius, double degrees) => PointOnCircle(center, radius, degrees);

    private void DrawStateArc(DrawingContext dc, Point center, double radius)
    {
        var sweep = ConnectionState switch
        {
            // Protected is represented by the static owner-approved marker and
            // the center status lamp; only connecting states receive a moving arc.
            UiConnectionState.Protected => 0d,
            UiConnectionState.Preparing => 92d,
            UiConnectionState.Reconnecting => 92d,
            UiConnectionState.Blocked => 360d,
            UiConnectionState.Error => 360d,
            _ => 0d,
        };
        if (sweep <= 0d) return;
        var brushKey = ConnectionState switch
        {
            UiConnectionState.Protected => "DialPositiveBrush",
            UiConnectionState.Preparing => "DialStatusBrush",
            UiConnectionState.Reconnecting => "DialSwitchingBrush",
            UiConnectionState.Blocked => "DialWarningBrush",
            UiConnectionState.Error => "DialErrorBrush",
            _ => "DialIdleBrush",
        };
        if (_statePen is null || !string.Equals(_statePenKey, brushKey, StringComparison.Ordinal))
        {
            _statePenKey = brushKey;
            _statePen = MakePen(ResolveBrush(brushKey, Brushes.Gray), 2.4d, PenLineCap.Round);
        }
        var start = ConnectionState is UiConnectionState.Preparing or UiConnectionState.Reconnecting ? _stateAngle - 45d : -90d;
        if (sweep >= 359d)
        {
            // A pair of translucent halos gives the connected/warning state a
            // restrained lamp-like glow instead of a neon halo.
            var glow = ResolveBrush(brushKey, Brushes.Gray).Clone();
            glow.Opacity = ConnectionState == UiConnectionState.Protected ? .09d : .16d;
            if (glow.CanFreeze) glow.Freeze();
            dc.DrawEllipse(null, MakePen(glow, ConnectionState == UiConnectionState.Protected ? 5d : 7d, PenLineCap.Round), center, radius, radius);
            dc.DrawEllipse(null, ConnectionState == UiConnectionState.Protected ? MakePen(ResolveBrush(brushKey, Brushes.Gray), 1.8d, PenLineCap.Round) : _statePen, center, radius, radius);
        }
        else
        {
            dc.DrawGeometry(null, _statePen, Arc(center, radius, start, sweep));
        }
    }

    private static StreamGeometry Arc(Point center, double radius, double startDegrees, double sweepDegrees)
    {
        var start = PointOnCircle(center, radius, startDegrees);
        var end = PointOnCircle(center, radius, startDegrees + sweepDegrees);
        var geometry = new StreamGeometry();
        using (var context = geometry.Open())
        {
            context.BeginFigure(start, false, false);
            context.ArcTo(end, new Size(radius, radius), 0d, sweepDegrees > 180d, SweepDirection.Clockwise, true, false);
        }
        geometry.Freeze();
        return geometry;
    }
    private static Point PointOnCircle(Point center, double radius, double degrees)
    {
        var radians = degrees * Math.PI / 180d;
        return new Point(center.X + radius * Math.Cos(radians), center.Y + radius * Math.Sin(radians));
    }
    private Brush ResolveBrush(string key, Brush fallback)
    {
        var source = TryFindResource(key) as Brush ?? fallback;
        var clone = source.Clone();
        if (clone.CanFreeze) clone.Freeze();
        return clone;
    }
    private static Pen MakePen(Brush brush, double thickness, PenLineCap cap = PenLineCap.Flat)
    {
        var pen = new Pen(brush, thickness) { StartLineCap = cap, EndLineCap = cap, DashCap = cap };
        if (pen.CanFreeze) pen.Freeze();
        return pen;
    }
}
