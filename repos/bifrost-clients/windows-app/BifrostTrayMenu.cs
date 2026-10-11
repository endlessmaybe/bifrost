using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Bifrost;

/// <summary>A compact native menu with keyboard navigation and system-theme contrast.</summary>
internal sealed class BifrostTrayMenu : ContextMenuStrip
{
    private readonly Font _menuFont = new("Microsoft YaHei UI", 10f);
    internal BifrostTrayMenu()
    {
        Font = _menuFont;
        ShowImageMargin = true;
        ShowCheckMargin = false;
        DropShadowEnabled = true;
        Padding = new Padding(7);
        ImageScalingSize = new Size(18, 18);
        SizeChanged += (_, _) => Round(this);
    }

    internal void ClearEntries()
    {
        foreach (ToolStripItem item in Items.Cast<ToolStripItem>().ToArray()) DisposeEntry(item);
        Items.Clear();
    }

    internal void ApplyTheme(bool? forcedDark = null)
    {
        var dark = false;
        try
        {
            using var preferences = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            dark = preferences?.GetValue("AppsUseLightTheme") is int value && value == 0;
        }
        catch { }
        var renderer = new MenuRenderer(forcedDark ?? dark);
        Configure(this, renderer);
    }

    private void Configure(ToolStripDropDownMenu menu, MenuRenderer renderer)
    {
        menu.Renderer = renderer;
        menu.Font = _menuFont;
        menu.BackColor = renderer.Surface;
        menu.ForeColor = renderer.Text;
        menu.Padding = new Padding(7);
        menu.ShowImageMargin = true;
        menu.ImageScalingSize = new Size(18, 18);
        foreach (ToolStripItem item in menu.Items)
        {
            item.ForeColor = item is ToolStripLabel ? renderer.Muted : renderer.Text;
            item.Margin = new Padding(0, 1, 0, 1);
            if (item is ToolStripMenuItem command)
            {
                command.AutoSize = false;
                command.Size = new Size(256, 36);
                command.Padding = new Padding(3, 0, 8, 0);
                if (command.Tag is string glyph)
                {
                    command.Image?.Dispose();
                    command.Image = DrawGlyph(glyph, renderer.Text);
                }
                if (command.HasDropDownItems && command.DropDown is ToolStripDropDownMenu child)
                {
                    Configure(child, renderer);
                    child.SizeChanged -= RoundMenu;
                    child.SizeChanged += RoundMenu;
                }
            }
            else if (item is ToolStripSeparator) item.Margin = new Padding(12, 5, 12, 5);
        }
        Round(menu);
    }

    internal static ToolStripMenuItem Action(string text, string glyph, System.Action action, bool enabled = true)
    {
        var item = new ToolStripMenuItem(text) { Tag = glyph, Enabled = enabled };
        item.Click += (_, _) => action();
        return item;
    }

    private static Bitmap DrawGlyph(string glyph, Color color)
    {
        var image = new Bitmap(24, 24);
        using var graphics = Graphics.FromImage(image);
        graphics.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAliasGridFit;
        using var font = new Font("Segoe MDL2 Assets", 15f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var brush = new SolidBrush(color);
        using var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        graphics.DrawString(glyph, font, brush, new RectangleF(0, 0, 24, 24), format);
        return image;
    }

    private static void RoundMenu(object? sender, EventArgs args)
    {
        if (sender is ToolStripDropDownMenu menu) Round(menu);
    }

    private static void Round(ToolStripDropDownMenu menu)
    {
        if (menu.Width <= 1 || menu.Height <= 1) return;
        using var shape = Rounded(new Rectangle(0, 0, menu.Width, menu.Height), 11);
        var previous = menu.Region;
        menu.Region = new Region(shape);
        previous?.Dispose();
    }

    private static GraphicsPath Rounded(Rectangle rectangle, int radius)
    {
        var path = new GraphicsPath();
        var diameter = Math.Min(radius * 2, Math.Min(rectangle.Width, rectangle.Height));
        if (diameter < 2) { path.AddRectangle(rectangle); return path; }
        path.AddArc(rectangle.Left, rectangle.Top, diameter, diameter, 180, 90);
        path.AddArc(rectangle.Right - diameter, rectangle.Top, diameter, diameter, 270, 90);
        path.AddArc(rectangle.Right - diameter, rectangle.Bottom - diameter, diameter, diameter, 0, 90);
        path.AddArc(rectangle.Left, rectangle.Bottom - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        return path;
    }

    private static void DisposeEntry(ToolStripItem item)
    {
        if (item is ToolStripMenuItem parent)
            foreach (var child in parent.DropDownItems.Cast<ToolStripItem>().ToArray()) DisposeEntry(child);
        item.Image?.Dispose();
        item.Image = null;
        item.Dispose();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { ClearEntries(); _menuFont.Dispose(); }
        base.Dispose(disposing);
    }

    private sealed class MenuRenderer(bool dark) : ToolStripProfessionalRenderer
    {
        internal Color Surface => ColorTranslator.FromHtml(dark ? "#252525" : "#FAFAFA");
        internal Color Text => ColorTranslator.FromHtml(dark ? "#F0F0F0" : "#202020");
        internal Color Muted => ColorTranslator.FromHtml(dark ? "#AEAEAE" : "#707070");
        private Color Hover => ColorTranslator.FromHtml(dark ? "#373737" : "#EDEDED");
        private Color Border => ColorTranslator.FromHtml(dark ? "#454545" : "#DEDEDE");
        protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e) => e.Graphics.Clear(Surface);
        protected override void OnRenderImageMargin(ToolStripRenderEventArgs e) { }
        protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var path = Rounded(new Rectangle(0, 0, e.ToolStrip.Width - 1, e.ToolStrip.Height - 1), 11);
            using var pen = new Pen(Border);
            e.Graphics.DrawPath(pen, path);
        }
        protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
        {
            if (!e.Item.Selected || !e.Item.Enabled) return;
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var shape = Rounded(new Rectangle(1, 1, e.Item.Width - 2, e.Item.Height - 2), 6);
            using var brush = new SolidBrush(Hover);
            e.Graphics.FillPath(brush, shape);
        }
        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = e.Item.Enabled && e.Item is not ToolStripLabel ? Text : Muted;
            base.OnRenderItemText(e);
        }
        protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
        {
            e.ArrowColor = Muted;
            base.OnRenderArrow(e);
        }
        protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
        {
            using var pen = new Pen(Border);
            e.Graphics.DrawLine(pen, 5, e.Item.Height / 2, e.Item.Width - 5, e.Item.Height / 2);
        }
        protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var pen = new Pen(Text, 1.7f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
            var r = e.ImageRectangle;
            e.Graphics.DrawLines(pen, new[] { new Point(r.Left + 3, r.Top + 9), new Point(r.Left + 7, r.Top + 13), new Point(r.Left + 14, r.Top + 5) });
        }
    }
}
