using System.Reflection;
using System.Windows;
using System.Windows.Threading;
using Bifrost;

internal static class AnimationLifecycleAcceptance
{
    internal static int Run()
    {
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        var dial = new ObsidianMechanicalDial { ConnectionState = UiConnectionState.Preparing };
        var window = new Window { Content = dial, Width = 80, Height = 80, Left = -20000, Top = -20000,
            ShowInTaskbar = false, ShowActivated = false, WindowStyle = WindowStyle.None };
        var field = typeof(ObsidianMechanicalDial).GetField("_renderingSubscribed", BindingFlags.Instance | BindingFlags.NonPublic)!;
        void Check(bool expected, string state)
        {
            var frame = new DispatcherFrame();
            app.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() => frame.Continue = false));
            Dispatcher.PushFrame(frame);
            if ((bool)field.GetValue(dial)! != expected) throw new InvalidOperationException("Animation subscription: " + state);
        }
        try
        {
            window.Show(); Check(true, "shown while connecting");
            window.Hide(); Check(false, "parent hidden with child Visibility still Visible");
            window.Show(); Check(true, "restored from tray");
            window.WindowState = WindowState.Minimized; Check(false, "minimized");
            window.WindowState = WindowState.Normal; Check(true, "restored");
            dial.ReduceMotion = true; Check(false, "reduced motion");
            dial.ReduceMotion = false; Check(true, "motion restored");
            dial.Visibility = Visibility.Collapsed; Check(false, "child collapsed");
            dial.Visibility = Visibility.Visible; Check(true, "child shown");
            dial.ConnectionState = UiConnectionState.Protected; Check(false, "connected static state");
            dial.ConnectionState = UiConnectionState.Reconnecting; Check(true, "reconnecting");
            window.Content = null; Check(false, "unloaded");
            Console.WriteLine("ANIMATION-LIFECYCLE PASS hide/show, minimize/restore, reduced motion, state changes and unload");
            return 0;
        }
        finally { window.Close(); app.Shutdown(); }
    }
}
