namespace Bifrost;

/// Immutable MVVM façade used by the real WPF view and the zero-I/O capture
/// path. Commands remain outside this value so a theme or navigation change
/// cannot mutate service evidence or invent telemetry.
public sealed record UiPresentationViewModel(UiPresentationState Presentation)
{
    public UiConnectionState State => Presentation.State;
    public bool IsProtected => Presentation.IsProtected;
    public bool IsTestState => Presentation.IsTestState;
    public string StatusText => Presentation.StatusText;
    public UiPresentationViewModel WithTheme(string _) => this;
}
