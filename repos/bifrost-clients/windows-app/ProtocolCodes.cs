namespace Bifrost;

/// <summary>Stable wire codes. Display labels are deliberately separate.</summary>
public static class ProtocolCodes
{
    public const string ModeSmart = "smart";
    public const string ModeGlobal = "global";
    public const string ModePerApp = "per-app";
    // SmartGate is a presentation mode.  The service receives the validated
    // smart route code while the UI preserves the country-first label.
    public const string ModeSmartGate = "smartgate";

    public const string CoreAuto = "auto";
    public const string CoreMihomo = "mihomo";

    public static string ModeLabel(string code) => code switch
    {
        ModeSmart => "智能选线", ModeGlobal => "全局代理", ModePerApp => "按应用分流", ModeSmartGate => "SmartGate", _ => code
    };

    public static string CoreLabel(string code) => code switch
    {
        CoreAuto => "自动（Mihomo）", CoreMihomo => "Mihomo", _ => code
    };
}
