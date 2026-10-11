using System.Reflection;
using System.Text.Json.Nodes;
using Bifrost;

internal static class NodeNotificationFixture
{
    internal static int Run()
    {
        var original = """{"config_version":69,"anti_rollback":69,"account":{"public_id":"fixture"},"sources":[{"code":"A","transport":{"uuid":"one","port":443}}],"countries":[],"routing":{"ruleset_version":"one"},"core_policy":{"default":"mihomo"}}""";
        var config = JsonNode.Parse(original)!;
        config["config_version"] = 70;
        config["anti_rollback"] = 70;
        var before = NodeConfigurationNotifications.Fingerprint(original);
        var after = NodeConfigurationNotifications.Fingerprint(config.ToJsonString());
        if (before != after) throw new Exception("A revocation counter changed the node fingerprint.");
        // Object property order and account metadata have no node meaning.
        config["account"] = new JsonObject { ["plan"] = "fixture" };
        config["sources"]![0]!["transport"] = new JsonObject { ["port"] = 443, ["uuid"] = "one" };
        if (before != NodeConfigurationNotifications.Fingerprint(config.ToJsonString()))
            throw new Exception("JSON order/account metadata changed the fingerprint.");
        using var model = new UiShellViewModel(new FixtureUiShellCoordinator(UiPresentationState.Idle()), new InMemoryUiShellPersistence(new UiShellState()));
        var notices = new List<long>();
        model.NodeConfigurationUpdated += notices.Add;
        var notify = typeof(UiShellViewModel).GetMethod("NotifyNodeConfigurationUpdated", BindingFlags.Instance | BindingFlags.NonPublic)!;
        notify.Invoke(model, [69L, 70L, before, after]);
        if (notices.Count != 0) throw new Exception("Unrelated account deletion produced a tray notification.");
        config["sources"]![0]!["transport"]!["uuid"] = "two";
        var changed = NodeConfigurationNotifications.Fingerprint(config.ToJsonString());
        if (before == changed) throw new Exception("A transport credential change was ignored.");
        notify.Invoke(model, [70L, 71L, before, changed]);
        notify.Invoke(model, [70L, 71L, before, changed]);
        notify.Invoke(model, [71L, 70L, changed, before]);
        notify.Invoke(model, [0L, 72L, null, changed]);
        if (!notices.SequenceEqual([71L])) throw new Exception("Real changes, duplicate events or initial activation were classified incorrectly.");
        Console.WriteLine("NODE-NOTIFICATIONS revocation quiet; routing credential change notifies once; rollback/initial activation quiet PASS");
        return 0;
    }
}
