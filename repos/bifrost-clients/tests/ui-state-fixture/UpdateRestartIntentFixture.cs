using Bifrost;
using System;
using System.IO;
internal static class UpdateRestartIntentFixture
{
    internal static int Run()
    {
        var root = Path.Combine(Path.GetTempPath(), "bifrost-update-intent-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new UpdateRestartIntentStore(root);
            store.Save(123, true);
            if (store.TryConsume(122)) throw new Exception("Old generation consumed reconnect intent");
            if (!store.TryConsume(123) || store.TryConsume(123)) throw new Exception("Intent must be consumed exactly once");
            store.Save(124, false);
            if (store.TryConsume(124)) throw new Exception("Disconnected users must remain disconnected");
            File.WriteAllText(Path.Combine(root, "update-restart-intent.bin"), "invalid fixture bytes");
            if (store.TryConsume(125)) throw new Exception("Unprotected state authorized a connection");
            Console.WriteLine("UPDATE-RESTART-INTENT PASS one-shot, generation binding, disconnected state and corrupt record");
            return 0;
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }
}
