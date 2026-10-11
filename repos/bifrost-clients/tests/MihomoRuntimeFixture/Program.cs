using System.Security.Cryptography;
using System.Text;
using Bifrost.ClientService;

static class Fixture
{
    private static int Main()
    {
        var source = Environment.GetEnvironmentVariable("BIFROST_MIHOMO_EXE")
            ?? throw new InvalidOperationException("BIFROST_MIHOMO_EXE required");
        var scratch = Path.Combine(Path.GetTempPath(), "bifrost-mihomo-runtime-" + Guid.NewGuid().ToString("N"));
        try
        {
            var generation = Path.Combine(scratch, "generation");
            var runtime = Path.Combine(scratch, "runtime");
            Directory.CreateDirectory(Path.Combine(generation, "cores"));
            var binary = Path.Combine(generation, "cores", "mihomo.exe");
            CopyRuntimeArtifacts(source, Path.GetDirectoryName(binary)!);
            var hash = Hash(binary);
            var config = Encoding.UTF8.GetBytes("{\"mixed-port\":0,\"allow-lan\":false,\"mode\":\"rule\",\"log-level\":\"silent\",\"rules\":[\"MATCH,DIRECT\"]}");
            var package = new MihomoCompiledPackage(config, Encoding.UTF8.GetBytes("{\"proxies\":[]}"),
                "BIFROST-SOURCE-A", "BIFROST-SMART-A", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "A-01" }, new string('a', 64));

            using var supervisor = new MihomoRuntimeSupervisor(binary, hash, runtime);
            var identity = supervisor.Start(package, generation);
            Assert(identity.ProcessId > 0 && supervisor.IsExactProcessAlive(identity), "one exact live runtime");
            ExpectCode(() => supervisor.Start(package, generation), "BF-MIHOMO-ALREADY-RUNNING");
            supervisor.StopConfirmed(identity, TimeSpan.FromSeconds(5));
            Assert(!supervisor.IsExactProcessAlive(identity), "stop confirmed");

            using var wrongHash = new MihomoRuntimeSupervisor(binary, new string('0', 64), Path.Combine(scratch, "wrong"));
            ExpectCode(() => wrongHash.Start(package, generation), "BF-CORE-HASH");
            Console.WriteLine("MIHOMO-RUNTIME-FIXTURE PASS");
            return 0;
        }
        finally { try { Directory.Delete(scratch, true); } catch { } }
    }

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static void CopyRuntimeArtifacts(string sourceBinary, string destination)
    {
        var source = Path.GetDirectoryName(Path.GetFullPath(sourceBinary)) ?? throw new InvalidOperationException("binary directory missing");
        foreach (var name in new[] { "mihomo.exe", "CORE-MANIFEST.json", "GeoSite.dat", "geoip.metadb" })
        {
            var path = Path.Combine(source, name);
            if (!File.Exists(path)) throw new InvalidOperationException("required Mihomo runtime artifact missing: " + path);
            File.Copy(path, Path.Combine(destination, name));
        }
    }

    private static void ExpectCode(Action action, string code)
    {
        try { action(); }
        catch (Exception error) when (error.Message == code) { return; }
        throw new InvalidOperationException("expected " + code);
    }

    private static void Assert(bool value, string label)
    {
        if (!value) throw new InvalidOperationException("fixture assertion failed: " + label);
    }
}
