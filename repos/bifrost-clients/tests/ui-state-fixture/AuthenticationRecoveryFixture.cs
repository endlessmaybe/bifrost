using System.Net;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Bifrost;

internal static class AuthenticationRecoveryFixture
{
    internal static int Run()
    {
        var root = Path.Combine(Path.GetTempPath(), "bifrost-auth-recovery-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            Check(root, "BF-AUTH-005", "BF-AUTH-005", 1, 1);
            Check(root, "BF-AUTH-NONCE-REPLAY", "BF-AUTH-NONCE-REPLAY", 1, 1);
            Check(root, "BF-EDGE-FORWARDED", "BF-EDGE-FORWARDED", 1, 1);
            Check(root, "BF-AUTH-003", "BF-AUTH-005", 2, 2);
            Check(root, "BF-AUTH-003", "BF-AUTH-003", 2, 2);
            Check(root, "BF-AUTH-003", "OK", 2, 2);
            Check(root, "HTML", "BF-CONTROL-CONTENT-TYPE", 1, 1);
            CheckLogout(root);
            Console.WriteLine("AUTHENTICATION-RECOVERY PASS seven production-transport scenarios");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void CheckLogout(string root)
    {
        var transport = new LogoutHandler();
        var state = Path.Combine(root, "logout.bin");
        using var client = BifrostControlClient.CreateEnrollmentIdentityClientForTest(state, "http://127.0.0.1:18183", transport);
        client.RestoreSessionIdentityForTestAsync().GetAwaiter().GetResult();
        var identity = client.DeviceIdForTest;
        try { client.LogoutAsync().GetAwaiter().GetResult(); throw new Exception("offline logout claimed success"); }
        catch (HttpRequestException) { }
        if (!client.IsEnrolled || client.DeviceIdForTest != identity) throw new Exception("failed logout discarded retry identity");
        transport.LoseResponse = true;
        try { client.LogoutAsync().GetAwaiter().GetResult(); throw new Exception("lost reply claimed success"); }
        catch (HttpRequestException) { }
        if (!client.IsEnrolled || client.DeviceIdForTest != identity) throw new Exception("lost reply discarded retry identity");
        transport.Revoked = true;
        client.LogoutAsync().GetAwaiter().GetResult();
        if (client.IsEnrolled || client.DeviceIdForTest == identity) throw new Exception("revoked retry did not clear old identity");
        Console.WriteLine("LOGOUT PASS offline retry, lost response, revoked confirmation, identity reset");
    }

    private sealed class LogoutHandler : HttpMessageHandler
    {
        internal bool LoseResponse;
        internal bool Revoked;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/v1/device/logout") throw new HttpRequestException(LoseResponse ? "TEST-ONLY reply lost" : "TEST-ONLY offline");
            var code = Revoked ? HttpStatusCode.Unauthorized : HttpStatusCode.OK;
            var body = Revoked ? JsonSerializer.Serialize(new { error = new { code = "BF-AUTH-003", message = "TEST-ONLY revoked", message_key = "error.generic", request_id = "req_TESTONLYlogout1", catalog_version = "1" } })
                : path == "/v1/device/challenge" ? "{\"challenge\":\"TEST-ONLY-logout-challenge\",\"expires_in\":120}"
                : JsonSerializer.Serialize(new { session_token = "TEST-ONLY-logout-session-0000000000000000", expires_at = "2099-01-01T00:00:00Z", public_id = "BF-TEST-LOGOUT" });
            return Task.FromResult(new HttpResponseMessage(code) { RequestMessage = request, Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private static void Check(string root, string initial, string expected, int requests, int sessions)
    {
        var transport = new Handler(initial, expected);
        using var client = BifrostControlClient.CreateEnrollmentIdentityClientForTest(
            Path.Combine(root, Guid.NewGuid().ToString("N") + ".bin"), "http://127.0.0.1:18183", transport);
        client.RestoreSessionIdentityForTestAsync().GetAwaiter().GetResult();
        var identity = client.DeviceIdForTest;
        try
        {
            client.SendAuthorizedForHarnessAsync("/v1/config/manifest").GetAwaiter().GetResult();
            if (expected != "OK") throw new Exception("rejected request unexpectedly succeeded");
        }
        catch (Exception error) when (error.Message == expected) { }
        if (transport.Requests != requests || transport.Sessions != sessions || client.DeviceIdForTest != identity)
            throw new Exception($"unexpected recovery sequence: {initial}/{expected} requests={transport.Requests} sessions={transport.Sessions}");
        if (initial != "HTML" && expected != "OK" && !UiErrorMapper.ToUserMessage(new InvalidOperationException(expected), "连接").Contains(expected))
            throw new Exception("stable authentication code is missing from user-facing error");
    }

    private sealed class Handler(string initial, string final) : HttpMessageHandler
    {
        internal int Requests;
        internal int Sessions;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path == "/v1/device/challenge") return Reply(request, HttpStatusCode.OK,
                "{\"challenge\":\"TEST-ONLY-auth-challenge\",\"expires_in\":120}");
            if (path == "/v1/device/session")
            {
                Sessions++;
                return Reply(request, HttpStatusCode.OK, JsonSerializer.Serialize(new {
                    session_token = "TEST-ONLY-auth-session-0000000000000000-" + Sessions,
                    expires_at = "2099-01-01T00:00:00Z", public_id = "BF-TEST-AUTH-RECOVERY" }));
            }
            if (path != "/v1/config/manifest") throw new Exception("unexpected fixture endpoint");
            Requests++;
            var code = Requests == 1 ? initial : final;
            if (code == "OK") return Reply(request, HttpStatusCode.OK, JsonSerializer.Serialize(new {
                config_version = 1, schema_version = "1.0", digest = new string('a', 64), rollback_floor = 1 }));
            if (code == "HTML") return Reply(request, HttpStatusCode.Unauthorized, "<html>edge rejection</html>", "text/html");
            return Reply(request, HttpStatusCode.Unauthorized, JsonSerializer.Serialize(new {
                error = new { code, message = "TEST-ONLY rejection", message_key = "error.generic",
                    request_id = "req_TESTONLYauth001", catalog_version = "1" } }));
        }
        private static Task<HttpResponseMessage> Reply(HttpRequestMessage request, HttpStatusCode status, string body, string type = "application/json") =>
            Task.FromResult(new HttpResponseMessage(status) { RequestMessage = request, Content = new StringContent(body, Encoding.UTF8, type) });
    }
}
