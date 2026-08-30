using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Adctir.Tests;

/// <summary>
/// Hosts the real app in-process. RDAP is disabled and reports go to a temp file so
/// the suite never touches the network or the developer's data directory.
/// </summary>
public sealed class ApiFactory : WebApplicationFactory<Program>, IDisposable
{
    private readonly string _dataFile = Path.Combine(
        Path.GetTempPath(), $"adctir-test-{Guid.NewGuid():N}.json");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Environment.SetEnvironmentVariable("ADCTIR_ENABLE_RDAP", "false");
        Environment.SetEnvironmentVariable("ADCTIR_DATA_FILE", _dataFile);
        Environment.SetEnvironmentVariable("ADCTIR_AI_ENABLED", "false");
        builder.UseEnvironment("Testing");
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && File.Exists(_dataFile)) File.Delete(_dataFile);
    }
}

public sealed class ApiTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private HttpClient Client => factory.CreateClient();

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    private static async Task<JsonElement> ReadAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();

    [Fact]
    public async Task HealthEndpointReportsReadinessAndWhichExplainerIsActive()
    {
        var response = await Client.GetAsync("/api/health");
        var body = await ReadAsync(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(body.GetProperty("ok").GetBoolean());
        Assert.False(body.GetProperty("rdap_enabled").GetBoolean());
        Assert.True(body.GetProperty("explain_enabled").GetBoolean());
        Assert.Contains(body.GetProperty("ai_generator").GetString(), new[] { "rules", "model" });
    }

    [Fact]
    public async Task RootReportsServiceMetadata()
    {
        var body = await ReadAsync(await Client.GetAsync("/"));
        Assert.Equal("ADCTIR Threat Analysis API", body.GetProperty("service").GetString());
        Assert.Equal("ready", body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task AnalysisEndpointReturnsEvidence()
    {
        var response = await Client.PostAsync("/api/threats/analyze",
            Json("""{"indicators":{"url":"http://verify-account.top","has_login_form":true}}"""));
        var body = await ReadAsync(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("High-Risk", body.GetProperty("risk_level").GetString());
        Assert.True(body.GetProperty("evidence").GetArrayLength() >= 3);
        Assert.Equal("verify-account.top", body.GetProperty("indicators").GetProperty("domain").GetString());
    }

    [Fact]
    public async Task ExplainEndpointReturnsACitedExplanationAlongsideTheVerdict()
    {
        var response = await Client.PostAsync("/api/threats/explain",
            Json("""{"indicators":{"url":"http://secure-login-verify.top/signin","has_login_form":true}}"""));
        var body = await ReadAsync(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("High-Risk", body.GetProperty("risk_level").GetString());

        var explanation = body.GetProperty("explanation");
        Assert.NotEmpty(explanation.GetProperty("summary").GetString()!);
        Assert.Equal(body.GetProperty("risk_level").GetString(), explanation.GetProperty("risk_level").GetString());

        var passageIds = explanation.GetProperty("passages").EnumerateArray()
            .Select(p => p.GetProperty("id").GetString())
            .ToHashSet();
        Assert.NotEmpty(passageIds);

        var keyPoints = explanation.GetProperty("key_points").EnumerateArray().ToList();
        Assert.NotEmpty(keyPoints);
        Assert.All(keyPoints, point => Assert.Contains(point.GetProperty("citation").GetString(), passageIds));
        Assert.Contains(explanation.GetProperty("generator").GetString(), new[] { "rules", "model" });
    }

    [Fact]
    public async Task ReportsAreStoredAndRetrievable()
    {
        var created = await ReadAsync(await Client.PostAsync("/api/threats",
            Json("""{"indicators":{"url":"https://example.com"}}""")));
        var threatId = created.GetProperty("threat_id").GetString()!;

        Assert.Matches("^[0-9a-f-]{36}$", threatId);

        var stored = await ReadAsync(await Client.GetAsync($"/api/threats/{threatId}"));
        Assert.Equal("example.com", stored.GetProperty("domain").GetString());
        Assert.Equal("Safe", stored.GetProperty("analysis").GetProperty("risk_level").GetString());
    }

    [Fact]
    public async Task StoredReportsOmitTheExplanationUnlessRequested()
    {
        var plain = await ReadAsync(await Client.PostAsync("/api/threats",
            Json("""{"indicators":{"url":"http://plain.example.com/"}}""")));
        var plainRecord = await ReadAsync(await Client.GetAsync($"/api/threats/{plain.GetProperty("threat_id").GetString()}"));
        Assert.Equal(JsonValueKind.Null, plainRecord.GetProperty("explanation").ValueKind);

        var explained = await ReadAsync(await Client.PostAsync("/api/threats",
            Json("""{"indicators":{"url":"http://plain.example.com/"},"explain":true}""")));
        var explainedRecord = await ReadAsync(await Client.GetAsync($"/api/threats/{explained.GetProperty("threat_id").GetString()}"));

        var explanation = explainedRecord.GetProperty("explanation");
        Assert.NotEmpty(explanation.GetProperty("summary").GetString()!);
        Assert.Equal(
            explainedRecord.GetProperty("analysis").GetProperty("risk_level").GetString(),
            explanation.GetProperty("risk_level").GetString());
    }

    [Fact]
    public async Task InvalidInputReceivesAClearClientError()
    {
        var response = await Client.PostAsync("/api/threats/analyze", Json("""{"url":"chrome://extensions"}"""));
        var body = await ReadAsync(response);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("HTTP or HTTPS", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task ExplainEndpointRejectsInvalidInputTheSameWayAnalysisDoes()
    {
        var response = await Client.PostAsync("/api/threats/explain",
            Json("""{"indicators":{"url":"file:///etc/passwd"}}"""));
        var body = await ReadAsync(response);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("HTTP or HTTPS", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task MalformedJsonIsRejectedWithAReadableMessage()
    {
        var response = await Client.PostAsync("/api/threats/analyze", Json("{not json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("JSON", (await ReadAsync(response)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task OversizedBodyIsRejected()
    {
        var padded = "{\"indicators\":{\"url\":\"https://example.com\",\"indicator_description\":\""
                     + new string('x', 200_000) + "\"}}";
        var response = await Client.PostAsync("/api/threats/analyze", Json(padded));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task UnknownRoutesAndMissingReportsReturnNotFound()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await Client.GetAsync("/api/nope")).StatusCode);

        var missing = await Client.GetAsync($"/api/threats/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Contains("not found", (await ReadAsync(missing)).GetProperty("error").GetString()!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CorsReflectsExtensionOriginsOnly()
    {
        using var allowed = new HttpRequestMessage(HttpMethod.Get, "/api/health");
        allowed.Headers.Add("Origin", "chrome-extension://abcdefghijklmnop");
        var allowedResponse = await Client.SendAsync(allowed);
        Assert.Equal("chrome-extension://abcdefghijklmnop",
            allowedResponse.Headers.GetValues("Access-Control-Allow-Origin").Single());

        using var denied = new HttpRequestMessage(HttpMethod.Get, "/api/health");
        denied.Headers.Add("Origin", "https://evil.example.com");
        var deniedResponse = await Client.SendAsync(denied);
        Assert.False(deniedResponse.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task PreflightSucceedsWithoutABody()
    {
        using var request = new HttpRequestMessage(HttpMethod.Options, "/api/threats/analyze");
        request.Headers.Add("Origin", "chrome-extension://abcdefghijklmnop");
        var response = await Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Contains("POST", response.Headers.GetValues("Access-Control-Allow-Methods").Single());
    }
}
