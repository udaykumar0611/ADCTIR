using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Adctir.Api;

namespace Adctir.Tests;

/// <summary>
/// Shared fixtures. The knowledge corpus is loaded once from the built output, and
/// every analysis runs with RDAP disabled so tests never touch the network.
/// </summary>
internal static class TestCorpus
{
    public static readonly KnowledgeIndex Index =
        KnowledgeIndex.LoadFrom(Path.Combine(AppContext.BaseDirectory, "Knowledge"));

    public static readonly ThreatExplainer Explainer = new(Index, new HttpClient());

    public static readonly IReadOnlyDictionary<string, string?> GeminiEnv =
        new Dictionary<string, string?> { ["GEMINI_API_KEY"] = "test-gemini-key" };

    public static readonly IReadOnlyDictionary<string, string?> OpenRouterEnv =
        new Dictionary<string, string?> { ["OPENROUTER_API_KEY"] = "sk-or-v1-test" };

    public static readonly IReadOnlyDictionary<string, string?> ClaudeEnv =
        new Dictionary<string, string?> { ["ANTHROPIC_API_KEY"] = "sk-ant-test" };

    public static async Task<(Indicators Indicators, Analysis Analysis)> AnalyzeAsync(
        string url,
        bool hasLoginForm = false,
        int redirectCount = 0)
    {
        var indicators = Analyzer.Normalize(new IndicatorInput
        {
            Url = url,
            HasLoginForm = hasLoginForm,
            RedirectCount = redirectCount
        });
        var analysis = await new Analyzer().AnalyzeAsync(indicators, enableRdap: false);
        return (indicators, analysis);
    }

    /// <summary>Builds an explainer whose HTTP transport is the supplied stub.</summary>
    public static ThreatExplainer ExplainerWith(Func<HttpRequestMessage, HttpResponseMessage> handler) =>
        new(Index, new HttpClient(new StubHandler(handler)));

    /// <summary>An HttpClient whose transport is the supplied stub.</summary>
    public static HttpClient StubClient(Func<HttpRequestMessage, HttpResponseMessage> handler) =>
        new(new StubHandler(handler));

    public static AiConfig Config(IReadOnlyDictionary<string, string?> environment) =>
        ThreatExplainer.ReadConfig(environment);

    public static HttpResponseMessage Ok(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };

    public static HttpResponseMessage Status(HttpStatusCode code, string json) => new(code)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };

    public static string GeminiMessage(object payload, string? text = null)
    {
        var body = text ?? JsonSerializer.Serialize(payload);
        return new JsonObject
        {
            ["candidates"] = new JsonArray(new JsonObject
            {
                ["finishReason"] = "STOP",
                ["content"] = new JsonObject { ["parts"] = new JsonArray(new JsonObject { ["text"] = body }) }
            })
        }.ToJsonString();
    }

    public static string OpenRouterMessage(object? payload, string? text = null)
    {
        var body = text ?? JsonSerializer.Serialize(payload);
        return new JsonObject
        {
            ["choices"] = new JsonArray(new JsonObject
            {
                ["finish_reason"] = "stop",
                ["message"] = new JsonObject { ["content"] = body }
            })
        }.ToJsonString();
    }

    public static string ClaudeMessage(object payload)
    {
        var body = JsonSerializer.Serialize(payload);
        return new JsonObject
        {
            ["model"] = "claude-haiku-4-5",
            ["stop_reason"] = "end_turn",
            ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = body })
        }.ToJsonString();
    }

    public static object Draft(string summary, string citation, params string[] actions) => new
    {
        summary,
        key_points = new[] { new { point = "Credentials would be sent in cleartext.", citation } },
        recommended_actions = actions,
        confidence = "high"
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Materialize the body before the caller disposes the request.
            if (request.Content is not null) await request.Content.LoadIntoBufferAsync(cancellationToken);
            return handler(request);
        }
    }
}

/// <summary>Captures what a provider actually put on the wire.</summary>
internal sealed record CapturedRequest(string Url, HttpRequestMessage Message, JsonElement Body)
{
    public string? Header(string name) =>
        Message.Headers.TryGetValues(name, out var values) ? string.Join(",", values) : null;
}
