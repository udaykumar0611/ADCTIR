using System.Net;
using System.Text.Json;
using Adctir.Api;

namespace Adctir.Tests;

public sealed class ProviderTests
{
    private static async Task<(Explanation Explanation, List<CapturedRequest> Requests)> RunAsync(
        IReadOnlyDictionary<string, string?> environment,
        Func<string, string> respond,
        string url = "http://verify-account.top",
        bool hasLoginForm = true)
    {
        var (indicators, analysis) = await TestCorpus.AnalyzeAsync(url, hasLoginForm);
        var passages = TestCorpus.Explainer.RetrieveContext(indicators, analysis);
        var requests = new List<CapturedRequest>();

        var explainer = TestCorpus.ExplainerWith(request =>
        {
            var raw = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            requests.Add(new CapturedRequest(
                request.RequestUri!.ToString(),
                request,
                JsonDocument.Parse(raw).RootElement.Clone()));
            return TestCorpus.Ok(respond(passages[0].Passage.Id));
        });

        var explanation = await explainer.ExplainAsync(indicators, analysis, TestCorpus.Config(environment));
        return (explanation, requests);
    }

    [Fact]
    public async Task GeminiRequestsCarryTheRightShapeAndProduceAGroundedExplanation()
    {
        var (explanation, requests) = await RunAsync(
            TestCorpus.GeminiEnv,
            citation => TestCorpus.GeminiMessage(TestCorpus.Draft(
                "This page asks for a password over an unencrypted connection.",
                citation,
                "Do not enter your password here.")));

        Assert.Equal("model", explanation.Generator);
        Assert.Equal("gemini", explanation.Provider);
        Assert.Equal("gemini-flash-latest", explanation.Model);
        Assert.NotEmpty(explanation.KeyPoints);

        var request = Assert.Single(requests);
        Assert.Equal(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent",
            request.Url);
        Assert.Equal("test-gemini-key", request.Header("x-goog-api-key"));
        Assert.Null(request.Header("authorization"));

        var generationConfig = request.Body.GetProperty("generationConfig");
        Assert.Equal("application/json", generationConfig.GetProperty("responseMimeType").GetString());
        Assert.Equal("OBJECT", generationConfig.GetProperty("responseSchema").GetProperty("type").GetString());
        Assert.Contains("Grounding rules",
            request.Body.GetProperty("systemInstruction").GetProperty("parts")[0].GetProperty("text").GetString());
    }

    [Fact]
    public async Task OpenRouterRequestsUseTheOpenAiCompatibleShape()
    {
        var (explanation, requests) = await RunAsync(
            TestCorpus.OpenRouterEnv,
            citation => TestCorpus.OpenRouterMessage(TestCorpus.Draft("Unencrypted credential form.", citation)));

        Assert.Equal("openrouter", explanation.Provider);
        Assert.Equal("meta-llama/llama-3.3-70b-instruct:free", explanation.Model);

        var request = Assert.Single(requests);
        Assert.Equal("https://openrouter.ai/api/v1/chat/completions", request.Url);
        Assert.Equal("Bearer sk-or-v1-test", request.Header("authorization"));
        Assert.Equal("system", request.Body.GetProperty("messages")[0].GetProperty("role").GetString());
        Assert.Equal("threat_explanation",
            request.Body.GetProperty("response_format").GetProperty("json_schema").GetProperty("name").GetString());
        Assert.EndsWith(":free", request.Body.GetProperty("model").GetString());
    }

    [Fact]
    public async Task ClaudeRequestsStillWorkThroughTheSamePath()
    {
        var (explanation, requests) = await RunAsync(
            TestCorpus.ClaudeEnv,
            citation => TestCorpus.ClaudeMessage(TestCorpus.Draft("Unencrypted credential form.", citation)));

        Assert.Equal("anthropic", explanation.Provider);

        var request = Assert.Single(requests);
        Assert.Equal("https://api.anthropic.com/v1/messages", request.Url);
        Assert.Equal("sk-ant-test", request.Header("x-api-key"));
        Assert.Equal("2023-06-01", request.Header("anthropic-version"));

        var outputConfig = request.Body.GetProperty("output_config");
        Assert.Equal("json_schema", outputConfig.GetProperty("format").GetProperty("type").GetString());
        Assert.False(outputConfig.TryGetProperty("effort", out _), "effort must stay opt-in");
    }

    [Fact]
    public async Task JsonWrappedInProseOrAMarkdownFenceIsStillAccepted()
    {
        var (explanation, _) = await RunAsync(
            TestCorpus.OpenRouterEnv,
            citation =>
            {
                var payload = JsonSerializer.Serialize(TestCorpus.Draft("Fenced reply.", citation));
                return TestCorpus.OpenRouterMessage(null, $"Here is the analysis:\n```json\n{payload}\n```");
            });

        Assert.Equal("model", explanation.Generator);
        Assert.Equal("Fenced reply.", explanation.Summary);
    }

    [Fact]
    public async Task GeminiSafetyBlockDegradesInsteadOfFailing()
    {
        var (indicators, analysis) = await TestCorpus.AnalyzeAsync("https://example.com/");

        var calls = 0;
        var explainer = TestCorpus.ExplainerWith(_ =>
        {
            calls++;
            return TestCorpus.Ok("""{"promptFeedback":{"blockReason":"SAFETY"}}""");
        });

        var explanation = await explainer.ExplainAsync(indicators, analysis, TestCorpus.Config(TestCorpus.GeminiEnv));

        Assert.Equal(1, calls);
        Assert.Equal("rules", explanation.Generator);
        Assert.Contains("gemini: Gemini blocked the prompt", explanation.DegradedReason);
        Assert.NotEmpty(explanation.Summary);
    }

    [Fact]
    public async Task OpenRouterErrorInsideA200ResponseIsHandled()
    {
        var (indicators, analysis) = await TestCorpus.AnalyzeAsync("https://example.com/");

        var explainer = TestCorpus.ExplainerWith(_ =>
            TestCorpus.Ok("""{"error":{"code":402,"message":"Insufficient credits"}}"""));

        var explanation = await explainer.ExplainAsync(indicators, analysis, TestCorpus.Config(TestCorpus.OpenRouterEnv));

        Assert.Equal("rules", explanation.Generator);
        Assert.Contains("Insufficient credits", explanation.DegradedReason);
    }

    [Fact]
    public async Task NetworkFailureDegradesRatherThanThrowing()
    {
        var (indicators, analysis) = await TestCorpus.AnalyzeAsync("https://example.com/");

        var explainer = TestCorpus.ExplainerWith(_ => throw new HttpRequestException("connection refused"));
        var explanation = await explainer.ExplainAsync(indicators, analysis, TestCorpus.Config(TestCorpus.GeminiEnv));

        Assert.Equal("rules", explanation.Generator);
        Assert.Contains("connection refused", explanation.DegradedReason);
        Assert.NotEmpty(explanation.KeyPoints);
    }

    [Fact]
    public async Task ServerErrorIsRetried()
    {
        var (indicators, analysis) = await TestCorpus.AnalyzeAsync("https://example.com/");

        var calls = 0;
        var explainer = TestCorpus.ExplainerWith(_ =>
        {
            calls++;
            return TestCorpus.Status(HttpStatusCode.ServiceUnavailable,
                """{"error":{"message":"This model is currently experiencing high demand."}}""");
        });

        var explanation = await explainer.ExplainAsync(indicators, analysis, TestCorpus.Config(TestCorpus.GeminiEnv));

        Assert.Equal(2, calls);
        Assert.Contains("high demand", explanation.DegradedReason);
    }
}
