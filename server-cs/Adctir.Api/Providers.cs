using System.Text.Json;
using System.Text.Json.Nodes;

namespace Adctir.Api;

/// <summary>An error from a synthesis provider, carrying whether a retry is worthwhile.</summary>
public sealed class ProviderException(string message, int? status = null, bool retryable = false)
    : Exception(message)
{
    public int? Status { get; } = status;
    public bool Retryable { get; } = retryable;
}

/// <summary>The model's draft, before citation checking.</summary>
public sealed record ExplanationDraft
{
    public string Summary { get; init; } = "";
    public IReadOnlyList<KeyPoint> KeyPoints { get; init; } = [];
    public IReadOnlyList<string> RecommendedActions { get; init; } = [];
    public string Confidence { get; init; } = "medium";
}

public sealed record ProviderRequest(string Url, IReadOnlyDictionary<string, string> Headers, JsonObject Body);

/// <summary>
/// Maps the same inputs - system prompt, user prompt, JSON schema - onto one
/// vendor's HTTP shape, and maps the reply back to a plain draft.
///
/// A provider is never trusted to have honored the schema: every reply goes
/// through <see cref="ProviderRegistry.ExtractJson"/>, and every citation is
/// verified against the retrieved passages afterwards.
/// </summary>
public interface ISynthesisProvider
{
    string Id { get; }
    IReadOnlyList<string> KeyEnvironmentNames { get; }
    string DefaultBaseUrl { get; }
    string DefaultModel { get; }

    ProviderRequest BuildRequest(string system, string prompt, JsonObject schema, AiConfig config);
    ExplanationDraft Parse(JsonElement body);
    string ErrorMessage(JsonElement body, int status);
}

public static class ProviderRegistry
{
    // The response is a small, schema-bounded JSON object. This ceiling is set from
    // that known shape rather than left at a general-purpose default.
    public const int MaxOutputTokens = 2048;

    public static readonly ISynthesisProvider Gemini = new GeminiProvider();
    public static readonly ISynthesisProvider OpenRouter = new OpenRouterProvider();
    public static readonly ISynthesisProvider Anthropic = new AnthropicProvider();

    /// <summary>
    /// Auto-detection order. Free-tier providers come first so that a project with
    /// several keys configured does not silently start spending money.
    /// </summary>
    public static readonly IReadOnlyList<ISynthesisProvider> DetectionOrder = [Gemini, OpenRouter, Anthropic];

    public static ISynthesisProvider? Get(string id) =>
        DetectionOrder.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));

    public static string ReadKey(ISynthesisProvider provider, IReadOnlyDictionary<string, string?> environment)
    {
        foreach (var name in provider.KeyEnvironmentNames)
        {
            if (environment.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }
        return "";
    }

    public static ISynthesisProvider? Detect(IReadOnlyDictionary<string, string?> environment) =>
        DetectionOrder.FirstOrDefault(provider => ReadKey(provider, environment).Length > 0);

    /// <summary>
    /// Free models vary in how well they honor a response schema: some return bare
    /// JSON, some wrap it in a markdown fence, some add a sentence of preamble.
    /// Rather than restrict the project to models with strict structured output,
    /// accept all three shapes and let citation checking catch anything malformed.
    /// </summary>
    public static ExplanationDraft ExtractJson(string? text)
    {
        var trimmed = (text ?? "").Trim();
        if (trimmed.Length == 0) throw new ProviderException("Provider returned no text content");

        var candidates = new List<string> { trimmed };

        var fenceStart = trimmed.IndexOf("```", StringComparison.Ordinal);
        if (fenceStart >= 0)
        {
            var afterFence = trimmed.IndexOf('\n', fenceStart);
            var fenceEnd = afterFence >= 0 ? trimmed.IndexOf("```", afterFence, StringComparison.Ordinal) : -1;
            if (afterFence >= 0 && fenceEnd > afterFence)
            {
                candidates.Add(trimmed[(afterFence + 1)..fenceEnd].Trim());
            }
        }

        var firstBrace = trimmed.IndexOf('{');
        var lastBrace = trimmed.LastIndexOf('}');
        if (firstBrace >= 0 && lastBrace > firstBrace)
        {
            candidates.Add(trimmed[firstBrace..(lastBrace + 1)]);
        }

        foreach (var candidate in candidates)
        {
            try
            {
                var node = JsonNode.Parse(candidate);
                if (node is not JsonObject obj) continue;

                return new ExplanationDraft
                {
                    Summary = obj["summary"]?.GetValue<string>() ?? "",
                    KeyPoints = [.. (obj["key_points"] as JsonArray ?? [])
                        .OfType<JsonObject>()
                        .Select(item => new KeyPoint
                        {
                            Point = item["point"]?.GetValue<string>() ?? "",
                            Citation = item["citation"]?.GetValue<string>()
                        })],
                    RecommendedActions = [.. (obj["recommended_actions"] as JsonArray ?? [])
                        .Select(item => item?.GetValue<string>() ?? "")
                        .Where(value => value.Length > 0)],
                    Confidence = obj["confidence"]?.GetValue<string>() is { } c && c is "low" or "medium" or "high" ? c : "medium"
                };
            }
            catch (JsonException)
            {
                // try the next shape
            }
            catch (InvalidOperationException)
            {
                // a field held an unexpected JSON type; try the next shape
            }
        }
        throw new ProviderException("Provider returned malformed JSON");
    }

    /// <summary>
    /// Gemini accepts an OpenAPI 3.0 subset rather than full JSON Schema: types are
    /// upper-case and additionalProperties is rejected.
    /// </summary>
    public static JsonNode? ToGeminiSchema(JsonNode? schema)
    {
        switch (schema)
        {
            case JsonArray array:
                return new JsonArray([.. array.Select(item => ToGeminiSchema(item?.DeepClone()))]);

            case JsonObject obj:
                var converted = new JsonObject();
                foreach (var (key, value) in obj)
                {
                    switch (key)
                    {
                        case "additionalProperties":
                            continue;
                        case "type":
                            converted["type"] = value?.GetValue<string>().ToUpperInvariant();
                            break;
                        case "items":
                            converted["items"] = ToGeminiSchema(value?.DeepClone());
                            break;
                        case "properties":
                            var properties = new JsonObject();
                            foreach (var (name, definition) in value as JsonObject ?? [])
                            {
                                properties[name] = ToGeminiSchema(definition?.DeepClone());
                            }
                            converted["properties"] = properties;
                            break;
                        default:
                            converted[key] = value?.DeepClone();
                            break;
                    }
                }
                if (converted["type"]?.GetValue<string>() == "OBJECT" && converted["properties"] is JsonObject ordered)
                {
                    converted["propertyOrdering"] = new JsonArray([.. ordered.Select(p => JsonValue.Create(p.Key))]);
                }
                return converted;

            default:
                return schema?.DeepClone();
        }
    }
}

internal sealed class GeminiProvider : ISynthesisProvider
{
    public string Id => "gemini";
    public IReadOnlyList<string> KeyEnvironmentNames => ["GEMINI_API_KEY", "GOOGLE_API_KEY"];
    public string DefaultBaseUrl => "https://generativelanguage.googleapis.com";
    public string DefaultModel => "gemini-flash-latest";

    public ProviderRequest BuildRequest(string system, string prompt, JsonObject schema, AiConfig config) => new(
        $"{config.BaseUrl}/v1beta/models/{Uri.EscapeDataString(config.Model)}:generateContent",
        new Dictionary<string, string> { ["x-goog-api-key"] = config.ApiKey },
        new JsonObject
        {
            ["systemInstruction"] = new JsonObject { ["parts"] = new JsonArray(new JsonObject { ["text"] = system }) },
            ["contents"] = new JsonArray(new JsonObject
            {
                ["role"] = "user",
                ["parts"] = new JsonArray(new JsonObject { ["text"] = prompt })
            }),
            ["generationConfig"] = new JsonObject
            {
                ["responseMimeType"] = "application/json",
                ["responseSchema"] = ProviderRegistry.ToGeminiSchema(schema),
                ["maxOutputTokens"] = ProviderRegistry.MaxOutputTokens,
                ["temperature"] = 0.2
            }
        });

    public ExplanationDraft Parse(JsonElement body)
    {
        if (body.TryGetProperty("promptFeedback", out var feedback) &&
            feedback.TryGetProperty("blockReason", out var blockReason))
        {
            throw new ProviderException($"Gemini blocked the prompt ({blockReason.GetString()})");
        }
        if (!body.TryGetProperty("candidates", out var candidates) ||
            candidates.ValueKind != JsonValueKind.Array ||
            candidates.GetArrayLength() == 0)
        {
            throw new ProviderException("Gemini returned no candidates");
        }

        var candidate = candidates[0];
        if (candidate.TryGetProperty("finishReason", out var finish) &&
            finish.GetString() is { } reason && reason is not ("STOP" or "MAX_TOKENS"))
        {
            throw new ProviderException($"Gemini stopped early ({reason})");
        }

        var text = "";
        if (candidate.TryGetProperty("content", out var content) &&
            content.TryGetProperty("parts", out var parts) &&
            parts.ValueKind == JsonValueKind.Array)
        {
            text = string.Concat(parts.EnumerateArray()
                .Select(part => part.TryGetProperty("text", out var t) ? t.GetString() ?? "" : ""));
        }
        return ProviderRegistry.ExtractJson(text);
    }

    public string ErrorMessage(JsonElement body, int status) =>
        body.TryGetProperty("error", out var error) && error.TryGetProperty("message", out var message)
            ? message.GetString() ?? $"Gemini API returned {status}"
            : $"Gemini API returned {status}";
}

internal sealed class OpenRouterProvider : ISynthesisProvider
{
    public string Id => "openrouter";
    public IReadOnlyList<string> KeyEnvironmentNames => ["OPENROUTER_API_KEY"];
    public string DefaultBaseUrl => "https://openrouter.ai/api/v1";
    public string DefaultModel => "meta-llama/llama-3.3-70b-instruct:free";

    public ProviderRequest BuildRequest(string system, string prompt, JsonObject schema, AiConfig config) => new(
        $"{config.BaseUrl}/chat/completions",
        new Dictionary<string, string>
        {
            ["authorization"] = $"Bearer {config.ApiKey}",
            // OpenRouter attributes traffic to an app by these headers; they are
            // optional and carry no user data.
            ["http-referer"] = "https://github.com/adctir/adctir-extension",
            ["x-title"] = "ADCTIR Security Extension"
        },
        new JsonObject
        {
            ["model"] = config.Model,
            ["messages"] = new JsonArray(
                new JsonObject { ["role"] = "system", ["content"] = system },
                new JsonObject { ["role"] = "user", ["content"] = prompt }),
            ["response_format"] = new JsonObject
            {
                ["type"] = "json_schema",
                ["json_schema"] = new JsonObject
                {
                    ["name"] = "threat_explanation",
                    ["strict"] = true,
                    ["schema"] = schema.DeepClone()
                }
            },
            ["max_tokens"] = ProviderRegistry.MaxOutputTokens,
            ["temperature"] = 0.2
        });

    public ExplanationDraft Parse(JsonElement body)
    {
        // OpenRouter can return a 200 whose payload carries a provider-side error.
        if (body.TryGetProperty("error", out var error))
        {
            var status = error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.Number
                ? code.GetInt32()
                : (int?)null;
            var message = error.TryGetProperty("message", out var m) ? m.GetString() : null;
            throw new ProviderException(message ?? "OpenRouter returned an error", status, status is 429 or >= 500);
        }
        if (!body.TryGetProperty("choices", out var choices) ||
            choices.ValueKind != JsonValueKind.Array ||
            choices.GetArrayLength() == 0)
        {
            throw new ProviderException("OpenRouter returned no choices");
        }

        var choice = choices[0];
        if (choice.TryGetProperty("finish_reason", out var finish) && finish.GetString() == "content_filter")
        {
            throw new ProviderException("The model declined to answer (content filter)");
        }

        var content = choice.TryGetProperty("message", out var message2) && message2.TryGetProperty("content", out var text)
            ? text.GetString()
            : null;
        return ProviderRegistry.ExtractJson(content);
    }

    public string ErrorMessage(JsonElement body, int status) =>
        body.TryGetProperty("error", out var error) && error.TryGetProperty("message", out var message)
            ? message.GetString() ?? $"OpenRouter API returned {status}"
            : $"OpenRouter API returned {status}";
}

internal sealed class AnthropicProvider : ISynthesisProvider
{
    public string Id => "anthropic";
    public IReadOnlyList<string> KeyEnvironmentNames => ["ANTHROPIC_API_KEY"];
    public string DefaultBaseUrl => "https://api.anthropic.com";
    public string DefaultModel => "claude-haiku-4-5";

    public ProviderRequest BuildRequest(string system, string prompt, JsonObject schema, AiConfig config)
    {
        var outputConfig = new JsonObject
        {
            ["format"] = new JsonObject { ["type"] = "json_schema", ["schema"] = schema.DeepClone() }
        };
        // `effort` is rejected by models that do not support it, so it stays opt-in.
        if (!string.IsNullOrWhiteSpace(config.Effort)) outputConfig["effort"] = config.Effort;

        return new ProviderRequest(
            $"{config.BaseUrl}/v1/messages",
            new Dictionary<string, string>
            {
                ["x-api-key"] = config.ApiKey,
                ["anthropic-version"] = "2023-06-01"
            },
            new JsonObject
            {
                ["model"] = config.Model,
                ["max_tokens"] = ProviderRegistry.MaxOutputTokens,
                ["system"] = system,
                ["output_config"] = outputConfig,
                ["messages"] = new JsonArray(new JsonObject { ["role"] = "user", ["content"] = prompt })
            });
    }

    public ExplanationDraft Parse(JsonElement body)
    {
        if (body.TryGetProperty("stop_reason", out var stopReason) && stopReason.GetString() == "refusal")
        {
            var category = body.TryGetProperty("stop_details", out var details) &&
                           details.TryGetProperty("category", out var c)
                ? c.GetString()
                : "unspecified";
            throw new ProviderException($"The model declined to answer ({category})");
        }

        var text = "";
        if (body.TryGetProperty("content", out var content) && content.ValueKind == JsonValueKind.Array)
        {
            text = string.Concat(content.EnumerateArray()
                .Where(block => block.TryGetProperty("type", out var type) && type.GetString() == "text")
                .Select(block => block.TryGetProperty("text", out var t) ? t.GetString() ?? "" : ""));
        }
        return ProviderRegistry.ExtractJson(text);
    }

    public string ErrorMessage(JsonElement body, int status) =>
        body.TryGetProperty("error", out var error) && error.TryGetProperty("message", out var message)
            ? message.GetString() ?? $"Claude API returned {status}"
            : $"Claude API returned {status}";
}
