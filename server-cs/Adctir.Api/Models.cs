using System.Text.Json.Serialization;

namespace Adctir.Api;

/// <summary>
/// Page signals after normalization. Property names are snake_case on the wire so
/// the existing extension client needs no changes.
/// </summary>
public sealed record Indicators
{
    [JsonPropertyName("url")] public required string Url { get; init; }
    [JsonPropertyName("domain")] public required string Domain { get; init; }
    [JsonPropertyName("https_used")] public required bool HttpsUsed { get; init; }
    [JsonPropertyName("redirect_count")] public required int RedirectCount { get; init; }
    [JsonPropertyName("has_login_form")] public required bool HasLoginForm { get; init; }
    [JsonPropertyName("suspicious_pattern")] public string? SuspiciousPattern { get; init; }
    [JsonPropertyName("domain_age_days")] public int? DomainAgeDays { get; init; }
    [JsonPropertyName("indicator_description")] public string? IndicatorDescription { get; init; }
}

/// <summary>One rule hit, carrying the weight it contributed and where it came from.</summary>
public sealed record Evidence
{
    [JsonPropertyName("id")] public required string Id { get; init; }
    [JsonPropertyName("weight")] public required int Weight { get; init; }
    [JsonPropertyName("source")] public required string Source { get; init; }
    [JsonPropertyName("value")] public required object Value { get; init; }
}

public sealed record Analysis
{
    [JsonPropertyName("risk_score")] public required int RiskScore { get; init; }
    [JsonPropertyName("risk_level")] public required string RiskLevel { get; init; }
    [JsonPropertyName("reasons")] public required IReadOnlyList<string> Reasons { get; init; }
    [JsonPropertyName("evidence")] public required IReadOnlyList<Evidence> EvidenceItems { get; init; }
    [JsonPropertyName("domain_age_days")] public int? DomainAgeDays { get; init; }
    [JsonPropertyName("engine_version")] public required string EngineVersion { get; init; }
    [JsonPropertyName("analyzed_at")] public required string AnalyzedAt { get; init; }
}

/// <summary>A retrieved knowledge passage as reported back to the client.</summary>
public sealed record PassageRef
{
    [JsonPropertyName("id")] public required string Id { get; init; }
    [JsonPropertyName("doc_title")] public required string DocTitle { get; init; }
    [JsonPropertyName("section")] public required string Section { get; init; }
    [JsonPropertyName("score")] public required double Score { get; init; }
    [JsonPropertyName("matched_finding_ids")] public required IReadOnlyList<string> MatchedFindingIds { get; init; }
}

public sealed record KeyPoint
{
    [JsonPropertyName("point")] public required string Point { get; init; }
    [JsonPropertyName("citation")] public string? Citation { get; init; }
}

public sealed record Explanation
{
    [JsonPropertyName("summary")] public required string Summary { get; init; }
    [JsonPropertyName("key_points")] public required IReadOnlyList<KeyPoint> KeyPoints { get; init; }
    [JsonPropertyName("recommended_actions")] public required IReadOnlyList<string> RecommendedActions { get; init; }
    [JsonPropertyName("confidence")] public required string Confidence { get; init; }
    [JsonPropertyName("risk_level")] public required string RiskLevel { get; init; }
    [JsonPropertyName("risk_score")] public required int RiskScore { get; init; }
    [JsonPropertyName("generator")] public required string Generator { get; init; }
    [JsonPropertyName("provider")] public string? Provider { get; init; }
    [JsonPropertyName("model")] public string? Model { get; init; }
    [JsonPropertyName("passages")] public required IReadOnlyList<PassageRef> Passages { get; init; }
    [JsonPropertyName("corpus_version")] public required string CorpusVersion { get; init; }
    [JsonPropertyName("explainer_version")] public required string ExplainerVersion { get; init; }
    [JsonPropertyName("degraded_reason")] public string? DegradedReason { get; init; }
    [JsonPropertyName("generated_at")] public required string GeneratedAt { get; init; }
}

/// <summary>A stored threat report.</summary>
public sealed record ThreatRecord
{
    [JsonPropertyName("threat_id")] public required string ThreatId { get; init; }
    [JsonPropertyName("status")] public required string Status { get; init; }
    [JsonPropertyName("url")] public required string Url { get; init; }
    [JsonPropertyName("domain")] public required string Domain { get; init; }
    [JsonPropertyName("indicators")] public required Indicators Indicators { get; init; }
    [JsonPropertyName("analysis")] public required Analysis Analysis { get; init; }
    [JsonPropertyName("explanation")] public Explanation? Explanation { get; init; }
    [JsonPropertyName("reported_at")] public required string ReportedAt { get; init; }
}

/// <summary>
/// Raw request body. Every field is nullable because validation is the analyzer's
/// job - a bad payload must produce a 400 with a readable message, not a bind error.
/// </summary>
public sealed class IndicatorInput
{
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("redirect_count")] public double? RedirectCount { get; set; }
    [JsonPropertyName("has_login_form")] public bool? HasLoginForm { get; set; }
    [JsonPropertyName("suspicious_pattern")] public string? SuspiciousPattern { get; set; }
    [JsonPropertyName("domain_age_days")] public double? DomainAgeDays { get; set; }
    [JsonPropertyName("indicator_description")] public string? IndicatorDescription { get; set; }
}

public sealed class ThreatRequest
{
    [JsonPropertyName("indicators")] public IndicatorInput? Indicators { get; set; }
    [JsonPropertyName("explain")] public bool? Explain { get; set; }

    // The analyze/explain endpoints also accept a bare indicator object, matching
    // the Node API's `body.indicators || body` behaviour.
    [JsonPropertyName("url")] public string? Url { get; set; }
    [JsonPropertyName("redirect_count")] public double? RedirectCount { get; set; }
    [JsonPropertyName("has_login_form")] public bool? HasLoginForm { get; set; }
    [JsonPropertyName("suspicious_pattern")] public string? SuspiciousPattern { get; set; }
    [JsonPropertyName("domain_age_days")] public double? DomainAgeDays { get; set; }
    [JsonPropertyName("indicator_description")] public string? IndicatorDescription { get; set; }

    public IndicatorInput ToIndicatorInput() => Indicators ?? new IndicatorInput
    {
        Url = Url,
        RedirectCount = RedirectCount,
        HasLoginForm = HasLoginForm,
        SuspiciousPattern = SuspiciousPattern,
        DomainAgeDays = DomainAgeDays,
        IndicatorDescription = IndicatorDescription
    };
}

/// <summary>Thrown for input the client can fix; surfaces as a 400 with the message.</summary>
public sealed class ValidationException(string message) : Exception(message);
