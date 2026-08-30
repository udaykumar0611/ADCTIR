using System.Net;
using System.Text.Json;

namespace Adctir.Api;

/// <summary>
/// Deterministic, explainable rules engine. This is the only source of the risk
/// score and risk level; the explanation layer may describe a verdict but never
/// change one.
/// </summary>
// rdapTimeoutMs of 0 means "use DefaultRdapTimeoutMs"; a primary-constructor
// default cannot reference a member of its own class.
public sealed class Analyzer(HttpClient? httpClient = null, int rdapTimeoutMs = 0, ILogger<Analyzer>? logger = null)
{
    public const string EngineVersion = "adctir-rules-1.0.0";

    /// <summary>
    /// A lookup is two round trips: rdap.org answers 302 and the authoritative
    /// registry serves the record, so two DNS resolutions and two TLS handshakes.
    /// Warm that is well under a second; cold it regularly exceeds three. The old
    /// 2.5s budget silently failed every first lookup.
    /// </summary>
    public const int DefaultRdapTimeoutMs = 8000;

    public const string RdapUserAgent = "ADCTIR-Security-Extension/1.0";

    private static readonly string[] SensitiveWords =
        ["login", "verify", "secure", "account", "update", "signin", "wallet", "password"];

    private static readonly HashSet<string> ShortenerHosts =
        ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "cutt.ly"];

    private static readonly HashSet<string> HighRiskTlds =
        ["zip", "mov", "top", "click", "work", "gq", "tk"];

    private readonly HttpClient? _httpClient = httpClient;
    private readonly int _rdapTimeoutMs = rdapTimeoutMs > 0 ? rdapTimeoutMs : DefaultRdapTimeoutMs;
    private readonly ILogger<Analyzer>? _logger = logger;

    public static Indicators Normalize(IndicatorInput? input)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (string.IsNullOrWhiteSpace(input.Url) ||
            !Uri.TryCreate(input.Url, UriKind.Absolute, out var parsed))
        {
            throw new ValidationException("url must be a valid HTTP or HTTPS URL");
        }
        if (parsed.Scheme is not ("http" or "https"))
        {
            throw new ValidationException("url must use HTTP or HTTPS");
        }

        var redirectCount = input.RedirectCount is { } raw && double.IsFinite(raw)
            ? Math.Max(0, Math.Min(50, (int)Math.Truncate(raw)))
            : 0;

        int? domainAge = input.DomainAgeDays is { } age && double.IsFinite(age)
            ? Math.Max(0, (int)Math.Truncate(age))
            : null;

        return new Indicators
        {
            Url = parsed.AbsoluteUri,
            Domain = parsed.Host.ToLowerInvariant(),
            HttpsUsed = parsed.Scheme == "https",
            RedirectCount = redirectCount,
            HasLoginForm = input.HasLoginForm == true,
            SuspiciousPattern = Truncate(input.SuspiciousPattern, 2000),
            DomainAgeDays = domainAge,
            IndicatorDescription = Truncate(input.IndicatorDescription, 500)
        };
    }

    private static string? Truncate(string? value, int max) =>
        value is null ? null : value.Length <= max ? value : value[..max];

    private static void Add(List<Evidence> findings, ICollection<string> reasons, string id, int weight, string reason, string source, object value)
    {
        if (findings.Any(f => f.Id == id)) return;
        findings.Add(new Evidence { Id = id, Weight = weight, Source = source, Value = value });
        reasons.Add(reason);
    }

    public async Task<Analysis> AnalyzeAsync(Indicators indicators, bool enableRdap, CancellationToken cancellationToken = default)
    {
        var findings = new List<Evidence>();
        var reasons = new List<string>();
        var parsed = new Uri(indicators.Url);
        var host = indicators.Domain;

        if (!indicators.HttpsUsed)
        {
            Add(findings, reasons, "no_https", 25, "Connection is not using HTTPS", "URL protocol", parsed.Scheme + ":");
        }
        if (indicators.HasLoginForm && !indicators.HttpsUsed)
        {
            Add(findings, reasons, "insecure_login", 25, "Login form is present on a non-HTTPS page", "page signal", true);
        }
        if (indicators.RedirectCount >= 3)
        {
            Add(findings, reasons, "many_redirects", 15, $"Page reported {indicators.RedirectCount} redirects", "Navigation Timing", indicators.RedirectCount);
        }
        if (IPAddress.TryParse(host, out _))
        {
            Add(findings, reasons, "raw_ip", 22, "Host is an IP address rather than a domain name", "URL host", host);
        }
        if (host.StartsWith("xn--", StringComparison.Ordinal) || host.Contains(".xn--", StringComparison.Ordinal))
        {
            Add(findings, reasons, "punycode", 25, "Domain uses punycode and may imitate another name", "URL host", host);
        }
        if (host.Count(c => c == '-') >= 3)
        {
            Add(findings, reasons, "many_hyphens", 10, "Domain contains an unusual number of hyphens", "URL host", host);
        }
        if (!string.IsNullOrEmpty(parsed.UserInfo))
        {
            Add(findings, reasons, "embedded_credentials", 28, "URL contains credentials before the host", "URL authority", "credentials present");
        }
        if (host.Split('.').Length - 2 >= 3)
        {
            Add(findings, reasons, "many_subdomains", 12, "Domain has an excessive number of subdomains", "URL host", host);
        }

        var wordHits = SensitiveWords.Where(word => host.Contains(word, StringComparison.Ordinal)).ToArray();
        if (wordHits.Length > 0)
        {
            Add(findings, reasons, "sensitive_domain_words", 10, $"Domain contains sensitive terms: {string.Join(", ", wordHits)}", "URL host", wordHits);
        }
        if (ShortenerHosts.Contains(host))
        {
            Add(findings, reasons, "url_shortener", 12, "URL uses a link-shortening service", "local reputation rules", host);
        }

        var tld = host.Split('.').LastOrDefault() ?? "";
        if (HighRiskTlds.Contains(tld))
        {
            Add(findings, reasons, "higher_risk_tld", 8, $"Domain uses the .{tld} top-level domain", "local reputation rules", tld);
        }
        if (indicators.Url.Length > 200)
        {
            Add(findings, reasons, "long_url", 8, "URL is unusually long", "URL length", indicators.Url.Length);
        }

        var domainAgeDays = indicators.DomainAgeDays;
        if (domainAgeDays is null && enableRdap)
        {
            domainAgeDays = await FetchDomainAgeDaysAsync(host, cancellationToken);
        }
        if (domainAgeDays is { } days && days < 30)
        {
            Add(findings, reasons, "new_domain", 25, $"Domain appears to be only {days} days old", "RDAP registration data", days);
        }
        else if (domainAgeDays is { } youngDays && youngDays < 180)
        {
            Add(findings, reasons, "young_domain", 12, $"Domain appears to be {youngDays} days old", "RDAP registration data", youngDays);
        }

        var riskScore = Math.Min(100, findings.Sum(f => f.Weight));
        var riskLevel = riskScore >= 60 ? "High-Risk" : riskScore >= 25 ? "Suspicious" : "Safe";

        return new Analysis
        {
            RiskScore = riskScore,
            RiskLevel = riskLevel,
            Reasons = reasons.Count > 0 ? reasons : ["No suspicious indicators were detected"],
            EvidenceItems = findings,
            DomainAgeDays = domainAgeDays,
            EngineVersion = EngineVersion,
            AnalyzedAt = DateTimeOffset.UtcNow.ToString("o")
        };
    }

    /// <summary>
    /// Public RDAP registration lookup. Enrichment only - any failure returns null
    /// so that an unreachable registry never breaks an analysis.
    /// </summary>
    public async Task<int?> FetchDomainAgeDaysAsync(string domain, CancellationToken cancellationToken = default)
    {
        if (_httpClient is null || IPAddress.TryParse(domain, out _) || domain == "localhost") return null;

        var labels = domain.Split('.');
        var registrableGuess = labels.Length >= 2 ? string.Join('.', labels[^2..]) : domain;

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(_rdapTimeoutMs));

            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://rdap.org/domain/{Uri.EscapeDataString(registrableGuess)}");
            request.Headers.TryAddWithoutValidation("Accept", "application/rdap+json, application/json");
            // rdap.org answers 403 to a request with no User-Agent, and HttpClient
            // sends none by default. Identifying the client is also the polite way
            // to use a free public service.
            request.Headers.TryAddWithoutValidation("User-Agent", RdapUserAgent);

            using var response = await _httpClient.SendAsync(request, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                // 404 is the normal answer for an unregistered or unlisted name.
                _logger?.LogDebug("[ADCTIR] RDAP lookup for {Domain} returned {Status}", registrableGuess, (int)response.StatusCode);
                return null;
            }

            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(timeout.Token));
            if (!document.RootElement.TryGetProperty("events", out var events) || events.ValueKind != JsonValueKind.Array)
            {
                _logger?.LogDebug("[ADCTIR] RDAP record for {Domain} carried no events array", registrableGuess);
                return null;
            }

            foreach (var entry in events.EnumerateArray())
            {
                if (!entry.TryGetProperty("eventAction", out var action) || action.GetString() != "registration") continue;
                if (!entry.TryGetProperty("eventDate", out var date)) continue;
                if (!DateTimeOffset.TryParse(date.GetString(), out var registeredAt)) return null;
                return Math.Max(0, (int)Math.Floor((DateTimeOffset.UtcNow - registeredAt).TotalDays));
            }

            _logger?.LogDebug("[ADCTIR] RDAP record for {Domain} had no registration event", registrableGuess);
            return null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Enrichment only: a slow registry must never fail or delay an analysis
            // beyond its budget, but silence here is what hid the too-short timeout.
            _logger?.LogDebug("[ADCTIR] RDAP lookup for {Domain} timed out after {TimeoutMs}ms", registrableGuess, _rdapTimeoutMs);
            return null;
        }
        catch (Exception error)
        {
            _logger?.LogDebug(error, "[ADCTIR] RDAP lookup for {Domain} failed", registrableGuess);
            return null;
        }
    }
}
