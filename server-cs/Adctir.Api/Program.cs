using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Adctir.Api;

var builder = WebApplication.CreateBuilder(args);

// Development convenience only: load .env before anything reads the environment.
// Already-set variables win, and this is skipped outside development so a deployed
// host uses its own secrets management.
string? loadedEnvFile = null;
if (!builder.Environment.IsProduction())
{
    loadedEnvFile = DotEnv.Load(builder.Environment.ContentRootPath);
}

var host = Environment.GetEnvironmentVariable("ADCTIR_HOST") ?? "127.0.0.1";
var port = int.TryParse(Environment.GetEnvironmentVariable("ADCTIR_PORT"), out var parsedPort) ? parsedPort : 5001;
var enableRdap = Environment.GetEnvironmentVariable("ADCTIR_ENABLE_RDAP") != "false";
var dataFile = Environment.GetEnvironmentVariable("ADCTIR_DATA_FILE")
               ?? Path.Combine(builder.Environment.ContentRootPath, "data", "threats.json");
var knowledgeDirectory = Path.Combine(AppContext.BaseDirectory, "Knowledge");

// Tests drive the app through WebApplicationFactory, which supplies its own server.
if (!builder.Environment.IsEnvironment("Testing"))
{
    builder.WebHost.UseUrls($"http://{host}:{port}");
}

// Minimal APIs otherwise swallow a JSON binding failure and return an empty 400.
// Throwing lets the error middleware return the same {"error": "..."} shape the
// extension already handles for every other failure.
builder.Services.Configure<RouteHandlerOptions>(options => options.ThrowOnBadRequest = true);

builder.Services.AddHttpClient();
builder.Services.AddSingleton(_ => KnowledgeIndex.LoadFrom(knowledgeDirectory));
builder.Services.AddSingleton(new ThreatStore(dataFile));
var rdapTimeoutMs = int.TryParse(Environment.GetEnvironmentVariable("ADCTIR_RDAP_TIMEOUT_MS"), out var parsedRdapTimeout) && parsedRdapTimeout > 0
    ? parsedRdapTimeout
    : Analyzer.DefaultRdapTimeoutMs;

builder.Services.AddSingleton(serviceProvider => new Analyzer(
    serviceProvider.GetRequiredService<IHttpClientFactory>().CreateClient(),
    rdapTimeoutMs,
    serviceProvider.GetRequiredService<ILogger<Analyzer>>()));
builder.Services.AddSingleton(serviceProvider => new ThreatExplainer(
    serviceProvider.GetRequiredService<KnowledgeIndex>(),
    serviceProvider.GetRequiredService<IHttpClientFactory>().CreateClient()));

var app = builder.Build();

if (loadedEnvFile is not null)
{
    // Log the path only - never the contents.
    app.Logger.LogInformation("[ADCTIR] loaded environment from {EnvFile}", loadedEnvFile);
}

var requestWindows = new ConcurrentDictionary<string, (long StartedAt, int Count)>();
var localOriginPattern = new Regex(@"^https?://(localhost|127\.0\.0\.1)(:\d+)?$", RegexOptions.Compiled);

// Registered first so it wraps every later middleware, including the body-size cap
// and minimal-API model binding - both of which throw BadHttpRequestException.
// Validation failures become a 400 with a readable message; anything else is a 500
// with the detail kept server-side.
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (ValidationException error)
    {
        if (context.Response.HasStarted) throw;
        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { error = error.Message });
    }
    catch (BadHttpRequestException error)
    {
        if (context.Response.HasStarted) throw;
        var tooLarge = error.StatusCode == StatusCodes.Status413PayloadTooLarge;
        context.Response.Clear();
        context.Response.StatusCode = tooLarge
            ? StatusCodes.Status413PayloadTooLarge
            : StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new
        {
            error = tooLarge ? "Request body is too large" : "Request body must be valid JSON"
        });
    }
    catch (Exception error)
    {
        if (context.Response.HasStarted) throw;
        app.Logger.LogError(error, "[ADCTIR] unhandled error");
        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsJsonAsync(new { error = "Internal server error" });
    }
});

app.Use(async (context, next) =>
{
    // CORS: only the packaged extension and local development origins are reflected.
    var origin = context.Request.Headers.Origin.ToString();
    if (origin.StartsWith("chrome-extension://", StringComparison.Ordinal) || localOriginPattern.IsMatch(origin))
    {
        context.Response.Headers.AccessControlAllowOrigin = origin;
        context.Response.Headers.Vary = "Origin";
    }
    context.Response.Headers.AccessControlAllowHeaders = "Content-Type";
    context.Response.Headers.AccessControlAllowMethods = "GET, POST, OPTIONS";

    if (HttpMethods.IsOptions(context.Request.Method))
    {
        context.Response.StatusCode = StatusCodes.Status204NoContent;
        return;
    }

    // Fixed-window rate limit, 120 requests per minute per remote address.
    var key = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var now = Environment.TickCount64;
    var allowed = true;
    requestWindows.AddOrUpdate(
        key,
        _ => (now, 1),
        (_, current) =>
        {
            if (now - current.StartedAt >= 60000) return (now, 1);
            var count = current.Count + 1;
            allowed = count <= 120;
            return (current.StartedAt, count);
        });

    if (!allowed)
    {
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.Response.WriteAsJsonAsync(new { error = "Too many requests; try again shortly" });
        return;
    }

    context.Request.Body = new MemoryStream(await ReadCappedBodyAsync(context));
    await next();
});

app.MapGet("/", () => Results.Json(new
{
    service = "ADCTIR Threat Analysis API",
    status = "ready",
    version = "1.0.0"
}));

app.MapGet("/api/health", () =>
{
    var ai = ThreatExplainer.ReadConfig(ReadEnvironment());
    return Results.Json(new
    {
        ok = true,
        rdap_enabled = enableRdap,
        explain_enabled = true,
        ai_generator = ai.Enabled ? "model" : "rules",
        ai_provider = ai.Enabled ? ai.ProviderId : null,
        ai_model = ai.Enabled ? ai.Model : null,
        ai_config_error = ai.ConfigError
    });
});

app.MapPost("/api/threats/analyze", async (ThreatRequest? request, Analyzer analyzer, CancellationToken cancellationToken) =>
{
    var indicators = Analyzer.Normalize(request?.ToIndicatorInput());
    var analysis = await analyzer.AnalyzeAsync(indicators, enableRdap, cancellationToken);
    return Results.Json(AnalysisResponse(analysis, indicators, explanation: null));
});

app.MapPost("/api/threats/explain", async (
    ThreatRequest? request,
    Analyzer analyzer,
    ThreatExplainer explainer,
    CancellationToken cancellationToken) =>
{
    var indicators = Analyzer.Normalize(request?.ToIndicatorInput());
    var analysis = await analyzer.AnalyzeAsync(indicators, enableRdap, cancellationToken);
    var enriched = indicators with { DomainAgeDays = analysis.DomainAgeDays };
    var explanation = await explainer.ExplainAsync(enriched, analysis, ThreatExplainer.ReadConfig(ReadEnvironment()), cancellationToken);
    return Results.Json(AnalysisResponse(analysis, indicators, explanation));
});

app.MapPost("/api/threats", async (
    ThreatRequest? request,
    Analyzer analyzer,
    ThreatExplainer explainer,
    ThreatStore store,
    CancellationToken cancellationToken) =>
{
    var indicators = Analyzer.Normalize(request?.ToIndicatorInput());
    var analysis = await analyzer.AnalyzeAsync(indicators, enableRdap, cancellationToken);
    var enriched = indicators with { DomainAgeDays = analysis.DomainAgeDays };

    var record = new ThreatRecord
    {
        ThreatId = Guid.NewGuid().ToString(),
        Status = "analyzed",
        Url = indicators.Url,
        Domain = indicators.Domain,
        Indicators = enriched,
        Analysis = analysis,
        Explanation = request?.Explain == true
            ? await explainer.ExplainAsync(enriched, analysis, ThreatExplainer.ReadConfig(ReadEnvironment()), cancellationToken)
            : null,
        ReportedAt = DateTimeOffset.UtcNow.ToString("o")
    };

    await store.InsertAsync(record, cancellationToken);

    return Results.Json(new
    {
        ok = true,
        threat_id = record.ThreatId,
        status = record.Status,
        message = "Threat report stored and analyzed"
    }, statusCode: StatusCodes.Status201Created);
});

app.MapGet("/api/threats/{threatId}", async (string threatId, ThreatStore store, CancellationToken cancellationToken) =>
{
    if (!Regex.IsMatch(threatId, "^[0-9a-fA-F-]+$"))
    {
        return Results.Json(new { error = "Not found" }, statusCode: StatusCodes.Status404NotFound);
    }
    var record = await store.FindByIdAsync(threatId, cancellationToken);
    return record is null
        ? Results.Json(new { error = "Threat report not found" }, statusCode: StatusCodes.Status404NotFound)
        : Results.Json(record);
});

app.MapFallback(() => Results.Json(new { error = "Not found" }, statusCode: StatusCodes.Status404NotFound));

app.Run();
return;

static Dictionary<string, string?> ReadEnvironment() =>
    Environment.GetEnvironmentVariables()
        .Cast<System.Collections.DictionaryEntry>()
        .ToDictionary(entry => (string)entry.Key, entry => entry.Value as string, StringComparer.OrdinalIgnoreCase);

static object AnalysisResponse(Analysis analysis, Indicators indicators, Explanation? explanation)
{
    var enriched = indicators with { DomainAgeDays = analysis.DomainAgeDays };
    return explanation is null
        ? new
        {
            risk_score = analysis.RiskScore,
            risk_level = analysis.RiskLevel,
            reasons = analysis.Reasons,
            evidence = analysis.EvidenceItems,
            domain_age_days = analysis.DomainAgeDays,
            engine_version = analysis.EngineVersion,
            analyzed_at = analysis.AnalyzedAt,
            indicators = enriched
        }
        : new
        {
            risk_score = analysis.RiskScore,
            risk_level = analysis.RiskLevel,
            reasons = analysis.Reasons,
            evidence = analysis.EvidenceItems,
            domain_age_days = analysis.DomainAgeDays,
            engine_version = analysis.EngineVersion,
            analyzed_at = analysis.AnalyzedAt,
            explanation,
            indicators = enriched
        };
}

static async Task<byte[]> ReadCappedBodyAsync(HttpContext context)
{
    using var buffer = new MemoryStream();
    var chunk = new byte[8192];
    int read;
    while ((read = await context.Request.Body.ReadAsync(chunk)) > 0)
    {
        if (buffer.Length + read > maxBodyBytesLimit)
        {
            throw new BadHttpRequestException("Request body is too large", StatusCodes.Status413PayloadTooLarge);
        }
        buffer.Write(chunk, 0, read);
    }
    return buffer.ToArray();
}

/// <summary>Exposed so the integration tests can host the app via WebApplicationFactory.</summary>
public partial class Program
{
    internal const int maxBodyBytesLimit = 100 * 1024;
}
