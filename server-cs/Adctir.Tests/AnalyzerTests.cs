using Adctir.Api;

namespace Adctir.Tests;

public sealed class AnalyzerTests
{
    [Fact]
    public void NormalizeRejectsNonHttpSchemes()
    {
        var error = Assert.Throws<ValidationException>(() =>
            Analyzer.Normalize(new IndicatorInput { Url = "file:///etc/passwd" }));
        Assert.Contains("HTTP or HTTPS", error.Message);

        Assert.Throws<ValidationException>(() => Analyzer.Normalize(new IndicatorInput { Url = "chrome://extensions" }));
        Assert.Throws<ValidationException>(() => Analyzer.Normalize(new IndicatorInput { Url = "not a url" }));
        Assert.Throws<ValidationException>(() => Analyzer.Normalize(new IndicatorInput { Url = null }));
    }

    [Fact]
    public void NormalizeClampsRedirectCountAndTruncatesText()
    {
        var clamped = Analyzer.Normalize(new IndicatorInput { Url = "https://example.com", RedirectCount = 900 });
        Assert.Equal(50, clamped.RedirectCount);

        var negative = Analyzer.Normalize(new IndicatorInput { Url = "https://example.com", RedirectCount = -5 });
        Assert.Equal(0, negative.RedirectCount);

        var truncated = Analyzer.Normalize(new IndicatorInput
        {
            Url = "https://example.com",
            SuspiciousPattern = new string('x', 5000),
            IndicatorDescription = new string('y', 5000)
        });
        Assert.Equal(2000, truncated.SuspiciousPattern!.Length);
        Assert.Equal(500, truncated.IndicatorDescription!.Length);
    }

    [Fact]
    public async Task SafePageScoresZeroWithNoFindings()
    {
        var (_, analysis) = await TestCorpus.AnalyzeAsync("https://example.com/");

        Assert.Equal(0, analysis.RiskScore);
        Assert.Equal("Safe", analysis.RiskLevel);
        Assert.Empty(analysis.EvidenceItems);
        Assert.Equal("No suspicious indicators were detected", Assert.Single(analysis.Reasons));
        Assert.Equal(Analyzer.EngineVersion, analysis.EngineVersion);
    }

    [Fact]
    public async Task HighRiskPageAccumulatesEveryMatchingRule()
    {
        var (_, analysis) = await TestCorpus.AnalyzeAsync(
            "http://secure-login-verify.top/signin", hasLoginForm: true, redirectCount: 4);

        var ids = analysis.EvidenceItems.Select(e => e.Id).ToList();

        Assert.Equal("High-Risk", analysis.RiskLevel);
        Assert.Contains("no_https", ids);
        Assert.Contains("insecure_login", ids);
        Assert.Contains("many_redirects", ids);
        Assert.Contains("sensitive_domain_words", ids);
        Assert.Contains("higher_risk_tld", ids);
        Assert.Equal(analysis.RiskScore, Math.Min(100, analysis.EvidenceItems.Sum(e => e.Weight)));
    }

    [Theory]
    [InlineData("http://192.168.1.10/", "raw_ip")]
    [InlineData("https://xn--pple-43d.com/", "punycode")]
    [InlineData("https://a-b-c-d-e.com/", "many_hyphens")]
    [InlineData("https://a.b.c.d.example.com/", "many_subdomains")]
    [InlineData("https://bit.ly/abc", "url_shortener")]
    [InlineData("https://example.zip/", "higher_risk_tld")]
    public async Task StructuralRulesFireOnTheirOwnSignal(string url, string expectedFinding)
    {
        var (_, analysis) = await TestCorpus.AnalyzeAsync(url);
        Assert.Contains(expectedFinding, analysis.EvidenceItems.Select(e => e.Id));
    }

    [Fact]
    public async Task ScoreIsCappedAtOneHundred()
    {
        var url = "http://xn--login-verify-secure-account-update.a.b.c.d.e.top/" + new string('p', 260);
        var (_, analysis) = await TestCorpus.AnalyzeAsync(url, hasLoginForm: true, redirectCount: 9);

        Assert.True(analysis.EvidenceItems.Sum(e => e.Weight) > 100, "this fixture should over-accumulate before the cap");
        Assert.Equal(100, analysis.RiskScore);
    }

    [Fact]
    public async Task SuppliedDomainAgeDrivesTheAgeRulesWithoutRdap()
    {
        var youngIndicators = Analyzer.Normalize(new IndicatorInput { Url = "https://example.com", DomainAgeDays = 10 });
        var young = await new Analyzer().AnalyzeAsync(youngIndicators, enableRdap: false);
        Assert.Contains("new_domain", young.EvidenceItems.Select(e => e.Id));

        var midIndicators = Analyzer.Normalize(new IndicatorInput { Url = "https://example.com", DomainAgeDays = 90 });
        var mid = await new Analyzer().AnalyzeAsync(midIndicators, enableRdap: false);
        Assert.Contains("young_domain", mid.EvidenceItems.Select(e => e.Id));

        var oldIndicators = Analyzer.Normalize(new IndicatorInput { Url = "https://example.com", DomainAgeDays = 4000 });
        var old = await new Analyzer().AnalyzeAsync(oldIndicators, enableRdap: false);
        Assert.DoesNotContain("young_domain", old.EvidenceItems.Select(e => e.Id));
        Assert.DoesNotContain("new_domain", old.EvidenceItems.Select(e => e.Id));
    }

    [Fact]
    public async Task RdapLookupIsSkippedForAddressesThatCannotHaveRegistrationData()
    {
        var analyzer = new Analyzer(new HttpClient());
        Assert.Null(await analyzer.FetchDomainAgeDaysAsync("127.0.0.1"));
        Assert.Null(await analyzer.FetchDomainAgeDaysAsync("localhost"));
    }

    [Fact]
    public async Task RdapRequestIdentifiesItselfAndAsksForRdapJson()
    {
        // rdap.org answers 403 when no User-Agent is present, and HttpClient sends
        // none by default - which silently disabled domain-age enrichment entirely.
        HttpRequestMessage? captured = null;
        var analyzer = new Analyzer(TestCorpus.StubClient(request =>
        {
            captured = request;
            return TestCorpus.Ok("""{"events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"}]}""");
        }));

        await analyzer.FetchDomainAgeDaysAsync("example.com");

        Assert.NotNull(captured);
        Assert.Equal("https://rdap.org/domain/example.com", captured.RequestUri!.ToString());
        Assert.NotEmpty(captured.Headers.UserAgent.ToString());
        Assert.Contains("rdap+json", captured.Headers.Accept.ToString());
    }

    [Fact]
    public async Task RdapRegistrationDateBecomesAnAgeInDays()
    {
        var registered = DateTimeOffset.UtcNow.AddDays(-45);
        var analyzer = new Analyzer(TestCorpus.StubClient(_ => TestCorpus.Ok(
            $$"""{"events":[{"eventAction":"last changed","eventDate":"2024-01-01T00:00:00Z"},{"eventAction":"registration","eventDate":"{{registered:o}}"}]}""")));

        var age = await analyzer.FetchDomainAgeDaysAsync("example.com");

        Assert.NotNull(age);
        Assert.InRange(age.Value, 44, 46);
    }

    [Fact]
    public async Task RdapUsesTheRegistrableDomainNotTheFullHost()
    {
        HttpRequestMessage? captured = null;
        var analyzer = new Analyzer(TestCorpus.StubClient(request =>
        {
            captured = request;
            return TestCorpus.Ok("""{"events":[]}""");
        }));

        await analyzer.FetchDomainAgeDaysAsync("login.secure.example.com");

        Assert.Equal("https://rdap.org/domain/example.com", captured!.RequestUri!.ToString());
    }

    [Fact]
    public async Task RdapFailuresDegradeToNullWithoutBreakingAnalysis()
    {
        var forbidden = new Analyzer(TestCorpus.StubClient(_ =>
            TestCorpus.Status(System.Net.HttpStatusCode.Forbidden, "{}")));
        Assert.Null(await forbidden.FetchDomainAgeDaysAsync("example.com"));

        var noEvents = new Analyzer(TestCorpus.StubClient(_ => TestCorpus.Ok("""{"objectClassName":"domain"}""")));
        Assert.Null(await noEvents.FetchDomainAgeDaysAsync("example.com"));

        var noRegistration = new Analyzer(TestCorpus.StubClient(_ =>
            TestCorpus.Ok("""{"events":[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}]}""")));
        Assert.Null(await noRegistration.FetchDomainAgeDaysAsync("example.com"));

        var offline = new Analyzer(TestCorpus.StubClient(_ => throw new HttpRequestException("no network")));
        Assert.Null(await offline.FetchDomainAgeDaysAsync("example.com"));
    }

    [Fact]
    public async Task RdapAgeFeedsTheDomainAgeRules()
    {
        var registered = DateTimeOffset.UtcNow.AddDays(-10);
        var analyzer = new Analyzer(TestCorpus.StubClient(_ => TestCorpus.Ok(
            $$"""{"events":[{"eventAction":"registration","eventDate":"{{registered:o}}"}]}""")));

        var indicators = Analyzer.Normalize(new IndicatorInput { Url = "https://brand-new-site.com" });
        var analysis = await analyzer.AnalyzeAsync(indicators, enableRdap: true);

        Assert.Contains("new_domain", analysis.EvidenceItems.Select(e => e.Id));
        Assert.NotNull(analysis.DomainAgeDays);
        Assert.InRange(analysis.DomainAgeDays!.Value, 9, 11);
    }
}
