using Adctir.Api;

namespace Adctir.Tests;

public sealed class RetrieverTests
{
    [Fact]
    public void KnowledgeCorpusLoadsWithTaggedPassages()
    {
        var passages = TestCorpus.Index.Passages;

        Assert.True(passages.Count >= 15, $"expected a populated corpus, got {passages.Count}");
        Assert.All(passages, passage =>
        {
            Assert.Contains('#', passage.Id);
            Assert.True(passage.Text.Length > 100);
        });

        var tagged = passages.SelectMany(p => p.FindingIds).ToHashSet();
        foreach (var findingId in new[] { "no_https", "insecure_login", "punycode", "new_domain", "many_redirects", "url_shortener" })
        {
            Assert.True(tagged.Contains(findingId), $"no passage is tagged for finding {findingId}");
        }
    }

    [Fact]
    public void TokenizerDropsStopwordsAndPunctuation()
    {
        Assert.Equal(["domain", "lookalike", "https"], KnowledgeIndex.Tokenize("The domain is a lookalike, not HTTPS!"));
    }

    [Fact]
    public async Task RetrievalRanksPassagesTaggedForFindingsThatFired()
    {
        var (indicators, analysis) = await TestCorpus.AnalyzeAsync("http://secure-login.example.com", hasLoginForm: true);
        var passages = TestCorpus.Explainer.RetrieveContext(indicators, analysis);

        Assert.NotEmpty(passages);
        Assert.NotEmpty(passages[0].MatchedFindingIds);
        Assert.Contains(passages, p => p.Passage.DocId == "transport-security");

        for (var i = 1; i < passages.Count; i++)
        {
            Assert.True(passages[i - 1].Score >= passages[i].Score, "passages must be sorted by descending score");
        }
    }

    [Fact]
    public void FindingTagsLiftAPassageAbovePureLexicalOverlap()
    {
        const string query = "domain registration age";
        var untagged = TestCorpus.Index.Retrieve(query, limit: 20);
        var tagged = TestCorpus.Index.Retrieve(query, limit: 20, findingIds: ["many_redirects"]);

        var redirectUntagged = untagged.FirstOrDefault(p => p.Passage.DocId == "redirect-chains");
        var redirectTagged = tagged.FirstOrDefault(p => p.Passage.DocId == "redirect-chains");

        Assert.NotNull(redirectTagged);
        Assert.True(
            redirectUntagged is null || redirectTagged.Score > redirectUntagged.Score,
            "the tag bonus must raise the score of a passage matching a fired finding");
    }

    [Fact]
    public async Task EveryFiredFindingGetsASupportingPassage()
    {
        var (indicators, analysis) = await TestCorpus.AnalyzeAsync(
            "http://secure-login-verify.top/signin", hasLoginForm: true, redirectCount: 4);
        var passages = TestCorpus.Explainer.RetrieveContext(indicators, analysis);

        var covered = passages.SelectMany(p => p.MatchedFindingIds).ToHashSet();
        var fired = analysis.EvidenceItems.Select(e => e.Id).ToList();

        Assert.True(fired.Count >= 5, "this fixture should fire several rules");
        foreach (var findingId in fired)
        {
            Assert.True(covered.Contains(findingId), $"no retrieved passage supports the fired finding {findingId}");
        }
    }

    [Fact]
    public async Task CoverageDoesNotCrowdOutTheStrongestPassage()
    {
        var (indicators, analysis) = await TestCorpus.AnalyzeAsync(
            "http://secure-login-verify.top/signin", hasLoginForm: true, redirectCount: 4);
        var passages = TestCorpus.Explainer.RetrieveContext(indicators, analysis);

        Assert.Equal("transport-security#login-forms-on-unencrypted-pages", passages[0].Passage.Id);
        for (var i = 1; i < passages.Count; i++)
        {
            Assert.True(passages[i - 1].Score >= passages[i].Score, "the returned set stays sorted by score");
        }
    }

    [Fact]
    public async Task RetrievalIsDeterministicAcrossCalls()
    {
        var (indicators, analysis) = await TestCorpus.AnalyzeAsync("https://xn--pple-43d.com/", hasLoginForm: true);

        var first = TestCorpus.Explainer.RetrieveContext(indicators, analysis).Select(p => p.Passage.Id);
        var second = TestCorpus.Explainer.RetrieveContext(indicators, analysis).Select(p => p.Passage.Id);

        Assert.Equal(first, second);
    }
}
