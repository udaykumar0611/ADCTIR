using System.Text;

namespace Adctir.Api;

public sealed record Passage
{
    public required string Id { get; init; }
    public required string DocId { get; init; }
    public required string DocTitle { get; init; }
    public required string Section { get; init; }
    public required string Text { get; init; }
    public required IReadOnlyList<string> FindingIds { get; init; }
}

public sealed record ScoredPassage
{
    public required Passage Passage { get; init; }
    public required double LexicalScore { get; init; }
    public required double Score { get; init; }
    public required IReadOnlyList<string> MatchedFindingIds { get; init; }

    public PassageRef ToRef() => new()
    {
        Id = Passage.Id,
        DocTitle = Passage.DocTitle,
        Section = Passage.Section,
        Score = Math.Round(Score, 4),
        MatchedFindingIds = MatchedFindingIds
    };
}

/// <summary>
/// Lexical retrieval over the local security-knowledge corpus.
///
/// BM25 is deliberate rather than a fallback: the corpus is a few dozen curated
/// passages, so an embedding service would add a network dependency, a second
/// provider key, and an index-build step without improving recall at this size.
/// Retrieval stays offline, deterministic, and unit-testable.
/// </summary>
public sealed class KnowledgeIndex
{
    public const string CorpusVersion = "adctir-knowledge-1.0.0";

    private const double K1 = 1.5;
    private const double B = 0.75;

    // Weight added per analyzer finding id shared between the query and a passage.
    // BM25 scores here land in roughly the 0-12 range, so this lifts an exactly
    // tagged passage above an untagged one that merely shares vocabulary.
    private const double FindingMatchWeight = 2.5;

    private static readonly HashSet<string> Stopwords =
    [
        "a", "an", "and", "are", "as", "at", "be", "because", "been", "but", "by", "can", "do", "does",
        "for", "from", "has", "have", "how", "in", "into", "is", "it", "its", "not", "of", "on", "one",
        "or", "over", "so", "than", "that", "the", "their", "them", "then", "there", "these", "they",
        "this", "to", "up", "was", "were", "what", "when", "which", "while", "who", "why", "with"
    ];

    private sealed record IndexedPassage(Passage Passage, int Length, Dictionary<string, int> Frequencies);

    private readonly List<IndexedPassage> _passages;
    private readonly Dictionary<string, int> _documentFrequency = [];
    private readonly double _averageLength;

    public KnowledgeIndex(IEnumerable<Passage> passages)
    {
        _passages = [.. passages.Select(passage =>
        {
            var tokens = Tokenize($"{passage.DocTitle} {passage.Section} {passage.Text}");
            var frequencies = new Dictionary<string, int>();
            foreach (var token in tokens)
            {
                frequencies[token] = frequencies.GetValueOrDefault(token) + 1;
            }
            return new IndexedPassage(passage, tokens.Count, frequencies);
        })];

        foreach (var passage in _passages)
        {
            foreach (var token in passage.Frequencies.Keys)
            {
                _documentFrequency[token] = _documentFrequency.GetValueOrDefault(token) + 1;
            }
        }

        _averageLength = _passages.Count > 0 ? _passages.Average(p => p.Length) : 0;
    }

    public int Size => _passages.Count;

    public IReadOnlyList<Passage> Passages => [.. _passages.Select(p => p.Passage)];

    public static List<string> Tokenize(string text)
    {
        var tokens = new List<string>();
        var current = new StringBuilder();

        foreach (var character in text.ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(character))
            {
                current.Append(character);
                continue;
            }
            Flush(tokens, current);
        }
        Flush(tokens, current);
        return tokens;

        static void Flush(List<string> tokens, StringBuilder current)
        {
            if (current.Length > 1)
            {
                var token = current.ToString();
                if (!Stopwords.Contains(token)) tokens.Add(token);
            }
            current.Clear();
        }
    }

    private double InverseDocumentFrequency(string token)
    {
        var df = _documentFrequency.GetValueOrDefault(token);
        return Math.Log(1 + (_passages.Count - df + 0.5) / (df + 0.5));
    }

    private double Score(IndexedPassage passage, IEnumerable<string> queryTokens)
    {
        var score = 0.0;
        foreach (var token in queryTokens)
        {
            if (!passage.Frequencies.TryGetValue(token, out var frequency)) continue;
            var denominator = frequency + K1 * (1 - B + B * passage.Length / (_averageLength == 0 ? 1 : _averageLength));
            score += InverseDocumentFrequency(token) * (frequency * (K1 + 1) / denominator);
        }
        return score;
    }

    /// <summary>
    /// Hybrid ranking: BM25 over the query text, plus a fixed bonus for each analyzer
    /// finding id the passage is tagged with. The tag bonus is what keeps a passage
    /// reachable when the rule's wording and the passage's wording do not overlap.
    ///
    /// Ranking alone can still starve a real finding: a weakly-worded rule loses every
    /// slot to a strongly-worded one, and the explanation then cites nothing for a
    /// finding that fired. With <paramref name="coverFindings"/>, each finding claims
    /// its best passage first - in the order given, so pass the fired findings by
    /// descending weight - and the remaining slots go to the top of the ranking.
    /// </summary>
    public IReadOnlyList<ScoredPassage> Retrieve(
        string query,
        int limit = 5,
        IReadOnlyList<string>? findingIds = null,
        bool coverFindings = false)
    {
        var queryTokens = Tokenize(query);
        var wanted = new HashSet<string>(findingIds ?? []);

        var ranked = _passages
            .Select(indexed =>
            {
                var matches = indexed.Passage.FindingIds.Where(wanted.Contains).ToArray();
                var lexical = Score(indexed, queryTokens);
                return new ScoredPassage
                {
                    Passage = indexed.Passage,
                    LexicalScore = Math.Round(lexical, 4),
                    Score = Math.Round(lexical + FindingMatchWeight * matches.Length, 4),
                    MatchedFindingIds = matches
                };
            })
            .Where(scored => scored.Score > 0)
            .OrderByDescending(scored => scored.Score)
            .ThenBy(scored => scored.Passage.Id, StringComparer.Ordinal)
            .ToList();

        var maximum = Math.Max(0, limit);
        if (!coverFindings) return ranked.Take(maximum).ToList();

        var selected = new List<ScoredPassage>();
        var taken = new HashSet<string>();

        foreach (var findingId in findingIds ?? [])
        {
            if (selected.Count >= maximum) break;
            var best = ranked.FirstOrDefault(p => !taken.Contains(p.Passage.Id) && p.Passage.FindingIds.Contains(findingId));
            if (best is null) continue;
            selected.Add(best);
            taken.Add(best.Passage.Id);
        }
        foreach (var passage in ranked)
        {
            if (selected.Count >= maximum) break;
            if (!taken.Add(passage.Passage.Id)) continue;
            selected.Add(passage);
        }

        return [.. selected.OrderByDescending(p => p.Score).ThenBy(p => p.Passage.Id, StringComparer.Ordinal)];
    }

    /// <summary>
    /// One markdown file is one document: a `# Title`, optional `finding-ids:` metadata,
    /// then `## Section` passages. A section may declare its own `finding-ids:` line to
    /// override the document-level tags.
    /// </summary>
    public static List<Passage> ParseDocument(string docId, string source)
    {
        var passages = new List<Passage>();
        var title = docId;
        IReadOnlyList<string> docFindingIds = [];

        string? heading = null;
        var sectionFindingIds = new List<string>();
        var body = new List<string>();

        void Flush()
        {
            if (heading is null) return;
            var text = string.Join("\n", body).Trim();
            if (text.Length > 0)
            {
                passages.Add(new Passage
                {
                    Id = $"{docId}#{Slugify(heading)}",
                    DocId = docId,
                    DocTitle = title,
                    Section = heading,
                    FindingIds = sectionFindingIds.Count > 0 ? [.. sectionFindingIds] : docFindingIds,
                    Text = text
                });
            }
            heading = null;
            sectionFindingIds.Clear();
            body.Clear();
        }

        foreach (var line in source.Split('\n').Select(l => l.TrimEnd('\r')))
        {
            if (line.StartsWith("## ", StringComparison.Ordinal))
            {
                Flush();
                heading = line[3..].Trim();
                continue;
            }
            if (line.StartsWith("# ", StringComparison.Ordinal))
            {
                title = line[2..].Trim();
                continue;
            }
            if (line.TrimStart().StartsWith("finding-ids", StringComparison.OrdinalIgnoreCase) && line.Contains(':'))
            {
                var ids = ParseFindingIds(line);
                if (heading is not null) sectionFindingIds.AddRange(ids);
                else docFindingIds = ids;
                continue;
            }
            if (heading is not null) body.Add(line);
        }
        Flush();
        return passages;
    }

    private static IReadOnlyList<string> ParseFindingIds(string line)
    {
        var separatorIndex = line.IndexOf(':');
        return [.. line[(separatorIndex + 1)..]
            .Split(',')
            .Select(value => value.Trim())
            .Where(value => value.Length > 0)];
    }

    private static string Slugify(string text)
    {
        var builder = new StringBuilder();
        foreach (var character in text.ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(character)) builder.Append(character);
            else if (builder.Length > 0 && builder[^1] != '-') builder.Append('-');
        }
        var slug = builder.ToString().Trim('-');
        return slug.Length > 60 ? slug[..60] : slug;
    }

    public static KnowledgeIndex LoadFrom(string directory)
    {
        var passages = Directory
            .EnumerateFiles(directory, "*.md")
            .OrderBy(path => Path.GetFileName(path), StringComparer.Ordinal)
            .SelectMany(path => ParseDocument(Path.GetFileNameWithoutExtension(path), File.ReadAllText(path)));
        return new KnowledgeIndex(passages);
    }
}
