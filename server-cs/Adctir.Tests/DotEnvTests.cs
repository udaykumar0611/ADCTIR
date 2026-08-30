using Adctir.Api;

namespace Adctir.Tests;

public sealed class DotEnvTests
{
    private static Dictionary<string, string> ParseToDictionary(params string[] lines) =>
        DotEnv.Parse(lines).ToDictionary(entry => entry.Key, entry => entry.Value);

    [Fact]
    public void ParsesKeyValuePairsAndIgnoresCommentsAndBlanks()
    {
        var parsed = ParseToDictionary(
            "# a comment",
            "",
            "GEMINI_API_KEY=abc123",
            "  OPENROUTER_API_KEY = sk-or-v1-xyz  ",
            "export ADCTIR_AI_MODEL=gemini-2.0-flash",
            "   ",
            "#GEMINI_API_KEY=commented-out");

        Assert.Equal("abc123", parsed["GEMINI_API_KEY"]);
        Assert.Equal("sk-or-v1-xyz", parsed["OPENROUTER_API_KEY"]);
        Assert.Equal("gemini-2.0-flash", parsed["ADCTIR_AI_MODEL"]);
        Assert.Equal(3, parsed.Count);
    }

    [Fact]
    public void StripsOneLayerOfMatchingQuotes()
    {
        var parsed = ParseToDictionary(
            "DOUBLE=\"quoted value\"",
            "SINGLE='quoted value'",
            "BARE=unquoted value",
            "MISMATCHED=\"not closed");

        Assert.Equal("quoted value", parsed["DOUBLE"]);
        Assert.Equal("quoted value", parsed["SINGLE"]);
        Assert.Equal("unquoted value", parsed["BARE"]);
        Assert.Equal("\"not closed", parsed["MISMATCHED"]);
    }

    [Fact]
    public void KeepsCharactersThatAppearInRealApiKeys()
    {
        // Keys legitimately contain '=', '.', '-' and '#'; none of these may be
        // treated as a separator or a comment once the value has started.
        var parsed = ParseToDictionary(
            "GEMINI_API_KEY=AQ.Ab8RN6Ig-pRt56QE31==",
            "WITH_HASH=abc#def");

        Assert.Equal("AQ.Ab8RN6Ig-pRt56QE31==", parsed["GEMINI_API_KEY"]);
        Assert.Equal("abc#def", parsed["WITH_HASH"]);
    }

    [Fact]
    public void SkipsMalformedLines()
    {
        var parsed = ParseToDictionary("no equals sign here", "=novalue", "GOOD=yes");

        Assert.Equal("yes", Assert.Single(parsed).Value);
    }

    [Fact]
    public void AlreadySetVariablesAreNotOverwritten()
    {
        var name = $"ADCTIR_TEST_{Guid.NewGuid():N}";
        var other = $"ADCTIR_TEST_{Guid.NewGuid():N}";
        var file = Path.Combine(Path.GetTempPath(), $"adctir-dotenv-{Guid.NewGuid():N}.env");

        try
        {
            Environment.SetEnvironmentVariable(name, "from-real-environment");
            File.WriteAllText(file, $"{name}=from-file\n{other}=from-file\n");

            DotEnv.LoadFile(file);

            Assert.Equal("from-real-environment", Environment.GetEnvironmentVariable(name));
            Assert.Equal("from-file", Environment.GetEnvironmentVariable(other));
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
            Environment.SetEnvironmentVariable(other, null);
            File.Delete(file);
        }
    }

    [Fact]
    public void LoadWalksUpToFindTheFileAndReturnsNullWhenAbsent()
    {
        var root = Directory.CreateTempSubdirectory("adctir-dotenv-walk");
        try
        {
            var nested = Directory.CreateDirectory(Path.Combine(root.FullName, "server-cs", "Adctir.Api"));
            Assert.Null(DotEnv.Load(nested.FullName, maxDepth: 3));

            var envFile = Path.Combine(root.FullName, ".env");
            File.WriteAllText(envFile, "# empty\n");

            Assert.Equal(envFile, DotEnv.Load(nested.FullName, maxDepth: 3));
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }
}
