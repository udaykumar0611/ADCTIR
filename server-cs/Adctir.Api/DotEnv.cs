namespace Adctir.Api;

/// <summary>
/// Minimal .env loader for local development.
///
/// Two rules keep this safe to leave switched on: it never overwrites a variable
/// that is already set, so real secrets management always wins, and the caller
/// skips it entirely outside development. A missing file is not an error.
/// </summary>
public static class DotEnv
{
    /// <summary>
    /// Walks up from <paramref name="startDirectory"/> looking for a .env file, so
    /// the API can be launched from the repo root or from its own project folder.
    /// Returns the file that was loaded, or null when none was found.
    /// </summary>
    public static string? Load(string startDirectory, int maxDepth = 5)
    {
        var directory = new DirectoryInfo(startDirectory);

        for (var depth = 0; depth < maxDepth && directory is not null; depth++)
        {
            var candidate = Path.Combine(directory.FullName, ".env");
            if (File.Exists(candidate))
            {
                LoadFile(candidate);
                return candidate;
            }
            directory = directory.Parent;
        }
        return null;
    }

    public static void LoadFile(string path)
    {
        foreach (var (key, value) in Parse(File.ReadAllLines(path)))
        {
            // An explicitly exported variable outranks the file.
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(key))) continue;
            Environment.SetEnvironmentVariable(key, value);
        }
    }

    public static IEnumerable<(string Key, string Value)> Parse(IEnumerable<string> lines)
    {
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;

            if (line.StartsWith("export ", StringComparison.Ordinal)) line = line[7..].TrimStart();

            var separator = line.IndexOf('=');
            if (separator <= 0) continue;

            var key = line[..separator].Trim();
            if (key.Length == 0) continue;

            var value = line[(separator + 1)..].Trim();

            // Strip one layer of matching quotes; an unquoted value keeps any inline
            // '#' because API keys can legitimately contain one.
            if (value.Length >= 2 &&
                ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
            {
                value = value[1..^1];
            }

            yield return (key, value);
        }
    }
}
