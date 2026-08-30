using System.Text.Json;

namespace Adctir.Api;

/// <summary>
/// Serialized, atomic JSON persistence. Writes are queued behind a semaphore and
/// land via a temp file plus rename, so a crash mid-write cannot truncate the
/// existing reports.
/// </summary>
public sealed class ThreatStore(string filePath)
{
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public string FilePath { get; } = filePath;

    public async Task<List<ThreatRecord>> ReadAllAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var text = await File.ReadAllTextAsync(FilePath, cancellationToken);
            return JsonSerializer.Deserialize<List<ThreatRecord>>(text) ?? [];
        }
        catch (FileNotFoundException)
        {
            return [];
        }
        catch (DirectoryNotFoundException)
        {
            return [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    public async Task<ThreatRecord> InsertAsync(ThreatRecord record, CancellationToken cancellationToken = default)
    {
        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            var records = await ReadAllAsync(cancellationToken);
            records.Add(record);

            var directory = Path.GetDirectoryName(Path.GetFullPath(FilePath));
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            var temporaryPath = FilePath + ".tmp";
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(records, WriteOptions), cancellationToken);
            File.Move(temporaryPath, FilePath, overwrite: true);

            return record;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<ThreatRecord?> FindByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        var records = await ReadAllAsync(cancellationToken);
        return records.FirstOrDefault(record => record.ThreatId == id);
    }
}
