using System.Text;
using System.Threading.Channels;

namespace Bifrost.ClientService;

/// <summary>Best-effort diagnostics never wait for disk on an IPC/runtime
/// thread. One consumer owns ordering, batching and I/O; overload drops new
/// messages within fixed memory bounds rather than delaying the tunnel.</summary>
internal sealed class BoundedTraceWriter
{
    private const int MaximumLineCharacters = 4096;
    private const int MaximumBatchLines = 32;
    private readonly Channel<string> _queue;
    private readonly Func<IReadOnlyList<string>, Task> _writeBatch;
    private readonly Task _consumer;
    private long _dropped;
    private long _failedBatches;

    internal BoundedTraceWriter(Func<IReadOnlyList<string>, Task> writeBatch, int capacity = 256)
    {
        ArgumentNullException.ThrowIfNull(writeBatch);
        if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity));
        _writeBatch = writeBatch;
        _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false,
        });
        _consumer = Task.Run(ConsumeAsync);
    }

    internal long DroppedMessages => Interlocked.Read(ref _dropped);
    internal long FailedBatches => Interlocked.Read(ref _failedBatches);

    internal bool TryWrite(string line)
    {
        ArgumentNullException.ThrowIfNull(line);
        if (line.Length > MaximumLineCharacters) line = line[..MaximumLineCharacters];
        if (_queue.Writer.TryWrite(line)) return true;
        Interlocked.Increment(ref _dropped);
        return false;
    }

    internal Task CompleteAsync()
    {
        _queue.Writer.TryComplete();
        return _consumer;
    }

    private async Task ConsumeAsync()
    {
        while (await _queue.Reader.WaitToReadAsync().ConfigureAwait(false))
        {
            var lines = new List<string>(MaximumBatchLines);
            while (lines.Count < MaximumBatchLines && _queue.Reader.TryRead(out var line)) lines.Add(line);
            try { await _writeBatch(lines).ConfigureAwait(false); }
            catch { Interlocked.Increment(ref _failedBatches); }
        }
    }
}

/// <summary>At most one current log and one archive, each bounded by bytes.
/// An oversized legacy log is reduced to a bounded tail on first rotation.</summary>
internal sealed class RotatingTraceFile(string path, int maximumBytes = 4 * 1024 * 1024)
{
    private readonly string _path = Path.GetFullPath(path);
    private readonly int _maximumBytes = maximumBytes >= 4096 ? maximumBytes : throw new ArgumentOutOfRangeException(nameof(maximumBytes));

    internal async Task WriteBatchAsync(IReadOnlyList<string> lines)
    {
        using var current = new FileStream(_path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read, 16 * 1024, FileOptions.Asynchronous);
        current.Seek(0, SeekOrigin.End);
        foreach (var line in lines)
        {
            var bounded = line.Length > _maximumBytes / 4 - 1 ? line[..(_maximumBytes / 4 - 1)] : line;
            var bytes = Encoding.UTF8.GetBytes(bounded.TrimEnd('\r', '\n') + Environment.NewLine);
            if (current.Length + bytes.Length > _maximumBytes)
            {
                using var archive = new FileStream(_path + ".1", FileMode.Create, FileAccess.Write, FileShare.Read, 16 * 1024, FileOptions.Asynchronous);
                current.Seek(Math.Max(0, current.Length - _maximumBytes), SeekOrigin.Begin);
                await current.CopyToAsync(archive).ConfigureAwait(false);
                current.SetLength(0);
                current.Position = 0;
            }
            await current.WriteAsync(bytes).ConfigureAwait(false);
        }
        await current.FlushAsync().ConfigureAwait(false);
    }
}
