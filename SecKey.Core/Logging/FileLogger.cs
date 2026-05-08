using Microsoft.Extensions.Logging;

namespace SecKey.Core.Logging;

/// <summary>
/// Lightweight log-to-file sink mirroring the PowerShell Start-Log/Write-Log helpers.
/// </summary>
public sealed class FileLogger : IDisposable
{
    private readonly StreamWriter _writer;
    private readonly object _lock = new();
    public string FilePath { get; }

    public FileLogger(string filePath)
    {
        FilePath = filePath;
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        _writer = new StreamWriter(new FileStream(filePath, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true
        };
    }

    public void Write(string level, string message)
    {
        lock (_lock)
        {
            _writer.WriteLine($"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffZ} [{level}] {message}");
        }
    }

    public void Info(string m) => Write("INFO", m);
    public void Warn(string m) => Write("WARN", m);
    public void Error(string m) => Write("ERROR", m);
    public void Debug(string m) => Write("DEBUG", m);

    public void Dispose() => _writer.Dispose();

    public static string DefaultLogPath()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(appData, "Microsoft", "SecKey", "SecKey.log");
    }
}

/// <summary>An ILogger that also fans out to a FileLogger.</summary>
public sealed class FileForwardingLogger : ILogger
{
    private readonly string _category;
    private readonly FileLogger _file;
    public FileForwardingLogger(string category, FileLogger file) { _category = category; _file = file; }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Debug;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var msg = formatter(state, exception);
        if (exception is not null) msg += " | " + exception;
        _file.Write(logLevel.ToString().ToUpperInvariant(), $"{_category}: {msg}");
    }
}
