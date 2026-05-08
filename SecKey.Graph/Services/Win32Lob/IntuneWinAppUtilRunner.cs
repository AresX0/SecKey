using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace SecKey.Graph.Services.Win32Lob;

/// <summary>
/// Wraps the IntuneWinAppUtil.exe tool (ports public Invoke-IntuneWinAppUtil.ps1).
/// </summary>
public sealed class IntuneWinAppUtilRunner
{
    private readonly ILogger<IntuneWinAppUtilRunner> _log;
    public string IntuneWinAppUtilPath { get; }

    public IntuneWinAppUtilRunner(string toolPath, ILogger<IntuneWinAppUtilRunner> log)
    {
        if (!File.Exists(toolPath))
            throw new FileNotFoundException("IntuneWinAppUtil.exe not found", toolPath);
        IntuneWinAppUtilPath = toolPath;
        _log = log;
    }

    /// <summary>
    /// Packages a folder into an .intunewin file.
    /// </summary>
    /// <param name="appType">PS1, EXE, or MSI</param>
    /// <param name="packageRoot">Parent folder containing a "Source" subfolder.</param>
    /// <param name="packageName">Base file name without extension.</param>
    /// <returns>Full path to the generated .intunewin file.</returns>
    public async Task<string> PackageAsync(string appType, string packageRoot, string packageName, CancellationToken ct = default)
    {
        var sourcePath = Path.Combine(packageRoot, "Source");
        if (!Directory.Exists(sourcePath))
            sourcePath = Path.Combine(packageRoot, "source");
        if (!Directory.Exists(sourcePath))
            throw new DirectoryNotFoundException($"Source folder not found under {packageRoot}");

        var ext = appType.ToUpperInvariant() switch
        {
            "PS1" => ".ps1",
            "EXE" => ".exe",
            "MSI" => ".msi",
            _ => throw new ArgumentException($"Unsupported AppType: {appType}")
        };
        var setupFile = Path.Combine(sourcePath, packageName + ext);
        if (!File.Exists(setupFile))
            throw new FileNotFoundException("Setup file not found inside Source", setupFile);

        var outputDir = Path.Combine(packageRoot, "IntuneWin");
        if (Directory.Exists(outputDir)) Directory.Delete(outputDir, true);
        Directory.CreateDirectory(outputDir);

        var args = $"-q -c \"{sourcePath}\" -s \"{setupFile}\" -o \"{outputDir}\"";
        _log.LogInformation("Running: {Tool} {Args}", IntuneWinAppUtilPath, args);

        var psi = new ProcessStartInfo(IntuneWinAppUtilPath, args)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start IntuneWinAppUtil");
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0)
        {
            var err = await p.StandardError.ReadToEndAsync(ct);
            throw new InvalidOperationException($"IntuneWinAppUtil exited with code {p.ExitCode}: {err}");
        }

        var result = Path.Combine(outputDir, packageName + ".intunewin");
        if (!File.Exists(result))
            throw new FileNotFoundException("Expected intunewin file was not produced", result);
        return result;
    }
}
